//! LearnOrExpose over a matrix of parameters, adversaries and seeds.
//!
//! Each run picks the Byzantine set and each Byzantine node's behavior from
//! a seeded RNG, so the number of distinct scenarios grows with the seed
//! count and every failure is reproducible from its (n, t, seed) triple.
//! The default test keeps CI fast; the ignored one is the full sweep:
//!
//! ```text
//! cargo test -p polaris-proto --release --test robustness -- --ignored --nocapture
//! ```

use std::sync::Arc;

use polaris_core::{Ctx, NodeId, NodeSet, Outgoing, Params, Round, RoundMachine, wire};
use polaris_crypto::bls;
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::accusations::Accusation;
use polaris_proto::disclosure::{Disclosure, Entries};
use polaris_proto::learn_or_expose::{LearnOrExpose, LoeMsg};
use polaris_sim::{Adversary, HonestSend, Node, Silent, Simulator};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha12Rng;

const RUN: u64 = 5;

/// Byzantine behaviors, all combinable with any disclosure pattern.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// Sends nothing.
    Silent,
    /// Accuses every honest node every round with valid signatures.
    AccuseHonest,
    /// Floods invalid accusations impersonating honest accusers.
    FakeFlood,
    /// Behaves honestly but never forwards.
    NoForward,
    /// Discloses to one honest node in the second round only.
    LateDisclose,
}

const KINDS: [Kind; 5] = [
    Kind::Silent,
    Kind::AccuseHonest,
    Kind::FakeFlood,
    Kind::NoForward,
    Kind::LateDisclose,
];

struct Scenario {
    kr: Arc<Keyring>,
    keys: Vec<Arc<NodeKeys>>,
    byzantine: NodeSet,
    kinds: Vec<Option<Kind>>,
    /// reached[j][i]: did Byzantine j's round-0 disclosure reach honest i.
    reached: Vec<Vec<bool>>,
}

impl Scenario {
    fn random(n: usize, t: usize, seed: u64) -> Self {
        let params = Params::new(n, t).unwrap();
        let (kr, keys) = keyring::generate(params, RUN, seed);
        let mut rng = ChaCha12Rng::seed_from_u64(seed);
        let f = rng.random_range(1..=t.min(n - 1));
        let mut ids: Vec<NodeId> = (0..n as NodeId).collect();
        for i in (1..ids.len()).rev() {
            let j = rng.random_range(0..=i);
            ids.swap(i, j);
        }
        let byzantine = NodeSet::from_iter(n, ids[..f].iter().copied());
        let kinds = (0..n as NodeId)
            .map(|i| {
                byzantine
                    .contains(i)
                    .then(|| KINDS[rng.random_range(0..KINDS.len())])
            })
            .collect();
        let reached = (0..n)
            .map(|_| (0..n).map(|_| rng.random_range(0..3) == 0).collect())
            .collect();
        Self {
            kr: Arc::new(kr),
            keys: keys.into_iter().map(Arc::new).collect(),
            byzantine,
            kinds,
            reached,
        }
    }

    fn value(j: NodeId) -> Vec<u8> {
        format!("input-{j}").into_bytes()
    }

    fn disclosure(&self, j: NodeId) -> Disclosure {
        Disclosure::sign(&self.keys[usize::from(j)], RUN, Self::value(j))
    }

    fn entries(&self, me: NodeId) -> Entries {
        (0..self.kr.n() as NodeId)
            .map(|j| {
                let have = !self.byzantine.contains(j)
                    || (self.reached[usize::from(j)][usize::from(me)]
                        && !matches!(self.kinds[usize::from(j)], Some(Kind::LateDisclose)));
                have.then(|| self.disclosure(j))
            })
            .collect()
    }

    fn loe(&self, me: NodeId, leader: NodeId) -> LearnOrExpose {
        LearnOrExpose::new(
            self.kr.clone(),
            self.keys[usize::from(me)].clone(),
            leader,
            self.entries(me),
        )
    }

    fn adversary(&self, me: NodeId, leader: NodeId) -> Box<dyn Adversary<LearnOrExpose>> {
        let honest: Vec<NodeId> = (0..self.kr.n() as NodeId)
            .filter(|i| !self.byzantine.contains(*i))
            .collect();
        match self.kinds[usize::from(me)].expect("Byzantine") {
            Kind::Silent => Box::new(Silent),
            Kind::AccuseHonest => Box::new(AccuseHonest {
                keys: self.keys[usize::from(me)].clone(),
                honest,
            }),
            Kind::FakeFlood => Box::new(FakeFlood { honest }),
            Kind::NoForward => Box::new(NoForward {
                inner: self.loe(me, leader),
                me,
            }),
            Kind::LateDisclose => Box::new(LateDisclose {
                disclosure: self.disclosure(me),
                to: honest[0],
            }),
        }
    }

    /// Runs one instance and checks every invariant; returns a summary line.
    fn run(&self, seed: u64) -> Summary {
        let n = self.kr.n();
        let leader = (0..n as NodeId)
            .find(|i| !self.byzantine.contains(*i))
            .expect("one honest node");
        let nodes = (0..n as NodeId)
            .map(|i| {
                if self.byzantine.contains(i) {
                    Node::Byzantine(self.adversary(i, leader))
                } else {
                    Node::Honest(self.loe(i, leader))
                }
            })
            .collect();
        let mut sim = Simulator::new(self.kr.params, RUN, nodes)
            .unwrap()
            .with_transcript(false);
        let r = self.kr.params.loe_rounds();
        let decided = sim
            .run_until_decided(r + 2)
            .expect("every honest node outputs");
        assert_eq!(decided, r, "seed {seed}: outputs must appear at round R");

        let mut summary = Summary {
            n,
            t: self.kr.params.t,
            f: self.byzantine.count(),
            seed,
            rounds: r,
            ..Default::default()
        };
        for i in (0..n as NodeId).filter(|i| !self.byzantine.contains(*i)) {
            let m = sim.honest(i).unwrap();
            let out = m
                .output()
                .unwrap_or_else(|| panic!("seed {seed}: honest {i} has no output"));
            for j in 0..n as NodeId {
                match &out.entries[usize::from(j)] {
                    Some(d) => assert_eq!(
                        (d.sender, &d.value),
                        (j, &Self::value(j)),
                        "seed {seed}: node {i}, entry {j}"
                    ),
                    None => assert!(
                        self.byzantine.contains(j),
                        "seed {seed}: node {i} exposed honest {j}"
                    ),
                }
            }
            for v in (0..n as NodeId).filter(|v| !self.byzantine.contains(*v)) {
                assert!(
                    out.verify(v, &self.kr),
                    "seed {seed}: output of {i} rejected by {v}"
                );
            }
            for (a, b) in m.accusations().edges() {
                assert!(
                    self.byzantine.contains(a) || self.byzantine.contains(b),
                    "seed {seed}: honest {a} accused honest {b}"
                );
            }
            let s = m.stats();
            summary.resolved_round = summary.resolved_round.max(s.resolved_round.unwrap_or(r));
            summary.accusations = summary.accusations.max(m.accusations().len());
            summary.rejected += s.accusations_rejected;
            summary.proof_bytes = summary
                .proof_bytes
                .max(wire::encode(&out.proof).unwrap().len());
            summary.exposed = summary.exposed.max(out.exposed().count());
        }
        summary.bytes_sent = sim.metrics(leader).total().bytes_sent;
        summary
    }
}

#[derive(Default, Debug)]
struct Summary {
    n: usize,
    t: usize,
    f: usize,
    seed: u64,
    rounds: u32,
    /// Latest round at which some honest node still had an unresolved party.
    resolved_round: u32,
    accusations: usize,
    rejected: u64,
    proof_bytes: usize,
    exposed: usize,
    bytes_sent: u64,
}

struct AccuseHonest {
    keys: Arc<NodeKeys>,
    honest: Vec<NodeId>,
}
impl Adversary<LearnOrExpose> for AccuseHonest {
    fn act(
        &mut self,
        _: &mut Ctx,
        _: Round,
        _: Vec<(NodeId, LoeMsg)>,
        _: &[HonestSend<'_, LoeMsg>],
    ) -> Vec<Outgoing<LoeMsg>> {
        self.honest
            .iter()
            .map(|&h| Outgoing::all(LoeMsg::Accuse(Accusation::sign(&self.keys, RUN, h))))
            .collect()
    }
}

struct FakeFlood {
    honest: Vec<NodeId>,
}
impl Adversary<LearnOrExpose> for FakeFlood {
    fn act(
        &mut self,
        _: &mut Ctx,
        round: Round,
        _: Vec<(NodeId, LoeMsg)>,
        _: &[HonestSend<'_, LoeMsg>],
    ) -> Vec<Outgoing<LoeMsg>> {
        let mut out = Vec::new();
        for (k, &a) in self.honest.iter().enumerate() {
            let b = self.honest[(k + 1) % self.honest.len()];
            if a != b {
                let garbage = bls::Sig([(round as u8).wrapping_add(k as u8); bls::SIG_LEN]);
                out.push(Outgoing::all(LoeMsg::Accuse(Accusation {
                    accuser: a,
                    target: b,
                    sig: garbage,
                })));
            }
        }
        out
    }
}

struct NoForward {
    inner: LearnOrExpose,
    me: NodeId,
}
impl NoForward {
    fn own_only(&self, out: Vec<Outgoing<LoeMsg>>) -> Vec<Outgoing<LoeMsg>> {
        out.into_iter()
            .filter(|o| match &o.msg {
                LoeMsg::Disclose(d) => d.sender == self.me,
                LoeMsg::Accuse(a) => a.accuser == self.me,
            })
            .collect()
    }
}
impl Adversary<LearnOrExpose> for NoForward {
    fn start(&mut self, ctx: &mut Ctx) -> Vec<Outgoing<LoeMsg>> {
        let out = self.inner.start(ctx);
        self.own_only(out)
    }
    fn act(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, LoeMsg)>,
        _: &[HonestSend<'_, LoeMsg>],
    ) -> Vec<Outgoing<LoeMsg>> {
        let out = self.inner.end_round(ctx, round, inbox);
        self.own_only(out)
    }
}

struct LateDisclose {
    disclosure: Disclosure,
    to: NodeId,
}
impl Adversary<LearnOrExpose> for LateDisclose {
    fn act(
        &mut self,
        _: &mut Ctx,
        round: Round,
        _: Vec<(NodeId, LoeMsg)>,
        _: &[HonestSend<'_, LoeMsg>],
    ) -> Vec<Outgoing<LoeMsg>> {
        if round == 1 {
            vec![Outgoing::to(
                self.to,
                LoeMsg::Disclose(self.disclosure.clone()),
            )]
        } else {
            vec![]
        }
    }
}

fn sweep(cases: &[(usize, usize)], seeds: u64) {
    println!(
        "{:>4} {:>4} {:>3} {:>5} {:>2} {:>5} {:>5} {:>7} {:>6} {:>4} {:>9}",
        "n", "t", "f", "seed", "R", "res", "accs", "rejected", "proofB", "exp", "bytesSent"
    );
    for &(n, t) in cases {
        for seed in 0..seeds {
            let s = Scenario::random(n, t, seed).run(seed);
            println!(
                "{:>4} {:>4} {:>3} {:>5} {:>2} {:>5} {:>5} {:>7} {:>6} {:>4} {:>9}",
                s.n,
                s.t,
                s.f,
                s.seed,
                s.rounds,
                s.resolved_round,
                s.accusations,
                s.rejected,
                s.proof_bytes,
                s.exposed,
                s.bytes_sent
            );
        }
    }
}

#[test]
fn learn_or_expose_random_adversaries_small() {
    sweep(&[(4, 2), (6, 3), (8, 4), (8, 6), (10, 9)], 8);
}

#[test]
#[ignore = "full sweep, minutes in release mode"]
fn learn_or_expose_random_adversaries_full() {
    sweep(
        &[
            (8, 4),
            (16, 8),
            (16, 12),
            (20, 18),
            (32, 16),
            (32, 24),
            (40, 36),
            (64, 32),
            (64, 48),
        ],
        25,
    );
}
