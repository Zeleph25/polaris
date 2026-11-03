//! LearnOrExpose under adversaries.
//!
//! Every scenario checks the same invariants over all honest nodes:
//! - an honest leader (every honest node here) has an output at round R;
//! - every honest entry is present with the right value (no honest node is
//!   ever exposed), Byzantine entries are bottom or the value they signed;
//! - every honest output verifies at every honest verifier (Transferability);
//! - no honest node ever accused an honest node.

use std::sync::Arc;

use polaris_core::{Ctx, NodeId, NodeSet, Outgoing, Params, Round, RoundMachine};
use polaris_crypto::bls;
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::accusations::{Accusation, AccusationProof, AccusationSet};
use polaris_proto::disclosure::{Disclosure, Entries, VerifiableVector};
use polaris_proto::learn_or_expose::{LearnOrExpose, LoeMsg};
use polaris_sim::{Adversary, HonestSend, Node, Silent, Simulator};

const RUN: u64 = 77;

struct World {
    kr: Arc<Keyring>,
    keys: Vec<Arc<NodeKeys>>,
    byzantine: NodeSet,
}

impl World {
    fn new(n: usize, t: usize, byzantine: impl IntoIterator<Item = NodeId>) -> Self {
        let (kr, keys) = keyring::generate(Params::new(n, t).unwrap(), RUN, 3);
        let byzantine = NodeSet::from_iter(n, byzantine);
        assert!(byzantine.count() <= t);
        Self {
            kr: Arc::new(kr),
            keys: keys.into_iter().map(Arc::new).collect(),
            byzantine,
        }
    }

    fn n(&self) -> usize {
        self.kr.n()
    }

    fn honest(&self) -> impl Iterator<Item = NodeId> + '_ {
        (0..self.n() as NodeId).filter(|i| !self.byzantine.contains(*i))
    }

    fn value(j: NodeId) -> Vec<u8> {
        format!("input-{j}").into_bytes()
    }

    fn disclosure(&self, j: NodeId) -> Disclosure {
        Disclosure::sign(&self.keys[usize::from(j)], RUN, Self::value(j))
    }

    /// Round-0 candidates at an honest node: every honest disclosure, plus
    /// the Byzantine ones `reached` says arrived there.
    fn entries(&self, me: NodeId, reached: impl Fn(NodeId, NodeId) -> bool) -> Entries {
        (0..self.n() as NodeId)
            .map(|j| {
                if !self.byzantine.contains(j) || reached(j, me) {
                    Some(self.disclosure(j))
                } else {
                    None
                }
            })
            .collect()
    }

    fn loe(&self, me: NodeId, leader: NodeId, entries: Entries) -> LearnOrExpose {
        LearnOrExpose::new(
            self.kr.clone(),
            self.keys[usize::from(me)].clone(),
            leader,
            entries,
        )
    }

    /// Runs one instance with the given Byzantine behaviors and checks the invariants.
    fn run(
        &self,
        leader: NodeId,
        reached: impl Fn(NodeId, NodeId) -> bool,
        mut adversary: impl FnMut(NodeId) -> Box<dyn Adversary<LearnOrExpose>>,
    ) -> Simulator<LearnOrExpose> {
        let nodes = (0..self.n() as NodeId)
            .map(|i| {
                if self.byzantine.contains(i) {
                    Node::Byzantine(adversary(i))
                } else {
                    Node::Honest(self.loe(i, leader, self.entries(i, &reached)))
                }
            })
            .collect();
        let mut sim = Simulator::new(self.kr.params, RUN, nodes).unwrap();
        let r = self.kr.params.loe_rounds();
        let decided = sim
            .run_until_decided(r + 5)
            .expect("every honest node outputs");
        assert_eq!(decided, r, "outputs appear exactly at the end of round R");
        self.check_invariants(&sim);
        sim
    }

    fn check_invariants(&self, sim: &Simulator<LearnOrExpose>) {
        for i in self.honest() {
            let m = sim.honest(i).unwrap();
            let out = m
                .output()
                .unwrap_or_else(|| panic!("honest node {i} has no output"));
            assert_eq!(out.entries.len(), self.n());
            for j in 0..self.n() as NodeId {
                match &out.entries[usize::from(j)] {
                    Some(d) => {
                        assert_eq!(d.sender, j);
                        assert_eq!(d.value, Self::value(j), "node {i}: wrong value for {j}");
                    }
                    None => assert!(
                        self.byzantine.contains(j),
                        "node {i} exposed honest node {j}"
                    ),
                }
            }
            for v in self.honest() {
                assert!(
                    out.verify(v, &self.kr),
                    "output of {i} rejected by honest verifier {v}"
                );
            }
            for (a, b) in m.accusations().edges() {
                assert!(
                    self.byzantine.contains(a) || self.byzantine.contains(b),
                    "honest {a} accused honest {b} (seen at node {i})"
                );
            }
        }
    }
}

fn output(sim: &Simulator<LearnOrExpose>, i: NodeId) -> &VerifiableVector {
    sim.honest(i).unwrap().output().unwrap()
}

fn silent(_: NodeId) -> Box<dyn Adversary<LearnOrExpose>> {
    Box::new(Silent)
}

// ---------------------------------------------------------------- adversaries

/// Every round, accuses every honest node with valid signatures; discloses nothing.
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

/// Floods invalid accusations: honest accusers impersonated with garbage
/// signatures, and its own signatures attached to the wrong target.
struct FakeFlood {
    keys: Arc<NodeKeys>,
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
        for (k, &h) in self.honest.iter().enumerate() {
            for &target in &self.honest {
                if h != target {
                    let garbage = bls::Sig([(round as u8).wrapping_add(k as u8); bls::SIG_LEN]);
                    out.push(Outgoing::all(LoeMsg::Accuse(Accusation {
                        accuser: h,
                        target,
                        sig: garbage,
                    })));
                }
            }
            let mut relabeled = Accusation::sign(&self.keys, RUN, h);
            relabeled.target = self.honest[(k + 1) % self.honest.len()];
            if relabeled.target != h {
                out.push(Outgoing::all(LoeMsg::Accuse(relabeled)));
            }
        }
        out
    }
}

/// Runs the honest machine but never forwards anything it did not sign itself.
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

/// Silent in round 0 and in the first LoE rounds, then discloses to one node only.
struct LateDiscloser {
    disclosure: Disclosure,
    at_round: Round,
    to: NodeId,
}

impl Adversary<LearnOrExpose> for LateDiscloser {
    fn act(
        &mut self,
        _: &mut Ctx,
        round: Round,
        _: Vec<(NodeId, LoeMsg)>,
        _: &[HonestSend<'_, LoeMsg>],
    ) -> Vec<Outgoing<LoeMsg>> {
        if round + 1 == self.at_round {
            vec![Outgoing::to(
                self.to,
                LoeMsg::Disclose(self.disclosure.clone()),
            )]
        } else {
            vec![]
        }
    }
}

// ---------------------------------------------------------------- scenarios

#[test]
fn all_honest_resolve_at_once_without_accusing() {
    let w = World::new(8, 4, []);
    let sim = w.run(0, |_, _| true, silent);
    for i in w.honest() {
        let m = sim.honest(i).unwrap();
        assert_eq!(m.stats().accusations_sent, 0);
        assert_eq!(m.stats().resolved_round, Some(1));
        assert!(m.accusations().is_empty());
        assert_eq!(output(&sim, i).exposed().count(), 0);
    }
    // Only disclosures were ever sent: n^2 of them per node in round 0, nothing after.
    let m = sim.metrics(0).total();
    assert_eq!(m.msgs_sent, 8 * 8);
}

#[test]
fn silent_byzantine_nodes_are_exposed() {
    let w = World::new(8, 4, [4, 5, 6, 7]);
    let sim = w.run(0, |_, _| false, silent);
    for i in w.honest() {
        let out = output(&sim, i);
        assert_eq!(out.exposed(), w.byzantine);
        let s = sim.honest(i).unwrap().stats();
        assert_eq!(s.exposed, 4);
        assert_eq!(s.learned, 0);
        // Round 1 accuses the four silent neighbors directly; nothing else is ever needed.
        assert_eq!(s.accusations_sent, 4);
        assert_eq!(s.resolved_round, Some(2));
    }
}

#[test]
fn withheld_disclosure_is_learned_by_forwarding() {
    // Byzantine 7 disclosed in round 0 to node 0 only, then stays silent.
    let w = World::new(8, 3, [7]);
    let sim = w.run(2, |j, me| j == 7 && me == 0, silent);
    for i in w.honest() {
        let out = output(&sim, i);
        assert_eq!(
            out.exposed().count(),
            0,
            "node {i}: 7 should be learned, not exposed"
        );
        let s = sim.honest(i).unwrap().stats();
        assert_eq!(
            s.accusations_sent, 0,
            "node {i} accused although 7's disclosure was forwarded in round 1"
        );
        assert_eq!(s.learned, u32::from(i != 0));
    }
}

#[test]
fn late_disclosure_to_one_node() {
    // Byzantine 5 is silent in round 0 and discloses to node 1 only, at the start of LoE round 2.
    let w = World::new(6, 2, [5]);
    let d = w.disclosure(5);
    let sim = w.run(
        0,
        |_, _| false,
        |_| {
            Box::new(LateDiscloser {
                disclosure: d.clone(),
                at_round: 1,
                to: 1,
            })
        },
    );
    // Node 1 learned it; the others had already exposed 5. Both are valid outputs for a Byzantine entry.
    assert!(output(&sim, 1).entries[5].is_some());
    assert_eq!(sim.honest(1).unwrap().stats().learned, 1);
    for i in [0u16, 2, 3, 4] {
        assert!(output(&sim, i).entries[5].is_none(), "node {i}");
    }
}

#[test]
fn accusing_every_honest_node_changes_nothing() {
    let w = World::new(8, 4, [4, 5, 6, 7]);
    let honest: Vec<NodeId> = w.honest().collect();
    let sim = w.run(
        1,
        |_, _| false,
        |i| {
            Box::new(AccuseHonest {
                keys: w.keys[usize::from(i)].clone(),
                honest: honest.clone(),
            })
        },
    );
    for i in w.honest() {
        let out = output(&sim, i);
        assert_eq!(out.exposed(), w.byzantine);
        // The Byzantine accusations are valid and in Acc, so they are in the proof too.
        assert_eq!(
            out.proof.accusers_of(0),
            NodeSet::from_iter(8, [4, 5, 6, 7])
        );
        let g = out.proof.graph(w.kr.params);
        assert!(g.is_clique(&NodeSet::from_iter(8, honest.iter().copied())));
    }
}

#[test]
fn fake_accusations_are_rejected() {
    let w = World::new(7, 3, [4, 5, 6]);
    let honest: Vec<NodeId> = w.honest().collect();
    let sim = w.run(
        3,
        |_, _| false,
        |i| {
            Box::new(FakeFlood {
                keys: w.keys[usize::from(i)].clone(),
                honest: honest.clone(),
            })
        },
    );
    for i in w.honest() {
        let m = sim.honest(i).unwrap();
        assert!(
            m.stats().accusations_rejected > 0,
            "node {i} saw no invalid accusation"
        );
        for (a, b) in m.accusations().edges() {
            assert!(
                w.byzantine.contains(b) && !w.byzantine.contains(a),
                "forged accusation {a} -> {b} accepted"
            );
        }
        assert_eq!(output(&sim, i).exposed(), w.byzantine);
    }
}

#[test]
fn a_node_that_never_forwards_does_not_matter() {
    // Node 6 discloses and accuses honestly but forwards nothing; node 7 is silent.
    let w = World::new(8, 4, [6, 7]);
    let sim = w.run(
        0,
        |j, _| j == 6,
        |i| {
            if i == 6 {
                Box::new(NoForward {
                    inner: w.loe(6, 0, w.entries(6, |j, _| j == 6)),
                    me: 6,
                })
            } else {
                Box::new(Silent)
            }
        },
    );
    for i in w.honest() {
        let out = output(&sim, i);
        assert!(out.entries[6].is_some());
        assert!(out.entries[7].is_none());
    }
}

#[test]
fn byzantine_leader_cannot_get_a_bad_vector_accepted() {
    let w = World::new(8, 4, [4, 5, 6, 7]);
    let sim = w.run(0, |_, _| false, silent);
    let good = output(&sim, 0).clone();
    let honest: Vec<NodeId> = w.honest().collect();
    let rejected_everywhere = |v: &VerifiableVector, what: &str| {
        for &i in &honest {
            assert!(
                !v.verify(i, &w.kr),
                "{what}: accepted by honest verifier {i}"
            );
        }
    };

    // Drop an honest entry: honest nodes stay connected to it, so its bottom is not justified.
    let mut dropped = good.clone();
    dropped.entries[2] = None;
    rejected_everywhere(&dropped, "honest entry dropped");

    // Replace an honest value with another one: the signature no longer matches.
    let mut forged = good.clone();
    forged.entries[1].as_mut().unwrap().value = b"not what node 1 said".to_vec();
    rejected_everywhere(&forged, "honest value replaced");

    // Drop an honest entry and back it with every accusation the adversary can sign.
    let mut acc = AccusationSet::new(8);
    for &b in &w.byzantine.iter().collect::<Vec<_>>() {
        for h in w.honest() {
            acc.insert(&Accusation::sign(&w.keys[usize::from(b)], RUN, h));
        }
    }
    let mut massive = good.clone();
    massive.entries[3] = None;
    massive.proof = acc.aggregate();
    assert!(
        massive.proof.verify(&w.kr),
        "the accusations themselves are valid"
    );
    rejected_everywhere(&massive, "honest entry dropped with t accusers");

    // Signer set extended by a node that never signed (every honest node did accuse 4, so pick 5).
    let mut extended = good.clone();
    assert!(
        extended.proof.per_target[4]
            .as_mut()
            .unwrap()
            .signers
            .insert(5)
    );
    rejected_everywhere(&extended, "forged signer set");
    assert!(good.proof.accusers_of(4) == NodeSet::from_iter(8, honest.iter().copied()));

    // The honest vector itself, and the same vector with an empty proof for a Byzantine bottom: the latter fails.
    assert!(good.verify(2, &w.kr));
    let mut unproven = good.clone();
    unproven.proof = AccusationProof::empty(8);
    rejected_everywhere(&unproven, "bottom without a polarizer");
}

#[test]
fn honest_leader_returns_by_round_r_across_parameters() {
    // f = t Byzantine nodes, silent; honest fractions from 1/2 down to 1/10.
    for (n, t) in [(4, 2), (8, 4), (8, 6), (12, 9), (10, 9), (16, 12), (20, 18)] {
        let byz: Vec<NodeId> = ((n - t) as NodeId..n as NodeId).collect();
        let w = World::new(n, t, byz);
        let sim = w.run(0, |_, _| false, silent);
        let r = w.kr.params.loe_rounds();
        for i in w.honest() {
            let m = sim.honest(i).unwrap();
            assert!(m.stats().resolved_round.unwrap() <= r, "n={n} t={t}");
            assert_eq!(
                output(&sim, i).exposed(),
                w.byzantine,
                "n={n} t={t} node {i}"
            );
        }
    }
}

#[test]
fn proof_size_is_quadratic_plus_linear_kappa() {
    let w = World::new(16, 12, 4..16);
    let sim = w.run(0, |_, _| false, silent);
    let out = output(&sim, 0);
    let bytes = polaris_core::wire::encode(&out.proof).unwrap();
    // 12 exposed targets, each: tag(1) + NodeSet(1 + 1 + 2) + Sig(1 + 48); 4 empty slots: 1 byte each.
    assert!(
        bytes.len() <= 12 * (1 + 4 + 49) + 4 + 2,
        "proof is {} bytes",
        bytes.len()
    );
}
