//! The WXSD broadcast: agreement and validity under silent, equivocating,
//! selective and forging adversaries, and the epoch structure.

use std::sync::Arc;

use polaris_core::{Ctx, NodeId, NodeSet, Outgoing, Params, Round, RoundMachine};
use polaris_crypto::bls::MultiSig;
use polaris_crypto::domain;
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::accusations::Accusation;
use polaris_proto::bb::wxsd::{
    Ballot, Commit, Evidence, Proposal, Signed, Vote, VoteProof, Wxsd, WxsdConfig, WxsdMsg, sign,
    sign_vote_bls, value_digest,
};
use polaris_sim::{Adversary, HonestSend, Node, Scripted, Selective, Silent, Simulator};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha12Rng;

const RUN: u64 = 19;
const INSTANCE: u64 = 3;

fn setup(n: usize, t: usize, seed: u64) -> (Arc<Keyring>, Vec<Arc<NodeKeys>>) {
    let (kr, keys) = keyring::generate(Params::new(n, t).unwrap(), RUN, seed);
    (Arc::new(kr), keys.into_iter().map(Arc::new).collect())
}

thread_local! {
    /// Every test runs twice, with the paper's evidence and with aggregated
    /// evidence; `both` flips this between the runs.
    static AGGREGATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn config() -> WxsdConfig {
    WxsdConfig {
        aggregate_votes: AGGREGATE.with(|a| a.get()),
        ..WxsdConfig::default()
    }
}

fn both(test: impl Fn()) {
    for aggregate in [false, true] {
        AGGREGATE.with(|a| a.set(aggregate));
        test();
    }
}

fn bb(kr: &Arc<Keyring>, keys: &Arc<NodeKeys>, sender: NodeId, input: Option<&[u8]>) -> Wxsd {
    Wxsd::new(
        kr.clone(),
        keys.clone(),
        sender,
        INSTANCE,
        input.map(<[u8]>::to_vec),
        config(),
    )
}

/// A vote as the current mode signs it.
fn vote(keys: &Arc<NodeKeys>, body: Vote) -> Signed<Vote> {
    if AGGREGATE.with(|a| a.get()) {
        sign_vote_bls(keys, RUN, INSTANCE, body)
    } else {
        sign(keys, RUN, INSTANCE, domain::WXSD_VOTE, body)
    }
}

/// Evidence as the current mode builds it from these votes.
fn evidence(
    epoch: u32,
    digest: polaris_crypto::hash::Digest,
    votes: Vec<Signed<Vote>>,
    n: usize,
) -> Evidence {
    let proof = if AGGREGATE.with(|a| a.get()) {
        VoteProof::Aggregate(
            MultiSig::aggregate(n, votes.iter().map(|v| (v.from, v.bls.unwrap()))).unwrap(),
        )
    } else {
        VoteProof::Individual(votes)
    };
    Evidence {
        epoch,
        digest,
        proof,
    }
}

fn phase_len(kr: &Keyring) -> Round {
    kr.params.diameter_bound() + 1
}

fn outputs(sim: &Simulator<Wxsd>) -> Vec<Option<Option<Vec<u8>>>> {
    sim.outputs().into_iter().map(|o| o.cloned()).collect()
}

fn honest_outputs(sim: &Simulator<Wxsd>, byzantine: &[NodeId]) -> Vec<Option<Vec<u8>>> {
    outputs(sim)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !byzantine.contains(&(*i as NodeId)))
        .map(|(i, o)| o.unwrap_or_else(|| panic!("node {i} has no output")))
        .collect()
}

fn first_honest_leader(sim: &Simulator<Wxsd>, honest: NodeId, byzantine: &[NodeId]) -> u32 {
    let m = sim.honest(honest).unwrap();
    (1..).find(|&e| !byzantine.contains(&m.leader(e))).unwrap()
}

fn decision_rounds(sim: &Simulator<Wxsd>, byzantine: &[NodeId]) -> Vec<Round> {
    (0..sim.params().n as NodeId)
        .filter(|i| !byzantine.contains(i))
        .map(|i| sim.metrics(i).decision_round().expect("decided"))
        .collect()
}

#[test]
fn honest_sender_decides_in_the_first_epoch() {
    both(|| {
        let (n, t) = (6, 2);
        let (kr, keys) = setup(n, t, 1);
        let nodes = keys
            .iter()
            .map(|k| Node::Honest(bb(&kr, k, 0, (k.id == 0).then_some(b"hello".as_slice()))))
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        let l = phase_len(&kr);
        // Propose and Vote take a phase each; everyone's commit arrives in the
        // first Commit round, which is the termination round.
        assert_eq!(sim.run_until_decided(100).unwrap(), 2 * l + 1);
        for o in outputs(&sim) {
            assert_eq!(o, Some(Some(b"hello".to_vec())));
        }
        for i in 0..n as NodeId {
            let s = sim.honest(i).unwrap().stats();
            assert_eq!(s.committed_in, Some(1));
            assert_eq!(s.accusations_sent, 0);
            assert_eq!(s.epochs, 1);
        }
    });
}

#[test]
fn silent_sender_gives_bottom_at_the_first_honest_leader() {
    both(|| {
        let (n, t) = (6, 2);
        let (kr, keys) = setup(n, t, 2);
        let byzantine = [0];
        let nodes = keys
            .iter()
            .map(|k| {
                if k.id == 0 {
                    Node::Byzantine(Box::new(Silent))
                } else {
                    Node::Honest(bb(&kr, k, 0, None))
                }
            })
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        sim.run_until_decided(2000).unwrap();
        assert!(honest_outputs(&sim, &byzantine).iter().all(Option::is_none));
        let epoch = first_honest_leader(&sim, 1, &byzantine);
        for i in 1..n as NodeId {
            let m = sim.honest(i).unwrap();
            assert_eq!(m.stats().committed_in, Some(epoch), "node {i}");
            assert!(
                !m.trusted().contains(0),
                "the silent sender is out of node {i}'s graph"
            );
        }
        let rounds = decision_rounds(&sim, &byzantine);
        assert!(rounds.iter().all(|r| *r == rounds[0]), "{rounds:?}");
    });
}

/// A Byzantine sender's two proposals, one for each half of the nodes.
fn split_proposals(keys: &Arc<NodeKeys>, n: usize, a: &[u8], b: &[u8]) -> Vec<Outgoing<WxsdMsg>> {
    let prop = |v: &[u8]| {
        WxsdMsg::Propose(sign(
            keys,
            RUN,
            INSTANCE,
            domain::WXSD_PROPOSE,
            Proposal {
                epoch: 1,
                value: Some(v.to_vec()),
                evidence: None,
            },
        ))
    };
    let (pa, pb) = (prop(a), prop(b));
    (0..n as NodeId)
        .map(|j| Outgoing::to(j, if j % 2 == 0 { pa.clone() } else { pb.clone() }))
        .collect()
}

#[test]
fn equivocating_sender_is_removed_and_bottom_is_decided() {
    both(|| {
        let (n, t) = (6, 2);
        let (kr, keys) = setup(n, t, 3);
        let byzantine = [0];
        let at_start = split_proposals(&keys[0], n, b"a", b"b");
        let nodes = keys
            .iter()
            .map(|k| {
                if k.id == 0 {
                    Node::Byzantine(Box::new(Scripted::at_start(at_start.clone())))
                } else {
                    Node::Honest(bb(&kr, k, 0, None))
                }
            })
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        sim.run_until_decided(2000).unwrap();
        assert!(honest_outputs(&sim, &byzantine).iter().all(Option::is_none));
        for i in 1..n as NodeId {
            let m = sim.honest(i).unwrap();
            assert!(
                m.stats().equivocations_found >= 1,
                "node {i} saw the equivocation"
            );
            assert!(!m.trusted().contains(0));
        }
    });
}

/// Runs the honest sender, except that at the start it accuses node
/// `victim` and withholds its proposal from it. The victim loses its edge
/// to the sender but keeps the sender in its graph, so it must get the
/// proposal forwarded by the others in round 2.
struct AccusingSender {
    inner: Wxsd,
    keys: Arc<NodeKeys>,
    victim: NodeId,
    n: usize,
}

impl Adversary<Wxsd> for AccusingSender {
    fn start(&mut self, ctx: &mut Ctx) -> Vec<Outgoing<WxsdMsg>> {
        let mut out: Vec<Outgoing<WxsdMsg>> = self
            .inner
            .start(ctx)
            .into_iter()
            .flat_map(|o| {
                (0..self.n as NodeId)
                    .filter(|&j| j != self.victim)
                    .map(|j| Outgoing::to(j, o.msg.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        out.push(Outgoing::all(WxsdMsg::Accuse(Accusation::sign(
            &self.keys,
            RUN,
            self.victim,
        ))));
        out
    }

    fn act(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, WxsdMsg)>,
        _: &[HonestSend<'_, WxsdMsg>],
    ) -> Vec<Outgoing<WxsdMsg>> {
        self.inner.end_round(ctx, round, inbox)
    }
}

#[test]
fn a_proposal_withheld_from_one_node_reaches_it_by_forwarding() {
    both(|| {
        let (n, t) = (6, 2);
        let (kr, keys) = setup(n, t, 4);
        let victim = 2;
        let nodes = keys
            .iter()
            .map(|k| {
                if k.id == 0 {
                    Node::Byzantine(Box::new(AccusingSender {
                        inner: bb(&kr, k, 0, Some(b"v")),
                        keys: k.clone(),
                        victim,
                        n,
                    }))
                } else {
                    Node::Honest(bb(&kr, k, 0, None))
                }
            })
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        sim.run_until_decided(2000).unwrap();
        for o in honest_outputs(&sim, &[0]) {
            assert_eq!(o, Some(b"v".to_vec()));
        }
        for i in 1..n as NodeId {
            let m = sim.honest(i).unwrap();
            assert_eq!(m.stats().committed_in, Some(1), "node {i}");
            assert!(
                m.trusted().contains(0),
                "the sender stays in node {i}'s graph"
            );
            assert_eq!(
                m.stats().accusations_sent,
                0,
                "node {i} had no reason to distrust anyone"
            );
        }
    });
}

/// A Byzantine leader of epoch 2 (the sender of epoch 1 stays silent) that
/// proposes a value with fabricated evidence: votes from Byzantine nodes
/// only. Honest nodes must reject it.
struct FakeEvidenceLeader {
    keys: Arc<NodeKeys>,
    helpers: Vec<Arc<NodeKeys>>,
    epoch_len: Round,
    n: usize,
}

impl Adversary<Wxsd> for FakeEvidenceLeader {
    fn act(
        &mut self,
        _: &mut Ctx,
        round: Round,
        _: Vec<(NodeId, WxsdMsg)>,
        _: &[HonestSend<'_, WxsdMsg>],
    ) -> Vec<Outgoing<WxsdMsg>> {
        if round + 1 != self.epoch_len {
            return vec![];
        }
        let value = Some(b"forged".to_vec());
        let digest = value_digest(INSTANCE, &value);
        let votes = self
            .helpers
            .iter()
            .map(|k| {
                vote(
                    k,
                    Vote {
                        epoch: 1,
                        ballot: Ballot::For(digest),
                    },
                )
            })
            .collect();
        let evidence = evidence(1, digest, votes, self.n);
        vec![Outgoing::all(WxsdMsg::Propose(sign(
            &self.keys,
            RUN,
            INSTANCE,
            domain::WXSD_PROPOSE,
            Proposal {
                epoch: 2,
                value,
                evidence: Some(evidence),
            },
        )))]
    }
}

#[test]
fn fabricated_evidence_is_rejected() {
    both(|| {
        let (n, t) = (6, 2);
        // A keyring whose epoch-2 leader is not the sender.
        let (kr, keys) = (1..)
            .map(|seed| setup(n, t, seed))
            .find(|(kr, keys)| bb(kr, &keys[0], 0, None).leader(2) != 0)
            .unwrap();
        let l2 = bb(&kr, &keys[0], 0, None).leader(2);
        let byzantine = [0, l2];
        let epoch_len = 3 * phase_len(&kr);
        let nodes = keys
            .iter()
            .map(|k| {
                if k.id == 0 {
                    Node::Byzantine(Box::new(Silent))
                } else if k.id == l2 {
                    Node::Byzantine(Box::new(FakeEvidenceLeader {
                        keys: k.clone(),
                        helpers: vec![keys[0].clone(), k.clone()],
                        epoch_len,
                        n,
                    }))
                } else {
                    Node::Honest(bb(&kr, k, 0, None))
                }
            })
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        sim.run_until_decided(5000).unwrap();
        let outs = honest_outputs(&sim, &byzantine);
        assert!(outs.iter().all(Option::is_none), "{outs:?}");
        let honest = (0..n as NodeId).find(|i| !byzantine.contains(i)).unwrap();
        let m = sim.honest(honest).unwrap();
        assert!(
            m.stats().committed_in.unwrap() > 2,
            "epochs 1 and 2 had Byzantine leaders"
        );
        assert!(
            !m.trusted().contains(l2),
            "the forging leader was distrusted"
        );
    });
}

/// Runs the honest protocol but replaces its own commit with one whose
/// evidence lacks the honest votes.
struct ForgingCommitter {
    inner: Wxsd,
    me: NodeId,
    fake: WxsdMsg,
}

impl Adversary<Wxsd> for ForgingCommitter {
    fn act(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, WxsdMsg)>,
        _: &[HonestSend<'_, WxsdMsg>],
    ) -> Vec<Outgoing<WxsdMsg>> {
        self.inner
            .end_round(ctx, round, inbox)
            .into_iter()
            .map(|o| match &o.msg {
                WxsdMsg::Commit(c) if c.from == self.me => Outgoing {
                    to: o.to,
                    msg: self.fake.clone(),
                },
                _ => o,
            })
            .collect()
    }
}

#[test]
fn forged_commits_do_not_terminate_anyone() {
    both(|| {
        // Byzantine node 2 votes honestly but commits with evidence missing the
        // honest votes: everyone else rejects it, distrusts node 2 during the
        // Commit TrustCast, and still decides the sender's value in epoch 1.
        let (n, t) = (6, 2);
        let (kr, keys) = setup(n, t, 5);
        let value = Some(b"v".to_vec());
        let digest = value_digest(INSTANCE, &value);
        let fake = WxsdMsg::Commit(sign(
            &keys[2],
            RUN,
            INSTANCE,
            domain::WXSD_COMMIT,
            Commit {
                epoch: 1,
                evidence: Some(evidence(
                    1,
                    digest,
                    vec![vote(
                        &keys[2],
                        Vote {
                            epoch: 1,
                            ballot: Ballot::For(digest),
                        },
                    )],
                    n,
                )),
            },
        ));
        let nodes = keys
            .iter()
            .map(|k| {
                if k.id == 2 {
                    Node::Byzantine(Box::new(ForgingCommitter {
                        inner: bb(&kr, k, 0, None),
                        me: 2,
                        fake: fake.clone(),
                    }))
                } else {
                    Node::Honest(bb(&kr, k, 0, (k.id == 0).then_some(b"v".as_slice())))
                }
            })
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        sim.run_until_decided(2000).unwrap();
        for o in honest_outputs(&sim, &[2]) {
            assert_eq!(o, Some(b"v".to_vec()));
        }
        for i in [0, 1, 3, 4, 5] {
            let m = sim.honest(i).unwrap();
            assert_eq!(m.stats().committed_in, Some(1));
            assert!(!m.trusted().contains(2), "node {i} distrusts the forger");
        }
    });
}

#[test]
fn random_adversaries_keep_agreement_validity_and_simultaneity() {
    both(|| {
        for &(n, t) in &[(4, 1), (6, 2), (8, 4), (8, 6), (10, 8)] {
            for seed in 0..20u64 {
                let (kr, keys) = setup(n, t, seed);
                let mut rng = ChaCha12Rng::seed_from_u64(seed * 31 + n as u64);
                let sender: NodeId = rng.random_range(0..n as NodeId);
                let mut ids: Vec<NodeId> = (0..n as NodeId).collect();
                for i in (1..ids.len()).rev() {
                    ids.swap(i, rng.random_range(0..=i));
                }
                let byzantine: Vec<NodeId> = ids[..t].to_vec();
                let value = format!("v-{seed}").into_bytes();
                let nodes = keys
                    .iter()
                    .map(|k| {
                        let input = (k.id == sender).then_some(value.as_slice());
                        if !byzantine.contains(&k.id) {
                            Node::Honest(bb(&kr, k, sender, input))
                        } else if rng.random_bool(0.3) {
                            Node::Byzantine(Box::new(Silent))
                        } else {
                            let subset = NodeSet::from_iter(
                                n,
                                (0..n as NodeId).filter(|_| rng.random_bool(0.5)),
                            );
                            Node::Byzantine(Box::new(Selective::new(
                                bb(&kr, k, sender, input),
                                subset,
                            )))
                        }
                    })
                    .collect();
                let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
                sim.run_until_decided(20_000)
                    .unwrap_or_else(|e| panic!("n={n} t={t} seed={seed}: {e}"));
                let outs = honest_outputs(&sim, &byzantine);
                assert!(
                    outs.windows(2).all(|w| w[0] == w[1]),
                    "n={n} t={t} seed={seed} sender={sender} byzantine={byzantine:?}: {outs:?}"
                );
                if !byzantine.contains(&sender) {
                    assert_eq!(
                        outs[0],
                        Some(value.clone()),
                        "n={n} t={t} seed={seed}: validity"
                    );
                }
                let rounds = decision_rounds(&sim, &byzantine);
                let (lo, hi) = (rounds.iter().min().unwrap(), rounds.iter().max().unwrap());
                assert!(
                    hi - lo <= 1,
                    "n={n} t={t} seed={seed}: termination skew {rounds:?}"
                );
                let honest = (0..n as NodeId).find(|i| !byzantine.contains(i)).unwrap();
                let bound = first_honest_leader(&sim, honest, &byzantine);
                let committed = sim.honest(honest).unwrap().stats().committed_in.unwrap();
                assert!(
                    committed <= bound,
                    "n={n} t={t} seed={seed}: committed in epoch {committed}, honest leader in {bound}"
                );
            }
        }
    });
}
