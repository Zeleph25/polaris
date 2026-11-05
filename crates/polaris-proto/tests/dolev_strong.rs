//! The Dolev-Strong broadcast: agreement and validity under scripted and
//! randomized adversaries, including the attack that breaks the naive one.

use std::sync::Arc;

use polaris_core::{Ctx, NodeId, NodeSet, Outgoing, Params, Round};
use polaris_crypto::ed25519::Sig;
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::bb::dolev_strong::{DolevStrong, DsMsg, Link, sign_link};
use polaris_sim::{Adversary, HonestSend, Node, Scripted, Silent, Simulator};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha12Rng;

const RUN: u64 = 13;
const INSTANCE: u64 = 7;

fn setup(n: usize, t: usize) -> (Arc<Keyring>, Vec<Arc<NodeKeys>>) {
    let (kr, keys) = keyring::generate(Params::new(n, t).unwrap(), RUN, 3);
    (Arc::new(kr), keys.into_iter().map(Arc::new).collect())
}

fn bb(
    kr: &Arc<Keyring>,
    keys: &Arc<NodeKeys>,
    sender: NodeId,
    input: Option<&[u8]>,
) -> DolevStrong {
    DolevStrong::new(
        kr.clone(),
        keys.clone(),
        sender,
        INSTANCE,
        input.map(<[u8]>::to_vec),
    )
}

/// A chain signed by `signers`, in order, on `value`.
fn chain(keys: &[Arc<NodeKeys>], signers: &[NodeId], value: &[u8]) -> DsMsg {
    DsMsg {
        value: value.to_vec(),
        chain: signers
            .iter()
            .map(|&s| sign_link(&keys[usize::from(s)], RUN, INSTANCE, value))
            .collect(),
    }
}

fn outputs(sim: &Simulator<DolevStrong>) -> Vec<Option<Option<Vec<u8>>>> {
    sim.outputs().into_iter().map(|o| o.cloned()).collect()
}

fn honest_outputs(sim: &Simulator<DolevStrong>, byzantine: &[NodeId]) -> Vec<Option<Vec<u8>>> {
    outputs(sim)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !byzantine.contains(&(*i as NodeId)))
        .map(|(i, o)| o.unwrap_or_else(|| panic!("node {i} has no output")))
        .collect()
}

#[test]
fn honest_sender_is_delivered_in_t_plus_one_rounds() {
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let nodes = keys
        .iter()
        .map(|k| Node::Honest(bb(&kr, k, 0, (k.id == 0).then_some(b"hello".as_slice()))))
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    assert_eq!(sim.run_until_decided(10).unwrap(), 3, "t + 1 rounds");
    for o in outputs(&sim) {
        assert_eq!(o, Some(Some(b"hello".to_vec())));
    }
    let m = sim.metrics(3).total();
    assert_eq!(
        m.sig_verifies, 1,
        "only the sender's chain is new; forwarded copies are skipped"
    );
    assert_eq!(
        sim.metrics(0).total().sig_verifies,
        0,
        "the sender knows its own value"
    );
}

#[test]
fn single_round_when_t_is_zero() {
    let (kr, keys) = setup(4, 0);
    let nodes = keys
        .iter()
        .map(|k| Node::Honest(bb(&kr, k, 1, (k.id == 1).then_some(b"x".as_slice()))))
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    assert_eq!(sim.run_until_decided(5).unwrap(), 1);
    for o in outputs(&sim) {
        assert_eq!(o, Some(Some(b"x".to_vec())));
    }
}

#[test]
fn silent_sender_gives_bottom() {
    let (kr, keys) = setup(5, 2);
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
    sim.run_until_decided(10).unwrap();
    assert!(honest_outputs(&sim, &[0]).iter().all(Option::is_none));
}

#[test]
fn equivocating_sender_gives_bottom_everywhere() {
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let v1 = chain(&keys, &[0], b"v1");
    let v2 = chain(&keys, &[0], b"v2");
    let at_start: Vec<_> = (1..n as NodeId)
        .map(|j| Outgoing::to(j, if j % 2 == 0 { v1.clone() } else { v2.clone() }))
        .collect();
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
    sim.run_until_decided(10).unwrap();
    assert!(honest_outputs(&sim, &[0]).iter().all(Option::is_none));
}

#[test]
fn the_attack_on_the_naive_broadcast_fails() {
    // Same script as `naive_broadcast_breaks_agreement`: the sender shows v1
    // to node 1 only, and a Byzantine helper shows v2 to node 3 only in the
    // second round, this time with the two-signature chain the round
    // demands. Node 3 forwards v2 in round 3, so everyone sees both values.
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let v1 = chain(&keys, &[0], b"v1");
    let v2 = chain(&keys, &[0, 2], b"v2");
    let nodes = keys
        .iter()
        .map(|k| match k.id {
            0 => Node::Byzantine(Box::new(Scripted::at_start(vec![Outgoing::to(
                1,
                v1.clone(),
            )]))),
            2 => Node::Byzantine(Box::new(Scripted::after_round(
                0,
                vec![Outgoing::to(3, v2.clone())],
            ))),
            _ => Node::Honest(bb(&kr, k, 0, None)),
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    sim.run_until_decided(10).unwrap();
    let outs = honest_outputs(&sim, &[0, 2]);
    assert!(outs.iter().all(Option::is_none), "{outs:?}");
}

#[test]
fn a_chain_of_t_byzantine_signatures_shown_to_one_node_reaches_all() {
    // Nodes 0 and 2 are Byzantine (t = 2). They deliver a valid two-link
    // chain to node 1 only, in round 2. Node 1 forwards it with a third
    // signature in round 3 = t + 1, and everyone decides v.
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let v = chain(&keys, &[0, 2], b"v");
    let nodes = keys
        .iter()
        .map(|k| match k.id {
            0 => Node::Byzantine(Box::new(Silent)),
            2 => Node::Byzantine(Box::new(Scripted::after_round(
                0,
                vec![Outgoing::to(1, v.clone())],
            ))),
            _ => Node::Honest(bb(&kr, k, 0, None)),
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    sim.run_until_decided(10).unwrap();
    for o in honest_outputs(&sim, &[0, 2]) {
        assert_eq!(o, Some(b"v".to_vec()));
    }
}

#[test]
fn a_short_chain_in_the_last_round_is_rejected() {
    // The same two-link chain delivered in round 3 needs three signatures
    // and is ignored, so node 1 agrees with everyone on bottom.
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let v = chain(&keys, &[0, 2], b"v");
    let nodes = keys
        .iter()
        .map(|k| match k.id {
            0 => Node::Byzantine(Box::new(Silent)),
            2 => Node::Byzantine(Box::new(Scripted::after_round(
                1,
                vec![Outgoing::to(1, v.clone())],
            ))),
            _ => Node::Honest(bb(&kr, k, 0, None)),
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    sim.run_until_decided(10).unwrap();
    assert!(honest_outputs(&sim, &[0, 2]).iter().all(Option::is_none));
}

#[test]
fn forged_links_are_rejected() {
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let mut forged_sig = chain(&keys, &[0, 2], b"v");
    forged_sig.chain[1].sig = Sig([7; 64]);
    let mut wrong_signer = chain(&keys, &[0, 2], b"v");
    wrong_signer.chain[1].signer = 4;
    let mut duplicate = chain(&keys, &[0], b"v");
    duplicate.chain.push(duplicate.chain[0].clone());
    let not_from_sender = chain(&keys, &[2, 0], b"v");
    let unknown = DsMsg {
        value: b"v".to_vec(),
        chain: vec![
            Link {
                signer: 0,
                sig: chain(&keys, &[0], b"v").chain[0].sig,
            },
            Link {
                signer: 60000,
                sig: Sig([1; 64]),
            },
        ],
    };
    let msgs = [
        forged_sig,
        wrong_signer,
        duplicate,
        not_from_sender,
        unknown,
    ];
    let nodes = keys
        .iter()
        .map(|k| match k.id {
            0 => Node::Byzantine(Box::new(Silent)),
            2 => Node::Byzantine(Box::new(Scripted::after_round(
                0,
                msgs.iter().map(|m| Outgoing::to(1, m.clone())).collect(),
            ))),
            _ => Node::Honest(bb(&kr, k, 0, None)),
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    sim.run_until_decided(10).unwrap();
    assert!(honest_outputs(&sim, &[0, 2]).iter().all(Option::is_none));
    assert_eq!(
        sim.metrics(1).total().sig_verifies,
        4,
        "only the two well-formed chains (two signatures each) are verified"
    );
}

/// A rushing Byzantine node: it extends every valid-looking chain it sees
/// (its own inbox and what honest nodes are about to send) with its own
/// signature and shows it to a random subset, fabricates chains on fresh
/// values signed only by Byzantine nodes when there are enough of them for
/// the round, and sprinkles forged links.
struct Chaos {
    keys: Arc<NodeKeys>,
    byzantine: Vec<Arc<NodeKeys>>,
    sender: NodeId,
    n: usize,
    rng: ChaCha12Rng,
    first_round: Option<Round>,
}

impl Chaos {
    fn subset(&mut self) -> NodeSet {
        let ids = (0..self.n as NodeId).filter(|_| self.rng.random_bool(0.5));
        NodeSet::from_iter(self.n, ids)
    }

    fn scatter(&mut self, msg: DsMsg) -> Vec<Outgoing<DsMsg>> {
        self.subset()
            .iter()
            .map(|j| Outgoing::to(j, msg.clone()))
            .collect()
    }

    /// A chain of `len` Byzantine signers starting with the sender, if the
    /// sender is Byzantine and there are enough of them.
    fn fabricate(&mut self, len: usize) -> Option<DsMsg> {
        let sender = self.byzantine.iter().find(|k| k.id == self.sender)?.clone();
        let others: Vec<_> = self
            .byzantine
            .iter()
            .filter(|k| k.id != self.sender)
            .cloned()
            .collect();
        if others.len() + 1 < len {
            return None;
        }
        let value = format!("fake-{}", self.rng.random_range(0..4u8)).into_bytes();
        let mut signers = vec![sender];
        signers.extend(others.into_iter().take(len - 1));
        Some(DsMsg {
            chain: signers
                .iter()
                .map(|k| sign_link(k, RUN, INSTANCE, &value))
                .collect(),
            value,
        })
    }
}

impl Adversary<DolevStrong> for Chaos {
    fn start(&mut self, _ctx: &mut Ctx) -> Vec<Outgoing<DsMsg>> {
        if self.keys.id != self.sender {
            return vec![];
        }
        let mut out = Vec::new();
        for _ in 0..3 {
            if let Some(m) = self.fabricate(1) {
                out.extend(self.scatter(m));
            }
        }
        out
    }

    fn act(
        &mut self,
        _ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, DsMsg)>,
        honest_sends: &[HonestSend<'_, DsMsg>],
    ) -> Vec<Outgoing<DsMsg>> {
        let phase = round - *self.first_round.get_or_insert(round) + 1;
        let mut out = Vec::new();
        let mut seen: Vec<DsMsg> = inbox.into_iter().map(|(_, m)| m).collect();
        seen.extend(honest_sends.iter().map(|h| h.msg.msg.clone()));
        for m in seen {
            if m.chain.iter().any(|l| l.signer == self.keys.id) || !self.rng.random_bool(0.6) {
                continue;
            }
            let mut ext = m.clone();
            ext.chain
                .push(sign_link(&self.keys, RUN, INSTANCE, &m.value));
            if self.rng.random_bool(0.2) {
                ext.chain.last_mut().unwrap().sig = Sig([9; 64]);
            }
            out.extend(self.scatter(ext));
        }
        if let Some(m) = self.fabricate(phase as usize + 1) {
            out.extend(self.scatter(m));
        }
        out
    }
}

#[test]
fn random_adversaries_keep_agreement_and_validity() {
    for &(n, t) in &[(4, 1), (6, 2), (8, 3), (8, 5), (10, 7)] {
        for seed in 0..40u64 {
            let (kr, keys) = setup(n, t);
            let mut rng = ChaCha12Rng::seed_from_u64(seed);
            let sender: NodeId = rng.random_range(0..n as NodeId);
            let mut ids: Vec<NodeId> = (0..n as NodeId).collect();
            for i in (1..ids.len()).rev() {
                ids.swap(i, rng.random_range(0..=i));
            }
            let byzantine: Vec<NodeId> = ids[..t].to_vec();
            let byz_keys: Vec<Arc<NodeKeys>> = byzantine
                .iter()
                .map(|&b| keys[usize::from(b)].clone())
                .collect();
            let value = format!("v-{seed}").into_bytes();
            let nodes = keys
                .iter()
                .map(|k| {
                    if byzantine.contains(&k.id) {
                        Node::Byzantine(Box::new(Chaos {
                            keys: k.clone(),
                            byzantine: byz_keys.clone(),
                            sender,
                            n,
                            rng: ChaCha12Rng::seed_from_u64(seed * 1000 + u64::from(k.id)),
                            first_round: None,
                        }))
                    } else {
                        Node::Honest(bb(
                            &kr,
                            k,
                            sender,
                            (k.id == sender).then_some(value.as_slice()),
                        ))
                    }
                })
                .collect();
            let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
            let last = sim
                .run_until_decided(20)
                .unwrap_or_else(|e| panic!("n={n} t={t} seed={seed}: {e}"));
            assert_eq!(
                last,
                t as Round + 1,
                "n={n} t={t} seed={seed}: t + 1 rounds"
            );
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
        }
    }
}
