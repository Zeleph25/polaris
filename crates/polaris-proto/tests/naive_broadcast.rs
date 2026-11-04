//! The naive broadcast: validity holds, agreement provably does not.

use std::collections::BTreeMap;
use std::sync::Arc;

use polaris_core::{Ctx, NodeId, Outgoing, Params, Round};
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::bb::naive::{NaiveBroadcast, NaiveMsg};
use polaris_sim::{Adversary, HonestSend, Node, Silent, Simulator};

const RUN: u64 = 11;
const INSTANCE: u64 = 1;

fn setup(n: usize, t: usize) -> (Arc<Keyring>, Vec<Arc<NodeKeys>>) {
    let (kr, keys) = keyring::generate(Params::new(n, t).unwrap(), RUN, 2);
    (Arc::new(kr), keys.into_iter().map(Arc::new).collect())
}

fn bb(
    kr: &Arc<Keyring>,
    keys: &Arc<NodeKeys>,
    sender: NodeId,
    input: Option<&[u8]>,
) -> NaiveBroadcast {
    NaiveBroadcast::new(
        kr.clone(),
        keys.clone(),
        sender,
        INSTANCE,
        input.map(<[u8]>::to_vec),
    )
}

/// Sends fixed messages at fixed rounds; the simplest Byzantine behavior.
struct Scripted {
    at_start: Vec<Outgoing<NaiveMsg>>,
    after_round: BTreeMap<Round, Vec<Outgoing<NaiveMsg>>>,
}

impl Adversary<NaiveBroadcast> for Scripted {
    fn start(&mut self, _: &mut Ctx) -> Vec<Outgoing<NaiveMsg>> {
        std::mem::take(&mut self.at_start)
    }
    fn act(
        &mut self,
        _: &mut Ctx,
        round: Round,
        _: Vec<(NodeId, NaiveMsg)>,
        _: &[HonestSend<'_, NaiveMsg>],
    ) -> Vec<Outgoing<NaiveMsg>> {
        self.after_round.remove(&round).unwrap_or_default()
    }
}

fn outputs(sim: &Simulator<NaiveBroadcast>) -> Vec<Option<Option<Vec<u8>>>> {
    sim.outputs().into_iter().map(|o| o.cloned()).collect()
}

#[test]
fn honest_sender_is_delivered_by_everyone_in_two_rounds() {
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let nodes = keys
        .iter()
        .map(|k| Node::Honest(bb(&kr, k, 0, (k.id == 0).then_some(b"hello".as_slice()))))
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    assert_eq!(sim.run_until_decided(5).unwrap(), 2);
    for o in outputs(&sim) {
        assert_eq!(o, Some(Some(b"hello".to_vec())));
    }
    let m = sim.metrics(3).total();
    assert_eq!(
        m.sig_verifies, 1,
        "the forwarded copies repeat a value already seen"
    );
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
    sim.run_until_decided(5).unwrap();
    for o in outputs(&sim).into_iter().skip(1) {
        assert_eq!(o, Some(None));
    }
}

#[test]
fn equivocation_seen_by_honest_forwarders_gives_bottom_everywhere() {
    // The sender shows v1 to half the nodes and v2 to the other half; honest
    // forwarding makes everyone see both.
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let sig = |v: &[u8]| sender_signature(&keys[0], v);
    let v1 = NaiveMsg {
        value: b"v1".to_vec(),
        sig: sig(b"v1"),
    };
    let v2 = NaiveMsg {
        value: b"v2".to_vec(),
        sig: sig(b"v2"),
    };
    let at_start: Vec<_> = (1..n as NodeId)
        .map(|j| Outgoing::to(j, if j % 2 == 0 { v1.clone() } else { v2.clone() }))
        .collect();
    let nodes = keys
        .iter()
        .map(|k| {
            if k.id == 0 {
                Node::Byzantine(Box::new(Scripted {
                    at_start: at_start.clone(),
                    after_round: BTreeMap::new(),
                }))
            } else {
                Node::Honest(bb(&kr, k, 0, None))
            }
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    sim.run_until_decided(5).unwrap();
    for o in outputs(&sim).into_iter().skip(1) {
        assert_eq!(o, Some(None));
    }
}

#[test]
fn naive_broadcast_breaks_agreement() {
    // The Byzantine sender shows v1 to node 1 only; node 1 forwards it to all
    // in round 2. A Byzantine helper (node 2) sends v2 to node 3 only, also in
    // round 2. Node 3 sees two values and decides bottom; the others decide v1.
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let sig = |v: &[u8]| sender_signature(&keys[0], v);
    let v1 = NaiveMsg {
        value: b"v1".to_vec(),
        sig: sig(b"v1"),
    };
    let v2 = NaiveMsg {
        value: b"v2".to_vec(),
        sig: sig(b"v2"),
    };
    let nodes = keys
        .iter()
        .map(|k| match k.id {
            0 => Node::Byzantine(Box::new(Scripted {
                at_start: vec![Outgoing::to(1, v1.clone())],
                after_round: BTreeMap::new(),
            })),
            2 => Node::Byzantine(Box::new(Scripted {
                at_start: vec![],
                after_round: BTreeMap::from([(0, vec![Outgoing::to(3, v2.clone())])]),
            })),
            _ => Node::Honest(bb(&kr, k, 0, None)),
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    sim.run_until_decided(5).unwrap();
    let outs = outputs(&sim);
    assert_eq!(outs[1], Some(Some(b"v1".to_vec())));
    assert_eq!(outs[4], Some(Some(b"v1".to_vec())));
    assert_eq!(outs[3], Some(None), "node 3 saw both values");
    assert_ne!(
        outs[1], outs[3],
        "honest nodes disagree: this broadcast is not Byzantine-safe"
    );
}

/// What a Byzantine sender can produce: valid signatures on any values.
fn sender_signature(sender: &NodeKeys, value: &[u8]) -> polaris_crypto::ed25519::Sig {
    let body = [&INSTANCE.to_le_bytes()[..], value].concat();
    polaris_crypto::ed25519::sign(
        &sender.ed25519,
        polaris_crypto::domain::NAIVE_BB,
        RUN,
        &body,
    )
}
