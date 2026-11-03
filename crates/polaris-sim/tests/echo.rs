//! The simulator on the signed echo protocol.

use std::sync::Arc;

use polaris_core::{NodeId, NodeSet, Params};
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::echo::{Echo, EchoOutput};
use polaris_sim::{Node, Selective, Silent, Simulator};

const RUN: u64 = 42;

fn value(i: NodeId) -> Vec<u8> {
    format!("value-of-{i}").into_bytes()
}

fn setup(n: usize, t: usize) -> (Arc<Keyring>, Vec<NodeKeys>) {
    let params = Params::new(n, t).unwrap();
    let (kr, keys) = keyring::generate(params, RUN, 1);
    (Arc::new(kr), keys)
}

fn echo(kr: &Arc<Keyring>, keys: &NodeKeys) -> Echo {
    Echo::new(kr.clone(), Arc::new(keys.ed25519.clone()), value(keys.id))
}

fn all_honest(n: usize) -> Simulator<Echo> {
    let (kr, keys) = setup(n, 0);
    let nodes = keys.iter().map(|k| Node::Honest(echo(&kr, k))).collect();
    Simulator::new(kr.params, RUN, nodes).unwrap()
}

fn outputs(sim: &Simulator<Echo>) -> Vec<Option<EchoOutput>> {
    sim.outputs().into_iter().map(|o| o.cloned()).collect()
}

#[test]
fn all_honest_agree_after_two_rounds() {
    let n = 8;
    let mut sim = all_honest(n);
    let decided = sim.run_until_decided(10).unwrap();
    assert_eq!(decided, 2, "echo decides at the end of round 1");
    let outs = outputs(&sim);
    let first = outs[0].clone().unwrap();
    for (i, o) in outs.iter().enumerate() {
        let o = o.as_ref().unwrap();
        assert_eq!(o, &first, "node {i} differs");
        assert_eq!(o.agreeing, NodeSet::full(n));
    }
    for j in 0..n {
        assert_eq!(
            first.values[j].as_deref(),
            Some(value(j as NodeId).as_slice())
        );
    }
    // Every node sent n messages in each of the two rounds and received as many.
    let m = sim.metrics(3).total();
    assert_eq!(m.msgs_sent, 2 * n as u64);
    assert_eq!(m.msgs_recv, 2 * n as u64);
    assert_eq!(m.sig_verifies, 2 * n as u64);
    assert_eq!(sim.metrics(3).decision_round(), Some(1));
    assert_eq!(sim.transcript().len(), 2 * n * n);
}

#[test]
fn same_inputs_same_transcript() {
    let mut a = all_honest(6);
    let mut b = all_honest(6);
    a.run_until_decided(10).unwrap();
    b.run_until_decided(10).unwrap();
    assert_eq!(a.transcript().fingerprint(), b.transcript().fingerprint());
    assert_eq!(
        a.transcript().inbox_fingerprints(),
        b.transcript().inbox_fingerprints()
    );

    // A different run id changes every signature, hence the transcript.
    let (kr, keys) = setup(6, 0);
    let nodes = keys.iter().map(|k| Node::Honest(echo(&kr, k))).collect();
    let mut c = Simulator::new(kr.params, RUN + 1, nodes).unwrap();
    c.run_until_decided(10).unwrap();
    assert_ne!(a.transcript().fingerprint(), c.transcript().fingerprint());
}

#[test]
fn silent_node_is_missing_everywhere() {
    let n = 5;
    let (kr, keys) = setup(n, 2);
    let nodes = keys
        .iter()
        .map(|k| {
            if k.id == 3 {
                Node::Byzantine(Box::new(Silent))
            } else {
                Node::Honest(echo(&kr, k))
            }
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    sim.run_until_decided(10).unwrap();
    for (i, o) in outputs(&sim).into_iter().enumerate() {
        if i == 3 {
            assert!(o.is_none());
            continue;
        }
        let o = o.unwrap();
        assert!(o.values[3].is_none());
        assert_eq!(o.values.iter().filter(|v| v.is_some()).count(), n - 1);
        assert_eq!(o.agreeing, NodeSet::from_iter(n, [0, 1, 2, 4]));
    }
}

#[test]
fn selective_delivery_splits_the_agreeing_set() {
    let n = 6;
    let (kr, keys) = setup(n, 2);
    let nodes = keys
        .iter()
        .map(|k| {
            if k.id == 2 {
                Node::Byzantine(Box::new(Selective::new(
                    echo(&kr, k),
                    NodeSet::from_iter(n, [0, 1, 2]),
                )))
            } else {
                Node::Honest(echo(&kr, k))
            }
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    sim.run_until_decided(10).unwrap();
    let outs = outputs(&sim);
    for i in [0usize, 1] {
        let o = outs[i].as_ref().unwrap();
        assert_eq!(o.values[2].as_deref(), Some(value(2).as_slice()));
        assert_eq!(o.agreeing, NodeSet::from_iter(n, [0, 1, 2]), "node {i}");
    }
    for i in [3usize, 4, 5] {
        let o = outs[i].as_ref().unwrap();
        assert!(o.values[2].is_none());
        assert_eq!(o.agreeing, NodeSet::from_iter(n, [3, 4, 5]), "node {i}");
    }
}

#[test]
fn too_many_byzantine_is_rejected() {
    let (kr, keys) = setup(4, 1);
    let nodes = keys
        .iter()
        .map(|k| {
            if k.id < 2 {
                Node::Byzantine(Box::new(Silent))
            } else {
                Node::Honest(echo(&kr, k))
            }
        })
        .collect();
    assert!(Simulator::<Echo>::new(kr.params, RUN, nodes).is_err());
}
