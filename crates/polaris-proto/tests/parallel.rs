//! The baselines: n parallel Dolev-Strong and n parallel WXSD give
//! Interactive Consistency too, at the predicted rounds, under the same
//! omission adversaries as the compiler.

use std::sync::Arc;

use polaris_core::{NodeId, NodeSet, Params, Round, RoundMachine};
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::bb::Broadcast;
use polaris_proto::bb::dolev_strong::DolevStrong;
use polaris_proto::bb::wxsd::{Wxsd, WxsdConfig};
use polaris_proto::parallel::{ParOutput, Parallel};
use polaris_sim::{Node, Selective, Silent, Simulator};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha12Rng;

const RUN: u64 = 23;

fn setup(n: usize, t: usize, seed: u64) -> (Arc<Keyring>, Vec<Arc<NodeKeys>>) {
    let (kr, keys) = keyring::generate(Params::new(n, t).unwrap(), RUN, seed);
    (Arc::new(kr), keys.into_iter().map(Arc::new).collect())
}

fn input(id: NodeId) -> Vec<u8> {
    format!("input-{id}").into_bytes()
}

fn ds(kr: &Arc<Keyring>, keys: &Arc<NodeKeys>) -> Parallel<DolevStrong> {
    Parallel::with_dolev_strong(kr.clone(), keys.clone(), input(keys.id))
}

fn wxsd(kr: &Arc<Keyring>, keys: &Arc<NodeKeys>) -> Parallel<Wxsd> {
    Parallel::with_wxsd(
        kr.clone(),
        keys.clone(),
        WxsdConfig::default(),
        input(keys.id),
    )
}

/// Agreement on the whole vector, validity for every honest entry.
fn check<B: Broadcast>(sim: &Simulator<Parallel<B>>, byzantine: &[NodeId], n: usize) -> ParOutput {
    let outs: Vec<ParOutput> = sim
        .outputs()
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !byzantine.contains(&(*i as NodeId)))
        .map(|(i, o)| {
            o.cloned()
                .unwrap_or_else(|| panic!("node {i} has no output"))
        })
        .collect();
    for o in &outs {
        assert_eq!(o, &outs[0], "honest nodes disagree");
    }
    for j in 0..n as NodeId {
        if !byzantine.contains(&j) {
            assert_eq!(
                outs[0].values[usize::from(j)],
                Some(input(j)),
                "entry of honest {j}"
            );
        }
    }
    outs[0].clone()
}

fn decision_rounds<M: RoundMachine>(sim: &Simulator<M>, byzantine: &[NodeId]) -> Vec<Round> {
    (0..sim.params().n as NodeId)
        .filter(|i| !byzantine.contains(i))
        .map(|i| sim.metrics(i).decision_round().expect("decided"))
        .collect()
}

#[test]
fn parallel_dolev_strong_all_honest() {
    let (n, t) = (6, 2);
    let (kr, keys) = setup(n, t, 1);
    let nodes = keys.iter().map(|k| Node::Honest(ds(&kr, k))).collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    assert_eq!(sim.run_until_decided(50).unwrap(), t as Round + 1);
    check(&sim, &[], n);
    for i in 0..n as NodeId {
        assert_eq!(sim.metrics(i).decision_round(), Some(t as Round));
        assert!(sim.honest(i).unwrap().is_halted());
    }
}

#[test]
fn parallel_wxsd_all_honest() {
    let (n, t) = (6, 2);
    let (kr, keys) = setup(n, t, 1);
    let nodes = keys.iter().map(|k| Node::Honest(wxsd(&kr, k))).collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    // Every instance terminates in the first Commit round of its epoch 1.
    let last = 2 * (kr.params.diameter_bound() + 1);
    assert_eq!(sim.run_until_decided(100).unwrap(), last + 1);
    check(&sim, &[], n);
    for i in 0..n as NodeId {
        assert_eq!(sim.metrics(i).decision_round(), Some(last));
    }
}

fn random_cases<B, F>(make: F, cases: &[(usize, usize)], seeds: u64)
where
    B: Broadcast + Send + 'static,
    F: Fn(&Arc<Keyring>, &Arc<NodeKeys>) -> Parallel<B>,
{
    for &(n, t) in cases {
        for seed in 0..seeds {
            let (kr, keys) = setup(n, t, seed);
            let mut rng = ChaCha12Rng::seed_from_u64(seed * 7 + n as u64);
            let mut ids: Vec<NodeId> = (0..n as NodeId).collect();
            for i in (1..ids.len()).rev() {
                ids.swap(i, rng.random_range(0..=i));
            }
            let byzantine: Vec<NodeId> = ids[..t].to_vec();
            let nodes = keys
                .iter()
                .map(|k| {
                    if !byzantine.contains(&k.id) {
                        Node::Honest(make(&kr, k))
                    } else if rng.random_bool(0.3) {
                        Node::Byzantine(Box::new(Silent))
                    } else {
                        let subset = NodeSet::from_iter(
                            n,
                            (0..n as NodeId).filter(|_| rng.random_bool(0.5)),
                        );
                        Node::Byzantine(Box::new(Selective::new(make(&kr, k), subset)))
                    }
                })
                .collect();
            let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
            sim.run_until_decided(20_000)
                .unwrap_or_else(|e| panic!("n={n} t={t} seed={seed}: {e}"));
            check(&sim, &byzantine, n);
            let rounds = decision_rounds(&sim, &byzantine);
            let (lo, hi) = (rounds.iter().min().unwrap(), rounds.iter().max().unwrap());
            assert!(hi - lo <= 1, "n={n} t={t} seed={seed}: skew {rounds:?}");
        }
    }
}

#[test]
fn parallel_dolev_strong_random_adversaries() {
    random_cases(ds, &[(4, 1), (6, 2), (8, 4), (8, 6), (10, 8)], 20);
}

#[test]
fn parallel_wxsd_random_adversaries() {
    random_cases(wxsd, &[(4, 1), (6, 2), (8, 4), (8, 6)], 10);
}
