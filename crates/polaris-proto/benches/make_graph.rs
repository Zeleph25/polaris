//! `MakeGraph` and batched accusation verification at the sizes the
//! experiments use. `cargo bench -p polaris-proto`.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use polaris_core::{NodeId, Params};
use polaris_crypto::keyring;
use polaris_proto::accusations::{Accusation, verify_many};
use polaris_proto::trust_graph::TrustGraph;

/// Worst case for pruning: f = t silent nodes, every honest node accuses every one of them.
fn silent_case(n: usize, t: usize) -> Vec<(NodeId, NodeId)> {
    let mut acc = Vec::new();
    for h in 0..(n - t) as NodeId {
        for b in (n - t) as NodeId..n as NodeId {
            acc.push((h, b));
        }
    }
    acc
}

fn bench_make_graph(c: &mut Criterion) {
    let mut g = c.benchmark_group("make_graph");
    for (n, t) in [(16, 8), (64, 32), (64, 48), (128, 64), (128, 115)] {
        let params = Params::new(n, t).unwrap();
        let acc = silent_case(n, t);
        g.bench_with_input(
            BenchmarkId::from_parameter(format!("n{n}_t{t}")),
            &acc,
            |b, acc| b.iter(|| TrustGraph::make(params, acc.iter().copied())),
        );
    }
    g.finish();
}

fn bench_verify_accusations(c: &mut Criterion) {
    let mut g = c.benchmark_group("verify_accusations");
    for n in [16usize, 64] {
        let params = Params::new(n, n / 2).unwrap();
        let (kr, keys) = keyring::generate(params, 1, 1);
        // Every node accuses one target: one aggregate check instead of n pairings.
        let accs: Vec<Accusation> = keys
            .iter()
            .filter(|k| k.id != 0)
            .map(|k| Accusation::sign(k, kr.run_id, 0))
            .collect();
        g.bench_with_input(BenchmarkId::new("one_target", n), &accs, |b, accs| {
            b.iter(|| verify_many(&kr, accs))
        });
        // Every node accuses a different target: n separate checks.
        let spread: Vec<Accusation> = keys
            .iter()
            .map(|k| Accusation::sign(k, kr.run_id, (k.id + 1) % n as NodeId))
            .collect();
        g.bench_with_input(BenchmarkId::new("spread", n), &spread, |b, accs| {
            b.iter(|| verify_many(&kr, accs))
        });
    }
    g.finish();
}

criterion_group!(benches, bench_make_graph, bench_verify_accusations);
criterion_main!(benches);
