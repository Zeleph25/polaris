//! Cost of the signature operations a node performs per round, at the
//! batch sizes the protocol produces. `cargo bench -p polaris-crypto`.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use polaris_core::{NodeId, Params};
use polaris_crypto::bls::MultiSig;
use polaris_crypto::{domain, ed25519, keyring};

fn bench_ed25519(c: &mut Criterion) {
    let params = Params::new(64, 32).unwrap();
    let (kr, keys) = keyring::generate(params, 1, 1);
    let body = [7u8; 256];
    let sig = ed25519::sign(&keys[0].ed25519, domain::DISCLOSE, 1, &body);
    c.bench_function("ed25519/sign_256B", |b| {
        b.iter(|| ed25519::sign(&keys[0].ed25519, domain::DISCLOSE, 1, &body))
    });
    c.bench_function("ed25519/verify_256B", |b| {
        b.iter(|| ed25519::verify(kr.ed25519(0), domain::DISCLOSE, 1, &body, &sig))
    });
    let mut g = c.benchmark_group("ed25519/batch_verify");
    for n in [8usize, 64] {
        let sigs: Vec<ed25519::Sig> = keys[..n]
            .iter()
            .map(|k| ed25519::sign(&k.ed25519, domain::DISCLOSE, 1, &body))
            .collect();
        let items: Vec<ed25519::Item<'_>> = (0..n)
            .map(|i| ed25519::Item {
                pk: kr.ed25519(i as NodeId),
                tag: domain::DISCLOSE,
                run_id: 1,
                body: &body,
                sig: &sigs[i],
            })
            .collect();
        g.bench_with_input(BenchmarkId::from_parameter(n), &items, |b, items| {
            b.iter(|| ed25519::verify_batch(items))
        });
    }
    g.finish();
}

fn bench_bls(c: &mut Criterion) {
    let params = Params::new(128, 64).unwrap();
    let (kr, keys) = keyring::generate(params, 1, 1);
    let body = [3u8; 2];
    let sig = keys[0].bls.sign(domain::ACCUSE, 1, &body);
    c.bench_function("bls/sign", |b| {
        b.iter(|| keys[0].bls.sign(domain::ACCUSE, 1, &body))
    });
    c.bench_function("bls/verify", |b| {
        b.iter(|| kr.bls(0).verify(domain::ACCUSE, 1, &body, &sig))
    });
    c.bench_function("bls/verify_pop", |b| {
        let pop = keys[0].bls.prove_possession();
        b.iter(|| kr.bls(0).verify_pop(&pop))
    });
    let mut agg = c.benchmark_group("bls/multisig");
    for n in [16usize, 64, 128] {
        let parts: Vec<(NodeId, polaris_crypto::bls::Sig)> = keys[..n]
            .iter()
            .map(|k| (k.id, k.bls.sign(domain::ACCUSE, 1, &body)))
            .collect();
        agg.bench_with_input(BenchmarkId::new("aggregate", n), &parts, |b, parts| {
            b.iter(|| MultiSig::aggregate(params.n, parts.iter().copied()).unwrap())
        });
        let ms = MultiSig::aggregate(params.n, parts.iter().copied()).unwrap();
        agg.bench_with_input(BenchmarkId::new("verify", n), &ms, |b, ms| {
            b.iter(|| ms.verify(kr.bls_keys(), domain::ACCUSE, 1, &body))
        });
    }
    agg.finish();
    c.bench_function("keyring/load_n128", |b| {
        let text = kr.to_toml().unwrap();
        b.iter(|| keyring::Keyring::from_toml(&text).unwrap())
    });
}

criterion_group!(benches, bench_ed25519, bench_bls);
criterion_main!(benches);
