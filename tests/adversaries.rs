//! The protocol-specific adversaries against every protocol they attack:
//! honest nodes must decide one vector holding every honest node's input,
//! whatever the Byzantine nodes do.

use polaris::local::{
    IcMachines, IcWxsdMachines, Machines, ParallelDsMachines, ParallelWxsdMachines, ic_input,
};
use polaris::sim::{AdversaryKind, SimSpec, run_sim};
use polaris_core::{NodeId, Params};
use polaris_proto::bb::wxsd::WxsdConfig;
use polaris_proto::compiler::CompilerConfig;

/// Runs `seeds` simulations and checks agreement and validity on the
/// decided vectors, as returned by `values`.
fn check<F: Machines>(
    machines: &F,
    adversary: AdversaryKind,
    n: usize,
    t: usize,
    seeds: std::ops::Range<u64>,
    values: impl Fn(&<F::M as polaris_core::RoundMachine>::Output) -> Vec<Option<Vec<u8>>>,
) where
    <F::M as polaris_core::RoundMachine>::Output: Clone,
{
    for seed in seeds {
        let ctx = format!("{adversary:?} n={n} t={t} seed={seed}");
        let run = run_sim(
            &SimSpec {
                n,
                t,
                byzantine: t,
                adversary,
                max_rounds: 20_000,
                seed,
                run_id: 7,
            },
            machines,
        )
        .unwrap_or_else(|e| panic!("{ctx}: {e}"));
        let outputs: Vec<_> = run
            .outcomes
            .iter()
            .map(|o| {
                values(
                    o.output
                        .as_ref()
                        .unwrap_or_else(|| panic!("{ctx}: undecided")),
                )
            })
            .collect();
        assert!(
            outputs.windows(2).all(|w| w[0] == w[1]),
            "{ctx}: disagreement"
        );
        for i in (0..n as NodeId).filter(|i| !run.byzantine.contains(i)) {
            assert_eq!(
                outputs[0][usize::from(i)].as_deref(),
                Some(ic_input(i, 0).as_slice()),
                "{ctx}: honest entry {i}"
            );
        }
    }
}

fn config(n: usize, t: usize) -> CompilerConfig {
    CompilerConfig::for_params(Params::new(n, t).unwrap())
}

#[test]
fn dolev_strong_adversary() {
    for (n, t) in [(6, 3), (8, 6)] {
        let ic = IcMachines {
            config: config(n, t),
            input_bytes: 0,
        };
        check(&ic, AdversaryKind::DsChaos, n, t, 0..4, |o| {
            o.values.clone()
        });
        let par = ParallelDsMachines { input_bytes: 0 };
        check(&par, AdversaryKind::DsChaos, n, t, 0..4, |o| {
            o.values.clone()
        });
    }
}

#[test]
fn wxsd_adversary() {
    for (n, t) in [(6, 3), (8, 6)] {
        for wxsd in [WxsdConfig::default(), WxsdConfig::default().aggregated()] {
            let ic = IcWxsdMachines {
                config: config(n, t),
                wxsd,
                input_bytes: 0,
            };
            check(&ic, AdversaryKind::WxsdChaos, n, t, 0..5, |o| {
                o.values.clone()
            });
            let seq = IcWxsdMachines {
                config: config(n, t).sequential().sharing_accusations(),
                wxsd,
                input_bytes: 0,
            };
            check(&seq, AdversaryKind::WxsdChaos, n, t, 0..3, |o| {
                o.values.clone()
            });
            let par = ParallelWxsdMachines {
                wxsd,
                input_bytes: 0,
            };
            check(&par, AdversaryKind::WxsdChaos, n, t, 0..3, |o| {
                o.values.clone()
            });
        }
    }
}
