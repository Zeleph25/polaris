//! `polaris sim` with no Byzantine node must report what a network run
//! measures, to the byte: the evaluation mixes the two, network runs for
//! wall-clock time and simulator runs for everything under attack. Over
//! WXSD the compiler keeps sending for one round after its decision, which
//! is where the two once disagreed.

use std::time::Duration;

use polaris::local::{IcWxsdMachines, LocalSpec, ParallelDsMachines, run_local};
use polaris::sim::{AdversaryKind, SimSpec, run_sim};
use polaris_core::Params;
use polaris_proto::bb::wxsd::WxsdConfig;
use polaris_proto::compiler::CompilerConfig;

fn totals<O>(outcomes: &[polaris::runner::Outcome<O>]) -> Vec<(u64, u64, u64, Option<u32>)> {
    let mut v: Vec<_> = outcomes
        .iter()
        .map(|o| {
            let t = o.metrics.total();
            (u64::from(o.me), t.msgs_sent, t.bytes_sent, o.decision_round)
        })
        .collect();
    v.sort_unstable();
    v
}

async fn compare<F>(n: usize, t: usize, machines: &F)
where
    F: polaris::local::Machines,
    <F::M as polaris_core::RoundMachine>::Output: Clone + serde::Serialize + Send + 'static,
{
    let local = run_local(
        &LocalSpec {
            n,
            t,
            round: Duration::from_millis(300),
            max_rounds: 80,
            seed: 3,
            run_id: 1,
        },
        machines,
    )
    .await
    .unwrap();
    let sim = run_sim(
        &SimSpec {
            n,
            t,
            byzantine: 0,
            adversary: AdversaryKind::Silent,
            max_rounds: 80,
            seed: 3,
            run_id: 1,
        },
        machines,
    )
    .unwrap();
    assert_eq!(totals(&sim.outcomes), totals(&local.outcomes));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compiler_over_wxsd() {
    let (n, t) = (8, 2);
    let machines = IcWxsdMachines {
        config: CompilerConfig::for_params(Params::new(n, t).unwrap()),
        wxsd: WxsdConfig::default(),
        input_bytes: 0,
    };
    compare(n, t, &machines).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_dolev_strong() {
    compare(8, 2, &ParallelDsMachines { input_bytes: 0 }).await;
}
