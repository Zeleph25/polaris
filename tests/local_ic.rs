//! Interactive Consistency over TCP at n = 8 with t = 2 (all nodes honest):
//! every node decides the same vector of all inputs in view 1, at the round
//! the simulator predicts, with the same per-round inboxes.

use std::time::Duration;

use polaris::local::{IcMachines, LocalSpec, compare_with_simulator, ic_input, run_local};
use polaris_core::{NodeId, Params};
use polaris_proto::compiler::CompilerConfig;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ic_cluster_matches_the_simulator() {
    let (n, t) = (8, 2);
    let params = Params::new(n, t).unwrap();
    let spec = LocalSpec {
        n,
        t,
        round: Duration::from_millis(300),
        max_rounds: 60,
        seed: 4,
        run_id: 10,
    };
    let machines = IcMachines {
        config: CompilerConfig::for_params(params),
        input_bytes: 0,
    };
    let result = run_local(&spec, &machines).await.unwrap();

    let last = params.loe_rounds() + t as u32 + 1;
    let first = result.outcomes[0].output.clone().unwrap();
    assert_eq!(first.view, 1);
    for o in &result.outcomes {
        assert_eq!(o.output.as_ref(), Some(&first), "node {} differs", o.me);
        assert_eq!(o.decision_round, Some(last), "node {}", o.me);
        assert_eq!(o.metrics.total().late_msgs, 0, "node {}", o.me);
    }
    for j in 0..n as NodeId {
        assert_eq!(first.values[usize::from(j)], Some(ic_input(j, 0)));
    }
    let mismatches = compare_with_simulator(&result, &machines, spec.max_rounds).unwrap();
    assert!(mismatches.is_empty(), "inboxes differ: {mismatches:?}");

    let dir = std::env::temp_dir().join(format!("polaris-local-ic-{}", std::process::id()));
    for o in &result.outcomes {
        o.write_to(&dir).unwrap();
    }
    let output = std::fs::read_to_string(dir.join("node-3.output.json")).unwrap();
    assert!(output.contains("\"view\": 1"), "{output}");
    assert!(
        output.contains(&polaris_crypto::hex::encode(&ic_input(5, 0))),
        "{output}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ic_over_wxsd_cluster_matches_the_simulator() {
    use polaris::local::IcWxsdMachines;
    use polaris_proto::bb::wxsd::WxsdConfig;

    let (n, t) = (8, 2);
    let params = Params::new(n, t).unwrap();
    let spec = LocalSpec {
        n,
        t,
        round: Duration::from_millis(300),
        max_rounds: 60,
        seed: 5,
        run_id: 11,
    };
    let machines = IcWxsdMachines {
        config: CompilerConfig::for_params(params),
        wxsd: WxsdConfig::default(),
        input_bytes: 0,
    };
    let result = run_local(&spec, &machines).await.unwrap();

    // LearnOrExpose, then WXSD terminates in the first Commit round of
    // epoch 1: two phases of d + 1 rounds plus one.
    let last = params.loe_rounds() + 2 * (params.diameter_bound() + 1) + 1;
    let first = result.outcomes[0].output.clone().unwrap();
    assert_eq!(first.view, 1);
    for o in &result.outcomes {
        assert_eq!(o.output.as_ref(), Some(&first), "node {} differs", o.me);
        assert_eq!(o.decision_round, Some(last), "node {}", o.me);
        assert_eq!(o.metrics.total().late_msgs, 0, "node {}", o.me);
    }
    for j in 0..n as NodeId {
        assert_eq!(first.values[usize::from(j)], Some(ic_input(j, 0)));
    }
    let mismatches = compare_with_simulator(&result, &machines, spec.max_rounds).unwrap();
    assert!(mismatches.is_empty(), "inboxes differ: {mismatches:?}");
}
