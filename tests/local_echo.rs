//! The echo protocol over TCP at n = 8 yields the same per-round
//! inboxes as the simulator, and every node writes its metrics file.

use std::time::Duration;

use polaris::local::{LocalSpec, compare_with_simulator, run_local_echo};
use polaris_core::NodeSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_cluster_matches_the_simulator() {
    let n = 8;
    let spec = LocalSpec {
        n,
        t: 0,
        round: Duration::from_millis(300),
        max_rounds: 20,
        seed: 3,
        run_id: 9,
    };
    let result = run_local_echo(&spec).await.unwrap();

    let first = result.outcomes[0].output.clone().unwrap();
    assert_eq!(first.agreeing, NodeSet::full(n));
    for o in &result.outcomes {
        assert_eq!(o.output.as_ref(), Some(&first), "node {} differs", o.me);
        assert_eq!(o.decision_round, Some(1));
        let m = o.metrics.total();
        assert_eq!(m.msgs_recv, 2 * n as u64, "node {}", o.me);
        assert_eq!(m.late_msgs, 0, "node {}", o.me);
    }
    let mismatches = compare_with_simulator(&result, spec.max_rounds).unwrap();
    assert!(mismatches.is_empty(), "inboxes differ: {mismatches:?}");

    let dir = std::env::temp_dir().join(format!("polaris-local-echo-{}", std::process::id()));
    for o in &result.outcomes {
        o.write_to(&dir).unwrap();
    }
    let metrics = std::fs::read_to_string(dir.join("node-5.metrics.jsonl")).unwrap();
    assert!(metrics.lines().any(|l| l.contains("\"kind\":\"summary\"")));
    assert_eq!(
        metrics.lines().count(),
        3 + 1,
        "two protocol rounds, one linger round, one summary"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
