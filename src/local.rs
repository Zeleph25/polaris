//! An n-node cluster in one process over real TCP, and its check against
//! the simulator.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use polaris_core::{NodeId, Params, Round};
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::echo::{Echo, EchoOutput};
use polaris_sim::{Node, Simulator, Transcript};

use crate::net::Transport;
use crate::runner::{Outcome, Schedule, run_node};

#[derive(Clone, Debug)]
pub struct LocalSpec {
    pub n: usize,
    pub t: usize,
    pub round: Duration,
    pub max_rounds: u32,
    pub seed: u64,
    pub run_id: u64,
}

pub struct LocalResult {
    pub keyring: Arc<Keyring>,
    pub keys: Vec<NodeKeys>,
    pub outcomes: Vec<Outcome<EchoOutput>>,
    /// Every node's received-message transcript, merged.
    pub merged: Transcript,
}

pub fn echo_value(id: NodeId) -> Vec<u8> {
    format!("value-of-{id}").into_bytes()
}

fn echo(kr: &Arc<Keyring>, keys: &NodeKeys) -> Echo {
    Echo::new(
        kr.clone(),
        Arc::new(keys.ed25519.clone()),
        echo_value(keys.id),
    )
}

pub async fn run_local_echo(spec: &LocalSpec) -> anyhow::Result<LocalResult> {
    let params = Params::new(spec.n, spec.t)?;
    let (kr, keys) = keyring::generate(params, spec.run_id, spec.seed);
    let kr = Arc::new(kr);

    let mut listeners = Vec::with_capacity(spec.n);
    let mut addrs = Vec::with_capacity(spec.n);
    for _ in 0..spec.n {
        let l = Transport::bind("127.0.0.1:0").await?;
        addrs.push(l.local_addr()?);
        listeners.push(l);
    }
    let mut connects = Vec::with_capacity(spec.n);
    for (i, listener) in listeners.into_iter().enumerate() {
        let node_keys = Arc::new(keys[i].clone());
        let kr = kr.clone();
        let addrs = addrs.clone();
        connects.push(tokio::spawn(Transport::connect(
            node_keys,
            kr,
            listener,
            addrs,
            64 << 20,
            Duration::from_secs(10),
        )));
    }
    let mut transports = Vec::with_capacity(spec.n);
    for (i, c) in connects.into_iter().enumerate() {
        transports.push(
            c.await?
                .with_context(|| format!("node {i} failed to connect"))?,
        );
    }

    let schedule = Schedule {
        params,
        run_id: spec.run_id,
        round: spec.round,
        max_rounds: spec.max_rounds,
        linger_rounds: 1,
    };
    let start = Instant::now() + Duration::from_millis(200);
    let mut runs = Vec::with_capacity(spec.n);
    for (i, transport) in transports.into_iter().enumerate() {
        let machine = echo(&kr, &keys[i]);
        let schedule = schedule.clone();
        let me = NodeId::try_from(i).expect("n fits a NodeId");
        runs.push(tokio::spawn(async move {
            run_node(me, &schedule, transport, start, machine).await
        }));
    }
    let mut outcomes = Vec::with_capacity(spec.n);
    for r in runs {
        outcomes.push(r.await?);
    }
    let mut merged = Transcript::default();
    for o in &outcomes {
        for e in o.transcript.entries() {
            merged.record(e.clone());
        }
    }
    Ok(LocalResult {
        keyring: kr,
        keys,
        outcomes,
        merged,
    })
}

/// Runs the same echo in the simulator and returns the `(round, node)`
/// inboxes whose fingerprints differ from the network run's (empty = match).
pub fn compare_with_simulator(
    result: &LocalResult,
    max_rounds: u32,
) -> anyhow::Result<Vec<(Round, NodeId)>> {
    let kr = &result.keyring;
    let nodes = result
        .keys
        .iter()
        .map(|k| Node::Honest(echo(kr, k)))
        .collect();
    let mut sim = Simulator::new(kr.params, kr.run_id, nodes)?;
    sim.run_until_decided(max_rounds)?;
    let expected = sim.transcript().inbox_fingerprints();
    let got = result.merged.inbox_fingerprints();
    let mut keys: Vec<_> = expected.keys().chain(got.keys()).copied().collect();
    keys.sort();
    keys.dedup();
    Ok(keys
        .into_iter()
        .filter(|k| expected.get(k) != got.get(k))
        .collect())
}
