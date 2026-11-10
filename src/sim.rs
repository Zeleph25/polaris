//! Adversarial runs in the simulator, written out like network runs.
//!
//! The simulator measures rounds, messages, bytes and signature work
//! exactly, so an experiment under attack is run here rather than on the
//! network, where every node is honest. Byzantine nodes are drawn from a
//! seed and play one of the generic behaviors (silent, or the honest
//! protocol delivered to a random subset of the nodes only) or a
//! protocol-specific one from [`crate::adversaries`]. Honest nodes get the
//! same `node-<i>` files as on the network, with an empty transcript;
//! Byzantine nodes get none, and `byzantine.json` lists them.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use polaris_core::{NodeId, NodeSet, Params, RoundMachine};
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_sim::{Node, Selective, Silent, Simulator, Transcript};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha12Rng;
use serde::Serialize;

use crate::local::Machines;
use crate::runner::{Outcome, Resources};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum AdversaryKind {
    /// Byzantine nodes send nothing.
    Silent,
    /// Byzantine nodes run the protocol but deliver each message to a
    /// random half of the nodes only.
    Selective,
    /// Each Byzantine node is silent with probability 0.3, selective otherwise.
    Mixed,
    /// Dolev-Strong only: senders equivocate with fabricated values,
    /// forwarders extend every chain with their (sometimes forged)
    /// signature and scatter it, and chains on fresh values are fabricated
    /// whenever enough Byzantine signers exist.
    DsChaos,
}

#[derive(Clone, Debug)]
pub struct SimSpec {
    pub n: usize,
    pub t: usize,
    /// Byzantine nodes actually played, at most `t`.
    pub byzantine: usize,
    pub adversary: AdversaryKind,
    pub max_rounds: u32,
    pub seed: u64,
    pub run_id: u64,
}

pub struct SimResult<O> {
    pub byzantine: Vec<NodeId>,
    /// One outcome per honest node.
    pub outcomes: Vec<Outcome<O>>,
    pub last_round: u32,
}

fn make_node<F: Machines>(
    machines: &F,
    kr: &std::sync::Arc<Keyring>,
    keys: &NodeKeys,
    byzantine: Option<&[std::sync::Arc<NodeKeys>]>,
    kind: AdversaryKind,
    rng: &mut ChaCha12Rng,
) -> anyhow::Result<Node<F::M>> {
    let Some(byzantine_keys) = byzantine else {
        return Ok(Node::Honest(machines.make(kr, keys)));
    };
    let silent = match kind {
        AdversaryKind::Silent => true,
        AdversaryKind::Selective => false,
        AdversaryKind::Mixed => rng.random_bool(0.3),
        AdversaryKind::DsChaos => {
            let own = ChaCha12Rng::seed_from_u64(rng.random());
            return machines
                .ds_adversary(kr, keys, byzantine_keys, own)
                .map(Node::Byzantine)
                .context("the ds-chaos adversary needs a protocol over Dolev-Strong");
        }
    };
    if silent {
        Ok(Node::Byzantine(Box::new(Silent)))
    } else {
        let n = kr.n();
        let subset = NodeSet::from_iter(n, (0..n as NodeId).filter(|_| rng.random_bool(0.5)));
        Ok(Node::Byzantine(Box::new(Selective::new(
            machines.make(kr, keys),
            subset,
        ))))
    }
}

pub fn run_sim<F>(
    spec: &SimSpec,
    machines: &F,
) -> anyhow::Result<SimResult<<F::M as RoundMachine>::Output>>
where
    F: Machines,
    <F::M as RoundMachine>::Output: Clone,
{
    anyhow::ensure!(
        spec.byzantine <= spec.t,
        "{} Byzantine nodes exceed t = {}",
        spec.byzantine,
        spec.t
    );
    let params = Params::new(spec.n, spec.t)?;
    let (kr, keys) = keyring::generate(params, spec.run_id, spec.seed);
    let kr = std::sync::Arc::new(kr);
    let mut rng = ChaCha12Rng::seed_from_u64(spec.seed ^ 0x5eed_ad7e);
    let mut ids: Vec<NodeId> = (0..spec.n as NodeId).collect();
    for i in (1..ids.len()).rev() {
        ids.swap(i, rng.random_range(0..=i));
    }
    let mut byzantine = ids[..spec.byzantine].to_vec();
    byzantine.sort_unstable();

    let byzantine_keys: Vec<std::sync::Arc<NodeKeys>> = keys
        .iter()
        .filter(|k| byzantine.contains(&k.id))
        .map(|k| std::sync::Arc::new(k.clone()))
        .collect();
    let nodes = keys
        .iter()
        .map(|k| {
            make_node(
                machines,
                &kr,
                k,
                byzantine
                    .contains(&k.id)
                    .then_some(byzantine_keys.as_slice()),
                spec.adversary,
                &mut rng,
            )
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut sim = Simulator::new(params, spec.run_id, nodes)?.with_transcript(false);
    sim.run_until_decided(spec.max_rounds)
        .context("the simulator stalled")?;
    // Keep going until every honest node has halted, as the network runner
    // does: a protocol with a termination skew keeps sending after its
    // decision (the compiler runs its views in progress for Delta_sim more
    // rounds), and those messages are part of its cost.
    let honest: Vec<NodeId> = (0..spec.n as NodeId)
        .filter(|i| !byzantine.contains(i))
        .collect();
    while honest
        .iter()
        .any(|&i| sim.honest(i).is_some_and(|m| !m.is_halted()))
    {
        anyhow::ensure!(
            sim.round() < spec.max_rounds,
            "honest nodes still running after {} rounds",
            spec.max_rounds
        );
        sim.step();
    }
    let last_round = sim.round();
    let outputs = sim.outputs();
    let outcomes = (0..spec.n as NodeId)
        .filter(|i| !byzantine.contains(i))
        .map(|i| Outcome {
            me: i,
            output: outputs[usize::from(i)].cloned(),
            decision_round: sim.metrics(i).decision_round(),
            rounds_run: last_round,
            metrics: sim.metrics(i).clone(),
            transcript: Transcript::default(),
            decided_after: None,
            ran_for: Duration::ZERO,
            resources: Resources::now(),
        })
        .collect();
    Ok(SimResult {
        byzantine,
        outcomes,
        last_round,
    })
}

impl<O: Serialize> SimResult<O> {
    pub fn write_to(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        for o in &self.outcomes {
            o.write_to(dir)?;
        }
        std::fs::write(
            dir.join("byzantine.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "byzantine": self.byzantine,
                "last_round": self.last_round,
            }))?,
        )?;
        Ok(())
    }
}
