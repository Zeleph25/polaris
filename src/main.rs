//! `polaris` command line: key generation, cluster configs, one node, and a
//! local in-process cluster checked against the simulator.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use polaris::config::{NodeConfig, Protocol, unix_ms_from_now};
use polaris::local::{LocalSpec, compare_with_simulator, echo_value, run_local_echo};
use polaris::net::Transport;
use polaris::runner::{Schedule, run_node};
use polaris_core::Params;
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::echo::Echo;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "polaris",
    version,
    about = "Interactive Consistency under a dishonest majority"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Write a keyring and one secret file per node into a directory.
    Keygen {
        #[arg(long)]
        n: usize,
        #[arg(long)]
        t: usize,
        #[arg(long, default_value_t = 1)]
        run_id: u64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write keys and node configs for an n-node cluster on one host
    /// (`polaris node --config <out>/node-<i>.toml` in n terminals).
    Genconfig {
        #[arg(long)]
        n: usize,
        #[arg(long)]
        t: usize,
        #[arg(long, default_value_t = 1)]
        run_id: u64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 7000)]
        base_port: u16,
        #[arg(long, default_value_t = 200)]
        round_ms: u64,
        /// Round 0 starts this many seconds from now; start every node before then.
        #[arg(long, default_value_t = 15)]
        start_in_s: u64,
        #[arg(long, default_value_t = 100)]
        max_rounds: u32,
    },
    /// Run one node from a config file.
    Node {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run an n-node echo cluster in this process over TCP and check its
    /// per-round inboxes against the simulator.
    Local {
        #[arg(long, default_value_t = 8)]
        n: usize,
        #[arg(long, default_value_t = 0)]
        t: usize,
        #[arg(long, default_value_t = 200)]
        round_ms: u64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Write per-node metrics, transcripts and outputs here.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn write_keys(
    params: Params,
    run_id: u64,
    seed: u64,
    out: &PathBuf,
) -> anyhow::Result<(Keyring, Vec<NodeKeys>)> {
    std::fs::create_dir_all(out)?;
    let (kr, keys) = keyring::generate(params, run_id, seed);
    kr.save(&out.join("keyring.toml"))?;
    for k in &keys {
        k.save(&out.join(format!("node-{}.secret.toml", k.id)))?;
    }
    Ok((kr, keys))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Keygen {
            n,
            t,
            run_id,
            seed,
            out,
        } => {
            write_keys(Params::new(n, t)?, run_id, seed, &out)?;
            println!("wrote {}/keyring.toml and {n} secret files", out.display());
        }
        Cmd::Genconfig {
            n,
            t,
            run_id,
            seed,
            out,
            host,
            base_port,
            round_ms,
            start_in_s,
            max_rounds,
        } => {
            let params = Params::new(n, t)?;
            write_keys(params, run_id, seed, &out)?;
            let last_port = base_port
                .checked_add(u16::try_from(n.saturating_sub(1))?)
                .context("port range exceeds 65535")?;
            let peers: Vec<String> = (base_port..=last_port)
                .map(|port| format!("{host}:{port}"))
                .collect();
            let start_at_unix_ms = unix_ms_from_now(Duration::from_secs(start_in_s));
            for i in 0..n {
                let cfg = NodeConfig {
                    id: u16::try_from(i)?,
                    keyring: "keyring.toml".into(),
                    secret: format!("node-{i}.secret.toml").into(),
                    peers: peers.clone(),
                    round_ms,
                    start_at_unix_ms,
                    max_rounds,
                    linger_rounds: 1,
                    connect_timeout_s: start_in_s + 5,
                    max_frame_bytes: 64 << 20,
                    out_dir: "runs".into(),
                    protocol: Protocol::Echo,
                };
                std::fs::write(out.join(format!("node-{i}.toml")), cfg.to_toml()?)?;
            }
            println!(
                "wrote {n} configs into {}; round 0 starts in {start_in_s} s",
                out.display()
            );
        }
        Cmd::Node { config } => {
            let cfg = NodeConfig::load(&config)?;
            let kr = Arc::new(Keyring::load(&cfg.keyring)?);
            let keys = NodeKeys::load(&cfg.secret)?;
            keys.check_against(&kr, cfg.id)?;
            let keys = Arc::new(keys);
            let addrs = cfg
                .peers
                .iter()
                .map(|p| p.parse().with_context(|| format!("peer address {p}")))
                .collect::<anyhow::Result<Vec<std::net::SocketAddr>>>()?;
            let listener = Transport::bind(&cfg.peers[usize::from(cfg.id)]).await?;
            tracing::info!(node = cfg.id, n = kr.n(), "connecting to peers");
            let transport = Transport::connect(
                keys.clone(),
                kr.clone(),
                listener,
                addrs,
                cfg.max_frame_bytes,
                cfg.connect_timeout(),
            )
            .await?;
            let start = cfg.start_instant();
            let schedule = Schedule {
                params: kr.params,
                run_id: kr.run_id,
                round: cfg.round(),
                max_rounds: cfg.max_rounds,
                linger_rounds: cfg.linger_rounds,
            };
            tracing::info!(node = cfg.id, "connected; waiting for round 0");
            let outcome = match cfg.protocol {
                Protocol::Echo => {
                    let machine = Echo::new(
                        kr.clone(),
                        Arc::new(keys.ed25519.clone()),
                        echo_value(cfg.id),
                    );
                    run_node(cfg.id, &schedule, transport, start, machine).await
                }
            };
            outcome.write_to(&cfg.out_dir)?;
            let m = outcome.metrics.total();
            println!(
                "node {}: decided at round {:?}, {} rounds, sent {} msgs / {} B, received {} msgs, {} late; files in {}",
                cfg.id,
                outcome.decision_round,
                outcome.rounds_run,
                m.msgs_sent,
                m.bytes_sent,
                m.msgs_recv,
                m.late_msgs,
                cfg.out_dir.display()
            );
        }
        Cmd::Local {
            n,
            t,
            round_ms,
            seed,
            out,
        } => {
            let spec = LocalSpec {
                n,
                t,
                round: Duration::from_millis(round_ms),
                max_rounds: 20,
                seed,
                run_id: 1,
            };
            let result = run_local_echo(&spec).await?;
            if let Some(dir) = &out {
                for o in &result.outcomes {
                    o.write_to(dir)?;
                }
            }
            let decided: Vec<_> = result.outcomes.iter().map(|o| o.decision_round).collect();
            let late: u64 = result
                .outcomes
                .iter()
                .map(|o| o.metrics.total().late_msgs)
                .sum();
            let first = result.outcomes[0].output.as_ref();
            let agree = result.outcomes.iter().all(|o| o.output.as_ref() == first);
            let mismatches = compare_with_simulator(&result, spec.max_rounds)?;
            println!(
                "n = {n}, round = {round_ms} ms: decision rounds {decided:?}, late messages {late}, outputs {}",
                if agree { "identical" } else { "DIFFER" }
            );
            if mismatches.is_empty() {
                println!("per-round inboxes match the simulator exactly");
            } else {
                println!(
                    "{} inboxes differ from the simulator: {mismatches:?}",
                    mismatches.len()
                );
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
