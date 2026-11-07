//! `polaris` command line: key generation, cluster configs, one node, and a
//! local in-process cluster checked against the simulator.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use polaris::config::{BroadcastKind, NodeConfig, Protocol, unix_ms_from_now};
use polaris::local::{
    EchoMachines, IcMachines, IcWxsdMachines, LocalSpec, Machines, ParallelDsMachines,
    ParallelWxsdMachines, compare_with_simulator, echo_value, ic_input, run_local,
};
use polaris::net::Transport;
use polaris::runner::{Outcome, Schedule, run_node};
use polaris_core::{Params, RoundMachine};
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::bb::wxsd::WxsdConfig;
use polaris_proto::compiler::{Compiler, CompilerConfig};
use polaris_proto::echo::Echo;
use polaris_proto::parallel::Parallel;
use serde::Serialize;
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
        #[arg(long, value_enum, default_value_t = Protocol::Echo)]
        protocol: Protocol,
        /// The broadcast of each view (`ic` only).
        #[arg(long, value_enum, default_value_t = BroadcastKind::DolevStrong)]
        broadcast: BroadcastKind,
        /// Rounds between view starts (`ic` only); the default is R.
        #[arg(long)]
        view_spacing: Option<u32>,
    },
    /// Run one node from a config file.
    Node {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run an n-node cluster in this process over TCP and check its
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
        #[arg(long, value_enum, default_value_t = Protocol::Echo)]
        protocol: Protocol,
        #[arg(long, value_enum, default_value_t = BroadcastKind::DolevStrong)]
        broadcast: BroadcastKind,
        #[arg(long)]
        view_spacing: Option<u32>,
        #[arg(long, default_value_t = 200)]
        max_rounds: u32,
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
            protocol,
            broadcast,
            view_spacing,
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
                    protocol,
                    broadcast,
                    view_spacing,
                    max_views: None,
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
            if cfg.start_at_unix_ms != 0 && cfg.start_at_unix_ms <= unix_ms_from_now(Duration::ZERO)
            {
                tracing::warn!(
                    "the start time in the config has already passed: this node begins round 0 at once and \
                     will not be in step with nodes started at another moment; rerun genconfig"
                );
            }
            let start = cfg.start_instant();
            let schedule = Schedule {
                params: kr.params,
                run_id: kr.run_id,
                round: cfg.round(),
                max_rounds: cfg.max_rounds,
                linger_rounds: cfg.linger_rounds,
            };
            tracing::info!(node = cfg.id, "connected; waiting for round 0");
            match cfg.protocol {
                Protocol::Echo => {
                    let machine = Echo::new(
                        kr.clone(),
                        Arc::new(keys.ed25519.clone()),
                        echo_value(cfg.id),
                    );
                    let outcome = run_node(cfg.id, &schedule, transport, start, machine).await;
                    report(&cfg, &outcome)?;
                }
                Protocol::Parallel => match cfg.broadcast {
                    BroadcastKind::DolevStrong => {
                        let machine =
                            Parallel::with_dolev_strong(kr.clone(), keys.clone(), ic_input(cfg.id));
                        let outcome = run_node(cfg.id, &schedule, transport, start, machine).await;
                        report(&cfg, &outcome)?;
                    }
                    BroadcastKind::Wxsd => {
                        let machine = Parallel::with_wxsd(
                            kr.clone(),
                            keys.clone(),
                            WxsdConfig::default(),
                            ic_input(cfg.id),
                        );
                        let outcome = run_node(cfg.id, &schedule, transport, start, machine).await;
                        report(&cfg, &outcome)?;
                    }
                },
                Protocol::Ic => {
                    let config = ic_config(kr.params, cfg.view_spacing, cfg.max_views);
                    match cfg.broadcast {
                        BroadcastKind::DolevStrong => {
                            let machine = Compiler::with_dolev_strong(
                                kr.clone(),
                                keys.clone(),
                                config,
                                ic_input(cfg.id),
                            );
                            let outcome =
                                run_node(cfg.id, &schedule, transport, start, machine).await;
                            report(&cfg, &outcome)?;
                        }
                        BroadcastKind::Wxsd => {
                            let machine = Compiler::with_wxsd(
                                kr.clone(),
                                keys.clone(),
                                config,
                                WxsdConfig::default(),
                                ic_input(cfg.id),
                            );
                            let outcome =
                                run_node(cfg.id, &schedule, transport, start, machine).await;
                            report(&cfg, &outcome)?;
                        }
                    }
                }
            }
        }
        Cmd::Local {
            n,
            t,
            round_ms,
            seed,
            protocol,
            broadcast,
            view_spacing,
            max_rounds,
            out,
        } => {
            let spec = LocalSpec {
                n,
                t,
                round: Duration::from_millis(round_ms),
                max_rounds,
                seed,
                run_id: 1,
            };
            match protocol {
                Protocol::Echo => local(&spec, &EchoMachines, out.as_deref()).await?,
                Protocol::Parallel => match broadcast {
                    BroadcastKind::DolevStrong => {
                        local(&spec, &ParallelDsMachines, out.as_deref()).await?;
                    }
                    BroadcastKind::Wxsd => {
                        let machines = ParallelWxsdMachines {
                            wxsd: WxsdConfig::default(),
                        };
                        local(&spec, &machines, out.as_deref()).await?;
                    }
                },
                Protocol::Ic => {
                    let config = ic_config(Params::new(n, t)?, view_spacing, None);
                    match broadcast {
                        BroadcastKind::DolevStrong => {
                            local(&spec, &IcMachines { config }, out.as_deref()).await?;
                        }
                        BroadcastKind::Wxsd => {
                            let machines = IcWxsdMachines {
                                config,
                                wxsd: WxsdConfig::default(),
                            };
                            local(&spec, &machines, out.as_deref()).await?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn ic_config(params: Params, view_spacing: Option<u32>, max_views: Option<u32>) -> CompilerConfig {
    let mut config = CompilerConfig::for_params(params);
    if let Some(c) = view_spacing {
        config = config.with_view_spacing(c);
    }
    if let Some(v) = max_views {
        config = config.with_max_views(v);
    }
    config
}

fn report<O: Serialize>(cfg: &NodeConfig, outcome: &Outcome<O>) -> anyhow::Result<()> {
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
    Ok(())
}

/// Runs the cluster, writes the files, prints the summary, and exits with
/// an error if any inbox differs from the simulator's.
async fn local<F>(spec: &LocalSpec, machines: &F, out: Option<&Path>) -> anyhow::Result<()>
where
    F: Machines,
    <F::M as RoundMachine>::Output: Clone + Serialize + Send + PartialEq,
{
    let result = run_local(spec, machines).await?;
    if let Some(dir) = out {
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
    let mismatches = compare_with_simulator(&result, machines, spec.max_rounds)?;
    println!(
        "n = {}, round = {} ms: decision rounds {decided:?}, late messages {late}, outputs {}",
        spec.n,
        spec.round.as_millis(),
        if agree { "identical" } else { "DIFFER" }
    );
    if mismatches.is_empty() {
        println!("per-round inboxes match the simulator exactly");
        Ok(())
    } else {
        println!(
            "{} inboxes differ from the simulator: {mismatches:?}",
            mismatches.len()
        );
        std::process::exit(1);
    }
}
