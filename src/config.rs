//! Per-node configuration file (TOML).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use polaris_core::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// The signed echo: validates the drivers, two rounds.
    #[default]
    Echo,
    /// Interactive Consistency: the compiler over a broadcast.
    Ic,
    /// The baseline: n parallel instances of a broadcast.
    Parallel,
}

/// The broadcast the compiler runs in each view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastKind {
    /// t + 1 rounds, deterministic.
    #[default]
    DolevStrong,
    /// Wan-Xiao-Shi-Devadas: expected constant epochs over a trust graph.
    Wxsd,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub id: NodeId,
    /// Bulletin-board key file; relative paths are resolved against the config file.
    pub keyring: PathBuf,
    /// This node's secret file.
    pub secret: PathBuf,
    /// `peers[j]` is the address the others reach node j at.
    pub peers: Vec<String>,
    /// The address this node binds; `peers[id]` when absent. On a cluster
    /// of several hosts this is `0.0.0.0:<port>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    pub round_ms: u64,
    /// Unix time in ms at which round 0 starts, shared by every node of the
    /// run; 0 means two seconds after this node connected to everyone.
    #[serde(default)]
    pub start_at_unix_ms: u64,
    #[serde(default = "default_max_rounds")]
    pub max_rounds: u32,
    #[serde(default = "default_linger_rounds")]
    pub linger_rounds: u32,
    #[serde(default = "default_connect_timeout_s")]
    pub connect_timeout_s: u64,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
    pub out_dir: PathBuf,
    #[serde(default)]
    pub protocol: Protocol,
    /// The broadcast of each view for `ic`, or of each instance for `parallel`.
    #[serde(default)]
    pub broadcast: BroadcastKind,
    /// WXSD: votes signed with BLS as well and commit evidence sent as one
    /// multi-signature instead of the votes themselves.
    #[serde(default)]
    pub aggregate_votes: bool,
    /// Input size in bytes for `ic` and `parallel`; 0 means the short label.
    #[serde(default)]
    pub input_bytes: usize,
    /// Rounds between view starts for `ic`; the default is R.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_spacing: Option<u32>,
    /// Views started at most for `ic`; unlimited by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_views: Option<u32>,
}

fn default_max_rounds() -> u32 {
    1000
}
fn default_linger_rounds() -> u32 {
    1
}
fn default_connect_timeout_s() -> u64 {
    30
}
fn default_max_frame_bytes() -> usize {
    64 << 20
}

impl NodeConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [&mut cfg.keyring, &mut cfg.secret, &mut cfg.out_dir] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        anyhow::ensure!(
            usize::from(cfg.id) < cfg.peers.len(),
            "id {} has no entry in peers (len {})",
            cfg.id,
            cfg.peers.len()
        );
        Ok(cfg)
    }

    pub fn listen(&self) -> &str {
        self.listen
            .as_deref()
            .unwrap_or(&self.peers[usize::from(self.id)])
    }

    pub fn round(&self) -> Duration {
        Duration::from_millis(self.round_ms)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_s)
    }

    /// The `Instant` of round 0, from the shared wall-clock start.
    pub fn start_instant(&self) -> Instant {
        if self.start_at_unix_ms == 0 {
            return Instant::now() + Duration::from_secs(2);
        }
        let target = UNIX_EPOCH + Duration::from_millis(self.start_at_unix_ms);
        match target.duration_since(SystemTime::now()) {
            Ok(ahead) => Instant::now() + ahead,
            Err(_) => Instant::now(),
        }
    }

    pub fn to_toml(&self) -> anyhow::Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }
}

/// Unix time in ms, `ahead` from now: what `genconfig` writes as the start.
pub fn unix_ms_from_now(ahead: Duration) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970");
    u64::try_from((now + ahead).as_millis()).expect("fits")
}
