//! Per-node configuration file (TOML).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use polaris_core::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Echo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub id: NodeId,
    /// Bulletin-board key file; relative paths are resolved against the config file.
    pub keyring: PathBuf,
    /// This node's secret file.
    pub secret: PathBuf,
    /// `peers[j]` is node j's listen address; ours is `peers[id]`.
    pub peers: Vec<String>,
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
