//! The polaris node: authenticated TCP channels, a wall-clock round schedule,
//! and a runner that drives any [`polaris_core::RoundMachine`] over them.
//! Protocol logic lives in `polaris-proto`; this crate only moves bytes on
//! time and writes metrics.

pub mod config;
pub mod local;
pub mod net;
pub mod runner;
