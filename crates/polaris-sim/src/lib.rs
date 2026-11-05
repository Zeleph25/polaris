//! Single-process lockstep simulator.
//!
//! Drives a set of [`polaris_core::RoundMachine`]s round by round under exact
//! synchrony, with Byzantine nodes played by an [`Adversary`]; records a
//! [`Transcript`] in the same format the network runner writes, so the two
//! can be diffed inbox by inbox. Deterministic: same inputs, same transcript.

pub mod adversary;
pub mod driver;
pub mod transcript;

pub use adversary::{Adversary, HonestSend, Scripted, Selective, Silent};
pub use driver::{Node, SimError, Simulator};
pub use transcript::{Entry, Transcript};
