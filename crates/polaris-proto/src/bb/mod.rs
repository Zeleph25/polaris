//! Byzantine broadcast behind one interface, so that the compiler can run
//! any of them and the test harness can compare them.
//!
//! A broadcast instance has one designated sender with an input; every other
//! node joins with no input. It decides a value or bottom (`None`). The
//! guarantees a real broadcast must give: every honest node decides the same
//! thing (agreement), and if the sender is honest they decide its input
//! (validity).

use polaris_core::{NodeId, RoundMachine};

use crate::accusations::AccusationSet;

pub mod dolev_strong;
pub mod naive;
pub mod wxsd;

pub trait Broadcast: RoundMachine<Output = Option<Vec<u8>>> {
    fn sender(&self) -> NodeId;

    /// Delta_sim: honest nodes terminate within this many rounds of each
    /// other. The compiler waits that long after deciding before it halts.
    fn termination_skew(&self) -> u32;

    /// The accusations this instance holds, for a broadcast built on a
    /// trust graph; the compiler carries them into later views.
    fn accusations(&self) -> Option<&AccusationSet> {
        None
    }
}
