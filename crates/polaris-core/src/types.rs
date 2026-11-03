//! Identifiers and message addressing.

use serde::{Deserialize, Serialize};

/// Index of a process, `0..n`. The paper's `p_i` is `NodeId` `i - 1`.
pub type NodeId = u16;

/// A synchronous round, counted from 0 (the compiler's disclosure round).
pub type Round = u32;

/// A view of the IC compiler, counted from 1 as in the paper.
pub type View = u32;

/// Where an outgoing message goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Dest {
    /// Every process, the sender included: a machine then handles its own
    /// accusations and disclosures through the same path as everyone else's.
    All,
    /// One process.
    One(NodeId),
}

/// A message a machine wants sent at the start of the next round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing<M> {
    pub to: Dest,
    pub msg: M,
}

impl<M> Outgoing<M> {
    pub fn all(msg: M) -> Self {
        Self { to: Dest::All, msg }
    }

    pub fn to(node: NodeId, msg: M) -> Self {
        Self {
            to: Dest::One(node),
            msg,
        }
    }
}
