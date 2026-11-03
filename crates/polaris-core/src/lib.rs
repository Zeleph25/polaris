//! Types shared by every protocol and both drivers.
//!
//! Nothing here does I/O or cryptography: the crate defines *what* a
//! protocol instance is (a [`RoundMachine`]), *who* it talks to
//! ([`NodeId`], [`Dest`], [`NodeSet`]), the system parameters of the paper
//! ([`Params`]), the wire encoding ([`wire`]) and the metrics every driver
//! records ([`Metrics`]).

mod machine;
mod metrics;
mod nodeset;
mod params;
mod types;
pub mod wire;

pub use machine::{Ctx, RoundMachine};
pub use metrics::{Counters, Metrics, Record};
pub use nodeset::{NodeSet, NodeSetError};
pub use params::{Params, ParamsError};
pub use types::{Dest, NodeId, Outgoing, Round, View};
