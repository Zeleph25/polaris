//! Types shared by every protocol and both drivers.
//!
//! Nothing here does I/O or cryptography: the crate defines *what* a
//! protocol instance is (a [`RoundMachine`]), *who* it talks to
//! ([`NodeId`], [`Dest`]) and the system parameters of the paper
//! ([`Params`]).

mod machine;
mod params;
mod types;
pub mod wire;

pub use machine::{Ctx, RoundMachine};
pub use params::{Params, ParamsError};
pub use types::{Dest, NodeId, Outgoing, Round, View};
