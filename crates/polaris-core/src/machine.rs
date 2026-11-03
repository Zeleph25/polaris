//! The round-machine interface every protocol implements.
//!
//! The paper's algorithms all have the shape "collect everything that arrived
//! this round, compute, send at the start of the next round", so that is the
//! whole interface. A machine never touches sockets, clocks or randomness;
//! the simulator and the network runner drive it through the same calls.
//!
//! Contract with the driver, for an instance whose first round is r0:
//! - `start` is called once; the messages it returns are sent at the start of r0.
//! - `end_round(r, inbox)` is called once per round r >= r0, with every message
//!   that arrived during r (the node's own `Dest::All` sends included), in
//!   sender-id order; the messages it returns are sent at the start of r + 1.
//! - After `halt`, the driver stops calling the machine and drops its messages.

use serde::{Serialize, de::DeserializeOwned};

use crate::{NodeId, Outgoing, Params, Round};

/// What the driver hands a machine on every call. Keys are deliberately not
/// here: a machine receives them when it is built.
#[derive(Clone, Debug)]
pub struct Ctx {
    pub me: NodeId,
    pub params: Params,
    pub run_id: u64,
}

pub trait RoundMachine {
    /// The wire message of this protocol.
    type Msg: Serialize + DeserializeOwned + Clone + Send + 'static;
    /// What the instance decides.
    type Output;

    /// Messages to send at the start of the instance's first round.
    fn start(&mut self, ctx: &mut Ctx) -> Vec<Outgoing<Self::Msg>>;

    /// End of round `round`, with everything that arrived during it;
    /// returns the messages to send at the start of the next round.
    fn end_round(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, Self::Msg)>,
    ) -> Vec<Outgoing<Self::Msg>>;

    /// The decision, once there is one.
    fn output(&self) -> Option<&Self::Output>;

    /// Stop the instance; later calls are not made.
    fn halt(&mut self);

    fn is_halted(&self) -> bool;
}
