//! Byzantine behaviors for the simulator.
//!
//! An adversary is rushing: when it chooses what to send at the start of
//! round `r + 1`, it has seen everything the honest nodes send at the start
//! of `r + 1`. Its messages can go to any subset of nodes, so an honest
//! node's inbox is whatever the adversary chose for it.

use polaris_core::{Ctx, Dest, NodeId, NodeSet, Outgoing, Round, RoundMachine};

/// A message an honest node is about to send, as the adversary sees it.
pub struct HonestSend<'a, M> {
    pub from: NodeId,
    pub msg: &'a Outgoing<M>,
}

pub trait Adversary<M: RoundMachine>: Send {
    /// Messages sent at the start of the first round.
    fn start(&mut self, _ctx: &mut Ctx) -> Vec<Outgoing<M::Msg>> {
        vec![]
    }

    /// Messages sent at the start of `round + 1`, chosen after seeing this
    /// node's inbox for `round` and the honest sends for `round + 1`.
    fn act(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, M::Msg)>,
        honest_sends: &[HonestSend<'_, M::Msg>],
    ) -> Vec<Outgoing<M::Msg>>;
}

/// Sends nothing, ever.
#[derive(Debug, Default, Clone, Copy)]
pub struct Silent;

impl<M: RoundMachine> Adversary<M> for Silent {
    fn act(
        &mut self,
        _ctx: &mut Ctx,
        _round: Round,
        _inbox: Vec<(NodeId, M::Msg)>,
        _honest_sends: &[HonestSend<'_, M::Msg>],
    ) -> Vec<Outgoing<M::Msg>> {
        vec![]
    }
}

/// Runs the honest machine but delivers its `All` messages only to
/// `deliver_to` (and `One(j)` messages only if `j` is in the set).
pub struct Selective<M> {
    inner: M,
    deliver_to: NodeSet,
}

impl<M: RoundMachine> Selective<M> {
    pub fn new(inner: M, deliver_to: NodeSet) -> Self {
        Self { inner, deliver_to }
    }

    fn filter(&self, out: Vec<Outgoing<M::Msg>>) -> Vec<Outgoing<M::Msg>> {
        out.into_iter()
            .flat_map(|o| match o.to {
                Dest::All => self
                    .deliver_to
                    .iter()
                    .map(|j| Outgoing::to(j, o.msg.clone()))
                    .collect::<Vec<_>>(),
                Dest::One(j) if self.deliver_to.contains(j) => vec![o],
                Dest::One(_) => vec![],
            })
            .collect()
    }
}

impl<M: RoundMachine + Send> Adversary<M> for Selective<M> {
    fn start(&mut self, ctx: &mut Ctx) -> Vec<Outgoing<M::Msg>> {
        let out = self.inner.start(ctx);
        self.filter(out)
    }

    fn act(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, M::Msg)>,
        _honest_sends: &[HonestSend<'_, M::Msg>],
    ) -> Vec<Outgoing<M::Msg>> {
        let out = self.inner.end_round(ctx, round, inbox);
        self.filter(out)
    }
}
