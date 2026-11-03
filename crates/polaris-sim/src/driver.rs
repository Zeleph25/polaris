//! The lockstep driver.
//!
//! One round: honest nodes get their inbox and produce their sends for the
//! next round; adversaries then act with those sends in view (rushing);
//! every message is delivered into the recipient's inbox for the next round,
//! in sender-id order, each sender's messages in the order it produced them.
//! Nothing is lost or delayed: synchrony holds exactly, so an honest node's
//! behavior depends only on the inputs and the adversary, and two runs with
//! the same inputs give the same transcript.

use polaris_core::{Ctx, Dest, Metrics, NodeId, Outgoing, Params, Round, RoundMachine, wire};

use crate::adversary::{Adversary, HonestSend};
use crate::transcript::{Entry, Transcript};

/// Everything a node received in one round, in sender-id order.
pub type Inbox<M> = Vec<(NodeId, <M as RoundMachine>::Msg)>;

pub enum Node<M: RoundMachine> {
    Honest(M),
    Byzantine(Box<dyn Adversary<M>>),
}

impl<M: RoundMachine> Node<M> {
    pub fn is_honest(&self) -> bool {
        matches!(self, Node::Honest(_))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error("expected {expected} nodes, got {got}")]
    Count { expected: usize, got: usize },
    #[error("{byzantine} Byzantine nodes exceed t = {t}")]
    TooManyByzantine { byzantine: usize, t: usize },
    #[error("not every honest node decided within {0} rounds")]
    Stalled(u32),
}

pub struct Simulator<M: RoundMachine> {
    params: Params,
    nodes: Vec<Node<M>>,
    ctxs: Vec<Ctx>,
    inboxes: Vec<Vec<(NodeId, M::Msg)>>,
    first_round: Round,
    round: Round,
    started: bool,
    transcript: Transcript,
    record_transcript: bool,
}

impl<M: RoundMachine> Simulator<M> {
    /// `nodes[i]` is process `i`; at most `params.t` may be Byzantine.
    pub fn new(params: Params, run_id: u64, nodes: Vec<Node<M>>) -> Result<Self, SimError> {
        if nodes.len() != params.n {
            return Err(SimError::Count {
                expected: params.n,
                got: nodes.len(),
            });
        }
        let byzantine = nodes.iter().filter(|n| !n.is_honest()).count();
        if byzantine > params.t {
            return Err(SimError::TooManyByzantine {
                byzantine,
                t: params.t,
            });
        }
        let ctxs = (0..params.n)
            .map(|i| {
                Ctx::new(
                    NodeId::try_from(i).expect("n fits a NodeId"),
                    params,
                    run_id,
                )
            })
            .collect();
        Ok(Self {
            params,
            nodes,
            ctxs,
            inboxes: (0..params.n).map(|_| Vec::new()).collect(),
            first_round: 0,
            round: 0,
            started: false,
            transcript: Transcript::default(),
            record_transcript: true,
        })
    }

    /// Round number of the first round (default 0).
    pub fn with_first_round(mut self, r0: Round) -> Self {
        self.first_round = r0;
        self.round = r0;
        self
    }

    pub fn with_transcript(mut self, record: bool) -> Self {
        self.record_transcript = record;
        self
    }

    /// The round about to be run (or being run).
    pub fn round(&self) -> Round {
        self.round
    }

    /// Runs one round and returns its number. The first call also starts
    /// every machine.
    pub fn step(&mut self) -> Round {
        if !self.started {
            self.started = true;
            let mut outboxes: Vec<Vec<Outgoing<M::Msg>>> = Vec::with_capacity(self.params.n);
            for (i, node) in self.nodes.iter_mut().enumerate() {
                let ctx = &mut self.ctxs[i];
                outboxes.push(match node {
                    Node::Honest(m) => m.start(ctx),
                    Node::Byzantine(a) => a.start(ctx),
                });
            }
            self.deliver(self.round, outboxes);
        }
        let r = self.round;
        let inboxes: Vec<Vec<(NodeId, M::Msg)>> =
            self.inboxes.iter_mut().map(std::mem::take).collect();
        let mut outboxes: Vec<Vec<Outgoing<M::Msg>>> =
            (0..self.params.n).map(|_| Vec::new()).collect();
        let mut byzantine_inboxes: Vec<Option<Inbox<M>>> =
            (0..self.params.n).map(|_| None).collect();

        for (i, inbox) in inboxes.into_iter().enumerate() {
            match &mut self.nodes[i] {
                Node::Honest(m) => {
                    let ctx = &mut self.ctxs[i];
                    ctx.metrics
                        .received(inbox.len() as u64, Self::wire_size(&inbox));
                    if !m.is_halted() {
                        outboxes[i] = m.end_round(ctx, r, inbox);
                    }
                }
                Node::Byzantine(_) => byzantine_inboxes[i] = Some(inbox),
            }
        }

        let honest_sends: Vec<HonestSend<'_, M::Msg>> = outboxes
            .iter()
            .enumerate()
            .filter(|(i, _)| self.nodes[*i].is_honest())
            .flat_map(|(i, out)| {
                out.iter().map(move |msg| HonestSend {
                    from: NodeId::try_from(i).expect("n fits a NodeId"),
                    msg,
                })
            })
            .collect();
        let mut byzantine_outboxes: Vec<(usize, Vec<Outgoing<M::Msg>>)> = Vec::new();
        for (i, inbox) in byzantine_inboxes.into_iter().enumerate() {
            if let (Some(inbox), Node::Byzantine(a)) = (inbox, &mut self.nodes[i]) {
                byzantine_outboxes.push((i, a.act(&mut self.ctxs[i], r, inbox, &honest_sends)));
            }
        }
        drop(honest_sends);
        for (i, out) in byzantine_outboxes {
            outboxes[i] = out;
        }

        for ctx in &mut self.ctxs {
            ctx.metrics.end_round(r);
        }
        self.round = r + 1;
        self.deliver(self.round, outboxes);
        r
    }

    /// Runs rounds until every honest node has an output, or `max_rounds`
    /// rounds (counted from the first round) have run.
    pub fn run_until_decided(&mut self, max_rounds: u32) -> Result<Round, SimError> {
        loop {
            if self.all_honest_decided() {
                return Ok(self.round);
            }
            if self.round - self.first_round >= max_rounds {
                return Err(SimError::Stalled(max_rounds));
            }
            self.step();
        }
    }

    pub fn all_honest_decided(&self) -> bool {
        self.nodes.iter().all(|n| match n {
            Node::Honest(m) => m.output().is_some(),
            Node::Byzantine(_) => true,
        })
    }

    pub fn honest(&self, id: NodeId) -> Option<&M> {
        match &self.nodes[usize::from(id)] {
            Node::Honest(m) => Some(m),
            Node::Byzantine(_) => None,
        }
    }

    pub fn outputs(&self) -> Vec<Option<&M::Output>> {
        self.nodes
            .iter()
            .map(|n| match n {
                Node::Honest(m) => m.output(),
                Node::Byzantine(_) => None,
            })
            .collect()
    }

    pub fn metrics(&self, id: NodeId) -> &Metrics {
        &self.ctxs[usize::from(id)].metrics
    }

    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    pub fn params(&self) -> Params {
        self.params
    }

    fn wire_size(msgs: &[(NodeId, M::Msg)]) -> u64 {
        msgs.iter()
            .map(|(_, m)| wire::encode(m).map(|b| b.len() as u64).unwrap_or(0))
            .sum()
    }

    /// Moves every outbox into the recipients' inboxes for `round`, recording
    /// the transcript and the senders' metrics.
    fn deliver(&mut self, round: Round, outboxes: Vec<Vec<Outgoing<M::Msg>>>) {
        for (i, out) in outboxes.into_iter().enumerate() {
            let from = NodeId::try_from(i).expect("n fits a NodeId");
            for o in out {
                let bytes = wire::encode(&o.msg).expect("protocol messages serialize");
                let recipients: Vec<NodeId> = match o.to {
                    Dest::All => (0..self.params.n)
                        .map(|j| NodeId::try_from(j).expect("fits"))
                        .collect(),
                    Dest::One(j) => vec![j],
                };
                self.ctxs[i].metrics.sent(
                    recipients.len() as u64,
                    bytes.len() as u64 * recipients.len() as u64,
                );
                for to in recipients {
                    if self.record_transcript {
                        self.transcript.record(Entry::new(round, from, to, &bytes));
                    }
                    self.inboxes[usize::from(to)].push((from, o.msg.clone()));
                }
            }
        }
    }
}
