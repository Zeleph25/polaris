//! The baseline: `n` parallel broadcasts, one per sender, all started at
//! round 0. Node `i` is the sender of instance `i` with its own input; the
//! output is the vector of what the instances delivered, ready once every
//! instance has delivered. Honest nodes agree on every entry and get an
//! honest sender's input at its position, which is Interactive Consistency
//! at the cost of `n` broadcasts instead of one per view.
//!
//! Instances get their own context, as in the compiler, so that their
//! decisions do not count as this machine's; their counters are absorbed.

use std::sync::Arc;

use polaris_core::{Ctx, NodeId, Outgoing, Round, RoundMachine};
use polaris_crypto::keyring::{Keyring, NodeKeys};
use serde::{Deserialize, Serialize};

use crate::accusations::AccusationSet;
use crate::bb::Broadcast;
use crate::bb::dolev_strong::DolevStrong;
use crate::bb::wxsd::{Wxsd, WxsdConfig};
use crate::compiler::{MakeBroadcast, hex_values};

/// A broadcast message tagged with its instance, the sender's id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParMsg<M> {
    pub instance: NodeId,
    pub msg: M,
}

/// The decided vector, entry `i` from instance `i`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ParOutput {
    #[serde(serialize_with = "hex_values")]
    pub values: Vec<Option<Vec<u8>>>,
}

pub struct Parallel<B: Broadcast> {
    keys: Arc<NodeKeys>,
    instances: Vec<Option<B>>,
    delivered: Vec<Option<Option<Vec<u8>>>>,
    termination_skew: u32,
    sub: Ctx,
    output: Option<ParOutput>,
    halt_at: Option<Round>,
    halted: bool,
}

impl Parallel<DolevStrong> {
    pub fn with_dolev_strong(keyring: Arc<Keyring>, keys: Arc<NodeKeys>, input: Vec<u8>) -> Self {
        let (kr, ks) = (keyring.clone(), keys.clone());
        let make_bb: MakeBroadcast<DolevStrong> = Box::new(move |sender, instance, input, _| {
            DolevStrong::new(kr.clone(), ks.clone(), sender, instance, input)
        });
        Self::new(keyring, keys, make_bb, input)
    }
}

impl Parallel<Wxsd> {
    pub fn with_wxsd(
        keyring: Arc<Keyring>,
        keys: Arc<NodeKeys>,
        wxsd: WxsdConfig,
        input: Vec<u8>,
    ) -> Self {
        let (kr, ks) = (keyring.clone(), keys.clone());
        let make_bb: MakeBroadcast<Wxsd> = Box::new(move |sender, instance, input, _| {
            Wxsd::new(kr.clone(), ks.clone(), sender, instance, input, wxsd)
        });
        Self::new(keyring, keys, make_bb, input)
    }
}

impl<B: Broadcast> Parallel<B> {
    /// `make_bb(sender, instance, input)` builds one broadcast; here the
    /// instance number is the sender's id.
    pub fn new(
        keyring: Arc<Keyring>,
        keys: Arc<NodeKeys>,
        make_bb: MakeBroadcast<B>,
        input: Vec<u8>,
    ) -> Self {
        let n = keyring.n();
        let instances: Vec<Option<B>> = (0..n)
            .map(|i| {
                let sender = NodeId::try_from(i).expect("fits");
                let input = (sender == keys.id).then(|| input.clone());
                Some(make_bb(
                    sender,
                    u64::from(sender),
                    input,
                    &AccusationSet::new(n),
                ))
            })
            .collect();
        let termination_skew = instances[0].as_ref().expect("built").termination_skew();
        Self {
            sub: Ctx::new(keys.id, keyring.params, keyring.run_id),
            keys,
            instances,
            delivered: vec![None; n],
            termination_skew,
            output: None,
            halt_at: None,
            halted: false,
        }
    }

    pub fn delivered(&self) -> usize {
        self.delivered.iter().flatten().count()
    }
}

fn wrap<M>(instance: NodeId, out: Vec<Outgoing<M>>) -> Vec<Outgoing<ParMsg<M>>> {
    out.into_iter()
        .map(|o| Outgoing {
            to: o.to,
            msg: ParMsg {
                instance,
                msg: o.msg,
            },
        })
        .collect()
}

impl<B: Broadcast> RoundMachine for Parallel<B> {
    type Msg = ParMsg<B::Msg>;
    type Output = ParOutput;

    fn start(&mut self, ctx: &mut Ctx) -> Vec<Outgoing<Self::Msg>> {
        let mut out = Vec::new();
        for (i, bb) in self.instances.iter_mut().enumerate() {
            if let Some(bb) = bb {
                let id = NodeId::try_from(i).expect("fits");
                out.extend(wrap(id, bb.start(&mut self.sub)));
            }
        }
        ctx.metrics.absorb(&mut self.sub.metrics);
        out
    }

    fn end_round(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, Self::Msg)>,
    ) -> Vec<Outgoing<Self::Msg>> {
        if self.halted {
            return vec![];
        }
        let n = self.instances.len();
        let mut inboxes: Vec<Vec<(NodeId, B::Msg)>> = (0..n).map(|_| Vec::new()).collect();
        for (from, m) in inbox {
            if usize::from(m.instance) < n {
                inboxes[usize::from(m.instance)].push((from, m.msg));
            }
        }
        let mut out = Vec::new();
        for (i, inbox) in inboxes.into_iter().enumerate() {
            let Some(bb) = self.instances[i].as_mut() else {
                continue;
            };
            let id = NodeId::try_from(i).expect("fits");
            out.extend(wrap(id, bb.end_round(&mut self.sub, round, inbox)));
            if let Some(v) = bb.output() {
                self.delivered[i] = Some(v.clone());
                self.instances[i] = None;
            }
        }
        ctx.metrics.absorb(&mut self.sub.metrics);
        if self.output.is_none() && self.delivered.iter().all(Option::is_some) {
            self.output = Some(ParOutput {
                values: self.delivered.iter().map(|d| d.clone().flatten()).collect(),
            });
            ctx.metrics.decided(round);
            self.halt_at = Some(round + self.termination_skew);
            tracing::debug!(node = self.keys.id, round, "all instances delivered");
        }
        if self.halt_at.is_some_and(|h| round >= h) {
            self.halted = true;
        }
        out
    }

    fn output(&self) -> Option<&ParOutput> {
        self.output.as_ref()
    }

    fn halt(&mut self) {
        self.halted = true;
    }

    fn is_halted(&self) -> bool {
        self.halted
    }
}
