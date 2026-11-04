//! A two-round broadcast for exercising the harness, not a Byzantine one.
//!
//! Round 1: the sender signs its value and sends it to all. Round 2: every
//! node forwards the distinct sender-signed values it received (at most two,
//! which is enough to prove equivocation). At the end of round 2 a node
//! decides the value if it has seen exactly one, and bottom otherwise.
//!
//! Validity holds: an honest sender's value reaches everyone in round 1 and
//! nothing else can carry a valid signature. Agreement does not: a Byzantine
//! sender helped by one Byzantine forwarder can show a second value to some
//! honest nodes only (see the test `naive_broadcast_breaks_agreement`).
//! That is exactly the gap Dolev-Strong and WXSD close, and why this one is
//! kept: it is the simplest machine with the broadcast interface, so the
//! compiler and the drivers can be tested before the real broadcasts exist.

use std::sync::Arc;
use std::time::Instant;

use polaris_core::{Ctx, NodeId, Outgoing, Round, RoundMachine};
use polaris_crypto::domain;
use polaris_crypto::ed25519::{self, Sig};
use polaris_crypto::keyring::{Keyring, NodeKeys};
use serde::{Deserialize, Serialize};

use super::Broadcast;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NaiveMsg {
    pub value: Vec<u8>,
    pub sig: Sig,
}

pub struct NaiveBroadcast {
    keyring: Arc<Keyring>,
    keys: Arc<NodeKeys>,
    sender: NodeId,
    /// Distinguishes instances of one run (the view, for the compiler), so a
    /// value signed for one instance is not valid in another.
    instance: u64,
    input: Option<Vec<u8>>,
    seen: Vec<Vec<u8>>,
    first_round: Option<Round>,
    output: Option<Option<Vec<u8>>>,
    halted: bool,
}

impl NaiveBroadcast {
    /// `input` is `Some` at the sender only.
    pub fn new(
        keyring: Arc<Keyring>,
        keys: Arc<NodeKeys>,
        sender: NodeId,
        instance: u64,
        input: Option<Vec<u8>>,
    ) -> Self {
        Self {
            keyring,
            keys,
            sender,
            instance,
            input,
            seen: Vec::new(),
            first_round: None,
            output: None,
            halted: false,
        }
    }

    fn body(&self, value: &[u8]) -> Vec<u8> {
        [&self.instance.to_le_bytes()[..], value].concat()
    }

    fn signed(&self, value: Vec<u8>) -> NaiveMsg {
        let sig = ed25519::sign(
            &self.keys.ed25519,
            domain::NAIVE_BB,
            self.keyring.run_id,
            &self.body(&value),
        );
        NaiveMsg { value, sig }
    }

    /// Records a value if it carries the sender's signature and is new;
    /// returns whether it was new. At most two values are kept.
    fn record(&mut self, ctx: &mut Ctx, msg: &NaiveMsg) -> bool {
        if self.seen.len() >= 2 || self.seen.contains(&msg.value) {
            return false;
        }
        let started = Instant::now();
        let ok = ed25519::verify(
            self.keyring.ed25519(self.sender),
            domain::NAIVE_BB,
            self.keyring.run_id,
            &self.body(&msg.value),
            &msg.sig,
        );
        ctx.metrics.verified(1, started.elapsed());
        if ok {
            self.seen.push(msg.value.clone());
        }
        ok
    }
}

impl RoundMachine for NaiveBroadcast {
    type Msg = NaiveMsg;
    type Output = Option<Vec<u8>>;

    fn start(&mut self, _ctx: &mut Ctx) -> Vec<Outgoing<NaiveMsg>> {
        match (self.keys.id == self.sender, self.input.take()) {
            (true, Some(value)) => vec![Outgoing::all(self.signed(value))],
            _ => vec![],
        }
    }

    fn end_round(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, NaiveMsg)>,
    ) -> Vec<Outgoing<NaiveMsg>> {
        if self.halted || self.output.is_some() {
            return vec![];
        }
        let phase = round - *self.first_round.get_or_insert(round);
        let mut fresh = Vec::new();
        for (_, msg) in &inbox {
            if self.record(ctx, msg) {
                fresh.push(msg.clone());
            }
        }
        match phase {
            0 => fresh.into_iter().map(Outgoing::all).collect(),
            _ => {
                self.output = Some(match self.seen.as_slice() {
                    [one] => Some(one.clone()),
                    _ => None,
                });
                ctx.metrics.decided(round);
                vec![]
            }
        }
    }

    fn output(&self) -> Option<&Option<Vec<u8>>> {
        self.output.as_ref()
    }

    fn halt(&mut self) {
        self.halted = true;
    }

    fn is_halted(&self) -> bool {
        self.halted
    }
}

impl Broadcast for NaiveBroadcast {
    fn sender(&self) -> NodeId {
        self.sender
    }

    fn termination_skew(&self) -> u32 {
        0
    }
}
