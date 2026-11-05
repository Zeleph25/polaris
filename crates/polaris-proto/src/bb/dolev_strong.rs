//! The Dolev-Strong broadcast: `t + 1` rounds of signature chains.
//!
//! Round 1: the sender signs its value and sends it to all. A message
//! received in round `r` is valid if it carries signatures on the value by
//! at least `r` distinct nodes, the first of them the sender. A node that
//! receives a valid message for a value it has not seen *extracts* the
//! value and, if `r <= t`, appends its own signature and forwards the chain
//! to all in round `r + 1`. At the end of round `t + 1` it decides the
//! value if it extracted exactly one, and bottom otherwise.
//!
//! Agreement: if an honest node extracts `v` in a round `r <= t`, it
//! forwards a chain of `r + 1` signatures that every honest node accepts in
//! round `r + 1`. If it extracts `v` in round `t + 1`, the chain carries
//! `t + 1` distinct signers, so one of them is honest and forwarded `v` in
//! an earlier round, and everyone extracted it then. Validity: an honest
//! sender's value reaches everyone in round 1 and no other value carries the
//! sender's signature.
//!
//! A node keeps at most two values: two are enough to decide bottom, and a
//! node that forwards both makes every honest node see two as well. The
//! value travels in every message rather than only in the sender's first
//! one, because a Byzantine sender may show the value to a single node, who
//! then has to carry it to the others. Signatures cover a digest of the
//! value together with the instance number, so signing and verifying cost
//! the same whatever the value's length.

use std::sync::Arc;
use std::time::Instant;

use polaris_core::{Ctx, NodeId, Outgoing, Round, RoundMachine};
use polaris_crypto::domain;
use polaris_crypto::ed25519::{self, Item, Sig};
use polaris_crypto::hash;
use polaris_crypto::keyring::{Keyring, NodeKeys};
use serde::{Deserialize, Serialize};

use super::Broadcast;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub signer: NodeId,
    pub sig: Sig,
}

/// A value with its chain; `chain[0]` is the sender's signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsMsg {
    pub value: Vec<u8>,
    pub chain: Vec<Link>,
}

/// The signed body: `instance || H(value)`.
pub fn signed_body(instance: u64, value: &[u8]) -> Vec<u8> {
    [
        &instance.to_le_bytes()[..],
        &hash::digest(domain::DS_ECHO, value),
    ]
    .concat()
}

pub fn sign_link(keys: &NodeKeys, run_id: u64, instance: u64, value: &[u8]) -> Link {
    Link {
        signer: keys.id,
        sig: ed25519::sign(
            &keys.ed25519,
            domain::DS_ECHO,
            run_id,
            &signed_body(instance, value),
        ),
    }
}

pub struct DolevStrong {
    keyring: Arc<Keyring>,
    keys: Arc<NodeKeys>,
    sender: NodeId,
    /// Distinguishes instances of one run (the view, for the compiler).
    instance: u64,
    input: Option<Vec<u8>>,
    /// Values extracted so far, at most two.
    extracted: Vec<Vec<u8>>,
    first_round: Option<Round>,
    output: Option<Option<Vec<u8>>>,
    halted: bool,
}

impl DolevStrong {
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
            extracted: Vec::new(),
            first_round: None,
            output: None,
            halted: false,
        }
    }

    /// The last round of the instance, counted from 1.
    pub fn rounds(&self) -> u32 {
        u32::try_from(self.keyring.params.t).expect("t fits") + 1
    }

    fn well_formed(&self, msg: &DsMsg, phase: u32) -> bool {
        let n = self.keyring.n();
        let mut seen = vec![false; n];
        msg.chain.len() >= phase as usize
            && msg.chain.first().is_some_and(|l| l.signer == self.sender)
            && msg.chain.iter().all(|l| {
                let i = usize::from(l.signer);
                i < n && !std::mem::replace(&mut seen[i], true)
            })
    }

    /// Verifies every signature of the chain in one batch.
    fn chain_verifies(&self, ctx: &mut Ctx, msg: &DsMsg) -> bool {
        let body = signed_body(self.instance, &msg.value);
        let items: Vec<Item<'_>> = msg
            .chain
            .iter()
            .map(|l| Item {
                pk: self.keyring.ed25519(l.signer),
                tag: domain::DS_ECHO,
                run_id: self.keyring.run_id,
                body: &body,
                sig: &l.sig,
            })
            .collect();
        let started = Instant::now();
        let ok = ed25519::verify_batch(&items).is_ok();
        ctx.metrics.verified(items.len() as u64, started.elapsed());
        ok
    }

    /// Extracts the message's value if it is new and the chain is valid for
    /// this phase; returns whether it was extracted.
    fn extract(&mut self, ctx: &mut Ctx, msg: &DsMsg, phase: u32) -> bool {
        if self.extracted.len() >= 2
            || self.extracted.contains(&msg.value)
            || !self.well_formed(msg, phase)
            || !self.chain_verifies(ctx, msg)
        {
            return false;
        }
        self.extracted.push(msg.value.clone());
        true
    }

    fn extend(&self, msg: &DsMsg) -> DsMsg {
        let mut chain = msg.chain.clone();
        chain.push(sign_link(
            &self.keys,
            self.keyring.run_id,
            self.instance,
            &msg.value,
        ));
        DsMsg {
            value: msg.value.clone(),
            chain,
        }
    }
}

impl RoundMachine for DolevStrong {
    type Msg = DsMsg;
    type Output = Option<Vec<u8>>;

    fn start(&mut self, _ctx: &mut Ctx) -> Vec<Outgoing<DsMsg>> {
        match (self.keys.id == self.sender, self.input.take()) {
            (true, Some(value)) => {
                let link = sign_link(&self.keys, self.keyring.run_id, self.instance, &value);
                self.extracted.push(value.clone());
                vec![Outgoing::all(DsMsg {
                    value,
                    chain: vec![link],
                })]
            }
            _ => vec![],
        }
    }

    fn end_round(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, DsMsg)>,
    ) -> Vec<Outgoing<DsMsg>> {
        if self.halted || self.output.is_some() {
            return vec![];
        }
        let phase = round - *self.first_round.get_or_insert(round) + 1;
        let mut fresh = Vec::new();
        for (_, msg) in &inbox {
            if self.extract(ctx, msg, phase) {
                fresh.push(msg);
            }
        }
        if phase < self.rounds() {
            return fresh
                .into_iter()
                .map(|m| Outgoing::all(self.extend(m)))
                .collect();
        }
        self.output = Some(match self.extracted.as_slice() {
            [one] => Some(one.clone()),
            _ => None,
        });
        ctx.metrics.decided(round);
        vec![]
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

impl Broadcast for DolevStrong {
    fn sender(&self) -> NodeId {
        self.sender
    }

    fn termination_skew(&self) -> u32 {
        0
    }
}
