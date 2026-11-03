//! Signed all-to-all echo: the toy protocol both drivers are validated with.
//!
//! Round `r0`: every node sends `<value, sig>` to all. Round `r0 + 1`: every
//! node sends the digest of the vector it collected. At the end of `r0 + 1`
//! it outputs the vector and the set of nodes whose digest matches its own.
//! Two rounds, so the round pipeline (messages labeled with the round they
//! are sent in, inboxes per round, batch verification) is exercised, and the
//! `agreeing` set makes selective delivery by an adversary visible.

use std::sync::Arc;
use std::time::Instant;

use polaris_core::{Ctx, NodeId, NodeSet, Outgoing, Round, RoundMachine, wire};
use polaris_crypto::domain;
use polaris_crypto::ed25519::{self, Sig, SigningKey};
use polaris_crypto::hash::{Digest, digest};
use polaris_crypto::keyring::Keyring;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EchoMsg {
    Value { value: Vec<u8>, sig: Sig },
    Confirm { digest: Digest, sig: Sig },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoOutput {
    /// `values[j]` = node j's value, or `None` if no valid one arrived.
    pub values: Vec<Option<Vec<u8>>>,
    /// Nodes whose confirmed digest equals ours (ourselves included).
    pub agreeing: NodeSet,
}

pub struct Echo {
    keys: Arc<Keyring>,
    sk: Arc<SigningKey>,
    value: Vec<u8>,
    first_round: Option<Round>,
    values: Vec<Option<Vec<u8>>>,
    digest: Option<Digest>,
    output: Option<EchoOutput>,
    halted: bool,
}

impl Echo {
    pub fn new(keys: Arc<Keyring>, sk: Arc<SigningKey>, value: Vec<u8>) -> Self {
        let n = keys.n();
        Self {
            keys,
            sk,
            value,
            first_round: None,
            values: vec![None; n],
            digest: None,
            output: None,
            halted: false,
        }
    }
}

fn value_body(value: &[u8]) -> Vec<u8> {
    [b"value:".as_slice(), value].concat()
}

fn confirm_body(d: &Digest) -> Vec<u8> {
    [b"confirm:".as_slice(), d].concat()
}

enum Payload<'a> {
    Value(&'a [u8]),
    Confirm(&'a Digest),
}

impl RoundMachine for Echo {
    type Msg = EchoMsg;
    type Output = EchoOutput;

    fn start(&mut self, ctx: &mut Ctx) -> Vec<Outgoing<EchoMsg>> {
        let sig = ed25519::sign(&self.sk, domain::ECHO, ctx.run_id, &value_body(&self.value));
        vec![Outgoing::all(EchoMsg::Value {
            value: self.value.clone(),
            sig,
        })]
    }

    fn end_round(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, EchoMsg)>,
    ) -> Vec<Outgoing<EchoMsg>> {
        if self.halted || self.output.is_some() {
            return vec![];
        }
        let phase = round - *self.first_round.get_or_insert(round);

        // Everything of this phase, signature-checked in one batch.
        let candidates: Vec<(NodeId, Vec<u8>, &Sig, Payload<'_>)> = inbox
            .iter()
            .filter_map(|(from, msg)| match (phase, msg) {
                (0, EchoMsg::Value { value, sig }) => {
                    Some((*from, value_body(value), sig, Payload::Value(value)))
                }
                (1, EchoMsg::Confirm { digest, sig }) => {
                    Some((*from, confirm_body(digest), sig, Payload::Confirm(digest)))
                }
                _ => None,
            })
            .collect();
        let items: Vec<ed25519::Item<'_>> = candidates
            .iter()
            .map(|(from, body, sig, _)| ed25519::Item {
                pk: self.keys.ed25519(*from),
                tag: domain::ECHO,
                run_id: ctx.run_id,
                body,
                sig,
            })
            .collect();
        let started = Instant::now();
        let bad = ed25519::verify_batch(&items).err().unwrap_or_default();
        ctx.metrics.verified(items.len() as u64, started.elapsed());
        let valid = candidates
            .iter()
            .enumerate()
            .filter(|(i, _)| !bad.contains(i))
            .map(|(_, c)| c);

        match phase {
            0 => {
                for (from, _, _, payload) in valid {
                    // The first valid value per sender wins.
                    if let Payload::Value(v) = payload {
                        let slot = &mut self.values[usize::from(*from)];
                        if slot.is_none() {
                            *slot = Some(v.to_vec());
                        }
                    }
                }
                let d = digest(
                    domain::ECHO,
                    &wire::encode(&self.values).expect("serializable"),
                );
                self.digest = Some(d);
                let sig = ed25519::sign(&self.sk, domain::ECHO, ctx.run_id, &confirm_body(&d));
                vec![Outgoing::all(EchoMsg::Confirm { digest: d, sig })]
            }
            1 => {
                let mine = self.digest.expect("set at the first round");
                let mut agreeing = NodeSet::empty(self.keys.n());
                for (from, _, _, payload) in valid {
                    if let Payload::Confirm(d) = payload
                        && **d == mine
                    {
                        agreeing.insert(*from);
                    }
                }
                self.output = Some(EchoOutput {
                    values: self.values.clone(),
                    agreeing,
                });
                ctx.metrics.decided(round);
                vec![]
            }
            _ => vec![],
        }
    }

    fn output(&self) -> Option<&EchoOutput> {
        self.output.as_ref()
    }

    fn halt(&mut self) {
        self.halted = true;
    }

    fn is_halted(&self) -> bool {
        self.halted
    }
}
