//! Protocol-specific adversaries for `polaris sim`, on top of the generic
//! silent and selective ones of the simulator.
//!
//! [`DsChaos`] attacks Dolev-Strong and [`WxsdChaos`] attacks WXSD.
//!
//! [`DsChaos`] attacks Dolev-Strong wherever it runs, inside the compiler
//! or the parallel baseline: it runs the honest protocol for everything
//! else, but as a sender it equivocates with fabricated values, as a
//! forwarder it extends every chain it sees with its own signature
//! (sometimes forged) and scatters it to random subsets, and whenever the
//! sender of an instance is Byzantine and enough Byzantine signers exist, it
//! fabricates chains on fresh values, and floods well-formed chains with
//! garbage signatures on fresh values, which every honest node verifies
//! before rejecting. This is what makes Dolev-Strong pay: chains grow to
//! `t + 1` links, every node verifies many of them, and a Byzantine sender
//! forces bottom.
//!
//! [`WxsdChaos`] runs the honest WXSD machine and corrupts what it sends: as
//! a leader it proposes two values to the two halves of the nodes; as a
//! voter it equivocates, attaches a BLS part that does not verify (which
//! sends the aggregated check of the round to its one-by-one fallback), or
//! holds its vote back and releases it a few rounds late to a random
//! subset; as a committer it attaches evidence whose multi-signature does
//! not verify (a pairing at every receiver) or commits late. Every round,
//! for every instance it sees, it also sends one copy of a seen message with
//! a changed body and a garbage signature, which every receiver verifies
//! before dropping.

use std::collections::BTreeMap;
use std::sync::Arc;

use polaris_core::{Ctx, Dest, NodeId, NodeSet, Outgoing, Round, RoundMachine};
use polaris_crypto::bls::MultiSig;
use polaris_crypto::domain;
use polaris_crypto::ed25519::Sig;
use polaris_crypto::hash::Digest;
use polaris_crypto::keyring::NodeKeys;
use polaris_proto::bb::dolev_strong::{DsMsg, Link, sign_link};
use polaris_proto::bb::wxsd::{
    self, Ballot, Commit, Evidence, Proposal, Signed, Vote, VoteProof, WxsdMsg,
};
use polaris_proto::compiler::IcMsg;
use polaris_proto::parallel::ParMsg;
use polaris_sim::{Adversary, HonestSend};
use rand::RngExt;
use rand_chacha::ChaCha12Rng;

/// A message type that may carry a Dolev-Strong message of some instance.
pub trait CarriesDs: Sized {
    fn ds(&self) -> Option<(u64, &DsMsg)>;
    fn wrap(instance: u64, msg: DsMsg) -> Self;
}

impl CarriesDs for IcMsg<DsMsg> {
    fn ds(&self) -> Option<(u64, &DsMsg)> {
        match self {
            IcMsg::Bb { view, msg } => Some((u64::from(*view), msg)),
            _ => None,
        }
    }
    fn wrap(instance: u64, msg: DsMsg) -> Self {
        IcMsg::Bb {
            view: u32::try_from(instance).expect("a view"),
            msg,
        }
    }
}

impl CarriesDs for ParMsg<DsMsg> {
    fn ds(&self) -> Option<(u64, &DsMsg)> {
        Some((u64::from(self.instance), &self.msg))
    }
    fn wrap(instance: u64, msg: DsMsg) -> Self {
        ParMsg {
            instance: NodeId::try_from(instance).expect("a node id"),
            msg,
        }
    }
}

pub struct DsChaos<M> {
    inner: M,
    keys: Arc<NodeKeys>,
    /// Every Byzantine node's keys, this one included.
    byzantine: Vec<Arc<NodeKeys>>,
    run_id: u64,
    n: usize,
    rng: ChaCha12Rng,
}

impl<M> DsChaos<M> {
    pub fn new(
        inner: M,
        keys: Arc<NodeKeys>,
        byzantine: Vec<Arc<NodeKeys>>,
        run_id: u64,
        n: usize,
        rng: ChaCha12Rng,
    ) -> Self {
        Self {
            inner,
            keys,
            byzantine,
            run_id,
            n,
            rng,
        }
    }

    fn subset(&mut self) -> NodeSet {
        let n = self.n;
        NodeSet::from_iter(n, (0..n as NodeId).filter(|_| self.rng.random_bool(0.5)))
    }

    fn scatter<T: Clone>(&mut self, msg: T) -> Vec<Outgoing<T>> {
        self.subset()
            .iter()
            .map(|j| Outgoing::to(j, msg.clone()))
            .collect()
    }

    fn byzantine_key(&self, id: NodeId) -> Option<&Arc<NodeKeys>> {
        self.byzantine.iter().find(|k| k.id == id)
    }

    /// A chain of `len` Byzantine signers starting with `sender` on a fresh
    /// value, if the sender is Byzantine and there are enough signers.
    fn fabricate(&mut self, instance: u64, sender: NodeId, len: usize) -> Option<DsMsg> {
        let first = self.byzantine_key(sender)?.clone();
        let others: Vec<Arc<NodeKeys>> = self
            .byzantine
            .iter()
            .filter(|k| k.id != sender)
            .cloned()
            .collect();
        if others.len() + 1 < len {
            return None;
        }
        let value = format!("fake-{}-{}", instance, self.rng.random_range(0..4u8)).into_bytes();
        let mut signers = vec![first];
        signers.extend(others.into_iter().take(len - 1));
        Some(DsMsg {
            chain: signers
                .iter()
                .map(|k| sign_link(k, self.run_id, instance, &value))
                .collect(),
            value,
        })
    }

    /// The honest machine's own sends, with its Dolev-Strong messages
    /// replaced: a first message (this node is the sender) becomes an
    /// equivocation, a forward goes to a random subset.
    fn corrupt_sends<T: CarriesDs + Clone>(&mut self, out: Vec<Outgoing<T>>) -> Vec<Outgoing<T>> {
        let mut result = Vec::new();
        for o in out {
            let Some((instance, ds)) = o.msg.ds() else {
                result.push(o);
                continue;
            };
            if ds.chain.len() == 1 && ds.chain[0].signer == self.keys.id {
                for _ in 0..3 {
                    if let Some(fake) = self.fabricate(instance, self.keys.id, 1) {
                        result.extend(self.scatter(T::wrap(instance, fake)));
                    }
                }
            } else {
                let msg = o.msg.clone();
                match o.to {
                    Dest::All => result.extend(self.scatter(msg)),
                    Dest::One(_) => result.push(o),
                }
            }
        }
        result
    }

    /// Extends, fabricates and forges from the chains seen this round: for
    /// each instance seen, one extension of its longest chain, one
    /// fabricated value if the sender is Byzantine, and one forged chain.
    /// Reacting once per instance keeps the Byzantine nodes from feeding on
    /// each other's forgeries without bound.
    fn exploit<T: CarriesDs + Clone>(&mut self, seen: &[T]) -> Vec<Outgoing<T>> {
        let mut longest: BTreeMap<u64, &DsMsg> = BTreeMap::new();
        for m in seen {
            if let Some((instance, ds)) = m.ds()
                && !ds.chain.is_empty()
                && longest
                    .get(&instance)
                    .is_none_or(|best| ds.chain.len() > best.chain.len())
            {
                longest.insert(instance, ds);
            }
        }
        let mut out = Vec::new();
        for (instance, ds) in longest {
            let sender = ds.chain[0].signer;
            let len = ds.chain.len() + 1;
            if !ds.chain.iter().any(|l| l.signer == self.keys.id) && self.rng.random_bool(0.6) {
                let mut ext = ds.clone();
                ext.chain
                    .push(sign_link(&self.keys, self.run_id, instance, &ds.value));
                if self.rng.random_bool(0.2) {
                    ext.chain.last_mut().expect("pushed").sig = Sig([9; 64]);
                }
                out.extend(self.scatter(T::wrap(instance, ext)));
            }
            if let Some(fake) = self.fabricate(instance, sender, len) {
                out.extend(self.scatter(T::wrap(instance, fake)));
            }
            let forged = self.forge(instance, sender, len);
            out.extend(self.scatter(T::wrap(instance, forged)));
        }
        out
    }

    /// A well-formed chain of `len` distinct signers starting with `sender`
    /// on a fresh value, with garbage signatures: honest nodes verify it in
    /// one batch before rejecting it.
    fn forge(&mut self, instance: u64, sender: NodeId, len: usize) -> DsMsg {
        let value =
            format!("forged-{}-{}", instance, self.rng.random_range(0..u32::MAX)).into_bytes();
        let mut chain = vec![Link {
            signer: sender,
            sig: Sig([self.rng.random(); 64]),
        }];
        let mut next: NodeId = 0;
        while chain.len() < len && usize::from(next) < self.n {
            if next != sender {
                chain.push(Link {
                    signer: next,
                    sig: Sig([self.rng.random(); 64]),
                });
            }
            next += 1;
        }
        DsMsg { value, chain }
    }
}

impl<M> Adversary<M> for DsChaos<M>
where
    M: RoundMachine + Send,
    M::Msg: CarriesDs,
{
    fn start(&mut self, ctx: &mut Ctx) -> Vec<Outgoing<M::Msg>> {
        let out = self.inner.start(ctx);
        self.corrupt_sends(out)
    }

    fn act(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, M::Msg)>,
        honest_sends: &[HonestSend<'_, M::Msg>],
    ) -> Vec<Outgoing<M::Msg>> {
        let mut seen: Vec<M::Msg> = inbox.iter().map(|(_, m)| m.clone()).collect();
        seen.extend(honest_sends.iter().map(|h| h.msg.msg.clone()));
        let own = self.inner.end_round(ctx, round, inbox);
        let mut out = self.corrupt_sends(own);
        out.extend(self.exploit(&seen));
        out
    }
}

/// A message type that may carry a WXSD message of some instance.
pub trait CarriesWxsd: Sized {
    fn wxsd(&self) -> Option<(u64, &WxsdMsg)>;
    fn wrap(instance: u64, msg: WxsdMsg) -> Self;
}

impl CarriesWxsd for IcMsg<WxsdMsg> {
    fn wxsd(&self) -> Option<(u64, &WxsdMsg)> {
        match self {
            IcMsg::Bb { view, msg } => Some((u64::from(*view), msg)),
            _ => None,
        }
    }
    fn wrap(instance: u64, msg: WxsdMsg) -> Self {
        IcMsg::Bb {
            view: u32::try_from(instance).expect("a view"),
            msg,
        }
    }
}

impl CarriesWxsd for ParMsg<WxsdMsg> {
    fn wxsd(&self) -> Option<(u64, &WxsdMsg)> {
        Some((u64::from(self.instance), &self.msg))
    }
    fn wrap(instance: u64, msg: WxsdMsg) -> Self {
        ParMsg {
            instance: NodeId::try_from(instance).expect("a node id"),
            msg,
        }
    }
}

pub struct WxsdChaos<M: RoundMachine> {
    inner: M,
    keys: Arc<NodeKeys>,
    run_id: u64,
    n: usize,
    rng: ChaCha12Rng,
    /// Messages held back, with the round after which they go out.
    held: Vec<(Round, Outgoing<M::Msg>)>,
}

impl<M: RoundMachine> WxsdChaos<M>
where
    M::Msg: CarriesWxsd + Clone,
{
    pub fn new(inner: M, keys: Arc<NodeKeys>, run_id: u64, n: usize, rng: ChaCha12Rng) -> Self {
        Self {
            inner,
            keys,
            run_id,
            n,
            rng,
            held: Vec::new(),
        }
    }

    /// A random half of the nodes and its complement.
    fn halves(&mut self) -> (NodeSet, NodeSet) {
        let n = self.n;
        let a = NodeSet::from_iter(n, (0..n as NodeId).filter(|_| self.rng.random_bool(0.5)));
        let b = NodeSet::from_iter(n, (0..n as NodeId).filter(|j| !a.contains(*j)));
        (a, b)
    }

    fn to_set(set: &NodeSet, msg: &M::Msg) -> Vec<Outgoing<M::Msg>> {
        set.iter().map(|j| Outgoing::to(j, msg.clone())).collect()
    }

    fn random_digest(&mut self) -> Digest {
        self.rng.random()
    }

    /// A BLS signature by this node on something else: a valid point that
    /// fails every check it is used in.
    fn wrong_bls(&mut self) -> polaris_crypto::bls::Sig {
        let junk: [u8; 16] = self.rng.random();
        self.keys.bls.sign(domain::WXSD_VOTE, self.run_id, &junk)
    }

    fn hold(&mut self, round: Round, msg: M::Msg) {
        let delay = self.rng.random_range(1..=3);
        let (some, _) = self.halves();
        for o in Self::to_set(&some, &msg) {
            self.held.push((round + delay, o));
        }
    }

    /// The honest machine's sends of `round + 1`, with this node's own
    /// WXSD messages corrupted.
    fn corrupt_sends(&mut self, round: Round, out: Vec<Outgoing<M::Msg>>) -> Vec<Outgoing<M::Msg>> {
        let mut result = Vec::new();
        for o in out {
            let Some((instance, msg)) = o.msg.wxsd() else {
                result.push(o);
                continue;
            };
            let me = self.keys.id;
            match msg.clone() {
                WxsdMsg::Propose(p) if p.from == me => {
                    let fake = Proposal {
                        value: Some(format!("wxsd-fake-{instance}-{}", p.body.epoch).into_bytes()),
                        ..p.body.clone()
                    };
                    let other = wxsd::sign(
                        &self.keys,
                        self.run_id,
                        instance,
                        domain::WXSD_PROPOSE,
                        fake,
                    );
                    let (a, b) = self.halves();
                    result.extend(Self::to_set(&a, &o.msg));
                    result.extend(Self::to_set(
                        &b,
                        &M::Msg::wrap(instance, WxsdMsg::Propose(other)),
                    ));
                }
                WxsdMsg::Vote(v) if v.from == me => match self.rng.random_range(0..3u8) {
                    0 => {
                        let body = Vote {
                            ballot: Ballot::For(self.random_digest()),
                            ..v.body
                        };
                        let mut other =
                            wxsd::sign(&self.keys, self.run_id, instance, domain::WXSD_VOTE, body);
                        other.bls = v.bls.map(|_| self.wrong_bls());
                        let (a, b) = self.halves();
                        result.extend(Self::to_set(&a, &o.msg));
                        result.extend(Self::to_set(
                            &b,
                            &M::Msg::wrap(instance, WxsdMsg::Vote(other)),
                        ));
                    }
                    1 if v.bls.is_some() => {
                        let bad = Signed {
                            bls: Some(self.wrong_bls()),
                            ..v
                        };
                        result.push(Outgoing::all(M::Msg::wrap(instance, WxsdMsg::Vote(bad))));
                    }
                    _ => self.hold(round, o.msg.clone()),
                },
                WxsdMsg::Commit(c) if c.from == me => {
                    if self.rng.random_bool(0.5) {
                        let body = Commit {
                            evidence: Some(Evidence {
                                epoch: c.body.epoch,
                                digest: self.random_digest(),
                                proof: VoteProof::Aggregate(MultiSig {
                                    signers: NodeSet::full(self.n),
                                    sig: self.wrong_bls(),
                                }),
                            }),
                            ..c.body
                        };
                        let bad = wxsd::sign(
                            &self.keys,
                            self.run_id,
                            instance,
                            domain::WXSD_COMMIT,
                            body,
                        );
                        result.push(Outgoing::all(M::Msg::wrap(instance, WxsdMsg::Commit(bad))));
                    } else {
                        self.hold(round, o.msg.clone());
                    }
                }
                _ => result.push(o),
            }
        }
        result
    }

    /// One message per instance seen this round: a copy of a seen signed
    /// message with a changed body and a garbage signature, to a random
    /// half of the nodes.
    /// The first signed message of each instance among those seen; only
    /// these are copied, since a round can carry millions of messages.
    fn pick<'a>(seen: impl Iterator<Item = &'a M::Msg>) -> BTreeMap<u64, WxsdMsg>
    where
        M::Msg: 'a,
    {
        let mut picked: BTreeMap<u64, WxsdMsg> = BTreeMap::new();
        for m in seen {
            if let Some((instance, msg)) = m.wxsd()
                && matches!(
                    msg,
                    WxsdMsg::Propose(_) | WxsdMsg::Vote(_) | WxsdMsg::Commit(_)
                )
            {
                picked.entry(instance).or_insert_with(|| msg.clone());
            }
        }
        picked
    }

    fn flood(&mut self, picked: BTreeMap<u64, WxsdMsg>) -> Vec<Outgoing<M::Msg>> {
        let mut out = Vec::new();
        for (instance, msg) in picked {
            let junk = Sig([self.rng.random(); 64]);
            let forged = match msg {
                WxsdMsg::Propose(p) => WxsdMsg::Propose(Signed {
                    body: Proposal {
                        value: Some(self.rng.random::<[u8; 8]>().to_vec()),
                        ..p.body
                    },
                    sig: junk,
                    ..p
                }),
                WxsdMsg::Vote(v) => WxsdMsg::Vote(Signed {
                    body: Vote {
                        ballot: Ballot::For(self.random_digest()),
                        ..v.body
                    },
                    sig: junk,
                    ..v
                }),
                WxsdMsg::Commit(c) => WxsdMsg::Commit(Signed {
                    body: Commit {
                        epoch: c.body.epoch,
                        evidence: None,
                    },
                    sig: junk,
                    ..c
                }),
                _ => continue,
            };
            let (a, _) = self.halves();
            out.extend(Self::to_set(&a, &M::Msg::wrap(instance, forged)));
        }
        out
    }
}

impl<M> Adversary<M> for WxsdChaos<M>
where
    M: RoundMachine + Send,
    M::Msg: CarriesWxsd + Clone + Send,
{
    fn start(&mut self, ctx: &mut Ctx) -> Vec<Outgoing<M::Msg>> {
        let out = self.inner.start(ctx);
        self.corrupt_sends(0, out)
    }

    fn act(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, M::Msg)>,
        honest_sends: &[HonestSend<'_, M::Msg>],
    ) -> Vec<Outgoing<M::Msg>> {
        let picked = Self::pick(
            inbox
                .iter()
                .map(|(_, m)| m)
                .chain(honest_sends.iter().map(|h| &h.msg.msg)),
        );
        let own = self.inner.end_round(ctx, round, inbox);
        let mut out = self.corrupt_sends(round, own);
        out.extend(self.flood(picked));
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|(at, _)| *at <= round);
        self.held = later;
        out.extend(due.into_iter().map(|(_, o)| o));
        out
    }
}
