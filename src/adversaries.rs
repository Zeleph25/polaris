//! Protocol-specific adversaries for `polaris sim`, on top of the generic
//! silent and selective ones of the simulator.
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

use std::collections::BTreeMap;
use std::sync::Arc;

use polaris_core::{Ctx, Dest, NodeId, NodeSet, Outgoing, Round, RoundMachine};
use polaris_crypto::ed25519::Sig;
use polaris_crypto::keyring::NodeKeys;
use polaris_proto::bb::dolev_strong::{DsMsg, Link, sign_link};
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
