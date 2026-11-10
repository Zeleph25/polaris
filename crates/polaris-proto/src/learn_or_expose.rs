//! Algorithm 2: `LearnOrExpose` for a dishonest majority.
//!
//! Every node starts from the candidate entries the compiler collected in
//! round 0 and runs exactly `R = ceil(2n/(n-t)) + 1` rounds. In each round it
//! adds and forwards new valid accusations, learns and forwards disclosures
//! of still-unresolved parties, rebuilds `G = MakeGraph(Acc)`, exposes every
//! unresolved party it is disconnected from, and accuses the frontier: its
//! neighbors within distance `r - 1` of some unresolved party. At the end
//! of round `R` it outputs `(v, (sigma, Aggregate(Acc)))`.
//!
//! Differences from the printed algorithm, all deliberate:
//! - every node runs all `R` rounds and keeps forwarding (the paper lets a
//!   non-leader return early); termination stays simultaneous and the
//!   "one round of lag" invariant the proof needs keeps holding;
//! - every honest node computes the output, not only the leader, so a test
//!   can check that any honest node's proof verifies at any other
//!   (Transferability); the compiler submits only the leader's;
//! - a node's own accusations enter its `Acc` when it signs them rather than
//!   when they echo back a round later, which is the same graph one round
//!   later and avoids re-forwarding them.

use std::sync::Arc;
use std::time::Instant;

use polaris_core::{Ctx, NodeId, NodeSet, Outgoing, Round, RoundMachine};
use polaris_crypto::ed25519;
use polaris_crypto::keyring::{Keyring, NodeKeys};
use serde::{Deserialize, Serialize};

use crate::accusations::{self, Accusation, AccusationSet};
use crate::disclosure::{Disclosure, Entries, VerifiableVector};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoeMsg {
    Disclose(Disclosure),
    Accuse(Accusation),
}

/// What happened in one instance, for tests and metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoeStats {
    /// Accusations this node signed.
    pub accusations_sent: u64,
    /// Valid, new accusations added to `Acc` (own ones included).
    pub accusations_added: u64,
    /// Accusations that failed verification.
    pub accusations_rejected: u64,
    /// Parties resolved by receiving their disclosure during the instance.
    pub learned: u32,
    /// Parties resolved by disconnection.
    pub exposed: u32,
    /// First instance round (1-based) at which nothing was unresolved.
    pub resolved_round: Option<u32>,
}

pub struct LearnOrExpose {
    keyring: Arc<Keyring>,
    keys: Arc<NodeKeys>,
    leader: NodeId,
    entries: Entries,
    acc: AccusationSet,
    unresolved: NodeSet,
    rounds: u32,
    first_round: Option<Round>,
    output: Option<VerifiableVector>,
    finished: bool,
    halted: bool,
    stats: LoeStats,
}

impl LearnOrExpose {
    /// `entries` is the candidate vector of round 0 (`VerifyVec_in` must hold).
    pub fn new(
        keyring: Arc<Keyring>,
        keys: Arc<NodeKeys>,
        leader: NodeId,
        entries: Entries,
    ) -> Self {
        let n = keyring.n();
        debug_assert_eq!(entries.len(), n);
        debug_assert!(crate::disclosure::verify_in(&entries, &keyring));
        let unresolved = NodeSet::from_iter(
            n,
            entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.is_none())
                .map(|(j, _)| NodeId::try_from(j).expect("fits")),
        );
        Self {
            rounds: keyring.params.loe_rounds(),
            acc: AccusationSet::new(n),
            keyring,
            keys,
            leader,
            entries,
            unresolved,
            first_round: None,
            output: None,
            finished: false,
            halted: false,
            stats: LoeStats::default(),
        }
    }

    /// Starts from `acc` instead of an empty accusation set: accusations
    /// are scoped to the run, so those of earlier views still stand, and a
    /// party they disconnect is exposed at once. Whoever seeds instances
    /// must keep every honest node's set within one round of every other's
    /// (the compiler gossips each accusation once), which is what the
    /// one-round-of-lag invariant of the proofs needs.
    pub fn with_accusations(
        keyring: Arc<Keyring>,
        keys: Arc<NodeKeys>,
        leader: NodeId,
        entries: Entries,
        acc: AccusationSet,
    ) -> Self {
        let mut loe = Self::new(keyring, keys, leader, entries);
        loe.acc = acc;
        loe
    }

    pub fn leader(&self) -> NodeId {
        self.leader
    }

    pub fn is_leader(&self) -> bool {
        self.keys.id == self.leader
    }

    /// `R`.
    pub fn rounds(&self) -> u32 {
        self.rounds
    }

    pub fn unresolved(&self) -> &NodeSet {
        &self.unresolved
    }

    pub fn accusations(&self) -> &AccusationSet {
        &self.acc
    }

    pub fn entries(&self) -> &Entries {
        &self.entries
    }

    pub fn stats(&self) -> &LoeStats {
        &self.stats
    }

    /// Lines 8-9: add new valid accusations to `Acc`; return the ones to forward.
    fn take_accusations(&mut self, ctx: &mut Ctx, mut accs: Vec<Accusation>) -> Vec<Accusation> {
        // Already-known pairs need no second verification (the first valid signature is kept).
        accs.retain(|a| !self.acc.contains(a.accuser, a.target));
        if accs.is_empty() {
            return vec![];
        }
        let started = Instant::now();
        let flags = accusations::verify_many(&self.keyring, &accs);
        ctx.metrics.verified(accs.len() as u64, started.elapsed());
        let mut fresh = Vec::new();
        for (a, ok) in accs.into_iter().zip(flags) {
            if !ok {
                self.stats.accusations_rejected += 1;
            } else if self.acc.insert(&a) {
                self.stats.accusations_added += 1;
                fresh.push(a);
            }
        }
        fresh
    }

    /// Lines 10-15: learn disclosures of unresolved parties; return the ones to forward.
    fn take_disclosures(&mut self, ctx: &mut Ctx, discs: Vec<Disclosure>) -> Vec<Disclosure> {
        let candidates: Vec<Disclosure> = discs
            .into_iter()
            .filter(|d| {
                usize::from(d.sender) < self.keyring.n() && self.unresolved.contains(d.sender)
            })
            .collect();
        if candidates.is_empty() {
            return vec![];
        }
        let items: Vec<ed25519::Item<'_>> = candidates
            .iter()
            .map(|d| d.batch_item(&self.keyring))
            .collect();
        let started = Instant::now();
        let bad = ed25519::verify_batch(&items).err().unwrap_or_default();
        ctx.metrics.verified(items.len() as u64, started.elapsed());
        let mut learned = Vec::new();
        for (i, d) in candidates.into_iter().enumerate() {
            if bad.contains(&i) || !self.unresolved.remove(d.sender) {
                continue;
            }
            self.entries[usize::from(d.sender)] = Some(d.clone());
            self.stats.learned += 1;
            learned.push(d);
        }
        learned
    }
}

impl RoundMachine for LearnOrExpose {
    type Msg = LoeMsg;
    type Output = VerifiableVector;

    /// Lines 3-5: broadcast every disclosure we hold.
    fn start(&mut self, _ctx: &mut Ctx) -> Vec<Outgoing<LoeMsg>> {
        self.entries
            .iter()
            .flatten()
            .map(|d| Outgoing::all(LoeMsg::Disclose(d.clone())))
            .collect()
    }

    fn end_round(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, LoeMsg)>,
    ) -> Vec<Outgoing<LoeMsg>> {
        if self.halted || self.finished {
            return vec![];
        }
        let r0 = *self.first_round.get_or_insert(round);
        let r = round - r0 + 1; // Algorithm 2's round, 1..=R
        let me = self.keys.id;
        let params = self.keyring.params;

        let mut accs = Vec::new();
        let mut discs = Vec::new();
        for (_, msg) in inbox {
            match msg {
                LoeMsg::Accuse(a) => accs.push(a),
                LoeMsg::Disclose(d) => discs.push(d),
            }
        }
        let mut out: Vec<Outgoing<LoeMsg>> = Vec::new();
        for a in self.take_accusations(ctx, accs) {
            out.push(Outgoing::all(LoeMsg::Accuse(a)));
        }
        for d in self.take_disclosures(ctx, discs) {
            out.push(Outgoing::all(LoeMsg::Disclose(d)));
        }

        // Line 16: G = MakeGraph(Acc). Lines 17-19: expose the disconnected.
        let graph = self.acc.graph(params);
        let reach = graph.component(me);
        for j in self.unresolved.iter().collect::<Vec<_>>() {
            if !reach.contains(j) {
                self.unresolved.remove(j);
                self.stats.exposed += 1;
            }
        }
        if self.unresolved.is_empty() {
            self.stats.resolved_round.get_or_insert(r);
        }

        if r >= self.rounds {
            // End of the instance: output, and nothing more is sent.
            self.finished = true;
            if self.unresolved.is_empty() {
                self.output = Some(VerifiableVector {
                    entries: self.entries.clone(),
                    proof: self.acc.aggregate(),
                });
                ctx.metrics.decided(round);
            } else {
                tracing::error!(
                    node = me,
                    unresolved = ?self.unresolved,
                    "LearnOrExpose ended with unresolved parties: synchrony or the bound on t was violated"
                );
            }
            return vec![];
        }

        // Lines 25-29: accuse the frontier.
        if !self.unresolved.is_empty() {
            let mut frontier = NodeSet::empty(params.n);
            for j in self.unresolved.iter() {
                let mut near = graph.neighbors(me).clone();
                near.intersect_with(&graph.ball(j, r - 1));
                frontier.union_with(&near);
            }
            for x in frontier.iter() {
                let a = Accusation::sign(&self.keys, self.keyring.run_id, x);
                if self.acc.insert(&a) {
                    self.stats.accusations_sent += 1;
                    self.stats.accusations_added += 1;
                    out.push(Outgoing::all(LoeMsg::Accuse(a)));
                }
            }
        }
        out
    }

    fn output(&self) -> Option<&VerifiableVector> {
        self.output.as_ref()
    }

    fn halt(&mut self) {
        self.halted = true;
    }

    fn is_halted(&self) -> bool {
        self.halted
    }
}
