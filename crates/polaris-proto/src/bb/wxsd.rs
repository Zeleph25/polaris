//! The Wan-Xiao-Shi-Devadas broadcast (TCC 2020): expected constant
//! epochs under a dishonest majority, built on a trust graph.
//!
//! Every node keeps a trust graph of the instance: the complete graph minus
//! the accused edges (an accusation `a -> b` is `a` distrusting `b`), minus
//! every edge of a node proven to have equivocated, pruned with the closed
//! neighborhood rule of [`crate::trust_graph`]. The nodes "in `u`'s graph"
//! are those connected to `u`. Honest nodes always form a clique, every
//! honest graph has diameter at most `d = ceil(2n / (n - t))`, and an honest
//! graph at the end of a round is a subgraph of every honest graph at the
//! end of the previous round, because everything is forwarded.
//!
//! TrustCast: a sender sends a signed message to all at the start of round
//! 1; every node forwards the first well-formed message it sees from each
//! sender. At the end of round `r = 1..=d`, a node that holds no valid
//! message from a sender `s` still in its graph distrusts every neighbor at
//! distance less than `r` from `s`. After round `d`, either the node holds a
//! valid message from `s` or `s` has left its graph, and an honest node never
//! distrusts an honest one. Each phase here is `d` such rounds plus one
//! settling round, so that forwards and distrusts made in round `d` reach
//! everyone before the next phase's messages are formed.
//!
//! An epoch is three phases. Propose: the leader (the sender in epoch 1, a
//! PRF choice after) TrustCasts a value with the freshest commit evidence it
//! has seen, or the bottom value with no evidence. Vote: a node TrustCasts a
//! vote for the proposed value's digest if the leader is still in its graph,
//! and an abstention otherwise. Commit: if every node in its graph voted for
//! the same digest, the node outputs that value and TrustCasts a commit
//! carrying those votes as evidence; otherwise it TrustCasts an empty commit.
//! A node terminates once everyone in its graph has sent a commit with valid
//! evidence for one digest; honest nodes terminate within one round of each
//! other, so `Delta_sim = 1`.
//!
//! Differences from the paper, all deliberate: values instead of bits, with
//! the digest in votes and evidence and the value only in proposals; the
//! bottom value where the paper's leader proposes a random bit; and the
//! freshness a proposal's evidence is checked against is the evidence a node
//! had seen one round before the end of the previous Commit phase, so that
//! an honest leader's knowledge always covers it (see `docs/design.md`).

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use polaris_core::{Ctx, NodeId, NodeSet, Outgoing, Round, RoundMachine, wire};
use polaris_crypto::bls::{self, MultiSig};
use polaris_crypto::domain;
use polaris_crypto::ed25519::{self, Item, Sig};
use polaris_crypto::hash::{self, Digest};
use polaris_crypto::keyring::{Keyring, NodeKeys};
use serde::{Deserialize, Serialize};

use super::Broadcast;
use crate::accusations::{self, Accusation, AccusationSet};
use crate::trust_graph::TrustGraph;

/// A proposed value; `None` is the bottom value a leader without evidence
/// proposes, which the broadcast then decides as bottom.
pub type Value = Option<Vec<u8>>;

pub type Epoch = u32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    pub from: NodeId,
    pub body: T,
    pub sig: Sig,
    /// A BLS signature on the same body, carried by votes when evidence is
    /// aggregated: the Ed25519 one still proves authorship cheaply and
    /// catches equivocation, this one goes into the multi-signature. Always
    /// on the wire (one byte when absent): postcard is not self-describing,
    /// so a skipped field cannot be decoded.
    pub bls: Option<bls::Sig>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub epoch: Epoch,
    pub value: Value,
    pub evidence: Option<Evidence>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ballot {
    /// The leader has left the voter's graph.
    Abstain,
    For(Digest),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub epoch: Epoch,
    pub ballot: Ballot,
}

/// Votes for one digest in one epoch from every node in the committer's
/// graph; valid at a receiver if they cover the receiver's graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub epoch: Epoch,
    pub digest: Digest,
    pub proof: VoteProof,
}

/// The paper's evidence is the signed votes themselves; aggregated, it is
/// one BLS multi-signature on the vote body plus the signer set, about a
/// hundred bytes whatever `n`, verified in one pairing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteProof {
    Individual(Vec<Signed<Vote>>),
    Aggregate(MultiSig),
}

impl Evidence {
    pub fn voters(&self, n: usize) -> Option<NodeSet> {
        match &self.proof {
            VoteProof::Individual(votes) => {
                let mut voters = NodeSet::empty(n);
                for v in votes {
                    if usize::from(v.from) >= n || !voters.insert(v.from) {
                        return None;
                    }
                }
                Some(voters)
            }
            VoteProof::Aggregate(ms) => (ms.signers.universe() == n).then(|| ms.signers.clone()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub epoch: Epoch,
    pub evidence: Option<Evidence>,
}

/// Two signed messages of one type and epoch from one node with different
/// bodies: proof that removes the node from every honest graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Equivocation {
    Propose(Signed<Proposal>, Signed<Proposal>),
    Vote(Signed<Vote>, Signed<Vote>),
    Commit(Signed<Commit>, Signed<Commit>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WxsdMsg {
    Propose(Signed<Proposal>),
    Vote(Signed<Vote>),
    Commit(Signed<Commit>),
    Accuse(Accusation),
    Equivocation(Box<Equivocation>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WxsdConfig {
    /// Epochs run at most; a run that exhausts them decides bottom.
    pub max_epochs: Epoch,
    /// Sign votes with BLS as well and send commit evidence as one
    /// multi-signature instead of the votes themselves.
    pub aggregate_votes: bool,
}

impl Default for WxsdConfig {
    fn default() -> Self {
        Self {
            max_epochs: 64,
            aggregate_votes: false,
        }
    }
}

impl WxsdConfig {
    pub fn aggregated(mut self) -> Self {
        self.aggregate_votes = true;
        self
    }
}

/// What happened in one instance, for tests and metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WxsdStats {
    pub epochs: Epoch,
    /// Epoch in which this node first output a value.
    pub committed_in: Option<Epoch>,
    pub accusations_sent: u64,
    pub equivocations_found: u64,
}

pub fn value_digest(instance: u64, value: &Value) -> Digest {
    hash::digest(
        domain::WXSD_VALUE,
        &wire::encode(&(instance, value)).expect("encodes"),
    )
}

/// What a signature covers: the instance and the body.
fn signing_body<T: Serialize>(instance: u64, body: &T) -> Vec<u8> {
    wire::encode(&(instance, body)).expect("encodes")
}

pub fn sign<T: Serialize>(
    keys: &NodeKeys,
    run_id: u64,
    instance: u64,
    tag: &[u8],
    body: T,
) -> Signed<T> {
    let sig = ed25519::sign(&keys.ed25519, tag, run_id, &signing_body(instance, &body));
    Signed {
        from: keys.id,
        body,
        sig,
        bls: None,
    }
}

/// A vote with both signatures, for aggregated evidence.
pub fn sign_vote_bls(keys: &NodeKeys, run_id: u64, instance: u64, body: Vote) -> Signed<Vote> {
    let mut v = sign(keys, run_id, instance, domain::WXSD_VOTE, body);
    v.bls = Some(
        keys.bls
            .sign(domain::WXSD_VOTE, run_id, &signing_body(instance, &body)),
    );
    v
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Propose,
    Vote,
    Commit,
}

/// Where the instance is: epoch, phase, and the round within the phase
/// (`1..=phase_len`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Clock {
    epoch: Epoch,
    phase: Phase,
    round: u32,
}

impl std::fmt::Debug for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Phase::Propose => "propose",
            Phase::Vote => "vote",
            Phase::Commit => "commit",
        })
    }
}

/// The first signed message seen from each node in one epoch, per type,
/// and whether it has passed `Vf` yet.
#[derive(Default)]
struct EpochState {
    proposal: Option<Signed<Proposal>>,
    proposal_ok: bool,
    votes: Vec<Option<Signed<Vote>>>,
    votes_ok: Vec<bool>,
    comms: Vec<Option<Signed<Commit>>>,
    comms_ok: Vec<bool>,
    /// The digest a node's commit carries valid evidence for.
    comm_evidence: Vec<Option<Digest>>,
}

impl EpochState {
    fn new(n: usize) -> Self {
        Self {
            votes: vec![None; n],
            votes_ok: vec![false; n],
            comms: vec![None; n],
            comms_ok: vec![false; n],
            comm_evidence: vec![None; n],
            ..Default::default()
        }
    }
}

pub struct Wxsd {
    keyring: Arc<Keyring>,
    keys: Arc<NodeKeys>,
    sender: NodeId,
    instance: u64,
    input: Option<Vec<u8>>,
    config: WxsdConfig,
    /// `d`: check rounds per TrustCast; a phase is `d + 1` rounds.
    d: u32,
    first_round: Option<Round>,

    acc: AccusationSet,
    removed: NodeSet,
    graph: TrustGraph,
    /// The nodes connected to this one.
    trusted: NodeSet,
    /// Digests of signed messages whose signature has been checked.
    verified: HashSet<Digest>,
    /// Digests of messages already forwarded once.
    forwarded: HashSet<Digest>,

    epochs: BTreeMap<Epoch, EpochState>,
    /// Values by digest, learned from accepted proposals.
    values: BTreeMap<Digest, Value>,
    /// The freshest valid commit evidence seen.
    best: Option<Evidence>,
    /// Epoch of `best` one round before the end of the last Commit phase;
    /// a proposal's evidence must be at least this fresh.
    floor: Epoch,

    committed: Option<Digest>,
    output: Option<Value>,
    halted: bool,
    stats: WxsdStats,
}

impl Wxsd {
    /// `input` is `Some` at the sender only.
    pub fn new(
        keyring: Arc<Keyring>,
        keys: Arc<NodeKeys>,
        sender: NodeId,
        instance: u64,
        input: Option<Vec<u8>>,
        config: WxsdConfig,
    ) -> Self {
        let n = keyring.n();
        let params = keyring.params;
        Self {
            d: params.diameter_bound(),
            acc: AccusationSet::new(n),
            removed: NodeSet::empty(n),
            graph: TrustGraph::complete(params),
            trusted: NodeSet::full(n),
            verified: HashSet::new(),
            forwarded: HashSet::new(),
            epochs: BTreeMap::new(),
            values: BTreeMap::new(),
            best: None,
            floor: 0,
            committed: None,
            output: None,
            halted: false,
            stats: WxsdStats::default(),
            first_round: None,
            keyring,
            keys,
            sender,
            instance,
            input,
            config,
        }
    }

    pub fn stats(&self) -> &WxsdStats {
        &self.stats
    }

    pub fn trusted(&self) -> &NodeSet {
        &self.trusted
    }

    /// Rounds per phase.
    pub fn phase_len(&self) -> u32 {
        self.d + 1
    }

    pub fn epoch_len(&self) -> u32 {
        3 * self.phase_len()
    }

    pub fn leader(&self, epoch: Epoch) -> NodeId {
        if epoch == 1 {
            return self.sender;
        }
        let mut input = self.instance.to_le_bytes().to_vec();
        input.extend_from_slice(&epoch.to_le_bytes());
        self.keyring
            .prf()
            .leader_of(domain::WXSD_LEADER_PRF, &input, self.keyring.n())
    }

    fn clock(&self, round: Round) -> Clock {
        let k = round - self.first_round.expect("started");
        let l = self.phase_len();
        let epoch = k / self.epoch_len() + 1;
        let within = k % self.epoch_len();
        let phase = match within / l {
            0 => Phase::Propose,
            1 => Phase::Vote,
            _ => Phase::Commit,
        };
        Clock {
            epoch,
            phase,
            round: within % l + 1,
        }
    }

    fn n(&self) -> usize {
        self.keyring.n()
    }

    fn me(&self) -> NodeId {
        self.keys.id
    }

    fn digest_of<T: Serialize>(msg: &T) -> Digest {
        hash::digest(b"polaris/wxsd/seen", &wire::encode(msg).expect("encodes"))
    }

    fn rebuild_graph(&mut self) {
        let mut g = self.acc.graph(self.keyring.params);
        for v in self.removed.iter() {
            g.remove_node(v);
        }
        g.prune();
        self.trusted = g.component(self.me());
        self.graph = g;
    }

    fn remove_node(&mut self, v: NodeId) {
        if self.removed.insert(v) {
            self.stats.equivocations_found += 1;
        }
    }

    /// Signs `me -> v` if the edge still stands; returns the accusation to send.
    fn distrust(&mut self, v: NodeId) -> Option<Accusation> {
        if v == self.me() || self.acc.contains(self.me(), v) {
            return None;
        }
        let a = Accusation::sign(&self.keys, self.keyring.run_id, v);
        self.acc.insert(&a);
        self.stats.accusations_sent += 1;
        Some(a)
    }

    /// Checks a signature once per distinct message.
    fn check_signed<T: Serialize>(&mut self, ctx: &mut Ctx, tag: &[u8], msg: &Signed<T>) -> bool {
        if usize::from(msg.from) >= self.n() {
            return false;
        }
        let key = Self::digest_of(&(tag, msg));
        if self.verified.contains(&key) {
            return true;
        }
        let started = Instant::now();
        let ok = ed25519::verify(
            self.keyring.ed25519(msg.from),
            tag,
            self.keyring.run_id,
            &signing_body(self.instance, &msg.body),
            &msg.sig,
        );
        ctx.metrics.verified(1, started.elapsed());
        if ok {
            self.verified.insert(key);
        }
        ok
    }

    /// Evidence for `(epoch, digest)` is valid here if its votes are distinct,
    /// correctly signed votes for that digest in that epoch, and cover every
    /// node in this node's graph.
    fn evidence_valid(&mut self, ctx: &mut Ctx, e: &Evidence) -> bool {
        let n = self.n();
        let Some(voters) = e.voters(n) else {
            return false;
        };
        if !self.trusted.is_subset(&voters) {
            return false;
        }
        let key = Self::digest_of(&("evidence", e));
        if self.verified.contains(&key) {
            return true;
        }
        let expected = Vote {
            epoch: e.epoch,
            ballot: Ballot::For(e.digest),
        };
        let started = Instant::now();
        let (ok, count) = match &e.proof {
            VoteProof::Individual(votes) => {
                if votes.iter().any(|v| v.body != expected) {
                    return false;
                }
                let bodies: Vec<Vec<u8>> = votes
                    .iter()
                    .map(|v| signing_body(self.instance, &v.body))
                    .collect();
                let items: Vec<Item<'_>> = votes
                    .iter()
                    .zip(&bodies)
                    .map(|(v, body)| Item {
                        pk: self.keyring.ed25519(v.from),
                        tag: domain::WXSD_VOTE,
                        run_id: self.keyring.run_id,
                        body,
                        sig: &v.sig,
                    })
                    .collect();
                (ed25519::verify_batch(&items).is_ok(), items.len())
            }
            VoteProof::Aggregate(ms) => (
                ms.verify(
                    self.keyring.bls_keys(),
                    domain::WXSD_VOTE,
                    self.keyring.run_id,
                    &signing_body(self.instance, &expected),
                ),
                1,
            ),
        };
        ctx.metrics.verified(count as u64, started.elapsed());
        if ok {
            self.verified.insert(key);
        }
        ok
    }

    /// Checks the BLS parts of this round's votes, one pairing per distinct
    /// body with a one-by-one fallback, so that a garbage part never
    /// reaches an aggregate. Returns which votes are usable.
    fn check_bls_votes(&mut self, ctx: &mut Ctx, votes: &[Signed<Vote>]) -> Vec<bool> {
        let n = self.n();
        let mut ok = vec![false; votes.len()];
        let mut groups: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
        for (i, v) in votes.iter().enumerate() {
            let key = Self::digest_of(&("bls", v));
            if self.verified.contains(&key) {
                ok[i] = true;
            } else if v.bls.is_some() {
                groups
                    .entry(signing_body(self.instance, &v.body))
                    .or_default()
                    .push(i);
            }
        }
        let started = Instant::now();
        let mut count = 0u64;
        for (body, idxs) in groups {
            let parts = idxs
                .iter()
                .map(|&i| (votes[i].from, votes[i].bls.expect("grouped with a part")));
            let batch_ok = idxs.len() > 1
                && MultiSig::aggregate(n, parts).is_ok_and(|ms| {
                    ms.verify(
                        self.keyring.bls_keys(),
                        domain::WXSD_VOTE,
                        self.keyring.run_id,
                        &body,
                    )
                });
            count += 1;
            for i in idxs {
                let v = &votes[i];
                let single = || {
                    self.keyring.bls(v.from).verify(
                        domain::WXSD_VOTE,
                        self.keyring.run_id,
                        &body,
                        &v.bls.expect("grouped with a part"),
                    )
                };
                if batch_ok || single() {
                    ok[i] = true;
                    self.verified.insert(Self::digest_of(&("bls", v)));
                } else {
                    count += 1;
                }
            }
        }
        ctx.metrics.verified(count, started.elapsed());
        ok
    }

    /// Whether a vote's BLS part passed this round's batch check.
    fn bls_ok(&self, v: &Signed<Vote>) -> bool {
        self.verified.contains(&Self::digest_of(&("bls", v)))
    }

    fn note_evidence(&mut self, e: &Evidence) {
        if self.best.as_ref().is_none_or(|b| e.epoch > b.epoch) {
            self.best = Some(e.clone());
        }
    }

    /// Records the first signed message of its kind from `msg.from` in its
    /// epoch, or produces equivocation evidence if a different one is
    /// already recorded. Returns whether the message is new.
    fn record<T>(
        slot: &mut Option<Signed<T>>,
        msg: &Signed<T>,
        equivocation: impl FnOnce(Signed<T>, Signed<T>) -> Equivocation,
    ) -> (bool, Option<Equivocation>)
    where
        T: Clone + PartialEq,
    {
        match slot {
            None => {
                *slot = Some(msg.clone());
                (true, None)
            }
            Some(first) if first.body == msg.body => (false, None),
            Some(first) => (false, Some(equivocation(first.clone(), msg.clone()))),
        }
    }

    fn equivocation_verifies(&mut self, ctx: &mut Ctx, eq: &Equivocation) -> Option<NodeId> {
        let (from, ok) = match eq {
            Equivocation::Propose(a, b) => (
                a.from,
                a.from == b.from
                    && a.body.epoch == b.body.epoch
                    && a.body != b.body
                    && self.check_signed(ctx, domain::WXSD_PROPOSE, a)
                    && self.check_signed(ctx, domain::WXSD_PROPOSE, b),
            ),
            Equivocation::Vote(a, b) => (
                a.from,
                a.from == b.from
                    && a.body.epoch == b.body.epoch
                    && a.body != b.body
                    && self.check_signed(ctx, domain::WXSD_VOTE, a)
                    && self.check_signed(ctx, domain::WXSD_VOTE, b),
            ),
            Equivocation::Commit(a, b) => (
                a.from,
                a.from == b.from
                    && a.body.epoch == b.body.epoch
                    && a.body != b.body
                    && self.check_signed(ctx, domain::WXSD_COMMIT, a)
                    && self.check_signed(ctx, domain::WXSD_COMMIT, b),
            ),
        };
        ok.then_some(from)
    }

    fn epoch_relevant(&self, clock: Clock, epoch: Epoch) -> bool {
        epoch == clock.epoch || epoch + 1 == clock.epoch
    }

    /// `Vf_prop` at this node.
    fn proposal_ok(&mut self, ctx: &mut Ctx, p: &Signed<Proposal>) -> bool {
        if p.from != self.leader(p.body.epoch) {
            return false;
        }
        let digest = value_digest(self.instance, &p.body.value);
        match &p.body.evidence {
            None => self.floor == 0,
            Some(e) => {
                e.epoch < p.body.epoch
                    && e.epoch >= self.floor
                    && e.digest == digest
                    && self.evidence_valid(ctx, &e.clone())
            }
        }
    }

    /// `Vf_vote`: anything once the leader is gone, else a vote for the
    /// accepted proposal.
    fn vote_ok(&self, v: &Signed<Vote>, leader: NodeId, accepted: Option<Digest>) -> bool {
        if !self.trusted.contains(leader) {
            return true;
        }
        matches!((v.body.ballot, accepted), (Ballot::For(x), Some(y)) if x == y)
    }

    /// `Vf_comm`, and the digest the commit's evidence is valid for.
    fn commit_ok(
        &mut self,
        ctx: &mut Ctx,
        c: &Signed<Commit>,
        leader: NodeId,
        accepted: Option<Digest>,
    ) -> (bool, Option<Digest>) {
        let valid_for = match &c.body.evidence {
            Some(e) if e.epoch == c.body.epoch && self.evidence_valid(ctx, &e.clone()) => {
                self.note_evidence(e);
                Some(e.digest)
            }
            _ => None,
        };
        if !self.trusted.contains(leader) {
            return (true, valid_for);
        }
        (valid_for.is_some() && valid_for == accepted, valid_for)
    }

    fn accepted_digest(&self, epoch: Epoch) -> Option<Digest> {
        let st = self.epochs.get(&epoch)?;
        let p = st.proposal.as_ref()?;
        st.proposal_ok
            .then(|| value_digest(self.instance, &p.body.value))
    }

    /// Re-evaluates `Vf` on every recorded message of `epoch` not yet
    /// accepted; returns the newly accepted ones to forward.
    fn evaluate(&mut self, ctx: &mut Ctx, epoch: Epoch) {
        let leader = self.leader(epoch);
        let Some(st) = self.epochs.get(&epoch) else {
            return;
        };
        if !st.proposal_ok
            && let Some(p) = st.proposal.clone()
            && self.proposal_ok(ctx, &p)
        {
            if let Some(e) = &p.body.evidence {
                self.note_evidence(e);
            }
            self.values.insert(
                value_digest(self.instance, &p.body.value),
                p.body.value.clone(),
            );
            self.epochs.get_mut(&epoch).expect("exists").proposal_ok = true;
        }
        let accepted = self.accepted_digest(epoch);
        let st = self.epochs.get(&epoch).expect("exists");
        let pending_votes: Vec<Signed<Vote>> = st
            .votes
            .iter()
            .zip(&st.votes_ok)
            .filter_map(|(v, ok)| if *ok { None } else { v.clone() })
            .collect();
        for v in pending_votes {
            if self.vote_ok(&v, leader, accepted) {
                self.epochs.get_mut(&epoch).expect("exists").votes_ok[usize::from(v.from)] = true;
            }
        }
        let st = self.epochs.get(&epoch).expect("exists");
        let pending_comms: Vec<Signed<Commit>> = st
            .comms
            .iter()
            .zip(&st.comms_ok)
            .filter_map(|(c, ok)| if *ok { None } else { c.clone() })
            .collect();
        for c in pending_comms {
            let (ok, valid_for) = self.commit_ok(ctx, &c, leader, accepted);
            let st = self.epochs.get_mut(&epoch).expect("exists");
            let i = usize::from(c.from);
            st.comm_evidence[i] = valid_for;
            if ok {
                st.comms_ok[i] = true;
            }
        }
    }

    /// The TrustCast check of round `r` for every sender of the phase.
    fn trustcast_check(&mut self, clock: Clock, out: &mut Vec<Outgoing<WxsdMsg>>) {
        let n = self.n();
        let st = self
            .epochs
            .entry(clock.epoch)
            .or_insert_with(|| EpochState::new(n));
        let missing: Vec<NodeId> = match clock.phase {
            Phase::Propose => (!st.proposal_ok)
                .then_some(self.leader(clock.epoch))
                .into_iter()
                .collect(),
            Phase::Vote => (0..n as NodeId)
                .filter(|&s| !st.votes_ok[usize::from(s)])
                .collect(),
            Phase::Commit => (0..n as NodeId)
                .filter(|&s| !st.comms_ok[usize::from(s)])
                .collect(),
        };
        let me = self.me();
        let mut doomed = NodeSet::empty(n);
        for s in missing {
            if !self.trusted.contains(s) {
                continue;
            }
            let dist = self.graph.distances_from(s);
            for v in self.graph.neighbors(me).iter() {
                if dist[usize::from(v)].is_some_and(|k| k < clock.round) {
                    doomed.insert(v);
                }
            }
        }
        for v in doomed.iter() {
            if let Some(a) = self.distrust(v) {
                out.push(Outgoing::all(WxsdMsg::Accuse(a)));
            }
        }
    }

    fn propose(&mut self, epoch: Epoch) -> WxsdMsg {
        let (value, evidence) = if epoch == 1 {
            (self.input.take(), None)
        } else {
            match self.best.clone() {
                Some(e) => (self.values.get(&e.digest).cloned().unwrap_or(None), Some(e)),
                None => (None, None),
            }
        };
        let body = Proposal {
            epoch,
            value,
            evidence,
        };
        WxsdMsg::Propose(sign(
            &self.keys,
            self.keyring.run_id,
            self.instance,
            domain::WXSD_PROPOSE,
            body,
        ))
    }

    fn vote(&mut self, epoch: Epoch) -> WxsdMsg {
        let leader = self.leader(epoch);
        let ballot = match self.accepted_digest(epoch) {
            Some(x) if self.trusted.contains(leader) => Ballot::For(x),
            _ => Ballot::Abstain,
        };
        let body = Vote { epoch, ballot };
        WxsdMsg::Vote(if self.config.aggregate_votes {
            sign_vote_bls(&self.keys, self.keyring.run_id, self.instance, body)
        } else {
            sign(
                &self.keys,
                self.keyring.run_id,
                self.instance,
                domain::WXSD_VOTE,
                body,
            )
        })
    }

    fn commit(&mut self, epoch: Epoch) -> WxsdMsg {
        let st = self.epochs.get(&epoch).expect("exists");
        let mut common: Option<Digest> = None;
        let mut unanimous = true;
        let mut votes = Vec::new();
        for v in self.trusted.iter() {
            let i = usize::from(v);
            match (&st.votes[i], st.votes_ok[i]) {
                (Some(sv), true) => match (sv.body.ballot, common) {
                    (Ballot::For(x), None) => {
                        common = Some(x);
                        votes.push(sv.clone());
                    }
                    (Ballot::For(x), Some(y)) if x == y => votes.push(sv.clone()),
                    _ => unanimous = false,
                },
                _ => unanimous = false,
            }
        }
        let proof = if self.config.aggregate_votes {
            let n = self.n();
            MultiSig::aggregate(n, votes.iter().filter_map(|v| v.bls.map(|s| (v.from, s))))
                .ok()
                .filter(|ms| ms.signers.count() == votes.len())
                .map(VoteProof::Aggregate)
        } else {
            Some(VoteProof::Individual(votes))
        };
        let evidence = match (common, proof) {
            (Some(digest), Some(proof)) if unanimous && self.values.contains_key(&digest) => {
                let e = Evidence {
                    epoch,
                    digest,
                    proof,
                };
                if self.committed.is_none() {
                    self.committed = Some(digest);
                    self.stats.committed_in = Some(epoch);
                }
                self.note_evidence(&e);
                Some(e)
            }
            _ => None,
        };
        WxsdMsg::Commit(sign(
            &self.keys,
            self.keyring.run_id,
            self.instance,
            domain::WXSD_COMMIT,
            Commit { epoch, evidence },
        ))
    }

    /// Everyone in the graph has committed with valid evidence for one digest.
    fn terminated(&self, epoch: Epoch) -> Option<Digest> {
        let st = self.epochs.get(&epoch)?;
        let mut digest = None;
        for v in self.trusted.iter() {
            let d = st.comm_evidence[usize::from(v)]?;
            match digest {
                None => digest = Some(d),
                Some(x) if x != d => return None,
                _ => {}
            }
        }
        digest
    }

    fn forward(&mut self, msg: WxsdMsg, out: &mut Vec<Outgoing<WxsdMsg>>) {
        if self.forwarded.insert(Self::digest_of(&msg)) {
            out.push(Outgoing::all(msg));
        }
    }
}

impl RoundMachine for Wxsd {
    type Msg = WxsdMsg;
    type Output = Value;

    fn start(&mut self, _ctx: &mut Ctx) -> Vec<Outgoing<WxsdMsg>> {
        if self.me() == self.sender && self.input.is_some() {
            let msg = self.propose(1);
            vec![Outgoing::all(msg)]
        } else {
            vec![]
        }
    }

    fn end_round(
        &mut self,
        ctx: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, WxsdMsg)>,
    ) -> Vec<Outgoing<WxsdMsg>> {
        if self.halted || self.output.is_some() {
            return vec![];
        }
        self.first_round.get_or_insert(round);
        let clock = self.clock(round);
        self.stats.epochs = clock.epoch;
        let n = self.n();
        self.epochs
            .entry(clock.epoch)
            .or_insert_with(|| EpochState::new(n));
        let mut out = Vec::new();

        // Graph messages first: accusations in one batch, then equivocations.
        let mut accs = Vec::new();
        let mut signed = Vec::new();
        for (_, msg) in inbox {
            match msg {
                WxsdMsg::Accuse(a) => accs.push(a),
                WxsdMsg::Equivocation(eq) => {
                    if let Some(v) = self.equivocation_verifies(ctx, &eq) {
                        self.remove_node(v);
                        self.forward(WxsdMsg::Equivocation(eq), &mut out);
                    }
                }
                other => signed.push(other),
            }
        }
        if !accs.is_empty() {
            let started = Instant::now();
            let ok = accusations::verify_many(&self.keyring, &accs);
            ctx.metrics.verified(accs.len() as u64, started.elapsed());
            for (a, ok) in accs.into_iter().zip(ok) {
                if ok && self.acc.insert(&a) {
                    self.forward(WxsdMsg::Accuse(a), &mut out);
                }
            }
        }

        // Votes' BLS parts, one pairing per distinct body for the round.
        if self.config.aggregate_votes {
            let votes: Vec<Signed<Vote>> = signed
                .iter()
                .filter_map(|m| match m {
                    WxsdMsg::Vote(v) if self.epoch_relevant(clock, v.body.epoch) => Some(v.clone()),
                    _ => None,
                })
                .collect();
            let authentic: Vec<Signed<Vote>> = votes
                .into_iter()
                .filter(|v| self.check_signed(ctx, domain::WXSD_VOTE, v))
                .collect();
            self.check_bls_votes(ctx, &authentic);
        }

        // Signed protocol messages: record the first body per node and type,
        // turn a second one into equivocation evidence.
        for msg in signed {
            let (new, equivocation) = match &msg {
                WxsdMsg::Propose(p) => {
                    if !self.epoch_relevant(clock, p.body.epoch)
                        || p.from != self.leader(p.body.epoch)
                        || !self.check_signed(ctx, domain::WXSD_PROPOSE, p)
                    {
                        continue;
                    }
                    let st = self
                        .epochs
                        .entry(p.body.epoch)
                        .or_insert_with(|| EpochState::new(n));
                    Self::record(&mut st.proposal, p, Equivocation::Propose)
                }
                WxsdMsg::Vote(v) => {
                    if !self.epoch_relevant(clock, v.body.epoch)
                        || !self.check_signed(ctx, domain::WXSD_VOTE, v)
                        || (self.config.aggregate_votes && !self.bls_ok(v))
                    {
                        continue;
                    }
                    let st = self
                        .epochs
                        .entry(v.body.epoch)
                        .or_insert_with(|| EpochState::new(n));
                    Self::record(&mut st.votes[usize::from(v.from)], v, Equivocation::Vote)
                }
                WxsdMsg::Commit(c) => {
                    if !self.epoch_relevant(clock, c.body.epoch)
                        || !self.check_signed(ctx, domain::WXSD_COMMIT, c)
                    {
                        continue;
                    }
                    let st = self
                        .epochs
                        .entry(c.body.epoch)
                        .or_insert_with(|| EpochState::new(n));
                    Self::record(&mut st.comms[usize::from(c.from)], c, Equivocation::Commit)
                }
                WxsdMsg::Accuse(_) | WxsdMsg::Equivocation(_) => unreachable!("sorted out above"),
            };
            if new {
                self.forward(msg.clone(), &mut out);
            }
            if let Some(eq) = equivocation {
                let from = match &eq {
                    Equivocation::Propose(a, _) => a.from,
                    Equivocation::Vote(a, _) => a.from,
                    Equivocation::Commit(a, _) => a.from,
                };
                self.remove_node(from);
                self.forward(WxsdMsg::Equivocation(Box::new(eq)), &mut out);
            }
        }

        self.rebuild_graph();
        if clock.epoch > 1 {
            self.evaluate(ctx, clock.epoch - 1);
        }
        self.evaluate(ctx, clock.epoch);

        if clock.round <= self.d {
            self.trustcast_check(clock, &mut out);
            if !out.is_empty() {
                self.rebuild_graph();
            }
        }

        // Termination: this epoch's commits, or the previous epoch's that
        // arrived one round late.
        for epoch in [clock.epoch.saturating_sub(1), clock.epoch] {
            if epoch >= 1
                && let Some(digest) = self.terminated(epoch)
            {
                let value = self.values.get(&digest).cloned().unwrap_or_else(|| {
                    tracing::error!(node = self.me(), "terminated on a digest without its value");
                    None
                });
                self.output = Some(value);
                ctx.metrics.decided(round);
                return out;
            }
        }

        if clock.round == self.d && clock.phase == Phase::Commit {
            self.floor = self.best.as_ref().map_or(0, |e| e.epoch);
        }
        if clock.round == self.phase_len() {
            match clock.phase {
                Phase::Propose => {
                    let msg = self.vote(clock.epoch);
                    out.push(Outgoing::all(msg));
                }
                Phase::Vote => {
                    let msg = self.commit(clock.epoch);
                    out.push(Outgoing::all(msg));
                }
                Phase::Commit => {
                    let next = clock.epoch + 1;
                    if next > self.config.max_epochs {
                        tracing::error!(
                            node = self.me(),
                            epochs = clock.epoch,
                            "no termination within the epoch budget; deciding bottom"
                        );
                        self.output = Some(None);
                        ctx.metrics.decided(round);
                        return out;
                    }
                    self.epochs.remove(&clock.epoch.saturating_sub(1));
                    self.epochs.insert(next, EpochState::new(n));
                    if self.leader(next) == self.me() {
                        let msg = self.propose(next);
                        out.push(Outgoing::all(msg));
                    }
                }
            }
        }
        out
    }

    fn output(&self) -> Option<&Value> {
        self.output.as_ref()
    }

    fn halt(&mut self) {
        self.halted = true;
    }

    fn is_halted(&self) -> bool {
        self.halted
    }
}

impl Broadcast for Wxsd {
    fn sender(&self) -> NodeId {
        self.sender
    }

    fn termination_skew(&self) -> u32 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polaris_core::Params;
    use polaris_crypto::keyring;

    /// Every message type survives the wire in both evidence modes; the
    /// simulator passes messages by value, so only this catches a format
    /// that cannot be decoded.
    #[test]
    fn messages_round_trip_through_the_wire() {
        let (kr, keys) = keyring::generate(Params::new(4, 1).unwrap(), 7, 1);
        let digest = value_digest(3, &Some(b"v".to_vec()));
        let body = Vote {
            epoch: 1,
            ballot: Ballot::For(digest),
        };
        let plain = sign(&keys[0], kr.run_id, 3, domain::WXSD_VOTE, body);
        let with_bls = sign_vote_bls(&keys[1], kr.run_id, 3, body);
        let aggregate = MultiSig::aggregate(4, [(1, with_bls.bls.unwrap())]).unwrap();
        let msgs = vec![
            WxsdMsg::Vote(plain.clone()),
            WxsdMsg::Vote(with_bls.clone()),
            WxsdMsg::Propose(sign(
                &keys[0],
                kr.run_id,
                3,
                domain::WXSD_PROPOSE,
                Proposal {
                    epoch: 2,
                    value: Some(b"v".to_vec()),
                    evidence: Some(Evidence {
                        epoch: 1,
                        digest,
                        proof: VoteProof::Individual(vec![plain.clone()]),
                    }),
                },
            )),
            WxsdMsg::Commit(sign(
                &keys[2],
                kr.run_id,
                3,
                domain::WXSD_COMMIT,
                Commit {
                    epoch: 1,
                    evidence: Some(Evidence {
                        epoch: 1,
                        digest,
                        proof: VoteProof::Aggregate(aggregate),
                    }),
                },
            )),
            WxsdMsg::Accuse(Accusation::sign(&keys[0], kr.run_id, 2)),
            WxsdMsg::Equivocation(Box::new(Equivocation::Vote(plain, with_bls))),
        ];
        for m in msgs {
            let bytes = wire::encode(&m).unwrap();
            let back: WxsdMsg = wire::decode(&bytes).unwrap();
            assert_eq!(back, m);
        }
    }
}
