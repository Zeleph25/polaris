//! Algorithm 1: Interactive Consistency from one broadcast per view.
//!
//! Round 0: every node signs its input and sends the disclosure to all.
//! From round 1 on, a new view starts every `c` rounds. In view `v` the
//! leader `L_v = PRF(v) mod n` runs LearnOrExpose with everyone for `R`
//! rounds, then submits its verifiable vector to a broadcast of which it is
//! the sender. A node that receives a vector from view `v`'s broadcast
//! accepts it if `VerifyVec_out` holds at its own position. Views are
//! scanned in order: the first view whose broadcast delivers an accepted
//! vector decides, and the output is that vector's entries, bottom for the
//! exposed parties. After deciding, a node keeps running the views in
//! progress for `Delta_sim` more rounds (the broadcast's termination skew),
//! so that honest nodes still finishing get its messages, then halts.
//!
//! A view is skipped when its broadcast delivers bottom or a vector that
//! fails verification, which only a Byzantine leader can cause: an honest
//! leader always holds a vector that every honest node accepts. With an
//! honest leader in a view with probability at least `epsilon`, the number
//! of views to a decision is geometric.
//!
//! Every view's LearnOrExpose starts from the disclosures the node knows at
//! that point, which includes the ones learned in earlier views. The paper
//! starts each view from the round 0 candidates; knowing more signed
//! disclosures never hurts (the input vector is still `VerifyVec_in`-valid)
//! and spares work for views that start after a slow party has been learned.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use polaris_core::{Ctx, NodeId, Outgoing, Params, Round, RoundMachine, View, wire};
use polaris_crypto::keyring::{Keyring, NodeKeys};
use polaris_crypto::{ed25519, hex};
use serde::{Deserialize, Serialize};

use crate::accusations::{self, Accusation, AccusationSet};
use crate::bb::Broadcast;
use crate::bb::dolev_strong::DolevStrong;
use crate::bb::wxsd::{Wxsd, WxsdConfig};
use crate::disclosure::{Disclosure, Entries, VerifiableVector};
use crate::learn_or_expose::{LearnOrExpose, LoeMsg};

/// `c` and the view budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompilerConfig {
    /// Rounds between the starts of two consecutive views. The default is
    /// `R`, so that at most one LearnOrExpose instance runs at a time. `0`
    /// makes the views sequential: the next one starts only once the
    /// previous one's broadcast has delivered without a decision, which
    /// spares the work of views that never get used when the leader is
    /// honest and costs a whole view of latency when it is not.
    pub view_spacing: u32,
    /// Views started at most; a run that exhausts them never decides.
    pub max_views: View,
    /// Carry the accusations of every finished LearnOrExpose and broadcast
    /// instance into the next ones, so that a Byzantine node cut off once
    /// stays cut off, instead of every instance starting from the complete
    /// graph as in the paper. Each accusation is gossiped once at the run
    /// level when it is learned, which keeps every honest node's set within
    /// one round of every other's, the invariant seeded instances rely on.
    pub share_accusations: bool,
}

impl CompilerConfig {
    pub fn for_params(params: Params) -> Self {
        Self {
            view_spacing: params.loe_rounds(),
            max_views: View::MAX,
            share_accusations: false,
        }
    }

    pub fn sharing_accusations(mut self) -> Self {
        self.share_accusations = true;
        self
    }

    /// `c`, or `0` for sequential views.
    pub fn with_view_spacing(mut self, c: u32) -> Self {
        self.view_spacing = c;
        self
    }

    pub fn sequential(self) -> Self {
        self.with_view_spacing(0)
    }

    pub fn with_max_views(mut self, views: View) -> Self {
        self.max_views = views;
        self
    }
}

/// The compiler's wire message; `M` is the broadcast's message type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcMsg<M> {
    Disclose(Disclosure),
    Loe {
        view: View,
        msg: LoeMsg,
    },
    Bb {
        view: View,
        msg: M,
    },
    /// Run-level gossip of an accusation learned in a finished instance,
    /// when accusations are shared; forwarded once by every node.
    Accuse(Accusation),
}

/// The decided vector and the view it came from. Serializes the values as
/// hex strings (`null` for bottom) so that output files stay readable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IcOutput {
    pub view: View,
    #[serde(serialize_with = "hex_values")]
    pub values: Vec<Option<Vec<u8>>>,
}

pub(crate) fn hex_values<S: serde::Serializer>(
    values: &[Option<Vec<u8>>],
    s: S,
) -> Result<S::Ok, S::Error> {
    s.collect_seq(values.iter().map(|v| v.as_deref().map(hex::encode)))
}

/// What happened in one run, for tests and metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IcStats {
    pub views_started: u32,
    /// Views whose broadcast delivered bottom or an invalid vector.
    pub views_skipped: u32,
    /// Accusations this node signed in its LearnOrExpose instances.
    pub accusations_sent: u64,
}

/// Builds the broadcast of a view: `(sender, instance, input, accusations)`,
/// with the input `Some` at the sender only and the accusations to start
/// from (empty unless they are shared; ignored by a broadcast without a
/// trust graph).
pub type MakeBroadcast<B> = Box<dyn Fn(NodeId, u64, Option<Vec<u8>>, &AccusationSet) -> B + Send>;

enum Phase<B> {
    Loe(Box<LearnOrExpose>),
    Bb(B),
}

struct ViewState<B> {
    leader: NodeId,
    loe_start: Round,
    phase: Phase<B>,
}

pub struct Compiler<B: Broadcast> {
    keyring: Arc<Keyring>,
    keys: Arc<NodeKeys>,
    config: CompilerConfig,
    make_bb: MakeBroadcast<B>,
    /// `Delta_sim` of the broadcast in use.
    termination_skew: u32,
    input: Option<Vec<u8>>,
    /// Every disclosure this node holds; `VerifyVec_in` holds at all times.
    known: Entries,
    /// Accusations of finished instances, when they are shared.
    shared: AccusationSet,
    views: BTreeMap<View, ViewState<B>>,
    /// Delivered broadcasts, by view; `None` for a skipped view.
    results: BTreeMap<View, Option<VerifiableVector>>,
    /// The next view the ordered scan looks at.
    scan: View,
    first_round: Option<Round>,
    /// The sub-machines' context; its metrics are absorbed every round.
    sub: Ctx,
    output: Option<IcOutput>,
    halt_at: Option<Round>,
    halted: bool,
    stats: IcStats,
}

impl Compiler<DolevStrong> {
    pub fn with_dolev_strong(
        keyring: Arc<Keyring>,
        keys: Arc<NodeKeys>,
        config: CompilerConfig,
        input: Vec<u8>,
    ) -> Self {
        let (kr, ks) = (keyring.clone(), keys.clone());
        let make_bb: MakeBroadcast<DolevStrong> = Box::new(move |sender, instance, input, _| {
            DolevStrong::new(kr.clone(), ks.clone(), sender, instance, input)
        });
        Self::new(keyring, keys, config, make_bb, input)
    }
}

impl Compiler<Wxsd> {
    pub fn with_wxsd(
        keyring: Arc<Keyring>,
        keys: Arc<NodeKeys>,
        config: CompilerConfig,
        wxsd: WxsdConfig,
        input: Vec<u8>,
    ) -> Self {
        let (kr, ks) = (keyring.clone(), keys.clone());
        let make_bb: MakeBroadcast<Wxsd> = Box::new(move |sender, instance, input, acc| {
            Wxsd::new(kr.clone(), ks.clone(), sender, instance, input, wxsd)
                .with_accusations(acc.clone())
        });
        Self::new(keyring, keys, config, make_bb, input)
    }
}

impl<B: Broadcast> Compiler<B> {
    pub fn new(
        keyring: Arc<Keyring>,
        keys: Arc<NodeKeys>,
        config: CompilerConfig,
        make_bb: MakeBroadcast<B>,
        input: Vec<u8>,
    ) -> Self {
        let n = keyring.n();
        let sub = Ctx::new(keys.id, keyring.params, keyring.run_id);
        let termination_skew = make_bb(0, 0, None, &AccusationSet::new(n)).termination_skew();
        Self {
            keyring,
            keys,
            config,
            make_bb,
            termination_skew,
            input: Some(input),
            known: vec![None; n],
            shared: AccusationSet::new(n),
            views: BTreeMap::new(),
            results: BTreeMap::new(),
            scan: 1,
            first_round: None,
            sub,
            output: None,
            halt_at: None,
            halted: false,
            stats: IcStats::default(),
        }
    }

    pub fn stats(&self) -> &IcStats {
        &self.stats
    }

    pub fn leader(&self, view: View) -> NodeId {
        self.keyring.prf().leader(view, self.keyring.n())
    }

    /// Whether `view` starts at `round + 1`: round 0 is the disclosure
    /// round, view 1 starts at round 1, later views `c` rounds apart, or
    /// right after the previous view's broadcast when views are sequential.
    fn starts_next_round(&self, view: View, round: Round) -> bool {
        let since = round + 1 - self.first_round.expect("started");
        if view == 1 {
            return since == 1;
        }
        match self.config.view_spacing {
            0 => self.views.is_empty() && self.results.is_empty(),
            c => since >= 1 && (since - 1).is_multiple_of(c),
        }
    }

    /// Keeps the first valid disclosure per sender. Everything is verified
    /// before anything is kept, so a forgery that arrives first cannot
    /// shadow the real one.
    fn take_disclosures(&mut self, ctx: &mut Ctx, discs: Vec<Disclosure>) {
        let candidates: Vec<Disclosure> = discs
            .into_iter()
            .filter(|d| {
                usize::from(d.sender) < self.keyring.n()
                    && self.known[usize::from(d.sender)].is_none()
            })
            .collect();
        if candidates.is_empty() {
            return;
        }
        let items: Vec<ed25519::Item<'_>> = candidates
            .iter()
            .map(|d| d.batch_item(&self.keyring))
            .collect();
        let started = Instant::now();
        let bad = ed25519::verify_batch(&items).err().unwrap_or_default();
        ctx.metrics.verified(items.len() as u64, started.elapsed());
        for (i, d) in candidates.into_iter().enumerate() {
            let slot = &mut self.known[usize::from(d.sender)];
            if !bad.contains(&i) && slot.is_none() {
                *slot = Some(d);
            }
        }
    }

    fn learn_from(&mut self, entries: &Entries) {
        for (slot, e) in self.known.iter_mut().zip(entries) {
            if slot.is_none() && e.is_some() {
                *slot = e.clone();
            }
        }
    }

    fn start_view(&mut self, view: View, round: Round) -> Vec<Outgoing<IcMsg<B::Msg>>> {
        let leader = self.leader(view);
        let mut loe = if self.config.share_accusations {
            LearnOrExpose::with_accusations(
                self.keyring.clone(),
                self.keys.clone(),
                leader,
                self.known.clone(),
                self.shared.clone(),
            )
        } else {
            LearnOrExpose::new(
                self.keyring.clone(),
                self.keys.clone(),
                leader,
                self.known.clone(),
            )
        };
        let out = wrap_loe(view, loe.start(&mut self.sub));
        self.views.insert(
            view,
            ViewState {
                leader,
                loe_start: round + 1,
                phase: Phase::Loe(Box::new(loe)),
            },
        );
        self.stats.views_started += 1;
        out
    }

    /// `VerifyVec_out` at this node, on what the broadcast delivered.
    fn accept(&mut self, ctx: &mut Ctx, delivered: Option<Vec<u8>>) -> Option<VerifiableVector> {
        let bytes = delivered?;
        let vv: VerifiableVector = wire::decode(&bytes).ok()?;
        let started = Instant::now();
        let ok = vv.verify(self.keys.id, &self.keyring);
        let sigs =
            vv.entries.iter().flatten().count() + vv.proof.per_target.iter().flatten().count();
        ctx.metrics.verified(sigs as u64, started.elapsed());
        if ok {
            self.learn_from(&vv.entries);
            Some(vv)
        } else {
            None
        }
    }

    fn decide(&mut self, ctx: &mut Ctx, round: Round, view: View, vv: VerifiableVector) {
        self.output = Some(IcOutput {
            view,
            values: vv.entries.into_iter().map(|e| e.map(|d| d.value)).collect(),
        });
        ctx.metrics.decided(round);
        self.halt_at = Some(round + self.termination_skew);
    }
}

fn wrap_loe<M>(view: View, out: Vec<Outgoing<LoeMsg>>) -> Vec<Outgoing<IcMsg<M>>> {
    out.into_iter()
        .map(|o| Outgoing {
            to: o.to,
            msg: IcMsg::Loe { view, msg: o.msg },
        })
        .collect()
}

fn wrap_bb<M>(view: View, out: Vec<Outgoing<M>>) -> Vec<Outgoing<IcMsg<M>>> {
    out.into_iter()
        .map(|o| Outgoing {
            to: o.to,
            msg: IcMsg::Bb { view, msg: o.msg },
        })
        .collect()
}

impl<B: Broadcast> RoundMachine for Compiler<B> {
    type Msg = IcMsg<B::Msg>;
    type Output = IcOutput;

    fn start(&mut self, _ctx: &mut Ctx) -> Vec<Outgoing<Self::Msg>> {
        let input = self.input.take().expect("start is called once");
        let d = Disclosure::sign(&self.keys, self.keyring.run_id, input);
        self.known[usize::from(self.keys.id)] = Some(d.clone());
        vec![Outgoing::all(IcMsg::Disclose(d))]
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
        self.first_round.get_or_insert(round);

        let mut discs = Vec::new();
        let mut accs = Vec::new();
        let mut loe_in: BTreeMap<View, Vec<(NodeId, LoeMsg)>> = BTreeMap::new();
        let mut bb_in: BTreeMap<View, Vec<(NodeId, B::Msg)>> = BTreeMap::new();
        for (from, msg) in inbox {
            match msg {
                IcMsg::Disclose(d) => discs.push(d),
                IcMsg::Accuse(a) => accs.push(a),
                IcMsg::Loe { view, msg } => loe_in.entry(view).or_default().push((from, msg)),
                IcMsg::Bb { view, msg } => bb_in.entry(view).or_default().push((from, msg)),
            }
        }
        self.take_disclosures(ctx, discs);

        let mut out = Vec::new();
        if self.config.share_accusations && !accs.is_empty() {
            let started = Instant::now();
            let ok = accusations::verify_many(&self.keyring, &accs);
            ctx.metrics.verified(accs.len() as u64, started.elapsed());
            for (a, ok) in accs.into_iter().zip(ok) {
                if ok && self.shared.insert(&a) {
                    out.push(Outgoing::all(IcMsg::Accuse(a)));
                }
            }
        }
        let loe_rounds = self.keyring.params.loe_rounds();
        let mut finished = Vec::new();
        let views: Vec<View> = self.views.keys().copied().collect();
        for view in views {
            let state = self.views.get_mut(&view).expect("listed");
            match &mut state.phase {
                Phase::Loe(loe) => {
                    let inbox = loe_in.remove(&view).unwrap_or_default();
                    out.extend(wrap_loe(view, loe.end_round(&mut self.sub, round, inbox)));
                    if round + 1 == state.loe_start + loe_rounds {
                        let entries = loe.entries().clone();
                        let submit = (state.leader == self.keys.id)
                            .then(|| loe.output().map(|vv| wire::encode(vv).expect("encodes")))
                            .flatten();
                        self.stats.accusations_sent += loe.stats().accusations_sent;
                        if self.config.share_accusations {
                            for a in loe.accusations().iter() {
                                if self.shared.insert(&a) {
                                    out.push(Outgoing::all(IcMsg::Accuse(a)));
                                }
                            }
                        }
                        let mut bb =
                            (self.make_bb)(state.leader, u64::from(view), submit, &self.shared);
                        out.extend(wrap_bb(view, bb.start(&mut self.sub)));
                        state.phase = Phase::Bb(bb);
                        self.learn_from(&entries);
                    }
                }
                Phase::Bb(bb) => {
                    let inbox = bb_in.remove(&view).unwrap_or_default();
                    out.extend(wrap_bb(view, bb.end_round(&mut self.sub, round, inbox)));
                    if let Some(delivered) = bb.output() {
                        finished.push((view, delivered.clone()));
                        if self.config.share_accusations
                            && let Some(acc) = bb.accusations()
                        {
                            for a in acc.iter() {
                                if self.shared.insert(&a) {
                                    out.push(Outgoing::all(IcMsg::Accuse(a)));
                                }
                            }
                        }
                    }
                }
            }
        }
        for (view, delivered) in finished {
            self.views.remove(&view);
            let accepted = self.accept(ctx, delivered);
            if accepted.is_none() {
                self.stats.views_skipped += 1;
            }
            self.results.insert(view, accepted);
        }
        ctx.metrics.absorb(&mut self.sub.metrics);

        if self.output.is_none() {
            while let Some(result) = self.results.remove(&self.scan) {
                let view = self.scan;
                self.scan += 1;
                if let Some(vv) = result {
                    self.decide(ctx, round, view, vv);
                    break;
                }
            }
        }

        if self.output.is_none() {
            let next = self.stats.views_started + 1;
            if next <= self.config.max_views && self.starts_next_round(next, round) {
                out.extend(self.start_view(next, round));
            }
        }

        if self.halt_at.is_some_and(|h| round >= h) {
            self.halted = true;
            self.views.clear();
        }
        out
    }

    fn output(&self) -> Option<&IcOutput> {
        self.output.as_ref()
    }

    fn halt(&mut self) {
        self.halted = true;
    }

    fn is_halted(&self) -> bool {
        self.halted
    }
}
