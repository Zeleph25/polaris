//! The IC compiler over Dolev-Strong: agreement, validity, the ordered scan
//! over skipped views, and pipelining.

use std::sync::Arc;

use polaris_core::{Ctx, NodeId, NodeSet, Outgoing, Params, Round, RoundMachine, View, wire};
use polaris_crypto::keyring::{self, Keyring, NodeKeys};
use polaris_proto::accusations::AccusationProof;
use polaris_proto::bb::dolev_strong::{DolevStrong, DsMsg, sign_link};
use polaris_proto::compiler::{Compiler, CompilerConfig, IcMsg, IcOutput};
use polaris_proto::disclosure::{Disclosure, Entries, VerifiableVector};
use polaris_sim::{Adversary, HonestSend, Node, Selective, Silent, Simulator};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha12Rng;

const RUN: u64 = 17;

type Ic = Compiler<DolevStrong>;
type Msg = IcMsg<DsMsg>;

fn setup(n: usize, t: usize, seed: u64) -> (Arc<Keyring>, Vec<Arc<NodeKeys>>) {
    let (kr, keys) = keyring::generate(Params::new(n, t).unwrap(), RUN, seed);
    (Arc::new(kr), keys.into_iter().map(Arc::new).collect())
}

fn input(id: NodeId) -> Vec<u8> {
    format!("input-{id}").into_bytes()
}

fn ic(kr: &Arc<Keyring>, keys: &Arc<NodeKeys>, config: CompilerConfig) -> Ic {
    Compiler::with_dolev_strong(kr.clone(), keys.clone(), config, input(keys.id))
}

fn leader(kr: &Keyring, view: View) -> NodeId {
    kr.prf().leader(view, kr.n())
}

fn first_honest_leader(kr: &Keyring, byzantine: &[NodeId]) -> View {
    (1..)
        .find(|&v| !byzantine.contains(&leader(kr, v)))
        .unwrap()
}

fn honest_outputs(sim: &Simulator<Ic>, byzantine: &[NodeId]) -> Vec<IcOutput> {
    sim.outputs()
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !byzantine.contains(&(*i as NodeId)))
        .map(|(i, o)| {
            o.cloned()
                .unwrap_or_else(|| panic!("node {i} has no output"))
        })
        .collect()
}

/// Agreement, and validity for every honest entry.
fn check(sim: &Simulator<Ic>, byzantine: &[NodeId], n: usize) -> IcOutput {
    let outs = honest_outputs(sim, byzantine);
    for o in &outs {
        assert_eq!(o, &outs[0], "honest nodes disagree");
    }
    for j in 0..n as NodeId {
        if !byzantine.contains(&j) {
            assert_eq!(
                outs[0].values[usize::from(j)],
                Some(input(j)),
                "entry of honest {j}"
            );
        }
    }
    outs[0].clone()
}

#[test]
fn all_honest_decide_in_view_one() {
    let (n, t) = (6, 2);
    let (kr, keys) = setup(n, t, 1);
    let config = CompilerConfig::for_params(kr.params);
    let nodes = keys
        .iter()
        .map(|k| Node::Honest(ic(&kr, k, config)))
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    let r = kr.params.loe_rounds();
    // Round 0 discloses, LearnOrExpose takes rounds 1..=R, the broadcast
    // rounds R+1..=R+t+1; the decision is at the end of that last round.
    let last = r + t as Round + 1;
    assert_eq!(sim.run_until_decided(100).unwrap(), last + 1);
    let out = check(&sim, &[], n);
    assert_eq!(out.view, 1);
    for i in 0..n as NodeId {
        let m = sim.metrics(i);
        assert_eq!(
            m.decision_round(),
            Some(last),
            "sub-machine decisions must not count"
        );
        assert!(
            m.total().sig_verifies >= (n - 1) as u64,
            "the sub-machines' work is absorbed"
        );
        assert!(
            sim.honest(i).unwrap().is_halted(),
            "Dolev-Strong has no skew: halt at once"
        );
    }
}

#[test]
fn silent_byzantine_leaders_are_skipped() {
    let (n, t) = (6, 2);
    let (kr, keys) = setup(n, t, 2);
    // The leaders of views 1 and 2 are Byzantine when they differ, else the
    // leader of view 1 and some other node.
    let l1 = leader(&kr, 1);
    let l2 = leader(&kr, 2);
    let other = if l2 != l1 {
        l2
    } else {
        (0..n as NodeId).find(|&i| i != l1).unwrap()
    };
    let byzantine = vec![l1, other];
    let config = CompilerConfig::for_params(kr.params);
    let nodes = keys
        .iter()
        .map(|k| {
            if byzantine.contains(&k.id) {
                Node::Byzantine(Box::new(Silent))
            } else {
                Node::Honest(ic(&kr, k, config))
            }
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    sim.run_until_decided(500).unwrap();
    let out = check(&sim, &byzantine, n);
    assert_eq!(out.view, first_honest_leader(&kr, &byzantine));
    for &b in &byzantine {
        assert_eq!(out.values[usize::from(b)], None, "a silent node is exposed");
    }
}

/// A Byzantine leader of view 1 that discloses normally, stays silent in
/// LearnOrExpose, and at the start of the broadcast sends whatever `submit`
/// builds from the disclosures it collected in round 0.
struct BadLeader {
    keys: Arc<NodeKeys>,
    bb_round: Round,
    known: Entries,
    submit: Submit,
}

type Submit = Arc<dyn Fn(&Arc<NodeKeys>, &Entries) -> Vec<Outgoing<Msg>> + Send + Sync>;

impl Adversary<Ic> for BadLeader {
    fn start(&mut self, _: &mut Ctx) -> Vec<Outgoing<Msg>> {
        let d = Disclosure::sign(&self.keys, RUN, input(self.keys.id));
        self.known[usize::from(self.keys.id)] = Some(d.clone());
        vec![Outgoing::all(IcMsg::Disclose(d))]
    }

    fn act(
        &mut self,
        _: &mut Ctx,
        round: Round,
        inbox: Vec<(NodeId, Msg)>,
        _: &[HonestSend<'_, Msg>],
    ) -> Vec<Outgoing<Msg>> {
        for (_, m) in inbox {
            if let IcMsg::Disclose(d) = m {
                self.known[usize::from(d.sender)].get_or_insert(d);
            }
        }
        if round + 1 == self.bb_round {
            (self.submit)(&self.keys, &self.known)
        } else {
            vec![]
        }
    }
}

fn ds_message(keys: &Arc<NodeKeys>, vv: &VerifiableVector) -> DsMsg {
    let value = wire::encode(vv).unwrap();
    DsMsg {
        chain: vec![sign_link(keys, RUN, 1, &value)],
        value,
    }
}

fn run_with_bad_leader(
    submit: impl Fn(&Arc<NodeKeys>, &Entries) -> Vec<Outgoing<Msg>> + Send + Sync + 'static,
) -> (Simulator<Ic>, NodeId) {
    let submit: Submit = Arc::new(submit);
    let (n, t) = (6, 2);
    // A seed whose view-1 leader differs from its view-2 leader.
    let (kr, keys) = (1..)
        .map(|seed| setup(n, t, seed))
        .find(|(kr, _)| leader(kr, 1) != leader(kr, 2))
        .unwrap();
    let l1 = leader(&kr, 1);
    let config = CompilerConfig::for_params(kr.params);
    let nodes = keys
        .iter()
        .map(|k| {
            if k.id == l1 {
                Node::Byzantine(Box::new(BadLeader {
                    keys: k.clone(),
                    bb_round: 1 + kr.params.loe_rounds(),
                    known: vec![None; n],
                    submit: submit.clone(),
                }))
            } else {
                Node::Honest(ic(&kr, k, config))
            }
        })
        .collect();
    let sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    (sim, l1)
}

#[test]
fn a_vector_missing_an_honest_entry_is_rejected() {
    let (mut sim, l1) = run_with_bad_leader(|keys, known| {
        let victim = (0..known.len() as NodeId).find(|&j| j != keys.id).unwrap();
        let mut entries = known.clone();
        entries[usize::from(victim)] = None;
        let vv = VerifiableVector {
            entries,
            proof: AccusationProof::empty(known.len()),
        };
        vec![Outgoing::all(IcMsg::Bb {
            view: 1,
            msg: ds_message(keys, &vv),
        })]
    });
    sim.run_until_decided(500).unwrap();
    let out = check(&sim, &[l1], 6);
    assert_eq!(out.view, 2, "view 1 delivered a vector nobody accepts");
    assert_eq!(
        out.values[usize::from(l1)],
        Some(input(l1)),
        "the leader did disclose"
    );
}

#[test]
fn an_equivocating_leader_is_skipped() {
    // Two valid vectors that differ in the leader's own entry, one to each
    // half of the nodes: Dolev-Strong delivers bottom and the view is skipped.
    let (mut sim, l1) = run_with_bad_leader(|keys, known| {
        let n = known.len();
        let a = VerifiableVector {
            entries: known.clone(),
            proof: AccusationProof::empty(n),
        };
        let mut b = a.clone();
        b.entries[usize::from(keys.id)] = Some(Disclosure::sign(keys, RUN, b"other".to_vec()));
        let (ma, mb) = (ds_message(keys, &a), ds_message(keys, &b));
        (0..n as NodeId)
            .map(|j| {
                let msg = if j % 2 == 0 { ma.clone() } else { mb.clone() };
                Outgoing::to(j, IcMsg::Bb { view: 1, msg })
            })
            .collect()
    });
    sim.run_until_decided(500).unwrap();
    let out = check(&sim, &[l1], 6);
    assert_eq!(out.view, 2);
}

#[test]
fn random_omission_adversaries() {
    // Byzantine nodes are silent or run the honest protocol while delivering
    // each message to a random subset only, so every view with a Byzantine
    // leader may or may not deliver. Honest nodes must agree, keep every
    // honest input, and decide no later than the first honest leader.
    for &(n, t) in &[(4, 1), (6, 2), (8, 4), (8, 6), (10, 8)] {
        for seed in 0..25u64 {
            let (kr, keys) = setup(n, t, seed);
            let mut rng = ChaCha12Rng::seed_from_u64(seed * 7919 + n as u64);
            let mut ids: Vec<NodeId> = (0..n as NodeId).collect();
            for i in (1..ids.len()).rev() {
                ids.swap(i, rng.random_range(0..=i));
            }
            let byzantine: Vec<NodeId> = ids[..t].to_vec();
            let r = kr.params.loe_rounds();
            // Pipelined every R rounds, denser, or sequential; accusations
            // shared on every other seed.
            let c = [r, (r / 2).max(1), 0][(seed % 3) as usize];
            let mut config = CompilerConfig::for_params(kr.params).with_view_spacing(c);
            if seed % 2 == 1 {
                config = config.sharing_accusations();
            }
            let nodes = keys
                .iter()
                .map(|k| {
                    if !byzantine.contains(&k.id) {
                        Node::Honest(ic(&kr, k, config))
                    } else if rng.random_bool(0.3) {
                        Node::Byzantine(Box::new(Silent))
                    } else {
                        let subset = NodeSet::from_iter(
                            n,
                            (0..n as NodeId).filter(|_| rng.random_bool(0.5)),
                        );
                        Node::Byzantine(Box::new(Selective::new(ic(&kr, k, config), subset)))
                    }
                })
                .collect();
            let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
            sim.run_until_decided(5000)
                .unwrap_or_else(|e| panic!("n={n} t={t} seed={seed} c={c}: {e}"));
            let out = check(&sim, &byzantine, n);
            let bound = first_honest_leader(&kr, &byzantine);
            assert!(
                out.view <= bound,
                "n={n} t={t} seed={seed} c={c}: decided at view {} after an honest leader in view {bound}",
                out.view
            );
            let rounds: Vec<_> = (0..n as NodeId)
                .filter(|i| !byzantine.contains(i))
                .map(|i| sim.metrics(i).decision_round())
                .collect();
            assert!(
                rounds.iter().all(|r| *r == rounds[0]),
                "n={n} t={t} seed={seed}: simultaneous termination: {rounds:?}"
            );
        }
    }
}

#[test]
fn sequential_views_start_after_a_failed_broadcast() {
    // Two silent Byzantine leaders in a row: with sequential views the
    // decision comes in the third view, started only after each previous
    // broadcast delivered bottom, so later than with pipelining.
    let (n, t) = (6, 2);
    let (kr, keys) = (1..)
        .map(|seed| setup(n, t, seed))
        .find(|(kr, _)| {
            leader(kr, 1) != leader(kr, 2)
                && leader(kr, 3) != leader(kr, 1)
                && leader(kr, 3) != leader(kr, 2)
        })
        .unwrap();
    let byzantine = vec![leader(&kr, 1), leader(&kr, 2)];
    let run = |config: CompilerConfig| {
        let nodes = keys
            .iter()
            .map(|k| {
                if byzantine.contains(&k.id) {
                    Node::Byzantine(Box::new(Silent))
                } else {
                    Node::Honest(ic(&kr, k, config))
                }
            })
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        sim.run_until_decided(500).unwrap();
        let out = check(&sim, &byzantine, n);
        assert_eq!(out.view, 3);
        let honest = (0..n as NodeId).find(|i| !byzantine.contains(i)).unwrap();
        (
            sim.metrics(honest).decision_round().unwrap(),
            sim.honest(honest).unwrap().stats().views_started,
        )
    };
    let (pipelined, started_pipelined) = run(CompilerConfig::for_params(kr.params));
    let (sequential, started_sequential) = run(CompilerConfig::for_params(kr.params).sequential());
    let view_len = kr.params.loe_rounds() + t as Round + 1;
    assert_eq!(sequential, 3 * view_len, "three full views back to back");
    assert!(
        sequential > pipelined,
        "sequential {sequential} vs pipelined {pipelined}"
    );
    assert_eq!(started_sequential, 3, "no view started in vain");
    assert!(started_pipelined >= 3);
}

#[test]
fn shared_accusations_spare_later_views() {
    // Two silent Byzantine leaders in a row. Without sharing, every view's
    // LearnOrExpose accuses the silent nodes again; with sharing, the second
    // and third views start with them already cut off and accuse nobody.
    let (n, t) = (6, 2);
    let (kr, keys) = (1..)
        .map(|seed| setup(n, t, seed))
        .find(|(kr, _)| {
            leader(kr, 1) != leader(kr, 2)
                && leader(kr, 3) != leader(kr, 1)
                && leader(kr, 3) != leader(kr, 2)
        })
        .unwrap();
    let byzantine = vec![leader(&kr, 1), leader(&kr, 2)];
    let run = |config: CompilerConfig| {
        let nodes = keys
            .iter()
            .map(|k| {
                if byzantine.contains(&k.id) {
                    Node::Byzantine(Box::new(Silent))
                } else {
                    Node::Honest(ic(&kr, k, config))
                }
            })
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        sim.run_until_decided(500).unwrap();
        let out = check(&sim, &byzantine, n);
        assert_eq!(out.view, 3);
        let honest = (0..n as NodeId).find(|i| !byzantine.contains(i)).unwrap();
        let s = sim.honest(honest).unwrap().stats();
        (s.accusations_sent, s.views_started)
    };
    let base = CompilerConfig::for_params(kr.params).sequential();
    let (plain, views) = run(base);
    let (shared, views_shared) = run(base.sharing_accusations());
    assert_eq!(views, 3);
    assert_eq!(views_shared, 3);
    assert_eq!(plain, 3 * 2, "two silent nodes accused once per view");
    assert_eq!(shared, 2, "accused in the first view only");
}

#[test]
fn view_budget_is_respected() {
    let (n, t) = (4, 1);
    let (kr, keys) = setup(n, t, 3);
    let l1 = leader(&kr, 1);
    let config = CompilerConfig::for_params(kr.params).with_max_views(1);
    let nodes = keys
        .iter()
        .map(|k| {
            if k.id == l1 {
                Node::Byzantine(Box::new(Silent))
            } else {
                Node::Honest(ic(&kr, k, config))
            }
        })
        .collect();
    let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
    assert!(
        sim.run_until_decided(100).is_err(),
        "one view, a silent leader: no decision"
    );
    let honest = (0..n as NodeId).find(|&i| i != l1).unwrap();
    assert_eq!(sim.honest(honest).unwrap().stats().views_started, 1);
    assert_eq!(sim.honest(honest).unwrap().stats().views_skipped, 1);
}

mod over_wxsd {
    //! The same compiler over WXSD: the decision round differs by at most
    //! `Delta_sim = 1` between honest nodes, and everything else holds.

    use super::*;
    use polaris_proto::bb::wxsd::{Wxsd, WxsdConfig};

    type IcW = Compiler<Wxsd>;

    fn ic(kr: &Arc<Keyring>, keys: &Arc<NodeKeys>, config: CompilerConfig) -> IcW {
        Compiler::with_wxsd(
            kr.clone(),
            keys.clone(),
            config,
            WxsdConfig::default(),
            input(keys.id),
        )
    }

    fn check(sim: &Simulator<IcW>, byzantine: &[NodeId], n: usize) -> IcOutput {
        let outs: Vec<IcOutput> = sim
            .outputs()
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !byzantine.contains(&(*i as NodeId)))
            .map(|(i, o)| {
                o.cloned()
                    .unwrap_or_else(|| panic!("node {i} has no output"))
            })
            .collect();
        for o in &outs {
            assert_eq!(o, &outs[0], "honest nodes disagree");
        }
        for j in 0..n as NodeId {
            if !byzantine.contains(&j) {
                assert_eq!(
                    outs[0].values[usize::from(j)],
                    Some(input(j)),
                    "entry of honest {j}"
                );
            }
        }
        outs[0].clone()
    }

    #[test]
    fn all_honest_decide_in_view_one() {
        let (n, t) = (6, 2);
        let (kr, keys) = setup(n, t, 1);
        let config = CompilerConfig::for_params(kr.params);
        let nodes = keys
            .iter()
            .map(|k| Node::Honest(ic(&kr, k, config)))
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        // Round 0, R rounds of LearnOrExpose, then WXSD terminates in the
        // first Commit round of epoch 1: two phases of d + 1 rounds plus one.
        let last = kr.params.loe_rounds() + 2 * (kr.params.diameter_bound() + 1) + 1;
        assert_eq!(sim.run_until_decided(100).unwrap(), last + 1);
        let out = check(&sim, &[], n);
        assert_eq!(out.view, 1);
        for i in 0..n as NodeId {
            assert_eq!(sim.metrics(i).decision_round(), Some(last));
            assert!(
                !sim.honest(i).unwrap().is_halted(),
                "still running for Delta_sim = 1"
            );
        }
        sim.step();
        for i in 0..n as NodeId {
            assert!(
                sim.honest(i).unwrap().is_halted(),
                "halted once the skew has passed"
            );
        }
    }

    /// One run under the omission adversary; checks agreement, validity, the
    /// view bound and the skew, and returns the earliest honest decision round.
    fn omission_run(n: usize, t: usize, seed: u64, config: CompilerConfig) -> Round {
        let (kr, keys) = setup(n, t, seed);
        let mut rng = ChaCha12Rng::seed_from_u64(seed * 104729 + n as u64);
        let mut ids: Vec<NodeId> = (0..n as NodeId).collect();
        for i in (1..ids.len()).rev() {
            ids.swap(i, rng.random_range(0..=i));
        }
        let byzantine: Vec<NodeId> = ids[..t].to_vec();
        let nodes = keys
            .iter()
            .map(|k| {
                if !byzantine.contains(&k.id) {
                    Node::Honest(ic(&kr, k, config))
                } else if rng.random_bool(0.3) {
                    Node::Byzantine(Box::new(Silent))
                } else {
                    let subset =
                        NodeSet::from_iter(n, (0..n as NodeId).filter(|_| rng.random_bool(0.5)));
                    Node::Byzantine(Box::new(Selective::new(ic(&kr, k, config), subset)))
                }
            })
            .collect();
        let mut sim = Simulator::new(kr.params, RUN, nodes).unwrap();
        let ctx = format!("n={n} t={t} seed={seed} {config:?}");
        sim.run_until_decided(20_000)
            .unwrap_or_else(|e| panic!("{ctx}: {e}"));
        while (0..n as NodeId)
            .filter(|i| !byzantine.contains(i))
            .any(|i| !sim.honest(i).unwrap().is_halted())
        {
            sim.step();
        }
        let out = check(&sim, &byzantine, n);
        let bound = first_honest_leader(&kr, &byzantine);
        assert!(out.view <= bound, "{ctx}: view {} after {bound}", out.view);
        let rounds: Vec<_> = (0..n as NodeId)
            .filter(|i| !byzantine.contains(i))
            .map(|i| sim.metrics(i).decision_round().unwrap())
            .collect();
        let (lo, hi) = (*rounds.iter().min().unwrap(), *rounds.iter().max().unwrap());
        assert!(hi - lo <= 1, "{ctx}: skew {rounds:?}");
        lo
    }

    #[test]
    fn random_omission_adversaries() {
        for &(n, t) in &[(4, 1), (6, 2), (8, 4), (8, 6)] {
            for seed in 0..16u64 {
                let mut config = CompilerConfig::for_params(Params::new(n, t).unwrap());
                if seed % 2 == 1 {
                    config = config.sharing_accusations();
                }
                omission_run(n, t, seed, config);
            }
        }
    }

    #[test]
    fn sequential_views_keep_agreement() {
        // WXSD's honest nodes may end a round apart; the next view must
        // still start in the same round everywhere.
        for &(n, t) in &[(6, 2), (8, 4), (8, 6)] {
            for seed in 0..24u64 {
                let mut config =
                    CompilerConfig::for_params(Params::new(n, t).unwrap()).sequential();
                if seed % 2 == 1 {
                    config = config.sharing_accusations();
                }
                omission_run(n, t, seed, config);
            }
        }
    }
}
