//! Signed accusations, their per-target store, and the aggregated proof.
//!
//! An accusation `a -> b` is a BLS signature by `a` on `<accuse, b>` (tag
//! [`domain::ACCUSE`], scoped to the run, not to a view: under static
//! corruption an honest accusation stays valid for the whole run). All
//! accusations against one target are aggregated into a single
//! [`MultiSig`] with an n-bit signer set, so a proof is `O(n^2 + nkappa)` bits.

use std::collections::BTreeMap;

use polaris_core::{NodeId, NodeSet, Params};
use polaris_crypto::bls::{self, MultiSig};
use polaris_crypto::domain;
use polaris_crypto::keyring::{Keyring, NodeKeys};
use serde::{Deserialize, Serialize};

use crate::trust_graph::TrustGraph;

/// The signed body of `<accuse, target>`.
pub fn accuse_body(target: NodeId) -> [u8; 2] {
    target.to_le_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accusation {
    pub accuser: NodeId,
    pub target: NodeId,
    pub sig: bls::Sig,
}

impl Accusation {
    pub fn sign(keys: &NodeKeys, run_id: u64, target: NodeId) -> Self {
        Self {
            accuser: keys.id,
            target,
            sig: keys.bls.sign(domain::ACCUSE, run_id, &accuse_body(target)),
        }
    }

    /// Well-formed (distinct known ids) and correctly signed.
    pub fn verify(&self, keyring: &Keyring) -> bool {
        self.well_formed(keyring.n())
            && keyring.bls(self.accuser).verify(
                domain::ACCUSE,
                keyring.run_id,
                &accuse_body(self.target),
                &self.sig,
            )
    }

    fn well_formed(&self, n: usize) -> bool {
        self.accuser != self.target && usize::from(self.accuser) < n && usize::from(self.target) < n
    }
}

/// Verifies many accusations with one pairing check per target: the
/// signatures on one body are aggregated and checked as a multi-signature;
/// only a failing group falls back to one-by-one checks. Returns one flag per
/// input, in order. Duplicate `(accuser, target)` pairs beyond the first are
/// reported invalid (they would be double-counted in an aggregate).
pub fn verify_many(keyring: &Keyring, accs: &[Accusation]) -> Vec<bool> {
    let n = keyring.n();
    let mut ok = vec![false; accs.len()];
    let mut groups: BTreeMap<NodeId, Vec<usize>> = BTreeMap::new();
    let mut seen = std::collections::HashSet::new();
    for (i, a) in accs.iter().enumerate() {
        if a.well_formed(n) && seen.insert((a.accuser, a.target)) {
            groups.entry(a.target).or_default().push(i);
        }
    }
    for (target, idxs) in groups {
        let body = accuse_body(target);
        let batch_ok = idxs.len() > 1
            && MultiSig::aggregate(n, idxs.iter().map(|&i| (accs[i].accuser, accs[i].sig)))
                .is_ok_and(|ms| {
                    ms.verify(keyring.bls_keys(), domain::ACCUSE, keyring.run_id, &body)
                });
        for i in idxs {
            ok[i] = batch_ok || accs[i].verify(keyring);
        }
    }
    ok
}

/// Every verified accusation seen so far, by target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccusationSet {
    n: usize,
    /// `by_target[b]` maps accuser -> signature.
    by_target: Vec<BTreeMap<NodeId, bls::Sig>>,
    len: usize,
}

impl AccusationSet {
    pub fn new(n: usize) -> Self {
        Self {
            n,
            by_target: (0..n).map(|_| BTreeMap::new()).collect(),
            len: 0,
        }
    }

    /// Adds a (verified) accusation; returns whether it was new.
    pub fn insert(&mut self, acc: &Accusation) -> bool {
        if acc.accuser == acc.target {
            return false;
        }
        let new = self.by_target[usize::from(acc.target)]
            .insert(acc.accuser, acc.sig)
            .is_none();
        if new {
            self.len += 1;
        }
        new
    }

    pub fn contains(&self, accuser: NodeId, target: NodeId) -> bool {
        self.by_target[usize::from(target)].contains_key(&accuser)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn accusers_of(&self, target: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.by_target[usize::from(target)].keys().copied()
    }

    /// Every accusation with its signature, by target then accuser.
    pub fn iter(&self) -> impl Iterator<Item = Accusation> + '_ {
        self.by_target.iter().enumerate().flat_map(|(b, m)| {
            m.iter().map(move |(&a, &sig)| Accusation {
                accuser: a,
                target: NodeId::try_from(b).expect("fits"),
                sig,
            })
        })
    }

    /// Adds every accusation of `other`; returns how many were new.
    pub fn merge(&mut self, other: &AccusationSet) -> usize {
        other.iter().filter(|a| self.insert(a)).count()
    }

    /// The edges `(accuser, target)` of the accusation graph.
    pub fn edges(&self) -> impl Iterator<Item = (NodeId, NodeId)> + '_ {
        self.by_target.iter().enumerate().flat_map(|(b, m)| {
            m.keys()
                .map(move |&a| (a, NodeId::try_from(b).expect("fits")))
        })
    }

    /// `MakeGraph(Acc)`.
    pub fn graph(&self, params: Params) -> TrustGraph {
        TrustGraph::make(params, self.edges())
    }

    /// `Aggregate(Acc)`: one multi-signature per accused target.
    pub fn aggregate(&self) -> AccusationProof {
        AccusationProof {
            per_target: self
                .by_target
                .iter()
                .map(|m| {
                    if m.is_empty() {
                        None
                    } else {
                        Some(
                            MultiSig::aggregate(self.n, m.iter().map(|(&a, &s)| (a, s)))
                                .expect("non-empty, distinct, well-formed signatures"),
                        )
                    }
                })
                .collect(),
        }
    }
}

/// `Pi`: `per_target[j]` aggregates every accusation against `j`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccusationProof {
    pub per_target: Vec<Option<MultiSig>>,
}

impl AccusationProof {
    pub fn empty(n: usize) -> Self {
        Self {
            per_target: vec![None; n],
        }
    }

    /// Every multi-signature verifies on its target's body, over the right
    /// universe, with no self-accusation.
    pub fn verify(&self, keyring: &Keyring) -> bool {
        let n = keyring.n();
        self.per_target.len() == n
            && self.per_target.iter().enumerate().all(|(j, ms)| match ms {
                None => true,
                Some(ms) => {
                    let j = NodeId::try_from(j).expect("fits");
                    ms.signers.universe() == n
                        && !ms.signers.contains(j)
                        && ms.verify(
                            keyring.bls_keys(),
                            domain::ACCUSE,
                            keyring.run_id,
                            &accuse_body(j),
                        )
                }
            })
    }

    /// The accusation set the proof encodes, as graph edges.
    pub fn edges(&self) -> impl Iterator<Item = (NodeId, NodeId)> + '_ {
        self.per_target.iter().enumerate().flat_map(|(j, ms)| {
            let target = NodeId::try_from(j).expect("fits");
            ms.iter()
                .flat_map(move |ms| ms.signers.iter().map(move |a| (a, target)))
        })
    }

    pub fn graph(&self, params: Params) -> TrustGraph {
        TrustGraph::make(params, self.edges())
    }

    /// Accusers of `target` according to the proof.
    pub fn accusers_of(&self, target: NodeId) -> NodeSet {
        self.per_target[usize::from(target)].as_ref().map_or_else(
            || NodeSet::empty(self.per_target.len()),
            |ms| ms.signers.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polaris_crypto::keyring;

    fn setup(n: usize, t: usize) -> (Keyring, Vec<NodeKeys>) {
        keyring::generate(Params::new(n, t).unwrap(), 5, 1)
    }

    #[test]
    fn sign_verify_and_malformed() {
        let (kr, keys) = setup(4, 1);
        let a = Accusation::sign(&keys[1], kr.run_id, 3);
        assert!(a.verify(&kr));
        let mut wrong_target = a;
        wrong_target.target = 2;
        assert!(!wrong_target.verify(&kr));
        let mut wrong_accuser = a;
        wrong_accuser.accuser = 0;
        assert!(!wrong_accuser.verify(&kr));
        let mut self_acc = a;
        self_acc.target = 1;
        assert!(!self_acc.verify(&kr));
        let (other, _) = keyring::generate(kr.params, 6, 1);
        assert!(!a.verify(&other), "a different run id");
    }

    #[test]
    fn verify_many_isolates_the_bad_ones() {
        let (kr, keys) = setup(6, 2);
        let mut accs = vec![
            Accusation::sign(&keys[0], kr.run_id, 5),
            Accusation::sign(&keys[1], kr.run_id, 5),
            Accusation::sign(&keys[2], kr.run_id, 5),
            Accusation::sign(&keys[3], kr.run_id, 4),
            Accusation::sign(&keys[0], kr.run_id, 5), // duplicate
        ];
        assert_eq!(verify_many(&kr, &accs), vec![true, true, true, true, false]);
        accs[1].sig = Accusation::sign(&keys[1], kr.run_id, 2).sig; // wrong body
        accs[4] = Accusation {
            accuser: 2,
            target: 2,
            sig: accs[2].sig,
        };
        assert_eq!(
            verify_many(&kr, &accs),
            vec![true, false, true, true, false]
        );
        assert!(verify_many(&kr, &[]).is_empty());
    }

    #[test]
    fn set_aggregates_into_a_verifying_proof() {
        let (kr, keys) = setup(5, 2);
        let mut set = AccusationSet::new(5);
        assert!(set.insert(&Accusation::sign(&keys[0], kr.run_id, 4)));
        assert!(set.insert(&Accusation::sign(&keys[1], kr.run_id, 4)));
        assert!(!set.insert(&Accusation::sign(&keys[1], kr.run_id, 4)));
        assert!(set.insert(&Accusation::sign(&keys[2], kr.run_id, 3)));
        assert_eq!(set.len(), 3);
        assert!(set.contains(0, 4) && !set.contains(4, 0));
        let mut edges: Vec<_> = set.edges().collect();
        edges.sort();
        assert_eq!(edges, vec![(0, 4), (1, 4), (2, 3)]);

        let proof = set.aggregate();
        assert!(proof.verify(&kr));
        assert_eq!(proof.accusers_of(4), NodeSet::from_iter(5, [0, 1]));
        let mut back: Vec<_> = proof.edges().collect();
        back.sort();
        assert_eq!(back, edges);
        assert_eq!(proof.graph(kr.params), set.graph(kr.params));

        let bytes = polaris_core::wire::encode(&proof).unwrap();
        assert_eq!(
            polaris_core::wire::decode::<AccusationProof>(&bytes).unwrap(),
            proof
        );

        // Tampering: claim an extra accuser, or move a multisig to another target.
        let mut forged = proof.clone();
        forged.per_target[4].as_mut().unwrap().signers.insert(3);
        assert!(!forged.verify(&kr));
        let mut moved = proof.clone();
        moved.per_target[2] = moved.per_target[3].take();
        assert!(!moved.verify(&kr));
        let mut selfish = proof.clone();
        selfish.per_target[4].as_mut().unwrap().signers.insert(4);
        assert!(!selfish.verify(&kr));
        assert!(AccusationProof::empty(5).verify(&kr));
        assert!(!AccusationProof::empty(4).verify(&kr));
    }
}
