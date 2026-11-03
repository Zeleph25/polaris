//! Signed inputs and the verifiable vector a LearnOrExpose leader produces.

use polaris_core::{NodeId, NodeSet};
use polaris_crypto::domain;
use polaris_crypto::ed25519;
use polaris_crypto::keyring::{Keyring, NodeKeys};
use serde::{Deserialize, Serialize};

use crate::accusations::AccusationProof;

/// `(<disclose, m_j>, sigma_j)`: node `sender`'s input, signed by it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disclosure {
    pub sender: NodeId,
    pub value: Vec<u8>,
    pub sig: ed25519::Sig,
}

impl Disclosure {
    pub fn sign(keys: &NodeKeys, run_id: u64, value: Vec<u8>) -> Self {
        let sig = ed25519::sign(&keys.ed25519, domain::DISCLOSE, run_id, &value);
        Self {
            sender: keys.id,
            value,
            sig,
        }
    }

    pub fn verify(&self, keyring: &Keyring) -> bool {
        usize::from(self.sender) < keyring.n()
            && ed25519::verify(
                keyring.ed25519(self.sender),
                domain::DISCLOSE,
                keyring.run_id,
                &self.value,
                &self.sig,
            )
    }

    pub fn batch_item<'a>(&'a self, keyring: &'a Keyring) -> ed25519::Item<'a> {
        ed25519::Item {
            pk: keyring.ed25519(self.sender),
            tag: domain::DISCLOSE,
            run_id: keyring.run_id,
            body: &self.value,
            sig: &self.sig,
        }
    }
}

/// `v` with its signatures: `entries[j]` is `j`'s disclosure or `bottom`.
pub type Entries = Vec<Option<Disclosure>>;

/// `VerifyVec_in`: every present entry carries a valid signature by its sender.
pub fn verify_in(entries: &Entries, keyring: &Keyring) -> bool {
    entries.len() == keyring.n()
        && entries.iter().enumerate().all(|(j, e)| match e {
            None => true,
            Some(d) => usize::from(d.sender) == j && d.verify(keyring),
        })
}

/// `(v, pi)`: what the leader hands to the broadcast.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiableVector {
    pub entries: Entries,
    pub proof: AccusationProof,
}

impl VerifiableVector {
    /// `VerifyVec_out` at verifier `me`: (1) every present entry verifies;
    /// (2) in `MakeGraph(Acc)` for the accusation set `pi` encodes, `me` is
    /// disconnected from every `j` with `entries[j] = bottom`. Local to the
    /// verifier (a polarizer), yet every honest verifier gets the same answer
    /// because honest nodes always sit in one component.
    pub fn verify(&self, me: NodeId, keyring: &Keyring) -> bool {
        if !verify_in(&self.entries, keyring) || !self.proof.verify(keyring) {
            return false;
        }
        let missing: Vec<NodeId> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.is_none())
            .map(|(j, _)| NodeId::try_from(j).expect("fits"))
            .collect();
        if missing.is_empty() {
            return true;
        }
        let graph = self.proof.graph(keyring.params);
        let reach = graph.component(me);
        missing.iter().all(|&j| !reach.contains(j))
    }

    /// The IC output vector: values, `None` for exposed entries.
    pub fn values(&self) -> Vec<Option<Vec<u8>>> {
        self.entries
            .iter()
            .map(|e| e.as_ref().map(|d| d.value.clone()))
            .collect()
    }

    pub fn exposed(&self) -> NodeSet {
        NodeSet::from_iter(
            self.entries.len(),
            self.entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.is_none())
                .map(|(j, _)| NodeId::try_from(j).expect("fits")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polaris_core::Params;
    use polaris_crypto::keyring;

    #[test]
    fn disclosure_signatures() {
        let (kr, keys) = keyring::generate(Params::new(3, 1).unwrap(), 2, 1);
        let d = Disclosure::sign(&keys[1], kr.run_id, b"m1".to_vec());
        assert!(d.verify(&kr));
        let mut forged = d.clone();
        forged.value = b"m2".to_vec();
        assert!(!forged.verify(&kr));
        let mut relabeled = d.clone();
        relabeled.sender = 2;
        assert!(!relabeled.verify(&kr));

        let entries = vec![None, Some(d.clone()), None];
        assert!(verify_in(&entries, &kr));
        assert!(
            !verify_in(&vec![Some(d.clone()), None, None], &kr),
            "entry in the wrong slot"
        );
        assert!(!verify_in(&vec![None, Some(d)], &kr), "wrong length");
    }
}
