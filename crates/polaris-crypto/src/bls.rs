//! BLS12-381 multi-signatures with proofs of possession, for accusations.
//!
//! `min_sig` variant: signatures are 48 bytes (G1) and public keys 96 bytes
//! (G2). Signatures travel in every accusation and every proof while keys
//! sit on the bulletin board, so the short-signature variant is the cheaper
//! one. Rogue-key attacks are excluded by the proof of possession every key
//! carries, checked once when the keyring is loaded; after that, verifying a
//! [`MultiSig`] is one pairing check against the sum of the signers' keys.

use std::fmt;

use blst::BLST_ERROR;
use blst::min_sig::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use polaris_core::{NodeId, NodeSet};
use serde::{Deserialize, Serialize};

use crate::{domain, hex, signing_input};

pub const PK_LEN: usize = 96;
pub const SIG_LEN: usize = 48;
pub const SK_LEN: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlsError {
    #[error("bad BLS encoding or point outside the subgroup: {0:?}")]
    Encoding(BLST_ERROR),
    #[error("a multi-signature needs at least one signer")]
    Empty,
    #[error("signer {0} appears twice")]
    Duplicate(NodeId),
    #[error("signer {0} is outside the key set")]
    UnknownSigner(NodeId),
}

#[derive(Clone)]
pub struct Secret(SecretKey);

impl Secret {
    /// Deterministic from 32 bytes of key material (RFC 9380 `KeyGen`).
    pub fn from_ikm(ikm: &[u8; 32]) -> Self {
        Self(SecretKey::key_gen(ikm, b"polaris").expect("32 bytes of ikm"))
    }

    pub fn to_bytes(&self) -> [u8; SK_LEN] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        SecretKey::from_bytes(bytes)
            .map(Self)
            .map_err(BlsError::Encoding)
    }

    pub fn public(&self) -> Public {
        Public(self.0.sk_to_pk())
    }

    pub fn sign(&self, tag: &[u8], run_id: u64, body: &[u8]) -> Sig {
        Sig(self
            .0
            .sign(&signing_input(tag, run_id, body), domain::BLS_DST, &[])
            .compress())
    }

    /// Proof of possession: a signature on the public key under its own DST.
    pub fn prove_possession(&self) -> Sig {
        Sig(self
            .0
            .sign(&self.public().to_bytes(), domain::BLS_POP_DST, &[])
            .compress())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bls::Secret(..)")
    }
}

/// A public key that passed the subgroup check.
#[derive(Clone, Copy)]
pub struct Public(PublicKey);

impl Public {
    pub fn to_bytes(&self) -> [u8; PK_LEN] {
        self.0.compress()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        PublicKey::key_validate(bytes)
            .map(Self)
            .map_err(BlsError::Encoding)
    }

    pub fn verify(&self, tag: &[u8], run_id: u64, body: &[u8], sig: &Sig) -> bool {
        let Ok(s) = Signature::from_bytes(&sig.0) else {
            return false;
        };
        s.verify(
            true,
            &signing_input(tag, run_id, body),
            domain::BLS_DST,
            &[],
            &self.0,
            false,
        ) == BLST_ERROR::BLST_SUCCESS
    }

    pub fn verify_pop(&self, pop: &Sig) -> bool {
        let Ok(s) = Signature::from_bytes(&pop.0) else {
            return false;
        };
        s.verify(
            true,
            &self.to_bytes(),
            domain::BLS_POP_DST,
            &[],
            &self.0,
            false,
        ) == BLST_ERROR::BLST_SUCCESS
    }
}

impl PartialEq for Public {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}
impl Eq for Public {}

impl fmt::Debug for Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bls:{}..", hex::encode(&self.to_bytes()[..4]))
    }
}

/// A signature on the wire (compressed G1 point).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sig(#[serde(with = "crate::fixed_bytes")] pub [u8; SIG_LEN]);

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blssig:{}..", hex::encode(&self.0[..4]))
    }
}

/// Several signatures on one message, by the processes in `signers`.
/// `ceil(n/8) + 48` bytes however many signers: this is what makes a
/// LearnOrExpose proof `O(n^2 + nkappa)` bits instead of `O(n^2kappa)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiSig {
    pub signers: NodeSet,
    pub sig: Sig,
}

impl MultiSig {
    /// Aggregates signatures on one message. Each signer at most once; the
    /// parts are expected to have been verified individually on receipt.
    pub fn aggregate(
        n: usize,
        parts: impl IntoIterator<Item = (NodeId, Sig)>,
    ) -> Result<Self, BlsError> {
        let mut signers = NodeSet::empty(n);
        let mut sigs = Vec::new();
        for (id, sig) in parts {
            if usize::from(id) >= n {
                return Err(BlsError::UnknownSigner(id));
            }
            if !signers.insert(id) {
                return Err(BlsError::Duplicate(id));
            }
            sigs.push(Signature::from_bytes(&sig.0).map_err(BlsError::Encoding)?);
        }
        if sigs.is_empty() {
            return Err(BlsError::Empty);
        }
        let refs: Vec<&Signature> = sigs.iter().collect();
        let agg = AggregateSignature::aggregate(&refs, false).map_err(BlsError::Encoding)?;
        Ok(Self {
            signers,
            sig: Sig(agg.to_signature().compress()),
        })
    }

    /// `keys` is the bulletin board, indexed by `NodeId`.
    pub fn verify(&self, keys: &[Public], tag: &[u8], run_id: u64, body: &[u8]) -> bool {
        if self.signers.universe() != keys.len() || self.signers.is_empty() {
            return false;
        }
        let pks: Vec<&PublicKey> = self
            .signers
            .iter()
            .map(|i| &keys[usize::from(i)].0)
            .collect();
        let Ok(agg) = AggregatePublicKey::aggregate(&pks, false) else {
            return false;
        };
        let Ok(s) = Signature::from_bytes(&self.sig.0) else {
            return false;
        };
        s.fast_aggregate_verify_pre_aggregated(
            true,
            &signing_input(tag, run_id, body),
            domain::BLS_DST,
            &agg.to_public_key(),
        ) == BLST_ERROR::BLST_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(i: u8) -> Secret {
        Secret::from_ikm(&[i; 32])
    }

    #[test]
    fn keys_are_deterministic_and_roundtrip() {
        let a = secret(1);
        assert_eq!(a.to_bytes(), secret(1).to_bytes());
        assert_ne!(a.to_bytes(), secret(2).to_bytes());
        assert_eq!(
            Secret::from_bytes(&a.to_bytes()).unwrap().public(),
            a.public()
        );
        let pk = a.public();
        assert_eq!(Public::from_bytes(&pk.to_bytes()).unwrap(), pk);
        assert!(Public::from_bytes(&[0u8; PK_LEN]).is_err());
    }

    #[test]
    fn sign_verify_and_pop() {
        let a = secret(1);
        let pk = a.public();
        let sig = a.sign(domain::ACCUSE, 3, &[7]);
        assert!(pk.verify(domain::ACCUSE, 3, &[7], &sig));
        assert!(!pk.verify(domain::ACCUSE, 4, &[7], &sig));
        assert!(!secret(2).public().verify(domain::ACCUSE, 3, &[7], &sig));
        let pop = a.prove_possession();
        assert!(pk.verify_pop(&pop));
        assert!(!secret(2).public().verify_pop(&pop));
        // A signature is not a proof of possession and vice versa.
        assert!(!pk.verify_pop(&sig));
    }

    #[test]
    fn multisig_verifies_only_with_the_right_signer_set() {
        let n = 6;
        let secrets: Vec<Secret> = (0..n).map(|i| secret(i as u8 + 1)).collect();
        let keys: Vec<Public> = secrets.iter().map(Secret::public).collect();
        let body = [4u8]; // accuse node 4
        let parts: Vec<(NodeId, Sig)> = [0u16, 2, 5]
            .iter()
            .map(|&i| (i, secrets[usize::from(i)].sign(domain::ACCUSE, 9, &body)))
            .collect();
        let ms = MultiSig::aggregate(n, parts.clone()).unwrap();
        assert!(ms.verify(&keys, domain::ACCUSE, 9, &body));
        assert!(!ms.verify(&keys, domain::ACCUSE, 9, &[3]));
        assert!(!ms.verify(&keys[..5], domain::ACCUSE, 9, &body));

        let mut wrong = ms.clone();
        wrong.signers.remove(2);
        assert!(!wrong.verify(&keys, domain::ACCUSE, 9, &body));
        let mut wrong = ms.clone();
        wrong.signers.insert(1);
        assert!(!wrong.verify(&keys, domain::ACCUSE, 9, &body));

        assert_eq!(
            MultiSig::aggregate(n, [parts[0], parts[0]]).unwrap_err(),
            BlsError::Duplicate(0)
        );
        assert_eq!(MultiSig::aggregate(n, []).unwrap_err(), BlsError::Empty);
        assert_eq!(
            MultiSig::aggregate(n, [(9u16, parts[0].1)]).unwrap_err(),
            BlsError::UnknownSigner(9)
        );

        // One part signed on another message poisons the aggregate.
        let mut bad = parts.clone();
        bad[1] = (2, secrets[2].sign(domain::ACCUSE, 9, &[3]));
        assert!(
            !MultiSig::aggregate(n, bad)
                .unwrap()
                .verify(&keys, domain::ACCUSE, 9, &body)
        );

        let bytes = polaris_core::wire::encode(&ms).unwrap();
        assert_eq!(bytes.len(), (1 + 1 + 1) + (1 + SIG_LEN));
        assert_eq!(polaris_core::wire::decode::<MultiSig>(&bytes).unwrap(), ms);
    }
}
