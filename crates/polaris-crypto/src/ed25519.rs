//! Ed25519: disclosures, votes, commits, the channel handshake.
//!
//! Verification is strict (`verify_strict`: no small-order or non-canonical
//! keys), and a round's worth of signatures is checked in one batch.

use std::fmt;

use ed25519_dalek::{Signature, Signer};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{hex, signing_input};

pub const SIG_LEN: usize = 64;
pub const SEED_LEN: usize = 32;
pub const PK_LEN: usize = 32;

/// A signature on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sig(#[serde(with = "crate::fixed_bytes")] pub [u8; SIG_LEN]);

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed25519:{}..", hex::encode(&self.0[..4]))
    }
}

pub fn sign(sk: &SigningKey, tag: &[u8], run_id: u64, body: &[u8]) -> Sig {
    Sig(sk.sign(&signing_input(tag, run_id, body)).to_bytes())
}

pub fn verify(pk: &VerifyingKey, tag: &[u8], run_id: u64, body: &[u8], sig: &Sig) -> bool {
    pk.verify_strict(
        &signing_input(tag, run_id, body),
        &Signature::from_bytes(&sig.0),
    )
    .is_ok()
}

/// One signature of a batch.
#[derive(Clone, Copy, Debug)]
pub struct Item<'a> {
    pub pk: &'a VerifyingKey,
    pub tag: &'a [u8],
    pub run_id: u64,
    pub body: &'a [u8],
    pub sig: &'a Sig,
}

/// Verifies every item in one batch equation; on failure, falls back to
/// one-by-one verification and returns the indices that fail.
pub fn verify_batch(items: &[Item<'_>]) -> Result<(), Vec<usize>> {
    if items.is_empty() {
        return Ok(());
    }
    let inputs: Vec<Vec<u8>> = items
        .iter()
        .map(|it| signing_input(it.tag, it.run_id, it.body))
        .collect();
    let msgs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let sigs: Vec<Signature> = items
        .iter()
        .map(|it| Signature::from_bytes(&it.sig.0))
        .collect();
    let pks: Vec<VerifyingKey> = items.iter().map(|it| *it.pk).collect();
    if ed25519_dalek::verify_batch(&msgs, &sigs, &pks).is_ok() {
        return Ok(());
    }
    let bad: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, it)| !verify(it.pk, it.tag, it.run_id, it.body, it.sig))
        .map(|(i, _)| i)
        .collect();
    Err(bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; SEED_LEN])
    }

    #[test]
    fn sign_verify_and_domains() {
        let sk = key(1);
        let pk = sk.verifying_key();
        let sig = sign(&sk, domain::DISCLOSE, 7, b"m");
        assert!(verify(&pk, domain::DISCLOSE, 7, b"m", &sig));
        assert!(!verify(&pk, domain::ACCUSE, 7, b"m", &sig));
        assert!(!verify(&pk, domain::DISCLOSE, 8, b"m", &sig));
        assert!(!verify(&pk, domain::DISCLOSE, 7, b"n", &sig));
        assert!(!verify(
            &key(2).verifying_key(),
            domain::DISCLOSE,
            7,
            b"m",
            &sig
        ));
    }

    const BODIES: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];

    fn items<'a>(pks: &'a [VerifyingKey], sigs: &'a [Sig]) -> Vec<Item<'a>> {
        (0..4)
            .map(|i| Item {
                pk: &pks[i],
                tag: domain::ECHO,
                run_id: 1,
                body: BODIES[i],
                sig: &sigs[i],
            })
            .collect()
    }

    #[test]
    fn batch_finds_the_bad_one() {
        let keys: Vec<SigningKey> = (1..=4).map(key).collect();
        let pks: Vec<VerifyingKey> = keys.iter().map(SigningKey::verifying_key).collect();
        let mut sigs: Vec<Sig> = keys
            .iter()
            .zip(BODIES)
            .map(|(k, b)| sign(k, domain::ECHO, 1, b))
            .collect();
        assert_eq!(verify_batch(&items(&pks, &sigs)), Ok(()));
        sigs[2] = sign(&keys[2], domain::ECHO, 2, b"c");
        assert_eq!(verify_batch(&items(&pks, &sigs)), Err(vec![2]));
        assert_eq!(verify_batch(&[]), Ok(()));
    }

    #[test]
    fn wire_size() {
        let sig = sign(&key(3), domain::ECHO, 1, b"x");
        let bytes = polaris_core::wire::encode(&sig).unwrap();
        assert_eq!(bytes.len(), 1 + SIG_LEN);
        assert_eq!(polaris_core::wire::decode::<Sig>(&bytes).unwrap(), sig);
    }
}
