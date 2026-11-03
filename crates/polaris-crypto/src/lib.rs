//! Cryptography for polaris.
//!
//! - [`domain`]: domain-separation tags, one per signed message type.
//! - [`hash`]: 32-byte digests (blake3) with a domain tag.
//! - [`ed25519`]: signatures with batch verification: disclosures, votes,
//!   commits, the channel handshake.
//! - [`bls`]: BLS12-381 (`min_sig`: 48-byte signatures, 96-byte keys) with
//!   proofs of possession, and per-message multi-signatures with an n-bit
//!   signer set; accusations only, because those are what gets aggregated
//!   into a LearnOrExpose proof.
//! - [`prf`]: HMAC-SHA-256 keyed by the common random string; leader election.
//! - [`keyring`]: the bulletin-board key file written by `keygen` and loaded
//!   by every node, and a node's own secrets.
//!
//! Every signature covers [`signing_input`]`(tag, run_id, body)` =
//! `tag || run_id || len(body) || body`, so nothing signed as one message type
//! or in one run verifies as another.

pub mod bls;
pub mod domain;
pub mod ed25519;
mod fixed_bytes;
pub mod hash;
pub mod hex;
pub mod keyring;
pub mod prf;

/// The bytes a signature covers: `tag || run_id || len(body) || body`.
pub fn signing_input(tag: &[u8], run_id: u64, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(tag.len() + 16 + body.len());
    v.extend_from_slice(tag);
    v.extend_from_slice(&run_id.to_le_bytes());
    v.extend_from_slice(&(body.len() as u64).to_le_bytes());
    v.extend_from_slice(body);
    v
}
