//! Cryptography for polaris.
//!
//! Planned layout (M1):
//! - `domain`: domain-separation tags, one per signed message type.
//! - `hash`: 32-byte digests (blake3) with a domain tag.
//! - `ed25519`: signing keys, batch verification; disclosures, votes, commits, handshake.
//! - `bls`: BLS12-381 keys with proofs of possession, per-target multi-signature
//!   aggregation and verification with an n-bit signer set; accusations only.
//! - `prf`: HMAC-SHA-256 keyed by the common random string; leader election.
//! - `keyring`: the bulletin-board key file written by `keygen` and loaded by every node.

pub mod domain;
pub mod hash;
