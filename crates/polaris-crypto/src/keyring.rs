//! The bulletin-board key file and a node's secrets.
//!
//! `keygen` writes one `keyring.toml` (every node's Ed25519 and BLS public
//! keys, the BLS proofs of possession, the crs, the run id and parameters)
//! plus one secret file per node. Loading the keyring checks every proof of
//! possession, so no key that could mount a rogue-key attack ever enters a
//! [`MultiSig`](crate::bls::MultiSig) verification.

use std::path::Path;

use polaris_core::{NodeId, Params, ParamsError};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::bls;
use crate::ed25519::{SigningKey, VerifyingKey};
use crate::hex::{self, HexError};
use crate::prf::Prf;

#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(String),
    #[error(transparent)]
    Hex(#[from] HexError),
    #[error(transparent)]
    Bls(#[from] bls::BlsError),
    #[error("ed25519 key: {0}")]
    Ed25519(String),
    #[error(transparent)]
    Params(#[from] ParamsError),
    #[error("expected {expected} node entries, got {got}")]
    Count { expected: usize, got: usize },
    #[error("node entries must carry ids 0..n in order; entry {index} has id {id}")]
    Order { index: usize, id: NodeId },
    #[error("proof of possession of node {0} does not verify")]
    Pop(NodeId),
    #[error("secret file is for run {found}, keyring is for run {expected}")]
    RunId { expected: u64, found: u64 },
    #[error("secret file is for node {found}, expected node {expected}")]
    NodeId { expected: NodeId, found: NodeId },
    #[error("secret keys of node {0} do not match the keyring")]
    Mismatch(NodeId),
}

impl From<toml::de::Error> for KeyringError {
    fn from(e: toml::de::Error) -> Self {
        Self::Toml(e.to_string())
    }
}

impl From<toml::ser::Error> for KeyringError {
    fn from(e: toml::ser::Error) -> Self {
        Self::Toml(e.to_string())
    }
}

/// Public material of every node, as published on the bulletin board.
#[derive(Clone, Debug)]
pub struct Keyring {
    pub run_id: u64,
    pub params: Params,
    pub crs: [u8; 32],
    ed25519: Vec<VerifyingKey>,
    bls: Vec<bls::Public>,
    pops: Vec<bls::Sig>,
}

#[derive(Serialize, Deserialize)]
struct KeyringFile {
    run_id: u64,
    n: usize,
    t: usize,
    crs: String,
    nodes: Vec<NodeEntry>,
}

#[derive(Serialize, Deserialize)]
struct NodeEntry {
    id: NodeId,
    ed25519: String,
    bls: String,
    bls_pop: String,
}

impl Keyring {
    pub fn n(&self) -> usize {
        self.params.n
    }

    pub fn ed25519(&self, id: NodeId) -> &VerifyingKey {
        &self.ed25519[usize::from(id)]
    }

    pub fn bls(&self, id: NodeId) -> &bls::Public {
        &self.bls[usize::from(id)]
    }

    /// Indexed by `NodeId`, as [`bls::MultiSig::verify`] wants it.
    pub fn bls_keys(&self) -> &[bls::Public] {
        &self.bls
    }

    pub fn prf(&self) -> Prf {
        Prf::new(self.crs)
    }

    pub fn to_toml(&self) -> Result<String, KeyringError> {
        let file = KeyringFile {
            run_id: self.run_id,
            n: self.params.n,
            t: self.params.t,
            crs: hex::encode(&self.crs),
            nodes: (0..self.n())
                .map(|i| NodeEntry {
                    id: NodeId::try_from(i).expect("n fits a NodeId"),
                    ed25519: hex::encode(&self.ed25519[i].to_bytes()),
                    bls: hex::encode(&self.bls[i].to_bytes()),
                    bls_pop: hex::encode(&self.pops[i].0),
                })
                .collect(),
        };
        Ok(toml::to_string_pretty(&file)?)
    }

    /// Parses and validates: parameters, key encodings and subgroup
    /// membership, and every proof of possession.
    pub fn from_toml(s: &str) -> Result<Self, KeyringError> {
        let file: KeyringFile = toml::from_str(s)?;
        let params = Params::new(file.n, file.t)?;
        if file.nodes.len() != params.n {
            return Err(KeyringError::Count {
                expected: params.n,
                got: file.nodes.len(),
            });
        }
        let mut ed25519 = Vec::with_capacity(params.n);
        let mut bls_keys = Vec::with_capacity(params.n);
        let mut pops = Vec::with_capacity(params.n);
        for (index, entry) in file.nodes.iter().enumerate() {
            if usize::from(entry.id) != index {
                return Err(KeyringError::Order {
                    index,
                    id: entry.id,
                });
            }
            let ed = VerifyingKey::from_bytes(&hex::decode_array(&entry.ed25519)?)
                .map_err(|e| KeyringError::Ed25519(e.to_string()))?;
            let pk = bls::Public::from_bytes(&hex::decode(&entry.bls)?)?;
            let pop = bls::Sig(hex::decode_array(&entry.bls_pop)?);
            if !pk.verify_pop(&pop) {
                return Err(KeyringError::Pop(entry.id));
            }
            ed25519.push(ed);
            bls_keys.push(pk);
            pops.push(pop);
        }
        Ok(Self {
            run_id: file.run_id,
            params,
            crs: hex::decode_array(&file.crs)?,
            ed25519,
            bls: bls_keys,
            pops,
        })
    }

    pub fn load(path: &Path) -> Result<Self, KeyringError> {
        Self::from_toml(&std::fs::read_to_string(path)?)
    }

    pub fn save(&self, path: &Path) -> Result<(), KeyringError> {
        Ok(std::fs::write(path, self.to_toml()?)?)
    }
}

/// A node's own secrets.
#[derive(Clone, Debug)]
pub struct NodeKeys {
    pub id: NodeId,
    pub run_id: u64,
    pub ed25519: SigningKey,
    pub bls: bls::Secret,
}

#[derive(Serialize, Deserialize)]
struct SecretFile {
    id: NodeId,
    run_id: u64,
    ed25519_seed: String,
    bls_secret: String,
}

impl NodeKeys {
    pub fn to_toml(&self) -> Result<String, KeyringError> {
        Ok(toml::to_string_pretty(&SecretFile {
            id: self.id,
            run_id: self.run_id,
            ed25519_seed: hex::encode(self.ed25519.as_bytes()),
            bls_secret: hex::encode(&self.bls.to_bytes()),
        })?)
    }

    pub fn from_toml(s: &str) -> Result<Self, KeyringError> {
        let file: SecretFile = toml::from_str(s)?;
        Ok(Self {
            id: file.id,
            run_id: file.run_id,
            ed25519: SigningKey::from_bytes(&hex::decode_array(&file.ed25519_seed)?),
            bls: bls::Secret::from_bytes(&hex::decode(&file.bls_secret)?)?,
        })
    }

    pub fn load(path: &Path) -> Result<Self, KeyringError> {
        Self::from_toml(&std::fs::read_to_string(path)?)
    }

    pub fn save(&self, path: &Path) -> Result<(), KeyringError> {
        Ok(std::fs::write(path, self.to_toml()?)?)
    }

    /// Checks that these secrets are the ones the keyring publishes for `id`.
    pub fn check_against(&self, keyring: &Keyring, id: NodeId) -> Result<(), KeyringError> {
        if self.run_id != keyring.run_id {
            return Err(KeyringError::RunId {
                expected: keyring.run_id,
                found: self.run_id,
            });
        }
        if self.id != id {
            return Err(KeyringError::NodeId {
                expected: id,
                found: self.id,
            });
        }
        if &self.ed25519.verifying_key() != keyring.ed25519(id)
            || &self.bls.public() != keyring.bls(id)
        {
            return Err(KeyringError::Mismatch(id));
        }
        Ok(())
    }
}

/// Deterministic key generation for a run: the same `(params, run_id, seed)`
/// gives the same keys, so experiment configs and tests are reproducible.
pub fn generate(params: Params, run_id: u64, seed: u64) -> (Keyring, Vec<NodeKeys>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut crs = [0u8; 32];
    rng.fill_bytes(&mut crs);
    let mut nodes = Vec::with_capacity(params.n);
    for i in 0..params.n {
        let mut ed_seed = [0u8; 32];
        rng.fill_bytes(&mut ed_seed);
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        nodes.push(NodeKeys {
            id: NodeId::try_from(i).expect("n fits a NodeId"),
            run_id,
            ed25519: SigningKey::from_bytes(&ed_seed),
            bls: bls::Secret::from_ikm(&ikm),
        });
    }
    let keyring = Keyring {
        run_id,
        params,
        crs,
        ed25519: nodes.iter().map(|k| k.ed25519.verifying_key()).collect(),
        bls: nodes.iter().map(|k| k.bls.public()).collect(),
        pops: nodes.iter().map(|k| k.bls.prove_possession()).collect(),
    };
    (keyring, nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain;

    #[test]
    fn generate_is_deterministic_and_files_roundtrip() {
        let params = Params::new(4, 2).unwrap();
        let (kr, nodes) = generate(params, 11, 1);
        let (kr2, _) = generate(params, 11, 1);
        assert_eq!(kr.crs, kr2.crs);
        assert_eq!(kr.ed25519(3), kr2.ed25519(3));
        assert_ne!(kr.crs, generate(params, 11, 2).0.crs);

        let text = kr.to_toml().unwrap();
        let back = Keyring::from_toml(&text).unwrap();
        assert_eq!(back.run_id, 11);
        assert_eq!(back.params, params);
        assert_eq!(back.crs, kr.crs);
        for i in 0..4u16 {
            assert_eq!(back.ed25519(i), kr.ed25519(i));
            assert_eq!(back.bls(i), kr.bls(i));
        }

        let nk = NodeKeys::from_toml(&nodes[2].to_toml().unwrap()).unwrap();
        nk.check_against(&back, 2).unwrap();
        assert!(matches!(
            nk.check_against(&back, 1),
            Err(KeyringError::NodeId { .. })
        ));
        let sig = crate::ed25519::sign(&nk.ed25519, domain::ECHO, 11, b"x");
        assert!(crate::ed25519::verify(
            back.ed25519(2),
            domain::ECHO,
            11,
            b"x",
            &sig
        ));
    }

    #[test]
    fn bad_proof_of_possession_is_rejected_at_load() {
        let params = Params::new(3, 1).unwrap();
        let (kr, _) = generate(params, 1, 7);
        let mut text = kr.to_toml().unwrap();
        // Swap node 1's proof for node 2's: a valid signature, wrong key.
        let pop1 = hex::encode(&kr.pops[1].0);
        let pop2 = hex::encode(&kr.pops[2].0);
        text = text.replacen(&pop1, &pop2, 1);
        assert!(matches!(
            Keyring::from_toml(&text),
            Err(KeyringError::Pop(1))
        ));

        let (other, _) = generate(params, 1, 8);
        let text = kr.to_toml().unwrap().replacen(
            &hex::encode(&kr.bls[0].to_bytes()),
            &hex::encode(&other.bls[0].to_bytes()),
            1,
        );
        assert!(matches!(
            Keyring::from_toml(&text),
            Err(KeyringError::Pop(0))
        ));
    }

    #[test]
    fn structural_errors() {
        let params = Params::new(3, 1).unwrap();
        // run_id 55: "run_id = 1" would otherwise match the "id = 1" replaced below.
        let (kr, _) = generate(params, 55, 7);
        let text = kr.to_toml().unwrap().replacen("n = 3", "n = 4", 1);
        assert!(matches!(
            Keyring::from_toml(&text),
            Err(KeyringError::Count {
                expected: 4,
                got: 3
            })
        ));
        let text = kr.to_toml().unwrap().replacen("id = 1", "id = 2", 1);
        assert!(matches!(
            Keyring::from_toml(&text),
            Err(KeyringError::Order { index: 1, id: 2 })
        ));
        assert!(matches!(
            Keyring::from_toml("nonsense"),
            Err(KeyringError::Toml(_))
        ));
    }
}
