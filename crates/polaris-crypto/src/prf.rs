//! A PRF keyed by the common random string; leader election.
//!
//! The crs is sampled after the corruption set is fixed (paper, Section 6.1.2), so
//! the adversary cannot pick corruptions to match the leaders. HMAC-SHA-256
//! is the PRF; the leader of view `v` is `PRF(v) mod n` (0-based here, the
//! paper's `(PRF(v) mod n) + 1`), with a bias of at most `n / 2^64`.

use hmac::{Hmac, KeyInit, Mac};
use polaris_core::{NodeId, View};
use sha2::Sha256;

use crate::domain;

#[derive(Clone, Debug)]
pub struct Prf {
    key: [u8; 32],
}

impl Prf {
    pub fn new(crs: [u8; 32]) -> Self {
        Self { key: crs }
    }

    pub fn eval(&self, tag: &[u8], input: u64) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes any key length");
        mac.update(tag);
        mac.update(&input.to_le_bytes());
        mac.finalize().into_bytes().into()
    }

    pub fn leader(&self, view: View, n: usize) -> NodeId {
        self.leader_of(domain::LEADER_PRF, &u64::from(view).to_le_bytes(), n)
    }

    /// `PRF_tag(input) mod n`, for elections other than the compiler's views.
    pub fn leader_of(&self, tag: &[u8], input: &[u8], n: usize) -> NodeId {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes any key length");
        mac.update(tag);
        mac.update(input);
        let out: [u8; 32] = mac.finalize().into_bytes().into();
        let x = u64::from_le_bytes(out[..8].try_into().expect("8 bytes"));
        NodeId::try_from(x % n as u64).expect("n fits a NodeId")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_in_range_and_spread() {
        let prf = Prf::new([5u8; 32]);
        assert_eq!(prf.leader(1, 7), prf.leader(1, 7));
        assert_ne!(prf.eval(b"a", 1), prf.eval(b"b", 1));
        assert_ne!(Prf::new([6u8; 32]).leader(1, 1000), prf.leader(1, 1000));
        let n = 4;
        let mut counts = [0u32; 4];
        for v in 1..=1000 {
            let l = prf.leader(v, n);
            assert!(usize::from(l) < n);
            counts[usize::from(l)] += 1;
        }
        assert!(counts.iter().all(|&c| c > 150), "{counts:?}");
    }
}
