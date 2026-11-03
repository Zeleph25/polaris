//! 32-byte digests with domain separation.

/// A blake3 digest; the paper's `κ`-bit hash.
pub type Digest = [u8; 32];

/// `H(tag ‖ len(body) ‖ body)`; the length prefix keeps tag and body from
/// being re-split.
pub fn digest(tag: &[u8], body: &[u8]) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&(body.len() as u64).to_le_bytes());
    h.update(body);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain;

    #[test]
    fn deterministic_and_domain_separated() {
        let body = b"m_i";
        assert_eq!(
            digest(domain::DISCLOSE, body),
            digest(domain::DISCLOSE, body)
        );
        assert_ne!(digest(domain::DISCLOSE, body), digest(domain::ACCUSE, body));
        assert_ne!(
            digest(domain::DISCLOSE, b"ab"),
            digest(domain::DISCLOSE, b"abc")
        );
    }
}
