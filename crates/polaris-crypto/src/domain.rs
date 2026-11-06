//! Domain-separation tags.
//!
//! Every signature and every digest is computed over `tag || run_id || body`,
//! so nothing signed as one message type or in one run verifies as another.
//! Accusations are deliberately scoped to the run only, not to a view: under
//! static corruption an honest accusation stays valid for the whole run, and
//! whether to reuse accusations across views is a measured decision.

pub const DISCLOSE: &[u8] = b"polaris/v1/ic/disclose";
pub const ACCUSE: &[u8] = b"polaris/v1/accuse";
pub const HANDSHAKE: &[u8] = b"polaris/v1/net/handshake";
pub const LEADER_PRF: &[u8] = b"polaris/v1/leader";
pub const ECHO: &[u8] = b"polaris/v1/echo";

pub const NAIVE_BB: &[u8] = b"polaris/v1/bb/naive";
pub const DS_ECHO: &[u8] = b"polaris/v1/bb/dolev-strong/echo";

pub const WXSD_PROPOSE: &[u8] = b"polaris/v1/bb/wxsd/propose";
pub const WXSD_VOTE: &[u8] = b"polaris/v1/bb/wxsd/vote";
pub const WXSD_COMMIT: &[u8] = b"polaris/v1/bb/wxsd/commit";
pub const WXSD_VALUE: &[u8] = b"polaris/v1/bb/wxsd/value";
pub const WXSD_LEADER_PRF: &[u8] = b"polaris/v1/bb/wxsd/leader";

/// BLS hash-to-curve domain separation tags (DSTs); the message type is
/// separated by the tag inside the signed input, the proof of possession by
/// its own DST as the BLS standard requires.
pub const BLS_DST: &[u8] = b"POLARIS-V1-BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_";
pub const BLS_POP_DST: &[u8] = b"POLARIS-V1-BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

/// Every message tag, for the uniqueness test and for documentation.
pub const ALL: &[&[u8]] = &[
    DISCLOSE,
    ACCUSE,
    HANDSHAKE,
    LEADER_PRF,
    ECHO,
    NAIVE_BB,
    DS_ECHO,
    WXSD_PROPOSE,
    WXSD_VOTE,
    WXSD_COMMIT,
    WXSD_VALUE,
    WXSD_LEADER_PRF,
];

#[cfg(test)]
mod tests {
    use super::ALL;

    #[test]
    fn tags_are_distinct_and_prefix_free() {
        for (i, a) in ALL.iter().enumerate() {
            for (j, b) in ALL.iter().enumerate() {
                if i != j {
                    assert!(
                        !b.starts_with(a),
                        "{} is a prefix of {}",
                        String::from_utf8_lossy(a),
                        String::from_utf8_lossy(b)
                    );
                }
            }
        }
    }
}
