//! Domain-separation tags.
//!
//! Every signature and every digest is computed over `tag ‖ run_id ‖ body`,
//! so nothing signed as one message type or in one run verifies as another.
//! Accusations are deliberately scoped to the run only, not to a view: under
//! static corruption an honest accusation stays valid for the whole run, and
//! whether to reuse accusations across views is a measured decision (M7).

pub const DISCLOSE: &[u8] = b"polaris/v1/ic/disclose";
pub const ACCUSE: &[u8] = b"polaris/v1/accuse";
pub const BLS_POP: &[u8] = b"polaris/v1/bls-pop";
pub const HANDSHAKE: &[u8] = b"polaris/v1/net/handshake";
pub const LEADER_PRF: &[u8] = b"polaris/v1/leader";

pub const DS_ECHO: &[u8] = b"polaris/v1/bb/dolev-strong/echo";

pub const WXSD_PROPOSE: &[u8] = b"polaris/v1/bb/wxsd/propose";
pub const WXSD_VOTE: &[u8] = b"polaris/v1/bb/wxsd/vote";
pub const WXSD_COMMIT: &[u8] = b"polaris/v1/bb/wxsd/commit";

/// Every tag, for the uniqueness test and for documentation.
pub const ALL: &[&[u8]] = &[
    DISCLOSE,
    ACCUSE,
    BLS_POP,
    HANDSHAKE,
    LEADER_PRF,
    DS_ECHO,
    WXSD_PROPOSE,
    WXSD_VOTE,
    WXSD_COMMIT,
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
