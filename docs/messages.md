# Message catalogue (M0)

Every message type on the wire, who signs it, over what, and its size. Sizes
in bytes; `n` processes, `L_in` input size, Ed25519 signature 64 B, BLS
signature 96 B (`min_pk`) or 48 B (`min_sig`) — decision pending.

Every envelope carries: `run_id` (8), `view` (varint), `instance` (1),
`round` (varint), then the payload below. Signatures are over
`tag ‖ run_id ‖ body` (tags in `polaris-crypto/src/domain.rs`).

| Message | Instance | Body | Signed by | Signature | Size (approx.) | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `disclose` | IC compiler, round 0; forwarded inside LearnOrExpose | sender `j`, `m_j` | `j` | Ed25519 | 2 + L_in + 64 | first valid one per sender is kept; conflicting ones ignored |
| `accuse` | LearnOrExpose view `v`; WXSD trust graph | accuser `a`, target `b` | `a` | BLS (aggregatable per target) | 4 + sig | unscoped by view on purpose (see domain.rs) |
| `vector` (LoE output) | input of BB_v | `vec[1..n]`, `sigs[1..n]`, `Π[j] = (multisig, signer bitset)` for `vec[j] = ⊥` | — | carried signatures | n(L_in + 64) + k(sig + n/8) | `k` = number of exposed entries |
| `ds-echo` | Dolev–Strong BB_v (M3) | value hash, chain of `≤ r` signatures | each forwarder | Ed25519 | 32 + r(2 + 64) | value itself only in the sender's first message |
| `wxsd-propose` | WXSD BB_v, epoch `e` (M4) | value or ⊥, commit evidence | epoch leader | Ed25519 | TBD | TrustCast-forwarded |
| `wxsd-vote` | WXSD BB_v, epoch `e` | value hash or ⊥ | voter | Ed25519 | TBD | TrustCast-forwarded |
| `wxsd-commit` | WXSD BB_v, epoch `e` | commit evidence (signed votes) or ⊥ | committer | Ed25519 | TBD | TrustCast-forwarded |
| `equivocation` | any TrustCast | two conflicting signed messages from one sender | — | carried | 2 × msg | removes the sender from the trust graph |
| `handshake` | network runner, per connection | nonce, node id | connecting node | Ed25519 | 2 + 32 + 64 | authenticated channels; nothing else is signed per message |

Open: exact WXSD bodies after reading WXSD §4–5; whether votes and commits
carry the hash only (depends on the commit-evidence rule).
