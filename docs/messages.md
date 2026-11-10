# Message catalogue

Every message type on the wire: who signs it, over what, and its encoded size.
The wire format is `postcard` (`polaris-core/src/wire.rs`): integers are
LEB128 varints, byte strings and vectors carry a varint length, enum
variants a varint tag. In the sizes below `n` is the number of nodes, `L`
the length of a value, and node ids take 1 byte (2 bytes from id 128 on).
An Ed25519 signature encodes to 65 bytes (64 plus its length), a BLS
signature to 49 (48 plus its length), a node set to about `3 + ceil(n / 8)`,
and the run id to 1 byte for small ids (up to 10 bytes). Sizes are for a
message on its own; inside an enum such as `LoeMsg` add 1 for the variant.

Every signature covers `tag || run_id || len(body) || body` with the tags of
`polaris-crypto/src/domain.rs`, so nothing signed as one message type or in
one run verifies as another. Accusations are scoped to the run, not to a
view, so that reusing them across views stays possible without a format
change.

| Message | Where | Body | Signed by | Signature | Size | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `Disclosure` | forwarded inside LearnOrExpose as `LoeMsg::Disclose`; later also the compiler's round 0 | `sender`, `value` | sender | Ed25519 on `value`, tag `ic/disclose` | `67 + L` | the first valid one per sender is kept |
| `Accusation` | LearnOrExpose as `LoeMsg::Accuse`; later also the WXSD trust graph | `accuser`, `target` | accuser | BLS on `target` (2 bytes little-endian), tag `accuse` | `51` | aggregatable per target; a self-accusation or an unknown id is rejected before any pairing |
| `MultiSig` | inside a proof | `signers` (node set), `sig` | the signers | one aggregate BLS signature on one body | `3 + ceil(n / 8) + 49` | verified against the sum of the signers' public keys; every key in the keyring has a checked proof of possession |
| `AccusationProof` | the `Pi` of a verifiable vector | `per_target[j]`: the multi-signature of all accusations against `j`, or none | carried | | `n + k (3 + ceil(n / 8) + 49)` | `k` accused targets; `O(n^2 + n kappa)` bits |
| `VerifiableVector` | LearnOrExpose output; later the input of the view's broadcast | `entries[j]`: `j`'s disclosure or bottom; `proof` | carried | | `n + present disclosures + proof` | `VerifyVec_in` checks the entries, `VerifyVec_out` also the disconnections |
| `IcMsg` | the compiler | `Disclose(Disclosure)`, `Loe { view, msg: LoeMsg }` or `Bb { view, msg }` | carried | | `1 + inner`, plus the view varint for the last two | the view routes the message to its LearnOrExpose or broadcast instance; messages for a view that has not started or has finished are dropped |
| `ParMsg` | the parallel baseline | `instance` (the sender's id), `msg` of the broadcast | carried | | `1 + inner` | routes the message to its instance |
| `DsMsg` | the Dolev-Strong broadcast | `value`, `chain` of `Link { signer, sig }` | the sender, then every forwarder | each link: Ed25519 on `instance (8 bytes) || H(value)`, tag `bb/dolev-strong/echo` | `1 + L + 1 + k * 66` | `k` links; a message received in round `r` needs at least `r` distinct signers, the first being the sender; at most two values are forwarded per node |
| `NaiveMsg` | the naive two-round broadcast | `value`, `sig` | the broadcast's sender | Ed25519 on `instance (8 bytes) || value`, tag `bb/naive` | `66 + L` | forwarded as is in round 2; a harness protocol, not a Byzantine broadcast |
| `WxsdMsg::Propose` | WXSD, Propose phase | `Signed<Proposal { epoch, value, evidence }>` | the epoch's leader | Ed25519 on `instance || body`, tag `bb/wxsd/propose` | `3 + L + evidence` | the only message that carries a value; `evidence` is the freshest commit evidence the leader holds, or none |
| `WxsdMsg::Vote` | WXSD, Vote phase | `Signed<Vote { epoch, ballot }>`, ballot `Abstain` or `For(digest)` | every node | Ed25519, tag `bb/wxsd/vote`; with aggregated evidence also BLS on the same body | `71` or `104`, plus `49` with the BLS part | `Abstain` when the leader has left the voter's graph |
| `WxsdMsg::Commit` | WXSD, Commit phase | `Signed<Commit { epoch, evidence }>` | every node | Ed25519, tag `bb/wxsd/commit` | `70` or `70 + evidence` | evidence: `epoch`, `digest`, and either the signed votes of everyone in the committer's graph (`37 + 104 k` bytes for `k` votes) or one BLS multi-signature with the signer set (about `37 + 52 + ceil(n / 8)`) |
| `WxsdMsg::Accuse` | WXSD, any round | an `Accusation` | the accuser | BLS, tag `accuse` | `52` | the paper's distrust message; same type as LearnOrExpose's |
| `WxsdMsg::Equivocation` | WXSD, any round | two signed messages of one type and epoch from one node with different bodies | carried | | `2 x` message | removes the node from every graph; forwarded once |
| `EchoMsg::Value` | signed echo, round 1 | `value`, `sig` | sender | Ed25519 on `"value:" || value`, tag `echo` | `67 + L` | the drivers' validation protocol |
| `EchoMsg::Confirm` | signed echo, round 2 | `digest` of the vector of values, `sig` | sender | Ed25519 on `"confirm:" || digest`, tag `echo` | `98` | |
| `Hello` | network runner, once per connection | `from`, `to`, `run_id`, `sig` | the connecting node | Ed25519 on `nonce || from || to` (32-byte nonce chosen by the acceptor), tag `net/handshake` | `68` | after the handshake nothing is signed per message |
| `Frame` | network runner, one per peer and round | `run_id`, `round`, `payloads` | none | | `4 + 2..15 + sum of (1 + payload)` | 4-byte big-endian length prefix; every message of the round for that peer; `round` is the round they were sent in, which is how late messages are counted |
