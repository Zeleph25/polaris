# polaris

Interactive Consistency (IC) under a dishonest majority, in Rust.

polaris implements the compiler of *Parallel Broadcast from Single-Source
Broadcast, for Free?* for t <= (1 - epsilon) n corruptions: in each view a
PRF-elected leader assembles one verifiable vector with LearnOrExpose and
broadcasts it once, instead of running n parallel Byzantine broadcasts. The
goal is to measure that protocol against n parallel broadcasts and a
specialized parallel-broadcast protocol.

Current state: the foundations (keys, drivers, metrics), the accusation
graph and LearnOrExpose, the Dolev-Strong and WXSD broadcasts, the
compiler over either, which gives end-to-end Interactive Consistency both
under the simulator and over TCP, and the baselines (n parallel
broadcasts). The evaluation harness is next. See [docs/design.md](docs/design.md) for the
design and its decisions and [docs/messages.md](docs/messages.md) for the
wire formats.

## Layout

```
polaris/                   root package: the node binary
  src/
    main.rs                command line: keygen, genconfig, node, local
    net.rs                 authenticated TCP channels (nonce handshake, framed, round-labeled)
    runner.rs              wall-clock round schedule, late-message accounting, output files
    config.rs              per-node TOML configuration
    local.rs               an n-node cluster in one process, checked against the simulator
  crates/
    polaris-core/          NodeId, Round, Params, NodeSet, wire encoding, RoundMachine, Metrics
    polaris-crypto/        Ed25519 (batch verify), BLS12-381 multi-signatures with proofs of
                           possession, HMAC PRF, hashing, domain tags, key files
    polaris-proto/         trust graph, accusations, disclosures, LearnOrExpose, broadcasts
                           (Dolev-Strong, WXSD, and a naive one for the harness), the IC
                           compiler, the parallel-broadcast baseline
    polaris-sim/           lockstep simulator, adversaries, transcripts
  docs/                    design.md, messages.md
```

Every protocol is a `RoundMachine`: a deterministic state machine that is
given the messages of a round and returns the messages to send next, with no
I/O of its own. The same machine runs under the simulator (exact round
counts, scripted adversaries, reproducible transcripts) and under the
network runner (wall-clock experiments over TCP).

## Build and test

Toolchain: stable, pinned by `rust-toolchain.toml`; MSRV 1.88. `blst`
compiles C and assembly, so a C compiler is needed (`xcode-select --install`
on macOS, `build-essential` on Debian and Ubuntu).

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps
```

The default test suite runs in well under a minute in debug mode (the crypto
and the runtime are compiled with optimizations even there, see
`[profile.dev.package."*"]` in `Cargo.toml`).

### Adversary tests and the full sweep

`crates/polaris-proto/tests/learn_or_expose.rs` runs LearnOrExpose under a
fixed adversary suite: silent nodes, withheld and late disclosures, nodes
that never forward, Byzantine nodes accusing every honest node every round,
floods of forged accusations, and a Byzantine leader trying forged vectors.
`crates/polaris-proto/tests/robustness.rs` draws the Byzantine set and each
Byzantine node's behavior from a seed. The small sweep is part of
`cargo test`; the full one is ignored by default:

```
cargo test -p polaris-proto --release --test robustness -- --ignored --nocapture
```

It runs (n, t) from (8, 4) up to (64, 48) with 25 seeds each and prints one
line per scenario (resolution round, accepted and rejected accusations,
proof size, bytes sent). The last full run took 96 minutes on one core and
passed every scenario.

### Benchmarks

```
cargo bench -p polaris-crypto --bench signatures    # Ed25519, BLS, multi-signatures, key file loading
cargo bench -p polaris-proto --bench make_graph     # MakeGraph and accusation verification up to n = 128
```

Criterion writes its reports under `target/criterion/`.

## Running nodes

The network runner runs one of three protocols (`--protocol`): the signed
echo (`echo`, the drivers' validation protocol, two rounds), Interactive
Consistency (`ic`, the compiler of the paper) or the baseline of n parallel
broadcasts (`parallel`), the last two over the broadcast of `--broadcast`:
`dolev-strong` (the default, t + 1 rounds) or `wxsd` (expected constant
epochs). Every node's input is `input-of-<i>`. All nodes are honest on the
network; adversaries live in the simulator.

```
# n nodes in this process over real TCP; every inbox is compared with the simulator's
cargo run --release -- local --protocol ic --n 16 --t 4 --round-ms 300 --out runs/local

# keys and configs for n separate processes on one host, then one terminal per node
cargo run --release -- genconfig --protocol ic --n 4 --t 1 --out cluster --base-port 7000 --round-ms 300 --start-in-s 15
cargo run --release -- node --config cluster/node-0.toml   # and node-1, node-2, node-3 before the start

# only the bulletin-board key file and the secret files
cargo run --release -- keygen --n 8 --t 4 --out keys
```

`--view-spacing` sets `c` for `ic` (default R). `genconfig` writes
`keyring.toml` (every node's public keys and proofs of possession),
`node-<i>.secret.toml` and `node-<i>.toml`. The config carries the peer
addresses, the round length, the shared wall-clock start of round 0, the
protocol and its options, and limits (`max_rounds`, `linger_rounds`,
`connect_timeout_s`, `max_frame_bytes`); relative paths resolve against the
config file. For hosts other than one machine, edit the `peers` list, keep
the same `start_at_unix_ms` everywhere, and make sure the clocks are
synchronized to well within one round.

Each node writes into its `out_dir`:

- `node-<i>.metrics.jsonl`: one line per round (messages and bytes sent and
  received, late messages, signature verifications and their time) and a
  `summary` line with the totals and the decision round; a late message is
  one that arrived after the end of the round it was sent in, so a nonzero
  count means the round length was too short for that network;
- `node-<i>.transcript.jsonl`: what the node received in each round, with
  order-independent digests, in the format the simulator produces, so the two
  can be diffed;
- `node-<i>.output.json`: the decided value (for `ic`: the view and the
  vector, values in hex, `null` for bottom).

With all nodes honest, `ic` decides in view 1 at round `R + t + 1` over
Dolev-Strong (round 0 discloses, LearnOrExpose takes R rounds, Dolev-Strong
t + 1) and at round `R + 2(d + 1) + 1` over WXSD, with
`d = ceil(2n / (n - t))`: for n = 32, t = 16 that is round 22 against
round 16. The heavy rounds are LearnOrExpose's first (every node sends
every disclosure it holds to everyone, `n^2` messages per node) and WXSD's
Commit phase (every node forwards every commit, each carrying `n` votes).
On a two-core machine, 64 nodes in one process keep up with 2 s rounds over
Dolev-Strong, and 32 nodes over WXSD, with zero late messages and inboxes
identical to the simulator's; 500 ms rounds are too short at those sizes.

First numbers, node 0 of an all-honest run in one process on two cores
with 2 s rounds (`local --out`, the `summary` line of the metrics file):

| protocol | broadcast | n | t | decision round | messages | bytes | signature checks |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ic | dolev-strong | 16 | 4 | 9 | 816 | 108 KB | 33 |
| ic | wxsd | 16 | 4 | 13 | 1904 | 668 KB | 98 |
| parallel | dolev-strong | 16 | 4 | 4 | 256 | 36 KB | 15 |
| parallel | wxsd | 16 | 4 | 8 | 8976 | 7.9 MB | 784 |
| ic | dolev-strong | 32 | 16 | 22 | 5280 | 760 KB | 67 |
| ic | wxsd | 32 | 16 | 16 | 7392 | 4.3 MB | 194 |
| parallel | dolev-strong | 32 | 16 | 16 | 1024 | 147 KB | 31 |
| parallel | wxsd | 32 | 16 | (115 MB sent per node, then out of memory) | | | |

With every node honest, n parallel Dolev-Strong is one forward per value
and nothing beats it; the compiler's advantage is against n parallel WXSD,
where it sends an order of magnitude fewer bytes, and in adversarial runs,
which the simulator measures.

Logging goes through `tracing`; set `RUST_LOG=debug` for per-round detail.

## Conventions

- Protocol logic never does I/O: it lives in `polaris-proto` as round
  machines and takes its keys at construction.
- Every signature covers `tag || run_id || len(body) || body` and every
  digest `tag || len(body) || body`, with a tag per message type
  (`polaris-crypto/src/domain.rs`), so nothing signed in one role or one run
  verifies in another.
- Wire format is `postcard`; sizes reported in metrics are the encoded
  lengths.
- `cargo clippy` with warnings denied and `cargo fmt` are part of CI.
