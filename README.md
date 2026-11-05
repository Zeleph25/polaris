# polaris

Interactive Consistency (IC) under a dishonest majority, in Rust.

polaris implements the compiler of *Parallel Broadcast from Single-Source
Broadcast, for Free?* for t <= (1 - epsilon) n corruptions: in each view a
PRF-elected leader assembles one verifiable vector with LearnOrExpose and
broadcasts it once, instead of running n parallel Byzantine broadcasts. The
goal is to measure that protocol against n parallel broadcasts and a
specialized parallel-broadcast protocol.

Current state: the foundations (keys, drivers, metrics), the accusation
graph and LearnOrExpose, the Dolev-Strong broadcast, and a naive two-round
broadcast that exercises the broadcast interface. The compiler, WXSD and the
baselines are next. See [docs/design.md](docs/design.md) for the
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
                           (Dolev-Strong, and a naive one for the harness)
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

The network runner currently runs the signed echo protocol, which is what
the drivers are validated with; the protocol machines of `polaris-proto` are
exercised under the simulator until the compiler exists.

```
# n nodes in this process over real TCP; every inbox is compared with the simulator's
cargo run --release -- local --n 8 --round-ms 200 --out runs/local

# keys and configs for n separate processes on one host, then one terminal per node
cargo run --release -- genconfig --n 4 --t 1 --out cluster --base-port 7000 --round-ms 200 --start-in-s 15
cargo run --release -- node --config cluster/node-0.toml   # and node-1, node-2, node-3 before the start

# only the bulletin-board key file and the secret files
cargo run --release -- keygen --n 8 --t 4 --out keys
```

`genconfig` writes `keyring.toml` (every node's public keys and proofs of
possession), `node-<i>.secret.toml` and `node-<i>.toml`. The config carries
the peer addresses, the round length, the shared wall-clock start of round 0,
and limits (`max_rounds`, `linger_rounds`, `connect_timeout_s`,
`max_frame_bytes`); relative paths resolve against the config file. For
hosts other than one machine, edit the `peers` list, keep the same
`start_at_unix_ms` everywhere, and make sure the clocks are synchronized to
well within one round.

Each node writes into its `out_dir`:

- `node-<i>.metrics.jsonl`: one line per round (messages and bytes sent and
  received, late messages, signature verifications and their time) and a
  `summary` line with the totals and the decision round; a late message is
  one that arrived after the end of the round it was sent in, so a nonzero
  count means the round length was too short for that network;
- `node-<i>.transcript.jsonl`: what the node received in each round, with
  order-independent digests, in the format the simulator produces, so the two
  can be diffed;
- `node-<i>.output.json`: the decided value.

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
