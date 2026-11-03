# polaris

Interactive Consistency (IC) under a dishonest majority, in Rust: an
implementation and evaluation of the compiler from *Parallel Broadcast from
Single-Source Broadcast, for Free?* (one verifiable vector per view, broadcast
once, instead of n parallel broadcasts), against n parallel Byzantine
Broadcasts and a specialised parallel-broadcast protocol.

Project brief, milestones and design decisions: see the brief doc
(link in the project's chat; copy it here).

## Layout

```
polaris/                 root package: the node binary (tokio runner, CLI)
  src/main.rs
  crates/
    polaris-core/        ids, rounds, Params, wire encoding, the RoundMachine interface
    polaris-crypto/      Ed25519 (batch), BLS12-381 multisig + PoP, PRF, hashing, keygen
    polaris-proto/       trust graph, LearnOrExpose, Byzantine broadcasts, IC compiler, baselines
    polaris-sim/         lockstep simulator, adversaries, transcripts
  docs/messages.md       message catalogue (M0)
```

One rule: protocol logic is written as deterministic round machines with no
I/O, driven either by the simulator (tests, adversaries, exact round counts)
or by the network runner (wall-clock experiments).

## Build

```
rustup update stable
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Toolchain: stable (pinned by `rust-toolchain.toml`), MSRV 1.88. `blst` builds
C and assembly, so a C compiler is needed (`xcode-select --install` on macOS).
