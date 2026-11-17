# polaris

Interactive Consistency (IC) under a dishonest majority, in Rust.

polaris implements the compiler of *Parallel Broadcast from Single-Source
Broadcast, for Free?* for t <= (1 - epsilon) n corruptions: in each view a
PRF-elected leader assembles one verifiable vector with LearnOrExpose and
broadcasts it once, instead of running n parallel Byzantine broadcasts. The
goal is to measure that protocol against n parallel broadcasts and a
specialized parallel-broadcast protocol. An earlier version of the paper is
Civit, Emdin and Guerraoui, *Constant-Round Interactive Consistency in
Dishonest Majority, or with Quadratic Communication in Honest Majority*
([ePrint 2026/1146](https://eprint.iacr.org/2026/1146)).

Current state: the foundations (keys, drivers, metrics), the accusation
graph and LearnOrExpose, the Dolev-Strong and WXSD broadcasts, the
compiler over either, which gives end-to-end Interactive Consistency both
under the simulator and over TCP, the baselines (n parallel broadcasts),
and the evaluation harness that runs them all and plots the results. See [docs/design.md](docs/design.md) for the
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
  eval/                    matrix.toml, run.py (one process per node), aggregate.py (tables, plots)
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

`--view-spacing` sets `c` for `ic` (default R; `0` makes the views
sequential, the next starting only when the previous broadcast delivered
without a decision), `--input-bytes` the size of every node's input
(default: the short label `input-of-<i>`), `--aggregate-votes` makes
WXSD send commit evidence as one BLS multi-signature instead of the signed
votes, `--share-accusations` carries the accusations of finished
instances into the next ones, `--share-disclosures` sends each
disclosure once per run instead of once per view, and `--worker-threads`
sets the worker threads of each node's runtime (default one per core;
with several nodes on a host, about cores / nodes, see decision 14 in
docs/design.md). `genconfig` writes
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
The runner packs a round's messages to one peer into a single frame, so a
round costs `n` system calls per node whatever the protocol sends; on a
two-core machine, 64 nodes in one process keep up with 500 ms rounds over
Dolev-Strong and 32 nodes over WXSD, with zero late messages and inboxes
identical to the simulator's.

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
| parallel | wxsd | 32 | 16 | 10 | 68640 | 115 MB | 3104 |

With every node honest, n parallel Dolev-Strong is one forward per value
and nothing beats it; the compiler's advantage is against n parallel WXSD,
where it sends an order of magnitude fewer bytes (27 times fewer at
n = 32, a run that needs 5.6 GB for the 32 nodes of one process), and in
adversarial runs, which the simulator measures.

Input size changes the picture. At 10 KB inputs and n = 16, bytes sent per
node, all honest:

| | pipelined views (c = R) | pipelined, shared disclosures | sequential views (c = 0) | n parallel |
| --- | --- | --- | --- | --- |
| over Dolev-Strong | 13.4 MB | 7.9 MB | 5.4 MB | 2.7 MB |
| over WXSD, aggregated evidence | 19.3 MB | 11.2 MB | 5.7 MB | 4.2 MB |

With pipelining, views 2 and 3 start while view 1 is about to succeed, and
every view's LearnOrExpose sends all `n` disclosures it holds to everyone
(`n^2 L` bytes per node in its first round); the decision round is
the same either way. What remains with sequential views is one such round
plus the vector forwarded once by every node (another `n^2 L`), which is
twice what n parallel Dolev-Strong sends when nobody attacks. Under attack
(t Byzantine nodes, each silent with probability 0.3 and otherwise
delivering to a random half of the nodes; 10 seeds) at n = 32, t = 16,
sequential views over Dolev-Strong decide in 24.2 +- 7.0 rounds against
22.5 +- 1.6 pipelined, for a quarter of the bytes (0.40 MB against
1.69 MB): a whole view of latency per failed view.

Shared disclosures (`--share-disclosures`) keep pipelining and its rounds
but send each disclosure once per run instead of once per view: about 41 %
fewer bytes at 10 KB inputs, the same decision in the same round. What
pipelining still costs over sequential views is the leader's vector of
every view whose broadcast starts before the decision. The design notes
(decision 12) give the argument that this keeps LearnOrExpose's
invariant.

Aggregated vote evidence (`--aggregate-votes`: one BLS multi-signature per
commit instead of the signed votes) takes WXSD's Commit phase, the heaviest
round of the system, down by a factor of four to six, bytes sent per node
with every node honest:

| | paper's evidence | aggregated |
| --- | --- | --- |
| polaris over WXSD, n = 16 | 677 KB | 279 KB |
| polaris over WXSD, n = 32 | 4.3 MB | 1.1 MB |
| n parallel WXSD, n = 16 | 8.0 MB | 1.4 MB |
| n parallel WXSD, n = 32 | 116 MB | 10.6 MB |

Signature work moves the other way at small n (a pairing costs twenty
Ed25519 checks, and every vote now gets one per distinct body per round),
and comes out ahead from n = 32 on.

Shared accusations (`--share-accusations`: every instance starts from the
accusations of the finished ones, gossiped once at the run level and handed
to the instances already running) pay off over Dolev-Strong and cost rounds
over WXSD. Mean decision round and bytes per honest node under the same
attack, 10 seeds:

| | fresh graph per instance | shared |
| --- | --- | --- |
| over Dolev-Strong, n = 32, t = 16 | 22.5 rounds, 1.69 MB | 22.5 rounds, 1.05 MB |
| over Dolev-Strong, n = 32, t = 24 | 34.9 rounds, 3.28 MB | 34.9 rounds, 1.87 MB |
| over WXSD, aggregated, n = 32, t = 16 | 19.0 rounds, 3.26 MB | 26.5 rounds, 2.87 MB |
| over WXSD, aggregated, n = 32, t = 24 | 33.9 rounds, 5.29 MB | 123.9 rounds, 8.60 MB |

Carried into WXSD, the accusations a Byzantine leader drew in its
LearnOrExpose make it distrusted from the first round of its own broadcast,
which then runs until an epoch with an honest epoch leader and delivers
bottom. On a fresh graph, a Byzantine leader that runs the protocol, even
delivering selectively, usually gets its vector through in the first epoch
and the view decides. Views decide in order, so one such view holds back
every later one: at t = 24, one seed in ten took 649 rounds.

The n parallel WXSD network run at n = 32 only completes with aggregation;
with 32 processes on two cores at 500 ms rounds it still reports late
messages. On a 16-core server it runs on schedule (see the Evaluation
section below).

Logging goes through `tracing`; set `RUST_LOG=debug` for per-round detail.

## Evaluation

`eval/matrix.toml` lists the experiments (protocol, broadcast, sizes,
repetitions, round length, and for runs under attack the adversary);
`eval/run.py` runs them, with one process per node on this host for the
honest runs (`mode = "net"`) and in the simulator for the runs with
Byzantine nodes (`mode = "sim"`), and `eval/aggregate.py` turns the results
into a table and plots:

```
cargo build --release
python3 eval/run.py eval/matrix.toml --out eval/results        # --only ic-wxsd for one experiment
python3 eval/aggregate.py eval/results --plots
```

Every run keeps its cluster files, the nodes' logs and their metrics,
transcript and output files under `eval/results/<experiment>/n<n>-t<t>/rep<k>/`,
and `summary.md`, `summary.csv` and one PNG per metric appear in
`eval/results/`. The metrics are the decision round and the wall-clock time
to decision (the largest over the nodes), bytes and messages sent and
received, signature verification time, CPU time and peak memory (means per
node), late messages, and whether every node decided the same output. Time,
CPU and memory come from network runs only: the simulator runs every node in
one process, so those cells are empty in its rows. Python 3.11 or newer;
matplotlib for the plots.

Runs under attack use `polaris sim`, which draws `--byzantine` nodes (at
most t) from the seed and has them play `--adversary silent` (send
nothing), `selective` (the honest protocol delivered to a random half of
the nodes only), `mixed`, or `ds-chaos` (Dolev-Strong only: senders
equivocate with fabricated values, forwarders extend every chain with
their signature and scatter it, and well-formed chains with garbage
signatures are flooded so that every honest node verifies and rejects
them), or `wxsd-chaos` (WXSD only: leaders propose two values, voters
equivocate, attach BLS parts that do not verify or vote late, committers
attach evidence that does not verify or commit late, and garbage-signed
copies of seen messages are flooded); honest nodes get the same files as on the network, and the
simulator counts rounds, messages, bytes and signature work exactly, so
only wall-clock time is missing from those rows:

```
cargo run --release -- sim --protocol ic --broadcast wxsd --n 32 --t 16 --adversary mixed --seed 1 --out runs/sim
```

The matrix as shipped (n up to 32, three repetitions, 500 ms rounds, the
four protocols honest and under attack) runs in about seven minutes on two
cores. Across several machines, the same launcher starts the nodes over
ssh: [docs/multihost.md](docs/multihost.md) lists what the hosts need,
`eval/check_hosts.py` checks them, and `eval/hosts.toml` holds the runs.
`eval/round_search.py` finds the shortest round length at which a
construction has no late message, and `run.py --round-ms-from` runs every
row at 500 ms or at that minimum (decision 15 in docs/design.md).

### On one server with 48 cores

The runs of `eval/hosts.toml` (every node honest, three runs each) on one
EPFL lab server with four Intel Xeon E7-4830 v3 processors (48 cores, 96
hardware threads, 2.1 GHz, 504 GB), every node a separate process. Each
node's runtime gets 96 / n workers: 6 at n = 16, 3 at n = 32 and 1 at
n = 64 (decision 14 in docs/design.md). Every row runs with 500 ms rounds
unless the round search (decision 15) found that it needs longer ones,
which only n parallel WXSD at n = 64 does. Time to decision is the largest
over the nodes, CPU time and peak memory are means per node, and the
ranges cover the two values of t:

| | n | round | t = n/2 | t = 3n/4 | past the round | CPU per node | memory per node |
| --- | --- | --- | --- | --- | --- | --- | --- |
| polaris over Dolev-Strong | 16 | 500 ms | 7.5 s (round 14) | 11.5 s (round 22) | 4 to 5 ms | 113 to 117 ms | 14 MB |
| polaris over Dolev-Strong | 32 | 500 ms | 11.5 s (round 22) | 17.5 s (round 34) | 7 to 8 ms | 228 to 237 ms | 14 MB |
| polaris over Dolev-Strong | 64 | 500 ms | 19.5 s (round 38) | 29.5 s (round 58) | 12 to 13 ms | 546 to 567 ms | 14 MB |
| polaris over WXSD, aggregated | 16 | 500 ms | 8.5 s (round 16) | 14.5 s (round 28) | 18 ms | 151 to 153 ms | 14 MB |
| polaris over WXSD, aggregated | 32 | 500 ms | 8.5 s (round 16) | 14.5 s (round 28) | 28 ms | 282 to 289 ms | 14 MB |
| polaris over WXSD, aggregated | 64 | 500 ms | 8.5 s (round 16) | 14.5 s (round 28) | 49 ms | 656 to 659 ms | 14 MB |
| n parallel Dolev-Strong | 16 | 500 ms | 4.5 s (round 8) | 6.5 s (round 12) | 1 ms | 103 ms | 14 MB |
| n parallel Dolev-Strong | 32 | 500 ms | 8.5 s (round 16) | 12.5 s (round 24) | 1 ms | 189 to 193 ms | 14 MB |
| n parallel Dolev-Strong | 64 | 500 ms | 16.5 s (round 32) | 24.5 s (round 48) | 1 to 2 ms | 411 ms | 14 MB |
| n parallel WXSD, aggregated | 16 | 500 ms | 5.6 s (round 10) | 9.6 s (round 18) | 86 to 90 ms | 350 to 364 ms | 14 MB |
| n parallel WXSD, aggregated | 32 | 500 ms | 5.8 s (round 10) | 9.8 s (round 18) | 252 to 257 ms | 1,149 to 1,154 ms | 18 to 19 MB |
| n parallel WXSD, aggregated | 64 | 1500 ms | 17.5 s (round 10) | 29.5 s (round 18) | 992 to 1,008 ms | 6,235 to 6,288 ms | 149 to 152 MB |

Every run reaches the simulator's decision round, with the same output at
every node and no late message. Time to decision is the round schedule, r +
1 round lengths for decision round r, plus the processing of the last
round: 1 to 257 ms with 500 ms rounds, and about 1 s for n parallel WXSD
at n = 64 with its 1.5 s rounds.

The shortest round length with no late message in any run, at n = 64
(`eval/round_search.py`; a length counts once three runs have none, and
fails at its first run with one):

| | t = n/2 | t = 3n/4 |
| --- | --- | --- |
| polaris over Dolev-Strong | at most 250 ms | at most 250 ms |
| polaris over WXSD, aggregated | at most 250 ms | at most 250 ms |
| n parallel Dolev-Strong | at most 250 ms | at most 250 ms |
| n parallel WXSD, aggregated | 1500 ms | 1500 ms |

250 ms is the shortest length tried, so for the first three it is an upper
bound. n parallel WXSD had late messages at 1000 ms and none at 1500 or
2000 ms.

At n = 64 the round length decides the comparison: polaris over WXSD
decides in 8.5 s with t = n/2 and 14.5 s with t = 3n/4, while n parallel
WXSD, which needs three times longer rounds, decides in 17.5 s and 29.5 s,
about twice as late, sending 20 times the bytes (84 MB against 4.3 MB per
node) and verifying 26 times the signatures. n parallel Dolev-Strong
decides in 16.5 s and 24.5 s and sends about a seventh of polaris's bytes.

The 16-core server below gives the same rounds, bytes and outputs. Its
cores are faster: at n = 64, where both servers give every node one
worker, a node here uses 1.7 to 2.2 times the CPU time. But this server
has six times the hardware threads (96 against 16 vCPUs), so n parallel
WXSD, whose rounds are long because every node has too much to process,
needs half the round length (1500 against 3000 ms), and polaris's lead
over it shrinks from about four times to about twice. The rounds of the
other three hold at 250 ms on both servers.

### On one server with 16 dedicated cores

The same runs, earlier, on one Hetzner CCX43 server (16 dedicated AMD
EPYC vCPUs, 64 GB), every node a separate process with one runtime worker,
and with the same rules for round lengths and the same columns:

| | n | round | t = n/2 | t = 3n/4 | past the round | CPU per node | memory per node |
| --- | --- | --- | --- | --- | --- | --- | --- |
| polaris over Dolev-Strong | 16 | 500 ms | 7.5 s (round 14) | 11.5 s (round 22) | 3 to 5 ms | 76 to 83 ms | 15 MB |
| polaris over Dolev-Strong | 32 | 500 ms | 11.5 s (round 22) | 17.5 s (round 34) | 12 to 13 ms | 129 to 135 ms | 15 MB |
| polaris over Dolev-Strong | 64 | 500 ms | 19.5 s (round 38) | 29.5 s (round 58) | 37 to 38 ms | 323 to 332 ms | 15 MB |
| polaris over WXSD, aggregated | 16 | 500 ms | 8.5 s (round 16) | 14.5 s (round 28) | 24 ms | 113 to 117 ms | 15 MB |
| polaris over WXSD, aggregated | 32 | 500 ms | 8.6 s (round 16) | 14.6 s (round 28) | 61 ms | 187 to 194 ms | 15 MB |
| polaris over WXSD, aggregated | 64 | 500 ms | 8.6 s (round 16) | 14.6 s (round 28) | 148 to 149 ms | 337 to 346 ms | 15 MB |
| n parallel Dolev-Strong | 16 | 500 ms | 4.5 s (round 8) | 6.5 s (round 12) | 2 ms | 68 to 73 ms | 15 MB |
| n parallel Dolev-Strong | 32 | 500 ms | 8.5 s (round 16) | 12.5 s (round 24) | 1 ms | 106 to 107 ms | 15 MB |
| n parallel Dolev-Strong | 64 | 500 ms | 16.5 s (round 32) | 24.5 s (round 48) | 2 ms | 189 to 193 ms | 15 MB |
| n parallel WXSD, aggregated | 16 | 500 ms | 5.6 s (round 10) | 9.6 s (round 18) | 86 to 90 ms | 305 to 306 ms | 15 MB |
| n parallel WXSD, aggregated | 32 | 500 ms | 5.8 s (round 10) | 9.9 s (round 18) | 347 to 367 ms | 684 to 702 ms | 25 MB |
| n parallel WXSD, aggregated | 64 | 3000 ms | 35.1 s (round 10) | 59.1 s (round 18) | 2,086 to 2,128 ms | 2,940 to 3,047 ms | 162 to 163 MB |

Every run reaches the simulator's decision round, with the same output at
every node and no late message. Time to decision is the round schedule, r +
1 round lengths for decision round r, plus the processing of the last
round: 1 to 367 ms with 500 ms rounds, and about 2.1 s for n parallel WXSD
at n = 64 with its 3 s rounds.

The shortest round length with no late message in any run, at n = 64
(`eval/round_search.py`; a length counts once three runs have none, and
fails at its first run with one):

| | t = n/2 | t = 3n/4 |
| --- | --- | --- |
| polaris over Dolev-Strong | at most 250 ms | at most 250 ms |
| polaris over WXSD, aggregated | at most 250 ms | at most 250 ms |
| n parallel Dolev-Strong | at most 250 ms | at most 250 ms |
| n parallel WXSD, aggregated | 3000 ms | 3000 ms |

250 ms is the shortest length tried, so for the first three it is an upper
bound. n parallel WXSD had late messages at 2000 ms and none at 3000 or
4000 ms.

At n = 64 the round length decides the comparison: polaris over WXSD
decides in 8.6 s with t = n/2 and 14.6 s with t = 3n/4, while n parallel
WXSD, which needs six times longer rounds, decides in 35.1 s and 59.1 s,
about four times later, sending 20 times the bytes (84 MB against 4.3 MB
per node) and verifying 26 times the signatures. n parallel Dolev-Strong
decides in 16.5 s and 24.5 s and sends about a seventh of polaris's bytes.

An earlier run on a server with 16 shared cores (CPX62), with the previous
network runner, did not complete n parallel WXSD at n = 64: the
out-of-memory killer took 23 of its 64 processes, which had peaked at 277
MB at the median and 1,705 MB at most. Decision 13 traces that memory to
the runner and removes most of it; on the CCX43 every process of that
baseline stays at 162 to 163 MB. Shared cores also make timings vary from
one server to the next (decision 14), so no number above comes from them.

### Against honest-majority protocols

`eval/honest_majority.py` runs Apollo and Sync HotStuff from the Apollo
artefact ([libchatter-rs](https://github.com/adithyabhatkajake/libchatter-rs),
built with `cargo build --release`) on loopback, f = (n - 1) / 2, all honest,
Delta set to polaris's 500 ms round: one client submits n 16-byte
transactions, the blocks hold n transactions, and the run ends when the
client reports them committed. With `--polaris`, it also runs polaris
(t = n/2 and t = 3n/4, all honest) on loopback, so that the bytes on the
loopback interface are counted the same way for every system:

```
ulimit -n 65536
python3 eval/honest_majority.py --chatter ../libchatter-rs \
    --polaris target/release/polaris --out eval/results/honest --sizes 8 16 32 64
```

`polaris local` runs every node in one process, so from n = 32 it needs
more open files than the usual limit of 1,024; without the `ulimit`, its
nodes time out waiting for each other's handshakes. On a machine without
OpenSSL's development headers, libchatter-rs builds once its two
`openssl = "0.10"` dependencies (in `net/Cargo.toml` and
`tools/genconfig/Cargo.toml`) take `features = ["vendored"]`, which
compiles OpenSSL from source.

On the 48-core server, three runs each (bytes per process on loopback, TLS
and TCP headers included; polaris's time is its round schedule as measured
by the network runs above, which start at n = 16):

| | n = 16 | n = 32 | n = 64 |
| --- | --- | --- | --- |
| Sync HotStuff | 1.00 s, 36 KB | 1.01 s, 92 KB | 1.01 s, 262 KB |
| Apollo | 6 ms, 56 KB | 32 ms, 190 KB | 254 ms, 710 KB |
| polaris over Dolev-Strong, t = n/2 | 7.5 s, 121 KB | 11.5 s, 795 KB | 19.5 s, 5.11 MB |
| polaris over WXSD, aggregated, t = n/2 | 8.5 s, 287 KB | 8.5 s, 1.11 MB | 8.5 s, 4.37 MB |
| polaris over Dolev-Strong, t = 3n/4 | 11.5 s, 121 KB | 17.5 s, 624 KB | 29.5 s, 4.44 MB |
| polaris over WXSD, aggregated, t = 3n/4 | 14.5 s, 287 KB | 14.5 s, 1.11 MB | 14.5 s, 4.37 MB |

The comparison is not like for like: those protocols tolerate fewer than
n/2 faults, agree on a leader's block of client transactions rather than on
every process's own input, and Apollo is responsive, so on loopback its
latency is the network's rather than Delta's. Sync HotStuff, which waits
on Delta as polaris does, commits in about 2 Delta; at t = n/2 polaris needs
15 to 39 rounds of Delta at these sizes, and at n = 64 sends 17 (over WXSD)
to 20 (over Dolev-Strong) times its bytes. Configured for a dishonest
majority, t = 3n/4, which those protocols cannot be, polaris needs 23 to 59
rounds of Delta over Dolev-Strong and 29 over WXSD, for the same bytes over
WXSD and no more over Dolev-Strong.

The same runs on two cores, at n = 8 to 32, gave polaris the same bytes and
Sync HotStuff about 2 Delta again (1.03 to 1.09 s); Apollo's latency there
was 7 to 129 ms, against 2 to 32 ms on the 48-core server.

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
