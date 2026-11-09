# Design

What polaris is built from, and the decisions that are not forced by the
paper. The paper is *Parallel Broadcast from Single-Source Broadcast, for
Free?*; algorithm and claim numbers below refer to it.

## The problem

Interactive Consistency: every node has an input, and every honest node must
output the same vector, with the honest inputs at their positions. The
setting is synchronous with authenticated channels, a PKI, and up to
`t <= (1 - epsilon) n` static corruptions, so there is no honest majority
and no quorum argument. The paper's compiler (Algorithm 1) runs in views:
in view `v` a PRF-elected leader runs LearnOrExpose (Algorithm 2) to
collect a *verifiable vector*, in which every missing entry comes with a
*polarizer* (an accusation set whose pruned graph disconnects any honest
verifier from the missing party), and broadcasts that vector once. Views
are pipelined every `c` rounds; the first view whose broadcast decides a
valid vector wins.

The parameters are `(n, t)`, from which everything else derives
(`polaris-core/src/params.rs`): the minimum number of honest nodes `n - t`,
the diameter bound `d = ceil(2n / (n - t))` (Claim 2), and the length of
a LearnOrExpose instance `R = d + 1` rounds.

## Round machines

Every protocol is a `RoundMachine` (`polaris-core/src/machine.rs`): `start`
returns the messages for the first round, `end_round(round, inbox)` takes
everything that arrived in a round and returns what to send at the start
of the next one, `output` and `halt` close an instance. A machine never
touches sockets, clocks or randomness; it receives its keys when it is
built and a `Ctx` (identity, parameters, run id, metrics sink) on every
call. Messages are typed per protocol and serialized with `postcard`.

Two drivers run the same machines:

- The simulator (`polaris-sim`) runs honest machines and scripted
  adversaries in lock step under exact synchrony. An adversary implements
  `Adversary::act(ctx, round, inbox, honest_sends)`: it sees what the honest
  nodes send in a round before choosing its own messages (a rushing
  adversary) and can deliver to any subset. Inboxes are sorted by sender id,
  so a run is deterministic, and a transcript records every delivery with an
  order-independent per-round fingerprint per recipient.
- The network runner (the root crate) opens one authenticated TCP connection
  per direction and peer (a nonce signed once at connection time, nothing
  signed per message afterwards, matching the model's authenticated
  channels), runs a wall-clock round schedule from a shared start time, and
  labels every frame with the round it was sent in; a frame carries every
  message of that round for that peer, so a round costs `n` system calls
  per node whatever the protocol sends, and the receiver splits it back
  into messages. A frame that arrives
  after the end of its round is counted as late and delivered in the round
  it arrived in: a synchrony violation the protocol may or may not survive,
  and the count is what says whether a run was synchronous. It writes
  per-round metrics, a transcript in the simulator's format, and the
  output.

The `local` command runs `n` nodes in one process over real TCP and diffs
every inbox against the simulator; this is the check that the two drivers
agree. It is done in the test suite with the signed echo and with the
compiler over both broadcasts at `n = 8`, and by hand with the compiler at
`n = 64` over Dolev-Strong (two-second rounds on two cores: zero late
messages, identical inboxes, all nodes deciding at round 38 for `t = 32`)
and at `n = 32` over WXSD (decision at round 16 for `t = 16`). The node binary runs the same two
protocols from a config file, one process per node.

## Cryptography

- Ed25519 (`ed25519-dalek`) for everything that is verified individually
  and in batches: disclosures, the channel handshake, later votes and
  commits. Batch verification reports the failing indices so one bad
  signature does not reject a batch.
- BLS12-381 (`blst`, `min_sig`: 48-byte signatures, 96-byte public keys)
  for accusations only, because those are what gets aggregated. All
  accusations against one target sign the same body, so they aggregate into
  one `MultiSig` (an `n`-bit signer set and one signature), which is what
  makes a LearnOrExpose proof `O(n^2 + n kappa)` bits (Lemma 6.1). Every
  public key comes with a proof of possession that is checked when the key
  file is loaded, so a rogue-key attack is excluded before any aggregate
  verification.
- Accusation verification is batched per target: one aggregate pairing for
  all accusations against a target, with a one-by-one fallback only when the
  aggregate fails. A node can receive `O(n^2)` accusations per instance and
  a Byzantine node can flood forged ones; the fallback bounds the damage to
  the targets the forgeries touch.
- Leader election is HMAC-SHA-256 keyed by the common random string of the
  key file, over the view number, reduced modulo `n`.
- Domain separation: every signature covers `tag || run_id || len(body) ||
  body`, one tag per message type. Accusations are scoped to the run and not
  to the view (see decisions below).
- Keys are generated deterministically from a seed by `keygen`, into one
  bulletin-board key file and one secret file per node.

## The accusation graph

`TrustGraph::make` (`polaris-proto/src/trust_graph.rs`) is Algorithm 3:
start from the complete graph, delete `{a, b}` for every accusation
`a -> b`, then delete every edge whose endpoints have fewer than `n - t`
common neighbors, until no such edge is left. The deletion order does not
matter: the result is the largest subgraph of the accusation-free graph in
which every edge satisfies the rule, so it is a function of the accusation
set, and it is monotone. Property tests over random accusation sets (honest
nodes never accusing each other) check that the honest clique survives,
that every component has diameter at most `d`, and that pruning is
monotone and idempotent.

LearnOrExpose (`polaris-proto/src/learn_or_expose.rs`) runs exactly `R`
rounds: forward new valid accusations and the disclosures of unresolved
parties, rebuild the graph, expose every unresolved party the node is
disconnected from, and accuse the frontier (its neighbors within distance
`r - 1` of an unresolved party). At the end it outputs the vector with the
aggregated proof. `VerifyVec_out` rebuilds the graph from the proof and
checks that the verifier is disconnected from every missing party; the
answer is local to the verifier, but all honest verifiers agree because
they always sit in one component.

## The WXSD broadcast

`Wxsd` (`polaris-proto/src/bb/wxsd.rs`) is the Wan-Xiao-Shi-Devadas
broadcast (TCC 2020), the paper's choice for `BB_v`, with expected
constant epochs. Each instance keeps one trust graph: the accusation set and
`MakeGraph` of LearnOrExpose, plus the nodes removed outright on
equivocation evidence (two signed messages of one type and epoch from one
node with different bodies, forwarded as proof). TrustCast is the paper's:
a sender's signed message is forwarded by everyone, and at the end of round
`r = 1..=d` a node missing a valid message from a sender still in its graph
distrusts every neighbor at distance less than `r` from that sender. A
phase is `d` such rounds plus one settling round, an epoch is three phases:
Propose (the leader, the sender in epoch 1 and a PRF choice after, sends a
value with the freshest commit evidence it holds, or bottom with none),
Vote (for the proposed digest if the leader is still in the voter's graph,
else an abstention) and Commit (a node whose whole graph voted for one
digest outputs that value and sends those votes as evidence, else an empty
commit). A node terminates once everyone in its graph has sent a commit
with valid evidence for one digest; honest nodes terminate within one round
of each other, so `termination_skew` is 1 and the compiler keeps the view
running one round after deciding.

## The compiler

`Compiler` (`polaris-proto/src/compiler.rs`) is Algorithm 1 as a round
machine that runs other round machines. Round 0 discloses the signed input
to all. From round 1 a view starts every `c` rounds: the leader
`PRF(v) mod n` runs LearnOrExpose with everyone for `R` rounds and submits
its vector, encoded, to a broadcast of which it is the sender. The broadcast
is any `Broadcast` implementation, built per view by a factory the compiler
is given, so the same compiler runs over Dolev-Strong today and WXSD later.
A delivered vector is accepted if `VerifyVec_out` holds at the node's own
position; the ordered scan decides on the first view (in view order) that
delivered an accepted vector, and the output is that vector's values with
bottom for the exposed parties. After deciding, the node keeps running the
views in progress for the broadcast's termination skew (`Delta_sim`, zero
for Dolev-Strong) and then halts.

Sub-machines get their own context: they record signature work into it and
also call `decided`, which must not count as the compiler's decision, so
the compiler absorbs their counters into its own metrics every round.

## The baseline

`Parallel` (`polaris-proto/src/parallel.rs`) runs `n` instances of a
broadcast side by side, node `i` the sender of instance `i` with its input,
all started at round 0, and outputs the vector of what they delivered once
every instance has. It takes the same broadcast factory as the compiler,
so `n` parallel Dolev-Strong and `n` parallel WXSD are the two baselines
the paper compares against, on the same drivers and metrics as the
compiler.

## Decisions

Each of these is a choice the paper leaves open or that differs from its
printed text. They are settled; changing one means revisiting the tests
that record it.

1. **The pruning rule counts closed neighborhoods.** The rule is applied as
   `|N[a] inter N[b]| < n - t`, where `N[.]` includes the node itself.
   Algorithm 3 is printed with open neighborhoods. With exactly `n - t`
   honest nodes and the adversary accusing all of them, two honest nodes
   share only `n - t - 2` other neighbors, so the open rule prunes the
   honest clique itself and an honest node can be exposed; the test
   `open_rule_breaks_the_honest_clique` records this. With closed
   neighborhoods the honest clique (size at least `n - t`) always survives.
   The proof of Claim 2 uses only `N[v_i] inter N[v_{i+1}]` being contained
   in `D_i union D_{i+1}`, so the diameter bound `ceil(2n / (n - t))` is
   unchanged.
2. **Every node runs all `R` rounds of LearnOrExpose and keeps forwarding.**
   Algorithm 2 lets a non-leader return early. Running to the end keeps
   termination simultaneous, which the broadcast's submission precondition
   needs, and keeps the "one round of lag" invariant of the proof.
3. **Every honest node computes the LearnOrExpose output,** not only the
   leader, so that transferability can be tested (any honest node's proof
   verifies at any other). The compiler will submit only the leader's.
4. **Accusations are scoped to the run, not to the view.** Under static
   corruption an honest accusation stays valid for the whole run. Reusing
   accusations across views, and sharing them with the WXSD trust graph, is
   a planned improvement to be measured separately; the format already
   allows it.
5. **A node's own accusations enter its accusation set when it signs them,**
   not a round later when they echo back. Same graph, one round earlier,
   and nothing is re-forwarded.
6. **Views are spaced `c = R` rounds apart by default**, so that at most one
   LearnOrExpose instance is running at a time; `CompilerConfig` makes `c`
   a parameter so that denser pipelining can be measured, and `c = 0` makes
   the views sequential: the next starts only once the previous broadcast
   has delivered without a decision. Pipelining is the paper's design and
   buys a view of latency per Byzantine leader; the measured price is every
   view started in vain, about 2.5 times the bytes at 10 KB inputs when the
   first leader is honest (see the README).
7. **Every view's LearnOrExpose starts from all the disclosures the node
   holds**, including those learned in earlier views, rather than from the
   round 0 candidates only. The input vector stays `VerifyVec_in`-valid, so
   nothing in the proofs changes; a party whose disclosure was slow is
   simply resolved from the start of later views.
8. **Dolev-Strong carries the value in every message** and signs
   `instance || H(value)`. A digest-only chain would be smaller, but a
   Byzantine sender can show the value to a single honest node, who then has
   to carry it to the others; signing the digest keeps the signature cost
   independent of the value's length, which matters once the value is a
   whole vector. A node keeps at most two values, enough to decide bottom
   and to make every other honest node see two as well.
9. **WXSD details.** Values instead of bits: votes and evidence carry the
   digest of `instance || value`, only proposals carry the value, and a
   node only ever accepts evidence for a value it holds (evidence valid at
   `u` contains `u`'s own vote for it). A leader without evidence proposes
   the bottom value where the paper proposes a random bit, so a Byzantine
   sender ends in bottom and the compiler skips the view. Each phase has a
   settling round after its `d` check rounds, so that forwards and
   distrusts of round `d` reach everyone before the next phase's messages
   are formed; this is what keeps "the leader is still in the graph" and
   "evidence valid at the committer" consistent between honest nodes. The
   freshness a proposal's evidence is checked against is the evidence a
   node had seen one round before the end of the previous Commit phase, so
   that an honest leader's knowledge always covers it: a node that accepts
   evidence in round `r` has forwarded it, and the leader holds it by
   `r + 1`. The diameter bound is `d = ceil(2n / (n - t))` from
   LearnOrExpose, slightly above the paper's `ceil(n/h) + floor(n/h) - 1`,
   which only adds check rounds.
10. **The naive broadcast stays in the tree.** It is a two-round broadcast
    with validity but without agreement (a Byzantine sender and one
    Byzantine forwarder split the honest nodes; see
    `naive_broadcast_breaks_agreement`). It is the simplest machine behind
    the `Broadcast` interface, so the compiler and the drivers could be
    tested before Dolev-Strong and WXSD existed, and it gives the tests a
    broadcast that is known to fail.
11. **Messages of a round are delivered in sender-id order** by both
    drivers, and a node's own `Dest::All` messages are in its own inbox.
    Protocol logic must not depend on arrival order, which the
    order-independent transcript fingerprints enforce.

## Testing

- Unit and property tests per crate (`cargo test --workspace`).
- A fixed adversary suite for LearnOrExpose
  (`crates/polaris-proto/tests/learn_or_expose.rs`): silent nodes, a
  disclosure withheld from all but one node, a late disclosure to a single
  node, Byzantine nodes accusing every honest node every round, floods of
  forged accusations, a node that never forwards, and a Byzantine leader
  trying five kinds of forged vectors. Under all of them every honest node
  outputs at round `R`, no honest input is missing or altered, every honest
  output is accepted by every honest verifier, forgeries are rejected
  everywhere, and no honest node ever accuses an honest node.
- A randomized sweep (`crates/polaris-proto/tests/robustness.rs`) that
  draws the Byzantine set and each Byzantine node's behavior from a seed,
  so every failure is reproducible from `(n, t, seed)`. The full sweep, from
  `(8, 4)` to `(64, 48)` with 25 seeds each, passes; the largest proof seen
  was under 4 KB at `n = 64`.
- Dolev-Strong (`crates/polaris-proto/tests/dolev_strong.rs`): the scripted
  attack that breaks the naive broadcast, chains of `t` Byzantine signatures
  shown to one node, short and forged chains, and a randomized rushing
  adversary that extends every chain it sees, fabricates chains on fresh
  values and forges links, over `(n, t)` up to `(10, 7)` with 40 seeds each.
  Agreement holds every time and validity whenever the sender is honest.
- WXSD (`crates/polaris-proto/tests/wxsd.rs`): the honest sender decides
  in the first epoch at the predicted round; a silent sender gives bottom
  at the first honest leader with simultaneous termination; an
  equivocating sender is removed everywhere; a proposal withheld from one
  node reaches it by forwarding; fabricated evidence (Byzantine votes only)
  and forged commits are rejected and their authors distrusted; random
  silent or selective Byzantine sets up to `(10, 8)`: agreement, validity,
  termination within one round, commit no later than the first honest
  leader.
- The compiler (`crates/polaris-proto/tests/compiler.rs`): all honest
  decide in view 1 at the expected round and halt at once; silent Byzantine
  leaders are skipped and exposed, with sequential views one full view
  later each; a Byzantine leader submitting a vector
  that drops an honest entry, or two valid vectors to two halves, is
  skipped; the view budget stops the run; and random Byzantine sets that are
  silent or deliver to random subsets, with `c = R`, `c = R / 2` and
  sequential views, over
  `(n, t)` up to `(10, 8)`: agreement, every honest input kept, a decision
  no later than the first view with an honest leader, and simultaneous
  termination. The same over WXSD, with decision rounds one apart at most.
- The baselines (`crates/polaris-proto/tests/parallel.rs`): all honest at
  the predicted rounds over both broadcasts, and the random omission
  adversaries: agreement on the whole vector, every honest input in place,
  termination within one round.
- Criterion benchmarks for the signatures, the multi-signatures, key file
  loading, `MakeGraph` and accusation verification.
- The evaluation harness (`eval/`): the experiment matrix run with one
  process per node, on this host or spread over ssh hosts, for the honest
  runs and in the simulator with Byzantine
  nodes for the runs under attack (generic silent and selective nodes, and
  the Dolev-Strong adversary of `src/adversaries.rs`, which bounds itself
  to one reaction per instance and round), aggregated into tables and
  plots;
  `run.json` per run records the exit codes, and the aggregator checks that
  every (honest) node of a run decided the same output.

## Next

Experiments on real hosts (the launcher is in place), a WXSD-specific
adversary in the harness (Dolev-Strong has one), the honest-majority
reference implementations from the project brief, and the improvements: accusations shared across views and with the
WXSD trust graph, and aggregated trust-graph evidence.
