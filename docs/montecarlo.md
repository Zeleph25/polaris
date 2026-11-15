# Monte Carlo baseline: the literature

The project compares the compiler with `n` parallel invocations of a
strong Monte Carlo Byzantine broadcast, chosen from the literature, and asks
whether a protocol built for parallel broadcast under a dishonest majority
is worth implementing too. This note compares three candidates and ends
with a recommendation. Nothing is implemented yet.

- [CPS] T-H. H. Chan, R. Pass, E. Shi. *Sublinear-round Byzantine agreement
  under corrupt majority.* PKC 2020.
  ([doi](https://doi.org/10.1007/978-3-030-45388-6_9))
- [BBCL] E. Blum, E. Boyle, R. Cohen, C.-D. Liu-Zhang. *Communication lower
  bounds for cryptographic broadcast protocols.* Distributed Computing,
  2025; DISC 2023. ([ePrint 2023/1316](https://eprint.iacr.org/2023/1316))
- [CLL+] Collins et al. *Towards optimal parallel broadcast under a
  dishonest majority.* FC 2025.
  ([ePrint 2024/974](https://eprint.iacr.org/2024/974))

All three tolerate `t <= (1 - eps) n` corruptions for a constant `eps`,
assume synchrony and a trusted setup, and fail with probability `delta`
(or negligible in `kappa`): agreement can break, which never happens to
Dolev-Strong, WXSD or the compiler. Round counts below are in our lockstep
rounds; a "mini-round" of the papers is one of our rounds.

## The three works

### [CPS]: committee Dolev-Strong

The idea: only a small random committee signs, so the Dolev-Strong chain
needs to grow to the committee's size, not to `t + 1`.

- **Static warm-up (Section 3.1).** An oracle elects a committee of `S`
  nodes after the corruptions are fixed. Each round has two mini-rounds:
  in the first, every node that sees a new value carrying `r` valid
  signatures (the sender's plus committee members') adds it to its
  extracted set and multicasts it; in the second, committee members do the
  same and append their own signature. After `S + 1` rounds a node outputs
  its single extracted value, or a default. One honest committee member is
  enough for agreement, so the failure probability is the probability that
  all `S` members are corrupt.
  - Rounds: `2 (S + 1)`. The paper sets `S = log(1/delta)` for constant
    `eps`; the exact need is `C(t, S) / C(n, S) <= delta` (our derivation,
    used in the table below).
  - Committee election: an idealized oracle drawn after corruption, which
    is exactly what our PRF on the common random string already is for the
    compiler's leaders (`polaris-crypto/src/prf.rs`).
- **Adaptive protocol (Section 4, Figure 1).** Committees are
  bit-specific and private: a node learns it may vote for `b` by calling
  `F_mine(b)`, with probability `p = min(1, ln(2/delta) / (eps n))`.
  - Rounds: fixed, `2 ceil((3 / eps) ln(2/delta))` (Theorem 2), so
    `O(log(1/delta) / eps)` independent of `n`.
  - Committee election: `F_mine`, instantiated (Section 5) with a PRF per
    node, a commitment to its key in the PKI, and a NIZK per vote under a
    CRS and bilinear groups. A VRF plays the same role in later work.
- **Communication.** Not analyzed in the paper. Counting from the
  protocol: per instance at most two values per node, each multicast once
  by everyone and once more by committee members, so `O(n^2)` messages of
  up to `S + 1` signatures; Dolev-Strong is also `O(n^2)` messages, of up to
  `t + 1` signatures.

### [BBCL]: CPS with sparse flooding

The paper is mostly about lower bounds; its upper bound (Proposition 5.1)
runs the adaptive CPS protocol, but replaces every multicast with `Flood`,
a gossip over random neighbors, to bring communication down.

- Rounds: `R = (3 / eps)(kappa + 1)` stages, each two floods of
  `rho = 7 ln(n / (2 (ln n + kappa))) + 2` rounds. The paper gives no
  closed form; it is about `2 (R + 1) rho`, so `O(kappa log n / eps)`.
- Communication: `O(kappa^3 n log n + kappa^4 n)` bits in total, that is
  `O~(n)`, polylogarithmic per node. This is its point.
- Committee election: `F_mine` with `p = min(1, (kappa + 1) / (eps n))`,
  under a trusted PKI for VRFs and signatures. Static adversary.
- At our sizes flooding is not sparse: a neighbor is kept with probability
  `(ln n + kappa) / (eps n)`, which is at least 1 below `n = 89` for
  `kappa = 40, eps = 1/2` and below `n = 181` for `eps = 1/4`. Every flood
  is then a multicast, and the protocol is the adaptive CPS with
  `R >= 246` stages.

### [CLL+]: parallel broadcast built for the job

Not `n` instances of a broadcast but one parallel broadcast protocol.

- **`PBC*_L` (Section 3).** Extends a `kappa`-bit parallel broadcast to
  `L`-bit values with erasure codes and an erasure coding proof (ECP)
  system under a CRS: three extra rounds, `O(n^2 L + P(kappa))` bits.
- **`PBC^static` (Section 4).** `F_mine` elects one committee of size
  `c > (3 (1 - eps) / mu^2) ln(1/delta)`; the committee runs an `L`-bit
  parallel broadcast among its members, then hands the results to
  everyone. `O(lambda)` rounds; `O(n^2 kappa^(1+K) + n kappa^3 + kappa^4)`
  bits with aggregate signatures. Trusted PKI and CRS.
- **`PBC^adaptive` (Section 5).** A committee per (sender, slot),
  forward-secure public-key encryption with constant-size ciphertexts,
  aggregate signatures checked against recursive NIZK eligibility proofs.
  `O(kappa log n)` rounds, `O~(n^2 kappa^2 + n kappa^3)` bits. Weakly
  adaptive adversary.
- No implementation or measurements in the paper.
- At our sizes the static committee is everyone: with `mu = eps / 2`,
  `c > 333` already for `eps = 1/2, delta = 2^-20` (and `c > 1996` for
  `eps = 1/4`), against `n <= 64`. The protocol then reduces to its inner
  `L`-bit parallel broadcast among all `n` nodes.

## Rounds at the sizes we run

`t + 1` is Dolev-Strong. For `n` parallel instances a union bound needs
`delta / n` per instance; one committee shared by all instances fails all
of them together, so it needs only `delta`.

| n | t | delta | CPS static, own committee | CPS static, shared committee | CPS adaptive | Dolev-Strong |
| --- | --- | --- | --- | --- | --- | --- |
| 64 | 32 | 2^-20 | 42 (S = 20) | 36 (S = 17) | 226 | 33 |
| 64 | 32 | 2^-40 | 60 (S = 29) | 56 (S = 27) | 392 | 33 |
| 64 | 48 | 2^-20 | 78 (S = 38) | 68 (S = 33) | 450 | 49 |
| 64 | 48 | 2^-40 | 98 (S = 48) | 94 (S = 46) | 782 | 49 |
| 128 | 64 | 2^-20 | 50 (S = 24) | 38 (S = 18) | | 65 |
| 256 | 128 | 2^-20 | 54 (S = 26) | 40 (S = 19) | | 129 |
| 256 | 192 | 2^-20 | 120 (S = 59) | 90 (S = 44) | | 193 |

The adaptive column uses Theorem 2 of [CPS] with `delta / n`. [BBCL] needs
at least `2 (R + 1) = 494` rounds at `eps = 1/2, kappa = 40` whatever `n`.

So at `n <= 64`, every Monte Carlo option takes more rounds than
Dolev-Strong, which we already run. The committee only pays off once
`t + 1` exceeds `2 (S + 1)`: around `n = 128` for `t = n/2` and
`n = 256` for `t = 3n/4`, at `delta = 2^-20`.

## Implementing behind `Broadcast`

- **CPS static.** Small. It is `bb/dolev_strong.rs` with two changes: only
  committee members' signatures count toward a chain, and each round splits
  into a relay round and a signing round. Fixed rounds, no skew, so
  `termination_skew() = 0` and the default `settled_round`. The committee
  comes from `Prf::leader_of` under a new domain tag, per instance or once
  per run. Multi-valued inputs work as in our Dolev-Strong (at most two
  values kept, signatures over a digest). New: a `delta` (or `S`) switch,
  plumbed through config, CLI, simulator and eval like `share_accusations`.
  About as much code as Dolev-Strong plus its tests.
- **CPS adaptive.** Medium with an idealized `F_mine` (a PRF of the
  common random string on `(value digest, node)`), but then it is the
  static protocol with more rounds and no added security in our static
  model. With real eligibility proofs: a VRF per vote (for example ECVRF,
  RFC 9381) is a new dependency and adds a proof and a verification per
  signature; the paper's own NIZK instantiation has no practical Rust
  library we know of.
- **BBCL.** CPS adaptive plus a `Flood` sub-machine run twice per stage,
  so a nested round machine with its own schedule. Medium to large, and at
  our sizes it is the same as CPS adaptive.
- **CLL+.** Large, and it does not fit behind `Broadcast`: it is a parallel
  broadcast, so it would sit next to `parallel.rs` and the compiler as a
  third construction. It needs the ECP system, erasure codes and, for the
  adaptive version, forward-secure encryption and recursive NIZKs, none of
  them in our dependencies. With `c >= n` at our sizes the static version
  would also need a separate `L`-bit parallel broadcast inside it.

## Recommendation

1. Implement `n` parallel CPS static (committee Dolev-Strong) as the Monte
   Carlo baseline: the committee from our PRF on the common random string,
   the same oracle and the same static model as the compiler's leaders.
   One committee per instance with `delta / n` each, which is literally
   `n` parallel invocations; the shared committee as an option if wanted.
2. Report it honestly: at `n <= 64` it takes more rounds than
   `n` parallel Dolev-Strong. If the simulator handles it, add rows at
   `n = 128` and `256` (rounds and bytes only), where it starts to win.
3. Do not implement the adaptive variants or [BBCL]: they need a VRF or
   NIZKs, defend against an adversary the compiler does not consider, and
   at our sizes cost hundreds of rounds. Cite [BBCL] for communication.
4. Do not implement [CLL+]: no reference implementation, heavy new
   cryptography, and at `n <= 64` its committee is the whole system. Cite
   it and compare asymptotically.

Questions for Grigorii: which `delta` (`2^-20`, `2^-40`, or both); one
committee per instance or one shared; and whether simulator rows beyond
`n = 64` are wanted.
