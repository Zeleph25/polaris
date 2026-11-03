//! Single-process lockstep simulator (M1).
//!
//! Drives a set of [`polaris_core::RoundMachine`]s round by round:
//! `for r in 0.. { for each node: inbox(r) → end_round → outbox → inbox(r + 1) }`.
//! Byzantine nodes are driven by an `Adversary` trait instead of a machine.
//! Deterministic given a seed; records a transcript `(round, from, to, hash(msg), bytes)`
//! in the same format the network runner writes, so the two can be diffed.
