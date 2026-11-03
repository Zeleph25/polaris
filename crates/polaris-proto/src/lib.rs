//! Protocol machines, each a [`polaris_core::RoundMachine`].
//!
//! Planned modules, in milestone order:
//! - `trust_graph` (M2): bitset adjacency, closed-neighbourhood pruning, BFS, reachability.
//! - `accusations` (M2): per-target store and BLS aggregation into the output proof.
//! - `learn_or_expose` (M2): Algorithms 2 and 3, exactly `R = d + 1` rounds.
//! - `leader` (M3): PRF leader election.
//! - `bb::dolev_strong` (M3), `bb::wxsd` (M4): Byzantine broadcasts behind one trait.
//! - `ic_compiler` (M3): Algorithm 1, pipelined views, ordered scan, halting.
//! - `baselines` (M5): n parallel broadcasts.
