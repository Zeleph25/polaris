//! Protocol machines, each a [`polaris_core::RoundMachine`].
//!
//! - [`echo`]: signed all-to-all echo, the toy protocol the drivers are validated with.
//! - [`trust_graph`]: `MakeGraph`, bitset adjacency, closed-neighborhood pruning, BFS.
//! - [`accusations`]: signed accusations, per-target store, `Aggregate` into a proof.
//! - [`disclosure`]: signed inputs, `VerifyVec_in`, the verifiable vector and `VerifyVec_out`.
//! - [`learn_or_expose`]: Algorithm 2, exactly R = d + 1 rounds.
//! - [`bb`]: the broadcast interface, the Dolev-Strong broadcast, and a naive
//!   two-round broadcast for the harness.
//! - [`compiler`]: Algorithm 1, Interactive Consistency from one broadcast per view.
//! - [`parallel`]: the baseline, `n` parallel broadcasts.

pub mod accusations;
pub mod bb;
pub mod compiler;
pub mod disclosure;
pub mod echo;
pub mod learn_or_expose;
pub mod parallel;
pub mod trust_graph;
