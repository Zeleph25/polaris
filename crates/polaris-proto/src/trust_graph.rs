//! The accusation graph of Algorithm 3 (`MakeGraph`), shared by
//! LearnOrExpose and the WXSD broadcast's trust graph.
//!
//! Start from the complete graph on `n` nodes, delete `{a, b}` for every
//! accusation `a -> b`, then repeatedly delete every edge whose endpoints have
//! fewer than `n - t` common neighbors. The deletion order does not matter:
//! the result is the largest subgraph of the accusation-free graph in which
//! every edge meets the rule, so it is a function of the accusation set, and
//! it is monotone (more accusations, fewer edges).
//!
//! **Closed neighborhoods.** The rule counts `|N[a] inter N[b]|`, i.e. `a` and
//! `b` count themselves. Algorithm 3 is printed with open neighborhoods
//! `|N(a) inter N(b)| < n - t`; with exactly `n - t` honest nodes and every
//! honest-Byzantine edge accused away, two honest nodes then share only
//! `n - t - 2` neighbors and the honest clique would be pruned, letting an
//! honest node be "exposed" (see `open_rule_breaks_the_honest_clique`). With
//! closed neighborhoods the honest clique (size >= n - t) always survives,
//! and the diameter bound `ceil(2n / (n - t))` of Claim 2 holds unchanged, since
//! its proof only uses `N[v_i] inter N[v_{i+1}] subset of D_i union D_{i+1}`.

use std::collections::VecDeque;

use polaris_core::{NodeId, NodeSet, Params};

#[derive(Clone, PartialEq, Eq)]
pub struct TrustGraph {
    n: usize,
    /// `|N[a] inter N[b]| >= threshold` for every surviving edge; `n - t`.
    threshold: usize,
    adj: Vec<NodeSet>,
}

impl TrustGraph {
    /// The complete graph on `params.n` nodes.
    pub fn complete(params: Params) -> Self {
        let n = params.n;
        let adj = (0..n)
            .map(|i| {
                let mut row = NodeSet::full(n);
                row.remove(id(i));
                row
            })
            .collect();
        Self {
            n,
            threshold: params.min_honest(),
            adj,
        }
    }

    /// `MakeGraph(Acc)`: the complete graph minus the accused edges, pruned.
    pub fn make(params: Params, accusations: impl IntoIterator<Item = (NodeId, NodeId)>) -> Self {
        let mut g = Self::complete(params);
        for (a, b) in accusations {
            g.remove_edge(a, b);
        }
        g.prune();
        g
    }

    pub fn n(&self) -> usize {
        self.n
    }

    pub fn has_edge(&self, a: NodeId, b: NodeId) -> bool {
        a != b && self.adj[usize::from(a)].contains(b)
    }

    /// Open neighborhood `N(v)`.
    pub fn neighbors(&self, v: NodeId) -> &NodeSet {
        &self.adj[usize::from(v)]
    }

    pub fn degree(&self, v: NodeId) -> usize {
        self.adj[usize::from(v)].count()
    }

    pub fn edge_count(&self) -> usize {
        self.adj.iter().map(NodeSet::count).sum::<usize>() / 2
    }

    /// Removes `{a, b}`; returns whether it was present. Self-loops do not exist.
    pub fn remove_edge(&mut self, a: NodeId, b: NodeId) -> bool {
        if a == b {
            return false;
        }
        let was = self.adj[usize::from(a)].remove(b);
        self.adj[usize::from(b)].remove(a);
        was
    }

    /// Isolates `v`: what a node proven to have equivocated gets.
    pub fn remove_node(&mut self, v: NodeId) {
        let others: Vec<NodeId> = self.adj[usize::from(v)].iter().collect();
        for u in others {
            self.remove_edge(v, u);
        }
    }

    /// `|N[a] inter N[b]|` for an edge `{a, b}`: the common open neighbors plus
    /// the endpoints themselves.
    fn closed_common(&self, a: NodeId, b: NodeId) -> usize {
        self.adj[usize::from(a)].intersection_count(&self.adj[usize::from(b)]) + 2
    }

    /// Deletes edges until every remaining edge has at least `n - t` common
    /// closed neighbors. Returns the number of edges deleted.
    pub fn prune(&mut self) -> usize {
        let mut deleted = 0;
        loop {
            let mut doomed = Vec::new();
            for a in 0..self.n {
                for b in self.adj[a].iter() {
                    if usize::from(b) > a && self.closed_common(id(a), b) < self.threshold {
                        doomed.push((id(a), b));
                    }
                }
            }
            if doomed.is_empty() {
                return deleted;
            }
            for (a, b) in doomed {
                self.remove_edge(a, b);
                deleted += 1;
            }
        }
    }

    /// BFS distances from `s`; `None` for nodes in other components.
    pub fn distances_from(&self, s: NodeId) -> Vec<Option<u32>> {
        let mut dist = vec![None; self.n];
        dist[usize::from(s)] = Some(0);
        let mut queue = VecDeque::from([s]);
        while let Some(u) = queue.pop_front() {
            let d = dist[usize::from(u)].expect("queued nodes have a distance");
            for v in self.adj[usize::from(u)].iter() {
                if dist[usize::from(v)].is_none() {
                    dist[usize::from(v)] = Some(d + 1);
                    queue.push_back(v);
                }
            }
        }
        dist
    }

    pub fn distance(&self, a: NodeId, b: NodeId) -> Option<u32> {
        self.distances_from(a)[usize::from(b)]
    }

    pub fn connected(&self, a: NodeId, b: NodeId) -> bool {
        self.distance(a, b).is_some()
    }

    /// `B_G(c, r)`: every node within distance `r` of `c`, `c` included.
    pub fn ball(&self, c: NodeId, r: u32) -> NodeSet {
        let dist = self.distances_from(c);
        NodeSet::from_iter(
            self.n,
            dist.iter()
                .enumerate()
                .filter(|(_, d)| d.is_some_and(|d| d <= r))
                .map(|(i, _)| id(i)),
        )
    }

    pub fn component(&self, v: NodeId) -> NodeSet {
        self.ball(v, u32::MAX)
    }

    /// The largest eccentricity over all nodes: the diameter of the widest
    /// component. `O(n * (n^2/64))`; for tests and diagnostics.
    pub fn max_component_diameter(&self) -> u32 {
        (0..self.n)
            .flat_map(|s| self.distances_from(id(s)).into_iter().flatten())
            .max()
            .unwrap_or(0)
    }

    /// Every edge of `self` is an edge of `other`.
    pub fn is_subgraph_of(&self, other: &TrustGraph) -> bool {
        self.n == other.n && self.adj.iter().zip(&other.adj).all(|(a, b)| a.is_subset(b))
    }

    /// The nodes of `set` form a clique.
    pub fn is_clique(&self, set: &NodeSet) -> bool {
        set.iter()
            .all(|a| set.iter().all(|b| a == b || self.has_edge(a, b)))
    }
}

fn id(i: usize) -> NodeId {
    NodeId::try_from(i).expect("n fits a NodeId")
}

impl std::fmt::Debug for TrustGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut edges = Vec::new();
        for a in 0..self.n {
            for b in self.adj[a].iter() {
                if usize::from(b) > a {
                    edges.push((a, b));
                }
            }
        }
        f.debug_struct("TrustGraph")
            .field("n", &self.n)
            .field("threshold", &self.threshold)
            .field("edges", &edges)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn params(n: usize, t: usize) -> Params {
        Params::new(n, t).unwrap()
    }

    #[test]
    fn complete_graph_basics() {
        let g = TrustGraph::complete(params(5, 2));
        assert_eq!(g.edge_count(), 10);
        assert!(g.has_edge(0, 4) && !g.has_edge(2, 2));
        assert_eq!(g.distance(0, 4), Some(1));
        assert_eq!(g.max_component_diameter(), 1);
        assert_eq!(g.ball(1, 0).iter().collect::<Vec<_>>(), vec![1]);
        assert_eq!(g.ball(1, 1).count(), 5);
    }

    #[test]
    fn accusations_cut_edges_and_pruning_cascades() {
        // n = 6, t = 3: an edge survives with >= 3 common closed neighbors.
        // Cut node 5 off from 0..3; the edge {4, 5} then has N[4] inter N[5] = {4, 5}: pruned.
        let g = TrustGraph::make(params(6, 3), [(0u16, 5u16), (1, 5), (2, 5), (3, 5)]);
        assert!(!g.has_edge(4, 5));
        assert_eq!(g.degree(5), 0);
        assert!(g.is_clique(&NodeSet::from_iter(6, 0..5)));
        assert!(!g.connected(0, 5));
        assert!(g.connected(0, 4));
    }

    #[test]
    fn remove_node_isolates() {
        let mut g = TrustGraph::complete(params(4, 1));
        g.remove_node(2);
        assert_eq!(g.degree(2), 0);
        assert_eq!(g.edge_count(), 3);
    }

    #[test]
    fn open_rule_breaks_the_honest_clique() {
        // n = 4, t = f = 2, honest {0, 1}; the Byzantine nodes accuse every honest node.
        let p = params(4, 2);
        let acc = [(2u16, 0u16), (2, 1), (3, 0), (3, 1)];
        let g = TrustGraph::make(p, acc);
        assert!(g.has_edge(0, 1), "closed rule keeps the honest edge");
        // The literal open-neighborhood rule would count |N(0) inter N(1)| = 0 < 2 and delete it.
        let mut open = TrustGraph::complete(p);
        for (a, b) in acc {
            open.remove_edge(a, b);
        }
        let common_open = open.neighbors(0).intersection_count(open.neighbors(1));
        assert!(common_open < p.min_honest());
    }

    /// Random accusation sets in which an honest subset `H` of size `n - t`
    /// never accuses within itself (Claim 1), with every other accusation
    /// chosen freely.
    fn accusation_sets() -> impl Strategy<Value = (Params, NodeSet, Vec<(NodeId, NodeId)>)> {
        (2usize..=12).prop_flat_map(|n| {
            (0..n).prop_flat_map(move |t| {
                let honest =
                    NodeSet::from_iter(n, (0..n - t).map(|i| NodeId::try_from(i).unwrap()));
                let pairs = (0..n as u16, 0..n as u16);
                proptest::collection::vec(pairs, 0..=(n * n)).prop_map(move |acc| {
                    let acc: Vec<_> = acc
                        .into_iter()
                        .filter(|&(a, b)| a != b && !(honest.contains(a) && honest.contains(b)))
                        .collect();
                    (Params::new(n, t).unwrap(), honest.clone(), acc)
                })
            })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(300))]

        #[test]
        fn honest_clique_survives_and_diameter_is_bounded((p, honest, acc) in accusation_sets()) {
            let g = TrustGraph::make(p, acc.iter().copied());
            prop_assert!(g.is_clique(&honest), "honest clique broken: {g:?}");
            for (a, b) in &acc {
                prop_assert!(!g.has_edge(*a, *b));
            }
            prop_assert!(g.max_component_diameter() <= p.diameter_bound(), "{g:?}");
        }

        #[test]
        fn pruning_is_monotone_and_idempotent((p, _honest, acc) in accusation_sets()) {
            let k = acc.len() / 2;
            let fewer = TrustGraph::make(p, acc[..k].iter().copied());
            let mut more = TrustGraph::make(p, acc.iter().copied());
            prop_assert!(more.is_subgraph_of(&fewer));
            prop_assert_eq!(more.prune(), 0);
        }
    }
}
