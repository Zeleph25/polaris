//! Per-node metrics, recorded at the send boundary and at verification calls.
//!
//! Both drivers write one JSON-lines file per node per run: a line per round
//! with that round's deltas, then one `summary` line. Byte counts are the
//! lengths produced by [`crate::wire::encode`].

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{NodeId, Round};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub msgs_sent: u64,
    pub bytes_sent: u64,
    pub msgs_recv: u64,
    pub bytes_recv: u64,
    /// Messages that arrived after the end of the round they were sent in
    /// (network runner only; always 0 in the simulator).
    pub late_msgs: u64,
    pub sig_verifies: u64,
    pub sig_verify_ns: u64,
}

impl Counters {
    fn add(&mut self, o: &Counters) {
        self.msgs_sent += o.msgs_sent;
        self.bytes_sent += o.bytes_sent;
        self.msgs_recv += o.msgs_recv;
        self.bytes_recv += o.bytes_recv;
        self.late_msgs += o.late_msgs;
        self.sig_verifies += o.sig_verifies;
        self.sig_verify_ns += o.sig_verify_ns;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    Round {
        node: NodeId,
        round: Round,
        #[serde(flatten)]
        counters: Counters,
    },
    Summary {
        node: NodeId,
        rounds: u32,
        decision_round: Option<Round>,
        #[serde(flatten)]
        total: Counters,
    },
}

#[derive(Clone, Debug, Default)]
pub struct Metrics {
    current: Counters,
    total: Counters,
    rounds: Vec<(Round, Counters)>,
    decision_round: Option<Round>,
}

impl Metrics {
    pub fn sent(&mut self, msgs: u64, bytes: u64) {
        self.current.msgs_sent += msgs;
        self.current.bytes_sent += bytes;
    }

    pub fn received(&mut self, msgs: u64, bytes: u64) {
        self.current.msgs_recv += msgs;
        self.current.bytes_recv += bytes;
    }

    pub fn late(&mut self, msgs: u64) {
        self.current.late_msgs += msgs;
    }

    pub fn verified(&mut self, count: u64, elapsed: Duration) {
        self.current.sig_verifies += count;
        self.current.sig_verify_ns += u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
    }

    /// Closes the round: its deltas become a record and join the totals.
    pub fn end_round(&mut self, round: Round) {
        self.total.add(&self.current);
        self.rounds.push((round, std::mem::take(&mut self.current)));
    }

    pub fn decided(&mut self, round: Round) {
        self.decision_round.get_or_insert(round);
    }

    pub fn decision_round(&self) -> Option<Round> {
        self.decision_round
    }

    /// Totals of the closed rounds.
    pub fn total(&self) -> Counters {
        self.total
    }

    pub fn rounds(&self) -> &[(Round, Counters)] {
        &self.rounds
    }

    pub fn records(&self, node: NodeId) -> Vec<Record> {
        let mut out: Vec<Record> = self
            .rounds
            .iter()
            .map(|(round, counters)| Record::Round {
                node,
                round: *round,
                counters: *counters,
            })
            .collect();
        out.push(Record::Summary {
            node,
            rounds: u32::try_from(self.rounds.len()).unwrap_or(u32::MAX),
            decision_round: self.decision_round,
            total: self.total,
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_roll_into_totals() {
        let mut m = Metrics::default();
        m.sent(3, 300);
        m.received(2, 150);
        m.end_round(0);
        m.verified(5, Duration::from_micros(10));
        m.decided(1);
        m.decided(2);
        m.end_round(1);
        assert_eq!(m.total().msgs_sent, 3);
        assert_eq!(m.total().sig_verifies, 5);
        assert_eq!(m.total().sig_verify_ns, 10_000);
        assert_eq!(m.decision_round(), Some(1));
        let recs = m.records(4);
        assert_eq!(recs.len(), 3);
        assert!(matches!(recs[2], Record::Summary { rounds: 2, .. }));
    }
}
