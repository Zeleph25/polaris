//! What was delivered to whom, in a form both drivers produce identically.
//!
//! One entry per delivered message: the round it was sent in, sender,
//! recipient, wire size and digest of the wire bytes. The per-round inbox
//! fingerprint of a node is order-independent, so a simulator run and a
//! network run of the same protocol with the same keys can be compared
//! inbox by inbox.

use std::collections::BTreeMap;

use polaris_core::{NodeId, Round};
use polaris_crypto::hash::{Digest, digest};
use serde::{Deserialize, Serialize};

const TAG: &[u8] = b"polaris/v1/transcript";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub round: Round,
    pub from: NodeId,
    pub to: NodeId,
    pub bytes: u32,
    pub digest: Digest,
}

impl Entry {
    pub fn new(round: Round, from: NodeId, to: NodeId, wire: &[u8]) -> Self {
        Self {
            round,
            from,
            to,
            bytes: u32::try_from(wire.len()).unwrap_or(u32::MAX),
            digest: digest(TAG, wire),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transcript {
    entries: Vec<Entry>,
}

impl Transcript {
    pub fn record(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Fingerprint of the whole transcript in delivery order: two runs of
    /// the simulator with one seed must agree on it.
    pub fn fingerprint(&self) -> Digest {
        let mut h = blake3::Hasher::new();
        for e in &self.entries {
            h.update(&e.round.to_le_bytes());
            h.update(&e.from.to_le_bytes());
            h.update(&e.to.to_le_bytes());
            h.update(&e.digest);
        }
        *h.finalize().as_bytes()
    }

    /// One fingerprint per `(round, recipient)`, independent of the order
    /// messages arrived in: the simulator and the network runner must agree.
    pub fn inbox_fingerprints(&self) -> BTreeMap<(Round, NodeId), Digest> {
        let mut inboxes: BTreeMap<(Round, NodeId), Vec<(NodeId, Digest)>> = BTreeMap::new();
        for e in &self.entries {
            inboxes
                .entry((e.round, e.to))
                .or_default()
                .push((e.from, e.digest));
        }
        inboxes
            .into_iter()
            .map(|(key, mut msgs)| {
                msgs.sort();
                let mut h = blake3::Hasher::new();
                for (from, d) in msgs {
                    h.update(&from.to_le_bytes());
                    h.update(&d);
                }
                (key, *h.finalize().as_bytes())
            })
            .collect()
    }

    pub fn to_json_lines(&self) -> String {
        let mut s = String::new();
        for e in &self.entries {
            s.push_str(&serde_json::to_string(&Line::from(e)).expect("serializable"));
            s.push('\n');
        }
        s
    }

    pub fn from_json_lines(s: &str) -> Result<Self, serde_json::Error> {
        let mut t = Self::default();
        for line in s.lines().filter(|l| !l.trim().is_empty()) {
            t.record(Entry::try_from(serde_json::from_str::<Line>(line)?)?);
        }
        Ok(t)
    }
}

/// JSON form with a hex digest, readable and greppable.
#[derive(Serialize, Deserialize)]
struct Line {
    round: Round,
    from: NodeId,
    to: NodeId,
    bytes: u32,
    digest: String,
}

impl From<&Entry> for Line {
    fn from(e: &Entry) -> Self {
        Self {
            round: e.round,
            from: e.from,
            to: e.to,
            bytes: e.bytes,
            digest: polaris_crypto::hex::encode(&e.digest),
        }
    }
}

impl TryFrom<Line> for Entry {
    type Error = serde_json::Error;
    fn try_from(l: Line) -> Result<Self, serde_json::Error> {
        Ok(Self {
            round: l.round,
            from: l.from,
            to: l.to,
            bytes: l.bytes,
            digest: polaris_crypto::hex::decode_array(&l.digest)
                .map_err(serde::de::Error::custom)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbox_fingerprints_ignore_arrival_order() {
        let mut a = Transcript::default();
        a.record(Entry::new(1, 0, 2, b"x"));
        a.record(Entry::new(1, 1, 2, b"y"));
        let mut b = Transcript::default();
        b.record(Entry::new(1, 1, 2, b"y"));
        b.record(Entry::new(1, 0, 2, b"x"));
        assert_eq!(a.inbox_fingerprints(), b.inbox_fingerprints());
        assert_ne!(a.fingerprint(), b.fingerprint());
        let mut c = a.clone();
        c.record(Entry::new(1, 1, 2, b"y"));
        assert_ne!(a.inbox_fingerprints(), c.inbox_fingerprints());
    }

    #[test]
    fn json_lines_roundtrip() {
        let mut a = Transcript::default();
        a.record(Entry::new(3, 4, 5, b"hello"));
        let back = Transcript::from_json_lines(&a.to_json_lines()).unwrap();
        assert_eq!(back, a);
    }
}
