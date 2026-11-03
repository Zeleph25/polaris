//! A set of process ids as a fixed-width bitset.
//!
//! Used for the signer set of a multi-signature, for adversary delivery
//! masks, and for the adjacency rows of the trust graph, where common
//! neighbors are a popcount of an intersection.

use std::fmt;

use fixedbitset::FixedBitSet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::NodeId;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NodeSet {
    bits: FixedBitSet,
}

impl NodeSet {
    pub fn empty(n: usize) -> Self {
        Self {
            bits: FixedBitSet::with_capacity(n),
        }
    }

    pub fn full(n: usize) -> Self {
        let mut s = Self::empty(n);
        s.bits.set_range(.., true);
        s
    }

    pub fn from_iter(n: usize, ids: impl IntoIterator<Item = NodeId>) -> Self {
        let mut s = Self::empty(n);
        for id in ids {
            s.insert(id);
        }
        s
    }

    /// Number of processes the set ranges over (`n`), not the number of members.
    pub fn universe(&self) -> usize {
        self.bits.len()
    }

    /// Adds `id`; returns whether it was newly inserted.
    pub fn insert(&mut self, id: NodeId) -> bool {
        !self.bits.put(usize::from(id))
    }

    /// Removes `id`; returns whether it was a member.
    pub fn remove(&mut self, id: NodeId) -> bool {
        let was = self.bits.contains(usize::from(id));
        self.bits.set(usize::from(id), false);
        was
    }

    pub fn contains(&self, id: NodeId) -> bool {
        self.bits.contains(usize::from(id))
    }

    pub fn count(&self) -> usize {
        self.bits.count_ones(..)
    }

    pub fn is_empty(&self) -> bool {
        self.bits.is_clear()
    }

    pub fn iter(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.bits
            .ones()
            .map(|i| NodeId::try_from(i).expect("universe fits a NodeId"))
    }

    pub fn union_with(&mut self, other: &NodeSet) {
        self.bits.union_with(&other.bits);
    }

    pub fn intersect_with(&mut self, other: &NodeSet) {
        self.bits.intersect_with(&other.bits);
    }

    pub fn difference_with(&mut self, other: &NodeSet) {
        self.bits.difference_with(&other.bits);
    }

    /// `|self inter other|` without allocating.
    pub fn intersection_count(&self, other: &NodeSet) -> usize {
        self.bits.intersection_count(&other.bits)
    }

    pub fn is_subset(&self, other: &NodeSet) -> bool {
        self.bits.is_subset(&other.bits)
    }

    /// Little-endian bit packing, `ceil(n/8)` bytes; the wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.universe().div_ceil(8)];
        for i in self.bits.ones() {
            out[i / 8] |= 1 << (i % 8);
        }
        out
    }

    pub fn from_bytes(n: usize, bytes: &[u8]) -> Result<Self, NodeSetError> {
        if bytes.len() != n.div_ceil(8) {
            return Err(NodeSetError::Length {
                n,
                bytes: bytes.len(),
            });
        }
        let mut s = Self::empty(n);
        for i in 0..n {
            if bytes[i / 8] & (1 << (i % 8)) != 0 {
                s.bits.insert(i);
            }
        }
        // Bits past `n` in the last byte would make two encodings of one set.
        if !n.is_multiple_of(8) && bytes[n / 8] >> (n % 8) != 0 {
            return Err(NodeSetError::TrailingBits);
        }
        Ok(s)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NodeSetError {
    #[error("node set over {n} processes needs {} bytes, got {bytes}", n.div_ceil(8))]
    Length { n: usize, bytes: usize },
    #[error("node set encoding has bits set past n")]
    TrailingBits,
}

impl fmt::Debug for NodeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

#[derive(Serialize, Deserialize)]
struct Wire {
    n: u32,
    #[serde(with = "serde_bytes_vec")]
    bits: Vec<u8>,
}

impl Serialize for NodeSet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Wire {
            n: u32::try_from(self.universe()).map_err(serde::ser::Error::custom)?,
            bits: self.to_bytes(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for NodeSet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = Wire::deserialize(d)?;
        let n = usize::try_from(w.n).map_err(serde::de::Error::custom)?;
        NodeSet::from_bytes(n, &w.bits).map_err(serde::de::Error::custom)
    }
}

/// `Vec<u8>` as a byte string rather than a sequence of integers (postcard
/// encodes both compactly, JSON does not).
mod serde_bytes_vec {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Vec<u8>, E> {
                Ok(b.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, b: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(b)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_bytes(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_operations() {
        let mut a = NodeSet::from_iter(10, [1, 3, 9]);
        let b = NodeSet::from_iter(10, [3, 4]);
        assert_eq!(a.count(), 3);
        assert!(a.contains(9) && !a.contains(0));
        assert_eq!(a.intersection_count(&b), 1);
        assert!(a.insert(4));
        assert!(!a.insert(4));
        a.intersect_with(&b);
        assert_eq!(a.iter().collect::<Vec<_>>(), vec![3, 4]);
        assert!(a.is_subset(&b));
        assert_eq!(NodeSet::full(10).count(), 10);
    }

    #[test]
    fn bytes_roundtrip_and_canonical() {
        let s = NodeSet::from_iter(11, [0, 7, 8, 10]);
        let bytes = s.to_bytes();
        assert_eq!(bytes, vec![0b1000_0001, 0b0000_0101]);
        assert_eq!(NodeSet::from_bytes(11, &bytes).unwrap(), s);
        assert_eq!(
            NodeSet::from_bytes(11, &[1]),
            Err(NodeSetError::Length { n: 11, bytes: 1 })
        );
        assert_eq!(
            NodeSet::from_bytes(11, &[0, 0b1000_0000]),
            Err(NodeSetError::TrailingBits)
        );
    }

    #[test]
    fn serde_roundtrip() {
        let s = NodeSet::from_iter(70, [0, 64, 69]);
        let bytes = crate::wire::encode(&s).unwrap();
        assert_eq!(crate::wire::decode::<NodeSet>(&bytes).unwrap(), s);
        // 1 (n) + 1 (len) + 9 (bits)
        assert_eq!(bytes.len(), 11);
    }
}
