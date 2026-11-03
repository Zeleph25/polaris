//! serde for `[u8; N]` as a byte string (`#[serde(with = "fixed_bytes")]`).
//! serde only implements arrays up to 32 bytes, and signatures are longer.

use serde::{Deserializer, Serializer, de};

pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(v)
}

pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
    struct V<const N: usize>;
    impl<'de, const N: usize> de::Visitor<'de> for V<N> {
        type Value = [u8; N];
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{N} bytes")
        }
        fn visit_bytes<E: de::Error>(self, b: &[u8]) -> Result<[u8; N], E> {
            <[u8; N]>::try_from(b).map_err(|_| E::invalid_length(b.len(), &self))
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; N], A::Error> {
            let mut out = [0u8; N];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(i, &self))?;
            }
            Ok(out)
        }
    }
    d.deserialize_bytes(V::<N>)
}
