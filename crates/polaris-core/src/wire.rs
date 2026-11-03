//! Wire encoding: postcard (serde, compact varints, deterministic).
//!
//! Both drivers encode through these two functions, and the byte counts
//! reported in the metrics are the lengths these return.

use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, thiserror::Error)]
#[error("wire encoding: {0}")]
pub struct WireError(#[from] postcard::Error);

pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, WireError> {
    Ok(postcard::to_allocvec(value)?)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    Ok(postcard::from_bytes(bytes)?)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::{Dest, NodeId, Round};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Envelope {
        round: Round,
        from: NodeId,
        to: Dest,
        payload: Vec<u8>,
    }

    #[test]
    fn roundtrip_is_exact_and_compact() {
        let e = Envelope {
            round: 7,
            from: 3,
            to: Dest::One(12),
            payload: vec![1, 2, 3],
        };
        let bytes = encode(&e).unwrap();
        assert_eq!(decode::<Envelope>(&bytes).unwrap(), e);
        // 1 (round) + 1 (from) + 2 (variant + id) + 1 (len) + 3 (payload)
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(decode::<Envelope>(&[0xff; 3]).is_err());
    }
}
