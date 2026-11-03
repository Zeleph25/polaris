//! Lower-case hex for key files.

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HexError {
    #[error("odd number of hex digits")]
    OddLength,
    #[error("invalid hex digit {0:?}")]
    InvalidDigit(char),
    #[error("expected {expected} bytes, got {got}")]
    Length { expected: usize, got: usize },
}

pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0xf)] as char);
    }
    s
}

pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    if !s.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = digit(pair[0])?;
            let lo = digit(pair[1])?;
            Ok(hi << 4 | lo)
        })
        .collect()
}

pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    let v = decode(s)?;
    <[u8; N]>::try_from(v.as_slice()).map_err(|_| HexError::Length {
        expected: N,
        got: v.len(),
    })
}

fn digit(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexError::InvalidDigit(c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(encode(&bytes), "0001abff");
        assert_eq!(decode("0001abff").unwrap(), bytes);
        assert_eq!(decode("0001ABFF").unwrap(), bytes);
        assert_eq!(decode_array::<4>("0001abff").unwrap(), bytes);
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(decode("zz"), Err(HexError::InvalidDigit('z')));
        assert_eq!(
            decode_array::<2>("0001abff"),
            Err(HexError::Length {
                expected: 2,
                got: 4
            })
        );
    }
}
