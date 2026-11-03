//! Lowercase hex.

use crate::{Error, Result};

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(char::from(DIGITS[usize::from(x >> 4)]));
        s.push(char::from(DIGITS[usize::from(x & 15)]));
    }
    s
}

fn nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Strict decode: lowercase digits only, even length.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    decode_bytes(s.as_bytes())
}

#[allow(clippy::manual_is_multiple_of, clippy::chunks_exact_to_as_chunks)]
pub fn decode_bytes(s: &[u8]) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::InvalidHex);
    }
    s.chunks_exact(2)
        .map(|p| match (nib(p[0]), nib(p[1])) {
            (Some(h), Some(l)) => Ok((h << 4) | l),
            _ => Err(Error::InvalidHex),
        })
        .collect()
}

/// Decodes exactly `N` bytes.
pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    crate::arr(&decode(s)?)
}

/// True if `s` is lowercase hex of exactly `bytes` bytes.
pub fn is_hex_len(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2 && s.bytes().all(|c| nib(c).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_strict() {
        assert_eq!(encode(&[0, 15, 255]), "000fff");
        assert_eq!(decode("000fff").unwrap(), vec![0, 15, 255]);
        assert!(decode("000FFF").is_err());
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
        assert!(is_hex_len("00ff", 2));
        assert!(!is_hex_len("00fF", 2));
    }
}
