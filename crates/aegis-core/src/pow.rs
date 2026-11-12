//! Proof of work (spec section 4).

use crate::hex;
use sha2::{Digest, Sha256};

pub const DEFAULT_BITS: u32 = 18;
/// Allowed clock skew between client and server, in seconds.
pub const MAX_SKEW_SECS: u64 = 600;

fn prefix(scope: &str, ts: u64, body_hash: &str) -> Sha256 {
    let mut h = Sha256::new();
    h.update(b"aegis-v2 pow\n");
    h.update(scope.as_bytes());
    h.update(b"\n");
    h.update(ts.to_string().as_bytes());
    h.update(b"\n");
    h.update(body_hash.as_bytes());
    h.update(b"\n");
    h
}

/// `SHA256("aegis-v2 pow\n" || scope || "\n" || ts || "\n" || body_hash || "\n" || pow)`.
pub fn pow_hash(scope: &str, ts: u64, body_hash: &str, pow: u64) -> [u8; 32] {
    let mut h = prefix(scope, ts, body_hash);
    h.update(pow.to_string().as_bytes());
    h.finalize().into()
}

pub fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut n = 0;
    for &b in h {
        if b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

pub fn verify(scope: &str, ts: u64, body_hash: &str, pow: u64, bits: u32) -> bool {
    leading_zero_bits(&pow_hash(scope, ts, body_hash, pow)) >= bits
}

/// Smallest `pow` that satisfies `bits`, searching upward from zero.
pub fn mine(scope: &str, ts: u64, body_hash: &str, bits: u32) -> u64 {
    mine_from(scope, ts, body_hash, bits, 0)
}

/// Like `mine`, searching upward from `start` so identical requests get distinct proofs.
pub fn mine_from(scope: &str, ts: u64, body_hash: &str, bits: u32, start: u64) -> u64 {
    let base = prefix(scope, ts, body_hash);
    let mut n = start;
    loop {
        let mut h = base.clone();
        h.update(n.to_string().as_bytes());
        let d: [u8; 32] = h.finalize().into();
        if leading_zero_bits(&d) >= bits || n == u64::MAX {
            return n;
        }
        n += 1;
    }
}

/// Hex SHA-256, the `body_hash` input.
pub fn body_hash_hex(body: &[u8]) -> String {
    hex::encode(&crate::sha256(&[body]))
}

/// True if `|ts - now| <= 600`.
pub fn ts_in_window(ts: u64, now: u64) -> bool {
    ts.abs_diff(now) <= MAX_SKEW_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mine_and_verify() {
        let q = "ab".repeat(32);
        let bh = body_hash_hex(b"body");
        let n = mine(&q, 1000, &bh, 12);
        assert!(verify(&q, 1000, &bh, n, 12));
        assert!(leading_zero_bits(&pow_hash(&q, 1000, &bh, n)) >= 12);
        assert!(!verify(&q, 1001, &bh, n, 12) || !verify(&q, 1002, &bh, n, 12));
        assert!(!verify(&q, 1000, &body_hash_hex(b"other"), n, 16));
        assert!(verify(&q, 1000, &bh, 0, 0));
    }

    #[test]
    fn zero_bits_counting() {
        let mut h = [0u8; 32];
        h[1] = 0b0001_0000;
        assert_eq!(leading_zero_bits(&h), 11);
        assert_eq!(leading_zero_bits(&[0; 32]), 256);
    }

    #[test]
    fn window() {
        assert!(ts_in_window(1000, 1600));
        assert!(!ts_in_window(1000, 1601));
        assert!(ts_in_window(1600, 1000));
        assert!(!ts_in_window(1601, 1000));
    }
}
