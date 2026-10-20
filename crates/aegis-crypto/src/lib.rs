//! `aegis-crypto` — Core cryptographic boundary, secret buffer zeroization,
//! suite versioning, and anti-DoS Proof-of-Work challenge interfaces (D-0001, D-0007, D-0012).
//!
//! No custom cryptographic primitives are permitted (AGENTS.md §2.1).
//! Phase 1 binds audited crates (Argon2id, BLAKE3, HKDF-SHA256, ChaCha20-Poly1305,
//! Ed25519, X25519 + ML-KEM-768, OPAQUE, Double Ratchet) behind these traits.

use core::fmt;
use core::sync::atomic::{compiler_fence, Ordering};
use std::hint::black_box;

/// Current cryptographic suite version (D-0012).
pub const CRYPTO_SUITE_VERSION: u16 = 1;

/// Minimum allowed Proof-of-Work difficulty in leading zero bits (prevents 0-bit PoW bypass).
pub const MIN_POW_DIFFICULTY_BITS: u8 = 1;

/// Maximum allowed Proof-of-Work difficulty in leading zero bits (prevents CPU DoS).
pub const MAX_POW_DIFFICULTY_BITS: u8 = 32;

/// Typed errors returned by cryptographic operations.
/// Fail-closed by design: any verification failure aborts processing (AGENTS.md §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD authentication tag or MAC verification failed.
    AuthenticationFailed,
    /// Digital signature verification failed.
    InvalidSignature,
    /// Provided key or nonce length does not match primitive requirements.
    InvalidLength { expected: usize, actual: usize },
    /// Proof-of-Work solution does not satisfy required difficulty.
    InvalidPowSolution,
    /// Unsupported cryptographic suite version.
    UnsupportedSuiteVersion(u16),
    /// Key derivation or entropy source failure.
    KeyDerivationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => write!(f, "authentication tag verification failed"),
            Self::InvalidSignature => write!(f, "signature verification failed"),
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid buffer length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidPowSolution => write!(f, "proof-of-work solution rejected"),
            Self::UnsupportedSuiteVersion(v) => {
                write!(f, "unsupported crypto suite version: {v}")
            }
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Memory-safe buffer for secret material that overwrites its contents with zeroes on `Drop`
/// without using `unsafe` code, and redacts its contents in `Debug` output (AGENTS.md §2.4, §2.7).
#[derive(Clone, PartialEq, Eq)]
pub struct ZeroizingBuffer {
    bytes: Vec<u8>,
}

impl ZeroizingBuffer {
    /// Creates a new secret buffer taking ownership of `bytes`.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Creates a zero-initialized secret buffer of `len` bytes.
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        Self {
            bytes: vec![0u8; len],
        }
    }

    /// Borrows the secret bytes for cryptographic operations.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutably borrows the secret bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Returns the length of the buffer in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Explicitly zeroes the buffer contents using `black_box` and a compiler fence
    /// to prevent dead-store elimination.
    pub fn zeroize(&mut self) {
        for byte in &mut self.bytes {
            *byte = black_box(0u8);
        }
        let _ = black_box(self.bytes.as_mut_slice());
        compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for ZeroizingBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for ZeroizingBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZeroizingBuffer([REDACTED; {} bytes])", self.bytes.len())
    }
}

/// Constant-time slice equality check to avoid timing side-channels on MAC/tag comparisons.
#[must_use]
pub fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&a, &b) in lhs.iter().zip(rhs.iter()) {
        diff |= a ^ b;
    }
    black_box(diff) == 0
}

/// Anti-DDoS Proof-of-Work challenge descriptor (D-0006, D-0007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowChallenge {
    /// Server-issued random challenge nonce (32 bytes).
    pub challenge: [u8; 32],
    /// Required number of leading zero bits in the hash output.
    pub difficulty_bits: u8,
    /// Challenge expiration timestamp (Unix seconds).
    pub expires_at_unix_secs: u64,
}

/// Proof-of-Work puzzle solver and verifier interface.
pub trait PowVerifier {
    /// Verifies that `nonce` solves `challenge` at `current_unix_secs`.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidPowSolution`] if expired or insufficient leading zeroes.
    fn verify_pow(
        &self,
        challenge: &PowChallenge,
        nonce: u64,
        current_unix_secs: u64,
    ) -> Result<(), CryptoError>;
}

/// Counts leading zero bits across a byte slice.
#[must_use]
pub fn count_leading_zero_bits(digest: &[u8]) -> u32 {
    let mut total = 0u32;
    for &byte in digest {
        if byte == 0 {
            total = total.saturating_add(8);
        } else {
            total = total.saturating_add(byte.leading_zeros());
            break;
        }
    }
    total
}

/// Deterministic test verifier used before BLAKE3 integration in Phase 1.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicPowVerifier;

impl DeterministicPowVerifier {
    /// Computes a deterministic 32-byte digest placeholder for Phase 0 contract testing.
    /// Replaced by `blake3::Hasher` in Phase 1 (T-0004).
    #[must_use]
    pub fn digest_for_test(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        let nonce_bytes = nonce.to_le_bytes();
        for (i, slot) in out.iter_mut().enumerate() {
            let c = challenge[i];
            let n = nonce_bytes[i % 8];
            let mixed = c
                .wrapping_add(n)
                .wrapping_mul(0x9E)
                .rotate_left((i as u32) % 7 + 1);
            *slot = mixed ^ n;
        }
        out
    }
}

impl PowVerifier for DeterministicPowVerifier {
    fn verify_pow(
        &self,
        challenge: &PowChallenge,
        nonce: u64,
        current_unix_secs: u64,
    ) -> Result<(), CryptoError> {
        if challenge.difficulty_bits < MIN_POW_DIFFICULTY_BITS
            || challenge.difficulty_bits > MAX_POW_DIFFICULTY_BITS
            || challenge.challenge == [0u8; 32]
            || current_unix_secs > challenge.expires_at_unix_secs
        {
            return Err(CryptoError::InvalidPowSolution);
        }
        let digest = Self::digest_for_test(&challenge.challenge, nonce);
        if count_leading_zero_bits(&digest) >= u32::from(challenge.difficulty_bits) {
            Ok(())
        } else {
            Err(CryptoError::InvalidPowSolution)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn zeroizing_buffer_redacts_debug_and_zeroes_memory() {
        let mut buf = ZeroizingBuffer::new(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let dbg = format!("{buf:?}");
        assert!(!dbg.contains("170"));
        assert!(!dbg.contains("AA"));
        assert!(dbg.contains("[REDACTED; 4 bytes]"));

        buf.zeroize();
        assert_eq!(buf.as_slice(), &[0, 0, 0, 0]);
    }

    #[test]
    fn constant_time_equality_works_on_edge_cases() {
        assert!(constant_time_eq(&[], &[]));
        assert!(constant_time_eq(b"aegis-mac-tag", b"aegis-mac-tag"));
        assert!(!constant_time_eq(b"aegis-mac-tag", b"aegis-mac-taG"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn leading_zero_bits_calculation() {
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0x0F, 0xFF]), 20);
        assert_eq!(count_leading_zero_bits(&[0x80, 0x00]), 0);
        assert_eq!(count_leading_zero_bits(&[0x01]), 7);
    }

    #[test]
    fn pow_verifier_rejects_expired_and_accepts_valid_nonce() {
        let verifier = DeterministicPowVerifier;
        let challenge = PowChallenge {
            challenge: [0xA5; 32],
            difficulty_bits: 4,
            expires_at_unix_secs: 1_000,
        };

        let solved_nonce = (0..10_000u64)
            .find(|&n| verifier.verify_pow(&challenge, n, 500).is_ok())
            .expect("must find a nonce for 4-bit difficulty");

        assert!(verifier.verify_pow(&challenge, solved_nonce, 500).is_ok());
        assert_eq!(
            verifier.verify_pow(&challenge, solved_nonce, 1_001),
            Err(CryptoError::InvalidPowSolution)
        );
    }

    #[test]
    fn b0011_pow_verifier_rejects_zero_difficulty_excessive_difficulty_and_zero_challenge() {
        let verifier = DeterministicPowVerifier;
        assert_eq!(
            verifier.verify_pow(
                &PowChallenge {
                    challenge: [0xA5; 32],
                    difficulty_bits: 0,
                    expires_at_unix_secs: 1_000,
                },
                0,
                500
            ),
            Err(CryptoError::InvalidPowSolution)
        );
        assert_eq!(
            verifier.verify_pow(
                &PowChallenge {
                    challenge: [0xA5; 32],
                    difficulty_bits: 33,
                    expires_at_unix_secs: 1_000,
                },
                0,
                500
            ),
            Err(CryptoError::InvalidPowSolution)
        );
        assert_eq!(
            verifier.verify_pow(
                &PowChallenge {
                    challenge: [0u8; 32],
                    difficulty_bits: 4,
                    expires_at_unix_secs: 1_000,
                },
                0,
                500
            ),
            Err(CryptoError::InvalidPowSolution)
        );
    }
}
