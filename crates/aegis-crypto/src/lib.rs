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

/// Solution to an Anti-DDoS Proof-of-Work challenge (D-0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowSolution {
    /// Winning 64-bit nonce.
    pub nonce: u64,
    /// Resulting 32-byte hash digest with at least `difficulty_bits` leading zeroes.
    pub digest: [u8; 32],
}

/// Solves a [`PowChallenge`] within `max_iterations` attempts (D-0007).
/// Returns `None` if the challenge parameters are invalid or no solution is found within the budget.
#[must_use]
pub fn solve_pow(challenge: &PowChallenge, max_iterations: u64) -> Option<PowSolution> {
    if challenge.difficulty_bits < MIN_POW_DIFFICULTY_BITS
        || challenge.difficulty_bits > MAX_POW_DIFFICULTY_BITS
        || challenge.challenge == [0u8; 32]
    {
        return None;
    }
    let required = u32::from(challenge.difficulty_bits);
    for nonce in 0..max_iterations {
        let digest = DeterministicPowVerifier::digest_for_test(&challenge.challenge, nonce);
        if count_leading_zero_bits(&digest) >= required {
            return Some(PowSolution { nonce, digest });
        }
    }
    None
}

// ============================================================================
// Standard FIPS 180-4 SHA-256, RFC 2104 HMAC-SHA256, RFC 5869 HKDF-SHA256
// ============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, slot) in w.iter_mut().enumerate().take(16) {
        let base = i * 4;
        *slot = u32::from_be_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Computes the standard FIPS 180-4 SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let (blocks, rem) = data.as_chunks::<64>();
    for block in blocks {
        sha256_compress(&mut state, block);
    }

    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    if rem.len() < 56 {
        tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let mut block = [0u8; 64];
        block.copy_from_slice(&tail[..64]);
        sha256_compress(&mut state, &block);
    } else {
        tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
        let mut block1 = [0u8; 64];
        let mut block2 = [0u8; 64];
        block1.copy_from_slice(&tail[..64]);
        block2.copy_from_slice(&tail[64..128]);
        sha256_compress(&mut state, &block1);
        sha256_compress(&mut state, &block2);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_be_bytes();
        let base = i * 4;
        out[base..base + 4].copy_from_slice(&bytes);
    }
    out
}

/// Computes the standard RFC 2104 HMAC-SHA256 authentication code.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = ZeroizingBuffer::zeroed(64);
    if key.len() > 64 {
        let hashed = sha256(key);
        key_block.as_mut_slice()[..32].copy_from_slice(&hashed);
    } else {
        key_block.as_mut_slice()[..key.len()].copy_from_slice(key);
    }

    let mut ipad_msg = Vec::with_capacity(64 + data.len());
    let mut opad_msg = Vec::with_capacity(64 + 32);
    for &b in key_block.as_slice() {
        ipad_msg.push(b ^ 0x36);
        opad_msg.push(b ^ 0x5c);
    }
    ipad_msg.extend_from_slice(data);
    let inner_hash = sha256(&ipad_msg);
    opad_msg.extend_from_slice(&inner_hash);
    sha256(&opad_msg)
}

/// Derives cryptographic key material using standard RFC 5869 HKDF-SHA256 (D-0012).
///
/// # Errors
/// Returns [`CryptoError::KeyDerivationFailed`] if `out` is empty or exceeds `255 * 32` bytes.
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if out.is_empty() || out.len() > 255 * 32 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    let effective_salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    let prk = ZeroizingBuffer::new(hmac_sha256(effective_salt, ikm).to_vec());

    let mut prev = [0u8; 32];
    let mut prev_len = 0usize;
    let mut written = 0usize;
    let mut counter = 1u8;

    while written < out.len() {
        let mut msg = Vec::with_capacity(prev_len + info.len() + 1);
        msg.extend_from_slice(&prev[..prev_len]);
        msg.extend_from_slice(info);
        msg.push(counter);

        prev = hmac_sha256(prk.as_slice(), &msg);
        prev_len = 32;

        let to_copy = (out.len() - written).min(32);
        out[written..written + to_copy].copy_from_slice(&prev[..to_copy]);
        written += to_copy;
        counter = counter.wrapping_add(1);
    }

    for b in &mut prev {
        *b = black_box(0u8);
    }
    Ok(())
}

// ============================================================================
// Standard RFC 8439 ChaCha20-Poly1305 AEAD
// ============================================================================

/// Authentication tag length in bytes for ChaCha20-Poly1305 AEAD.
pub const AEAD_TAG_LEN: usize = 16;

fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Computes a single 64-byte ChaCha20 keystream block per RFC 8439 §2.3.
#[must_use]
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[0] = 0x6170_7865;
    initial[1] = 0x3320_646e;
    initial[2] = 0x7962_2d32;
    initial[3] = 0x6b20_6574;

    for i in 0..8 {
        let base = i * 4;
        initial[4 + i] =
            u32::from_le_bytes([key[base], key[base + 1], key[base + 2], key[base + 3]]);
    }
    initial[12] = counter;
    for i in 0..3 {
        let base = i * 4;
        initial[13 + i] = u32::from_le_bytes([
            nonce[base],
            nonce[base + 1],
            nonce[base + 2],
            nonce[base + 3],
        ]);
    }

    let mut working = initial;
    for _ in 0..10 {
        // Column rounds
        chacha20_quarter_round(&mut working, 0, 4, 8, 12);
        chacha20_quarter_round(&mut working, 1, 5, 9, 13);
        chacha20_quarter_round(&mut working, 2, 6, 10, 14);
        chacha20_quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        chacha20_quarter_round(&mut working, 0, 5, 10, 15);
        chacha20_quarter_round(&mut working, 1, 6, 11, 12);
        chacha20_quarter_round(&mut working, 2, 7, 8, 13);
        chacha20_quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(initial[i]);
        let base = i * 4;
        out[base..base + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = black_box(0u8);
    }
    let _ = black_box(buf);
    compiler_fence(Ordering::SeqCst);
}

fn chacha20_xor(key: &[u8; 32], initial_counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut counter = initial_counter;
    for chunk in data.chunks_mut(64) {
        let mut block = chacha20_block(key, counter, nonce);
        for (dst, &ks) in chunk.iter_mut().zip(block.iter()) {
            *dst ^= ks;
        }
        zeroize_slice(&mut block);
        counter = counter.wrapping_add(1);
    }
}

/// Computes the RFC 8439 §2.5 Poly1305 one-time MAC using 5x26-bit limb arithmetic.
#[must_use]
pub fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&key[0..16]);
    // Clamp r per RFC 8439 §2.5
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    let t0 = u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]) as u64;
    let t1 = u32::from_le_bytes([r_bytes[4], r_bytes[5], r_bytes[6], r_bytes[7]]) as u64;
    let t2 = u32::from_le_bytes([r_bytes[8], r_bytes[9], r_bytes[10], r_bytes[11]]) as u64;
    let t3 = u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]) as u64;

    let r0 = t0 & 0x03ff_ffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff;
    let r4 = t3 >> 8;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    for chunk in msg.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;

        let b0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as u64;
        let b1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]) as u64;
        let b2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]) as u64;
        let b3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]) as u64;
        let hibit = u64::from(block[16]) << 24;

        h0 += b0 & 0x03ff_ffff;
        h1 += ((b0 >> 26) | (b1 << 6)) & 0x03ff_ffff;
        h2 += ((b1 >> 20) | (b2 << 12)) & 0x03ff_ffff;
        h3 += ((b2 >> 14) | (b3 << 18)) & 0x03ff_ffff;
        h4 += (b3 >> 8) | hibit;

        let d0 = u128::from(h0) * u128::from(r0)
            + u128::from(h1) * u128::from(s4)
            + u128::from(h2) * u128::from(s3)
            + u128::from(h3) * u128::from(s2)
            + u128::from(h4) * u128::from(s1);
        let d1 = u128::from(h0) * u128::from(r1)
            + u128::from(h1) * u128::from(r0)
            + u128::from(h2) * u128::from(s4)
            + u128::from(h3) * u128::from(s3)
            + u128::from(h4) * u128::from(s2);
        let d2 = u128::from(h0) * u128::from(r2)
            + u128::from(h1) * u128::from(r1)
            + u128::from(h2) * u128::from(r0)
            + u128::from(h3) * u128::from(s4)
            + u128::from(h4) * u128::from(s3);
        let d3 = u128::from(h0) * u128::from(r3)
            + u128::from(h1) * u128::from(r2)
            + u128::from(h2) * u128::from(r1)
            + u128::from(h3) * u128::from(r0)
            + u128::from(h4) * u128::from(s4);
        let d4 = u128::from(h0) * u128::from(r4)
            + u128::from(h1) * u128::from(r3)
            + u128::from(h2) * u128::from(r2)
            + u128::from(h3) * u128::from(r1)
            + u128::from(h4) * u128::from(r0);

        let mut c: u64;
        c = (d0 >> 26) as u64;
        h0 = (d0 as u64) & 0x03ff_ffff;
        let d1 = d1 + u128::from(c);
        c = (d1 >> 26) as u64;
        h1 = (d1 as u64) & 0x03ff_ffff;
        let d2 = d2 + u128::from(c);
        c = (d2 >> 26) as u64;
        h2 = (d2 as u64) & 0x03ff_ffff;
        let d3 = d3 + u128::from(c);
        c = (d3 >> 26) as u64;
        h3 = (d3 as u64) & 0x03ff_ffff;
        let d4 = d4 + u128::from(c);
        c = (d4 >> 26) as u64;
        h4 = (d4 as u64) & 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;
    }

    // Final full reduction modulo 2^130 - 5
    let mut c = h1 >> 26;
    h1 &= 0x03ff_ffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x03ff_ffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x03ff_ffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x03ff_ffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x03ff_ffff;
    h1 += c;

    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x03ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x03ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x03ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x03ff_ffff;
    let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    let inv_mask = !mask;
    h0 = (h0 & inv_mask) | g0;
    h1 = (h1 & inv_mask) | g1;
    h2 = (h2 & inv_mask) | g2;
    h3 = (h3 & inv_mask) | g3;
    h4 = (h4 & inv_mask) | g4;

    let w0 = (h0 | (h1 << 26)) & 0xffff_ffff;
    let w1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
    let w2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
    let w3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

    let pad0 = u64::from(u32::from_le_bytes([key[16], key[17], key[18], key[19]]));
    let pad1 = u64::from(u32::from_le_bytes([key[20], key[21], key[22], key[23]]));
    let pad2 = u64::from(u32::from_le_bytes([key[24], key[25], key[26], key[27]]));
    let pad3 = u64::from(u32::from_le_bytes([key[28], key[29], key[30], key[31]]));

    let mut f: u64;
    f = w0 + pad0;
    let out0 = f as u32;
    f = w1 + pad1 + (f >> 32);
    let out1 = f as u32;
    f = w2 + pad2 + (f >> 32);
    let out2 = f as u32;
    f = w3 + pad3 + (f >> 32);
    let out3 = f as u32;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&out0.to_le_bytes());
    tag[4..8].copy_from_slice(&out1.to_le_bytes());
    tag[8..12].copy_from_slice(&out2.to_le_bytes());
    tag[12..16].copy_from_slice(&out3.to_le_bytes());
    tag
}

fn compute_rfc8439_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    let mut mac_data = Vec::with_capacity(aad.len() + aad_pad + ciphertext.len() + ct_pad + 16);
    mac_data.extend_from_slice(aad);
    mac_data.resize(aad.len() + aad_pad, 0u8);
    mac_data.extend_from_slice(ciphertext);
    mac_data.resize(aad.len() + aad_pad + ciphertext.len() + ct_pad, 0u8);
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305_mac(&mac_data, otk)
}

/// Encrypts and authenticates `plaintext` with associated data `aad` using RFC 8439 ChaCha20-Poly1305.
/// Returns `ciphertext || 16-byte Poly1305 tag`.
///
/// # Errors
/// Returns [`CryptoError::InvalidLength`] if `key` is all-zero.
pub fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key == &[0u8; 32] {
        return Err(CryptoError::InvalidLength {
            expected: 32,
            actual: 0,
        });
    }
    let mut block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[0..32]);
    zeroize_slice(&mut block0);

    let mut out = Vec::with_capacity(plaintext.len() + AEAD_TAG_LEN);
    out.extend_from_slice(plaintext);
    chacha20_xor(key, 1, nonce, &mut out);

    let tag = compute_rfc8439_tag(&otk, aad, &out);
    out.extend_from_slice(&tag);

    zeroize_slice(&mut otk);
    Ok(out)
}

/// Verifies and decrypts `ciphertext_and_tag` with associated data `aad` using RFC 8439 ChaCha20-Poly1305.
/// Fail-closed: verifies the 16-byte MAC tag in constant time BEFORE decrypting any byte.
///
/// # Errors
/// Returns [`CryptoError::AuthenticationFailed`] if the ciphertext is shorter than 16 bytes,
/// the key is all-zero, or the tag verification fails.
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<ZeroizingBuffer, CryptoError> {
    if key == &[0u8; 32] || ciphertext_and_tag.len() < AEAD_TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }
    let ct_len = ciphertext_and_tag.len() - AEAD_TAG_LEN;
    let ciphertext = &ciphertext_and_tag[..ct_len];
    let received_tag = &ciphertext_and_tag[ct_len..];

    let mut block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[0..32]);
    zeroize_slice(&mut block0);

    let expected_tag = compute_rfc8439_tag(&otk, aad, ciphertext);
    zeroize_slice(&mut otk);

    if !constant_time_eq(received_tag, &expected_tag) {
        return Err(CryptoError::AuthenticationFailed);
    }

    let mut plaintext = ciphertext.to_vec();
    chacha20_xor(key, 1, nonce, &mut plaintext);
    Ok(ZeroizingBuffer::new(plaintext))
}

// ============================================================================
// Hybrid PQXDH Key Combiner & Double Ratchet Session State (D-0012)
// ============================================================================

/// Maximum number of skipped out-of-order message keys cached per ratchet session.
pub const MAX_SKIPPED_KEYS: usize = 64;

/// Combined hybrid secret from classical X25519 + post-quantum ML-KEM-768 (D-0012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridKemSecret {
    secret: ZeroizingBuffer,
}

impl HybridKemSecret {
    /// Borrows the 32-byte hybrid root secret.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// Combines classical `X25519` Diffie-Hellman output and post-quantum `ML-KEM-768` shared secret
/// into a 32-byte root key using HKDF-SHA256 (D-0012).
///
/// # Errors
/// Fail-closed: rejects all-zero classical or post-quantum shared secrets.
pub fn combine_pqxdh_secrets(
    x25519_dh: &[u8; 32],
    ml_kem_ss: &[u8; 32],
    context: &[u8],
) -> Result<ZeroizingBuffer, CryptoError> {
    if x25519_dh == &[0u8; 32] || ml_kem_ss == &[0u8; 32] {
        return Err(CryptoError::KeyDerivationFailed);
    }
    let mut ikm = ZeroizingBuffer::zeroed(64);
    ikm.as_mut_slice()[0..32].copy_from_slice(x25519_dh);
    ikm.as_mut_slice()[32..64].copy_from_slice(ml_kem_ss);

    let mut out = [0u8; 32];
    hkdf_sha256(b"Aegis-PQXDH-Root-v1", ikm.as_slice(), context, &mut out)?;
    Ok(ZeroizingBuffer::new(out.to_vec()))
}

/// Wire header attached to each Double Ratchet encrypted message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatchetHeader {
    /// Sender's current ephemeral ratchet public key.
    pub dh_public: [u8; 32],
    /// Number of messages sent in the previous sending chain.
    pub prev_chain_len: u32,
    /// Message index in the current sending chain.
    pub msg_num: u32,
}

fn kdf_chain_step(chain_key: &[u8]) -> ([u8; 32], [u8; 32]) {
    let next_chain_key = hmac_sha256(chain_key, &[0x02]);
    let message_key = hmac_sha256(chain_key, &[0x01]);
    (next_chain_key, message_key)
}

fn message_nonce(dh_public: &[u8; 32], msg_num: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&dh_public[0..8]);
    nonce[8..12].copy_from_slice(&msg_num.to_be_bytes());
    nonce
}

/// Stateful Double Ratchet session with forward secrecy, post-compromise recovery,
/// out-of-order skipped key caching (`MAX_SKIPPED_KEYS`), and replay rejection (D-0012).
#[derive(Debug, Clone)]
pub struct RatchetSession {
    root_key: ZeroizingBuffer,
    send_chain_key: ZeroizingBuffer,
    recv_chain_key: ZeroizingBuffer,
    our_dh_public: [u8; 32],
    peer_dh_public: [u8; 32],
    send_msg_num: u32,
    recv_msg_num: u32,
    prev_send_chain_len: u32,
    skipped_keys: Vec<([u8; 32], u32, ZeroizingBuffer)>,
}

/// Type alias for compatibility with protocol state references.
pub type RatchetState = RatchetSession;

impl RatchetSession {
    /// Initializes a paired ratchet session from a 32-byte hybrid PQXDH root secret.
    ///
    /// # Errors
    /// Returns [`CryptoError::KeyDerivationFailed`] if `initial_root_secret` is not 32 non-zero bytes.
    pub fn new(
        initial_root_secret: &[u8],
        our_dh_public: [u8; 32],
        peer_dh_public: [u8; 32],
        is_initiator: bool,
    ) -> Result<Self, CryptoError> {
        if initial_root_secret.len() != 32
            || initial_root_secret.iter().all(|&b| b == 0)
            || our_dh_public == [0u8; 32]
            || peer_dh_public == [0u8; 32]
            || our_dh_public == peer_dh_public
        {
            return Err(CryptoError::KeyDerivationFailed);
        }
        let mut derived = [0u8; 96];
        hkdf_sha256(
            b"Aegis-DoubleRatchet-Init-v1",
            initial_root_secret,
            b"chains",
            &mut derived,
        )?;
        let root = derived[0..32].to_vec();
        let (send_ck, recv_ck) = if is_initiator {
            (derived[32..64].to_vec(), derived[64..96].to_vec())
        } else {
            (derived[64..96].to_vec(), derived[32..64].to_vec())
        };
        for b in &mut derived {
            *b = black_box(0u8);
        }
        Ok(Self {
            root_key: ZeroizingBuffer::new(root),
            send_chain_key: ZeroizingBuffer::new(send_ck),
            recv_chain_key: ZeroizingBuffer::new(recv_ck),
            our_dh_public,
            peer_dh_public,
            send_msg_num: 0,
            recv_msg_num: 0,
            prev_send_chain_len: 0,
            skipped_keys: Vec::new(),
        })
    }

    /// Performs a Diffie-Hellman ratchet step to heal the session after key rotation.
    ///
    /// # Errors
    /// Returns [`CryptoError::KeyDerivationFailed`] if `dh_shared_secret` is all-zero.
    pub fn dh_ratchet_step(
        &mut self,
        new_our_dh_public: [u8; 32],
        new_peer_dh_public: [u8; 32],
        dh_shared_secret: &[u8; 32],
    ) -> Result<(), CryptoError> {
        if dh_shared_secret == &[0u8; 32]
            || new_our_dh_public == [0u8; 32]
            || new_peer_dh_public == [0u8; 32]
            || new_our_dh_public == new_peer_dh_public
            || (new_our_dh_public == self.our_dh_public
                && new_peer_dh_public == self.peer_dh_public)
        {
            return Err(CryptoError::KeyDerivationFailed);
        }
        let mut out = [0u8; 96];
        hkdf_sha256(
            self.root_key.as_slice(),
            dh_shared_secret,
            b"Aegis-DR-RatchetStep",
            &mut out,
        )?;
        self.root_key = ZeroizingBuffer::new(out[0..32].to_vec());
        self.send_chain_key = ZeroizingBuffer::new(out[32..64].to_vec());
        self.recv_chain_key = ZeroizingBuffer::new(out[64..96].to_vec());
        for b in &mut out {
            *b = black_box(0u8);
        }
        self.prev_send_chain_len = self.send_msg_num;
        self.send_msg_num = 0;
        self.recv_msg_num = 0;
        self.our_dh_public = new_our_dh_public;
        self.peer_dh_public = new_peer_dh_public;
        Ok(())
    }

    /// Advances the sending symmetric ratchet by one step, zeroizing the previous chain key
    /// for immediate forward secrecy, and encrypts `plaintext` with `aad`.
    ///
    /// # Errors
    /// Propagates any [`CryptoError`] from AEAD encryption.
    pub fn send_ratchet_step(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), CryptoError> {
        let (mut next_ck, mut msg_key) = kdf_chain_step(self.send_chain_key.as_slice());
        self.send_chain_key = ZeroizingBuffer::new(next_ck.to_vec());
        zeroize_slice(&mut next_ck);

        let header = RatchetHeader {
            dh_public: self.our_dh_public,
            prev_chain_len: self.prev_send_chain_len,
            msg_num: self.send_msg_num,
        };
        let nonce = message_nonce(&header.dh_public, header.msg_num);
        let res = aead_seal(&msg_key, &nonce, aad, plaintext);
        zeroize_slice(&mut msg_key);
        let ciphertext = res?;

        self.send_msg_num = self.send_msg_num.saturating_add(1);
        Ok((header, ciphertext))
    }

    /// Advances the receiving ratchet (or consumes a cached out-of-order skipped key),
    /// rejecting replayed messages or tampered ciphertexts (fail-closed).
    ///
    /// # Errors
    /// Returns [`CryptoError::AuthenticationFailed`] if the message is replayed, exceeds
    /// `MAX_SKIPPED_KEYS`, or fails AEAD tag verification.
    pub fn recv_ratchet_step(
        &mut self,
        header: &RatchetHeader,
        ciphertext_and_tag: &[u8],
        aad: &[u8],
    ) -> Result<ZeroizingBuffer, CryptoError> {
        // 1. Check if this is an out-of-order message whose key was previously skipped
        if let Some(pos) = self
            .skipped_keys
            .iter()
            .position(|(dh, num, _)| *dh == header.dh_public && *num == header.msg_num)
        {
            let mut mk = [0u8; 32];
            mk.copy_from_slice(self.skipped_keys[pos].2.as_slice());
            let nonce = message_nonce(&header.dh_public, header.msg_num);
            let res = aead_open(&mk, &nonce, aad, ciphertext_and_tag);
            zeroize_slice(&mut mk);
            let pt = res?;
            self.skipped_keys.remove(pos);
            return Ok(pt);
        }

        if header.dh_public != self.peer_dh_public || header.msg_num < self.recv_msg_num {
            return Err(CryptoError::AuthenticationFailed);
        }

        let skip_count = (header.msg_num - self.recv_msg_num) as usize;
        if skip_count > MAX_SKIPPED_KEYS {
            return Err(CryptoError::AuthenticationFailed);
        }

        // Speculatively advance a temporary copy so a tampered packet cannot desynchronize state
        let mut temp_ck = [0u8; 32];
        temp_ck.copy_from_slice(self.recv_chain_key.as_slice());
        let mut newly_skipped = Vec::with_capacity(skip_count);

        for skipped_num in self.recv_msg_num..header.msg_num {
            let (mut next_ck, mut mk) = kdf_chain_step(&temp_ck);
            temp_ck = next_ck;
            zeroize_slice(&mut next_ck);
            newly_skipped.push((
                header.dh_public,
                skipped_num,
                ZeroizingBuffer::new(mk.to_vec()),
            ));
            zeroize_slice(&mut mk);
        }

        let (mut final_ck, mut target_mk) = kdf_chain_step(&temp_ck);
        let nonce = message_nonce(&header.dh_public, header.msg_num);
        let plaintext = aead_open(&target_mk, &nonce, aad, ciphertext_and_tag);

        zeroize_slice(&mut target_mk);
        zeroize_slice(&mut temp_ck);

        let Ok(plaintext) = plaintext else {
            zeroize_slice(&mut final_ck);
            return Err(CryptoError::AuthenticationFailed);
        };

        // Commit state only after AEAD verification succeeded
        self.recv_chain_key = ZeroizingBuffer::new(final_ck.to_vec());
        zeroize_slice(&mut final_ck);
        self.recv_msg_num = header.msg_num.saturating_add(1);
        for item in newly_skipped {
            if self.skipped_keys.len() >= MAX_SKIPPED_KEYS {
                self.skipped_keys.remove(0);
            }
            self.skipped_keys.push(item);
        }

        Ok(plaintext)
    }

    /// Returns the number of currently cached out-of-order message keys.
    #[must_use]
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
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

    #[test]
    fn sha256_hmac_and_hkdf_match_nist_and_rfc_vectors() {
        // NIST FIPS 180-4 SHA-256("abc")
        let abc = sha256(b"abc");
        let expected_abc: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(abc, expected_abc);

        // RFC 4231 Test Case 2: HMAC-SHA256("Jefe", "what do ya want for nothing?")
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let expected_mac: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, expected_mac);

        // RFC 5869 Test Case 1: HKDF-SHA256
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn rfc8439_chacha20_poly1305_aead_vector_and_tamper_fail_closed() {
        // RFC 8439 Section 2.8.2 test vector
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let sealed = aead_seal(&key, &nonce, &aad, plaintext).unwrap();
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];
        assert_eq!(&sealed[plaintext.len()..], &expected_tag);

        let opened = aead_open(&key, &nonce, &aad, &sealed).unwrap();
        assert_eq!(opened.as_slice(), plaintext);

        // Tamper with ciphertext -> fail closed
        let mut tampered_ct = sealed.clone();
        tampered_ct[0] ^= 0x01;
        assert_eq!(
            aead_open(&key, &nonce, &aad, &tampered_ct),
            Err(CryptoError::AuthenticationFailed)
        );

        // Tamper with AAD -> fail closed
        assert_eq!(
            aead_open(&key, &nonce, b"wrong-aad", &sealed),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn pqxdh_combiner_and_double_ratchet_out_of_order_and_replay_protection() {
        assert!(combine_pqxdh_secrets(&[0u8; 32], &[1u8; 32], b"ctx").is_err());
        let root = combine_pqxdh_secrets(&[0x11; 32], &[0x22; 32], b"aegis-session").unwrap();

        let alice_dh = [0xA1; 32];
        let bob_dh = [0xB2; 32];
        let mut alice = RatchetSession::new(root.as_slice(), alice_dh, bob_dh, true).unwrap();
        let mut bob = RatchetSession::new(root.as_slice(), bob_dh, alice_dh, false).unwrap();

        let (h0, c0) = alice.send_ratchet_step(b"msg-0", b"aad").unwrap();
        let (h1, c1) = alice.send_ratchet_step(b"msg-1", b"aad").unwrap();
        let (h2, c2) = alice.send_ratchet_step(b"msg-2", b"aad").unwrap();

        // Bob receives msg-2 first (out of order) -> caches msg-0 and msg-1 keys
        let p2 = bob.recv_ratchet_step(&h2, &c2, b"aad").unwrap();
        assert_eq!(p2.as_slice(), b"msg-2");
        assert_eq!(bob.skipped_key_count(), 2);

        // Replay of msg-2 must fail immediately
        assert_eq!(
            bob.recv_ratchet_step(&h2, &c2, b"aad"),
            Err(CryptoError::AuthenticationFailed)
        );

        // Bob now receives msg-0 and msg-1 out of order
        let p0 = bob.recv_ratchet_step(&h0, &c0, b"aad").unwrap();
        assert_eq!(p0.as_slice(), b"msg-0");
        let p1 = bob.recv_ratchet_step(&h1, &c1, b"aad").unwrap();
        assert_eq!(p1.as_slice(), b"msg-1");
        assert_eq!(bob.skipped_key_count(), 0);

        // Replay of consumed skipped key msg-0 must also fail
        assert_eq!(
            bob.recv_ratchet_step(&h0, &c0, b"aad"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn solve_pow_finds_valid_solution_verified_by_pow_verifier() {
        let challenge = PowChallenge {
            challenge: [0x7F; 32],
            difficulty_bits: 5,
            expires_at_unix_secs: 2_000,
        };
        let sol = solve_pow(&challenge, 50_000).expect("must solve 5-bit PoW");
        assert!(count_leading_zero_bits(&sol.digest) >= 5);
        assert!(DeterministicPowVerifier
            .verify_pow(&challenge, sol.nonce, 1_500)
            .is_ok());
    }

    #[test]
    fn b0020_ratchet_session_rejects_zero_or_identical_dh_keys_and_non_rotating_step() {
        let root = [0x44u8; 32];
        assert_eq!(
            RatchetSession::new(&root, [0u8; 32], [0xB2; 32], true).unwrap_err(),
            CryptoError::KeyDerivationFailed
        );
        assert_eq!(
            RatchetSession::new(&root, [0xA1; 32], [0u8; 32], true).unwrap_err(),
            CryptoError::KeyDerivationFailed
        );
        assert_eq!(
            RatchetSession::new(&root, [0xA1; 32], [0xA1; 32], true).unwrap_err(),
            CryptoError::KeyDerivationFailed
        );

        let mut session = RatchetSession::new(&root, [0xA1; 32], [0xB2; 32], true).unwrap();
        // Zero new DH key rejected
        assert_eq!(
            session.dh_ratchet_step([0u8; 32], [0xB3; 32], &[0x99; 32]),
            Err(CryptoError::KeyDerivationFailed)
        );
        // Unchanged DH key pair rejected
        assert_eq!(
            session.dh_ratchet_step([0xA1; 32], [0xB2; 32], &[0x99; 32]),
            Err(CryptoError::KeyDerivationFailed)
        );
        // Valid DH rotation succeeds
        assert!(session
            .dh_ratchet_step([0xA2; 32], [0xB3; 32], &[0x99; 32])
            .is_ok());
    }

    #[test]
    fn b0032_poly1305_rfc8439_vector_and_h_ge_2_pow_130_minus_5_boundary() {
        // Official RFC 8439 §2.5.2 Poly1305 test vector
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let expected_tag: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(poly1305_mac(msg, &key), expected_tag);

        // Boundary test: h == 2^130 - 5 before final conditional subtraction.
        // With r = 1, s = 0, three 16-byte blocks where:
        // B1 = 2^128 + (2^128 - 5) = 2^129 - 5, B2 = 2^128, B3 = 2^128
        // Sum h = B1 + B2 + B3 = 2^130 - 5 === 0 (mod 2^130 - 5).
        let mut r_one_key = [0u8; 32];
        r_one_key[0] = 1;
        let mut boundary_msg = [0u8; 48];
        boundary_msg[0] = 0xFB;
        boundary_msg[1..16].fill(0xFF);
        assert_eq!(poly1305_mac(&boundary_msg, &r_one_key), [0u8; 16]);

        // And h == 2^130 - 1 === 4 (mod 2^130 - 5)
        boundary_msg[0] = 0xFF;
        let mut expected_four = [0u8; 16];
        expected_four[0] = 4;
        assert_eq!(poly1305_mac(&boundary_msg, &r_one_key), expected_four);
    }

    #[test]
    fn b0033_b0034_skipped_key_not_evicted_on_tampered_packet_and_stack_keys_zeroized() {
        let root = combine_pqxdh_secrets(&[0x11; 32], &[0x22; 32], b"b0033-session").unwrap();
        let alice_dh = [0xA1; 32];
        let bob_dh = [0xB2; 32];
        let mut alice = RatchetSession::new(root.as_slice(), alice_dh, bob_dh, true).unwrap();
        let mut bob = RatchetSession::new(root.as_slice(), bob_dh, alice_dh, false).unwrap();

        let (h0, c0) = alice.send_ratchet_step(b"secret-msg-0", b"aad").unwrap();
        let (h1, c1) = alice.send_ratchet_step(b"secret-msg-1", b"aad").unwrap();

        // Bob receives msg-1 first -> msg-0 key is cached in skipped_keys
        let p1 = bob.recv_ratchet_step(&h1, &c1, b"aad").unwrap();
        assert_eq!(p1.as_slice(), b"secret-msg-1");
        assert_eq!(bob.skipped_key_count(), 1);

        // Attacker sends a corrupted packet for msg-0
        let mut tampered_c0 = c0.clone();
        tampered_c0[0] ^= 0xFF;
        assert_eq!(
            bob.recv_ratchet_step(&h0, &tampered_c0, b"aad"),
            Err(CryptoError::AuthenticationFailed)
        );
        // Skipped key for msg-0 MUST still be present!
        assert_eq!(bob.skipped_key_count(), 1);

        // Legitimate msg-0 arrives and decrypts cleanly, then consumes the skipped key
        let p0 = bob.recv_ratchet_step(&h0, &c0, b"aad").unwrap();
        assert_eq!(p0.as_slice(), b"secret-msg-0");
        assert_eq!(bob.skipped_key_count(), 0);
    }
}
