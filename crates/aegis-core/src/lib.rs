//! Aegis protocol v2 core: the single implementation of `docs/PROTOCOL.md`.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod attach;
pub mod avatar;
pub mod channel;
pub mod cover;
pub mod directory;
pub mod envelope;
mod error;
pub mod group;
pub mod hex;
pub mod identity;
pub mod mp4clean;
pub mod net;
pub mod official;
pub mod pad;
pub mod pin;
pub mod pow;
pub mod prekeys;
pub mod profile;
pub mod queue_ids;
pub mod ratchet;
pub mod seal;
pub mod sealed;
pub mod senderkey;
pub mod session;
pub mod text;
pub mod vault;
pub mod vectors;
pub mod x3dh;

pub use error::{Error, Result};

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// SHA-256 of the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HKDF-SHA256 to 32 bytes. An empty `salt` means no salt.
pub(crate) fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut()).map_err(|_| Error::Kdf)?;
    Ok(out)
}

pub(crate) fn arr<const N: usize>(b: &[u8]) -> Result<[u8; N]> {
    <[u8; N]>::try_from(b).map_err(|_| Error::Length)
}

/// Current unix time in seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fills a fixed array from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; N];
    OsRng.try_fill_bytes(&mut b).map_err(|_| Error::Rng)?;
    Ok(b)
}
