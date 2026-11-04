//! Account keys, usernames and safety numbers.

use crate::{sha256, Error, Result};
use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Lowercases and validates a username (`^[a-z0-9_]{3,24}$`).
pub fn normalize_username(u: &str) -> Result<String> {
    let l = u.to_ascii_lowercase();
    if is_valid_username(&l) {
        Ok(l)
    } else {
        Err(Error::InvalidUsername)
    }
}

/// True if `u` is already a valid, lowercase username.
pub fn is_valid_username(u: &str) -> bool {
    (3..=24).contains(&u.len())
        && u.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// X25519 public key for a secret.
pub fn x25519_public(sk: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*sk)).to_bytes()
}

/// Ed25519 public key for a secret.
pub fn ed25519_public(sk: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(sk).verifying_key().to_bytes()
}

/// Ed25519 signature (deterministic).
pub fn ed25519_sign(sk: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(sk).sign(msg).to_bytes()
}

/// Strict Ed25519 verification.
pub fn ed25519_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk) else {
        return false;
    };
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
        .is_ok()
}

/// X25519 with the all-zero result rejected.
pub fn dh(sk: &[u8; 32], pk: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let ss = StaticSecret::from(*sk).diffie_hellman(&PublicKey::from(*pk));
    if !ss.was_contributory() {
        return Err(Error::ZeroSharedSecret);
    }
    Ok(Zeroizing::new(ss.to_bytes()))
}

/// The two secret keys of an account.
pub struct Identity {
    x_sk: Zeroizing<[u8; 32]>,
    ed_sk: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Identity(..)")
    }
}

impl Identity {
    /// New random keys from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_secrets(
            crate::random_bytes::<32>()?,
            crate::random_bytes::<32>()?,
        ))
    }

    pub fn from_secrets(x_sk: [u8; 32], ed_sk: [u8; 32]) -> Self {
        Self {
            x_sk: Zeroizing::new(x_sk),
            ed_sk: Zeroizing::new(ed_sk),
        }
    }

    pub fn x_secret(&self) -> &[u8; 32] {
        &self.x_sk
    }

    pub fn ed_secret(&self) -> &[u8; 32] {
        &self.ed_sk
    }

    pub fn x_public(&self) -> [u8; 32] {
        x25519_public(&self.x_sk)
    }

    pub fn ed_public(&self) -> [u8; 32] {
        ed25519_public(&self.ed_sk)
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        ed25519_sign(&self.ed_sk, msg)
    }
}

/// Safety number for two users, each given as `(ed_pk, x_pk)`. Six groups of five digits.
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn safety_number(a: (&[u8; 32], &[u8; 32]), b: (&[u8; 32], &[u8; 32])) -> String {
    let mut ka = [0u8; 64];
    ka[..32].copy_from_slice(a.0);
    ka[32..].copy_from_slice(a.1);
    let mut kb = [0u8; 64];
    kb[..32].copy_from_slice(b.0);
    kb[32..].copy_from_slice(b.1);
    let (lo, hi) = if ka <= kb { (ka, kb) } else { (kb, ka) };
    let h = sha256(&[b"aegis-v2 safety", &lo, &hi]);
    h[..30]
        .chunks_exact(5)
        .map(|c| {
            let v = c.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
            format!("{:05}", v % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        assert_eq!(normalize_username("Alice_01").unwrap(), "alice_01");
        for bad in ["ab", "a b", "alice!", &"a".repeat(25), "алиса", ""] {
            assert!(normalize_username(bad).is_err(), "{bad}");
        }
        assert!(!is_valid_username("Alice"));
    }

    #[test]
    fn safety_number_symmetric() {
        let a = Identity::from_secrets([1; 32], [2; 32]);
        let b = Identity::from_secrets([3; 32], [4; 32]);
        let n1 = safety_number((&a.ed_public(), &a.x_public()), (&b.ed_public(), &b.x_public()));
        let n2 = safety_number((&b.ed_public(), &b.x_public()), (&a.ed_public(), &a.x_public()));
        assert_eq!(n1, n2);
        assert_eq!(n1.split(' ').count(), 6);
        assert!(n1.split(' ').all(|g| g.len() == 5));
        let c = Identity::from_secrets([5; 32], [4; 32]);
        let n3 = safety_number((&a.ed_public(), &a.x_public()), (&c.ed_public(), &c.x_public()));
        assert_ne!(n1, n3);
    }

    #[test]
    fn zero_dh_rejected() {
        assert_eq!(dh(&[7; 32], &[0; 32]).unwrap_err(), Error::ZeroSharedSecret);
        assert!(dh(&[7; 32], &x25519_public(&[9; 32])).is_ok());
    }

    #[test]
    fn sign_verify() {
        let id = Identity::generate().unwrap();
        let sig = id.sign(b"m");
        assert!(ed25519_verify(&id.ed_public(), b"m", &sig));
        assert!(!ed25519_verify(&id.ed_public(), b"n", &sig));
        assert!(!format!("{id:?}").contains('['));
    }
}
