//! PIN unlock, client side (spec sections 20 and 25).
//!
//! The server holds `S`; the device holds the pin file. Neither alone can open the vault key.

use crate::seal::{aead_open, aead_seal};
use crate::{arr, hex, hkdf32, Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"AGP1";
const DURESS_MAGIC: &[u8; 4] = b"AGD1";
/// `"AGP1" || salt || slot || nonce || AEAD(vault_key)`.
pub const PIN_FILE_LEN: usize = 4 + 16 + 32 + 12 + 32 + 16;
pub const DURESS_FILE_LEN: usize = 4 + 16 + 32 + 32;

/// Argon2id cost for the PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl PinParams {
    pub const DEFAULT: Self = Self { m_kib: 19456, t: 2, p: 1 };
}

/// True for exactly 4 or 6 ASCII digits.
pub fn is_valid_pin(pin: &str) -> bool {
    matches!(pin.len(), 4 | 6) && pin.bytes().all(|b| b.is_ascii_digit())
}

fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Key derived from the PIN and the stored salt: `T = Argon2id(pin, salt)`.
pub struct PinKey {
    t: Zeroizing<[u8; 32]>,
    slot: [u8; 32],
}

impl core::fmt::Debug for PinKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PinKey(..)")
    }
}

impl PinKey {
    pub fn derive(pin: &str, salt: &[u8; 16], slot: &[u8; 32]) -> Result<Self> {
        Self::derive_with(pin, salt, slot, PinParams::DEFAULT)
    }

    /// Explicit cost parameters (the test vectors use small ones).
    pub fn derive_with(pin: &str, salt: &[u8; 16], slot: &[u8; 32], params: PinParams) -> Result<Self> {
        if !is_valid_pin(pin) {
            return Err(Error::InvalidText);
        }
        let p = Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| Error::VaultParams)?;
        let mut t = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
            .hash_password_into(pin.as_bytes(), salt, t.as_mut())
            .map_err(|_| Error::Kdf)?;
        Ok(Self { t, slot: *slot })
    }

    pub fn t(&self) -> &[u8; 32] {
        &self.t
    }

    /// `HKDF(T, slot, "aegis-v2 pin-verify", 32)`, sent to the server as `v`.
    pub fn verifier(&self) -> Result<[u8; 32]> {
        Ok(*hkdf32(self.t.as_ref(), &self.slot, b"aegis-v2 pin-verify")?)
    }

    /// `HKDF(T || S, slot, "aegis-v2 pin-wrap", 32)`.
    pub fn wrap_key(&self, s: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let ikm = Zeroizing::new([self.t.as_slice(), s.as_slice()].concat());
        hkdf32(&ikm, &self.slot, b"aegis-v2 pin-wrap")
    }
}

/// The local pin file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinFile {
    pub salt: [u8; 16],
    pub slot: [u8; 32],
    pub nonce: [u8; 12],
    ct: Vec<u8>,
}

/// Everything produced by setting a PIN.
#[derive(Debug)]
pub struct PinSetup {
    pub file: PinFile,
    /// Verifier `v` for `pin/create`.
    pub verifier: [u8; 32],
    /// Server secret `S`; send it to the server, then drop it.
    pub s: Zeroizing<[u8; 32]>,
}

fn aad(salt: &[u8; 16], slot: &[u8; 32]) -> Vec<u8> {
    [MAGIC.as_slice(), salt, slot].concat()
}

impl PinFile {
    pub fn slot_hex(&self) -> String {
        hex::encode(&self.slot)
    }

    pub fn encode(&self) -> Vec<u8> {
        [MAGIC.as_slice(), &self.salt, &self.slot, &self.nonce, &self.ct].concat()
    }

    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != PIN_FILE_LEN || &b[..4] != MAGIC {
            return Err(Error::VaultFormat);
        }
        Ok(Self {
            salt: arr(&b[4..20])?,
            slot: arr(&b[20..52])?,
            nonce: arr(&b[52..64])?,
            ct: b[64..].to_vec(),
        })
    }

    /// Derives the key for a typed PIN (one Argon2 run); use it for both `verifier` and `unwrap`.
    pub fn derive(&self, pin: &str) -> Result<PinKey> {
        PinKey::derive(pin, &self.salt, &self.slot)
    }

    /// Recovers the vault key with the PIN key and the secret returned by the server.
    pub fn unwrap(&self, key: &PinKey, s: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let wrap = key.wrap_key(s)?;
        let pt = Zeroizing::new(aead_open(&wrap, &self.nonce, &aad(&self.salt, &self.slot), &self.ct)?);
        Ok(Zeroizing::new(arr(&pt)?))
    }
}

impl PinSetup {
    /// New PIN with fresh random salt, slot, `S` and nonce.
    pub fn new(pin: &str, vault_key: &[u8; 32]) -> Result<Self> {
        Self::new_with(
            pin,
            vault_key,
            PinParams::DEFAULT,
            &crate::random_bytes::<16>()?,
            &crate::random_bytes::<32>()?,
            &crate::random_bytes::<32>()?,
            &crate::random_bytes::<12>()?,
        )
    }

    /// Deterministic variant with injected randomness and cost parameters.
    pub fn new_with(
        pin: &str,
        vault_key: &[u8; 32],
        params: PinParams,
        salt: &[u8; 16],
        slot: &[u8; 32],
        s: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Self> {
        let key = PinKey::derive_with(pin, salt, slot, params)?;
        let wrap = key.wrap_key(s)?;
        let ct = aead_seal(&wrap, nonce, &aad(salt, slot), vault_key)?;
        Ok(Self {
            file: PinFile { salt: *salt, slot: *slot, nonce: *nonce, ct },
            verifier: key.verifier()?,
            s: Zeroizing::new(*s),
        })
    }
}

/// Body hash input for `pin/create`: `slot \n v \n s` as hex strings.
pub fn create_hash_input(slot_hex: &str, v_hex: &str, s_hex: &str) -> String {
    format!("{slot_hex}\n{v_hex}\n{s_hex}")
}

/// Body hash input for `pin/open` and `pin/delete`: `slot \n v` as hex strings.
pub fn open_hash_input(slot_hex: &str, v_hex: &str) -> String {
    format!("{slot_hex}\n{v_hex}")
}

/// Proof-of-work scope of the PIN endpoints.
pub fn pow_scope(slot_hex: &str) -> String {
    format!("pin:{slot_hex}")
}

/// Local record of the duress PIN. It has no server slot: the client checks it before
/// contacting the server, and a match means "wipe" (section 25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuressRecord {
    pub salt: [u8; 16],
    pub slot: [u8; 32],
    verifier: [u8; 32],
}

impl DuressRecord {
    pub fn new(pin: &str) -> Result<Self> {
        Self::new_with(pin, PinParams::DEFAULT, &crate::random_bytes::<16>()?, &crate::random_bytes::<32>()?)
    }

    pub fn new_with(pin: &str, params: PinParams, salt: &[u8; 16], slot: &[u8; 32]) -> Result<Self> {
        let key = PinKey::derive_with(pin, salt, slot, params)?;
        Ok(Self { salt: *salt, slot: *slot, verifier: key.verifier()? })
    }

    /// True when `pin` is the duress PIN. Also use it at setup to refuse a duress PIN equal to the real one.
    pub fn matches(&self, pin: &str) -> Result<bool> {
        self.matches_with(pin, PinParams::DEFAULT)
    }

    pub fn matches_with(&self, pin: &str, params: PinParams) -> Result<bool> {
        let key = PinKey::derive_with(pin, &self.salt, &self.slot, params)?;
        Ok(eq_ct(&key.verifier()?, &self.verifier))
    }

    pub fn encode(&self) -> Vec<u8> {
        [DURESS_MAGIC.as_slice(), &self.salt, &self.slot, &self.verifier].concat()
    }

    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != DURESS_FILE_LEN || &b[..4] != DURESS_MAGIC {
            return Err(Error::VaultFormat);
        }
        Ok(Self { salt: arr(&b[4..20])?, slot: arr(&b[20..52])?, verifier: arr(&b[52..84])? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: PinParams = PinParams { m_kib: 64, t: 1, p: 1 };

    fn setup(pin: &str) -> PinSetup {
        PinSetup::new_with(pin, &[9; 32], SMALL, &[1; 16], &[2; 32], &[3; 32], &[4; 12]).unwrap()
    }

    #[test]
    fn file_roundtrip_and_unwrap() {
        let st = setup("123456");
        let bytes = st.file.encode();
        assert_eq!(bytes.len(), PIN_FILE_LEN);
        assert_eq!(PinFile::parse(&bytes).unwrap(), st.file);
        let key = PinKey::derive_with("123456", &[1; 16], &[2; 32], SMALL).unwrap();
        assert_eq!(key.verifier().unwrap(), st.verifier);
        assert_eq!(*st.file.unwrap(&key, &[3; 32]).unwrap(), [9; 32]);
        assert!(st.file.unwrap(&key, &[4; 32]).is_err());
        let other = PinKey::derive_with("123457", &[1; 16], &[2; 32], SMALL).unwrap();
        assert_ne!(other.verifier().unwrap(), st.verifier);
        assert!(st.file.unwrap(&other, &[3; 32]).is_err());
    }

    #[test]
    fn parse_is_strict_and_tamper_fails() {
        let st = setup("1234");
        let b = st.file.encode();
        assert!(PinFile::parse(&b[..b.len() - 1]).is_err());
        assert!(PinFile::parse(&[b.as_slice(), &[0]].concat()).is_err());
        let mut bad = b.clone();
        bad[0] = b'X';
        assert!(PinFile::parse(&bad).is_err());
        let key = PinKey::derive_with("1234", &[1; 16], &[2; 32], SMALL).unwrap();
        for i in 20..b.len() {
            let mut t = b.clone();
            t[i] ^= 1;
            let f = PinFile::parse(&t).unwrap();
            assert!(f.unwrap(&key, &[3; 32]).is_err(), "byte {i}");
        }
    }

    #[test]
    fn pin_format_and_hash_inputs() {
        for bad in ["", "123", "12345", "1234567", "12a4", "\u{661}\u{662}\u{663}\u{664}", " 1234", "1234\n"] {
            assert!(!is_valid_pin(bad), "{bad:?}");
            assert!(PinKey::derive_with(bad, &[0; 16], &[0; 32], SMALL).is_err());
        }
        assert!(is_valid_pin("0000") && is_valid_pin("000000"));
        assert_eq!(create_hash_input("a", "b", "c"), "a\nb\nc");
        assert_eq!(open_hash_input("a", "b"), "a\nb");
        assert_eq!(pow_scope("ab"), "pin:ab");
    }

    #[test]
    fn duress_record() {
        let d = DuressRecord::new_with("9999", SMALL, &[5; 16], &[6; 32]).unwrap();
        assert!(d.matches_with("9999", SMALL).unwrap());
        assert!(!d.matches_with("9998", SMALL).unwrap());
        let b = d.encode();
        assert_eq!(b.len(), DURESS_FILE_LEN);
        assert_eq!(DuressRecord::parse(&b).unwrap(), d);
        assert!(DuressRecord::parse(&b[..83]).is_err());
        let mut bad = b;
        bad[1] = b'X';
        assert!(DuressRecord::parse(&bad).is_err());
    }
}
