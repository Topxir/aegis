//! Encrypted local storage file (spec section 9).

use crate::seal::{aead_open, aead_seal};
use crate::{arr, hex, sha256, Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use std::path::Path;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"AGV2";
/// Bytes covered as AEAD associated data: magic, three parameters, salt.
const AAD_LEN: usize = 32;
const HEADER_LEN: usize = AAD_LEN + 12;
const MAX_M_KIB: u32 = 1 << 18;
const MAX_T: u32 = 16;
const MAX_P: u32 = 16;

/// Argon2id cost parameters stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl VaultParams {
    pub const DESKTOP: Self = Self { m_kib: 65536, t: 2, p: 1 };
    pub const ANDROID: Self = Self { m_kib: 19456, t: 2, p: 1 };

    fn validate(self) -> Result<()> {
        let ok = (1..=MAX_P).contains(&self.p)
            && (1..=MAX_T).contains(&self.t)
            && (8 * self.p..=MAX_M_KIB).contains(&self.m_kib);
        if ok {
            Ok(())
        } else {
            Err(Error::VaultParams)
        }
    }
}

fn derive_key(password: &str, salt: &[u8; 16], params: VaultParams) -> Result<Zeroizing<[u8; 32]>> {
    params.validate()?;
    let p = Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| Error::VaultParams)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Kdf)?;
    Ok(key)
}

/// Encrypts `data` with a fresh random salt and nonce.
pub fn vault_encrypt(password: &str, params: VaultParams, data: &[u8]) -> Result<Vec<u8>> {
    vault_encrypt_with(
        password,
        params,
        &crate::random_bytes::<16>()?,
        &crate::random_bytes::<12>()?,
        data,
    )
}

/// Deterministic variant of [`vault_encrypt`] with injected salt and nonce.
pub fn vault_encrypt_with(
    password: &str,
    params: VaultParams,
    salt: &[u8; 16],
    nonce: &[u8; 12],
    data: &[u8],
) -> Result<Vec<u8>> {
    let key = derive_key(password, salt, params)?;
    let mut out = Vec::with_capacity(HEADER_LEN + data.len() + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&params.m_kib.to_be_bytes());
    out.extend_from_slice(&params.t.to_be_bytes());
    out.extend_from_slice(&params.p.to_be_bytes());
    out.extend_from_slice(salt);
    let ct = aead_seal(&key, nonce, &out, data)?;
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts a vault file. A wrong password and a damaged file are indistinguishable.
pub fn vault_decrypt(password: &str, file: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if file.len() < HEADER_LEN + 16 || &file[..4] != MAGIC {
        return Err(Error::VaultFormat);
    }
    let be = |i: usize| -> Result<u32> { Ok(u32::from_be_bytes(arr(&file[i..i + 4])?)) };
    let params = VaultParams {
        m_kib: be(4)?,
        t: be(8)?,
        p: be(12)?,
    };
    let salt: [u8; 16] = arr(&file[16..32])?;
    let nonce: [u8; 12] = arr(&file[AAD_LEN..HEADER_LEN])?;
    let key = derive_key(password, &salt, params)?;
    aead_open(&key, &nonce, &file[..AAD_LEN], &file[HEADER_LEN..])
        .map(Zeroizing::new)
        .map_err(|_| Error::VaultDecrypt)
}

/// File name for an account: first 32 hex chars of
/// `SHA256("aegis-v2 vault-name\n" || username)` plus `.vault`.
pub fn vault_file_name(username: &str) -> String {
    let h = sha256(&[b"aegis-v2 vault-name\n", username.as_bytes()]);
    format!("{}.vault", &hex::encode(&h)[..32])
}

/// Writes `bytes` to a uniquely named temporary sibling (owner-only permissions on unix), syncs
/// it and renames it over `path`. Concurrent writers never share a temporary file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut tmp_name = path
        .file_name()
        .ok_or(Error::Io("path has no file name".into()))?
        .to_os_string();
    tmp_name.push(format!(".{}.tmp", hex::encode(&crate::random_bytes::<8>()?)));
    let tmp = path.with_file_name(tmp_name);
    let res = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res.map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: VaultParams = VaultParams { m_kib: 256, t: 1, p: 1 };

    #[test]
    fn roundtrip_and_wrong_password() {
        let f = vault_encrypt("correct horse", FAST, b"secret data").unwrap();
        assert_eq!(&**vault_decrypt("correct horse", &f).unwrap(), b"secret data");
        assert_eq!(vault_decrypt("wrong horse!", &f).unwrap_err(), Error::VaultDecrypt);
        let g = vault_encrypt("correct horse", FAST, b"secret data").unwrap();
        assert_ne!(f, g);
    }

    #[test]
    fn any_flipped_byte_rejected() {
        let f = vault_encrypt_with("pw-pw-pw-pw", FAST, &[1; 16], &[2; 12], b"x").unwrap();
        for i in 0..f.len() {
            let mut t = f.clone();
            t[i] ^= 1;
            assert!(vault_decrypt("pw-pw-pw-pw", &t).is_err(), "byte {i}");
        }
        assert!(vault_decrypt("pw-pw-pw-pw", &f[..f.len() - 1]).is_err());
        assert_eq!(vault_decrypt("pw-pw-pw-pw", b"short").unwrap_err(), Error::VaultFormat);
    }

    #[test]
    fn hostile_params_refused() {
        let mut f = vault_encrypt_with("pw-pw-pw-pw", FAST, &[1; 16], &[2; 12], b"x").unwrap();
        f[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(vault_decrypt("pw-pw-pw-pw", &f).unwrap_err(), Error::VaultParams);
        assert!(vault_encrypt("pw", VaultParams { m_kib: 1, t: 1, p: 1 }, b"").is_err());
    }

    #[test]
    fn layout_and_name() {
        let f = vault_encrypt_with("pw-pw-pw-pw", FAST, &[1; 16], &[2; 12], b"abc").unwrap();
        assert_eq!(&f[..4], b"AGV2");
        assert_eq!(f[4..8], 256u32.to_be_bytes());
        assert_eq!(f[16..32], [1; 16]);
        assert_eq!(f[32..44], [2; 12]);
        assert_eq!(f.len(), 44 + 3 + 16);
        let n = vault_file_name("alice");
        assert_eq!(n.len(), 32 + 6);
        assert!(n.ends_with(".vault"));
    }

    #[test]
    fn atomic_write_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("aegis-core-vault-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.vault");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert!(!dir.join("a.vault.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_atomic_writes_do_not_collide() {
        let dir = std::env::temp_dir().join(format!("aegis-core-vault-conc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("s.bin");
        let hs: Vec<_> = (0..8u8)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || {
                    for _ in 0..40 {
                        write_atomic(&p, &[i; 64]).unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let got = std::fs::read(&p).unwrap();
        assert!(got.len() == 64 && got.iter().all(|b| *b == got[0]));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
