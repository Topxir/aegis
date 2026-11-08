//! Signed application updates (spec section 29).
//!
//! The owner signs a small JSON manifest with an offline Ed25519 key. The signed file is the
//! 64-byte signature followed by the manifest bytes exactly as signed; clients verify before they
//! parse anything. Files are fetched in chunks over the same route as all other traffic.

use crate::identity::{ed25519_public, ed25519_sign, ed25519_verify};
use crate::net::Client;
use crate::{hex, Error, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;

/// The only key clients accept update manifests from. The secret half stays offline with the owner.
pub const TRUSTED_KEY_HEX: &str = "d0477ef7f2cd4618395408fc518c8691ff528ea290514dd50822cebbc41d6761";

/// `TRUSTED_KEY_HEX` as bytes.
pub fn trusted_key() -> Result<[u8; 32]> {
    hex::decode_array(TRUSTED_KEY_HEX)
}

/// Domain separation for the manifest signature.
pub const SIG_CONTEXT: &[u8] = b"aegis-update-v1\n";
/// Largest signed manifest a client or the server accepts.
pub const MAX_MANIFEST: usize = 64 * 1024;
/// Largest file a manifest may point at.
pub const MAX_FILE: u64 = 512 * 1024 * 1024;
/// Bytes per `update/file` reply.
pub const CHUNK: usize = 1 << 20;
/// Manifest format version.
pub const FORMAT: u64 = 1;
/// Platform keys in `files`.
pub const WINDOWS: &str = "windows-x86_64";
pub const ANDROID: &str = "android";

fn bad(why: &'static str) -> Error {
    Error::Update(why)
}

/// One downloadable build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub size: u64,
    pub sha256: [u8; 32],
    /// Version of this build, dotted numbers.
    pub version: String,
    /// Oldest version the server still supports for this platform.
    pub min: String,
    /// Android `versionCode`; 0 elsewhere.
    pub code: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Grows with every published manifest; clients never accept a lower one.
    pub seq: u64,
    /// Release name shown to the user.
    pub version: String,
    pub files: BTreeMap<String, Artifact>,
}

/// A file name the server serves and a client accepts: no separators, no leading dot.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 96
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// `major.minor.patch` (more or fewer parts allowed); anything after `-` or `+` is ignored.
pub fn parse_version(v: &str) -> Option<Vec<u64>> {
    let core = v.split(['-', '+']).next()?;
    if core.is_empty() || core.len() > 32 {
        return None;
    }
    core.split('.')
        .map(|p| {
            if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                p.parse().ok()
            }
        })
        .collect()
}

/// Compares two versions; missing parts count as zero. `None` if either does not parse.
pub fn compare_versions(a: &str, b: &str) -> Option<core::cmp::Ordering> {
    let (mut a, mut b) = (parse_version(a)?, parse_version(b)?);
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    Some(a.cmp(&b))
}

/// Public key for a 32-byte signing seed.
pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    ed25519_public(sk)
}

/// The signed file for `manifest`: signature, then the manifest bytes.
pub fn sign(sk: &[u8; 32], manifest: &[u8]) -> Vec<u8> {
    let sig = ed25519_sign(sk, &[SIG_CONTEXT, manifest].concat());
    [sig.as_slice(), manifest].concat()
}

/// Checks the signature with `pk` and only then parses the manifest.
pub fn open(signed: &[u8], pk: &[u8; 32]) -> Result<Manifest> {
    if signed.len() <= 64 || signed.len() > MAX_MANIFEST {
        return Err(bad("manifest size"));
    }
    let (sig, body) = signed.split_at(64);
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    if !ed25519_verify(pk, &[SIG_CONTEXT, body].concat(), &s) {
        return Err(Error::BadSignature);
    }
    parse(body)
}

fn parse(body: &[u8]) -> Result<Manifest> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| bad("manifest json"))?;
    if v["v"].as_u64() != Some(FORMAT) {
        return Err(bad("manifest format"));
    }
    let seq = v["seq"].as_u64().ok_or(bad("manifest seq"))?;
    let version = v["version"].as_str().ok_or(bad("manifest version"))?.to_owned();
    let mut files = BTreeMap::new();
    for (k, f) in v["files"].as_object().ok_or(bad("manifest files"))? {
        let s = |key: &str| f[key].as_str().ok_or(bad("manifest entry"));
        let name = s("name")?.to_owned();
        let size = f["size"].as_u64().ok_or(bad("manifest entry"))?;
        let version = s("version")?.to_owned();
        let min = s("min")?.to_owned();
        if !valid_name(&name) {
            return Err(bad("file name"));
        }
        if size == 0 || size > MAX_FILE {
            return Err(bad("file size"));
        }
        if parse_version(&version).is_none() || parse_version(&min).is_none() {
            return Err(bad("manifest version"));
        }
        let sha256 = hex::decode_array(s("sha256")?).map_err(|_| bad("manifest entry"))?;
        let code = f["code"].as_u64().unwrap_or(0);
        files.insert(k.clone(), Artifact { name, size, sha256, version, min, code });
    }
    Ok(Manifest { seq, version, files })
}

/// What a verified manifest means for a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offer {
    /// Nothing newer for this platform.
    Current,
    /// A newer build; `required` when the running version is below the supported minimum.
    Newer { artifact: Artifact, required: bool },
}

/// Decides on a verified manifest. `last_seq` is the highest sequence this client has accepted;
/// a lower one is an old manifest being replayed and is an error. `current` is the running
/// version, `code` the running Android `versionCode` (0 elsewhere, then versions decide).
pub fn evaluate(m: &Manifest, platform: &str, current: &str, code: u64, last_seq: u64) -> Result<Offer> {
    if m.seq < last_seq {
        return Err(bad("manifest rollback"));
    }
    let Some(a) = m.files.get(platform) else {
        return Ok(Offer::Current);
    };
    let newer = if code > 0 {
        a.code > code
    } else {
        compare_versions(&a.version, current) == Some(core::cmp::Ordering::Greater)
    };
    if !newer {
        return Ok(Offer::Current);
    }
    let required = compare_versions(current, &a.min) == Some(core::cmp::Ordering::Less);
    Ok(Offer::Newer { artifact: a.clone(), required })
}

/// Manifest bytes for a release: deterministic key order, no whitespace.
pub fn manifest_json(seq: u64, version: &str, files: &BTreeMap<String, Artifact>) -> String {
    let mut map = serde_json::Map::new();
    for (k, a) in files {
        let mut e = serde_json::Map::new();
        e.insert("name".into(), a.name.clone().into());
        e.insert("size".into(), a.size.into());
        e.insert("sha256".into(), hex::encode(&a.sha256).into());
        e.insert("version".into(), a.version.clone().into());
        e.insert("min".into(), a.min.clone().into());
        if a.code > 0 {
            e.insert("code".into(), a.code.into());
        }
        map.insert(k.clone(), e.into());
    }
    serde_json::json!({"v": FORMAT, "seq": seq, "version": version, "files": map}).to_string()
}

/// Streams `a` into `out` chunk by chunk and checks the size and the hash. A server that sends
/// more than the manifest says, or different bytes, fails the download.
pub fn download(client: &Client, a: &Artifact, out: &mut impl Write) -> Result<()> {
    download_with(a, out, |off| client.update_chunk(&a.name, off))
}

/// `download` with the chunk source given as a function, for tests.
pub fn download_with(
    a: &Artifact,
    out: &mut impl Write,
    mut chunk: impl FnMut(u64) -> Result<Vec<u8>>,
) -> Result<()> {
    if a.size == 0 || a.size > MAX_FILE || !valid_name(&a.name) {
        return Err(bad("file size"));
    }
    let mut h = Sha256::new();
    let mut off = 0u64;
    while off < a.size {
        let part = chunk(off)?;
        let n = part.len() as u64;
        if part.is_empty() || part.len() > CHUNK || off + n > a.size {
            return Err(bad("file size"));
        }
        h.update(&part);
        out.write_all(&part)?;
        off += n;
    }
    let got: [u8; 32] = h.finalize().into();
    if got != a.sha256 {
        return Err(bad("file hash"));
    }
    out.flush()?;
    Ok(())
}

/// SHA-256 and length of a reader, for the release tool and for checking a staged file.
pub fn hash_reader(r: &mut impl std::io::Read) -> Result<([u8; 32], u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        len += n as u64;
    }
    Ok((h.finalize().into(), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(version: &str, code: u64) -> Artifact {
        Artifact {
            name: "aegis.exe".into(),
            size: 3,
            sha256: crate::sha256(&[b"abc"]),
            version: version.into(),
            min: "0.1.0".into(),
            code,
        }
    }

    #[test]
    fn trusted_key_is_a_valid_point() {
        let pk = trusted_key().unwrap();
        let m = manifest_json(1, "0.1.0", &BTreeMap::new());
        let signed = sign(&[1u8; 32], m.as_bytes());
        assert_eq!(open(&signed, &pk), Err(Error::BadSignature));
    }

    #[test]
    fn versions_compare_numerically() {
        use core::cmp::Ordering::*;
        assert_eq!(compare_versions("0.10.0", "0.9.9"), Some(Greater));
        assert_eq!(compare_versions("0.2.0-alpha", "0.2"), Some(Equal));
        assert_eq!(compare_versions("1.0.0", "1.0.1"), Some(Less));
        assert_eq!(compare_versions("1.x", "1.0"), None);
        assert_eq!(compare_versions("", "1.0"), None);
    }

    #[test]
    fn names_are_plain() {
        assert!(valid_name("aegis-desktop-0.2.0.exe"));
        for n in ["", ".hidden", "../x", "a/b", "a\\b", "a..b", "c:x", "a b"] {
            assert!(!valid_name(n), "{n}");
        }
    }

    #[test]
    fn manifest_round_trips() {
        let sk = [3u8; 32];
        let mut files = BTreeMap::new();
        files.insert(WINDOWS.to_owned(), art("0.2.0", 0));
        let body = manifest_json(7, "0.2.0", &files);
        let m = open(&sign(&sk, body.as_bytes()), &public_key(&sk)).unwrap();
        assert_eq!(m.seq, 7);
        assert_eq!(m.files[WINDOWS], art("0.2.0", 0));
    }

    #[test]
    fn evaluate_offers_only_newer() {
        let mut files = BTreeMap::new();
        files.insert(WINDOWS.to_owned(), art("0.2.0", 0));
        files.insert(ANDROID.to_owned(), art("0.3.0", 4));
        let m = Manifest { seq: 5, version: "0.2.0".into(), files };
        assert!(matches!(evaluate(&m, WINDOWS, "0.1.0", 0, 5), Ok(Offer::Newer { .. })));
        assert_eq!(evaluate(&m, WINDOWS, "0.2.0", 0, 0), Ok(Offer::Current));
        assert_eq!(evaluate(&m, "linux", "0.1.0", 0, 0), Ok(Offer::Current));
        assert!(matches!(evaluate(&m, ANDROID, "0.2.0", 3, 0), Ok(Offer::Newer { required: false, .. })));
        assert_eq!(evaluate(&m, ANDROID, "0.9.0", 4, 0), Ok(Offer::Current));
        assert!(matches!(
            evaluate(&m, WINDOWS, "0.0.9", 0, 0),
            Ok(Offer::Newer { required: true, .. })
        ));
    }
}
