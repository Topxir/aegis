//! Sealed transport (spec section 23): every API call wrapped in one AEAD envelope to the
//! server's long-term X25519 key, so a TLS terminator sees one path and bucketed sizes.

use crate::identity::{dh, x25519_public};
use crate::seal::{aead_open, aead_seal};
use crate::{arr, hkdf32, Error, Result};
use zeroize::Zeroizing;

/// Padding buckets of the sealed transport.
pub const BUCKETS: [usize; 7] = [1024, 4096, 16384, 65536, 262_144, 1_048_576, 1_114_112];
/// Largest accepted outer request: `e_pk` + largest bucket + AEAD tag.
pub const MAX_OUTER_BYTES: usize = 32 + 1_114_112 + 16;
const AAD_REQ: &[u8] = b"aegis-v2 sealed-req";
const AAD_RESP: &[u8] = b"aegis-v2 sealed-resp";

/// Smallest bucket that fits `BE32(len) || data`.
pub fn bucket_for(data_len: usize) -> Result<usize> {
    BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= data_len.saturating_add(4))
        .ok_or(Error::FrameTooLarge)
}

pub fn pad(data: &[u8]) -> Result<Vec<u8>> {
    let total = bucket_for(data.len())?;
    let len = u32::try_from(data.len()).map_err(|_| Error::FrameTooLarge)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out.resize(total, 0);
    Ok(out)
}

pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if !BUCKETS.contains(&padded.len()) {
        return Err(Error::BadPadding);
    }
    let len = u32::from_be_bytes(arr(&padded[..4])?) as usize;
    let end = 4usize.checked_add(len).ok_or(Error::BadPadding)?;
    let data = padded.get(4..end).ok_or(Error::BadPadding)?;
    if bucket_for(len)? != padded.len() || padded[end..].iter().any(|&b| b != 0) {
        return Err(Error::BadPadding);
    }
    Ok(data.to_vec())
}

/// A request opened by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRequest {
    pub method: String,
    /// Path with the query string, as in an HTTP request target.
    pub target: String,
    pub body: Vec<u8>,
    /// Client clock at sealing time, when the request carries one.
    pub ts: Option<u64>,
}

type Key = Zeroizing<[u8; 32]>;

fn keys(shared: &[u8; 32], e_pk: &[u8; 32], srv_pk: &[u8; 32]) -> Result<(Key, Key)> {
    let salt = [e_pk.as_slice(), srv_pk.as_slice()].concat();
    Ok((
        hkdf32(shared, &salt, b"aegis-v2 sealed-req")?,
        hkdf32(shared, &salt, b"aegis-v2 sealed-resp")?,
    ))
}

/// Seals a request with a fresh ephemeral key. Returns the outer body and the response key.
pub fn seal_request(srv_pk: &[u8; 32], method: &str, target: &str, body: &[u8]) -> Result<(Vec<u8>, Key)> {
    seal_request_at(&*crate::random_key()?, srv_pk, method, target, body, Some(crate::now_secs()))
}

/// Deterministic variant of [`seal_request`] with an injected ephemeral secret.
pub fn seal_request_with(
    e_sk: &[u8; 32],
    srv_pk: &[u8; 32],
    method: &str,
    target: &str,
    body: &[u8],
) -> Result<(Vec<u8>, Key)> {
    seal_request_at(e_sk, srv_pk, method, target, body, None)
}

/// Like [`seal_request_with`], with an optional timestamp after the method (`GET 1700000000`).
/// The server rejects a timestamp more than 600 s away from its own clock.
pub fn seal_request_at(
    e_sk: &[u8; 32],
    srv_pk: &[u8; 32],
    method: &str,
    target: &str,
    body: &[u8],
    ts: Option<u64>,
) -> Result<(Vec<u8>, Key)> {
    if method.contains('\n') || target.contains('\n') {
        return Err(Error::InvalidText);
    }
    let e_pk = x25519_public(e_sk);
    let shared = dh(e_sk, srv_pk)?;
    let (k_req, k_resp) = keys(&shared, &e_pk, srv_pk)?;
    let mut inner = Zeroizing::new(Vec::with_capacity(method.len() + target.len() + body.len() + 2));
    inner.extend_from_slice(method.as_bytes());
    if let Some(ts) = ts {
        inner.extend_from_slice(format!(" {ts}").as_bytes());
    }
    inner.push(b'\n');
    inner.extend_from_slice(target.as_bytes());
    inner.push(b'\n');
    inner.extend_from_slice(body);
    let padded = Zeroizing::new(pad(&inner)?);
    let aad = [AAD_REQ, e_pk.as_slice()].concat();
    let ct = aead_seal(&k_req, &[0; 12], &aad, &padded)?;
    Ok(([e_pk.as_slice(), &ct].concat(), k_resp))
}

/// Opens an outer request on the server. Returns the request and the response key.
pub fn open_request(srv_sk: &[u8; 32], outer: &[u8]) -> Result<(SealedRequest, Key)> {
    if outer.len() <= 32 + 16 || outer.len() > MAX_OUTER_BYTES {
        return Err(Error::Length);
    }
    let e_pk: [u8; 32] = arr(&outer[..32])?;
    let srv_pk = x25519_public(srv_sk);
    let shared = dh(srv_sk, &e_pk)?;
    let (k_req, k_resp) = keys(&shared, &e_pk, &srv_pk)?;
    let aad = [AAD_REQ, e_pk.as_slice()].concat();
    let padded = Zeroizing::new(aead_open(&k_req, &[0; 12], &aad, &outer[32..])?);
    let inner = Zeroizing::new(unpad(&padded)?);
    let mut parts = inner.splitn(3, |&b| b == b'\n');
    let (Some(m), Some(t), Some(body)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::Length);
    };
    let method = String::from_utf8(m.to_vec()).map_err(|_| Error::InvalidText)?;
    let (method, ts) = match method.split_once(' ') {
        Some((m, t)) if t.bytes().all(|c| c.is_ascii_digit()) && !t.is_empty() && t.len() <= 19 => {
            (m.to_owned(), Some(t.parse().map_err(|_| Error::InvalidText)?))
        }
        Some(_) => return Err(Error::InvalidText),
        None => (method, None),
    };
    let target = String::from_utf8(t.to_vec()).map_err(|_| Error::InvalidText)?;
    Ok((SealedRequest { method, target, body: body.to_vec(), ts }, k_resp))
}

/// Seals `BE16(status) || body` under the response key with a fresh random nonce.
/// The result is `nonce(12) || AEAD`.
pub fn seal_response(k_resp: &[u8; 32], status: u16, body: &[u8]) -> Result<Vec<u8>> {
    seal_response_with(&crate::random_bytes::<12>()?, k_resp, status, body)
}

/// Deterministic variant of [`seal_response`] with an injected nonce (tests and vectors).
pub fn seal_response_with(nonce: &[u8; 12], k_resp: &[u8; 32], status: u16, body: &[u8]) -> Result<Vec<u8>> {
    let inner = [status.to_be_bytes().as_slice(), body].concat();
    let ct = aead_seal(k_resp, nonce, AAD_RESP, &pad(&inner)?)?;
    Ok([nonce.as_slice(), &ct].concat())
}

pub fn open_response(k_resp: &[u8; 32], sealed: &[u8]) -> Result<(u16, Vec<u8>)> {
    if sealed.len() <= 12 {
        return Err(Error::Length);
    }
    let nonce: [u8; 12] = arr(&sealed[..12])?;
    let padded = aead_open(k_resp, &nonce, AAD_RESP, &sealed[12..])?;
    let inner = unpad(&padded)?;
    if inner.len() < 2 {
        return Err(Error::Length);
    }
    Ok((u16::from_be_bytes(arr(&inner[..2])?), inner[2..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_buckets() {
        let srv_sk = [5u8; 32];
        let srv_pk = x25519_public(&srv_sk);
        let body = b"body\nwith\nnewlines";
        let (outer, k_resp) =
            seal_request_with(&[9; 32], &srv_pk, "POST", "/api/v2/queue/send?q=ab", body).unwrap();
        assert_eq!(outer.len(), 32 + 1024 + 16);
        let (req, k2) = open_request(&srv_sk, &outer).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/api/v2/queue/send?q=ab");
        assert_eq!(req.body, body);
        assert_eq!(*k_resp, *k2);
        let resp = seal_response(&k2, 403, b"{\"left\":2}").unwrap();
        assert_eq!(resp.len(), 12 + 1024 + 16);
        assert_eq!(open_response(&k_resp, &resp).unwrap(), (403, b"{\"left\":2}".to_vec()));
        assert!(open_request(&[6; 32], &outer).is_err());
        let mut bad = outer.clone();
        bad[100] ^= 1;
        assert!(open_request(&srv_sk, &bad).is_err());
        assert!(seal_response(&k2, 200, &vec![0; 1_114_112]).is_err());
        let fit = seal_response(&k2, 200, &vec![0; 1_114_112 - 6]).unwrap();
        assert_eq!(fit.len(), 12 + 1_114_112 + 16);
        let again = seal_response(&k2, 200, &vec![0; 1_114_112 - 6]).unwrap();
        assert_ne!(fit[..12], again[..12]);
    }

    #[test]
    fn pad_rules() {
        assert_eq!(pad(&[]).unwrap().len(), 1024);
        assert_eq!(pad(&[1; 1020]).unwrap().len(), 1024);
        assert_eq!(pad(&[1; 1021]).unwrap().len(), 4096);
        assert!(unpad(&pad(b"x").unwrap()).is_ok());
        let mut p = pad(b"x").unwrap();
        p[1023] = 1;
        assert!(unpad(&p).is_err());
        assert!(unpad(&[0; 100]).is_err());
        let mut big = pad(&[1; 2000]).unwrap();
        big[3] = 5; // claims 5 bytes, which would have fit the 1024 bucket
        assert!(unpad(&big).is_err());
    }

    #[test]
    fn fixed_randomness_vector_is_stable() {
        let srv_pk = x25519_public(&[1; 32]);
        let (outer, k) = seal_request_with(&[2; 32], &srv_pk, "GET", "/health", b"").unwrap();
        let (outer2, _) = seal_request_with(&[2; 32], &srv_pk, "GET", "/health", b"").unwrap();
        assert_eq!(outer, outer2);
        let resp = seal_response_with(&[3; 12], &k, 200, b"{}").unwrap();
        // Run with `-- --nocapture` to export these as vectors.
        println!("sealed-req {}", crate::hex::encode(&outer));
        println!("sealed-resp {}", crate::hex::encode(&resp));
        assert_eq!(open_response(&k, &resp).unwrap().0, 200);
    }
}
