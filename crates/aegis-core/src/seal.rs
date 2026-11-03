//! Direct messages and group invites: frame type 0x01 (spec section 6).

use crate::envelope::{Envelope, Kind};
use crate::identity::{dh, x25519_public};
use crate::{arr, hkdf32, Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

pub const FRAME_SEAL: u8 = 0x01;
const C1_LEN: usize = 32 + 16;
const MIN_LEN: usize = 1 + 32 + C1_LEN + 16;

pub(crate) fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| Error::Decrypt)
}

pub(crate) fn aead_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)
}

/// A frame opened by [`open_dm`].
#[derive(Debug)]
pub struct Opened {
    /// Sender key authenticated by the second DH; compare it with the pinned contact.
    pub sender_x_pk: [u8; 32],
    pub envelope: Envelope,
}

/// Seals a `dm` or `ginv` envelope with a fresh ephemeral key.
pub fn seal_dm(sender_x_sk: &[u8; 32], recipient_x_pk: &[u8; 32], env: &Envelope) -> Result<Vec<u8>> {
    seal_dm_with(&crate::random_bytes::<32>()?, sender_x_sk, recipient_x_pk, env)
}

/// Deterministic variant of [`seal_dm`] with an injected ephemeral secret.
pub fn seal_dm_with(
    e_sk: &[u8; 32],
    sender_x_sk: &[u8; 32],
    recipient_x_pk: &[u8; 32],
    env: &Envelope,
) -> Result<Vec<u8>> {
    if env.kind == Kind::Gmsg {
        return Err(Error::BadFrameType);
    }
    let plain = zeroize::Zeroizing::new(env.encode()?);
    let e_pk = x25519_public(e_sk);
    let s_pk = x25519_public(sender_x_sk);
    let dh1 = dh(e_sk, recipient_x_pk)?;
    let dh2 = dh(sender_x_sk, recipient_x_pk)?;
    let salt = [e_pk.as_slice(), recipient_x_pk.as_slice()].concat();

    let k1 = hkdf32(dh1.as_ref(), &salt, b"aegis-v2 seal-1")?;
    let aad1 = [[FRAME_SEAL].as_slice(), &e_pk].concat();
    let c1 = aead_seal(&k1, &[0; 12], &aad1, &s_pk)?;

    let ikm = zeroize::Zeroizing::new([dh1.as_slice(), dh2.as_slice()].concat());
    let k2 = hkdf32(&ikm, &salt, b"aegis-v2 seal-2")?;
    let aad2 = [aad1.as_slice(), &c1].concat();
    let c2 = aead_seal(&k2, &[0; 12], &aad2, &plain)?;

    Ok([aad2.as_slice(), &c2].concat())
}

/// Opens a type 0x01 frame addressed to the owner of `recipient_x_sk`.
pub fn open_dm(recipient_x_sk: &[u8; 32], frame: &[u8]) -> Result<Opened> {
    if frame.len() < MIN_LEN {
        return Err(Error::Length);
    }
    if frame[0] != FRAME_SEAL {
        return Err(Error::BadFrameType);
    }
    let e_pk: [u8; 32] = arr(&frame[1..33])?;
    let c1 = &frame[33..33 + C1_LEN];
    let c2 = &frame[33 + C1_LEN..];
    let r_pk = x25519_public(recipient_x_sk);
    let salt = [e_pk.as_slice(), r_pk.as_slice()].concat();

    let dh1 = dh(recipient_x_sk, &e_pk)?;
    let k1 = hkdf32(dh1.as_ref(), &salt, b"aegis-v2 seal-1")?;
    let aad1 = [[FRAME_SEAL].as_slice(), &e_pk].concat();
    let s_pk: [u8; 32] = arr(&aead_open(&k1, &[0; 12], &aad1, c1)?)?;

    let dh2 = dh(recipient_x_sk, &s_pk)?;
    let ikm = zeroize::Zeroizing::new([dh1.as_slice(), dh2.as_slice()].concat());
    let k2 = hkdf32(&ikm, &salt, b"aegis-v2 seal-2")?;
    let aad2 = [aad1.as_slice(), c1].concat();
    let plain = zeroize::Zeroizing::new(aead_open(&k2, &[0; 12], &aad2, c2)?);

    let envelope = Envelope::decode(&plain)?;
    if envelope.kind == Kind::Gmsg {
        return Err(Error::BadFrameType);
    }
    Ok(Opened {
        sender_x_pk: s_pk,
        envelope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::{dm, ginv};
    use crate::envelope::{check_pinned_dm, PinnedKeys};

    const S: [u8; 32] = [0x11; 32];
    const R: [u8; 32] = [0x22; 32];

    fn frame() -> Vec<u8> {
        seal_dm(&S, &x25519_public(&R), &dm()).unwrap()
    }

    #[test]
    fn roundtrip_dm_and_ginv() {
        for e in [dm(), ginv()] {
            let f = seal_dm(&S, &x25519_public(&R), &e).unwrap();
            let o = open_dm(&R, &f).unwrap();
            assert_eq!(o.envelope, e);
            assert_eq!(o.sender_x_pk, x25519_public(&S));
        }
    }

    #[test]
    fn deterministic_with_injected_key() {
        let a = seal_dm_with(&[5; 32], &S, &x25519_public(&R), &dm()).unwrap();
        let b = seal_dm_with(&[5; 32], &S, &x25519_public(&R), &dm()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, frame());
        assert_eq!(a[0], 1);
    }

    #[test]
    fn every_flipped_byte_rejected() {
        let f = frame();
        for i in 0..f.len() {
            let mut t = f.clone();
            t[i] ^= 0x01;
            assert!(open_dm(&R, &t).is_err(), "byte {i}");
        }
        assert!(open_dm(&R, &f[..f.len() - 1]).is_err());
        assert!(open_dm(&R, &[]).is_err());
    }

    #[test]
    fn wrong_recipient() {
        assert!(open_dm(&[0x33; 32], &frame()).is_err());
    }

    #[test]
    fn sender_key_mismatch_detected() {
        let o = open_dm(&R, &frame()).unwrap();
        let ok = PinnedKeys { x_pk: x25519_public(&S), ed_pk: o.envelope.sender_ed };
        assert!(check_pinned_dm(&o.envelope, &o.sender_x_pk, &ok).is_ok());
        let other = PinnedKeys { x_pk: x25519_public(&[0x44; 32]), ..ok };
        assert_eq!(
            check_pinned_dm(&o.envelope, &o.sender_x_pk, &other),
            Err(Error::SenderMismatch)
        );
    }

    #[test]
    fn zero_dh_and_wrong_kind_rejected() {
        assert_eq!(
            seal_dm_with(&[5; 32], &S, &[0; 32], &dm()).unwrap_err(),
            Error::ZeroSharedSecret
        );
        let mut g = dm();
        g.kind = Kind::Gmsg;
        g.group_id = "ab".repeat(32);
        assert_eq!(seal_dm(&S, &x25519_public(&R), &g).unwrap_err(), Error::BadFrameType);
        let mut f = frame();
        f[0] = 2;
        assert_eq!(open_dm(&R, &f).unwrap_err(), Error::BadFrameType);
    }

    #[test]
    fn malicious_content_roundtrips() {
        let mut e = dm();
        e.body = "<img src=x onerror=alert(1)>\u{202E}\u{200B}".into();
        let f = seal_dm(&S, &x25519_public(&R), &e).unwrap();
        assert_eq!(open_dm(&R, &f).unwrap().envelope.body, e.body);
    }
}
