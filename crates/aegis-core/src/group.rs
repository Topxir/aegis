//! Group messages: frame type 0x02 (spec section 7).

use crate::envelope::{Envelope, Kind};
use crate::identity::{ed25519_public, ed25519_sign, ed25519_verify};
use crate::seal::{aead_open, aead_seal};
use crate::{arr, hex, hkdf32, sha256, Error, Result};
use zeroize::Zeroizing;

pub const FRAME_GROUP: u8 = 0x02;

/// Fresh random group secret `G`.
pub fn new_group_secret() -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(crate::random_bytes::<32>()?))
}

/// `hex(SHA256("aegis-v2 group-id" || G))`.
pub fn group_id(g: &[u8; 32]) -> String {
    hex::encode(&sha256(&[b"aegis-v2 group-id", g]))
}

/// Queue the group's frames are posted to.
pub fn group_queue(g: &[u8; 32]) -> Result<[u8; 32]> {
    crate::queue_ids::group_queue(g)
}

fn group_msg_key(g: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    hkdf32(g, b"", b"aegis-v2 group-msg")
}

fn sig_input(envelope: &[u8]) -> Vec<u8> {
    [b"aegis-v2 gmsg\n".as_slice(), envelope].concat()
}

/// Signs and encrypts a `gmsg` or `gmf` envelope with a random nonce.
pub fn group_encrypt(g: &[u8; 32], ed_sk: &[u8; 32], env: &Envelope) -> Result<Vec<u8>> {
    group_encrypt_with(&crate::random_bytes::<12>()?, g, ed_sk, env)
}

/// Deterministic variant of [`group_encrypt`] with an injected nonce.
pub fn group_encrypt_with(
    nonce: &[u8; 12],
    g: &[u8; 32],
    ed_sk: &[u8; 32],
    env: &Envelope,
) -> Result<Vec<u8>> {
    if !matches!(env.kind, Kind::Gmsg | Kind::Gmf) {
        return Err(Error::BadFrameType);
    }
    let k = group_msg_key(g)?;
    signed_frame_seal(&k, &group_id(g), nonce, ed_sk, env)
}

/// Decrypts a type 0x02 frame delivered on the queue of group `g` and verifies
/// the envelope signature against its `sender_ed`. The caller still has to
/// compare `sender_ed` with the pinned contact ([`crate::envelope::check_pinned_group`]).
pub fn group_decrypt(g: &[u8; 32], frame: &[u8]) -> Result<Envelope> {
    let k = group_msg_key(g)?;
    let env = signed_frame_open(&k, frame)?;
    if !matches!(env.kind, Kind::Gmsg | Kind::Gmf) {
        return Err(Error::BadFrameType);
    }
    if env.group_id != group_id(g) {
        return Err(Error::GroupMismatch);
    }
    Ok(env)
}

/// Shared framing of sections 7 and 15: `0x02 || nonce || AEAD(k, nonce, 0x02, envelope || sig)`.
/// `expected_id` is the group or channel id the envelope must carry.
pub(crate) fn signed_frame_seal(
    k: &[u8; 32],
    expected_id: &str,
    nonce: &[u8; 12],
    ed_sk: &[u8; 32],
    env: &Envelope,
) -> Result<Vec<u8>> {
    if env.kind.frame_type() != FRAME_GROUP {
        return Err(Error::BadFrameType);
    }
    if env.group_id != expected_id {
        return Err(Error::GroupMismatch);
    }
    if env.sender_ed != ed25519_public(ed_sk) {
        return Err(Error::SenderMismatch);
    }
    let bytes = env.encode()?;
    let sig = ed25519_sign(ed_sk, &sig_input(&bytes));
    let plain = Zeroizing::new([bytes.as_slice(), &sig].concat());
    let ct = aead_seal(k, nonce, &[FRAME_GROUP], &plain)?;
    Ok([[FRAME_GROUP].as_slice(), nonce, &ct].concat())
}

/// Decrypts a 0x02 frame and verifies the signature against the envelope's own `sender_ed`.
/// The caller checks kind, group/channel id and the pinned key.
pub(crate) fn signed_frame_open(k: &[u8; 32], frame: &[u8]) -> Result<Envelope> {
    if frame.len() < 1 + 12 + 16 + 64 {
        return Err(Error::Length);
    }
    if frame[0] != FRAME_GROUP {
        return Err(Error::BadFrameType);
    }
    let nonce: [u8; 12] = arr(&frame[1..13])?;
    let plain = Zeroizing::new(aead_open(k, &nonce, &[FRAME_GROUP], &frame[13..])?);
    if plain.len() < 64 {
        return Err(Error::Length);
    }
    let (body, sig) = plain.split_at(plain.len() - 64);
    let env = Envelope::decode(body)?;
    if env.kind.frame_type() != FRAME_GROUP {
        return Err(Error::BadFrameType);
    }
    let sig: [u8; 64] = arr(sig)?;
    if !ed25519_verify(&env.sender_ed, &sig_input(body), &sig) {
        return Err(Error::BadSignature);
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::dm;
    use crate::envelope::{check_pinned_group, PinnedKeys};

    const G: [u8; 32] = [0x55; 32];
    const ED: [u8; 32] = [0x66; 32];

    fn msg(g: &[u8; 32], ed: &[u8; 32]) -> Envelope {
        Envelope {
            kind: Kind::Gmsg,
            group_id: group_id(g),
            sender_ed: ed25519_public(ed),
            body: "<img src=x onerror=alert(1)>\u{202E}".into(),
            ..dm()
        }
    }

    #[test]
    fn roundtrip() {
        let e = msg(&G, &ED);
        let f = group_encrypt(&G, &ED, &e).unwrap();
        assert_eq!(f[0], 2);
        assert_eq!(group_decrypt(&G, &f).unwrap(), e);
    }

    #[test]
    fn deterministic_with_nonce() {
        let e = msg(&G, &ED);
        let a = group_encrypt_with(&[1; 12], &G, &ED, &e).unwrap();
        assert_eq!(a, group_encrypt_with(&[1; 12], &G, &ED, &e).unwrap());
        assert_ne!(a, group_encrypt_with(&[2; 12], &G, &ED, &e).unwrap());
    }

    #[test]
    fn every_flipped_byte_rejected() {
        let f = group_encrypt(&G, &ED, &msg(&G, &ED)).unwrap();
        for i in 0..f.len() {
            let mut t = f.clone();
            t[i] ^= 0x80;
            assert!(group_decrypt(&G, &t).is_err(), "byte {i}");
        }
    }

    #[test]
    fn cross_group_replay_rejected() {
        let g2 = [0x77; 32];
        let f = group_encrypt(&G, &ED, &msg(&G, &ED)).unwrap();
        assert!(group_decrypt(&g2, &f).is_err());
        // Same inner envelope re-encrypted under another group's key must fail the id check.
        let bytes = msg(&G, &ED).encode().unwrap();
        let sig = ed25519_sign(&ED, &sig_input(&bytes));
        let plain = [bytes.as_slice(), &sig].concat();
        let k = group_msg_key(&g2).unwrap();
        let ct = aead_seal(&k, &[3; 12], &[FRAME_GROUP], &plain).unwrap();
        let forged = [[FRAME_GROUP].as_slice(), &[3; 12], &ct].concat();
        assert_eq!(group_decrypt(&g2, &forged).unwrap_err(), Error::GroupMismatch);
        assert_eq!(
            group_encrypt(&g2, &ED, &msg(&G, &ED)).unwrap_err(),
            Error::GroupMismatch
        );
    }

    #[test]
    fn forged_sender_rejected() {
        // A group member signs with their own key but claims another sender_ed.
        let mut e = msg(&G, &ED);
        e.sender_ed = ed25519_public(&[0x99; 32]);
        assert_eq!(group_encrypt(&G, &ED, &e).unwrap_err(), Error::SenderMismatch);
        let bytes = e.encode().unwrap();
        let sig = ed25519_sign(&ED, &sig_input(&bytes));
        let plain = [bytes.as_slice(), &sig].concat();
        let k = group_msg_key(&G).unwrap();
        let ct = aead_seal(&k, &[3; 12], &[FRAME_GROUP], &plain).unwrap();
        let forged = [[FRAME_GROUP].as_slice(), &[3; 12], &ct].concat();
        assert_eq!(group_decrypt(&G, &forged).unwrap_err(), Error::BadSignature);
    }

    #[test]
    fn pin_mismatch_and_kind() {
        let e = group_decrypt(&G, &group_encrypt(&G, &ED, &msg(&G, &ED)).unwrap()).unwrap();
        let pin = PinnedKeys { x_pk: [0; 32], ed_pk: ed25519_public(&ED) };
        assert!(check_pinned_group(&e, &pin).is_ok());
        assert!(check_pinned_group(&e, &PinnedKeys { ed_pk: [1; 32], ..pin }).is_err());
        assert_eq!(group_encrypt(&G, &ED, &dm()).unwrap_err(), Error::BadFrameType);
        let mut f = group_encrypt(&G, &ED, &msg(&G, &ED)).unwrap();
        f[0] = 1;
        assert_eq!(group_decrypt(&G, &f).unwrap_err(), Error::BadFrameType);
    }
}
