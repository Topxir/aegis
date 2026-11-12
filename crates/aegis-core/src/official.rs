//! The built-in official channel (spec section 19): section 15 framing with a public `G`.

use crate::envelope::Envelope;
use crate::{channel, sha256, Result};
use zeroize::Zeroizing;

/// Username of the channel owner.
pub const OFFICIAL_OWNER: &str = "owner";

/// Owner `ed_pk` compiled into the clients. Clients never take this key from the directory or
/// the server, so whoever answers a lookup cannot forge official posts.
pub const OFFICIAL_OWNER_ED_PK: Option<[u8; 32]> = Some([
    0x9b, 0x71, 0x4d, 0x3e, 0x9f, 0x6b, 0x7d, 0x24, 0x8a, 0x15, 0xc7, 0x30, 0x2d, 0x3b, 0x1f, 0xf3, 0x91, 0xca, 0x41, 0x6c, 0x98, 0xcc, 0xc9, 0x35, 0xbb, 0x43, 0x49, 0xf0, 0x0e, 0xec, 0x58, 0x84,
]);

/// `G = SHA256("aegis-v2 official-channel")`.
pub fn official_g() -> [u8; 32] {
    sha256(&[b"aegis-v2 official-channel"])
}

pub fn official_channel_id() -> String {
    channel::channel_id(&official_g())
}

pub fn official_queue() -> Result<[u8; 32]> {
    channel::channel_queue(&official_g())
}

pub fn official_msg_key() -> Result<Zeroizing<[u8; 32]>> {
    channel::channel_msg_key(&official_g())
}

/// The key to verify against: only the compiled-in one. The argument (a key pinned locally
/// or fetched from the directory) is ignored on purpose.
pub fn owner_key(_pinned: Option<[u8; 32]>) -> Option<[u8; 32]> {
    OFFICIAL_OWNER_ED_PK
}

/// Opens a frame from the official queue against the compiled-in owner key.
/// Fails when no key was compiled in.
pub fn verify(frame: &[u8]) -> Result<Envelope> {
    verify_with(OFFICIAL_OWNER_ED_PK, frame)
}

/// [`verify`] with the build-time key passed in (for tests).
pub fn verify_with(build_key: Option<[u8; 32]>, frame: &[u8]) -> Result<Envelope> {
    let key = build_key.ok_or(crate::Error::InvalidEnvelope("no official owner key"))?;
    open_official_post(&key, frame)
}

/// What the owner signs to append `frame` to the official queue:
/// `"aegis-v2 official-post" || queue_id || BE64(ts) || SHA256(frame)`.
pub fn post_auth_message(queue_id: &[u8; 32], ts: u64, frame: &[u8]) -> Vec<u8> {
    [b"aegis-v2 official-post".as_slice(), queue_id, &ts.to_be_bytes(), &sha256(&[frame])].concat()
}

pub fn sign_post_auth(owner_ed_sk: &[u8; 32], queue_id: &[u8; 32], ts: u64, frame: &[u8]) -> [u8; 64] {
    crate::identity::ed25519_sign(owner_ed_sk, &post_auth_message(queue_id, ts, frame))
}

pub fn post_auth_ok(owner_ed_pk: &[u8; 32], queue_id: &[u8; 32], ts: u64, frame: &[u8], sig: &[u8; 64]) -> bool {
    crate::identity::ed25519_verify(owner_ed_pk, &post_auth_message(queue_id, ts, frame), sig)
}

/// Opens a frame from the official queue against an explicit owner key.
pub fn open_official_post(owner_ed_pk: &[u8; 32], frame: &[u8]) -> Result<Envelope> {
    channel::open_post(&official_g(), OFFICIAL_OWNER, owner_ed_pk, frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::dm;
    use crate::envelope::Kind;
    use crate::identity::ed25519_public;

    #[test]
    fn post_and_pin() {
        let sk = [0x42u8; 32];
        let pk = ed25519_public(&sk);
        let e = Envelope {
            kind: Kind::Cmsg,
            sender: OFFICIAL_OWNER.into(),
            group_id: official_channel_id(),
            sender_ed: pk,
            ..dm()
        };
        let f = channel::seal_post(&official_g(), &sk, &e).unwrap();
        assert_eq!(open_official_post(&pk, &f).unwrap(), e);
        assert!(open_official_post(&[1; 32], &f).is_err());
        assert_eq!(owner_key(Some(pk)), OFFICIAL_OWNER_ED_PK);
        assert_eq!(verify_with(Some(pk), &f).unwrap(), e);
        assert!(verify_with(None, &f).is_err());
        assert!(verify(&f).is_err() || OFFICIAL_OWNER_ED_PK.is_some());
        let q = official_queue().unwrap();
        let sig = sign_post_auth(&sk, &q, 5, &f);
        assert!(post_auth_ok(&pk, &q, 5, &f, &sig));
        assert!(!post_auth_ok(&pk, &q, 6, &f, &sig));
        assert!(!post_auth_ok(&pk, &q, 5, &f[1..], &sig));
        assert!(!post_auth_ok(&pk, &[0; 32], 5, &f, &sig));
        assert_ne!(official_queue().unwrap(), channel::channel_queue(&[0; 32]).unwrap());
    }
}
