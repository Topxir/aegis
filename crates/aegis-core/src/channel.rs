//! Channels: broadcast groups where only the owner posts (spec section 15).
//!
//! Posts are framed exactly like group messages (section 7) but under keys derived with
//! channel-specific labels, so a group frame never opens as a channel post or vice versa.

use crate::envelope::{Envelope, Kind};
use crate::group::{signed_frame_open, signed_frame_seal};
use crate::{hex, hkdf32, sha256, Error, Result};
use zeroize::Zeroizing;

/// Maximum number of subscribers (one invite each).
pub const MAX_SUBSCRIBERS: usize = 200;

/// Fresh random channel secret `G`.
pub fn new_channel_secret() -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(crate::random_bytes::<32>()?))
}

/// `hex(SHA256("aegis-v2 channel-id" || G))`.
pub fn channel_id(g: &[u8; 32]) -> String {
    hex::encode(&sha256(&[b"aegis-v2 channel-id", g]))
}

/// Queue the channel's posts are sent to.
pub fn channel_queue(g: &[u8; 32]) -> Result<[u8; 32]> {
    crate::queue_ids::channel_queue(g)
}

/// Symmetric key for posts: `HKDF(G, "", "aegis-v2 channel-msg", 32)`.
pub fn channel_msg_key(g: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    hkdf32(g, b"", b"aegis-v2 channel-msg")
}

/// Signs and encrypts a `cmsg` or `cmf` post with a random nonce. Owner only.
pub fn seal_post(g: &[u8; 32], owner_ed_sk: &[u8; 32], env: &Envelope) -> Result<Vec<u8>> {
    seal_post_with(&crate::random_bytes::<12>()?, g, owner_ed_sk, env)
}

/// Deterministic variant of [`seal_post`] with an injected nonce.
pub fn seal_post_with(
    nonce: &[u8; 12],
    g: &[u8; 32],
    owner_ed_sk: &[u8; 32],
    env: &Envelope,
) -> Result<Vec<u8>> {
    if !matches!(env.kind, Kind::Cmsg | Kind::Cmf) {
        return Err(Error::BadFrameType);
    }
    let k = channel_msg_key(g)?;
    signed_frame_seal(&k, &channel_id(g), nonce, owner_ed_sk, env)
}

/// Opens a frame delivered on the queue of channel `g`. Accepts it only if it is a `cmsg`/`cmf`
/// for this channel whose `sender` is `owner`, whose `sender_ed` equals the owner's pinned
/// key `owner_ed_pk`, and whose signature verifies against that key.
pub fn open_post(
    g: &[u8; 32],
    owner: &str,
    owner_ed_pk: &[u8; 32],
    frame: &[u8],
) -> Result<Envelope> {
    let k = channel_msg_key(g)?;
    let env = signed_frame_open(&k, frame)?;
    if !matches!(env.kind, Kind::Cmsg | Kind::Cmf) {
        return Err(Error::BadFrameType);
    }
    if env.group_id != channel_id(g) {
        return Err(Error::GroupMismatch);
    }
    if env.sender != owner || &env.sender_ed != owner_ed_pk {
        return Err(Error::SenderMismatch);
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::dm;
    use crate::identity::{ed25519_public, ed25519_sign};
    use crate::seal::aead_seal;

    const G: [u8; 32] = [0x55; 32];
    const OWNER: [u8; 32] = [0x66; 32];

    fn post(g: &[u8; 32]) -> Envelope {
        Envelope {
            kind: Kind::Cmsg,
            group_id: channel_id(g),
            sender_ed: ed25519_public(&OWNER),
            body: "news <b>\u{202E}".into(),
            ..dm()
        }
    }

    #[test]
    fn derivations_are_domain_separated() {
        assert_ne!(channel_id(&G), crate::group::group_id(&G));
        assert_ne!(channel_queue(&G).unwrap(), crate::group::group_queue(&G).unwrap());
        assert_ne!(
            *channel_msg_key(&G).unwrap(),
            *hkdf32(&G, b"", b"aegis-v2 group-msg").unwrap()
        );
    }

    #[test]
    fn roundtrip_and_owner_checks() {
        let pk = ed25519_public(&OWNER);
        let f = seal_post(&G, &OWNER, &post(&G)).unwrap();
        assert_eq!(f[0], 2);
        assert_eq!(open_post(&G, "alice", &pk, &f).unwrap(), post(&G));
        assert_eq!(open_post(&G, "bob", &pk, &f).unwrap_err(), Error::SenderMismatch);
        assert_eq!(open_post(&G, "alice", &[1; 32], &f).unwrap_err(), Error::SenderMismatch);
        assert!(open_post(&[0x77; 32], "alice", &pk, &f).is_err());
        for i in 0..f.len() {
            let mut t = f.clone();
            t[i] ^= 0x40;
            assert!(open_post(&G, "alice", &pk, &t).is_err(), "byte {i}");
        }
    }

    #[test]
    fn group_and_channel_frames_do_not_cross() {
        let pk = ed25519_public(&OWNER);
        let f = seal_post(&G, &OWNER, &post(&G)).unwrap();
        assert!(crate::group::group_decrypt(&G, &f).is_err());
        let gm = Envelope {
            kind: Kind::Gmsg,
            group_id: crate::group::group_id(&G),
            ..post(&G)
        };
        let gf = crate::group::group_encrypt(&G, &OWNER, &gm).unwrap();
        assert!(open_post(&G, "alice", &pk, &gf).is_err());
        assert_eq!(seal_post(&G, &OWNER, &gm).unwrap_err(), Error::BadFrameType);
    }

    #[test]
    fn subscriber_cannot_forge_post() {
        // A subscriber knows G (so the key) but signs with their own key: sender_ed != owner.
        let mine = [0x99u8; 32];
        let owner_pk = ed25519_public(&OWNER);
        let mut e = post(&G);
        e.sender_ed = ed25519_public(&mine);
        assert_eq!(seal_post(&G, &OWNER, &e).unwrap_err(), Error::SenderMismatch);
        let f = seal_post(&G, &mine, &e).unwrap();
        assert_eq!(open_post(&G, "alice", &owner_pk, &f).unwrap_err(), Error::SenderMismatch);
        // Claiming the owner's key but signing with their own: bad signature.
        let mut e2 = post(&G);
        e2.sender_ed = owner_pk;
        let bytes = e2.encode().unwrap();
        let sig = ed25519_sign(&mine, &[b"aegis-v2 gmsg\n".as_slice(), &bytes].concat());
        let plain = [bytes.as_slice(), &sig].concat();
        let ct = aead_seal(&channel_msg_key(&G).unwrap(), &[3; 12], &[2], &plain).unwrap();
        let forged = [[2u8].as_slice(), &[3; 12], &ct].concat();
        assert_eq!(
            open_post(&G, "alice", &owner_pk, &forged).unwrap_err(),
            Error::BadSignature
        );
    }

    #[test]
    fn cinv_validation() {
        let inv = Envelope {
            kind: Kind::Cinv,
            group_id: channel_id(&G),
            group_key: Some(Zeroizing::new(G)),
            body: "Channel".into(),
            ..dm()
        };
        assert_eq!(Envelope::decode(&inv.encode().unwrap()).unwrap(), inv);
        let mut bad = inv.clone();
        bad.group_id = crate::group::group_id(&G);
        assert!(bad.encode().is_err());
        let mut bad = inv;
        bad.members = vec!["bob".into()];
        assert!(bad.encode().is_err());
    }
}
