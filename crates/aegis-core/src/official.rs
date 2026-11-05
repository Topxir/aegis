//! The built-in official channel (spec section 19): section 15 framing with a public `G`.

use crate::envelope::Envelope;
use crate::{channel, sha256, Result};
use zeroize::Zeroizing;

/// Username of the channel owner.
pub const OFFICIAL_OWNER: &str = "owner";

/// Owner `ed_pk` compiled into the clients; `None` until it is known (clients then pin it on first use).
pub const OFFICIAL_OWNER_ED_PK: Option<[u8; 32]> = None;

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

/// The key to verify against: the compiled-in one, else the one pinned locally.
pub fn owner_key(pinned: Option<[u8; 32]>) -> Option<[u8; 32]> {
    OFFICIAL_OWNER_ED_PK.or(pinned)
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
        assert_eq!(owner_key(Some(pk)), Some(pk));
        assert_eq!(owner_key(None), None);
        assert_ne!(official_queue().unwrap(), channel::channel_queue(&[0; 32]).unwrap());
    }
}
