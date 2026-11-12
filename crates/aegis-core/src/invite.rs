//! One-time invites and the hidden-profile switch (spec section 30).
//!
//! An invite is a random 32-byte secret `s` carried in a link. The server keeps only
//! `id = SHA256("aegis-v2 invite-id" || s)` and a box it cannot open, so its state never names
//! the inviter. Redeeming hands out the box once; the inviter's contact details are inside.

use crate::identity::{ed25519_verify, is_valid_username, Identity};
use crate::prekeys::strict_pairs;
use crate::seal::{aead_open, aead_seal};
use crate::text::{parse_u64, pct_encode};
use crate::{hex, hkdf32, sha256, Error, Result};
use zeroize::Zeroizing;

/// An invite can be redeemed for this long after it was created.
pub const INVITE_TTL_SECS: u64 = 7 * 24 * 3600;
/// Most invites one user may create in any window of `INVITE_TTL_SECS` (and so the most that
/// can be open at once).
pub const MAX_OPEN_INVITES: usize = 10;
/// Plaintext of the box, zero-padded so its length says nothing about the username.
pub const BUNDLE_PLAIN_LEN: usize = 160;
/// `BUNDLE_PLAIN_LEN` plus the AEAD tag.
pub const BOX_LEN: usize = BUNDLE_PLAIN_LEN + 16;
/// Link prefix; the secret follows as 64 lowercase hex characters.
pub const LINK_PREFIX: &str = "aegis://invite/";

const BUNDLE_MAGIC: &str = "AIV1";

/// Server-side name of an invite.
pub fn invite_id(s: &[u8; 32]) -> [u8; 32] {
    sha256(&[b"aegis-v2 invite-id", s])
}

fn box_key(s: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    hkdf32(s, &[], b"aegis-v2 invite-key")
}

/// The contact details an invite hands out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub u: String,
    pub x: [u8; 32],
    pub ed: [u8; 32],
}

/// Seals the inviter's details under a key only the link holder can derive.
/// `AEAD(HKDF(s, "aegis-v2 invite-key"), nonce = 0^12, aad = id, "AIV1\n" u "\n" x "\n" ed || 0..)`.
pub fn seal_bundle(s: &[u8; 32], b: &Bundle) -> Result<Vec<u8>> {
    if !is_valid_username(&b.u) {
        return Err(Error::InvalidUsername);
    }
    let text = format!("{BUNDLE_MAGIC}\n{}\n{}\n{}", b.u, hex::encode(&b.x), hex::encode(&b.ed));
    let mut plain = Zeroizing::new(vec![0u8; BUNDLE_PLAIN_LEN]);
    plain[..text.len()].copy_from_slice(text.as_bytes());
    // The key is used for exactly one message, so the fixed nonce is safe.
    aead_seal(&*box_key(s)?, &[0; 12], &invite_id(s), &plain)
}

/// Opens a box handed out by `invite/redeem`.
pub fn open_bundle(s: &[u8; 32], sealed: &[u8]) -> Result<Bundle> {
    if sealed.len() != BOX_LEN {
        return Err(Error::Length);
    }
    let plain = Zeroizing::new(aead_open(&*box_key(s)?, &[0; 12], &invite_id(s), sealed)?);
    let end = plain.iter().position(|b| *b == 0).unwrap_or(plain.len());
    if plain[end..].iter().any(|b| *b != 0) {
        return Err(Error::InvalidText);
    }
    let text = core::str::from_utf8(&plain[..end]).map_err(|_| Error::InvalidText)?;
    let f: Vec<&str> = text.split('\n').collect();
    if f.len() != 4 || f[0] != BUNDLE_MAGIC || !is_valid_username(f[1]) {
        return Err(Error::InvalidText);
    }
    if !hex::is_hex_len(f[2], 32) || !hex::is_hex_len(f[3], 32) {
        return Err(Error::InvalidHex);
    }
    Ok(Bundle { u: f[1].to_owned(), x: hex::decode_array(f[2])?, ed: hex::decode_array(f[3])? })
}

/// Proof that the sender of an `iacc` envelope holds the invite secret, bound to the keys the
/// inviter will pin: `HKDF(s, info = "aegis-v2 invite-accept\n" u "\n" x "\n" ed)`.
pub fn accept_tag(s: &[u8; 32], u: &str, x: &[u8; 32], ed: &[u8; 32]) -> Result<[u8; 32]> {
    let info = format!("aegis-v2 invite-accept\n{u}\n{}\n{}", hex::encode(x), hex::encode(ed));
    Ok(*hkdf32(s, &[], info.as_bytes())?)
}

fn tag_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    core::hint::black_box(d) == 0
}

fn accept_message(u: &str, x: &[u8; 32], tag: &[u8; 32]) -> Vec<u8> {
    format!("aegis-v2 invite-accept-sig\n{u}\n{}\n{}", hex::encode(x), hex::encode(tag)).into_bytes()
}

/// Body of an `iacc` envelope: hex of `tag || sig`, where `sig` is the redeemer's Ed25519
/// signature over `"aegis-v2 invite-accept-sig\n" u "\n" x "\n" tag`. The tag shows the link was
/// held, the signature that the claimed identity key is the sender's own.
pub fn accept_body(identity: &Identity, s: &[u8; 32], u: &str) -> Result<String> {
    let x = identity.x_public();
    let tag = accept_tag(s, u, &x, &identity.ed_public())?;
    let sig = identity.sign(&accept_message(u, &x, &tag));
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&sig);
    Ok(hex::encode(&out))
}

/// Checks an `iacc` body against an open secret and the sender's keys.
pub fn check_accept(s: &[u8; 32], u: &str, x: &[u8; 32], ed: &[u8; 32], body: &str) -> bool {
    let Ok(raw) = hex::decode_array::<96>(body) else {
        return false;
    };
    let Ok(tag) = accept_tag(s, u, x, ed) else {
        return false;
    };
    let mut got = [0u8; 32];
    got.copy_from_slice(&raw[..32]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&raw[32..]);
    tag_eq(&got, &tag) & ed25519_verify(ed, &accept_message(u, x, &tag), &sig)
}

/// `aegis://invite/<hex s>`.
pub fn link(s: &[u8; 32]) -> String {
    format!("{LINK_PREFIX}{}", hex::encode(s))
}

/// Reads a pasted or opened link. Surrounding white space and the case of the scheme and of
/// the hex are ignored; anything else is refused.
pub fn parse_link(text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let t = text.trim();
    let n = LINK_PREFIX.len();
    if t.len() != n + 64 || !t.is_char_boundary(n) || !t[..n].eq_ignore_ascii_case(LINK_PREFIX) {
        return Err(Error::InvalidText);
    }
    let h = t[n..].to_ascii_lowercase();
    Ok(Zeroizing::new(hex::decode_array::<32>(&h)?))
}

/// Message signed over an `invite/create` request.
pub fn create_message(u: &str, id_hex: &str, box_hex: &str, ts: u64) -> Vec<u8> {
    format!("aegis-v2 invite\n{u}\n{id_hex}\n{box_hex}\n{ts}").into_bytes()
}

/// A decoded `POST /api/v2/invite/create` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCreate {
    pub u: String,
    pub id: [u8; 32],
    pub sealed: Vec<u8>,
    pub ts: u64,
    pub sig: [u8; 64],
}

impl InviteCreate {
    pub fn sign(identity: &Identity, u: &str, s: &[u8; 32], ts: u64) -> Result<Self> {
        let b = Bundle { u: u.to_owned(), x: identity.x_public(), ed: identity.ed_public() };
        let mut c = Self { u: u.to_owned(), id: invite_id(s), sealed: seal_bundle(s, &b)?, ts, sig: [0; 64] };
        c.sig = identity.sign(&c.message());
        Ok(c)
    }

    pub fn message(&self) -> Vec<u8> {
        create_message(&self.u, &hex::encode(&self.id), &hex::encode(&self.sealed), self.ts)
    }

    pub fn sig_ok(&self, ed: &[u8; 32]) -> bool {
        ed25519_verify(ed, &self.message(), &self.sig)
    }

    pub fn to_form(&self) -> String {
        format!(
            "u={}&id={}&box={}&ts={}&sig={}",
            pct_encode(&self.u),
            hex::encode(&self.id),
            hex::encode(&self.sealed),
            self.ts,
            hex::encode(&self.sig)
        )
    }

    /// Strict parser: five fields exactly once, lowercase hex, a box of exactly `BOX_LEN` bytes.
    pub fn from_form(body: &str) -> Result<Self> {
        let [u, id, sealed, ts, sig] = strict_pairs(body, ["u", "id", "box", "ts", "sig"])?;
        if !is_valid_username(&u) {
            return Err(Error::InvalidUsername);
        }
        if !hex::is_hex_len(&sealed, BOX_LEN) {
            return Err(Error::Length);
        }
        Ok(Self {
            u,
            id: hex::decode_array(&id)?,
            sealed: hex::decode(&sealed)?,
            ts: parse_u64(&ts)?,
            sig: hex::decode_array(&sig)?,
        })
    }
}

/// Body of `invite/redeem` and `invite/revoke`: `id=<hex>`.
pub fn id_form(id: &[u8; 32]) -> String {
    format!("id={}", hex::encode(id))
}

pub fn parse_id_form(body: &str) -> Result<[u8; 32]> {
    let [id] = strict_pairs(body, ["id"])?;
    hex::decode_array(&id)
}

/// Message signed over a `dir/hide` request.
pub fn hide_message(u: &str, hidden: bool, ts: u64) -> Vec<u8> {
    format!("aegis-v2 hide\n{u}\n{}\n{ts}", u8::from(hidden)).into_bytes()
}

/// A decoded `POST /api/v2/dir/hide` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hide {
    pub u: String,
    pub hidden: bool,
    pub ts: u64,
    pub sig: [u8; 64],
}

impl Hide {
    pub fn sign(identity: &Identity, u: &str, hidden: bool, ts: u64) -> Result<Self> {
        if !is_valid_username(u) {
            return Err(Error::InvalidUsername);
        }
        Ok(Self { u: u.to_owned(), hidden, ts, sig: identity.sign(&hide_message(u, hidden, ts)) })
    }

    pub fn sig_ok(&self, ed: &[u8; 32]) -> bool {
        ed25519_verify(ed, &hide_message(&self.u, self.hidden, self.ts), &self.sig)
    }

    pub fn to_form(&self) -> String {
        format!(
            "u={}&hidden={}&ts={}&sig={}",
            pct_encode(&self.u),
            u8::from(self.hidden),
            self.ts,
            hex::encode(&self.sig)
        )
    }

    pub fn from_form(body: &str) -> Result<Self> {
        let [u, hidden, ts, sig] = strict_pairs(body, ["u", "hidden", "ts", "sig"])?;
        if !is_valid_username(&u) {
            return Err(Error::InvalidUsername);
        }
        let hidden = match hidden.as_str() {
            "0" => false,
            "1" => true,
            _ => return Err(Error::InvalidText),
        };
        Ok(Self { u, hidden, ts: parse_u64(&ts)?, sig: hex::decode_array(&sig)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_roundtrip_and_wrong_secret() {
        let s = [7u8; 32];
        let b = Bundle { u: "alice".into(), x: [1; 32], ed: [2; 32] };
        let sealed = seal_bundle(&s, &b).unwrap();
        assert_eq!(sealed.len(), BOX_LEN);
        assert_eq!(open_bundle(&s, &sealed).unwrap(), b);
        assert!(open_bundle(&[8; 32], &sealed).is_err());
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(open_bundle(&s, &bad).is_err());
        let long = Bundle { u: "a".repeat(24), ..b };
        assert_eq!(seal_bundle(&s, &long).unwrap().len(), BOX_LEN);
    }

    #[test]
    fn links() {
        let s = [0xabu8; 32];
        let l = link(&s);
        assert_eq!(*parse_link(&l).unwrap(), s);
        assert_eq!(*parse_link(&format!("  {}\n", l.to_ascii_uppercase())).unwrap(), s);
        assert!(parse_link("aegis://invite/abcd").is_err());
        assert!(parse_link(&format!("{l}0")).is_err());
        assert!(parse_link(&l.replace("invite", "invitx")).is_err());
        assert!(parse_link(&format!("https://invite/{}", hex::encode(&s))).is_err());
    }

    #[test]
    fn forms_are_strict() {
        let id = Identity::from_secrets([1; 32], [2; 32]);
        let c = InviteCreate::sign(&id, "alice", &[3; 32], 1_700_000_000).unwrap();
        let back = InviteCreate::from_form(&c.to_form()).unwrap();
        assert_eq!(back, c);
        assert!(back.sig_ok(&id.ed_public()));
        assert!(InviteCreate::from_form(&format!("{}&x=1", c.to_form())).is_err());
        let h = Hide::sign(&id, "alice", true, 5).unwrap();
        let hb = Hide::from_form(&h.to_form()).unwrap();
        assert!(hb.hidden && hb.sig_ok(&id.ed_public()));
        assert!(!Hide { hidden: false, ..hb }.sig_ok(&id.ed_public()));
        assert!(Hide::from_form("u=alice&hidden=2&ts=5&sig=00").is_err());
        assert_eq!(parse_id_form(&id_form(&[9; 32])).unwrap(), [9; 32]);
        assert!(parse_id_form("id=zz").is_err());
    }
}
