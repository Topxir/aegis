//! Envelope: the plaintext inside every frame (spec section 5).

use crate::identity::is_valid_username;
use crate::text::{pct_decode_strict, pct_encode};
use crate::{hex, Error, Result};
use std::collections::{HashSet, VecDeque};
use zeroize::Zeroizing;

pub const MAX_MEMBERS: usize = 20;
const FIELDS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dm,
    Ginv,
    Gmsg,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Dm => "dm",
            Kind::Ginv => "ginv",
            Kind::Gmsg => "gmsg",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "dm" => Ok(Kind::Dm),
            "ginv" => Ok(Kind::Ginv),
            "gmsg" => Ok(Kind::Gmsg),
            _ => Err(Error::InvalidEnvelope("type")),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    /// 32 lowercase hex chars.
    pub msg_id: String,
    pub sender: String,
    pub sender_name: String,
    pub sender_ed: [u8; 32],
    pub ts_ms: u64,
    pub ttl_s: u64,
    /// 64 hex chars for `ginv` and `gmsg`, empty for `dm`.
    pub group_id: String,
    pub body: String,
    /// `ginv` only.
    pub group_key: Option<Zeroizing<[u8; 32]>>,
    /// `ginv` only.
    pub members: Vec<String>,
}

impl core::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Envelope")
            .field("kind", &self.kind)
            .field("msg_id", &self.msg_id)
            .field("sender", &self.sender)
            .field("ts_ms", &self.ts_ms)
            .field("group_id", &self.group_id)
            .finish_non_exhaustive()
    }
}

/// Fresh random `msg_id`.
pub fn random_msg_id() -> Result<String> {
    Ok(hex::encode(&crate::random_bytes::<16>()?))
}

fn parse_dec(s: &str) -> Result<u64> {
    crate::text::parse_u64(s).map_err(|_| Error::InvalidEnvelope("number"))
}

impl Envelope {
    fn validate(&self) -> Result<()> {
        if !hex::is_hex_len(&self.msg_id, 16) {
            return Err(Error::InvalidEnvelope("msg_id"));
        }
        if !is_valid_username(&self.sender) {
            return Err(Error::InvalidEnvelope("sender"));
        }
        match self.kind {
            Kind::Dm => {
                if !self.group_id.is_empty() || self.group_key.is_some() || !self.members.is_empty()
                {
                    return Err(Error::InvalidEnvelope("dm carries group fields"));
                }
            }
            Kind::Gmsg => {
                if !hex::is_hex_len(&self.group_id, 32) {
                    return Err(Error::InvalidEnvelope("group_id"));
                }
                if self.group_key.is_some() || !self.members.is_empty() {
                    return Err(Error::InvalidEnvelope("gmsg carries invite fields"));
                }
            }
            Kind::Ginv => {
                let Some(key) = &self.group_key else {
                    return Err(Error::InvalidEnvelope("group_key"));
                };
                if self.group_id != crate::group::group_id(key) {
                    return Err(Error::InvalidEnvelope("group_id does not match group_key"));
                }
                if self.members.is_empty()
                    || self.members.len() > MAX_MEMBERS
                    || !self.members.iter().all(|m| is_valid_username(m))
                {
                    return Err(Error::InvalidEnvelope("members"));
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let key_hex = self
            .group_key
            .as_ref()
            .map(|k| hex::encode(k.as_ref()))
            .unwrap_or_default();
        let ts = self.ts_ms.to_string();
        let ttl = self.ttl_s.to_string();
        let members = self.members.join(",");
        let ed = hex::encode(&self.sender_ed);
        let fields: [&str; FIELDS] = [
            "AEGIS2",
            self.kind.as_str(),
            &self.msg_id,
            &self.sender,
            &self.sender_name,
            &ed,
            &ts,
            &ttl,
            &self.group_id,
            &self.body,
            &key_hex,
            &members,
        ];
        let line = fields
            .iter()
            .map(|f| pct_encode(f))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(line.into_bytes())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let s = core::str::from_utf8(bytes).map_err(|_| Error::InvalidEnvelope("utf-8"))?;
        let parts: Vec<&str> = s.split('\n').collect();
        if parts.len() != FIELDS {
            return Err(Error::InvalidEnvelope("field count"));
        }
        if parts[0] != "AEGIS2" {
            return Err(Error::InvalidEnvelope("header"));
        }
        let mut f: Vec<String> = Vec::with_capacity(FIELDS);
        for p in &parts {
            f.push(pct_decode_strict(p).map_err(|_| Error::InvalidEnvelope("percent-encoding"))?);
        }
        let kind = Kind::parse(&f[1])?;
        if !hex::is_hex_len(&f[5], 32) {
            return Err(Error::InvalidEnvelope("sender_ed"));
        }
        let sender_ed = hex::decode_array::<32>(&f[5])?;
        let group_key = if f[10].is_empty() {
            None
        } else if hex::is_hex_len(&f[10], 32) {
            Some(Zeroizing::new(hex::decode_array::<32>(&f[10])?))
        } else {
            return Err(Error::InvalidEnvelope("group_key"));
        };
        if !f[8].is_empty() && !hex::is_hex_len(&f[8], 32) {
            return Err(Error::InvalidEnvelope("group_id"));
        }
        let members: Vec<String> = if f[11].is_empty() {
            Vec::new()
        } else {
            f[11].split(',').map(str::to_owned).collect()
        };
        let env = Envelope {
            kind,
            msg_id: f[2].clone(),
            sender: f[3].clone(),
            sender_name: f[4].clone(),
            sender_ed,
            ts_ms: parse_dec(&f[6])?,
            ttl_s: parse_dec(&f[7])?,
            group_id: f[8].clone(),
            body: f[9].clone(),
            group_key,
            members,
        };
        env.validate()?;
        Ok(env)
    }
}

/// Keys pinned for a contact on first contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedKeys {
    pub x_pk: [u8; 32],
    pub ed_pk: [u8; 32],
}

/// Receiver check for `dm`/`ginv`: the sealed sender key and `sender_ed` must equal the pin.
pub fn check_pinned_dm(env: &Envelope, sender_x_pk: &[u8; 32], pinned: &PinnedKeys) -> Result<()> {
    if &pinned.x_pk == sender_x_pk && pinned.ed_pk == env.sender_ed {
        Ok(())
    } else {
        Err(Error::SenderMismatch)
    }
}

/// Receiver check for `gmsg`: `sender_ed` must equal the pinned key.
pub fn check_pinned_group(env: &Envelope, pinned: &PinnedKeys) -> Result<()> {
    if pinned.ed_pk == env.sender_ed {
        Ok(())
    } else {
        Err(Error::SenderMismatch)
    }
}

/// Bounded set of seen `msg_id`s, oldest evicted first. Persist it in the vault.
#[derive(Debug, Clone, Default)]
pub struct SeenIds {
    cap: usize,
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl SeenIds {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    pub fn from_ids(cap: usize, ids: impl IntoIterator<Item = String>) -> Self {
        let mut s = Self::new(cap);
        for id in ids {
            s.insert(&id);
        }
        s
    }

    /// Returns true if `id` was not seen before (and records it).
    pub fn insert(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }
        self.set.insert(id.to_owned());
        self.order.push_back(id.to_owned());
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }

    pub fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }

    pub fn ids(&self) -> impl Iterator<Item = &String> {
        self.order.iter()
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// `ttl_s`-based expiry: true when the message should be deleted at `now_ms`.
pub fn is_expired(env: &Envelope, now_ms: u64) -> bool {
    env.ttl_s != 0 && now_ms >= env.ts_ms.saturating_add(env.ttl_s.saturating_mul(1000))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn dm() -> Envelope {
        Envelope {
            kind: Kind::Dm,
            msg_id: "00112233445566778899aabbccddeeff".into(),
            sender: "alice".into(),
            sender_name: "Alice <b>\u{202E}".into(),
            sender_ed: [7; 32],
            ts_ms: 1_700_000_000_123,
            ttl_s: 0,
            group_id: String::new(),
            body: "<img src=x onerror=alert(1)>\nline2 \u{202E}%41".into(),
            group_key: None,
            members: vec![],
        }
    }

    pub fn ginv() -> Envelope {
        let g = [9u8; 32];
        Envelope {
            kind: Kind::Ginv,
            group_id: crate::group::group_id(&g),
            body: "Team".into(),
            group_key: Some(Zeroizing::new(g)),
            members: vec!["alice".into(), "bob".into()],
            ..dm()
        }
    }

    #[test]
    fn roundtrip_byte_exact() {
        for e in [dm(), ginv()] {
            let enc = e.encode().unwrap();
            assert_eq!(Envelope::decode(&enc).unwrap(), e);
        }
        let d = Envelope::decode(&dm().encode().unwrap()).unwrap();
        assert_eq!(d.body, "<img src=x onerror=alert(1)>\nline2 \u{202E}%41");
        assert_eq!(d.sender_name, "Alice <b>\u{202E}");
    }

    #[test]
    fn rejects_malformed() {
        let enc = String::from_utf8(dm().encode().unwrap()).unwrap();
        let bad = [
            enc.replacen("AEGIS2", "AEGIS1", 1),
            format!("{enc}\nextra"),
            enc.replacen("\n", "", 1),
            enc.replacen("dm", "xx", 1),
            enc.replacen("00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeefF", 1),
            enc.replacen("alice", "Alice", 1),
            enc.replacen("1700000000123", "01700000000123", 1),
            enc.replacen("1700000000123", "+1700000000123", 1),
            enc.replacen("alice", "al ice", 1),
            enc.replacen("%25", "%2G", 1),
        ];
        for b in bad {
            assert!(Envelope::decode(b.as_bytes()).is_err(), "{b}");
        }
        assert!(Envelope::decode(&[0xff, 0xfe]).is_err());
        let mut e = dm();
        e.group_id = "ab".repeat(32);
        assert!(e.encode().is_err());
        let mut g = ginv();
        g.group_id = "ab".repeat(32);
        assert!(g.encode().is_err());
        let mut g = ginv();
        g.members = (0..21).map(|i| format!("user{i:02}")).collect();
        assert!(g.encode().is_err());
    }

    #[test]
    fn seen_ids() {
        let mut s = SeenIds::new(2);
        assert!(s.insert("a"));
        assert!(!s.insert("a"));
        assert!(s.insert("b"));
        assert!(s.insert("c"));
        assert!(s.insert("a"));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn expiry_and_pins() {
        let mut e = dm();
        assert!(!is_expired(&e, u64::MAX));
        e.ttl_s = 10;
        assert!(!is_expired(&e, e.ts_ms + 9_999));
        assert!(is_expired(&e, e.ts_ms + 10_000));
        let p = PinnedKeys { x_pk: [1; 32], ed_pk: [7; 32] };
        assert!(check_pinned_dm(&e, &[1; 32], &p).is_ok());
        assert_eq!(check_pinned_dm(&e, &[2; 32], &p), Err(Error::SenderMismatch));
        let p2 = PinnedKeys { ed_pk: [8; 32], ..p };
        assert!(check_pinned_dm(&e, &[1; 32], &p2).is_err());
        assert!(check_pinned_group(&e, &p).is_ok());
        assert!(check_pinned_group(&e, &p2).is_err());
    }
}
