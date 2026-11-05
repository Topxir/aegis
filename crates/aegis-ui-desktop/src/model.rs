//! Account data stored inside the encrypted vault.

use crate::i18n::Lang;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const DEFAULT_ENDPOINT: &str = "https://freeoasis.space";
pub const MAX_MESSAGES_PER_CHAT: usize = 1000;
pub const SEEN_CAP: usize = 4096;
pub const SCHEMA: u32 = 1;

mod hex32 {
    use aegis_core::hex;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        hex::decode_array::<32>(&s).map_err(serde::de::Error::custom)
    }
}

/// Secret byte strings (encoded ratchet stores and chains) kept as hex in the vault.
mod hexvec {
    use aegis_core::hex;
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(v: &Zeroizing<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let h = Zeroizing::new(hex::encode(v.as_slice()));
        s.serialize_str(&h)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        hex::decode(&s)
            .map(Zeroizing::new)
            .map_err(serde::de::Error::custom)
    }
}

mod hex32_secret {
    use aegis_core::hex;
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(v: &Zeroizing<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        let h = Zeroizing::new(hex::encode(v.as_ref()));
        s.serialize_str(&h)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<[u8; 32]>, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        hex::decode_array::<32>(&s)
            .map(Zeroizing::new)
            .map_err(serde::de::Error::custom)
    }
}

mod hex32_opt {
    use aegis_core::hex;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(s) => hex::decode_array::<32>(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub endpoint: String,
    pub socks5: String,
    pub lang: Lang,
    pub idle_min: u32,
    /// Notifications on or off (a taskbar flash while the window is not focused).
    pub flash_taskbar: bool,
    /// Show the sender name in the notification instead of "New message".
    #[serde(default)]
    pub notify_name: bool,
    /// Hide the window from screen capture.
    #[serde(default = "yes")]
    pub protect: bool,
    /// Pinned key of the sealed transport (spec section 23) and the endpoint it belongs to.
    #[serde(default, with = "hex32_opt")]
    pub server_key: Option<[u8; 32]>,
    #[serde(default)]
    pub server_key_for: String,
    /// Connect through a local Tor SOCKS5 proxy.
    #[serde(default)]
    pub tor: bool,
    /// Cover traffic: 0 off, 1 standard, 2 high.
    #[serde(default = "cover_std")]
    pub cover: u8,
}

fn yes() -> bool {
    true
}

fn cover_std() -> u8 {
    1
}

fn no_particles() -> String {
    "none".to_owned()
}

fn zero_key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([0; 32])
}

impl Settings {
    /// The transport key we trust for the current endpoint, if one was pinned.
    pub fn pinned_key(&self) -> Option<[u8; 32]> {
        if self.server_key_for == self.endpoint {
            self.server_key
        } else {
            None
        }
    }

    /// The SOCKS5 address to use, if any. Empty means a direct connection.
    pub fn proxy(&self) -> Option<&str> {
        (!self.socks5.is_empty()).then_some(self.socks5.as_str())
    }

    pub fn new(lang: Lang) -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_owned(),
            socks5: String::new(),
            lang,
            idle_min: 10,
            flash_taskbar: true,
            notify_name: false,
            protect: true,
            server_key: None,
            server_key_for: String::new(),
            tor: false,
            cover: 1,
        }
    }
}

/// Keys offered by a sender that differ from the pinned ones.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Changed {
    #[serde(with = "hex32_opt")]
    pub x: Option<[u8; 32]>,
    #[serde(with = "hex32")]
    pub ed: [u8; 32],
    /// True when the keys arrived inside an authenticated direct message.
    pub via_dm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    pub u: String,
    pub name: String,
    #[serde(with = "hex32")]
    pub x: [u8; 32],
    #[serde(with = "hex32")]
    pub ed: [u8; 32],
    pub verified: bool,
    pub changed: Option<Changed>,
    /// Profile card from the contact (spec section 22).
    #[serde(default)]
    pub about: String,
    #[serde(default = "no_particles")]
    pub particles: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MsgState {
    Sent,
    Sending,
    Failed,
}

/// A photo or video kept in the encrypted media store next to the vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaRef {
    pub video: bool,
    pub w: u32,
    pub h: u32,
    pub dur_ms: u64,
    /// 32 hex characters, the name of the `.bin` file.
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Msg {
    pub id: String,
    pub from: String,
    pub ts_ms: u64,
    pub ttl_s: u64,
    /// Message text, or the caption of an attachment.
    pub text: String,
    pub out: bool,
    pub state: MsgState,
    #[serde(default)]
    pub media: Option<MediaRef>,
}

impl Msg {
    pub fn expired(&self, now_ms: u64) -> bool {
        self.ttl_s != 0 && now_ms >= self.ts_ms.saturating_add(self.ttl_s.saturating_mul(1000))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Chat {
    pub ttl_s: u64,
    pub unread: u32,
    pub touched_ms: u64,
    pub msgs: Vec<Msg>,
}

impl Chat {
    pub fn new(now_ms: u64) -> Self {
        Self {
            touched_ms: now_ms,
            ..Self::default()
        }
    }

    pub fn last_ms(&self) -> u64 {
        self.msgs
            .last()
            .map_or(self.touched_ms, |m| m.ts_ms.max(self.touched_ms))
    }

    pub fn push(&mut self, m: Msg) {
        self.touched_ms = self.touched_ms.max(m.ts_ms);
        self.msgs.push(m);
        self.msgs.sort_by_key(|m| m.ts_ms);
        let extra = self.msgs.len().saturating_sub(MAX_MESSAGES_PER_CHAT);
        if extra > 0 {
            self.msgs.drain(..extra);
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    #[serde(with = "hex32_secret")]
    pub key: Zeroizing<[u8; 32]>,
    pub title: String,
    pub creator: String,
    pub members: Vec<String>,
    pub cursor: u64,
    pub chat: Chat,
}

impl core::fmt::Debug for Group {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Group")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A broadcast channel (spec section 15), also used for the official channel (section 19).
#[derive(Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    #[serde(with = "hex32_secret")]
    pub g: Zeroizing<[u8; 32]>,
    pub title: String,
    #[serde(default)]
    pub about: String,
    pub owner: String,
    /// Pinned owner key; `None` only for the official channel before first use.
    #[serde(default, with = "hex32_opt")]
    pub owner_ed: Option<[u8; 32]>,
    pub mine: bool,
    #[serde(default)]
    pub official: bool,
    /// Invited subscribers (owner only).
    #[serde(default)]
    pub subs: Vec<String>,
    pub cursor: u64,
    /// The directory now shows another key for the owner than the pinned one.
    #[serde(default)]
    pub warn: bool,
    pub chat: Chat,
}

impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Channel")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Text of the local "could not be decrypted" line. Network text never contains control
/// characters (see `clean_text`), so a real message cannot imitate it.
pub const UNDECRYPTABLE: &str = "\u{1}undecryptable";

/// Most requests from unknown keys kept at once, and most frames kept for each.
pub const MAX_PENDING: usize = 20;
pub const MAX_PENDING_FRAMES: usize = 3;
pub const MAX_BLOCKED: usize = 200;
pub const MAX_DEFERRED: usize = 20;
/// Most group or channel frames kept while their sender key has not arrived.
pub const MAX_HELD: usize = 50;

/// Sender-key state of one group or channel, as stored in the vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkeyState {
    /// Our sending chain (AGC1), empty before the first message.
    #[serde(default, with = "hexvec")]
    pub send: Zeroizing<Vec<u8>>,
    /// Chains of the other senders (AGK1), empty before the first one arrives.
    #[serde(default, with = "hexvec")]
    pub recv: Zeroizing<Vec<u8>>,
    /// Members who got the current sending chain.
    #[serde(default)]
    pub given: Vec<String>,
    /// A new sending chain is due (someone was removed).
    #[serde(default)]
    pub rotate: bool,
    /// Frames that arrived before their chain (unpadded, hex).
    #[serde(default)]
    pub held: Vec<String>,
}

/// A decrypted message whose attachment could not be fetched yet. The ratchet has moved on,
/// so it is kept (encoded envelope, hex) and tried again at the next poll.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Deferred {
    /// "" for a direct message, "g" for a group, "c" for a channel.
    #[serde(default)]
    pub kind: String,
    /// The contact, group id or channel id.
    pub contact: String,
    pub env: String,
}

/// A first message from a key that is not a contact. The frame cannot be read before the
/// sender is known, so the user decides whom it is from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pending {
    #[serde(with = "hex32")]
    pub x: [u8; 32],
    pub first_ms: u64,
    /// Unpadded type 0x03 frames, oldest first.
    pub frames: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Data {
    pub schema: u32,
    pub username: String,
    pub display: String,
    #[serde(with = "hex32_secret")]
    pub x_sk: Zeroizing<[u8; 32]>,
    #[serde(with = "hex32_secret")]
    pub ed_sk: Zeroizing<[u8; 32]>,
    pub settings: Settings,
    pub contacts: BTreeMap<String, Contact>,
    pub dms: BTreeMap<String, Chat>,
    pub groups: BTreeMap<String, Group>,
    pub seen: Vec<String>,
    pub inbox_cursor: u64,
    /// Key for the local media store; made on first load of an older vault.
    #[serde(default = "zero_key", with = "hex32_secret")]
    pub media_key: Zeroizing<[u8; 32]>,
    #[serde(default)]
    pub about: String,
    #[serde(default = "no_particles")]
    pub particles: String,
    #[serde(default)]
    pub channels: BTreeMap<String, Channel>,
    /// Pinned chats as `kind:id`.
    #[serde(default)]
    pub pinned: Vec<String>,
    #[serde(default)]
    pub muted: Vec<String>,
    /// Encoded `SessionStore` (AGS1); empty before the first session.
    #[serde(default, with = "hexvec")]
    pub sessions: Zeroizing<Vec<u8>>,
    /// Requests from unknown keys.
    #[serde(default)]
    pub pending: Vec<Pending>,
    /// Keys the user blocked, as hex.
    #[serde(default)]
    pub blocked: Vec<String>,
    #[serde(default)]
    pub deferred: Vec<Deferred>,
    #[serde(default)]
    pub skeys: BTreeMap<String, SkeyState>,
}

impl core::fmt::Debug for Data {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Data")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// Message text from the network: control characters and invisible or
/// direction-changing characters are dropped, newlines are kept.
pub fn clean_text(s: &str) -> String {
    s.chars()
        .filter(|&c| (c == '\n' || !c.is_control()) && !is_invisible(c))
        .collect()
}

fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{FEFF}'
        | '\u{00AD}'
        | '\u{061C}'
        | '\u{180E}')
}
