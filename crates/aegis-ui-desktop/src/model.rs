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
    pub flash_taskbar: bool,
}

impl Settings {
    pub fn new(lang: Lang) -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_owned(),
            socks5: String::new(),
            lang,
            idle_min: 10,
            flash_taskbar: true,
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
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MsgState {
    Sent,
    Sending,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Msg {
    pub id: String,
    pub from: String,
    pub ts_ms: u64,
    pub ttl_s: u64,
    pub text: String,
    pub out: bool,
    pub state: MsgState,
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
