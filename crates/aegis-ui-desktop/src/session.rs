//! Decrypted account state and the rules for applying incoming and outgoing messages.
//! Nothing here touches the network or the disk.

use std::collections::BTreeMap;
use crate::i18n::Lang;
use crate::model::{
    clean_text, Changed, Channel, Chat, Contact, Data, Group, MediaRef, Msg, MsgState, Deferred, Pending,
    Settings, SkeyState, MAX_BLOCKED, MAX_DEFERRED, MAX_HELD, MAX_PENDING, MAX_PENDING_FRAMES, SEEN_CAP, UNDECRYPTABLE,
};
use aegis_core::channel::{channel_id, channel_queue, new_channel_secret, MAX_SUBSCRIBERS};
use aegis_core::envelope::{
    check_pinned_dm, check_pinned_group, random_msg_id, Envelope, Kind, PinnedKeys,
    SeenIds, MAX_MEMBERS,
};
use aegis_core::group::{group_id, group_queue, new_group_secret};
use aegis_core::senderkey::{RecvSet, Scope, SendChain};
use aegis_core::identity::{ed25519_public, x25519_public, Identity};
use aegis_core::prekeys::PrekeyPut;
use aegis_core::net::DirEntry;
use aegis_core::profile::{Particles, Profile, MAX_ABOUT};
use aegis_core::queue_ids::inbox_queue;
use aegis_core::session::{Encrypted, Received, SessionStore};
use aegis_core::text::sanitize_display_text;
use aegis_core::x3dh::Bundle;
use aegis_core::{hex, pad, Error};
use zeroize::Zeroizing;

pub use aegis_core::envelope::TTL_CHOICES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatRef {
    Dm(String),
    Group(String),
    Channel(String),
}

impl ChatRef {
    /// Stable `kind:id` form used for pins, mutes and page commands.
    pub fn key(&self) -> String {
        match self {
            ChatRef::Dm(i) => format!("dm:{i}"),
            ChatRef::Group(i) => format!("group:{i}"),
            ChatRef::Channel(i) => format!("channel:{i}"),
        }
    }

    pub fn from_parts(kind: &str, id: &str) -> Option<Self> {
        let id = id.to_owned();
        match kind {
            "dm" => Some(ChatRef::Dm(id)),
            "group" => Some(ChatRef::Group(id)),
            "channel" => Some(ChatRef::Channel(id)),
            _ => None,
        }
    }
}

/// What a message carries.
#[derive(Debug)]
pub enum Payload {
    Text(String),
    /// `body` is the encoded attachment descriptor; the caption is kept locally as text.
    Media {
        body: String,
        caption: String,
        media: MediaRef,
    },
}

/// What happened to an incoming frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Added(ChatRef),
    GroupJoined(String),
    ChannelJoined(String),
    Profile(String),
    KeyChanged(String),
    /// The timer of a chat was changed by the other side.
    Timer(ChatRef),
    Dropped,
}

/// A user-facing failure: a translation key plus optional technical detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub key: &'static str,
    pub detail: String,
}

impl Failure {
    pub fn new(key: &'static str) -> Self {
        Self {
            key,
            detail: String::new(),
        }
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        let key = match &e {
            Error::ServerKeyChanged => "err.server_key_changed",
            Error::Http(409) => "err.taken",
            Error::Http(429) => "err.queue_full",
            Error::Http(403) => "err.rejected",
            Error::Http(_) | Error::Net(_) | Error::BadResponse => "err.network",
            Error::VaultDecrypt | Error::VaultFormat => "err.password",
            Error::InvalidUsername => "err.username",
            Error::InvalidEndpoint => "err.endpoint",
            Error::FrameTooLarge | Error::BadPadding => "err.too_long",
            _ => "err.generic",
        };
        Self {
            key,
            detail: e.to_string(),
        }
    }
}

/// A direct-type envelope that still has to be wrapped in a session frame. Wrapping advances
/// the ratchet, so it happens right before sending (after the vault is saved), not when the
/// message is composed.
#[derive(Clone)]
pub struct Draft {
    pub to: String,
    pub env: Envelope,
}

impl core::fmt::Debug for Draft {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Draft").field("to", &self.to).finish_non_exhaustive()
    }
}

/// A group or channel message that still has to be encrypted on our sender chain.
#[derive(Clone)]
pub struct ChainDraft {
    pub id: String,
    pub env: Envelope,
}

impl core::fmt::Debug for ChainDraft {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChainDraft").field("id", &self.id).finish_non_exhaustive()
    }
}

/// Something to post: a finished frame, a draft for a pairwise session, or a draft for a
/// sender chain.
#[derive(Debug, Clone)]
pub enum Sendable {
    Frame(Outbound),
    Draft(Draft),
    Chain(ChainDraft),
}

/// A sealed chain message and the key distributions that must reach members first.
pub struct ChainSeal {
    pub out: Outbound,
    pub chain_id: [u8; 16],
    pub skeys: Vec<Draft>,
}

impl core::fmt::Debug for ChainSeal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChainSeal")
            .field("skeys", &self.skeys.len())
            .finish_non_exhaustive()
    }
}

/// What a frame on a group or channel queue turned out to be.
pub enum ChainRx {
    Env(Box<Envelope>),
    /// No chain for it yet: keep it until the key arrives.
    Unknown,
    Bad,
}

impl core::fmt::Debug for ChainRx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ChainRx::Env(_) => "ChainRx::Env(..)",
            ChainRx::Unknown => "ChainRx::Unknown",
            ChainRx::Bad => "ChainRx::Bad",
        })
    }
}

/// Sender-key state of one group or channel.
#[derive(Default)]
pub struct Chains {
    pub send: Option<SendChain>,
    pub recv: Option<RecvSet>,
    pub given: Vec<String>,
    pub rotate: bool,
    pub held: Vec<String>,
}

impl core::fmt::Debug for Chains {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Chains")
            .field("sending", &self.send.is_some())
            .field("receiving", &self.recv.is_some())
            .field("given", &self.given.len())
            .field("held", &self.held.len())
            .finish_non_exhaustive()
    }
}

/// Why a draft could not be sealed yet.
#[derive(Debug)]
pub enum Need {
    /// There is no session: take the contact's prekeys and start one.
    Prekeys,
    Fail(Failure),
}

/// A frame ready to be posted.
#[derive(Clone)]
pub struct Outbound {
    pub queue: [u8; 32],
    pub padded: Vec<u8>,
}

impl core::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Outbound")
            .field("len", &self.padded.len())
            .finish()
    }
}

pub struct Session {
    pub data: Data,
    pub password: Zeroizing<String>,
    pub seen: SeenIds,
    pub store: SessionStore,
    pub chains: BTreeMap<String, Chains>,
    pub dirty: bool,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("username", &self.data.username)
            .finish_non_exhaustive()
    }
}

/// The built-in channel is always present. Its owner key is compiled in; a key that an older
/// version pinned from the directory is dropped.
fn ensure_official(data: &mut Data) {
    let id = aegis_core::official::official_channel_id();
    if let Some(c) = data.channels.get_mut(&id) {
        c.owner_ed = None;
        c.warn = false;
    }
    data.channels.entry(id.clone()).or_insert_with(|| Channel {
        id,
        g: Zeroizing::new(aegis_core::official::official_g()),
        title: "Aegis".to_owned(),
        about: String::new(),
        owner: aegis_core::official::OFFICIAL_OWNER.to_owned(),
        owner_ed: None,
        mine: false,
        official: true,
        subs: Vec::new(),
        cursor: 0,
        warn: false,
        chat: Chat::new(0),
    });
}

/// Core session code counts in seconds.
pub fn now_s() -> u64 {
    aegis_core::now_secs()
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl Session {
    pub fn new(mut data: Data, password: &str) -> Result<Self, Failure> {
        let mut store = if data.sessions.is_empty() {
            SessionStore::new()
        } else {
            SessionStore::decode(&data.sessions).map_err(|_| Failure::new("err.vault_format"))?
        };
        data.sessions = Zeroizing::default();
        let mut chains: BTreeMap<String, Chains> = BTreeMap::new();
        for (id, st) in std::mem::take(&mut data.skeys) {
            let bad = || Failure::new("err.vault_format");
            let send = if st.send.is_empty() {
                None
            } else {
                Some(SendChain::decode(&st.send).map_err(|_| bad())?)
            };
            let recv = if st.recv.is_empty() {
                None
            } else {
                Some(RecvSet::decode(&st.recv).map_err(|_| bad())?)
            };
            chains.insert(
                id,
                Chains {
                    send,
                    recv,
                    given: st.given,
                    rotate: st.rotate,
                    held: st.held,
                },
            );
        }
        for c in data.contacts.values() {
            if store.add_contact(&c.u, c.ed, c.x).is_err() {
                store.remove_contact(&c.u);
                let _ = store.add_contact(&c.u, c.ed, c.x);
            }
        }
        if *data.media_key == [0u8; 32] {
            if let Ok(k) = aegis_core::random_bytes::<32>() {
                data.media_key = Zeroizing::new(k);
            }
        }
        ensure_official(&mut data);
        for chat in data
            .dms
            .values_mut()
            .chain(data.groups.values_mut().map(|g| &mut g.chat))
            .chain(data.channels.values_mut().map(|c| &mut c.chat))
        {
            chat.unread = 0;
            for m in &mut chat.msgs {
                if m.state == MsgState::Sending {
                    m.state = MsgState::Failed;
                }
            }
        }
        let seen = SeenIds::from_ids(SEEN_CAP, std::mem::take(&mut data.seen));
        Ok(Self {
            data,
            password: Zeroizing::new(password.to_owned()),
            seen,
            store,
            chains,
            dirty: false,
        })
    }

    pub fn fresh(username: &str, display: &str, lang: Lang, password: &str) -> Result<Self, Failure> {
        let id = aegis_core::identity::Identity::generate()?;
        let data = Data {
            schema: crate::model::SCHEMA,
            username: username.to_owned(),
            display: display.to_owned(),
            x_sk: Zeroizing::new(*id.x_secret()),
            ed_sk: Zeroizing::new(*id.ed_secret()),
            settings: Settings::new(lang),
            contacts: Default::default(),
            dms: Default::default(),
            groups: Default::default(),
            seen: Vec::new(),
            inbox_cursor: 0,
            media_key: Zeroizing::new(aegis_core::random_bytes::<32>()?),
            about: String::new(),
            particles: "none".to_owned(),
            channels: Default::default(),
            pinned: Vec::new(),
            muted: Vec::new(),
            sessions: Zeroizing::default(),
            pending: Vec::new(),
            blocked: Vec::new(),
            deferred: Vec::new(),
            skeys: BTreeMap::new(),
            pin_verifier: String::new(),
        };
        Self::new(data, password)
    }

    /// Serialized form for the vault. The buffer is wiped on drop.
    pub fn snapshot(&mut self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        self.data.seen = self.seen.ids().cloned().collect();
        self.data.sessions = self.store.encode().map_err(|_| Failure::new("err.generic"))?;
        self.data.skeys = self
            .chains
            .iter()
            .filter(|(id, _)| self.data.groups.contains_key(*id) || self.data.channels.contains_key(*id))
            .map(|(id, c)| {
                let recv = c.recv.as_ref().map(RecvSet::encode).transpose().map_err(|_| Failure::new("err.generic"))?;
                Ok((
                    id.clone(),
                    SkeyState {
                        send: c.send.as_ref().map(SendChain::encode).unwrap_or_default(),
                        recv: recv.unwrap_or_default(),
                        given: c.given.clone(),
                        rotate: c.rotate,
                        held: c.held.clone(),
                    },
                ))
            })
            .collect::<Result<_, Failure>>()?;
        let out = serde_json::to_vec(&self.data).map_err(|_| Failure::new("err.generic"));
        self.data.seen.clear();
        self.data.sessions = Zeroizing::default();
        self.data.skeys.clear();
        out.map(Zeroizing::new)
    }

    pub fn x_public(&self) -> [u8; 32] {
        x25519_public(&self.data.x_sk)
    }

    pub fn ed_public(&self) -> [u8; 32] {
        ed25519_public(&self.data.ed_sk)
    }

    pub fn inbox(&self) -> [u8; 32] {
        inbox_queue(&self.x_public())
    }

    pub fn sweep(&mut self, now_ms: u64) -> bool {
        let mut changed = false;
        let chats = self
            .data
            .dms
            .values_mut()
            .chain(self.data.groups.values_mut().map(|g| &mut g.chat))
            .chain(self.data.channels.values_mut().map(|c| &mut c.chat));
        for chat in chats {
            let before = chat.msgs.len();
            chat.msgs.retain(|m| !m.expired(now_ms));
            changed |= chat.msgs.len() != before;
        }
        self.dirty |= changed;
        changed
    }

    pub fn chat_mut(&mut self, r: &ChatRef) -> Option<&mut Chat> {
        match r {
            ChatRef::Dm(u) => self.data.dms.get_mut(u),
            ChatRef::Group(id) => self.data.groups.get_mut(id).map(|g| &mut g.chat),
            ChatRef::Channel(id) => self.data.channels.get_mut(id).map(|c| &mut c.chat),
        }
    }

    pub fn chat(&self, r: &ChatRef) -> Option<&Chat> {
        match r {
            ChatRef::Dm(u) => self.data.dms.get(u),
            ChatRef::Group(id) => self.data.groups.get(id).map(|g| &g.chat),
            ChatRef::Channel(id) => self.data.channels.get(id).map(|c| &c.chat),
        }
    }

    pub fn identity(&self) -> Identity {
        Identity::from_secrets(*self.data.x_sk, *self.data.ed_sk)
    }

    /// Makes the session store hold exactly these keys for `u`; old sessions are dropped.
    fn pin_in_store(&mut self, u: &str, ed: [u8; 32], x: [u8; 32]) {
        if self.store.add_contact(u, ed, x).is_err() {
            self.store.remove_contact(u);
            let _ = self.store.add_contact(u, ed, x);
        }
        self.dirty = true;
    }

    /// Wraps a draft in a session frame. The caller saves the vault before posting it.
    pub fn seal_draft(&mut self, d: &Draft, now_s: u64) -> Result<Outbound, Need> {
        let me = self.identity();
        let cx = self
            .data
            .contacts
            .get(&d.to)
            .ok_or(Need::Fail(Failure::new("err.no_contact")))?
            .x;
        match self.store.encrypt(&me, &d.to, &d.env, now_s) {
            Ok(Encrypted::Frame(f)) => {
                self.dirty = true;
                let padded = pad::pad(&f).map_err(|e| Need::Fail(e.into()))?;
                Ok(Outbound {
                    queue: inbox_queue(&cx),
                    padded,
                })
            }
            Ok(Encrypted::NeedsPrekeys) => Err(Need::Prekeys),
            Err(e) => Err(Need::Fail(e.into())),
        }
    }

    /// Starts a session from a bundle taken from the server.
    pub fn begin_session(&mut self, to: &str, b: &Bundle, now_s: u64) -> Result<(), Failure> {
        let me = self.identity();
        self.store.start_session(&me, to, b, now_s)?;
        self.dirty = true;
        Ok(())
    }

    /// The signed `prekeys/put` request. Rotating the signed prekey or adding one-time
    /// prekeys changes the store: the caller saves the vault before uploading.
    pub fn prekey_request(
        &mut self,
        server_opks: Option<usize>,
        now_s: u64,
    ) -> Result<PrekeyPut, Failure> {
        let me = self.identity();
        let u = self.data.username.clone();
        let put = self.store.prepare_prekeys(&me, &u, now_s, server_opks)?;
        self.dirty = true;
        Ok(put)
    }

    /// Opens a type 0x03 frame. The ratchet state changes even when nothing is delivered.
    pub fn session_receive(&mut self, frame: &[u8], now_s: u64) -> Result<Received, Error> {
        let me = self.identity();
        let r = self.store.decrypt(&me, frame, now_s);
        self.dirty = true;
        r
    }

    pub fn defer_env(&mut self, kind: &str, contact: &str, env: &Envelope) {
        let Ok(b) = env.encode() else { return };
        let h = hex::encode(&b);
        if self.data.deferred.iter().any(|d| d.env == h) {
            return;
        }
        if self.data.deferred.len() >= MAX_DEFERRED {
            self.data.deferred.remove(0);
        }
        self.data.deferred.push(Deferred {
            kind: kind.to_owned(),
            contact: contact.to_owned(),
            env: h,
        });
        self.dirty = true;
    }

    pub fn take_deferred(&mut self) -> Vec<(String, String, Envelope)> {
        if self.data.deferred.is_empty() {
            return Vec::new();
        }
        self.dirty = true;
        std::mem::take(&mut self.data.deferred)
            .into_iter()
            .filter_map(|d| {
                let b = hex::decode(&d.env).ok()?;
                Some((d.kind, d.contact, Envelope::decode(&b).ok()?))
            })
            .collect()
    }

    /// Encrypts a group or channel message on our sender chain, starting or replacing the
    /// chain first when it is due. Members who do not have the chain yet get it through their
    /// pairwise session, before the message.
    pub fn seal_chain(&mut self, d: &ChainDraft, now_s: u64) -> Result<ChainSeal, Failure> {
        let me = self.data.username.clone();
        let (scope, g, recipients) = if let Some(gr) = self.data.groups.get(&d.id) {
            (
                Scope::Group,
                *gr.key,
                gr.members.iter().filter(|m| **m != me).cloned().collect::<Vec<_>>(),
            )
        } else if let Some(ch) = self.data.channels.get(&d.id) {
            if !ch.mine || ch.official {
                return Err(Failure::new("err.channel_readonly"));
            }
            (Scope::Channel, *ch.g, ch.subs.clone())
        } else {
            return Err(Failure::new("err.no_group"));
        };
        let queue = match scope {
            Scope::Group => group_queue(&g)?,
            Scope::Channel => channel_queue(&g)?,
        };
        let name = self.data.display.clone();
        let ed_pub = ed25519_public(&self.data.ed_sk);
        let entry = self.chains.entry(d.id.clone()).or_default();
        let due = entry.rotate;
        if entry.send.as_ref().is_none_or(|c| c.needs_rotation(now_s, due)) {
            entry.send = Some(SendChain::new(now_s)?);
            entry.given.clear();
            entry.rotate = false;
        }
        let Some(chain) = entry.send.as_mut() else {
            return Err(Failure::new("err.generic"));
        };
        let mut skeys = Vec::new();
        for m in recipients {
            if entry.given.contains(&m) || !self.data.contacts.contains_key(&m) {
                continue;
            }
            let env = chain.skey_envelope(&me, &name, ed_pub, &d.id, now_s.saturating_mul(1000))?;
            skeys.push(Draft { to: m, env });
        }
        let chain_id = chain.chain_id();
        let frame = chain.encrypt(scope, &g, &self.data.ed_sk, &d.env)?;
        self.dirty = true;
        Ok(ChainSeal {
            out: Outbound {
                queue,
                padded: pad::pad(&frame)?,
            },
            chain_id,
            skeys,
        })
    }

    /// Notes which members now hold the chain `chain_id` of `id`.
    pub fn mark_given(&mut self, id: &str, chain_id: [u8; 16], users: &[String]) {
        if let Some(c) = self.chains.get_mut(id) {
            if c.send.as_ref().is_some_and(|s| s.chain_id() == chain_id) {
                for u in users {
                    if !c.given.contains(u) {
                        c.given.push(u.clone());
                    }
                }
                self.dirty = true;
            }
        }
    }

    /// Takes a sender key that arrived through the pairwise session of `contact`.
    pub fn accept_skey(&mut self, contact: &str, env: &Envelope, now_s: u64) -> Result<(), Failure> {
        let pinned_ed = self.data.contacts.get(contact).map(|c| c.ed);
        if env.kind != Kind::Skey
            || env.sender != contact
            || pinned_ed != Some(env.sender_ed)
            || self.seen.contains(&env.msg_id)
        {
            return Err(Failure::new("err.generic"));
        }
        let (scope, g, owner_ed) = if let Some(gr) = self.data.groups.get(&env.group_id) {
            if !gr.members.iter().any(|m| m == contact) {
                return Err(Failure::new("err.generic"));
            }
            (Scope::Group, *gr.key, None)
        } else if let Some(ch) = self.data.channels.get(&env.group_id) {
            if ch.mine || ch.official || ch.owner != contact {
                return Err(Failure::new("err.generic"));
            }
            (Scope::Channel, *ch.g, ch.owner_ed)
        } else {
            return Err(Failure::new("err.generic"));
        };
        let entry = self.chains.entry(env.group_id.clone()).or_default();
        if entry.recv.is_none() {
            entry.recv = Some(RecvSet::new(scope, &g, owner_ed)?);
        }
        if let Some(rs) = entry.recv.as_mut() {
            rs.add_from_skey(env, now_s)?;
        }
        self.seen.insert(&env.msg_id);
        self.dirty = true;
        Ok(())
    }

    /// Opens a type 0x05 frame of group or channel `id`.
    pub fn chain_decrypt(&mut self, id: &str, frame: &[u8], now_s: u64) -> ChainRx {
        let Some(rs) = self.chains.get_mut(id).and_then(|c| c.recv.as_mut()) else {
            return ChainRx::Unknown;
        };
        match rs.decrypt(frame, now_s) {
            Ok(e) => {
                self.dirty = true;
                ChainRx::Env(Box::new(e))
            }
            Err(Error::Session("unknown chain")) => ChainRx::Unknown,
            Err(_) => ChainRx::Bad,
        }
    }

    /// Keeps a frame until its sender key arrives.
    pub fn hold_frame(&mut self, id: &str, frame: &[u8]) {
        if !self.data.groups.contains_key(id) && !self.data.channels.contains_key(id) {
            return;
        }
        let e = self.chains.entry(id.to_owned()).or_default();
        let h = hex::encode(frame);
        if e.held.contains(&h) {
            return;
        }
        if e.held.len() >= MAX_HELD {
            e.held.remove(0);
        }
        e.held.push(h);
        self.dirty = true;
    }

    pub fn take_held(&mut self, id: &str) -> Vec<Vec<u8>> {
        let Some(e) = self.chains.get_mut(id) else {
            return Vec::new();
        };
        if e.held.is_empty() {
            return Vec::new();
        }
        self.dirty = true;
        std::mem::take(&mut e.held)
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .collect()
    }

    pub fn is_blocked(&self, x: &[u8; 32]) -> bool {
        let h = hex::encode(x);
        self.data.blocked.contains(&h)
    }

    /// Keeps a frame from an unknown key until the user decides.
    pub fn add_pending(&mut self, x: [u8; 32], frame: &[u8], now_ms: u64) {
        let h = hex::encode(frame);
        if let Some(p) = self.data.pending.iter_mut().find(|p| p.x == x) {
            if !p.frames.contains(&h) {
                p.frames.push(h);
                if p.frames.len() > MAX_PENDING_FRAMES {
                    p.frames.remove(0);
                }
            }
        } else {
            if self.data.pending.len() >= MAX_PENDING {
                self.data.pending.remove(0);
            }
            self.data.pending.push(Pending {
                x,
                first_ms: now_ms,
                frames: vec![h],
            });
        }
        self.dirty = true;
    }

    pub fn take_pending(&mut self, x: &[u8; 32]) -> Option<Pending> {
        let i = self.data.pending.iter().position(|p| p.x == *x)?;
        self.dirty = true;
        Some(self.data.pending.remove(i))
    }

    pub fn block_key(&mut self, x: [u8; 32]) {
        let _ = self.take_pending(&x);
        let h = hex::encode(&x);
        if !self.data.blocked.contains(&h) {
            self.data.blocked.push(h);
            if self.data.blocked.len() > MAX_BLOCKED {
                self.data.blocked.remove(0);
            }
        }
        self.dirty = true;
    }

    /// Adds the "could not be decrypted" line to a chat, once in a row.
    pub fn note_undecryptable(&mut self, contact: &str, now_ms: u64) -> Outcome {
        let Ok(id) = random_msg_id() else {
            return Outcome::Dropped;
        };
        let Some(chat) = self.data.dms.get_mut(contact) else {
            return Outcome::Dropped;
        };
        if chat.msgs.last().is_some_and(|m| m.text == UNDECRYPTABLE) {
            return Outcome::Dropped;
        }
        chat.unread = chat.unread.saturating_add(1);
        chat.push(Msg {
            id,
            from: contact.to_owned(),
            ts_ms: now_ms,
            ttl_s: 0,
            text: UNDECRYPTABLE.to_owned(),
            out: false,
            state: MsgState::Sent,
            media: None,
            base_ms: now_ms,
        });
        self.dirty = true;
        Outcome::Added(ChatRef::Dm(contact.to_owned()))
    }

    pub fn add_contact(&mut self, e: &DirEntry, now_ms: u64) {
        self.pin_in_store(&e.u, e.ed, e.x);
        let name = sanitize_display_text(&e.title);
        self.data.contacts.insert(
            e.u.clone(),
            Contact {
                u: e.u.clone(),
                name,
                x: e.x,
                ed: e.ed,
                verified: false,
                changed: None,
                about: String::new(),
                particles: "none".to_owned(),
            },
        );
        self.data
            .dms
            .entry(e.u.clone())
            .or_insert_with(|| Chat::new(now_ms));
        self.dirty = true;
    }

    fn flag_changed(&mut self, sender: &str, ch: Changed) {
        if let Some(c) = self.data.contacts.get_mut(sender) {
            let keep = matches!(&c.changed, Some(old) if old.via_dm && !ch.via_dm);
            if !keep {
                c.changed = Some(ch);
            }
        }
        self.dirty = true;
    }

    /// Applies a `dm` or `ginv` that was opened with the sealed sender key `sender_x`.
    /// `dir` is the directory entry for a sender that is not a contact yet.
    pub fn accept_inbox(
        &mut self,
        env: Envelope,
        sender_x: [u8; 32],
        dir: Option<&DirEntry>,
        media: Option<MediaRef>,
        now_ms: u64,
    ) -> Outcome {
        if self.seen.contains(&env.msg_id) || env.sender == self.data.username {
            return Outcome::Dropped;
        }
        if !matches!(
            env.kind,
            Kind::Dm | Kind::Dmf | Kind::Ginv | Kind::Cinv | Kind::Prof | Kind::Ttl
        ) || (env.kind == Kind::Dmf) != media.is_some()
        {
            return Outcome::Dropped;
        }
        let sender = env.sender.clone();
        if !self.data.contacts.contains_key(&sender) {
            let Some(e) = dir else {
                return Outcome::Dropped;
            };
            if e.u != sender || e.x != sender_x || e.ed != env.sender_ed {
                return Outcome::Dropped;
            }
            self.add_contact(e, now_ms);
        }
        let Some(c) = self.data.contacts.get(&sender) else {
            return Outcome::Dropped;
        };
        let pinned = PinnedKeys {
            x_pk: c.x,
            ed_pk: c.ed,
        };
        if check_pinned_dm(&env, &sender_x, &pinned).is_err() {
            self.seen.insert(&env.msg_id);
            let x = (sender_x != pinned.x_pk).then_some(sender_x);
            self.flag_changed(
                &sender,
                Changed {
                    x,
                    ed: env.sender_ed,
                    via_dm: true,
                },
            );
            return Outcome::KeyChanged(sender);
        }
        self.seen.insert(&env.msg_id);
        self.dirty = true;
        let name = sanitize_display_text(&env.sender_name);
        if let Some(c) = self.data.contacts.get_mut(&sender) {
            if !name.is_empty() {
                c.name = name;
            }
        }
        match env.kind {
            Kind::Prof => self.accept_profile(&sender, &env),
            Kind::Cinv => self.accept_channel_invite(env, now_ms),
            Kind::Ttl => self.accept_ttl(ChatRef::Dm(sender), &env, now_ms),
            Kind::Dm | Kind::Dmf => {
                let text = env.body.clone();
                let chat = self
                    .data
                    .dms
                    .entry(sender.clone())
                    .or_insert_with(|| Chat::new(now_ms));
                chat.unread = chat.unread.saturating_add(1);
                chat.push(Msg {
                    id: env.msg_id,
                    from: sender.clone(),
                    ts_ms: env.ts_ms,
                    ttl_s: env.ttl_s,
                    text: clean_text(&text),
                    out: false,
                    state: MsgState::Sent,
                    media,
                    base_ms: now_ms,
                });
                Outcome::Added(ChatRef::Dm(sender))
            }
            _ => self.accept_invite(env, now_ms),
        }
    }

    fn accept_profile(&mut self, sender: &str, env: &Envelope) -> Outcome {
        let Ok(p) = Profile::parse(&env.body) else {
            return Outcome::Dropped;
        };
        let Some(c) = self.data.contacts.get_mut(sender) else {
            return Outcome::Dropped;
        };
        let name = sanitize_display_text(&p.name);
        if !name.is_empty() {
            c.name = name;
        }
        c.about = clean_text(&p.about);
        c.particles = p.particles.as_str().to_owned();
        self.dirty = true;
        Outcome::Profile(sender.to_owned())
    }

    fn accept_channel_invite(&mut self, env: Envelope, now_ms: u64) -> Outcome {
        let Some(g) = env.group_key.clone() else {
            return Outcome::Dropped;
        };
        if channel_id(&g) != env.group_id
            || self.data.channels.contains_key(&env.group_id)
            || self.data.channels.values().filter(|c| !c.official).count() >= 500
        {
            return Outcome::Dropped;
        }
        let mut title = sanitize_display_text(&env.body);
        if title.is_empty() {
            title = env.group_id.chars().take(8).collect();
        }
        let id = env.group_id.clone();
        self.data.channels.insert(
            id.clone(),
            Channel {
                id: id.clone(),
                g,
                title,
                about: String::new(),
                owner: env.sender,
                owner_ed: Some(env.sender_ed),
                mine: false,
                official: false,
                subs: Vec::new(),
                cursor: 0,
                warn: false,
                chat: Chat::new(now_ms),
            },
        );
        self.dirty = true;
        Outcome::ChannelJoined(id)
    }

    /// Applies a verified `cmsg` or `cmf` from channel `cid`.
    pub fn accept_channel_post(
        &mut self,
        cid: &str,
        env: Envelope,
        media: Option<MediaRef>,
        now_ms: u64,
    ) -> Outcome {
        let Some(ch) = self.data.channels.get(cid) else {
            return Outcome::Dropped;
        };
        if !matches!(env.kind, Kind::Cmsg | Kind::Cmf)
            || (env.kind == Kind::Cmf) != media.is_some()
            || env.group_id != ch.id
            || env.sender != ch.owner
            || ch.mine
            || self.seen.contains(&env.msg_id)
        {
            return Outcome::Dropped;
        }
        self.seen.insert(&env.msg_id);
        self.dirty = true;
        let Some(ch) = self.data.channels.get_mut(cid) else {
            return Outcome::Dropped;
        };
        ch.chat.unread = ch.chat.unread.saturating_add(1);
        ch.chat.push(Msg {
            id: env.msg_id,
            from: env.sender,
            ts_ms: env.ts_ms,
            ttl_s: env.ttl_s,
            text: clean_text(&env.body),
            out: false,
            state: MsgState::Sent,
            media,
            base_ms: now_ms,
        });
        Outcome::Added(ChatRef::Channel(cid.to_owned()))
    }

    fn accept_invite(&mut self, env: Envelope, now_ms: u64) -> Outcome {
        let Some(key) = env.group_key.clone() else {
            return Outcome::Dropped;
        };
        if !env.members.contains(&self.data.username) || !env.members.contains(&env.sender) {
            return Outcome::Dropped;
        }
        if self.data.groups.contains_key(&env.group_id) {
            return Outcome::Dropped;
        }
        let mut title = sanitize_display_text(&env.body);
        if title.is_empty() {
            title = env.group_id.chars().take(8).collect();
        }
        let id = env.group_id.clone();
        self.data.groups.insert(
            id.clone(),
            Group {
                id: id.clone(),
                key,
                title,
                creator: env.sender,
                members: env.members,
                cursor: 0,
                chat: Chat::new(now_ms),
            },
        );
        self.dirty = true;
        Outcome::GroupJoined(id)
    }

    /// Applies a decrypted and signature-checked `gmsg` from group `gid`.
    pub fn accept_group_msg(
        &mut self,
        gid: &str,
        env: Envelope,
        dir: Option<&DirEntry>,
        media: Option<MediaRef>,
        now_ms: u64,
    ) -> Outcome {
        let Some(g) = self.data.groups.get(gid) else {
            return Outcome::Dropped;
        };
        if !matches!(env.kind, Kind::Gmsg | Kind::Gmf | Kind::Gttl)
            || (env.kind == Kind::Gmf) != media.is_some()
            || env.group_id != g.id
            || env.sender == self.data.username
            || !g.members.contains(&env.sender)
            || self.seen.contains(&env.msg_id)
        {
            return Outcome::Dropped;
        }
        let sender = env.sender.clone();
        if !self.data.contacts.contains_key(&sender) {
            let Some(e) = dir else {
                return Outcome::Dropped;
            };
            if e.u != sender || e.ed != env.sender_ed {
                return Outcome::Dropped;
            }
            self.add_contact(e, now_ms);
        }
        let Some(c) = self.data.contacts.get(&sender) else {
            return Outcome::Dropped;
        };
        let pinned = PinnedKeys {
            x_pk: c.x,
            ed_pk: c.ed,
        };
        if check_pinned_group(&env, &pinned).is_err() {
            self.seen.insert(&env.msg_id);
            self.flag_changed(
                &sender,
                Changed {
                    x: None,
                    ed: env.sender_ed,
                    via_dm: false,
                },
            );
            return Outcome::KeyChanged(sender);
        }
        self.seen.insert(&env.msg_id);
        self.dirty = true;
        if env.kind == Kind::Gttl {
            return self.accept_ttl(ChatRef::Group(gid.to_owned()), &env, now_ms);
        }
        let Some(g) = self.data.groups.get_mut(gid) else {
            return Outcome::Dropped;
        };
        g.chat.unread = g.chat.unread.saturating_add(1);
        g.chat.push(Msg {
            id: env.msg_id,
            from: sender,
            ts_ms: env.ts_ms,
            ttl_s: env.ttl_s,
            text: clean_text(&env.body),
            out: false,
            state: MsgState::Sent,
            media,
            base_ms: now_ms,
        });
        Outcome::Added(ChatRef::Group(gid.to_owned()))
    }

    pub(crate) fn own_envelope(&self, kind: Kind, id: String, ts_ms: u64, ttl_s: u64) -> Envelope {
        Envelope {
            kind,
            msg_id: id,
            sender: self.data.username.clone(),
            sender_name: self.data.display.clone(),
            sender_ed: self.ed_public(),
            ts_ms,
            ttl_s,
            group_id: String::new(),
            body: String::new(),
            group_key: None,
            members: Vec::new(),
        }
    }

    fn prepare_text(text: &str) -> Result<String, Failure> {
        let t = clean_text(text);
        let t = t.trim();
        if t.is_empty() {
            return Err(Failure::new("err.empty"));
        }
        Ok(t.to_owned())
    }

    /// Builds the frame for a direct message and records it as "sending".
    /// `retry_id` re-sends an existing failed message under the same id.
    pub fn prepare_dm(
        &mut self,
        to: &str,
        text: &str,
        retry_id: Option<&str>,
        now_ms: u64,
    ) -> Result<(String, Sendable), Failure> {
        let p = Payload::Text(text.to_owned());
        self.prepare_send(&ChatRef::Dm(to.to_owned()), p, retry_id, now_ms)
    }

    pub fn prepare_group_msg(
        &mut self,
        gid: &str,
        text: &str,
        retry_id: Option<&str>,
        now_ms: u64,
    ) -> Result<(String, Sendable), Failure> {
        let p = Payload::Text(text.to_owned());
        self.prepare_send(&ChatRef::Group(gid.to_owned()), p, retry_id, now_ms)
    }

    /// Builds the frame for a message in any kind of chat and records it as "sending".
    pub fn prepare_send(
        &mut self,
        r: &ChatRef,
        payload: Payload,
        retry_id: Option<&str>,
        now_ms: u64,
    ) -> Result<(String, Sendable), Failure> {
        let (body, text, media) = match payload {
            Payload::Text(t) => {
                let t = Self::prepare_text(&t)?;
                (t.clone(), t, None)
            }
            Payload::Media {
                body,
                caption,
                media,
            } => (body, clean_text(&caption), Some(media)),
        };
        let is_media = media.is_some();
        let id = match retry_id {
            Some(i) => i.to_owned(),
            None => random_msg_id()?,
        };
        let (out, ttl) = match r {
            ChatRef::Dm(to) => {
                let c = self
                    .data
                    .contacts
                    .get(to)
                    .ok_or(Failure::new("err.no_contact"))?;
                let ttl = self.data.dms.get(to).map_or(0, |c| c.ttl_s);
                let to = c.u.clone();
                let kind = if is_media { Kind::Dmf } else { Kind::Dm };
                let mut env = self.own_envelope(kind, id.clone(), now_ms, ttl);
                env.body = body;
                (Sendable::Draft(Draft { to, env }), ttl)
            }
            ChatRef::Group(gid) => {
                let g = self
                    .data
                    .groups
                    .get(gid)
                    .ok_or(Failure::new("err.no_group"))?;
                let ttl = g.chat.ttl_s;
                let kind = if is_media { Kind::Gmf } else { Kind::Gmsg };
                let mut env = self.own_envelope(kind, id.clone(), now_ms, ttl);
                env.group_id = gid.clone();
                env.body = body;
                (
                    Sendable::Chain(ChainDraft {
                        id: gid.clone(),
                        env,
                    }),
                    ttl,
                )
            }
            ChatRef::Channel(cid) => {
                let ch = self
                    .data
                    .channels
                    .get(cid)
                    .ok_or(Failure::new("err.no_channel"))?;
                if !ch.mine {
                    return Err(Failure::new("err.channel_readonly"));
                }
                if ch.official {
                    return Err(Failure::new("err.channel_readonly"));
                }
                let ttl = ch.chat.ttl_s;
                let kind = if is_media { Kind::Cmf } else { Kind::Cmsg };
                let mut env = self.own_envelope(kind, id.clone(), now_ms, ttl);
                env.group_id = cid.clone();
                env.body = body;
                (
                    Sendable::Chain(ChainDraft {
                        id: cid.clone(),
                        env,
                    }),
                    ttl,
                )
            }
        };
        self.record_sent(r, id.clone(), text, media, ttl, now_ms);
        Ok((id, out))
    }

    fn record_sent(
        &mut self,
        r: &ChatRef,
        id: String,
        text: String,
        media: Option<MediaRef>,
        ttl_s: u64,
        now_ms: u64,
    ) {
        self.seen.insert(&id);
        let me = self.data.username.clone();
        if let Some(chat) = self.chat_mut(r) {
            chat.msgs.retain(|m| m.id != id);
            chat.push(Msg {
                id,
                from: me,
                ts_ms: now_ms,
                ttl_s,
                text,
                out: true,
                state: MsgState::Sending,
                media,
                base_ms: now_ms,
            });
        }
        self.dirty = true;
    }

    pub fn set_msg_state(&mut self, r: &ChatRef, id: &str, st: MsgState) {
        if let Some(m) = self
            .chat_mut(r)
            .and_then(|c| c.msgs.iter_mut().find(|m| m.id == id))
        {
            m.state = st;
            self.dirty = true;
        }
    }

    pub fn failed_text(&self, r: &ChatRef, id: &str) -> Option<String> {
        self.chat(r)?
            .msgs
            .iter()
            .find(|m| m.id == id && m.out && m.state == MsgState::Failed && m.media.is_none())
            .map(|m| m.text.clone())
    }

    /// Creates a group locally and returns one invite frame per member.
    pub fn prepare_group(
        &mut self,
        title: &str,
        members: &[String],
        now_ms: u64,
    ) -> Result<(String, Vec<(String, Draft)>), Failure> {
        let title = sanitize_display_text(title.trim());
        if title.is_empty() {
            return Err(Failure::new("err.group_title"));
        }
        let mut chosen: Vec<String> = Vec::new();
        for m in members {
            if !self.data.contacts.contains_key(m) {
                return Err(Failure::new("err.no_contact"));
            }
            if !chosen.contains(m) {
                chosen.push(m.clone());
            }
        }
        if chosen.is_empty() {
            return Err(Failure::new("err.group_members"));
        }
        if chosen.len() + 1 > MAX_MEMBERS {
            return Err(Failure::new("err.group_big"));
        }
        let key = new_group_secret()?;
        let id = group_id(&key);
        let mut all = vec![self.data.username.clone()];
        all.extend(chosen.iter().cloned());
        let group = Group {
            id: id.clone(),
            key,
            title,
            creator: self.data.username.clone(),
            members: all,
            cursor: 0,
            chat: Chat::new(now_ms),
        };
        self.data.groups.insert(id.clone(), group);
        self.dirty = true;
        let mut out = Vec::new();
        for m in chosen {
            let frame = self.invite_frame(&id, &m, now_ms)?;
            out.push((m, frame));
        }
        Ok((id, out))
    }

    pub fn invite_frame(&self, gid: &str, member: &str, now_ms: u64) -> Result<Draft, Failure> {
        let g = self
            .data
            .groups
            .get(gid)
            .ok_or(Failure::new("err.no_group"))?;
        let c = self
            .data
            .contacts
            .get(member)
            .ok_or(Failure::new("err.no_contact"))?;
        let mut env = self.own_envelope(Kind::Ginv, random_msg_id()?, now_ms, 0);
        env.group_id = g.id.clone();
        env.body = g.title.clone();
        env.group_key = Some(g.key.clone());
        env.members = g.members.clone();
        Ok(Draft {
            to: c.u.clone(),
            env,
        })
    }

    pub fn set_verified(&mut self, u: &str, on: bool) {
        if let Some(c) = self.data.contacts.get_mut(u) {
            c.verified = on;
            self.dirty = true;
        }
    }

    /// Pins the keys offered in a direct message. Only possible for authenticated offers.
    pub fn accept_new_keys(&mut self, u: &str) -> bool {
        let Some(c) = self.data.contacts.get_mut(u) else {
            return false;
        };
        match c.changed.take() {
            Some(ch) if ch.via_dm => {
                if let Some(x) = ch.x {
                    c.x = x;
                }
                c.ed = ch.ed;
                c.verified = false;
                let (ed, x) = (c.ed, c.x);
                self.pin_in_store(u, ed, x);
                self.forget_given(u, false);
                true
            }
            other => {
                c.changed = other;
                false
            }
        }
    }

    pub fn dismiss_warning(&mut self, u: &str) {
        if let Some(c) = self.data.contacts.get_mut(u) {
            c.changed = None;
            self.dirty = true;
        }
    }

    pub fn delete_contact_chat(&mut self, u: &str) {
        self.data.dms.remove(u);
        self.data.contacts.remove(u);
        self.store.remove_contact(u);
        self.forget_given(u, true);
        self.dirty = true;
    }

    /// `u` no longer holds our sending chains. With `rotate`, every chain they were given is
    /// replaced before the next message.
    fn forget_given(&mut self, u: &str, rotate: bool) {
        for c in self.chains.values_mut() {
            if c.given.iter().any(|m| m == u) {
                c.given.retain(|m| m != u);
                c.rotate |= rotate;
            }
        }
    }

    pub fn leave_group(&mut self, gid: &str) {
        self.data.groups.remove(gid);
        self.chains.remove(gid);
        self.dirty = true;
    }

    pub fn mark_read(&mut self, r: &ChatRef) {
        if let Some(c) = self.chat_mut(r) {
            if c.unread != 0 {
                c.unread = 0;
                self.dirty = true;
            }
        }
    }

    /// Creates a channel owned by this account. Returns its id.
    pub fn create_channel(
        &mut self,
        title: &str,
        about: &str,
        now_ms: u64,
    ) -> Result<String, Failure> {
        let title = sanitize_display_text(title.trim());
        if title.is_empty() || title.chars().count() > 64 {
            return Err(Failure::new("err.channel_title"));
        }
        let about = one_line(about);
        if about.chars().count() > MAX_ABOUT {
            return Err(Failure::new("err.about_long"));
        }
        let g = new_channel_secret()?;
        let id = channel_id(&g);
        self.data.channels.insert(
            id.clone(),
            Channel {
                id: id.clone(),
                g,
                title,
                about,
                owner: self.data.username.clone(),
                owner_ed: Some(self.ed_public()),
                mine: true,
                official: false,
                subs: Vec::new(),
                cursor: 0,
                warn: false,
                chat: Chat::new(now_ms),
            },
        );
        self.dirty = true;
        Ok(id)
    }

    /// Adds contacts as subscribers and returns one `cinv` frame for each of them.
    pub fn channel_invites(
        &mut self,
        cid: &str,
        members: &[String],
        now_ms: u64,
    ) -> Result<Vec<(String, Draft)>, Failure> {
        let ch = self
            .data
            .channels
            .get(cid)
            .ok_or(Failure::new("err.no_channel"))?;
        if !ch.mine {
            return Err(Failure::new("err.channel_readonly"));
        }
        let mut chosen: Vec<String> = Vec::new();
        for m in members {
            if !self.data.contacts.contains_key(m) {
                return Err(Failure::new("err.no_contact"));
            }
            if !chosen.contains(m) {
                chosen.push(m.clone());
            }
        }
        let fresh = chosen.iter().filter(|m| !ch.subs.contains(m)).count();
        if ch.subs.len() + fresh > MAX_SUBSCRIBERS {
            return Err(Failure::new("err.channel_big"));
        }
        let mut out = Vec::new();
        for m in chosen {
            let frame = self.channel_invite_frame(cid, &m, now_ms)?;
            out.push((m, frame));
        }
        if let Some(ch) = self.data.channels.get_mut(cid) {
            for (m, _) in &out {
                if !ch.subs.contains(m) {
                    ch.subs.push(m.clone());
                }
            }
        }
        self.dirty = true;
        Ok(out)
    }

    pub fn channel_invite_frame(
        &self,
        cid: &str,
        member: &str,
        now_ms: u64,
    ) -> Result<Draft, Failure> {
        let ch = self
            .data
            .channels
            .get(cid)
            .ok_or(Failure::new("err.no_channel"))?;
        let c = self
            .data
            .contacts
            .get(member)
            .ok_or(Failure::new("err.no_contact"))?;
        let mut env = self.own_envelope(Kind::Cinv, random_msg_id()?, now_ms, 0);
        env.group_id = ch.id.clone();
        env.body = ch.title.clone();
        env.group_key = Some(ch.g.clone());
        Ok(Draft {
            to: c.u.clone(),
            env,
        })
    }

    pub fn leave_channel(&mut self, cid: &str) {
        if self.data.channels.get(cid).is_some_and(|c| !c.official) {
            self.data.channels.remove(cid);
            self.chains.remove(cid);
            self.dirty = true;
        }
    }

    pub fn set_profile(&mut self, about: &str, particles: &str) -> Result<(), Failure> {
        let about = one_line(about);
        if about.chars().count() > MAX_ABOUT {
            return Err(Failure::new("err.about_long"));
        }
        let p = Particles::parse(particles).map_err(|_| Failure::new("err.generic"))?;
        self.data.about = about;
        self.data.particles = p.as_str().to_owned();
        self.dirty = true;
        Ok(())
    }

    /// A `prof` card for one contact.
    pub fn profile_frame(&self, to: &str, now_ms: u64) -> Result<Draft, Failure> {
        let c = self
            .data
            .contacts
            .get(to)
            .ok_or(Failure::new("err.no_contact"))?;
        let card = Profile {
            name: self.data.display.clone(),
            about: self.data.about.clone(),
            particles: Particles::parse(&self.data.particles).unwrap_or(Particles::None),
        };
        let mut env = self.own_envelope(Kind::Prof, random_msg_id()?, now_ms, 0);
        env.body = card.encode()?;
        Ok(Draft {
            to: c.u.clone(),
            env,
        })
    }

    pub fn is_pinned(&self, r: &ChatRef) -> bool {
        let official = matches!(r, ChatRef::Channel(id)
            if self.data.channels.get(id).is_some_and(|c| c.official));
        official || self.data.pinned.contains(&r.key())
    }

    pub fn is_muted(&self, r: &ChatRef) -> bool {
        self.data.muted.contains(&r.key())
    }

    pub fn toggle_pin(&mut self, r: &ChatRef) {
        toggle(&mut self.data.pinned, r.key());
        self.dirty = true;
    }

    pub fn toggle_mute(&mut self, r: &ChatRef) {
        toggle(&mut self.data.muted, r.key());
        self.dirty = true;
    }

    pub fn clear_history(&mut self, r: &ChatRef) {
        if let Some(c) = self.chat_mut(r) {
            c.msgs.clear();
            c.unread = 0;
            self.dirty = true;
        }
    }

    /// Names of the media files that messages still point to.
    pub fn media_files(&self) -> std::collections::HashSet<String> {
        let chats = self
            .data
            .dms
            .values()
            .chain(self.data.groups.values().map(|g| &g.chat))
            .chain(self.data.channels.values().map(|c| &c.chat));
        chats
            .flat_map(|c| c.msgs.iter())
            .filter_map(|m| m.media.as_ref().map(|r| r.file.clone()))
            .collect()
    }

    /// Cheap check before downloading an attachment from an inbox frame.
    pub fn inbox_plausible(
        &self,
        env: &Envelope,
        sender_x: [u8; 32],
        dir: Option<&DirEntry>,
    ) -> bool {
        match self.data.contacts.get(&env.sender) {
            Some(c) => check_pinned_dm(
                env,
                &sender_x,
                &PinnedKeys {
                    x_pk: c.x,
                    ed_pk: c.ed,
                },
            )
            .is_ok(),
            None => {
                dir.is_some_and(|e| e.u == env.sender && e.x == sender_x && e.ed == env.sender_ed)
            }
        }
    }

    /// Same for a group frame.
    pub fn group_plausible(&self, env: &Envelope, dir: Option<&DirEntry>) -> bool {
        match self.data.contacts.get(&env.sender) {
            Some(c) => check_pinned_group(
                env,
                &PinnedKeys {
                    x_pk: c.x,
                    ed_pk: c.ed,
                },
            )
            .is_ok(),
            None => dir.is_some_and(|e| e.u == env.sender && e.ed == env.sender_ed),
        }
    }

    pub fn safety_number(&self, u: &str) -> Option<String> {
        let c = self.data.contacts.get(u)?;
        Some(aegis_core::identity::safety_number(
            (&self.ed_public(), &self.x_public()),
            (&c.ed, &c.x),
        ))
    }
}

fn toggle(v: &mut Vec<String>, k: String) {
    if let Some(i) = v.iter().position(|x| *x == k) {
        v.remove(i);
    } else {
        v.push(k);
    }
}

fn one_line(s: &str) -> String {
    clean_text(s)
        .chars()
        .map(|c| if c == '\n' { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn entry(u: &str, n: u8) -> DirEntry {
        DirEntry {
            u: u.to_owned(),
            title: u.to_owned(),
            x: [n; 32],
            ed: [n + 100; 32],
        }
    }

    fn session() -> Session {
        Session::fresh("alice", "Alice", Lang::En, "pw-pw-pw-pw-pw").expect("session")
    }

    #[test]
    fn session_store_survives_a_vault_round_trip() {
        let mut s = session();
        s.add_contact(&entry("bob", 1), 1);
        assert!(s.data.sessions.is_empty(), "store is only written by snapshot");
        let plain = s.snapshot().expect("snapshot");
        assert!(s.data.sessions.is_empty());
        let data: Data = serde_json::from_slice(&plain).expect("json");
        assert!(!data.sessions.is_empty());
        let again = Session::new(data, "pw-pw-pw-pw-pw").expect("reopen");
        assert!(again.data.contacts.contains_key("bob"));
        assert!(again.store.encode().unwrap().len() > 4);
    }

    #[test]
    fn corrupt_store_is_an_error_not_a_fresh_store() {
        let mut s = session();
        let plain = s.snapshot().expect("snapshot");
        let mut data: Data = serde_json::from_slice(&plain).expect("json");
        data.sessions = Zeroizing::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(Session::new(data, "pw-pw-pw-pw-pw").is_err());
    }

    #[test]
    fn requests_are_capped_and_blocking_removes_them() {
        let mut s = session();
        for i in 0..(MAX_PENDING as u8 + 5) {
            s.add_pending([i; 32], &[0x03, i], 1);
        }
        assert_eq!(s.data.pending.len(), MAX_PENDING);
        let x = [(MAX_PENDING as u8) + 4; 32];
        for k in 0..10u8 {
            s.add_pending(x, &[0x03, 200, k], 2);
        }
        let p = s.data.pending.iter().find(|p| p.x == x).expect("pending");
        assert_eq!(p.frames.len(), MAX_PENDING_FRAMES);
        s.block_key(x);
        assert!(s.is_blocked(&x));
        assert!(s.data.pending.iter().all(|p| p.x != x));
    }

    #[test]
    fn undecryptable_notice_is_not_repeated() {
        let mut s = session();
        s.add_contact(&entry("bob", 1), 1);
        assert!(matches!(s.note_undecryptable("bob", 5), Outcome::Added(_)));
        assert!(matches!(s.note_undecryptable("bob", 6), Outcome::Dropped));
        assert!(matches!(s.note_undecryptable("nobody", 6), Outcome::Dropped));
        let last = s.data.dms["bob"].msgs.last().expect("msg");
        assert_eq!(last.text, UNDECRYPTABLE);
    }

    #[test]
    fn direct_messages_become_drafts_and_need_a_session() {
        let mut s = session();
        s.add_contact(&entry("bob", 1), 1);
        let (_, out) = s
            .prepare_send(
                &ChatRef::Dm("bob".into()),
                Payload::Text("hi".into()),
                None,
                1000,
            )
            .expect("prepare");
        let Sendable::Draft(d) = out else {
            panic!("a direct message must not be sealed on the legacy path");
        };
        assert!(matches!(s.seal_draft(&d, 1), Err(Need::Prekeys)));
    }

    #[test]
    fn deferred_messages_round_trip() {
        let mut s = session();
        s.add_contact(&entry("bob", 1), 1);
        let (_, out) = s
            .prepare_send(
                &ChatRef::Dm("bob".into()),
                Payload::Text("hi".into()),
                None,
                1000,
            )
            .expect("prepare");
        let Sendable::Draft(d) = out else { panic!() };
        s.defer_env("", "bob", &d.env);
        s.defer_env("", "bob", &d.env);
        assert_eq!(s.data.deferred.len(), 1);
        let list = s.take_deferred();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].2.msg_id, d.env.msg_id);
        assert!(s.data.deferred.is_empty());
    }


    fn gid() -> String {
        aegis_core::group::group_id(&[7; 32])
    }

    fn pair() -> (Session, Session) {
        let mut a = Session::fresh("alice", "Alice", Lang::En, "pw-pw-pw-pw-pw").expect("a");
        let mut b = Session::fresh("bob", "Bob", Lang::En, "pw-pw-pw-pw-pw").expect("b");
        let ea = DirEntry { u: "alice".into(), title: "A".into(), x: a.x_public(), ed: a.ed_public() };
        let eb = DirEntry { u: "bob".into(), title: "B".into(), x: b.x_public(), ed: b.ed_public() };
        a.add_contact(&eb, 1);
        b.add_contact(&ea, 1);
        for s in [&mut a, &mut b] {
            s.data.groups.insert(
                gid(),
                Group {
                    id: gid(),
                    key: Zeroizing::new([7; 32]),
                    title: "t".into(),
                    creator: "alice".into(),
                    members: vec!["alice".into(), "bob".into()],
                    cursor: 0,
                    chat: Chat::new(1),
                },
            );
        }
        (a, b)
    }

    fn chain_draft(s: &mut Session, text: &str) -> ChainDraft {
        let (_, out) = s
            .prepare_send(&ChatRef::Group(gid()), Payload::Text(text.into()), None, 5000)
            .expect("prepare");
        let Sendable::Chain(d) = out else {
            panic!("a group message must go on a sender chain");
        };
        d
    }

    #[test]
    fn group_messages_use_sender_chains_and_the_key_goes_once() {
        let (mut a, mut b) = pair();
        let d1 = chain_draft(&mut a, "one");
        let s1 = a.seal_chain(&d1, 10).expect("seal");
        assert_eq!(s1.skeys.len(), 1, "bob needs the chain");
        // bob gets the message before the key: it waits
        let frame = pad::unpad(&s1.out.padded).expect("unpad");
        assert_eq!(frame[0], 0x05);
        assert!(matches!(b.chain_decrypt(&gid(), &frame, 11), ChainRx::Unknown));
        b.hold_frame(&gid(), &frame);
        b.hold_frame(&gid(), &frame);
        // the key arrives
        b.accept_skey("alice", &s1.skeys[0].env, 12).expect("skey");
        let held = b.take_held(&gid());
        assert_eq!(held.len(), 1);
        let ChainRx::Env(env) = b.chain_decrypt(&gid(), &held[0], 13) else {
            panic!("held frame must open");
        };
        assert_eq!(env.body, "one");
        // after it is marked, the next message carries no key
        a.mark_given(&gid(), s1.chain_id, &["bob".to_owned()]);
        let d2 = chain_draft(&mut a, "two");
        let s2 = a.seal_chain(&d2, 14).expect("seal");
        assert!(s2.skeys.is_empty());
        assert_eq!(s2.chain_id, s1.chain_id);
        let f2 = pad::unpad(&s2.out.padded).expect("unpad");
        assert!(matches!(b.chain_decrypt(&gid(), &f2, 15), ChainRx::Env(_)));
        // the state survives the vault
        let plain = b.snapshot().expect("snapshot");
        let data: Data = serde_json::from_slice(&plain).expect("json");
        let again = Session::new(data, "pw-pw-pw-pw-pw").expect("reopen");
        assert!(again.chains[&gid()].recv.is_some());
    }

    #[test]
    fn removing_a_contact_replaces_the_sender_chain() {
        let (mut a, _b) = pair();
        let d = chain_draft(&mut a, "one");
        let s1 = a.seal_chain(&d, 10).expect("seal");
        a.mark_given(&gid(), s1.chain_id, &["bob".to_owned()]);
        a.forget_given("bob", true);
        let d = chain_draft(&mut a, "two");
        let s2 = a.seal_chain(&d, 11).expect("seal");
        assert_ne!(s1.chain_id, s2.chain_id);
    }

    #[test]
    fn a_skey_from_a_stranger_or_a_non_member_is_refused() {
        let (mut a, mut b) = pair();
        let d = chain_draft(&mut a, "one");
        let s = a.seal_chain(&d, 10).expect("seal");
        let mut forged = s.skeys[0].env.clone();
        forged.sender = "mallory".into();
        assert!(b.accept_skey("mallory", &forged, 12).is_err());
        assert!(b.accept_skey("bob", &s.skeys[0].env, 12).is_err());
        let mut other = s.skeys[0].env.clone();
        other.group_id = "nope".into();
        assert!(b.accept_skey("alice", &other, 12).is_err());
    }
}
