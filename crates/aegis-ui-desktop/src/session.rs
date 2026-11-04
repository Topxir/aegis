//! Decrypted account state and the rules for applying incoming and outgoing messages.
//! Nothing here touches the network or the disk.

use crate::i18n::Lang;
use crate::model::{
    clean_text, Changed, Chat, Contact, Data, Group, Msg, MsgState, Settings, SEEN_CAP,
};
use aegis_core::envelope::{
    check_pinned_dm, check_pinned_group, is_expired, random_msg_id, Envelope, Kind, PinnedKeys,
    SeenIds, MAX_MEMBERS,
};
use aegis_core::group::{group_encrypt, group_id, group_queue, new_group_secret};
use aegis_core::identity::{ed25519_public, x25519_public};
use aegis_core::net::DirEntry;
use aegis_core::queue_ids::inbox_queue;
use aegis_core::seal::seal_dm;
use aegis_core::text::sanitize_display_text;
use aegis_core::{pad, Error};
use zeroize::Zeroizing;

pub const TTL_CHOICES: [u64; 4] = [0, 3600, 86_400, 604_800];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatRef {
    Dm(String),
    Group(String),
}

/// What happened to an incoming frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Added(ChatRef),
    GroupJoined(String),
    KeyChanged(String),
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
    pub dirty: bool,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("username", &self.data.username)
            .finish_non_exhaustive()
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl Session {
    pub fn new(mut data: Data, password: &str) -> Self {
        for chat in data
            .dms
            .values_mut()
            .chain(data.groups.values_mut().map(|g| &mut g.chat))
        {
            chat.unread = 0;
            for m in &mut chat.msgs {
                if m.state == MsgState::Sending {
                    m.state = MsgState::Failed;
                }
            }
        }
        let seen = SeenIds::from_ids(SEEN_CAP, std::mem::take(&mut data.seen));
        Self {
            data,
            password: Zeroizing::new(password.to_owned()),
            seen,
            dirty: false,
        }
    }

    pub fn fresh(username: &str, display: &str, lang: Lang, password: &str) -> Result<Self, Error> {
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
        };
        Ok(Self::new(data, password))
    }

    /// Serialized form for the vault. The buffer is wiped on drop.
    pub fn snapshot(&mut self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        self.data.seen = self.seen.ids().cloned().collect();
        let out = serde_json::to_vec(&self.data).map_err(|_| Failure::new("err.generic"));
        self.data.seen.clear();
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
            .chain(self.data.groups.values_mut().map(|g| &mut g.chat));
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
        }
    }

    pub fn chat(&self, r: &ChatRef) -> Option<&Chat> {
        match r {
            ChatRef::Dm(u) => self.data.dms.get(u),
            ChatRef::Group(id) => self.data.groups.get(id).map(|g| &g.chat),
        }
    }

    pub fn add_contact(&mut self, e: &DirEntry, now_ms: u64) {
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
        now_ms: u64,
    ) -> Outcome {
        if self.seen.contains(&env.msg_id) || env.sender == self.data.username {
            return Outcome::Dropped;
        }
        if !matches!(env.kind, Kind::Dm | Kind::Ginv) {
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
        if is_expired(&env, now_ms) {
            return Outcome::Dropped;
        }
        let name = sanitize_display_text(&env.sender_name);
        if let Some(c) = self.data.contacts.get_mut(&sender) {
            if !name.is_empty() {
                c.name = name;
            }
        }
        match env.kind {
            Kind::Dm => {
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
                    text: clean_text(&env.body),
                    out: false,
                    state: MsgState::Sent,
                });
                Outcome::Added(ChatRef::Dm(sender))
            }
            _ => self.accept_invite(env, now_ms),
        }
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
        now_ms: u64,
    ) -> Outcome {
        let Some(g) = self.data.groups.get(gid) else {
            return Outcome::Dropped;
        };
        if env.kind != Kind::Gmsg
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
        if is_expired(&env, now_ms) {
            return Outcome::Dropped;
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
        });
        Outcome::Added(ChatRef::Group(gid.to_owned()))
    }

    fn own_envelope(&self, kind: Kind, id: String, ts_ms: u64, ttl_s: u64) -> Envelope {
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
    ) -> Result<(String, Outbound), Failure> {
        let c = self
            .data
            .contacts
            .get(to)
            .ok_or(Failure::new("err.no_contact"))?;
        let cx = c.x;
        let text = Self::prepare_text(text)?;
        let ttl = self.data.dms.get(to).map_or(0, |c| c.ttl_s);
        let id = match retry_id {
            Some(i) => i.to_owned(),
            None => random_msg_id()?,
        };
        let mut env = self.own_envelope(Kind::Dm, id.clone(), now_ms, ttl);
        env.body = text.clone();
        let frame = seal_dm(&self.data.x_sk, &cx, &env)?;
        let out = Outbound {
            queue: inbox_queue(&cx),
            padded: pad::pad(&frame)?,
        };
        self.record_sent(&ChatRef::Dm(to.to_owned()), id.clone(), text, ttl, now_ms);
        Ok((id, out))
    }

    pub fn prepare_group_msg(
        &mut self,
        gid: &str,
        text: &str,
        retry_id: Option<&str>,
        now_ms: u64,
    ) -> Result<(String, Outbound), Failure> {
        let g = self
            .data
            .groups
            .get(gid)
            .ok_or(Failure::new("err.no_group"))?;
        let (key, ttl) = (g.key.clone(), g.chat.ttl_s);
        let text = Self::prepare_text(text)?;
        let id = match retry_id {
            Some(i) => i.to_owned(),
            None => random_msg_id()?,
        };
        let mut env = self.own_envelope(Kind::Gmsg, id.clone(), now_ms, ttl);
        env.group_id = gid.to_owned();
        env.body = text.clone();
        let frame = group_encrypt(&key, &self.data.ed_sk, &env)?;
        let out = Outbound {
            queue: group_queue(&key)?,
            padded: pad::pad(&frame)?,
        };
        self.record_sent(
            &ChatRef::Group(gid.to_owned()),
            id.clone(),
            text,
            ttl,
            now_ms,
        );
        Ok((id, out))
    }

    fn record_sent(&mut self, r: &ChatRef, id: String, text: String, ttl_s: u64, now_ms: u64) {
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
            .find(|m| m.id == id && m.out && m.state == MsgState::Failed)
            .map(|m| m.text.clone())
    }

    /// Creates a group locally and returns one invite frame per member.
    pub fn prepare_group(
        &mut self,
        title: &str,
        members: &[String],
        now_ms: u64,
    ) -> Result<(String, Vec<(String, Outbound)>), Failure> {
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

    pub fn invite_frame(&self, gid: &str, member: &str, now_ms: u64) -> Result<Outbound, Failure> {
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
        let frame = seal_dm(&self.data.x_sk, &c.x, &env)?;
        Ok(Outbound {
            queue: inbox_queue(&c.x),
            padded: pad::pad(&frame)?,
        })
    }

    pub fn set_ttl(&mut self, r: &ChatRef, ttl_s: u64) -> bool {
        if !TTL_CHOICES.contains(&ttl_s) {
            return false;
        }
        if let Some(c) = self.chat_mut(r) {
            c.ttl_s = ttl_s;
            self.dirty = true;
            return true;
        }
        false
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
                self.dirty = true;
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
        self.dirty = true;
    }

    pub fn leave_group(&mut self, gid: &str) {
        self.data.groups.remove(gid);
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

    pub fn safety_number(&self, u: &str) -> Option<String> {
        let c = self.data.contacts.get(u)?;
        Some(aegis_core::identity::safety_number(
            (&self.ed_public(), &self.x_public()),
            (&c.ed, &c.x),
        ))
    }
}
