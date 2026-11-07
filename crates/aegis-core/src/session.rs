//! Pairwise sessions with forward secrecy: frame type 0x03 (spec sections 27.4 and 27.5).
//!
//! Pure logic: no network and no clock. The client fetches prekeys when told to, passes the
//! current time, and writes [`SessionStore::encode`] to the vault before a frame leaves.

use crate::envelope::Envelope;
use crate::identity::{x25519_public, Identity};
use crate::prekeys::PrekeyPut;
use crate::ratchet::{Ratchet, Reader, Writer, HEADER_LEN};
use crate::seal::{open_raw, seal_raw};
use crate::x3dh::{self, Bundle, Parties, SignedPrekey, SPK_KEEP_SECS, SPK_ROTATE_SECS};
use crate::{arr, sha256, Error, Result};
use std::collections::VecDeque;
use zeroize::Zeroizing;

pub const FRAME_SESSION: u8 = 0x03;
pub const SEEN_EK_CAP: usize = 1000;
pub const SESSION_IDLE_SECS: u64 = 180 * 24 * 3600;
pub const SUPERSEDED_KEEP_SECS: u64 = 30 * 24 * 3600;
pub const RECOVERY_AFTER_FAILURES: u32 = 3;
pub const RECOVERY_MIN_GAP_SECS: u64 = 24 * 3600;
const SEEN_FRAME_CAP: usize = 1024;
const SEEN_EK_PER_CONTACT: usize = 64;
const OLD_CHAINS_PER_CONTACT: usize = 256;
const MAX_SESSIONS_PER_CONTACT: usize = 8;
const MAX_OPKS_HELD: usize = 200;
const START_LEN: usize = 1 + 96;

/// What the client has to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No session to send on: take prekeys of `contact`, then call `start_session`.
    NeedsPrekeysFetch { contact: String },
    /// The session is broken: take prekeys of `contact` and start a new one.
    StartNewSession { contact: String },
    /// Show "Some messages could not be decrypted" for `contact`.
    UndecryptableNotice { contact: String },
    /// The sender key is not a known contact: look it up (section 6), pin it, decrypt again.
    LookupSender { x_pk: [u8; 32] },
}

#[derive(Debug)]
pub enum Encrypted {
    Frame(Vec<u8>),
    /// Same as [`Action::NeedsPrekeysFetch`]; the contact is the one passed to `encrypt`.
    NeedsPrekeys,
}

type StartTriple = ([u8; 32], [u8; 32], [u8; 32]);

#[derive(Debug, Default)]
pub struct Received {
    pub contact: Option<String>,
    pub envelope: Option<Envelope>,
    pub actions: Vec<Action>,
}

struct SpkEntry {
    sk: Zeroizing<[u8; 32]>,
    ts: u64,
    retired_at: Option<u64>,
}

struct StartHeader {
    spk: [u8; 32],
    opk: [u8; 32],
}

struct Session {
    ratchet: Ratchet,
    ek_pk: [u8; 32],
    we_initiated: bool,
    received_any: bool,
    start: Option<StartHeader>,
    last_active: u64,
    superseded_at: Option<u64>,
}

struct ContactSessions {
    u: String,
    ed: [u8; 32],
    x: [u8; 32],
    sessions: Vec<Session>,
    send_ek: Option<[u8; 32]>,
    need_start: bool,
    fail_count: u32,
    last_recovery: Option<u64>,
    seen_ek: VecDeque<[u8; 32]>,
    old_chains: VecDeque<([u8; 32], u32)>,
}

#[derive(Default)]
pub struct SessionStore {
    spks: Vec<SpkEntry>,
    opks: Vec<Zeroizing<[u8; 32]>>,
    seen_ek: VecDeque<[u8; 32]>,
    seen_frames: VecDeque<[u8; 32]>,
    contacts: Vec<ContactSessions>,
}

impl core::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionStore(..)")
    }
}

fn push_capped<T>(q: &mut VecDeque<T>, v: T, cap: usize) {
    q.push_back(v);
    while q.len() > cap {
        q.pop_front();
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a pinned contact. Different keys for a known name are an error: remove the
    /// contact first (that drops its sessions) once the user has confirmed the key change.
    pub fn add_contact(&mut self, u: &str, ed: [u8; 32], x: [u8; 32]) -> Result<()> {
        if u.len() > usize::from(u8::MAX) {
            return Err(Error::Session("name too long"));
        }
        if let Some(c) = self.contacts.iter().find(|c| c.u == u) {
            return if c.ed == ed && c.x == x { Ok(()) } else { Err(Error::Session("contact keys changed")) };
        }
        self.contacts.push(ContactSessions {
            u: u.to_owned(),
            ed,
            x,
            sessions: Vec::new(),
            send_ek: None,
            need_start: false,
            fail_count: 0,
            last_recovery: None,
            seen_ek: VecDeque::new(),
            old_chains: VecDeque::new(),
        });
        Ok(())
    }

    pub fn remove_contact(&mut self, u: &str) {
        self.contacts.retain(|c| c.u != u);
    }

    pub fn has_session(&self, u: &str) -> bool {
        self.contacts.iter().any(|c| c.u == u && !c.sessions.is_empty())
    }

    /// Rotates the signed prekey when due, creates one-time prekeys and returns the signed
    /// `prekeys/put` request. `server_opks` is the count from the last `put` answer; pass
    /// `None` when unknown (no one-time prekeys are added, and the answer tells the count).
    pub fn prepare_prekeys(
        &mut self,
        me: &Identity,
        u: &str,
        now: u64,
        server_opks: Option<usize>,
    ) -> Result<PrekeyPut> {
        self.purge(now);
        let due = match self.spks.iter().rev().find(|s| s.retired_at.is_none()) {
            None => true,
            Some(s) => now >= s.ts.saturating_add(SPK_ROTATE_SECS),
        };
        if due {
            let fresh = SignedPrekey::generate(me, now)?;
            for s in &mut self.spks {
                s.retired_at.get_or_insert(now);
            }
            self.spks.push(SpkEntry { sk: fresh.sk, ts: now, retired_at: None });
        }
        let cur = self.spks.iter().rev().find(|s| s.retired_at.is_none()).ok_or(Error::Session("no prekey"))?;
        let sp = SignedPrekey::from_secret(me, *cur.sk, cur.ts);
        let mut pks = Vec::new();
        for sk in x3dh::generate_opks(server_opks.map_or(0, x3dh::opks_needed))? {
            pks.push(x25519_public(&sk));
            self.opks.push(sk);
        }
        if self.opks.len() > MAX_OPKS_HELD {
            self.opks.drain(..self.opks.len() - MAX_OPKS_HELD);
        }
        PrekeyPut::sign(me, u, sp.pk, sp.ts, pks, now)
    }

    /// Starts a session as initiator from a bundle taken from the server.
    pub fn start_session(&mut self, me: &Identity, contact: &str, bundle: &Bundle, now: u64) -> Result<()> {
        let ek = crate::random_key()?;
        let dhs = crate::random_key()?;
        self.start_session_with(&ek, &dhs, me, contact, bundle, now)
    }

    /// Deterministic variant with the ephemeral key `EK` and the first ratchet key.
    pub fn start_session_with(
        &mut self,
        ek_sk: &[u8; 32],
        dhs_sk: &[u8; 32],
        me: &Identity,
        contact: &str,
        bundle: &Bundle,
        now: u64,
    ) -> Result<()> {
        let c = self.contact_mut(contact)?;
        bundle.check(&c.ed, now)?;
        let sk = x3dh::initiate_with(ek_sk, me.x_secret(), &c.x, bundle)?;
        let ad = Parties { a_ed: me.ed_public(), a_x: me.x_public(), b_ed: c.ed, b_x: c.x }.ad();
        let ratchet = Ratchet::init_initiator_with(dhs_sk, &sk, &ad, &bundle.spk)?;
        let ek_pk = x25519_public(ek_sk);
        let session = Session {
            ratchet,
            ek_pk,
            we_initiated: true,
            received_any: false,
            start: Some(StartHeader { spk: bundle.spk, opk: bundle.opk.unwrap_or([0; 32]) }),
            last_active: now,
            superseded_at: None,
        };
        c.install(session, true, now);
        c.need_start = false;
        Ok(())
    }

    /// Wraps `env` in a type 0x03 frame (unpadded; the caller pads as in section 4).
    pub fn encrypt(&mut self, me: &Identity, contact: &str, env: &Envelope, now: u64) -> Result<Encrypted> {
        self.encrypt_with(&*crate::random_key()?, me, contact, env, now)
    }

    pub fn encrypt_with(
        &mut self,
        e_sk: &[u8; 32],
        me: &Identity,
        contact: &str,
        env: &Envelope,
        now: u64,
    ) -> Result<Encrypted> {
        if env.kind.frame_type() != 0x01 {
            return Err(Error::BadFrameType);
        }
        self.purge(now);
        let c = self.contact_mut(contact)?;
        let Some(i) = c.send_index() else {
            return Ok(Encrypted::NeedsPrekeys);
        };
        let plain = Zeroizing::new(env.encode()?);
        let s = &mut c.sessions[i];
        let msg = s.ratchet.encrypt(&plain)?;
        let inner = match &s.start {
            Some(h) => [[0u8].as_slice(), &s.ek_pk, &h.spk, &h.opk, &msg].concat(),
            None => [[1u8].as_slice(), &msg].concat(),
        };
        s.last_active = now;
        let frame = seal_raw(FRAME_SESSION, e_sk, me.x_secret(), &c.x, &inner)?;
        Ok(Encrypted::Frame(frame))
    }

    /// Opens a type 0x03 frame addressed to `me`.
    pub fn decrypt(&mut self, me: &Identity, frame: &[u8], now: u64) -> Result<Received> {
        self.decrypt_with(&*crate::random_key()?, me, frame, now)
    }

    /// `new_dhs_sk` is the ratchet key used if the frame triggers a DH step.
    pub fn decrypt_with(&mut self, new_dhs_sk: &[u8; 32], me: &Identity, frame: &[u8], now: u64) -> Result<Received> {
        self.purge(now);
        let (s_pk, inner) = open_raw(FRAME_SESSION, me.x_secret(), frame)?;
        let Some(ci) = self.contacts.iter().position(|c| c.x == s_pk) else {
            return Ok(Received { actions: vec![Action::LookupSender { x_pk: s_pk }], ..Received::default() });
        };
        let fh = sha256(&[frame]);
        if self.seen_frames.contains(&fh) {
            return Ok(Received::default());
        }
        push_capped(&mut self.seen_frames, fh, SEEN_FRAME_CAP);

        let (kind, rest) = inner.split_first().ok_or(Error::Length)?;
        let (start, msg): (Option<StartTriple>, &[u8]) = match kind {
            0x00 => {
                if inner.len() < START_LEN + HEADER_LEN + 16 {
                    return Err(Error::Length);
                }
                let t = (arr(&rest[..32])?, arr(&rest[32..64])?, arr(&rest[64..96])?);
                (Some(t), &rest[96..])
            }
            0x01 => (None, rest),
            _ => return Err(Error::Session("unknown inner kind")),
        };
        if msg.len() < HEADER_LEN + 16 {
            return Err(Error::Length);
        }

        let (plain, created) = match start {
            Some((ek, spk, opk)) => match self.open_start(ci, me, new_dhs_sk, ek, spk, opk, msg, now)? {
                Some(r) => r,
                None => return Ok(Received::default()),
            },
            None => (self.open_message(ci, new_dhs_sk, msg, now), None),
        };
        let c = &mut self.contacts[ci];
        let Some(plain) = plain else {
            if c.is_replay(msg) {
                return Ok(Received::default());
            }
            return Ok(c.failed(now));
        };
        if created.is_some() {
            c.need_start = false;
        }
        c.fail_count = 0;
        let env = Envelope::decode(&plain)?;
        if env.kind.frame_type() != 0x01 {
            return Err(Error::BadFrameType);
        }
        if env.sender_ed != c.ed || env.sender != c.u {
            return Err(Error::SenderMismatch);
        }
        Ok(Received { contact: Some(c.u.clone()), envelope: Some(env), actions: Vec::new() })
    }

    /// Handles a start frame. `Ok(None)`: dropped. `Ok(Some((None, _)))`: did not decrypt.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn open_start(
        &mut self,
        ci: usize,
        me: &Identity,
        new_dhs_sk: &[u8; 32],
        ek: [u8; 32],
        spk: [u8; 32],
        opk: [u8; 32],
        msg: &[u8],
        now: u64,
    ) -> Result<Option<(Option<Zeroizing<Vec<u8>>>, Option<()>)>> {
        let known = self.contacts[ci].sessions.iter().position(|s| s.ek_pk == ek);
        if let Some(i) = known {
            let c = &mut self.contacts[ci];
            let plain = c.sessions[i].try_decrypt(new_dhs_sk, msg, now, &mut c.old_chains);
            return Ok(Some((plain, None)));
        }
        if self.seen_ek.contains(&ek) || self.contacts[ci].seen_ek.contains(&ek) || self.contacts[ci].is_replay(msg) {
            return Ok(None);
        }
        let Some(sp) = self.spks.iter().find(|s| x25519_public(&s.sk) == spk) else {
            return Ok(None);
        };
        let opk_sk = if opk == [0; 32] {
            None
        } else {
            match self.opks.iter().position(|o| x25519_public(o) == opk) {
                Some(i) => Some(i),
                None => return Ok(None),
            }
        };
        let c = &self.contacts[ci];
        let sk = x3dh::respond(me.x_secret(), &sp.sk, opk_sk.map(|i| &*self.opks[i]), &c.x, &ek)?;
        let ad = Parties { a_ed: c.ed, a_x: c.x, b_ed: me.ed_public(), b_x: me.x_public() }.ad();
        let mut session = Session {
            ratchet: Ratchet::init_responder(&sk, &ad, &sp.sk),
            ek_pk: ek,
            we_initiated: false,
            received_any: false,
            start: None,
            last_active: now,
            superseded_at: None,
        };
        let Some(plain) = session.try_decrypt(new_dhs_sk, msg, now, &mut VecDeque::new()) else {
            return Ok(Some((None, None)));
        };
        push_capped(&mut self.seen_ek, ek, SEEN_EK_CAP);
        push_capped(&mut self.contacts[ci].seen_ek, ek, SEEN_EK_PER_CONTACT);
        if let Some(i) = opk_sk {
            self.opks.remove(i);
        }
        self.contacts[ci].install(session, false, now);
        Ok(Some((Some(plain), Some(()))))
    }

    fn open_message(&mut self, ci: usize, new_dhs_sk: &[u8; 32], msg: &[u8], now: u64) -> Option<Zeroizing<Vec<u8>>> {
        let c = &mut self.contacts[ci];
        let old = &mut c.old_chains;
        c.sessions.iter_mut().find_map(|s| s.try_decrypt(new_dhs_sk, msg, now, old))
    }

    /// Deletes expired sessions, superseded sessions and old signed prekey secrets.
    pub fn purge(&mut self, now: u64) {
        self.spks.retain(|s| s.retired_at.is_none_or(|t| now < t.saturating_add(SPK_KEEP_SECS)));
        for c in &mut self.contacts {
            for s in &mut c.sessions {
                s.ratchet.expire(now);
            }
            let old = &mut c.old_chains;
            c.sessions.retain(|s| {
                let keep = now < s.last_active.saturating_add(SESSION_IDLE_SECS)
                    && s.superseded_at.is_none_or(|t| now < t.saturating_add(SUPERSEDED_KEEP_SECS));
                if !keep {
                    s.retire(old);
                }
                keep
            });
            if let Some(ek) = c.send_ek {
                if !c.sessions.iter().any(|s| s.ek_pk == ek) {
                    c.send_ek = None;
                }
            }
        }
    }

    fn contact_mut(&mut self, u: &str) -> Result<&mut ContactSessions> {
        self.contacts.iter_mut().find(|c| c.u == u).ok_or(Error::Session("unknown contact"))
    }

    /// Local store encoding `AGS2` (spec section 27.5, "Local state").
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut w = Writer::new();
        w.raw(b"AGS2");
        w.u16(len16(self.spks.len()));
        for s in &self.spks {
            w.raw(s.sk.as_ref());
            w.u64(s.ts);
            w.opt_u64(s.retired_at);
        }
        w.u16(len16(self.opks.len()));
        for o in &self.opks {
            w.raw(o.as_ref());
        }
        w.u16(len16(self.seen_ek.len()));
        for e in &self.seen_ek {
            w.raw(e);
        }
        w.u16(len16(self.seen_frames.len()));
        for h in &self.seen_frames {
            w.raw(h);
        }
        w.u16(len16(self.contacts.len()));
        for c in &self.contacts {
            w.str(&c.u)?;
            w.raw(&c.ed);
            w.raw(&c.x);
            w.opt32(c.send_ek.as_ref());
            w.u8(u8::from(c.need_start));
            w.u32(c.fail_count);
            w.opt_u64(c.last_recovery);
            w.u16(len16(c.seen_ek.len()));
            for e in &c.seen_ek {
                w.raw(e);
            }
            w.u16(len16(c.old_chains.len()));
            for (dh, n) in &c.old_chains {
                w.raw(dh);
                w.u32(*n);
            }
            w.u8(u8::try_from(c.sessions.len()).unwrap_or(u8::MAX));
            for s in &c.sessions {
                w.raw(&s.ek_pk);
                w.u8(u8::from(s.we_initiated) | u8::from(s.received_any) << 1 | u8::from(s.start.is_some()) << 2);
                if let Some(h) = &s.start {
                    w.raw(&h.spk);
                    w.raw(&h.opk);
                }
                w.u64(s.last_active);
                w.opt_u64(s.superseded_at);
                let r = s.ratchet.encode();
                w.u32(u32::try_from(r.len()).unwrap_or(u32::MAX));
                w.raw(&r);
            }
        }
        Ok(w.finish())
    }

    /// Reads `AGS2` and the older `AGS1`, which has no per-contact replay state.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let v2 = bytes.starts_with(b"AGS2");
        r.magic(if v2 { b"AGS2" } else { b"AGS1" })?;
        let mut st = Self::new();
        for _ in 0..r.u16()? {
            let sk = Zeroizing::new(r.array::<32>()?);
            st.spks.push(SpkEntry { sk, ts: r.u64()?, retired_at: r.opt_u64()? });
        }
        for _ in 0..r.u16()? {
            st.opks.push(Zeroizing::new(r.array::<32>()?));
        }
        for _ in 0..r.u16()? {
            st.seen_ek.push_back(r.array()?);
        }
        for _ in 0..r.u16()? {
            st.seen_frames.push_back(r.array()?);
        }
        if st.seen_ek.len() > SEEN_EK_CAP || st.seen_frames.len() > SEEN_FRAME_CAP || st.opks.len() > MAX_OPKS_HELD {
            return Err(Error::Session("state"));
        }
        for _ in 0..r.u16()? {
            let u = r.str()?;
            let (ed, x) = (r.array()?, r.array()?);
            let send_ek = r.opt32()?;
            let need_start = r.flag()?;
            let fail_count = r.u32()?;
            let last_recovery = r.opt_u64()?;
            let (mut seen_ek, mut old_chains) = (VecDeque::new(), VecDeque::new());
            if v2 {
                for _ in 0..r.u16()? {
                    seen_ek.push_back(r.array()?);
                }
                for _ in 0..r.u16()? {
                    old_chains.push_back((r.array()?, r.u32()?));
                }
                if seen_ek.len() > SEEN_EK_PER_CONTACT || old_chains.len() > OLD_CHAINS_PER_CONTACT {
                    return Err(Error::Session("state"));
                }
            }
            let mut sessions = Vec::new();
            for _ in 0..r.u8()? {
                let ek_pk = r.array()?;
                let f = r.u8()?;
                if f > 7 {
                    return Err(Error::Session("state"));
                }
                let start = if f & 4 != 0 { Some(StartHeader { spk: r.array()?, opk: r.array()? }) } else { None };
                let last_active = r.u64()?;
                let superseded_at = r.opt_u64()?;
                let n = usize::try_from(r.u32()?).map_err(|_| Error::Session("state"))?;
                let ratchet = Ratchet::decode(r.take(n)?)?;
                sessions.push(Session {
                    ratchet,
                    ek_pk,
                    we_initiated: f & 1 != 0,
                    received_any: f & 2 != 0,
                    start,
                    last_active,
                    superseded_at,
                });
            }
            if sessions.len() > MAX_SESSIONS_PER_CONTACT {
                return Err(Error::Session("state"));
            }
            st.contacts.push(ContactSessions {
                u,
                ed,
                x,
                sessions,
                send_ek,
                need_start,
                fail_count,
                last_recovery,
                seen_ek,
                old_chains,
            });
        }
        r.end()?;
        Ok(st)
    }
}

fn len16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

impl Session {
    /// Decrypts on a copy of the ratchet; commits and updates flags only on success. A receiving
    /// chain left behind by a DH step goes to `old` with its final counter.
    fn try_decrypt(
        &mut self,
        new_dhs_sk: &[u8; 32],
        msg: &[u8],
        now: u64,
        old: &mut VecDeque<([u8; 32], u32)>,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let before = self.ratchet.recv_chain();
        let plain = self.ratchet.decrypt_with(new_dhs_sk, msg, now).ok()?;
        if let Some((dh, nr)) = before {
            if self.ratchet.recv_chain().is_some_and(|(d, _)| d != dh) {
                let pn = msg.get(32..36).and_then(|b| arr::<4>(b).ok()).map_or(0, u32::from_be_bytes);
                push_capped(old, (dh, nr.max(pn)), OLD_CHAINS_PER_CONTACT);
            }
        }
        self.received_any = true;
        self.start = None;
        self.last_active = now;
        // A superseded session the peer still uses stays until it has been idle for the keep time.
        if self.superseded_at.is_some() {
            self.superseded_at = Some(now);
        }
        Some(plain)
    }

    /// Keeps the receiving chain of a session that is being dropped.
    fn retire(&self, old: &mut VecDeque<([u8; 32], u32)>) {
        if let Some(rc) = self.ratchet.recv_chain() {
            push_capped(old, rc, OLD_CHAINS_PER_CONTACT);
        }
    }
}

impl ContactSessions {
    /// True if `msg` names a receiving chain we hold or held, at a counter whose key is spent.
    fn is_replay(&self, msg: &[u8]) -> bool {
        let Some(h) = msg.get(..HEADER_LEN) else {
            return false;
        };
        let (Ok(dh), Ok(n)) = (arr::<32>(&h[..32]), arr::<4>(&h[36..]).map(u32::from_be_bytes)) else {
            return false;
        };
        if self.sessions.iter().any(|s| s.ratchet.has_skipped(&dh, n)) {
            return false;
        }
        let spent = |c: &([u8; 32], u32)| c.0 == dh && n < c.1;
        self.sessions.iter().filter_map(|s| s.ratchet.recv_chain()).any(|c| spent(&c))
            || self.old_chains.iter().any(spent)
    }

    fn send_index(&self) -> Option<usize> {
        if self.need_start {
            return None;
        }
        let ek = self.send_ek?;
        let i = self.sessions.iter().position(|s| s.ek_pk == ek)?;
        self.sessions[i].ratchet.can_send().then_some(i)
    }

    /// Adds a session at the front. `initiated`: we started it (always used for sending).
    fn install(&mut self, session: Session, initiated: bool, now: u64) {
        let new_ek = session.ek_pk;
        let simultaneous = !initiated
            && self
                .send_ek
                .and_then(|ek| self.sessions.iter().find(|s| s.ek_pk == ek))
                .is_some_and(|s| s.we_initiated && !s.received_any);
        let send_ek = match (simultaneous, self.send_ek) {
            (true, Some(old)) => old.min(new_ek),
            _ => new_ek,
        };
        self.sessions.insert(0, session);
        self.send_ek = Some(send_ek);
        for s in &mut self.sessions {
            if s.ek_pk != send_ek {
                s.superseded_at.get_or_insert(now);
            } else {
                s.superseded_at = None;
            }
        }
        while self.sessions.len() > MAX_SESSIONS_PER_CONTACT {
            if let Some(i) = self.sessions.iter().rposition(|s| s.ek_pk != send_ek) {
                let gone = self.sessions.remove(i);
                gone.retire(&mut self.old_chains);
            } else {
                break;
            }
        }
    }

    /// Counts a frame that verified but did not decrypt; may trigger recovery.
    fn failed(&mut self, now: u64) -> Received {
        self.fail_count = self.fail_count.saturating_add(1);
        let mut out = Received { contact: Some(self.u.clone()), ..Received::default() };
        let allowed = self.last_recovery.is_none_or(|t| now >= t.saturating_add(RECOVERY_MIN_GAP_SECS));
        if self.fail_count >= RECOVERY_AFTER_FAILURES && allowed {
            self.fail_count = 0;
            self.last_recovery = Some(now);
            self.need_start = true;
            out.actions.push(Action::StartNewSession { contact: self.u.clone() });
            out.actions.push(Action::UndecryptableNotice { contact: self.u.clone() });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::dm;
    use crate::envelope::Kind;

    const T0: u64 = 1_700_000_000;

    struct Side {
        id: Identity,
        store: SessionStore,
        name: &'static str,
    }

    fn side(name: &'static str, x: u8, ed: u8) -> Side {
        Side { id: Identity::from_secrets([x; 32], [ed; 32]), store: SessionStore::new(), name }
    }

    fn pair() -> (Side, Side) {
        let (mut a, mut b) = (side("alice", 1, 2), side("bob", 3, 4));
        a.store.add_contact("bob", b.id.ed_public(), b.id.x_public()).unwrap();
        b.store.add_contact("alice", a.id.ed_public(), a.id.x_public()).unwrap();
        (a, b)
    }

    fn env_from(s: &Side, body: &str) -> Envelope {
        Envelope {
            sender: s.name.into(),
            sender_ed: s.id.ed_public(),
            body: body.into(),
            msg_id: crate::envelope::random_msg_id().unwrap(),
            ..dm()
        }
    }

    fn bundle_for(b: &mut Side, now: u64, opk: bool) -> Bundle {
        let put = b.store.prepare_prekeys(&b.id, b.name, now, if opk { Some(0) } else { None }).unwrap();
        Bundle { spk: put.spk, spk_ts: put.spk_ts, spk_sig: put.spk_sig, opk: put.opks.first().copied() }
    }

    fn send(from: &mut Side, to: &str, body: &str, now: u64) -> Vec<u8> {
        let e = env_from(from, body);
        match from.store.encrypt(&from.id, to, &e, now).unwrap() {
            Encrypted::Frame(f) => f,
            Encrypted::NeedsPrekeys => panic!("needs prekeys"),
        }
    }

    fn recv(to: &mut Side, frame: &[u8], now: u64) -> Received {
        to.store.decrypt(&to.id, frame, now).unwrap()
    }

    fn body(r: &Received) -> &str {
        &r.envelope.as_ref().unwrap().body
    }

    #[test]
    fn full_conversation_with_opk() {
        let (mut a, mut b) = pair();
        let e = env_from(&a, "hi");
        assert!(matches!(a.store.encrypt(&a.id, "bob", &e, T0).unwrap(), Encrypted::NeedsPrekeys));
        let bundle = bundle_for(&mut b, T0, true);
        assert!(bundle.opk.is_some());
        a.store.start_session(&a.id, "bob", &bundle, T0).unwrap();
        let f1 = send(&mut a, "bob", "one", T0);
        let f2 = send(&mut a, "bob", "two", T0);
        let r = recv(&mut b, &f1, T0);
        assert_eq!(body(&r), "one");
        assert_eq!(r.contact.as_deref(), Some("alice"));
        assert_eq!(b.store.opks.len(), 49, "opk erased after first decrypt");
        assert_eq!(body(&recv(&mut b, &f2, T0)), "two");
        let reply = send(&mut b, "alice", "back", T0 + 1);
        assert_eq!(reply[0], 0x03);
        assert_eq!(body(&recv(&mut a, &reply, T0 + 1)), "back");
        let f3 = send(&mut a, "bob", "three", T0 + 2);
        assert_eq!(body(&recv(&mut b, &f3, T0 + 2)), "three");
        assert!(a.store.contacts[0].sessions[0].start.is_none());
        // Frames are sealed-sender: replaying one changes nothing.
        let again = recv(&mut b, &f3, T0 + 3);
        assert!(again.envelope.is_none() && again.actions.is_empty());
    }

    #[test]
    fn start_without_opk_and_replayed_start_does_not_reset() {
        let (mut a, mut b) = pair();
        let bundle = bundle_for(&mut b, T0, false);
        assert!(bundle.opk.is_none());
        a.store.start_session(&a.id, "bob", &bundle, T0).unwrap();
        let f1 = send(&mut a, "bob", "one", T0);
        let f2 = send(&mut a, "bob", "two", T0);
        recv(&mut b, &f1, T0);
        let reply = send(&mut b, "alice", "back", T0);
        recv(&mut a, &reply, T0);
        // A start frame whose EK is known is handled on the same session.
        assert_eq!(body(&recv(&mut b, &f2, T0)), "two");
        assert_eq!(b.store.contacts[0].sessions.len(), 1);
        let again = recv(&mut b, &f1, T0);
        assert!(again.envelope.is_none());
        assert_eq!(b.store.contacts[0].sessions.len(), 1);
    }

    #[test]
    fn unknown_prekeys_and_senders_are_dropped() {
        let (mut a, mut b) = pair();
        let mut bundle = bundle_for(&mut b, T0, true);
        let real = bundle.clone();
        bundle.opk = Some(x25519_public(&[0x99; 32]));
        a.store.start_session(&a.id, "bob", &bundle, T0).unwrap();
        let f = send(&mut a, "bob", "x", T0);
        let r = recv(&mut b, &f, T0);
        assert!(r.envelope.is_none() && b.store.contacts[0].sessions.is_empty());
        let (mut a2, _) = pair();
        let mut stale = real;
        stale.spk = x25519_public(&[0x98; 32]);
        a2.store.contacts[0].sessions.clear();
        assert!(a2.store.start_session(&a2.id, "bob", &stale, T0).is_err(), "bad spk_sig");

        let (mut c, mut b2) = pair();
        let bundle = bundle_for(&mut b2, T0, false);
        c.store.start_session(&c.id, "bob", &bundle, T0).unwrap();
        let f = send(&mut c, "bob", "x", T0);
        b2.store.remove_contact("alice");
        let r = recv(&mut b2, &f, T0);
        assert_eq!(r.actions, vec![Action::LookupSender { x_pk: c.id.x_public() }]);
    }

    #[test]
    fn sender_must_match_contact() {
        let (mut a, mut b) = pair();
        let bundle = bundle_for(&mut b, T0, false);
        a.store.start_session(&a.id, "bob", &bundle, T0).unwrap();
        let mut e = env_from(&a, "x");
        e.sender = "mallory".into();
        let Encrypted::Frame(f) = a.store.encrypt(&a.id, "bob", &e, T0).unwrap() else { panic!() };
        assert_eq!(b.store.decrypt(&b.id, &f, T0).unwrap_err(), Error::SenderMismatch);
        let mut e = env_from(&a, "x");
        e.sender_ed = [0; 32];
        let Encrypted::Frame(f) = a.store.encrypt(&a.id, "bob", &e, T0).unwrap() else { panic!() };
        assert_eq!(b.store.decrypt(&b.id, &f, T0).unwrap_err(), Error::SenderMismatch);
        let mut e = env_from(&a, "x");
        e.kind = Kind::Gmsg;
        assert_eq!(a.store.encrypt(&a.id, "bob", &e, T0).unwrap_err(), Error::BadFrameType);
    }

    #[test]
    fn simultaneous_start_picks_smaller_ek() {
        let (mut a, mut b) = pair();
        let ba = bundle_for(&mut a, T0, false);
        let bb = bundle_for(&mut b, T0, false);
        a.store.start_session_with(&[0x41; 32], &[0x51; 32], &a.id, "bob", &bb, T0).unwrap();
        b.store.start_session_with(&[0x42; 32], &[0x52; 32], &b.id, "alice", &ba, T0).unwrap();
        let fa = send(&mut a, "bob", "from a", T0);
        let fb = send(&mut b, "alice", "from b", T0);
        assert_eq!(body(&recv(&mut b, &fa, T0)), "from a");
        assert_eq!(body(&recv(&mut a, &fb, T0)), "from b");
        let ea = x25519_public(&[0x41; 32]);
        let eb = x25519_public(&[0x42; 32]);
        let want = ea.min(eb);
        assert_eq!(a.store.contacts[0].send_ek, Some(want));
        assert_eq!(b.store.contacts[0].send_ek, Some(want));
        assert_eq!(a.store.contacts[0].sessions.len(), 2);
        let m1 = send(&mut a, "bob", "again a", T0 + 1);
        let m2 = send(&mut b, "alice", "again b", T0 + 1);
        assert_eq!(body(&recv(&mut b, &m1, T0 + 1)), "again a");
        assert_eq!(body(&recv(&mut a, &m2, T0 + 1)), "again b");
    }

    #[test]
    fn recovery_after_three_failures_once_a_day() {
        let (mut a, mut b) = pair();
        let bundle = bundle_for(&mut b, T0, false);
        a.store.start_session(&a.id, "bob", &bundle, T0).unwrap();
        let f = send(&mut a, "bob", "one", T0);
        recv(&mut b, &f, T0);
        let reply = send(&mut b, "alice", "r", T0);
        recv(&mut a, &reply, T0);
        // B loses its sessions (old vault); A keeps talking on the old one.
        b.store.contacts[0].sessions.clear();
        b.store.contacts[0].send_ek = None;
        for i in 0..2 {
            let f = send(&mut a, "bob", "lost", T0 + 10 + i);
            let r = recv(&mut b, &f, T0 + 10 + i);
            assert!(r.envelope.is_none() && r.actions.is_empty());
        }
        let f = send(&mut a, "bob", "lost", T0 + 20);
        let r = recv(&mut b, &f, T0 + 20);
        assert_eq!(
            r.actions,
            vec![
                Action::StartNewSession { contact: "alice".into() },
                Action::UndecryptableNotice { contact: "alice".into() }
            ]
        );
        let e = env_from(&b, "x");
        assert!(matches!(b.store.encrypt(&b.id, "alice", &e, T0 + 21).unwrap(), Encrypted::NeedsPrekeys));
        // Within 24 hours a second recovery is not offered.
        for i in 0..4 {
            let f = send(&mut a, "bob", "lost", T0 + 30 + i);
            assert!(recv(&mut b, &f, T0 + 30 + i).actions.is_empty());
        }
        // Start over: B starts a new session, A accepts it as a new EK.
        let ba = bundle_for(&mut a, T0 + 40, false);
        b.store.start_session(&b.id, "alice", &ba, T0 + 40).unwrap();
        let f = send(&mut b, "alice", "fresh", T0 + 41);
        assert_eq!(body(&recv(&mut a, &f, T0 + 41)), "fresh");
        let back = send(&mut a, "bob", "hello again", T0 + 42);
        assert_eq!(body(&recv(&mut b, &back, T0 + 42)), "hello again");
        // After a day a new failure series may trigger again.
        b.store.contacts[0].fail_count = 2;
        let r = b.store.contacts[0].failed(T0 + 20 + RECOVERY_MIN_GAP_SECS);
        assert_eq!(r.actions.len(), 2);
    }

    #[test]
    fn expiry_and_superseded() {
        let (mut a, mut b) = pair();
        let bundle = bundle_for(&mut b, T0, false);
        a.store.start_session(&a.id, "bob", &bundle, T0).unwrap();
        let f = send(&mut a, "bob", "one", T0);
        recv(&mut b, &f, T0);
        let bundle2 = bundle_for(&mut b, T0, false);
        a.store.start_session(&a.id, "bob", &bundle2, T0 + 5).unwrap();
        assert_eq!(a.store.contacts[0].sessions.len(), 2);
        let f = send(&mut a, "bob", "two", T0 + 6);
        assert_eq!(body(&recv(&mut b, &f, T0 + 6)), "two");
        a.store.purge(T0 + 5 + SUPERSEDED_KEEP_SECS - 1);
        assert_eq!(a.store.contacts[0].sessions.len(), 2);
        a.store.purge(T0 + 5 + SUPERSEDED_KEEP_SECS);
        assert_eq!(a.store.contacts[0].sessions.len(), 1);
        a.store.purge(T0 + 6 + SESSION_IDLE_SECS);
        assert!(a.store.contacts[0].sessions.is_empty());
        let e = env_from(&a, "x");
        assert!(matches!(a.store.encrypt(&a.id, "bob", &e, T0 + 6 + SESSION_IDLE_SECS).unwrap(), Encrypted::NeedsPrekeys));
    }

    #[test]
    fn prekey_rotation_and_refill() {
        let (_, mut b) = pair();
        let p1 = b.store.prepare_prekeys(&b.id, "bob", T0, None).unwrap();
        assert!(p1.opks.is_empty());
        let p2 = b.store.prepare_prekeys(&b.id, "bob", T0 + 60, Some(0)).unwrap();
        assert_eq!((p2.spk, p2.spk_ts, p2.spk_sig), (p1.spk, p1.spk_ts, p1.spk_sig));
        assert_eq!(p2.opks.len(), 50);
        let p3 = b.store.prepare_prekeys(&b.id, "bob", T0 + 120, Some(10)).unwrap();
        assert!(p3.opks.is_empty());
        let p4 = b.store.prepare_prekeys(&b.id, "bob", T0 + SPK_ROTATE_SECS, Some(3)).unwrap();
        assert_ne!(p4.spk, p1.spk);
        assert_eq!(p4.opks.len(), 47);
        assert!(p4.sig_ok(&b.id.ed_public()) && p4.spk_sig_ok(&b.id.ed_public()));
        assert_eq!(b.store.spks.len(), 2);
        b.store.purge(T0 + SPK_ROTATE_SECS + SPK_KEEP_SECS);
        assert_eq!(b.store.spks.len(), 1);
    }

    #[test]
    fn encode_roundtrip() {
        let (mut a, mut b) = pair();
        let bundle = bundle_for(&mut b, T0, true);
        a.store.start_session(&a.id, "bob", &bundle, T0).unwrap();
        let f = send(&mut a, "bob", "one", T0);
        recv(&mut b, &f, T0);
        for s in [&a, &b] {
            let bytes = s.store.encode().unwrap();
            let again = SessionStore::decode(&bytes).unwrap();
            assert_eq!(*again.encode().unwrap(), *bytes);
            assert!(SessionStore::decode(&bytes[..bytes.len() - 1]).is_err());
            assert!(SessionStore::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        }
        let mut b2 = SessionStore::decode(&b.store.encode().unwrap()).unwrap();
        let reply = send(&mut b, "alice", "r", T0 + 1);
        let again = b2.decrypt(&b.id, &send(&mut a, "bob", "two", T0 + 1), T0 + 1).unwrap();
        assert_eq!(again.envelope.unwrap().body, "two");
        assert_eq!(body(&recv(&mut a, &reply, T0 + 1)), "r");
    }
}
