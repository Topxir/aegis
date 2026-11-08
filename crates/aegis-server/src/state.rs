use crate::blob::{is_blob_id, BlobStore, Reserve, DEFAULT_BLOB_QUOTA_BYTES, DEFAULT_BLOB_TTL_SECS, MAX_BLOB_BYTES};
use crate::http::{BlobReply, Request, Response};
use aegis_core::directory::Registration;
use aegis_core::invite::{Hide, InviteCreate, INVITE_TTL_SECS, MAX_OPEN_INVITES};
use aegis_core::prekeys::{PrekeyPut, PrekeyTake, MAX_OPKS};
use aegis_core::identity::is_valid_username;
use aegis_core::text::parse_u64;
use aegis_core::{hex, pad, pow};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Frames are kept this long (14 days).
pub const DEFAULT_QUEUE_TTL_SECS: u64 = 14 * 24 * 3600;
/// Name of the persisted state inside the data directory.
pub const STATE_FILE: &str = "server-v2.state";
const MAGIC: &[u8; 8] = b"AEGSRV05";
const MAGIC_V4: &[u8; 8] = b"AEGSRV04";
const MAGIC_V3: &[u8; 8] = b"AEGSRV03";
const MAGIC_V2: &[u8; 8] = b"AEGSRV02";
/// Name of the server's long-term X25519 secret (section 23) inside the data directory.
pub const KEY_FILE: &str = "server-x25519.key";
/// Slots unused for this long expire (section 20).
const PIN_TTL_SECS: u64 = 90 * 24 * 3600;
const PIN_MAX_FAILS: u8 = 5;
const POLL_PAGE: usize = 100;
/// A poll answer must fit the largest sealed bucket (1114112 bytes minus framing) with room to spare.
const POLL_MAX_BYTES: usize = 1_000_000;
const POLL_ENVELOPE_BYTES: usize = 64;

/// Tunable limits. The defaults are the protocol values.
#[derive(Debug, Clone)]
pub struct Config {
    pub pow_bits: u32,
    pub ttl_secs: u64,
    pub max_frames_per_queue: usize,
    pub replay_secs: u64,
    pub max_queues: usize,
    pub max_directory_entries: usize,
    pub max_pin_slots: usize,
    /// Most users with stored prekeys (about 3.5 KiB each when full).
    pub max_prekey_users: usize,
    /// Minimum seconds between accepted `prekeys/put` calls of one user (`0` disables).
    pub prekey_put_interval_secs: u64,
    /// Most accepted `prekeys/put` calls per user in any rolling hour (`0` disables).
    pub prekey_puts_per_hour: usize,
    /// Minimum seconds between verification attempts on one PIN slot (`0` disables).
    pub pin_min_interval_secs: u64,
    /// Total size cap of the blob store in bytes.
    pub blob_quota_bytes: u64,
    pub blob_ttl_secs: u64,
    /// Owner `ed_pk`. Only this key may register `owner` and append to the official queue.
    pub owner_ed_pk: Option<[u8; 32]>,
    /// Reply bytes `nop` may hand out per second, shared by all clients; up to
    /// `NOP_BURST_SECS` seconds of it can be spent at once.
    pub nop_bytes_per_sec: u64,
    /// Most open invites stored at once, over all users.
    pub max_invites: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pow_bits: pow::DEFAULT_BITS,
            ttl_secs: DEFAULT_QUEUE_TTL_SECS,
            max_frames_per_queue: 2000,
            replay_secs: 20 * 60,
            max_queues: 200_000,
            max_directory_entries: 1_000_000,
            max_pin_slots: 100_000,
            max_prekey_users: 1_000_000,
            prekey_put_interval_secs: 60,
            prekey_puts_per_hour: 5,
            pin_min_interval_secs: 1,
            blob_quota_bytes: DEFAULT_BLOB_QUOTA_BYTES,
            blob_ttl_secs: DEFAULT_BLOB_TTL_SECS,
            owner_ed_pk: None,
            nop_bytes_per_sec: 8 * 1024 * 1024,
            max_invites: 1_000_000,
        }
    }
}

#[derive(Debug)]
pub enum ServerError {
    Io(String),
    /// The state file exists but cannot be parsed; it is left untouched.
    Corrupt,
    /// The server key file exists but is unusable; it is never regenerated.
    CorruptKey,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::Io(e) => write!(f, "i/o error: {e}"),
            ServerError::Corrupt => f.write_str("state file is corrupt"),
            ServerError::CorruptKey => f.write_str("server key file is corrupt"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        ServerError::Io(format!("{:?}", e.kind()))
    }
}

#[derive(Clone)]
struct DirEntry {
    x: [u8; 32],
    ed: [u8; 32],
    /// Lookups answer "not found" (section 29).
    hidden: bool,
}

/// An open invite: only the hash of the secret and the sealed bundle are kept.
#[derive(Clone)]
struct Invite {
    exp: u64,
    sealed: Vec<u8>,
}

/// Most sealed requests accepted per timestamp second. A full second refuses further requests
/// with that `ts` only; the next second starts empty.
const SEALED_PER_SECOND: usize = 2048;
/// Seconds of `nop` budget that may be spent at once.
pub const NOP_BURST_SECS: u64 = 4;

/// What to put back when a change could not be written to disk.
enum Undo {
    Dir(String, Option<DirEntry>),
    Pin([u8; 32], Option<PinSlot>),
    Prekeys(String, Option<Prekeys>),
    PrekeyPut(String),
    Frame([u8; 32], u64),
    Invite([u8; 32], Option<Invite>),
    InviteDay(String, u64),
}

/// Changes made by one request, newest last.
pub(crate) struct Changes(Vec<Undo>);

#[derive(Clone)]
struct PinSlot {
    v: [u8; 32],
    s: [u8; 32],
    fails: u8,
    last_used: u64,
    /// Unix second of the last counted attempt (memory only).
    last_attempt: u64,
}

#[derive(Clone)]
struct Prekeys {
    spk: [u8; 32],
    spk_ts: u64,
    spk_sig: [u8; 64],
    opks: VecDeque<[u8; 32]>,
}

/// Hashes with an expiry time, evicted in expiry order.
#[derive(Default)]
struct Expiring {
    map: HashMap<[u8; 32], u64>,
    order: BTreeSet<(u64, [u8; 32])>,
}

impl Expiring {
    fn contains_key(&self, k: &[u8; 32]) -> bool {
        self.map.contains_key(k)
    }

    fn insert(&mut self, k: [u8; 32], exp: u64) {
        if let Some(old) = self.map.insert(k, exp) {
            self.order.remove(&(old, k));
        }
        self.order.insert((exp, k));
    }

    fn expire(&mut self, now: u64) {
        while let Some(&(exp, k)) = self.order.first() {
            if exp > now {
                break;
            }
            self.order.pop_first();
            self.map.remove(&k);
        }
    }
}

struct Frame {
    seq: u64,
    stored_at: u64,
    data: Vec<u8>,
}

/// In-memory server state with optional on-disk persistence.
pub struct ServerState {
    config: Config,
    path: Option<PathBuf>,
    dir: HashMap<String, DirEntry>,
    /// The username held by each identity key.
    owners: HashMap<[u8; 32], String>,
    invites: HashMap<[u8; 32], Invite>,
    /// Invites created per user and unix day (memory only, never linked to the invites).
    invite_days: HashMap<String, BTreeMap<u64, usize>>,
    /// Stand-in key checked for unknown users, so they answer like a bad signature.
    dummy_ed: [u8; 32],
    queues: HashMap<[u8; 32], VecDeque<Frame>>,
    /// Times of recent accepted prekey puts per user (memory only).
    prekey_puts: HashMap<String, VecDeque<u64>>,
    next_seq: u64,
    replay: Expiring,
    /// Ephemeral keys of sealed requests (first 16 bytes), by the request's `ts`.
    sealed_seen: BTreeMap<u64, HashSet<[u8; 16]>>,
    blobs: Option<Arc<BlobStore>>,
    pins: HashMap<[u8; 32], PinSlot>,
    prekeys: HashMap<String, Prekeys>,
    srv_sk: Option<[u8; 32]>,
    dirty: bool,
    journal: Vec<Undo>,
    /// `nop` reply bytes left, and the second they were counted at.
    nop_budget: (u64, u64),
}

impl fmt::Debug for ServerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerState")
            .field("users", &self.dir.len())
            .field("queues", &self.queues.len())
            .finish_non_exhaustive()
    }
}

/// `<APPDATA>/Aegis/server` when `appdata` is set, otherwise `<home>/.local/share/aegis/server`.
pub fn default_data_dir_from(appdata: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    fn non_empty(v: Option<&OsStr>) -> Option<&OsStr> {
        v.filter(|s| !s.is_empty())
    }
    if let Some(a) = non_empty(appdata) {
        return Some(Path::new(a).join("Aegis").join("server"));
    }
    non_empty(home).map(|h| Path::new(h).join(".local").join("share").join("aegis").join("server"))
}

fn json_resp(status: u16, v: &serde_json::Value) -> Response {
    Response { status, body: v.to_string() }
}

fn err(status: u16, msg: &str) -> Response {
    json_resp(status, &json!({ "error": msg }))
}

fn one<'a>(q: &'a [(String, String)], key: &str) -> Result<Option<&'a str>, Response> {
    let mut it = q.iter().filter(|(k, _)| k == key);
    let first = it.next().map(|(_, v)| v.as_str());
    if it.next().is_some() {
        return Err(err(400, "duplicate parameter"));
    }
    Ok(first)
}

fn queue_id(q: &[(String, String)]) -> Result<[u8; 32], Response> {
    let s = one(q, "q")?.ok_or_else(|| err(400, "missing q"))?;
    hex::decode_array(s).map_err(|_| err(400, "bad q"))
}

impl ServerState {
    /// Opens (or creates) the state in `data_dir` with the protocol defaults.
    pub fn open(data_dir: &Path) -> Result<Self, ServerError> {
        Self::open_with(data_dir, Config::default())
    }

    pub fn open_with(data_dir: &Path, config: Config) -> Result<Self, ServerError> {
        if data_dir.as_os_str().is_empty() {
            return Err(ServerError::Io("empty data directory".into()));
        }
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(STATE_FILE);
        let mut s = Self::ephemeral(config);
        match std::fs::read(&path) {
            Ok(bytes) => s.load(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        s.srv_sk = Some(load_or_create_key(&data_dir.join(KEY_FILE))?);
        s.path = Some(path);
        let blobs = BlobStore::open(data_dir, s.config.blob_quota_bytes, s.config.blob_ttl_secs)?;
        blobs.purge(aegis_core::now_secs());
        s.blobs = Some(Arc::new(blobs));
        Ok(s)
    }

    /// State that is never written to disk.
    pub fn ephemeral(config: Config) -> Self {
        Self {
            config,
            path: None,
            dir: HashMap::new(),
            owners: HashMap::new(),
            invites: HashMap::new(),
            invite_days: HashMap::new(),
            dummy_ed: aegis_core::identity::ed25519_public(&[1; 32]),
            queues: HashMap::new(),
            prekey_puts: HashMap::new(),
            next_seq: 1,
            replay: Expiring::default(),
            sealed_seen: BTreeMap::new(),
            blobs: None,
            pins: HashMap::new(),
            prekeys: HashMap::new(),
            srv_sk: aegis_core::random_bytes::<32>().ok(),
            dirty: false,
            journal: Vec::new(),
            nop_budget: (0, 0),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn state_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// [`Self::handle`], also returning what the request changed so it can be undone.
    pub(crate) fn handle_tracked(&mut self, req: &Request, now: u64) -> (Response, Changes) {
        let resp = self.handle(req, now);
        (resp, Changes(std::mem::take(&mut self.journal)))
    }

    /// Puts back what `changes` replaced, newest first. Spent proofs of work stay spent.
    fn undo(&mut self, changes: Changes) {
        for u in changes.0.into_iter().rev() {
            match u {
                Undo::Dir(u, Some(e)) => {
                    self.dir.insert(u, e);
                }
                Undo::Dir(u, None) => {
                    if let Some(e) = self.dir.remove(&u) {
                        if self.owners.get(&e.ed) == Some(&u) {
                            self.owners.remove(&e.ed);
                        }
                    }
                }
                Undo::Pin(slot, Some(p)) => {
                    self.pins.insert(slot, p);
                }
                Undo::Pin(slot, None) => {
                    self.pins.remove(&slot);
                }
                Undo::Prekeys(u, Some(p)) => {
                    self.prekeys.insert(u, p);
                }
                Undo::Prekeys(u, None) => {
                    self.prekeys.remove(&u);
                }
                Undo::PrekeyPut(u) => {
                    if let Some(t) = self.prekey_puts.get_mut(&u) {
                        t.pop_back();
                    }
                }
                Undo::Invite(id, Some(i)) => {
                    self.invites.insert(id, i);
                }
                Undo::Invite(id, None) => {
                    self.invites.remove(&id);
                }
                Undo::InviteDay(u, day) => {
                    if let Some(n) = self.invite_days.get_mut(&u).and_then(|d| d.get_mut(&day)) {
                        *n = n.saturating_sub(1);
                    }
                }
                Undo::Frame(q, seq) => {
                    if let Some(fr) = self.queues.get_mut(&q) {
                        if let Some(i) = fr.iter().rposition(|f| f.seq == seq) {
                            fr.remove(i);
                        }
                        if fr.is_empty() {
                            self.queues.remove(&q);
                        }
                    }
                }
            }
        }
    }

    /// Routes one request. `now` is unix seconds.
    pub fn handle(&mut self, req: &Request, now: u64) -> Response {
        self.journal.clear();
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/health") => json_resp(200, &json!({"status": "ok", "protocol": 2})),
            ("GET", "/api/v2/key") => match self.server_public_key() {
                Some(pk) => json_resp(200, &json!({"x": hex::encode(&pk)})),
                None => err(503, "no server key"),
            },
            ("POST", "/api/v2/nop") => self.nop(&req.body, now),
            ("POST", "/api/v2/pin/create") => self.pin_create(&req.body, now),
            ("POST", "/api/v2/pin/open") => self.pin_verify(&req.body, now, false),
            ("POST", "/api/v2/pin/delete") => self.pin_verify(&req.body, now, true),
            ("POST", "/api/v2/prekeys/put") => self.prekeys_put(&req.body, now),
            ("POST", "/api/v2/prekeys/take") => self.prekeys_take(&req.body, now),
            ("POST", "/api/v2/dir/register") => self.register(&req.body, now),
            ("GET", "/api/v2/dir/lookup") => self.lookup(&req.query),
            ("POST", "/api/v2/dir/hide") => self.hide(&req.body, now),
            ("POST", "/api/v2/invite/create") => self.invite_create(&req.body, now),
            ("POST", "/api/v2/invite/redeem") => self.invite_redeem(&req.body, now),
            ("POST", "/api/v2/invite/revoke") => self.invite_revoke(&req.body),
            ("POST", "/api/v2/queue/send") => self.send(&req.query, &req.body, now),
            ("GET", "/api/v2/queue/poll") => self.poll(&req.query, now),
            (_, "/health" | "/api/v2/key" | "/api/v2/nop" | "/api/v2/pin/create" | "/api/v2/pin/open" | "/api/v2/pin/delete" | "/api/v2/prekeys/put" | "/api/v2/prekeys/take" | "/api/v2/dir/register" | "/api/v2/dir/lookup" | "/api/v2/dir/hide" | "/api/v2/invite/create" | "/api/v2/invite/redeem" | "/api/v2/invite/revoke" | "/api/v2/queue/send" | "/api/v2/queue/poll") => {
                err(405, "method not allowed")
            }
            _ => err(404, "not found"),
        }
    }

    fn pow_spent(&mut self, hash: [u8; 32], now: u64) -> bool {
        self.replay.expire(now);
        self.replay.contains_key(&hash)
    }

    fn register(&mut self, body: &[u8], now: u64) -> Response {
        let Ok(text) = core::str::from_utf8(body) else {
            return err(400, "body is not utf-8");
        };
        let Ok(reg) = Registration::from_form(text) else {
            return err(400, "malformed registration");
        };
        if !pow::ts_in_window(reg.ts, now) {
            return err(403, "timestamp out of range");
        }
        if !reg.pow_ok(self.config.pow_bits) {
            return err(403, "insufficient proof of work");
        }
        if !reg.signature_ok() {
            return err(403, "bad signature");
        }
        let hash = pow::pow_hash(&aegis_core::directory::pow_scope(&reg.u), reg.ts, &reg.body_hash(), reg.pow);
        if self.pow_spent(hash, now) {
            return err(403, "proof of work already used");
        }
        match self.dir.get(&reg.u) {
            Some(e) if e.ed != reg.ed => return err(409, "username is bound to another key"),
            // A name already bound to this key keeps working even if a later rule reserves it.
            Some(_) => {}
            None if self.owners.contains_key(&reg.ed) => return err(409, "key already has a username"),
            None if is_reserved_name(&reg.u) && self.config.owner_ed_pk != Some(reg.ed) => {
                return err(403, "reserved username");
            }
            None if self.dir.len() >= self.config.max_directory_entries => {
                return err(503, "directory full");
            }
            None => {}
        }
        self.replay.insert(hash, self.replay_expiry(reg.ts, now));
        // The title is covered by the signature but never stored (section 3).
        let hidden = self.dir.get(&reg.u).is_some_and(|e| e.hidden);
        let old = self.dir.insert(reg.u.clone(), DirEntry { x: reg.x, ed: reg.ed, hidden });
        self.owners.entry(reg.ed).or_insert_with(|| reg.u.clone());
        self.journal.push(Undo::Dir(reg.u, old));
        self.dirty = true;
        json_resp(200, &json!({"ok": true}))
    }

    fn lookup(&self, q: &[(String, String)]) -> Response {
        let u = match one(q, "u") {
            Ok(Some(u)) if is_valid_username(u) => u,
            Ok(_) => return err(400, "bad username"),
            Err(r) => return r,
        };
        match self.dir.get(u) {
            Some(e) if !e.hidden => json_resp(
                200,
                &json!({"u": u, "title": "", "x": hex::encode(&e.x), "ed": hex::encode(&e.ed)}),
            ),
            _ => err(404, "not found"),
        }
    }

    /// The key a signed request of `u` is checked against: the registered one, or a stand-in
    /// for an unknown user so both cases cost the same and answer the same.
    fn signing_key(&self, u: &str) -> (bool, [u8; 32]) {
        match self.dir.get(u) {
            Some(e) => (true, e.ed),
            None => (false, self.dummy_ed),
        }
    }

    fn hide(&mut self, body: &[u8], now: u64) -> Response {
        let Ok(text) = core::str::from_utf8(body) else {
            return err(400, "body is not utf-8");
        };
        let Ok(h) = Hide::from_form(text) else {
            return err(400, "malformed request");
        };
        if !pow::ts_in_window(h.ts, now) {
            return err(403, "timestamp out of range");
        }
        let (known, ed) = self.signing_key(&h.u);
        if !(h.sig_ok(&ed) & known) {
            return err(403, "bad signature");
        }
        let hash = aegis_core::sha256(&[&aegis_core::invite::hide_message(&h.u, h.hidden, h.ts)]);
        if self.pow_spent(hash, now) {
            return err(403, "request already used");
        }
        self.replay.insert(hash, self.replay_expiry(h.ts, now));
        if let Some(e) = self.dir.get_mut(&h.u) {
            if e.hidden != h.hidden {
                let old = e.clone();
                e.hidden = h.hidden;
                self.journal.push(Undo::Dir(h.u, Some(old)));
                self.dirty = true;
            }
        }
        json_resp(200, &json!({"ok": true}))
    }

    fn invite_create(&mut self, body: &[u8], now: u64) -> Response {
        let Ok(text) = core::str::from_utf8(body) else {
            return err(400, "body is not utf-8");
        };
        let Ok(c) = InviteCreate::from_form(text) else {
            return err(400, "malformed invite");
        };
        if !pow::ts_in_window(c.ts, now) {
            return err(403, "timestamp out of range");
        }
        let (known, ed) = self.signing_key(&c.u);
        if !(c.sig_ok(&ed) & known) {
            return err(403, "bad signature");
        }
        let hash = aegis_core::sha256(&[&c.message()]);
        if self.pow_spent(hash, now) {
            return err(403, "request already used");
        }
        let today = now / 86_400;
        let made: usize = self
            .invite_days
            .get(&c.u)
            .map(|d| d.range(today.saturating_sub(INVITE_DAYS - 1)..).map(|(_, n)| n).sum())
            .unwrap_or(0);
        if made >= MAX_OPEN_INVITES {
            return err(429, "too many invites");
        }
        if self.invites.contains_key(&c.id) {
            return err(409, "invite exists");
        }
        if self.invites.len() >= self.config.max_invites {
            return err(503, "invite table full");
        }
        self.replay.insert(hash, self.replay_expiry(c.ts, now));
        // Rounded up to the hour so the expiry does not give away the creation second.
        let exp = (now + INVITE_TTL_SECS).div_ceil(3600) * 3600;
        self.invites.insert(c.id, Invite { exp, sealed: c.sealed });
        *self.invite_days.entry(c.u.clone()).or_default().entry(today).or_default() += 1;
        self.journal.push(Undo::Invite(c.id, None));
        self.journal.push(Undo::InviteDay(c.u, today));
        self.dirty = true;
        json_resp(200, &json!({"ok": true}))
    }

    /// Hands out the bundle once. Unknown, used and expired invites answer the same.
    fn invite_redeem(&mut self, body: &[u8], now: u64) -> Response {
        let Some(id) = invite_id_form(body) else {
            return err(400, "malformed request");
        };
        // An expired record is left for `purge`, so it answers exactly like an unknown id and
        // causes no write.
        match self.invites.get(&id) {
            Some(inv) if inv.exp > now => {}
            _ => return err(404, "not found"),
        }
        let Some(inv) = self.invites.remove(&id) else {
            return err(404, "not found");
        };
        self.journal.push(Undo::Invite(id, Some(inv.clone())));
        self.dirty = true;
        json_resp(200, &json!({"box": hex::encode(&inv.sealed)}))
    }

    /// Whoever holds the link may drop the invite. Its creation still counts towards the cap.
    fn invite_revoke(&mut self, body: &[u8]) -> Response {
        let Some(id) = invite_id_form(body) else {
            return err(400, "malformed request");
        };
        if let Some(inv) = self.invites.remove(&id) {
            self.journal.push(Undo::Invite(id, Some(inv)));
            self.dirty = true;
        }
        json_resp(200, &json!({"ok": true}))
    }

    fn send(&mut self, q: &[(String, String)], body: &[u8], now: u64) -> Response {
        let qid = match queue_id(q) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let parse = |k: &str| -> Result<u64, Response> {
            one(q, k)?
                .and_then(|s| parse_u64(s).ok())
                .ok_or_else(|| err(400, "bad parameter"))
        };
        let (ts, nonce) = match (parse("ts"), parse("pow")) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(r), _) | (_, Err(r)) => return r,
        };
        let Ok(frame) = hex::decode_bytes(body) else {
            return err(400, "body is not lowercase hex");
        };
        if !pad::is_bucket(frame.len()) {
            return err(400, "bad frame size");
        }
        if !pow::ts_in_window(ts, now) {
            return err(403, "timestamp out of range");
        }
        let qhex = hex::encode(&qid);
        let body_hash = pow::body_hash_hex(body);
        self.purge_queue(&qid, now);
        let len = self.queues.get(&qid).map_or(0, VecDeque::len);
        let base = self.config.pow_bits;
        if len >= self.config.max_frames_per_queue {
            // Fullness is told only for a fresh base proof of work, which is then spent.
            if !pow::verify(&qhex, ts, &body_hash, nonce, base) {
                return err(403, "insufficient proof of work");
            }
            let hash = pow::pow_hash(&qhex, ts, &body_hash, nonce);
            if self.pow_spent(hash, now) {
                return err(403, "proof of work already used");
            }
            self.replay.insert(hash, self.replay_expiry(ts, now));
            return err(429, "queue full");
        }
        let need = base + fill_extra_bits(len, self.config.max_frames_per_queue);
        if !pow::verify(&qhex, ts, &body_hash, nonce, need) {
            if need > base && pow::verify(&qhex, ts, &body_hash, nonce, base) {
                return json_resp(429, &json!({"error": "queue is filling, more proof of work needed", "bits": need}));
            }
            return err(403, "insufficient proof of work");
        }
        let hash = pow::pow_hash(&qhex, ts, &body_hash, nonce);
        if self.pow_spent(hash, now) {
            return err(403, "proof of work already used");
        }
        if official_queue_id() == Some(qid) {
            let sig = one(q, "sig").ok().flatten().and_then(|s| hex::decode_array::<64>(s).ok());
            let ok = match (self.config.owner_ed_pk, sig) {
                (Some(pk), Some(sig)) => aegis_core::official::post_auth_ok(&pk, &qid, ts, &frame, &sig),
                _ => false,
            };
            if !ok {
                return err(403, "official queue needs the owner signature");
            }
        }
        match self.queues.get(&qid) {
            Some(fr) if fr.len() >= self.config.max_frames_per_queue => {
                return err(429, "queue full");
            }
            None if self.queues.len() >= self.config.max_queues => {
                return err(503, "server full");
            }
            _ => {}
        }
        self.replay.insert(hash, self.replay_expiry(ts, now));
        let seq = self.next_seq;
        self.next_seq += 1;
        self.queues
            .entry(qid)
            .or_default()
            .push_back(Frame { seq, stored_at: now, data: frame });
        self.journal.push(Undo::Frame(qid, seq));
        self.dirty = true;
        json_resp(200, &json!({"seq": seq}))
    }

    fn poll(&mut self, q: &[(String, String)], now: u64) -> Response {
        let qid = match queue_id(q) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let after = match one(q, "after") {
            Ok(None) => 0,
            Ok(Some(s)) => match parse_u64(s) {
                Ok(n) => n,
                Err(_) => return err(400, "bad after"),
            },
            Err(r) => return r,
        };
        self.purge_queue(&qid, now);
        let mut frames = Vec::new();
        let mut size = POLL_ENVELOPE_BYTES;
        let mut has_more = false;
        if let Some(fr) = self.queues.get(&qid) {
            for f in fr.iter().filter(|f| f.seq > after) {
                // `{"seq":N,"d":"..."},` per frame.
                let item = 2 * f.data.len() + 40;
                if frames.len() >= POLL_PAGE || (!frames.is_empty() && size + item > POLL_MAX_BYTES) {
                    has_more = true;
                    break;
                }
                size += item;
                frames.push(json!({"seq": f.seq, "d": hex::encode(&f.data)}));
            }
        }
        let next = frames
            .last()
            .and_then(|f| f["seq"].as_u64())
            .unwrap_or(after);
        json_resp(200, &json!({"frames": frames, "next": next, "has_more": has_more}))
    }

    fn purge_queue(&mut self, qid: &[u8; 32], now: u64) {
        let ttl = self.config.ttl_secs;
        let Some(fr) = self.queues.get_mut(qid) else {
            return;
        };
        let before = fr.len();
        while fr.front().is_some_and(|f| f.stored_at.saturating_add(ttl) <= now) {
            fr.pop_front();
        }
        if fr.is_empty() {
            self.queues.remove(qid);
        }
        if self.queues.get(qid).map_or(0, VecDeque::len) != before {
            self.dirty = true;
        }
    }

    /// Records the ephemeral key of a sealed request. False when the request has no timestamp,
    /// when it is outside the window, when the key was already seen, or when that timestamp
    /// second is full. A key is kept until its `ts` can no longer pass the window check, and a
    /// replay carries the same `ts`, so only that second has to be searched.
    pub fn sealed_admit(&mut self, e_pk: [u8; 32], ts: Option<u64>, now: u64) -> bool {
        let Some(ts) = ts.filter(|&t| pow::ts_in_window(t, now)) else {
            return false;
        };
        self.expire_sealed(now);
        let mut key = [0u8; 16];
        key.copy_from_slice(&e_pk[..16]);
        let second = self.sealed_seen.entry(ts).or_default();
        if second.len() >= SEALED_PER_SECOND {
            return false;
        }
        second.insert(key)
    }

    fn expire_sealed(&mut self, now: u64) {
        while let Some(e) = self.sealed_seen.first_entry() {
            if e.key().saturating_add(pow::MAX_SKEW_SECS + 1) > now {
                break;
            }
            e.remove();
        }
    }

    /// A spent proof of work stays remembered until its `ts` can no longer pass the window check.
    fn replay_expiry(&self, ts: u64, now: u64) -> u64 {
        (now + self.config.replay_secs).max(ts.saturating_add(pow::MAX_SKEW_SECS + 1))
    }

    /// Drops expired frames, empty queues and expired replay entries.
    pub fn purge(&mut self, now: u64) {
        let ttl = self.config.ttl_secs;
        let mut changed = false;
        self.queues.retain(|_, fr| {
            let before = fr.len();
            while fr.front().is_some_and(|f| f.stored_at.saturating_add(ttl) <= now) {
                fr.pop_front();
            }
            changed |= fr.len() != before;
            !fr.is_empty()
        });
        self.replay.expire(now);
        self.expire_sealed(now);
        self.prekey_puts.retain(|_, t| t.back().is_some_and(|b| b.saturating_add(3600) > now));
        let before = self.invites.len();
        self.invites.retain(|_, i| i.exp > now);
        changed |= self.invites.len() != before;
        let today = now / 86_400;
        self.invite_days.retain(|_, d| {
            d.retain(|day, n| *n > 0 && day + INVITE_DAYS > today);
            !d.is_empty()
        });
        let before = self.pins.len();
        self.pins.retain(|_, p| p.last_used.saturating_add(PIN_TTL_SECS) > now);
        changed |= self.pins.len() != before;
        if let Some(b) = &self.blobs {
            b.purge(now);
        }
        self.dirty |= changed;
    }

    /// Public half of the long-term transport key (section 23).
    pub fn server_public_key(&self) -> Option<[u8; 32]> {
        self.srv_sk.as_ref().map(aegis_core::identity::x25519_public)
    }

    /// Secret half, for opening sealed requests.
    pub fn server_secret_key(&self) -> Option<[u8; 32]> {
        self.srv_sk
    }

    pub fn pin_slots(&self) -> usize {
        self.pins.len()
    }

    fn prekeys_put(&mut self, body: &[u8], now: u64) -> Response {
        let Ok(text) = core::str::from_utf8(body) else {
            return err(400, "body is not utf-8");
        };
        let Ok(put) = PrekeyPut::from_form(text) else {
            return err(400, "malformed prekeys");
        };
        if !pow::ts_in_window(put.ts, now) {
            return err(403, "timestamp out of range");
        }
        // Unknown users answer like a bad signature, so a hidden name cannot be told apart.
        let (known, ed) = self.signing_key(&put.u);
        if !(put.sig_ok(&ed) & put.spk_sig_ok(&ed) & known) {
            return err(403, "bad signature");
        }
        let hash = aegis_core::sha256(&[&put.message()]);
        if self.pow_spent(hash, now) {
            return err(403, "request already used");
        }
        if put.spk_ts > now.saturating_add(pow::MAX_SKEW_SECS) {
            return err(403, "spk_ts in the future");
        }
        let stored = self.prekeys.get(&put.u);
        let stale = stored.is_some_and(|p| {
            put.spk_ts < p.spk_ts || (put.spk_ts == p.spk_ts && (put.spk != p.spk || put.spk_sig != p.spk_sig))
        });
        if stale {
            return err(409, "spk_ts is not newer");
        }
        if stored.is_none() && self.prekeys.len() >= self.config.max_prekey_users {
            return err(503, "prekey table full");
        }
        {
            let times = self.prekey_puts.entry(put.u.clone()).or_default();
            while times.front().is_some_and(|t| t.saturating_add(3600) <= now) {
                times.pop_front();
            }
            let (gap, per_hour) = (self.config.prekey_put_interval_secs, self.config.prekey_puts_per_hour);
            let too_soon = gap > 0 && times.back().is_some_and(|t| t.saturating_add(gap) > now);
            let too_many = per_hour > 0 && times.len() >= per_hour;
            if too_soon || too_many {
                return err(429, "too many prekey uploads");
            }
            times.push_back(now);
        }
        self.journal.push(Undo::PrekeyPut(put.u.clone()));
        self.journal.push(Undo::Prekeys(put.u.clone(), self.prekeys.get(&put.u).cloned()));
        self.replay.insert(hash, self.replay_expiry(put.ts, now));
        let rec = self.prekeys.entry(put.u).or_insert_with(|| Prekeys {
            spk: put.spk,
            spk_ts: put.spk_ts,
            spk_sig: put.spk_sig,
            opks: VecDeque::new(),
        });
        rec.spk = put.spk;
        rec.spk_ts = put.spk_ts;
        rec.spk_sig = put.spk_sig;
        for o in put.opks {
            if !rec.opks.contains(&o) {
                rec.opks.push_back(o);
            }
        }
        while rec.opks.len() > MAX_OPKS {
            rec.opks.pop_front();
        }
        self.dirty = true;
        json_resp(200, &json!({"opks": rec.opks.len()}))
    }

    fn prekeys_take(&mut self, body: &[u8], now: u64) -> Response {
        let Ok(text) = core::str::from_utf8(body) else {
            return err(400, "body is not utf-8");
        };
        let Ok(take) = PrekeyTake::from_form(text) else {
            return err(400, "malformed request");
        };
        if !pow::ts_in_window(take.ts, now) {
            return err(403, "timestamp out of range");
        }
        if !take.pow_ok(self.config.pow_bits) {
            return err(403, "insufficient proof of work");
        }
        let hash = pow::pow_hash(
            &aegis_core::prekeys::take_scope(&take.u),
            take.ts,
            &aegis_core::prekeys::take_body_hash(&take.u, take.ts),
            take.pow,
        );
        if self.pow_spent(hash, now) {
            return err(403, "proof of work already used");
        }
        self.replay.insert(hash, self.replay_expiry(take.ts, now));
        // A hidden user's prekeys go only to callers that already know its key.
        let visible = match (self.dir.get(&take.u), take.ed) {
            (Some(e), Some(ed)) => ct_eq(&e.ed, &ed),
            (Some(e), None) => !e.hidden,
            (None, _) => false,
        };
        let Some(rec) = self.prekeys.get_mut(&take.u).filter(|_| visible) else {
            return err(404, "not found");
        };
        let before = rec.clone();
        let opk = rec.opks.pop_front();
        if opk.is_some() {
            self.journal.push(Undo::Prekeys(take.u.clone(), Some(before)));
            self.dirty = true;
        }
        json_resp(
            200,
            &json!({
                "spk": hex::encode(&rec.spk),
                "spk_ts": rec.spk_ts,
                "spk_sig": hex::encode(&rec.spk_sig),
                "opk": opk.map(|o| hex::encode(&o)).unwrap_or_default(),
            }),
        )
    }

    /// Parses a form body with exactly the given keys, each a 32-byte lowercase hex value
    /// (`ts` and `pow` are decimal).
    fn pin_form(body: &[u8], keys: &[&str]) -> Result<(Vec<[u8; 32]>, u64, u64), Response> {
        let text = core::str::from_utf8(body).map_err(|_| err(400, "body is not utf-8"))?;
        let pairs = aegis_core::text::parse_pairs(text).map_err(|_| err(400, "malformed form"))?;
        if pairs.len() != keys.len() + 2 {
            return Err(err(400, "malformed form"));
        }
        let mut vals = Vec::new();
        for k in keys {
            let v = one(&pairs, k)?.ok_or_else(|| err(400, "missing field"))?;
            vals.push(hex::decode_array::<32>(v).map_err(|_| err(400, "bad field"))?);
        }
        let num = |k: &str| -> Result<u64, Response> {
            one(&pairs, k)?
                .and_then(|s| parse_u64(s).ok())
                .ok_or_else(|| err(400, "bad parameter"))
        };
        Ok((vals, num("ts")?, num("pow")?))
    }

    /// Checks ts window, proof of work and replay for a PIN request. Returns the pow hash;
    /// the caller records it once the request is accepted for processing.
    fn pin_pow(&mut self, slot: &[u8; 32], hash_fields: &[&[u8; 32]], ts: u64, nonce: u64, now: u64) -> Result<[u8; 32], Response> {
        if !pow::ts_in_window(ts, now) {
            return Err(err(403, "timestamp out of range"));
        }
        let joined = hash_fields.iter().map(|f| hex::encode(*f)).collect::<Vec<_>>().join("\n");
        let scope = format!("pin:{}", hex::encode(slot));
        let body_hash = pow::body_hash_hex(joined.as_bytes());
        if !pow::verify(&scope, ts, &body_hash, nonce, self.config.pow_bits) {
            return Err(err(403, "insufficient proof of work"));
        }
        let hash = pow::pow_hash(&scope, ts, &body_hash, nonce);
        if self.pow_spent(hash, now) {
            return Err(err(403, "proof of work already used"));
        }
        Ok(hash)
    }

    fn pin_create(&mut self, body: &[u8], now: u64) -> Response {
        let (vals, ts, nonce) = match Self::pin_form(body, &["slot", "v", "s"]) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let (slot, v, s) = (vals[0], vals[1], vals[2]);
        let hash = match self.pin_pow(&slot, &[&slot, &v, &s], ts, nonce, now) {
            Ok(h) => h,
            Err(r) => return r,
        };
        if self.pins.contains_key(&slot) {
            return err(409, "slot exists");
        }
        if self.pins.len() >= self.config.max_pin_slots {
            return err(503, "pin table full");
        }
        self.replay.insert(hash, self.replay_expiry(ts, now));
        self.pins.insert(slot, PinSlot { v, s, fails: 0, last_used: now, last_attempt: 0 });
        self.journal.push(Undo::Pin(slot, None));
        self.dirty = true;
        json_resp(200, &json!({}))
    }

    /// `pin/open` (returns the secret) and `pin/delete` (removes the slot) share the attempt counter.
    fn pin_verify(&mut self, body: &[u8], now: u64, delete: bool) -> Response {
        let (vals, ts, nonce) = match Self::pin_form(body, &["slot", "v"]) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let (slot, v) = (vals[0], vals[1]);
        let hash = match self.pin_pow(&slot, &[&slot, &v], ts, nonce, now) {
            Ok(h) => h,
            Err(r) => return r,
        };
        let expiry = self.replay_expiry(ts, now);
        let Some(entry) = self.pins.get(&slot) else {
            self.replay.insert(hash, expiry);
            return err(404, "not found");
        };
        if entry.last_used.saturating_add(PIN_TTL_SECS) <= now {
            self.pins.remove(&slot);
            self.dirty = true;
            self.replay.insert(hash, expiry);
            return err(404, "not found");
        }
        // The only throttle is per slot: a throttled request is not counted and its proof of work
        // stays usable. There is deliberately no budget shared between slots: attackers can open
        // as many slots of their own as they like and would starve everybody else with it.
        // Every wrong verifier counts against its own slot, so nothing is guessed for free.
        let min = self.config.pin_min_interval_secs;
        if min > 0 && entry.last_attempt != 0 && now < entry.last_attempt.saturating_add(min) {
            return err(429, "too many attempts");
        }
        self.replay.insert(hash, expiry);
        self.journal.push(Undo::Pin(slot, Some(entry.clone())));
        let Some(entry) = self.pins.get_mut(&slot) else {
            return err(404, "not found");
        };
        entry.last_attempt = now;
        if ct_eq(&entry.v, &v) {
            self.dirty = true;
            if delete {
                self.pins.remove(&slot);
                return json_resp(200, &json!({}));
            }
            entry.fails = 0;
            entry.last_used = now;
            return json_resp(200, &json!({"s": hex::encode(&entry.s)}));
        }
        entry.fails += 1;
        self.dirty = true;
        let left = PIN_MAX_FAILS.saturating_sub(entry.fails);
        if left == 0 {
            self.pins.remove(&slot);
        }
        json_resp(403, &json!({"left": left}))
    }

    /// The blob store, present when the state is backed by a data directory.
    pub fn blob_store(&self) -> Option<&Arc<BlobStore>> {
        self.blobs.as_ref()
    }

    /// Validates a blob upload, spends its proof of work and reserves quota. The caller then
    /// writes the data outside the state lock with `BlobStore::write_reserved`.
    fn blob_put_prepare(
        &mut self,
        q: &[(String, String)],
        body: &[u8],
        now: u64,
    ) -> Result<(Arc<BlobStore>, String), Response> {
        let id = match one(q, "id") {
            Ok(Some(id)) if is_blob_id(id) => id.to_owned(),
            Ok(_) => return Err(err(400, "bad id")),
            Err(r) => return Err(r),
        };
        let parse = |k: &str| -> Result<u64, Response> {
            one(q, k)?
                .and_then(|s| parse_u64(s).ok())
                .ok_or_else(|| err(400, "bad parameter"))
        };
        let (ts, nonce) = match (parse("ts"), parse("pow")) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(r), _) | (_, Err(r)) => return Err(r),
        };
        if body.is_empty() {
            return Err(err(400, "empty body"));
        }
        if body.len() > MAX_BLOB_BYTES {
            return Err(err(413, "request too large"));
        }
        if !pow::ts_in_window(ts, now) {
            return Err(err(403, "timestamp out of range"));
        }
        let scope = format!("blob:{id}");
        let body_hash = pow::body_hash_hex(body);
        if !pow::verify(&scope, ts, &body_hash, nonce, self.config.pow_bits) {
            return Err(err(403, "insufficient proof of work"));
        }
        let hash = pow::pow_hash(&scope, ts, &body_hash, nonce);
        if self.pow_spent(hash, now) {
            return Err(err(403, "proof of work already used"));
        }
        let Some(store) = self.blobs.clone() else {
            return Err(err(503, "blob store unavailable"));
        };
        match store.reserve(&id, body.len() as u64, now) {
            Ok(()) => {}
            Err(Reserve::Exists) => return Err(err(409, "blob exists")),
            Err(Reserve::OverQuota) => return Err(err(503, "blob store full")),
        }
        self.replay.insert(hash, self.replay_expiry(ts, now));
        Ok((store, id))
    }

    pub fn queue_len(&self, qid: &[u8; 32]) -> usize {
        self.queues.get(qid).map_or(0, VecDeque::len)
    }

    pub fn directory_len(&self) -> usize {
        self.dir.len()
    }

    /// Serialized state if there are unsaved changes (clears the dirty flag).
    fn take_snapshot(&mut self) -> Option<(PathBuf, Vec<u8>)> {
        let path = self.path.clone()?;
        if !self.dirty {
            return None;
        }
        self.dirty = false;
        Some((path, self.encode()))
    }

    fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(MAGIC);
        o.extend_from_slice(&self.next_seq.to_be_bytes());
        put_len(&mut o, self.dir.len());
        for (u, e) in &self.dir {
            put_bytes(&mut o, u.as_bytes());
            o.extend_from_slice(&e.x);
            o.extend_from_slice(&e.ed);
            o.push(u8::from(e.hidden));
        }
        put_len(&mut o, self.pins.len());
        for (slot, p) in &self.pins {
            o.extend_from_slice(slot);
            o.extend_from_slice(&p.v);
            o.extend_from_slice(&p.s);
            o.push(p.fails);
            o.extend_from_slice(&p.last_used.to_be_bytes());
        }
        put_len(&mut o, self.prekeys.len());
        for (u, p) in &self.prekeys {
            put_bytes(&mut o, u.as_bytes());
            o.extend_from_slice(&p.spk);
            o.extend_from_slice(&p.spk_ts.to_be_bytes());
            o.extend_from_slice(&p.spk_sig);
            put_len(&mut o, p.opks.len());
            for k in &p.opks {
                o.extend_from_slice(k);
            }
        }
        put_len(&mut o, self.invites.len());
        for (id, i) in &self.invites {
            o.extend_from_slice(id);
            o.extend_from_slice(&i.exp.to_be_bytes());
            put_bytes(&mut o, &i.sealed);
        }
        put_len(&mut o, self.queues.len());
        for (q, frames) in &self.queues {
            o.extend_from_slice(q);
            put_len(&mut o, frames.len());
            for f in frames {
                o.extend_from_slice(&f.seq.to_be_bytes());
                o.extend_from_slice(&f.stored_at.to_be_bytes());
                put_bytes(&mut o, &f.data);
            }
        }
        o
    }

    fn load(&mut self, bytes: &[u8]) -> Result<(), ServerError> {
        let mut r = Reader { b: bytes, i: 0 };
        let parsed = (|| -> Option<()> {
            let magic = r.take(8)?;
            if magic != MAGIC && magic != MAGIC_V4 && magic != MAGIC_V3 && magic != MAGIC_V2 {
                return None;
            }
            let has_pins = magic != MAGIC_V2;
            let has_prekeys = magic == MAGIC || magic == MAGIC_V4;
            // Older files carry a display title per user; it is read and dropped.
            let has_titles = magic != MAGIC;
            self.next_seq = r.u64()?;
            for _ in 0..r.u32()? {
                let u = String::from_utf8(r.bytes()?.to_vec()).ok()?;
                if has_titles {
                    core::str::from_utf8(r.bytes()?).ok()?;
                }
                let x: [u8; 32] = r.take(32)?.try_into().ok()?;
                let ed: [u8; 32] = r.take(32)?.try_into().ok()?;
                let hidden = if has_titles {
                    false
                } else {
                    match r.take(1)?[0] {
                        0 => false,
                        1 => true,
                        _ => return None,
                    }
                };
                if !is_valid_username(&u) {
                    return None;
                }
                self.owners.entry(ed).or_insert_with(|| u.clone());
                self.dir.insert(u, DirEntry { x, ed, hidden });
            }
            if has_pins {
                for _ in 0..r.u32()? {
                    let slot: [u8; 32] = r.take(32)?.try_into().ok()?;
                    let v: [u8; 32] = r.take(32)?.try_into().ok()?;
                    let s: [u8; 32] = r.take(32)?.try_into().ok()?;
                    let fails = r.take(1)?[0];
                    let last_used = r.u64()?;
                    if fails >= PIN_MAX_FAILS {
                        return None;
                    }
                    self.pins.insert(slot, PinSlot { v, s, fails, last_used, last_attempt: 0 });
                }
            }
            if has_prekeys {
                for _ in 0..r.u32()? {
                    let u = String::from_utf8(r.bytes()?.to_vec()).ok()?;
                    let spk: [u8; 32] = r.take(32)?.try_into().ok()?;
                    let spk_ts = r.u64()?;
                    let spk_sig: [u8; 64] = r.take(64)?.try_into().ok()?;
                    let n = r.u32()? as usize;
                    if n > MAX_OPKS || !is_valid_username(&u) {
                        return None;
                    }
                    let mut opks = VecDeque::new();
                    for _ in 0..n {
                        opks.push_back(<[u8; 32]>::try_from(r.take(32)?).ok()?);
                    }
                    self.prekeys.insert(u, Prekeys { spk, spk_ts, spk_sig, opks });
                }
            }
            if !has_titles {
                for _ in 0..r.u32()? {
                    let id: [u8; 32] = r.take(32)?.try_into().ok()?;
                    let exp = r.u64()?;
                    let sealed = r.bytes()?.to_vec();
                    if sealed.len() != aegis_core::invite::BOX_LEN {
                        return None;
                    }
                    self.invites.insert(id, Invite { exp, sealed });
                }
            }
            for _ in 0..r.u32()? {
                let q: [u8; 32] = r.take(32)?.try_into().ok()?;
                let mut frames = VecDeque::new();
                for _ in 0..r.u32()? {
                    let seq = r.u64()?;
                    let stored_at = r.u64()?;
                    let data = r.bytes()?.to_vec();
                    if !pad::is_bucket(data.len()) || seq >= self.next_seq {
                        return None;
                    }
                    frames.push_back(Frame { seq, stored_at, data });
                }
                self.queues.insert(q, frames);
            }
            (r.i == bytes.len()).then_some(())
        })();
        if parsed.is_none() {
            self.dir.clear();
            self.owners.clear();
            self.invites.clear();
            self.pins.clear();
            self.prekeys.clear();
            self.queues.clear();
            return Err(ServerError::Corrupt);
        }
        Ok(())
    }
}

/// Handles the `/api/v2/blob/*` routes. File I/O happens outside the state lock.
pub fn handle_blob(state: &Mutex<ServerState>, req: &Request, now: u64) -> BlobReply {
    let lock = || state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/api/v2/blob/put") => {
            let prepared = lock().blob_put_prepare(&req.query, &req.body, now);
            match prepared {
                Ok((store, id)) => match store.write_reserved(&id, &req.body, now) {
                    Ok(()) => BlobReply::Json(json_resp(200, &json!({}))),
                    Err(_) => BlobReply::Json(err(503, "storage error")),
                },
                Err(r) => BlobReply::Json(r),
            }
        }
        ("GET", "/api/v2/blob/get") => {
            let id = match one(&req.query, "id") {
                Ok(Some(id)) if is_blob_id(id) => id,
                Ok(_) => return BlobReply::Json(err(400, "bad id")),
                Err(r) => return BlobReply::Json(r),
            };
            let store = lock().blobs.clone();
            match store.and_then(|b| b.get(id, now)) {
                Some(bytes) => BlobReply::Bytes(bytes),
                None => BlobReply::Json(err(404, "not found")),
            }
        }
        (_, "/api/v2/blob/put" | "/api/v2/blob/get") => BlobReply::Json(err(405, "method not allowed")),
        _ => BlobReply::Json(err(404, "not found")),
    }
}

/// Cover traffic (section 26): `BE32(resp_len) || random` is answered with `resp_len` zero bytes.
fn official_queue_id() -> Option<[u8; 32]> {
    static Q: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();
    *Q.get_or_init(|| aegis_core::official::official_queue().ok())
}

/// Extra proof-of-work bits for a queue holding `len` of `max` frames: none up to half full,
/// then one more bit for every further 12.5% (so +1 from 62.5%, +4 when full).
fn fill_extra_bits(len: usize, max: usize) -> u32 {
    if max == 0 {
        return 0;
    }
    let eighths = len.saturating_mul(8) / max;
    u32::try_from(eighths.saturating_sub(4)).unwrap_or(4).min(4)
}

const RESERVED_NAMES: [&str; 5] = ["owner", "aegis", "admin", "support", "official"];

/// Folds look-alike spellings (digits, underscores) to a plain skeleton.
fn name_skeleton(u: &str) -> String {
    u.chars()
        .filter(|c| *c != '_')
        .map(|c| match c {
            '0' => 'o',
            '1' | 'l' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            '6' | '8' => 'b',
            '9' => 'g',
            '2' => 'z',
            c => c.to_ascii_lowercase(),
        })
        .collect::<String>()
        .replace("rn", "m")
        .replace("vv", "w")
}

fn is_reserved_name(u: &str) -> bool {
    let sk = name_skeleton(u);
    RESERVED_NAMES.iter().any(|r| sk.contains(&name_skeleton(r)))
}

impl ServerState {
    /// Cover traffic (section 26). Replies draw on a byte budget shared by everyone, so cheap
    /// requests cannot be turned into a bandwidth amplifier.
    fn nop(&mut self, body: &[u8], now: u64) -> Response {
        let Some(len) = body.first_chunk::<4>().map(|b| u32::from_be_bytes(*b) as usize) else {
            return err(400, "short body");
        };
        if len > aegis_core::cover::max_resp_len(body.len()) as usize {
            return err(400, "bad length");
        }
        let rate = self.config.nop_bytes_per_sec;
        let cap = rate.saturating_mul(NOP_BURST_SECS);
        let (left, at) = self.nop_budget;
        let left = if at == 0 { cap } else { left.saturating_add(rate.saturating_mul(now.saturating_sub(at))).min(cap) };
        let Some(rest) = left.checked_sub(len as u64) else {
            self.nop_budget = (left, now);
            return err(429, "busy");
        };
        self.nop_budget = (rest, now);
        Response { status: 200, body: "\0".repeat(len) }
    }
}

/// Days an invite creation counts towards the cap.
const INVITE_DAYS: u64 = INVITE_TTL_SECS / 86_400;

fn invite_id_form(body: &[u8]) -> Option<[u8; 32]> {
    aegis_core::invite::parse_id_form(core::str::from_utf8(body).ok()?).ok()
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    std::hint::black_box(d) == 0
}

/// Loads the server key, or creates it on first start. A bad file is an error, never replaced.
fn load_or_create_key(path: &Path) -> Result<[u8; 32], ServerError> {
    match std::fs::read(path) {
        Ok(b) => return <[u8; 32]>::try_from(b.as_slice()).map_err(|_| ServerError::CorruptKey),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let sk = aegis_core::random_bytes::<32>().map_err(|_| ServerError::Io("rng".into()))?;
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    let res = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&sk)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(sk)
}

fn put_len(o: &mut Vec<u8>, n: usize) {
    o.extend_from_slice(&u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes());
}

fn put_bytes(o: &mut Vec<u8>, b: &[u8]) {
    put_len(o, b.len());
    o.extend_from_slice(b);
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// Writes the state to disk if it changed since the last call.
pub fn persist_now(state: &Mutex<ServerState>) -> Result<(), ServerError> {
    persist(state, None)
}

/// [`persist_now`] for a request that must be on disk before its reply. If the write fails,
/// `changes` are taken back out of memory before any other snapshot can include them.
pub(crate) fn persist_or_undo(state: &Mutex<ServerState>, changes: Changes) -> Result<(), ServerError> {
    persist(state, Some(changes))
}

fn persist(state: &Mutex<ServerState>, changes: Option<Changes>) -> Result<(), ServerError> {
    // One writer at a time: a snapshot taken later is always written later.
    static PERSIST: Mutex<()> = Mutex::new(());
    let _one = PERSIST.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let snap = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take_snapshot();
    if let Some((path, bytes)) = snap {
        if let Err(e) = aegis_core::vault::write_atomic(&path, &bytes) {
            let mut s = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            s.dirty = true;
            if let Some(c) = changes {
                s.undo(c);
            }
            return Err(ServerError::Io(e.to_string()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::identity::Identity;
    use aegis_core::text::pct_encode;

    const NOW: u64 = 1_700_000_000;

    fn cfg() -> Config {
        Config { pow_bits: 6, ..Config::default() }
    }

    fn req(method: &str, path: &str, query: &str, body: &[u8]) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query: aegis_core::text::parse_pairs(query).unwrap(),
            body: body.to_vec(),
        }
    }

    fn reg_form(id: &Identity, u: &str, title: &str, ts: u64, bits: u32) -> String {
        let mut r = Registration::sign(id, u, title, ts).unwrap();
        r.mine(bits);
        r.to_form()
    }

    fn send_req(q: &[u8; 32], frame_len: usize, ts: u64, bits: u32, fill: u8) -> Request {
        let body = hex::encode(&vec![fill; frame_len]);
        let qh = hex::encode(q);
        let n = pow::mine(&qh, ts, &pow::body_hash_hex(body.as_bytes()), bits);
        req("POST", "/api/v2/queue/send", &format!("q={qh}&ts={ts}&pow={n}"), body.as_bytes())
    }

    fn poll(s: &mut ServerState, q: &[u8; 32], after: u64, now: u64) -> serde_json::Value {
        let r = s.handle(
            &req("GET", "/api/v2/queue/poll", &format!("q={}&after={after}", hex::encode(q)), b""),
            now,
        );
        assert_eq!(r.status, 200);
        serde_json::from_str(&r.body).unwrap()
    }

    #[test]
    fn health_and_unknown_routes() {
        let mut s = ServerState::ephemeral(cfg());
        let r = s.handle(&req("GET", "/health", "", b""), NOW);
        assert_eq!((r.status, r.body.as_str()), (200, r#"{"protocol":2,"status":"ok"}"#));
        assert_eq!(s.handle(&req("GET", "/", "", b""), NOW).status, 404);
        assert_eq!(s.handle(&req("GET", "/api/v1/queue/send", "", b""), NOW).status, 404);
        assert_eq!(s.handle(&req("POST", "/health", "", b""), NOW).status, 405);
        assert_eq!(s.handle(&req("GET", "/api/v2/dir/register", "", b""), NOW).status, 405);
    }

    #[test]
    fn register_and_lookup() {
        let mut s = ServerState::ephemeral(cfg());
        let id = Identity::from_secrets([1; 32], [2; 32]);
        let form = reg_form(&id, "alice", "Alice <b>", NOW, 6);
        let r = s.handle(&req("POST", "/api/v2/dir/register", "", form.as_bytes()), NOW);
        assert_eq!(r.status, 200, "{}", r.body);
        let r = s.handle(&req("GET", "/api/v2/dir/lookup", "u=alice", b""), NOW);
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["u"], "alice");
        assert_eq!(v["title"], "");
        assert_eq!(v["x"], hex::encode(&id.x_public()));
        assert_eq!(v["ed"], hex::encode(&id.ed_public()));
        assert_eq!(s.handle(&req("GET", "/api/v2/dir/lookup", "u=bob", b""), NOW).status, 404);
        for bad in ["u=Alice", "u=al", "u=ali", "", "u=a&u=b", "u=%2e%2e"] {
            let st = s.handle(&req("GET", "/api/v2/dir/lookup", bad, b""), NOW).status;
            assert!(st == 400 || st == 404, "{bad} -> {st}");
        }
        assert_eq!(s.handle(&req("GET", "/api/v2/dir/lookup", "u=al", b""), NOW).status, 400);
        assert_eq!(s.handle(&req("GET", "/api/v2/dir/lookup", "u=ali%2A", b""), NOW).status, 400);
    }

    #[test]
    fn lookup_is_exact_only() {
        let mut s = ServerState::ephemeral(cfg());
        let id = Identity::from_secrets([1; 32], [2; 32]);
        let form = reg_form(&id, "alice", "", NOW, 6);
        s.handle(&req("POST", "/api/v2/dir/register", "", form.as_bytes()), NOW);
        for q in ["u=alic", "u=alice2", "u=ali%25", "u=a*"] {
            assert_ne!(s.handle(&req("GET", "/api/v2/dir/lookup", q, b""), NOW).status, 200, "{q}");
        }
    }

    #[test]
    fn title_is_never_stored_and_other_key_conflicts() {
        let mut s = ServerState::ephemeral(cfg());
        let a = Identity::from_secrets([1; 32], [2; 32]);
        let m = Identity::from_secrets([1; 32], [9; 32]);
        let post = |s: &mut ServerState, f: &str, now| {
            s.handle(&req("POST", "/api/v2/dir/register", "", f.as_bytes()), now).status
        };
        assert_eq!(post(&mut s, &reg_form(&a, "alice", "One", NOW, 6), NOW), 200);
        assert_eq!(post(&mut s, &reg_form(&a, "alice", "Two", NOW + 1, 6), NOW + 1), 200);
        let r = s.handle(&req("GET", "/api/v2/dir/lookup", "u=alice", b""), NOW);
        assert!(!r.body.contains("One") && !r.body.contains("Two"));
        assert_eq!(post(&mut s, &reg_form(&m, "alice", "Evil", NOW + 2, 6), NOW + 2), 409);
        assert!(!s.handle(&req("GET", "/api/v2/dir/lookup", "u=alice", b""), NOW).body.contains("Evil"));
    }

    #[test]
    fn register_rejections() {
        let mut s = ServerState::ephemeral(cfg());
        let id = Identity::from_secrets([1; 32], [2; 32]);
        let post = |s: &mut ServerState, f: &str| {
            s.handle(&req("POST", "/api/v2/dir/register", "", f.as_bytes()), NOW).status
        };
        let good = reg_form(&id, "alice", "A", NOW, 6);
        // bad signature: title altered after signing
        assert_eq!(post(&mut s, &good.replace("title=A", "title=B")), 403);
        // signed by another key
        let mut r = Registration::sign(&Identity::from_secrets([1; 32], [3; 32]), "alice", "A", NOW).unwrap();
        r.ed = id.ed_public();
        r.mine(6);
        assert_eq!(post(&mut s, &r.to_form()), 403);
        // bad pow: mined for a different difficulty and different message
        let mut weak = Registration::sign(&id, "alice", "A", NOW).unwrap();
        weak.pow = (0..).find(|n| !pow::verify("dir:alice", NOW, &weak.body_hash(), *n, 6)).unwrap();
        assert_eq!(post(&mut s, &weak.to_form()), 403);
        // clock skew
        assert_eq!(post(&mut s, &reg_form(&id, "alice", "A", NOW - 601, 6)), 403);
        assert_eq!(post(&mut s, &reg_form(&id, "alice", "A", NOW + 601, 6)), 403);
        // malformed
        for body in ["", "u=alice", "garbage", &good.replace("&sig=", "&sig=00"), &format!("{good}&u=bob")] {
            assert_eq!(post(&mut s, body), 400, "{body}");
        }
        assert_eq!(s.handle(&req("POST", "/api/v2/dir/register", "", &[0xff, 0xfe]), NOW).status, 400);
        assert_eq!(s.directory_len(), 0);
        assert_eq!(post(&mut s, &good), 200);
        // replay of the same registration
        assert_eq!(post(&mut s, &good), 403);
    }

    #[test]
    fn send_and_poll_with_cursor() {
        let mut s = ServerState::ephemeral(cfg());
        let q = [7u8; 32];
        for i in 0..3u8 {
            let r = s.handle(&send_req(&q, 256, NOW, 6, i), NOW);
            assert_eq!(r.status, 200, "{}", r.body);
            assert_eq!(serde_json::from_str::<serde_json::Value>(&r.body).unwrap()["seq"], u64::from(i) + 1);
        }
        let all = poll(&mut s, &q, 0, NOW);
        assert_eq!(all["frames"].as_array().unwrap().len(), 3);
        assert_eq!(all["next"], 3);
        let rest = poll(&mut s, &q, 2, NOW);
        assert_eq!(rest["frames"].as_array().unwrap().len(), 1);
        assert_eq!(rest["frames"][0]["seq"], 3);
        assert_eq!(rest["frames"][0]["d"], hex::encode(&[2u8; 256]));
        let none = poll(&mut s, &q, 3, NOW);
        assert_eq!(none["frames"].as_array().unwrap().len(), 0);
        assert_eq!(none["next"], 3);
        assert_eq!(poll(&mut s, &[8; 32], 0, NOW)["frames"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn poll_pages_of_100() {
        let mut s = ServerState::ephemeral(Config { pow_bits: 0, ..Config::default() });
        let q = [1u8; 32];
        for i in 0..150u32 {
            let ts = NOW - 300 + u64::from(i);
            assert_eq!(s.handle(&send_req(&q, 256, ts, 0, 1), NOW).status, 200);
        }
        let p1 = poll(&mut s, &q, 0, NOW);
        assert_eq!(p1["frames"].as_array().unwrap().len(), 100);
        let p2 = poll(&mut s, &q, p1["next"].as_u64().unwrap(), NOW);
        assert_eq!(p2["frames"].as_array().unwrap().len(), 50);
    }

    #[test]
    fn send_validation() {
        let mut s = ServerState::ephemeral(cfg());
        let q = [7u8; 32];
        for len in [0, 100, 255, 257, 16385, 32768] {
            let body = hex::encode(&vec![0u8; len]);
            let qh = hex::encode(&q);
            let n = pow::mine(&qh, NOW, &pow::body_hash_hex(body.as_bytes()), 6);
            let r = req("POST", "/api/v2/queue/send", &format!("q={qh}&ts={NOW}&pow={n}"), body.as_bytes());
            assert_eq!(s.handle(&r, NOW).status, 400, "len {len}");
        }
        for bucket in pad::BUCKETS {
            assert_eq!(s.handle(&send_req(&[bucket as u8; 32], bucket, NOW, 6, 0), NOW).status, 200);
        }
        let good = send_req(&[9; 32], 256, NOW, 6, 0);
        let mut bad = good.clone();
        bad.body[0] = b'G';
        assert_eq!(s.handle(&bad, NOW).status, 400);
        let mut upper = good.clone();
        upper.body = hex::encode(&[0xabu8; 256]).to_uppercase().into_bytes();
        assert_eq!(s.handle(&upper, NOW).status, 400);
        let mut no_q = good.clone();
        no_q.query.retain(|(k, _)| k != "q");
        assert_eq!(s.handle(&no_q, NOW).status, 400);
        let mut short_q = good.clone();
        short_q.query[0].1 = "abcd".into();
        assert_eq!(s.handle(&short_q, NOW).status, 400);
        let mut dup = good.clone();
        dup.query.push(dup.query[1].clone());
        assert_eq!(s.handle(&dup, NOW).status, 400);
        // body changed after mining -> pow no longer matches
        let mut tampered = good.clone();
        tampered.body[10] = b'f';
        tampered.body[11] = b'f';
        assert_eq!(s.handle(&tampered, NOW).status, 403);
        // wrong queue for the mined pow
        let mut other_q = good.clone();
        other_q.query[0].1 = hex::encode(&[1u8; 32]);
        assert_eq!(s.handle(&other_q, NOW).status, 403);
        assert_eq!(s.handle(&send_req(&[9; 32], 256, NOW + 601, 6, 0), NOW).status, 403);
        assert_eq!(s.handle(&good, NOW).status, 200);
        assert_eq!(s.handle(&req("GET", "/api/v2/queue/send", "", b""), NOW).status, 405);
    }

    #[test]
    fn pow_cannot_be_replayed() {
        let mut s = ServerState::ephemeral(cfg());
        let r = send_req(&[7; 32], 256, NOW, 6, 5);
        assert_eq!(s.handle(&r, NOW).status, 200);
        assert_eq!(s.handle(&r, NOW).status, 403);
        assert_eq!(s.queue_len(&[7; 32]), 1);
        // after the replay window the same ts is outside the skew window anyway
        assert_eq!(s.handle(&r, NOW + 20 * 60 + 1).status, 403);
    }

    #[test]
    fn full_queue_gets_429_and_keeps_old_frames() {
        let mut s = ServerState::ephemeral(Config { pow_bits: 0, max_frames_per_queue: 3, ..Config::default() });
        let q = [3u8; 32];
        for i in 0..3u64 {
            assert_eq!(s.handle(&send_req(&q, 256, NOW + i, 0, i as u8), NOW).status, 200);
        }
        assert_eq!(s.handle(&send_req(&q, 256, NOW + 9, 0, 9), NOW).status, 429);
        let all = poll(&mut s, &q, 0, NOW);
        assert_eq!(all["frames"].as_array().unwrap().len(), 3);
        assert_eq!(all["frames"][0]["d"], hex::encode(&[0u8; 256]));
        // the proof of work behind a 429 is spent like any other
        assert_eq!(s.handle(&send_req(&q, 256, NOW + 9, 0, 9), NOW).status, 403);
    }

    #[test]
    fn full_default_limit_is_2000() {
        assert_eq!(Config::default().max_frames_per_queue, 2000);
        assert_eq!(Config::default().pow_bits, 18);
        assert_eq!(Config::default().ttl_secs, 14 * 86400);
        assert_eq!(Config::default().replay_secs, 1200);
    }

    #[test]
    fn ttl_purge() {
        let ttl = DEFAULT_QUEUE_TTL_SECS;
        let mut s = ServerState::ephemeral(Config { pow_bits: 0, ..Config::default() });
        let q = [4u8; 32];
        assert_eq!(s.handle(&send_req(&q, 256, NOW, 0, 1), NOW).status, 200);
        assert_eq!(s.handle(&send_req(&q, 256, NOW + 100, 0, 2), NOW + 100).status, 200);
        assert_eq!(poll(&mut s, &q, 0, NOW + ttl - 1)["frames"].as_array().unwrap().len(), 2);
        assert_eq!(poll(&mut s, &q, 0, NOW + ttl)["frames"].as_array().unwrap().len(), 1);
        s.purge(NOW + 100 + ttl);
        assert_eq!(s.queue_len(&q), 0);
        // sequence numbers keep increasing after a queue is recreated
        let r = s.handle(&send_req(&q, 256, NOW + ttl + 200, 0, 3), NOW + ttl + 200);
        assert!(r.body.contains("\"seq\":3"), "{}", r.body);
    }

    #[test]
    fn persistence_roundtrip_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("aegis-server-test-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let id = Identity::from_secrets([1; 32], [2; 32]);
        {
            let s = Mutex::new(ServerState::open_with(&dir, cfg()).unwrap());
            let form = reg_form(&id, "alice", "A", NOW, 6);
            let mut g = s.lock().unwrap();
            assert_eq!(g.handle(&req("POST", "/api/v2/dir/register", "", form.as_bytes()), NOW).status, 200);
            assert_eq!(g.handle(&send_req(&[5; 32], 512, NOW, 6, 7), NOW).status, 200);
            drop(g);
            persist_now(&s).unwrap();
            assert!(dir.join(STATE_FILE).exists());
        }
        let mut s = ServerState::open_with(&dir, cfg()).unwrap();
        assert_eq!(s.directory_len(), 1);
        assert_eq!(poll(&mut s, &[5; 32], 0, NOW)["frames"][0]["d"], hex::encode(&[7u8; 512]));
        let r = s.handle(&send_req(&[5; 32], 256, NOW + 1, 6, 1), NOW + 1);
        assert!(r.body.contains("\"seq\":2"), "{}", r.body);

        // a damaged file is reported and not overwritten
        let path = dir.join(STATE_FILE);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 3);
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(ServerState::open_with(&dir, cfg()), Err(ServerError::Corrupt)));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ephemeral_state_never_writes() {
        let s = Mutex::new(ServerState::ephemeral(cfg()));
        s.lock().unwrap().dirty = true;
        persist_now(&s).unwrap();
        assert!(s.lock().unwrap().state_path().is_none());
    }

    #[test]
    fn default_dir_is_not_profile_root() {
        use std::ffi::OsString;
        let appdata = OsString::from("C:\\Fake\\Roaming");
        let home = OsString::from("/fake/home");
        let d = default_data_dir_from(Some(&appdata), Some(&home)).unwrap();
        assert!(d.ends_with(Path::new("Aegis").join("server")));
        assert_ne!(d, Path::new(&appdata));
        let d = default_data_dir_from(None, Some(&home)).unwrap();
        assert!(d.ends_with(Path::new("aegis").join("server")));
        assert!(d.starts_with(&home) && d != Path::new(&home));
        assert_eq!(default_data_dir_from(Some(OsStr::new("")), None), None);
        assert!(ServerState::open(Path::new("")).is_err());
        let _ = pct_encode("");
    }

    #[test]
    fn no_reference_to_legacy_state_file() {
        let needle = [".aegis", "-server-state", ".tsv"].concat();
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src];
        let mut scanned = 0;
        while let Some(p) = stack.pop() {
            for e in std::fs::read_dir(&p).unwrap() {
                let path = e.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|x| x == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    assert!(!text.contains(&needle), "{}", path.display());
                    scanned += 1;
                }
            }
        }
        assert!(scanned >= 3);
        assert_eq!(STATE_FILE, "server-v2.state");
    }
}
