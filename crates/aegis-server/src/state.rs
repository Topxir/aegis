use crate::http::{Request, Response};
use aegis_core::directory::Registration;
use aegis_core::identity::is_valid_username;
use aegis_core::text::parse_u64;
use aegis_core::{hex, pad, pow};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Frames are kept this long (14 days).
pub const DEFAULT_QUEUE_TTL_SECS: u64 = 14 * 24 * 3600;
/// Name of the persisted state inside the data directory.
pub const STATE_FILE: &str = "server-v2.state";
const MAGIC: &[u8; 8] = b"AEGSRV02";
const POLL_PAGE: usize = 100;

/// Tunable limits. The defaults are the protocol values.
#[derive(Debug, Clone)]
pub struct Config {
    pub pow_bits: u32,
    pub ttl_secs: u64,
    pub max_frames_per_queue: usize,
    pub replay_secs: u64,
    pub max_queues: usize,
    pub max_directory_entries: usize,
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
        }
    }
}

#[derive(Debug)]
pub enum ServerError {
    Io(String),
    /// The state file exists but cannot be parsed; it is left untouched.
    Corrupt,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::Io(e) => write!(f, "i/o error: {e}"),
            ServerError::Corrupt => f.write_str("state file is corrupt"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        ServerError::Io(format!("{:?}", e.kind()))
    }
}

struct DirEntry {
    title: String,
    x: [u8; 32],
    ed: [u8; 32],
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
    queues: HashMap<[u8; 32], VecDeque<Frame>>,
    next_seq: u64,
    replay: HashMap<[u8; 32], u64>,
    dirty: bool,
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
        s.path = Some(path);
        Ok(s)
    }

    /// State that is never written to disk.
    pub fn ephemeral(config: Config) -> Self {
        Self {
            config,
            path: None,
            dir: HashMap::new(),
            queues: HashMap::new(),
            next_seq: 1,
            replay: HashMap::new(),
            dirty: false,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn state_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Routes one request. `now` is unix seconds.
    pub fn handle(&mut self, req: &Request, now: u64) -> Response {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/health") => json_resp(200, &json!({"status": "ok", "protocol": 2})),
            ("POST", "/api/v2/dir/register") => self.register(&req.body, now),
            ("GET", "/api/v2/dir/lookup") => self.lookup(&req.query),
            ("POST", "/api/v2/queue/send") => self.send(&req.query, &req.body, now),
            ("GET", "/api/v2/queue/poll") => self.poll(&req.query, now),
            (_, "/health" | "/api/v2/dir/register" | "/api/v2/dir/lookup" | "/api/v2/queue/send" | "/api/v2/queue/poll") => {
                err(405, "method not allowed")
            }
            _ => err(404, "not found"),
        }
    }

    fn pow_spent(&mut self, hash: [u8; 32], now: u64) -> bool {
        self.replay.retain(|_, exp| *exp > now);
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
            None if self.dir.len() >= self.config.max_directory_entries => {
                return err(503, "directory full");
            }
            _ => {}
        }
        self.replay.insert(hash, now + self.config.replay_secs);
        self.dir.insert(
            reg.u,
            DirEntry { title: reg.title, x: reg.x, ed: reg.ed },
        );
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
            Some(e) => json_resp(
                200,
                &json!({"u": u, "title": e.title, "x": hex::encode(&e.x), "ed": hex::encode(&e.ed)}),
            ),
            None => err(404, "not found"),
        }
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
        if !pow::verify(&qhex, ts, &body_hash, nonce, self.config.pow_bits) {
            return err(403, "insufficient proof of work");
        }
        let hash = pow::pow_hash(&qhex, ts, &body_hash, nonce);
        if self.pow_spent(hash, now) {
            return err(403, "proof of work already used");
        }
        self.purge_queue(&qid, now);
        match self.queues.get(&qid) {
            Some(fr) if fr.len() >= self.config.max_frames_per_queue => {
                return err(429, "queue full");
            }
            None if self.queues.len() >= self.config.max_queues => {
                return err(503, "server full");
            }
            _ => {}
        }
        self.replay.insert(hash, now + self.config.replay_secs);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.queues
            .entry(qid)
            .or_default()
            .push_back(Frame { seq, stored_at: now, data: frame });
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
        let frames: Vec<_> = self
            .queues
            .get(&qid)
            .map(|fr| {
                fr.iter()
                    .filter(|f| f.seq > after)
                    .take(POLL_PAGE)
                    .map(|f| json!({"seq": f.seq, "d": hex::encode(&f.data)}))
                    .collect()
            })
            .unwrap_or_default();
        let next = frames
            .last()
            .and_then(|f| f["seq"].as_u64())
            .unwrap_or(after);
        json_resp(200, &json!({"frames": frames, "next": next}))
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
        self.replay.retain(|_, exp| *exp > now);
        self.dirty |= changed;
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
            put_bytes(&mut o, e.title.as_bytes());
            o.extend_from_slice(&e.x);
            o.extend_from_slice(&e.ed);
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
            if r.take(8)? != MAGIC {
                return None;
            }
            self.next_seq = r.u64()?;
            for _ in 0..r.u32()? {
                let u = String::from_utf8(r.bytes()?.to_vec()).ok()?;
                let title = String::from_utf8(r.bytes()?.to_vec()).ok()?;
                let x: [u8; 32] = r.take(32)?.try_into().ok()?;
                let ed: [u8; 32] = r.take(32)?.try_into().ok()?;
                if !is_valid_username(&u) {
                    return None;
                }
                self.dir.insert(u, DirEntry { title, x, ed });
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
            self.queues.clear();
            return Err(ServerError::Corrupt);
        }
        Ok(())
    }
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
    let snap = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take_snapshot();
    if let Some((path, bytes)) = snap {
        if let Err(e) = aegis_core::vault::write_atomic(&path, &bytes) {
            state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .dirty = true;
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
        assert_eq!(v["title"], "Alice <b>");
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
    fn title_update_same_key_and_conflict_other_key() {
        let mut s = ServerState::ephemeral(cfg());
        let a = Identity::from_secrets([1; 32], [2; 32]);
        let m = Identity::from_secrets([1; 32], [9; 32]);
        let post = |s: &mut ServerState, f: &str, now| {
            s.handle(&req("POST", "/api/v2/dir/register", "", f.as_bytes()), now).status
        };
        assert_eq!(post(&mut s, &reg_form(&a, "alice", "One", NOW, 6), NOW), 200);
        assert_eq!(post(&mut s, &reg_form(&a, "alice", "Two", NOW + 1, 6), NOW + 1), 200);
        let r = s.handle(&req("GET", "/api/v2/dir/lookup", "u=alice", b""), NOW);
        assert!(r.body.contains("Two"));
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
        // a 429 does not burn the proof of work
        assert_eq!(s.handle(&send_req(&q, 256, NOW + 9, 0, 9), NOW).status, 429);
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
