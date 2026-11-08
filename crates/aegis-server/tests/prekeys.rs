#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::directory::Registration;
use aegis_core::identity::Identity;
use aegis_core::prekeys::{PrekeyPut, PrekeyTake};
use aegis_core::{hex, now_secs, sealed};
use aegis_server::{persist_now, serve, Config, Request, ServerState};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BITS: u32 = 6;
static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("aegis-prekeys-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cfg() -> Config {
    Config { pow_bits: BITS, prekey_put_interval_secs: 0, prekey_puts_per_hour: 0, ..Config::default() }
}

fn open(dir: &TempDir, config: Config) -> Mutex<ServerState> {
    Mutex::new(ServerState::open_with(&dir.0, config).unwrap())
}

fn id() -> Identity {
    Identity::from_secrets([1; 32], [2; 32])
}

fn post(path: &str, body: &str) -> Request {
    Request { method: "POST".into(), path: path.into(), query: vec![], body: body.as_bytes().to_vec() }
}

fn call(s: &Mutex<ServerState>, path: &str, body: &str, now: u64) -> (u16, serde_json::Value) {
    let r = s.lock().unwrap().handle(&post(path, body), now);
    (r.status, serde_json::from_str(&r.body).unwrap_or(serde_json::Value::Null))
}

fn register(s: &Mutex<ServerState>, identity: &Identity, u: &str, now: u64) {
    let mut reg = Registration::sign(identity, u, u, now).unwrap();
    reg.mine(BITS);
    assert_eq!(call(s, "/api/v2/dir/register", &reg.to_form(), now).0, 200);
}

fn opk(n: u8) -> [u8; 32] {
    [n; 32]
}

fn put_form(identity: &Identity, u: &str, spk: u8, spk_ts: u64, opks: Vec<[u8; 32]>, ts: u64) -> String {
    PrekeyPut::sign(identity, u, [spk; 32], spk_ts, opks, ts).unwrap().to_form()
}

fn take(s: &Mutex<ServerState>, u: &str, now: u64) -> (u16, serde_json::Value) {
    // distinct ts per call so repeated takes are not replays
    let ts = now - u64::from(COUNTER.fetch_add(1, Ordering::SeqCst) % 500);
    call(s, "/api/v2/prekeys/take", &PrekeyTake::mine(u, ts, BITS).to_form(), now)
}

fn setup() -> (TempDir, Mutex<ServerState>, u64) {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    register(&s, &id(), "alice", now);
    (d, s, now)
}

#[test]
fn put_take_roundtrip_and_opk_popped_once() {
    let (_d, s, now) = setup();
    let f = put_form(&id(), "alice", 3, now - 5, vec![opk(10), opk(11)], now);
    let (c, b) = call(&s, "/api/v2/prekeys/put", &f, now);
    assert_eq!((c, b["opks"].as_u64()), (200, Some(2)));
    let p = PrekeyPut::from_form(&f).unwrap();
    let (c, b) = take(&s, "alice", now);
    assert_eq!(c, 200);
    assert_eq!(b["spk"], hex::encode(&[3u8; 32]));
    assert_eq!(b["spk_ts"].as_u64(), Some(now - 5));
    assert_eq!(b["spk_sig"], hex::encode(&p.spk_sig));
    assert_eq!(b["opk"], hex::encode(&opk(10)), "oldest first");
    assert_eq!(take(&s, "alice", now).1["opk"], hex::encode(&opk(11)));
    let (c, b) = take(&s, "alice", now);
    assert_eq!((c, b["opk"].as_str()), (200, Some("")));
    assert_eq!(b["spk"], hex::encode(&[3u8; 32]));
}

#[test]
fn put_rejections() {
    let (_d, s, now) = setup();
    let put = |f: &str| call(&s, "/api/v2/prekeys/put", f, now).0;
    // unknown user: answers like a bad signature, so hidden users cannot be told apart
    assert_eq!(put(&put_form(&id(), "bobby", 3, now, vec![], now)), 403);
    // signed by another key
    let other = Identity::from_secrets([7; 32], [8; 32]);
    assert_eq!(put(&put_form(&other, "alice", 3, now, vec![], now)), 403);
    // bad outer sig
    let mut p = PrekeyPut::sign(&id(), "alice", [3; 32], now, vec![], now).unwrap();
    p.sig[0] ^= 1;
    assert_eq!(put(&p.to_form()), 403);
    // bad spk_sig, outer sig made valid over it
    let mut p = PrekeyPut::sign(&id(), "alice", [3; 32], now, vec![], now).unwrap();
    p.spk_sig[0] ^= 1;
    p.sig = id().sign(&p.message());
    assert_eq!(put(&p.to_form()), 403);
    // spk_sig over a different spk
    let mut p = PrekeyPut::sign(&id(), "alice", [3; 32], now, vec![], now).unwrap();
    p.spk = [4; 32];
    p.sig = id().sign(&p.message());
    assert_eq!(put(&p.to_form()), 403);
    // ts window
    assert_eq!(put(&put_form(&id(), "alice", 3, now, vec![], now - 601)), 403);
    assert_eq!(put(&put_form(&id(), "alice", 3, now, vec![], now + 601)), 403);
    // spk_ts too far in the future
    assert_eq!(put(&put_form(&id(), "alice", 3, now + 601, vec![], now)), 403);
    // malformed forms
    let good = put_form(&id(), "alice", 3, now, vec![], now);
    assert_eq!(put(&format!("{good}&x=1")), 400);
    assert_eq!(put(&good.replace("&sig=", "&sog=")), 400);
    assert_eq!(put(&good.to_uppercase()), 400);
    assert_eq!(put(""), 400);
    // nothing stored by any of the above
    assert_eq!(take(&s, "alice", now).0, 404);
    // wrong method
    let r = s.lock().unwrap().handle(
        &Request { method: "GET".into(), path: "/api/v2/prekeys/put".into(), query: vec![], body: vec![] },
        now,
    );
    assert_eq!(r.status, 405);
}

#[test]
fn stale_or_equal_spk_ts_is_rejected_newer_replaces() {
    let (_d, s, now) = setup();
    let put = |spk: u8, spk_ts: u64, ts: u64| call(&s, "/api/v2/prekeys/put", &put_form(&id(), "alice", spk, spk_ts, vec![], ts), now).0;
    assert_eq!(put(3, now - 100, now), 200);
    assert_eq!(put(4, now - 200, now - 1), 409);
    assert_eq!(put(4, now - 100, now - 2), 409, "equal is not newer");
    assert_eq!(take(&s, "alice", now).1["spk"], hex::encode(&[3u8; 32]));
    assert_eq!(put(5, now + 600, now - 3), 200, "600 s ahead is allowed");
    assert_eq!(take(&s, "alice", now).1["spk"], hex::encode(&[5u8; 32]));
}

#[test]
fn replayed_put_is_rejected() {
    let (_d, s, now) = setup();
    let f = put_form(&id(), "alice", 3, now, vec![opk(1)], now);
    assert_eq!(call(&s, "/api/v2/prekeys/put", &f, now).0, 200);
    assert_eq!(call(&s, "/api/v2/prekeys/put", &f, now).0, 403);
    assert_eq!(call(&s, "/api/v2/prekeys/put", &f, now + 1199).0, 403);
}

#[test]
fn opks_dedupe_cap_and_drop_oldest() {
    let (_d, s, now) = setup();
    let put = |spk_ts: u64, opks: Vec<[u8; 32]>| call(&s, "/api/v2/prekeys/put", &put_form(&id(), "alice", 3, spk_ts, opks, now - (now - spk_ts)), now);
    let first: Vec<[u8; 32]> = (0..60u8).map(opk).collect();
    let (c, b) = put(now - 50, first);
    assert_eq!((c, b["opks"].as_u64()), (200, Some(60)));
    // 30 duplicates and 40 new: 100 total
    let second: Vec<[u8; 32]> = (30..100u8).map(opk).collect();
    let (c, b) = put(now - 40, second);
    assert_eq!((c, b["opks"].as_u64()), (200, Some(100)));
    // 10 more new ones: the 10 oldest (0..10) are dropped
    let third: Vec<[u8; 32]> = (100..110u8).map(opk).collect();
    let (_, b) = put(now - 30, third);
    assert_eq!(b["opks"].as_u64(), Some(100));
    assert_eq!(take(&s, "alice", now).1["opk"], hex::encode(&opk(10)));
    // more than 100 in one request is refused outright
    let many: Vec<[u8; 32]> = (0..101u8).map(opk).collect();
    let mut p = PrekeyPut::sign(&id(), "alice", [3; 32], now - 20, vec![], now).unwrap();
    p.opks = many;
    p.sig = id().sign(&p.message());
    assert_eq!(call(&s, "/api/v2/prekeys/put", &p.to_form(), now).0, 400);
}

#[test]
fn take_requires_pow_and_rejects_replay() {
    let (_d, s, now) = setup();
    assert_eq!(call(&s, "/api/v2/prekeys/put", &put_form(&id(), "alice", 3, now, vec![opk(1), opk(2)], now), now).0, 200);
    let t = PrekeyTake::mine("alice", now, BITS);
    // a nonce that does not satisfy the work
    let bad = (0..).find(|n| !PrekeyTake { u: "alice".into(), ts: now, pow: *n, ed: None }.pow_ok(BITS)).unwrap();
    assert_eq!(call(&s, "/api/v2/prekeys/take", &format!("u=alice&ts={now}&pow={bad}"), now).0, 403);
    // work for another user does not carry over
    // (skip work that happens to satisfy alice's puzzle too, which a low BITS allows by chance)
    let other = (0..)
        .map(|i| PrekeyTake::mine("bobby", now - i, BITS))
        .find(|o| !PrekeyTake { u: "alice".into(), ts: now, pow: o.pow, ed: None }.pow_ok(BITS))
        .unwrap();
    assert_eq!(call(&s, "/api/v2/prekeys/take", &format!("u=alice&ts={now}&pow={}", other.pow), now).0, 403);
    // stale ts
    assert_eq!(call(&s, "/api/v2/prekeys/take", &PrekeyTake::mine("alice", now - 601, BITS).to_form(), now).0, 403);
    // malformed
    assert_eq!(call(&s, "/api/v2/prekeys/take", &format!("{}&x=1", t.to_form()), now).0, 400);
    assert_eq!(call(&s, "/api/v2/prekeys/take", &format!("u=alice&ts={now}"), now).0, 400);
    // failures consumed nothing
    assert_eq!(call(&s, "/api/v2/prekeys/take", &t.to_form(), now).1["opk"], hex::encode(&opk(1)));
    assert_eq!(call(&s, "/api/v2/prekeys/take", &t.to_form(), now).0, 403, "replay");
    assert_eq!(take(&s, "alice", now).1["opk"], hex::encode(&opk(2)));
}

#[test]
fn take_unknown_user_or_no_spk_is_404() {
    let (_d, s, now) = setup();
    assert_eq!(take(&s, "alice", now).0, 404, "registered but nothing published");
    assert_eq!(take(&s, "nobody", now).0, 404);
}

#[test]
fn prekeys_and_taken_opks_survive_restart() {
    let d = TempDir::new();
    let now = now_secs();
    {
        let s = open(&d, cfg());
        register(&s, &id(), "alice", now);
        assert_eq!(call(&s, "/api/v2/prekeys/put", &put_form(&id(), "alice", 3, now, vec![opk(1), opk(2), opk(3)], now), now).0, 200);
        assert_eq!(take(&s, "alice", now).1["opk"], hex::encode(&opk(1)));
        persist_now(&s).unwrap();
    }
    {
        let s = open(&d, cfg());
        assert_eq!(take(&s, "alice", now).1["opk"], hex::encode(&opk(2)), "opk 1 is not handed out again");
        persist_now(&s).unwrap();
    }
    let s = open(&d, cfg());
    let (c, b) = take(&s, "alice", now);
    assert_eq!((c, b["opk"].as_str()), (200, Some(hex::encode(&opk(3)).as_str())));
    assert_eq!(b["spk"], hex::encode(&[3u8; 32]));
}

#[test]
fn old_state_formats_still_load_and_corrupt_prekeys_are_refused() {
    let d = TempDir::new();
    let now = now_secs();
    {
        let s = open(&d, cfg());
        register(&s, &id(), "alice", now);
        persist_now(&s).unwrap();
    }
    let path = d.0.join("server-v2.state");
    let good = std::fs::read(&path).unwrap();
    assert_eq!(&good[..8], b"AEGSRV05");
    // truncated file
    std::fs::write(&path, &good[..good.len() - 1]).unwrap();
    assert!(ServerState::open_with(&d.0, cfg()).is_err());
    assert_eq!(std::fs::read(&path).unwrap().len(), good.len() - 1, "left untouched");
    // a v4 file stores a title after the username, has no hidden flag and no invite section
    // (magic 8, next_seq 8, entry count 4, name length 4, "alice" 5, then x and ed)
    let mut v4 = good.clone();
    v4[..8].copy_from_slice(b"AEGSRV04");
    v4.remove(29 + 64);
    v4.splice(29..29, 0u32.to_be_bytes());
    let n = v4.len();
    // layout tail: prekey count (4), invite count (4), queue count (4)
    v4.drain(n - 8..n - 4);
    std::fs::write(&path, &v4).unwrap();
    assert_eq!(ServerState::open_with(&d.0, cfg()).unwrap().directory_len(), 1);
    // a v3 file is the v4 layout without the prekey section
    let mut v3 = v4.clone();
    v3[..8].copy_from_slice(b"AEGSRV03");
    let n = v3.len();
    v3.drain(n - 8..n - 4);
    std::fs::write(&path, &v3).unwrap();
    let s = ServerState::open_with(&d.0, cfg()).unwrap();
    assert_eq!(s.directory_len(), 1);
}

#[test]
fn prekey_user_table_is_bounded() {
    let d = TempDir::new();
    let s = open(&d, Config { max_prekey_users: 1, ..cfg() });
    let now = now_secs();
    let bob = Identity::from_secrets([5; 32], [6; 32]);
    register(&s, &id(), "alice", now);
    register(&s, &bob, "bobby", now);
    assert_eq!(call(&s, "/api/v2/prekeys/put", &put_form(&id(), "alice", 3, now, vec![], now), now).0, 200);
    assert_eq!(call(&s, "/api/v2/prekeys/put", &put_form(&bob, "bobby", 3, now, vec![], now), now).0, 503);
    // existing user can still rotate
    assert_eq!(call(&s, "/api/v2/prekeys/put", &put_form(&id(), "alice", 4, now + 1, vec![], now - 1), now).0, 200);
}

// ---- over the sealed transport ---------------------------------------------------------------

struct Running {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    srv_pk: [u8; 32],
    _dir: TempDir,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn start() -> Running {
    let dir = TempDir::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(open(&dir, cfg()));
    let srv_pk = state.lock().unwrap().server_public_key().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        serve(&listener, &state, &s2).unwrap();
    });
    Running { addr, stop, handle: Some(handle), srv_pk, _dir: dir }
}

fn sealed_call(r: &Running, method: &str, target: &str, body: &[u8]) -> (u16, serde_json::Value) {
    let (outer, k) = sealed::seal_request(&r.srv_pk, method, target, body).unwrap();
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = format!("POST /api/v2/s HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", outer.len());
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(&outer).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let pos = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let resp = &out[pos + 4..];
    assert!(sealed::BUCKETS.contains(&(resp.len() - 28)));
    let (status, body) = sealed::open_response(&k, resp).unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
}

#[test]
fn prekeys_over_sealed_transport() {
    let r = start();
    let now = now_secs();
    let mut reg = Registration::sign(&id(), "alice", "Alice", now).unwrap();
    reg.mine(BITS);
    assert_eq!(sealed_call(&r, "POST", "/api/v2/dir/register", reg.to_form().as_bytes()).0, 200);
    let f = put_form(&id(), "alice", 3, now, vec![opk(1), opk(2)], now);
    let (c, b) = sealed_call(&r, "POST", "/api/v2/prekeys/put", f.as_bytes());
    assert_eq!((c, b["opks"].as_u64()), (200, Some(2)));
    assert_eq!(sealed_call(&r, "POST", "/api/v2/prekeys/put", f.as_bytes()).0, 403, "replayed inner request");
    let t = PrekeyTake::mine("alice", now, BITS).to_form();
    let (c, b) = sealed_call(&r, "POST", "/api/v2/prekeys/take", t.as_bytes());
    assert_eq!((c, b["opk"].as_str()), (200, Some(hex::encode(&opk(1)).as_str())));
    assert_eq!(sealed_call(&r, "POST", "/api/v2/prekeys/take", t.as_bytes()).0, 403);
    let t2 = PrekeyTake::mine("alice", now - 1, BITS).to_form();
    assert_eq!(sealed_call(&r, "POST", "/api/v2/prekeys/take", t2.as_bytes()).1["opk"], hex::encode(&opk(2)));
    assert_eq!(sealed_call(&r, "POST", "/api/v2/prekeys/take", b"u=alice&ts=1&pow=1").0, 403);
}

#[test]
fn equal_spk_ts_with_identical_spk_refills_opks() {
    let (_d, s, now) = setup();
    let put = |spk: u8, opks: Vec<[u8; 32]>, ts: u64| call(&s, "/api/v2/prekeys/put", &put_form(&id(), "alice", spk, now - 100, opks, ts), now);
    assert_eq!(put(3, vec![opk(1)], now).0, 200);
    let (c, b) = put(3, vec![opk(2), opk(3)], now - 1);
    assert_eq!((c, b["opks"].as_u64()), (200, Some(3)));
    assert_eq!(put(4, vec![opk(9)], now - 2).0, 409, "different spk at equal ts");
    assert_eq!(take(&s, "alice", now).1["spk"], hex::encode(&[3u8; 32]));
}
