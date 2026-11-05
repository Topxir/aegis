#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::directory::Registration;
use aegis_core::identity::Identity;
use aegis_core::{hex, now_secs, pad, pow, sealed};
use aegis_server::{persist_now, serve, Config, Request, ServerState, KEY_FILE};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BITS: u32 = 6;
const DAY: u64 = 24 * 3600;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("aegis-sealed-test-{}-{n}", std::process::id()));
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
    Config { pow_bits: BITS, pin_min_interval_secs: 0, ..Config::default() }
}

fn open(dir: &TempDir, config: Config) -> Mutex<ServerState> {
    Mutex::new(ServerState::open_with(&dir.0, config).unwrap())
}

// ---- PIN, driven directly --------------------------------------------------------------

fn h32(n: u8) -> String {
    hex::encode(&[n; 32])
}

fn pin_body(slot: &str, fields: &[&str], ts: u64) -> String {
    let joined = std::iter::once(slot).chain(fields.iter().copied()).collect::<Vec<_>>().join("\n");
    let n = pow::mine(&format!("pin:{slot}"), ts, &pow::body_hash_hex(joined.as_bytes()), BITS);
    let mut f = format!("slot={slot}");
    for (k, v) in ["v", "s"].iter().zip(fields) {
        f.push_str(&format!("&{k}={v}"));
    }
    format!("{f}&ts={ts}&pow={n}")
}

fn post(path: &str, body: &str) -> Request {
    Request { method: "POST".into(), path: path.into(), query: vec![], body: body.as_bytes().to_vec() }
}

fn call(s: &Mutex<ServerState>, path: &str, body: &str, now: u64) -> (u16, String) {
    let r = s.lock().unwrap().handle(&post(path, body), now);
    (r.status, r.body)
}

static UNIQ: AtomicU32 = AtomicU32::new(0);

/// A distinct timestamp inside the window, so repeated identical attempts are not replays.
fn uniq(now: u64) -> u64 {
    now - u64::from(UNIQ.fetch_add(1, Ordering::SeqCst) % 500)
}

fn create(s: &Mutex<ServerState>, slot: u8, v: u8, sec: u8, now: u64) -> u16 {
    call(s, "/api/v2/pin/create", &pin_body(&h32(slot), &[&h32(v), &h32(sec)], uniq(now)), now).0
}

fn open_pin(s: &Mutex<ServerState>, slot: u8, v: u8, now: u64) -> (u16, String) {
    call(s, "/api/v2/pin/open", &pin_body(&h32(slot), &[&h32(v)], uniq(now)), now)
}

#[test]
fn pin_create_open_delete() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    assert_eq!(create(&s, 1, 2, 3, now), 200);
    assert_eq!(create(&s, 1, 9, 9, now), 409);
    let (c, b) = open_pin(&s, 1, 2, now);
    assert_eq!((c, b.as_str()), (200, format!("{{\"s\":\"{}\"}}", h32(3)).as_str()));
    assert_eq!(open_pin(&s, 7, 2, now).0, 404);
    // delete needs the verifier
    let del = |v: u8, t: u64| call(&s, "/api/v2/pin/delete", &pin_body(&h32(1), &[&h32(v)], uniq(t)), t);
    assert_eq!(del(8, now).0, 403);
    assert_eq!(del(2, now).0, 200);
    assert_eq!(open_pin(&s, 1, 2, now).0, 404);
    assert_eq!(s.lock().unwrap().pin_slots(), 0);
}

#[test]
fn pin_form_and_pow_checks() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    let good = pin_body(&h32(1), &[&h32(2), &h32(3)], now);
    assert_eq!(call(&s, "/api/v2/pin/create", &format!("{good}&x=1"), now).0, 400);
    assert_eq!(call(&s, "/api/v2/pin/create", &good.replace("slot=0101", "slot=0X01"), now).0, 400);
    assert_eq!(call(&s, "/api/v2/pin/create", &good.to_uppercase(), now).0, 400);
    assert_eq!(call(&s, "/api/v2/pin/create", "", now).0, 400);
    // wrong pow
    let h = pow::body_hash_hex(format!("{}\n{}\n{}", h32(1), h32(2), h32(3)).as_bytes());
    let scope = format!("pin:{}", h32(1));
    let bad = (0..).find(|n| !pow::verify(&scope, now, &h, *n, BITS)).unwrap();
    let f = format!("slot={}&v={}&s={}&ts={now}&pow={bad}", h32(1), h32(2), h32(3));
    assert_eq!(call(&s, "/api/v2/pin/create", &f, now).0, 403);
    // hash covers the fields: change s after mining
    let swapped = good.replace(&h32(3), &h32(4));
    assert_eq!(call(&s, "/api/v2/pin/create", &swapped, now).0, 403);
    // stale ts
    assert_eq!(call(&s, "/api/v2/pin/create", &pin_body(&h32(1), &[&h32(2), &h32(3)], now - 601), now).0, 403);
    // replay
    assert_eq!(call(&s, "/api/v2/pin/create", &good, now).0, 200);
    assert_eq!(call(&s, "/api/v2/pin/create", &good, now).0, 403);
    // wrong method
    let r = s.lock().unwrap().handle(
        &Request { method: "GET".into(), path: "/api/v2/pin/open".into(), query: vec![], body: vec![] },
        now,
    );
    assert_eq!(r.status, 405);
}

#[test]
fn pin_five_wrong_deletes_slot() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    assert_eq!(create(&s, 1, 2, 3, now), 200);
    for left in (0..5).rev() {
        let (c, b) = open_pin(&s, 1, 100 + left, now);
        assert_eq!((c, b), (403, format!("{{\"left\":{left}}}")));
    }
    assert_eq!(open_pin(&s, 1, 2, now).0, 404, "correct verifier after 5 wrong must not work");
    assert_eq!(create(&s, 1, 2, 3, now), 200, "slot can be created again");
}

#[test]
fn pin_success_resets_counter() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    assert_eq!(create(&s, 1, 2, 3, now), 200);
    for _ in 0..4 {
        assert_eq!(open_pin(&s, 1, 50, now).0, 403);
    }
    assert_eq!(open_pin(&s, 1, 2, now).0, 200);
    let (c, b) = open_pin(&s, 1, 51, now);
    assert_eq!((c, b.as_str()), (403, "{\"left\":4}"));
}

#[test]
fn pin_counters_survive_restart() {
    let d = TempDir::new();
    let now = now_secs();
    {
        let s = open(&d, cfg());
        assert_eq!(create(&s, 1, 2, 3, now), 200);
        assert_eq!(open_pin(&s, 1, 50, now).0, 403);
        assert_eq!(open_pin(&s, 1, 50, now).0, 403);
        persist_now(&s).unwrap();
    }
    {
        let s = open(&d, cfg());
        let (c, b) = open_pin(&s, 1, 50, now);
        assert_eq!((c, b.as_str()), (403, "{\"left\":2}"));
        persist_now(&s).unwrap();
    }
    let s = open(&d, cfg());
    assert_eq!(open_pin(&s, 1, 50, now).0, 403);
    assert_eq!(open_pin(&s, 1, 50, now).0, 403);
    assert_eq!(open_pin(&s, 1, 2, now).0, 404);
    persist_now(&s).unwrap();
    drop(s);
    let s = open(&d, cfg());
    assert_eq!(open_pin(&s, 1, 2, now).0, 404, "deletion persisted");
}

#[test]
fn pin_slots_expire_after_90_days_unused() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    assert_eq!(create(&s, 1, 2, 3, now), 200);
    assert_eq!(create(&s, 2, 2, 3, now), 200);
    let later = now + 60 * DAY;
    assert_eq!(open_pin(&s, 2, 2, later).0, 200); // use refreshes slot 2
    let end = now + 91 * DAY;
    s.lock().unwrap().purge(end);
    assert_eq!(s.lock().unwrap().pin_slots(), 1);
    assert_eq!(open_pin(&s, 1, 2, end).0, 404);
    assert_eq!(open_pin(&s, 2, 2, end).0, 200);
}

#[test]
fn pin_throttle_per_slot_and_global() {
    let d = TempDir::new();
    let s = open(&d, Config { pin_min_interval_secs: 1, pin_global_per_sec: 3, ..cfg() });
    let now = now_secs();
    for slot in 1..=5 {
        assert_eq!(create(&s, slot, 2, 3, now), 200);
    }
    // per slot: second attempt in the same second is throttled, not counted
    assert_eq!(open_pin(&s, 1, 50, now).0, 403);
    assert_eq!(open_pin(&s, 1, 50, now).0, 429);
    let (c, b) = open_pin(&s, 1, 50, now + 1);
    assert_eq!((c, b.as_str()), (403, "{\"left\":3}"));
    // the right verifier is also throttled right after an attempt
    assert_eq!(open_pin(&s, 1, 2, now + 1).0, 429);
    assert_eq!(open_pin(&s, 1, 2, now + 2).0, 200);
    // global: 3 per second over all slots
    let t = now + 10;
    assert_eq!(open_pin(&s, 2, 2, t).0, 200);
    assert_eq!(open_pin(&s, 3, 2, t).0, 200);
    assert_eq!(open_pin(&s, 4, 2, t).0, 200);
    assert_eq!(open_pin(&s, 5, 2, t).0, 429);
    assert_eq!(open_pin(&s, 5, 2, t + 1).0, 200);
}

// ---- key file ------------------------------------------------------------------------

#[test]
fn server_key_is_created_once_and_corrupt_key_stops_server() {
    let d = TempDir::new();
    let pk = {
        let s = open(&d, cfg());
        let pk = s.lock().unwrap().server_public_key().unwrap();
        pk
    };
    let raw = std::fs::read(d.0.join(KEY_FILE)).unwrap();
    assert_eq!(raw.len(), 32);
    assert!(!d.0.join(format!("{KEY_FILE}.tmp")).exists());
    let s = open(&d, cfg());
    assert_eq!(s.lock().unwrap().server_public_key().unwrap(), pk);
    drop(s);
    for bad in [&b""[..], &[1u8; 31][..], &[1u8; 33][..]] {
        std::fs::write(d.0.join(KEY_FILE), bad).unwrap();
        assert!(ServerState::open_with(&d.0, cfg()).is_err());
        assert_eq!(std::fs::read(d.0.join(KEY_FILE)).unwrap(), bad, "never regenerated");
    }
}

// ---- sealed transport over sockets -------------------------------------------------------

struct Running {
    addr: SocketAddr,
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

fn http(r: &Running, head: &str, body: &[u8]) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let pos = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&out[..pos]).into_owned();
    let code = head[9..12].parse().unwrap();
    (code, head, out[pos + 4..].to_vec())
}

fn post_outer(r: &Running, outer: &[u8]) -> (u16, Vec<u8>) {
    let head = format!(
        "POST /api/v2/s HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        outer.len()
    );
    let (c, _, b) = http(r, &head, outer);
    (c, b)
}

/// Sends a sealed request; returns the inner status and body, checking the response bucket.
fn sealed_call(r: &Running, method: &str, target: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let (outer, k) = sealed::seal_request(&r.srv_pk, method, target, body).unwrap();
    let (c, resp) = post_outer(r, &outer);
    assert_eq!(c, 200);
    assert!(sealed::BUCKETS.contains(&(resp.len() - 16)), "response size {}", resp.len());
    sealed::open_response(&k, &resp).unwrap()
}

#[test]
fn key_endpoint_matches_state() {
    let r = start();
    let (c, _, b) = http(&r, "GET /api/v2/key HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert_eq!(c, 200);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["x"].as_str().unwrap(), hex::encode(&r.srv_pk));
}

#[test]
fn sealed_queue_send_and_poll() {
    let r = start();
    let q = hex::encode(&[7u8; 32]);
    let frame = hex::encode(&pad::pad(b"hello").unwrap());
    let ts = now_secs();
    let n = pow::mine(&q, ts, &pow::body_hash_hex(frame.as_bytes()), BITS);
    let target = format!("/api/v2/queue/send?q={q}&ts={ts}&pow={n}");
    let (c, b) = sealed_call(&r, "POST", &target, frame.as_bytes());
    assert_eq!((c, b.as_slice()), (200, &b"{\"seq\":1}"[..]));
    // replaying the identical inner request in a new outer envelope hits the pow replay cache
    let (c, _) = sealed_call(&r, "POST", &target, frame.as_bytes());
    assert_eq!(c, 403);
    let (c, b) = sealed_call(&r, "GET", &format!("/api/v2/queue/poll?q={q}&after=0"), b"");
    assert_eq!(c, 200);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["frames"].as_array().unwrap().len(), 1);
    assert_eq!(v["frames"][0]["d"].as_str().unwrap(), frame);
}

#[test]
fn replayed_outer_request_is_replayed_inner() {
    let r = start();
    let q = hex::encode(&[8u8; 32]);
    let frame = hex::encode(&pad::pad(b"x").unwrap());
    let ts = now_secs();
    let n = pow::mine(&q, ts, &pow::body_hash_hex(frame.as_bytes()), BITS);
    let target = format!("/api/v2/queue/send?q={q}&ts={ts}&pow={n}");
    let (outer, k) = sealed::seal_request(&r.srv_pk, "POST", &target, frame.as_bytes()).unwrap();
    let (_, a) = post_outer(&r, &outer);
    let (_, b) = post_outer(&r, &outer);
    assert_eq!(sealed::open_response(&k, &a).unwrap().0, 200);
    assert_eq!(sealed::open_response(&k, &b).unwrap().0, 403);
}

#[test]
fn sealed_directory_register_and_lookup() {
    let r = start();
    let id = Identity::from_secrets([1; 32], [2; 32]);
    let mut reg = Registration::sign(&id, "alice", "Alice", now_secs()).unwrap();
    reg.mine(BITS);
    let (c, _) = sealed_call(&r, "POST", "/api/v2/dir/register", reg.to_form().as_bytes());
    assert_eq!(c, 200);
    let (c, b) = sealed_call(&r, "GET", "/api/v2/dir/lookup?u=alice", b"");
    assert_eq!(c, 200);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["title"], "Alice");
    assert_eq!(sealed_call(&r, "GET", "/api/v2/dir/lookup?u=bobby", b"").0, 404);
}

#[test]
fn sealed_blob_put_and_get_max_size() {
    let r = start();
    let id = h32(0x21);
    let body: Vec<u8> = (0..1_048_592usize).map(|i| (i % 253) as u8).collect();
    let ts = now_secs();
    let n = pow::mine(&format!("blob:{id}"), ts, &pow::body_hash_hex(&body), BITS);
    let (c, _) = sealed_call(&r, "POST", &format!("/api/v2/blob/put?id={id}&ts={ts}&pow={n}"), &body);
    assert_eq!(c, 200);
    let (c, got) = sealed_call(&r, "GET", &format!("/api/v2/blob/get?id={id}"), b"");
    assert_eq!(c, 200);
    assert_eq!(got, body);
    assert_eq!(sealed_call(&r, "GET", &format!("/api/v2/blob/get?id={}", h32(0x22)), b"").0, 404);
}

#[test]
fn sealed_pin_flow_and_oversize_inner_bodies() {
    let r = start();
    let now = now_secs();
    let slot = h32(1);
    let (c, _) = sealed_call(&r, "POST", "/api/v2/pin/create", pin_body(&slot, &[&h32(2), &h32(3)], now).as_bytes());
    assert_eq!(c, 200);
    let (c, b) = sealed_call(&r, "POST", "/api/v2/pin/open", pin_body(&slot, &[&h32(9)], now).as_bytes());
    assert_eq!((c, b.as_slice()), (403, &b"{\"left\":4}"[..]));
    std::thread::sleep(Duration::from_millis(1100));
    let (c, b) = sealed_call(&r, "POST", "/api/v2/pin/open", pin_body(&slot, &[&h32(2)], now).as_bytes());
    assert_eq!(c, 200);
    assert!(String::from_utf8(b).unwrap().contains(&h32(3)));
    // an inner non-blob body over 64 KiB gets the same 413 as a direct request
    let (c, _) = sealed_call(&r, "POST", "/api/v2/queue/send?q=aa", &vec![b'a'; 64 * 1024 + 1]);
    assert_eq!(c, 413);
}

#[test]
fn sealed_rejections() {
    let r = start();
    let target = "/health";
    // wrong server key
    let wrong = aegis_core::identity::x25519_public(&[99; 32]);
    let (outer, _) = sealed::seal_request(&wrong, "GET", target, b"").unwrap();
    let (c, b) = post_outer(&r, &outer);
    assert_eq!((c, b.len()), (400, 0));
    // tampered ciphertext, tampered ephemeral key, truncated, garbage
    let (outer, _) = sealed::seal_request(&r.srv_pk, "GET", target, b"").unwrap();
    for i in [0usize, 31, 32, 100, outer.len() - 1] {
        let mut t = outer.clone();
        t[i] ^= 1;
        assert_eq!(post_outer(&r, &t), (400, vec![]), "byte {i}");
    }
    assert_eq!(post_outer(&r, &outer[..outer.len() - 1]), (400, vec![]));
    assert_eq!(post_outer(&r, &[0u8; 100]), (400, vec![]));
    assert_eq!(post_outer(&r, &[]), (400, vec![]));
    // all-zero ephemeral key
    let mut zero = outer.clone();
    zero[..32].fill(0);
    assert_eq!(post_outer(&r, &zero), (400, vec![]));
    // no nesting
    let (outer, k) = sealed::seal_request(&r.srv_pk, "POST", "/api/v2/s", b"x").unwrap();
    let (c, resp) = post_outer(&r, &outer);
    assert_eq!(c, 200);
    assert_eq!(sealed::open_response(&k, &resp).unwrap().0, 400);
    // newline in target cannot be sealed by the client, and an unknown inner path is a sealed 404
    assert_eq!(sealed_call(&r, "GET", "/nope", b"").0, 404);
    assert_eq!(sealed_call(&r, "GET", "/health", b"").0, 200);
    // outer over the limit is refused before reading
    let head = format!(
        "POST /api/v2/s HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        sealed::MAX_OUTER_BYTES + 1
    );
    assert_eq!(http(&r, &head, b"").0, 413);
}

#[test]
fn response_buckets_for_many_sizes() {
    let r = start();
    // blob get of various sizes
    for (i, n) in [1usize, 1000, 1019, 1020, 5000, 70_000].into_iter().enumerate() {
        let id = h32(0x30 + i as u8);
        let body = vec![5u8; n];
        let ts = now_secs();
        let nonce = pow::mine(&format!("blob:{id}"), ts, &pow::body_hash_hex(&body), BITS);
        assert_eq!(sealed_call(&r, "POST", &format!("/api/v2/blob/put?id={id}&ts={ts}&pow={nonce}"), &body).0, 200);
        let (outer, k) = sealed::seal_request(&r.srv_pk, "GET", &format!("/api/v2/blob/get?id={id}"), b"").unwrap();
        let (_, resp) = post_outer(&r, &outer);
        assert_eq!(resp.len() - 16, sealed::bucket_for(n + 2).unwrap(), "n={n}");
        assert_eq!(sealed::open_response(&k, &resp).unwrap().1, body);
    }
}

// ---- cover traffic -------------------------------------------------------------------------

fn nop_body(resp_len: u32, extra: usize) -> Vec<u8> {
    let mut b = resp_len.to_be_bytes().to_vec();
    b.extend(std::iter::repeat_n(0xA5u8, extra));
    b
}

#[test]
fn nop_through_sealed_transport() {
    let r = start();
    let (c, b) = sealed_call(&r, "POST", "/api/v2/nop", &nop_body(3000, 500));
    assert_eq!(c, 200);
    assert_eq!(b, vec![0u8; 3000]);
    assert_eq!(sealed_call(&r, "POST", "/api/v2/nop", &nop_body(0, 0)).1, Vec::<u8>::new());
    assert_eq!(sealed_call(&r, "POST", "/api/v2/nop", &nop_body(65_536, 10)).1.len(), 65_536);
    // no pow needed and nothing consumed: repeat is fine
    assert_eq!(sealed_call(&r, "POST", "/api/v2/nop", &nop_body(3000, 500)).0, 200);
}

#[test]
fn nop_rejections() {
    let r = start();
    assert_eq!(sealed_call(&r, "POST", "/api/v2/nop", &nop_body(65_537, 0)).0, 400);
    assert_eq!(sealed_call(&r, "POST", "/api/v2/nop", &nop_body(u32::MAX, 0)).0, 400);
    assert_eq!(sealed_call(&r, "POST", "/api/v2/nop", b"").0, 400);
    assert_eq!(sealed_call(&r, "POST", "/api/v2/nop", &[0, 0, 1]).0, 400);
    assert_eq!(sealed_call(&r, "POST", "/api/v2/nop", &nop_body(10, 64 * 1024)).0, 413);
    assert_eq!(sealed_call(&r, "GET", "/api/v2/nop", b"").0, 405);
}

#[test]
fn nop_response_bucket_matches_real_response_of_same_length() {
    let r = start();
    // a real response of N body bytes: blob get of N bytes
    for (i, n) in [1usize, 700, 1018, 1019, 1020, 4000, 20_000].into_iter().enumerate() {
        let id = h32(0x50 + i as u8);
        let body = vec![1u8; n];
        let ts = now_secs();
        let nonce = pow::mine(&format!("blob:{id}"), ts, &pow::body_hash_hex(&body), BITS);
        assert_eq!(sealed_call(&r, "POST", &format!("/api/v2/blob/put?id={id}&ts={ts}&pow={nonce}"), &body).0, 200);
        let (o1, _) = sealed::seal_request(&r.srv_pk, "GET", &format!("/api/v2/blob/get?id={id}"), b"").unwrap();
        let real = post_outer(&r, &o1).1.len();
        let (o2, _) = sealed::seal_request(&r.srv_pk, "POST", "/api/v2/nop", &nop_body(n as u32, 300)).unwrap();
        let cover = post_outer(&r, &o2).1.len();
        assert_eq!(real, cover, "n={n}");
    }
}
