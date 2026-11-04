#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Black-box adversarial and anonymity tests for the v2 server (docs/PROTOCOL.md sections 3, 4, 12).

use aegis_core::directory::Registration;
use aegis_core::identity::Identity;
use aegis_core::{hex, pad, pow, sha256};
use aegis_server::{persist_now, serve, Config, Request, ServerError, ServerState, STATE_FILE};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BITS: u32 = 8;

struct Srv {
    addr: SocketAddr,
    state: Arc<Mutex<ServerState>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Srv {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn cfg() -> Config {
    Config { pow_bits: BITS, ..Config::default() }
}

fn start_with(state: ServerState) -> Srv {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(state));
    let stop = Arc::new(AtomicBool::new(false));
    let (s1, s2) = (Arc::clone(&state), Arc::clone(&stop));
    let handle = std::thread::spawn(move || {
        serve(&listener, &s1, &s2).unwrap();
    });
    Srv { addr, state, stop, handle: Some(handle) }
}

fn start(config: Config) -> Srv {
    start_with(ServerState::ephemeral(config))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!(
        "aegis-adv-{tag}-{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Reply {
    status: u16,
    headers: String,
    body: String,
}

fn raw_bytes(addr: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = s.write_all(bytes);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

fn parse_reply(out: &[u8]) -> Reply {
    let text = String::from_utf8_lossy(out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Reply { status, headers: head.to_owned(), body: body.to_owned() }
}

fn http(addr: SocketAddr, method: &str, target: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if method == "POST" {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body);
    parse_reply(&raw_bytes(addr, &bytes))
}

fn get(addr: SocketAddr, target: &str) -> Reply {
    http(addr, "GET", target, &[], b"")
}

fn health_ok(addr: SocketAddr) -> bool {
    get(addr, "/health").status == 200
}

// ------------------------------------------------------------------ helpers

fn frame_of(tag: u64, size: usize) -> Vec<u8> {
    let mut f = tag.to_be_bytes().to_vec();
    f.resize(size - 4 - 8 + 8, 0xa5);
    f.truncate(size - 4);
    pad::pad(&f).unwrap()
}

fn q_hex(n: u8) -> String {
    hex::encode(&sha256(&[b"adv-queue", &[n]]))
}

fn send_target(q: &str, ts: u64, pow_n: u64) -> String {
    format!("/api/v2/queue/send?q={q}&ts={ts}&pow={pow_n}")
}

fn send_at(addr: SocketAddr, q: &str, padded: &[u8], ts: u64) -> Reply {
    let body = hex::encode(padded).into_bytes();
    let n = pow::mine(q, ts, &pow::body_hash_hex(&body), BITS);
    http(addr, "POST", &send_target(q, ts, n), &[], &body)
}

fn send(addr: SocketAddr, q: &str, padded: &[u8]) -> Reply {
    send_at(addr, q, padded, now())
}

fn bad_pow_for(q: &str, ts: u64, body: &[u8]) -> u64 {
    let bh = pow::body_hash_hex(body);
    (0..).find(|&n| !pow::verify(q, ts, &bh, n, BITS)).unwrap()
}

fn seq_of(r: &Reply) -> u64 {
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    v["seq"].as_u64().unwrap()
}

fn poll(addr: SocketAddr, q: &str, after: &str) -> Reply {
    get(addr, &format!("/api/v2/queue/poll?q={q}&after={after}"))
}

fn poll_json(addr: SocketAddr, q: &str, after: u64) -> (Vec<(u64, String)>, u64) {
    let r = poll(addr, q, &after.to_string());
    assert_eq!(r.status, 200, "{}", r.body);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let frames = v["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["seq"].as_u64().unwrap(), f["d"].as_str().unwrap().to_owned()))
        .collect();
    (frames, v["next"].as_u64().unwrap())
}

fn identity(n: u8) -> Identity {
    Identity::from_secrets([n; 32], [n.wrapping_add(100); 32])
}

fn mined(id: &Identity, u: &str, title: &str, ts: u64) -> Registration {
    let mut r = Registration::sign(id, u, title, ts).unwrap();
    r.mine(BITS);
    r
}

fn post_form(addr: SocketAddr, form: &str) -> Reply {
    http(
        addr,
        "POST",
        "/api/v2/dir/register",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        form.as_bytes(),
    )
}

fn register(addr: SocketAddr, id: &Identity, u: &str, title: &str) -> Reply {
    post_form(addr, &mined(id, u, title, now()).to_form())
}

fn lookup(addr: SocketAddr, u: &str) -> Reply {
    get(addr, &format!("/api/v2/dir/lookup?u={u}"))
}

// ---------------------------------------------------------------- 11. Directory

#[test]
fn dir_register_and_exact_lookup() {
    let s = start(cfg());
    let a = identity(1);
    assert_eq!(register(s.addr, &a, "alice", "Alice").status, 200);
    let r = lookup(s.addr, "alice");
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["u"], "alice");
    assert_eq!(v["title"], "Alice");
    assert_eq!(v["x"], hex::encode(&a.x_public()));
    assert_eq!(v["ed"], hex::encode(&a.ed_public()));
    assert!(v.as_object().unwrap().keys().all(|k| ["u", "title", "x", "ed"].contains(&k.as_str())));
}

#[test]
fn dir_bad_signature_rejected_even_with_valid_pow() {
    let s = start(cfg());
    let a = identity(1);
    let mut reg = mined(&a, "alice", "Alice", now());
    reg.title = "Mallory".into();
    reg.mine(BITS);
    assert_eq!(post_form(s.addr, &reg.to_form()).status, 403);
    let mut reg = mined(&a, "alice", "Alice", now());
    reg.sig[10] ^= 1;
    assert_eq!(post_form(s.addr, &reg.to_form()).status, 403);
    // Signature by another key over the same data.
    let b = identity(2);
    let mut reg = mined(&b, "alice", "Alice", now());
    reg.ed = a.ed_public();
    reg.mine(BITS);
    assert_eq!(post_form(s.addr, &reg.to_form()).status, 403);
    assert_eq!(lookup(s.addr, "alice").status, 404);
}

#[test]
fn dir_timestamp_window_enforced() {
    let s = start(cfg());
    let a = identity(1);
    for off in [-700i64, 700, -86_400, 86_400] {
        let ts = u64::try_from(i64::try_from(now()).unwrap() + off).unwrap();
        assert_eq!(post_form(s.addr, &mined(&a, "alice", "A", ts).to_form()).status, 403, "off {off}");
    }
    assert_eq!(post_form(s.addr, &mined(&a, "alice", "A", 0).to_form()).status, 403);
    assert_eq!(lookup(s.addr, "alice").status, 404);
}

#[test]
fn dir_malformed_forms_rejected() {
    let s = start(cfg());
    let a = identity(1);
    let good = mined(&a, "alice", "Alice", now()).to_form();
    let forms: Vec<(String, &str)> = vec![
        (String::new(), "empty"),
        (format!("{good}&u=bob"), "duplicate field"),
        (format!("{good}&extra=1"), "extra field"),
        (good.replacen("u=alice&", "", 1), "missing u"),
        (good.replacen("&pow=", "&pw=", 1), "missing pow"),
        (good.replacen("u=alice", "u=Alice", 1), "uppercase name"),
        (good.replacen("u=alice", "u=al", 1), "short name"),
        (good.replacen("u=alice", "u=ali%00ce", 1), "nul in name"),
        (good.replacen("title=Alice", &format!("title={}", "a".repeat(65)), 1), "long title"),
        (good.replacen("title=Alice", "title=A%0Ab", 1), "newline in title"),
        (good.replacen("title=Alice", "title=A%1Bb", 1), "escape in title"),
        (good.replacen("&ts=", "&ts=0", 1), "leading zero ts"),
        (good.replacen("&pow=", "&pow=0", 1), "leading zero pow"),
        ("pow=1&pow=1&pow=1".repeat(100), "repeated"),
        ("%".repeat(1000), "percent noise"),
        ("\u{0}".repeat(100), "nul noise"),
    ];
    for (f, why) in &forms {
        let r = post_form(s.addr, f);
        assert!(r.status == 400 || r.status == 403, "{why}: {}", r.status);
        assert_ne!(r.status, 200, "{why}");
    }
    let r = http(s.addr, "POST", "/api/v2/dir/register", &[], &[0xff, 0xfe, 0x80, b'=', b'&']);
    assert_eq!(r.status, 400);
    assert_eq!(lookup(s.addr, "alice").status, 404);
    assert!(health_ok(s.addr));
}

#[test]
fn dir_pow_required_scoped_and_not_replayable() {
    let s = start(cfg());
    let a = identity(1);
    let ts = now();
    let mut reg = Registration::sign(&a, "alice", "A", ts).unwrap();
    let bh = reg.body_hash();
    reg.pow = (0..)
        .find(|&n| !pow::verify(&aegis_core::directory::pow_scope("alice"), ts, &bh, n, BITS))
        .unwrap();
    assert_eq!(post_form(s.addr, &reg.to_form()).status, 403, "no pow");

    // PoW mined for another username does not transfer.
    let other = mined(&a, "alicf", "A", ts);
    let mut reg = Registration::sign(&a, "alice", "A", ts).unwrap();
    reg.pow = other.pow;
    if reg.pow_ok(BITS) {
        reg.pow = bad_pow_for(&aegis_core::directory::pow_scope("alice"), ts, &reg.message());
    }
    assert_eq!(post_form(s.addr, &reg.to_form()).status, 403);

    // The same accepted request cannot be submitted twice.
    let good = mined(&a, "alice", "A", ts);
    assert_eq!(post_form(s.addr, &good.to_form()).status, 200);
    assert_eq!(post_form(s.addr, &good.to_form()).status, 403, "replayed registration");
}

#[test]
fn dir_username_bound_to_first_key() {
    let s = start(cfg());
    let (a, m) = (identity(1), identity(2));
    assert_eq!(register(s.addr, &a, "alice", "Alice").status, 200);
    let before = lookup(s.addr, "alice").body;
    assert_eq!(register(s.addr, &m, "alice", "Mallory").status, 409);
    assert_eq!(lookup(s.addr, "alice").body, before, "squatter must not change the entry");
    // Same key may update its title.
    assert_eq!(register(s.addr, &a, "alice", "Alice 2").status, 200);
    let v: serde_json::Value = serde_json::from_str(&lookup(s.addr, "alice").body).unwrap();
    assert_eq!(v["title"], "Alice 2");
    // Case variants cannot create a second entry for the same name.
    assert_eq!(post_form(s.addr, &mined(&m, "alice", "x", now()).to_form().replacen("u=alice", "u=ALICE", 1)).status, 400);
}

#[test]
fn dir_table_limit_returns_503() {
    let s = start(Config { max_directory_entries: 2, ..cfg() });
    assert_eq!(register(s.addr, &identity(1), "aaa", "").status, 200);
    assert_eq!(register(s.addr, &identity(2), "bbb", "").status, 200);
    assert_eq!(register(s.addr, &identity(3), "ccc", "").status, 503);
    assert_eq!(lookup(s.addr, "ccc").status, 404);
    // Updating an existing entry still works at the limit.
    assert_eq!(register(s.addr, &identity(1), "aaa", "new").status, 200);
}

#[test]
fn dir_lookup_is_exact_only() {
    let s = start(cfg());
    assert_eq!(register(s.addr, &identity(1), "alice", "A").status, 200);
    assert_eq!(register(s.addr, &identity(2), "alicia", "B").status, 200);
    assert_eq!(lookup(s.addr, "alice").status, 200);
    for u in ["ali", "alic", "alice1", "a", "alicia_", "al%2A", "ali*", "%25", "_lice", "alice%00", "alic%65x"] {
        let r = lookup(s.addr, u);
        assert!(r.status == 404 || r.status == 400, "{u}: {}", r.status);
        assert!(!r.body.contains("alicia"));
    }
    for u in ["ALICE", "Alice", "alice&u=alicia", "", "a%20b"] {
        let r = lookup(s.addr, u);
        assert_ne!(r.status, 200, "{u}");
    }
    assert_eq!(get(s.addr, "/api/v2/dir/lookup").status, 400);
    assert_eq!(get(s.addr, "/api/v2/dir/lookup?u=alice&u=alicia").status, 400);
    assert_eq!(get(s.addr, "/api/v2/dir/lookup?x=alice").status, 400);
    assert_eq!(http(s.addr, "POST", "/api/v2/dir/lookup?u=alice", &[], b"").status, 405);
    assert_eq!(get(s.addr, "/api/v2/dir/register").status, 405);
}

#[test]
fn dir_cannot_be_enumerated() {
    let s = start(cfg());
    for (i, u) in ["alice", "bobby", "carol"].iter().enumerate() {
        assert_eq!(register(s.addr, &identity(i as u8 + 1), u, "T").status, 200);
    }
    for p in [
        "/api/v2/dir", "/api/v2/dir/", "/api/v2/dir/list", "/api/v2/dir/search?q=a", "/api/v2/dir/all",
        "/api/v2/dir/lookup?u=", "/api/v2/dir/lookup?u=*", "/api/v2/dir/lookup?u=%", "/api/v2/dir/lookup?prefix=a",
        "/api/v2/users", "/api/v2/users/alice", "/api/v2/dir/export", "/dir", "/users", "/admin", "/metrics",
        "/debug", "/state", "/server-v2.state", "/api/v2/queue/list", "/api/v2/queue", "/api/v2/queues",
        "/api/v2/queue/poll", "/", "/..", "/../server-v2.state", "/%2e%2e/server-v2.state",
    ] {
        let r = get(s.addr, p);
        assert_ne!(r.status, 200, "{p}");
        for u in ["alice", "bobby", "carol"] {
            assert!(!r.body.contains(u), "{p} leaked {u}");
        }
    }
}

// ------------------------------------------------------------------ 12. Queues

#[test]
fn send_rejects_bad_pow_scope_and_replay() {
    let s = start(cfg());
    let q = q_hex(1);
    let f = frame_of(1, 256);
    let body = hex::encode(&f).into_bytes();
    let ts = now();
    let bad = bad_pow_for(&q, ts, &body);
    assert_eq!(http(s.addr, "POST", &send_target(&q, ts, bad), &[], &body).status, 403);

    // PoW mined for another queue.
    let other = q_hex(2);
    let n = pow::mine(&other, ts, &pow::body_hash_hex(&body), BITS);
    if !pow::verify(&q, ts, &pow::body_hash_hex(&body), n, BITS) {
        assert_eq!(http(s.addr, "POST", &send_target(&q, ts, n), &[], &body).status, 403);
    }
    // PoW mined for another body.
    let n = pow::mine(&q, ts, &pow::body_hash_hex(b"other"), BITS);
    if !pow::verify(&q, ts, &pow::body_hash_hex(&body), n, BITS) {
        assert_eq!(http(s.addr, "POST", &send_target(&q, ts, n), &[], &body).status, 403);
    }
    // PoW mined for another ts.
    let n = pow::mine(&q, ts + 1, &pow::body_hash_hex(&body), BITS);
    if !pow::verify(&q, ts, &pow::body_hash_hex(&body), n, BITS) {
        assert_eq!(http(s.addr, "POST", &send_target(&q, ts, n), &[], &body).status, 403);
    }
    let good = pow::mine(&q, ts, &pow::body_hash_hex(&body), BITS);
    let t = send_target(&q, ts, good);
    assert_eq!(http(s.addr, "POST", &t, &[], &body).status, 200);
    assert_eq!(http(s.addr, "POST", &t, &[], &body).status, 403, "reused pow");
    assert_eq!(poll_json(s.addr, &q, 0).0.len(), 1, "replay must not enqueue twice");
    // Nothing leaked into the other queue.
    assert!(poll_json(s.addr, &other, 0).0.is_empty());
}

#[test]
fn send_timestamp_window() {
    let s = start(cfg());
    let q = q_hex(3);
    for (i, off) in [-700i64, 700, -100_000, 100_000].into_iter().enumerate() {
        let ts = u64::try_from(i64::try_from(now()).unwrap() + off).unwrap();
        assert_eq!(send_at(s.addr, &q, &frame_of(i as u64, 256), ts).status, 403, "off {off}");
    }
    assert_eq!(send_at(s.addr, &q, &frame_of(9, 256), 0).status, 403);
    assert_eq!(send_at(s.addr, &q, &frame_of(9, 256), u64::MAX).status, 403);
    assert_eq!(send_at(s.addr, &q, &frame_of(10, 256), now() + 500).status, 200);
    assert_eq!(send_at(s.addr, &q, &frame_of(11, 256), now() - 500).status, 200);
    assert_eq!(poll_json(s.addr, &q, 0).0.len(), 2);
}

#[test]
fn send_malformed_parameters_and_bodies() {
    let s = start(cfg());
    let q = q_hex(4);
    let f = frame_of(1, 256);
    let body = hex::encode(&f).into_bytes();
    let ts = now();
    let n = pow::mine(&q, ts, &pow::body_hash_hex(&body), BITS);
    let post = |target: String, b: &[u8]| http(s.addr, "POST", &target, &[], b).status;
    let base = "/api/v2/queue/send";
    assert_eq!(post(format!("{base}?ts={ts}&pow={n}"), &body), 400, "missing q");
    assert_eq!(post(format!("{base}?q={q}&pow={n}"), &body), 400, "missing ts");
    assert_eq!(post(format!("{base}?q={q}&ts={ts}"), &body), 400, "missing pow");
    assert_eq!(post(format!("{base}?q={q}&ts={ts}&pow=0{n}"), &body), 400, "leading zero pow");
    assert_eq!(post(format!("{base}?q={q}&ts=0{ts}&pow={n}"), &body), 400, "leading zero ts");
    assert_eq!(post(format!("{base}?q={q}&ts=-1&pow={n}"), &body), 400);
    assert_eq!(post(format!("{base}?q={q}&ts={ts}.5&pow={n}"), &body), 400);
    assert_eq!(post(format!("{base}?q={q}&ts={ts}&pow=-5"), &body), 400);
    assert_eq!(post(format!("{base}?q={q}&ts={ts}&pow=18446744073709551616"), &body), 400);
    assert_eq!(post(format!("{base}?q={q}&ts={ts}&pow={n}&pow={n}"), &body), 400, "duplicate param");
    assert_eq!(post(format!("{base}?q={q}&q={q}&ts={ts}&pow={n}"), &body), 400, "duplicate q");
    for bad_q in [
        q[..62].to_owned(), format!("{q}00"), q.to_uppercase(), format!("{}g", &q[..63]), String::new(),
        "..".into(), "%00".repeat(32),
    ] {
        let t = format!("{base}?q={bad_q}&ts={ts}&pow={n}");
        assert_eq!(post(t, &body), 400, "q {bad_q}");
    }
    assert!(poll_json(s.addr, &q, 0).0.is_empty());
    assert_eq!(get(s.addr, &format!("{base}?q={q}&ts={ts}&pow={n}")).status, 405);
}

#[test]
fn send_body_must_be_lowercase_hex_of_bucket_size() {
    let s = start(cfg());
    let q = q_hex(5);
    let ts = now();
    let try_body = |body: Vec<u8>| {
        let n = pow::mine(&q, ts, &pow::body_hash_hex(&body), BITS);
        http(s.addr, "POST", &send_target(&q, ts, n), &[], &body).status
    };
    let good = hex::encode(&frame_of(1, 256));
    assert_eq!(try_body(good.clone().into_bytes()), 200);
    assert_eq!(try_body(good.to_uppercase().into_bytes()), 400, "uppercase");
    assert_eq!(try_body(format!("{good}0").into_bytes()), 400, "odd length");
    assert_eq!(try_body(format!("{good}00").into_bytes()), 400, "one byte too long");
    assert_eq!(try_body(good.as_bytes()[..good.len() - 2].to_vec()), 400, "one byte short");
    assert_eq!(try_body(good.replacen('a', "g", 1).into_bytes()), 400, "non hex");
    assert_eq!(try_body(format!(" {}", &good[1..]).into_bytes()), 400, "space");
    assert_eq!(try_body(format!("{good}\n").into_bytes()), 400, "newline");
    assert_eq!(try_body(Vec::new()), 400, "empty");
    assert_eq!(try_body(vec![0xff; 512]), 400, "binary");
    assert_eq!(try_body(hex::encode(&[0u8; 255]).into_bytes()), 400, "255 bytes");
    assert_eq!(try_body(hex::encode(&[0u8; 257]).into_bytes()), 400, "257 bytes");
    assert_eq!(try_body(hex::encode(&[0u8; 16385]).into_bytes()), 400, "above max bucket");
    assert_eq!(try_body(hex::encode(&[0u8; 32768]).into_bytes()), 400, "32 KiB frame");
    for size in pad::BUCKETS {
        let q2 = q_hex(size as u8);
        assert_eq!(send(s.addr, &q2, &frame_of(1, size)).status, 200, "bucket {size}");
    }
    // The server only sees opaque bytes; it must hand back exactly what was stored.
    let (frames, _) = poll_json(s.addr, &q, 0);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].1, good);
}

#[test]
fn queue_full_returns_429_keeps_old_frames_and_does_not_burn_pow() {
    let s = start(Config { max_frames_per_queue: 3, ..cfg() });
    let q = q_hex(6);
    let other = q_hex(7);
    for i in 0..3 {
        assert_eq!(send(s.addr, &q, &frame_of(i, 256)).status, 200);
    }
    let body = hex::encode(&frame_of(99, 256)).into_bytes();
    let ts = now();
    let n = pow::mine(&q, ts, &pow::body_hash_hex(&body), BITS);
    let t = send_target(&q, ts, n);
    assert_eq!(http(s.addr, "POST", &t, &[], &body).status, 429);
    assert_eq!(http(s.addr, "POST", &t, &[], &body).status, 429, "pow not consumed by a rejected send");
    let (frames, _) = poll_json(s.addr, &q, 0);
    let tags: Vec<u64> = frames
        .iter()
        .map(|(_, d)| u64::from_str_radix(&d[8..24], 16).unwrap())
        .collect();
    assert_eq!(tags, vec![0, 1, 2], "oldest frames are kept in order");
    assert_eq!(send(s.addr, &other, &frame_of(5, 256)).status, 200, "other queues unaffected");
    // Draining is not possible by polling: the queue stays full.
    let _ = poll_json(s.addr, &q, 1_000_000);
    assert_eq!(send(s.addr, &q, &frame_of(100, 256)).status, 429);
}

#[test]
fn poll_paging_order_and_cursor() {
    let s = start(cfg());
    let q = q_hex(8);
    let mut seqs = Vec::new();
    for i in 0..130u64 {
        let r = send(s.addr, &q, &frame_of(i, 256));
        assert_eq!(r.status, 200);
        seqs.push(seq_of(&r));
    }
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "seq strictly increasing");
    let (page1, next1) = poll_json(s.addr, &q, 0);
    assert_eq!(page1.len(), 100);
    assert!(page1.windows(2).all(|w| w[0].0 < w[1].0));
    assert_eq!(next1, page1.last().unwrap().0);
    assert_eq!(page1[0].0, seqs[0]);
    let (page2, next2) = poll_json(s.addr, &q, next1);
    assert_eq!(page2.len(), 30);
    assert_eq!(next2, seqs[129]);
    assert_eq!(page2[0].0, seqs[100]);
    let (page3, next3) = poll_json(s.addr, &q, next2);
    assert!(page3.is_empty());
    assert_eq!(next3, next2);
    // Cursor in the middle, and beyond the end.
    let (mid, _) = poll_json(s.addr, &q, seqs[49]);
    assert_eq!(mid[0].0, seqs[50]);
    for after in [u64::MAX, u64::MAX - 1, 1 << 63] {
        let (f, next) = poll_json(s.addr, &q, after);
        assert!(f.is_empty());
        assert_eq!(next, after);
    }
    // Default cursor is zero.
    let r = get(s.addr, &format!("/api/v2/queue/poll?q={q}"));
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["frames"].as_array().unwrap().len(), 100);
    // Frames are returned verbatim.
    assert_eq!(page1[5].1, hex::encode(&frame_of(5, 256)));
}

#[test]
fn poll_malformed_and_unknown_queue() {
    let s = start(cfg());
    let q = q_hex(9);
    for after in ["01", "-1", "1.0", "abc", "18446744073709551616", " 1", "1 ", "0x1", "+1", "%31%31x", ""] {
        let r = poll(s.addr, &q, after);
        assert_eq!(r.status, 400, "after={after:?}");
    }
    for bad_q in [&q[..62], &q.to_uppercase(), "", "zz", &format!("{q}{q}")] {
        assert_eq!(poll(s.addr, bad_q, "0").status, 400, "q={bad_q}");
    }
    assert_eq!(get(s.addr, "/api/v2/queue/poll").status, 400);
    assert_eq!(get(s.addr, &format!("/api/v2/queue/poll?q={q}&q={q}")).status, 400);
    assert_eq!(get(s.addr, &format!("/api/v2/queue/poll?q={q}&after=0&after=0")).status, 400);
    assert_eq!(http(s.addr, "POST", &format!("/api/v2/queue/poll?q={q}"), &[], b"").status, 405);

    // A queue nobody ever wrote to looks exactly like a drained one.
    let unknown = poll(s.addr, &q_hex(200), "0");
    assert_eq!(unknown.status, 200);
    let v: serde_json::Value = serde_json::from_str(&unknown.body).unwrap();
    assert!(v["frames"].as_array().unwrap().is_empty());
    assert_eq!(v["next"], 0);
}

#[test]
fn concurrent_identical_sends_enqueue_once() {
    let s = start(cfg());
    let q = q_hex(10);
    let body = hex::encode(&frame_of(1, 256)).into_bytes();
    let ts = now();
    let n = pow::mine(&q, ts, &pow::body_hash_hex(&body), BITS);
    let t = send_target(&q, ts, n);
    let addr = s.addr;
    let ok = Arc::new(AtomicU64::new(0));
    let mut hs = Vec::new();
    for _ in 0..16 {
        let (t, body, ok) = (t.clone(), body.clone(), Arc::clone(&ok));
        hs.push(std::thread::spawn(move || {
            if http(addr, "POST", &t, &[], &body).status == 200 {
                ok.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(ok.load(Ordering::SeqCst), 1);
    assert_eq!(poll_json(s.addr, &q, 0).0.len(), 1);
}

#[test]
fn concurrent_senders_respect_queue_cap_and_unique_seq() {
    let s = start(Config { max_frames_per_queue: 5, ..cfg() });
    let q = q_hex(11);
    let addr = s.addr;
    let ok = Arc::new(AtomicU64::new(0));
    let full = Arc::new(AtomicU64::new(0));
    let mut hs = Vec::new();
    for i in 0..20u64 {
        let (q, ok, full) = (q.clone(), Arc::clone(&ok), Arc::clone(&full));
        hs.push(std::thread::spawn(move || {
            match send(addr, &q, &frame_of(i, 256)).status {
                200 => ok.fetch_add(1, Ordering::SeqCst),
                429 => full.fetch_add(1, Ordering::SeqCst),
                other => panic!("unexpected status {other}"),
            };
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(ok.load(Ordering::SeqCst), 5);
    assert_eq!(full.load(Ordering::SeqCst), 15);
    let (frames, _) = poll_json(s.addr, &q, 0);
    let mut seqs: Vec<u64> = frames.iter().map(|f| f.0).collect();
    let n = seqs.len();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len(), n);
}

#[test]
fn queue_table_limit_returns_503() {
    let s = start(Config { max_queues: 2, ..cfg() });
    assert_eq!(send(s.addr, &q_hex(20), &frame_of(1, 256)).status, 200);
    assert_eq!(send(s.addr, &q_hex(21), &frame_of(1, 256)).status, 200);
    assert_eq!(send(s.addr, &q_hex(22), &frame_of(1, 256)).status, 503);
    assert_eq!(send(s.addr, &q_hex(20), &frame_of(2, 256)).status, 200, "existing queue still accepts");
}

// ------------------------------------------------------- HTTP robustness

fn status_of(bytes: &[u8]) -> u16 {
    parse_reply(bytes).status
}

#[test]
fn http_oversize_body_and_header_limits() {
    let s = start(cfg());
    let q = q_hex(30);
    let target = format!("/api/v2/queue/send?q={q}&ts={}&pow=0", now());
    let mk = |len: usize, body: &[u8]| {
        let mut r = format!("POST {target} HTTP/1.1\r\nHost: x\r\nContent-Length: {len}\r\n\r\n").into_bytes();
        r.extend_from_slice(body);
        r
    };
    assert_eq!(status_of(&raw_bytes(s.addr, &mk(65_537, &vec![b'a'; 65_537]))), 413);
    assert_eq!(status_of(&raw_bytes(s.addr, &mk(65_537, b""))), 413, "declared size alone is enough");
    assert_eq!(status_of(&raw_bytes(s.addr, &mk(u32::MAX as usize, b"x"))), 413);
    assert!([400, 413].contains(&status_of(&raw_bytes(s.addr, &mk(usize::MAX, b"x")))), "overflowing length");
    assert_eq!(status_of(&raw_bytes(s.addr, b"POST /x HTTP/1.1\r\nContent-Length: -1\r\n\r\n")), 400);
    assert_eq!(status_of(&raw_bytes(s.addr, b"POST /x HTTP/1.1\r\nContent-Length: abc\r\n\r\n")), 400);
    assert_eq!(status_of(&raw_bytes(s.addr, b"POST /x HTTP/1.1\r\nContent-Length: 1 2\r\n\r\n")), 400);

    // Huge header line, huge request line, and a flood of small headers.
    let mut big = b"GET /health HTTP/1.1\r\nX-A: ".to_vec();
    big.extend(vec![b'a'; 40_000]);
    big.extend_from_slice(b"\r\n\r\n");
    let st = status_of(&raw_bytes(s.addr, &big));
    assert!(st == 413 || st == 400 || st == 431 || st == 0, "huge header: {st}");
    let mut line = b"GET /".to_vec();
    line.extend(vec![b'a'; 40_000]);
    line.extend_from_slice(b" HTTP/1.1\r\n\r\n");
    let st = status_of(&raw_bytes(s.addr, &line));
    assert!(st == 413 || st == 400 || st == 414 || st == 0 || st == 404, "huge line: {st}");
    let mut many = b"GET /health HTTP/1.1\r\n".to_vec();
    for i in 0..5000 {
        many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
    }
    many.extend_from_slice(b"\r\n");
    let st = status_of(&raw_bytes(s.addr, &many));
    assert!(st == 413 || st == 400 || st == 431 || st == 0, "many headers: {st}");
    assert!(health_ok(s.addr));
}

#[test]
fn http_smuggling_vectors_rejected() {
    let s = start(cfg());
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("TE chunked", b"POST /api/v2/queue/send HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec()),
        ("TE and CL", b"POST /api/v2/queue/send HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec()),
        ("double CL differing", b"POST /api/v2/queue/send HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcde".to_vec()),
        ("TE identity", b"POST /x HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n".to_vec()),
        ("bare LF TE", b"POST /x HTTP/1.1\nTransfer-Encoding: chunked\n\n0\n\n".to_vec()),
    ];
    for (why, bytes) in cases {
        let st = status_of(&raw_bytes(s.addr, &bytes));
        assert!(st == 400 || st == 0, "{why}: {st}");
    }
    // A pipelined second request after the first must not be served.
    let two = b"GET /health HTTP/1.1\r\nConnection: close\r\n\r\nGET /health HTTP/1.1\r\n\r\n";
    let out = raw_bytes(s.addr, two);
    let text = String::from_utf8_lossy(&out);
    assert_eq!(text.matches("HTTP/1.1 200").count() + text.matches("HTTP/1.0 200").count(), 1);
    assert!(health_ok(s.addr));
}

#[test]
fn http_garbage_requests_do_not_kill_the_server() {
    let s = start(cfg());
    let garbage: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\r\n\r\n".to_vec(),
        b"GET\r\n\r\n".to_vec(),
        b"GET / \r\n\r\n".to_vec(),
        b"GET /health\r\n\r\n".to_vec(),
        b"GET /health HTTP/9.9\r\n\r\n".to_vec(),
        b"get /health HTTP/1.1\r\n\r\n".to_vec(),
        b"BREW /health HTTP/1.1\r\n\r\n".to_vec(),
        b"GET http://evil/health HTTP/1.1\r\n\r\n".to_vec(),
        b"GET /health HTTP/1.1\r\nno-colon\r\n\r\n".to_vec(),
        b"GET /health HTTP/1.1\r\n: empty\r\n\r\n".to_vec(),
        b"GET /health HTTP/1.1\r\nA: \xff\xfe\r\n\r\n".to_vec(),
        b"GET /%ZZ HTTP/1.1\r\n\r\n".to_vec(),
        b"GET /?q=%00%ff HTTP/1.1\r\n\r\n".to_vec(),
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03".to_vec(),
        vec![0u8; 5000],
        (0..=255u8).cycle().take(20_000).collect(),
        b"POST /api/v2/dir/register HTTP/1.1\r\nContent-Length: 5\r\n\r\nab".to_vec(),
    ];
    for g in &garbage {
        let st = status_of(&raw_bytes(s.addr, g));
        assert!(st == 0 || (400..500).contains(&st) || st == 200, "garbage got {st}");
    }
    assert!(health_ok(s.addr));
}

#[test]
fn http_responses_carry_no_identifying_headers() {
    let s = start(cfg());
    for r in [
        get(s.addr, "/health"),
        get(s.addr, "/nope"),
        get(s.addr, "/api/v2/dir/lookup?u=zzz"),
        http(s.addr, "POST", "/health", &[], b""),
    ] {
        let h = r.headers.to_ascii_lowercase();
        for forbidden in ["set-cookie", "server:", "x-powered-by", "via:", "x-forwarded", "date:", "etag", "last-modified"] {
            assert!(!h.contains(forbidden), "header {forbidden} in {h}");
        }
        assert!(h.contains("cache-control: no-store"), "{h}");
    }
    assert_eq!(get(s.addr, "/nope").status, 404);
    assert_eq!(http(s.addr, "DELETE", "/health", &[], b"").status, 405);
}

#[test]
fn http_slow_partial_request_is_dropped() {
    let s = start(cfg());
    let mut c = TcpStream::connect(s.addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(12))).unwrap();
    c.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n").unwrap();
    let t = Instant::now();
    let mut buf = Vec::new();
    let _ = c.read_to_end(&mut buf);
    assert!(t.elapsed() < Duration::from_secs(10), "stalled client held for {:?}", t.elapsed());
    let st = status_of(&buf);
    assert!(st == 0 || st == 408 || st == 400, "{st}");
    assert!(health_ok(s.addr));
}

#[test]
fn http_slow_connections_do_not_block_others() {
    let s = start(cfg());
    let mut slow = Vec::new();
    for _ in 0..50 {
        let mut c = TcpStream::connect(s.addr).unwrap();
        c.write_all(b"GET /health HTTP/1.1\r\n").unwrap();
        slow.push(c);
    }
    let t = Instant::now();
    for _ in 0..5 {
        assert!(health_ok(s.addr));
    }
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    drop(slow);
}

#[test]
fn http_byte_drip_hits_total_deadline() {
    let s = start(cfg());
    let mut c = TcpStream::connect(s.addr).unwrap();
    c.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let start = Instant::now();
    let req = b"GET /health HTTP/1.1\r\nHost: x\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
    let mut closed_at = None;
    'outer: for b in req.iter().cycle().take(400) {
        if c.write_all(&[*b]).is_err() {
            closed_at = Some(start.elapsed());
            break;
        }
        let mut one = [0u8; 1];
        match c.read(&mut one) {
            Ok(0) => {
                closed_at = Some(start.elapsed());
                break 'outer;
            }
            Ok(_) => {
                closed_at = Some(start.elapsed());
                break 'outer;
            }
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(100));
        if start.elapsed() > Duration::from_secs(25) {
            break;
        }
    }
    let t = closed_at.expect("server never cut off a byte-drip client");
    assert!(t < Duration::from_secs(22), "cut off after {t:?}");
    assert!(health_ok(s.addr));
}

#[test]
fn http_many_idle_connections_do_not_wedge_server() {
    let s = start(cfg());
    let mut held = Vec::new();
    for _ in 0..300 {
        match TcpStream::connect(s.addr) {
            Ok(c) => held.push(c),
            Err(_) => break,
        }
    }
    drop(held);
    let t = Instant::now();
    let mut ok = false;
    while t.elapsed() < Duration::from_secs(20) {
        if health_ok(s.addr) {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(ok, "server did not recover after 300 idle connections");
}

// --------------------------------------------------- direct handle() tests

fn req(method: &str, path: &str, query: &[(&str, String)], body: Vec<u8>) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        query: query.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect(),
        body,
    }
}

fn handle_send(st: &mut ServerState, q: &str, frame: &[u8], ts: u64, now_s: u64) -> u16 {
    let body = hex::encode(frame).into_bytes();
    let n = pow::mine(q, ts, &pow::body_hash_hex(&body), BITS);
    st.handle(
        &req(
            "POST",
            "/api/v2/queue/send",
            &[("q", q.into()), ("ts", ts.to_string()), ("pow", n.to_string())],
            body,
        ),
        now_s,
    )
    .status
}

fn handle_poll_len(st: &mut ServerState, q: &str, now_s: u64) -> usize {
    let r = st.handle(&req("GET", "/api/v2/queue/poll", &[("q", q.into()), ("after", "0".into())], vec![]), now_s);
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    v["frames"].as_array().unwrap().len()
}

#[test]
fn frames_expire_after_ttl() {
    let mut st = ServerState::ephemeral(cfg());
    let t0 = 1_800_000_000u64;
    let q = q_hex(40);
    assert_eq!(handle_send(&mut st, &q, &frame_of(1, 256), t0, t0), 200);
    let ttl = 14 * 24 * 3600;
    assert_eq!(handle_poll_len(&mut st, &q, t0 + ttl - 1), 1);
    assert_eq!(handle_poll_len(&mut st, &q, t0 + ttl), 0);
    st.purge(t0 + ttl + 1);
    assert_eq!(st.queue_len(&sha256_arr(&q)), 0);
}

fn sha256_arr(q_hex_str: &str) -> [u8; 32] {
    hex::decode_array(q_hex_str).unwrap()
}

#[test]
fn queue_full_clears_after_expiry() {
    let mut st = ServerState::ephemeral(Config { max_frames_per_queue: 2, ..cfg() });
    let t0 = 1_800_000_000u64;
    let q = q_hex(41);
    assert_eq!(handle_send(&mut st, &q, &frame_of(1, 256), t0, t0), 200);
    assert_eq!(handle_send(&mut st, &q, &frame_of(2, 256), t0, t0), 200);
    assert_eq!(handle_send(&mut st, &q, &frame_of(3, 256), t0, t0), 429);
    let later = t0 + 14 * 24 * 3600 + 1;
    assert_eq!(handle_send(&mut st, &q, &frame_of(4, 256), later, later), 200);
    assert_eq!(handle_poll_len(&mut st, &q, later), 1);
}

#[test]
fn pow_cannot_be_replayed_inside_ts_window() {
    let mut st = ServerState::ephemeral(cfg());
    let t = 1_800_000_000u64;
    let q = q_hex(42);
    let frame = frame_of(7, 256);
    let body = hex::encode(&frame).into_bytes();
    let ts = t + 600;
    let n = pow::mine(&q, ts, &pow::body_hash_hex(&body), BITS);
    let r = req(
        "POST",
        "/api/v2/queue/send",
        &[("q", q.clone()), ("ts", ts.to_string()), ("pow", n.to_string())],
        body,
    );
    assert_eq!(st.handle(&r, t).status, 200);
    // Still inside |ts - now| <= 600, so the signature of freshness holds; it must still be refused.
    let replay_at = t + 1200;
    assert_eq!(st.handle(&r, replay_at).status, 403, "replayed after the cache entry expired");
}

#[test]
fn pow_replay_cache_holds_within_window_for_normal_clients() {
    let mut st = ServerState::ephemeral(cfg());
    let t = 1_800_000_000u64;
    let q = q_hex(43);
    let body = hex::encode(&frame_of(8, 256)).into_bytes();
    let n = pow::mine(&q, t, &pow::body_hash_hex(&body), BITS);
    let r = req(
        "POST",
        "/api/v2/queue/send",
        &[("q", q.clone()), ("ts", t.to_string()), ("pow", n.to_string())],
        body,
    );
    assert_eq!(st.handle(&r, t).status, 200);
    for dt in [0u64, 1, 599, 600, 1199] {
        assert_eq!(st.handle(&r, t + dt).status, 403, "dt {dt}");
    }
    // Outside the ts window the request is refused for staleness regardless of the cache.
    assert_eq!(st.handle(&r, t + 1201).status, 403);
    assert_eq!(handle_poll_len(&mut st, &q, t + 10), 1);
}

// ---------------------------------------------------------------- 13. Anonymity

fn read_state(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join(STATE_FILE)).unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn state_and_responses_contain_no_sender_or_network_metadata() {
    let dir = temp_dir("anon");
    let st = ServerState::open_with(&dir, cfg()).unwrap();
    let s = start_with(st);
    let (alice, bob, carol) = (identity(1), identity(2), identity(3));
    assert_eq!(register(s.addr, &alice, "alice", "Alice").status, 200);
    assert_eq!(register(s.addr, &bob, "bobby", "Bob").status, 200);
    // carol never registers; her name must not appear anywhere.

    let env = aegis_core::envelope::Envelope {
        kind: aegis_core::envelope::Kind::Dm,
        msg_id: "00112233445566778899aabbccddeeff".into(),
        sender: "carol_unreg".into(),
        sender_name: "CarolSecretName".into(),
        sender_ed: carol.ed_public(),
        ts_ms: 1_700_000_000_000,
        ttl_s: 0,
        group_id: String::new(),
        body: "PLAINTEXT-MARKER-XYZZY".into(),
        group_key: None,
        members: vec![],
    };
    let inbox = sha256(&[b"aegis-v2 inbox", &bob.x_public()]);
    let q = hex::encode(&inbox);
    let frame = aegis_core::seal::seal_dm(carol.x_secret(), &bob.x_public(), &env).unwrap();
    let padded = pad::pad(&frame).unwrap();

    let body = hex::encode(&padded).into_bytes();
    let ts = now();
    let n = pow::mine(&q, ts, &pow::body_hash_hex(&body), BITS);
    let hdrs = [
        ("X-Forwarded-For", "203.0.113.9"),
        ("X-Real-IP", "203.0.113.10"),
        ("CF-Connecting-IP", "203.0.113.11"),
        ("Forwarded", "for=203.0.113.12"),
        ("Cookie", "session=COOKIE-MARKER-123"),
        ("Authorization", "Bearer AUTH-MARKER-456"),
        ("User-Agent", "UA-MARKER-789/1.0"),
        ("Referer", "https://REFERER-MARKER.example/"),
        ("Origin", "https://ORIGIN-MARKER.example"),
        ("Accept-Language", "xx-MARKER"),
    ];
    let r = http(s.addr, "POST", &send_target(&q, ts, n), &hdrs, &body);
    assert_eq!(r.status, 200);
    let mut replies = vec![r];
    replies.push(http(s.addr, "GET", &format!("/api/v2/queue/poll?q={q}&after=0"), &hdrs, b""));
    replies.push(http(s.addr, "GET", "/api/v2/dir/lookup?u=alice", &hdrs, b""));
    replies.push(http(s.addr, "GET", "/does-not-exist-MARKER-PATH", &hdrs, b""));
    replies.push(http(s.addr, "POST", "/health", &hdrs, b"BODY-MARKER"));
    replies.push(http(s.addr, "POST", "/api/v2/dir/register", &hdrs, b"u=MARKER-USER&junk=1"));
    for r in &replies {
        let all = format!("{}\n{}", r.headers, r.body);
        for m in [
            "203.0.113", "COOKIE-MARKER", "AUTH-MARKER", "UA-MARKER", "REFERER-MARKER", "ORIGIN-MARKER",
            "MARKER-PATH", "BODY-MARKER", "MARKER-USER", "127.0.0.1",
        ] {
            assert!(!all.contains(m), "response echoes {m}");
        }
        assert!(!r.headers.to_ascii_lowercase().contains("set-cookie"));
    }

    persist_now(&s.state).unwrap();
    let state = read_state(&dir);
    assert!(contains(&state, &padded), "positive control: frame must be in the state file");
    for needle in [
        "127.0.0.1", "localhost", "203.0.113", "COOKIE-MARKER", "AUTH-MARKER", "UA-MARKER", "REFERER-MARKER",
        "ORIGIN-MARKER", "PLAINTEXT-MARKER", "carol_unreg", "CarolSecretName", "MARKER-PATH", "User-Agent",
        "X-Forwarded", "BODY-MARKER", "MARKER-USER", "Bearer",
    ] {
        assert!(!contains(&state, needle.as_bytes()), "state file contains {needle}");
    }
    let sender_x = carol.x_public();
    let sender_ed = carol.ed_public();
    assert!(!contains(&state, &sender_x), "sender x_pk must not be stored");
    assert!(!contains(&state, &sender_ed), "sender ed_pk must not be stored");
    assert!(!contains(&state, hex::encode(&sender_x).as_bytes()));
    // Recipient-side facts the spec says the server may see.
    assert!(contains(&state, b"alice"));

    // Only the state file (or its temp) lives in the data directory.
    for e in std::fs::read_dir(&dir).unwrap() {
        let name = e.unwrap().file_name().into_string().unwrap();
        assert!(name == STATE_FILE || name.starts_with(STATE_FILE), "stray file {name}");
        assert!(!name.contains("log"));
    }
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn repeated_sends_from_distinct_clients_are_indistinguishable_in_state() {
    let dir = temp_dir("anon2");
    let s = start_with(ServerState::open_with(&dir, cfg()).unwrap());
    let q = q_hex(50);
    for i in 0..6u64 {
        let ua = format!("Client-{i}");
        let body = hex::encode(&frame_of(i, 256)).into_bytes();
        let ts = now();
        let n = pow::mine(&q, ts, &pow::body_hash_hex(&body), BITS);
        let ip = format!("198.51.100.{i}");
        let r = http(s.addr, "POST", &send_target(&q, ts, n), &[("User-Agent", &ua), ("X-Forwarded-For", &ip)], &body);
        assert_eq!(r.status, 200);
    }
    persist_now(&s.state).unwrap();
    let state = read_state(&dir);
    assert!(!contains(&state, b"Client-"));
    assert!(!contains(&state, b"198.51.100"));
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_queue_poll_matches_empty_queue() {
    let s = start(cfg());
    let q = q_hex(60);
    assert_eq!(send(s.addr, &q, &frame_of(1, 256)).status, 200);
    let (frames, next) = poll_json(s.addr, &q, 0);
    assert_eq!(frames.len(), 1);
    // Reading past the end of a real queue and polling a queue that never existed give the same shape.
    let drained = poll(s.addr, &q, &next.to_string());
    let unknown = poll(s.addr, &q_hex(61), &next.to_string());
    assert_eq!(drained.status, unknown.status);
    assert_eq!(drained.body, unknown.body);
    assert_eq!(drained.headers.len(), unknown.headers.len());
}

// ------------------------------------------------------------ 14. Persistence

#[test]
fn state_survives_restart() {
    let dir = temp_dir("persist");
    let q = q_hex(70);
    let last_seq;
    {
        let s = start_with(ServerState::open_with(&dir, cfg()).unwrap());
        assert_eq!(register(s.addr, &identity(1), "alice", "Alice").status, 200);
        assert_eq!(send(s.addr, &q, &frame_of(1, 256)).status, 200);
        last_seq = seq_of(&send(s.addr, &q, &frame_of(2, 512)));
        persist_now(&s.state).unwrap();
    }
    let s = start_with(ServerState::open_with(&dir, cfg()).unwrap());
    assert_eq!(lookup(s.addr, "alice").status, 200);
    let (frames, _) = poll_json(s.addr, &q, 0);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].1, hex::encode(&frame_of(1, 256)));
    assert_eq!(frames[1].1, hex::encode(&frame_of(2, 512)));
    assert_eq!(s.state.lock().unwrap().queue_len(&sha256_arr(&q)), 2);
    assert_eq!(s.state.lock().unwrap().directory_len(), 1);
    // seq never repeats across restarts.
    let new_seq = seq_of(&send(s.addr, &q, &frame_of(3, 256)));
    assert!(new_seq > last_seq);
    // The username is still bound to the original key after restart.
    assert_eq!(register(s.addr, &identity(9), "alice", "X").status, 409);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

fn valid_small_state() -> (PathBuf, Vec<u8>) {
    let dir = temp_dir("corrupt-src");
    let s = start_with(ServerState::open_with(&dir, cfg()).unwrap());
    assert_eq!(register(s.addr, &identity(1), "alice", "A").status, 200);
    assert_eq!(send(s.addr, &q_hex(80), &frame_of(1, 256)).status, 200);
    persist_now(&s.state).unwrap();
    let bytes = read_state(&dir);
    drop(s);
    (dir, bytes)
}

fn open_bytes(bytes: &[u8]) -> (Result<ServerState, ServerError>, PathBuf) {
    let dir = temp_dir("corrupt");
    std::fs::write(dir.join(STATE_FILE), bytes).unwrap();
    (ServerState::open_with(&dir, cfg()), dir)
}

fn assert_refused_and_untouched(bytes: &[u8], why: &str) {
    let (r, dir) = open_bytes(bytes);
    assert!(matches!(r, Err(ServerError::Corrupt)), "{why}: opened or wrong error");
    assert_eq!(std::fs::read(dir.join(STATE_FILE)).unwrap(), bytes, "{why}: file modified");
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec![STATE_FILE.to_owned()], "{why}: stray files {names:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_state_is_refused_and_never_overwritten() {
    let (src, good) = valid_small_state();
    let _ = std::fs::remove_dir_all(&src);
    // The unmodified file loads.
    let (r, dir) = open_bytes(&good);
    assert!(r.is_ok());
    let _ = std::fs::remove_dir_all(&dir);

    assert_refused_and_untouched(b"", "empty");
    assert_refused_and_untouched(b"garbage garbage garbage", "garbage");
    assert_refused_and_untouched(&vec![0u8; 4096], "zeros");
    assert_refused_and_untouched(&vec![0xffu8; 4096], "ones");
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 1;
    assert_refused_and_untouched(&bad_magic, "magic flip");
    let mut v1 = good.clone();
    v1[7] = b'1';
    assert_refused_and_untouched(&v1, "old version");
    let mut trailing = good.clone();
    trailing.push(0);
    assert_refused_and_untouched(&trailing, "trailing byte");
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"AEGSRV02");
    assert_refused_and_untouched(&trailing, "appended state");
    for n in 0..good.len() {
        assert_refused_and_untouched(&good[..n], &format!("prefix {n}"));
    }
}

#[test]
fn corrupt_state_with_hostile_counts_is_refused_without_huge_allocation() {
    let (src, good) = valid_small_state();
    let _ = std::fs::remove_dir_all(&src);
    // Replace every 4- and 8-byte window after the magic with all-ones; each must be refused or
    // load cleanly, never panic or allocate unbounded memory.
    let t = Instant::now();
    for off in 8..good.len().saturating_sub(4) {
        for width in [4usize, 8] {
            if off + width > good.len() {
                continue;
            }
            let mut b = good.clone();
            for x in &mut b[off..off + width] {
                *x = 0xff;
            }
            let (r, dir) = open_bytes(&b);
            drop(r);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    assert!(t.elapsed() < Duration::from_secs(60));
}

#[test]
fn lowered_next_seq_is_refused() {
    let (src, good) = valid_small_state();
    let _ = std::fs::remove_dir_all(&src);
    // Find any 8-byte big-endian field equal to a plausible next_seq (>= 2) and zero it: the file
    // must then be rejected or still consistent, but must never hand out a repeated seq.
    let mut rejected = false;
    for off in 8..good.len().saturating_sub(8) {
        let mut b = good.clone();
        b[off..off + 8].copy_from_slice(&0u64.to_be_bytes());
        if b == good {
            continue;
        }
        let (r, dir) = open_bytes(&b);
        if let Ok(st) = r {
            // A state that loads must keep seq monotonic for the stored frames.
            let s = start_with(st);
            let q = q_hex(80);
            let (frames, _) = poll_json(s.addr, &q, 0);
            let new = send(s.addr, &q, &frame_of(77, 256));
            if new.status == 200 {
                let ns = seq_of(&new);
                assert!(frames.iter().all(|f| f.0 < ns), "repeated seq after zeroing offset {off}");
            }
        } else {
            rejected = true;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(rejected);
}

#[test]
fn unusable_data_dir_is_an_error_not_a_wipe() {
    let dir = temp_dir("notadir");
    let file = dir.join("file");
    std::fs::write(&file, b"keep me").unwrap();
    let r = ServerState::open_with(&file, cfg());
    assert!(r.is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persisted_file_is_replaced_atomically_and_leaves_no_temp() {
    let dir = temp_dir("atomic");
    let s = start_with(ServerState::open_with(&dir, cfg()).unwrap());
    for i in 0..5 {
        assert_eq!(send(s.addr, &q_hex(90 + i), &frame_of(u64::from(i), 256)).status, 200);
        persist_now(&s.state).unwrap();
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec![STATE_FILE.to_owned()]);
    }
    let bytes = read_state(&dir);
    let (r, d2) = open_bytes(&bytes);
    assert!(r.is_ok());
    let _ = std::fs::remove_dir_all(&d2);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}
