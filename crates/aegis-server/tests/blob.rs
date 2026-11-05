#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::{now_secs, pow};
use aegis_server::{handle_blob, serve, BlobReply, Config, Request, ServerState, MAX_BLOB_BYTES};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BITS: u32 = 6;
const TTL: u64 = 14 * 24 * 3600;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("aegis-blob-test-{}-{n}", std::process::id()));
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
    Config { pow_bits: BITS, ..Config::default() }
}

fn open(dir: &TempDir, config: Config) -> Mutex<ServerState> {
    Mutex::new(ServerState::open_with(&dir.0, config).unwrap())
}

fn id_of(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

fn put_query(id: &str, body: &[u8], ts: u64) -> String {
    let nonce = pow::mine(&format!("blob:{id}"), ts, &pow::body_hash_hex(body), BITS);
    format!("id={id}&ts={ts}&pow={nonce}")
}

fn put_req(id: &str, body: &[u8], now: u64) -> Request {
    req("POST", "/api/v2/blob/put", &put_query(id, body, now), body)
}

fn req(method: &str, path: &str, query: &str, body: &[u8]) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        query: aegis_core::text::parse_pairs(query).unwrap(),
        body: body.to_vec(),
    }
}

fn status(r: &BlobReply) -> u16 {
    match r {
        BlobReply::Json(j) => j.status,
        BlobReply::Bytes(_) => 200,
    }
}

fn get(s: &Mutex<ServerState>, id: &str, now: u64) -> BlobReply {
    handle_blob(s, &req("GET", "/api/v2/blob/get", &format!("id={id}"), b""), now)
}

#[test]
fn put_get_roundtrip_and_duplicate() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    let id = id_of(1);
    let body = vec![7u8; 5000];
    assert_eq!(status(&handle_blob(&s, &put_req(&id, &body, now), now)), 200);
    assert_eq!(get(&s, &id, now), BlobReply::Bytes(body.clone()));
    // not deleted on read
    assert_eq!(get(&s, &id, now), BlobReply::Bytes(body.clone()));
    assert_eq!(std::fs::read(d.0.join("blobs").join(&id)).unwrap(), body);
    // duplicate id with a fresh pow
    let other = vec![8u8; 100];
    assert_eq!(status(&handle_blob(&s, &put_req(&id, &other, now), now)), 409);
    assert_eq!(get(&s, &id, now), BlobReply::Bytes(body));
    // no temp leftovers
    assert_eq!(std::fs::read_dir(d.0.join("blobs")).unwrap().count(), 1);
}

#[test]
fn max_size_ok_and_empty_rejected() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    let body = vec![1u8; MAX_BLOB_BYTES];
    assert_eq!(status(&handle_blob(&s, &put_req(&id_of(2), &body, now), now)), 200);
    assert_eq!(status(&handle_blob(&s, &put_req(&id_of(3), b"", now), now)), 400);
    let big = vec![1u8; MAX_BLOB_BYTES + 1];
    assert_eq!(status(&handle_blob(&s, &put_req(&id_of(4), &big, now), now)), 413);
}

#[test]
fn bad_pow_stale_ts_and_reuse() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    let id = id_of(5);
    let body = b"hello".to_vec();
    let h = pow::body_hash_hex(&body);
    let bad = (0..).find(|n| !pow::verify(&format!("blob:{id}"), now, &h, *n, BITS)).unwrap();
    let r = req("POST", "/api/v2/blob/put", &format!("id={id}&ts={now}&pow={bad}"), &body);
    assert_eq!(status(&handle_blob(&s, &r, now)), 403);
    // a pow mined for another id does not carry over
    let q = put_query(&id_of(6), &body, now).replacen(&id_of(6), &id, 1);
    assert_eq!(status(&handle_blob(&s, &req("POST", "/api/v2/blob/put", &q, &body), now)), 403);
    // stale ts
    let old = now - 601;
    assert_eq!(status(&handle_blob(&s, &put_req(&id, &body, old), now)), 403);
    // good, then replayed
    let good = put_req(&id, &body, now);
    assert_eq!(status(&handle_blob(&s, &good, now)), 200);
    assert_eq!(status(&handle_blob(&s, &good, now)), 403);
}

#[test]
fn bad_ids_rejected() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    let body = b"x".to_vec();
    let bad = [
        id_of(0xab).to_uppercase(),
        "a".repeat(63),
        "a".repeat(65),
        "../../etc/passwd".to_string(),
        format!("..%2f{}", "a".repeat(58)),
        format!("{}/..", "a".repeat(60)),
        String::new(),
        "g".repeat(64),
    ];
    for id in &bad {
        let enc = aegis_core::text::pct_encode(id);
        let q = format!("id={enc}&ts={now}&pow=0");
        let r = handle_blob(&s, &req("POST", "/api/v2/blob/put", &q, &body), now);
        assert_eq!(status(&r), 400, "{id}");
        let r = handle_blob(&s, &req("GET", "/api/v2/blob/get", &format!("id={enc}"), b""), now);
        assert_eq!(status(&r), 400, "{id}");
    }
    let r = handle_blob(&s, &req("GET", "/api/v2/blob/get", "", b""), now);
    assert_eq!(status(&r), 400);
    assert!(!d.0.join("blobs").exists());
}

#[test]
fn unknown_is_404_and_wrong_method_405() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    assert_eq!(status(&get(&s, &id_of(9), now)), 404);
    let r = handle_blob(&s, &req("GET", "/api/v2/blob/put", "", b""), now);
    assert_eq!(status(&r), 405);
    let r = handle_blob(&s, &req("POST", "/api/v2/blob/get", "", b""), now);
    assert_eq!(status(&r), 405);
}

#[test]
fn quota_is_enforced_and_failed_put_does_not_consume_pow() {
    let d = TempDir::new();
    let s = open(&d, Config { blob_quota_bytes: 1000, ..cfg() });
    let now = now_secs();
    assert_eq!(status(&handle_blob(&s, &put_req(&id_of(1), &[1; 600], now), now)), 200);
    let over = put_req(&id_of(2), &[2; 500], now);
    assert_eq!(status(&handle_blob(&s, &over, now)), 503);
    assert_eq!(status(&handle_blob(&s, &over, now)), 503);
    assert_eq!(status(&get(&s, &id_of(2), now)), 404);
    assert_eq!(status(&handle_blob(&s, &put_req(&id_of(3), &[3; 400], now), now)), 200);
    assert_eq!(s.lock().unwrap().blob_store().unwrap().total_bytes(), 1000);
    assert_eq!(status(&handle_blob(&s, &put_req(&id_of(4), &[4; 1], now), now)), 503);
}

#[test]
fn concurrent_puts_respect_quota() {
    let d = TempDir::new();
    let s = Arc::new(open(&d, Config { blob_quota_bytes: 5000, ..cfg() }));
    let now = now_secs();
    let reqs: Vec<Request> = (0..20u8).map(|i| put_req(&id_of(i), &[i; 1000], now)).collect();
    let handles: Vec<_> = reqs
        .into_iter()
        .map(|r| {
            let s = Arc::clone(&s);
            std::thread::spawn(move || status(&handle_blob(&s, &r, now)))
        })
        .collect();
    let ok = handles.into_iter().map(|h| h.join().unwrap()).filter(|c| *c == 200).count();
    assert_eq!(ok, 5);
    let st = s.lock().unwrap();
    let b = st.blob_store().unwrap();
    assert_eq!(b.total_bytes(), 5000);
    assert_eq!(b.count(), 5);
}

#[test]
fn expiry_purges_and_frees_quota() {
    let d = TempDir::new();
    let s = open(&d, Config { blob_quota_bytes: 1000, ..cfg() });
    let now = now_secs();
    let id = id_of(1);
    assert_eq!(status(&handle_blob(&s, &put_req(&id, &[1; 900], now), now)), 200);
    assert!(matches!(get(&s, &id, now + TTL - 1), BlobReply::Bytes(_)));
    let later = now + TTL;
    assert_eq!(status(&get(&s, &id, later)), 404);
    s.lock().unwrap().purge(later);
    assert!(!d.0.join("blobs").join(&id).exists());
    assert_eq!(s.lock().unwrap().blob_store().unwrap().total_bytes(), 0);
    let r = put_req(&id, &[2; 900], later);
    assert_eq!(status(&handle_blob(&s, &r, later)), 200);
}

#[test]
fn expired_blob_is_replaced_without_explicit_purge() {
    let d = TempDir::new();
    let s = open(&d, cfg());
    let now = now_secs();
    let id = id_of(1);
    assert_eq!(status(&handle_blob(&s, &put_req(&id, &[1; 10], now), now)), 200);
    let later = now + TTL + 1;
    assert_eq!(status(&handle_blob(&s, &put_req(&id, &[2; 20], later), later)), 200);
    assert_eq!(get(&s, &id, later), BlobReply::Bytes(vec![2; 20]));
}

#[test]
fn restart_rebuilds_totals_and_cleans_leftovers() {
    let d = TempDir::new();
    let now = now_secs();
    {
        let s = open(&d, cfg());
        assert_eq!(status(&handle_blob(&s, &put_req(&id_of(1), &[1; 300], now), now)), 200);
        assert_eq!(status(&handle_blob(&s, &put_req(&id_of(2), &[2; 200], now), now)), 200);
    }
    let dir = d.0.join("blobs");
    std::fs::write(dir.join(format!("{}.tmp", id_of(3))), [0u8; 50]).unwrap();
    std::fs::write(dir.join("notes.txt"), [0u8; 7]).unwrap();
    std::fs::write(dir.join(id_of(0xab).to_uppercase()), [0u8; 9]).unwrap();
    let s = open(&d, Config { blob_quota_bytes: 600, ..cfg() });
    {
        let st = s.lock().unwrap();
        let b = st.blob_store().unwrap();
        assert_eq!(b.total_bytes(), 500);
        assert_eq!(b.count(), 2);
    }
    assert!(!dir.join(format!("{}.tmp", id_of(3))).exists());
    assert!(dir.join("notes.txt").exists());
    assert_eq!(get(&s, &id_of(1), now), BlobReply::Bytes(vec![1; 300]));
    assert_eq!(status(&handle_blob(&s, &put_req(&id_of(5), &[5; 101], now), now)), 503);
    assert_eq!(status(&handle_blob(&s, &put_req(&id_of(5), &[5; 100], now), now)), 200);
}

#[test]
fn startup_purges_backdated_blobs() {
    let d = TempDir::new();
    let now = now_secs();
    {
        let s = open(&d, cfg());
        assert_eq!(status(&handle_blob(&s, &put_req(&id_of(1), &[1; 300], now), now)), 200);
        assert_eq!(status(&handle_blob(&s, &put_req(&id_of(2), &[2; 200], now), now)), 200);
    }
    let old = std::time::SystemTime::now() - Duration::from_secs(TTL + 3600);
    let f = std::fs::File::options().write(true).open(d.0.join("blobs").join(id_of(1))).unwrap();
    f.set_modified(old).unwrap();
    drop(f);
    let s = open(&d, cfg());
    assert_eq!(status(&get(&s, &id_of(1), now)), 404);
    assert!(!d.0.join("blobs").join(id_of(1)).exists());
    assert!(matches!(get(&s, &id_of(2), now), BlobReply::Bytes(_)));
    assert_eq!(s.lock().unwrap().blob_store().unwrap().total_bytes(), 200);
}

// ---- over real sockets ---------------------------------------------------------------------

struct Running {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
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

fn start(config: Config) -> Running {
    let dir = TempDir::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(open(&dir, config));
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        serve(&listener, &state, &s2).unwrap();
    });
    Running { addr, stop, handle: Some(handle), _dir: dir }
}

/// Sends a request, returns (head, body).
fn http(r: &Running, head: &str, body: &[u8]) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let pos = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    (String::from_utf8_lossy(&out[..pos]).into_owned(), out[pos + 4..].to_vec())
}

fn put_http(r: &Running, id: &str, body: &[u8]) -> String {
    let q = put_query(id, body, now_secs());
    let head = format!(
        "POST /api/v2/blob/put?{q} HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    http(r, &head, body).0
}

#[test]
fn http_roundtrip_with_headers() {
    let r = start(cfg());
    let id = id_of(0x11);
    let body: Vec<u8> = (0..MAX_BLOB_BYTES).map(|i| (i % 251) as u8).collect();
    let head = put_http(&r, &id, &body);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (head, got) =
        http(&r, &format!("GET /api/v2/blob/get?id={id} HTTP/1.1\r\nHost: x\r\n\r\n"), b"");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("content-type: application/octet-stream"));
    assert!(lower.contains("cache-control: no-store"));
    assert!(lower.contains("x-content-type-options: nosniff"));
    assert_eq!(got, body);
    assert!(put_http(&r, &id, b"again").starts_with("HTTP/1.1 409"));
    let (head, _) =
        http(&r, &format!("GET /api/v2/blob/get?id={} HTTP/1.1\r\n\r\n", id_of(0x12)), b"");
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
}

#[test]
fn http_size_limits_by_route() {
    let r = start(cfg());
    // blob route: over the cap is rejected from the headers alone, no body sent
    let head = format!(
        "POST /api/v2/blob/put?id={} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        id_of(1),
        MAX_BLOB_BYTES + 1
    );
    let (h, _) = http(&r, &head, b"");
    assert!(h.starts_with("HTTP/1.1 413"), "{h}");
    // every other route stays at 64 KiB, also when only the headers arrive
    for path in ["/api/v2/queue/send?q=aa", "/api/v2/dir/register", "/api/v2/blob/get?id=aa", "/x"] {
        let head = format!("POST {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n", 64 * 1024 + 1);
        let (h, _) = http(&r, &head, b"");
        assert!(h.starts_with("HTTP/1.1 413"), "{path}: {h}");
    }
    let head = format!("GET /api/v2/blob/put HTTP/1.1\r\nContent-Length: {}\r\n\r\n", 64 * 1024 + 1);
    let (h, _) = http(&r, &head, b"");
    assert!(h.starts_with("HTTP/1.1 413"), "{h}");
}

#[test]
fn http_blob_quota_503() {
    let r = start(Config { blob_quota_bytes: 100, ..cfg() });
    assert!(put_http(&r, &id_of(1), &[1; 101]).starts_with("HTTP/1.1 503"));
    assert!(put_http(&r, &id_of(1), &[1; 100]).starts_with("HTTP/1.1 200"));
}
