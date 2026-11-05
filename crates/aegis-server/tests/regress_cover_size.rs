#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::{cover, hex, now_secs, pad, pow, sealed};
use aegis_server::{serve, Config, ServerState};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BITS: u32 = 6;

struct Running {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    srv_pk: [u8; 32],
    dir: PathBuf,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start() -> Running {
    let dir = std::env::temp_dir().join(format!("aegis-regress-cover-size-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = Config { pow_bits: BITS, pin_min_interval_secs: 0, ..Config::default() };
    let state = Arc::new(Mutex::new(ServerState::open_with(&dir, cfg).unwrap()));
    let srv_pk = state.lock().unwrap().server_public_key().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        serve(&listener, &state, &s2).unwrap();
    });
    Running { addr, stop, handle: Some(handle), srv_pk, dir }
}

/// Posts one sealed request. Returns (outer request bytes, outer response bytes, inner status).
fn sealed_rt(r: &Running, method: &str, target: &str, body: &[u8]) -> (usize, usize, u16) {
    let (outer, k) = sealed::seal_request(&r.srv_pk, method, target, body).unwrap();
    let head = format!(
        "POST /api/v2/s HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        outer.len()
    );
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(&outer);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let pos = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let resp = &out[pos + 4..];
    let (status, _) = sealed::open_response(&k, resp).unwrap();
    (outer.len(), resp.len(), status)
}

#[test]
fn attachment_download_and_large_poll_are_never_matched_by_cover() {
    let r = start();

    // Real 1: an attachment chunk as the sender uploads it (1 MiB + tag), fetched by a receiver.
    let id = hex::encode(&[0x42u8; 32]);
    let chunk: Vec<u8> = (0..1_048_592usize).map(|i| (i % 251) as u8).collect();
    let ts = now_secs();
    let n = pow::mine(&format!("blob:{id}"), ts, &pow::body_hash_hex(&chunk), BITS);
    let (_, _, st) = sealed_rt(&r, "POST", &format!("/api/v2/blob/put?id={id}&ts={ts}&pow={n}"), &chunk);
    assert_eq!(st, 200, "setup: blob put");
    let (blob_req, blob_resp, st) = sealed_rt(&r, "GET", &format!("/api/v2/blob/get?id={id}"), b"");
    assert_eq!(st, 200, "setup: blob get");

    // Real 2: a poll page with one 8192-bucket frame waiting (a long text or a group frame).
    let q = hex::encode(&[7u8; 32]);
    let frame = hex::encode(&pad::pad(&vec![0x33u8; 8000]).unwrap());
    let ts = now_secs();
    let n = pow::mine(&q, ts, &pow::body_hash_hex(frame.as_bytes()), BITS);
    let (_, _, st) = sealed_rt(&r, "POST", &format!("/api/v2/queue/send?q={q}&ts={ts}&pow={n}"), frame.as_bytes());
    assert_eq!(st, 200, "setup: queue send");
    let (poll_req, poll_resp, st) = sealed_rt(&r, "GET", &format!("/api/v2/queue/poll?q={q}&after=0"), b"");
    assert_eq!(st, 200, "setup: poll");

    // Every dummy the client can emit: request bodies across all buckets up to the 64 KiB body
    // limit, each asking for the largest response the scheduler allows (cover::max_resp_len).
    let mut dummies: Vec<(usize, usize)> = Vec::new();
    for req_len in [
        4u32, 64, 512, 1000, 1010, 1020, 1030, 2000, 4000, 4090, 4100, 8000, 16_000, 16_370, 16_400,
        32_000, 60_000, 65_000, 65_400,
    ] {
        let resp_len = cover::max_resp_len(req_len as usize);
        let body = cover::nop_body(req_len, resp_len).unwrap();
        let (q_len, s_len, st) = sealed_rt(&r, "POST", "/api/v2/nop", &body);
        if st == 200 {
            dummies.push((q_len, s_len));
        }
    }
    assert!(!dummies.is_empty(), "setup: no dummy answered 200");
    let largest_dummy = dummies.iter().map(|d| d.1).max().unwrap();
    eprintln!("blob get: req {blob_req} resp {blob_resp}; poll: req {poll_req} resp {poll_resp}");
    eprintln!("dummies (req, resp): {dummies:?}");

    let blob_hidden = dummies.iter().any(|&(q, s)| q == blob_req && s >= blob_resp);
    let poll_hidden = dummies.iter().any(|&(q, s)| q == poll_req && s >= poll_resp);
    assert!(
        blob_hidden && poll_hidden,
        "no cover dummy reaches a real (request, response) size pair: blob get ({blob_req}, {blob_resp}) \
         hidden={blob_hidden}; poll with a frame ({poll_req}, {poll_resp}) hidden={poll_hidden}; \
         the largest dummy response is {largest_dummy} bytes"
    );
}
