//! A replayed sealed outer request must not produce a second response under the same keystream:
//! the server refuses the repeat, and every response carries its own random nonce.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::{hex, now_secs, pow, sealed};
use aegis_server::{serve, Config, ServerState};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BITS: u32 = 6;

fn http_post_outer(addr: SocketAddr, outer: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = format!(
        "POST /api/v2/s HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        outer.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(outer).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let pos = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    out[pos + 4..].to_vec()
}

fn form(slot: &str, fields: &[(&str, &str)], ts: u64) -> String {
    let joined = std::iter::once(slot).chain(fields.iter().map(|f| f.1)).collect::<Vec<_>>().join("\n");
    let n = pow::mine(&format!("pin:{slot}"), ts, &pow::body_hash_hex(joined.as_bytes()), BITS);
    let mut f = format!("slot={slot}");
    for (k, v) in fields {
        f.push_str(&format!("&{k}={v}"));
    }
    format!("{f}&ts={ts}&pow={n}")
}

#[test]
fn replayed_sealed_request_gets_no_second_response() {
    let dir = std::env::temp_dir().join(format!("aegis-hack-anon1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = Config { pow_bits: BITS, pin_min_interval_secs: 0, ..Config::default() };
    let state = Arc::new(Mutex::new(ServerState::open_with(&dir, cfg).unwrap()));
    let srv_pk = state.lock().unwrap().server_public_key().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (st2, stop2) = (Arc::clone(&state), Arc::clone(&stop));
    let h = std::thread::spawn(move || serve(&listener, &st2, &stop2).unwrap());

    let (slot, v, secret) = (hex::encode(&[1u8; 32]), hex::encode(&[2u8; 32]), hex::encode(&[0xabu8; 32]));
    let now = now_secs();

    // Honest client: pin/create, then pin/open (both sealed).
    let call = |path: &str, body: String| {
        let (outer, k) = sealed::seal_request(&srv_pk, "POST", path, body.as_bytes()).unwrap();
        let resp = http_post_outer(addr, &outer);
        (outer, k, resp)
    };
    let (_, k, r) = call("/api/v2/pin/create", form(&slot, &[("v", &v), ("s", &secret)], now));
    assert_eq!(sealed::open_response(&k, &r).unwrap().0, 200);
    let (outer, k, c1) = call("/api/v2/pin/open", form(&slot, &[("v", &v)], now - 1));
    let (st, body) = sealed::open_response(&k, &c1).unwrap();
    assert_eq!(st, 200);
    assert!(String::from_utf8_lossy(&body).contains(&secret));

    // Attacker = TLS terminator: replays the captured outer bytes, never learns k_resp.
    let c2 = http_post_outer(addr, &outer);
    assert!(c2.is_empty(), "replay must get a plain 400 with no sealed body");
    // A second honest call has a different nonce even for the same plaintext.
    let (_, k2, c3) = call("/api/v2/pin/open", form(&slot, &[("v", &v)], now - 2));
    assert_eq!(sealed::open_response(&k2, &c3).unwrap().0, 200);
    assert_ne!(c1[..12], c3[..12]);
    assert_eq!(c1.len(), c3.len());

    stop.store(true, Ordering::SeqCst);
    let _ = h.join();
    let _ = std::fs::remove_dir_all(&dir);
}
