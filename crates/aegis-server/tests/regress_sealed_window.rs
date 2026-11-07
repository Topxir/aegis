#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Sealed requests must carry a timestamp, and flooding the replay set fills one timestamp
//! second only: the next second, which honest clients move on to, is untouched.
use aegis_core::{now_secs, sealed};
use aegis_server::{serve, Config, ServerState};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NOW: u64 = 1_700_000_000;

fn key(i: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&i.to_be_bytes());
    k
}

#[test]
fn untimed_sealed_request_is_refused() {
    let mut s = ServerState::ephemeral(Config::default());
    assert!(!s.sealed_admit([1; 32], None, NOW));
    assert!(s.sealed_admit([1; 32], Some(NOW), NOW));
}

#[test]
fn untimed_sealed_request_gets_no_answer_over_http() {
    let state = Arc::new(Mutex::new(ServerState::ephemeral(Config::default())));
    let srv_pk = state.lock().unwrap().server_public_key().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, st2) = (Arc::clone(&stop), Arc::clone(&state));
    let h = std::thread::spawn(move || serve(&listener, &st2, &s2).unwrap());
    let post = |outer: &[u8]| -> Vec<u8> {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let head = format!("POST /api/v2/s HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", outer.len());
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(outer).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    };
    let (untimed, _) = sealed::seal_request_with(&[3; 32], &srv_pk, "GET", "/health", b"").unwrap();
    let (timed, _) = sealed::seal_request_at(&[4; 32], &srv_pk, "GET", "/health", b"", Some(now_secs())).unwrap();
    let a = post(&untimed);
    let b = post(&timed);
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
    assert!(a.starts_with(b"HTTP/1.1 400 "), "{}", String::from_utf8_lossy(&a));
    assert!(b.starts_with(b"HTTP/1.1 200 "), "{}", String::from_utf8_lossy(&b));
}

#[test]
fn flooding_one_second_leaves_the_next_one_open() {
    let mut s = ServerState::ephemeral(Config::default());
    let mut n = 0u32;
    while s.sealed_admit(key(n), Some(NOW), NOW) {
        n += 1;
        assert!(n < 100_000, "one second is not capped");
    }
    assert!(n >= 1000, "cap too small for honest traffic: {n}");
    // Honest clients a second later still get in, and so does every later second.
    assert!(s.sealed_admit(key(u32::MAX), Some(NOW + 1), NOW + 1));
    assert!(s.sealed_admit(key(u32::MAX - 1), Some(NOW + 2), NOW + 2));
    // A flooded second is never retried with fresh keys by a replay: its keys stay known
    // until the timestamp leaves the window.
    assert!(!s.sealed_admit(key(0), Some(NOW), NOW + 600));
}

#[test]
fn keys_are_forgotten_once_their_timestamp_cannot_pass() {
    let mut s = ServerState::ephemeral(Config::default());
    assert!(s.sealed_admit([7; 32], Some(NOW), NOW));
    assert!(!s.sealed_admit([7; 32], Some(NOW), NOW + 600), "replay inside the window");
    // At ts + 601 the timestamp itself is refused, so nothing has to be remembered.
    assert!(!s.sealed_admit([7; 32], Some(NOW), NOW + 601));
    s.purge(NOW + 601);
    let mut n = 0u32;
    while s.sealed_admit(key(n), Some(NOW + 601), NOW + 601) {
        n += 1;
        assert!(n < 100_000);
    }
    let mut m = 0u32;
    while s.sealed_admit(key(n + 1 + m), Some(NOW + 1202), NOW + 1202) {
        m += 1;
        assert!(m < 100_000);
    }
    assert_eq!(n, m, "an expired second still takes up room");
}
