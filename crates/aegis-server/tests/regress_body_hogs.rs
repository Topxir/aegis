#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Connections that sent complete headers but no body are evicted like idle ones, so they cannot
//! lock out honest clients.
use aegis_server::{serve, Config, ServerState};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[test]
fn header_complete_hogs_do_not_lock_out_honest_clients() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(ServerState::ephemeral(Config::default())));
    let stop = Arc::new(AtomicBool::new(false));
    let (st, s2) = (Arc::clone(&state), Arc::clone(&stop));
    let h = std::thread::spawn(move || serve(&listener, &st, &s2).unwrap());
    let hog: Vec<TcpStream> = (0..256)
        .map(|_| {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"POST /api/v2/s HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n").unwrap();
            s
        })
        .collect();
    std::thread::sleep(Duration::from_millis(500));
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let _ = s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    drop(hog);
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "honest /health was dropped: {out:?}");
}
