//! Connection cap and PIN budget regression tests: idle sockets must not lock others out, and a
//! handful of attacker-owned PIN slots must not burn the global PIN budget of everybody else.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::{hex, pow};
use aegis_server::{serve, Config, Request, ServerState};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[test]
fn idle_sockets_do_not_lock_out_honest_clients() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(ServerState::ephemeral(Config::default())));
    let stop = Arc::new(AtomicBool::new(false));
    let (st, s2) = (Arc::clone(&state), Arc::clone(&stop));
    let h = std::thread::spawn(move || serve(&listener, &st, &s2).unwrap());
    // Attacker: 256 connections that send nothing (each holds a slot for ~5-15 s, and can be
    // refreshed forever by trickling one byte per 4 s).
    let hog: Vec<TcpStream> = (0..256).map(|_| TcpStream::connect(addr).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(500));
    // Honest user.
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    drop(hog);
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "honest /health was dropped: {out:?}");
}

fn req(path: &str, body: &str) -> Request {
    Request { method: "POST".into(), path: path.into(), query: vec![], body: body.as_bytes().to_vec() }
}

fn pin_form(keys: &[(&str, [u8; 32])], scope_slot: [u8; 32], fields: &[[u8; 32]], ts: u64, bits: u32) -> String {
    let joined = fields.iter().map(|f| hex::encode(f)).collect::<Vec<_>>().join("\n");
    let scope = format!("pin:{}", hex::encode(&scope_slot));
    let n = pow::mine(&scope, ts, &pow::body_hash_hex(joined.as_bytes()), bits);
    let mut s = keys.iter().map(|(k, v)| format!("{k}={}", hex::encode(v))).collect::<Vec<_>>().join("&");
    s.push_str(&format!("&ts={ts}&pow={n}"));
    s
}

#[test]
fn attacker_slots_do_not_starve_global_pin_budget() {
    const BITS: u32 = 6; // the real server uses 18 (about 0.25M hashes = tens of ms per request)
    let now = aegis_core::now_secs();
    let mut s = ServerState::ephemeral(Config { pow_bits: BITS, pin_min_interval_secs: 1, ..Config::default() });
    // Victim slot.
    let (vs, vv, vsec) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let f = pin_form(&[("slot", vs), ("v", vv), ("s", vsec)], vs, &[vs, vv, vsec], now, BITS);
    assert_eq!(s.handle(&req("/api/v2/pin/create", &f), now).status, 200);
    // Attacker: 50 own slots, each opened once with the right PIN in the same second.
    let t = now + 5;
    for i in 0..50u8 {
        let (a, v, sec) = ([100 + i; 32], [200u8; 32], [9u8; 32]);
        let f = pin_form(&[("slot", a), ("v", v), ("s", sec)], a, &[a, v, sec], t, BITS);
        assert_eq!(s.handle(&req("/api/v2/pin/create", &f), t).status, 200);
    }
    for i in 0..50u8 {
        let (a, v) = ([100 + i; 32], [200u8; 32]);
        let f = pin_form(&[("slot", a), ("v", v)], a, &[a, v], t, BITS);
        assert_eq!(s.handle(&req("/api/v2/pin/open", &f), t).status, 200);
    }
    // The honest user with the right PIN is now refused in the same second.
    let f = pin_form(&[("slot", vs), ("v", vv)], vs, &[vs, vv], t, BITS);
    let r = s.handle(&req("/api/v2/pin/open", &f), t);
    assert_eq!(r.status, 200, "victim got {} {}", r.status, r.body);
}

