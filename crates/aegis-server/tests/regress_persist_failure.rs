#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A PIN change that cannot be written to disk is not acknowledged.
use aegis_core::net::Client;
use aegis_core::pin::{PinParams, PinSetup};
use aegis_core::Error;
use aegis_server::{serve, Config, ServerState};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const BITS: u32 = 6;
const PARAMS: PinParams = PinParams { m_kib: 64, t: 1, p: 1 };

#[test]
fn pin_reply_waits_for_a_successful_write() {
    let dir = std::env::temp_dir().join(format!("aegis-persist-fail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = Config { pow_bits: BITS, pin_min_interval_secs: 0, ..Config::default() };
    let state = Arc::new(Mutex::new(ServerState::open_with(&dir, config).unwrap()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let h = std::thread::spawn(move || serve(&listener, &state, &s2).unwrap());
    let c = Client::new(&url, None).unwrap().with_pow_bits(BITS);
    let a = PinSetup::new_with("123456", &[1; 32], PARAMS, &[5; 16], &[1; 32], &[6; 32], &[7; 12]).unwrap();
    c.pin_create(&a.file.slot, &a.verifier, &a.s).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let b = PinSetup::new_with("123456", &[1; 32], PARAMS, &[5; 16], &[2; 32], &[6; 32], &[7; 12]).unwrap();
    let r = c.pin_create(&b.file.slot, &b.verifier, &b.s);
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
    assert!(matches!(r, Err(Error::Http(503))), "{r:?}");
}
