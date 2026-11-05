#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A burst of requests must keep ts inside the server window.
use aegis_core::net::Client;
use aegis_server::{serve, Config, ServerState};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[test]
fn burst_of_requests_keeps_ts_in_window() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = Config { pow_bits: 0, ..Config::default() };
    let state = Arc::new(Mutex::new(ServerState::ephemeral(cfg)));
    let stop = Arc::new(AtomicBool::new(false));
    let (st, s2) = (Arc::clone(&state), Arc::clone(&stop));
    let h = std::thread::spawn(move || serve(&listener, &st, &s2).unwrap());
    let c = Client::new(&format!("http://127.0.0.1:{port}"), None).unwrap().with_pow_bits(0);
    let mut first_fail = None;
    for i in 0..700 {
        // Unknown user: 404 -> Ok(None) while ts is in the window.
        if let Err(e) = c.prekeys_take("nobody") {
            first_fail = Some((i, format!("{e:?}")));
            break;
        }
    }
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
    assert!(first_fail.is_none(), "request failed after a burst: {first_fail:?}");
}
