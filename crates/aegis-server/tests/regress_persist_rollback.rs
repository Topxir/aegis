#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A PIN change that could not be written is taken back out of memory too, so memory and disk
//! agree: a refused create leaves no slot, a refused guess leaves the counter as it was.
use aegis_core::net::{Client, PinOpen};
use aegis_core::pin::{PinParams, PinSetup};
use aegis_core::Error;
use aegis_server::{serve, Config, ServerState};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const BITS: u32 = 6;
const PARAMS: PinParams = PinParams { m_kib: 64, t: 1, p: 1 };

#[test]
fn failed_write_rolls_the_pin_change_back() {
    let dir = std::env::temp_dir().join(format!("aegis-persist-rollback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = Config { pow_bits: BITS, pin_min_interval_secs: 0, ..Config::default() };
    let state = Arc::new(Mutex::new(ServerState::open_with(&dir, config).unwrap()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, st2) = (Arc::clone(&stop), Arc::clone(&state));
    let h = std::thread::spawn(move || serve(&listener, &st2, &s2).unwrap());
    let c = Client::new(&url, None).unwrap().with_pow_bits(BITS);
    let a = PinSetup::new_with("123456", &[1; 32], PARAMS, &[5; 16], &[1; 32], &[6; 32], &[7; 12]).unwrap();
    let b = PinSetup::new_with("123456", &[1; 32], PARAMS, &[5; 16], &[2; 32], &[6; 32], &[7; 12]).unwrap();
    c.pin_create(&a.file.slot, &a.verifier, &a.s).unwrap();

    std::fs::remove_dir_all(&dir).unwrap();
    let created = c.pin_create(&b.file.slot, &b.verifier, &b.s);
    let guessed = c.pin_open(&a.file.slot, &[0; 32]);
    let slots_while_failing = state.lock().unwrap().pin_slots();
    std::fs::create_dir_all(&dir).unwrap();

    // The slot that was refused can be created now; it was not left behind in memory.
    let again = c.pin_create(&b.file.slot, &b.verifier, &b.s);
    // The refused guess did not count.
    let left = c.pin_open(&a.file.slot, &[0; 32]);
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(matches!(created, Err(Error::Http(503))), "{created:?}");
    assert!(matches!(guessed, Err(Error::Http(503))), "{guessed:?}");
    assert_eq!(slots_while_failing, 1, "refused create stayed in memory");
    assert!(again.is_ok(), "{again:?}");
    assert!(matches!(left, Ok(PinOpen::Wrong { left: 4 })), "{left:?}");
}
