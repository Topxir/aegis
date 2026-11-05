#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The real client (`aegis_core::net::Client`, plain and sealed) against the real server.

use aegis_core::directory::Registration;
use aegis_core::identity::Identity;
use aegis_core::net::{Client, PinOpen};
use aegis_core::pin::{PinKey, PinParams, PinSetup};
use aegis_core::prekeys::PrekeyPut;
use aegis_core::x3dh::SignedPrekey;
use aegis_core::{now_secs, Error};
use aegis_server::{serve, Config, ServerState};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

const BITS: u32 = 6;
static COUNTER: AtomicU32 = AtomicU32::new(0);
const PARAMS: PinParams = PinParams { m_kib: 64, t: 1, p: 1 };

struct Running {
    url: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
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
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("aegis-pinclient-test-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = Config { pow_bits: BITS, pin_min_interval_secs: 0, prekey_put_interval_secs: 0, ..Config::default() };
    let state = Arc::new(Mutex::new(ServerState::open_with(&dir, config).unwrap()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        serve(&listener, &state, &s2).unwrap();
    });
    Running { url, stop, handle: Some(handle), dir }
}

fn clients(r: &Running) -> Vec<Client> {
    let plain = Client::new(&r.url, None).unwrap().with_pow_bits(BITS);
    let sealed = Client::new(&r.url, None).unwrap().with_pow_bits(BITS).with_pinned_server_key(None).unwrap();
    assert!(sealed.server_key().is_some());
    vec![plain, sealed]
}

#[test]
fn pin_setup_create_open_wrong_attempts_then_gone() {
    let r = start();
    for (i, c) in clients(&r).into_iter().enumerate() {
        let vault = [7u8 + i as u8; 32];
        let salt = [1u8 + i as u8; 16];
        let slot = [2u8 + i as u8; 32];
        let setup = PinSetup::new_with("1234", &vault, PARAMS, &salt, &slot, &[3u8; 32], &[4u8; 12]).unwrap();
        c.pin_create(&setup.file.slot, &setup.verifier, &setup.s).unwrap();
        assert!(matches!(c.pin_create(&setup.file.slot, &setup.verifier, &[8; 32]), Err(Error::Http(409))));

        let key = PinKey::derive_with("1234", &salt, &slot, PARAMS).unwrap();
        let PinOpen::Secret(s) = c.pin_open(&slot, &key.verifier().unwrap()).unwrap() else { panic!("open failed") };
        assert_eq!(*setup.file.unwrap(&key, &s).unwrap(), vault);

        let wrong = PinKey::derive_with("4321", &salt, &slot, PARAMS).unwrap().verifier().unwrap();
        for left in (0..5).rev() {
            assert_eq!(c.pin_open(&slot, &wrong).unwrap(), PinOpen::Wrong { left });
        }
        assert_eq!(c.pin_open(&slot, &wrong).unwrap(), PinOpen::Gone);
        assert_eq!(c.pin_open(&slot, &key.verifier().unwrap()).unwrap(), PinOpen::Gone);
    }
}

#[test]
fn pin_delete_removes_slot_and_wrong_delete_counts() {
    let r = start();
    for c in clients(&r) {
        let slot = [9u8; 32];
        let setup = PinSetup::new_with("123456", &[1; 32], PARAMS, &[5; 16], &slot, &[6; 32], &[7; 12]).unwrap();
        c.pin_create(&slot, &setup.verifier, &setup.s).unwrap();
        assert!(matches!(c.pin_delete(&slot, &[0u8; 32]), Err(Error::Http(403))));
        assert_eq!(c.pin_open(&slot, &setup.verifier).unwrap(), PinOpen::Secret(*setup.s));
        c.pin_delete(&slot, &setup.verifier).unwrap();
        assert_eq!(c.pin_open(&slot, &setup.verifier).unwrap(), PinOpen::Gone);
    }
}

#[test]
fn prekeys_and_nop_through_the_sealed_client() {
    let r = start();
    let id = Identity::from_secrets([1; 32], [2; 32]);
    let now = now_secs();
    let mut reg = Registration::sign(&id, "alice", "alice", now).unwrap();
    reg.mine(BITS);
    let c = Client::new(&r.url, None).unwrap().with_pow_bits(BITS).with_pinned_server_key(None).unwrap();
    c.submit_registration(&reg).unwrap();
    c.nop(1024, 4096).unwrap();
    c.nop(0, 0).unwrap();
    assert!(c.prekeys_take("alice").unwrap().is_none());
    let spk = SignedPrekey::from_secret(&id, [5; 32], now - 10);
    let put = |opks: Vec<[u8; 32]>, ts: u64| PrekeyPut::sign(&id, "alice", spk.pk, spk.ts, opks, ts).unwrap();
    assert_eq!(c.prekeys_put(&put(vec![[1; 32]], now)).unwrap(), 1);
    assert_eq!(c.prekeys_put(&put(vec![[2; 32], [3; 32]], now - 1)).unwrap(), 3, "same spk refills");
    let b = c.prekeys_take("alice").unwrap().unwrap();
    assert_eq!((b.spk, b.opk), (spk.pk, Some([1; 32])));
    b.check(&id.ed_public(), now).unwrap();
}

#[test]
fn a_changed_server_key_is_a_hard_error() {
    let r = start();
    let c = Client::new(&r.url, None).unwrap().with_pow_bits(BITS);
    let key = c.fetch_server_key().unwrap();
    assert!(c.clone().with_pinned_server_key(Some(key)).is_ok());
    let mut other = key;
    other[0] ^= 1;
    assert!(matches!(c.with_pinned_server_key(Some(other)), Err(Error::ServerKeyChanged)));
}
