#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Engine tests. Every file lives in a unique directory under the system
//! temporary folder; nothing here resolves the user's real data directory.

use aegis_core::group::group_queue;
use aegis_core::net::Client;
use aegis_core::vault::VaultParams;
use aegis_server::{serve, Config as ServerConfig, ServerState};
use aegis_ui_desktop::config::Config;
use aegis_ui_desktop::engine::Engine;
use aegis_ui_desktop::session::ChatRef;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const BITS: u32 = 8;
const PW: &str = "correct horse battery";

struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn start_server() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(ServerState::ephemeral(ServerConfig {
        pow_bits: BITS,
        pin_min_interval_secs: 0,
        ..ServerConfig::default()
    })));
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        serve(&listener, &state, &s2).unwrap();
    });
    Server {
        addr,
        stop,
        handle: Some(handle),
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = u64::from_le_bytes(aegis_core::random_bytes::<8>().unwrap());
        let p = std::env::temp_dir().join(format!("aegis-ui-test-{tag}-{n:016x}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn engine(dir: &TempDir, server: &Server) -> Arc<Engine> {
    let cfg = Config {
        data_dir: dir.0.clone(),
        vault_params: VaultParams {
            m_kib: 8,
            t: 1,
            p: 1,
        },
        pow_bits: BITS,
        default_endpoint: format!("http://{}", server.addr),
    };
    Engine::new(cfg, || {})
}

fn texts(e: &Engine, chat: &ChatRef) -> Vec<String> {
    let app = e.app();
    let s = app.session.as_ref().unwrap();
    s.chat(chat)
        .map(|c| c.msgs.iter().map(|m| m.text.clone()).collect())
        .unwrap_or_default()
}

#[test]
fn vault_round_trip_and_wrong_password() {
    let dir = TempDir::new("vault");
    let srv = start_server();
    let e = engine(&dir, &srv);
    e.create_account("alice", "Alice", PW, PW).unwrap();
    assert!(e.vault_path("alice").starts_with(&dir.0));
    e.mutate(|s| {
        s.data.display = "Alice B".to_owned();
        s.dirty = true;
    })
    .unwrap();
    let s = e.detach().unwrap();
    e.persist(s);
    assert!(e.app().session.is_none());

    assert!(e.unlock("alice", "wrong password!!").is_err());
    assert!(e.app().session.is_none());
    assert!(e.unlock("nobody", PW).is_err());
    e.unlock("alice", PW).unwrap();
    assert_eq!(e.app().session.as_ref().unwrap().data.display, "Alice B");

    assert!(e
        .create_account("carol", "Carol", "short", "short")
        .is_err());
    assert!(e
        .create_account("carol", "Carol", PW, "different password")
        .is_err());
    assert!(!e.vault_path("carol").exists());

    // The server refuses a taken username and no vault is left behind.
    let dir2 = TempDir::new("vault2");
    let e2 = engine(&dir2, &srv);
    assert!(e2.create_account("alice", "Impostor", PW, PW).is_err());
    assert!(!e2.vault_path("alice").exists());
    assert!(e2.app().session.is_none());
}

#[test]
fn export_and_import_round_trip() {
    let dir = TempDir::new("export");
    let srv = start_server();
    let e = engine(&dir, &srv);
    e.create_account("alice", "Alice", PW, PW).unwrap();
    let target = dir.0.join("backup.vault");
    let t = target.to_str().unwrap();
    e.export_vault(t).unwrap();
    assert!(e.export_vault(t).is_err(), "must not overwrite");
    assert!(e.export_vault("relative.vault").is_err());

    let dir2 = TempDir::new("import");
    let e2 = engine(&dir2, &srv);
    assert!(e2.import_vault(t, "wrong password!!").is_err());
    assert!(!e2.vault_path("alice").exists());
    e2.import_vault(t, PW).unwrap();
    assert_eq!(e2.app().session.as_ref().unwrap().data.username, "alice");
}

#[test]
fn messages_groups_tamper_and_replay() {
    let srv = start_server();
    let (da, db, dc) = (TempDir::new("a"), TempDir::new("b"), TempDir::new("c"));
    let (a, b, c) = (engine(&da, &srv), engine(&db, &srv), engine(&dc, &srv));
    a.create_account("alice", "Alice", PW, PW).unwrap();
    b.create_account("bob", "Bob", PW, PW).unwrap();
    c.create_account("carol", "Carol", PW, PW).unwrap();

    a.add_contact("bob").unwrap();
    a.add_contact("carol").unwrap();
    b.add_contact("alice").unwrap();
    b.add_contact("carol").unwrap();
    c.add_contact("alice").unwrap();
    c.add_contact("bob").unwrap();
    assert!(a.add_contact("nobody-here").is_err());

    // Everyone publishes prekeys on the first poll; a session needs them.
    a.poll_once();
    b.poll_once();
    c.poll_once();

    // Direct message, then the same frames fetched again.
    a.send_message(&ChatRef::Dm("bob".into()), "hello bob", None)
        .unwrap();
    assert!(b.poll_once() >= 1);
    let dm = ChatRef::Dm("alice".into());
    assert_eq!(texts(&b, &dm), vec!["hello bob".to_owned()]);
    b.mutate(|s| s.data.inbox_cursor = 0).unwrap();
    b.poll_once();
    assert_eq!(texts(&b, &dm).len(), 1, "replay must be dropped");

    // A garbage frame in the inbox is ignored and does not block later messages.
    let client = Client::new(&format!("http://{}", srv.addr), None)
        .unwrap()
        .with_pow_bits(BITS);
    let inbox = b.app().session.as_ref().unwrap().inbox();
    client
        .send(&inbox, &aegis_core::pad::pad(&[7u8; 200]).unwrap())
        .unwrap();
    a.send_message(&ChatRef::Dm("bob".into()), "second", None)
        .unwrap();
    b.poll_once();
    assert_eq!(
        texts(&b, &dm),
        vec!["hello bob".to_owned(), "second".to_owned()]
    );

    // Group of three.
    a.create_group("trio", &["bob".to_owned(), "carol".to_owned()])
        .unwrap();
    b.poll_once();
    c.poll_once();
    let gid = {
        let app = b.app();
        let s = app.session.as_ref().unwrap();
        assert_eq!(s.data.groups.len(), 1);
        s.data.groups.keys().next().unwrap().clone()
    };
    assert_eq!(c.app().session.as_ref().unwrap().data.groups.len(), 1);
    let chat = ChatRef::Group(gid.clone());
    let queue = {
        let app = b.app();
        let g = app.session.as_ref().unwrap().data.groups.get(&gid).unwrap();
        group_queue(&g.key).unwrap()
    };
    b.send_message(&chat, "hi group", None).unwrap();
    // Grab the frame from the server before the members consume it.
    let page = client.poll(&queue, 0).unwrap();
    let frame = page.frames.last().unwrap().1.clone();
    a.poll_once();
    c.poll_once();
    assert_eq!(texts(&a, &chat), vec!["hi group".to_owned()]);
    assert_eq!(texts(&c, &chat), vec!["hi group".to_owned()]);

    // Tampered and replayed group frames are dropped.
    let mut tampered = frame.clone();
    tampered[40] ^= 0x01;
    client.send(&queue, &tampered).unwrap();
    // The server rejects an identical request within the same second, so let the clock move.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    client.send(&queue, &frame).unwrap();
    a.poll_once();
    c.poll_once();
    assert_eq!(texts(&a, &chat).len(), 1);
    assert_eq!(texts(&c, &chat).len(), 1);
}

#[test]
fn pin_unlock_wrong_pin_password_fallback_and_duress() {
    let dir = TempDir::new("pin");
    let srv = start_server();
    let e = engine(&dir, &srv);
    e.create_account("alice", "Alice", PW, PW).unwrap();
    assert!(e.pin_set("12", "12").is_err());
    assert_eq!(e.pin_set("1234", "4321").unwrap_err().key, "err.pin_mismatch");
    e.pin_set("1234", "1234").unwrap();
    assert!(e.app().pin_on);
    assert_eq!(e.pin_set("1234", "1234").unwrap_err().key, "err.pin_exists");
    assert_eq!(e.duress_set("1234", "1234").unwrap_err().key, "err.duress_same");
    e.duress_set("1234", "9999").unwrap();
    assert!(e.app().duress_on);

    let lock = |e: &Engine| {
        let s = e.detach().unwrap();
        e.persist(s);
    };
    lock(&e);
    let f = e.unlock("alice", "4321").unwrap_err();
    assert_eq!(f.key, "err.pin_wrong");
    assert!(f.detail.parse::<u32>().is_ok(), "tries left: {}", f.detail);
    assert!(e.app().session.is_none());
    e.unlock("alice", "1234").unwrap();
    assert_eq!(e.app().session.as_ref().unwrap().data.username, "alice");
    lock(&e);

    // The password always works.
    e.unlock("alice", PW).unwrap();
    assert!(e.app().pin_on);
    lock(&e);

    // The duress PIN wipes the account and looks exactly like a wrong PIN.
    let f = e.unlock("alice", "9999").unwrap_err();
    assert_eq!(f.key, "err.pin_wrong");
    assert!(f.detail.parse::<u32>().is_ok(), "tries left: {}", f.detail);
    assert!(e.app().session.is_none());
    assert!(!e.vault_path("alice").exists());
    for ext in ["pin", "pinpw", "pinmeta", "duress"] {
        let mut n = e.vault_path("alice").file_name().unwrap().to_os_string();
        n.push(".");
        n.push(ext);
        assert!(!e.vault_path("alice").with_file_name(n).exists(), "{ext}");
    }
    // Afterwards the account still looks like one with a PIN: the counter runs down, then
    // "PIN gone", then a password is simply wrong. Nothing says that a wipe happened.
    assert!(e.has_vaults());
    let first: u32 = f.detail.parse().unwrap();
    let mut left = first;
    while left > 1 {
        let f = e.unlock("alice", "5555").unwrap_err();
        assert_eq!(f.key, "err.pin_wrong");
        left -= 1;
        assert_eq!(f.detail, left.to_string());
    }
    assert_eq!(e.unlock("alice", "5555").unwrap_err().key, "err.pin_gone");
    let f = e.unlock("alice", PW).unwrap_err();
    assert_ne!(f.key, "err.no_account");
    assert_eq!(f.key, e.unlock("alice", "other password!!").unwrap_err().key);
    // A restart (new engine on the same folder) shows the same.
    let e2 = engine(&dir, &srv);
    assert!(e2.has_vaults());
    assert_ne!(e2.unlock("alice", "5555").unwrap_err().key, "err.no_account");
    assert_eq!(e2.unlock("bob", PW).unwrap_err().key, "err.no_account");
}

#[cfg(windows)]
#[test]
fn an_edited_pinmeta_is_refused_before_anything_is_sent() {
    let dir = TempDir::new("pinmeta");
    let srv = start_server();
    let e = engine(&dir, &srv);
    e.create_account("alice", "Alice", PW, PW).unwrap();
    e.pin_set("1234", "1234").unwrap();
    let s = e.detach().unwrap();
    e.persist(s);
    let meta = e.vault_path("alice").with_extension("vault.pinmeta");
    let good = std::fs::read(&meta).unwrap();
    // Plain JSON that points to another server.
    let evil = format!(
        "{{\"endpoint\":\"http://127.0.0.1:9\",\"socks5\":\"\",\"tor\":false,\"server_key\":\"{}\"}}",
        "00".repeat(32)
    );
    std::fs::write(&meta, evil).unwrap();
    assert_eq!(e.unlock("alice", "1234").unwrap_err().key, "err.pin_gone");
    // A flipped byte, and a copy from another vault, are refused too.
    let mut bad = good.clone();
    let n = bad.len() - 2;
    bad[n] ^= 1;
    std::fs::write(&meta, &bad).unwrap();
    assert_eq!(e.unlock("alice", "1234").unwrap_err().key, "err.pin_gone");
    // The PIN still works once the real file is back, and the password always does.
    std::fs::write(&meta, &good).unwrap();
    e.unlock("alice", "1234").unwrap();
}

#[test]
fn deleting_the_account_removes_the_pin_files_and_the_server_slot() {
    use aegis_core::net::PinOpen;
    use aegis_core::pin::PinFile;
    let dir = TempDir::new("delpin");
    let srv = start_server();
    let e = engine(&dir, &srv);
    e.create_account("alice", "Alice", PW, PW).unwrap();
    e.pin_set("1234", "1234").unwrap();
    e.duress_set("1234", "9999").unwrap();
    let vault = e.vault_path("alice");
    let side = |ext: &str| {
        let mut n = vault.file_name().unwrap().to_os_string();
        n.push(".");
        n.push(ext);
        vault.with_file_name(n)
    };
    let file = PinFile::parse(&std::fs::read(side("pin")).unwrap()).unwrap();
    let verifier = file.derive("1234").unwrap().verifier().unwrap();
    let client = Client::new(&format!("http://{}", srv.addr), None)
        .unwrap()
        .with_pow_bits(BITS)
        .with_pinned_server_key(None)
        .unwrap();
    assert!(matches!(
        client.pin_open(&file.slot, &verifier).unwrap(),
        PinOpen::Secret(_)
    ));
    e.delete_account("alice").unwrap();
    for ext in ["pin", "pinpw", "pinmeta", "duress", "ghost"] {
        assert!(!side(ext).exists(), "{ext}");
    }
    assert!(matches!(
        client.pin_open(&file.slot, &verifier).unwrap(),
        PinOpen::Gone
    ));
    assert_eq!(e.unlock("alice", "1234").unwrap_err().key, "err.no_account");
}

#[test]
fn removing_the_pin_needs_the_pin() {
    let dir = TempDir::new("pinrm");
    let srv = start_server();
    let e = engine(&dir, &srv);
    e.create_account("alice", "Alice", PW, PW).unwrap();
    e.pin_set("123456", "123456").unwrap();
    assert_eq!(e.pin_remove("654321").unwrap_err().key, "err.pin_wrong");
    e.pin_remove("123456").unwrap();
    assert!(!e.app().pin_on);
    e.pin_set("1234", "1234").unwrap();
}
