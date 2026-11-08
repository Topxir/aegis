#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Invites and the hidden profile through the engine. Every file lives in a unique directory
//! under the system temporary folder; nothing here resolves the user's real data directory.

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

fn link_of(e: &Engine) -> String {
    e.app().invite.as_ref().map(|l| l.to_string()).unwrap()
}

#[test]
fn invite_connects_a_hidden_user_once() {
    let srv = start_server();
    let (da, db, dc) = (TempDir::new("ia"), TempDir::new("ib"), TempDir::new("ic"));
    let (a, b, c) = (engine(&da, &srv), engine(&db, &srv), engine(&dc, &srv));
    a.create_account("alice", "Alice", PW, PW).unwrap();
    b.create_account("bob", "Bob", PW, PW).unwrap();
    c.create_account("carol", "Carol", PW, PW).unwrap();
    a.poll_once();
    b.poll_once();

    a.set_hidden(true).unwrap();
    assert!(a.app().session.as_ref().unwrap().data.settings.hidden);
    assert_eq!(b.add_contact("alice").unwrap_err().key, "err.not_found");
    assert_eq!(b.add_contact("nobody-here").unwrap_err().key, "err.not_found");

    a.create_invite().unwrap();
    let link = link_of(&a);
    assert!(link.starts_with("aegis://invite/"));
    assert_eq!(a.redeem_invite(&link).unwrap_err().key, "err.self");
    b.redeem_invite(&link).unwrap();
    assert!(b.app().session.as_ref().unwrap().data.contacts.contains_key("alice"));
    assert_eq!(c.redeem_invite(&link).unwrap_err().key, "err.invite_gone");
    assert_eq!(c.redeem_invite("aegis://invite/xyz").unwrap_err().key, "err.invite_link");

    a.poll_once();
    {
        let app = a.app();
        let s = app.session.as_ref().unwrap();
        assert!(s.data.contacts.contains_key("bob"));
        assert!(s.data.invites.is_empty());
        assert_eq!(s.data.contacts["bob"].name, "Bob");
    }
    b.send_message(&ChatRef::Dm("alice".into()), "hi via invite", None)
        .unwrap();
    a.poll_once();
    assert_eq!(
        texts(&a, &ChatRef::Dm("bob".into())),
        vec!["hi via invite".to_owned()]
    );
    a.send_message(&ChatRef::Dm("bob".into()), "hello", None).unwrap();
    b.poll_once();
    assert_eq!(texts(&b, &ChatRef::Dm("alice".into())), vec!["hello".to_owned()]);
    {
        let app = b.app();
        assert_eq!(app.session.as_ref().unwrap().data.contacts["alice"].name, "Alice");
    }

    a.set_hidden(false).unwrap();
    c.add_contact("alice").unwrap();
}

#[test]
fn the_directory_never_learns_the_display_name() {
    let srv = start_server();
    let (da, db) = (TempDir::new("na"), TempDir::new("nb"));
    let (a, b) = (engine(&da, &srv), engine(&db, &srv));
    a.create_account("alice", "Alice", PW, PW).unwrap();
    b.create_account("bob", "Bob", PW, PW).unwrap();
    a.update_display("Alice B").unwrap();
    let client = Client::new(&format!("http://{}", srv.addr), None)
        .unwrap()
        .with_pow_bits(BITS);
    assert_eq!(client.lookup("alice").unwrap().unwrap().title, "");
    b.add_contact("alice").unwrap();
    let app = b.app();
    assert_eq!(app.session.as_ref().unwrap().data.contacts["alice"].name, "");
}
