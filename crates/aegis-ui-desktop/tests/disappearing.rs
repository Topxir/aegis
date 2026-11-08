#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use aegis_core::envelope::{expired_since, TTL_CHOICES};
use aegis_core::vault::VaultParams;
use aegis_server::{serve, Config as ServerConfig, ServerState};
use aegis_ui_desktop::config::Config;
use aegis_ui_desktop::engine::Engine;
use aegis_ui_desktop::session::ChatRef;
use aegis_ui_desktop::timer::{line, parse_line};
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

fn ttl_of(e: &Engine, chat: &ChatRef) -> u64 {
    e.app().session.as_ref().unwrap().chat(chat).unwrap().ttl_s
}

#[test]
fn timer_lines_are_local_and_parse_back() {
    for t in TTL_CHOICES {
        assert_eq!(parse_line(&line(t)), Some(t));
    }
    assert_eq!(parse_line("ttl:30"), None);
    assert_eq!(parse_line("\u{1}ttl:31"), None);
    assert_eq!(parse_line("\u{1}ttl:"), None);
    assert!(expired_since(1000, 30, 31_000));
    assert!(!expired_since(1000, 0, u64::MAX));
}

#[test]
fn timer_reaches_the_other_side_and_messages_expire() {
    let srv = start_server();
    let (da, db, dc) = (TempDir::new("ta"), TempDir::new("tb"), TempDir::new("tc"));
    let (a, b, c) = (engine(&da, &srv), engine(&db, &srv), engine(&dc, &srv));
    a.create_account("alice", "Alice", PW, PW).unwrap();
    b.create_account("bob", "Bob", PW, PW).unwrap();
    c.create_account("carol", "Carol", PW, PW).unwrap();
    for (e, others) in [(&a, ["bob", "carol"]), (&b, ["alice", "carol"]), (&c, ["alice", "bob"])] {
        for o in others {
            e.add_contact(o).unwrap();
        }
    }
    a.poll_once();
    b.poll_once();
    c.poll_once();

    // Direct chat: the change, a line on both sides, and messages that carry the timer.
    let to_bob = ChatRef::Dm("bob".into());
    let from_alice = ChatRef::Dm("alice".into());
    a.set_timer(&to_bob, 300).unwrap();
    assert!(a.set_timer(&to_bob, 301).is_err());
    a.send_message(&to_bob, "short lived", None).unwrap();
    b.poll_once();
    assert_eq!(ttl_of(&a, &to_bob), 300);
    assert_eq!(ttl_of(&b, &from_alice), 300);
    assert_eq!(texts(&a, &to_bob), vec![line(300), "short lived".to_owned()]);
    assert_eq!(texts(&b, &from_alice), vec![line(300), "short lived".to_owned()]);
    {
        let app = b.app();
        let ch = app.session.as_ref().unwrap().chat(&from_alice).unwrap();
        assert_eq!(ch.unread, 1, "the timer line is not unread");
        assert!(ch.msgs.iter().all(|m| m.base_ms != 0));
    }

    // The receiver's copy counts from receipt; after the timer only the line is left.
    b.mutate(|s| {
        for m in &mut s.data.dms.get_mut("alice").unwrap().msgs {
            m.base_ms -= 300_000;
        }
    })
    .unwrap();
    b.sweep();
    assert_eq!(texts(&b, &from_alice), vec![line(300)]);
    assert_eq!(texts(&a, &to_bob).len(), 2);

    // An older change that arrives late is ignored; turning it off goes through.
    b.set_timer(&from_alice, 0).unwrap();
    a.poll_once();
    assert_eq!(ttl_of(&a, &to_bob), 0);
    assert_eq!(texts(&a, &to_bob).last(), Some(&line(0)));
    b.mutate(|s| s.data.dms.get_mut("alice").unwrap().ttl_ms = u64::MAX).unwrap();
    a.set_timer(&to_bob, 30).unwrap();
    b.poll_once();
    assert_eq!(ttl_of(&b, &from_alice), 0);

    // Group: the change goes on the sender-key chain to every member.
    a.create_group("trio", &["bob".to_owned(), "carol".to_owned()]).unwrap();
    b.poll_once();
    c.poll_once();
    let gid = b.app().session.as_ref().unwrap().data.groups.keys().next().unwrap().clone();
    let g = ChatRef::Group(gid);
    b.set_timer(&g, 86_400).unwrap();
    a.poll_once();
    c.poll_once();
    for e in [&a, &b, &c] {
        assert_eq!(ttl_of(e, &g), 86_400);
        assert_eq!(texts(e, &g), vec![line(86_400)]);
    }
    c.send_message(&g, "for a day", None).unwrap();
    a.poll_once();
    let app = a.app();
    let m = app.session.as_ref().unwrap().chat(&g).unwrap().msgs.last().unwrap().clone();
    assert_eq!((m.text.as_str(), m.ttl_s), ("for a day", 86_400));
}
