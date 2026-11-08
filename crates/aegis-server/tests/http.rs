#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::identity::Identity;
use aegis_core::net::Client;
use aegis_core::pad;
use aegis_server::{serve, Config, ServerState};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BITS: u32 = 8;

struct Running {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn start(config: Config) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(ServerState::ephemeral(config)));
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        serve(&listener, &state, &s2).unwrap();
    });
    Running { addr, stop, handle: Some(handle) }
}

fn client(r: &Running, bits: u32) -> Client {
    Client::new(&format!("http://{}", r.addr), None)
        .unwrap()
        .with_pow_bits(bits)
        .with_timeout(Duration::from_secs(10))
}

fn raw(r: &Running, bytes: &[u8]) -> String {
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = s.write_all(bytes);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn cfg() -> Config {
    Config { pow_bits: BITS, ..Config::default() }
}

#[test]
fn health_register_lookup_over_http() {
    let r = start(cfg());
    let c = client(&r, BITS);
    c.health().unwrap();
    let id = Identity::from_secrets([1; 32], [2; 32]);
    c.register(&id, "alice", "Alice").unwrap();
    let e = c.lookup("alice").unwrap().unwrap();
    assert_eq!(e.title, "", "titles are never stored (section 3)");
    assert_eq!(e.x, id.x_public());
    assert_eq!(e.ed, id.ed_public());
    assert!(c.lookup("bobby").unwrap().is_none());
    let other = Identity::from_secrets([3; 32], [4; 32]);
    assert!(c.register(&other, "alice", "Mallory").is_err());
    assert_eq!(c.lookup("alice").unwrap().unwrap().ed, id.ed_public());
}

#[test]
fn send_and_poll_over_http() {
    let r = start(cfg());
    let c = client(&r, BITS);
    let q = [9u8; 32];
    let f1 = pad::pad(&[1u8; 40]).unwrap();
    let f2 = pad::pad(&[2u8; 700]).unwrap();
    let s1 = c.send(&q, &f1).unwrap();
    let s2 = c.send(&q, &f2).unwrap();
    assert!(s2 > s1);
    let p = c.poll(&q, 0).unwrap();
    assert_eq!(p.frames.len(), 2);
    assert_eq!(p.frames[0].1, f1);
    assert_eq!(p.frames[1].1, f2);
    let p = c.poll(&q, s1).unwrap();
    assert_eq!(p.frames.len(), 1);
    assert_eq!(p.next, s2);
    assert!(c.poll(&[1; 32], 0).unwrap().frames.is_empty());
}

#[test]
fn weak_pow_is_rejected_over_http() {
    let r = start(Config { pow_bits: 20, ..Config::default() });
    let weak = client(&r, 0);
    let q = [1u8; 32];
    let mut accepted = 0;
    for i in 0..4u8 {
        if weak.send(&q, &pad::pad(&[i; 10]).unwrap()).is_ok() {
            accepted += 1;
        }
    }
    assert!(accepted < 4);
    assert!(weak.poll(&q, 0).unwrap().frames.len() < 4);
}

#[test]
fn garbage_http_does_not_kill_server() {
    let r = start(cfg());
    let cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\x00\x01\x02\xff\xfe".to_vec(),
        b"GET\r\n\r\n".to_vec(),
        b"GET / HTTP/9.9\r\n\r\n".to_vec(),
        b"POST /api/v2/dir/register HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n".to_vec(),
        b"POST /api/v2/dir/register HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort".to_vec(),
        b"POST /api/v2/queue/send?q=zz HTTP/1.1\r\nContent-Length: 2\r\n\r\nzz".to_vec(),
        b"GET /api/v2/queue/poll?q=%ff%fe HTTP/1.1\r\n\r\n".to_vec(),
        vec![b'A'; 100_000],
        format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(40_000)).into_bytes(),
    ];
    for c in &cases {
        let resp = raw(&r, c);
        assert!(resp.is_empty() || resp.starts_with("HTTP/1.1 4"), "{resp}");
    }
    let ok = raw(&r, b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");
    assert!(ok.contains("\"protocol\":2"));
    assert!(raw(&r, b"GET /api/v1/queue/poll HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404"));
    assert!(raw(&r, b"GET /support HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404"));
    client(&r, BITS).health().unwrap();
}

#[test]
fn oversize_body_gets_413() {
    let r = start(cfg());
    let mut req = b"POST /api/v2/queue/send HTTP/1.1\r\nContent-Length: 70000\r\n\r\n".to_vec();
    req.extend(vec![b'a'; 70_000]);
    assert!(raw(&r, &req).starts_with("HTTP/1.1 413"));
}

#[test]
fn many_parallel_clients() {
    let r = start(cfg());
    let addr = r.addr;
    let handles: Vec<_> = (0..8u8)
        .map(|i| {
            std::thread::spawn(move || {
                let c = Client::new(&format!("http://{addr}"), None)
                    .unwrap()
                    .with_pow_bits(BITS);
                let q = [i; 32];
                for n in 0..3u8 {
                    c.send(&q, &pad::pad(&[n; 20]).unwrap()).unwrap();
                }
                assert_eq!(c.poll(&q, 0).unwrap().frames.len(), 3);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
