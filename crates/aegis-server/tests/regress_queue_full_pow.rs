#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! "Queue full" is only told for a fresh base proof of work, the same price as any send, so
//! probing a queue for fullness is not free and cannot be repeated with one proof.
use aegis_core::{hex, pow};
use aegis_server::{Config, Request, ServerState};

const NOW: u64 = 1_700_000_000;

fn send(s: &mut ServerState, q: &[u8; 32], ts: u64, nonce: u64, fill: u8) -> u16 {
    let r = Request {
        method: "POST".into(),
        path: "/api/v2/queue/send".into(),
        query: vec![("q".into(), hex::encode(q)), ("ts".into(), ts.to_string()), ("pow".into(), nonce.to_string())],
        body: hex::encode(&vec![fill; 256]).into_bytes(),
    };
    s.handle(&r, NOW).status
}

fn body_hash(fill: u8) -> String {
    pow::body_hash_hex(hex::encode(&vec![fill; 256]).as_bytes())
}

#[test]
fn full_queue_answer_costs_a_fresh_proof_of_work() {
    let bits = 8;
    let mut s = ServerState::ephemeral(Config { pow_bits: bits, max_frames_per_queue: 1, ..Config::default() });
    let q = [9u8; 32];
    let qh = hex::encode(&q);
    let first = pow::mine(&qh, NOW, &body_hash(1), bits + 4);
    assert_eq!(send(&mut s, &q, NOW, first, 1), 200);
    assert_eq!(s.queue_len(&q), 1);

    let bad = (0..).find(|&n| !pow::verify(&qh, NOW + 1, &body_hash(2), n, bits)).unwrap();
    assert_eq!(send(&mut s, &q, NOW + 1, bad, 2), 403, "fullness told for free");

    let good = pow::mine(&qh, NOW + 1, &body_hash(2), bits);
    assert_eq!(send(&mut s, &q, NOW + 1, good, 2), 429);
    assert_eq!(send(&mut s, &q, NOW + 1, good, 2), 403, "one proof bought two answers");
}
