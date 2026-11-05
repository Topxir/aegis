#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A full queue says so before asking for more proof of work.
//! "queue full", so the sender burns 2^(base+4) work for a request that cannot succeed.
use aegis_core::{hex, pow};
use aegis_server::{Config, Request, ServerState};

const NOW: u64 = 1_700_000_000;

fn send(s: &mut ServerState, q: &[u8; 32], ts: u64, bits: u32, fill: u8) -> (u16, serde_json::Value) {
    let body = hex::encode(&vec![fill; 256]);
    let qh = hex::encode(q);
    let n = pow::mine(&qh, ts, &pow::body_hash_hex(body.as_bytes()), bits);
    let r = Request {
        method: "POST".into(),
        path: "/api/v2/queue/send".into(),
        query: vec![("q".into(), qh), ("ts".into(), ts.to_string()), ("pow".into(), n.to_string())],
        body: body.into_bytes(),
    };
    let resp = s.handle(&r, NOW);
    (resp.status, serde_json::from_str(&resp.body).unwrap())
}

#[test]
fn full_queue_says_full_without_asking_for_more_work() {
    let base = 4;
    let mut s = ServerState::ephemeral(Config { pow_bits: base, max_frames_per_queue: 8, ..Config::default() });
    let q = [7u8; 32];
    for i in 0..8u8 {
        let mut bits = base;
        loop {
            let (st, v) = send(&mut s, &q, NOW + u64::from(i), bits, i);
            if st == 200 { break; }
            bits = u32::try_from(v["bits"].as_u64().unwrap()).unwrap();
        }
    }
    assert_eq!(s.queue_len(&q), 8);
    let (st, v) = send(&mut s, &q, NOW + 100, base, 99);
    assert_eq!(st, 429);
    assert!(v.get("bits").is_none(), "full queue demanded more work ({v}) before saying it is full");
}
