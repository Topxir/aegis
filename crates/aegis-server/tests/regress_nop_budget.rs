#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Cover replies draw on one byte budget for the whole server, refilled every second, so a
//! stream of tiny requests cannot pull unbounded padding out of it.
use aegis_server::{Config, Request, ServerState, NOP_BURST_SECS};

const NOW: u64 = 1_700_000_000;
const RATE: u64 = 64 * 1024;

fn nop(s: &mut ServerState, len: u32, now: u64) -> u16 {
    let mut body = len.to_be_bytes().to_vec();
    body.resize(64, 0);
    let r = Request { method: "POST".into(), path: "/api/v2/nop".into(), query: vec![], body };
    let resp = s.handle(&r, now);
    if resp.status == 200 {
        assert_eq!(resp.body.len(), len as usize);
        assert!(resp.body.bytes().all(|b| b == 0));
    }
    resp.status
}

#[test]
fn nop_replies_stop_at_the_byte_budget() {
    let mut s = ServerState::ephemeral(Config { nop_bytes_per_sec: RATE, ..Config::default() });
    let chunk = 16 * 1024;
    let mut served = 0u64;
    while nop(&mut s, chunk, NOW) == 200 {
        served += u64::from(chunk);
        assert!(served <= RATE * NOP_BURST_SECS, "budget not enforced");
    }
    assert_eq!(served, RATE * NOP_BURST_SECS);
    assert_eq!(nop(&mut s, chunk, NOW), 429);
    // A second later one second's worth is back, and no more.
    for _ in 0..RATE / u64::from(chunk) {
        assert_eq!(nop(&mut s, chunk, NOW + 1), 200);
    }
    assert_eq!(nop(&mut s, chunk, NOW + 1), 429);
    // A long pause refills only up to the burst.
    let mut again = 0u64;
    while nop(&mut s, chunk, NOW + 3600) == 200 {
        again += u64::from(chunk);
        assert!(again <= RATE * NOP_BURST_SECS);
    }
    assert_eq!(again, RATE * NOP_BURST_SECS);
}

#[test]
fn state_source_has_no_raw_nul_byte() {
    // A literal NUL made tools treat the file as binary and hid it from review and diffs.
    assert!(!include_bytes!("../src/state.rs").contains(&0));
}
