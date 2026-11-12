#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Cover traffic scheduling: burst pacing and dummy body size.
use aegis_core::cover::{nop_body, Mode, Platform, Scheduler, SeededRng, Slot, Tick};

const SERVER_MAX_BODY: usize = 64 * 1024;

#[test]
fn burst_after_early_slot_runs_at_minimum_gap() {
    for seed in 0..50u64 {
        let mut r = SeededRng(seed);
        let mut s = Scheduler::new(Platform::Desktop, Mode::Standard, 0, &mut r);
        let g = s.next_slot_ms().unwrap();
        if g <= 4000 {
            continue;
        }
        s.early_slot(0); // user sends an attachment: 3 requests queued
        s.queue_grew(0, 3);
        assert_eq!(s.tick(0, 3, false, &mut r), Tick::Slot(aegis_core::cover::Slot::Real));
        let next = s.next_slot_ms().unwrap();
        assert!(next <= 2000, "seed {seed}: 2 requests still queued but next slot at {next} ms (regular slot was {g})");
    }
}

#[test]
fn dummy_never_exceeds_server_body_limit() {
    let mut r = SeededRng(7);
    let mut s = Scheduler::new(Platform::Desktop, Mode::Standard, 0, &mut r);
    // smallest blob put body: 65536 padded bytes + 16-byte tag
    s.record_request(65_536 + 16);
    let t = s.next_slot_ms().unwrap();
    let Tick::Slot(Slot::Dummy { req_len, resp_len }) = s.tick(t, 0, false, &mut r) else { panic!("no dummy") };
    let body = nop_body(req_len, resp_len).unwrap();
    assert!(body.len() <= SERVER_MAX_BODY, "dummy body {} bytes, server rejects with 413", body.len());
}
