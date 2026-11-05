#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use aegis_core::cover::{max_resp_len, nop_body, CoverRng, Mode, Platform, Scheduler, SeededRng, Tick, MAX_RESP_LEN};

struct Broken(SeededRng);

impl CoverRng for Broken {
    fn unit(&mut self) -> f64 {
        self.0.unit()
    }
    fn below(&mut self, n: u64) -> u64 {
        self.0.below(n)
    }
    fn failed(&mut self) -> bool {
        true
    }
}

#[test]
fn rng_failure_turns_cover_off_for_the_tick() {
    let mut s = Scheduler::new(Platform::Desktop, Mode::Standard, 0, &mut SeededRng(7));
    let mut rng = Broken(SeededRng(1));
    assert_eq!(s.tick(1_000_000, 0, false, &mut rng), Tick::Off);
}

#[test]
fn dummy_can_ask_for_the_largest_real_response_with_any_request() {
    for req in [4usize, 1000, 5000, 60_000] {
        assert_eq!(max_resp_len(req), MAX_RESP_LEN);
    }
    let b = nop_body(1024, u32::MAX).unwrap();
    assert_eq!(u32::from_be_bytes([b[0], b[1], b[2], b[3]]), MAX_RESP_LEN);
}

#[test]
fn compiled_server_key_is_looked_up_by_endpoint() {
    use aegis_core::{pinned_key_for, DEFAULT_SERVER_URL, DEFAULT_SERVER_X_PK};
    assert!(DEFAULT_SERVER_X_PK.is_some());
    assert_eq!(pinned_key_for(DEFAULT_SERVER_URL), DEFAULT_SERVER_X_PK);
    assert_eq!(pinned_key_for("https://FreeOasis.space/"), DEFAULT_SERVER_X_PK);
    assert_eq!(pinned_key_for("https://freeoasis.space:8443"), None);
    assert_eq!(pinned_key_for("https://example.org"), None);
    assert_eq!(pinned_key_for("not a url"), None);
}
