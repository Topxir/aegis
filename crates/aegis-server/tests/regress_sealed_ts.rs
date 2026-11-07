#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Sealed requests carry a timestamp: a recorded request cannot be replayed once the window passed.
use aegis_core::{hex, sealed};
use aegis_server::{Config, ServerState};

const NOW: u64 = 1_700_000_000;

fn e_pk(outer: &[u8]) -> [u8; 32] {
    outer[..32].try_into().unwrap()
}

#[test]
fn recorded_sealed_poll_cannot_be_replayed_later() {
    let mut s = ServerState::ephemeral(Config::default());
    let pk = s.server_public_key().unwrap();
    let sk = s.server_secret_key().unwrap();
    let q = hex::encode(&[9u8; 32]);
    let target = format!("/api/v2/queue/poll?q={q}&after=0");
    let (outer, _) = sealed::seal_request_at(&[7; 32], &pk, "GET", &target, b"", Some(NOW)).unwrap();
    let (inner, _) = sealed::open_request(&sk, &outer).unwrap();
    assert_eq!((inner.method.as_str(), inner.ts), ("GET", Some(NOW)));
    assert!(s.sealed_admit(e_pk(&outer), inner.ts, NOW));
    assert!(!s.sealed_admit(e_pk(&outer), inner.ts, NOW + 60), "immediate replay");
    // Still remembered for as long as the timestamp could pass the window.
    assert!(!s.sealed_admit(e_pk(&outer), inner.ts, NOW + 21 * 60 - 1));
    assert!(!s.sealed_admit(e_pk(&outer), inner.ts, NOW + 21 * 60), "replay after the window");
}

#[test]
fn stale_and_future_timestamps_are_refused() {
    let mut s = ServerState::ephemeral(Config::default());
    assert!(!s.sealed_admit([1; 32], Some(NOW - 601), NOW));
    assert!(!s.sealed_admit([2; 32], Some(NOW + 601), NOW));
    assert!(s.sealed_admit([3; 32], Some(NOW - 600), NOW));
    assert!(s.sealed_admit([4; 32], Some(NOW + 600), NOW));
    // The entry outlives the latest moment its timestamp could still pass.
    assert!(!s.sealed_admit([4; 32], Some(NOW + 600), NOW + 1190));
}

#[test]
fn request_without_timestamp_opens_but_is_not_admitted() {
    let mut s = ServerState::ephemeral(Config::default());
    let pk = s.server_public_key().unwrap();
    let sk = s.server_secret_key().unwrap();
    let (outer, _) = sealed::seal_request_with(&[8; 32], &pk, "POST", "/api/v2/nop", b"x").unwrap();
    let (inner, _) = sealed::open_request(&sk, &outer).unwrap();
    assert_eq!((inner.method.as_str(), inner.ts), ("POST", None));
    assert!(!s.sealed_admit(e_pk(&outer), inner.ts, NOW));
}
