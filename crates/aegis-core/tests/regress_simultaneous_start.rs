#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
include!("regress_session_common.inc");
use aegis_core::identity::x25519_public;

#[test]
fn simultaneous_start_diverges_and_black_holes_after_30_days() {
    let (mut a, mut b) = pair();
    let (mut e1, mut e2) = ([0x11u8; 32], [0x22u8; 32]);
    if x25519_public(&e1) > x25519_public(&e2) {
        std::mem::swap(&mut e1, &mut e2);
    }
    let bn_b = bundle_for(&mut b, T0);
    let bn_a = bundle_for(&mut a, T0);
    a.store.start_session_with(&e1, &[0x31; 32], &a.id, "bob", &bn_b, T0).unwrap();
    let fa = send(&mut a, "bob", "a1", T0);
    assert!(recv(&mut b, &fa, T0).envelope.is_some());
    b.store.start_session_with(&e2, &[0x32; 32], &b.id, "alice", &bn_a, T0).unwrap();
    let fb = send(&mut b, "alice", "b1", T0);
    assert!(recv(&mut a, &fb, T0).envelope.is_some());
    let mut t = T0 + 1;
    let mut silent = Vec::new();
    for day in 0..32 {
        t += DAY;
        let m = send(&mut a, "bob", "a", t);
        let r = recv(&mut b, &m, t);
        if r.envelope.is_none() && r.actions.is_empty() {
            silent.push(("a->b", day));
        }
        let m = send(&mut b, "alice", "b", t);
        let r = recv(&mut a, &m, t);
        if r.envelope.is_none() && r.actions.is_empty() {
            silent.push(("b->a", day));
        }
    }
    assert!(silent.is_empty(), "messages dropped silently after the 30-day superseded purge: {silent:?}");
}
