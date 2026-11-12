#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
include!("regress_session_common.inc");

#[test]
fn bundle_older_than_the_prekey_is_kept_is_refused_up_front() {
    let (mut a, mut b) = pair();
    let old = bundle_for(&mut b, T0);
    b.store.prepare_prekeys(&b.id, "bob", T0 + 7 * DAY, Some(50)).unwrap();
    assert!(a.store.start_session(&a.id, "bob", &old, T0 + 22 * DAY).is_err());
    a.store.start_session(&a.id, "bob", &old, T0 + 20 * DAY).unwrap();
    let f = send(&mut a, "bob", "hi", T0 + 20 * DAY);
    assert!(recv(&mut b, &f, T0 + 20 * DAY).envelope.is_some());
}
