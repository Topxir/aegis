#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
include!("regress_session_common.inc");
use aegis_core::session::Action;

#[test]
fn server_replay_of_old_frames_triggers_recovery() {
    let (mut a, mut b) = pair();
    let bn = bundle_for(&mut b, T0);
    a.store.start_session(&a.id, "bob", &bn, T0).unwrap();
    let frames: Vec<Vec<u8>> = (0..260).map(|i| send(&mut a, "bob", &format!("m{i}"), T0)).collect();
    for f in &frames {
        assert!(recv(&mut b, f, T0).envelope.is_some());
    }
    assert!(matches!(b.store.encrypt(&b.id, "alice", &env_from(&b, "ok"), T0).unwrap(), Encrypted::Frame(_)));
    // The server replays three stored frames that fell out of the 256-entry seen set.
    let mut actions = Vec::new();
    for f in &frames[..3] {
        actions.extend(recv(&mut b, f, T0 + 10).actions);
    }
    let blocked =
        matches!(b.store.encrypt(&b.id, "alice", &env_from(&b, "x"), T0 + 10).unwrap(), Encrypted::NeedsPrekeys);
    eprintln!("actions after 3 replays: {actions:?}; bob can no longer send: {blocked}");
    assert!(
        !actions.iter().any(|x| matches!(x, Action::StartNewSession { .. } | Action::UndecryptableNotice { .. })),
        "replayed frames must not count as decryption failures"
    );
    assert!(!blocked);
}
