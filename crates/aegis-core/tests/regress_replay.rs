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

fn no_recovery(actions: &[Action]) -> bool {
    !actions.iter().any(|x| matches!(x, Action::StartNewSession { .. } | Action::UndecryptableNotice { .. }))
}

fn can_send(b: &mut Side, now: u64) -> bool {
    matches!(b.store.encrypt(&b.id, "alice", &env_from(b, "x"), now).unwrap(), Encrypted::Frame(_))
}

#[test]
fn replayed_start_frames_are_ignored_after_seen_set_rolls_over() {
    let (mut a, mut b) = pair();
    let bn = bundle_for(&mut b, T0);
    a.store.start_session(&a.id, "bob", &bn, T0).unwrap();
    let frames: Vec<Vec<u8>> = (0..1100).map(|i| send(&mut a, "bob", &format!("m{i}"), T0)).collect();
    for f in &frames {
        assert!(recv(&mut b, f, T0).envelope.is_some());
    }
    let mut actions = Vec::new();
    for f in frames[..3].iter().chain([&frames[0], &frames[0]]) {
        let r = recv(&mut b, f, T0 + 10);
        assert!(r.envelope.is_none());
        actions.extend(r.actions);
    }
    assert!(no_recovery(&actions), "{actions:?}");
    assert!(can_send(&mut b, T0 + 10));
    assert!(recv(&mut b, &send(&mut a, "bob", "live", T0 + 11), T0 + 11).envelope.is_some());
}

#[test]
fn replayed_frames_from_past_chains_are_ignored() {
    let (mut a, mut b) = pair();
    let bn = bundle_for(&mut b, T0);
    a.store.start_session(&a.id, "bob", &bn, T0).unwrap();
    let f0 = send(&mut a, "bob", "hello", T0);
    assert!(recv(&mut b, &f0, T0).envelope.is_some());
    assert!(recv(&mut a, &send(&mut b, "alice", "reply", T0), T0).envelope.is_some());
    let mut old = vec![f0];
    for round in 0..3 {
        for i in 0..2 {
            let f = send(&mut a, "bob", &format!("r{round}-{i}"), T0);
            assert!(recv(&mut b, &f, T0).envelope.is_some());
            old.push(f);
        }
        assert!(recv(&mut a, &send(&mut b, "alice", "ack", T0), T0).envelope.is_some());
    }
    for i in 0..1100 {
        assert!(recv(&mut b, &send(&mut a, "bob", &format!("m{i}"), T0), T0).envelope.is_some());
    }
    let mut actions = Vec::new();
    for _ in 0..5 {
        for f in &old {
            let r = recv(&mut b, f, T0 + 10);
            assert!(r.envelope.is_none());
            actions.extend(r.actions);
        }
    }
    assert!(no_recovery(&actions), "{actions:?}");
    assert!(can_send(&mut b, T0 + 10));
    assert!(recv(&mut b, &send(&mut a, "bob", "live", T0 + 11), T0 + 11).envelope.is_some());
}

#[test]
fn out_of_order_frames_still_decrypt() {
    let (mut a, mut b) = pair();
    let bn = bundle_for(&mut b, T0);
    a.store.start_session(&a.id, "bob", &bn, T0).unwrap();
    let f: Vec<Vec<u8>> = (0..4).map(|i| send(&mut a, "bob", &format!("m{i}"), T0)).collect();
    assert!(recv(&mut b, &f[0], T0).envelope.is_some());
    assert!(recv(&mut b, &f[3], T0).envelope.is_some());
    assert!(recv(&mut b, &f[2], T0).envelope.is_some());
    assert!(recv(&mut b, &f[1], T0).envelope.is_some());
}

#[test]
fn v1_session_state_still_decodes() {
    let mut st = SessionStore::new();
    st.add_contact("alice", [1; 32], [2; 32]).unwrap();
    let v2 = st.encode().unwrap();
    assert_eq!(&v2[..4], b"AGS2");
    let n = v2.len();
    assert_eq!(&v2[n - 5..], &[0, 0, 0, 0, 0]);
    let v1 = [b"AGS1".as_slice(), &v2[4..n - 5], &v2[n - 1..]].concat();
    let back = SessionStore::decode(&v1).unwrap();
    assert_eq!(*back.encode().unwrap(), *v2);
}
