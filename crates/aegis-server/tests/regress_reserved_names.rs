#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use aegis_core::directory::Registration;
use aegis_core::identity::Identity;
use aegis_server::{Config, Request, ServerState};

const NOW: u64 = 1_700_000_000;

#[test]
fn lookalike_staff_names_are_reserved() {
    let mut s = ServerState::ephemeral(Config { pow_bits: 4, ..Config::default() });
    let mut accepted = Vec::new();
    for (i, u) in ["adrnin", "ovvner", "ae9is", "aegis_support", "official_aegis"].iter().enumerate() {
        let id = Identity::from_secrets([i as u8 + 1; 32], [i as u8 + 50; 32]);
        let mut r = Registration::sign(&id, u, "Aegis Support", NOW).unwrap();
        r.mine(4);
        let resp = s.handle(&Request { method: "POST".into(), path: "/api/v2/dir/register".into(), query: vec![], body: r.to_form().into_bytes() }, NOW);
        if resp.status == 200 {
            accepted.push(*u);
        }
    }
    assert!(accepted.is_empty(), "look-alike staff names registered without the owner key: {accepted:?}");
}

#[test]
fn ordinary_names_still_register() {
    let mut s = ServerState::ephemeral(Config { pow_bits: 4, ..Config::default() });
    for (i, u) in ["bob_smith", "maria_92", "carl", "vivian"].iter().enumerate() {
        let id = Identity::from_secrets([i as u8 + 1; 32], [i as u8 + 50; 32]);
        let mut r = Registration::sign(&id, u, "", NOW).unwrap();
        r.mine(4);
        let resp = s.handle(&Request { method: "POST".into(), path: "/api/v2/dir/register".into(), query: vec![], body: r.to_form().into_bytes() }, NOW);
        assert_eq!(resp.status, 200, "{u}");
    }
}

#[test]
fn bound_name_survives_a_new_reserved_rule() {
    let dir = std::env::temp_dir().join(format!("aegis-reserved-bound-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let id = Identity::from_secrets([7; 32], [8; 32]);
    let register = |s: &mut ServerState, ts: u64| {
        let mut r = Registration::sign(&id, "badminton", "", ts).unwrap();
        r.mine(4);
        s.handle(&Request { method: "POST".into(), path: "/api/v2/dir/register".into(), query: vec![], body: r.to_form().into_bytes() }, ts).status
    };
    {
        // Bound while the name was allowed for this key.
        let mut s = ServerState::open_with(&dir, Config { pow_bits: 4, owner_ed_pk: Some(id.ed_public()), ..Config::default() }).unwrap();
        assert_eq!(register(&mut s, NOW), 200);
        let s = std::sync::Mutex::new(s);
        aegis_server::persist_now(&s).unwrap();
    }
    let mut s = ServerState::open_with(&dir, Config { pow_bits: 4, ..Config::default() }).unwrap();
    assert_eq!(register(&mut s, NOW + 1), 200, "the bound owner of a now-reserved name must be able to update it");
    let other = Identity::from_secrets([9; 32], [10; 32]);
    let mut r = Registration::sign(&other, "badminton", "", NOW + 2).unwrap();
    r.mine(4);
    let resp = s.handle(&Request { method: "POST".into(), path: "/api/v2/dir/register".into(), query: vec![], body: r.to_form().into_bytes() }, NOW + 2);
    assert_eq!(resp.status, 409);
    let _ = std::fs::remove_dir_all(&dir);
}
