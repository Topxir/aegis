#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Disappearing-message timer: control envelopes and local expiry (spec section 5.2).

use aegis_core::envelope::{expired_since, ttl_allowed, Envelope, Kind, TTL_CHOICES};
use aegis_core::group::group_id;
use aegis_core::identity::x25519_public;
use aegis_core::seal::{open_dm, seal_dm};
use aegis_core::senderkey::{RecvSet, Scope, SendChain};
use aegis_core::Error;

fn ttl_env(ttl_s: u64) -> Envelope {
    Envelope {
        kind: Kind::Ttl,
        msg_id: "00112233445566778899aabbccddeeff".into(),
        sender: "alice".into(),
        sender_name: "Alice".into(),
        sender_ed: [7; 32],
        ts_ms: 1_700_000_000_123,
        ttl_s,
        group_id: String::new(),
        body: String::new(),
        group_key: None,
        members: vec![],
    }
}

#[test]
fn choices_are_fixed() {
    assert_eq!(TTL_CHOICES, [0, 30, 300, 3600, 86_400, 604_800]);
    for t in TTL_CHOICES {
        assert!(ttl_allowed(t));
    }
    for t in [1, 29, 60, 7200, 604_801, u64::MAX] {
        assert!(!ttl_allowed(t), "{t}");
    }
}

#[test]
fn expiry_counts_from_the_base() {
    let base = 1_000_000;
    assert!(!expired_since(base, 0, u64::MAX), "0 keeps");
    assert!(!expired_since(base, 30, base + 29_999));
    assert!(expired_since(base, 30, base + 30_000));
    assert!(!expired_since(base, 300, 0), "clock before the base");
    assert!(!expired_since(u64::MAX - 10, u64::MAX, u64::MAX - 1), "saturates");
    assert!(expired_since(u64::MAX, 1, u64::MAX));
}

#[test]
fn ttl_envelopes_round_trip_and_reject_extra_fields() {
    for t in TTL_CHOICES {
        let e = ttl_env(t);
        assert_eq!(Envelope::decode(&e.encode().unwrap()).unwrap(), e);
    }
    let g = Envelope { kind: Kind::Gttl, group_id: "ab".repeat(32), ..ttl_env(30) };
    assert_eq!(Envelope::decode(&g.encode().unwrap()).unwrap(), g);
    assert!(Envelope { body: "x".into(), ..ttl_env(30) }.encode().is_err());
    assert!(Envelope { group_id: "ab".repeat(32), ..ttl_env(30) }.encode().is_err());
    assert!(Envelope { group_id: String::new(), ..g.clone() }.encode().is_err());
    assert!(Envelope { members: vec!["bob".into()], ..g }.encode().is_err());
    let enc = String::from_utf8(ttl_env(30).encode().unwrap()).unwrap();
    for bad in ["TTL", "ttls", "gtt"] {
        assert!(Envelope::decode(enc.replacen("ttl", bad, 1).as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn ttl_goes_sealed_and_gttl_on_the_group_chain() {
    let r = x25519_public(&[2; 32]);
    let f = seal_dm(&[1; 32], &r, &ttl_env(300)).unwrap();
    assert_eq!(open_dm(&[2; 32], &f).unwrap().envelope.ttl_s, 300);
    let g = [9u8; 32];
    let gttl = Envelope { kind: Kind::Gttl, group_id: group_id(&g), ..ttl_env(86_400) };
    assert_eq!(seal_dm(&[1; 32], &r, &gttl).unwrap_err(), Error::BadFrameType);

    let ed_sk = [3u8; 32];
    let ed = aegis_core::identity::ed25519_public(&ed_sk);
    let gttl = Envelope { sender_ed: ed, ..gttl };
    let mut chain = SendChain::new_with([4; 16], [5; 32], 100);
    let skey = chain.skey_envelope_with("ffeeddccbbaa99887766554433221100".into(), "alice", "Alice", ed, &gttl.group_id, 1);
    let frame = chain.encrypt_with(&[6; 12], Scope::Group, &g, &ed_sk, &gttl).unwrap();
    let mut rs = RecvSet::new(Scope::Group, &g, None).unwrap();
    rs.add_from_skey(&skey, 100).unwrap();
    assert_eq!(rs.decrypt(&frame, 100).unwrap(), gttl);
    let mut ch = SendChain::new_with([4; 16], [5; 32], 100);
    let on_channel = Envelope { kind: Kind::Gttl, ..gttl };
    assert!(ch.encrypt_with(&[6; 12], Scope::Channel, &g, &ed_sk, &on_channel).is_err());
}
