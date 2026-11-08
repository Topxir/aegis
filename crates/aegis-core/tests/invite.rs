#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Invite links (PROTOCOL.md section 29). The vectors are shared with the Kotlin core.

use aegis_core::envelope::{Envelope, Kind};
use aegis_core::hex;
use aegis_core::identity::Identity;
use aegis_core::invite::{self, Bundle, Hide, InviteCreate, BOX_LEN};

const S: [u8; 32] = [0x11; 32];
const ID: &str = "1a86791297c6f73dc95d866dd901c213c1d10cb112e5d85f4906291ba4ecc030";
const BOX: &str = "764bcc5e512e703c9c11bdf08bf54db1d89b40176a2bb5053ffd460e258f58c3f4fbd42e7c8b77cd41e769c4c26c1ec53c0837ae8de8f02715b051e582ac81b30d35fd352509605c24750e7c7d12fd8fd7d6499634de8499362c76c0ccb878fe4d59d29c77e2c6a0dff0cca56d588f31cf09e7addd0be86ba723a4c59d9ebe9a493937d6a131c518fbe17cabca3db88d471bdab54a8c7436aff76edd953ceaac0d19f106e73666c9943301ac4afd36d5";
const TAG: &str = "04abbf161426f4d264813bc5d84417ec4c1c0f3598b3674605009d84043ea5b8";
const BODY: &str = "04abbf161426f4d264813bc5d84417ec4c1c0f3598b3674605009d84043ea5b87947973b5aa61ee565e1f5e95b363792a58224f7ae2bb265cf68b6e24874fa3b085b80d7078f6c10bbb2c725842c0d3df4972c07313e1399eede224bbd0a8202";

fn alice() -> Identity {
    Identity::from_secrets([1; 32], [2; 32])
}

fn bob() -> Identity {
    Identity::from_secrets([3; 32], [4; 32])
}

fn alice_bundle() -> Bundle {
    Bundle { u: "alice".into(), x: alice().x_public(), ed: alice().ed_public() }
}

#[test]
fn vectors() {
    assert_eq!(hex::encode(&invite::invite_id(&S)), ID);
    let sealed = invite::seal_bundle(&S, &alice_bundle()).unwrap();
    assert_eq!(sealed.len(), BOX_LEN);
    assert_eq!(hex::encode(&sealed), BOX);
    let tag = invite::accept_tag(&S, "bob", &bob().x_public(), &bob().ed_public()).unwrap();
    assert_eq!(hex::encode(&tag), TAG);
    assert_eq!(invite::accept_body(&bob(), &S, "bob").unwrap(), BODY);
}

#[test]
fn bundle_opens_only_with_its_secret() {
    let sealed = hex::decode(BOX).unwrap();
    let b = invite::open_bundle(&S, &sealed).unwrap();
    assert_eq!((b.u.as_str(), b.x, b.ed), ("alice", alice().x_public(), alice().ed_public()));
    assert!(invite::open_bundle(&[0x12; 32], &sealed).is_err());
    let mut bad = sealed.clone();
    bad[5] ^= 1;
    assert!(invite::open_bundle(&S, &bad).is_err());
    assert!(invite::open_bundle(&S, &sealed[..BOX_LEN - 1]).is_err());
    // the longest name still fits the fixed size
    let long = Bundle { u: "a".repeat(24), ..alice_bundle() };
    assert_eq!(invite::seal_bundle(&S, &long).unwrap().len(), BOX_LEN);
}

#[test]
fn links_round_trip_and_reject_junk() {
    let l = invite::link(&S);
    assert_eq!(l, format!("aegis://invite/{}", hex::encode(&S)));
    assert_eq!(*invite::parse_link(&l).unwrap(), S);
    assert_eq!(*invite::parse_link(&format!("  {}\n", l.to_uppercase())).unwrap(), S);
    for bad in ["", "aegis://invite/", "aegis://invite/zz", "https://invite/1111", &l[..l.len() - 1], &format!("{l}0"), &format!("{l}?x")] {
        assert!(invite::parse_link(bad).is_err(), "{bad}");
    }
}

#[test]
fn accept_proves_the_secret_and_the_key() {
    let (x, ed) = (bob().x_public(), bob().ed_public());
    assert!(invite::check_accept(&S, "bob", &x, &ed, BODY));
    // another secret
    assert!(!invite::check_accept(&[0x12; 32], "bob", &x, &ed, BODY));
    // a claimed name or key that is not the signer's
    assert!(!invite::check_accept(&S, "carol", &x, &ed, BODY));
    assert!(!invite::check_accept(&S, "bob", &alice().x_public(), &ed, BODY));
    assert!(!invite::check_accept(&S, "bob", &x, &alice().ed_public(), BODY));
    // someone holding the link but not bob's key cannot speak for bob
    let tag = invite::accept_tag(&S, "bob", &x, &ed).unwrap();
    let forged = format!("{}{}", hex::encode(&tag), hex::encode(&alice().sign(b"anything")));
    assert!(!invite::check_accept(&S, "bob", &x, &ed, &forged));
    assert!(!invite::check_accept(&S, "bob", &x, &ed, &BODY[..64]));
    assert!(!invite::check_accept(&S, "bob", &x, &ed, ""));
}

#[test]
fn iacc_envelope_carries_only_the_proof() {
    let env = Envelope {
        kind: Kind::Iacc,
        msg_id: "00112233445566778899aabbccddeeff".into(),
        sender: "bob".into(),
        sender_name: String::new(),
        sender_ed: bob().ed_public(),
        ts_ms: 1_700_000_000_000,
        ttl_s: 0,
        group_id: String::new(),
        body: BODY.into(),
        group_key: None,
        members: vec![],
    };
    let back = Envelope::decode(&env.encode().unwrap()).unwrap();
    assert_eq!(back.kind, Kind::Iacc);
    assert_eq!(back.body, BODY);
    assert_eq!(Kind::Iacc.frame_type(), 0x01);
    let short = Envelope { body: TAG.into(), ..back.clone() };
    assert!(short.encode().is_err());
    let grouped = Envelope { members: vec!["alice".into()], ..back };
    assert!(grouped.encode().is_err());
}

#[test]
fn signed_forms_round_trip() {
    let c = InviteCreate::sign(&alice(), "alice", &S, 1_700_000_000).unwrap();
    let back = InviteCreate::from_form(&c.to_form()).unwrap();
    assert_eq!(hex::encode(&back.id), ID);
    assert!(back.sig_ok(&alice().ed_public()));
    assert!(!back.sig_ok(&bob().ed_public()));
    assert!(InviteCreate::from_form(&format!("{}&x=1", c.to_form())).is_err());
    let h = Hide::sign(&alice(), "alice", true, 1_700_000_000).unwrap();
    let back = Hide::from_form(&h.to_form()).unwrap();
    assert!(back.hidden && back.sig_ok(&alice().ed_public()));
    assert!(!Hide { hidden: false, ..back }.sig_ok(&alice().ed_public()));
    assert_eq!(invite::parse_id_form(&invite::id_form(&invite::invite_id(&S))).unwrap(), invite::invite_id(&S));
}
