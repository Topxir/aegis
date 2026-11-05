#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Sender-key receive sets: chain ownership and strict state decoding.
use aegis_core::envelope::{random_msg_id, Envelope, Kind};
use aegis_core::group::new_group_secret;
use aegis_core::identity::ed25519_public;
use aegis_core::senderkey::{RecvSet, Scope, SendChain};

fn post(g: &[u8; 32], sk: &[u8; 32], name: &str, body: &str, chain: &mut SendChain, scope: Scope, kind: Kind) -> Vec<u8> {
    let env = Envelope {
        kind,
        msg_id: random_msg_id().unwrap(),
        sender: name.into(),
        sender_name: name.into(),
        sender_ed: ed25519_public(sk),
        ts_ms: 1,
        ttl_s: 0,
        group_id: scope_id(scope, g),
        body: body.into(),
        group_key: None,
        members: vec![],
    };
    chain.encrypt(scope, g, sk, &env).unwrap()
}

fn scope_id(scope: Scope, g: &[u8; 32]) -> String {
    match scope {
        Scope::Group => aegis_core::group::group_id(g),
        Scope::Channel => aegis_core::channel::channel_id(g),
    }
}

#[test]
fn decode_enforces_channel_owner() {
    let g = [0x42u8; 32];
    let owner_ed = ed25519_public(&[0x10; 32]);
    let mallory_ed = ed25519_public(&[0x20; 32]);
    let (chain_id, ck) = ([0xAAu8; 16], [0xBBu8; 32]);
    let mut live = RecvSet::new(Scope::Channel, &g, Some(owner_ed)).unwrap();
    assert!(live.add_chain("mallory", mallory_ed, chain_id, 0, &ck, 1).is_err());
    let mut b = b"AGK1".to_vec();
    b.push(1);
    b.extend_from_slice(&g);
    b.push(1);
    b.extend_from_slice(&owner_ed);
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&chain_id);
    b.push(7);
    b.extend_from_slice(b"mallory");
    b.extend_from_slice(&mallory_ed);
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&ck);
    b.push(0);
    b.extend_from_slice(&0u16.to_be_bytes());
    assert!(RecvSet::decode(&b).is_err());
}

#[test]
fn decode_rejects_duplicate_chains() {
    let g = *new_group_secret().unwrap();
    let mut rs = RecvSet::new(Scope::Group, &g, None).unwrap();
    rs.add_chain("a", [1; 32], [1; 16], 0, &[9; 32], 1).unwrap();
    let enc = rs.encode();
    assert!(RecvSet::decode(&enc).is_ok());
    // The same chain twice.
    let mut dup = enc.to_vec();
    let body = dup[4 + 1 + 32 + 1 + 2..].to_vec();
    dup.extend_from_slice(&body);
    dup[4 + 1 + 32 + 1 + 1] = 2;
    assert!(RecvSet::decode(&dup).is_err());
}

#[test]
fn squatted_chain_id_does_not_block_the_real_sender() {
    let g = *new_group_secret().unwrap();
    let (alice_sk, mallory_sk) = ([0x0A; 32], [0x0B; 32]);
    let mut alice = SendChain::new_with([0xA1; 16], [0x02; 32], 1);
    let mut rs = RecvSet::new(Scope::Group, &g, None).unwrap();
    rs.add_chain("mallory", ed25519_public(&mallory_sk), [0xA1; 16], 0, &[0x01; 32], 10).unwrap();
    rs.add_chain("alice", ed25519_public(&alice_sk), [0xA1; 16], 0, &[0x02; 32], 11).unwrap();
    assert_eq!(rs.chain_count(), 2);
    let frame = post(&g, &alice_sk, "alice", "hi", &mut alice, Scope::Group, Kind::Gmsg);
    assert_eq!(rs.decrypt(&frame, 12).unwrap().body, "hi");
    // Re-distribution of an already known chain stays idempotent.
    rs.add_chain("alice", ed25519_public(&alice_sk), [0xA1; 16], 0, &[0x02; 32], 13).unwrap();
    assert!(rs.add_chain("eve", ed25519_public(&alice_sk), [0xA1; 16], 0, &[0x02; 32], 13).is_err());
}
