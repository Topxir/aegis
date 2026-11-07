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
    let enc = rs.encode().unwrap();
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

fn chain_bytes(chain_id: [u8; 16], sender: &str, ed: [u8; 32], ck: [u8; 32], v2: bool) -> Vec<u8> {
    let mut b = chain_id.to_vec();
    b.push(u8::try_from(sender.len()).unwrap());
    b.extend_from_slice(sender.as_bytes());
    b.extend_from_slice(&ed);
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&ck);
    b.push(0);
    b.extend_from_slice(&0u16.to_be_bytes());
    if v2 {
        b.extend_from_slice(&0u16.to_be_bytes());
    }
    b
}

fn set_bytes(magic: &[u8; 4], channel: bool, g: &[u8; 32], owner: Option<[u8; 32]>, count: u16, chains: &[u8]) -> Vec<u8> {
    let mut b = magic.to_vec();
    b.push(u8::from(channel));
    b.extend_from_slice(g);
    match owner {
        Some(o) => {
            b.push(1);
            b.extend_from_slice(&o);
        }
        None => b.push(0),
    }
    b.extend_from_slice(&count.to_be_bytes());
    b.extend_from_slice(chains);
    b
}

#[test]
fn group_set_refuses_an_owner_key() {
    let g = [0x42u8; 32];
    let owner = ed25519_public(&[0x10; 32]);
    assert!(RecvSet::new(Scope::Group, &g, Some(owner)).is_err());
    let chain = chain_bytes([1; 16], "alice", owner, [2; 32], true);
    assert!(RecvSet::decode(&set_bytes(b"AGK2", false, &g, Some(owner), 1, &chain)).is_err());
    assert!(RecvSet::decode(&set_bytes(b"AGK2", false, &g, None, 1, &chain)).is_ok());
}

#[test]
fn decode_caps_total_chains() {
    let g = [0x42u8; 32];
    let mut chains = Vec::new();
    for i in 0..1001u32 {
        let mut sk = [0x33u8; 32];
        sk[..4].copy_from_slice(&(i / 8).to_be_bytes());
        let ed = ed25519_public(&sk);
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&i.to_be_bytes());
        chains.push(chain_bytes(id, "m", ed, [9; 32], true));
    }
    let ok: Vec<u8> = chains[..1000].concat();
    assert_eq!(RecvSet::decode(&set_bytes(b"AGK2", false, &g, None, 1000, &ok)).unwrap().chain_count(), 1000);
    let over: Vec<u8> = chains.concat();
    assert!(RecvSet::decode(&set_bytes(b"AGK2", false, &g, None, 1001, &over)).is_err());
    assert!(RecvSet::decode(&set_bytes(b"AGK2", false, &g, None, u16::MAX, &[])).is_err());
}

#[test]
fn v1_state_still_decodes() {
    let g = [0x42u8; 32];
    let ed = ed25519_public(&[0x10; 32]);
    let v1 = set_bytes(b"AGK1", false, &g, None, 1, &chain_bytes([1; 16], "alice", ed, [2; 32], false));
    let rs = RecvSet::decode(&v1).unwrap();
    assert_eq!(rs.chain_count(), 1);
    let v2 = set_bytes(b"AGK2", false, &g, None, 1, &chain_bytes([1; 16], "alice", ed, [2; 32], true));
    assert_eq!(*rs.encode().unwrap(), *v2);
}
