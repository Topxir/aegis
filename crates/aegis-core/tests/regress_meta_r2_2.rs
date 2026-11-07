#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A subscriber who holds the owner's chain key re-encrypts an old signed post
//! at a later chain position. The receiver must ignore it and keep the key for
//! the owner's real post.

use aegis_core::channel::channel_id;
use aegis_core::envelope::{random_msg_id, Envelope, Kind};
use aegis_core::identity::ed25519_public;
use aegis_core::senderkey::{RecvSet, Scope, SendChain};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const G: [u8; 32] = [0x55; 32];
const OWNER_SK: [u8; 32] = [0x66; 32];
const CID: [u8; 16] = [1; 16];
const CK0: [u8; 32] = [2; 32];
const CID2: [u8; 16] = [3; 16];
const CK2: [u8; 32] = [4; 32];

fn hmac1(k: &[u8; 32], b: u8) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k).unwrap();
    m.update(&[b]);
    m.finalize().into_bytes().into()
}

fn key_nonce(mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut o = [0u8; 44];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk).expand(b"aegis-v2 group-key", &mut o).unwrap();
    (o[..32].try_into().unwrap(), o[32..].try_into().unwrap())
}

fn aead(k: &[u8; 32], n: &[u8], aad: &[u8], m: &[u8], enc: bool) -> Vec<u8> {
    let c = ChaCha20Poly1305::new(Key::from_slice(k));
    let p = Payload { msg: m, aad };
    if enc { c.encrypt(Nonce::from_slice(n), p) } else { c.decrypt(Nonce::from_slice(n), p) }.unwrap()
}

fn aad(cid: &[u8; 16], n: u32) -> Vec<u8> {
    [[0x05u8].as_slice(), cid, &n.to_be_bytes()].concat()
}

fn chain_key(ck0: &[u8; 32], n: u32) -> [u8; 32] {
    (0..n).fold(*ck0, |ck, _| hmac1(&ck, 2))
}

fn open_plain(ck0: &[u8; 32], cid: &[u8; 16], n: u32, frame: &[u8]) -> Vec<u8> {
    let (k, nonce) = key_nonce(&hmac1(&chain_key(ck0, n), 1));
    aead(&k, &nonce, &aad(cid, n), &frame[1 + 48..], false)
}

fn forge(ck0: &[u8; 32], cid: &[u8; 16], n: u32, plain: &[u8]) -> Vec<u8> {
    let (k, nonce) = key_nonce(&hmac1(&chain_key(ck0, n), 1));
    let mut hk = [0u8; 32];
    Hkdf::<Sha256>::new(None, &G).expand(b"aegis-v2 group-hdr", &mut hk).unwrap();
    let hnonce = [9u8; 12];
    let hdr = aead(&hk, &hnonce, &[0x05], &aad(cid, n)[1..], true);
    let ct = aead(&k, &nonce, &aad(cid, n), plain, true);
    [[0x05u8].as_slice(), &hnonce, &hdr, &ct].concat()
}

fn post(body: &str) -> Envelope {
    Envelope {
        kind: Kind::Cmsg,
        msg_id: random_msg_id().unwrap(),
        sender: "owner".into(),
        sender_name: "Owner".into(),
        sender_ed: ed25519_public(&OWNER_SK),
        ts_ms: 1,
        ttl_s: 0,
        group_id: channel_id(&G),
        body: body.into(),
        group_key: None,
        members: vec![],
    }
}

#[test]
fn replayed_post_at_next_n_is_ignored_and_real_post_still_decrypts() {
    let owner_ed = ed25519_public(&OWNER_SK);
    let mut owner = SendChain::new_with(CID, CK0, 100);
    let mut victim = RecvSet::new(Scope::Channel, &G, Some(owner_ed)).unwrap();
    victim.add_chain("owner", owner_ed, CID, 0, &CK0, 100).unwrap();

    let f0 = owner.encrypt(Scope::Channel, &G, &OWNER_SK, &post("post 0")).unwrap();
    assert_eq!(victim.decrypt(&f0, 101).unwrap().body, "post 0");

    let forged = forge(&CK0, &CID, 1, &open_plain(&CK0, &CID, 0, &f0));
    let before = victim.encode().unwrap();
    assert!(victim.decrypt(&forged, 102).is_err());
    assert_eq!(*victim.encode().unwrap(), *before, "a replay must not change state");

    let f1 = owner.encrypt(Scope::Channel, &G, &OWNER_SK, &post("post 1")).unwrap();
    assert_eq!(victim.decrypt(&f1, 103).unwrap().body, "post 1");
}

#[test]
fn replayed_post_on_newer_chain_is_ignored() {
    let owner_ed = ed25519_public(&OWNER_SK);
    let mut old = SendChain::new_with(CID, CK0, 100);
    let mut new = SendChain::new_with(CID2, CK2, 200);
    let mut victim = RecvSet::new(Scope::Channel, &G, Some(owner_ed)).unwrap();
    victim.add_chain("owner", owner_ed, CID, 0, &CK0, 100).unwrap();

    let f0 = old.encrypt(Scope::Channel, &G, &OWNER_SK, &post("old post")).unwrap();
    assert_eq!(victim.decrypt(&f0, 101).unwrap().body, "old post");
    victim.add_chain("owner", owner_ed, CID2, 0, &CK2, 200).unwrap();

    let forged = forge(&CK2, &CID2, 0, &open_plain(&CK0, &CID, 0, &f0));
    let before = victim.encode().unwrap();
    assert!(victim.decrypt(&forged, 201).is_err());
    assert_eq!(*victim.encode().unwrap(), *before);

    let f1 = new.encrypt(Scope::Channel, &G, &OWNER_SK, &post("new post")).unwrap();
    assert_eq!(victim.decrypt(&f1, 202).unwrap().body, "new post");
}
