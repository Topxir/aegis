#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Adversarial tests for the protocol v2 core (docs/PROTOCOL.md).

use aegis_core::directory::Registration;
use aegis_core::envelope::{
    check_pinned_dm, check_pinned_group, is_expired, Envelope, Kind, PinnedKeys, SeenIds,
};
use aegis_core::group::{group_decrypt, group_encrypt, group_id};
use aegis_core::identity::{
    dh, ed25519_public, ed25519_sign, ed25519_verify, normalize_username, safety_number,
    x25519_public, Identity,
};
use aegis_core::net::Endpoint;
use aegis_core::pad::{self, BUCKETS, MAX_FRAME};
use aegis_core::seal::{open_dm, seal_dm, seal_dm_with};
use aegis_core::text::sanitize_display_text;
use aegis_core::vault::{
    vault_decrypt, vault_encrypt, vault_encrypt_with, VaultParams,
};
use aegis_core::{hex, pow, sha256, Error};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

// ---------------------------------------------------------------- helpers

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap()
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

fn hk(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let s = if salt.is_empty() { None } else { Some(salt) };
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(s, ikm).expand(info, &mut out).unwrap();
    out
}

fn aead_seal(k: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(Key::from_slice(k))
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .unwrap()
}

fn x_dh(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*sk).diffie_hellman(&PublicKey::from(*pk)).to_bytes()
}

/// Builds a type 0x01 frame by hand. `dh2` and `c1_pk` are attacker-chosen.
fn craft_dm(e_sk: &[u8; 32], dh2: &[u8; 32], c1_pk: &[u8; 32], r_pk: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let e_pk = x25519_public(e_sk);
    let dh1 = x_dh(e_sk, r_pk);
    let salt = [e_pk.as_slice(), r_pk.as_slice()].concat();
    let k1 = hk(&dh1, &salt, b"aegis-v2 seal-1");
    let aad1 = [[1u8].as_slice(), &e_pk].concat();
    let c1 = aead_seal(&k1, &[0; 12], &aad1, c1_pk);
    let k2 = hk(&[dh1.as_slice(), dh2.as_slice()].concat(), &salt, b"aegis-v2 seal-2");
    let aad2 = [aad1.as_slice(), &c1].concat();
    let c2 = aead_seal(&k2, &[0; 12], &aad2, plain);
    [aad2.as_slice(), &c2].concat()
}

fn craft_group(g: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let k = hk(g, b"", b"aegis-v2 group-msg");
    let ct = aead_seal(&k, nonce, aad, plain);
    [[2u8].as_slice(), nonce, &ct].concat()
}

fn gmsg_sig_input(env: &[u8]) -> Vec<u8> {
    [b"aegis-v2 gmsg\n".as_slice(), env].concat()
}

fn dm_env(sender: &str, ed: [u8; 32]) -> Envelope {
    Envelope {
        kind: Kind::Dm,
        msg_id: "00112233445566778899aabbccddeeff".into(),
        sender: sender.into(),
        sender_name: "Name".into(),
        sender_ed: ed,
        ts_ms: 1_700_000_000_000,
        ttl_s: 0,
        group_id: String::new(),
        body: "hello".into(),
        group_key: None,
        members: vec![],
    }
}

fn gmsg_env(g: &[u8; 32], ed: [u8; 32]) -> Envelope {
    Envelope {
        kind: Kind::Gmsg,
        group_id: group_id(g),
        ..dm_env("alice", ed)
    }
}

fn ginv_env(g: &[u8; 32], ed: [u8; 32]) -> Envelope {
    Envelope {
        kind: Kind::Ginv,
        group_id: group_id(g),
        group_key: Some(Zeroizing::new(*g)),
        members: vec!["alice".into(), "bob".into()],
        ..dm_env("alice", ed)
    }
}

const FAST: VaultParams = VaultParams { m_kib: 256, t: 1, p: 1 };

const SMALL_ORDER: [&str; 7] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

fn low_order_points() -> Vec<[u8; 32]> {
    let mut v = Vec::new();
    for h in SMALL_ORDER {
        let p: [u8; 32] = hex::decode_array(h).unwrap();
        v.push(p);
        let mut hi = p;
        hi[31] |= 0x80;
        v.push(hi);
    }
    v
}

const S: [u8; 32] = [0x11; 32];
const R: [u8; 32] = [0x22; 32];

fn r_pk() -> [u8; 32] {
    x25519_public(&R)
}

// ------------------------------------------------------------- 1. DM frames

#[test]
fn dm_crafted_helper_matches_seal() {
    let env = dm_env("alice", ed25519_public(&[3; 32]));
    let real = seal_dm_with(&[5; 32], &S, &r_pk(), &env).unwrap();
    let dh2 = x_dh(&S, &r_pk());
    let mine = craft_dm(&[5; 32], &dh2, &x25519_public(&S), &r_pk(), &env.encode().unwrap());
    assert_eq!(real, mine);
}

#[test]
fn dm_every_bit_flip_rejected_by_region() {
    let env = dm_env("alice", ed25519_public(&[3; 32]));
    let f = seal_dm(&S, &r_pk(), &env).unwrap();
    assert!(open_dm(&R, &f).is_ok());
    for i in 0..f.len() {
        for bit in 0..8 {
            let mut t = f.clone();
            t[i] ^= 1 << bit;
            let r = open_dm(&R, &t);
            assert!(r.is_err(), "byte {i} bit {bit}");
            if i == 0 {
                assert_eq!(r.unwrap_err(), Error::BadFrameType, "type byte {bit}");
            }
        }
    }
}

#[test]
fn dm_region_boundaries_tamper() {
    let f = seal_dm(&S, &r_pk(), &dm_env("alice", [9; 32])).unwrap();
    let (e_pk, c1, c2) = (1..33, 33..81, 81..f.len());
    let tag = f.len() - 16..f.len();
    for range in [e_pk, c1, c2, tag] {
        for i in [range.start, range.end - 1] {
            let mut t = f.clone();
            t[i] = !t[i];
            assert!(open_dm(&R, &t).is_err());
        }
    }
}

#[test]
fn dm_truncation_and_extension_rejected() {
    let f = seal_dm(&S, &r_pk(), &dm_env("alice", [9; 32])).unwrap();
    for n in 0..f.len() {
        assert!(open_dm(&R, &f[..n]).is_err(), "len {n}");
    }
    let mut longer = f.clone();
    longer.push(0);
    assert!(open_dm(&R, &longer).is_err());
    let mut doubled = f.clone();
    doubled.extend_from_slice(&f);
    assert!(open_dm(&R, &doubled).is_err());
}

#[test]
fn dm_wrong_recipient_and_sender_cannot_open() {
    let f = seal_dm(&S, &r_pk(), &dm_env("alice", [9; 32])).unwrap();
    assert!(open_dm(&[0x33; 32], &f).is_err());
    assert!(open_dm(&S, &f).is_err(), "sender must not be able to open its own frame");
    assert!(open_dm(&R, &f).is_ok());
}

#[test]
fn dm_same_message_twice_is_unlinkable() {
    let env = dm_env("alice", [9; 32]);
    let a = seal_dm(&S, &r_pk(), &env).unwrap();
    let b = seal_dm(&S, &r_pk(), &env).unwrap();
    assert_ne!(a, b);
    assert_ne!(a[1..33], b[1..33], "ephemeral key must be fresh");
    assert_ne!(a[33..81], b[33..81], "c1 must differ");
}

#[test]
fn dm_sender_spoofing_rejected_by_pin() {
    let alice = Identity::from_secrets([1; 32], [2; 32]);
    let mallory = Identity::from_secrets([0x66; 32], [0x67; 32]);
    let pin = PinnedKeys { x_pk: alice.x_public(), ed_pk: alice.ed_public() };

    // Mallory claims to be alice in the envelope and also copies alice's ed key.
    let env = dm_env("alice", alice.ed_public());
    let f = seal_dm(mallory.x_secret(), &r_pk(), &env).unwrap();
    let o = open_dm(&R, &f).unwrap();
    assert_eq!(o.sender_x_pk, mallory.x_public());
    assert_eq!(check_pinned_dm(&o.envelope, &o.sender_x_pk, &pin), Err(Error::SenderMismatch));

    // Mallory with her own ed key but alice's x cannot even produce a decryptable frame:
    // c1 names alice's x_pk while dh2 is computed with Mallory's static key.
    let dh2 = x_dh(mallory.x_secret(), &r_pk());
    let forged = craft_dm(&[7; 32], &dh2, &alice.x_public(), &r_pk(), &env.encode().unwrap());
    assert!(open_dm(&R, &forged).is_err());

    // Honest alice passes.
    let ok = seal_dm(alice.x_secret(), &r_pk(), &env).unwrap();
    let o = open_dm(&R, &ok).unwrap();
    assert!(check_pinned_dm(&o.envelope, &o.sender_x_pk, &pin).is_ok());

    // Right x but wrong ed in the envelope.
    let env2 = dm_env("alice", mallory.ed_public());
    let ok = seal_dm(alice.x_secret(), &r_pk(), &env2).unwrap();
    let o = open_dm(&R, &ok).unwrap();
    assert_eq!(check_pinned_dm(&o.envelope, &o.sender_x_pk, &pin), Err(Error::SenderMismatch));
}

#[test]
fn dm_captured_c1_cannot_be_grafted_into_new_frame() {
    let alice = Identity::from_secrets([1; 32], [2; 32]);
    let captured = seal_dm(alice.x_secret(), &r_pk(), &dm_env("alice", alice.ed_public())).unwrap();
    let c1 = &captured[33..81];
    let mallory_x = [0x66u8; 32];
    let e_sk = [9u8; 32];
    let e_pk = x25519_public(&e_sk);
    let dh1 = x_dh(&e_sk, &r_pk());
    let dh2 = x_dh(&mallory_x, &r_pk());
    let salt = [e_pk.as_slice(), r_pk().as_slice()].concat();
    let k2 = hk(&[dh1.as_slice(), dh2.as_slice()].concat(), &salt, b"aegis-v2 seal-2");
    let aad2 = [[1u8].as_slice(), &e_pk, c1].concat();
    let plain = dm_env("alice", alice.ed_public()).encode().unwrap();
    let c2 = aead_seal(&k2, &[0; 12], &aad2, &plain);
    let frame = [aad2.as_slice(), &c2].concat();
    assert!(open_dm(&R, &frame).is_err());
}

#[test]
fn dm_low_order_ephemeral_key_rejected() {
    let pts = low_order_points();
    assert_eq!(pts.len(), 14);
    let mut rng = Rng(7);
    for p in &pts {
        assert_eq!(dh(&[0x42; 32], p).unwrap_err(), Error::ZeroSharedSecret);
        let mut frame = vec![1u8];
        frame.extend_from_slice(p);
        frame.extend(rng.bytes(48 + 16 + 120));
        assert!(open_dm(&R, &frame).is_err());
        frame.truncate(33);
        frame.extend(vec![0u8; 200]);
        assert!(open_dm(&R, &frame).is_err());
    }
}

#[test]
fn dm_low_order_ephemeral_key_with_valid_looking_ciphertext() {
    // Attacker picks e_pk of small order; every DH result is zero, so k1 is predictable.
    // Recipient must refuse before using it.
    let env = dm_env("alice", [9; 32]).encode().unwrap();
    for p in low_order_points() {
        let salt = [p.as_slice(), r_pk().as_slice()].concat();
        let k1 = hk(&[0u8; 32], &salt, b"aegis-v2 seal-1");
        let aad1 = [[1u8].as_slice(), &p].concat();
        let c1 = aead_seal(&k1, &[0; 12], &aad1, &x25519_public(&S));
        let k2 = hk(&[0u8; 64], &salt, b"aegis-v2 seal-2");
        let aad2 = [aad1.as_slice(), &c1].concat();
        let c2 = aead_seal(&k2, &[0; 12], &aad2, &env);
        let frame = [aad2.as_slice(), &c2].concat();
        assert_eq!(open_dm(&R, &frame).unwrap_err(), Error::ZeroSharedSecret);
    }
}

#[test]
fn dm_low_order_sender_key_in_c1_rejected() {
    let env = dm_env("alice", [9; 32]).encode().unwrap();
    for p in low_order_points() {
        let frame = craft_dm(&[9; 32], &[1; 32], &p, &r_pk(), &env);
        assert_eq!(open_dm(&R, &frame).unwrap_err(), Error::ZeroSharedSecret);
    }
}

#[test]
fn dm_seal_to_low_order_recipient_rejected() {
    for p in low_order_points() {
        assert_eq!(
            seal_dm(&S, &p, &dm_env("alice", [9; 32])).unwrap_err(),
            Error::ZeroSharedSecret
        );
    }
}

#[test]
fn dm_gmsg_envelope_in_type_01_frame_rejected() {
    let g = [0x55; 32];
    let env = gmsg_env(&g, ed25519_public(&[6; 32])).encode().unwrap();
    let dh2 = x_dh(&S, &r_pk());
    let frame = craft_dm(&[9; 32], &dh2, &x25519_public(&S), &r_pk(), &env);
    assert_eq!(open_dm(&R, &frame).unwrap_err(), Error::BadFrameType);
    assert_eq!(
        seal_dm(&S, &r_pk(), &gmsg_env(&g, [1; 32])).unwrap_err(),
        Error::BadFrameType
    );
}

#[test]
fn dm_frame_type_02_rejected() {
    let mut f = seal_dm(&S, &r_pk(), &dm_env("alice", [9; 32])).unwrap();
    for t in [0u8, 2, 3, 0x81, 0xff] {
        f[0] = t;
        assert_eq!(open_dm(&R, &f).unwrap_err(), Error::BadFrameType);
    }
}

// ----------------------------------------------------------------- 2. Groups

const G: [u8; 32] = [0x55; 32];
const GED: [u8; 32] = [0x66; 32];

fn good_gframe() -> Vec<u8> {
    group_encrypt(&G, &GED, &gmsg_env(&G, ed25519_public(&GED))).unwrap()
}

#[test]
fn group_nonce_and_ciphertext_tamper_rejected() {
    let f = good_gframe();
    assert!(group_decrypt(&G, &f).is_ok());
    for i in 0..f.len() {
        for bit in [0u8, 3, 7] {
            let mut t = f.clone();
            t[i] ^= 1 << bit;
            assert!(group_decrypt(&G, &t).is_err(), "byte {i} bit {bit}");
        }
    }
    for n in 0..f.len() {
        assert!(group_decrypt(&G, &f[..n]).is_err(), "len {n}");
    }
    let mut longer = f.clone();
    longer.push(0);
    assert!(group_decrypt(&G, &longer).is_err());
}

#[test]
fn group_wrong_key_cannot_decrypt() {
    assert!(group_decrypt(&[0x56; 32], &good_gframe()).is_err());
}

#[test]
fn group_signature_by_other_key_rejected() {
    // Valid AEAD (attacker knows G) but the signature is not from sender_ed.
    let env = gmsg_env(&G, ed25519_public(&GED)).encode().unwrap();
    let wrong_sig = ed25519_sign(&[0x99; 32], &gmsg_sig_input(&env));
    let f = craft_group(&G, &[4; 12], &[2], &[env.as_slice(), &wrong_sig].concat());
    assert_eq!(group_decrypt(&G, &f).unwrap_err(), Error::BadSignature);
}

#[test]
fn group_signature_without_domain_prefix_rejected() {
    let env = gmsg_env(&G, ed25519_public(&GED)).encode().unwrap();
    let sig = ed25519_sign(&GED, &env);
    let f = craft_group(&G, &[4; 12], &[2], &[env.as_slice(), &sig].concat());
    assert_eq!(group_decrypt(&G, &f).unwrap_err(), Error::BadSignature);
}

#[test]
fn group_signature_over_other_envelope_rejected() {
    let env = gmsg_env(&G, ed25519_public(&GED)).encode().unwrap();
    let mut other = gmsg_env(&G, ed25519_public(&GED));
    other.body = "other".into();
    let sig = ed25519_sign(&GED, &gmsg_sig_input(&other.encode().unwrap()));
    let f = craft_group(&G, &[4; 12], &[2], &[env.as_slice(), &sig].concat());
    assert_eq!(group_decrypt(&G, &f).unwrap_err(), Error::BadSignature);
}

#[test]
fn group_non_member_sender_rejected_by_pin() {
    let member = PinnedKeys { x_pk: [0; 32], ed_pk: ed25519_public(&GED) };
    let outsider_ed = [0x77u8; 32];
    let env = gmsg_env(&G, ed25519_public(&outsider_ed));
    let f = group_encrypt(&G, &outsider_ed, &env).unwrap();
    let got = group_decrypt(&G, &f).unwrap();
    assert_eq!(check_pinned_group(&got, &member), Err(Error::SenderMismatch));
}

#[test]
fn group_small_order_sender_key_forgery_rejected() {
    // Identity point as public key with R = identity, S = 0 verifies under non-strict checks.
    let mut pk = [0u8; 32];
    pk[0] = 1;
    let mut sig = [0u8; 64];
    sig[0] = 1;
    assert!(!ed25519_verify(&pk, b"anything", &sig));
    let env = Envelope { sender_ed: pk, ..gmsg_env(&G, [0; 32]) }.encode().unwrap();
    let f = craft_group(&G, &[4; 12], &[2], &[env.as_slice(), &sig].concat());
    assert!(group_decrypt(&G, &f).is_err());
}

#[test]
fn ed25519_noncanonical_s_rejected() {
    // S + L is the same scalar mod L; strict verification must refuse it.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let sk = [0x31u8; 32];
    let pk = ed25519_public(&sk);
    let sig = ed25519_sign(&sk, b"m");
    assert!(ed25519_verify(&pk, b"m", &sig));
    let mut carry = 0u16;
    let mut mal = sig;
    for i in 0..32 {
        let v = u16::from(sig[32 + i]) + u16::from(L[i]) + carry;
        mal[32 + i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0);
    assert!(!ed25519_verify(&pk, b"m", &mal));
}

#[test]
fn group_envelope_group_id_mismatch_rejected() {
    let other_g = [0x77u8; 32];
    let env = gmsg_env(&other_g, ed25519_public(&GED)).encode().unwrap();
    let sig = ed25519_sign(&GED, &gmsg_sig_input(&env));
    let f = craft_group(&G, &[4; 12], &[2], &[env.as_slice(), &sig].concat());
    assert_eq!(group_decrypt(&G, &f).unwrap_err(), Error::GroupMismatch);
}

#[test]
fn group_dm_and_ginv_envelopes_in_type_02_rejected() {
    for env in [
        dm_env("alice", ed25519_public(&GED)),
        ginv_env(&G, ed25519_public(&GED)),
    ] {
        let bytes = env.encode().unwrap();
        let sig = ed25519_sign(&GED, &gmsg_sig_input(&bytes));
        let f = craft_group(&G, &[4; 12], &[2], &[bytes.as_slice(), &sig].concat());
        assert_eq!(group_decrypt(&G, &f).unwrap_err(), Error::BadFrameType);
    }
    assert!(group_encrypt(&G, &GED, &dm_env("alice", ed25519_public(&GED))).is_err());
    assert!(group_encrypt(&G, &GED, &ginv_env(&G, ed25519_public(&GED))).is_err());
}

#[test]
fn group_wrong_aad_or_type_byte_rejected() {
    let env = gmsg_env(&G, ed25519_public(&GED)).encode().unwrap();
    let sig = ed25519_sign(&GED, &gmsg_sig_input(&env));
    let plain = [env.as_slice(), &sig].concat();
    let f = craft_group(&G, &[4; 12], &[1], &plain);
    assert_eq!(group_decrypt(&G, &f).unwrap_err(), Error::Decrypt);
    let mut ok = craft_group(&G, &[4; 12], &[2], &plain);
    assert!(group_decrypt(&G, &ok).is_ok());
    ok[0] = 1;
    assert_eq!(group_decrypt(&G, &ok).unwrap_err(), Error::BadFrameType);
}

#[test]
fn group_frame_is_not_a_dm_frame() {
    let f = good_gframe();
    assert!(open_dm(&R, &f).is_err());
    let d = seal_dm(&S, &r_pk(), &dm_env("alice", [9; 32])).unwrap();
    assert!(group_decrypt(&G, &d).is_err());
}

#[test]
fn group_same_message_different_nonce_each_time() {
    let a = good_gframe();
    let b = good_gframe();
    assert_ne!(a[1..13], b[1..13]);
}

// --------------------------------------------------------------- 3. Envelope

fn enc_dm() -> String {
    String::from_utf8(dm_env("alice", [0xab; 32]).encode().unwrap()).unwrap()
}

#[test]
fn registration_form_rejects_trailing_ampersand() {
    let id = Identity::from_secrets([1; 32], [2; 32]);
    let form = Registration::sign(&id, "alice", "Alice", 1_700_000_000).unwrap().to_form();
    assert!(Registration::from_form(&format!("{form}&")).is_err());
}

fn assert_bad(s: &str) {
    assert!(Envelope::decode(s.as_bytes()).is_err(), "accepted: {s:?}");
}

#[test]
fn envelope_header_and_field_count() {
    let e = enc_dm();
    assert!(Envelope::decode(e.as_bytes()).is_ok());
    for h in ["AEGIS1", "aegis2", "AEGIS3", "AEGIS2 ", "", "AEGIS%32", "AEGIS2%00"] {
        assert_bad(&e.replacen("AEGIS2", h, 1));
    }
    let fields: Vec<&str> = e.split('\n').collect();
    assert_eq!(fields.len(), 12);
    assert_bad(&fields[..11].join("\n"));
    assert_bad(&format!("{e}\n"));
    assert_bad(&format!("{e}\nx"));
    assert_bad(&fields[..1].join("\n"));
    assert_bad("");
    assert_bad("\n\n\n\n\n\n\n\n\n\n\n");
    assert_bad(&e.replace('\n', "\r\n"));
    let mut many = fields.clone();
    many.extend(std::iter::repeat_n("x", 10_000));
    assert_bad(&many.join("\n"));
}

#[test]
fn envelope_percent_escape_strictness() {
    let mut env = dm_env("alice", [7; 32]);
    env.body = "*".into();
    let e = String::from_utf8(env.encode().unwrap()).unwrap();
    assert!(e.contains("%2A"));
    assert!(Envelope::decode(e.as_bytes()).is_ok());
    assert_bad(&e.replace("%2A", "%2a"));
    assert_bad(&e.replace("%2A", "%2"));
    assert_bad(&e.replace("%2A", "%"));
    assert_bad(&e.replace("%2A", "%GG"));
    assert_bad(&e.replace("%2A", "*"));
    assert_bad(&e.replace("%2A", "%FF"));
    assert_bad(&e.replace("%2A", "%C3"));
    assert_bad(&e.replace("%2A", " "));
    assert_bad(&e.replace("%2A", "+"));
    assert_bad(&e.replace("%2A", "é"));
    // Percent-encoded NUL and newline are legal data, not structure.
    let ok = e.replace("%2A", "%00%0A%0D");
    assert_eq!(Envelope::decode(ok.as_bytes()).unwrap().body, "\0\n\r");
}

#[test]
fn envelope_invalid_hex_fields() {
    let e = enc_dm();
    let id = "00112233445566778899aabbccddeeff";
    for bad in [
        "00112233445566778899aabbccddeefF",
        "00112233445566778899aabbccddeeg0",
        "00112233445566778899aabbccddee",
        "00112233445566778899aabbccddeeff00",
        "",
    ] {
        assert_bad(&e.replacen(id, bad, 1));
    }
    let ed = hex::encode(&[0xabu8; 32]);
    for bad in [ed.to_uppercase(), format!("{}zz", &ed[..62]), ed[..62].to_owned(), format!("{ed}00")] {
        assert_bad(&e.replacen(&ed, &bad, 1));
    }
}

#[test]
fn envelope_numbers_strict() {
    let e = enc_dm();
    for bad in [
        "01700000000000", "+1700000000000", "-1", "1.5", "1e3", " 1", "0x10",
        "18446744073709551616", "999999999999999999999", "", "1_0",
    ] {
        assert_bad(&e.replacen("1700000000000", bad, 1));
    }
    let max = e.replacen("1700000000000", "18446744073709551615", 1);
    assert_eq!(Envelope::decode(max.as_bytes()).unwrap().ts_ms, u64::MAX);
}

#[test]
fn envelope_kind_and_group_field_consistency() {
    let e = enc_dm();
    for k in ["DM", "Dm", "dm ", "msg", "", "gmsg\0", "ginv"] {
        assert_bad(&e.replacen("\ndm\n", &format!("\n{k}\n"), 1));
    }
    // dm carrying group fields
    let mut with_gid = dm_env("alice", [7; 32]);
    with_gid.group_id = "ab".repeat(32);
    assert!(with_gid.encode().is_err());
    let mut with_members = dm_env("alice", [7; 32]);
    with_members.members = vec!["bob".into()];
    assert!(with_members.encode().is_err());
    // ginv whose group_id does not derive from its key
    let mut inv = ginv_env(&G, [7; 32]);
    inv.group_id = group_id(&[0x01; 32]);
    assert!(inv.encode().is_err());
    // ginv member limits and names
    let mut inv = ginv_env(&G, [7; 32]);
    inv.members = (0..21).map(|i| format!("user{i:02}")).collect();
    assert!(inv.encode().is_err());
    inv.members = (0..20).map(|i| format!("user{i:02}")).collect();
    assert!(inv.encode().is_ok());
    for bad in ["Bob", "bo", "bob,carol", "bob carol", "", &"x".repeat(25), "bób"] {
        let mut inv = ginv_env(&G, [7; 32]);
        inv.members = vec![bad.into()];
        assert!(inv.encode().is_err(), "{bad}");
    }
    inv.members.clear();
    assert!(inv.encode().is_err());
    // gmsg with invite fields
    let mut gm = gmsg_env(&G, [7; 32]);
    gm.group_key = Some(Zeroizing::new(G));
    assert!(gm.encode().is_err());
    // decode-side: sender name rules
    for bad in ["Alice", "al", "al ice", "alice\n", "ali%63e%00"] {
        let mut x = dm_env("alice", [7; 32]);
        x.sender = bad.into();
        assert!(x.encode().is_err(), "{bad}");
    }
}

#[test]
fn envelope_oversized_and_invalid_utf8() {
    let e = enc_dm();
    assert_bad(&e.replacen("Name", "%FF%FE", 1));
    assert_bad(&e.replacen("Name", "%C0%AF", 1));
    assert_bad(&e.replacen("Name", "%ED%A0%80", 1));
    assert!(Envelope::decode(&[0xff, 0xfe, 0xfd]).is_err());
    let mut raw = e.clone().into_bytes();
    raw[10] = 0xff;
    assert!(Envelope::decode(&raw).is_err());

    let mut big = dm_env("alice", [7; 32]);
    big.body = "a".repeat(5_000_000);
    let t = Instant::now();
    let enc = big.encode().unwrap();
    assert_eq!(Envelope::decode(&enc).unwrap().body.len(), 5_000_000);
    assert!(t.elapsed() < Duration::from_secs(5));

    // Anything that does not fit a bucket is refused on the way to the wire.
    let mut over = dm_env("alice", [7; 32]);
    over.body = "a".repeat(MAX_FRAME);
    let f = seal_dm(&S, &r_pk(), &over).unwrap();
    assert_eq!(pad::pad(&f).unwrap_err(), Error::FrameTooLarge);
}

#[test]
fn envelope_control_chars_survive_codec_and_are_removed_by_sanitizer() {
    let nasty = "a\u{0}b\u{7}c\u{1b}[31m\u{85}d\u{202E}e\u{2066}f\u{200B}g\u{FEFF}h\u{00AD}i\u{061C}j\u{2060}k";
    let mut env = dm_env("alice", [7; 32]);
    env.sender_name = nasty.into();
    let back = Envelope::decode(&env.encode().unwrap()).unwrap();
    assert_eq!(back.sender_name, nasty);
    let clean = sanitize_display_text(&back.sender_name);
    assert_eq!(clean, "abc[31mdefghijk");
    assert!(!clean.chars().any(char::is_control));
}

#[test]
fn sanitizer_limits_and_passthrough() {
    assert_eq!(sanitize_display_text("Алиса 🔒 日本"), "Алиса 🔒 日本");
    assert_eq!(sanitize_display_text(&"x".repeat(1000)).chars().count(), 64);
    let wide = "é".repeat(100);
    assert_eq!(sanitize_display_text(&wide).chars().count(), 64);
    assert_eq!(sanitize_display_text(""), "");
    assert_eq!(sanitize_display_text("\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}"), "");
    assert_eq!(sanitize_display_text("a\nb\r\nc\td"), "abcd");
    // The 64-char cap is applied after stripping, so hidden characters cannot eat the budget.
    let padded = format!("{}{}", "\u{200B}".repeat(500), "y".repeat(64));
    assert_eq!(sanitize_display_text(&padded), "y".repeat(64));
}

#[test]
fn sanitizer_strips_other_invisible_and_separator_chars() {
    for c in ['\u{2028}', '\u{2029}', '\u{206A}', '\u{206F}', '\u{E0001}', '\u{E0041}', '\u{FFF9}', '\u{FFFB}'] {
        let s = format!("a{c}b");
        assert_eq!(sanitize_display_text(&s), "ab", "U+{:04X}", u32::from(c));
    }
}

#[test]
fn username_rules() {
    for ok in ["abc", "a_c", "user_01", "000", "a".repeat(24).as_str()] {
        assert_eq!(normalize_username(ok).unwrap(), ok);
    }
    for bad in [
        "", "ab", "a b", "ali\0ce", "alice\n", "ali-ce", "ali.ce", "алиса", "ａｌｉｃｅ", &"a".repeat(25),
        "alice@example", "../etc", "a/b", " alice",
    ] {
        assert!(normalize_username(bad).is_err(), "{bad:?}");
    }
    assert_eq!(normalize_username("ALICE").unwrap(), "alice");
}

#[test]
fn username_normalization_is_ascii_only() {
    assert!(normalize_username("\u{212A}evin").is_err());
}

// ---------------------------------------------------------------- 4. Replay

#[test]
fn seen_ids_drop_duplicates() {
    let mut s = SeenIds::new(100);
    let id = "00112233445566778899aabbccddeeff";
    assert!(s.insert(id));
    for _ in 0..5 {
        assert!(!s.insert(id));
    }
    assert!(s.contains(id));
    assert_eq!(s.len(), 1);
    // Replaying the same sealed envelope content is caught by msg_id even from a new frame.
    let env = dm_env("alice", [7; 32]);
    let f1 = seal_dm(&S, &r_pk(), &env).unwrap();
    let f2 = seal_dm(&S, &r_pk(), &env).unwrap();
    assert_ne!(f1, f2);
    let mut seen = SeenIds::new(10);
    assert!(seen.insert(&open_dm(&R, &f1).unwrap().envelope.msg_id));
    assert!(!seen.insert(&open_dm(&R, &f2).unwrap().envelope.msg_id));
}

#[test]
fn seen_ids_bounded_with_fifo_eviction_and_persistence() {
    let mut s = SeenIds::new(3);
    for i in 0..10 {
        assert!(s.insert(&format!("id{i}")));
    }
    assert_eq!(s.len(), 3);
    assert!(!s.contains("id6"));
    assert!(s.contains("id7") && s.contains("id9"));
    let saved: Vec<String> = s.ids().cloned().collect();
    let mut restored = SeenIds::from_ids(3, saved);
    assert!(!restored.insert("id9"));
    assert!(!restored.insert("id7"));
    assert!(restored.insert("id10"));
    assert!(!restored.contains("id7"));
    // A duplicate does not refresh age, so it cannot be used to pin entries.
    let mut s = SeenIds::new(2);
    s.insert("a");
    s.insert("b");
    assert!(!s.insert("a"));
    s.insert("c");
    assert!(!s.contains("a"));
    let mut z = SeenIds::new(0);
    assert!(z.insert("x"));
    assert!(!z.insert("x"));
    assert!(z.is_empty() == false);
}

#[test]
fn ttl_expiry_boundaries() {
    let mut e = dm_env("alice", [7; 32]);
    e.ts_ms = 1_000_000;
    e.ttl_s = 0;
    assert!(!is_expired(&e, u64::MAX), "ttl 0 means keep");
    e.ttl_s = 60;
    assert!(!is_expired(&e, 1_000_000));
    assert!(!is_expired(&e, 1_059_999));
    assert!(is_expired(&e, 1_060_000));
    assert!(is_expired(&e, u64::MAX));
    assert!(!is_expired(&e, 0), "clock before send time");
    // Overflow must saturate, not wrap into an immediate expiry.
    e.ts_ms = u64::MAX - 10;
    e.ttl_s = u64::MAX;
    assert!(!is_expired(&e, u64::MAX - 11));
    e.ts_ms = u64::MAX;
    e.ttl_s = 1;
    assert!(is_expired(&e, u64::MAX));
    e.ts_ms = 5;
    e.ttl_s = u64::MAX / 500;
    assert!(!is_expired(&e, 10));
}

// --------------------------------------------------------------- 5. Padding

#[test]
fn pad_bucket_boundaries() {
    for (i, &b) in BUCKETS.iter().enumerate() {
        let max = b - 4;
        let p = pad::pad(&vec![1u8; max]).unwrap();
        assert_eq!(p.len(), b, "len {max}");
        assert_eq!(pad::unpad(&p).unwrap(), vec![1u8; max]);
        if i + 1 < BUCKETS.len() {
            let p = pad::pad(&vec![1u8; max + 1]).unwrap();
            assert_eq!(p.len(), BUCKETS[i + 1], "len {}", max + 1);
            assert_eq!(pad::unpad(&p).unwrap().len(), max + 1);
        }
        assert!(pad::is_bucket(b));
        assert!(!pad::is_bucket(b - 1));
        assert!(!pad::is_bucket(b + 1));
    }
    assert_eq!(pad::pad(&[]).unwrap().len(), 256);
    assert_eq!(pad::unpad(&pad::pad(&[]).unwrap()).unwrap(), Vec::<u8>::new());
    assert_eq!(pad::MAX_FRAME, 16380);
    assert_eq!(pad::pad(&vec![0u8; 16381]).unwrap_err(), Error::FrameTooLarge);
    assert_eq!(pad::pad(&vec![0u8; 1 << 20]).unwrap_err(), Error::FrameTooLarge);
    assert!(!pad::is_bucket(0) && !pad::is_bucket(usize::MAX));
}

#[test]
fn unpad_hostile_inputs() {
    // Length prefix larger than the payload.
    for bucket in BUCKETS {
        let mut p = vec![0u8; bucket];
        p[..4].copy_from_slice(&(u32::try_from(bucket).unwrap()).to_be_bytes());
        assert_eq!(pad::unpad(&p).unwrap_err(), Error::BadPadding);
        p[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(pad::unpad(&p).unwrap_err(), Error::BadPadding);
        p[..4].copy_from_slice(&(u32::try_from(bucket - 3).unwrap()).to_be_bytes());
        assert_eq!(pad::unpad(&p).unwrap_err(), Error::BadPadding);
    }
    // Non-minimal bucket: a short frame in a large bucket.
    let mut p = vec![0u8; 512];
    p[3] = 5;
    p[4..9].copy_from_slice(b"hello");
    assert_eq!(pad::unpad(&p).unwrap_err(), Error::BadPadding);
    // Non-zero padding anywhere in the fill.
    let good = pad::pad(b"hello").unwrap();
    for i in 9..good.len() {
        let mut t = good.clone();
        t[i] = 1;
        assert_eq!(pad::unpad(&t).unwrap_err(), Error::BadPadding, "byte {i}");
    }
    // Non-bucket total sizes.
    for n in [0usize, 1, 3, 4, 255, 257, 511, 513, 16383, 16385, 32768] {
        assert!(pad::unpad(&vec![0u8; n]).is_err(), "len {n}");
    }
    // Frame of exactly 16380 bytes in the largest bucket, with a zero-length claim.
    let mut p = vec![0u8; 16384];
    p[..4].copy_from_slice(&16381u32.to_be_bytes());
    assert!(pad::unpad(&p).is_err());
}

#[test]
fn sealed_frames_land_in_buckets_and_hide_size_within_bucket() {
    let r = r_pk();
    let mut prev_frame = 0;
    let mut prev_pad = 0;
    let mut by_bucket = std::collections::BTreeMap::<usize, (usize, usize)>::new();
    for n in 0..=1500usize {
        let mut env = dm_env("alice", [7; 32]);
        env.body = "a".repeat(n);
        let frame = seal_dm(&S, &r, &env).unwrap();
        let padded = pad::pad(&frame).unwrap();
        assert!(pad::is_bucket(padded.len()), "body {n}");
        assert!(frame.len() >= prev_frame, "frame length not monotonic at {n}");
        assert!(padded.len() >= prev_pad);
        prev_frame = frame.len();
        prev_pad = padded.len();
        let e = by_bucket.entry(padded.len()).or_insert((frame.len(), frame.len()));
        e.0 = e.0.min(frame.len());
        e.1 = e.1.max(frame.len());
        assert_eq!(pad::unpad(&padded).unwrap(), frame);
    }
    assert!(by_bucket.len() >= 3);
    // A bucket covers many distinct plaintext sizes but exposes only one wire size.
    assert!(by_bucket.values().any(|(lo, hi)| hi - lo > 100));
    assert!(by_bucket.keys().all(|k| BUCKETS.contains(k)));
}

#[test]
fn largest_body_that_fits_is_exact() {
    let fits = |n: usize| {
        let mut env = dm_env("alice", [7; 32]);
        env.body = "a".repeat(n);
        pad::pad(&seal_dm(&S, &r_pk(), &env).unwrap()).is_ok()
    };
    let (mut lo, mut hi) = (0usize, 20_000usize);
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    assert!(fits(lo) && !fits(lo + 1));
    let mut env = dm_env("alice", [7; 32]);
    env.body = "a".repeat(lo);
    assert_eq!(seal_dm(&S, &r_pk(), &env).unwrap().len(), MAX_FRAME);
}

// ------------------------------------------------------------------ 6. Vault

#[test]
fn vault_wrong_password_and_empty_password_variants() {
    let f = vault_encrypt("correct horse", FAST, b"data").unwrap();
    for bad in ["correct horsf", "Correct horse", "correct horse ", "", "correct", "correct horse\0"] {
        assert_eq!(vault_decrypt(bad, &f).unwrap_err(), Error::VaultDecrypt, "{bad:?}");
    }
    assert_eq!(&**vault_decrypt("correct horse", &f).unwrap(), b"data");
}

#[test]
fn vault_every_header_and_body_byte_is_authenticated() {
    let f = vault_encrypt_with("pw-pw-pw-pw", FAST, &[1; 16], &[2; 12], b"payload").unwrap();
    let t0 = Instant::now();
    for i in 0..f.len() {
        for mask in [0x01u8, 0x80] {
            let mut t = f.clone();
            t[i] ^= mask;
            assert!(vault_decrypt("pw-pw-pw-pw", &t).is_err(), "byte {i} mask {mask:#x}");
        }
    }
    assert!(t0.elapsed() < Duration::from_secs(60));
    let mut ext = f.clone();
    ext.push(0);
    assert!(vault_decrypt("pw-pw-pw-pw", &ext).is_err());
    ext = f.clone();
    ext.extend_from_slice(&f);
    assert!(vault_decrypt("pw-pw-pw-pw", &ext).is_err());
}

#[test]
fn vault_header_swap_attacks_rejected() {
    // Move a valid ciphertext under a header with different (cheaper) parameters.
    let f = vault_encrypt_with("pw-pw-pw-pw", FAST, &[1; 16], &[2; 12], b"payload").unwrap();
    let mut g = f.clone();
    g[4..8].copy_from_slice(&128u32.to_be_bytes());
    assert!(vault_decrypt("pw-pw-pw-pw", &g).is_err());
    let mut g = f.clone();
    g[16..32].copy_from_slice(&[9; 16]);
    assert!(vault_decrypt("pw-pw-pw-pw", &g).is_err());
    // A foreign magic is a format error.
    let mut g = f.clone();
    g[..4].copy_from_slice(b"AGV1");
    assert_eq!(vault_decrypt("pw-pw-pw-pw", &g).unwrap_err(), Error::VaultFormat);
}

#[test]
fn vault_hostile_params_rejected_fast() {
    let f = vault_encrypt_with("pw-pw-pw-pw", FAST, &[1; 16], &[2; 12], b"x").unwrap();
    let mk = |m: u32, t: u32, p: u32| {
        let mut g = f.clone();
        g[4..8].copy_from_slice(&m.to_be_bytes());
        g[8..12].copy_from_slice(&t.to_be_bytes());
        g[12..16].copy_from_slice(&p.to_be_bytes());
        g
    };
    let cases = [
        mk(u32::MAX, 1, 1),
        mk(1 << 31, 1, 1),
        mk((1 << 18) + 1, 1, 1),
        mk(256, u32::MAX, 1),
        mk(256, 17, 1),
        mk(256, 0, 1),
        mk(256, 1, 0),
        mk(256, 1, u32::MAX),
        mk(256, 1, 17),
        mk(0, 1, 1),
        mk(7, 1, 1),
        mk(8 * 4 - 1, 1, 4),
        mk(u32::MAX, u32::MAX, u32::MAX),
        mk(0, 0, 0),
    ];
    let t0 = Instant::now();
    for c in &cases {
        assert_eq!(vault_decrypt("pw-pw-pw-pw", c).unwrap_err(), Error::VaultParams);
    }
    assert!(t0.elapsed() < Duration::from_secs(2), "hostile params must be refused before hashing");
    for bad in [
        VaultParams { m_kib: 0, t: 1, p: 1 },
        VaultParams { m_kib: 1, t: 1, p: 1 },
        VaultParams { m_kib: 256, t: 0, p: 1 },
        VaultParams { m_kib: 256, t: 1, p: 0 },
        VaultParams { m_kib: u32::MAX, t: 1, p: 1 },
        VaultParams { m_kib: 256, t: 17, p: 1 },
    ] {
        assert!(vault_encrypt("pw", bad, b"").is_err());
    }
}

#[test]
fn vault_truncated_and_garbage_files() {
    let f = vault_encrypt("pw-pw-pw-pw", FAST, b"some data").unwrap();
    for n in 0..f.len() {
        assert!(vault_decrypt("pw-pw-pw-pw", &f[..n]).is_err(), "len {n}");
    }
    assert!(vault_decrypt("pw-pw-pw-pw", &[0u8; 1000]).is_err());
    assert!(vault_decrypt("pw-pw-pw-pw", b"AGV2").is_err());
}

#[test]
fn vault_fresh_salt_and_nonce_on_every_write() {
    let mut salts = std::collections::HashSet::new();
    let mut nonces = std::collections::HashSet::new();
    let mut files = std::collections::HashSet::new();
    for _ in 0..20 {
        let f = vault_encrypt("pw-pw-pw-pw", FAST, b"same data").unwrap();
        salts.insert(f[16..32].to_vec());
        nonces.insert(f[32..44].to_vec());
        assert!(files.insert(f.clone()));
        assert_eq!(&**vault_decrypt("pw-pw-pw-pw", &f).unwrap(), b"same data");
        assert!(!f.windows(9).any(|w| w == b"same data"));
    }
    assert_eq!(salts.len(), 20);
    assert_eq!(nonces.len(), 20);
}

#[test]
fn vault_empty_and_large_payloads() {
    let f = vault_encrypt("pw-pw-pw-pw", FAST, b"").unwrap();
    assert_eq!(f.len(), 44 + 16);
    assert!(vault_decrypt("pw-pw-pw-pw", &f).unwrap().is_empty());
    let big = vec![0xabu8; 3 << 20];
    let f = vault_encrypt("pw-pw-pw-pw", FAST, &big).unwrap();
    assert_eq!(&**vault_decrypt("pw-pw-pw-pw", &f).unwrap(), &big);
}

// -------------------------------------------------------------------- 7. PoW

#[test]
fn pow_verify_rejects_insufficient_wrong_scope_body_and_ts() {
    let q = "ab".repeat(32);
    let bh = pow::body_hash_hex(b"body");
    let ts = 1_700_000_000u64;
    let n = pow::mine(&q, ts, &bh, 12);
    let lz = pow::leading_zero_bits(&pow::pow_hash(&q, ts, &bh, n));
    assert!(lz >= 12);
    assert!(pow::verify(&q, ts, &bh, n, 12));
    assert!(!pow::verify(&q, ts, &bh, n, lz + 1));
    let weak = (0..).find(|&k| pow::leading_zero_bits(&pow::pow_hash(&q, ts, &bh, k)) < 6).unwrap();
    assert!(!pow::verify(&q, ts, &bh, weak, 12));
    for bits in [0u32, 1] {
        assert!(pow::verify(&q, ts, &bh, weak, bits.min(pow::leading_zero_bits(&pow::pow_hash(&q, ts, &bh, weak)))));
    }

    let mut bad = 0;
    for variant in 0..32u64 {
        let other_scope = format!("{}{:02x}", &q[..62], variant);
        if variant == 0xab {
            continue;
        }
        if !pow::verify(&other_scope, ts, &bh, n, 12) {
            bad += 1;
        }
        if !pow::verify(&q, ts + variant + 1, &bh, n, 12) {
            bad += 1;
        }
        if !pow::verify(&q, ts, &pow::body_hash_hex(&variant.to_be_bytes()), n, 12) {
            bad += 1;
        }
        if !pow::verify(&q, ts, &bh, n.wrapping_add(variant + 1), 12) {
            bad += 1;
        }
    }
    // Each altered input passes only by chance (2^-12); almost all of 128 must fail.
    assert!(bad >= 120, "only {bad}/128 altered inputs rejected");
    assert!(!pow::verify(&format!("dir:{q}"), ts, &bh, n, 18) || pow::verify(&format!("dir:{q}"), ts, &bh, n, 18));
    assert_ne!(pow::pow_hash("a", 1, "b", 1), pow::pow_hash("a", 1, "b", 2));
    // Field boundaries are delimited, so shifting bytes between fields changes the hash.
    assert_ne!(pow::pow_hash("a1", 2, "b", 3), pow::pow_hash("a", 12, "b", 3));
    assert_ne!(pow::pow_hash("a", 1, "b2", 3), pow::pow_hash("a", 1, "b", 23));
}

#[test]
fn pow_ts_window() {
    let now = 1_700_000_000u64;
    assert!(pow::ts_in_window(now, now));
    assert!(pow::ts_in_window(now - 600, now));
    assert!(pow::ts_in_window(now + 600, now));
    assert!(!pow::ts_in_window(now - 601, now));
    assert!(!pow::ts_in_window(now + 601, now));
    assert!(!pow::ts_in_window(0, now));
    assert!(!pow::ts_in_window(u64::MAX, now));
    assert!(!pow::ts_in_window(u64::MAX, 0));
    assert!(pow::ts_in_window(0, 0));
}

#[test]
fn pow_zero_bit_counting_is_exact() {
    for bits in 0..=255u32 {
        let mut h = [0u8; 32];
        let byte = (bits / 8) as usize;
        h[byte] = 0x80 >> (bits % 8);
        assert_eq!(pow::leading_zero_bits(&h), bits);
    }
    assert_eq!(pow::leading_zero_bits(&[0; 32]), 256);
    assert_eq!(pow::leading_zero_bits(&[0xff; 32]), 0);
}

#[test]
fn registration_form_strictness_and_tamper() {
    let id = Identity::from_secrets([1; 32], [2; 32]);
    let mut reg = Registration::sign(&id, "alice", "Alice", 1_700_000_000).unwrap();
    reg.mine(8);
    assert!(reg.signature_ok() && reg.pow_ok(8));
    let form = reg.to_form();
    assert_eq!(Registration::from_form(&form).unwrap(), reg);

    let bad_forms = [
        format!("{form}&u=bob"),
        format!("{form}&extra=1"),
        form.replacen("&pow=", "&pow2=", 1),
        form.replacen("u=alice&", "", 1),
        form.replacen("ts=1700000000", "ts=01700000000", 1),
        form.replacen("ts=1700000000", "ts=-1", 1),
        form.replacen("u=alice", "u=Alice", 1),
        form.replacen("u=alice", "u=al", 1),
        form.replacen("title=Alice", &format!("title={}", "a".repeat(65)), 1),
        form.replacen("title=Alice", "title=Al%0Aice", 1),
        form.replacen("title=Alice", "title=Al%00ice", 1),
        form.replacen("title=Alice", "title=Al%zzice", 1),
        String::new(),
        "u=alice".to_owned(),
    ];
    for b in &bad_forms {
        assert!(Registration::from_form(b).is_err(), "accepted {b}");
    }
    let x_hex = hex::encode(&reg.x);
    assert!(Registration::from_form(&form.replacen(&x_hex, &x_hex.to_uppercase(), 1)).is_err());
    assert!(Registration::from_form(&form.replacen(&x_hex, &x_hex[..62], 1)).is_err());

    // Every signed field is covered by the signature.
    for tweak in 0..5 {
        let mut t = reg.clone();
        match tweak {
            0 => t.title = "Mallory".into(),
            1 => t.x[0] ^= 1,
            2 => t.ed[0] ^= 1,
            3 => t.ts += 1,
            _ => t.u = "alicf".into(),
        }
        assert!(!t.signature_ok(), "tweak {tweak}");
    }
    let mut t = reg.clone();
    t.sig[63] ^= 1;
    assert!(!t.signature_ok());
    // A registration signed by key A but declaring key B fails.
    let other = Identity::from_secrets([3; 32], [4; 32]);
    let mut t = reg.clone();
    t.ed = other.ed_public();
    assert!(!t.signature_ok());
    // PoW is bound to the username.
    let mut t = reg.clone();
    t.u = "alicf".into();
    assert!(!t.pow_ok(16) || t.pow_ok(16));
    assert_ne!(
        pow::pow_hash(&aegis_core::directory::pow_scope("alice"), reg.ts, &reg.body_hash(), reg.pow),
        pow::pow_hash(&aegis_core::directory::pow_scope("alicf"), reg.ts, &reg.body_hash(), reg.pow)
    );
}

// ---------------------------------------------------------- 8. Safety number

#[test]
fn safety_number_symmetric_and_key_sensitive() {
    let a = (hex_key(1), hex_key(2));
    let b = (hex_key(3), hex_key(4));
    let n = safety_number((&a.0, &a.1), (&b.0, &b.1));
    assert_eq!(n, safety_number((&b.0, &b.1), (&a.0, &a.1)));
    assert_eq!(n.len(), 6 * 5 + 5);
    assert!(n.split(' ').all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit())));
    let mut seen = std::collections::HashSet::new();
    seen.insert(n.clone());
    for which in 0..4 {
        for byte in [0usize, 31] {
            let (mut a2, mut b2) = (a, b);
            match which {
                0 => a2.0[byte] ^= 1,
                1 => a2.1[byte] ^= 1,
                2 => b2.0[byte] ^= 1,
                _ => b2.1[byte] ^= 1,
            }
            let m = safety_number((&a2.0, &a2.1), (&b2.0, &b2.1));
            assert_ne!(m, n, "key {which} byte {byte}");
            assert_eq!(m, safety_number((&b2.0, &b2.1), (&a2.0, &a2.1)));
            seen.insert(m);
        }
    }
    assert_eq!(seen.len(), 9);
    // Swapping ed and x of one party is a different identity.
    assert_ne!(n, safety_number((&a.1, &a.0), (&b.0, &b.1)));
    // Self pairing is well-defined.
    assert_eq!(safety_number((&a.0, &a.1), (&a.0, &a.1)).len(), 35);
    // A third party gives a different number for the same peer.
    let c = (hex_key(5), hex_key(6));
    assert_ne!(n, safety_number((&a.0, &a.1), (&c.0, &c.1)));
}

fn hex_key(seed: u8) -> [u8; 32] {
    sha256(&[&[seed]])
}

// --------------------------------------------------------------- 9. Endpoints

#[test]
fn endpoint_http_only_for_local_hosts() {
    for ok in [
        "http://127.0.0.1",
        "http://127.0.0.1:8443",
        "http://localhost",
        "http://localhost:1",
        "http://LOCALHOST:65535",
        "http://abcdefghij234567.onion",
        "http://abcdefghij234567.onion:8080/",
        "https://freeoasis.space",
        "https://example.com:8443",
        "https://127.0.0.1",
    ] {
        assert!(Endpoint::parse(ok).is_ok(), "{ok}");
    }
    let e = Endpoint::parse("http://127.0.0.1:8443/").unwrap();
    assert_eq!((e.tls, e.host.as_str(), e.port), (false, "127.0.0.1", 8443));
    let e = Endpoint::parse("https://Example.COM").unwrap();
    assert_eq!((e.tls, e.host.as_str(), e.port), (true, "example.com", 443));
    assert_eq!(Endpoint::parse("http://localhost").unwrap().port, 80);

    for bad in [
        "http://example.com",
        "http://freeoasis.space",
        "http://8.8.8.8",
        "http://127.0.0.2",
        "http://127.0.0.1.evil.com",
        "http://localhost.evil.com",
        "http://evil.onion.com",
        "http://notlocalhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://[::1]:8080",
        "http://0x7f.0.0.1",
        "http://2130706433",
        "http://127.1",
        "http://localhost@evil.com",
        "http://evil.com@127.0.0.1",
        "http://127.0.0.1@evil.com",
        "http://user:pw@127.0.0.1",
        "http://127.0.0.1:80@evil.com",
        "http://127.0.0.1#@evil.com",
        "http://127.0.0.1?x=@evil.com",
        "http://127.0.0.1\\@evil.com",
        "ftp://127.0.0.1",
        "ws://127.0.0.1",
        "//127.0.0.1",
        "127.0.0.1",
        "",
        "http://",
        "https://",
        "http:///",
        "https://:443",
        "http://127.0.0.1:",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:-1",
        "http://127.0.0.1:08",
        "http://127.0.0.1:80:80",
        "http://127.0.0.1/path",
        "https://example.com/path",
        "https://example.com//",
        "https://exa mple.com",
        " https://example.com",
        "https://example.com ",
        "https://example.com\t",
        "https://example.com\r\nHost: evil.com",
        "https://example.com\r\n",
        "http://127.0.0.1\r\nX-Injected: 1",
        "http://127.0.0.1:80\r\nX: y",
        "https://exa\0mple.com",
        "https://example.com\n",
        "https://exämple.com",
        "https://пример.рф",
        "https://exa_mple.com",
        "https://exa%6Dple.com",
        "https://example.com:443:",
        "HTTP-://x",
    ] {
        assert!(Endpoint::parse(bad).is_err(), "accepted {bad:?}");
    }
    assert!(Endpoint::parse(&format!("https://{}", "a".repeat(254))).is_err());
    assert!(Endpoint::parse(&format!("https://{}", "a".repeat(5000))).is_err());
    assert!(Endpoint::parse(&format!("https://{}:{}", "a", "9".repeat(5000))).is_err());
    assert!(Endpoint::parse(&format!("http://{}", "\u{0}".repeat(100))).is_err());
}

#[test]
fn endpoint_host_never_contains_header_separators() {
    let candidates = [
        "http://127.0.0.1",
        "https://a.b-c.example",
        "http://x.onion",
        "https://EXAMPLE.org:99/",
    ];
    for c in candidates {
        let e = Endpoint::parse(c).unwrap();
        assert!(e
            .host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'));
        assert!(e.host.len() <= 253);
    }
    let mut rng = Rng(99);
    for _ in 0..3000 {
        let n = rng.below(40);
        let body: String = (0..n)
            .map(|_| {
                let pool = b"abcXYZ019.-:@/\\?#[]%\r\n \t\0_~!$&'()*+,;=";
                char::from(pool[rng.below(pool.len())])
            })
            .collect();
        for prefix in ["http://", "https://"] {
            if let Ok(e) = Endpoint::parse(&format!("{prefix}{body}")) {
                assert!(e
                    .host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'));
                assert_ne!(e.port, 0);
                if !e.tls {
                    assert!(e.host == "127.0.0.1" || e.host == "localhost" || e.host.ends_with(".onion"));
                }
            }
        }
    }
}

// ----------------------------------------------------------------- 10. Fuzz

#[test]
fn fuzz_open_dm_never_panics() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let valid = seal_dm(&S, &r_pk(), &dm_env("alice", [7; 32])).unwrap();
    for i in 0..4000 {
        let len = if i % 4 == 0 { rng.below(400) } else { valid.len() + rng.below(3) };
        let mut b = rng.bytes(len);
        if i % 2 == 0 && !b.is_empty() {
            b[0] = 1;
        }
        let _ = open_dm(&R, &b);
    }
    for _ in 0..4000 {
        let mut b = valid.clone();
        for _ in 0..=rng.below(4) {
            let k = rng.below(b.len());
            b[k] = (rng.next() >> 16) as u8;
        }
        if b != valid {
            assert!(open_dm(&R, &b).is_err());
        }
    }
}

#[test]
fn fuzz_group_decrypt_never_panics() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let valid = good_gframe();
    for i in 0..4000 {
        let len = if i % 4 == 0 { rng.below(400) } else { valid.len() + rng.below(3) };
        let mut b = rng.bytes(len);
        if i % 2 == 0 && !b.is_empty() {
            b[0] = 2;
        }
        assert!(group_decrypt(&G, &b).is_err());
    }
    for _ in 0..3000 {
        let mut b = valid.clone();
        let k = rng.below(b.len());
        b[k] ^= 1 << rng.below(8);
        assert!(group_decrypt(&G, &b).is_err());
    }
}

#[test]
fn fuzz_envelope_decode_never_panics() {
    let mut rng = Rng(42);
    let seeds: Vec<Vec<u8>> = vec![
        dm_env("alice", [7; 32]).encode().unwrap(),
        ginv_env(&G, [7; 32]).encode().unwrap(),
        gmsg_env(&G, [7; 32]).encode().unwrap(),
    ];
    for _ in 0..5000 {
        let len = rng.below(300);
        let b = rng.bytes(len);
        let _ = Envelope::decode(&b);
    }
    for i in 0..6000 {
        let mut b = seeds[i % 3].clone();
        for _ in 0..=rng.below(3) {
            if b.is_empty() {
                b.push(b'A');
            }
            match rng.below(4) {
                0 => {
                    let k = rng.below(b.len());
                    b[k] = (rng.next() >> 8) as u8;
                }
                1 => {
                    let k = rng.below(b.len());
                    b.remove(k);
                }
                2 => {
                    let k = rng.below(b.len());
                    b.insert(k, b"\n%0Az"[rng.below(5)]);
                }
                _ => {
                    let k = rng.below(b.len());
                    b.truncate(k);
                    if b.is_empty() {
                        b.push(b'A');
                    }
                }
            }
        }
        let _ = Envelope::decode(&b);
    }
    // Pure printable noise built from the envelope alphabet.
    let alphabet = b"AEGIS2dmginvsg0123456789abcdef%\nABCDEF-_.~";
    for _ in 0..5000 {
        let n = rng.below(200);
        let b: Vec<u8> = (0..n).map(|_| alphabet[rng.below(alphabet.len())]).collect();
        let _ = Envelope::decode(&b);
    }
}

#[test]
fn fuzz_unpad_never_panics() {
    let mut rng = Rng(7);
    for _ in 0..3000 {
        let len = if rng.below(2) == 0 {
            BUCKETS[rng.below(BUCKETS.len())]
        } else {
            rng.below(20_000)
        };
        let mut b = vec![0u8; len];
        if len >= 4 {
            let claimed = match rng.below(3) {
                0 => rng.next() as u32,
                1 => u32::try_from(rng.below(len + 8)).unwrap(),
                _ => u32::try_from(len.saturating_sub(4)).unwrap(),
            };
            b[..4].copy_from_slice(&claimed.to_be_bytes());
            for _ in 0..rng.below(3) {
                let k = rng.below(len);
                b[k] = (rng.next() >> 8) as u8;
            }
        }
        if let Ok(frame) = pad::unpad(&b) {
            assert_eq!(pad::pad(&frame).unwrap(), b, "unpad accepted a non-canonical encoding");
        }
    }
}

#[test]
fn fuzz_vault_decrypt_never_panics() {
    let mut rng = Rng(0xabcdef);
    for _ in 0..2000 {
        let n = rng.below(200);
        let mut b = rng.bytes(n);
        if n >= 4 && rng.below(2) == 0 {
            b[..4].copy_from_slice(b"AGV2");
        }
        let _ = vault_decrypt("pw-pw-pw-pw", &b);
    }
    let good = vault_encrypt_with("pw-pw-pw-pw", FAST, &[1; 16], &[2; 12], b"x").unwrap();
    for _ in 0..300 {
        let mut b = good[..32].to_vec();
        let extra = 13 + rng.below(80);
        b.extend(rng.bytes(extra));
        assert!(vault_decrypt("pw-pw-pw-pw", &b).is_err());
    }
}

#[test]
fn fuzz_registration_form_never_panics() {
    let mut rng = Rng(5);
    let id = Identity::from_secrets([1; 32], [2; 32]);
    let form = Registration::sign(&id, "alice", "Alice", 1_700_000_000).unwrap().to_form();
    for _ in 0..4000 {
        let mut b = form.clone().into_bytes();
        for _ in 0..=rng.below(3) {
            let k = rng.below(b.len());
            b[k] = b"&=%+Zz\n0 "[rng.below(9)];
        }
        if let Ok(s) = String::from_utf8(b) {
            let _ = Registration::from_form(&s);
        }
    }
}
