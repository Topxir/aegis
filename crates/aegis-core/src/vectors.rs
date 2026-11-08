//! Deterministic test vectors for `docs/test-vectors.json`.
//!
//! All inputs are fixed; every value is hex unless it ends in `_text`.

use crate::directory::Registration;
use crate::envelope::{Envelope, Kind};
use crate::identity::{ed25519_public, safety_number, x25519_public, Identity};
use crate::vault::{vault_encrypt_with, vault_file_name, VaultParams};
use crate::attach::{self, AttachmentMeta, MediaKind};
use crate::avatar::Avatar;
use crate::pin::{self, DuressRecord, PinKey, PinParams, PinSetup};
use crate::profile::{Particles, Profile};
use crate::ratchet::Ratchet;
use crate::senderkey::{Scope, SendChain};
use crate::session::{Encrypted, SessionStore};
use crate::x3dh::{self, Bundle, Parties, SignedPrekey};
use crate::{channel, group, sealed, hex, mp4clean, official, pad, pow, queue_ids, seal, sha256, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

fn seq(start: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = start.wrapping_add(u8::try_from(i).unwrap_or(0));
    }
    b
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn env_json(e: &Envelope) -> Result<Value> {
    let bytes = e.encode()?;
    Ok(json!({
        "kind": e.kind.as_str(),
        "msg_id": e.msg_id,
        "sender": e.sender,
        "sender_name_text": e.sender_name,
        "sender_ed": h(&e.sender_ed),
        "ts_ms": e.ts_ms,
        "ttl_s": e.ttl_s,
        "group_id": e.group_id,
        "body_text": e.body,
        "group_key": e.group_key.as_ref().map(|k| h(k.as_ref())).unwrap_or_default(),
        "members": e.members.join(","),
        "encoded_text": String::from_utf8_lossy(&bytes),
        "encoded": h(&bytes),
    }))
}

/// Builds the full vector document.
pub fn generate() -> Result<Value> {
    let alice = Identity::from_secrets(seq(0x10), seq(0x20));
    let bob = Identity::from_secrets(seq(0x30), seq(0x40));
    let g = seq(0x50);

    let safety = json!({
        "a_ed": h(&alice.ed_public()), "a_x": h(&alice.x_public()),
        "b_ed": h(&bob.ed_public()), "b_x": h(&bob.x_public()),
        "number": safety_number((&alice.ed_public(), &alice.x_public()), (&bob.ed_public(), &bob.x_public())),
        "number_swapped": safety_number((&bob.ed_public(), &bob.x_public()), (&alice.ed_public(), &alice.x_public())),
    });

    let mut padding = Vec::new();
    for len in [0usize, 1, 252, 253, 508, 509, 1020, 16380] {
        let frame: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap_or(0) + 1).collect();
        let p = pad::pad(&frame)?;
        padding.push(json!({
            "frame_len": len,
            "frame_rule": "frame[i] = (i mod 251) + 1",
            "padded_len": p.len(),
            "padded_sha256": h(&sha256(&[&p])),
        }));
    }
    let small = pad::pad(&[0xde, 0xad, 0xbe, 0xef, 0x01])?;
    padding.push(json!({"frame": "deadbeef01", "padded": h(&small), "padded_len": small.len()}));

    let dm = Envelope {
        kind: Kind::Dm,
        msg_id: h(&seq(0x60)[..16]),
        sender: "alice".into(),
        sender_name: "Alice <b>\u{202E}\u{00e9}".into(),
        sender_ed: alice.ed_public(),
        ts_ms: 1_700_000_000_123,
        ttl_s: 0,
        group_id: String::new(),
        body: "hi %41\nline2 <img src=x onerror=alert(1)>".into(),
        group_key: None,
        members: vec![],
    };
    let ginv = Envelope {
        kind: Kind::Ginv,
        msg_id: h(&seq(0x70)[..16]),
        group_id: group::group_id(&g),
        body: "Team".into(),
        ttl_s: 3600,
        group_key: Some(Zeroizing::new(g)),
        members: vec!["alice".into(), "bob".into()],
        ..dm.clone()
    };
    let gmsg = Envelope {
        kind: Kind::Gmsg,
        msg_id: h(&seq(0x80)[..16]),
        group_id: group::group_id(&g),
        body: "hello group".into(),
        ttl_s: 0,
        group_key: None,
        members: vec![],
        ..dm.clone()
    };

    let e_sk = seq(0x90);
    let seal_dm = seal::seal_dm_with(&e_sk, alice.x_secret(), &bob.x_public(), &dm)?;
    let seal_ginv = seal::seal_dm_with(&seq(0x91), alice.x_secret(), &bob.x_public(), &ginv)?;
    let seals = json!({
        "sender_x_sk": h(alice.x_secret()), "sender_x_pk": h(&alice.x_public()),
        "recipient_x_sk": h(bob.x_secret()), "recipient_x_pk": h(&bob.x_public()),
        "recipient_inbox_queue": h(&queue_ids::inbox_queue(&bob.x_public())),
        "cases": [
            {"e_sk": h(&e_sk), "e_pk": h(&x25519_public(&e_sk)), "envelope": env_json(&dm)?, "frame": h(&seal_dm)},
            {"e_sk": h(&seq(0x91)), "e_pk": h(&x25519_public(&seq(0x91))), "envelope": env_json(&ginv)?, "frame": h(&seal_ginv)},
        ],
    });

    let nonce = [0xa5u8; 12];
    let gframe = group::group_encrypt_with(&nonce, &g, alice.ed_secret(), &gmsg)?;
    let groups = json!({
        "g": h(&g),
        "group_id": group::group_id(&g),
        "queue": h(&group::group_queue(&g)?),
        "sender_ed_sk": h(alice.ed_secret()), "sender_ed_pk": h(&ed25519_public(alice.ed_secret())),
        "nonce": h(&nonce),
        "envelope": env_json(&gmsg)?,
        "frame": h(&gframe),
    });

    let params = VaultParams { m_kib: 256, t: 1, p: 1 };
    let (salt, vnonce) = ([0x0bu8; 16], [0x0cu8; 12]);
    let data = b"vault payload \xf0\x9f\x94\x92".to_vec();
    let file = vault_encrypt_with("correct horse battery", params, &salt, &vnonce, &data)?;
    let vault = json!({
        "password_text": "correct horse battery",
        "m_kib": params.m_kib, "t": params.t, "p": params.p,
        "salt": h(&salt), "nonce": h(&vnonce),
        "data": h(&data),
        "file": h(&file),
        "file_name_for_alice": vault_file_name("alice"),
    });

    let (scope, ts, bits) = (h(&seq(0xb0)), 1_700_000_000u64, 16u32);
    let body_hash = pow::body_hash_hex(b"example body");
    let nonce_pow = pow::mine(&scope, ts, &body_hash, bits);
    let pow_v = json!({
        "scope_text": scope, "ts": ts, "body": h(b"example body"), "body_hash": body_hash,
        "bits": bits, "pow": nonce_pow,
        "hash": h(&pow::pow_hash(&scope, ts, &body_hash, nonce_pow)),
    });

    let mut reg = Registration::sign(&alice, "alice", "Alice A", 1_700_000_000)?;
    reg.mine(8);
    let dir = json!({
        "u": reg.u, "title_text": reg.title, "x": h(&reg.x), "ed": h(&reg.ed), "ts": reg.ts,
        "ed_sk": h(alice.ed_secret()),
        "signed_message": h(&reg.message()),
        "sig": h(&reg.sig),
        "pow_bits": 8, "pow": reg.pow,
        "pow_body_hash": reg.body_hash(),
        "form": reg.to_form(),
    });

    let queues = json!({
        "x_pk": h(&bob.x_public()),
        "inbox": h(&queue_ids::inbox_queue(&bob.x_public())),
        "g": h(&g),
        "group_queue": h(&queue_ids::group_queue(&g)?),
    });

    let attachments = attachment_vectors(&dm)?;
    let channels = channel_vectors(&alice, &dm)?;
    let avatars: Vec<Value> = [&alice, &bob]
        .iter()
        .map(|id| {
            let a = Avatar::from_ed_pk(&id.ed_public());
            json!({"ed_pk": h(&id.ed_public()), "mask": a.mask_string(), "bg": a.bg, "fg": a.fg})
        })
        .collect();
    let fx = mp4clean::fixture::build();
    let clean = mp4clean::sanitize_video(&fx.bytes)?;
    let mp4 = json!({
        "input": h(&fx.bytes),
        "output_sha256": h(&sha256(&[&clean.bytes])),
        "output": h(&clean.bytes),
        "width": clean.width, "height": clean.height, "duration_ms": clean.duration_ms,
    });

    let official_v = official_vectors(&alice, &dm)?;
    let prof = profile_vectors(&dm)?;
    let pin_v = pin_vectors()?;

    Ok(json!({
        "protocol": 2,
        "note": "Generated by aegis-core (examples/gen_vectors.rs). Hex is lowercase; keys ending in _text are UTF-8.",
        "safety_number": safety,
        "padding": padding,
        "envelopes": [env_json(&dm)?, env_json(&ginv)?, env_json(&gmsg)?],
        "seal": seals,
        "group": groups,
        "vault": vault,
        "pow": pow_v,
        "directory": dir,
        "queues": queues,
        "attachment": attachments,
        "channel": channels,
        "avatar": avatars,
        "mp4": mp4,
        "official": official_v,
        "prof": prof,
        "pin": pin_v,
        "x3dh": x3dh_vectors()?,
        "ratchet": ratchet_vectors()?,
        "session": session_vectors(&dm)?,
        "senderkey": senderkey_vectors(&dm, &g)?,
        "sealed_transport": sealed_vectors()?,
        "timer": timer_vectors(&dm, &g)?,
    }))
}

/// `m[i] = (i mod 251)` with `FF D8 FF` as the first three bytes.
fn image_like(len: usize) -> Vec<u8> {
    let mut m: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
    m[..3].copy_from_slice(&[0xff, 0xd8, 0xff]);
    m
}

fn attachment_vectors(dm: &Envelope) -> Result<Value> {
    let key = seq(0xa0);
    let meta = AttachmentMeta {
        kind: MediaKind::Image,
        width: 640,
        height: 480,
        duration_ms: 0,
        caption: "caption %41 \u{00e9}".into(),
    };
    let mut cases = Vec::new();
    for (len, full) in [(100usize, true), (1_100_000usize, false)] {
        let m = image_like(len);
        let n = attach::chunk_count(len as u64).unwrap_or(0);
        let ids: Vec<[u8; 32]> = (0..n)
            .map(|i| seq(0xb0u8.wrapping_add(u8::try_from(i).unwrap_or(0).wrapping_mul(8))))
            .collect();
        let s = attach::seal_attachment_with(&meta, &m, &key, &ids)?;
        let body = s.descriptor.encode()?;
        let env = Envelope {
            kind: Kind::Dmf,
            msg_id: h(&seq(0xd0)[..16]),
            body: body.clone(),
            ..dm.clone()
        };
        let mut c = json!({
            "m_rule": "m[i] = i mod 251, then m[0..3] = ff d8 ff",
            "m_len": len,
            "key": h(&key),
            "ids": ids.iter().map(|i| h(i)).collect::<Vec<_>>(),
            "padded_len": attach::padded_len(len as u64).unwrap_or(0),
            "n": n,
            "m_sha256": h(&sha256(&[&m])),
            "descriptor_body_text": body,
            "chunk_lens": s.chunks.iter().map(Vec::len).collect::<Vec<_>>(),
            "chunk_sha256": s.chunks.iter().map(|c| h(&sha256(&[c]))).collect::<Vec<_>>(),
            "dmf_envelope": env_json(&env)?,
        });
        if full {
            c["chunks"] = json!(s.chunks.iter().map(|c| h(c)).collect::<Vec<_>>());
        }
        cases.push(c);
    }
    Ok(json!({"cases": cases}))
}

fn channel_vectors(alice: &Identity, dm: &Envelope) -> Result<Value> {
    let g = seq(0xc0);
    let id = channel::channel_id(&g);
    let cinv = Envelope {
        kind: Kind::Cinv,
        msg_id: h(&seq(0xe0)[..16]),
        group_id: id.clone(),
        body: "News".into(),
        group_key: Some(Zeroizing::new(g)),
        members: vec![],
        ..dm.clone()
    };
    let post = Envelope {
        kind: Kind::Cmsg,
        msg_id: h(&seq(0xe8)[..16]),
        group_id: id.clone(),
        body: "first post".into(),
        group_key: None,
        members: vec![],
        ..dm.clone()
    };
    let nonce = [0x5au8; 12];
    let frame = channel::seal_post_with(&nonce, &g, alice.ed_secret(), &post)?;
    Ok(json!({
        "g": h(&g),
        "channel_id": id,
        "queue": h(&channel::channel_queue(&g)?),
        "key": h(channel::channel_msg_key(&g)?.as_ref()),
        "owner": "alice",
        "owner_ed_sk": h(alice.ed_secret()), "owner_ed_pk": h(&alice.ed_public()),
        "cinv_envelope": env_json(&cinv)?,
        "nonce": h(&nonce),
        "post_envelope": env_json(&post)?,
        "frame": h(&frame),
    }))
}

fn official_vectors(alice: &Identity, dm: &Envelope) -> Result<Value> {
    let g = official::official_g();
    let post = Envelope {
        kind: Kind::Cmsg,
        msg_id: h(&seq(0xf0)[..16]),
        sender: official::OFFICIAL_OWNER.into(),
        group_id: official::official_channel_id(),
        body: "welcome".into(),
        group_key: None,
        members: vec![],
        ..dm.clone()
    };
    let nonce = [0x6bu8; 12];
    let frame = channel::seal_post_with(&nonce, &g, alice.ed_secret(), &post)?;
    Ok(json!({
        "g": h(&g),
        "channel_id": official::official_channel_id(),
        "queue": h(&official::official_queue()?),
        "key": h(official::official_msg_key()?.as_ref()),
        "owner": official::OFFICIAL_OWNER,
        "owner_ed_sk": h(alice.ed_secret()), "owner_ed_pk": h(&alice.ed_public()),
        "nonce": h(&nonce),
        "post_envelope": env_json(&post)?,
        "frame": h(&frame),
    }))
}

fn profile_vectors(dm: &Envelope) -> Result<Value> {
    let p = Profile {
        name: "Alice <b>\u{e9}".into(),
        about: "100% here <b>".into(),
        particles: Particles::Embers,
    };
    let env = Envelope {
        kind: Kind::Prof,
        msg_id: h(&seq(0xf8)[..16]),
        body: p.encode()?,
        group_key: None,
        members: vec![],
        group_id: String::new(),
        ..dm.clone()
    };
    Ok(json!({
        "name": p.name, "about": p.about, "particles": p.particles.as_str(),
        "body_text": env.body,
        "envelope": env_json(&env)?,
        "invalid_bodies": [
            "PF2\nn\nx\nnone", "PF1\nn\nx\nsparkle", "PF1\nn\nx", "PF1\nn\nx\nnone\nextra",
            "PF1\nn\u{7}\nx\nnone", "PF1\nn\nx\ty\nnone",
        ],
    }))
}

/// Argon2 cost is reduced here so that tests stay fast; real clients use 19456/2/1.
fn pin_vectors() -> Result<Value> {
    let params = PinParams { m_kib: 64, t: 1, p: 1 };
    let (salt, slot, s_secret, nonce) = (seq(0x10), seq(0x30), seq(0x50), seq(0x70));
    let (salt, nonce): ([u8; 16], [u8; 12]) = (crate::arr(&salt[..16])?, crate::arr(&nonce[..12])?);
    let vault_key = seq(0x90);
    let pin_text = "123456";
    let key = PinKey::derive_with(pin_text, &salt, &slot, params)?;
    let st = PinSetup::new_with(pin_text, &vault_key, params, &salt, &slot, &s_secret, &nonce)?;
    let duress = DuressRecord::new_with("9999", params, &crate::arr(&seq(0xa0)[..16])?, &seq(0xb0))?;
    let slot_hex = h(&slot);
    let v_hex = h(&st.verifier);
    Ok(json!({
        "params_note": "reduced Argon2id cost for the vector; the protocol value is m=19456 KiB, t=2, p=1",
        "m_kib": params.m_kib, "t": params.t, "p": params.p,
        "pin_text": pin_text,
        "salt": h(&salt), "slot": slot_hex, "s": h(&s_secret), "nonce": h(&nonce),
        "vault_key": h(&vault_key),
        "t_key": h(key.t()),
        "verifier": v_hex,
        "wrap": h(key.wrap_key(&s_secret)?.as_ref()),
        "file": h(&st.file.encode()),
        "create_hash_input_text": pin::create_hash_input(&slot_hex, &v_hex, &h(&s_secret)),
        "open_hash_input_text": pin::open_hash_input(&slot_hex, &v_hex),
        "pow_scope_text": pin::pow_scope(&slot_hex),
        "duress_pin_text": "9999",
        "duress_file": h(&duress.encode()),
    }))
}

fn b32(b: &[u8]) -> Result<[u8; 32]> {
    crate::arr(b)
}

fn x3dh_vectors() -> Result<Value> {
    let alice = Identity::from_secrets(seq(0x10), seq(0x20));
    let bob = Identity::from_secrets(seq(0x30), seq(0x40));
    let (spk_sk, opk_sk, ek_sk) = (seq(0xc0), seq(0xd0), seq(0xe0));
    let spk_ts = 1_700_000_000;
    let spk = SignedPrekey::from_secret(&bob, spk_sk, spk_ts);
    let opk_pk = x25519_public(&opk_sk);
    let ad = Parties { a_ed: alice.ed_public(), a_x: alice.x_public(), b_ed: bob.ed_public(), b_x: bob.x_public() }.ad();
    let mut cases = Vec::new();
    for with_opk in [true, false] {
        let bundle = Bundle { spk: spk.pk, spk_ts, spk_sig: spk.sig, opk: with_opk.then_some(opk_pk) };
        let sk = x3dh::initiate_with(&ek_sk, alice.x_secret(), &bob.x_public(), &bundle)?;
        cases.push(json!({"with_opk": with_opk, "sk": h(sk.as_ref())}));
    }
    Ok(json!({
        "a_x_sk": h(alice.x_secret()), "b_x_sk": h(bob.x_secret()),
        "b_ed_pk": h(&bob.ed_public()), "ek_sk": h(&ek_sk), "ek_pk": h(&x25519_public(&ek_sk)),
        "spk_sk": h(&spk_sk), "spk_pk": h(&spk.pk), "spk_ts": spk_ts, "spk_sig": h(&spk.sig),
        "opk_sk": h(&opk_sk), "opk_pk": h(&opk_pk),
        "ad": h(&ad),
        "cases": cases,
    }))
}

fn ratchet_vectors() -> Result<Value> {
    let alice = Identity::from_secrets(seq(0x10), seq(0x20));
    let bob = Identity::from_secrets(seq(0x30), seq(0x40));
    let ad = Parties { a_ed: alice.ed_public(), a_x: alice.x_public(), b_ed: bob.ed_public(), b_x: bob.x_public() }.ad();
    let (sk, spk_sk, a_dhs, b_dhs, a_dhs2) = (seq(0x01), seq(0xc0), seq(0xe1), seq(0xe2), seq(0xe3));
    let mut a = Ratchet::init_initiator_with(&a_dhs, &sk, &ad, &x25519_public(&spk_sk))?;
    let mut b = Ratchet::init_responder(&sk, &ad, &spk_sk);
    let t = 1_700_000_000;
    let plains = ["one", "two", "three"];
    let msgs: Vec<Vec<u8>> = plains.iter().map(|p| a.encrypt(p.as_bytes())).collect::<Result<_>>()?;
    // delivery order 0, 2, 1: message 1 arrives late from the skipped-key store
    for i in [0usize, 2, 1] {
        b.decrypt_with(&b_dhs, &msgs[i], t)?;
    }
    let reply = b.encrypt(b"reply")?;
    a.decrypt_with(&a_dhs2, &reply, t)?;
    Ok(json!({
        "sk": h(&sk), "ad": h(&ad), "spk_sk": h(&spk_sk),
        "a_dhs_sk": h(&a_dhs), "b_new_dhs_sk": h(&b_dhs), "a_new_dhs_sk": h(&a_dhs2),
        "now": t,
        "a_to_b": msgs.iter().zip(plains).map(|(m, p)| json!({"plain_text": p, "msg": h(m)})).collect::<Vec<_>>(),
        "delivery_order": [0, 2, 1],
        "b_to_a": {"plain_text": "reply", "msg": h(&reply)},
    }))
}

fn session_vectors(dm: &Envelope) -> Result<Value> {
    let alice = Identity::from_secrets(seq(0x10), seq(0x20));
    let bob = Identity::from_secrets(seq(0x30), seq(0x40));
    let (spk_sk, opk_sk, ek_sk, dhs_sk) = (seq(0xc0), seq(0xd0), seq(0xe0), seq(0xe1));
    let spk_ts = 1_700_000_000;
    let now = spk_ts + 100;
    let spk = SignedPrekey::from_secret(&bob, spk_sk, spk_ts);
    let bundle = Bundle { spk: spk.pk, spk_ts, spk_sig: spk.sig, opk: Some(x25519_public(&opk_sk)) };
    let mut store = SessionStore::new();
    store.add_contact("bob", bob.ed_public(), bob.x_public())?;
    store.start_session_with(&ek_sk, &dhs_sk, &alice, "bob", &bundle, now)?;
    let Encrypted::Frame(start) = store.encrypt_with(&seq(0xa1), &alice, "bob", dm, now)? else {
        return Err(crate::Error::Session("vector: no frame"));
    };
    // Bob answers; until Alice hears back every frame of hers still carries the start header.
    let ad = Parties { a_ed: alice.ed_public(), a_x: alice.x_public(), b_ed: bob.ed_public(), b_x: bob.x_public() }.ad();
    let sk = x3dh::respond(bob.x_secret(), &spk_sk, Some(&opk_sk), &alice.x_public(), &x25519_public(&ek_sk))?;
    let mut bob_ratchet = Ratchet::init_responder(&sk, &ad, &spk_sk);
    let first_inner = crate::seal::open_raw(0x03, bob.x_secret(), &start)?.1;
    bob_ratchet.decrypt_with(&seq(0x77), &first_inner[97..], now)?;
    let mut pong = dm.clone();
    pong.sender = "bob".into();
    pong.sender_ed = bob.ed_public();
    pong.msg_id = h(&seq(0x61)[..16]);
    pong.body = "pong".into();
    let reply_msg = bob_ratchet.encrypt(&pong.encode()?)?;
    let reply_frame = crate::seal::seal_raw(0x03, &seq(0xa3), bob.x_secret(), &alice.x_public(), &[&[1u8][..], &reply_msg].concat())?;
    let got = store.decrypt_with(&seq(0xe2), &alice, &reply_frame, now + 2)?;
    if got.envelope.as_ref().map(|e| e.body.as_str()) != Some("pong") {
        return Err(crate::Error::Session("vector: reply not accepted"));
    }
    let mut next_env = dm.clone();
    next_env.msg_id = h(&seq(0x62)[..16]);
    next_env.body = "second".into();
    let Encrypted::Frame(second) = store.encrypt_with(&seq(0xa2), &alice, "bob", &next_env, now + 3)? else {
        return Err(crate::Error::Session("vector: no frame"));
    };
    Ok(json!({
        "a_x_sk": h(alice.x_secret()), "a_ed_pk": h(&alice.ed_public()),
        "b_x_sk": h(bob.x_secret()), "b_ed_pk": h(&bob.ed_public()),
        "spk_sk": h(&spk_sk), "spk_pk": h(&spk.pk), "spk_ts": spk_ts, "spk_sig": h(&spk.sig),
        "opk_sk": h(&opk_sk), "opk_pk": h(&x25519_public(&opk_sk)),
        "ek_sk": h(&ek_sk), "dhs_sk": h(&dhs_sk), "now": now,
        "start_e_sk": h(&seq(0xa1)), "start_frame": h(&start),
        "start_body_text": dm.body,
        "reply_e_sk": h(&seq(0xa3)), "reply_frame": h(&reply_frame), "reply_body_text": "pong", "a_new_dhs_sk": h(&seq(0xe2)),
        "message_e_sk": h(&seq(0xa2)), "message_frame": h(&second),
        "message_body_text": next_env.body,
        "message_msg_id": next_env.msg_id,
        "note": "frames are unpadded; the start frame inner is 0x00||EK||spk||opk||ratchet_msg, 0x01||ratchet_msg once the sender has received a frame",
    }))
}

fn senderkey_vectors(dm: &Envelope, g: &[u8; 32]) -> Result<Value> {
    let alice = Identity::from_secrets(seq(0x10), seq(0x20));
    let (chain_id, ck, hnonce) = (crate::arr::<16>(&seq(0xf0)[..16])?, seq(0xf1), crate::arr::<12>(&seq(0xf2)[..12])?);
    let gid = group::group_id(g);
    let mut chain = SendChain::new_with(chain_id, b32(&ck)?, 1_700_000_000);
    let skey = chain.skey_envelope_with(h(&seq(0x63)[..16]), "alice", &dm.sender_name, alice.ed_public(), &gid, dm.ts_ms);
    let gmsg = Envelope {
        kind: Kind::Gmsg,
        msg_id: h(&seq(0x64)[..16]),
        group_id: gid.clone(),
        body: "hello chain".into(),
        ttl_s: 0,
        group_key: None,
        members: vec![],
        ..dm.clone()
    };
    let frame = chain.encrypt_with(&hnonce, Scope::Group, g, alice.ed_secret(), &gmsg)?;
    Ok(json!({
        "g": h(g), "group_id": gid, "chain_id": h(&chain_id), "ck": h(&ck), "hnonce": h(&hnonce),
        "ed_sk": h(alice.ed_secret()),
        "skey_envelope": env_json(&skey)?,
        "gmsg_envelope": env_json(&gmsg)?,
        "frame": h(&frame),
        "frame_layout": "0x05 || hnonce(12) || AEAD(hk, hnonce, aad 0x05, chain_id||BE32(n)) (36 bytes) || AEAD(msg_key, nonce, aad 0x05||chain_id||BE32(n), envelope||sig)",
        "n": 0,
        "now": 1_700_000_000,
    }))
}

fn timer_vectors(dm: &Envelope, g: &[u8; 32]) -> Result<Value> {
    let alice = Identity::from_secrets(seq(0x10), seq(0x20));
    let gid = group::group_id(g);
    let ttl = Envelope {
        kind: Kind::Ttl,
        msg_id: h(&seq(0x65)[..16]),
        ttl_s: 300,
        body: String::new(),
        group_id: String::new(),
        group_key: None,
        members: vec![],
        ..dm.clone()
    };
    let gttl = Envelope {
        kind: Kind::Gttl,
        msg_id: h(&seq(0x66)[..16]),
        ttl_s: 30,
        group_id: gid.clone(),
        ..ttl.clone()
    };
    let (chain_id, hnonce) = (crate::arr::<16>(&seq(0xf3)[..16])?, crate::arr::<12>(&seq(0xf4)[..12])?);
    let mut chain = SendChain::new_with(chain_id, b32(&seq(0xf5))?, 1_700_000_000);
    let skey = chain.skey_envelope_with(h(&seq(0x67)[..16]), "alice", &dm.sender_name, alice.ed_public(), &gid, dm.ts_ms);
    let frame = chain.encrypt_with(&hnonce, Scope::Group, g, alice.ed_secret(), &gttl)?;
    let base = 1_700_000_000_000u64;
    let expiry: Vec<Value> = [(0u64, 0u64), (30, 29_999), (30, 30_000), (300, 299_999), (86_400, 86_399_999), (604_800, 604_800_000), (0, 1_000_000_000_000)]
        .iter()
        .map(|&(t, d)| json!({"base_ms": base, "ttl_s": t, "now_ms": base + d, "expired": crate::envelope::expired_since(base, t, base + d)}))
        .collect();
    Ok(json!({
        "choices": crate::envelope::TTL_CHOICES,
        "ttl_envelope": env_json(&ttl)?,
        "gttl_envelope": env_json(&gttl)?,
        "g": h(g), "chain_id": h(&chain_id), "ck": h(&seq(0xf5)), "hnonce": h(&hnonce), "now": 1_700_000_000,
        "skey_envelope": env_json(&skey)?,
        "gttl_frame": h(&frame),
        "expiry": expiry,
    }))
}

fn sealed_vectors() -> Result<Value> {
    let (srv_sk, e_sk) = (seq(0xb0), seq(0xb1));
    let srv_pk = x25519_public(&srv_sk);
    let body = b"u=alice&ts=1700000000&pow=1".to_vec();
    let (outer, k_resp) = sealed::seal_request_with(&e_sk, &srv_pk, "POST", "/api/v2/prekeys/take", &body)?;
    let resp = sealed::seal_response_with(&seq(0xb2)[..12].try_into().map_err(|_| crate::Error::Length)?, &k_resp, 200, br#"{"opks":3}"#)?;
    Ok(json!({
        "srv_sk": h(&srv_sk), "srv_pk": h(&srv_pk), "e_sk": h(&e_sk),
        "method": "POST", "target": "/api/v2/prekeys/take", "body_text": String::from_utf8_lossy(&body),
        "request": h(&outer), "request_len": outer.len(),
        "k_resp": h(k_resp.as_ref()),
        "response_nonce": h(&seq(0xb2)[..12]), "response_status": 200, "response_body_text": r#"{"opks":3}"#, "response": h(&resp), "response_len": resp.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(v: &Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap()).unwrap()
    }

    #[test]
    fn session_frames_follow_the_spec() {
        let v = generate().unwrap();
        let s = &v["session"];
        let b_x = b32(&hx(s, "b_x_sk")).unwrap();
        let a_x = b32(&hx(s, "a_x_sk")).unwrap();
        let a_x = x25519_public(&a_x);
        let (spk_sk, opk_sk) = (b32(&hx(s, "spk_sk")).unwrap(), b32(&hx(s, "opk_sk")).unwrap());
        let now = s["now"].as_u64().unwrap();

        let (sender, inner) = crate::seal::open_raw(0x03, &b_x, &hx(s, "start_frame")).unwrap();
        assert_eq!(sender, a_x);
        assert_eq!(inner[0], 0);
        let ek = b32(&inner[1..33]).unwrap();
        assert_eq!(ek, b32(&hx(s, "ek_sk")).map(|k| x25519_public(&k)).unwrap());
        assert_eq!(inner[33..65], hx(s, "spk_pk")[..]);
        assert_eq!(inner[65..97], hx(s, "opk_pk")[..]);
        let sk = x3dh::respond(&b_x, &spk_sk, Some(&opk_sk), &a_x, &ek).unwrap();
        let ad = Parties {
            a_ed: b32(&hx(s, "a_ed_pk")).unwrap(),
            a_x,
            b_ed: b32(&hx(s, "b_ed_pk")).unwrap(),
            b_x: x25519_public(&b_x),
        }
        .ad();
        let mut r = Ratchet::init_responder(&sk, &ad, &spk_sk);
        let plain = r.decrypt_with(&seq(0x77), &inner[97..], now).unwrap();
        assert_eq!(Envelope::decode(&plain).unwrap().body, s["start_body_text"].as_str().unwrap());

        let reply = r.encrypt(b"x").unwrap();
        drop(reply);
        let (_, inner) = crate::seal::open_raw(0x03, &b_x, &hx(s, "message_frame")).unwrap();
        assert_eq!(inner[0], 1);
        let plain = r.decrypt_with(&seq(0x78), &inner[1..], now).unwrap();
        assert_eq!(Envelope::decode(&plain).unwrap().body, s["message_body_text"].as_str().unwrap());
    }
}
