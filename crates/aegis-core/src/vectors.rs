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
use crate::{channel, group, hex, mp4clean, official, pad, pow, queue_ids, seal, sha256, Result};
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
        about: "100% here\u{202e}".into(),
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
