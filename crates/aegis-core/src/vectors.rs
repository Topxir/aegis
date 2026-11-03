//! Deterministic test vectors for `docs/test-vectors.json`.
//!
//! All inputs are fixed; every value is hex unless it ends in `_text`.

use crate::directory::Registration;
use crate::envelope::{Envelope, Kind};
use crate::identity::{ed25519_public, safety_number, x25519_public, Identity};
use crate::vault::{vault_encrypt_with, vault_file_name, VaultParams};
use crate::{group, hex, pad, pow, queue_ids, seal, sha256, Result};
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
    }))
}
