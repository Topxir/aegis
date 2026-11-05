#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::{group, hex, pad, pow, seal, vault, vectors};
use serde_json::Value;

fn load() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/test-vectors.json");
    let text = std::fs::read_to_string(&path)
        .expect("docs/test-vectors.json missing: run `cargo run -p aegis-core --example gen_vectors`");
    serde_json::from_str(&text).unwrap()
}

#[test]
fn file_matches_generator() {
    assert_eq!(
        load(),
        vectors::generate().unwrap(),
        "docs/test-vectors.json is stale: run `cargo run -p aegis-core --example gen_vectors`"
    );
}

#[test]
fn generator_is_deterministic() {
    assert_eq!(vectors::generate().unwrap(), vectors::generate().unwrap());
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

fn a32(v: &Value, k: &str) -> [u8; 32] {
    hex::decode_array(s(v, k)).unwrap()
}

#[test]
fn file_vectors_decrypt_with_published_secrets() {
    let v = load();

    let sealed = &v["seal"];
    for case in sealed["cases"].as_array().unwrap() {
        let frame = hex::decode(s(case, "frame")).unwrap();
        let opened = seal::open_dm(&a32(sealed, "recipient_x_sk"), &frame).unwrap();
        assert_eq!(h(&opened.sender_x_pk), s(sealed, "sender_x_pk"));
        let enc = opened.envelope.encode().unwrap();
        assert_eq!(h(&enc), s(&case["envelope"], "encoded"));
    }

    let gv = &v["group"];
    let env = group::group_decrypt(&a32(gv, "g"), &hex::decode(s(gv, "frame")).unwrap()).unwrap();
    assert_eq!(env.body, "hello group");

    let vt = &v["vault"];
    let plain = vault::vault_decrypt(
        s(vt, "password_text"),
        &hex::decode(s(vt, "file")).unwrap(),
    )
    .unwrap();
    assert_eq!(h(&plain), s(vt, "data"));

    let p = &v["pow"];
    assert!(pow::verify(
        s(p, "scope_text"),
        p["ts"].as_u64().unwrap(),
        s(p, "body_hash"),
        p["pow"].as_u64().unwrap(),
        u32::try_from(p["bits"].as_u64().unwrap()).unwrap(),
    ));

    for pv in v["padding"].as_array().unwrap() {
        if let Some(padded) = pv.get("padded") {
            let un = pad::unpad(&hex::decode(padded.as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(h(&un), s(pv, "frame"));
        }
    }
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

#[test]
fn new_vectors_verify_with_published_inputs() {
    use aegis_core::attach::{open_attachment, AttachmentDescriptor};
    use aegis_core::avatar::Avatar;
    use aegis_core::pin::{self, DuressRecord, PinFile, PinKey, PinParams};
    use aegis_core::profile::Profile;
    use aegis_core::{channel, mp4clean, official};

    let v = load();
    let case = &v["attachment"]["cases"][0];
    let desc = AttachmentDescriptor::parse(s(case, "descriptor_body_text")).unwrap();
    let chunks: Vec<Vec<u8>> = case["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| hex::decode(c.as_str().unwrap()).unwrap())
        .collect();
    let m = open_attachment(&desc, &chunks).unwrap();
    assert_eq!(h(&aegis_core::sha256(&[&m])), s(case, "m_sha256"));

    let c = &v["channel"];
    let env = channel::open_post(
        &a32(c, "g"),
        s(c, "owner"),
        &a32(c, "owner_ed_pk"),
        &hex::decode(s(c, "frame")).unwrap(),
    )
    .unwrap();
    assert_eq!(env.body, "first post");

    for a in v["avatar"].as_array().unwrap() {
        let av = Avatar::from_ed_pk(&a32(a, "ed_pk"));
        assert_eq!(av.mask_string(), s(a, "mask"));
        assert_eq!(u64::from(av.bg), a["bg"].as_u64().unwrap());
        assert_eq!(u64::from(av.fg), a["fg"].as_u64().unwrap());
    }

    let mp4 = &v["mp4"];
    let out = mp4clean::sanitize_video(&hex::decode(s(mp4, "input")).unwrap()).unwrap();
    assert_eq!(h(&aegis_core::sha256(&[&out.bytes])), s(mp4, "output_sha256"));
    assert_eq!(u64::from(out.width), mp4["width"].as_u64().unwrap());

    let o = &v["official"];
    assert_eq!(h(&official::official_g()), s_(o, "g"));
    assert_eq!(h(&official::official_queue().unwrap()), s_(o, "queue"));
    assert_eq!(official::official_channel_id(), s_(o, "channel_id"));
    let env = official::open_official_post(&a32(o, "owner_ed_pk"), &hex::decode(s_(o, "frame")).unwrap()).unwrap();
    assert_eq!(env.body, "welcome");

    let pf = &v["prof"];
    let p = Profile::parse(s_(pf, "body_text")).unwrap();
    assert_eq!((p.name.as_str(), p.about.as_str(), p.particles.as_str()), (s_(pf, "name"), s_(pf, "about"), s_(pf, "particles")));
    assert_eq!(p.encode().unwrap(), s_(pf, "body_text"));
    for b in pf["invalid_bodies"].as_array().unwrap() {
        assert!(Profile::parse(b.as_str().unwrap()).is_err());
    }

    let pn = &v["pin"];
    let params = PinParams { m_kib: 64, t: 1, p: 1 };
    assert_eq!(
        (u64::from(params.m_kib), u64::from(params.t), u64::from(params.p)),
        (pn["m_kib"].as_u64().unwrap(), pn["t"].as_u64().unwrap(), pn["p"].as_u64().unwrap())
    );
    let key = PinKey::derive_with(s_(pn, "pin_text"), &a16(pn, "salt"), &a32(pn, "slot"), params).unwrap();
    assert_eq!(h(key.t()), s_(pn, "t_key"));
    assert_eq!(h(&key.verifier().unwrap()), s_(pn, "verifier"));
    assert_eq!(h(key.wrap_key(&a32(pn, "s")).unwrap().as_ref()), s_(pn, "wrap"));
    let file = PinFile::parse(&hex::decode(s_(pn, "file")).unwrap()).unwrap();
    assert_eq!(h(file.unwrap(&key, &a32(pn, "s")).unwrap().as_ref()), s_(pn, "vault_key"));
    assert_eq!(pin::pow_scope(&file.slot_hex()), s_(pn, "pow_scope_text"));
    let d = DuressRecord::parse(&hex::decode(s_(pn, "duress_file")).unwrap()).unwrap();
    assert!(d.matches_with(s_(pn, "duress_pin_text"), params).unwrap());
    assert!(!d.matches_with(s_(pn, "pin_text"), params).unwrap());
}

fn a16(v: &serde_json::Value, k: &str) -> [u8; 16] {
    hex::decode(s_(v, k)).unwrap().try_into().unwrap()
}

fn s_<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}
