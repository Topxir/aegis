#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::identity::x25519_public;
use aegis_core::ratchet::Ratchet;
use aegis_core::senderkey::{RecvSet, Scope};
use aegis_core::x3dh::{self, Bundle};
use aegis_core::envelope::Envelope;
use aegis_core::{group, hex, pad, pow, seal, sealed, vault, vectors};
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

    let x = &v["x3dh"];
    let (a_x, b_x) = (a32(x, "a_x_sk"), a32(x, "b_x_sk"));
    for case in x["cases"].as_array().unwrap() {
        let with_opk = case["with_opk"].as_bool().unwrap();
        let bundle = Bundle {
            spk: a32(x, "spk_pk"),
            spk_ts: x["spk_ts"].as_u64().unwrap(),
            spk_sig: hex::decode(s_(x, "spk_sig")).unwrap().try_into().unwrap(),
            opk: with_opk.then(|| a32(x, "opk_pk")),
        };
        bundle.check(&a32(x, "b_ed_pk"), x["spk_ts"].as_u64().unwrap()).unwrap();
        let sk = x3dh::initiate_with(&a32(x, "ek_sk"), &a_x, &x25519_public(&b_x), &bundle).unwrap();
        assert_eq!(h(sk.as_ref()), s_(case, "sk"));
        let sk_b = x3dh::respond(&b_x, &a32(x, "spk_sk"), with_opk.then(|| a32(x, "opk_sk")).as_ref(), &x25519_public(&a_x), &a32(x, "ek_pk")).unwrap();
        assert_eq!(*sk_b, *sk);
    }

    let r = &v["ratchet"];
    let ad: [u8; 128] = hex::decode(s_(r, "ad")).unwrap().try_into().unwrap();
    let now = r["now"].as_u64().unwrap();
    let mut rb = Ratchet::init_responder(&a32(r, "sk"), &ad, &a32(r, "spk_sk"));
    let msgs: Vec<Vec<u8>> = r["a_to_b"].as_array().unwrap().iter().map(|m| hex::decode(s_(m, "msg")).unwrap()).collect();
    for i in r["delivery_order"].as_array().unwrap() {
        let i = i.as_u64().unwrap() as usize;
        let p = rb.decrypt_with(&a32(r, "b_new_dhs_sk"), &msgs[i], now).unwrap();
        assert_eq!(p.as_slice(), r["a_to_b"][i]["plain_text"].as_str().unwrap().as_bytes());
    }
    assert_eq!(rb.skipped_len(), 0);
    let mut ra = Ratchet::init_initiator_with(&a32(r, "a_dhs_sk"), &a32(r, "sk"), &ad, &x25519_public(&a32(r, "spk_sk"))).unwrap();
    let again = ra.encrypt(b"one").unwrap();
    assert_eq!(h(&again), s_(&r["a_to_b"][0], "msg"));
    let reply = hex::decode(s_(&r["b_to_a"], "msg")).unwrap();
    let p = ra.decrypt_with(&a32(r, "a_new_dhs_sk"), &reply, now).unwrap();
    assert_eq!(p.as_slice(), b"reply");

    let sk = &v["senderkey"];
    let g = a32(sk, "g");
    let mut rs = RecvSet::new(Scope::Group, &g, None).unwrap();
    let skey = Envelope::decode(&hex::decode(s_(&sk["skey_envelope"], "encoded")).unwrap()).unwrap();
    assert_eq!(skey.kind.as_str(), "skey");
    rs.add_from_skey(&skey, sk["now"].as_u64().unwrap()).unwrap();
    let frame = hex::decode(s_(sk, "frame")).unwrap();
    assert_eq!(frame[0], 5);
    assert_eq!(h(&frame[1..13]), s_(sk, "hnonce"));
    let env = rs.decrypt(&frame, sk["now"].as_u64().unwrap()).unwrap();
    assert_eq!(env.body, "hello chain");

    let tv = &v["timer"];
    for k in ["ttl_envelope", "gttl_envelope"] {
        let enc = hex::decode(s_(&tv[k], "encoded")).unwrap();
        let e = Envelope::decode(&enc).unwrap();
        assert_eq!(e.kind.as_str(), s_(&tv[k], "kind"));
        assert_eq!(e.ttl_s, tv[k]["ttl_s"].as_u64().unwrap());
        assert!(e.body.is_empty());
        assert_eq!(e.encode().unwrap(), enc);
    }
    let g = a32(tv, "g");
    let mut rs = RecvSet::new(Scope::Group, &g, None).unwrap();
    let skey = Envelope::decode(&hex::decode(s_(&tv["skey_envelope"], "encoded")).unwrap()).unwrap();
    rs.add_from_skey(&skey, tv["now"].as_u64().unwrap()).unwrap();
    let env = rs.decrypt(&hex::decode(s_(tv, "gttl_frame")).unwrap(), tv["now"].as_u64().unwrap()).unwrap();
    assert_eq!(env.kind.as_str(), "gttl");
    assert_eq!(env.ttl_s, 30);
    let choices: Vec<u64> = tv["choices"].as_array().unwrap().iter().map(|c| c.as_u64().unwrap()).collect();
    assert_eq!(choices, aegis_core::envelope::TTL_CHOICES);
    for c in tv["expiry"].as_array().unwrap() {
        let n = |k: &str| c[k].as_u64().unwrap();
        assert_eq!(
            aegis_core::envelope::expired_since(n("base_ms"), n("ttl_s"), n("now_ms")),
            c["expired"].as_bool().unwrap()
        );
    }

    let st = &v["sealed_transport"];
    let (req, k_resp) = sealed::open_request(&a32(st, "srv_sk"), &hex::decode(s_(st, "request")).unwrap()).unwrap();
    assert_eq!((req.method.as_str(), req.target.as_str()), (s_(st, "method"), s_(st, "target")));
    assert_eq!(req.body, s_(st, "body_text").as_bytes());
    assert_eq!(h(k_resp.as_ref()), s_(st, "k_resp"));
    let (code, body) = sealed::open_response(&k_resp, &hex::decode(s_(st, "response")).unwrap()).unwrap();
    assert_eq!((u64::from(code), body.as_slice()), (st["response_status"].as_u64().unwrap(), s_(st, "response_body_text").as_bytes()));

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
