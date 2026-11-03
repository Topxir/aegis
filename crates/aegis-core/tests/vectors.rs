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
