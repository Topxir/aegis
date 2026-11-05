//! Reserved names, the owner-signed official queue, queue fill difficulty, poll paging and the
//! prekey upload limit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::directory::Registration;
use aegis_core::identity::Identity;
use aegis_core::prekeys::PrekeyPut;
use aegis_core::{hex, now_secs, official, pow, queue_ids};
use aegis_server::{Config, Request, ServerState};

const BITS: u32 = 4;

fn cfg() -> Config {
    Config { pow_bits: BITS, ..Config::default() }
}

fn owner() -> Identity {
    Identity::from_secrets([0x31; 32], [0x32; 32])
}

fn mallory() -> Identity {
    Identity::from_secrets([0x66; 32], [0x77; 32])
}

fn register(s: &mut ServerState, id: &Identity, u: &str, now: u64) -> u16 {
    let mut reg = Registration::sign(id, u, "t", now).unwrap();
    reg.mine(BITS);
    let r = Request {
        method: "POST".into(),
        path: "/api/v2/dir/register".into(),
        query: vec![],
        body: reg.to_form().into_bytes(),
    };
    s.handle(&r, now).status
}

fn send_req(q: &[u8; 32], body: &[u8], ts: u64, bits: u32, sig: Option<[u8; 64]>) -> Request {
    let qh = hex::encode(q);
    let n = pow::mine(&qh, ts, &pow::body_hash_hex(body), bits);
    let mut query = vec![("q".into(), qh), ("ts".into(), ts.to_string()), ("pow".into(), n.to_string())];
    if let Some(s) = sig {
        query.push(("sig".into(), hex::encode(&s)));
    }
    Request { method: "POST".into(), path: "/api/v2/queue/send".into(), query, body: body.to_vec() }
}

fn frame(fill: u8) -> Vec<u8> {
    hex::encode(&vec![fill; 256]).into_bytes()
}

#[test]
fn reserved_names_need_the_owner_key() {
    let now = now_secs();
    let mut s = ServerState::ephemeral(cfg());
    for u in ["owner", "admin", "aegis", "support", "official", "0wner", "adm1n", "a_dmin", "supp0rt", "aeg1s", "off1cia1"] {
        assert_eq!(register(&mut s, &mallory(), u, now), 403, "{u}");
    }
    assert_eq!(register(&mut s, &mallory(), "mallory", now), 200);

    let mut s = ServerState::ephemeral(Config { owner_ed_pk: Some(owner().ed_public()), ..cfg() });
    assert_eq!(register(&mut s, &mallory(), "owner", now), 403);
    assert_eq!(register(&mut s, &owner(), "owner", now), 200);
}

#[test]
fn official_verify_has_no_trust_on_first_use() {
    let e = aegis_core::envelope::Envelope {
        kind: aegis_core::envelope::Kind::Cmsg,
        msg_id: "00112233445566778899aabbccddeeff".into(),
        sender: official::OFFICIAL_OWNER.into(),
        sender_name: "Aegis".into(),
        sender_ed: mallory().ed_public(),
        ts_ms: 1_700_000_000_000,
        ttl_s: 0,
        group_id: official::official_channel_id(),
        body: "install evil.apk".into(),
        group_key: None,
        members: vec![],
    };
    let frame = aegis_core::channel::seal_post(&official::official_g(), mallory().ed_secret(), &e).unwrap();
    // Whatever the directory says, nothing verifies without a compiled-in key.
    assert_eq!(official::owner_key(Some(mallory().ed_public())), official::OFFICIAL_OWNER_ED_PK);
    assert!(official::verify_with(None, &frame).is_err());
    assert!(official::verify_with(Some(owner().ed_public()), &frame).is_err());
    assert!(official::verify_with(Some(mallory().ed_public()), &frame).is_ok());
}

#[test]
fn official_queue_takes_only_owner_signed_posts() {
    let now = now_secs();
    let q = official::official_queue().unwrap();
    let body = frame(1);
    let raw = hex::decode(std::str::from_utf8(&body).unwrap()).unwrap();

    // No owner configured: closed.
    let mut s = ServerState::ephemeral(cfg());
    let sig = official::sign_post_auth(owner().ed_secret(), &q, now, &raw);
    assert_eq!(s.handle(&send_req(&q, &body, now, BITS, Some(sig)), now).status, 403);

    let mut s = ServerState::ephemeral(Config { owner_ed_pk: Some(owner().ed_public()), ..cfg() });
    assert_eq!(s.handle(&send_req(&q, &body, now, BITS, None), now).status, 403, "no signature");
    let bad = official::sign_post_auth(mallory().ed_secret(), &q, now, &raw);
    assert_eq!(s.handle(&send_req(&q, &body, now, BITS, Some(bad)), now).status, 403, "wrong key");
    let other_ts = official::sign_post_auth(owner().ed_secret(), &q, now + 1, &raw);
    assert_eq!(s.handle(&send_req(&q, &body, now, BITS, Some(other_ts)), now).status, 403, "other ts");
    let good = official::sign_post_auth(owner().ed_secret(), &q, now, &raw);
    assert_eq!(s.handle(&send_req(&q, &body, now, BITS, Some(good)), now).status, 200);
    assert_eq!(s.queue_len(&q), 1);

    // Other queues need no signature.
    let inbox = queue_ids::inbox_queue(&[9; 32]);
    assert_eq!(s.handle(&send_req(&inbox, &body, now, BITS, None), now).status, 200);
}

#[test]
fn fuller_queues_ask_for_more_work_and_say_how_much() {
    let now = now_secs();
    let mut s = ServerState::ephemeral(Config { max_frames_per_queue: 16, ..cfg() });
    let q = queue_ids::inbox_queue(&[0x42; 32]);
    // Up to half full (and a little beyond: 8 of 16 is still 50%) the base difficulty is enough.
    for i in 0..9u8 {
        assert_eq!(s.handle(&send_req(&q, &frame(i), now, BITS + 4, None), now).status, 200, "frame {i}");
    }
    // 9 of 16 = 56%: still the base. 10 of 16 = 62.5%: one extra bit.
    assert_eq!(s.handle(&send_req(&q, &frame(20), now, BITS, None), now).status, 200);
    // A proof that meets the base but not base+1 gets a 429 that names the bits wanted.
    let body = frame(21);
    let qh = hex::encode(&q);
    let bh = pow::body_hash_hex(&body);
    let n = (0u64..).find(|n| pow::verify(&qh, now, &bh, *n, BITS) && !pow::verify(&qh, now, &bh, *n, BITS + 1)).unwrap();
    let r = s.handle(
        &Request {
            method: "POST".into(),
            path: "/api/v2/queue/send".into(),
            query: vec![("q".into(), qh.clone()), ("ts".into(), now.to_string()), ("pow".into(), n.to_string())],
            body: body.clone(),
        },
        now,
    );
    assert_eq!(r.status, 429, "{}", r.body);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["bits"].as_u64(), Some(u64::from(BITS) + 1));
    // With the asked-for work it goes through.
    assert_eq!(s.handle(&send_req(&q, &body, now, BITS + 1, None), now).status, 200);
}

#[test]
fn flooding_a_public_queue_at_base_difficulty_stops_working() {
    // hack_crypto_3, inverted: junk mined only at the base difficulty cannot fill the queue.
    let now = now_secs();
    let mut s = ServerState::ephemeral(Config { max_frames_per_queue: 40, ..cfg() });
    let inbox = queue_ids::inbox_queue(&[0x42; 32]);
    let mut accepted = 0;
    for i in 0..40u32 {
        let ts = now - u64::from(i % 600);
        // pow::mine returns the first nonce that works, so the proof is just above base.
        if s.handle(&send_req(&inbox, &frame((i % 251) as u8), ts, BITS, None), now).status == 200 {
            accepted += 1;
        }
    }
    assert!(accepted < 40, "all {accepted} junk frames were accepted at base difficulty");
    assert!(s.queue_len(&inbox) < 40);
}

#[test]
fn poll_stops_at_the_response_cap_and_says_more() {
    let now = now_secs();
    let mut s = ServerState::ephemeral(cfg());
    let q = [0x55u8; 32];
    for i in 0..70u8 {
        let body = hex::encode(&aegis_core::pad::pad(&vec![i; 16_000]).unwrap()).into_bytes();
        let r = s.handle(&send_req(&q, &body, now - u64::from(i), BITS + 4, None), now);
        assert_eq!(r.status, 200, "{}", r.body);
    }
    let mut after = 0u64;
    let mut total = 0;
    let mut rounds = 0;
    loop {
        let r = s.handle(
            &Request {
                method: "GET".into(),
                path: "/api/v2/queue/poll".into(),
                query: vec![("q".into(), hex::encode(&q)), ("after".into(), after.to_string())],
                body: vec![],
            },
            now,
        );
        assert_eq!(r.status, 200);
        assert!(r.body.len() <= aegis_core::sealed::BUCKETS[6] - 6, "{} bytes", r.body.len());
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        total += v["frames"].as_array().unwrap().len();
        after = v["next"].as_u64().unwrap();
        rounds += 1;
        if !v["has_more"].as_bool().unwrap() {
            break;
        }
        assert!(rounds < 100);
    }
    assert_eq!(total, 70);
    assert!(rounds > 1);
}

#[test]
fn prekey_uploads_are_rate_limited_per_user() {
    let now = now_secs();
    let mut s = ServerState::ephemeral(cfg());
    let id = Identity::from_secrets([1; 32], [2; 32]);
    assert_eq!(register(&mut s, &id, "alice", now), 200);
    let put = |s: &mut ServerState, n: u8, at: u64| {
        let f = PrekeyPut::sign(&id, "alice", [3; 32], now - 5, vec![[n; 32]], at).unwrap().to_form();
        s.handle(
            &Request { method: "POST".into(), path: "/api/v2/prekeys/put".into(), query: vec![], body: f.into_bytes() },
            at,
        )
        .status
    };
    assert_eq!(put(&mut s, 1, now), 200);
    assert_eq!(put(&mut s, 2, now + 10), 429, "inside 60 s");
    let mut t = now;
    for n in 2..=5u8 {
        t += 61;
        assert_eq!(put(&mut s, n, t), 200, "put {n}");
    }
    t += 61;
    assert_eq!(put(&mut s, 6, t), 429, "sixth in the hour");
    t = now + 3601 + 61;
    assert_eq!(put(&mut s, 7, t), 200, "an hour later");
}
