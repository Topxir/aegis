#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::directory::Registration;
use aegis_core::identity::Identity;
use aegis_core::invite::{self, Hide, InviteCreate, BOX_LEN, INVITE_TTL_SECS, MAX_OPEN_INVITES};
use aegis_core::prekeys::{PrekeyPut, PrekeyTake};
use aegis_core::{hex, now_secs};
use aegis_server::{persist_now, Config, Request, ServerState, STATE_FILE};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

const BITS: u32 = 6;
static COUNTER: AtomicU32 = AtomicU32::new(0);
static TS: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("aegis-invites-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn state(&self) -> Vec<u8> {
        std::fs::read(self.0.join(STATE_FILE)).unwrap()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cfg() -> Config {
    Config { pow_bits: BITS, prekey_put_interval_secs: 0, prekey_puts_per_hour: 0, ..Config::default() }
}

fn open(dir: &TempDir) -> Mutex<ServerState> {
    Mutex::new(ServerState::open_with(&dir.0, cfg()).unwrap())
}

fn alice() -> Identity {
    Identity::from_secrets([1; 32], [2; 32])
}

fn bob() -> Identity {
    Identity::from_secrets([3; 32], [4; 32])
}

/// A timestamp inside the window that no earlier call used, so signed requests are not replays.
fn ts(now: u64) -> u64 {
    now - TS.fetch_add(1, Ordering::SeqCst) % 500
}

fn call(s: &Mutex<ServerState>, method: &str, path: &str, query: &str, body: &str, now: u64) -> (u16, String) {
    let query = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap();
            (k.to_owned(), v.to_owned())
        })
        .collect();
    let req = Request { method: method.into(), path: path.into(), query, body: body.as_bytes().to_vec() };
    let r = s.lock().unwrap().handle(&req, now);
    (r.status, r.body)
}

fn post(s: &Mutex<ServerState>, path: &str, body: &str, now: u64) -> (u16, String) {
    call(s, "POST", path, "", body, now)
}

fn register_as(s: &Mutex<ServerState>, identity: &Identity, u: &str, title: &str, now: u64) -> u16 {
    let mut reg = Registration::sign(identity, u, title, ts(now)).unwrap();
    reg.mine(BITS);
    post(s, "/api/v2/dir/register", &reg.to_form(), now).0
}

fn lookup(s: &Mutex<ServerState>, u: &str, now: u64) -> (u16, String) {
    call(s, "GET", "/api/v2/dir/lookup", &format!("u={u}"), "", now)
}

fn create(s: &Mutex<ServerState>, identity: &Identity, u: &str, secret: &[u8; 32], now: u64) -> (u16, String) {
    let c = InviteCreate::sign(identity, u, secret, ts(now)).unwrap();
    post(s, "/api/v2/invite/create", &c.to_form(), now)
}

fn redeem(s: &Mutex<ServerState>, secret: &[u8; 32], now: u64) -> (u16, String) {
    post(s, "/api/v2/invite/redeem", &invite::id_form(&invite::invite_id(secret)), now)
}

fn revoke(s: &Mutex<ServerState>, secret: &[u8; 32], now: u64) -> u16 {
    post(s, "/api/v2/invite/revoke", &invite::id_form(&invite::invite_id(secret)), now).0
}

fn hide(s: &Mutex<ServerState>, identity: &Identity, u: &str, hidden: bool, now: u64) -> (u16, String) {
    post(s, "/api/v2/dir/hide", &Hide::sign(identity, u, hidden, ts(now)).unwrap().to_form(), now)
}

fn take(s: &Mutex<ServerState>, u: &str, ed: Option<[u8; 32]>, now: u64) -> (u16, String) {
    let mut t = PrekeyTake::mine(u, ts(now), BITS);
    if let Some(ed) = ed {
        t = t.with_ed(ed);
    }
    post(s, "/api/v2/prekeys/take", &t.to_form(), now)
}

fn put(s: &Mutex<ServerState>, identity: &Identity, u: &str, now: u64) -> (u16, String) {
    let p = PrekeyPut::sign(identity, u, [9; 32], now, vec![[10; 32]], ts(now)).unwrap();
    post(s, "/api/v2/prekeys/put", &p.to_form(), now)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn setup() -> (TempDir, Mutex<ServerState>, u64) {
    let d = TempDir::new();
    let s = open(&d);
    let now = now_secs();
    assert_eq!(register_as(&s, &alice(), "alice", "", now), 200);
    (d, s, now)
}

#[test]
fn invite_redeems_once_and_gives_the_bundle() {
    let (_d, s, now) = setup();
    let secret = [42u8; 32];
    assert_eq!(create(&s, &alice(), "alice", &secret, now).0, 200);
    let (c, body) = redeem(&s, &secret, now);
    assert_eq!(c, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let sealed = hex::decode(v["box"].as_str().unwrap()).unwrap();
    let b = invite::open_bundle(&secret, &sealed).unwrap();
    assert_eq!((b.u.as_str(), b.x, b.ed), ("alice", alice().x_public(), alice().ed_public()));
    // a second use, an unknown id and a revoked id all answer the same
    let used = redeem(&s, &secret, now);
    assert_eq!(used.0, 404);
    assert_eq!(used, redeem(&s, &[43; 32], now));
    let other = [44u8; 32];
    assert_eq!(create(&s, &alice(), "alice", &other, now).0, 200);
    assert_eq!(revoke(&s, &other, now), 200);
    assert_eq!(used, redeem(&s, &other, now));
    // revoking something unknown is no oracle either
    assert_eq!(revoke(&s, &[0; 32], now), 200);
    // the same id cannot be created twice
    assert_eq!(create(&s, &alice(), "alice", &[45; 32], now).0, 200);
    assert_eq!(create(&s, &alice(), "alice", &[45; 32], now).0, 409);
    // a used or revoked id stays taken, so nobody can put another bundle under it
    assert_eq!(register_as(&s, &bob(), "bob", "", now), 200);
    assert_eq!(create(&s, &bob(), "bob", &secret, now).0, 409);
    assert_eq!(create(&s, &bob(), "bob", &other, now).0, 409);
}

#[test]
fn a_used_id_stays_taken_after_a_restart_until_it_expires() {
    let d = TempDir::new();
    let now = now_secs();
    let secret = [6u8; 32];
    {
        let s = open(&d);
        assert_eq!(register_as(&s, &alice(), "alice", "", now), 200);
        assert_eq!(register_as(&s, &bob(), "bob", "", now), 200);
        assert_eq!(create(&s, &alice(), "alice", &secret, now).0, 200);
        assert_eq!(redeem(&s, &secret, now).0, 200);
        persist_now(&s).unwrap();
    }
    let s = open(&d);
    assert_eq!(redeem(&s, &secret, now).0, 404);
    assert_eq!(create(&s, &bob(), "bob", &secret, now).0, 409);
    let later = now + INVITE_TTL_SECS + 3600;
    s.lock().unwrap().purge(later);
    assert_eq!(create(&s, &bob(), "bob", &secret, later).0, 200);
}

#[test]
fn single_use_survives_a_restart() {
    let d = TempDir::new();
    let now = now_secs();
    let secret = [7u8; 32];
    {
        let s = open(&d);
        assert_eq!(register_as(&s, &alice(), "alice", "", now), 200);
        assert_eq!(create(&s, &alice(), "alice", &secret, now).0, 200);
        persist_now(&s).unwrap();
    }
    {
        let s = open(&d);
        assert_eq!(redeem(&s, &secret, now).0, 200);
        persist_now(&s).unwrap();
    }
    let s = open(&d);
    assert_eq!(redeem(&s, &secret, now).0, 404);
}

#[test]
fn invite_expires_after_seven_days_without_a_write() {
    let (d, s, now) = setup();
    let secret = [8u8; 32];
    assert_eq!(create(&s, &alice(), "alice", &secret, now).0, 200);
    persist_now(&s).unwrap();
    let before = d.state();
    let later = now + INVITE_TTL_SECS + 3600;
    let expired = redeem(&s, &secret, later);
    assert_eq!(expired.0, 404);
    assert_eq!(expired, redeem(&s, &[9; 32], later));
    persist_now(&s).unwrap();
    assert_eq!(d.state(), before, "an expired redeem changes nothing");
    // still valid just before the end
    let fresh = [10u8; 32];
    assert_eq!(create(&s, &alice(), "alice", &fresh, now).0, 200);
    assert_eq!(redeem(&s, &fresh, now + INVITE_TTL_SECS - 1).0, 200);
    // purge drops expired records
    s.lock().unwrap().purge(later);
    persist_now(&s).unwrap();
    assert!(!contains(&d.state(), &invite::invite_id(&secret)));
}

#[test]
fn server_keeps_only_the_hash_and_the_sealed_box() {
    let (d, s, now) = setup();
    assert_eq!(register_as(&s, &bob(), "bobthebuilder", "", now), 200);
    let secret = [0x5a; 32];
    assert_eq!(create(&s, &bob(), "bobthebuilder", &secret, now).0, 200);
    persist_now(&s).unwrap();
    let st = d.state();
    let id = invite::invite_id(&secret);
    assert!(!contains(&st, &secret));
    assert!(!contains(&st, hex::encode(&secret).as_bytes()));
    // record layout: id, expiry, length, box; nothing ties it to the inviter
    let at = st.windows(32).position(|w| w == id).unwrap() + 32;
    let exp = u64::from_be_bytes(st[at..at + 8].try_into().unwrap());
    assert_eq!(exp % 3600, 0, "expiry is rounded to the hour");
    assert!(exp >= now + INVITE_TTL_SECS && exp < now + INVITE_TTL_SECS + 3600);
    let len = u32::from_be_bytes(st[at + 8..at + 12].try_into().unwrap()) as usize;
    assert_eq!(len, BOX_LEN);
    let sealed = &st[at + 12..at + 12 + len];
    assert!(!contains(sealed, b"bobthebuilder"));
    assert!(!contains(sealed, &bob().ed_public()));
    assert_eq!(invite::open_bundle(&secret, sealed).unwrap().u, "bobthebuilder");
    // the name occurs once: in its directory entry
    assert_eq!(st.windows(13).filter(|w| *w == b"bobthebuilder").count(), 1);
}

#[test]
fn open_invites_are_capped_per_user_and_revoke_frees_nothing() {
    let (_d, s, now) = setup();
    for i in 0..MAX_OPEN_INVITES {
        let secret = [u8::try_from(i).unwrap() + 100; 32];
        assert_eq!(create(&s, &alice(), "alice", &secret, now).0, 200);
        assert_eq!(revoke(&s, &secret, now), 200);
    }
    assert_eq!(create(&s, &alice(), "alice", &[1; 32], now).0, 429);
    // another user is not affected
    assert_eq!(register_as(&s, &bob(), "bob", "", now), 200);
    assert_eq!(create(&s, &bob(), "bob", &[2; 32], now).0, 200);
    // the window slides
    let later = now + INVITE_TTL_SECS + 86_400;
    assert_eq!(create(&s, &alice(), "alice", &[3; 32], later).0, 200);
}

#[test]
fn invite_create_needs_the_owner_key() {
    let (_d, s, now) = setup();
    let wrong = create(&s, &bob(), "alice", &[1; 32], now);
    assert_eq!(wrong.0, 403);
    assert_eq!(wrong, create(&s, &bob(), "nobody", &[1; 32], now), "an unknown user looks like a bad signature");
    assert_eq!(redeem(&s, &[1; 32], now).0, 404);
}

#[test]
fn invites_never_touch_the_directory() {
    let (_d, s, now) = setup();
    let secret = [11u8; 32];
    assert_eq!(create(&s, &alice(), "alice", &secret, now).0, 200);
    assert_eq!(redeem(&s, &secret, now).0, 200);
    // the redeemer still has no name, and the normal path gives one
    assert_eq!(lookup(&s, "bob", now).0, 404);
    assert_eq!(register_as(&s, &bob(), "bob", "", now), 200);
    let (c, body) = lookup(&s, "alice", now);
    assert_eq!(c, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ed"], hex::encode(&alice().ed_public()));
}

#[test]
fn one_name_per_server_and_one_name_per_key() {
    let (_d, s, now) = setup();
    // a name taken by another key
    assert_eq!(register_as(&s, &bob(), "alice", "", now), 409);
    // a second name for the same key
    assert_eq!(register_as(&s, &alice(), "alice2", "", now), 409);
    assert_eq!(lookup(&s, "alice2", now).0, 404);
    // the same pair may register again
    assert_eq!(register_as(&s, &alice(), "alice", "", now), 200);
    assert_eq!(register_as(&s, &bob(), "bob", "", now), 200);
    assert_eq!(register_as(&s, &bob(), "bob2", "", now), 409);
}

#[test]
fn one_name_per_key_survives_a_restart() {
    let d = TempDir::new();
    let now = now_secs();
    {
        let s = open(&d);
        assert_eq!(register_as(&s, &alice(), "alice", "", now), 200);
        persist_now(&s).unwrap();
    }
    let s = open(&d);
    assert_eq!(register_as(&s, &alice(), "carol", "", now), 409);
    assert_eq!(register_as(&s, &alice(), "alice", "", now), 200);
}

#[test]
fn titles_are_ignored_and_never_stored() {
    let (d, s, now) = setup();
    assert_eq!(register_as(&s, &bob(), "bob", "Bob Secretname", now), 200);
    let (c, body) = lookup(&s, "bob", now);
    assert_eq!(c, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["title"], "");
    persist_now(&s).unwrap();
    assert!(!contains(&d.state(), b"Secretname"));
}

fn legacy_v3(entries: &[(&str, &str, &Identity)]) -> Vec<u8> {
    let mut o = b"AEGSRV03".to_vec();
    o.extend_from_slice(&1u64.to_be_bytes());
    o.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
    for (u, title, id) in entries {
        o.extend_from_slice(&u32::try_from(u.len()).unwrap().to_be_bytes());
        o.extend_from_slice(u.as_bytes());
        o.extend_from_slice(&u32::try_from(title.len()).unwrap().to_be_bytes());
        o.extend_from_slice(title.as_bytes());
        o.extend_from_slice(&id.x_public());
        o.extend_from_slice(&id.ed_public());
    }
    o.extend_from_slice(&0u32.to_be_bytes()); // pins
    o.extend_from_slice(&0u32.to_be_bytes()); // queues
    o
}

#[test]
fn old_state_loads_without_titles_and_keeps_legacy_double_names() {
    let d = TempDir::new();
    let now = now_secs();
    let old = legacy_v3(&[("alice", "Alice Oldtitle", &alice()), ("alice2", "Second", &alice())]);
    std::fs::write(d.0.join(STATE_FILE), old).unwrap();
    {
        let s = open(&d);
        for u in ["alice", "alice2"] {
            let (c, body) = lookup(&s, u, now);
            assert_eq!(c, 200, "{u}");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["title"], "");
            // both legacy names keep working for their key
            assert_eq!(register_as(&s, &alice(), u, "", now), 200);
        }
        assert_eq!(register_as(&s, &alice(), "alice3", "", now), 409);
        persist_now(&s).unwrap();
    }
    let st = d.state();
    assert_eq!(&st[..8], b"AEGSRV05");
    assert!(!contains(&st, b"Oldtitle"));
    assert!(!contains(&st, b"Second"));
    let s = open(&d);
    assert_eq!(lookup(&s, "alice2", now).0, 200);
}

#[test]
fn hidden_profile_is_indistinguishable_from_unknown() {
    let (_d, s, now) = setup();
    assert_eq!(put(&s, &alice(), "alice", now).0, 200);
    assert_eq!(hide(&s, &alice(), "alice", true, now).0, 200);
    let hidden = lookup(&s, "alice", now);
    assert_eq!(hidden.0, 404);
    assert_eq!(hidden, lookup(&s, "nobody", now));
    // prekeys without the key, or with a wrong one: as unknown
    assert_eq!(take(&s, "alice", None, now).0, 404);
    assert_eq!(take(&s, "alice", None, now), take(&s, "nobody", None, now));
    let wrong = Some(bob().ed_public());
    assert_eq!(take(&s, "alice", wrong, now), take(&s, "nobody", wrong, now));
    // an existing contact knows the key and still gets prekeys
    assert_eq!(take(&s, "alice", Some(alice().ed_public()), now).0, 200);
    // signed routes answer a stranger the same for hidden and unknown names
    assert_eq!(put(&s, &bob(), "alice", now), put(&s, &bob(), "nobody", now));
    assert_eq!(hide(&s, &bob(), "alice", true, now), hide(&s, &bob(), "nobody", true, now));
    assert_eq!(create(&s, &bob(), "alice", &[1; 32], now), create(&s, &bob(), "nobody", &[1; 32], now));
    // the owner keeps full use
    assert_eq!(put(&s, &alice(), "alice", now).0, 200);
    let secret = [12u8; 32];
    assert_eq!(create(&s, &alice(), "alice", &secret, now).0, 200);
    assert_eq!(redeem(&s, &secret, now).0, 200);
    // the setting survives re-registration and can be turned off
    assert_eq!(register_as(&s, &alice(), "alice", "", now), 200);
    assert_eq!(lookup(&s, "alice", now).0, 404);
    assert_eq!(hide(&s, &alice(), "alice", false, now).0, 200);
    assert_eq!(lookup(&s, "alice", now).0, 200);
}

#[test]
fn hidden_flag_survives_a_restart() {
    let d = TempDir::new();
    let now = now_secs();
    {
        let s = open(&d);
        assert_eq!(register_as(&s, &alice(), "alice", "", now), 200);
        assert_eq!(hide(&s, &alice(), "alice", true, now).0, 200);
        persist_now(&s).unwrap();
    }
    let s = open(&d);
    assert_eq!(lookup(&s, "alice", now).0, 404);
    assert_eq!(lookup(&s, "alice", now), lookup(&s, "nobody", now));
}

#[test]
fn signed_requests_cannot_be_replayed() {
    let (_d, s, now) = setup();
    let h = Hide::sign(&alice(), "alice", true, now).unwrap().to_form();
    assert_eq!(post(&s, "/api/v2/dir/hide", &h, now).0, 200);
    assert_eq!(post(&s, "/api/v2/dir/hide", &h, now).0, 403);
    let c = InviteCreate::sign(&alice(), "alice", &[13; 32], now).unwrap().to_form();
    assert_eq!(post(&s, "/api/v2/invite/create", &c, now).0, 200);
    assert_eq!(post(&s, "/api/v2/invite/create", &c, now).0, 403);
}

#[test]
fn server_has_no_membership_routes() {
    let (_d, s, now) = setup();
    for path in ["/api/v2/group/members", "/api/v2/group/lookup", "/api/v2/dir/members"] {
        assert_eq!(call(&s, "GET", path, "", "", now).0, 404, "{path}");
        assert_eq!(post(&s, path, "", now).0, 404, "{path}");
    }
}
