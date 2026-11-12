use aegis_core::envelope::{Envelope, Kind};
use aegis_core::identity::Identity;
use aegis_core::session::{Encrypted, Received, SessionStore};
use aegis_core::x3dh::Bundle;

#[allow(dead_code)]
const T0: u64 = 1_700_000_000;
#[allow(dead_code)]
const DAY: u64 = 24 * 3600;

#[allow(dead_code)]
struct Side {
    id: Identity,
    store: SessionStore,
    name: &'static str,
}

#[allow(dead_code)]
fn side(name: &'static str, x: u8, ed: u8) -> Side {
    Side { id: Identity::from_secrets([x; 32], [ed; 32]), store: SessionStore::new(), name }
}

#[allow(dead_code)]
fn pair() -> (Side, Side) {
    let (mut a, mut b) = (side("alice", 1, 2), side("bob", 3, 4));
    a.store.add_contact("bob", b.id.ed_public(), b.id.x_public()).unwrap();
    b.store.add_contact("alice", a.id.ed_public(), a.id.x_public()).unwrap();
    (a, b)
}

#[allow(dead_code)]
fn env_from(s: &Side, body: &str) -> Envelope {
    Envelope {
        kind: Kind::Dm,
        msg_id: aegis_core::envelope::random_msg_id().unwrap(),
        sender: s.name.into(),
        sender_name: s.name.into(),
        sender_ed: s.id.ed_public(),
        ts_ms: 1,
        ttl_s: 0,
        group_id: String::new(),
        body: body.into(),
        group_key: None,
        members: vec![],
    }
}

#[allow(dead_code)]
fn bundle_for(b: &mut Side, now: u64) -> Bundle {
    let put = b.store.prepare_prekeys(&b.id, b.name, now, Some(0)).unwrap();
    Bundle { spk: put.spk, spk_ts: put.spk_ts, spk_sig: put.spk_sig, opk: put.opks.first().copied() }
}

#[allow(dead_code)]
fn send(from: &mut Side, to: &str, body: &str, now: u64) -> Vec<u8> {
    let e = env_from(from, body);
    match from.store.encrypt(&from.id, to, &e, now).unwrap() {
        Encrypted::Frame(f) => f,
        Encrypted::NeedsPrekeys => panic!("needs prekeys"),
    }
}

#[allow(dead_code)]
fn recv(to: &mut Side, frame: &[u8], now: u64) -> Received {
    to.store.decrypt(&to.id, frame, now).unwrap()
}
