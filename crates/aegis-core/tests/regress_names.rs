#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use aegis_core::senderkey::{RecvSet, Scope};
use aegis_core::session::SessionStore;

#[test]
fn long_contact_name_is_refused_and_state_still_decodes() {
    let mut st = SessionStore::new();
    st.add_contact("alice", [1; 32], [2; 32]).unwrap();
    assert!(st.add_contact(&"a".repeat(300), [3; 32], [4; 32]).is_err());
    assert!(SessionStore::decode(&st.encode()).is_ok());
}

#[test]
fn long_sender_name_is_refused_and_state_still_decodes() {
    let mut rs = RecvSet::new(Scope::Group, &[9; 32], None).unwrap();
    assert!(rs.add_chain(&"m".repeat(256), [5; 32], [6; 16], 0, &[7; 32], 1).is_err());
    rs.add_chain(&"m".repeat(255), [5; 32], [6; 16], 0, &[7; 32], 1).unwrap();
    assert!(RecvSet::decode(&rs.encode()).is_ok());
}
