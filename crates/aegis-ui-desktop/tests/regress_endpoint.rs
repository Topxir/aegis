#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The default server keeps its compiled key however its address is spelled, and a key pinned
//! for one spelling of an endpoint still belongs to the others.
use aegis_core::net::{DEFAULT_SERVER_URL, DEFAULT_SERVER_X_PK};
use aegis_ui_desktop::i18n::Lang;
use aegis_ui_desktop::model::{normalize_endpoint, same_endpoint, Settings, DEFAULT_ENDPOINT};

#[test]
fn default_endpoint_and_key_come_from_core() {
    assert_eq!(DEFAULT_ENDPOINT, DEFAULT_SERVER_URL);
    let mut st = Settings::new(Lang::En);
    st.server_key = Some([3; 32]);
    st.server_key_for.clone_from(&st.endpoint);
    for e in ["https://freeoasis.space", "https://freeoasis.space/", "HTTPS://FreeOasis.Space/", "https://freeoasis.space:443"] {
        st.endpoint = e.into();
        assert_eq!(st.pinned_key(), DEFAULT_SERVER_X_PK, "{e}");
    }
}

#[test]
fn endpoints_compare_after_normalizing() {
    assert_eq!(normalize_endpoint("  HTTPS://Example.ORG/ "), "https://example.org");
    assert!(same_endpoint("https://a.example", "HTTPS://A.Example/"));
    assert!(same_endpoint("https://a.example", "https://a.example:443"));
    assert!(!same_endpoint("https://a.example", "https://b.example"));
    assert!(!same_endpoint("https://a.example", "http://a.example"));
    let mut st = Settings::new(Lang::En);
    st.server_key = Some([5; 32]);
    st.server_key_for = "https://a.example".into();
    st.endpoint = "HTTPS://A.EXAMPLE/".into();
    assert_eq!(st.pinned_key(), Some([5; 32]));
    st.endpoint = "https://b.example".into();
    assert!(st.pinned_key().is_none());
}
