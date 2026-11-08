#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_ui_desktop::bridges::{self, Mode, LYREBIRD_PATH, MAX_LINES, OBFS4, SNOWFLAKE};
use aegis_ui_desktop::connection::{endpoint_for, is_clearnet_entry};
use aegis_ui_desktop::i18n::Lang;
use aegis_ui_desktop::model::{Settings, DEFAULT_ENDPOINT, DEFAULT_ONION};

const WEBTUNNEL: &str = "webtunnel [2001:db8:3d87:60f1:6b2:5c2a:a1a7:4d5e]:443 4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A url=https://example.com/aBcD ver=0.0.1";

#[test]
fn off_writes_no_bridge_options() {
    assert_eq!(bridges::torrc(Mode::Off, WEBTUNNEL), "");
    assert_eq!(bridges::torrc_for(&Settings::new(Lang::En)), "");
}

#[test]
fn snowflake_uses_the_builtin_list_and_lyrebird() {
    let rc = bridges::torrc(Mode::Snowflake, "");
    let lines: Vec<&str> = rc.lines().collect();
    assert_eq!(lines[0], "UseBridges 1");
    assert_eq!(lines[1], format!("ClientTransportPlugin snowflake exec {LYREBIRD_PATH}"));
    assert_eq!(lines.len(), 2 + SNOWFLAKE.len());
    for (l, b) in lines[2..].iter().zip(SNOWFLAKE) {
        assert_eq!(*l, format!("Bridge {b}"));
    }
}

#[test]
fn obfs4_uses_the_builtin_list() {
    let rc = bridges::torrc(Mode::Obfs4, "");
    assert!(rc.starts_with("UseBridges 1\nClientTransportPlugin meek_lite,obfs4,webtunnel exec "));
    assert!(!rc.contains("snowflake"));
    assert_eq!(rc.matches("\nBridge obfs4 ").count(), OBFS4.len());
    for b in OBFS4 {
        assert_eq!(bridges::parse_line(b).as_deref(), Some(*b), "builtin lines pass the check");
    }
    for b in SNOWFLAKE {
        assert_eq!(bridges::parse_line(b).as_deref(), Some(*b));
    }
}

#[test]
fn custom_lines_are_checked_and_normalized() {
    let text = format!("  Bridge {WEBTUNNEL}\r\n\n# comment\n198.51.100.7:9001\t0123456789ABCDEF0123456789ABCDEF01234567\n{WEBTUNNEL}\n");
    let (mode, stored) = bridges::check("custom", &text).unwrap();
    assert_eq!(mode, Mode::Custom);
    assert_eq!(stored, format!("{WEBTUNNEL}\n198.51.100.7:9001 0123456789ABCDEF0123456789ABCDEF01234567"));
    let rc = bridges::torrc(mode, &stored);
    assert_eq!(
        rc,
        format!(
            "UseBridges 1\nClientTransportPlugin meek_lite,obfs4,webtunnel exec {LYREBIRD_PATH}\nBridge {WEBTUNNEL}\nBridge 198.51.100.7:9001 0123456789ABCDEF0123456789ABCDEF01234567\n"
        )
    );
    // Plain relays as bridges need no transport plugin.
    let rc = bridges::torrc(Mode::Custom, "203.0.113.5:443");
    assert_eq!(rc, "UseBridges 1\nBridge 203.0.113.5:443\n");
}

#[test]
fn bad_lines_are_refused_with_their_number() {
    for (text, n) in [
        ("obfs4 1.2.3.4 cert=x", "1"),
        ("\nobfs5 1.2.3.4:443", "2"),
        ("obfs4 1.2.3.4:0 cert=x", "1"),
        ("obfs4 example.com:443 cert=x", "1"),
        ("obfs4 1.2.3.4:443 cert", "1"),
        ("obfs4 1.2.3.4:443 =x", "1"),
        ("UseBridges 0", "1"),
        ("Socks5Proxy 127.0.0.1:1", "1"),
        ("1.2.3.4:443 key=value", "1"),
        ("obfs4 1.2.3.4:443 cert=\u{7f}", "1"),
        ("obfs4 1.2.3.4:443 cert=\u{0}x", "1"),
        ("obfs4 1.2.3.4:443 cert=\u{442}", "1"),
    ] {
        let f = bridges::check("custom", text).unwrap_err();
        assert_eq!((f.key, f.detail.as_str()), ("err.bridge_line", n), "{text:?}");
    }
    assert_eq!(bridges::check("custom", "  \n# only a comment").unwrap_err().key, "err.bridges_empty");
    assert_eq!(bridges::check("nonsense", "").unwrap_err().key, "err.generic");
    let many: String = (0..=MAX_LINES).map(|i| format!("203.0.113.{i}:443\n")).collect();
    assert_eq!(bridges::check("custom", &many).unwrap_err().key, "err.bridges_many");
    let long = format!("obfs4 1.2.3.4:443 cert={}", "a".repeat(bridges::MAX_LINE));
    assert!(bridges::parse_line(&long).is_none());
}

#[test]
fn stored_text_cannot_inject_torrc_options() {
    // A stored value that skipped the check on save (an edited vault, an old version).
    let evil = "obfs4 1.2.3.4:443 cert=x\nSocksPort 0.0.0.0:9050\nobfs4 1.2.3.4:443 cert=x\rExitNodes {ru}\nBridge 5.6.7.8:443\n%include C:\\x";
    let rc = bridges::torrc(Mode::Custom, evil);
    for line in rc.lines() {
        let ok = line == "UseBridges 1" || line.starts_with("ClientTransportPlugin ") || line.starts_with("Bridge ");
        assert!(ok, "unexpected torrc line {line:?}");
    }
    assert!(!rc.contains("SocksPort") && !rc.contains("ExitNodes") && !rc.contains("%include"));
    assert!(rc.contains("Bridge 5.6.7.8:443\n"));
    let mut st = Settings::new(Lang::En);
    st.bridges = "custom".into();
    st.bridge_lines = evil.into();
    assert_eq!(bridges::torrc_for(&st), rc);
    st.bridges = "garbage".into();
    assert_eq!(bridges::torrc_for(&st), "");
}

#[test]
fn clearnet_entry_is_never_used_with_tor() {
    assert_eq!(endpoint_for(DEFAULT_ENDPOINT, true).unwrap(), DEFAULT_ONION);
    assert_eq!(endpoint_for(&format!("{DEFAULT_ENDPOINT}/"), true).unwrap(), DEFAULT_ONION);
    assert_eq!(endpoint_for("HTTPS://FreeOasis.Space:443", true).unwrap(), DEFAULT_ONION);
    for ep in ["https://www.freeoasis.space", "https://api.freeoasis.space:8443", "https://freeoasis.space:8443"] {
        assert!(is_clearnet_entry(ep), "{ep}");
        assert_eq!(endpoint_for(ep, true).unwrap_err().key, "err.clearnet_tor", "{ep}");
    }
    assert!(!is_clearnet_entry("https://notfreeoasis.space"));
    assert!(!is_clearnet_entry(DEFAULT_ONION));
    assert_eq!(endpoint_for("https://other.example", true).unwrap(), "https://other.example");
    // Without Tor the clearnet entry is allowed: the user confirmed turning Tor off.
    assert_eq!(endpoint_for(DEFAULT_ONION, false).unwrap(), DEFAULT_ENDPOINT);
    assert_eq!(endpoint_for("https://www.freeoasis.space", false).unwrap(), "https://www.freeoasis.space");
}

#[test]
fn every_tor_route_skips_the_clearnet_host() {
    let host = aegis_core::net::Endpoint::parse(DEFAULT_ENDPOINT).unwrap().host;
    let mut st = Settings::new(Lang::En);
    assert!(st.tor, "Tor is on by default");
    for ep in [DEFAULT_ENDPOINT, "https://freeoasis.space/", DEFAULT_ONION] {
        st.endpoint = ep.into();
        let routed = endpoint_for(&st.endpoint, st.tor).unwrap();
        let h = aegis_core::net::Endpoint::parse(&routed).unwrap().host;
        assert_ne!(h, host);
        assert!(h.ends_with(".onion"));
    }
}
