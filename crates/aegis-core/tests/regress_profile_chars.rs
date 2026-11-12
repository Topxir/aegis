#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use aegis_core::profile::Profile;

#[test]
fn hidden_and_separator_characters_are_rejected() {
    for c in ['\u{061C}', '\u{2028}', '\u{2029}', '\u{E0041}', '\u{180E}', '\u{00AD}', '\u{206A}'] {
        assert!(Profile::parse(&format!("PF1\nbob{c}\nabout\nnone")).is_err(), "name accepts {:#x}", c as u32);
        assert!(Profile::parse(&format!("PF1\nbob\nab{c}out\nnone")).is_err(), "about accepts {:#x}", c as u32);
    }
    assert!(Profile::parse("PF1\nbob\nabout\nnone").is_ok());
}
