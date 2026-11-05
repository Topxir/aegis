//! Profile text refuses bidi overrides and zero-width characters.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::profile::Profile;

#[test]
fn bidi_and_zero_width_rejected_in_profile() {
    for bad in ["PF1\nBob\u{202E}x\nabout\nnone", "PF1\nBob\nvisit \u{202E}moc.elgoog\nnone", "PF1\nB\u{200B}ob\nabout\nnone"] {
        assert!(Profile::parse(bad).is_err(), "accepted spoofing text {bad:?}");
    }
}
