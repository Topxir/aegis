#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use aegis_ui_desktop::notify::{note, Incoming, Note, MAX_BODY};

const DM: Incoming = Incoming {
    chat: "Bob",
    sender: None,
    text: "meet at nine",
};

fn generic() -> Note {
    Note {
        title: "Aegis".into(),
        body: "New message".into(),
    }
}

#[test]
fn hidden_unless_allowed_and_unlocked() {
    assert_eq!(note(true, true, "Aegis", "New message", &DM), generic());
    assert_eq!(note(false, false, "Aegis", "New message", &DM), generic());
    assert_eq!(note(true, false, "Aegis", "New message", &DM), generic());
    let shown = note(false, true, "Aegis", "New message", &DM);
    assert_eq!(shown.title, "Bob");
    assert_eq!(shown.body, "meet at nine");
}

#[test]
fn group_names_the_sender_and_text_is_one_short_line() {
    let long = "x".repeat(500);
    let g = Incoming {
        chat: "trio",
        sender: Some("Carol\n"),
        text: &long,
    };
    let n = note(false, true, "Aegis", "New message", &g);
    assert_eq!(n.title, "trio");
    assert!(n.body.starts_with("Carol: xxx"));
    assert_eq!(n.body.chars().count(), MAX_BODY);
    assert!(n.body.ends_with('\u{2026}'));

    let odd = Incoming {
        chat: "\u{202E}Eve",
        sender: None,
        text: "line one\nline\u{0}two",
    };
    let n = note(false, true, "Aegis", "New message", &odd);
    assert_eq!(n.title, "Eve");
    assert_eq!(n.body, "line one linetwo");
}

#[test]
fn empty_parts_fall_back_to_generic() {
    let m = Incoming {
        chat: "",
        sender: None,
        text: "  ",
    };
    assert_eq!(note(false, true, "Aegis", "New message", &m), generic());
}
