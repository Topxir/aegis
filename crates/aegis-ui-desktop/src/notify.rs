//! What a new-message notification may show. Nothing here touches the system.

use crate::model::clean_text;

/// Longest notification text, in characters.
pub const MAX_BODY: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub title: String,
    pub body: String,
}

/// The message a notification is about.
#[derive(Debug, Clone, Copy)]
pub struct Incoming<'a> {
    /// Name of the chat: the contact, group or channel.
    pub chat: &'a str,
    /// Sender inside a group, `None` in direct chats and channels.
    pub sender: Option<&'a str>,
    /// Message text, or the attachment label when there is no caption.
    pub text: &'a str,
}

/// The notification for `m`. Unless content is allowed and the app is unlocked it is the
/// same for every message: the app name and `generic`, with no sender and no text.
pub fn note(locked: bool, show_content: bool, app: &str, generic: &str, m: &Incoming) -> Note {
    if locked || !show_content {
        return Note {
            title: app.to_owned(),
            body: generic.to_owned(),
        };
    }
    let text = one_line(m.text);
    let body = match m.sender {
        Some(s) => format!("{}: {text}", one_line(s)),
        None => text,
    };
    let title = one_line(m.chat);
    Note {
        title: if title.is_empty() { app.to_owned() } else { title },
        body: if body.is_empty() {
            generic.to_owned()
        } else {
            shorten(&body)
        },
    }
}

fn one_line(s: &str) -> String {
    clean_text(s).split_whitespace().collect::<Vec<_>>().join(" ")
}

fn shorten(s: &str) -> String {
    if s.chars().count() <= MAX_BODY {
        return s.to_owned();
    }
    let mut t: String = s.chars().take(MAX_BODY - 1).collect();
    t.push('\u{2026}');
    t
}
