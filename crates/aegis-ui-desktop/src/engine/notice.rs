//! The text of new-message notifications, chosen by `crate::notify`.

use super::*;
use crate::i18n::tr;
use crate::notify::{note, Incoming, Note};

impl Engine {
    /// The notification for the latest message that asked for attention, if any.
    pub fn take_note(&self) -> Option<Note> {
        let mut app = self.app();
        if !std::mem::take(&mut app.attention) {
            return None;
        }
        let r = app.note.take();
        let l = app.lang();
        let generic = tr(l, "notify.new");
        let s = app.session.as_ref()?;
        let show = s.data.settings.notify_name;
        let found = r.and_then(|r| {
            let m = s
                .chat(&r)?
                .msgs
                .iter()
                .rev()
                .find(|m| !m.out && crate::timer::parse_line(&m.text).is_none())?;
            let name = |u: &str| {
                s.data
                    .contacts
                    .get(u)
                    .map(|c| sanitize_display_text(&c.name))
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| u.to_owned())
            };
            let (chat, sender) = match &r {
                ChatRef::Dm(u) => (name(u), None),
                ChatRef::Group(g) => (s.data.groups.get(g)?.title.clone(), Some(name(&m.from))),
                ChatRef::Channel(c) => (s.data.channels.get(c)?.title.clone(), None),
            };
            let text = match &m.media {
                Some(mr) if m.text.trim().is_empty() => {
                    tr(l, if mr.video { "media.video" } else { "media.photo" }).to_owned()
                }
                _ => m.text.clone(),
            };
            Some((chat, sender, text))
        });
        let (chat, sender, text) = found.unwrap_or_default();
        let m = Incoming {
            chat: &chat,
            sender: sender.as_deref(),
            text: &text,
        };
        Some(note(false, show, "Aegis", generic, &m))
    }
}
