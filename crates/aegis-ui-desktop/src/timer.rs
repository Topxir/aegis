//! Disappearing-message timers (spec section 5.2): the `ttl` and `gttl` control messages
//! and the local line that records each change in the chat.

use crate::model::{Msg, MsgState};
use crate::session::{ChainDraft, ChatRef, Draft, Failure, Outcome, Sendable, Session};
use aegis_core::envelope::{random_msg_id, ttl_allowed, Envelope, Kind};

/// Text of the local timer line. Like `UNDECRYPTABLE` it starts with a control character,
/// which network text never contains, so a real message cannot imitate it.
const PREFIX: &str = "\u{1}ttl:";

pub fn line(ttl_s: u64) -> String {
    format!("{PREFIX}{ttl_s}")
}

/// The timer value of a local timer line, `None` for any other text.
pub fn parse_line(text: &str) -> Option<u64> {
    text.strip_prefix(PREFIX)?
        .parse()
        .ok()
        .filter(|t| ttl_allowed(*t))
}

impl Session {
    /// Sets the timer of a direct chat or group and returns the control message for the
    /// other side, or `None` when nothing changed.
    pub fn change_ttl(
        &mut self,
        r: &ChatRef,
        ttl_s: u64,
        now_ms: u64,
    ) -> Result<Option<Sendable>, Failure> {
        if !ttl_allowed(ttl_s) {
            return Err(Failure::new("err.generic"));
        }
        let chat = self.chat(r).ok_or(Failure::new("err.generic"))?;
        if chat.ttl_s == ttl_s {
            return Ok(None);
        }
        // Later than any change applied here, so the other side cannot rank it below that one.
        let now_ms = now_ms.max(chat.ttl_ms.saturating_add(1));
        let id = random_msg_id()?;
        let out = match r {
            ChatRef::Dm(to) => {
                if !self.data.contacts.contains_key(to) {
                    return Err(Failure::new("err.no_contact"));
                }
                let env = self.own_envelope(Kind::Ttl, id.clone(), now_ms, ttl_s);
                Sendable::Draft(Draft {
                    to: to.clone(),
                    env,
                })
            }
            ChatRef::Group(gid) => {
                let mut env = self.own_envelope(Kind::Gttl, id.clone(), now_ms, ttl_s);
                env.group_id = gid.clone();
                Sendable::Chain(ChainDraft {
                    id: gid.clone(),
                    env,
                })
            }
            ChatRef::Channel(_) => return Err(Failure::new("err.channel_readonly")),
        };
        self.seen.insert(&id);
        let me = self.data.username.clone();
        self.apply_ttl(r, id, me, true, ttl_s, now_ms, now_ms);
        Ok(Some(out))
    }

    /// Applies a verified `ttl` or `gttl` from the other side. A change older than the
    /// last one applied is ignored, so crossing changes end with the newer one everywhere.
    pub(crate) fn accept_ttl(&mut self, r: ChatRef, env: &Envelope, now_ms: u64) -> Outcome {
        if !ttl_allowed(env.ttl_s) {
            return Outcome::Dropped;
        }
        let Some(chat) = self.chat_mut(&r) else {
            return Outcome::Dropped;
        };
        if env.ts_ms < chat.ttl_ms {
            return Outcome::Dropped;
        }
        if chat.ttl_s == env.ttl_s {
            chat.ttl_ms = env.ts_ms;
            return Outcome::Dropped;
        }
        let (id, from) = (env.msg_id.clone(), env.sender.clone());
        self.apply_ttl(&r, id, from, false, env.ttl_s, env.ts_ms, now_ms);
        Outcome::Timer(r)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_ttl(
        &mut self,
        r: &ChatRef,
        id: String,
        from: String,
        out: bool,
        ttl_s: u64,
        ts_ms: u64,
        now_ms: u64,
    ) {
        let Some(chat) = self.chat_mut(r) else {
            return;
        };
        chat.ttl_s = ttl_s;
        chat.ttl_ms = ts_ms;
        chat.push(Msg {
            id,
            from,
            ts_ms,
            ttl_s: 0,
            text: line(ttl_s),
            out,
            state: MsgState::Sent,
            media: None,
            base_ms: now_ms,
        });
        self.dirty = true;
    }

    /// Removes expired messages and returns the stored files only they referred to.
    pub fn sweep_files(&mut self, now_ms: u64) -> (bool, Vec<String>) {
        let gone: Vec<String> = self
            .data
            .dms
            .values()
            .chain(self.data.groups.values().map(|g| &g.chat))
            .chain(self.data.channels.values().map(|c| &c.chat))
            .flat_map(|c| c.msgs.iter())
            .filter(|m| m.expired(now_ms))
            .filter_map(|m| m.media.as_ref().map(|r| r.file.clone()))
            .collect();
        if !self.sweep(now_ms) {
            return (false, Vec::new());
        }
        if gone.is_empty() {
            return (true, gone);
        }
        let keep = self.media_files();
        (true, gone.into_iter().filter(|f| !keep.contains(f)).collect())
    }
}
