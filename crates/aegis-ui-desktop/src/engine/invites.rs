//! One-time invites and the hidden profile switch (spec section 30).

use super::*;
use crate::session::{Outbound, Pinned};
use aegis_core::invite;

/// An `aegis://invite/` link given on the command line, kept until the account is open.
pub fn launch_link() -> Option<Zeroizing<String>> {
    std::env::args()
        .skip(1)
        .find(|a| invite::parse_link(a).is_ok())
        .map(Zeroizing::new)
}

impl Engine {
    /// Makes an invite, saves its secret, then registers it on the server. The link is shown
    /// only in memory and never stored.
    pub fn create_invite(&self) -> Result<(), Failure> {
        let (epoch, client, identity, u, secret) = {
            let mut app = self.app();
            let epoch = app.epoch;
            let s = app.session.as_mut().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            let secret = s.open_invite(now_s())?;
            (epoch, client, identity_of(s), s.data.username.clone(), secret)
        };
        let made = self.flush().and_then(|()| {
            self.net_invite_create(&client, &identity, &u, &secret)
                .map_err(|e| match e {
                    Error::Http(429) => Failure::new("err.invite_limit"),
                    e => Failure::from(e),
                })
        });
        if let Err(f) = made {
            self.live(epoch, |s| s.drop_invite(&secret));
            let _ = self.flush();
            return Err(f);
        }
        let mut app = self.app();
        if app.epoch == epoch {
            app.invite = Some(Zeroizing::new(invite::link(&secret)));
        }
        Ok(())
    }

    /// Redeems a link: pins the inviter without asking the directory and tells the inviter
    /// who used it.
    pub fn redeem_invite(&self, text: &str) -> Result<(), Failure> {
        let secret = invite::parse_link(text).map_err(|_| Failure::new("err.invite_link"))?;
        let (epoch, client) = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            if s.data.invites.iter().any(|i| *i.secret == *secret) {
                return Err(Failure::new("err.self"));
            }
            (app.epoch, self.client_for(&s.data.settings)?)
        };
        let b = self
            .net_invite_redeem(&client, &secret)?
            .ok_or(Failure::new("err.invite_gone"))?;
        // A visible inviter must match the directory; a hidden one is pinned as given. The
        // invite is already used up, so a failed lookup does not stop it.
        if let Ok(Some(e)) = self.net_lookup(&client, &b.u) {
            if e.x != b.x || e.ed != b.ed {
                return Err(Failure::new("err.invite_link"));
            }
        }
        let now = now_ms();
        let (pinned, out) = self
            .live(epoch, |s| {
                let p = s.pin_redeemed(&b, now)?;
                Ok::<_, Failure>((p, s.accept_frame(&secret, &b, now)?))
            })
            .ok_or(Failure::new("err.locked"))??;
        self.flush()?;
        self.post_accept(&client, out);
        if pinned == Pinned::New {
            self.send_profile_to(&client, &b.u);
        }
        let mut app = self.app();
        if app.epoch == epoch {
            app.link_in = None;
            app.route = Route::Chat(ChatRef::Dm(b.u));
        }
        Ok(())
    }

    /// Posts an `iacc`. One that cannot go out now waits in memory for the next poll.
    fn post_accept(&self, client: &Client, out: Outbound) {
        if self.net_send(client, &out.queue, &out.padded).is_err() {
            self.app().accepts.push(out);
        }
    }

    pub(super) fn retry_accepts(&self, client: &Client) {
        let list = std::mem::take(&mut self.app().accepts);
        for out in list {
            self.post_accept(client, out);
        }
    }

    /// An `iacc` in the inbox. Only a sender proving one of the open invites is pinned; any
    /// frames it sent before the accept arrived are then opened.
    pub(super) fn handle_accept(
        &self,
        epoch: u64,
        client: &Client,
        env: &Envelope,
        sender_x: [u8; 32],
    ) -> (Flow, bool) {
        // A name that is listed in the directory must come with the listed keys, so whoever
        // intercepted a link cannot take the name of a visible user.
        match self.net_lookup(client, &env.sender) {
            Err(_) => return (Flow::Retry, false),
            Ok(Some(e)) if e.x != sender_x || e.ed != env.sender_ed => return (Flow::Next, false),
            Ok(_) => {}
        }
        let outcome = match self.live(epoch, |s| s.accept_invite_use(env, sender_x, now_ms())) {
            None => return (Flow::Stop, false),
            Some(Outcome::Dropped) => return (Flow::Next, false),
            Some(o) => o,
        };
        let _ = self.flush();
        if let Some(Some(p)) = self.live(epoch, |s| s.take_pending(&sender_x)) {
            for h in p.frames {
                if let Ok(f) = aegis_core::hex::decode(&h) {
                    let _ = self.handle_session_frame(epoch, client, &f, false);
                }
            }
        }
        self.send_profile_to(client, &env.sender);
        (Flow::Next, self.note_outcome(epoch, &outcome))
    }

    /// Turns the hidden profile on or off. The local switch follows the server's answer.
    pub fn set_hidden(&self, on: bool) -> Result<(), Failure> {
        let (epoch, client, identity, u) = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            (
                app.epoch,
                self.client_for(&s.data.settings)?,
                identity_of(s),
                s.data.username.clone(),
            )
        };
        self.net_hide(&client, &identity, &u, on)?;
        self.live(epoch, |s| {
            s.data.settings.hidden = on;
            s.dirty = true;
        });
        self.flush()
    }
}
