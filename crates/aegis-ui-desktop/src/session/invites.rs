//! One-time invites (spec section 30): the secrets this user handed out, and the `iacc`
//! envelope that turns a redeemed invite into a contact on both sides.

use super::{ChatRef, Failure, Outbound, Outcome, Session};
use crate::model::OpenInvite;
use aegis_core::envelope::{random_msg_id, Envelope, Kind};
use aegis_core::invite::{self, Bundle, INVITE_TTL_SECS, MAX_OPEN_INVITES};
use aegis_core::net::DirEntry;
use aegis_core::pad;
use aegis_core::queue_ids::inbox_queue;
use aegis_core::seal::seal_dm;
use zeroize::Zeroizing;

/// What a redeemed bundle means for the local contact list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pinned {
    New,
    /// Already a contact with exactly these keys.
    Known,
}

impl Session {
    /// Makes a fresh invite secret and keeps it until it is used or expires. The caller saves
    /// the vault before the server learns the invite, so an accept is never lost.
    pub fn open_invite(&mut self, now_s: u64) -> Result<Zeroizing<[u8; 32]>, Failure> {
        self.purge_invites(now_s);
        if self.data.invites.len() >= MAX_OPEN_INVITES {
            return Err(Failure::new("err.invite_limit"));
        }
        let secret = Zeroizing::new(aegis_core::random_bytes::<32>()?);
        self.data.invites.push(OpenInvite {
            secret: secret.clone(),
            exp_s: now_s.saturating_add(INVITE_TTL_SECS),
        });
        self.dirty = true;
        Ok(secret)
    }

    pub fn drop_invite(&mut self, secret: &[u8; 32]) {
        let before = self.data.invites.len();
        self.data.invites.retain(|i| *i.secret != *secret);
        self.dirty |= self.data.invites.len() != before;
    }

    /// Forgets invites the server has dropped anyway. The server rounds expiry up to the hour.
    pub fn purge_invites(&mut self, now_s: u64) -> bool {
        let before = self.data.invites.len();
        self.data
            .invites
            .retain(|i| i.exp_s.saturating_add(3600) > now_s);
        let changed = self.data.invites.len() != before;
        self.dirty |= changed;
        changed
    }

    pub fn open_invites(&self) -> usize {
        self.data.invites.len()
    }

    /// Pins the inviter from a redeemed bundle. A name that is already a contact with other
    /// keys is never overwritten: the invite cannot be used to swap a pinned key.
    pub fn pin_redeemed(&mut self, b: &Bundle, now_ms: u64) -> Result<Pinned, Failure> {
        if b.u == self.data.username || b.ed == self.ed_public() || b.x == self.x_public() {
            return Err(Failure::new("err.self"));
        }
        if let Some(c) = self.data.contacts.get(&b.u) {
            return if c.x == b.x && c.ed == b.ed {
                Ok(Pinned::Known)
            } else {
                Err(Failure::new("err.invite_conflict"))
            };
        }
        if self
            .data
            .contacts
            .values()
            .any(|c| c.x == b.x || c.ed == b.ed)
        {
            return Err(Failure::new("err.invite_conflict"));
        }
        self.add_contact(
            &DirEntry {
                u: b.u.clone(),
                title: String::new(),
                x: b.x,
                ed: b.ed,
            },
            now_ms,
        );
        Ok(Pinned::New)
    }

    /// The `iacc` that tells the inviter who redeemed `secret`, sealed to the inviter's key.
    pub fn accept_frame(&self, secret: &[u8; 32], b: &Bundle, now_ms: u64) -> Result<Outbound, Failure> {
        let mut env = self.own_envelope(Kind::Iacc, random_msg_id()?, now_ms, 0);
        env.body = invite::accept_body(&self.identity(), secret, &self.data.username)?;
        let frame = seal_dm(&self.data.x_sk, &b.x, &env)?;
        Ok(Outbound {
            queue: inbox_queue(&b.x),
            padded: pad::pad(&frame)?,
        })
    }

    /// Applies an `iacc` opened with the sealed sender key `sender_x`. It is taken only from a
    /// stranger whose proof matches one of the open secrets; that secret is then used up.
    pub fn accept_invite_use(&mut self, env: &Envelope, sender_x: [u8; 32], now_ms: u64) -> Outcome {
        if env.kind != Kind::Iacc
            || self.seen.contains(&env.msg_id)
            || env.sender == self.data.username
            || self.data.contacts.contains_key(&env.sender)
            || self.is_blocked(&sender_x)
        {
            return Outcome::Dropped;
        }
        let hit = self.data.invites.iter().position(|i| {
            invite::check_accept(&i.secret, &env.sender, &sender_x, &env.sender_ed, &env.body)
        });
        let Some(i) = hit else {
            return Outcome::Dropped;
        };
        if self
            .data
            .contacts
            .values()
            .any(|c| c.x == sender_x || c.ed == env.sender_ed)
        {
            return Outcome::Dropped;
        }
        self.data.invites.remove(i);
        self.seen.insert(&env.msg_id);
        self.add_contact(
            &DirEntry {
                u: env.sender.clone(),
                title: env.sender_name.clone(),
                x: sender_x,
                ed: env.sender_ed,
            },
            now_ms,
        );
        Outcome::Added(ChatRef::Dm(env.sender.clone()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::i18n::Lang;
    use aegis_core::seal::open_dm;

    fn session(u: &str) -> Session {
        Session::fresh(u, "", Lang::En, "pw-pw-pw-pw-pw").expect("session")
    }

    fn bundle_of(s: &Session) -> Bundle {
        Bundle {
            u: s.data.username.clone(),
            x: s.x_public(),
            ed: s.ed_public(),
        }
    }

    fn opened(to: &Session, o: &Outbound) -> (Envelope, [u8; 32]) {
        let frame = pad::unpad(&o.padded).expect("unpad");
        let d = open_dm(&to.data.x_sk, &frame).expect("open");
        (d.envelope, d.sender_x_pk)
    }

    #[test]
    fn an_invite_turns_into_a_contact_once() {
        let mut alice = session("alice");
        let mut bob = session("bob");
        let s = alice.open_invite(1_000).expect("invite");
        assert_eq!(bob.pin_redeemed(&bundle_of(&alice), 1).expect("pin"), Pinned::New);
        let out = bob.accept_frame(&s, &bundle_of(&alice), 2).expect("frame");
        assert_eq!(out.queue, alice.inbox());
        let (env, x) = opened(&alice, &out);
        assert_eq!(
            alice.accept_invite_use(&env, x, 3),
            Outcome::Added(ChatRef::Dm("bob".into()))
        );
        let c = alice.data.contacts.get("bob").expect("contact");
        assert_eq!((c.x, c.ed), (bob.x_public(), bob.ed_public()));
        assert_eq!(alice.open_invites(), 0);

        // The same secret cannot add anyone else.
        let mut carol = session("carol");
        carol.pin_redeemed(&bundle_of(&alice), 4).expect("pin");
        let (env, x) = opened(&alice, &carol.accept_frame(&s, &bundle_of(&alice), 5).expect("frame"));
        assert_eq!(alice.accept_invite_use(&env, x, 6), Outcome::Dropped);
        assert!(!alice.data.contacts.contains_key("carol"));
    }

    #[test]
    fn a_forged_or_replayed_accept_is_dropped() {
        let mut alice = session("alice");
        let bob = session("bob");
        let s = alice.open_invite(1_000).expect("invite");
        let wrong = [9u8; 32];
        let (env, x) = opened(&alice, &bob.accept_frame(&wrong, &bundle_of(&alice), 1).expect("frame"));
        assert_eq!(alice.accept_invite_use(&env, x, 2), Outcome::Dropped);
        assert_eq!(alice.open_invites(), 1);

        // A proof made for one sender does not work when another key carries it.
        let (mut env, x) = opened(&alice, &bob.accept_frame(&s, &bundle_of(&alice), 3).expect("frame"));
        env.sender = "mallory".into();
        assert_eq!(alice.accept_invite_use(&env, x, 4), Outcome::Dropped);
        assert_eq!(alice.accept_invite_use(&env, [7; 32], 4), Outcome::Dropped);
        assert_eq!(alice.open_invites(), 1);
    }

    #[test]
    fn redeeming_never_replaces_a_pinned_contact() {
        let mut bob = session("bob");
        let alice = session("alice");
        let impostor = session("alice");
        assert_eq!(bob.pin_redeemed(&bundle_of(&alice), 1).expect("pin"), Pinned::New);
        assert_eq!(bob.pin_redeemed(&bundle_of(&alice), 2).expect("again"), Pinned::Known);
        assert_eq!(
            bob.pin_redeemed(&bundle_of(&impostor), 3).unwrap_err().key,
            "err.invite_conflict"
        );
        let c = bob.data.contacts.get("alice").expect("contact");
        assert_eq!(c.ed, alice.ed_public());
        let own = bundle_of(&bob);
        assert_eq!(bob.pin_redeemed(&own, 4).unwrap_err().key, "err.self");
    }

    #[test]
    fn open_invites_are_capped_and_expire() {
        let mut alice = session("alice");
        for _ in 0..MAX_OPEN_INVITES {
            alice.open_invite(1_000).expect("invite");
        }
        assert_eq!(alice.open_invite(1_000).unwrap_err().key, "err.invite_limit");
        assert!(alice.purge_invites(1_000 + INVITE_TTL_SECS + 3600));
        assert_eq!(alice.open_invites(), 0);
        let s = alice.open_invite(2_000).expect("invite");
        alice.drop_invite(&s);
        assert_eq!(alice.open_invites(), 0);
    }
}
