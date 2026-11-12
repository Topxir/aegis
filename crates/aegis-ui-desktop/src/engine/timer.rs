//! Disappearing messages: sending a timer change and deleting what has expired.

use super::*;

impl Engine {
    /// Sets the timer of `chat` and tells the other side.
    pub fn set_timer(&self, chat: &ChatRef, ttl_s: u64) -> Result<(), Failure> {
        let (epoch, client, out) = {
            let mut app = self.app();
            let epoch = app.epoch;
            let s = app.session.as_mut().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            let out = s.change_ttl(chat, ttl_s, now_ms())?;
            (epoch, client, out)
        };
        self.changed();
        let Some(out) = out else {
            return Ok(());
        };
        self.deliver(epoch, &client, vec![(String::new(), out)])
            .pop()
            .map_or(Ok(()), |(_, r)| r)
    }

    /// Drops expired messages and deletes their stored attachments right away.
    pub(super) fn sweep_expired(&self, epoch: u64) -> bool {
        let Some((changed, files, dir)) = self.live(epoch, |s| {
            let (changed, files) = s.sweep_files(now_ms());
            let dir = media::media_dir(&self.vault_path(&s.data.username));
            (changed, files, dir)
        }) else {
            return false;
        };
        for f in &files {
            media::remove(&dir, f);
        }
        changed
    }
}
