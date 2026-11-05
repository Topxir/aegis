//! Media, channels and profile cards: the parts of the engine added on top of
//! plain direct and group messages.

use super::*;
/// id, group key, cursor, owner, owner ed key, official.
type ChannelRow = (String, [u8; 32], u64, String, Option<[u8; 32]>, bool);

enum Fetch {
    Drop,
    Retry,
    Stop,
}

fn media_failure(e: media::MediaError) -> Failure {
    Failure::new(match e {
        media::MediaError::TooLarge => "err.media_big",
        media::MediaError::Unsupported => "err.media_type",
        media::MediaError::Corrupt => "err.media_bad",
        media::MediaError::Io => "err.disk",
    })
}

fn video_failure(e: Error) -> Failure {
    Failure::new(match e {
        Error::Media("too large") => "err.media_big",
        _ => "err.media_bad",
    })
}

/// A picture or video reduced to what the protocol allows, with its sizes.
struct Clean {
    kind: MediaKind,
    bytes: Vec<u8>,
    w: u32,
    h: u32,
    dur_ms: u64,
}

fn clean_media(raw: &[u8]) -> Result<Clean, Failure> {
    if media::is_video(raw) {
        let v = aegis_core::mp4clean::sanitize_video(raw).map_err(video_failure)?;
        Ok(Clean {
            kind: MediaKind::Video,
            bytes: v.bytes,
            w: v.width,
            h: v.height,
            dur_ms: v.duration_ms,
        })
    } else {
        let c = media::sanitize_image(raw).map_err(media_failure)?;
        Ok(Clean {
            kind: MediaKind::Image,
            bytes: c.bytes,
            w: c.w,
            h: c.h,
            dur_ms: 0,
        })
    }
}

impl Engine {
    // ---- sending media --------------------------------------------------------

    /// Asks for a file with the system dialog and sends it. Runs on the worker thread.
    pub fn pick_and_send(&self, chat: &ChatRef) -> Result<(), Failure> {
        let picked = rfd::FileDialog::new()
            .add_filter(
                "Photo, video",
                &["jpg", "jpeg", "png", "webp", "mp4", "mov", "m4v"],
            )
            .pick_file();
        match picked {
            Some(p) => self.send_media(chat, &p),
            None => Ok(()),
        }
    }

    pub fn send_media(&self, chat: &ChatRef, path: &Path) -> Result<(), Failure> {
        let (epoch, client, dir, key) = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            if let ChatRef::Channel(c) = chat {
                if !s.data.channels.get(c).is_some_and(|c| c.mine) {
                    return Err(Failure::new("err.channel_readonly"));
                }
            }
            (
                app.epoch,
                self.client_for(&s.data.settings)?,
                media::media_dir(&self.vault_path(&s.data.username)),
                s.data.media_key.clone(),
            )
        };
        let meta = std::fs::metadata(path).map_err(|e| io_failure(&e))?;
        if !meta.is_file() {
            return Err(Failure::new("err.media_type"));
        }
        if meta.len() > media::MAX_INPUT as u64 {
            return Err(Failure::new("err.media_big"));
        }
        let raw = std::fs::read(path).map_err(|e| io_failure(&e))?;
        let clean = clean_media(&raw)?;
        drop(raw);
        let sealed = seal_attachment(
            &AttachmentMeta {
                kind: clean.kind,
                width: u64::from(clean.w),
                height: u64::from(clean.h),
                duration_ms: clean.dur_ms,
                caption: String::new(),
            },
            &clean.bytes,
        )?;
        let file = media::new_file_id().map_err(media_failure)?;
        media::store(&dir, &key, &file, &clean.bytes).map_err(media_failure)?;
        let body = sealed.descriptor.encode()?;
        let payload = Payload::Media {
            body,
            caption: String::new(),
            media: MediaRef {
                video: clean.kind == MediaKind::Video,
                w: clean.w,
                h: clean.h,
                dur_ms: clean.dur_ms,
                file: file.clone(),
            },
        };
        let prepared = self.live(epoch, |s| s.prepare_send(chat, payload, None, now_ms()));
        let (id, out) = match prepared {
            Some(Ok(v)) => v,
            Some(Err(f)) => {
                media::remove(&dir, &file);
                return Err(f);
            }
            None => {
                media::remove(&dir, &file);
                return Ok(());
            }
        };
        self.changed();
        let mut res: Result<(), Error> = Ok(());
        for (i, chunk) in sealed.chunks.iter().enumerate() {
            let Some(cid) = sealed.descriptor.ids.get(i) else {
                res = Err(Error::BadResponse);
                break;
            };
            self.slot(chunk.len());
            if let Err(e) = client.blob_put(cid, chunk) {
                res = Err(e);
                break;
            }
        }
        let mut res: Result<(), Failure> = res.map_err(Failure::from);
        if res.is_ok() {
            res = self
                .deliver(epoch, &client, vec![(id.clone(), out)])
                .pop()
                .map_or(Ok(()), |(_, r)| r);
        }
        let state = if res.is_ok() {
            MsgState::Sent
        } else {
            MsgState::Failed
        };
        self.live(epoch, |s| s.set_msg_state(chat, &id, state));
        res
    }

    /// Serves `/media/<id>` to the page. Unknown ids and locked sessions give 404.
    pub fn media_reply(&self, sid: &str, range: Option<&str>) -> media::Reply {
        let found = {
            let app = self.app();
            let Some(s) = app.session.as_ref() else {
                return media::Reply::not_found();
            };
            let chats = s
                .data
                .dms
                .values()
                .chain(s.data.groups.values().map(|g| &g.chat))
                .chain(s.data.channels.values().map(|c| &c.chat));
            let file = chats
                .flat_map(|c| c.msgs.iter())
                .filter_map(|m| m.media.as_ref())
                .find(|m| media::session_id(&app.media_secret, &m.file) == sid)
                .map(|m| m.file.clone());
            file.map(|f| {
                (
                    media::media_dir(&self.vault_path(&s.data.username)),
                    s.data.media_key.clone(),
                    f,
                )
            })
        };
        let Some((dir, key, file)) = found else {
            return media::Reply::not_found();
        };
        match media::load(&dir, &key, &file) {
            Some(plain) => media::reply(plain, range),
            None => media::Reply::not_found(),
        }
    }

    /// Removes stored files that no message refers to any more.
    pub(super) fn gc_media(&self, epoch: u64) {
        let Some((dir, keep)) = self.live(epoch, |s| {
            (
                media::media_dir(&self.vault_path(&s.data.username)),
                s.media_files(),
            )
        }) else {
            return;
        };
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return;
        };
        let recent = Duration::from_secs(600);
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".bin") else {
                continue;
            };
            if keep.contains(id) || !media::valid_file_id(id) {
                continue;
            }
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|d| d > recent);
            if old {
                media::remove(&dir, id);
            }
        }
    }

    // ---- receiving media -------------------------------------------------------

    /// Downloads, opens and cleans an attachment. Returns the caption and the stored file.
    fn fetch_media(
        &self,
        epoch: u64,
        client: &Client,
        body: &str,
    ) -> Result<(String, MediaRef), Fetch> {
        let desc = AttachmentDescriptor::parse(body).map_err(|_| Fetch::Drop)?;
        let mut chunks = Vec::with_capacity(desc.ids.len());
        for id in &desc.ids {
            match client.blob_get(id) {
                Err(_) => return Err(Fetch::Retry),
                Ok(None) => return Err(Fetch::Drop),
                Ok(Some(c)) => chunks.push(c),
            }
        }
        let plain = open_attachment(&desc, &chunks).map_err(|_| Fetch::Drop)?;
        drop(chunks);
        let got = match (desc.kind, clean_media(&plain)) {
            (MediaKind::Image, Ok(c)) if c.kind == MediaKind::Image => c,
            (MediaKind::Video, Ok(c)) if c.kind == MediaKind::Video => c,
            _ => return Err(Fetch::Drop),
        };
        let Some((dir, key)) = self.live(epoch, |s| {
            (
                media::media_dir(&self.vault_path(&s.data.username)),
                s.data.media_key.clone(),
            )
        }) else {
            return Err(Fetch::Stop);
        };
        let file = media::new_file_id().map_err(|_| Fetch::Drop)?;
        media::store(&dir, &key, &file, &got.bytes).map_err(|_| Fetch::Drop)?;
        Ok((
            desc.caption,
            MediaRef {
                video: got.kind == MediaKind::Video,
                w: got.w,
                h: got.h,
                dur_ms: got.dur_ms,
                file,
            },
        ))
    }

    /// Inbox frame of kind `dmf`: fetch the attachment before applying it.
    pub(super) fn with_media(
        &self,
        epoch: u64,
        client: &Client,
        mut env: aegis_core::envelope::Envelope,
    ) -> Result<(aegis_core::envelope::Envelope, Option<MediaRef>), Flow> {
        if !matches!(env.kind, Kind::Dmf | Kind::Gmf | Kind::Cmf) {
            return Ok((env, None));
        }
        match self.fetch_media(epoch, client, &env.body) {
            Ok((caption, m)) => {
                env.body = caption;
                Ok((env, Some(m)))
            }
            Err(Fetch::Retry) => Err(Flow::Retry),
            Err(Fetch::Stop) => Err(Flow::Stop),
            Err(Fetch::Drop) => Err(Flow::Next),
        }
    }

    // ---- channels ----------------------------------------------------------------

    fn handle_channel_frame(
        &self,
        epoch: u64,
        client: &Client,
        ch: &ChannelPoll,
        padded: &[u8],
        rejected: &mut usize,
    ) -> (Flow, bool) {
        let Ok(frame) = pad::unpad(padded) else {
            return (Flow::Next, false);
        };
        if frame.first() == Some(&0x05) {
            if ch.official {
                *rejected += 1;
                return (Flow::Next, false);
            }
            return self.handle_chain_frame(epoch, client, &ch.id, &frame);
        }
        let opened = if ch.official {
            official::verify(&frame)
        } else {
            channel::open_post(&ch.g, &ch.owner, &ch.owner_ed, &frame)
        };
        let Ok(env) = opened else {
            *rejected += 1;
            return (Flow::Next, false);
        };
        let fresh = self.live(epoch, |s| {
            !s.seen.contains(&env.msg_id) && s.data.channels.contains_key(&ch.id)
        });
        match fresh {
            None => return (Flow::Stop, false),
            Some(false) => return (Flow::Next, false),
            Some(true) => {}
        }
        let (env, media) = match self.with_media(epoch, client, env) {
            Ok(v) => v,
            Err(f) => return (f, false),
        };
        let outcome = self.live(epoch, |s| {
            s.accept_channel_post(&ch.id, env, media, now_ms())
        });
        match outcome {
            None => (Flow::Stop, false),
            Some(o) => (Flow::Next, self.note_outcome(epoch, &o)),
        }
    }

    /// Polls every channel queue. Returns false when the session changed under us.
    pub(super) fn poll_channels(
        &self,
        epoch: u64,
        client: &Client,
        reached: &mut bool,
        applied: &mut usize,
    ) -> bool {
        let list: Option<Vec<ChannelRow>> = self.live(epoch, |s| {
            s.data
                .channels
                .values()
                .filter(|c| !c.mine)
                .map(|c| {
                    (
                        c.id.clone(),
                        *c.g,
                        c.cursor,
                        c.owner.clone(),
                        c.owner_ed,
                        c.official,
                    )
                })
                .collect()
        });
        let Some(list) = list else {
            return false;
        };
        for (id, g, mut cursor, owner, pinned, is_official) in list {
            // The official owner key is compiled in; without one the channel stays empty.
            let key = if is_official {
                if official::OFFICIAL_OWNER_ED_PK.is_none() {
                    continue;
                }
                [0u8; 32]
            } else {
                match pinned {
                    Some(k) => k,
                    None => continue,
                }
            };
            let queue = if is_official {
                official::official_queue()
            } else {
                channel::channel_queue(&g)
            };
            let Ok(queue) = queue else {
                continue;
            };
            let ch = ChannelPoll {
                id: id.clone(),
                g,
                owner,
                owner_ed: key,
                official: is_official,
            };
            let mut rejected = 0usize;
            'pages: for _ in 0..POLL_PAGES {
                let page = match client.poll(&queue, cursor) {
                    Ok(p) => p,
                    Err(_) => {
                        *reached = false;
                        break;
                    }
                };
                let count = page.frames.len();
                for (seq, data) in &page.frames {
                    let (flow, hit) =
                        self.handle_channel_frame(epoch, client, &ch, data, &mut rejected);
                    match flow {
                        Flow::Stop => return false,
                        Flow::Retry => break 'pages,
                        Flow::Next => {
                            *applied += usize::from(hit);
                            cursor = *seq;
                            self.live(epoch, |s| {
                                if let Some(c) = s.data.channels.get_mut(&id) {
                                    c.cursor = cursor;
                                    s.dirty = true;
                                }
                            });
                        }
                    }
                }
                if count < 100 {
                    break;
                }
            }
            let _ = rejected;
        }
        true
    }

    pub fn create_channel(
        &self,
        title: &str,
        about: &str,
        members: &[String],
    ) -> Result<(), Failure> {
        let (client, id, invites) = {
            let mut app = self.app();
            let s = app.session.as_mut().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            let now = now_ms();
            let id = s.create_channel(title, about, now)?;
            let invites = s.channel_invites(&id, members, now);
            app.route = Route::Chat(ChatRef::Channel(id.clone()));
            (client, id, invites)
        };
        self.changed();
        let _ = id;
        self.deliver_invites(&client, invites?)
    }

    pub fn invite_channel(&self, cid: &str, members: &[String]) -> Result<(), Failure> {
        let (client, invites) = {
            let mut app = self.app();
            let s = app.session.as_mut().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            (client, s.channel_invites(cid, members, now_ms())?)
        };
        self.changed();
        self.deliver_invites(&client, invites)
    }

    fn deliver_invites(
        &self,
        client: &Client,
        invites: Vec<(String, Draft)>,
    ) -> Result<(), Failure> {
        let epoch = self.app().epoch;
        let failed = self.deliver_drafts(epoch, client, invites);
        if failed.is_empty() {
            Ok(())
        } else {
            Err(Failure {
                key: "err.invite_failed",
                detail: failed
                    .iter()
                    .map(|u| format!("@{u}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            })
        }
    }

    // ---- profile -----------------------------------------------------------------

    /// Saves name, about and particles, then sends the card to every contact.
    pub fn save_profile(&self, display: &str, about: &str, particles: &str) -> Result<(), Failure> {
        let name = sanitize_display_text(display.trim());
        let changed_name = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            s.data.display != name
        };
        if changed_name {
            self.update_display(&name)?;
        }
        self.mutate(|s| s.set_profile(about, particles))
            .ok_or(Failure::new("err.locked"))??;
        self.changed();
        let (epoch, client, frames) = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            let now = now_ms();
            let frames: Vec<(String, Draft)> = s
                .data
                .contacts
                .keys()
                .filter_map(|u| s.profile_frame(u, now).ok().map(|f| (u.clone(), f)))
                .collect();
            (app.epoch, client, frames)
        };
        let _ = self.deliver_drafts(epoch, &client, frames);
        Ok(())
    }

    /// Sends the profile card to one new contact when there is something to share.
    pub(super) fn send_profile_to(&self, client: &Client, u: &str) {
        let frame = {
            let app = self.app();
            let Some(s) = app.session.as_ref() else {
                return;
            };
            if s.data.about.is_empty() && s.data.particles == "none" {
                return;
            }
            s.profile_frame(u, now_ms()).ok().map(|d| (app.epoch, d))
        };
        if let Some((epoch, d)) = frame {
            let _ = self.deliver_drafts(epoch, client, vec![(u.to_owned(), d)]);
        }
    }
}

pub(super) struct ChannelPoll {
    id: String,
    g: [u8; 32],
    owner: String,
    owner_ed: [u8; 32],
    official: bool,
}
