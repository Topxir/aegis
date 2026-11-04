//! Shared application state and everything that talks to the disk or the network.
//!
//! The UI thread only takes short locks on [`App`]; slow work (key derivation,
//! proof of work, HTTP) happens outside the lock and re-checks the session epoch
//! before writing its result back.

use crate::config::Config;
use crate::i18n::Lang;
use crate::model::{Data, MsgState, Settings, SCHEMA};
use crate::session::{now_ms, ChatRef, Failure, Outbound, Outcome, Session};
use aegis_core::envelope::Kind;
use aegis_core::group::group_decrypt;
use aegis_core::identity::{normalize_username, Identity};
use aegis_core::net::{Client, DirEntry};
use aegis_core::seal::open_dm;
use aegis_core::text::sanitize_display_text;
use aegis_core::vault::{vault_decrypt, vault_encrypt, vault_file_name, write_atomic};
use aegis_core::{directory, pad, Error};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
const POLL_PAGES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTab {
    Unlock,
    Create,
    Import,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Welcome,
    Chat(ChatRef),
    Contact(String),
    GroupInfo(String),
    NewChat,
    NewGroup,
    Settings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialog {
    DeleteChat(String),
    LeaveGroup(String),
    DeleteAccount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flash {
    pub ok: bool,
    pub key: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnTest {
    Running,
    Reachable,
    Failed(Failure),
}

#[derive(Debug)]
pub struct App {
    pub session: Option<Session>,
    pub epoch: u64,
    pub route: Route,
    pub tab: AuthTab,
    pub dialog: Option<Dialog>,
    pub pre_lang: Lang,
    pub busy: Option<&'static str>,
    pub flash: Option<Flash>,
    pub conn: Option<ConnTest>,
    pub net_ok: Option<bool>,
    pub last_activity: Instant,
    pub attention: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            session: None,
            epoch: 0,
            route: Route::Welcome,
            tab: AuthTab::Unlock,
            dialog: None,
            pre_lang: Lang::En,
            busy: None,
            flash: None,
            conn: None,
            net_ok: None,
            last_activity: Instant::now(),
            attention: false,
        }
    }

    pub fn lang(&self) -> Lang {
        self.session
            .as_ref()
            .map_or(self.pre_lang, |s| s.data.settings.lang)
    }
}

pub enum Job {
    Create {
        username: String,
        display: String,
        password: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    Unlock {
        username: String,
        password: Zeroizing<String>,
    },
    Import {
        path: String,
        password: Zeroizing<String>,
    },
    AddContact(String),
    Send {
        chat: ChatRef,
        text: String,
    },
    Retry {
        chat: ChatRef,
        id: String,
    },
    CreateGroup {
        title: String,
        members: Vec<String>,
    },
    ResendInvite {
        group: String,
        member: String,
    },
    TestConnection {
        endpoint: String,
        socks5: String,
    },
    UpdateDisplay(String),
    Export(String),
    DeleteAccount(String),
    Flush,
    Persist(Box<Session>),
    Stop,
}

impl core::fmt::Debug for Job {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Job")
    }
}

enum Flow {
    Next,
    Retry,
    Stop,
}

pub struct Engine {
    cfg: Config,
    app: Mutex<App>,
    save_lock: Mutex<()>,
    on_change: Box<dyn Fn() + Send + Sync>,
    kick: Mutex<Option<Sender<()>>>,
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

fn io_failure(e: &std::io::Error) -> Failure {
    Failure {
        key: "err.disk",
        detail: format!("{:?}", e.kind()),
    }
}

fn identity_of(s: &Session) -> Identity {
    Identity::from_secrets(*s.data.x_sk, *s.data.ed_sk)
}

fn valid_socks(s: &str) -> bool {
    match s.rsplit_once(':') {
        Some((h, p)) => {
            !h.is_empty()
                && h.len() <= 253
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
                && p.parse::<u16>().is_ok_and(|n| n != 0)
        }
        None => false,
    }
}

impl Engine {
    pub fn new(cfg: Config, on_change: impl Fn() + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            app: Mutex::new(App::new()),
            save_lock: Mutex::new(()),
            on_change: Box::new(on_change),
            kick: Mutex::new(None),
        })
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn app(&self) -> MutexGuard<'_, App> {
        self.app.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_kick(&self, tx: Sender<()>) {
        *self.kick.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    }

    fn kick_poll(&self) {
        if let Some(tx) = self.kick.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = tx.send(());
        }
    }

    pub fn changed(&self) {
        (self.on_change)();
    }

    /// True when the data directory already holds at least one vault file.
    pub fn has_vaults(&self) -> bool {
        std::fs::read_dir(&self.cfg.data_dir).is_ok_and(|mut d| {
            d.any(|e| e.is_ok_and(|e| e.file_name().to_string_lossy().ends_with(".vault")))
        })
    }

    pub fn vault_path(&self, username: &str) -> PathBuf {
        self.cfg.data_dir.join(vault_file_name(username))
    }

    /// Runs `f` on the session if it is still the one that started the operation.
    fn live<R>(&self, epoch: u64, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
        let mut app = self.app();
        if app.epoch != epoch {
            return None;
        }
        app.session.as_mut().map(f)
    }

    /// Runs `f` on the current session and marks it as needing a save.
    pub fn mutate<R>(&self, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
        let mut app = self.app();
        let s = app.session.as_mut()?;
        s.dirty = true;
        Some(f(s))
    }

    pub fn touch(&self) {
        self.app().last_activity = Instant::now();
    }

    pub fn idle_expired(&self) -> bool {
        let app = self.app();
        match &app.session {
            Some(s) if s.data.settings.idle_min > 0 => {
                app.last_activity.elapsed()
                    >= Duration::from_secs(u64::from(s.data.settings.idle_min) * 60)
            }
            _ => false,
        }
    }

    pub fn take_attention(&self) -> bool {
        std::mem::take(&mut self.app().attention)
    }

    fn client_for(&self, s: &Settings) -> Result<Client, Failure> {
        let socks = (!s.socks5.is_empty()).then_some(s.socks5.as_str());
        Ok(Client::new(&s.endpoint, socks)?.with_pow_bits(self.cfg.pow_bits))
    }

    fn install(&self, s: Session) {
        {
            let mut app = self.app();
            app.session = Some(s);
            app.epoch += 1;
            app.route = Route::Welcome;
            app.dialog = None;
            app.flash = None;
            app.conn = None;
            app.net_ok = None;
            app.last_activity = Instant::now();
        }
        self.kick_poll();
    }

    /// Removes the session from memory and returns it so it can be saved off-thread.
    pub fn detach(&self) -> Option<Session> {
        let mut app = self.app();
        let s = app.session.take();
        if s.is_some() {
            app.epoch += 1;
        }
        app.route = Route::Welcome;
        app.dialog = None;
        app.flash = None;
        app.conn = None;
        app.busy = None;
        s
    }

    pub fn persist(&self, mut s: Session) {
        if s.dirty {
            if let Err(f) = self.write_session(&mut s) {
                self.app().flash = Some(Flash {
                    ok: false,
                    key: f.key,
                    detail: f.detail,
                });
            }
        }
        self.changed();
    }

    fn write_session(&self, s: &mut Session) -> Result<(), Failure> {
        let _g = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        let plain = s.snapshot()?;
        let enc = vault_encrypt(&s.password, self.cfg.vault_params, &plain)?;
        std::fs::create_dir_all(&self.cfg.data_dir).map_err(|e| io_failure(&e))?;
        write_atomic(&self.vault_path(&s.data.username), &enc)?;
        s.dirty = false;
        Ok(())
    }

    /// Saves the live session if it changed.
    pub fn flush(&self) -> Result<(), Failure> {
        let _g = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (plain, pw, epoch, path) = {
            let mut app = self.app();
            let epoch = app.epoch;
            let Some(s) = app.session.as_mut() else {
                return Ok(());
            };
            if !s.dirty {
                return Ok(());
            }
            s.dirty = false;
            let plain = match s.snapshot() {
                Ok(p) => p,
                Err(e) => {
                    s.dirty = true;
                    return Err(e);
                }
            };
            (
                plain,
                s.password.clone(),
                epoch,
                self.vault_path(&s.data.username),
            )
        };
        let result = vault_encrypt(&pw, self.cfg.vault_params, &plain).and_then(|enc| {
            let mut app = self.app();
            if app.epoch != epoch {
                return Ok(());
            }
            std::fs::create_dir_all(&self.cfg.data_dir).map_err(Error::from)?;
            let r = write_atomic(&path, &enc);
            if r.is_err() {
                if let Some(s) = app.session.as_mut() {
                    s.dirty = true;
                }
            }
            r
        });
        if result.is_err() {
            self.live(epoch, |s| s.dirty = true);
        }
        result.map_err(Failure::from)
    }

    // ---- account lifecycle -------------------------------------------------

    pub fn create_account(
        &self,
        username: &str,
        display: &str,
        password: &str,
        confirm: &str,
    ) -> Result<(), Failure> {
        let u = normalize_username(username)?;
        if password != confirm {
            return Err(Failure::new("err.confirm"));
        }
        if password.chars().count() < 10 {
            return Err(Failure::new("err.password_short"));
        }
        let display = sanitize_display_text(display.trim());
        if !directory::is_valid_title(&display) {
            return Err(Failure::new("err.display"));
        }
        let path = self.vault_path(&u);
        if path.exists() {
            return Err(Failure::new("err.exists"));
        }
        let lang = self.app().pre_lang;
        let mut s = Session::fresh(&u, &display, lang, password)?;
        s.data
            .settings
            .endpoint
            .clone_from(&self.cfg.default_endpoint);
        let identity = identity_of(&s);
        s.dirty = true;
        self.write_session(&mut s)?;
        let registered = self
            .client_for(&s.data.settings)
            .and_then(|c| c.register(&identity, &u, &display).map_err(Failure::from));
        if let Err(e) = registered {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        self.install(s);
        Ok(())
    }

    pub fn unlock(&self, username: &str, password: &str) -> Result<(), Failure> {
        let u = normalize_username(username)?;
        let path = self.vault_path(&u);
        let bytes = read_vault_file(&path)?;
        let data = decode_vault(password, &bytes)?;
        if data.username != u {
            return Err(Failure::new("err.vault_format"));
        }
        self.install(Session::new(data, password));
        Ok(())
    }

    pub fn import_vault(&self, path: &str, password: &str) -> Result<(), Failure> {
        let p = Path::new(path.trim());
        if !p.is_absolute() {
            return Err(Failure::new("err.path"));
        }
        let bytes = read_vault_file(p)?;
        let data = decode_vault(password, &bytes)?;
        let u = normalize_username(&data.username)?;
        let dest = self.vault_path(&u);
        if dest.exists() {
            return Err(Failure::new("err.exists"));
        }
        std::fs::create_dir_all(&self.cfg.data_dir).map_err(|e| io_failure(&e))?;
        write_atomic(&dest, &bytes)?;
        self.install(Session::new(data, password));
        Ok(())
    }

    pub fn export_vault(&self, path: &str) -> Result<String, Failure> {
        self.flush()?;
        let dest = Path::new(path.trim());
        if !dest.is_absolute() || dest.parent().is_none_or(|p| !p.is_dir()) {
            return Err(Failure::new("err.path"));
        }
        if dest.exists() {
            return Err(Failure::new("err.file_exists"));
        }
        let src = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            self.vault_path(&s.data.username)
        };
        let bytes = std::fs::read(&src).map_err(|e| io_failure(&e))?;
        write_atomic(dest, &bytes)?;
        Ok(dest.display().to_string())
    }

    pub fn delete_account(&self, confirm: &str) -> Result<(), Failure> {
        let _g = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut app = self.app();
        let Some(s) = app.session.as_ref() else {
            return Err(Failure::new("err.locked"));
        };
        if s.data.username != confirm.trim() {
            return Err(Failure::new("err.confirm_name"));
        }
        let path = self.vault_path(&s.data.username);
        app.session = None;
        app.epoch += 1;
        app.route = Route::Welcome;
        app.dialog = None;
        let mut tmp_name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        tmp_name.push(".tmp");
        for p in [path.clone(), path.with_file_name(tmp_name)] {
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_failure(&e)),
            }
        }
        Ok(())
    }

    // ---- contacts and messages ---------------------------------------------

    pub fn add_contact(&self, username: &str) -> Result<(), Failure> {
        let u = normalize_username(username)?;
        let (epoch, client, exists) = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            if s.data.username == u {
                return Err(Failure::new("err.self"));
            }
            (
                app.epoch,
                self.client_for(&s.data.settings)?,
                s.data.contacts.contains_key(&u),
            )
        };
        if !exists {
            let entry = client.lookup(&u)?.ok_or(Failure::new("err.not_found"))?;
            self.live(epoch, |s| s.add_contact(&entry, now_ms()));
        }
        let mut app = self.app();
        if app.epoch == epoch {
            app.route = Route::Chat(ChatRef::Dm(u));
        }
        Ok(())
    }

    pub fn send_message(
        &self,
        chat: &ChatRef,
        text: &str,
        retry_id: Option<&str>,
    ) -> Result<(), Failure> {
        let (epoch, client, id, out) = {
            let mut app = self.app();
            let epoch = app.epoch;
            let s = app.session.as_mut().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            let now = now_ms();
            let (id, out) = match chat {
                ChatRef::Dm(u) => s.prepare_dm(u, text, retry_id, now)?,
                ChatRef::Group(g) => s.prepare_group_msg(g, text, retry_id, now)?,
            };
            (epoch, client, id, out)
        };
        self.changed();
        let res = client.send(&out.queue, &out.padded);
        let state = if res.is_ok() {
            MsgState::Sent
        } else {
            MsgState::Failed
        };
        self.live(epoch, |s| s.set_msg_state(chat, &id, state));
        res.map(|_| ()).map_err(Failure::from)
    }

    pub fn retry(&self, chat: &ChatRef, id: &str) -> Result<(), Failure> {
        let text = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            s.failed_text(chat, id).ok_or(Failure::new("err.generic"))?
        };
        self.send_message(chat, &text, Some(id))
    }

    pub fn create_group(&self, title: &str, members: &[String]) -> Result<(), Failure> {
        let (epoch, client, gid, invites) = {
            let mut app = self.app();
            let epoch = app.epoch;
            let s = app.session.as_mut().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            let (gid, invites) = s.prepare_group(title, members, now_ms())?;
            app.route = Route::Chat(ChatRef::Group(gid.clone()));
            (epoch, client, gid, invites)
        };
        self.changed();
        let failed = send_all(&client, invites);
        self.kick_poll();
        let _ = (epoch, gid);
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

    pub fn resend_invite(&self, group: &str, member: &str) -> Result<(), Failure> {
        let (client, out) = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            (client, s.invite_frame(group, member, now_ms())?)
        };
        client.send(&out.queue, &out.padded)?;
        Ok(())
    }

    pub fn update_display(&self, name: &str) -> Result<(), Failure> {
        let name = sanitize_display_text(name.trim());
        if !directory::is_valid_title(&name) {
            return Err(Failure::new("err.display"));
        }
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
        client.register(&identity, &u, &name)?;
        self.live(epoch, |s| {
            s.data.display = name;
            s.dirty = true;
        });
        Ok(())
    }

    pub fn test_connection(&self, endpoint: &str, socks5: &str) -> Result<(), Failure> {
        let socks = (!socks5.is_empty()).then_some(socks5);
        if socks.is_some_and(|s| !valid_socks(s)) {
            return Err(Failure::new("err.socks"));
        }
        let client = Client::new(endpoint, socks)?;
        client.health()?;
        Ok(())
    }

    pub fn apply_settings(
        &self,
        endpoint: &str,
        socks5: &str,
        idle_min: u32,
        flash_taskbar: bool,
    ) -> Result<(), Failure> {
        let endpoint = endpoint.trim().trim_end_matches('/').to_owned();
        let socks5 = socks5.trim().to_owned();
        aegis_core::net::Endpoint::parse(&endpoint)?;
        if !socks5.is_empty() && !valid_socks(&socks5) {
            return Err(Failure::new("err.socks"));
        }
        if idle_min > 24 * 60 {
            return Err(Failure::new("err.generic"));
        }
        self.mutate(|s| {
            let st = &mut s.data.settings;
            st.endpoint = endpoint;
            st.socks5 = socks5;
            st.idle_min = idle_min;
            st.flash_taskbar = flash_taskbar;
        })
        .ok_or(Failure::new("err.locked"))
    }

    pub fn set_lang(&self, lang: Lang) {
        let mut app = self.app();
        match app.session.as_mut() {
            Some(s) => {
                s.data.settings.lang = lang;
                s.dirty = true;
            }
            None => app.pre_lang = lang,
        }
    }

    // ---- receiving ------------------------------------------------------------

    fn note_outcome(&self, epoch: u64, outcome: &Outcome) -> bool {
        let mut app = self.app();
        if app.epoch != epoch {
            return false;
        }
        let route = app.route.clone();
        let flash = app
            .session
            .as_ref()
            .is_some_and(|s| s.data.settings.flash_taskbar);
        match outcome {
            Outcome::Added(r) => {
                if route == Route::Chat(r.clone()) {
                    if let Some(s) = app.session.as_mut() {
                        s.mark_read(r);
                    }
                }
                app.attention |= flash;
                true
            }
            Outcome::GroupJoined(_) => {
                app.attention |= flash;
                true
            }
            Outcome::KeyChanged(_) => true,
            Outcome::Dropped => false,
        }
    }

    fn handle_inbox_frame(&self, epoch: u64, client: &Client, padded: &[u8]) -> (Flow, bool) {
        let Ok(frame) = pad::unpad(padded) else {
            return (Flow::Next, false);
        };
        let opened = match self.live(epoch, |s| open_dm(&s.data.x_sk, &frame)) {
            None => return (Flow::Stop, false),
            Some(Err(_)) => return (Flow::Next, false),
            Some(Ok(o)) => o,
        };
        let env = opened.envelope;
        if !matches!(env.kind, Kind::Dm | Kind::Ginv) {
            return (Flow::Next, false);
        }
        let known = self.live(epoch, |s| {
            if s.seen.contains(&env.msg_id) || env.sender == s.data.username {
                None
            } else {
                Some(s.data.contacts.contains_key(&env.sender))
            }
        });
        let entry: Option<DirEntry> = match known {
            None => return (Flow::Stop, false),
            Some(None) => return (Flow::Next, false),
            Some(Some(true)) => None,
            Some(Some(false)) => match client.lookup(&env.sender) {
                Err(_) => return (Flow::Retry, false),
                Ok(None) => return (Flow::Next, false),
                Ok(Some(e)) => Some(e),
            },
        };
        let sender_x = opened.sender_x_pk;
        let outcome = self.live(epoch, |s| {
            s.accept_inbox(env, sender_x, entry.as_ref(), now_ms())
        });
        match outcome {
            None => (Flow::Stop, false),
            Some(o) => (Flow::Next, self.note_outcome(epoch, &o)),
        }
    }

    fn handle_group_frame(
        &self,
        epoch: u64,
        client: &Client,
        gid: &str,
        padded: &[u8],
    ) -> (Flow, bool) {
        let Ok(frame) = pad::unpad(padded) else {
            return (Flow::Next, false);
        };
        let decoded = self.live(epoch, |s| {
            let g = s.data.groups.get(gid)?;
            let env = group_decrypt(&g.key, &frame).ok()?;
            if env.group_id != g.id
                || env.kind != Kind::Gmsg
                || env.sender == s.data.username
                || !g.members.contains(&env.sender)
                || s.seen.contains(&env.msg_id)
            {
                return None;
            }
            Some((s.data.contacts.contains_key(&env.sender), env))
        });
        let (known, env) = match decoded {
            None => return (Flow::Stop, false),
            Some(None) => return (Flow::Next, false),
            Some(Some(v)) => v,
        };
        let entry = if known {
            None
        } else {
            match client.lookup(&env.sender) {
                Err(_) => return (Flow::Retry, false),
                Ok(None) => return (Flow::Next, false),
                Ok(Some(e)) => Some(e),
            }
        };
        let outcome = self.live(epoch, |s| {
            s.accept_group_msg(gid, env, entry.as_ref(), now_ms())
        });
        match outcome {
            None => (Flow::Stop, false),
            Some(o) => (Flow::Next, self.note_outcome(epoch, &o)),
        }
    }

    /// Fetches new frames from the inbox and every group queue. Returns the
    /// number of frames that changed local state.
    pub fn poll_once(&self) -> usize {
        let (epoch, client, inbox, mut cursor, groups) = {
            let app = self.app();
            let Some(s) = app.session.as_ref() else {
                return 0;
            };
            let Ok(client) = self.client_for(&s.data.settings) else {
                return 0;
            };
            let groups: Vec<(String, [u8; 32], u64)> = s
                .data
                .groups
                .values()
                .map(|g| (g.id.clone(), *g.key, g.cursor))
                .collect();
            (app.epoch, client, s.inbox(), s.data.inbox_cursor, groups)
        };
        let mut applied = 0usize;
        let mut reached = true;

        'inbox: for _ in 0..POLL_PAGES {
            let page = match client.poll(&inbox, cursor) {
                Ok(p) => p,
                Err(_) => {
                    reached = false;
                    break;
                }
            };
            let count = page.frames.len();
            for (seq, data) in &page.frames {
                let (flow, hit) = self.handle_inbox_frame(epoch, &client, data);
                match flow {
                    Flow::Stop => return applied,
                    Flow::Retry => break 'inbox,
                    Flow::Next => {
                        applied += usize::from(hit);
                        cursor = *seq;
                        self.live(epoch, |s| {
                            s.data.inbox_cursor = cursor;
                            s.dirty = true;
                        });
                    }
                }
            }
            if count < 100 {
                break;
            }
        }

        for (gid, key, mut gcursor) in groups {
            let Ok(q) = aegis_core::group::group_queue(&key) else {
                continue;
            };
            'group: for _ in 0..POLL_PAGES {
                let page = match client.poll(&q, gcursor) {
                    Ok(p) => p,
                    Err(_) => {
                        reached = false;
                        break;
                    }
                };
                let count = page.frames.len();
                for (seq, data) in &page.frames {
                    let (flow, hit) = self.handle_group_frame(epoch, &client, &gid, data);
                    match flow {
                        Flow::Stop => return applied,
                        Flow::Retry => break 'group,
                        Flow::Next => {
                            applied += usize::from(hit);
                            gcursor = *seq;
                            self.live(epoch, |s| {
                                if let Some(g) = s.data.groups.get_mut(&gid) {
                                    g.cursor = gcursor;
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
        }

        self.live(epoch, |s| s.sweep(now_ms()));
        self.app().net_ok = Some(reached);
        let _ = self.flush();
        self.changed();
        applied
    }

    pub fn sweep(&self) {
        if self.mutate_if(|s| s.sweep(now_ms())) {
            self.changed();
        }
    }

    fn mutate_if(&self, f: impl FnOnce(&mut Session) -> bool) -> bool {
        let mut app = self.app();
        app.session.as_mut().is_some_and(f)
    }

    // ---- job runner -----------------------------------------------------------

    fn set_busy(&self, key: Option<&'static str>) {
        self.app().busy = key;
        self.changed();
    }

    fn finish(&self, r: Result<Option<(&'static str, String)>, Failure>) {
        {
            let mut app = self.app();
            app.busy = None;
            app.flash = match r {
                Ok(None) => None,
                Ok(Some((key, detail))) => Some(Flash {
                    ok: true,
                    key,
                    detail,
                }),
                Err(f) => Some(Flash {
                    ok: false,
                    key: f.key,
                    detail: f.detail,
                }),
            };
        }
        self.changed();
    }

    /// Executes one job synchronously. Called from the worker thread, and directly in tests.
    pub fn exec(&self, job: Job) {
        match job {
            Job::Create {
                username,
                display,
                password,
                confirm,
            } => {
                self.set_busy(Some("busy.create"));
                let r = self.create_account(&username, &display, &password, &confirm);
                self.finish(r.map(|()| None));
            }
            Job::Unlock { username, password } => {
                self.set_busy(Some("busy.unlock"));
                let r = self.unlock(&username, &password);
                self.finish(r.map(|()| None));
            }
            Job::Import { path, password } => {
                self.set_busy(Some("busy.unlock"));
                let r = self.import_vault(&path, &password);
                self.finish(r.map(|()| None));
            }
            Job::AddContact(u) => {
                self.set_busy(Some("busy.lookup"));
                let r = self.add_contact(&u);
                self.finish(r.map(|()| None));
            }
            Job::Send { chat, text } => {
                let r = self.send_message(&chat, &text, None);
                self.finish(r.map(|()| None));
            }
            Job::Retry { chat, id } => {
                let r = self.retry(&chat, &id);
                self.finish(r.map(|()| None));
            }
            Job::CreateGroup { title, members } => {
                self.set_busy(Some("busy.group"));
                let r = self.create_group(&title, &members);
                self.finish(r.map(|()| None));
            }
            Job::ResendInvite { group, member } => {
                let r = self.resend_invite(&group, &member);
                self.finish(r.map(|()| Some(("ok.invite_sent", format!("@{member}")))));
            }
            Job::TestConnection { endpoint, socks5 } => {
                self.app().conn = Some(ConnTest::Running);
                self.changed();
                let r = self.test_connection(endpoint.trim().trim_end_matches('/'), socks5.trim());
                self.app().conn = Some(match r {
                    Ok(()) => ConnTest::Reachable,
                    Err(f) => ConnTest::Failed(f),
                });
                self.changed();
            }
            Job::UpdateDisplay(name) => {
                self.set_busy(Some("busy.profile"));
                let r = self.update_display(&name);
                self.finish(r.map(|()| Some(("ok.saved", String::new()))));
            }
            Job::Export(path) => {
                let r = self.export_vault(&path);
                self.finish(r.map(|p| Some(("ok.exported", p))));
            }
            Job::DeleteAccount(confirm) => {
                let r = self.delete_account(&confirm);
                self.finish(r.map(|()| Some(("ok.deleted", String::new()))));
            }
            Job::Flush => {
                if let Err(f) = self.flush() {
                    self.finish(Err(f));
                }
            }
            Job::Persist(s) => self.persist(*s),
            Job::Stop => {}
        }
    }
}

fn send_all(client: &Client, items: Vec<(String, Outbound)>) -> Vec<String> {
    items
        .into_iter()
        .filter_map(|(member, out)| client.send(&out.queue, &out.padded).err().map(|_| member))
        .collect()
}

fn read_vault_file(path: &Path) -> Result<Vec<u8>, Failure> {
    let meta = std::fs::metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Failure::new("err.no_account")
        } else {
            io_failure(&e)
        }
    })?;
    if !meta.is_file() || meta.len() > MAX_VAULT_BYTES {
        return Err(Failure::new("err.vault_format"));
    }
    std::fs::read(path).map_err(|e| io_failure(&e))
}

fn decode_vault(password: &str, bytes: &[u8]) -> Result<Data, Failure> {
    let plain = vault_decrypt(password, bytes)?;
    let data: Data =
        serde_json::from_slice(&plain).map_err(|_| Failure::new("err.vault_format"))?;
    if data.schema != SCHEMA {
        return Err(Failure::new("err.vault_format"));
    }
    Ok(data)
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
