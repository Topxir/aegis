//! Shared application state and everything that talks to the disk or the network.
//!
//! The UI thread only takes short locks on [`App`]; slow work (key derivation,
//! proof of work, HTTP) happens outside the lock and re-checks the session epoch
//! before writing its result back.

use crate::config::Config;
use crate::i18n::Lang;
use crate::media;
use crate::model::{Data, MediaRef, MsgState, Settings, SCHEMA};
use crate::tor;
use crate::session::{
    ChainRx,
    now_ms, now_s, ChatRef, Draft, Failure, Need, Outbound, Outcome, Payload, Sendable, Session,
};
use aegis_core::attach::{
    open_attachment, seal_attachment, AttachmentDescriptor, AttachmentMeta, MediaKind,
};
use aegis_core::envelope::{Envelope, Kind};
use aegis_core::session::Action;
use aegis_core::group::group_decrypt;
use aegis_core::identity::{normalize_username, Identity};
use aegis_core::net::{Client, DirEntry};
use aegis_core::seal::open_dm;
use aegis_core::text::sanitize_display_text;
use aegis_core::vault::{vault_decrypt, vault_encrypt, vault_file_name, write_atomic};
use aegis_core::{channel, official};
use aegis_core::{directory, pad, Error};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub mod cover;
mod extra;
mod lock;
mod notice;
pub mod invites;
mod oseal;
mod pin;
mod timer;
pub mod update;

const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
const POLL_PAGES: usize = 10;
const KEY_RECHECK: Duration = Duration::from_secs(600);

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
    Account(&'static str),
    NewChannel,
    ChannelInfo(String),
    Contacts,
}

/// Sections of the account cabinet, in display order.
pub const SECTIONS: [&str; 7] = [
    "privacy",
    "connection",
    "appearance",
    "notifications",
    "profile",
    "data",
    "about",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialog {
    DeleteChat(String),
    LeaveGroup(String),
    LeaveChannel(String),
    ClearChat(ChatRef),
    DeleteAccount,
    /// Turning Tor off, with the connection settings to save once confirmed.
    TorOff(crate::connection::ConnForm),
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
    /// Chat of the latest message that asked for attention.
    pub note: Option<ChatRef>,
    /// Info panel next to the open chat.
    pub info: bool,
    /// Keys the page-visible media ids; changes on every start.
    pub media_secret: [u8; 32],
    /// The server showed another transport key than the pinned one. Nothing is sent.
    pub key_alert: bool,
    /// The reset-key confirmation step is showing.
    pub key_reset_ask: bool,
    /// When the server key was last compared with the pinned one.
    pub key_checked: Option<Instant>,
    /// Next time to top up the one-time prekeys on the server.
    pub prekeys_due: Instant,
    /// A PIN, and a duress PIN, are set for the open account.
    pub pin_on: bool,
    pub duress_on: bool,
    /// Tries left the server last reported for a wrong PIN (memory only).
    pub pin_left: Option<u32>,
    /// State of the embedded Tor client.
    pub tor: tor::Status,
    /// Step of the first-run tour while it is open again from the settings.
    pub guide: Option<u8>,
    pub update: update::State,
    /// The invite link made last, shown until the account is locked (memory only).
    pub invite: Option<Zeroizing<String>>,
    /// An invite link to open once an account is unlocked.
    pub link_in: Option<Zeroizing<String>>,
    /// Invite accepts that could not be posted yet.
    pub accepts: Vec<crate::session::Outbound>,
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
            note: None,
            info: false,
            media_secret: aegis_core::random_bytes::<32>().unwrap_or([7; 32]),
            key_alert: false,
            key_reset_ask: false,
            key_checked: None,
            prekeys_due: Instant::now(),
            pin_on: false,
            duress_on: false,
            pin_left: None,
            tor: tor::Status::Off,
            guide: None,
            update: update::State::new(),
            invite: None,
            link_in: None,
            accepts: Vec::new(),
        }
    }

    pub fn lang(&self) -> Lang {
        self.session
            .as_ref()
            .map_or(self.pre_lang, |s| s.data.settings.lang)
    }
}

const PREKEY_EVERY: Duration = Duration::from_secs(30 * 60);

enum Resolved {
    Held,
    Dropped,
    Stop,
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
    AcceptRequest {
        x: String,
        username: String,
    },
    Send {
        chat: ChatRef,
        text: String,
    },
    Retry {
        chat: ChatRef,
        id: String,
    },
    SetTimer {
        chat: ChatRef,
        ttl: u64,
    },
    PickMedia(ChatRef),
    SendMedia {
        chat: ChatRef,
        path: PathBuf,
    },
    CreateChannel {
        title: String,
        about: String,
        members: Vec<String>,
    },
    InviteChannel {
        channel: String,
        members: Vec<String>,
    },
    SaveProfile {
        display: String,
        about: String,
        particles: String,
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
        tor: bool,
    },
    UpdateDisplay(String),
    CreateInvite,
    RedeemInvite(Zeroizing<String>),
    SetHidden(bool),
    PinSet {
        pin: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    PinRemove(Zeroizing<String>),
    DuressSet {
        pin: Zeroizing<String>,
        duress: Zeroizing<String>,
    },
    DuressClear,
    Export(String),
    DeleteAccount(String),
    Flush,
    Persist(Box<Session>),
    InstallUpdate,
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

/// One frame ready to post: the tag the caller knows it by, the sealed frame, whether the
/// vault must be saved first, and a key distribution to note once it is out.
type Step = (Option<String>, Result<Outbound, Failure>, bool, Option<(String, [u8; 16], String)>);

pub struct Engine {
    cfg: Config,
    app: Mutex<App>,
    save_lock: Mutex<()>,
    /// Held for the length of a poll cycle; a second cycle is skipped instead of overlapping.
    poll_lock: Mutex<()>,
    on_change: Box<dyn Fn() + Send + Sync>,
    /// Mirror of `App::key_alert` that can be read while the app lock is held.
    key_alert: AtomicBool,
    kick: Mutex<Option<Sender<()>>>,
    /// The window is on screen (not minimized). Cover traffic runs only then.
    visible: AtomicBool,
    /// Real requests wait here for their cover-traffic slot.
    pub gate: cover::Gate,
    tor: tor::Tor,
    me: std::sync::Weak<Engine>,
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

/// 0 off, 1 standard, 2 high.
pub fn cover_level(s: &str) -> u8 {
    match s {
        "off" => 0,
        "high" => 2,
        _ => 1,
    }
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
        Arc::new_cyclic(|me| Self {
            tor: tor::Tor::default(),
            me: me.clone(),
            cfg,
            app: Mutex::new(App::new()),
            save_lock: Mutex::new(()),
            poll_lock: Mutex::new(()),
            on_change: Box::new(on_change),
            key_alert: AtomicBool::new(false),
            kick: Mutex::new(None),
            visible: AtomicBool::new(true),
            gate: cover::Gate::default(),
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
            d.any(|e| {
                e.is_ok_and(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n.ends_with(".vault") || n.ends_with(".vault.ghost")
                })
            })
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
            Some(s) if s.data.settings.app_lock && s.data.settings.idle_min > 0 => {
                app.last_activity.elapsed()
                    >= Duration::from_secs(u64::from(s.data.settings.idle_min) * 60)
            }
            _ => false,
        }
    }

    pub fn take_attention(&self) -> bool {
        std::mem::take(&mut self.app().attention)
    }

    /// A client on the sealed transport with the pinned server key. It does not touch the
    /// network, so it is safe to call while the app lock is held.
    fn client_for(&self, s: &Settings) -> Result<Client, Failure> {
        if self.key_alert.load(Ordering::SeqCst) {
            return Err(Failure::new("err.server_key_changed"));
        }
        let socks = self.socks_for(s)?;
        let Some(key) = s.pinned_key() else {
            return Err(Failure::new("err.server_key_unset"));
        };
        Ok(Client::new(&crate::connection::endpoint_for(&s.endpoint, s.tor)?, socks.as_deref())?
            .with_pow_bits(self.cfg.pow_bits)
            .with_server_key(key))
    }

    /// The SOCKS5 address for `s`. With Tor on this is always the embedded client, and while it
    /// is still connecting nothing is sent: there is no fallback to a direct connection.
    fn socks_for(&self, s: &Settings) -> Result<Option<String>, Failure> {
        if s.tor {
            return self
                .tor
                .socks_addr()
                .map(Some)
                .ok_or(Failure::new("err.tor_boot"));
        }
        Ok(s.proxy().map(str::to_owned))
    }

    /// Starts the embedded Tor client when the open account uses it. Never call with the app
    /// lock held: status updates take it.
    pub(crate) fn tor_sync(&self) {
        let (on, torrc) = match self.app().session.as_ref() {
            Some(s) => (s.data.settings.tor, crate::bridges::torrc_for(&s.data.settings)),
            None => (false, String::new()),
        };
        if on {
            self.tor.configure(torrc);
        }
        self.tor_sync_for(on);
    }

    fn tor_sync_for(&self, on: bool) {
        if !on {
            return;
        }
        let me = self.me.clone();
        self.tor.ensure_started(&self.cfg.data_dir.join("tor"), move |st| {
            if let Some(e) = me.upgrade() {
                e.app().tor = st;
                e.changed();
            }
        });
    }

    /// Forgets the pinned key after the user confirmed twice; the next check pins whatever
    /// the server shows then.
    pub fn reset_server_key(&self) {
        let mut app = self.app();
        if !app.key_alert || !app.key_reset_ask {
            return;
        }
        if let Some(s) = app.session.as_mut() {
            s.data.settings.server_key = None;
            s.data.settings.server_key_for.clear();
            s.dirty = true;
        }
        app.key_alert = false;
        app.key_reset_ask = false;
        app.key_checked = None;
        app.prekeys_due = Instant::now();
        self.key_alert.store(false, Ordering::SeqCst);
        drop(app);
        self.kick_poll();
        self.changed();
    }

    /// Stops all network traffic and shows the blocking screen.
    fn raise_key_alert(&self) {
        self.key_alert.store(true, Ordering::SeqCst);
        self.app().key_alert = true;
        self.changed();
    }

    /// Fetches the server key. The first key seen for an endpoint is pinned in `st`; a
    /// different key later is a hard stop.
    fn pin_key(&self, st: &mut Settings) -> Result<(), Failure> {
        let known = st.pinned_key();
        let socks = self.socks_for(st)?;
        let client = Client::new(&crate::connection::endpoint_for(&st.endpoint, st.tor)?, socks.as_deref())?
            .with_pow_bits(self.cfg.pow_bits)
            .with_pinned_server_key(known)
            .map_err(|e| {
                if matches!(e, Error::ServerKeyChanged) {
                    self.raise_key_alert();
                }
                Failure::from(e)
            })?;
        if known.is_none() {
            st.server_key = client.server_key();
            st.server_key_for.clone_from(&st.endpoint);
        }
        Ok(())
    }

    /// Compares the server key with the pinned one, pinning it on first use. Network errors
    /// are ignored here; the next poll tries again.
    pub(crate) fn verify_server_key(&self) {
        let (epoch, mut st) = {
            let app = self.app();
            match app.session.as_ref() {
                Some(s) => (app.epoch, s.data.settings.clone()),
                None => return,
            }
        };
        let had = st.pinned_key().is_some();
        let ok = self.pin_key(&mut st).is_ok();
        if ok {
            self.app().key_checked = Some(Instant::now());
        }
        if ok && !had {
            self.live(epoch, |s| {
                if s.data.settings.endpoint == st.endpoint {
                    s.data.settings.server_key = st.server_key;
                    s.data.settings.server_key_for.clone_from(&st.server_key_for);
                    s.dirty = true;
                }
            });
        }
    }

    /// True when the pinned key is missing or has not been compared for a while.
    fn key_check_due(&self) -> bool {
        let app = self.app();
        let Some(s) = app.session.as_ref() else {
            return false;
        };
        s.data.settings.pinned_key().is_none()
            || app.key_checked.is_none_or(|t| t.elapsed() > KEY_RECHECK)
    }

    fn install(&self, s: Session) {
        // A stand-in left by the duress PIN is not needed once the account exists again.
        let _ = std::fs::remove_file(pin::side(&self.vault_path(&s.data.username), "ghost"));
        {
            let mut app = self.app();
            app.session = Some(s);
            app.epoch += 1;
            app.route = if app.link_in.is_some() {
                Route::NewChat
            } else {
                Route::Welcome
            };
            app.invite = None;
            app.dialog = None;
            app.info = false;
            app.flash = None;
            app.conn = None;
            app.net_ok = None;
            app.last_activity = Instant::now();
            app.key_checked = None;
        }
        self.refresh_pin();
        self.tor_sync();
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
        app.key_alert = false;
        app.key_reset_ask = false;
        app.key_checked = None;
        self.key_alert.store(false, Ordering::SeqCst);
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
        let path = self.vault_path(&s.data.username);
        write_atomic(&path, &enc)?;
        pin::sync_meta(&path, &s.data.settings);
        s.dirty = false;
        Ok(())
    }

    /// Saves the live session if it changed.
    pub fn flush(&self) -> Result<(), Failure> {
        let _g = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (plain, pw, epoch, path, st) = {
            let mut app = self.app();
            let epoch = app.epoch;
            let Some(s) = app.session.as_mut() else {
                return Ok(());
            };
            if !s.dirty {
                s.dirty = false;
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
                s.data.settings.clone(),
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
        } else {
            pin::sync_meta(&path, &st);
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
        // Tor is on for the public server. A build pointed at another server, such as a local
        // test one, starts without it, since Tor cannot reach a loopback address.
        s.data.settings.tor =
            crate::model::same_endpoint(&self.cfg.default_endpoint, crate::model::DEFAULT_ENDPOINT);
        let identity = identity_of(&s);
        let mut st = s.data.settings.clone();
        self.pin_key(&mut st)?;
        s.data.settings = st;
        s.dirty = true;
        self.write_session(&mut s)?;
        let registered = self
            .client_for(&s.data.settings)
            .and_then(|c| c.register(&identity, &u, "").map_err(Failure::from));
        if let Err(e) = registered {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        self.install(s);
        Ok(())
    }

    /// `secret` is the password, or the PIN when one is set for this account. A password has
    /// at least ten characters and a PIN is four or six digits, so the two never overlap.
    pub fn unlock(&self, username: &str, password: &str) -> Result<(), Failure> {
        let u = normalize_username(username)?;
        let path = self.vault_path(&u);
        if Self::is_ghost(&path) {
            if let Some(f) = self.ghost_unlock(&path, password) {
                return Err(f);
            }
        }
        if aegis_core::pin::is_valid_pin(password) && pin::side(&path, "pin").exists() {
            return self.pin_unlock(&u, &path, password);
        }
        let bytes = read_vault_file(&path)?;
        let data = decode_vault(password, &bytes)?;
        if data.username != u {
            return Err(Failure::new("err.vault_format"));
        }
        self.install(Session::new(data, password)?);
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
        let s = Session::new(data, password)?;
        write_atomic(&dest, &bytes)?;
        self.install(s);
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
        {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            if s.data.username != confirm.trim() {
                return Err(Failure::new("err.confirm_name"));
            }
        }
        self.pin_free_slot();
        let _g = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut app = self.app();
        let Some(s) = app.session.as_ref() else {
            return Err(Failure::new("err.locked"));
        };
        if s.data.username != confirm.trim() {
            return Err(Failure::new("err.confirm_name"));
        }
        let path = self.vault_path(&s.data.username);
        let _ = std::fs::remove_dir_all(media::media_dir(&path));
        pin::remove_pin_files(&path);
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
            let entry = self.net_lookup(&client, &u)?.ok_or(Failure::new("err.not_found"))?;
            self.live(epoch, |s| s.add_contact(&entry, now_ms()));
            self.send_profile_to(&client, &u);
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
        let (epoch, client, id, out): (u64, Client, String, Sendable) = {
            let mut app = self.app();
            let epoch = app.epoch;
            let s = app.session.as_mut().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            let now = now_ms();
            let (id, out) = s.prepare_send(chat, Payload::Text(text.to_owned()), retry_id, now)?;
            (epoch, client, id, out)
        };
        self.changed();
        let res = self
            .deliver(epoch, &client, vec![(id.clone(), out)])
            .pop()
            .map_or(Ok(()), |(_, r)| r);
        let state = if res.is_ok() {
            MsgState::Sent
        } else {
            MsgState::Failed
        };
        self.live(epoch, |s| s.set_msg_state(chat, &id, state));
        res
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
        let failed = self.deliver_drafts(epoch, &client, invites);
        self.kick_poll();
        let _ = gid;
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
        let (epoch, client, d) = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            let client = self.client_for(&s.data.settings)?;
            (app.epoch, client, s.invite_frame(group, member, now_ms())?)
        };
        self.deliver(epoch, &client, vec![(member.to_owned(), Sendable::Draft(d))])
            .pop()
            .map_or(Ok(()), |(_, r)| r)
    }

    /// The display name stays on this device; contacts get it in the profile card and in
    /// every envelope. The directory keeps no name (spec section 3).
    pub fn update_display(&self, name: &str) -> Result<(), Failure> {
        let name = sanitize_display_text(name.trim());
        if !directory::is_valid_title(&name) {
            return Err(Failure::new("err.display"));
        }
        self.mutate(|s| {
            s.data.display = name;
            s.dirty = true;
        })
        .ok_or(Failure::new("err.locked"))
    }

    pub fn test_connection(&self, endpoint: &str, socks5: &str, tor: bool) -> Result<(), Failure> {
        let saved_off = self.app().session.as_ref().is_some_and(|s| !s.data.settings.tor);
        if !tor && !saved_off {
            return Err(Failure::new("err.tor_off_first"));
        }
        let endpoint = crate::connection::endpoint_for(endpoint, tor)?;
        let endpoint = endpoint.as_str();
        let socks = if tor {
            self.tor_sync_for(true);
            let mut up = self.tor.socks_addr();
            for _ in 0..180 {
                if up.is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
                up = self.tor.socks_addr();
            }
            up.ok_or(Failure::new("err.tor_boot"))?
        } else {
            let socks = socks5.to_owned();
            if !socks.is_empty() && !valid_socks(&socks) {
                return Err(Failure::new("err.socks"));
            }
            socks
        };
        let known = {
            let app = self.app();
            app.session
                .as_ref()
                .filter(|s| crate::model::same_endpoint(&s.data.settings.connect_endpoint(), endpoint))
                .and_then(|s| s.data.settings.pinned_key())
        };
        let proxy = (!socks.is_empty()).then_some(socks.as_str());
        let client = Client::new(endpoint, proxy)?
            .with_pinned_server_key(known)
            .map_err(|e| {
                if known.is_some() && matches!(e, Error::ServerKeyChanged) {
                    self.raise_key_alert();
                }
                Failure::from(e)
            })?;
        client.health()?;
        Ok(())
    }

    /// Saves the connection settings: server, proxy, Tor and cover traffic.
    pub fn apply_connection(
        &self,
        endpoint: &str,
        socks5: &str,
        tor: bool,
        cover: &str,
        bridges: &str,
        bridge_lines: &str,
    ) -> Result<(), Failure> {
        let endpoint = crate::model::normalize_endpoint(endpoint);
        let socks5 = socks5.trim().to_owned();
        aegis_core::net::Endpoint::parse(&endpoint)?;
        crate::connection::endpoint_for(&endpoint, tor)?;
        let (bridges, bridge_lines) = crate::bridges::check(bridges, bridge_lines)?;
        if !socks5.is_empty() && !valid_socks(&socks5) {
            return Err(Failure::new("err.socks"));
        }
        let cover = cover_level(cover);
        self.mutate(|s| {
            let st = &mut s.data.settings;
            if !crate::model::same_endpoint(&st.endpoint, &endpoint) {
                st.server_key = None;
                st.server_key_for.clear();
            }
            st.endpoint = endpoint;
            st.socks5 = socks5;
            st.tor = tor;
            st.cover = cover;
            st.bridges = bridges.code().to_owned();
            st.bridge_lines = bridge_lines;
        })
        .ok_or(Failure::new("err.locked"))?;
        self.app().key_checked = None;
        self.tor_sync();
        self.kick_poll();
        Ok(())
    }

    pub fn apply_privacy(&self, idle_min: u32, protect: bool) -> Result<(), Failure> {
        if idle_min > 24 * 60 {
            return Err(Failure::new("err.generic"));
        }
        self.mutate(|s| {
            s.data.settings.idle_min = idle_min;
            s.data.settings.protect = protect;
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
                let muted = app.session.as_ref().is_some_and(|s| s.is_muted(r));
                if route == Route::Chat(r.clone()) {
                    if let Some(s) = app.session.as_mut() {
                        s.mark_read(r);
                    }
                }
                if flash && !muted {
                    app.attention = true;
                    app.note = Some(r.clone());
                }
                true
            }
            Outcome::GroupJoined(_) | Outcome::ChannelJoined(_) => {
                app.attention |= flash;
                true
            }
            Outcome::Profile(_) => true,
            Outcome::KeyChanged(_) => true,
            Outcome::Timer(_) => true,
            Outcome::Dropped => false,
        }
    }

    fn handle_inbox_frame(&self, epoch: u64, client: &Client, padded: &[u8]) -> (Flow, bool) {
        let Ok(frame) = pad::unpad(padded) else {
            return (Flow::Next, false);
        };
        if frame.first() == Some(&0x03) {
            return self.handle_session_frame(epoch, client, &frame, true);
        }
        let opened = match self.live(epoch, |s| open_dm(&s.data.x_sk, &frame)) {
            None => return (Flow::Stop, false),
            Some(Err(_)) => return (Flow::Next, false),
            Some(Ok(o)) => o,
        };
        let env = opened.envelope;
        if env.kind == Kind::Iacc {
            return self.handle_accept(epoch, client, &env, opened.sender_x_pk);
        }
        if !matches!(
            env.kind,
            Kind::Dm | Kind::Dmf | Kind::Ginv | Kind::Cinv | Kind::Prof | Kind::Ttl
        ) {
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
            Some(Some(false)) => match self.net_lookup(client, &env.sender) {
                Err(_) => return (Flow::Retry, false),
                Ok(None) => return (Flow::Next, false),
                Ok(Some(e)) => Some(e),
            },
        };
        let sender_x = opened.sender_x_pk;
        let mut media = None;
        let mut env = env;
        if env.kind == Kind::Dmf {
            let ok = self.live(epoch, |s| s.inbox_plausible(&env, sender_x, entry.as_ref()));
            match ok {
                None => return (Flow::Stop, false),
                Some(false) => return (Flow::Next, false),
                Some(true) => {}
            }
            match self.with_media(epoch, client, env) {
                Ok((e, m)) => {
                    env = e;
                    media = m;
                }
                Err(f) => return (f, false),
            }
        }
        let outcome = self.live(epoch, |s| {
            s.accept_inbox(env, sender_x, entry.as_ref(), media, now_ms())
        });
        match outcome {
            None => (Flow::Stop, false),
            Some(o) => (Flow::Next, self.note_outcome(epoch, &o)),
        }
    }

    /// Seals one draft on its pairwise session, taking the contact's prekeys when no session
    /// exists yet.
    fn seal(&self, epoch: u64, client: &Client, d: &Draft) -> Result<Outbound, Failure> {
        for round in 0..2 {
            match self.live(epoch, |s| s.seal_draft(d, now_s())) {
                None => return Err(Failure::new("err.locked")),
                Some(Ok(o)) => return Ok(o),
                Some(Err(Need::Fail(f))) => return Err(f),
                Some(Err(Need::Prekeys)) => {
                    if round == 1 {
                        return Err(Failure::new("err.needs_update"));
                    }
                    let ed = self.live(epoch, |s| s.data.contacts.get(&d.to).map(|c| c.ed)).flatten();
                    let Some(b) = self.net_prekeys_take(client, &d.to, ed.as_ref())? else {
                        return Err(Failure::new("err.needs_update"));
                    };
                    match self.live(epoch, |s| s.begin_session(&d.to, &b, now_s())) {
                        None => return Err(Failure::new("err.locked")),
                        Some(Err(_)) => return Err(Failure::new("err.needs_update")),
                        Some(Ok(())) => {}
                    }
                }
            }
        }
        Err(Failure::new("err.needs_update"))
    }

    /// Seals every draft, saves the vault once, and only then posts. A session frame never
    /// leaves before the ratchet state that produced it is on disk.
    pub(super) fn deliver(
        &self,
        epoch: u64,
        client: &Client,
        items: Vec<(String, Sendable)>,
    ) -> Vec<(String, Result<(), Failure>)> {
        // (tag, sealed frame, needs the vault saved first, key distribution to note once sent)
        let mut ready: Vec<Step> = Vec::new();
        for (tag, it) in items {
            match it {
                Sendable::Frame(o) => ready.push((Some(tag), Ok(o), false, None)),
                Sendable::Draft(d) => {
                    let r = self.seal(epoch, client, &d);
                    ready.push((Some(tag), r, true, None));
                }
                Sendable::Chain(cd) => match self.live(epoch, |s| s.seal_chain(&cd, now_s())) {
                    None => ready.push((Some(tag), Err(Failure::new("err.locked")), false, None)),
                    Some(Err(f)) => ready.push((Some(tag), Err(f), false, None)),
                    Some(Ok(cs)) => {
                        // Members without the chain get it first, through their sessions.
                        for d in cs.skeys {
                            let to = d.to.clone();
                            let r = self.seal(epoch, client, &d);
                            ready.push((None, r, true, Some((cd.id.clone(), cs.chain_id, to))));
                        }
                        ready.push((Some(tag), Ok(cs.out), true, None));
                    }
                },
            }
        }
        let saved = if ready.iter().any(|(_, r, d, _)| *d && r.is_ok()) {
            self.flush()
        } else {
            Ok(())
        };
        let mut out = Vec::new();
        for (tag, r, draft, given) in ready {
            let r = match (r, draft, &saved) {
                (Ok(_), true, Err(f)) => Err(f.clone()),
                (Ok(o), _, _) => {
                    self.net_send(client, &o.queue, &o.padded)
                        .map(|_| ())
                        .map_err(Failure::from)
                }
                (Err(f), _, _) => Err(f),
            };
            if let (Ok(()), Some((id, chain_id, user))) = (&r, given) {
                self.live(epoch, |s| s.mark_given(&id, chain_id, &[user]));
            }
            if let Some(tag) = tag {
                out.push((tag, r));
            }
        }
        out
    }

    /// Tags of the drafts that could not be sent.
    pub(super) fn deliver_drafts(
        &self,
        epoch: u64,
        client: &Client,
        items: Vec<(String, Draft)>,
    ) -> Vec<String> {
        let items = items
            .into_iter()
            .map(|(t, d)| (t, Sendable::Draft(d)))
            .collect();
        self.deliver(epoch, client, items)
            .into_iter()
            .filter_map(|(t, r)| r.err().map(|_| t))
            .collect()
    }

    /// Tops up the one-time prekeys on the server. At most two uploads per call.
    fn refill_prekeys(&self, epoch: u64, client: &Client) {
        {
            let mut app = self.app();
            if app.epoch != epoch || Instant::now() < app.prekeys_due {
                return;
            }
            app.prekeys_due = Instant::now() + Duration::from_secs(60);
        }
        let mut hint: Option<usize> = None;
        for _ in 0..2 {
            let put = match self.live(epoch, |s| s.prekey_request(hint, now_s())) {
                Some(Ok(p)) => p,
                _ => return,
            };
            if self.flush().is_err() {
                return;
            }
            let Ok(n) = client.prekeys_put(&put) else {
                return;
            };
            if hint.is_some() || aegis_core::x3dh::opks_needed(n) == 0 {
                break;
            }
            hint = Some(n);
        }
        self.app().prekeys_due = Instant::now() + PREKEY_EVERY;
    }

    /// Retries messages whose attachment could not be fetched earlier.
    fn retry_deferred(&self, epoch: u64, client: &Client) -> bool {
        let Some(list) = self.live(epoch, |s| s.take_deferred()) else {
            return false;
        };
        let mut hit = false;
        for (kind, contact, env) in list {
            let h = match kind.as_str() {
                "g" | "c" => self.process_chain_env(epoch, client, &contact, env).1,
                _ => self.process_session_env(epoch, client, &contact, env).1,
            };
            hit |= h;
        }
        hit
    }

    /// Opens a type 0x03 frame and applies what the session layer asks for.
    fn handle_session_frame(
        &self,
        epoch: u64,
        client: &Client,
        frame: &[u8],
        may_lookup: bool,
    ) -> (Flow, bool) {
        let received = match self.live(epoch, |s| s.session_receive(frame, now_s())) {
            None => return (Flow::Stop, false),
            Some(Err(_)) => return (Flow::Next, false),
            Some(Ok(r)) => r,
        };
        let mut hit = false;
        let mut lookup: Option<[u8; 32]> = None;
        for a in &received.actions {
            match a {
                Action::UndecryptableNotice { contact } => {
                    let o = self.live(epoch, |s| s.note_undecryptable(contact, now_ms()));
                    if let Some(o) = o {
                        hit |= self.note_outcome(epoch, &o);
                    }
                }
                Action::LookupSender { x_pk } => lookup = Some(*x_pk),
                // The session is marked as needing a start; the next send takes prekeys.
                Action::NeedsPrekeysFetch { .. } | Action::StartNewSession { .. } => {}
            }
        }
        if let Some(x) = lookup {
            if !may_lookup {
                return (Flow::Next, hit);
            }
            return match self.resolve_sender(epoch, x, frame) {
                Resolved::Held => (Flow::Next, true),
                Resolved::Dropped => (Flow::Next, hit),
                Resolved::Stop => (Flow::Stop, hit),
            };
        }
        if let (Some(contact), Some(env)) = (received.contact, received.envelope) {
            let (f, h) = self.process_session_env(epoch, client, &contact, env);
            return (f, h || hit);
        }
        (Flow::Next, hit)
    }

    /// A frame from a key that is not a contact. Nothing goes to the network: asking the
    /// directory about the people we share groups or channels with would show the server who
    /// they are. The frame waits as a request; matching happens when the user names the sender
    /// and accepts (`accept_request`), and the directory is asked about that one name only.
    fn resolve_sender(&self, epoch: u64, x: [u8; 32], frame: &[u8]) -> Resolved {
        let blocked = self.live(epoch, |s| s.is_blocked(&x));
        match blocked {
            None => return Resolved::Stop,
            Some(true) => return Resolved::Dropped,
            Some(false) => {}
        }
        match self.live(epoch, |s| s.add_pending(x, frame, now_ms())) {
            None => Resolved::Stop,
            Some(()) => Resolved::Held,
        }
    }

    /// A sender key from `contact`: store it, then open what was waiting for it.
    fn process_skey(
        &self,
        epoch: u64,
        client: &Client,
        contact: &str,
        env: Envelope,
    ) -> (Flow, bool) {
        let id = env.group_id.clone();
        let Some(accepted) = self.live(epoch, |s| s.accept_skey(contact, &env, now_s()).is_ok())
        else {
            return (Flow::Stop, false);
        };
        if !accepted {
            return (Flow::Next, false);
        }
        let held = self.live(epoch, |s| s.take_held(&id)).unwrap_or_default();
        let mut hit = false;
        for f in held {
            let (flow, h) = self.handle_chain_frame(epoch, client, &id, &f);
            hit |= h;
            if matches!(flow, Flow::Stop) {
                return (Flow::Stop, hit);
            }
        }
        (Flow::Next, hit)
    }

    /// Opens a type 0x05 frame of a group or channel. A frame whose chain has not arrived
    /// yet is kept until the sender key shows up.
    fn handle_chain_frame(
        &self,
        epoch: u64,
        client: &Client,
        id: &str,
        frame: &[u8],
    ) -> (Flow, bool) {
        let rx = self.live(epoch, |s| s.chain_decrypt(id, frame, now_s()));
        match rx {
            None => (Flow::Stop, false),
            Some(ChainRx::Bad) => (Flow::Next, false),
            Some(ChainRx::Unknown) => {
                self.live(epoch, |s| s.hold_frame(id, frame));
                (Flow::Next, false)
            }
            // The ratchet has moved: whatever happens next, this message must not be lost.
            Some(ChainRx::Env(env)) => self.process_chain_env(epoch, client, id, *env),
        }
    }

    /// Applies a message that was opened on a sender chain.
    fn process_chain_env(
        &self,
        epoch: u64,
        client: &Client,
        id: &str,
        env: Envelope,
    ) -> (Flow, bool) {
        let group = self.live(epoch, |s| {
            if s.data.groups.contains_key(id) {
                Some(true)
            } else if s.data.channels.contains_key(id) {
                Some(false)
            } else {
                None
            }
        });
        let is_group = match group {
            None => return (Flow::Stop, false),
            Some(None) => return (Flow::Next, false),
            Some(Some(g)) => g,
        };
        let (kind_ok, tag) = if is_group {
            (matches!(env.kind, Kind::Gmsg | Kind::Gmf | Kind::Gttl), "g")
        } else {
            (matches!(env.kind, Kind::Cmsg | Kind::Cmf), "c")
        };
        if !kind_ok || env.group_id != id {
            return (Flow::Next, false);
        }
        let fresh = self.live(epoch, |s| {
            !s.seen.contains(&env.msg_id)
                && env.sender != s.data.username
                && if is_group {
                    s.group_plausible(&env, None)
                        && s.data.groups.get(id).is_some_and(|g| g.members.contains(&env.sender))
                } else {
                    true
                }
        });
        match fresh {
            None => return (Flow::Stop, false),
            Some(false) => return (Flow::Next, false),
            Some(true) => {}
        }
        let kept = env.clone();
        let (env, media) = match self.with_media(epoch, client, env) {
            Ok(v) => v,
            Err(Flow::Retry) => {
                self.live(epoch, |s| s.defer_env(tag, id, &kept));
                return (Flow::Next, false);
            }
            Err(f) => return (f, false),
        };
        let outcome = self.live(epoch, |s| {
            if is_group {
                s.accept_group_msg(id, env, None, media, now_ms())
            } else {
                s.accept_channel_post(id, env, media, now_ms())
            }
        });
        match outcome {
            None => (Flow::Stop, false),
            Some(o) => (Flow::Next, self.note_outcome(epoch, &o)),
        }
    }

    /// Applies a message that came through a session from a known contact.
    fn process_session_env(
        &self,
        epoch: u64,
        client: &Client,
        contact: &str,
        env: Envelope,
    ) -> (Flow, bool) {
        let cx = self.live(epoch, |s| s.data.contacts.get(contact).map(|c| c.x));
        let cx = match cx {
            None => return (Flow::Stop, false),
            Some(None) => return (Flow::Next, false),
            Some(Some(x)) => x,
        };
        if env.kind == Kind::Skey {
            return self.process_skey(epoch, client, contact, env);
        }
        if env.sender != contact
            || !matches!(
                env.kind,
                Kind::Dm | Kind::Dmf | Kind::Ginv | Kind::Cinv | Kind::Prof | Kind::Ttl
            )
        {
            return (Flow::Next, false);
        }
        let mut env = env;
        let mut media = None;
        if env.kind == Kind::Dmf {
            match self.live(epoch, |s| s.inbox_plausible(&env, cx, None)) {
                None => return (Flow::Stop, false),
                Some(false) => return (Flow::Next, false),
                Some(true) => {}
            }
            let kept = env.clone();
            match self.with_media(epoch, client, env) {
                Ok((e, m)) => {
                    env = e;
                    media = m;
                }
                Err(Flow::Retry) => {
                    self.live(epoch, |s| s.defer_env("", contact, &kept));
                    return (Flow::Next, false);
                }
                Err(f) => return (f, false),
            }
        }
        let outcome = self.live(epoch, |s| s.accept_inbox(env, cx, None, media, now_ms()));
        match outcome {
            None => (Flow::Stop, false),
            Some(o) => (Flow::Next, self.note_outcome(epoch, &o)),
        }
    }

    /// The user accepted a waiting request as `username`; the directory must agree.
    pub fn accept_request(&self, x_hex: &str, username: &str) -> Result<(), Failure> {
        let x: [u8; 32] =
            aegis_core::hex::decode_array(x_hex).map_err(|_| Failure::new("err.generic"))?;
        let u = normalize_username(username)?;
        let (epoch, client) = {
            let app = self.app();
            let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
            (app.epoch, self.client_for(&s.data.settings)?)
        };
        let e = self.net_lookup(&client, &u)?.ok_or(Failure::new("err.not_found"))?;
        if e.u != u || e.x != x {
            return Err(Failure::new("err.request_mismatch"));
        }
        let pend = self
            .live(epoch, |s| {
                if s.data.contacts.contains_key(&u) {
                    return Err(Failure::new("err.request_mismatch"));
                }
                s.add_contact(&e, now_ms());
                Ok(s.take_pending(&x))
            })
            .ok_or(Failure::new("err.locked"))??;
        if let Some(p) = pend {
            for h in p.frames {
                if let Ok(f) = aegis_core::hex::decode(&h) {
                    let _ = self.handle_session_frame(epoch, &client, &f, false);
                }
            }
        }
        self.live(epoch, |s| s.dirty = true);
        self.changed();
        Ok(())
    }

    /// The user blocked a waiting request: its frames are dropped and the key is ignored.
    pub fn block_request(&self, x_hex: &str) -> Result<(), Failure> {
        let x: [u8; 32] =
            aegis_core::hex::decode_array(x_hex).map_err(|_| Failure::new("err.generic"))?;
        self.mutate(|s| s.block_key(x))
            .ok_or(Failure::new("err.locked"))?;
        self.changed();
        Ok(())
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
        if frame.first() == Some(&0x05) {
            return self.handle_chain_frame(epoch, client, gid, &frame);
        }
        let decoded = self.live(epoch, |s| {
            let g = s.data.groups.get(gid)?;
            let env = group_decrypt(&g.key, &frame).ok()?;
            if env.group_id != g.id
                || !matches!(env.kind, Kind::Gmsg | Kind::Gmf)
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
        // A member who is not a contact is never looked up: asking the directory about the
        // senders in a group would show the server who is in it (section 7).
        if !known {
            return (Flow::Next, false);
        }
        let entry: Option<DirEntry> = None;
        let mut media = None;
        let mut env = env;
        if env.kind == Kind::Gmf {
            let ok = self.live(epoch, |s| s.group_plausible(&env, entry.as_ref()));
            match ok {
                None => return (Flow::Stop, false),
                Some(false) => return (Flow::Next, false),
                Some(true) => {}
            }
            match self.with_media(epoch, client, env) {
                Ok((e, m)) => {
                    env = e;
                    media = m;
                }
                Err(f) => return (f, false),
            }
        }
        let outcome = self.live(epoch, |s| {
            s.accept_group_msg(gid, env, entry.as_ref(), media, now_ms())
        });
        match outcome {
            None => (Flow::Stop, false),
            Some(o) => (Flow::Next, self.note_outcome(epoch, &o)),
        }
    }

    /// Fetches new frames from the inbox and every group queue. Returns the
    /// number of frames that changed local state.
    pub fn poll_once(&self) -> usize {
        if self.key_alert.load(Ordering::SeqCst) {
            return 0;
        }
        let Ok(_cycle) = self.poll_lock.try_lock() else {
            return 0;
        };
        if self.key_check_due() {
            self.verify_server_key();
        }
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
        self.refill_prekeys(epoch, &client);
        if self.retry_deferred(epoch, &client) {
            applied += 1;
        }
        self.retry_accepts(&client);

        'inbox: for _ in 0..POLL_PAGES {
            let page = match self.net_poll(&client, &inbox, cursor) {
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
                let page = match self.net_poll(&client, &q, gcursor) {
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

        if !self.poll_channels(epoch, &client, &mut reached, &mut applied) {
            return applied;
        }

        self.sweep_expired(epoch);
        self.gc_media(epoch);
        self.app().net_ok = Some(reached);
        let _ = self.flush();
        self.changed();
        applied
    }

    pub fn sweep(&self) {
        let epoch = self.app().epoch;
        if self.sweep_expired(epoch) {
            self.changed();
        }
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
                if r.is_ok() {
                    self.verify_server_key();
                }
                self.finish(r.map(|()| None));
            }
            Job::Import { path, password } => {
                self.set_busy(Some("busy.unlock"));
                let r = self.import_vault(&path, &password);
                if r.is_ok() {
                    self.verify_server_key();
                }
                self.finish(r.map(|()| None));
            }
            Job::AcceptRequest { x, username } => {
                self.set_busy(Some("busy.lookup"));
                let r = self.accept_request(&x, &username);
                self.finish(r.map(|()| None));
            }
            Job::AddContact(u) => {
                self.set_busy(Some("busy.lookup"));
                let r = self.add_contact(&u);
                self.finish(r.map(|()| None));
            }
            Job::CreateInvite => {
                self.set_busy(Some("busy.invite"));
                let r = self.create_invite();
                self.finish(r.map(|()| None));
            }
            Job::RedeemInvite(link) => {
                self.set_busy(Some("busy.invite"));
                let r = self.redeem_invite(&link);
                self.finish(r.map(|()| None));
            }
            Job::SetHidden(on) => {
                self.set_busy(Some("busy.pin"));
                let r = self.set_hidden(on);
                self.finish(r.map(|()| Some(("ok.saved", String::new()))));
            }
            Job::Send { chat, text } => {
                let r = self.send_message(&chat, &text, None);
                self.finish(r.map(|()| None));
            }
            Job::Retry { chat, id } => {
                let r = self.retry(&chat, &id);
                self.finish(r.map(|()| None));
            }
            Job::SetTimer { chat, ttl } => {
                let r = self.set_timer(&chat, ttl);
                self.finish(r.map(|()| None));
            }
            Job::PickMedia(chat) => {
                let r = self.pick_and_send(&chat);
                self.finish(r.map(|()| None));
            }
            Job::SendMedia { chat, path } => {
                let r = self.send_media(&chat, &path);
                self.finish(r.map(|()| None));
            }
            Job::CreateChannel {
                title,
                about,
                members,
            } => {
                self.set_busy(Some("busy.group"));
                let r = self.create_channel(&title, &about, &members);
                self.kick_poll();
                self.finish(r.map(|()| None));
            }
            Job::InviteChannel { channel, members } => {
                let r = self.invite_channel(&channel, &members);
                self.finish(r.map(|()| Some(("ok.invite_sent", String::new()))));
            }
            Job::SaveProfile {
                display,
                about,
                particles,
            } => {
                self.set_busy(Some("busy.profile"));
                let r = self.save_profile(&display, &about, &particles);
                self.finish(r.map(|()| Some(("ok.saved", String::new()))));
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
            Job::TestConnection {
                endpoint,
                socks5,
                tor,
            } => {
                self.app().conn = Some(ConnTest::Running);
                self.changed();
                let r = self.test_connection(
                    endpoint.trim().trim_end_matches('/'),
                    socks5.trim(),
                    tor,
                );
                self.app().conn = Some(match r {
                    Ok(()) => ConnTest::Reachable,
                    Err(f) => ConnTest::Failed(f),
                });
                self.changed();
            }
            Job::UpdateDisplay(name) => {
                self.set_busy(Some("busy.profile"));
                let card = self.mutate(|s| (s.data.about.clone(), s.data.particles.clone()));
                let r = match card {
                    Some((about, particles)) => self.save_profile(&name, &about, &particles),
                    None => Err(Failure::new("err.locked")),
                };
                self.finish(r.map(|()| Some(("ok.saved", String::new()))));
            }
            Job::PinSet { pin, confirm } => {
                self.set_busy(Some("busy.pin"));
                let r = self.pin_set(&pin, &confirm);
                self.finish(r.map(|()| Some(("ok.pin_set", String::new()))));
            }
            Job::PinRemove(pin) => {
                self.set_busy(Some("busy.pin"));
                let r = self.pin_remove(&pin);
                self.finish(r.map(|()| Some(("ok.pin_removed", String::new()))));
            }
            Job::DuressSet { pin, duress } => {
                self.set_busy(Some("busy.pin"));
                let r = self.duress_set(&pin, &duress);
                self.finish(r.map(|()| Some(("ok.duress_set", String::new()))));
            }
            Job::DuressClear => {
                let r = self.duress_clear();
                self.finish(r.map(|()| Some(("ok.duress_cleared", String::new()))));
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
            Job::InstallUpdate => self.restart_into_update(),
            Job::Stop => {}
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_addresses() {
        assert!(valid_socks("127.0.0.1:9050"));
        assert!(valid_socks("localhost:9150"));
        assert!(!valid_socks("127.0.0.1"));
        assert!(!valid_socks("127.0.0.1:0"));
        assert!(!valid_socks("bad host:9050"));
    }

    #[test]
    fn cover_levels() {
        assert_eq!(cover_level("off"), 0);
        assert_eq!(cover_level("std"), 1);
        assert_eq!(cover_level("high"), 2);
        assert_eq!(cover_level("anything"), 1);
    }

    #[test]
    fn pinned_key_belongs_to_its_endpoint() {
        let mut st = Settings::new(Lang::En);
        st.endpoint = "https://c.example".into();
        assert!(st.pinned_key().is_none());
        st.server_key = Some([3; 32]);
        st.server_key_for = "https://a.example".into();
        st.endpoint = "https://a.example".into();
        assert_eq!(st.pinned_key(), Some([3; 32]));
        st.endpoint = "https://b.example".into();
        assert!(st.pinned_key().is_none());
    }

    #[test]
    fn the_default_endpoint_uses_the_compiled_key_and_ignores_a_stored_one() {
        let mut st = Settings::new(Lang::En);
        st.server_key = Some([3; 32]);
        st.server_key_for.clone_from(&st.endpoint);
        // No compiled key: the stored one counts.
        assert_eq!(st.pinned_key_in(None), Some([3; 32]));
        // A compiled key wins, whatever was stored, with or without a trailing slash.
        assert_eq!(st.pinned_key_in(Some([9; 32])), Some([9; 32]));
        st.server_key = None;
        assert_eq!(st.pinned_key_in(Some([9; 32])), Some([9; 32]));
        st.endpoint = format!("{}/", crate::model::DEFAULT_ENDPOINT);
        assert_eq!(st.pinned_key_in(Some([9; 32])), Some([9; 32]));
        // Other endpoints are not affected.
        st.endpoint = "https://other.example".into();
        assert!(st.pinned_key_in(Some([9; 32])).is_none());
        assert!(aegis_core::net::DEFAULT_SERVER_X_PK.is_some());
    }

    #[test]
    fn tor_switch_picks_the_default_server_address() {
        use crate::model::{route_endpoint, DEFAULT_ENDPOINT, DEFAULT_ONION};
        assert_eq!(route_endpoint(DEFAULT_ENDPOINT, true), DEFAULT_ONION);
        assert_eq!(route_endpoint(&format!("{DEFAULT_ENDPOINT}/"), true), DEFAULT_ONION);
        assert_eq!(route_endpoint(DEFAULT_ONION, false), DEFAULT_ENDPOINT);
        assert_eq!(route_endpoint(DEFAULT_ONION, true), DEFAULT_ONION);
        assert_eq!(route_endpoint(DEFAULT_ENDPOINT, false), DEFAULT_ENDPOINT);
        assert_eq!(route_endpoint("https://other.example/", true), "https://other.example");
        let mut st = Settings::new(Lang::En);
        assert!(st.tor);
        assert_eq!(st.connect_endpoint(), DEFAULT_ONION);
        assert_eq!(st.pinned_key_in(Some([9; 32])), Some([9; 32]));
        st.endpoint = DEFAULT_ONION.into();
        assert_eq!(st.pinned_key_in(Some([9; 32])), Some([9; 32]));
        st.tor = false;
        assert_eq!(st.connect_endpoint(), DEFAULT_ENDPOINT);
    }

    #[test]
    fn client_needs_a_pinned_key_and_tor_must_be_up() {
        let e = Engine::new(Config::production(std::env::temp_dir()), || {});
        let mut st = Settings::new(Lang::En);
        st.tor = false;
        st.endpoint = "http://127.0.0.1:9".into();
        assert_eq!(e.client_for(&st).err().map(|f| f.key), Some("err.server_key_unset"));
        st.server_key = Some([1; 32]);
        st.server_key_for = st.endpoint.clone();
        assert!(e.client_for(&st).is_ok());
        st.tor = true;
        assert_eq!(e.client_for(&st).err().map(|f| f.key), Some("err.tor_boot"));
        st.tor = false;
        e.key_alert.store(true, Ordering::SeqCst);
        assert_eq!(e.client_for(&st).err().map(|f| f.key), Some("err.server_key_changed"));
    }
}
