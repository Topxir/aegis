//! Signed application updates on the desktop (spec section 29).
//!
//! The manifest is fetched with the same client as every other request, so it goes to the onion
//! address through Tor and never to the clearnet entry. Nothing is used before the signature of
//! the trusted key, the sequence number, the version and the file hash check out. A verified build
//! waits in `<data>/update/` and replaces the running exe when the app locks, is closed or the user
//! asks for it.

use super::*;
use aegis_core::update::{self as upd, Artifact, Offer};

/// Time between checks while an account is open.
pub const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
/// First check after start, once Tor had time to connect.
const FIRST_CHECK: Duration = Duration::from_secs(20);
/// Highest manifest sequence accepted so far, inside the update directory.
const SEQ_FILE: &str = "seq";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Idle,
    Checking,
    Current,
    /// A newer build that waits for the user (auto-update off).
    Available(String),
    Downloading(String),
    /// Verified and staged; installs on lock, close or restart.
    Ready { version: String, required: bool },
    Failed(&'static str),
}

#[derive(Debug)]
pub struct State {
    pub status: Status,
    due: Instant,
    running: bool,
    /// Download even with auto-update off (the user asked).
    force: bool,
    staged: Option<(PathBuf, Artifact)>,
    /// Download progress in percent.
    pub pct: u8,
}

impl State {
    pub fn new() -> Self {
        Self {
            status: Status::Idle,
            due: Instant::now() + FIRST_CHECK,
            running: false,
            force: false,
            staged: None,
            pct: 0,
        }
    }

    pub fn ready(&self) -> bool {
        self.staged.is_some()
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

pub fn dir(data: &Path) -> PathBuf {
    data.join("update")
}

/// Highest accepted sequence number, 0 before the first manifest.
pub fn last_seq(data: &Path) -> u64 {
    std::fs::read_to_string(dir(data).join(SEQ_FILE))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Remembers `seq` if it is higher than the stored one.
pub fn store_seq(data: &Path, seq: u64) -> Result<(), Error> {
    if seq <= last_seq(data) {
        return Ok(());
    }
    std::fs::create_dir_all(dir(data))?;
    write_atomic(&dir(data).join(SEQ_FILE), format!("{seq}\n").as_bytes())
}

/// Opens a signed manifest with the trusted key and decides on it against the stored sequence.
/// The sequence is stored once the signature is good, so an older manifest is refused later.
pub fn accept(data: &Path, signed: &[u8], pk: &[u8; 32], current: &str) -> Result<Offer, Error> {
    let m = upd::open(signed, pk)?;
    let offer = upd::evaluate(&m, upd::WINDOWS, current, 0, last_seq(data))?;
    store_seq(data, m.seq)?;
    Ok(offer)
}

/// Whether `path` holds exactly the file `a` describes.
pub fn matches(path: &Path, a: &Artifact) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    upd::hash_reader(&mut f).is_ok_and(|(h, n)| n == a.size && h == a.sha256)
}

/// Downloads `a` into `<dir>/<name>`, through a `.part` file that is renamed only after the size
/// and hash checked out.
pub fn fetch(
    data: &Path,
    a: &Artifact,
    chunk: impl FnMut(u64) -> Result<Vec<u8>, Error>,
) -> Result<PathBuf, Error> {
    let d = dir(data);
    std::fs::create_dir_all(&d)?;
    let dst = d.join(&a.name);
    if matches(&dst, a) {
        return Ok(dst);
    }
    let part = d.join(format!("{}.part", a.name));
    let r = std::fs::File::create(&part)
        .map_err(Error::from)
        .and_then(|f| upd::download_with(a, &mut std::io::BufWriter::new(f), chunk));
    if let Err(e) = r {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, &dst)?;
    Ok(dst)
}

/// The exe kept aside during an install; removed on the next start.
pub fn old_path(exe: &Path) -> PathBuf {
    let mut n = exe.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    n.push(".old");
    exe.with_file_name(n)
}

/// Puts `staged` in place of `exe`. Windows lets a running exe be renamed but not overwritten,
/// so the current one moves aside first and comes back if the copy fails.
pub fn swap(staged: &Path, exe: &Path) -> std::io::Result<()> {
    let old = old_path(exe);
    let _ = std::fs::remove_file(&old);
    std::fs::rename(exe, &old)?;
    if let Err(e) = std::fs::copy(staged, exe) {
        let _ = std::fs::remove_file(exe);
        let _ = std::fs::rename(&old, exe);
        return Err(e);
    }
    Ok(())
}

/// Removes what an earlier install left behind: the old exe and staged files that are not
/// newer than this build.
pub fn cleanup(data: &Path) {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(old_path(&exe));
    }
    let Ok(rd) = std::fs::read_dir(dir(data)) else { return };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n != SEQ_FILE {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

fn failure_key(e: &Error) -> &'static str {
    match e {
        Error::BadSignature => "upd.bad_sig",
        Error::Update("file hash" | "file size") => "upd.bad_file",
        Error::Update("manifest rollback") => "upd.rollback",
        _ => "upd.failed",
    }
}

impl Engine {
    /// Called about once a second from the poll thread. Starts a check when one is due and an
    /// account is open; with Tor still connecting it waits.
    pub fn update_tick(&self) {
        let client = {
            let mut app = self.app();
            let u = &app.update;
            if u.running || Instant::now() < u.due {
                return;
            }
            let Some(s) = app.session.as_ref() else { return };
            let auto = s.data.settings.auto_update;
            let Ok(client) = self.client_for(&s.data.settings) else { return };
            let u = &mut app.update;
            let force = std::mem::take(&mut u.force);
            u.running = true;
            u.due = Instant::now() + CHECK_EVERY;
            u.status = Status::Checking;
            (client, auto || force)
        };
        let Some(me) = self.me.upgrade() else { return };
        let spawned = std::thread::Builder::new().name("update".into()).spawn(move || {
            let (client, download) = client;
            let status = me.update_run(&client, download);
            {
                let mut app = me.app();
                app.update.running = false;
                app.update.status = status;
            }
            me.changed();
        });
        if spawned.is_err() {
            self.app().update.running = false;
        }
        self.changed();
    }

    fn update_run(&self, client: &Client, download: bool) -> Status {
        let data = self.cfg.data_dir.clone();
        let pk = match upd::trusted_key() {
            Ok(k) => k,
            Err(_) => return Status::Failed("upd.failed"),
        };
        let offer = match client.update_manifest() {
            Ok(None) => return Status::Current,
            Ok(Some(signed)) => accept(&data, &signed, &pk, VERSION),
            Err(e) => Err(e),
        };
        let (a, required) = match offer {
            Ok(Offer::Current) => return Status::Current,
            Ok(Offer::Newer { artifact, required }) => (artifact, required),
            Err(e) => return Status::Failed(failure_key(&e)),
        };
        if !download && !matches(&dir(&data).join(&a.name), &a) {
            return Status::Available(a.version);
        }
        {
            let mut app = self.app();
            app.update.status = Status::Downloading(a.version.clone());
            app.update.pct = 0;
        }
        self.changed();
        let size = a.size.max(1);
        match fetch(&data, &a, |off| {
            self.app().update.pct = (off.saturating_mul(100) / size).min(99) as u8;
            self.changed();
            client.update_chunk(&a.name, off)
        }) {
            Ok(path) => {
                let version = a.version.clone();
                self.app().update.staged = Some((path, a));
                Status::Ready { version, required }
            }
            Err(e) => Status::Failed(failure_key(&e)),
        }
    }

    /// Check now, and download what is found even with auto-update off.
    pub fn update_now(&self) {
        {
            let mut app = self.app();
            app.update.force = true;
            app.update.due = Instant::now();
        }
        self.kick_poll();
    }

    pub fn update_ready(&self) -> bool {
        self.app().update.ready()
    }

    /// Replaces the exe with the staged build after checking it once more. `restart` starts the
    /// new build and ends this process; the open account must already be saved.
    pub fn install_update(&self, restart: bool) -> Result<(), Failure> {
        let Some((path, a)) = self.app().update.staged.clone() else {
            return Err(Failure::new("upd.failed"));
        };
        if !matches(&path, &a) {
            self.app().update.staged = None;
            return Err(Failure::new("upd.bad_file"));
        }
        let exe = std::env::current_exe().map_err(|e| io_failure(&e))?;
        swap(&path, &exe).map_err(|e| io_failure(&e))?;
        self.app().update.staged = None;
        let _ = std::fs::remove_file(&path);
        if restart {
            std::process::Command::new(&exe).spawn().map_err(|e| io_failure(&e))?;
            std::process::exit(0);
        }
        Ok(())
    }

    /// Saves and closes the open account, then installs the staged build and restarts.
    /// Nothing happens if the account cannot be saved.
    pub(crate) fn restart_into_update(&self) {
        let r = self.flush().and_then(|()| {
            if let Some(s) = self.detach() {
                self.persist(s);
            }
            // Held until the process ends, so no other save is cut off half way.
            let _g = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
            self.install_update(true)
        });
        if let Err(f) = r {
            self.app().update.status = Status::Failed(f.key);
            self.changed();
        }
    }
}

/// The updates card on the connection page.
pub fn card_html(app: &App, l: Lang, st: &Settings) -> String {
    use crate::i18n::tr;
    use crate::render::esc;
    let (class, text) = match &app.update.status {
        Status::Idle | Status::Current => ("note", format!("{} {VERSION}", tr(l, "upd.version"))),
        Status::Checking => ("note", tr(l, "upd.checking").to_owned()),
        Status::Available(v) => ("status okc", format!("{} {v}", tr(l, "upd.available"))),
        Status::Downloading(v) => ("note", format!("{} {v}", tr(l, "upd.downloading"))),
        Status::Ready { version, required: false } => ("status okc", format!("{} {version}. {}", tr(l, "upd.ready"), tr(l, "upd.ready_when"))),
        Status::Ready { version, required: true } => ("status badc", format!("{} {version}. {}", tr(l, "upd.ready"), tr(l, "upd.required"))),
        Status::Failed(k) => ("status badc", tr(l, k).to_owned()),
    };
    let busy = matches!(app.update.status, Status::Checking | Status::Downloading(_));
    let action = if app.update.ready() {
        format!(r#"<button type="button" class="btn" data-act="install_update">{}</button>"#, esc(tr(l, "upd.restart")))
    } else {
        format!(
            r#"<button type="button" class="btn" data-act="update_now"{}>{}</button>"#,
            if busy { " disabled" } else { "" },
            esc(tr(l, if matches!(app.update.status, Status::Available(_)) { "upd.download" } else { "upd.check" }))
        )
    };
    format!(
        r#"<section class="card" data-scope><h2>{}</h2><label class="chk"><input type="checkbox" name="auto_update"{}><span>{}</span></label><p class="note">{}</p><p class="{class}">{}</p><div class="row"><button type="button" class="btn primary" data-act="save_updates" data-primary>{}</button>{action}</div></section>"#,
        esc(tr(l, "upd.title")),
        if st.auto_update { " checked" } else { "" },
        esc(tr(l, "upd.auto")),
        esc(tr(l, "upd.note")),
        esc(&text),
        esc(tr(l, "common.save")),
    )
}
