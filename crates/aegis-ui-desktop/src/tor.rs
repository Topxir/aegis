//! Tor through the official `tor.exe` shipped next to the app. The child process is the only
//! thing that talks to the network in Tor mode: the app reaches it over a loopback SOCKS5
//! port, so names are resolved inside Tor.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Off,
    /// Bootstrap progress in percent.
    Starting(u8),
    Ready,
    Failed(String),
}

type Notify = Arc<dyn Fn(Status) + Send + Sync>;

/// Handle to the Tor child process. Starting is lazy and happens at most once.
#[derive(Debug, Default)]
pub struct Tor {
    port: Arc<AtomicU16>,
    started: Mutex<bool>,
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
}

impl Tor {
    /// The loopback SOCKS5 address once Tor has finished bootstrapping.
    pub fn socks_addr(&self) -> Option<String> {
        match self.port.load(Ordering::SeqCst) {
            0 => None,
            p => Some(format!("127.0.0.1:{p}")),
        }
    }

    pub fn started(&self) -> bool {
        *self.started.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts `tor.exe` if it has not been started yet. Its state lives under `dir`.
    pub fn ensure_started(&self, dir: &Path, notify: impl Fn(Status) + Send + Sync + 'static) {
        let mut started = self.started.lock().unwrap_or_else(|e| e.into_inner());
        if *started {
            return;
        }
        *started = true;
        let notify: Notify = Arc::new(notify);
        notify(Status::Starting(0));
        let job = Job {
            dir: dir.to_path_buf(),
            port: Arc::clone(&self.port),
            stop: Arc::clone(&self.stop),
            child: Arc::clone(&self.child),
            notify: Arc::clone(&notify),
        };
        let spawned = std::thread::Builder::new().name("tor".into()).spawn(move || job.run());
        if spawned.is_err() {
            *started = false;
            notify(Status::Failed("thread".into()));
        }
    }
}

impl Drop for Tor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(mut c) = self.child.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct Job {
    dir: PathBuf,
    port: Arc<AtomicU16>,
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    notify: Notify,
}

impl Job {
    fn run(&self) {
        while !self.stop.load(Ordering::SeqCst) {
            let why = self.once().unwrap_or_else(|e| e);
            self.port.store(0, Ordering::SeqCst);
            if self.stop.load(Ordering::SeqCst) {
                return;
            }
            (self.notify)(Status::Failed(why));
            for _ in 0..30 {
                if self.stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            (self.notify)(Status::Starting(0));
        }
    }

    /// Runs one Tor process until it exits and returns why it stopped.
    fn once(&self) -> Result<String, String> {
        let exe = locate().ok_or("tor.exe not found")?;
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let torrc = self.dir.join("torrc");
        std::fs::write(&torrc, "").map_err(|e| e.to_string())?;
        let mut cmd = Command::new(&exe);
        cmd.args(["--SocksPort", "127.0.0.1:auto", "--ClientOnly", "1", "--AvoidDiskWrites", "1"])
            .args(["--Log", "notice stdout", "-f"])
            .arg(&torrc)
            .args(["--__OwningControllerProcess", &std::process::id().to_string()])
            .arg("--DataDirectory")
            .arg(&self.dir)
            .current_dir(exe.parent().unwrap_or(Path::new(".")))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        hide_window(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        let Some(out) = child.stdout.take() else {
            let _ = child.kill();
            return Err("no output".into());
        };
        *self.child.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
        let mut socks = 0u16;
        for line in BufReader::new(out).lines() {
            let Ok(line) = line else { break };
            if let Some(p) = socks_port(&line) {
                socks = p;
            }
            if let Some(pct) = progress(&line) {
                if pct >= 100 && socks != 0 {
                    self.port.store(socks, Ordering::SeqCst);
                    (self.notify)(Status::Ready);
                } else {
                    (self.notify)(Status::Starting(pct));
                }
            }
        }
        let taken = self.child.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(mut c) = taken {
            let _ = c.kill();
            let _ = c.wait();
        }
        Ok("tor exited".into())
    }
}

/// `tor.exe` next to the app, or the path in `AEGIS_TOR_EXE` for development.
pub fn locate() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("AEGIS_TOR_EXE") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let p = std::env::current_exe().ok()?.parent()?.join("tor").join("tor.exe");
    p.is_file().then_some(p)
}

#[cfg(windows)]
fn hide_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x0800_0000);
}

#[cfg(not(windows))]
fn hide_window(_: &mut Command) {}

/// Percent from a `Bootstrapped N% (tag): text` notice.
fn progress(line: &str) -> Option<u8> {
    let rest = line.split("Bootstrapped ").nth(1)?;
    let n: u32 = rest.split('%').next()?.trim().parse().ok()?;
    Some(n.min(100) as u8)
}

/// Port from `Opened Socks listener connection (ready) on 127.0.0.1:NNNN`.
fn socks_port(line: &str) -> Option<u16> {
    let rest = line.split("Socks listener").nth(1)?;
    let addr = rest.rsplit(" on ").next()?.trim();
    addr.strip_prefix("127.0.0.1:")?.parse().ok().filter(|p| *p != 0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_read_and_clamped() {
        let l = "Nov 07 10:00:00.000 [notice] Bootstrapped 45% (loading_descriptors): Loading";
        assert_eq!(progress(l), Some(45));
        assert_eq!(progress("Bootstrapped 100% (done): Done"), Some(100));
        assert_eq!(progress("Bootstrapped 400% (x): y"), Some(100));
        assert_eq!(progress("Opened Socks listener"), None);
    }

    #[test]
    fn socks_port_is_read_from_the_listener_notice() {
        let l = "Nov 07 [notice] Opened Socks listener connection (ready) on 127.0.0.1:49731";
        assert_eq!(socks_port(l), Some(49731));
        assert_eq!(socks_port("Opened Socks listener on 0.0.0.0:9050"), None);
        assert_eq!(socks_port("Bootstrapped 5%"), None);
    }

    #[test]
    fn idle_handle_has_no_proxy() {
        let t = Tor::default();
        assert!(t.socks_addr().is_none());
        assert!(!t.started());
    }
}
