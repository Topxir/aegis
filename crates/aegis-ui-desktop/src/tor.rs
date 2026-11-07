//! Embedded Tor client. It bootstraps in the background and serves a SOCKS5 listener on the
//! loopback interface, so the blocking HTTP client reaches the server through Tor without any
//! name lookup or connection outside it.

use arti_client::config::TorClientConfigBuilder;
use arti_client::{BootstrapBehavior, TorClient};
use futures::StreamExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_rtcompat::PreferredRuntime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Off,
    /// Bootstrap progress in percent.
    Starting(u8),
    Ready,
    Failed(String),
}

type Notify = Arc<dyn Fn(Status) + Send + Sync>;

/// Handle to the embedded Tor client. Starting is lazy and happens at most once.
#[derive(Debug, Default)]
pub struct Tor {
    port: Arc<AtomicU16>,
    started: Mutex<bool>,
}

impl Tor {
    /// The loopback SOCKS5 address once Tor is connected and listening.
    pub fn socks_addr(&self) -> Option<String> {
        match self.port.load(Ordering::SeqCst) {
            0 => None,
            p => Some(format!("127.0.0.1:{p}")),
        }
    }

    pub fn started(&self) -> bool {
        *self.started.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts bootstrapping if it has not started yet. State and cache live under `dir`.
    pub fn ensure_started(&self, dir: &Path, notify: impl Fn(Status) + Send + Sync + 'static) {
        let mut started = self.started.lock().unwrap_or_else(|e| e.into_inner());
        if *started {
            return;
        }
        *started = true;
        let notify: Notify = Arc::new(notify);
        let port = Arc::clone(&self.port);
        let dir = dir.to_path_buf();
        notify(Status::Starting(0));
        let spawned = std::thread::Builder::new().name("tor".into()).spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return notify(Status::Failed(e.to_string())),
            };
            rt.block_on(run(dir, port, notify));
        });
        if spawned.is_err() {
            *started = false;
        }
    }
}

async fn run(dir: PathBuf, port: Arc<AtomicU16>, notify: Notify) {
    loop {
        match serve(&dir, &port, &notify).await {
            Ok(()) => return,
            Err(e) => {
                port.store(0, Ordering::SeqCst);
                notify(Status::Failed(e));
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        }
    }
}

fn client_config(dir: &Path) -> Result<arti_client::TorClientConfig, String> {
    let mut b = TorClientConfigBuilder::from_directories(dir.join("state"), dir.join("cache"));
    b.address_filter().allow_onion_addrs(true);
    b.build().map_err(|e| e.to_string())
}

async fn serve(dir: &Path, port: &AtomicU16, notify: &Notify) -> Result<(), String> {
    let cfg = client_config(dir)?;
    let rt = PreferredRuntime::current().map_err(|e| e.to_string())?;
    let client = TorClient::with_runtime(rt)
        .config(cfg)
        .bootstrap_behavior(BootstrapBehavior::Manual)
        .create_unbootstrapped()
        .map_err(|e| e.to_string())?;
    let mut events = client.bootstrap_events();
    let progress = Arc::clone(notify);
    tokio::spawn(async move {
        while let Some(st) = events.next().await {
            progress(Status::Starting(percent(st.as_frac())));
        }
    });
    client.bootstrap().await.map_err(|e| e.to_string())?;
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .map_err(|e| e.to_string())?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    port.store(local.port(), Ordering::SeqCst);
    notify(Status::Ready);
    loop {
        let (conn, peer) = listener.accept().await.map_err(|e| e.to_string())?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let client = client.isolated_client();
        tokio::spawn(async move {
            let _ = relay(conn, client).await;
        });
    }
}

fn percent(frac: f32) -> u8 {
    (frac.clamp(0.0, 1.0) * 100.0) as u8
}

/// Reads a SOCKS5 CONNECT request (no authentication) and returns host and port.
async fn handshake(c: &mut TcpStream) -> std::io::Result<(String, u16)> {
    let bad = |m: &'static str| std::io::Error::new(std::io::ErrorKind::InvalidData, m);
    let mut h = [0u8; 2];
    c.read_exact(&mut h).await?;
    if h[0] != 5 {
        return Err(bad("socks version"));
    }
    let mut methods = vec![0u8; usize::from(h[1])];
    c.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        c.write_all(&[5, 0xff]).await?;
        return Err(bad("socks auth"));
    }
    c.write_all(&[5, 0]).await?;
    let mut r = [0u8; 4];
    c.read_exact(&mut r).await?;
    if r[0] != 5 || r[1] != 1 {
        return Err(bad("socks command"));
    }
    let host = match r[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).await?;
            IpAddr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            c.read_exact(&mut a).await?;
            IpAddr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut n = vec![0u8; usize::from(l[0])];
            c.read_exact(&mut n).await?;
            String::from_utf8(n).map_err(|_| bad("socks host"))?
        }
        _ => return Err(bad("socks address type")),
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p).await?;
    Ok((host, u16::from_be_bytes(p)))
}

async fn relay(mut conn: TcpStream, client: Arc<TorClient<PreferredRuntime>>) -> std::io::Result<()> {
    let (host, port) = handshake(&mut conn).await?;
    match client.connect((host.as_str(), port)).await {
        Ok(stream) => {
            conn.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let mut stream = stream.compat();
            tokio::io::copy_bidirectional(&mut conn, &mut stream).await?;
            Ok(())
        }
        Err(_) => conn.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_clamped_to_percent() {
        assert_eq!(percent(-1.0), 0);
        assert_eq!(percent(0.5), 50);
        assert_eq!(percent(7.0), 100);
    }

    #[test]
    fn idle_handle_has_no_proxy() {
        let t = Tor::default();
        assert!(t.socks_addr().is_none());
        assert!(!t.started());
    }

    #[test]
    fn config_builds_with_onion_addresses_allowed() {
        let dir = std::env::temp_dir().join("aegis-tor-cfg-test");
        assert!(client_config(&dir).is_ok());
    }

    #[test]
    fn socks_handshake_reads_domain_requests() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let (mut c, _) = l.accept().await.unwrap();
                handshake(&mut c).await.unwrap()
            });
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&[5, 1, 0]).await.unwrap();
            let mut r = [0u8; 2];
            c.read_exact(&mut r).await.unwrap();
            assert_eq!(r, [5, 0]);
            let mut req = vec![5, 1, 0, 3, 5];
            req.extend_from_slice(b"a.com");
            req.extend_from_slice(&80u16.to_be_bytes());
            c.write_all(&req).await.unwrap();
            assert_eq!(srv.await.unwrap(), ("a.com".to_owned(), 80));
        });
    }
}
