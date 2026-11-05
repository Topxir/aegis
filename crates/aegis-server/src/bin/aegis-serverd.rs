use aegis_server::{default_data_dir_from, persist_now, serve, Config, ServerState};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Args {
    bind: IpAddr,
    port: u16,
    data_dir: Option<PathBuf>,
    blob_quota_mib: u64,
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut out = Args {
        bind: IpAddr::from([127, 0, 0, 1]),
        port: 8443,
        data_dir: None,
        blob_quota_mib: 4096,
    };
    let mut it = args;
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n.to_owned(), Some(v.to_owned())),
            None => (arg, None),
        };
        let mut value = |label: &str| {
            inline
                .clone()
                .or_else(|| it.next())
                .ok_or_else(|| format!("{label} needs a value"))
        };
        match name.as_str() {
            "--bind" => {
                out.bind = value("--bind")?.parse().map_err(|_| "invalid --bind address".to_owned())?;
            }
            "--port" => {
                out.port = value("--port")?.parse().map_err(|_| "invalid --port".to_owned())?;
            }
            "--data-dir" => out.data_dir = Some(PathBuf::from(value("--data-dir")?)),
            "--blob-quota-mib" => {
                out.blob_quota_mib = value("--blob-quota-mib")?
                    .parse()
                    .map_err(|_| "invalid --blob-quota-mib".to_owned())?;
            }
            "--help" | "-h" => {
                return Err("usage: aegis-serverd [--bind ADDR] [--port PORT] [--data-dir DIR] [--blob-quota-mib MIB]".into());
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(out)
}

/// Owner `ed_pk` (64 hex digits) from `AEGIS_OWNER_ED_PK`, else from `<data dir>/owner-ed-pk`.
fn owner_key(data_dir: &std::path::Path) -> Result<Option<[u8; 32]>, String> {
    let text = match std::env::var("AEGIS_OWNER_ED_PK") {
        Ok(v) => v,
        Err(_) => match std::fs::read_to_string(data_dir.join("owner-ed-pk")) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("cannot read owner-ed-pk".into()),
        },
    };
    aegis_core::hex::decode_array::<32>(text.trim())
        .map(Some)
        .map_err(|_| "owner key must be 64 lowercase hex digits".to_owned())
}

fn run() -> Result<(), String> {
    let args = parse_args(std::env::args().skip(1))?;
    let data_dir = match args.data_dir {
        Some(d) => d,
        None => default_data_dir_from(
            std::env::var_os("APPDATA").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )
        .ok_or("no data directory: pass --data-dir")?,
    };
    let owner_ed_pk = owner_key(&data_dir)?;
    if owner_ed_pk.is_none() {
        eprintln!("no owner key configured: `owner` cannot be registered and the official queue is closed");
    }
    let state = ServerState::open_with(
        &data_dir,
        Config {
            blob_quota_bytes: args.blob_quota_mib.saturating_mul(1024 * 1024),
            owner_ed_pk,
            ..Config::default()
        },
    ).map_err(|e| format!("cannot open state: {e}"))?;
    let state = Arc::new(Mutex::new(state));
    let listener = TcpListener::bind(SocketAddr::new(args.bind, args.port))
        .map_err(|e| format!("cannot bind: {e}"))?;
    println!("aegis-serverd listening on {}", SocketAddr::new(args.bind, args.port));
    println!("data directory {}", data_dir.display());

    let bg = Arc::clone(&state);
    std::thread::Builder::new()
        .name("maintenance".into())
        .spawn(move || {
            let mut ticks = 0u32;
            loop {
                std::thread::sleep(Duration::from_secs(5));
                ticks = ticks.wrapping_add(1);
                if ticks.is_multiple_of(60) {
                    bg.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .purge(aegis_core::now_secs());
                }
                if persist_now(&bg).is_err() {
                    eprintln!("state write failed");
                }
            }
        })
        .map_err(|e| format!("cannot start maintenance thread: {e}"))?;

    let stop = AtomicBool::new(false);
    serve(&listener, &state, &stop).map_err(|e| format!("server stopped: {e}"))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
