#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
//! `aegis-desktop` — runnable desktop client for Aegis.
//!
//! Default mode opens a native Windows window (WebView2) around the local UI
//! server without spawning a console window. On other platforms it falls back
//! to the system browser. `--self-test` runs the end-to-end verification suite.

use aegis_ffi::Locale;
use aegis_ui_desktop::{
    run_automated_demo_walkthrough, DesktopAppState, DesktopGuiServer, DesktopUiError, Screen,
};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, ExitCode};
use std::thread;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut run_gui = false;
    let mut run_demo = false;
    let mut port: u16 = 7878;
    let mut max_requests: Option<usize> = None;

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--self-test" | "--demo" => {
                run_demo = true;
            }
            "--gui" => {
                run_gui = true;
            }
            "--port" => {
                if let Some(val) = args.get(idx + 1) {
                    if let Ok(parsed) = val.parse::<u16>() {
                        if parsed > 0 {
                            port = parsed;
                        }
                    }
                    idx += 1;
                }
                run_gui = true;
            }
            "--once" => {
                max_requests = Some(1);
                run_gui = true;
            }
            "--help" | "-h" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            _ => {}
        }
        idx += 1;
    }

    // Double-clicking aegis-desktop.exe with no flags launches the interactive UI.
    if !run_gui && !run_demo {
        run_gui = true;
    }

    if run_demo {
        match run_automated_demo_walkthrough() {
            Ok(report) => {
                println!("{report}");
                if !run_gui {
                    return ExitCode::SUCCESS;
                }
            }
            Err(err) => {
                eprintln!("❌ Ошибка самопроверки Aegis Desktop: {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    if run_gui {
        if let Err(err) = launch_gui_server(port, max_requests) {
            eprintln!("❌ Ошибка запуска Aegis Desktop: {err}");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

fn find_available_port(preferred: u16) -> u16 {
    for candidate in preferred..=preferred.saturating_add(20) {
        if TcpListener::bind(format!("127.0.0.1:{candidate}")).is_ok() {
            return candidate;
        }
    }
    preferred
}

fn launch_gui_server(
    preferred_port: u16,
    max_requests: Option<usize>,
) -> Result<(), DesktopUiError> {
    let port = if max_requests.is_none() {
        find_available_port(preferred_port)
    } else {
        preferred_port
    };
    let mut state = DesktopAppState::new(Locale::Ru);
    state.current_screen = Screen::Onboarding;
    let url = format!("http://127.0.0.1:{port}");

    let mut server = DesktopGuiServer::new(port, state);
    if max_requests.is_some() {
        return server.serve_blocking(max_requests);
    }

    #[cfg(target_os = "windows")]
    {
        ensure_background_tunnel_server();
        let server_thread = thread::spawn(move || server.serve_blocking(None));
        if !wait_for_local_port(port, Duration::from_secs(5)) {
            return Err(DesktopUiError::IoError(
                "локальный UI-сервер не запустился за 5 секунд".to_owned(),
            ));
        }
        if run_native_window(port).is_err() {
            open_in_browser(&url);
            let _ = server_thread.join();
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        open_in_browser(&url);
        server.serve_blocking(None)
    }
}

#[cfg(target_os = "windows")]
fn ensure_background_tunnel_server() {
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    if TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], 8443)),
        Duration::from_millis(120),
    )
    .is_err()
    {
        let exe_dir = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(PathBuf::from));
        let candidates = [
            exe_dir.as_ref().map(|d| d.join("aegis-serverd.exe")),
            exe_dir
                .as_ref()
                .and_then(|d| d.parent().map(|p| p.join("server").join("aegis-serverd.exe"))),
        ];
        for cand in candidates.into_iter().flatten() {
            if cand.is_file() {
                let _ = Command::new(cand)
                    .args(["--bind=127.0.0.1", "--port=8443"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .spawn();
                break;
            }
        }
    }

    if let Ok(profile) = env::var("USERPROFILE") {
        let cfg = PathBuf::from(profile)
            .join(".cloudflared")
            .join("aegis-tunnel.yml");
        if cfg.is_file() {
            let _ = Command::new("cloudflared")
                .args(["tunnel", "--config"])
                .arg(&cfg)
                .arg("run")
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
        }
    }
}

#[cfg(target_os = "windows")]
fn wait_for_local_port(port: u16, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

#[cfg(target_os = "windows")]
fn run_native_window(port: u16) -> Result<(), String> {
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::WindowBuilder;
    use wry::{NewWindowResponse, PermissionResponse, WebViewBuilder};

    const HARDEN_SCRIPT: &str = r#"
document.addEventListener('contextmenu', function (event) { event.preventDefault(); });
document.addEventListener('dragover', function (event) { event.preventDefault(); });
document.addEventListener('drop', function (event) { event.preventDefault(); });
document.addEventListener('keydown', function (event) {
  if (event.key === 'F12' ||
      (event.ctrlKey && event.shiftKey && (event.key === 'I' || event.key === 'J' || event.key === 'C'))) {
    event.preventDefault();
  }
});
"#;

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("Aegis")
        .with_inner_size(tao::dpi::LogicalSize::new(1180.0, 780.0))
        .with_min_inner_size(tao::dpi::LogicalSize::new(900.0, 600.0))
        .build(&event_loop)
        .map_err(|e| e.to_string())?;

    let root = format!("http://127.0.0.1:{port}");
    let allowed_root = root.clone();
    let allowed_path = format!("{root}/");
    let url = format!("{root}/");
    let _webview = WebViewBuilder::new()
        .with_url(&url)
        .with_devtools(false)
        .with_navigation_handler(move |uri| uri == allowed_root || uri.starts_with(&allowed_path))
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .with_permission_handler(|_| PermissionResponse::Deny)
        .with_initialization_script(HARDEN_SCRIPT)
        .build(&window)
        .map_err(|e| e.to_string())?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
}

fn open_in_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = Command::new("cmd")
            .args(["/C", "start", "", url])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(url).spawn();
    }
}

fn print_help() {
    println!("Aegis Desktop — приватный мессенджер");
    println!("Использование:");
    println!("  aegis-desktop                    Запуск приложения");
    println!("  aegis-desktop --gui [--port N]   Запуск на указанном локальном порту");
    println!("  aegis-desktop --once             Один запрос (диагностика)");
    println!("  aegis-desktop --self-test        Полный автотест подсистем");
}
