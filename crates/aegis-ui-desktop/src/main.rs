//! `aegis-desktop` — Runnable Desktop Client binary for Aegis.
//!
//! Modes:
//! - Default (double-click `aegis-desktop.exe` or `--gui [--port 7878]`):
//!   starts the local interactive Aurora Glassmorphism Desktop GUI on `http://127.0.0.1:7878`
//!   (starting with Step 1: Account Login -> Step 2: Server Selection -> Step 3: Messenger Chats)
//!   and automatically opens the interface in the system browser.
//! - `aegis-desktop --self-test` or `aegis-desktop --demo`:
//!   runs a complete end-to-end verification of all 10 desktop subsystems and prints a detailed Russian report.

use aegis_ffi::Locale;
use aegis_ui_desktop::{
    run_automated_demo_walkthrough, DesktopAppState, DesktopGuiServer, DesktopUiError, Screen,
};
use std::env;
use std::net::TcpListener;
use std::process::{Command, ExitCode};

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

    // Double-clicking aegis-desktop.exe with no flags launches the interactive GUI immediately!
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
            eprintln!("❌ Ошибка локального GUI-сервера Aegis Desktop: {err}");
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
    // Start on Step 1 (Account Login / Registration -> Step 2 Server Selection -> Step 3 Chats)
    state.current_screen = Screen::Onboarding;
    let url = format!("http://127.0.0.1:{port}");
    println!("============================================================");
    println!("🛡 AEGIS AURORA GLASS DESKTOP ЗАПУЩЕН: {url}");
    println!("   Шаг 1: Вход в аккаунт -> Шаг 2: Выбор сервера -> Шаг 3: Чаты");
    println!("   Окно открывается автоматически. Нажмите Ctrl+C для выхода.");
    println!("============================================================");

    if max_requests.is_none() {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("cmd").args(["/C", "start", "", &url]).spawn();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("xdg-open").arg(&url).spawn();
        }
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("open").arg(&url).spawn();
        }
    }

    let mut server = DesktopGuiServer::new(port, state);
    server.serve_blocking(max_requests)
}

fn print_help() {
    println!("Aegis Desktop Client (Aurora Glass / E2EE / Zero-Knowledge)");
    println!("Использование:");
    println!(
        "  aegis-desktop                    Запуск интерактивного GUI (Вход -> Серверы -> Чаты)"
    );
    println!("  aegis-desktop --gui [--port N]   Запуск GUI на указанном локальном порту");
    println!("  aegis-desktop --self-test        Полный автотест всех подсистем на ПК");
}
