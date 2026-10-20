//! `aegis-desktop` — Runnable Desktop Client binary for Aegis.
//!
//! Modes:
//! - `aegis-desktop --self-test` or `aegis-desktop --demo` (or default when no flags given in non-GUI mode):
//!   runs a complete end-to-end verification of all 10 desktop subsystems and prints a detailed Russian report.
//! - `aegis-desktop --gui [--port 7878]`:
//!   starts the local interactive Desktop GUI HTTP server on `http://127.0.0.1:7878` so the user can
//!   test every feature interactively in their browser/WebView.

use aegis_ffi::Locale;
use aegis_ui_desktop::{
    run_automated_demo_walkthrough, DesktopAppState, DesktopGuiServer, DesktopUiError,
};
use std::env;
use std::process::ExitCode;

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

    if !run_gui && !run_demo {
        run_demo = true;
    }

    if run_demo {
        match run_automated_demo_walkthrough() {
            Ok(report) => {
                println!("{report}");
                if !run_gui {
                    println!(
                        "💡 Для запуска интерактивного графического окна в браузере выполните:\n   cargo run -p aegis-ui-desktop --bin aegis-desktop -- --gui --port 7878"
                    );
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

fn launch_gui_server(port: u16, max_requests: Option<usize>) -> Result<(), DesktopUiError> {
    let state = DesktopAppState::new(Locale::Ru);
    let mut server = DesktopGuiServer::new(port, state);
    println!("============================================================");
    println!("🖥 AEGIS DESKTOP GUI ЗАПУЩЕН: http://127.0.0.1:{port}");
    println!("   Откройте ссылку в браузере для интерактивного управления всеми функциями.");
    println!("   Нажмите Ctrl+C для завершения работы.");
    println!("============================================================");
    server.serve_blocking(max_requests)
}

fn print_help() {
    println!("Aegis Desktop Client (E2EE / Zero-Knowledge)");
    println!("Использование:");
    println!(
        "  aegis-desktop --self-test        Полный автотест и демонстрация всех функций на ПК"
    );
    println!("  aegis-desktop --demo             Аналогично --self-test");
    println!("  aegis-desktop --gui [--port N]   Запуск интерактивного локального GUI на http://127.0.0.1:7878");
}
