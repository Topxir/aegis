#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
//! Aegis desktop client entry point.

#[cfg(target_os = "windows")]
fn main() {
    let dir = match aegis_ui_desktop::config::default_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("aegis: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = aegis_ui_desktop::ui::run(aegis_ui_desktop::config::Config::production(dir)) {
        eprintln!("aegis: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("aegis-desktop supports Windows only");
    std::process::exit(1);
}
