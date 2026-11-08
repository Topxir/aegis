//! Desktop client for Aegis: encrypted local vault, protocol v2 networking and a
//! WebView2 front end that is served from memory.

pub mod assets;
pub mod config;
pub mod controller;
pub mod engine;
pub mod guide;
pub mod i18n;
pub mod ipc;
pub mod look;
pub mod look_text;
pub mod media;
pub mod model;
pub mod notify;
pub mod render;
pub mod session;
#[cfg(target_os = "windows")]
mod shield;
pub mod timer;
pub mod tor;
#[cfg(target_os = "windows")]
mod tray;
#[cfg(target_os = "windows")]
pub mod ui;
