//! Desktop client for Aegis: encrypted local vault, protocol v2 networking and a
//! WebView2 front end that is served from memory.

pub mod assets;
pub mod bridges;
pub mod config;
pub mod connection;
pub mod controller;
pub mod engine;
pub mod i18n;
pub mod ipc;
pub mod media;
pub mod model;
pub mod render;
pub mod session;
pub mod tor;
#[cfg(target_os = "windows")]
pub mod ui;
