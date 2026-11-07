//! Needs the network: bootstraps the embedded Tor client and asks the onion service for
//! `/health`. Run with `cargo test -p aegis-ui-desktop --test tor_smoke -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::net::Client;
use aegis_core::{DEFAULT_ONION_URL, DEFAULT_SERVER_X_PK};
use aegis_ui_desktop::tor::Tor;
use std::time::{Duration, Instant};

#[test]
#[ignore]
fn onion_health_through_embedded_tor() {
    let dir = std::env::temp_dir().join("aegis-tor-smoke");
    let tor = Tor::default();
    tor.ensure_started(&dir, |s| eprintln!("tor: {s:?}"));
    let end = Instant::now() + Duration::from_secs(300);
    let socks = loop {
        if let Some(a) = tor.socks_addr() {
            break a;
        }
        assert!(Instant::now() < end, "tor did not connect");
        std::thread::sleep(Duration::from_millis(500));
    };
    let client = Client::new(DEFAULT_ONION_URL, Some(&socks))
        .unwrap()
        .with_server_key(DEFAULT_SERVER_X_PK.unwrap())
        .with_timeout(Duration::from_secs(90));
    client.health().unwrap();
}
