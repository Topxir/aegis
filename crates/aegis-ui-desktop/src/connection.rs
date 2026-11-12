//! Where the app connects to. With Tor on, the clearnet entry of the default server (behind
//! Cloudflare) is never contacted: the default goes to its onion address and any other name under
//! the same domain is refused. Every client the engine builds goes through `endpoint_for`.

use crate::model::{normalize_endpoint, route_endpoint, DEFAULT_ENDPOINT};
use crate::session::Failure;

/// Host of the clearnet entry, `freeoasis.space`.
fn clearnet_host() -> Option<String> {
    aegis_core::net::Endpoint::parse(DEFAULT_ENDPOINT).ok().map(|e| e.host.to_ascii_lowercase())
}

/// Whether `endpoint` is the clearnet entry or a name below it.
pub fn is_clearnet_entry(endpoint: &str) -> bool {
    let (Some(base), Ok(ep)) = (clearnet_host(), aegis_core::net::Endpoint::parse(&normalize_endpoint(endpoint)))
    else {
        return false;
    };
    let host = ep.host.trim_end_matches('.').to_ascii_lowercase();
    host == base || host.ends_with(&format!(".{base}"))
}

/// The address to connect to for `endpoint` with the Tor switch `tor`.
pub fn endpoint_for(endpoint: &str, tor: bool) -> Result<String, Failure> {
    let ep = route_endpoint(endpoint, tor);
    if tor && is_clearnet_entry(&ep) {
        return Err(Failure::new("err.clearnet_tor"));
    }
    Ok(ep)
}

/// Connection settings waiting for the Tor-off confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnForm {
    pub endpoint: String,
    pub socks5: String,
    pub cover: String,
    pub bridges: String,
    pub bridge_lines: String,
}
