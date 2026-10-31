//! `aegis-serverd` — Zero-knowledge Aegis Federation Server & Support/Donation Web Portal daemon.
//!
//! Serves:
//! - `GET /` and `GET /en` — Built-in Support & Anonymous Donation Web Portal (`SupporterPass`)
//! - `GET /health` — Zero-personal-data uptime and adaptive PoW status
//! - `GET /api/v1/pow` — Adaptive Anti-DDoS Proof-of-Work challenge parameters
//! - `POST /api/v1/queue/send` — Enqueue padded E2EE frame into anonymous unidirectional queue
//! - `POST /api/v1/queue/poll` — Drain pending frames from anonymous unidirectional queue
//! - `POST /api/v1/queue/relay` — Blindly forward a padded capsule to a remote federation node (`D-0023`)
//! - `POST /api/v1/queue/relay_poll` — Blindly poll pending capsules from a remote federation node (`D-0023`)
//! - `POST /api/v1/support/ticket` — Submit encrypted E2EE support ticket
//! - `POST /api/v1/donate/claim-pass` — Issue blind-signed `SupporterPass` token
//!
//! Run with `--self-test` for CI verification without binding a persistent loop.

use aegis_crypto::sha256;
use aegis_protocol::hex_decode_bytes;
use aegis_server::{handle_http_request, FederationServerState, SupportPortalState};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_HTTP_REQ_BYTES: usize = 65_536;
const MAX_CONCURRENT_CONNECTIONS: usize = 128;

fn read_http_request_bytes(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let mut expected_total: Option<usize> = None;

    loop {
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > MAX_HTTP_REQ_BYTES {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);

        if expected_total.is_none() {
            if let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let body_start = hdr_end + 4;
                let head_str = core::str::from_utf8(&buf[..hdr_end]).ok()?;
                let mut content_len = 0usize;
                let mut seen_content_len = false;
                for line in head_str.lines().skip(1) {
                    let (k, v) = line.split_once(':')?;
                    if k.is_empty() || k.bytes().any(|b| b.is_ascii_whitespace()) {
                        return None;
                    }
                    let k_trim = k.trim();
                    if k_trim.eq_ignore_ascii_case("transfer-encoding") {
                        return None;
                    }
                    if k_trim.eq_ignore_ascii_case("content-length") {
                        if seen_content_len {
                            return None;
                        }
                        seen_content_len = true;
                        let v_trim = v.trim();
                        if v_trim.is_empty() || !v_trim.bytes().all(|b| b.is_ascii_digit()) {
                            return None;
                        }
                        content_len = v_trim.parse::<usize>().ok()?;
                        if body_start.saturating_add(content_len) > MAX_HTTP_REQ_BYTES {
                            return None;
                        }
                    }
                }
                expected_total = Some(body_start + content_len);
            }
        }
        if let Some(total) = expected_total {
            if buf.len() >= total {
                buf.truncate(total);
                break;
            }
        }
    }
    if buf.is_empty() {
        None
    } else if let Some(total) = expected_total {
        if buf.len() == total {
            Some(buf)
        } else {
            None
        }
    } else {
        None
    }
}

fn parse_http_request(raw: &[u8]) -> Option<(&str, &str, &str, bool)> {
    let text = core::str::from_utf8(raw).ok()?;
    let (head, body) = text.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let first_line = lines.next()?.trim_end_matches('\r');
    if first_line.is_empty()
        || first_line.starts_with(char::is_whitespace)
        || first_line.chars().any(char::is_control)
    {
        return None;
    }
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || !method.bytes().all(|b| b.is_ascii_alphabetic())
        || !path.starts_with('/')
        || path.len() > 1024
        || !(version == "HTTP/1.1" || version == "HTTP/1.0")
    {
        return None;
    }
    let mut is_relayed_hop = false;
    for hdr_line in lines {
        let clean_hdr = hdr_line.trim_end_matches('\r');
        if clean_hdr.chars().any(char::is_control) {
            return None;
        }
        let (k, _v) = clean_hdr.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("x-aegis-blind-relay") {
            is_relayed_hop = true;
        }
    }
    Some((method, path, body, is_relayed_hop))
}

fn init_server_blinding_salt() -> [u8; 32] {
    if let Ok(hex_salt) = env::var("AEGIS_BLINDING_SALT_HEX") {
        if let Ok(mut bytes) = hex_decode_bytes(&hex_salt) {
            if bytes.len() == 32 && bytes.iter().any(|&b| b != 0) {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                bytes.fill(0);
                return out;
            }
            bytes.fill(0);
        }
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0xA7A7_2026_u128, |d| d.as_nanos());
    let pid = std::process::id();
    let mut seed = [0u8; 28];
    seed[0..8].copy_from_slice(b"AEG-SLT1");
    seed[8..24].copy_from_slice(&nanos.to_le_bytes());
    seed[24..28].copy_from_slice(&pid.to_le_bytes());
    let mut salt = sha256(&seed);
    seed.fill(0);
    if salt == [0u8; 32] {
        salt[0] = 0xA7;
    }
    salt
}

fn run_self_test() -> Result<(), String> {
    let mut srv = FederationServerState::default();
    let mut portal = SupportPortalState::new();

    let (code_health, _, health_json) =
        handle_http_request(&mut srv, &mut portal, "GET", "/health", "");
    if code_health != 200 || !health_json.contains(r#""ip_logging":false"#) {
        return Err("self-test failed on /health".to_owned());
    }

    let (code_portal, _, portal_html) = handle_http_request(&mut srv, &mut portal, "GET", "/", "");
    if code_portal != 200 || !portal_html.contains("SupporterPass") {
        return Err("self-test failed on /".to_owned());
    }

    let (code_send, _, _) = handle_http_request(
        &mut srv,
        &mut portal,
        "POST",
        "/api/v1/queue/send",
        "sealed-e2ee-test",
    );
    if code_send != 200 {
        return Err("self-test failed on /api/v1/queue/send".to_owned());
    }

    let (code_poll, _, poll_json) =
        handle_http_request(&mut srv, &mut portal, "POST", "/api/v1/queue/poll", "");
    if code_poll != 200 || !poll_json.contains(r#""frames_delivered":1"#) {
        return Err("self-test failed on /api/v1/queue/poll".to_owned());
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--self-test") {
        if let Err(err) = run_self_test() {
            let _ = writeln!(std::io::stderr(), "aegis-serverd self-test error: {err}");
            std::process::exit(1);
        }
        let _ = writeln!(
            std::io::stdout(),
            "aegis-serverd self-test passed (zero-knowledge queues + support portal ok)"
        );
        return;
    }

    let mut bind_host = env::var("AEGIS_BIND_HOST")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "0.0.0.0".to_owned());

    let mut port: u16 = env::var("AEGIS_BIND_PORT")
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(8_443);

    let mut idx = 1usize;
    while idx < args.len() {
        let arg = args[idx].as_str();
        if let Some(p_str) = arg.strip_prefix("--port=") {
            if let Ok(parsed) = p_str.parse::<u16>() {
                if parsed > 0 {
                    port = parsed;
                }
            }
        } else if arg == "--port" {
            if let Some(next) = args.get(idx + 1) {
                if let Ok(parsed) = next.parse::<u16>() {
                    if parsed > 0 {
                        port = parsed;
                    }
                }
                idx += 1;
            }
        } else if let Some(b_str) = arg.strip_prefix("--bind=") {
            let trimmed = b_str.trim();
            if !trimmed.is_empty() {
                bind_host = trimmed.to_owned();
            }
        } else if arg == "--bind" {
            if let Some(next) = args.get(idx + 1) {
                let trimmed = next.trim();
                if !trimmed.is_empty() {
                    bind_host = trimmed.to_owned();
                }
                idx += 1;
            }
        }
        idx += 1;
    }

    let bind_addr = format!("{bind_host}:{port}");
    let Ok(listener) = TcpListener::bind(&bind_addr) else {
        let _ = writeln!(
            std::io::stderr(),
            "aegis-serverd: could not bind to {bind_addr}"
        );
        std::process::exit(1);
    };

    let _ = writeln!(
        std::io::stdout(),
        "aegis-serverd listening on http://{bind_addr} (Static-IP & Direct Ready, Zero IP Logs, OPAQUE + Queues + Support Portal)"
    );

    let shared_state = Arc::new(Mutex::new((
        FederationServerState::new(init_server_blinding_salt()),
        SupportPortalState::new(),
    )));
    let active_conns = Arc::new(AtomicUsize::new(0));

    for stream_res in listener.incoming() {
        let Ok(mut stream) = stream_res else {
            continue;
        };
        let current = active_conns.fetch_add(1, Ordering::SeqCst);
        if current >= MAX_CONCURRENT_CONNECTIONS {
            active_conns.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let state_ref = Arc::clone(&shared_state);
        let conns_ref = Arc::clone(&active_conns);

        let _ = thread::spawn(move || {
            struct ActiveConnGuard(Arc<AtomicUsize>);
            impl Drop for ActiveConnGuard {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _conn_guard = ActiveConnGuard(conns_ref);
            let io_timeout = Some(Duration::from_secs(2));
            let _ = stream.set_read_timeout(io_timeout);
            let _ = stream.set_write_timeout(io_timeout);
            // Note: peer_addr() is intentionally NEVER inspected or logged (AGENTS.md §2.3, D-0007).
            if let Some(raw_req) = read_http_request_bytes(&mut stream) {
                let (status, content_type, response_body) = if let Some((
                    method,
                    path,
                    body,
                    is_relayed_hop,
                )) = parse_http_request(&raw_req)
                {
                    let (clean_path, query_opt) = path
                        .trim()
                        .split_once('?')
                        .map_or((path.trim(), None), |(p, q)| (p, Some(q)));
                    let has_hop_param = query_opt.is_some_and(|q| {
                        q.split('&').any(|pair| {
                            pair.split_once('=')
                                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("hop"))
                        })
                    });
                    let is_relay_route = clean_path.eq_ignore_ascii_case("/api/v1/queue/relay")
                        || clean_path.eq_ignore_ascii_case("/api/v1/queue/relay_poll");
                    if is_relayed_hop
                        && (clean_path.eq_ignore_ascii_case("/api/v1/tunnel/sealed")
                            || (is_relay_route && has_hop_param))
                    {
                        (
                            400,
                            "application/json",
                            r#"{"error":"relay_loop_detected"}"#.to_owned(),
                        )
                    } else if method.eq_ignore_ascii_case("POST") && is_relay_route {
                        {
                            let mut guard = state_ref
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            let _ = guard.0.record_request(false);
                        }
                        let mut stateless_srv = FederationServerState::default();
                        let mut stateless_portal = SupportPortalState::new();
                        handle_http_request(
                            &mut stateless_srv,
                            &mut stateless_portal,
                            method,
                            path,
                            body,
                        )
                    } else {
                        let mut guard = state_ref
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let (ref mut srv, ref mut portal) = *guard;
                        handle_http_request(srv, portal, method, path, body)
                    }
                } else {
                    (
                        400,
                        "application/json",
                        r#"{"error":"bad_request"}"#.to_owned(),
                    )
                };
                let status_text = match status {
                    200 => "OK",
                    400 => "Bad Request",
                    403 => "Forbidden",
                    429 => "Too Many Requests",
                    500 => "Internal Server Error",
                    502 => "Bad Gateway",
                    _ => "Not Found",
                };
                let header = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nConnection: close\r\n\r\n",
                    response_body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(response_body.as_bytes());
                let _ = stream.flush();
            }
        });
    }
}
