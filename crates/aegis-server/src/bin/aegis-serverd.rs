//! `aegis-serverd` — Zero-knowledge Aegis Federation Server & Support/Donation Web Portal daemon.
//!
//! Serves:
//! - `GET /` and `GET /en` — Built-in Support & Anonymous Donation Web Portal (`SupporterPass`)
//! - `GET /health` — Zero-personal-data uptime and adaptive PoW status
//! - `GET /api/v1/pow` — Adaptive Anti-DDoS Proof-of-Work challenge parameters
//! - `POST /api/v1/queue/send` — Enqueue padded E2EE frame into anonymous unidirectional queue
//! - `POST /api/v1/queue/poll` — Drain pending frames from anonymous unidirectional queue
//! - `POST /api/v1/support/ticket` — Submit encrypted E2EE support ticket
//! - `POST /api/v1/donate/claim-pass` — Issue blind-signed `SupporterPass` token
//!
//! Run with `--self-test` for CI verification without binding a persistent loop.

use aegis_server::{handle_http_request, FederationServerState, SupportPortalState};
use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

fn parse_http_request(raw: &[u8]) -> Option<(&str, &str, &str)> {
    let text = core::str::from_utf8(raw).ok()?;
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));
    let mut lines = head.lines();
    let first_line = lines.next()?.trim();
    if first_line.is_empty() {
        return None;
    }
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    if !path.starts_with('/') {
        return None;
    }
    Some((method, path, body))
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

    let mut server_state = FederationServerState::default();
    let mut portal_state = SupportPortalState::new();

    for stream_res in listener.incoming() {
        let Ok(mut stream) = stream_res else {
            continue;
        };
        let io_timeout = Some(Duration::from_secs(2));
        let _ = stream.set_read_timeout(io_timeout);
        let _ = stream.set_write_timeout(io_timeout);
        // Note: peer_addr() is intentionally NEVER inspected or logged (AGENTS.md §2.3, D-0007).
        let mut buf = [0u8; 8192];
        let Ok(n) = stream.read(&mut buf) else {
            continue;
        };
        if n == 0 {
            continue;
        }
        let (status, content_type, response_body) =
            if let Some((method, path, body)) = parse_http_request(&buf[..n]) {
                handle_http_request(&mut server_state, &mut portal_state, method, path, body)
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
            429 => "Too Many Requests",
            _ => "Not Found",
        };
        let header = format!(
            "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(response_body.as_bytes());
        let _ = stream.flush();
    }
}
