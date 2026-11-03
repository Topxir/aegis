use crate::state::ServerState;
use aegis_core::text::parse_pairs;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 256;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_DEADLINE: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// A parsed request. The query string is already form-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A JSON response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

#[derive(Debug)]
pub enum HttpError {
    Malformed,
    TooLarge,
    Timeout,
    Io,
}

impl HttpError {
    pub fn status(&self) -> u16 {
        match self {
            HttpError::Malformed => 400,
            HttpError::TooLarge => 413,
            HttpError::Timeout => 408,
            HttpError::Io => 400,
        }
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HttpError::Malformed => "malformed request",
            HttpError::TooLarge => "request too large",
            HttpError::Timeout => "request timed out",
            HttpError::Io => "connection error",
        })
    }
}

impl std::error::Error for HttpError {}

fn io_err(e: &io::Error) -> HttpError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => HttpError::Timeout,
        _ => HttpError::Io,
    }
}

fn read_line<R: BufRead>(r: &mut R, budget: &mut usize, deadline: Instant) -> Result<Vec<u8>, HttpError> {
    let mut line = Vec::new();
    loop {
        if Instant::now() > deadline {
            return Err(HttpError::Timeout);
        }
        let mut b = [0u8; 1];
        match r.read(&mut b) {
            Ok(0) => return Err(HttpError::Io),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(&e)),
        }
        if *budget == 0 {
            return Err(HttpError::TooLarge);
        }
        *budget -= 1;
        if b[0] == b'\n' {
            if line.last() != Some(&b'\r') {
                return Err(HttpError::Malformed);
            }
            line.pop();
            return Ok(line);
        }
        line.push(b[0]);
    }
}

fn ascii(b: Vec<u8>) -> Result<String, HttpError> {
    if b.iter().any(|c| !(0x20..0x7f).contains(c)) {
        return Err(HttpError::Malformed);
    }
    String::from_utf8(b).map_err(|_| HttpError::Malformed)
}

/// Reads one request. Only `Content-Length` bodies are accepted.
pub fn read_request<R: BufRead>(r: &mut R, deadline: Instant) -> Result<Request, HttpError> {
    let mut budget = MAX_HEADER_BYTES;
    let first = ascii(read_line(r, &mut budget, deadline)?)?;
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HttpError::Malformed);
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0")
        || method.is_empty()
        || !method.bytes().all(|c| c.is_ascii_uppercase())
        || !target.starts_with('/')
        || target.contains('#')
    {
        return Err(HttpError::Malformed);
    }
    let mut length: Option<usize> = None;
    loop {
        let line = read_line(r, &mut budget, deadline)?;
        if line.is_empty() {
            break;
        }
        let line = ascii(line)?;
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(HttpError::Malformed);
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::Malformed)?;
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(HttpError::Malformed);
                }
                let n: usize = value.parse().map_err(|_| HttpError::TooLarge)?;
                if length.is_some_and(|prev| prev != n) {
                    return Err(HttpError::Malformed);
                }
                length = Some(n);
            }
            "transfer-encoding" => return Err(HttpError::Malformed),
            _ => {}
        }
    }
    let length = length.unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err(HttpError::TooLarge);
    }
    let mut body = vec![0u8; length];
    let mut got = 0;
    while got < length {
        if Instant::now() > deadline {
            return Err(HttpError::Timeout);
        }
        match r.read(&mut body[got..]) {
            Ok(0) => return Err(HttpError::Io),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_err(&e)),
        }
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = parse_pairs(query).map_err(|_| HttpError::Malformed)?;
    Ok(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        query,
        body,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

pub fn write_response<W: Write>(w: &mut W, resp: &Response) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        resp.status,
        reason(resp.status),
        resp.body.len()
    );
    w.write_all(head.as_bytes())?;
    w.write_all(resp.body.as_bytes())?;
    w.flush()
}

fn handle_connection(stream: TcpStream, state: &Mutex<ServerState>) {
    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
    {
        return;
    }
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let resp = match read_request(&mut reader, deadline) {
        Ok(req) => state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .handle(&req, aegis_core::now_secs()),
        Err(HttpError::Io) => return,
        Err(e) => Response {
            status: e.status(),
            body: format!("{{\"error\":\"{e}\"}}"),
        },
    };
    let mut out = &stream;
    if write_response(&mut out, &resp).is_err() {
        return;
    }
    let _ = stream.shutdown(Shutdown::Write);
    let mut sink = [0u8; 1024];
    let drain_until = Instant::now() + Duration::from_secs(1);
    let mut left = 64 * 1024usize;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    while left > 0 && Instant::now() < drain_until {
        match (&stream).read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => left = left.saturating_sub(n),
        }
    }
}

struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accepts connections until `stop` is set. One thread per connection, capped.
pub fn serve(
    listener: &TcpListener,
    state: &Arc<Mutex<ServerState>>,
    stop: &AtomicBool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let slot = Slot(Arc::clone(&active));
                let st = Arc::clone(state);
                let spawned = std::thread::Builder::new()
                    .stack_size(256 * 1024)
                    .spawn(move || {
                        let _slot = slot;
                        handle_connection(stream, &st);
                    });
                drop(spawned);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(raw: &[u8]) -> Result<Request, HttpError> {
        read_request(&mut Cursor::new(raw.to_vec()), Instant::now() + Duration::from_secs(5))
    }

    #[test]
    fn parses_get_with_query() {
        let r = parse(b"GET /api/v2/dir/lookup?u=alice HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/api/v2/dir/lookup");
        assert_eq!(r.query, vec![("u".to_string(), "alice".to_string())]);
        assert!(r.body.is_empty());
    }

    #[test]
    fn parses_post_body() {
        let r = parse(b"POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcEXTRA").unwrap();
        assert_eq!(r.body, b"abc");
        let r = parse(b"POST /x HTTP/1.0\r\ncontent-length: 2\r\ncontent-length: 2\r\n\r\nhi").unwrap();
        assert_eq!(r.body, b"hi");
    }

    #[test]
    fn rejects_garbage() {
        let cases: &[&[u8]] = &[
            b"",
            b"\r\n",
            b"GARBAGE\r\n\r\n",
            b"GET / HTTP/2\r\n\r\n",
            b"GET / HTTP/1.1 extra\r\n\r\n",
            b"get / HTTP/1.1\r\n\r\n",
            b"GET x HTTP/1.1\r\n\r\n",
            b"GET /#f HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\n\n",
            b"GET / HTTP/1.1\r\nno-colon\r\n\r\n",
            b"GET / HTTP/1.1\r\n folded: x\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: \xff\r\n\r\n",
            b"GET /\x00 HTTP/1.1\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"GET /?a=%zz HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x",
        ];
        for c in cases {
            assert!(parse(c).is_err(), "{:?}", String::from_utf8_lossy(c));
        }
    }

    #[test]
    fn enforces_size_caps() {
        let big = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY_BYTES + 1);
        assert!(matches!(parse(big.as_bytes()), Err(HttpError::TooLarge)));
        let huge = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", "9".repeat(40));
        assert!(matches!(parse(huge.as_bytes()), Err(HttpError::TooLarge)));
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_HEADER_BYTES));
        assert!(matches!(parse(long.as_bytes()), Err(HttpError::TooLarge)));
        let many = format!("GET / HTTP/1.1\r\n{}\r\n", "X: y\r\n".repeat(5000));
        assert!(matches!(parse(many.as_bytes()), Err(HttpError::TooLarge)));
        let ok = format!("POST / HTTP/1.1\r\nContent-Length: {MAX_BODY_BYTES}\r\n\r\n");
        let mut raw = ok.into_bytes();
        raw.extend(vec![b'a'; MAX_BODY_BYTES]);
        assert_eq!(parse(&raw).unwrap().body.len(), MAX_BODY_BYTES);
    }

    #[test]
    fn expired_deadline_times_out() {
        let past = Instant::now() - Duration::from_secs(1);
        let r = read_request(&mut Cursor::new(b"GET / HTTP/1.1\r\n\r\n".to_vec()), past);
        assert!(matches!(r, Err(HttpError::Timeout)));
    }

    #[test]
    fn response_format() {
        let mut out = Vec::new();
        write_response(&mut out, &Response { status: 429, body: "{}".into() }).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("\r\n\r\n{}"));
    }
}
