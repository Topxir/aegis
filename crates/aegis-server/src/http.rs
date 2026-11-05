use crate::blob::MAX_BLOB_BYTES;
use crate::state::{handle_blob, persist_now, ServerState};
use aegis_core::sealed;
use aegis_core::text::parse_pairs;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
/// A blob body must arrive within this window (absolute, per connection).
const BLOB_BODY_WINDOW: Duration = Duration::from_secs(60);
const BLOB_PUT_PATH: &str = "/api/v2/blob/put";
const SEALED_PATH: &str = "/api/v2/s";
const MAX_CONNECTIONS: usize = 256;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// The request line and all headers must be complete this long after the connection opened.
const HEADER_DEADLINE: Duration = Duration::from_secs(10);
/// A small body must be complete this long after the headers.
const SMALL_BODY_WINDOW: Duration = Duration::from_secs(10);
/// Large bodies: after this grace period the average rate must stay above `MIN_BODY_RATE`.
const BODY_RATE_GRACE: Duration = Duration::from_secs(10);
const MIN_BODY_RATE: u64 = 4096;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// A parsed request. The query string is already form-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Reply of the blob routes: JSON, or raw blob bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobReply {
    Json(Response),
    Bytes(Vec<u8>),
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
    read_request_with(r, deadline, &mut |_| {})
}

/// Like [`read_request`]; `progress` gets `Some(n)` while a body is incoming (`n` bytes so far) and `None`
/// once the request is complete or has no body, after the headers are in.
fn read_request_with<R: BufRead>(
    r: &mut R,
    deadline: Instant,
    progress: &mut dyn FnMut(Option<usize>),
) -> Result<Request, HttpError> {
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
    progress((length.unwrap_or(0) > 0).then_some(0));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    // The limit is decided by the request line alone, before any body byte is read.
    let body_start = Instant::now();
    let (limit, deadline, floor) = if method == "POST" && path == BLOB_PUT_PATH {
        (MAX_BLOB_BYTES, body_start + BLOB_BODY_WINDOW, true)
    } else if method == "POST" && path == SEALED_PATH {
        (sealed::MAX_OUTER_BYTES, body_start + BLOB_BODY_WINDOW, true)
    } else {
        (MAX_BODY_BYTES, body_start + SMALL_BODY_WINDOW, false)
    };
    let length = length.unwrap_or(0);
    if length > limit {
        return Err(HttpError::TooLarge);
    }
    // Grow with the data actually received so idle connections do not pin the full size.
    let mut body = Vec::with_capacity(length.min(16 * 1024));
    let mut chunk = [0u8; 16 * 1024];
    while body.len() < length {
        let now = Instant::now();
        if now > deadline {
            return Err(HttpError::Timeout);
        }
        if floor {
            let slow = now.duration_since(body_start).saturating_sub(BODY_RATE_GRACE).as_secs();
            if (body.len() as u64) < slow.saturating_mul(MIN_BODY_RATE) {
                return Err(HttpError::Timeout);
            }
        }
        let want = chunk.len().min(length - body.len());
        match r.read(&mut chunk[..want]) {
            Ok(0) => return Err(HttpError::Io),
            Ok(n) => {
                body.extend_from_slice(&chunk[..n]);
                progress(Some(body.len()));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_err(&e)),
        }
    }
    progress(None);
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

/// Writes a `200` with raw blob bytes.
pub fn write_blob_bytes<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    w.write_all(head.as_bytes())?;
    w.write_all(bytes)?;
    w.flush()
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

/// Routes one request to the blob handlers or the main state. PIN changes are written to
/// disk before the reply, so a restart can never reset an attempt counter.
fn dispatch(state: &Mutex<ServerState>, req: &Request, now: u64) -> BlobReply {
    if req.path.starts_with("/api/v2/blob/") {
        return handle_blob(state, req, now);
    }
    let resp = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .handle(req, now);
    let durable = req.path.starts_with("/api/v2/pin/") || req.path.starts_with("/api/v2/prekeys/");
    if durable && persist_now(state).is_err() {
        return json_err(503, "storage unavailable");
    }
    BlobReply::Json(resp)
}

fn json_err(status: u16, msg: &str) -> BlobReply {
    BlobReply::Json(Response { status, body: format!("{{\"error\":\"{msg}\"}}") })
}

/// `POST /api/v2/s`: opens the sealed request, runs it like a direct one and seals the answer.
fn handle_sealed(state: &Mutex<ServerState>, outer: &Request) -> BlobReply {
    let empty_400 = || BlobReply::Json(Response { status: 400, body: String::new() });
    let sk = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .server_secret_key();
    let Some(sk) = sk else { return empty_400() };
    let Ok((inner, k_resp)) = sealed::open_request(&sk, &outer.body) else {
        return empty_400();
    };
    let mut e_pk = [0u8; 32];
    e_pk.copy_from_slice(&outer.body[..32]);
    let fresh = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .sealed_admit(e_pk, inner.ts, aegis_core::now_secs());
    if !fresh {
        return empty_400();
    }
    let (status, body) = run_inner(state, &inner);
    match sealed::seal_response(&k_resp, status, &body) {
        Ok(b) => BlobReply::Bytes(b),
        Err(_) => empty_400(),
    }
}

fn run_inner(state: &Mutex<ServerState>, inner: &sealed::SealedRequest) -> (u16, Vec<u8>) {
    let fail = |status: u16, msg: &str| (status, format!("{{\"error\":\"{msg}\"}}").into_bytes());
    let (path, query) = inner.target.split_once('?').unwrap_or((inner.target.as_str(), ""));
    if !inner.method.bytes().all(|c| c.is_ascii_uppercase())
        || inner.method.is_empty()
        || !path.starts_with('/')
        || !inner.target.bytes().all(|c| (0x21..0x7f).contains(&c))
        || path == SEALED_PATH
    {
        return fail(400, "malformed request");
    }
    let limit = if inner.method == "POST" && path == BLOB_PUT_PATH { MAX_BLOB_BYTES } else { MAX_BODY_BYTES };
    if inner.body.len() > limit {
        return fail(413, "request too large");
    }
    let Ok(query) = parse_pairs(query) else {
        return fail(400, "malformed request");
    };
    let req = Request {
        method: inner.method.clone(),
        path: path.to_owned(),
        query,
        body: inner.body.clone(),
    };
    match dispatch(state, &req, aegis_core::now_secs()) {
        BlobReply::Json(r) => (r.status, r.body.into_bytes()),
        BlobReply::Bytes(b) => (200, b),
    }
}

fn handle_connection(stream: TcpStream, state: &Mutex<ServerState>, phase: &AtomicU64) {
    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
    {
        return;
    }
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let deadline = Instant::now() + HEADER_DEADLINE;
    let reply = match read_request_with(&mut reader, deadline, &mut |p| {
        phase.store(p.map_or(PHASE_IDLE, |n| n as u64), Ordering::SeqCst);
    }) {
        Ok(req) if req.method == "POST" && req.path == SEALED_PATH => handle_sealed(state, &req),
        Ok(req) => dispatch(state, &req, aegis_core::now_secs()),
        Err(HttpError::Io) => return,
        Err(e) => json_err(e.status(), &e.to_string()),
    };
    let mut out = &stream;
    let written = match &reply {
        BlobReply::Json(resp) => write_response(&mut out, resp),
        BlobReply::Bytes(b) => write_blob_bytes(&mut out, b),
    };
    if written.is_err() {
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

/// A live connection, so that one still waiting for its headers can be cut when the server is full.
struct Conn {
    id: u64,
    started: Instant,
    stream: TcpStream,
    phase: Arc<AtomicU64>,
}

/// `Conn::phase` while the headers are still incoming.
const PHASE_HEADERS: u64 = u64::MAX;
/// `Conn::phase` once the request is complete (or has no body); otherwise the body bytes received.
const PHASE_IDLE: u64 = u64::MAX - 1;

type Registry = Arc<Mutex<Vec<Conn>>>;

struct Slot {
    active: Arc<AtomicUsize>,
    registry: Registry,
    id: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|c| c.id != self.id);
    }
}

/// Closes the connection that has made the least progress: the oldest one still sending headers,
/// else the one that has received the fewest body bytes. False when every connection is working
/// on a complete request.
fn evict_stalled(registry: &Registry) -> bool {
    let reg = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let victim = reg
        .iter()
        .filter_map(|c| match c.phase.load(Ordering::SeqCst) {
            PHASE_IDLE => None,
            PHASE_HEADERS => Some((0u8, 0u64, c)),
            n => Some((1, n, c)),
        })
        .min_by_key(|&(rank, bytes, c)| (rank, bytes, c.started))
        .map(|(_, _, c)| c);
    match victim {
        Some(c) => {
            let _ = c.stream.shutdown(Shutdown::Both);
            true
        }
        None => false,
    }
}

/// Accepts connections until `stop` is set. One thread per connection, capped. When the cap is
/// reached the connection that has made the least progress is cut (headers first, then the
/// fewest body bytes), so idle or trickling sockets cannot lock others out; there are no per-IP
/// limits (Tor exits are shared).
pub fn serve(
    listener: &TcpListener,
    state: &Arc<Mutex<ServerState>>,
    stop: &AtomicBool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    let registry: Registry = Arc::new(Mutex::new(Vec::new()));
    let mut next_id = 0u64;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS
                    && (!evict_stalled(&registry)
                        || active.load(Ordering::SeqCst) >= MAX_CONNECTIONS + MAX_CONNECTIONS / 4)
                {
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                next_id += 1;
                let phase = Arc::new(AtomicU64::new(PHASE_HEADERS));
                let Ok(clone) = stream.try_clone() else {
                    active.fetch_sub(1, Ordering::SeqCst);
                    continue;
                };
                registry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Conn { id: next_id, started: Instant::now(), stream: clone, phase: Arc::clone(&phase) });
                let slot = Slot { active: Arc::clone(&active), registry: Arc::clone(&registry), id: next_id };
                let st = Arc::clone(state);
                let spawned = std::thread::Builder::new()
                    .stack_size(256 * 1024)
                    .spawn(move || {
                        let _slot = slot;
                        handle_connection(stream, &st, &phase);
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
