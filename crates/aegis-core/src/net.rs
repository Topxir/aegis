//! Blocking client for the server endpoints of spec sections 3 and 4.

use crate::directory::Registration;
use crate::identity::{is_valid_username, Identity};
use crate::invite::{Hide, InviteCreate};
use crate::text::{pct_encode, sanitize_display_text};
use crate::prekeys::{PrekeyPut, PrekeyTake};
use crate::x3dh::Bundle;
use crate::{hex, now_secs, pad, pin, pow, sealed, Error, Result};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Response bodies larger than this are refused.
pub const MAX_RESPONSE: usize = 1 << 20;
/// Largest blob body: one 1 MiB chunk plus the AEAD tag.
pub const MAX_BLOB: usize = (1 << 20) + 16;
const MAX_HEADERS: usize = 16 * 1024;
const MAX_POLL_FRAMES: usize = 100;

/// The server clients use until the user picks another one.
pub const DEFAULT_SERVER_URL: &str = "https://freeoasis.space";

/// The onion service of the default server. It is the same server and the same transport key.
pub const DEFAULT_ONION_URL: &str =
    "http://axwvmhfhymxuwwzegl4k3o4xfmlwfflaeunsnn557tjyiuy2wetlx7ad.onion";

/// X25519 public key of the default server, compiled into the clients so the first contact is
/// already pinned. If it were `None`, even the default server would be pinned on first use.
pub const DEFAULT_SERVER_X_PK: Option<[u8; 32]> = Some([
    0x8e, 0x5b, 0x9b, 0x5c, 0x70, 0x9e, 0xc8, 0x93, 0xf1, 0x66, 0x24, 0xd0, 0x0d, 0x41, 0x0d, 0xc6,
    0x97, 0x88, 0x7d, 0x4d, 0xee, 0x43, 0x4d, 0x5b, 0xcf, 0x5f, 0x70, 0x5a, 0x35, 0x06, 0x28, 0x60,
]);

/// The compiled-in server key for `endpoint`, if it is the default server (by name or onion
/// address). Any other server (or an unparsable endpoint) gets `None` and is pinned on first use.
pub fn pinned_key_for(endpoint: &str) -> Option<[u8; 32]> {
    let key = DEFAULT_SERVER_X_PK?;
    let ep = Endpoint::parse(endpoint).ok()?;
    [DEFAULT_SERVER_URL, DEFAULT_ONION_URL]
        .iter()
        .any(|d| Endpoint::parse(d).ok().as_ref() == Some(&ep))
        .then_some(key)
}

/// Parsed `https://host[:port]` or (restricted) `http://host[:port]` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

fn http_allowed(host: &str) -> bool {
    host == "127.0.0.1" || host == "localhost" || host.ends_with(".onion")
}

impl Endpoint {
    pub fn parse(s: &str) -> Result<Self> {
        let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(Error::InvalidEndpoint);
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        let host = host.to_ascii_lowercase();
        let host_ok = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
        if !host_ok || (!tls && !http_allowed(&host)) {
            return Err(Error::InvalidEndpoint);
        }
        let port = match port {
            Some(p) => crate::text::parse_u64(p)
                .ok()
                .and_then(|n| u16::try_from(n).ok())
                .filter(|&n| n != 0)
                .ok_or(Error::InvalidEndpoint)?,
            None if tls => 443,
            None => 80,
        };
        Ok(Self { tls, host, port })
    }

    fn host_header(&self) -> String {
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Directory entry returned by a lookup. `title` is already sanitized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub u: String,
    pub title: String,
    pub x: [u8; 32],
    pub ed: [u8; 32],
}

/// Result of a queue poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poll {
    pub frames: Vec<(u64, Vec<u8>)>,
    pub next: u64,
    /// More frames are waiting beyond `next`; poll again right away.
    pub has_more: bool,
}

#[derive(Debug, Clone)]
pub struct Client {
    endpoint: Endpoint,
    socks5: Option<String>,
    pow_bits: u32,
    timeout: Duration,
    srv_pk: Option<[u8; 32]>,
}

/// Most work a client agrees to do when a queue asks for more.
const MAX_SEND_BITS: u32 = 28;

/// How far ahead of the wall clock `unique_ts` may run, well inside the server's window.
const MAX_TS_LEAD: u64 = 30;

static LAST_TS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A timestamp strictly greater than any returned before, so two identical requests in the
/// same second still carry different proofs of work (the server rejects a repeated one).
fn unique_ts() -> u64 {
    use std::sync::atomic::Ordering;
    let now = now_secs();
    let mut last = LAST_TS.load(Ordering::SeqCst);
    loop {
        let next = if last < now.saturating_add(MAX_TS_LEAD) { now.max(last + 1) } else { now };
        match LAST_TS.compare_exchange(last, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return next,
            Err(l) => last = l,
        }
    }
}

/// Random starting point for the proof search, so a repeated request never repeats its proof.
fn pow_start() -> u64 {
    crate::random_bytes::<4>().map_or(0, |b| u64::from(u32::from_be_bytes(b)))
}

/// Result of `pin/open`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinOpen {
    Secret([u8; 32]),
    Wrong { left: u32 },
    Gone,
    Throttled,
}

impl Client {
    /// `socks5` is an optional `host:port` of a SOCKS5 proxy; the server name is
    /// then resolved by the proxy and never locally.
    pub fn new(endpoint: &str, socks5: Option<&str>) -> Result<Self> {
        Ok(Self {
            endpoint: Endpoint::parse(endpoint)?,
            socks5: socks5.map(str::to_owned),
            pow_bits: pow::DEFAULT_BITS,
            timeout: Duration::from_secs(20),
            srv_pk: None,
        })
    }

    /// Proof-of-work difficulty to mine for (the public server uses 18).
    pub fn with_pow_bits(mut self, bits: u32) -> Self {
        self.pow_bits = bits;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Uses the sealed transport (section 23) with a known server key, without contacting the server.
    pub fn with_server_key(mut self, pk: [u8; 32]) -> Self {
        self.srv_pk = Some(pk);
        self
    }

    pub fn server_key(&self) -> Option<[u8; 32]> {
        self.srv_pk
    }

    /// Fetches `GET /api/v2/key` (the only call that is not sealed).
    pub fn fetch_server_key(&self) -> Result<[u8; 32]> {
        let (code, body) = self.raw_request("GET", "/api/v2/key", "", &[], 4096)?;
        if code != 200 {
            return Err(Error::Http(code));
        }
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| Error::BadResponse)?;
        hex::decode_array(v["x"].as_str().ok_or(Error::BadResponse)?).map_err(|_| Error::BadResponse)
    }

    /// Fetches the server key and switches to the sealed transport. With a `known` (pinned) key
    /// a different answer is a hard error; the caller stores `server_key()` on first use.
    pub fn with_pinned_server_key(self, known: Option<[u8; 32]>) -> Result<Self> {
        let key = self.fetch_server_key()?;
        if known.is_some_and(|k| k != key) {
            return Err(Error::ServerKeyChanged);
        }
        Ok(self.with_server_key(key))
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn health(&self) -> Result<()> {
        let (code, body) = self.request("GET", "/health", "", &[])?;
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| Error::BadResponse)?;
        if code == 200 && v["status"] == "ok" && v["protocol"] == 2 {
            Ok(())
        } else {
            Err(Error::BadResponse)
        }
    }

    /// Signs, mines and submits a directory registration.
    pub fn register(&self, identity: &Identity, u: &str, title: &str) -> Result<()> {
        let mut reg = Registration::sign(identity, u, title, now_secs())?;
        reg.mine(self.pow_bits);
        self.submit_registration(&reg)
    }

    pub fn submit_registration(&self, reg: &Registration) -> Result<()> {
        let (code, _) = self.request(
            "POST",
            "/api/v2/dir/register",
            "application/x-www-form-urlencoded",
            reg.to_form().as_bytes(),
        )?;
        if code == 200 {
            Ok(())
        } else {
            Err(Error::Http(code))
        }
    }

    pub fn lookup(&self, u: &str) -> Result<Option<DirEntry>> {
        if !is_valid_username(u) {
            return Err(Error::InvalidUsername);
        }
        let path = format!("/api/v2/dir/lookup?u={}", pct_encode(u));
        let (code, body) = self.request("GET", &path, "", &[])?;
        match code {
            404 => Ok(None),
            200 => {
                let v: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|_| Error::BadResponse)?;
                let s = |k: &str| v[k].as_str().ok_or(Error::BadResponse);
                if s("u")? != u {
                    return Err(Error::BadResponse);
                }
                Ok(Some(DirEntry {
                    u: u.to_owned(),
                    // Servers no longer store titles (section 3); the field may be empty or absent.
                    title: sanitize_display_text(v["title"].as_str().unwrap_or("")),
                    x: hex::decode_array(s("x")?).map_err(|_| Error::BadResponse)?,
                    ed: hex::decode_array(s("ed")?).map_err(|_| Error::BadResponse)?,
                }))
            }
            c => Err(Error::Http(c)),
        }
    }

    /// Posts a padded frame to queue `q`; returns the assigned sequence number.
    pub fn send(&self, q: &[u8; 32], padded: &[u8]) -> Result<u64> {
        self.send_inner(q, padded, None)
    }

    /// Posts to the official queue, which the server accepts only with the owner's signature.
    pub fn send_official(&self, owner_ed_sk: &[u8; 32], padded: &[u8]) -> Result<u64> {
        self.send_inner(&crate::official::official_queue()?, padded, Some(owner_ed_sk))
    }

    fn send_inner(&self, q: &[u8; 32], padded: &[u8], owner_sk: Option<&[u8; 32]>) -> Result<u64> {
        if !pad::is_bucket(padded.len()) {
            return Err(Error::BadPadding);
        }
        let body = hex::encode(padded);
        let qhex = hex::encode(q);
        let mut bits = self.pow_bits;
        // A filling queue asks for more work (429 with the bits it wants); retry once.
        for _ in 0..2 {
            let ts = unique_ts();
            let n = pow::mine_from(&qhex, ts, &pow::body_hash_hex(body.as_bytes()), bits, pow_start());
            let mut path = format!("/api/v2/queue/send?q={qhex}&ts={ts}&pow={n}");
            if let Some(sk) = owner_sk {
                let sig = crate::official::sign_post_auth(sk, q, ts, padded);
                path.push_str(&format!("&sig={}", hex::encode(&sig)));
            }
            let (code, resp) = self.request("POST", &path, "text/plain", body.as_bytes())?;
            if code == 429 {
                let want = serde_json::from_slice::<serde_json::Value>(&resp)
                    .ok()
                    .and_then(|v| v["bits"].as_u64())
                    .and_then(|b| u32::try_from(b).ok());
                if let Some(w) = want.filter(|w| *w > bits && *w <= MAX_SEND_BITS) {
                    bits = w;
                    continue;
                }
            }
            if code != 200 {
                return Err(Error::Http(code));
            }
            let v: serde_json::Value = serde_json::from_slice(&resp).map_err(|_| Error::BadResponse)?;
            return v["seq"].as_u64().ok_or(Error::BadResponse);
        }
        Err(Error::Http(429))
    }

    /// Fetches up to 100 frames with `seq > after`.
    pub fn poll(&self, q: &[u8; 32], after: u64) -> Result<Poll> {
        let path = format!("/api/v2/queue/poll?q={}&after={after}", hex::encode(q));
        let (code, body) = self.request("GET", &path, "", &[])?;
        if code != 200 {
            return Err(Error::Http(code));
        }
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| Error::BadResponse)?;
        let arr = v["frames"].as_array().ok_or(Error::BadResponse)?;
        if arr.len() > MAX_POLL_FRAMES {
            return Err(Error::BadResponse);
        }
        let mut frames = Vec::with_capacity(arr.len());
        let mut last = after;
        for f in arr {
            let seq = f["seq"].as_u64().ok_or(Error::BadResponse)?;
            if seq <= last {
                return Err(Error::BadResponse);
            }
            let d = hex::decode(f["d"].as_str().ok_or(Error::BadResponse)?)
                .map_err(|_| Error::BadResponse)?;
            last = seq;
            frames.push((seq, d));
        }
        let next = v["next"].as_u64().ok_or(Error::BadResponse)?;
        if next != last {
            return Err(Error::BadResponse);
        }
        Ok(Poll { frames, next, has_more: v["has_more"].as_bool().unwrap_or(false) })
    }

    /// Uploads signed and one-time prekeys (section 27.1); returns the number of one-time
    /// prekeys now stored.
    pub fn prekeys_put(&self, put: &PrekeyPut) -> Result<usize> {
        let (code, body) = self.request("POST", "/api/v2/prekeys/put", "application/x-www-form-urlencoded", put.to_form().as_bytes())?;
        if code != 200 {
            return Err(Error::Http(code));
        }
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| Error::BadResponse)?;
        usize::try_from(v["opks"].as_u64().ok_or(Error::BadResponse)?).map_err(|_| Error::BadResponse)
    }

    /// Takes a prekey bundle for `u`; `None` if the user has no signed prekey.
    pub fn prekeys_take(&self, u: &str) -> Result<Option<Bundle>> {
        self.prekeys_take_for(u, None)
    }

    /// [`Self::prekeys_take`] naming the key the caller knows for `u`. A hidden user's
    /// prekeys are only handed out this way (section 29.4).
    pub fn prekeys_take_for(&self, u: &str, ed: Option<&[u8; 32]>) -> Result<Option<Bundle>> {
        if !is_valid_username(u) {
            return Err(Error::InvalidUsername);
        }
        let mut take = PrekeyTake::mine_from(u, unique_ts(), self.pow_bits, pow_start());
        if let Some(ed) = ed {
            take = take.with_ed(*ed);
        }
        let (code, body) = self.request("POST", "/api/v2/prekeys/take", "application/x-www-form-urlencoded", take.to_form().as_bytes())?;
        match code {
            404 => Ok(None),
            200 => Bundle::from_json(&body).map(Some),
            c => Err(Error::Http(c)),
        }
    }

    /// Turns the directory listing of `u` off (`hidden`) or back on (section 29.4).
    pub fn hide(&self, identity: &Identity, u: &str, hidden: bool) -> Result<()> {
        let h = Hide::sign(identity, u, hidden, unique_ts())?;
        self.form_ok("/api/v2/dir/hide", &h.to_form())
    }

    /// Stores a sealed contact bundle for the invite secret `s` (section 29).
    pub fn invite_create(&self, identity: &Identity, u: &str, s: &[u8; 32]) -> Result<()> {
        let c = InviteCreate::sign(identity, u, s, unique_ts())?;
        self.form_ok("/api/v2/invite/create", &c.to_form())
    }

    /// Redeems an invite: `None` if it is unknown, used or expired.
    pub fn invite_redeem(&self, s: &[u8; 32]) -> Result<Option<crate::invite::Bundle>> {
        let form = crate::invite::id_form(&crate::invite::invite_id(s));
        let (code, body) = self.request("POST", "/api/v2/invite/redeem", "application/x-www-form-urlencoded", form.as_bytes())?;
        match code {
            404 => Ok(None),
            200 => {
                let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| Error::BadResponse)?;
                let sealed = hex::decode(v["box"].as_str().ok_or(Error::BadResponse)?).map_err(|_| Error::BadResponse)?;
                crate::invite::open_bundle(s, &sealed).map(Some)
            }
            c => Err(Error::Http(c)),
        }
    }

    /// Drops an open invite. The server answers the same whether it existed or not.
    pub fn invite_revoke(&self, s: &[u8; 32]) -> Result<()> {
        self.form_ok("/api/v2/invite/revoke", &crate::invite::id_form(&crate::invite::invite_id(s)))
    }

    fn form_ok(&self, path: &str, form: &str) -> Result<()> {
        match self.request("POST", path, "application/x-www-form-urlencoded", form.as_bytes())?.0 {
            200 => Ok(()),
            c => Err(Error::Http(c)),
        }
    }

    /// Cover-traffic request of `req_len` bytes asking for `resp_len` bytes back (section 26).
    pub fn nop(&self, req_len: u32, resp_len: u32) -> Result<()> {
        let body = crate::cover::nop_body(req_len, resp_len)?;
        let (code, _) = self.request("POST", "/api/v2/nop", "application/octet-stream", &body)?;
        if code == 200 {
            Ok(())
        } else {
            Err(Error::Http(code))
        }
    }

    fn pin_call(&self, op: &str, slot: &[u8; 32], v: &[u8; 32], s: Option<&[u8; 32]>) -> Result<(u16, Vec<u8>)> {
        let (slot_h, v_h) = (hex::encode(slot), hex::encode(v));
        let s_h = s.map(|s| hex::encode(s));
        let input = match &s_h {
            Some(s_h) => pin::create_hash_input(&slot_h, &v_h, s_h),
            None => pin::open_hash_input(&slot_h, &v_h),
        };
        let ts = unique_ts();
        let n = pow::mine_from(&pin::pow_scope(&slot_h), ts, &pow::body_hash_hex(input.as_bytes()), self.pow_bits, pow_start());
        let mut form = format!("slot={slot_h}&v={v_h}");
        if let Some(s_h) = &s_h {
            form.push_str(&format!("&s={s_h}"));
        }
        form.push_str(&format!("&ts={ts}&pow={n}"));
        self.request("POST", &format!("/api/v2/pin/{op}"), "application/x-www-form-urlencoded", form.as_bytes())
    }

    /// Stores a new PIN slot; `Error::Http(409)` if it exists.
    pub fn pin_create(&self, slot: &[u8; 32], verifier: &[u8; 32], s: &[u8; 32]) -> Result<()> {
        match self.pin_call("create", slot, verifier, Some(s))?.0 {
            200 => Ok(()),
            c => Err(Error::Http(c)),
        }
    }

    pub fn pin_open(&self, slot: &[u8; 32], verifier: &[u8; 32]) -> Result<PinOpen> {
        let (code, body) = self.pin_call("open", slot, verifier, None)?;
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        match code {
            200 => {
                let s = hex::decode_array(v["s"].as_str().ok_or(Error::BadResponse)?).map_err(|_| Error::BadResponse)?;
                Ok(PinOpen::Secret(s))
            }
            403 => {
                let left = u32::try_from(v["left"].as_u64().ok_or(Error::BadResponse)?).map_err(|_| Error::BadResponse)?;
                Ok(PinOpen::Wrong { left })
            }
            404 => Ok(PinOpen::Gone),
            429 => Ok(PinOpen::Throttled),
            c => Err(Error::Http(c)),
        }
    }

    /// Removes the slot when `verifier` matches (a mismatch counts as a failed attempt).
    pub fn pin_delete(&self, slot: &[u8; 32], verifier: &[u8; 32]) -> Result<()> {
        match self.pin_call("delete", slot, verifier, None)?.0 {
            200 | 404 => Ok(()),
            c => Err(Error::Http(c)),
        }
    }

    /// Uploads one ciphertext chunk under a random id (spec section 14).
    pub fn blob_put(&self, id: &[u8; 32], data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() > MAX_BLOB {
            return Err(Error::BadResponse);
        }
        let idhex = hex::encode(id);
        let ts = now_secs();
        let scope = format!("blob:{idhex}");
        let n = pow::mine_from(&scope, ts, &pow::body_hash_hex(data), self.pow_bits, pow_start());
        let path = format!("/api/v2/blob/put?id={idhex}&ts={ts}&pow={n}");
        let (code, _) =
            self.request_capped("POST", &path, "application/octet-stream", data, MAX_RESPONSE)?;
        if code == 200 {
            Ok(())
        } else {
            Err(Error::Http(code))
        }
    }

    /// Downloads one ciphertext chunk; `None` if the server does not have it.
    pub fn blob_get(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let path = format!("/api/v2/blob/get?id={}", hex::encode(id));
        let (code, body) = self.request_capped("GET", &path, "", &[], MAX_BLOB)?;
        match code {
            404 => Ok(None),
            200 if !body.is_empty() => Ok(Some(body)),
            200 => Err(Error::BadResponse),
            c => Err(Error::Http(c)),
        }
    }

    fn connect(&self) -> Result<TcpStream> {
        let ep = &self.endpoint;
        let stream = if let Some(proxy) = &self.socks5 {
            let mut s = connect_addr(proxy, self.timeout)?;
            s.set_read_timeout(Some(self.timeout))?;
            s.set_write_timeout(Some(self.timeout))?;
            socks5_connect(&mut s, &ep.host, ep.port)?;
            s
        } else {
            connect_addr(&format!("{}:{}", ep.host, ep.port), self.timeout)?
        };
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    fn request(&self, method: &str, path: &str, ctype: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        self.request_capped(method, path, ctype, body, MAX_RESPONSE)
    }

    fn request_capped(
        &self,
        method: &str,
        path: &str,
        ctype: &str,
        body: &[u8],
        cap: usize,
    ) -> Result<(u16, Vec<u8>)> {
        let Some(pk) = &self.srv_pk else {
            return self.raw_request(method, path, ctype, body, cap);
        };
        let (outer, k_resp) = sealed::seal_request(pk, method, path, body)?;
        let (code, resp) =
            self.raw_request("POST", "/api/v2/s", "application/octet-stream", &outer, sealed::MAX_OUTER_BYTES + 64)?;
        if code != 200 {
            return Err(Error::Http(code));
        }
        let (status, inner) = sealed::open_response(&k_resp, &resp)?;
        if inner.len() > cap {
            return Err(Error::BadResponse);
        }
        Ok((status, inner))
    }

    fn raw_request(
        &self,
        method: &str,
        path: &str,
        ctype: &str,
        body: &[u8],
        cap: usize,
    ) -> Result<(u16, Vec<u8>)> {
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: aegis\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
            self.endpoint.host_header()
        );
        if method == "POST" {
            head.push_str(&format!("Content-Type: {ctype}\r\nContent-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        let mut req = head.into_bytes();
        req.extend_from_slice(body);

        let tcp = self.connect()?;
        let deadline = Instant::now() + self.timeout * 3;
        if self.endpoint.tls {
            let connector = native_tls::TlsConnector::builder()
                .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
                .build()
                .map_err(|e| Error::Net(format!("tls setup: {e}")))?;
            let mut s = connector
                .connect(&self.endpoint.host, tcp)
                .map_err(|e| Error::Net(format!("tls: {e}")))?;
            exchange(&mut s, &req, deadline, cap)
        } else {
            let mut s = tcp;
            exchange(&mut s, &req, deadline, cap)
        }
    }
}

fn connect_addr(addr: &str, timeout: Duration) -> Result<TcpStream> {
    let mut last = Error::Net("no address".into());
    for a in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = Error::from(e),
        }
    }
    Err(last)
}

/// SOCKS5 CONNECT with the destination sent as a domain name (remote DNS).
pub fn socks5_connect<S: Read + Write>(s: &mut S, host: &str, port: u16) -> Result<()> {
    let host_b = host.as_bytes();
    let hl = u8::try_from(host_b.len()).map_err(|_| Error::InvalidEndpoint)?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [5, 0] {
        return Err(Error::Net("socks5: no acceptable auth method".into()));
    }
    let mut req = vec![5, 1, 0, 3, hl];
    req.extend_from_slice(host_b);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h)?;
    if h[0] != 5 || h[1] != 0 {
        return Err(Error::Net(format!("socks5: connect refused ({})", h[1])));
    }
    let skip = match h[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            usize::from(l[0]) + 2
        }
        _ => return Err(Error::Net("socks5: bad reply".into())),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest)?;
    Ok(())
}

fn read_some<S: Read>(s: &mut S, buf: &mut Vec<u8>, deadline: Instant) -> Result<usize> {
    if Instant::now() > deadline {
        return Err(Error::Net("deadline exceeded".into()));
    }
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                return Ok(n);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // TLS peers that close without close_notify.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(0),
            Err(e) => return Err(e.into()),
        }
    }
}

fn exchange<S: Read + Write>(
    s: &mut S,
    req: &[u8],
    deadline: Instant,
    cap: usize,
) -> Result<(u16, Vec<u8>)> {
    s.write_all(req)?;
    s.flush()?;
    read_response_capped(s, deadline, cap)
}

/// Reads one HTTP/1.x response (Content-Length, chunked or until close), capped at 1 MiB.
pub fn read_response<S: Read>(s: &mut S, deadline: Instant) -> Result<(u16, Vec<u8>)> {
    read_response_capped(s, deadline, MAX_RESPONSE)
}

fn read_response_capped<S: Read>(s: &mut S, deadline: Instant, cap: usize) -> Result<(u16, Vec<u8>)> {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEADERS {
            return Err(Error::BadResponse);
        }
        if read_some(s, &mut buf, deadline)? == 0 {
            return Err(Error::BadResponse);
        }
    };
    let head = core::str::from_utf8(&buf[..head_end]).map_err(|_| Error::BadResponse)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(Error::BadResponse)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !(version == "HTTP/1.1" || version == "HTTP/1.0") {
        return Err(Error::BadResponse);
    }
    let code: u16 = parts
        .next()
        .and_then(|c| c.parse().ok())
        .filter(|c| (100..600).contains(c))
        .ok_or(Error::BadResponse)?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            return Err(Error::BadResponse);
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "content-length" {
            let n: usize = v.parse().map_err(|_| Error::BadResponse)?;
            if n > cap || content_length.replace(n).is_some_and(|o| o != n) {
                return Err(Error::BadResponse);
            }
        } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    let mut raw = buf.split_off(head_end + 4);
    let body = if chunked {
        loop {
            if let Some(r) = decode_chunked(&raw, cap) {
                break r?;
            }
            if raw.len() > cap * 2 {
                return Err(Error::BadResponse);
            }
            if read_some(s, &mut raw, deadline)? == 0 {
                return Err(Error::BadResponse);
            }
        }
    } else if let Some(n) = content_length {
        while raw.len() < n {
            if read_some(s, &mut raw, deadline)? == 0 {
                return Err(Error::BadResponse);
            }
        }
        raw.truncate(n);
        raw
    } else {
        while read_some(s, &mut raw, deadline)? != 0 {
            if raw.len() > cap {
                return Err(Error::BadResponse);
            }
        }
        raw
    };
    if body.len() > cap {
        return Err(Error::BadResponse);
    }
    Ok((code, body))
}

/// Decodes a complete chunked body, or `None` if more data is needed.
fn decode_chunked(raw: &[u8], cap: usize) -> Option<Result<Vec<u8>>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let eol = raw[i..].windows(2).position(|w| w == b"\r\n")? + i;
        let size_line = match core::str::from_utf8(&raw[i..eol]) {
            Ok(s) => s.split(';').next().unwrap_or("").trim(),
            Err(_) => return Some(Err(Error::BadResponse)),
        };
        let Ok(size) = usize::from_str_radix(size_line, 16) else {
            return Some(Err(Error::BadResponse));
        };
        i = eol + 2;
        if size == 0 {
            // Trailers are ignored; wait for the terminating blank line.
            return if raw[i..].windows(2).any(|w| w == b"\r\n") {
                Some(Ok(out))
            } else {
                None
            };
        }
        if out.len().checked_add(size).is_none_or(|n| n > cap) {
            return Some(Err(Error::BadResponse));
        }
        let end = i + size;
        if raw.len() < end + 2 {
            return None;
        }
        out.extend_from_slice(&raw[i..end]);
        if &raw[end..end + 2] != b"\r\n" {
            return Some(Err(Error::BadResponse));
        }
        i = end + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn endpoints() {
        let e = Endpoint::parse("https://freeoasis.space").unwrap();
        assert_eq!((e.tls, e.host.as_str(), e.port), (true, "freeoasis.space", 443));
        assert_eq!(Endpoint::parse("https://example.org:8443/").unwrap().port, 8443);
        assert!(Endpoint::parse("http://127.0.0.1:8080").is_ok());
        assert!(Endpoint::parse("http://localhost").is_ok());
        assert!(Endpoint::parse("http://abcdefghijklmnop.onion").is_ok());
        for bad in [
            "http://example.com",
            "ftp://x",
            "example.com",
            "https://",
            "https://a/b",
            "https://user@a.com",
            "https://a.com:0",
            "https://a.com:99999",
            "https://a b.com",
            "http://127.0.0.1.evil.com",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn onion_default_is_pinned() {
        assert_eq!(pinned_key_for(DEFAULT_ONION_URL), DEFAULT_SERVER_X_PK);
        assert_eq!(pinned_key_for(&format!("{DEFAULT_ONION_URL}/")), DEFAULT_SERVER_X_PK);
        assert_eq!(pinned_key_for("http://other.onion"), None);
        assert_eq!(pinned_key_for(&format!("{DEFAULT_ONION_URL}:8080")), None);
    }

    #[test]
    fn responses() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(read_response(&mut Cursor::new(&ok[..]), far()).unwrap(), (200, b"hello".to_vec()));
        let ch = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
        assert_eq!(read_response(&mut Cursor::new(&ch[..]), far()).unwrap().1, b"abcde");
        let eof = b"HTTP/1.0 404 Not Found\r\n\r\nbody";
        assert_eq!(read_response(&mut Cursor::new(&eof[..]), far()).unwrap(), (404, b"body".to_vec()));
        for bad in [
            &b"garbage"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n",
            b"HTTP/1.1 abc OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
        ] {
            assert!(read_response(&mut Cursor::new(bad), far()).is_err());
        }
    }

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn socks5_sends_domain_name() {
        let reply = vec![5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut d = Duplex { input: Cursor::new(reply), output: vec![] };
        socks5_connect(&mut d, "example.onion", 80).unwrap();
        let mut want = vec![5, 1, 0, 5, 1, 0, 3, 13];
        want.extend_from_slice(b"example.onion");
        want.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(d.output, want);
        let mut refused = Duplex { input: Cursor::new(vec![5, 0, 5, 5, 0, 1]), output: vec![] };
        assert!(socks5_connect(&mut refused, "a.onion", 80).is_err());
        let mut noauth = Duplex { input: Cursor::new(vec![5, 0xff]), output: vec![] };
        assert!(socks5_connect(&mut noauth, "a.onion", 80).is_err());
    }
}
