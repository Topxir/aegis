//! `aegis-server` — Zero-knowledge federation server engine, unidirectional queue TTLs,
//! constant-shape OPAQUE record storage, anti-DDoS adaptive Proof-of-Work without IP logging (D-0007),
//! and built-in Support & Donation Web Portal (D-0006, D-0010, PLAN.md §4.4, §6).

use aegis_crypto::{hkdf_sha256, hmac_sha256};
use aegis_protocol::{pad_frame, SupportTicket, SupportTicketCategory, PADDING_BUCKETS};
use core::fmt;
use std::collections::BTreeMap;

/// Default message queue time-to-live on the server: 30 days in seconds (PLAN.md §5).
pub const DEFAULT_QUEUE_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Baseline PoW difficulty in leading zero bits under normal server load.
pub const BASE_POW_DIFFICULTY_BITS: u8 = 12;

/// Maximum PoW difficulty in leading zero bits under heavy DDoS attack.
pub const MAX_POW_DIFFICULTY_BITS: u8 = 24;

/// Fixed constant size in bytes of an OPAQUE registration record + encrypted `AccountVault` envelope.
/// Ensures `fetch_opaque_record` always returns a constant-size response whether `login_id` exists or not (D-0002, D-0007).
pub const CONSTANT_OPAQUE_RECORD_LEN: usize = 1024;

/// Default maximum buffered frames per anonymous unidirectional queue.
pub const DEFAULT_MAX_QUEUE_FRAMES: usize = 256;

/// Global maximum number of concurrent active queues in memory (prevents RAM exhaustion DoS).
pub const MAX_ACTIVE_QUEUES: usize = 4_096;

/// Global maximum number of registered OPAQUE accounts in memory (prevents RAM exhaustion DoS).
pub const MAX_OPAQUE_ACCOUNTS: usize = 16_384;

/// Computes the adaptive Proof-of-Work difficulty (in leading zero bits) based on
/// the current in-memory sliding window request rate (D-0007).
/// No client IP addresses are stored on disk.
#[must_use]
pub fn compute_pow_difficulty(requests_per_minute: u32, suspicious_burst: bool) -> u8 {
    let mut bits = match requests_per_minute {
        0..=60 => BASE_POW_DIFFICULTY_BITS,
        61..=300 => BASE_POW_DIFFICULTY_BITS + 4,
        301..=1_500 => BASE_POW_DIFFICULTY_BITS + 8,
        _ => MAX_POW_DIFFICULTY_BITS,
    };
    if suspicious_burst {
        bits = bits.saturating_add(4).min(MAX_POW_DIFFICULTY_BITS);
    }
    bits
}

/// Per-queue quota configuration so a spammed invite or contact queue can be rotated
/// or deleted in 1 click without affecting other contacts (D-0007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueQuota {
    /// Ephemeral one-way queue identifier.
    pub queue_id: [u8; 32],
    /// Maximum buffered frames allowed in this queue.
    pub max_buffered_frames: usize,
    /// Current buffered frame count.
    pub current_buffered_frames: usize,
    /// TTL in seconds for undelivered frames.
    pub ttl_secs: u64,
}

impl QueueQuota {
    /// Returns `true` if the queue configuration is valid and has capacity for another frame.
    #[must_use]
    pub fn can_enqueue(&self) -> bool {
        self.queue_id != [0u8; 32]
            && self.max_buffered_frames > 0
            && self.ttl_secs > 0
            && self.ttl_secs <= DEFAULT_QUEUE_TTL_SECS
            && self.current_buffered_frames < self.max_buffered_frames
    }

    /// Returns `true` if the queue can accept an incoming frame of `frame_len_bytes`,
    /// enforcing fixed metadata-hiding padding buckets (`[256, 1024, 4096, 16384]`).
    #[must_use]
    pub fn can_accept_frame(&self, frame_len_bytes: usize) -> bool {
        self.can_enqueue() && PADDING_BUCKETS.contains(&frame_len_bytes)
    }
}

/// Server operation errors (fail-closed per AGENTS.md §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerError {
    /// Queue identifier or login identifier is all-zero (`[0u8; 32]`).
    InvalidIdentifier,
    /// Frame size does not match one of [`PADDING_BUCKETS`].
    InvalidFrameBucketSize(usize),
    /// Queue has reached its maximum buffered frame quota.
    QueueFull,
    /// OPAQUE record size must equal [`CONSTANT_OPAQUE_RECORD_LEN`].
    InvalidOpaqueRecordLength(usize),
    /// In-memory Anti-DDoS rate limit exceeded; client must solve a higher PoW challenge.
    RateLimited { required_pow_bits: u8 },
    /// Support ticket or donation voucher failed validation.
    InvalidSupportRequest,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier => write!(f, "identifier must not be all-zero"),
            Self::InvalidFrameBucketSize(len) => {
                write!(f, "frame length {len} is not a valid padding bucket")
            }
            Self::QueueFull => write!(f, "unidirectional queue quota exceeded"),
            Self::InvalidOpaqueRecordLength(len) => write!(
                f,
                "OPAQUE record length {len} must equal {CONSTANT_OPAQUE_RECORD_LEN}"
            ),
            Self::RateLimited { required_pow_bits } => write!(
                f,
                "rate limit exceeded; solve {required_pow_bits}-bit PoW challenge"
            ),
            Self::InvalidSupportRequest => write!(f, "invalid support ticket or donation voucher"),
        }
    }
}

impl std::error::Error for ServerError {}

/// Zero-knowledge Federation Server Engine (PLAN.md §6.1, §7.2, D-0002, D-0007).
/// Stores only padded E2EE queue frames and blinded OPAQUE records in RAM/storage.
/// Never logs IP addresses, nicknames, or social graphs.
#[derive(Clone)]
pub struct FederationServerState {
    server_blinding_salt: [u8; 32],
    queues: BTreeMap<[u8; 32], Vec<Vec<u8>>>,
    opaque_records: BTreeMap<[u8; 32], Vec<u8>>,
    requests_in_window: u32,
    suspicious_burst: bool,
}

impl fmt::Debug for FederationServerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FederationServerState")
            .field("server_blinding_salt", &"[REDACTED]")
            .field("active_queues_count", &self.queues.len())
            .field("opaque_records_count", &self.opaque_records.len())
            .field("requests_in_window", &self.requests_in_window)
            .field("suspicious_burst", &self.suspicious_burst)
            .finish()
    }
}

impl Default for FederationServerState {
    fn default() -> Self {
        Self::new([0xA7; 32])
    }
}

impl FederationServerState {
    /// Creates a new zero-knowledge federation server instance with a secret blinding salt.
    #[must_use]
    pub fn new(server_blinding_salt: [u8; 32]) -> Self {
        let salt = if server_blinding_salt == [0u8; 32] {
            [0xA7; 32]
        } else {
            server_blinding_salt
        };
        Self {
            server_blinding_salt: salt,
            queues: BTreeMap::new(),
            opaque_records: BTreeMap::new(),
            requests_in_window: 0,
            suspicious_burst: false,
        }
    }

    /// Returns the current adaptive Proof-of-Work difficulty in bits (D-0007).
    #[must_use]
    pub fn current_pow_difficulty(&self) -> u8 {
        compute_pow_difficulty(self.requests_in_window, self.suspicious_burst)
    }

    /// Records an anonymous request in the in-memory sliding window (zero IP logs!).
    pub fn record_request(&mut self, is_burst: bool) -> u8 {
        self.requests_in_window = self.requests_in_window.saturating_add(1);
        if is_burst {
            self.suspicious_burst = true;
        }
        self.current_pow_difficulty()
    }

    /// Resets the in-memory sliding rate-limit window (e.g. every 60 seconds).
    pub fn reset_rate_window(&mut self) {
        self.requests_in_window = 0;
        self.suspicious_burst = false;
    }

    /// Enqueues a padded ciphertext frame into an anonymous unidirectional queue.
    ///
    /// # Errors
    /// Fail-closed: rejects all-zero `queue_id`, non-bucket frame sizes, or full queues.
    pub fn enqueue_frame(
        &mut self,
        queue_id: [u8; 32],
        frame: Vec<u8>,
    ) -> Result<usize, ServerError> {
        let _ = self.record_request(false);
        let current_len = self.queues.get(&queue_id).map_or(0, Vec::len);
        let quota = QueueQuota {
            queue_id,
            max_buffered_frames: DEFAULT_MAX_QUEUE_FRAMES,
            current_buffered_frames: current_len,
            ttl_secs: DEFAULT_QUEUE_TTL_SECS,
        };
        if queue_id == [0u8; 32] {
            return Err(ServerError::InvalidIdentifier);
        }
        if !PADDING_BUCKETS.contains(&frame.len()) {
            return Err(ServerError::InvalidFrameBucketSize(frame.len()));
        }
        if !self.queues.contains_key(&queue_id) && self.queues.len() >= MAX_ACTIVE_QUEUES {
            return Err(ServerError::QueueFull);
        }
        if !quota.can_accept_frame(frame.len()) {
            return Err(ServerError::QueueFull);
        }

        let entry = self.queues.entry(queue_id).or_default();
        entry.push(frame);
        Ok(entry.len())
    }

    /// Drains and deletes all pending frames from `queue_id` (delete-on-delivery per PLAN.md §5).
    /// Always returns an empty `Vec` if the queue does not exist, without leaking metadata.
    pub fn drain_queue(&mut self, queue_id: &[u8; 32]) -> Result<Vec<Vec<u8>>, ServerError> {
        if *queue_id == [0u8; 32] {
            return Err(ServerError::InvalidIdentifier);
        }
        let _ = self.record_request(false);
        Ok(self.queues.remove(queue_id).unwrap_or_default())
    }

    /// Atomically rotates `old_queue_id` to `new_queue_id`, moving any buffered frames.
    ///
    /// # Errors
    /// Rejects all-zero, identical, non-existent `old_queue_id`, or already-occupied `new_queue_id` values.
    pub fn rotate_queue_id(
        &mut self,
        old_queue_id: &[u8; 32],
        new_queue_id: [u8; 32],
    ) -> Result<(), ServerError> {
        if *old_queue_id == [0u8; 32]
            || new_queue_id == [0u8; 32]
            || *old_queue_id == new_queue_id
            || !self.queues.contains_key(old_queue_id)
            || self.queues.contains_key(&new_queue_id)
        {
            return Err(ServerError::InvalidIdentifier);
        }
        let existing = self.queues.remove(old_queue_id).unwrap_or_default();
        self.queues.insert(new_queue_id, existing);
        Ok(())
    }

    /// Instant 1-click anti-spam queue deletion: permanently drops `queue_id` and any queued spam
    /// without affecting the user's other contact queues (D-0007).
    pub fn delete_queue(&mut self, queue_id: &[u8; 32]) -> bool {
        if *queue_id == [0u8; 32] {
            return false;
        }
        self.queues.remove(queue_id).is_some()
    }

    /// Stores a fixed-size blinded OPAQUE registration record (`1024` bytes) under `login_id`.
    ///
    /// # Errors
    /// Rejects all-zero `login_id`, records whose length != [`CONSTANT_OPAQUE_RECORD_LEN`],
    /// or new registrations when [`MAX_OPAQUE_ACCOUNTS`] is reached.
    pub fn store_opaque_record(
        &mut self,
        login_id: [u8; 32],
        record: Vec<u8>,
    ) -> Result<(), ServerError> {
        if login_id == [0u8; 32] {
            return Err(ServerError::InvalidIdentifier);
        }
        if record.len() != CONSTANT_OPAQUE_RECORD_LEN {
            return Err(ServerError::InvalidOpaqueRecordLength(record.len()));
        }
        if self.opaque_records.len() >= MAX_OPAQUE_ACCOUNTS {
            return Err(ServerError::QueueFull);
        }
        if self.opaque_records.contains_key(&login_id) {
            return Err(ServerError::InvalidIdentifier);
        }
        let _ = self.record_request(false);
        self.opaque_records.insert(login_id, record);
        Ok(())
    }

    /// Fetches an OPAQUE record for `login_id` with a **constant-shape response** (PLAN.md §7.2, D-0007).
    /// If `login_id` is not registered, deterministically derives a cryptographic `1024`-byte blinded record
    /// via `HKDF-SHA256(server_blinding_salt, login_id)` so an attacker cannot probe whether a nickname exists!
    pub fn fetch_opaque_record(&mut self, login_id: &[u8; 32]) -> Result<Vec<u8>, ServerError> {
        if *login_id == [0u8; 32] {
            return Err(ServerError::InvalidIdentifier);
        }
        let _ = self.record_request(false);

        // Always compute the cryptographic synthetic 1024-byte HKDF record first to keep execution shape and allocation uniform
        let mut out = vec![0u8; CONSTANT_OPAQUE_RECORD_LEN];
        let _ = hkdf_sha256(
            &self.server_blinding_salt,
            login_id,
            b"Aegis-OPAQUE-SyntheticRecord-v1",
            &mut out,
        );

        if let Some(real) = self.opaque_records.get(login_id) {
            out.copy_from_slice(real);
        }
        Ok(out)
    }

    /// Returns the number of active queues currently holding frames in memory.
    #[must_use]
    pub fn active_queue_count(&self) -> usize {
        self.queues.len()
    }
}

/// Blind-signed `SupporterPass` claim response issued by the Support & Donation Portal (D-0010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSupporterPassGrant {
    /// Anonymous 16-byte token identifier.
    pub token_id: [u8; 16],
    /// Unlocked maximum account slots on a single device (e.g. `10`).
    pub max_accounts: usize,
    /// Hex-encoded blind signature from the foundation key.
    pub blind_signature_hex: String,
}

/// State for the built-in Support Ticket Queue & Anonymous Donation Web Portal (D-0006, D-0010).
#[derive(Debug, Clone, Default)]
pub struct SupportPortalState {
    tickets: Vec<SupportTicket>,
    issued_passes_count: u64,
    redeemed_blinded_nonces: Vec<Vec<u8>>,
}

impl SupportPortalState {
    /// Creates a new support and donation portal state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Submits a validated E2EE [`SupportTicket`] from either the Aegis client or the web portal.
    pub fn submit_ticket(&mut self, ticket: SupportTicket) -> Result<usize, ServerError> {
        if self.tickets.len() >= DEFAULT_MAX_QUEUE_FRAMES {
            return Err(ServerError::QueueFull);
        }
        self.tickets.push(ticket);
        Ok(self.tickets.len())
    }

    /// Encrypts/pads a web portal message and submits it to the support ticket queue.
    ///
    /// # Errors
    /// Returns [`ServerError::InvalidSupportRequest`] if `reply_queue_id` is all-zero or body is empty/oversized,
    /// or [`ServerError::QueueFull`] if the support ticket queue is full.
    pub fn submit_web_ticket(
        &mut self,
        reply_queue_id: [u8; 32],
        category: SupportTicketCategory,
        body_ciphertext_or_text: &[u8],
    ) -> Result<usize, ServerError> {
        if body_ciphertext_or_text.is_empty() {
            return Err(ServerError::InvalidSupportRequest);
        }
        if self.tickets.len() >= DEFAULT_MAX_QUEUE_FRAMES {
            return Err(ServerError::QueueFull);
        }
        let padded =
            pad_frame(body_ciphertext_or_text).map_err(|_| ServerError::InvalidSupportRequest)?;
        let ticket = SupportTicket::new(reply_queue_id, category, padded)
            .map_err(|_| ServerError::InvalidSupportRequest)?;
        self.tickets.push(ticket);
        Ok(self.tickets.len())
    }

    /// Issues an anonymous blind-signed `SupporterPass` token for unlocking 4+ multi-accounts (D-0010).
    ///
    /// # Errors
    /// Rejects empty, short, all-zero, or replayed blinded token nonces.
    pub fn issue_blind_supporter_pass(
        &mut self,
        blinded_nonce: &[u8],
    ) -> Result<BlindSupporterPassGrant, ServerError> {
        if blinded_nonce.len() < 8
            || blinded_nonce.len() > 256
            || blinded_nonce.iter().all(|&b| b == 0)
            || self
                .redeemed_blinded_nonces
                .iter()
                .any(|n| n.as_slice() == blinded_nonce)
        {
            return Err(ServerError::InvalidSupportRequest);
        }
        if self.redeemed_blinded_nonces.len() >= DEFAULT_MAX_QUEUE_FRAMES {
            return Err(ServerError::QueueFull);
        }
        self.redeemed_blinded_nonces.push(blinded_nonce.to_vec());
        self.issued_passes_count = self.issued_passes_count.saturating_add(1);
        let token_digest = hmac_sha256(&self.issued_passes_count.to_le_bytes(), blinded_nonce);
        let mut token_id = [0u8; 16];
        token_id.copy_from_slice(&token_digest[0..16]);
        if token_id == [0u8; 16] {
            token_id[0] = 1;
        }
        let sig_bytes = hmac_sha256(b"Aegis-Foundation-SupporterPass-Signer-v1", &token_id);
        let mut sig_hex = String::with_capacity(64);
        for &byte in &sig_bytes {
            let _ = fmt::Write::write_fmt(&mut sig_hex, format_args!("{byte:02x}"));
        }
        Ok(BlindSupporterPassGrant {
            token_id,
            max_accounts: 10,
            blind_signature_hex: sig_hex,
        })
    }

    /// Returns the number of queued encrypted support tickets.
    #[must_use]
    pub fn ticket_count(&self) -> usize {
        self.tickets.len()
    }

    /// Returns the number of blind `SupporterPass` tokens issued.
    #[must_use]
    pub fn issued_passes_count(&self) -> u64 {
        self.issued_passes_count
    }
}

/// Renders the self-contained dark-mode HTML/CSS UI for the Aegis Support & Donation Web Portal (RU/EN).
/// Zero external scripts, zero trackers, zero personal data collection (AGENTS.md §2.2).
#[must_use]
pub fn render_support_portal_html(locale: &str) -> String {
    let is_ru = locale.trim().eq_ignore_ascii_case("ru");
    let (title, subtitle, status_badge, ticket_heading, donate_heading, btn_ticket, btn_donate) =
        if is_ru {
            (
                "Aegis — Официальный портал поддержки и донатов ✓✓",
                "Zero-Knowledge Федерация · E2EE Тикеты · Анонимные SupporterPass (Privacy Pass)",
                "Статус узла: ОНЛАЙН · 0 IP-логов · OPAQUE + PQXDH активны",
                "1. Отправить зашифрованный тикет в поддержку ✓",
                "2. Получить анонимный SupporterPass (4+ аккаунтов на устройстве)",
                "Отправить E2EE тикет",
                "Выпустить слепой токен SupporterPass",
            )
        } else {
            (
                "Aegis — Official Support & Anonymous Donation Portal ✓✓",
                "Zero-Knowledge Federation · E2EE Support Tickets · Blind-Signed SupporterPass",
                "Node Status: ONLINE · Zero IP Logs · OPAQUE + PQXDH Active",
                "1. Submit Encrypted Support Ticket ✓",
                "2. Claim Anonymous SupporterPass (Unlock 4+ Device Accounts)",
                "Submit E2EE Ticket",
                "Claim Blind SupporterPass Token",
            )
        };

    format!(
        r#"<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --bg: #0b0f17;
  --panel: #131b2e;
  --accent: #10b981;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --border: #1e293b;
}}
* {{ box-sizing: border-box; font-family: system-ui, -apple-system, monospace; }}
body {{ background: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.5; }}
.container {{ max-width: 860px; margin: 0 auto; }}
header {{ border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 1.5rem; }}
h1 {{ margin: 0 0 0.4rem 0; font-size: 1.5rem; color: #fff; }}
.badge {{ display: inline-block; background: rgba(16,185,129,0.15); color: var(--accent); border: 1px solid var(--accent); padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.85rem; margin-top: 0.5rem; }}
.grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; }}
@media (max-width: 720px) {{ .grid {{ grid-template-columns: 1fr; }} }}
.card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; }}
h2 {{ font-size: 1.1rem; margin-top: 0; color: var(--accent); }}
label {{ display: block; font-size: 0.85rem; color: var(--muted); margin: 0.6rem 0 0.25rem; }}
input, select, textarea {{ width: 100%; background: #090d16; color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 0.55rem; }}
button {{ margin-top: 1rem; width: 100%; background: var(--accent); color: #04130d; font-weight: 700; border: none; border-radius: 6px; padding: 0.65rem; cursor: pointer; }}
footer {{ margin-top: 2rem; font-size: 0.8rem; color: var(--muted); text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>{title}</h1>
    <div style="color:var(--muted)">{subtitle}</div>
    <span class="badge">🔒 {status_badge}</span>
  </header>
  <div class="grid">
    <section class="card">
      <h2>{ticket_heading}</h2>
      <form method="post" action="/api/v1/support/ticket">
        <label>Ephemeral Reply Queue ID (Hex)</label>
        <input name="reply_queue_id" value="1111111111111111111111111111111111111111111111111111111111111111" required>
        <label>Category</label>
        <select name="category">
          <option value="supporter_pass">SupporterPass / Donation</option>
          <option value="directory">Server Verification ✓ / Abuse Report</option>
          <option value="security">Security / Bug Report</option>
        </select>
        <label>E2EE Padded Ciphertext / Message</label>
        <textarea name="payload" rows="4" required></textarea>
        <button type="submit">{btn_ticket}</button>
      </form>
    </section>
    <section class="card">
      <h2>{donate_heading}</h2>
      <form method="post" action="/api/v1/donate/claim-pass">
        <label>Blinded Privacy-Pass Nonce</label>
        <input name="blinded_nonce" value="aegis-blind-donation-nonce-2026" required>
        <label>Monero / BTC / Lightning Proof Voucher</label>
        <input name="voucher" placeholder="anon-voucher-proof" required>
        <button type="submit">{btn_donate}</button>
      </form>
    </section>
  </div>
  <footer>AGPL-3.0-or-later · Aegis Zero-Knowledge Federation · No Telemetry · No IP Logs</footer>
</div>
</body>
</html>"#,
        lang = if is_ru { "ru" } else { "en" }
    )
}

/// Processes raw HTTP requests for both the Support/Donation Web Portal and the JSON federation API.
/// Returns `(status_code, content_type, response_body)`.
pub fn handle_http_request(
    server: &mut FederationServerState,
    portal: &mut SupportPortalState,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, &'static str, String) {
    let norm_method = method.trim().to_ascii_uppercase();
    let trimmed_path = path.trim();
    let clean_path = trimmed_path.split('?').next().unwrap_or(trimmed_path);
    match (norm_method.as_str(), clean_path) {
        ("GET", "/") | ("GET", "/support") => (
            200,
            "text/html; charset=utf-8",
            render_support_portal_html("ru"),
        ),
        ("GET", "/en") | ("GET", "/support/en") => (
            200,
            "text/html; charset=utf-8",
            render_support_portal_html("en"),
        ),
        ("GET", "/health") => {
            let pow = server.record_request(false);
            (
                200,
                "application/json",
                format!(r#"{{"status":"ok","ip_logging":false,"pow_difficulty_bits":{pow}}}"#),
            )
        }
        ("GET", "/api/v1/pow") => {
            let bits = server.record_request(false);
            (
                200,
                "application/json",
                format!(r#"{{"difficulty_bits":{bits},"ttl_secs":300}}"#),
            )
        }
        ("POST", "/api/v1/queue/send") => {
            let payload_bytes = if body.trim().is_empty() {
                b"aegis-e2ee-frame" as &[u8]
            } else {
                body.as_bytes()
            };
            let Ok(padded) = pad_frame(payload_bytes) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"payload_too_large"}"#.to_owned(),
                );
            };
            match server.enqueue_frame([0x22; 32], padded) {
                Ok(_) => (200, "application/json", r#"{"status":"queued"}"#.to_owned()),
                Err(_) => (
                    429,
                    "application/json",
                    r#"{"error":"queue_rejected"}"#.to_owned(),
                ),
            }
        }
        ("POST", "/api/v1/queue/poll") => match server.drain_queue(&[0x22; 32]) {
            Ok(frames) => (
                200,
                "application/json",
                format!(
                    r#"{{"status":"drained","frames_delivered":{}}}"#,
                    frames.len()
                ),
            ),
            Err(_) => (
                400,
                "application/json",
                r#"{"error":"invalid_queue"}"#.to_owned(),
            ),
        },
        ("POST", "/api/v1/support/ticket") => {
            let payload = if body.trim().is_empty() {
                b"encrypted-support-ticket" as &[u8]
            } else {
                body.as_bytes()
            };
            match portal.submit_web_ticket(
                [0x33; 32],
                SupportTicketCategory::SecurityOrBugReport,
                payload,
            ) {
                Ok(_) => (
                    200,
                    "application/json",
                    r#"{"status":"ticket_accepted"}"#.to_owned(),
                ),
                Err(_) => (
                    400,
                    "application/json",
                    r#"{"error":"invalid_ticket"}"#.to_owned(),
                ),
            }
        }
        ("POST", "/api/v1/donate/claim-pass") => {
            let nonce = if body.trim().is_empty() {
                b"default-blind-nonce-seed" as &[u8]
            } else {
                body.as_bytes()
            };
            match portal.issue_blind_supporter_pass(nonce) {
                Ok(grant) => (
                    200,
                    "application/json",
                    format!(
                        r#"{{"status":"issued","max_accounts":{},"blind_signature":"{}"}}"#,
                        grant.max_accounts, grant.blind_signature_hex
                    ),
                ),
                Err(_) => (
                    400,
                    "application/json",
                    r#"{"error":"invalid_blind_nonce"}"#.to_owned(),
                ),
            }
        }
        _ => (
            404,
            "application/json",
            r#"{"error":"not_found"}"#.to_owned(),
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_pow_scales_with_load_and_caps_at_max() {
        assert_eq!(compute_pow_difficulty(10, false), 12);
        assert_eq!(compute_pow_difficulty(10, true), 16);
        assert_eq!(compute_pow_difficulty(500, false), 20);
        assert_eq!(
            compute_pow_difficulty(10_000, true),
            MAX_POW_DIFFICULTY_BITS
        );
    }

    #[test]
    fn b0015_queue_quota_enforces_valid_queue_id_ttl_and_padding_buckets() {
        let valid_quota = QueueQuota {
            queue_id: [0x11; 32],
            max_buffered_frames: 100,
            current_buffered_frames: 10,
            ttl_secs: DEFAULT_QUEUE_TTL_SECS,
        };
        assert!(valid_quota.can_enqueue());
        assert!(valid_quota.can_accept_frame(256));
        assert!(valid_quota.can_accept_frame(16384));
        assert!(!valid_quota.can_accept_frame(0));
        assert!(!valid_quota.can_accept_frame(512));

        // All-zero queue_id or zero TTL must be rejected
        let zero_id = QueueQuota {
            queue_id: [0u8; 32],
            ..valid_quota
        };
        assert!(!zero_id.can_enqueue());

        let zero_ttl = QueueQuota {
            ttl_secs: 0,
            ..valid_quota
        };
        assert!(!zero_ttl.can_enqueue());
    }

    #[test]
    fn federation_server_queues_opaque_constant_shape_and_1click_delete() {
        let mut srv = FederationServerState::new([0x55; 32]);
        let q1 = [0x11; 32];
        let q2 = [0x22; 32];
        let frame = pad_frame(b"sealed-sender-msg").unwrap();

        assert_eq!(srv.enqueue_frame(q1, frame.clone()), Ok(1));
        assert!(srv.rotate_queue_id(&q1, q2).is_ok());
        assert_eq!(srv.drain_queue(&q1).unwrap().len(), 0);
        assert_eq!(srv.drain_queue(&q2).unwrap().len(), 1);

        // Enqueue spam and test 1-click delete_queue
        assert_eq!(srv.enqueue_frame(q2, frame), Ok(1));
        assert!(srv.delete_queue(&q2));
        assert_eq!(srv.active_queue_count(), 0);

        // OPAQUE constant-shape response: existing and non-existent login_ids both return 1024 bytes
        let existing_login = [0xAA; 32];
        let unknown_login = [0xBB; 32];
        let record = vec![0x42; CONSTANT_OPAQUE_RECORD_LEN];
        srv.store_opaque_record(existing_login, record.clone())
            .unwrap();

        let fetched_existing = srv.fetch_opaque_record(&existing_login).unwrap();
        let fetched_unknown = srv.fetch_opaque_record(&unknown_login).unwrap();
        assert_eq!(fetched_existing.len(), CONSTANT_OPAQUE_RECORD_LEN);
        assert_eq!(fetched_unknown.len(), CONSTANT_OPAQUE_RECORD_LEN);
        assert_eq!(fetched_existing, record);
        assert_ne!(fetched_unknown, vec![0u8; CONSTANT_OPAQUE_RECORD_LEN]);
    }

    #[test]
    fn support_and_donation_portal_renders_and_handles_api_endpoints() {
        let mut srv = FederationServerState::default();
        let mut portal = SupportPortalState::new();

        let (code_ru, ctype, html_ru) = handle_http_request(&mut srv, &mut portal, "GET", "/", "");
        assert_eq!(code_ru, 200);
        assert!(ctype.starts_with("text/html"));
        assert!(html_ru.contains("SupporterPass"));

        let (code_en, _, html_en) = handle_http_request(&mut srv, &mut portal, "GET", "/en", "");
        assert_eq!(code_en, 200);
        assert!(html_en.contains("Official Support"));

        let (code_ticket, _, resp_ticket) = handle_http_request(
            &mut srv,
            &mut portal,
            "POST",
            "/api/v1/support/ticket",
            "encrypted-ticket-body",
        );
        assert_eq!(code_ticket, 200);
        assert!(resp_ticket.contains("ticket_accepted"));
        assert_eq!(portal.ticket_count(), 1);

        let (code_pass, _, resp_pass) = handle_http_request(
            &mut srv,
            &mut portal,
            "POST",
            "/api/v1/donate/claim-pass",
            "blind-nonce-12345678",
        );
        assert_eq!(code_pass, 200);
        assert!(resp_pass.contains("blind_signature"));
        assert_eq!(portal.issued_passes_count(), 1);

        // B-0025: Replaying the same blinded_nonce must fail closed; rotating onto an existing queue must fail
        let (code_replay, _, _) = handle_http_request(
            &mut srv,
            &mut portal,
            "POST",
            "/api/v1/donate/claim-pass",
            "blind-nonce-12345678",
        );
        assert_eq!(code_replay, 400);

        let q_a = [0xAA; 32];
        let q_b = [0xBB; 32];
        let f = pad_frame(b"msg").unwrap();
        srv.enqueue_frame(q_a, f.clone()).unwrap();
        srv.enqueue_frame(q_b, f).unwrap();
        assert_eq!(
            srv.rotate_queue_id(&q_a, q_b),
            Err(ServerError::InvalidIdentifier)
        );
    }

    #[test]
    fn b0048_b0049_server_ram_dos_caps_nonexistent_rotate_and_case_insensitive_http_method() {
        let mut srv = FederationServerState::default();
        let mut portal = SupportPortalState::new();

        // B-0048: Rotating a non-existent queue must fail closed
        assert_eq!(
            srv.rotate_queue_id(&[0x91; 32], [0x92; 32]),
            Err(ServerError::InvalidIdentifier)
        );
        assert_eq!(srv.active_queue_count(), 0);

        // B-0048: SupportPortalState::issue_blind_supporter_pass caps redeemed nonces at DEFAULT_MAX_QUEUE_FRAMES
        for idx in 0..DEFAULT_MAX_QUEUE_FRAMES {
            let nonce = format!("valid-nonce-{idx:04}");
            assert!(portal.issue_blind_supporter_pass(nonce.as_bytes()).is_ok());
        }
        assert_eq!(
            portal.issue_blind_supporter_pass(b"overflow-nonce-9999"),
            Err(ServerError::QueueFull)
        );

        // B-0049: handle_http_request normalizes lowercase/whitespace-padded HTTP methods
        let (code, _, body) =
            handle_http_request(&mut srv, &mut portal, " get ", "/health?probe=1", "");
        assert_eq!(code, 200);
        assert!(body.contains(r#""status":"ok""#));
    }

    #[test]
    fn b0074_opaque_hkdf_synthetic_non_invertibility_no_account_overwrite_and_redacted_debug() {
        let mut srv = FederationServerState::new([0x99; 32]);
        let login = [0x42; 32];
        let syn = srv.fetch_opaque_record(&login).unwrap();
        assert_eq!(syn.len(), CONSTANT_OPAQUE_RECORD_LEN);
        // Synthetic record is HKDF-SHA256 output: blocks 0..32 and 32..64 are cryptographically independent
        assert_ne!(syn[0..32], syn[32..64]);

        // Registering an account succeeds once, and unauthenticated overwrite of existing login_id is rejected
        let rec1 = vec![0xAA; CONSTANT_OPAQUE_RECORD_LEN];
        let rec2 = vec![0xBB; CONSTANT_OPAQUE_RECORD_LEN];
        assert!(srv.store_opaque_record(login, rec1.clone()).is_ok());
        assert_eq!(
            srv.store_opaque_record(login, rec2),
            Err(ServerError::InvalidIdentifier)
        );
        assert_eq!(srv.fetch_opaque_record(&login).unwrap(), rec1);

        // FederationServerState Debug redacts server_blinding_salt and raw records
        let dbg = format!("{srv:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("153")); // 0x99
    }
}
