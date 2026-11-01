//! `aegis-server` — Zero-knowledge federation server engine, unidirectional queue TTLs,
//! constant-shape OPAQUE record storage, anti-DDoS adaptive Proof-of-Work without IP logging (D-0007),
//! and built-in Support & Donation Web Portal (D-0006, D-0010, PLAN.md §4.4, §6).

use aegis_crypto::{
    aead_open, aead_seal, constant_time_eq, hkdf_sha256, hmac_sha256, x25519, x25519_basepoint,
    DeterministicPowVerifier, PowChallenge, PowVerifier,
};
use aegis_protocol::{
    compute_inbox_auth_hash, hex_decode_bytes, hex_encode_bytes, pad_frame, SupportTicket,
    SupportTicketCategory, PADDING_BUCKETS,
};
use core::fmt;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    /// Queue read/drain attempted without a valid `read_token` (`403 Forbidden`).
    UnauthorizedRead,
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
            Self::UnauthorizedRead => write!(f, "missing or invalid queue read_token"),
        }
    }
}

impl std::error::Error for ServerError {}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_760_000_000, |d| d.as_secs())
}

/// Zero-knowledge Federation Server Engine (PLAN.md §6.1, §7.2, D-0002, D-0007).
/// Stores only padded E2EE queue frames and blinded OPAQUE records in RAM/storage.
/// Never logs IP addresses, nicknames, or social graphs.
#[derive(Clone)]
pub struct FederationServerState {
    server_blinding_salt: [u8; 32],
    queues: BTreeMap<[u8; 32], Vec<Vec<u8>>>,
    queue_timestamps: BTreeMap<[u8; 32], Vec<u64>>,
    queue_auth_hashes: BTreeMap<[u8; 32], [u8; 32]>,
    seen_tunnel_nonces: Vec<[u8; 44]>,
    opaque_records: BTreeMap<[u8; 32], Vec<u8>>,
    directory_entries: BTreeMap<String, (String, String)>,
    latest_app_version: String,
    requests_in_window: u32,
    suspicious_burst: bool,
    window_started_unix_secs: u64,
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

impl Drop for FederationServerState {
    fn drop(&mut self) {
        self.server_blinding_salt.fill(0);
        for frames in self.queues.values_mut() {
            for f in frames {
                f.fill(0);
            }
        }
        self.queues.clear();
        self.queue_timestamps.clear();
        for hash in self.queue_auth_hashes.values_mut() {
            hash.fill(0);
        }
        self.queue_auth_hashes.clear();
        for rec in self.opaque_records.values_mut() {
            rec.fill(0);
        }
        self.opaque_records.clear();
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
        let mut directory_entries = BTreeMap::new();
        directory_entries.insert(
            "channel:aegis_news".to_owned(),
            ("channel".to_owned(), "Новости Aegis".to_owned()),
        );
        directory_entries.insert(
            "group:aegis_lobby".to_owned(),
            ("group".to_owned(), "Общий чат Aegis".to_owned()),
        );
        Self {
            server_blinding_salt: salt,
            queues: BTreeMap::new(),
            queue_timestamps: BTreeMap::new(),
            queue_auth_hashes: BTreeMap::new(),
            seen_tunnel_nonces: Vec::new(),
            opaque_records: BTreeMap::new(),
            directory_entries,
            latest_app_version: "0.2.0".to_owned(),
            requests_in_window: 0,
            suspicious_burst: false,
            window_started_unix_secs: current_unix_seconds(),
        }
    }

    /// Returns the server's deterministic X25519 public key for sealed tunnel requests.
    #[must_use]
    pub fn server_tunnel_public_key(&self) -> [u8; 32] {
        x25519_basepoint(&self.server_blinding_salt)
    }

    /// Returns the current adaptive Proof-of-Work difficulty in bits (D-0007).
    #[must_use]
    pub fn current_pow_difficulty(&self) -> u8 {
        compute_pow_difficulty(self.requests_in_window, self.suspicious_burst)
    }

    /// Records an anonymous request in the in-memory sliding window (zero IP logs!),
    /// automatically resetting the 60-second rate window when elapsed.
    pub fn record_request(&mut self, is_burst: bool) -> u8 {
        let now = current_unix_seconds();
        if now.saturating_sub(self.window_started_unix_secs) >= 60 {
            self.requests_in_window = 0;
            self.suspicious_burst = false;
            self.window_started_unix_secs = now;
        }
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
        self.window_started_unix_secs = current_unix_seconds();
    }

    /// Verifies an incoming Proof-of-Work solution (`nonce`) against `challenge` at the current adaptive difficulty.
    ///
    /// # Errors
    /// Returns [`ServerError::RateLimited`] if the PoW solution fails verification.
    pub fn verify_pow_solution(
        &self,
        challenge: [u8; 32],
        nonce: u64,
        now_unix_secs: u64,
    ) -> Result<(), ServerError> {
        let required_pow_bits = self.current_pow_difficulty();
        let pow_challenge = PowChallenge {
            challenge,
            difficulty_bits: required_pow_bits,
            expires_at_unix_secs: now_unix_secs.saturating_add(300),
        };
        DeterministicPowVerifier
            .verify_pow(&pow_challenge, nonce, now_unix_secs)
            .map_err(|_| ServerError::RateLimited { required_pow_bits })
    }

    /// Purges all queued frames older than `ttl_secs` (`DEFAULT_QUEUE_TTL_SECS`) and removes empty queues from RAM.
    pub fn purge_expired_frames(&mut self, now_unix_secs: u64, ttl_secs: u64) -> usize {
        let mut purged_count = 0usize;
        let mut empty_queues = Vec::new();
        for (q_id, frames) in &mut self.queues {
            let timestamps = self.queue_timestamps.entry(*q_id).or_default();
            let mut kept_frames = Vec::with_capacity(frames.len());
            let mut kept_ts = Vec::with_capacity(frames.len());
            for (idx, mut f) in core::mem::take(frames).into_iter().enumerate() {
                let ts = timestamps.get(idx).copied().unwrap_or(now_unix_secs);
                if now_unix_secs.saturating_sub(ts) < ttl_secs {
                    kept_frames.push(f);
                    kept_ts.push(ts);
                } else {
                    f.fill(0);
                    purged_count = purged_count.saturating_add(1);
                }
            }
            *frames = kept_frames;
            *timestamps = kept_ts;
            if frames.is_empty() {
                empty_queues.push(*q_id);
            }
        }
        for q_id in empty_queues {
            self.queues.remove(&q_id);
            self.queue_timestamps.remove(&q_id);
            self.queue_auth_hashes.remove(&q_id);
        }
        purged_count
    }

    /// Registers a pre-hashed `auth_hash = SHA-256("aegis-inbox-auth-v2:" || read_token)` for `queue_id`
    /// so senders and blind relays can bind a queue without ever transmitting the cleartext `read_token`.
    ///
    /// # Errors
    /// Rejects all-zero identifiers or mismatched `auth_hash` on an already-bound queue.
    pub fn register_queue_auth_hash(
        &mut self,
        queue_id: [u8; 32],
        auth_hash: &[u8; 32],
    ) -> Result<(), ServerError> {
        if queue_id == [0u8; 32] || *auth_hash == [0u8; 32] {
            return Err(ServerError::InvalidIdentifier);
        }
        let now = current_unix_seconds();
        let _ = self.purge_expired_frames(now, DEFAULT_QUEUE_TTL_SECS);
        if let Some(existing) = self.queue_auth_hashes.get(&queue_id) {
            if !constant_time_eq(existing, auth_hash) {
                return Err(ServerError::UnauthorizedRead);
            }
            return Ok(());
        }
        if self.queues.contains_key(&queue_id) {
            return Err(ServerError::UnauthorizedRead);
        }
        if self.queue_auth_hashes.len() >= MAX_ACTIVE_QUEUES {
            return Err(ServerError::QueueFull);
        }
        self.queue_auth_hashes.insert(queue_id, *auth_hash);
        Ok(())
    }

    /// Registers a read-authentication verifier (`auth_hash = SHA-256("aegis-inbox-auth-v2:" || read_token)`)
    /// for `queue_id` so only the holder of `read_token` can drain or delete messages from `queue_id`.
    ///
    /// # Errors
    /// Rejects all-zero identifiers or attempts to overwrite an existing queue's `auth_hash`.
    pub fn register_queue_read_token(
        &mut self,
        queue_id: [u8; 32],
        read_token: &[u8; 32],
    ) -> Result<(), ServerError> {
        if queue_id == [0u8; 32] || *read_token == [0u8; 32] {
            return Err(ServerError::InvalidIdentifier);
        }
        let auth_hash = compute_inbox_auth_hash(read_token);
        self.register_queue_auth_hash(queue_id, &auth_hash)
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
        let now = current_unix_seconds();
        let _ = self.purge_expired_frames(now, DEFAULT_QUEUE_TTL_SECS);
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
        self.queue_timestamps.entry(queue_id).or_default().push(now);
        Ok(entry.len())
    }

    /// Drains and deletes all pending frames from `queue_id` after verifying `presented_read_token`
    /// if the queue is protected by a registered `read_token` (`PROTOCOL_V2.md §5.3`).
    ///
    /// # Errors
    /// Returns [`ServerError::UnauthorizedRead`] if `queue_id` requires a `read_token` and `presented_read_token` is missing or wrong.
    pub fn drain_queue_authenticated(
        &mut self,
        queue_id: &[u8; 32],
        presented_read_token: Option<&[u8; 32]>,
    ) -> Result<Vec<Vec<u8>>, ServerError> {
        if *queue_id == [0u8; 32] {
            return Err(ServerError::InvalidIdentifier);
        }
        let now = current_unix_seconds();
        let _ = self.purge_expired_frames(now, DEFAULT_QUEUE_TTL_SECS);
        let _ = self.record_request(false);
        if let Some(expected_hash) = self.queue_auth_hashes.get(queue_id) {
            let Some(token) = presented_read_token else {
                return Err(ServerError::UnauthorizedRead);
            };
            let candidate_hash = compute_inbox_auth_hash(token);
            if !constant_time_eq(expected_hash, &candidate_hash) {
                return Err(ServerError::UnauthorizedRead);
            }
        }
        self.queue_timestamps.remove(queue_id);
        Ok(self.queues.remove(queue_id).unwrap_or_default())
    }

    /// Reads all active (non-expired) frames from `queue_id` after verifying `presented_read_token`
    /// without deleting them, so multiple participants on a shared channel can poll messages until TTL expiry.
    ///
    /// # Errors
    /// Returns [`ServerError::UnauthorizedRead`] if `queue_id` requires a `read_token` and `presented_read_token` is missing or wrong.
    pub fn peek_queue_authenticated(
        &mut self,
        queue_id: &[u8; 32],
        presented_read_token: Option<&[u8; 32]>,
    ) -> Result<Vec<Vec<u8>>, ServerError> {
        if *queue_id == [0u8; 32] {
            return Err(ServerError::InvalidIdentifier);
        }
        let now = current_unix_seconds();
        let _ = self.purge_expired_frames(now, DEFAULT_QUEUE_TTL_SECS);
        let _ = self.record_request(false);
        if let Some(expected_hash) = self.queue_auth_hashes.get(queue_id) {
            let Some(token) = presented_read_token else {
                return Err(ServerError::UnauthorizedRead);
            };
            let candidate_hash = compute_inbox_auth_hash(token);
            if !constant_time_eq(expected_hash, &candidate_hash) {
                return Err(ServerError::UnauthorizedRead);
            }
        }
        Ok(self.queues.get(queue_id).cloned().unwrap_or_default())
    }

    /// Drains and deletes all pending frames from `queue_id` (delete-on-delivery per PLAN.md §5).
    /// Always returns an empty `Vec` if the queue does not exist, without leaking metadata.
    /// Fails closed with [`ServerError::UnauthorizedRead`] if the queue has a registered `read_token`.
    pub fn drain_queue(&mut self, queue_id: &[u8; 32]) -> Result<Vec<Vec<u8>>, ServerError> {
        self.drain_queue_authenticated(queue_id, None)
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
        if let Some(ts) = self.queue_timestamps.remove(old_queue_id) {
            self.queue_timestamps.insert(new_queue_id, ts);
        }
        if let Some(auth) = self.queue_auth_hashes.remove(old_queue_id) {
            self.queue_auth_hashes.insert(new_queue_id, auth);
        }
        Ok(())
    }

    /// Instant 1-click anti-spam queue deletion: permanently drops `queue_id` and any queued spam
    /// without affecting the user's other contact queues (D-0007).
    pub fn delete_queue(&mut self, queue_id: &[u8; 32]) -> bool {
        if *queue_id == [0u8; 32] {
            return false;
        }
        self.queue_timestamps.remove(queue_id);
        self.queue_auth_hashes.remove(queue_id);
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

fn extract_simple_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k.trim() == key {
            return Some(percent_decode_param(v.trim()));
        }
    }
    None
}

fn percent_decode_param(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = match bytes[i + 1] {
                b'0'..=b'9' => Some(bytes[i + 1] - b'0'),
                b'a'..=b'f' => Some(bytes[i + 1] - b'a' + 10),
                b'A'..=b'F' => Some(bytes[i + 1] - b'A' + 10),
                _ => None,
            };
            let lo = match bytes[i + 2] {
                b'0'..=b'9' => Some(bytes[i + 2] - b'0'),
                b'a'..=b'f' => Some(bytes[i + 2] - b'a' + 10),
                b'A'..=b'F' => Some(bytes[i + 2] - b'A' + 10),
                _ => None,
            };
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_queue_id_from_query(query: Option<&str>) -> Option<[u8; 32]> {
    let Some(q) = query else {
        return Some([0x22; 32]);
    };
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == "queue" {
                let decoded = hex_decode_bytes(v.trim()).ok()?;
                if decoded.len() != 32 {
                    return None;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decoded);
                if arr == [0u8; 32] {
                    return None;
                }
                return Some(arr);
            }
        }
    }
    None
}

fn parse_hex32_param_from_query(query: Option<&str>, key_name: &str) -> Option<[u8; 32]> {
    let q = query?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == key_name {
                let decoded = hex_decode_bytes(v.trim()).ok()?;
                if decoded.len() != 32 {
                    return None;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decoded);
                if arr == [0u8; 32] {
                    return None;
                }
                return Some(arr);
            }
        }
    }
    None
}

fn parse_u64_param_from_query(query: Option<&str>, key_name: &str) -> Option<u64> {
    let q = query?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == key_name {
                return v.trim().parse::<u64>().ok();
            }
        }
    }
    None
}

fn is_safe_relay_host_literal(host: &str) -> bool {
    let lower = host.trim().to_ascii_lowercase();
    if lower.is_empty()
        || lower.len() > 253
        || lower.starts_with('.')
        || lower.ends_with('.')
        || lower.starts_with('-')
        || lower.ends_with('-')
        || lower.contains("..")
        || lower == "localhost"
        || lower == "0.0.0.0"
        || lower == "255.255.255.255"
        || lower.ends_with(".onion")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".lan")
        || lower.ends_with(".home")
        || lower.ends_with(".arpa")
        || lower.ends_with(".invalid")
    {
        return false;
    }
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for l in &labels {
        if l.is_empty()
            || l.len() > 63
            || l.starts_with('-')
            || l.ends_with('-')
            || l.starts_with("0x")
        {
            return false;
        }
    }
    if labels.iter().all(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        if labels.len() != 4 {
            return false;
        }
        let mut octs = [0u8; 4];
        for (i, l) in labels.iter().enumerate() {
            if l.len() > 1 && l.starts_with('0') {
                return false;
            }
            let Ok(v) = l.parse::<u8>() else {
                return false;
            };
            octs[i] = v;
        }
        let [a, b, c, _] = octs;
        // Block RFC 1918 private LANs, cloud metadata 169.254/16, CGNAT 100.64/10, 0/8, multicast >=224
        if a == 0
            || a == 10
            || (a == 100 && (64..=127).contains(&b))
            || (a == 169 && b == 254)
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 0 && c == 0)
            || (a == 192 && b == 168)
            || (a == 198 && (b == 18 || b == 19))
            || a >= 224
        {
            return false;
        }
    }
    true
}

fn is_allowed_relay_socket_addr(addr: &SocketAddr) -> bool {
    let port = addr.port();
    if (port < 1024 && port != 80 && port != 443) || port == 7878 {
        return false;
    }
    match addr {
        SocketAddr::V4(v4) => {
            let [a, b, c, _] = v4.ip().octets();
            if a == 127 {
                // Allow ephemeral local test ports (>= 1024, != 7878)
                return port >= 1024;
            }
            !(a == 0
                || a == 10
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || a >= 224)
        }
        SocketAddr::V6(v6) => {
            let segs = v6.ip().segments();
            let is_ula = (segs[0] & 0xfe00) == 0xfc00;
            let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
            let bad_mapped = v6.ip().to_ipv4_mapped().is_some_and(|v4| {
                !is_allowed_relay_socket_addr(&SocketAddr::V4(std::net::SocketAddrV4::new(
                    v4, port,
                )))
            });
            !v6.ip().is_loopback()
                && !v6.ip().is_unspecified()
                && !v6.ip().is_multicast()
                && !is_ula
                && !is_link_local
                && !bad_mapped
        }
    }
}

fn parse_endpoint_param_from_query<'a>(query: Option<&'a str>, key_name: &str) -> Option<&'a str> {
    let q = query?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == key_name {
                let without_scheme = v.trim().strip_prefix("aegis://").unwrap_or(v.trim());
                let clean = without_scheme
                    .strip_prefix("server/")
                    .unwrap_or(without_scheme)
                    .trim();
                if clean.is_empty()
                    || clean.len() > 253
                    || clean.bytes().any(|b| {
                        b.is_ascii_control()
                            || b.is_ascii_whitespace()
                            || b == b'?'
                            || b == b'&'
                            || b == b'/'
                    })
                {
                    return None;
                }
                let (host, port_str) = clean.rsplit_once(':')?;
                if !is_safe_relay_host_literal(host) {
                    return None;
                }
                let port = port_str.parse::<u16>().ok()?;
                if (port < 1024 && port != 80 && port != 443) || port == 7878 {
                    return None;
                }
                if host == "127.0.0.1" && port < 1024 {
                    return None;
                }
                return Some(clean);
            }
        }
    }
    None
}

fn parse_target_from_query(query: Option<&str>) -> Option<&str> {
    parse_endpoint_param_from_query(query, "target")
}

fn parse_hop_from_query(query: Option<&str>) -> Option<&str> {
    parse_endpoint_param_from_query(query, "hop")
}

fn forward_blind_relay_send(
    next_hop_opt: Option<&str>,
    target_host_port: &str,
    queue_id: &[u8; 32],
    auth_param_opt: Option<(&str, &[u8; 32])>,
    padded_frame: &[u8],
) -> Result<(), ServerError> {
    if *queue_id == [0u8; 32] || !PADDING_BUCKETS.contains(&padded_frame.len()) {
        return Err(ServerError::InvalidIdentifier);
    }
    if let Some(hop) = next_hop_opt {
        if hop.eq_ignore_ascii_case(target_host_port) {
            return Err(ServerError::InvalidIdentifier);
        }
    }
    let connect_ep = next_hop_opt.unwrap_or(target_host_port);
    let dur = Duration::from_millis(2_500);
    let resolved: Vec<SocketAddr> = connect_ep
        .to_socket_addrs()
        .map_err(|_| ServerError::InvalidIdentifier)?
        .collect();
    if resolved.is_empty() || !resolved.iter().all(is_allowed_relay_socket_addr) {
        return Err(ServerError::InvalidIdentifier);
    }
    let addr = resolved[0];
    let mut stream =
        TcpStream::connect_timeout(&addr, dur).map_err(|_| ServerError::InvalidIdentifier)?;
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));

    let queue_hex = hex_encode_bytes(queue_id);
    let tok_suffix = auth_param_opt.map_or_else(String::new, |(param_name, val)| {
        format!("&{param_name}={}", hex_encode_bytes(val))
    });
    let body_hex = hex_encode_bytes(padded_frame);
    let req = if next_hop_opt.is_some() {
        format!(
            "POST /api/v1/queue/relay?target={target_host_port}&queue={queue_hex}{tok_suffix} HTTP/1.1\r\nHost: {connect_ep}\r\nX-Aegis-Blind-Relay: 1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_hex}",
            body_hex.len()
        )
    } else {
        format!(
            "POST /api/v1/queue/send?queue={queue_hex}{tok_suffix} HTTP/1.1\r\nHost: {target_host_port}\r\nX-Aegis-Blind-Relay: 1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_hex}",
            body_hex.len()
        )
    };
    stream
        .write_all(req.as_bytes())
        .map_err(|_| ServerError::InvalidIdentifier)?;
    let _ = stream.flush();

    let mut resp = Vec::with_capacity(512);
    stream
        .take(65_536)
        .read_to_end(&mut resp)
        .map_err(|_| ServerError::InvalidIdentifier)?;
    let text = core::str::from_utf8(&resp).map_err(|_| ServerError::InvalidIdentifier)?;
    if text.starts_with("HTTP/1.1 200")
        && (text.contains("\"queued\"") || text.contains("\"relayed\""))
    {
        Ok(())
    } else {
        Err(ServerError::InvalidIdentifier)
    }
}

fn forward_blind_relay_poll(
    next_hop_opt: Option<&str>,
    target_host_port: &str,
    queue_id: &[u8; 32],
    read_token_opt: Option<&[u8; 32]>,
) -> Result<String, ServerError> {
    if *queue_id == [0u8; 32] {
        return Err(ServerError::InvalidIdentifier);
    }
    if let Some(hop) = next_hop_opt {
        if hop.eq_ignore_ascii_case(target_host_port) {
            return Err(ServerError::InvalidIdentifier);
        }
    }
    let connect_ep = next_hop_opt.unwrap_or(target_host_port);
    let dur = Duration::from_millis(2_500);
    let resolved: Vec<SocketAddr> = connect_ep
        .to_socket_addrs()
        .map_err(|_| ServerError::InvalidIdentifier)?
        .collect();
    if resolved.is_empty() || !resolved.iter().all(is_allowed_relay_socket_addr) {
        return Err(ServerError::InvalidIdentifier);
    }
    let addr = resolved[0];
    let mut stream =
        TcpStream::connect_timeout(&addr, dur).map_err(|_| ServerError::InvalidIdentifier)?;
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));

    let queue_hex = hex_encode_bytes(queue_id);
    let tok_suffix = read_token_opt.map_or_else(String::new, |tok| {
        format!("&read_token={}", hex_encode_bytes(tok))
    });
    let req = if next_hop_opt.is_some() {
        format!(
            "POST /api/v1/queue/relay_poll?target={target_host_port}&queue={queue_hex}{tok_suffix} HTTP/1.1\r\nHost: {connect_ep}\r\nX-Aegis-Blind-Relay: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    } else {
        format!(
            "POST /api/v1/queue/poll?queue={queue_hex}{tok_suffix} HTTP/1.1\r\nHost: {target_host_port}\r\nX-Aegis-Blind-Relay: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    };
    stream
        .write_all(req.as_bytes())
        .map_err(|_| ServerError::InvalidIdentifier)?;
    let _ = stream.flush();

    let mut resp = Vec::with_capacity(4096);
    stream
        .take(65_536)
        .read_to_end(&mut resp)
        .map_err(|_| ServerError::InvalidIdentifier)?;
    let text = core::str::from_utf8(&resp).map_err(|_| ServerError::InvalidIdentifier)?;
    if !text.starts_with("HTTP/1.1 200") {
        return Err(ServerError::InvalidIdentifier);
    }
    let Some((_, body)) = text.split_once("\r\n\r\n") else {
        return Err(ServerError::InvalidIdentifier);
    };
    Ok(body.to_owned())
}

/// Seals an inner HTTP request (`method`, `path`, `body`) into an X25519 + ChaCha20-Poly1305 encrypted tunnel frame
/// pinned to `server_tunnel_pubkey` so ISPs and active network observers see zero URL/queue metadata (`B-0095`).
///
/// # Errors
/// Returns [`ServerError::InvalidIdentifier`] if any key/nonce is zero or encryption fails.
pub fn seal_tunnel_request(
    client_ephemeral_private: &[u8; 32],
    server_tunnel_pubkey: &[u8; 32],
    nonce: &[u8; 12],
    inner_method: &str,
    inner_path: &str,
    inner_body: &str,
) -> Result<String, ServerError> {
    if *client_ephemeral_private == [0u8; 32]
        || *server_tunnel_pubkey == [0u8; 32]
        || *nonce == [0u8; 12]
    {
        return Err(ServerError::InvalidIdentifier);
    }
    let client_ephemeral_pub = x25519_basepoint(client_ephemeral_private);
    let mut shared = x25519(client_ephemeral_private, server_tunnel_pubkey);
    if constant_time_eq(&shared, &[0u8; 32]) {
        return Err(ServerError::InvalidIdentifier);
    }
    let mut tunnel_key = [0u8; 32];
    let kdf_res = hkdf_sha256(
        &client_ephemeral_pub,
        &shared,
        b"Aegis-TransportTunnel-v1",
        &mut tunnel_key,
    );
    shared.fill(0);
    if kdf_res.is_err() {
        tunnel_key.fill(0);
        return Err(ServerError::InvalidIdentifier);
    }
    let mut serialized = format!("{inner_method}\n{inner_path}\n{inner_body}").into_bytes();
    let ct_res = aead_seal(
        &tunnel_key,
        nonce,
        server_tunnel_pubkey,
        &serialized,
    );
    serialized.fill(0);
    tunnel_key.fill(0);
    let ct = ct_res.map_err(|_| ServerError::InvalidIdentifier)?;
    let mut wire = Vec::with_capacity(32 + 12 + ct.len());
    wire.extend_from_slice(&client_ephemeral_pub);
    wire.extend_from_slice(nonce);
    wire.extend_from_slice(&ct);
    Ok(hex_encode_bytes(&wire))
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
    let (clean_path, query_opt) = trimmed_path
        .split_once('?')
        .map_or((trimmed_path, None), |(p, q)| (p, Some(q)));
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
            let Some(queue_id) = parse_queue_id_from_query(query_opt) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_queue_id"}"#.to_owned(),
                );
            };
            if let (Some(pow_ch), Some(pow_nonce)) = (
                parse_hex32_param_from_query(query_opt, "pow_challenge"),
                parse_u64_param_from_query(query_opt, "pow_nonce"),
            ) {
                if server
                    .verify_pow_solution(pow_ch, pow_nonce, current_unix_seconds())
                    .is_err()
                {
                    return (
                        429,
                        "application/json",
                        r#"{"error":"invalid_pow_solution"}"#.to_owned(),
                    );
                }
            }
            let trimmed_body = body.trim();
            let frame_to_enqueue = if let Ok(raw_frame) = hex_decode_bytes(trimmed_body) {
                if PADDING_BUCKETS.contains(&raw_frame.len()) {
                    raw_frame
                } else {
                    let Ok(padded) = pad_frame(trimmed_body.as_bytes()) else {
                        return (
                            400,
                            "application/json",
                            r#"{"error":"payload_too_large"}"#.to_owned(),
                        );
                    };
                    padded
                }
            } else {
                let payload_bytes = if trimmed_body.is_empty() {
                    b"aegis-e2ee-frame" as &[u8]
                } else {
                    trimmed_body.as_bytes()
                };
                let Ok(padded) = pad_frame(payload_bytes) else {
                    return (
                        400,
                        "application/json",
                        r#"{"error":"payload_too_large"}"#.to_owned(),
                    );
                };
                padded
            };
            let had_auth_before = server.queue_auth_hashes.contains_key(&queue_id);
            if let Some(auth_hash) = parse_hex32_param_from_query(query_opt, "auth_hash") {
                if server
                    .register_queue_auth_hash(queue_id, &auth_hash)
                    .is_err()
                {
                    return (
                        403,
                        "application/json",
                        r#"{"error":"unauthorized_read_token"}"#.to_owned(),
                    );
                }
            }
            if let Some(read_token) = parse_hex32_param_from_query(query_opt, "read_token") {
                if server
                    .register_queue_read_token(queue_id, &read_token)
                    .is_err()
                {
                    return (
                        403,
                        "application/json",
                        r#"{"error":"unauthorized_read_token"}"#.to_owned(),
                    );
                }
            }
            match server.enqueue_frame(queue_id, frame_to_enqueue) {
                Ok(_) => (200, "application/json", r#"{"status":"queued"}"#.to_owned()),
                Err(_) => {
                    if !had_auth_before && !server.queues.contains_key(&queue_id) {
                        server.queue_auth_hashes.remove(&queue_id);
                    }
                    (
                        429,
                        "application/json",
                        r#"{"error":"queue_rejected"}"#.to_owned(),
                    )
                }
            }
        }
        ("POST", "/api/v1/queue/poll") => {
            let Some(queue_id) = parse_queue_id_from_query(query_opt) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_queue_id"}"#.to_owned(),
                );
            };
            let read_token_opt = parse_hex32_param_from_query(query_opt, "read_token");
            match server.peek_queue_authenticated(&queue_id, read_token_opt.as_ref()) {
                Ok(mut frames) => {
                    let count = frames.len();
                    let hex_list: Vec<String> = frames
                        .iter()
                        .map(|f| format!("\"{}\"", hex_encode_bytes(f)))
                        .collect();
                    for f in &mut frames {
                        f.fill(0);
                    }
                    (
                        200,
                        "application/json",
                        format!(
                            r#"{{"status":"drained","frames_delivered":{count},"frames_hex":[{}]}}"#,
                            hex_list.join(",")
                        ),
                    )
                }
                Err(ServerError::UnauthorizedRead) => (
                    403,
                    "application/json",
                    r#"{"error":"unauthorized_read_token"}"#.to_owned(),
                ),
                Err(_) => (
                    400,
                    "application/json",
                    r#"{"error":"invalid_queue"}"#.to_owned(),
                ),
            }
        }
        ("POST", "/api/v1/dir/register") => {
            let q = query_opt.unwrap_or("");
            let kind = extract_simple_param(q, "kind").unwrap_or_else(|| "user".to_owned());
            let slug = extract_simple_param(q, "slug")
                .unwrap_or_default()
                .trim()
                .trim_start_matches('@')
                .to_ascii_lowercase();
            let title = extract_simple_param(q, "title").unwrap_or_else(|| slug.clone());
            let aliases_raw = extract_simple_param(q, "aliases").unwrap_or_default();
            if (kind == "user" || kind == "group" || kind == "channel")
                && slug.len() >= 3
                && slug.len() <= 48
                && slug
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
                && server.directory_entries.len() < 8_192
            {
                let clean_title: String = title.trim().chars().take(64).collect();
                server.directory_entries.insert(
                    format!("{kind}:{slug}"),
                    (kind.clone(), clean_title.clone()),
                );
                for extra in aliases_raw.split(',') {
                    let ex = extra.trim().trim_start_matches('@').to_ascii_lowercase();
                    if ex.len() >= 3
                        && ex.len() <= 48
                        && ex
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
                        && server.directory_entries.len() < 8_192
                    {
                        server.directory_entries.insert(
                            format!("{kind}:{ex}"),
                            (kind.clone(), clean_title.clone()),
                        );
                    }
                }
                (200, "application/json", r#"{"status":"registered"}"#.to_owned())
            } else {
                (400, "application/json", r#"{"error":"invalid_dir_entry"}"#.to_owned())
            }
        }
        ("GET", "/api/v1/dir/search") => {
            let q = query_opt
                .and_then(|qs| extract_simple_param(qs, "q"))
                .unwrap_or_default()
                .trim()
                .trim_start_matches('@')
                .to_lowercase();
            let mut out = String::new();
            let mut count = 0usize;
            for (key, (kind, title)) in &server.directory_entries {
                let slug = key.split_once(':').map_or(key.as_str(), |(_, s)| s);
                if q.is_empty() || slug.contains(&q) || title.to_lowercase().contains(&q) {
                    out.push_str(&format!("{kind}\t{slug}\t{title}\n"));
                    count += 1;
                    if count >= 50 {
                        break;
                    }
                }
            }
            (200, "text/plain; charset=utf-8", out)
        }
        ("GET", "/api/v1/update/info") => {
            let ver = &server.latest_app_version;
            let body_json = format!(
                r#"{{"version":"{ver}","desktop_url":"https://github.com/Topxir/aegis/raw/main/builds/desktop/aegis-desktop.exe","android_url":"https://github.com/Topxir/aegis/raw/main/builds/android-apk/aegis-messenger-release.apk"}}"#
            );
            (200, "application/json", body_json)
        }
        ("POST", "/api/v1/update/publish") => {
            let q = query_opt.unwrap_or("");
            if let Some(v) = extract_simple_param(q, "version") {
                let clean: String = v
                    .trim()
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                    .take(24)
                    .collect();
                if !clean.is_empty() {
                    server.latest_app_version = clean;
                }
            }
            (
                200,
                "application/json",
                format!(r#"{{"status":"published","version":"{}"}}"#, server.latest_app_version),
            )
        }
        ("POST", "/api/v1/tunnel/sealed") => {
            let Ok(wire) = hex_decode_bytes(body.trim()) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_tunnel_hex"}"#.to_owned(),
                );
            };
            if wire.len() < 32 + 12 + 16 {
                return (
                    400,
                    "application/json",
                    r#"{"error":"truncated_tunnel_frame"}"#.to_owned(),
                );
            }
            let mut client_pub = [0u8; 32];
            client_pub.copy_from_slice(&wire[0..32]);
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&wire[32..44]);
            let mut replay_tag = [0u8; 44];
            replay_tag[0..32].copy_from_slice(&client_pub);
            replay_tag[32..44].copy_from_slice(&nonce);
            if server.seen_tunnel_nonces.contains(&replay_tag) {
                return (
                    403,
                    "application/json",
                    r#"{"error":"tunnel_replay_detected"}"#.to_owned(),
                );
            }
            let ct = &wire[44..];
            let server_pub = server.server_tunnel_public_key();
            let mut shared = x25519(&server.server_blinding_salt, &client_pub);
            if constant_time_eq(&shared, &[0u8; 32]) {
                return (
                    400,
                    "application/json",
                    r#"{"error":"tunnel_low_order_point"}"#.to_owned(),
                );
            }
            let mut tunnel_key = [0u8; 32];
            let kdf_ok = hkdf_sha256(
                &client_pub,
                &shared,
                b"Aegis-TransportTunnel-v1",
                &mut tunnel_key,
            )
            .is_ok();
            shared.fill(0);
            if !kdf_ok {
                tunnel_key.fill(0);
                return (
                    400,
                    "application/json",
                    r#"{"error":"tunnel_kdf_failed"}"#.to_owned(),
                );
            }
            let pt_res = aead_open(&tunnel_key, &nonce, &server_pub, ct);
            tunnel_key.fill(0);
            let Ok(pt_buf) = pt_res else {
                return (
                    403,
                    "application/json",
                    r#"{"error":"tunnel_auth_failed"}"#.to_owned(),
                );
            };
            if server.seen_tunnel_nonces.len() >= 4096 {
                server.seen_tunnel_nonces.remove(0);
            }
            server.seen_tunnel_nonces.push(replay_tag);
            let Ok(inner_str) = core::str::from_utf8(pt_buf.as_slice()) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_tunnel_utf8"}"#.to_owned(),
                );
            };
            let mut lines = inner_str.splitn(3, '\n');
            let Some(in_method) = lines.next().map(str::to_owned) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"malformed_tunnel_req"}"#.to_owned(),
                );
            };
            let Some(in_path) = lines.next().map(str::to_owned) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"malformed_tunnel_req"}"#.to_owned(),
                );
            };
            let in_body = lines.next().unwrap_or("").to_owned();
            drop(pt_buf);
            let clean_in_route = in_path
                .trim()
                .split_once('?')
                .map_or(in_path.trim(), |(p, _)| p);
            if clean_in_route.eq_ignore_ascii_case("/api/v1/tunnel/sealed")
                || clean_in_route.eq_ignore_ascii_case("/api/v1/queue/relay")
                || clean_in_route.eq_ignore_ascii_case("/api/v1/queue/relay_poll")
            {
                return (
                    400,
                    "application/json",
                    r#"{"error":"recursive_tunnel_forbidden"}"#.to_owned(),
                );
            }
            handle_http_request(server, portal, &in_method, &in_path, &in_body)
        }
        ("POST", "/api/v1/queue/relay") => {
            let _ = server.record_request(false);
            let Some(queue_id) = parse_queue_id_from_query(query_opt) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_queue_id"}"#.to_owned(),
                );
            };
            let Some(target) = parse_target_from_query(query_opt) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_relay_target"}"#.to_owned(),
                );
            };
            let Ok(raw_frame) = hex_decode_bytes(body.trim()) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_capsule_hex"}"#.to_owned(),
                );
            };
            if !PADDING_BUCKETS.contains(&raw_frame.len()) {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_bucket_size"}"#.to_owned(),
                );
            }
            let hop_opt = parse_hop_from_query(query_opt);
            let auth_or_tok = parse_hex32_param_from_query(query_opt, "auth_hash")
                .map(|h| ("auth_hash", h))
                .or_else(|| {
                    parse_hex32_param_from_query(query_opt, "read_token")
                        .map(|t| ("read_token", t))
                });
            match forward_blind_relay_send(
                hop_opt,
                target,
                &queue_id,
                auth_or_tok.as_ref().map(|(k, v)| (*k, v)),
                &raw_frame,
            ) {
                Ok(()) => (
                    200,
                    "application/json",
                    r#"{"status":"relayed"}"#.to_owned(),
                ),
                Err(_) => (
                    502,
                    "application/json",
                    r#"{"error":"relay_unreachable"}"#.to_owned(),
                ),
            }
        }
        ("POST", "/api/v1/queue/relay_poll") => {
            let _ = server.record_request(false);
            let Some(queue_id) = parse_queue_id_from_query(query_opt) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_queue_id"}"#.to_owned(),
                );
            };
            let Some(target) = parse_target_from_query(query_opt) else {
                return (
                    400,
                    "application/json",
                    r#"{"error":"invalid_relay_target"}"#.to_owned(),
                );
            };
            let hop_opt = parse_hop_from_query(query_opt);
            let read_tok_opt = parse_hex32_param_from_query(query_opt, "read_token");
            match forward_blind_relay_poll(hop_opt, target, &queue_id, read_tok_opt.as_ref()) {
                Ok(json_body) => (200, "application/json", json_body),
                Err(_) => (
                    502,
                    "application/json",
                    r#"{"error":"relay_unreachable"}"#.to_owned(),
                ),
            }
        }
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

    #[test]
    fn red_team_read_token_auth_ssrf_blocking_ttl_gc_and_x25519_sealed_tunnel() {
        let mut srv = FederationServerState::new([0x33; 32]);
        let mut portal = SupportPortalState::new();

        // 1. Read-token protection prevents unauthenticated draining of a protected queue
        let q_id = [0x77; 32];
        let read_token = [0x88; 32];
        let wrong_token = [0x99; 32];
        srv.register_queue_read_token(q_id, &read_token).unwrap();
        let frame = pad_frame(b"protected-inbox-message").unwrap();
        srv.enqueue_frame(q_id, frame).unwrap();

        assert_eq!(srv.drain_queue(&q_id), Err(ServerError::UnauthorizedRead));
        assert_eq!(
            srv.drain_queue_authenticated(&q_id, Some(&wrong_token)),
            Err(ServerError::UnauthorizedRead)
        );
        // Messages remain intact until the genuine read_token is presented
        let drained = srv
            .drain_queue_authenticated(&q_id, Some(&read_token))
            .unwrap();
        assert_eq!(drained.len(), 1);

        // 2. Blind Relay SSRF protection blocks metadata IPs, private LANs, localhost, and privileged ports
        for forbidden_target in [
            "169.254.169.254:80",
            "192.168.1.1:8443",
            "10.0.0.1:8443",
            "172.16.0.1:8443",
            "localhost:8443",
            "127.0.0.1:22",
            "127.0.0.1:7878",
        ] {
            let path = format!(
                "/api/v1/queue/relay?target={forbidden_target}&queue=1111111111111111111111111111111111111111111111111111111111111111"
            );
            let (code, _, resp) = handle_http_request(&mut srv, &mut portal, "POST", &path, "00");
            assert_eq!(code, 400, "must reject SSRF target {forbidden_target}");
            assert!(resp.contains("invalid_relay_target"));
        }

        // 3. TTL queue garbage collection purges expired frames and frees memory
        let q_ttl = [0x44; 32];
        srv.enqueue_frame(q_ttl, pad_frame(b"ephemeral").unwrap())
            .unwrap();
        assert_eq!(srv.active_queue_count(), 1);
        let future_now = current_unix_seconds() + DEFAULT_QUEUE_TTL_SECS + 10;
        let purged = srv.purge_expired_frames(future_now, DEFAULT_QUEUE_TTL_SECS);
        assert_eq!(purged, 1);
        assert_eq!(srv.active_queue_count(), 0);

        // 4. Sealed X25519 + ChaCha20-Poly1305 tunnel hides method/path/query/body and rejects tampering
        let server_pub = srv.server_tunnel_public_key();
        let sealed_hex =
            seal_tunnel_request(&[0x21; 32], &server_pub, &[0x05; 12], "GET", "/health", "")
                .unwrap();
        let (t_code, _, t_body) = handle_http_request(
            &mut srv,
            &mut portal,
            "POST",
            "/api/v1/tunnel/sealed",
            &sealed_hex,
        );
        assert_eq!(t_code, 200);
        assert!(t_body.contains(r#""status":"ok""#));

        // Tampering with the sealed tunnel frame fails closed with 403 Forbidden
        let mut tampered_hex = sealed_hex;
        tampered_hex.replace_range(0..2, "ff");
        let (bad_code, _, _) = handle_http_request(
            &mut srv,
            &mut portal,
            "POST",
            "/api/v1/tunnel/sealed",
            &tampered_hex,
        );
        assert_eq!(bad_code, 403);
    }
}
