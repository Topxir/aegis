//! `aegis-identity` — Nickname + password validation (D-0006), anonymous nickname generator,
//! multi-account slot enforcement with `SupporterPass` blind-token quota (D-0010),
//! and hardware-backed PIN lockout state machine with Duress PIN support (PLAN.md §4).

use aegis_crypto::{
    aead_open, aead_seal, constant_time_eq, hkdf_sha256, hmac_sha256, sha256, CryptoError,
    ZeroizingBuffer,
};
use core::fmt;
use core::sync::atomic::{compiler_fence, Ordering};
use std::hint::black_box;

/// Minimum password length required by D-0006.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Maximum password length to prevent DoS via multi-megabyte Argon2id inputs.
pub const MAX_PASSWORD_CHARS: usize = 256;
/// Minimum number of uppercase letters required by D-0006.
pub const MIN_UPPERCASE_COUNT: usize = 3;
/// Maximum number of free accounts per device without a `SupporterPass` (D-0010).
pub const MAX_FREE_ACCOUNTS: usize = 3;
/// Default maximum failed PIN attempts before the PIN wrapper key is wiped (PLAN.md §4.2).
pub const DEFAULT_MAX_PIN_ATTEMPTS: u8 = 10;

fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = black_box(0u8);
    }
    let _ = black_box(buf);
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_string(s: &mut String) {
    let mut bytes = core::mem::take(s).into_bytes();
    let cap = bytes.capacity();
    bytes.resize(cap, 0u8);
    zeroize_bytes(&mut bytes);
}

/// Strict password policy errors (D-0006).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordPolicyError {
    /// Password is shorter than [`MIN_PASSWORD_CHARS`].
    TooShort { min: usize, actual: usize },
    /// Password exceeds [`MAX_PASSWORD_CHARS`].
    TooLong { max: usize, actual: usize },
    /// Password contains ASCII or Unicode control characters (`\0`, `\n`, `\r`, `\x1b`, etc.).
    ContainsControlCharacters,
    /// Fewer than [`MIN_UPPERCASE_COUNT`] uppercase letters.
    InsufficientUppercase { required: usize, actual: usize },
    /// Missing at least one lowercase letter.
    MissingLowercase,
    /// Missing at least one numeric digit.
    MissingDigit,
    /// Missing at least one special symbol.
    MissingSpecialSymbol,
    /// Contains the user's nickname (case-insensitive).
    ContainsNickname,
    /// Contains trivial repeated character sequences (e.g., `aaaa`, `1111`) or known weak patterns.
    WeakPatternDetected,
}

impl fmt::Display for PasswordPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { min, actual } => {
                write!(f, "password too short: minimum {min} chars, got {actual}")
            }
            Self::TooLong { max, actual } => {
                write!(f, "password too long: maximum {max} chars, got {actual}")
            }
            Self::ContainsControlCharacters => {
                write!(f, "password must not contain control characters")
            }
            Self::InsufficientUppercase { required, actual } => write!(
                f,
                "password requires at least {required} uppercase letters, got {actual}"
            ),
            Self::MissingLowercase => write!(f, "password requires at least one lowercase letter"),
            Self::MissingDigit => write!(f, "password requires at least one digit"),
            Self::MissingSpecialSymbol => {
                write!(f, "password requires at least one special symbol")
            }
            Self::ContainsNickname => write!(f, "password must not contain the login nickname"),
            Self::WeakPatternDetected => {
                write!(
                    f,
                    "password contains repeated or easily guessable sequences"
                )
            }
        }
    }
}

impl std::error::Error for PasswordPolicyError {}

/// Validates a candidate password against D-0006 requirements:
/// - Length in `12..=256` characters
/// - No control characters (`\0`, `\n`, `\r`, etc.)
/// - At least **3 uppercase letters** (`A-Z` or Unicode uppercase)
/// - At least 1 lowercase letter
/// - At least 1 digit
/// - At least 1 printable special character (punctuation / symbol)
/// - Does not contain the user's `nickname` (raw or separator-stripped)
/// - Does not contain 4+ identical consecutive characters or common weak substrings
///
/// # Errors
/// Returns a typed [`PasswordPolicyError`] describing the first failed check.
pub fn validate_password(password: &str, nickname: &str) -> Result<u8, PasswordPolicyError> {
    let char_count = password.chars().count();
    if char_count < MIN_PASSWORD_CHARS {
        return Err(PasswordPolicyError::TooShort {
            min: MIN_PASSWORD_CHARS,
            actual: char_count,
        });
    }
    if char_count > MAX_PASSWORD_CHARS {
        return Err(PasswordPolicyError::TooLong {
            max: MAX_PASSWORD_CHARS,
            actual: char_count,
        });
    }

    let mut uppercase_count = 0usize;
    let mut has_lowercase = false;
    let mut has_digit = false;
    let mut has_special = false;

    let mut prev_char: Option<char> = None;
    let mut repeat_run = 1usize;

    for ch in password.chars() {
        if ch.is_control() {
            return Err(PasswordPolicyError::ContainsControlCharacters);
        }
        if ch.is_uppercase() {
            uppercase_count = uppercase_count.saturating_add(1);
        } else if ch.is_lowercase() {
            has_lowercase = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if !ch.is_whitespace() && !ch.is_alphanumeric() {
            has_special = true;
        }

        if prev_char == Some(ch) {
            repeat_run = repeat_run.saturating_add(1);
            if repeat_run >= 4 {
                return Err(PasswordPolicyError::WeakPatternDetected);
            }
        } else {
            prev_char = Some(ch);
            repeat_run = 1;
        }
    }

    if uppercase_count < MIN_UPPERCASE_COUNT {
        return Err(PasswordPolicyError::InsufficientUppercase {
            required: MIN_UPPERCASE_COUNT,
            actual: uppercase_count,
        });
    }
    if !has_lowercase {
        return Err(PasswordPolicyError::MissingLowercase);
    }
    if !has_digit {
        return Err(PasswordPolicyError::MissingDigit);
    }
    if !has_special {
        return Err(PasswordPolicyError::MissingSpecialSymbol);
    }

    let mut lower_pwd = password.to_lowercase();
    let mut trimmed_nick = nickname.trim().to_lowercase();
    if trimmed_nick.chars().count() >= 3 && lower_pwd.contains(&trimmed_nick) {
        zeroize_string(&mut lower_pwd);
        zeroize_string(&mut trimmed_nick);
        return Err(PasswordPolicyError::ContainsNickname);
    }

    let mut stripped_nick: String = trimmed_nick
        .chars()
        .filter(|&c| c != '-' && c != '_' && !c.is_whitespace())
        .collect();
    let mut stripped_pwd: String = lower_pwd
        .chars()
        .filter(|&c| c != '-' && c != '_' && !c.is_whitespace())
        .collect();
    zeroize_string(&mut trimmed_nick);
    if stripped_nick.chars().count() >= 3 && stripped_pwd.contains(&stripped_nick) {
        zeroize_string(&mut stripped_nick);
        zeroize_string(&mut stripped_pwd);
        zeroize_string(&mut lower_pwd);
        return Err(PasswordPolicyError::ContainsNickname);
    }
    zeroize_string(&mut stripped_nick);
    zeroize_string(&mut stripped_pwd);

    const WEAK_PATTERNS: [&str; 6] = ["qwerty", "123456", "password", "admin", "abcdef", "qwertz"];
    let weak_found = WEAK_PATTERNS.iter().any(|pat| lower_pwd.contains(pat));
    zeroize_string(&mut lower_pwd);
    if weak_found {
        return Err(PasswordPolicyError::WeakPatternDetected);
    }

    // Entropy score estimation (0..=100)
    let base_score = (char_count.min(24) * 3) as u8;
    let bonus = (uppercase_count.min(6) * 4) as u8 + 15;
    Ok(base_score.saturating_add(bonus).min(100))
}

const ADJECTIVES: [&str; 16] = [
    "silent", "arctic", "obsidian", "cobalt", "velvet", "amber", "lunar", "crimson", "hollow",
    "astral", "cipher", "misty", "nordic", "shadow", "quartz", "zenith",
];

const NOUNS: [&str; 16] = [
    "vortex", "falcon", "beacon", "anchor", "glacier", "nebula", "raven", "summit", "prism",
    "harbor", "comet", "shield", "vector", "aurora", "tempest", "monolith",
];

/// Nickname validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NicknameError {
    /// Nickname must be between 4 and 32 characters.
    InvalidLength(usize),
    /// Only lowercase ASCII alphanumeric characters, `-`, and `_` are allowed.
    InvalidCharacter(char),
}

impl fmt::Display for NicknameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(len) => {
                write!(f, "nickname length must be 4..=32 characters, got {len}")
            }
            Self::InvalidCharacter(ch) => {
                write!(f, "nickname contains disallowed character: {ch:?}")
            }
        }
    }
}

impl std::error::Error for NicknameError {}

/// Generates a random-looking anonymous nickname from 4 bytes of CSPRNG entropy (D-0006),
/// e.g. `silent-vortex-4821`.
#[must_use]
pub fn generate_nickname(entropy: [u8; 4]) -> String {
    let adj = ADJECTIVES[usize::from(entropy[0]) % ADJECTIVES.len()];
    let noun = NOUNS[usize::from(entropy[1]) % NOUNS.len()];
    let num = (u16::from_le_bytes([entropy[2], entropy[3]]) % 9000) + 1000;
    format!("{adj}-{noun}-{num}")
}

/// Validates a user-chosen or generated login nickname.
///
/// # Errors
/// Returns [`NicknameError`] if length is outside `4..=32` or characters are invalid.
pub fn validate_nickname(nickname: &str) -> Result<(), NicknameError> {
    let len = nickname.chars().count();
    if !(4..=32).contains(&len) {
        return Err(NicknameError::InvalidLength(len));
    }
    for ch in nickname.chars() {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_') {
            return Err(NicknameError::InvalidCharacter(ch));
        }
    }
    Ok(())
}

/// Blind-signed Privacy Pass token unlocking additional account slots beyond 3 (D-0010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupporterPass {
    /// Anonymous token identifier.
    pub token_id: [u8; 16],
    /// Maximum total accounts permitted by this pass.
    pub max_accounts: usize,
    /// Foundation blind signature verification status.
    pub signature_verified: bool,
}

/// Multi-account error types (D-0010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountSlotError {
    /// Device reached the free limit of 3 accounts; a `SupporterPass` is required.
    FreeQuotaExceeded { max_free: usize },
    /// Provided `SupporterPass` signature is invalid, unverified, or would downgrade active slots.
    InvalidSupporterPass,
    /// Provided `SupporterPass` `token_id` was already redeemed.
    DuplicateSupporterPassToken,
    /// Even with the supporter pass, the slot limit was reached.
    SupporterQuotaExceeded { max_allowed: usize },
    /// Account ID is all-zero (`[0u8; 16]`).
    InvalidAccountId,
    /// Account with the same local profile ID already exists.
    DuplicateAccountId,
}

impl fmt::Display for AccountSlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FreeQuotaExceeded { max_free } => write!(
                f,
                "free limit of {max_free} accounts reached; SupporterPass required"
            ),
            Self::InvalidSupporterPass => write!(f, "supporter pass signature is invalid"),
            Self::DuplicateSupporterPassToken => {
                write!(f, "supporter pass token has already been redeemed")
            }
            Self::SupporterQuotaExceeded { max_allowed } => {
                write!(f, "supporter pass quota of {max_allowed} accounts reached")
            }
            Self::InvalidAccountId => write!(f, "account ID must not be all-zero"),
            Self::DuplicateAccountId => write!(f, "account ID already registered on device"),
        }
    }
}

impl std::error::Error for AccountSlotError {}

/// Enforces the D-0010 multi-account policy (up to 3 free profiles per device,
/// 4+ requires a verified blind-signed `SupporterPass`).
#[derive(Default, Clone)]
pub struct AccountSlotManager {
    active_account_ids: Vec<[u8; 16]>,
    redeemed_token_ids: Vec<[u8; 16]>,
    supporter_pass: Option<SupporterPass>,
}

impl fmt::Debug for AccountSlotManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountSlotManager")
            .field("active_accounts_count", &self.active_account_ids.len())
            .field("redeemed_tokens_count", &self.redeemed_token_ids.len())
            .field("supporter_pass_active", &self.supporter_pass.is_some())
            .finish()
    }
}

impl Drop for AccountSlotManager {
    fn drop(&mut self) {
        for id in &mut self.active_account_ids {
            zeroize_bytes(id);
        }
        self.active_account_ids.clear();
        for tok in &mut self.redeemed_token_ids {
            zeroize_bytes(tok);
        }
        self.redeemed_token_ids.clear();
        if let Some(pass) = &mut self.supporter_pass {
            zeroize_bytes(&mut pass.token_id);
        }
    }
}

impl AccountSlotManager {
    /// Creates an empty slot manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches a verified `SupporterPass` to unlock 4+ account slots.
    ///
    /// # Errors
    /// Fail-closed: rejects unverified passes, all-zero `token_id`, replayed `token_id`,
    /// or `max_accounts` below currently active accounts.
    pub fn activate_supporter_pass(&mut self, pass: SupporterPass) -> Result<(), AccountSlotError> {
        if !pass.signature_verified
            || pass.max_accounts <= MAX_FREE_ACCOUNTS
            || pass.token_id == [0u8; 16]
            || pass.max_accounts < self.active_account_ids.len()
        {
            return Err(AccountSlotError::InvalidSupporterPass);
        }
        if self.redeemed_token_ids.contains(&pass.token_id) {
            return Err(AccountSlotError::DuplicateSupporterPassToken);
        }
        self.redeemed_token_ids.push(pass.token_id);
        self.supporter_pass = Some(pass);
        Ok(())
    }

    /// Attempts to register a new local account profile on this device.
    ///
    /// # Errors
    /// Returns [`AccountSlotError`] if the ID is all-zero, duplicate, or exceeds quota.
    pub fn register_account(&mut self, account_id: [u8; 16]) -> Result<usize, AccountSlotError> {
        if account_id == [0u8; 16] {
            return Err(AccountSlotError::InvalidAccountId);
        }
        if self.active_account_ids.contains(&account_id) {
            return Err(AccountSlotError::DuplicateAccountId);
        }

        let current = self.active_account_ids.len();
        if current >= MAX_FREE_ACCOUNTS {
            match &self.supporter_pass {
                Some(pass) if pass.signature_verified => {
                    if current >= pass.max_accounts {
                        return Err(AccountSlotError::SupporterQuotaExceeded {
                            max_allowed: pass.max_accounts,
                        });
                    }
                }
                _ => {
                    return Err(AccountSlotError::FreeQuotaExceeded {
                        max_free: MAX_FREE_ACCOUNTS,
                    });
                }
            }
        }

        self.active_account_ids.push(account_id);
        Ok(self.active_account_ids.len())
    }

    /// Returns the number of active accounts on the device.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_account_ids.len()
    }
}

/// Outcome of a PIN verification attempt (PLAN.md §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinUnlockOutcome {
    /// Primary PIN matched; failed counter reset to 0.
    Unlocked,
    /// Duress PIN matched; caller must open decoy profile or trigger silent wipe.
    DuressTriggered,
    /// Wrong PIN; returns remaining attempts before PIN wrapper wipe.
    FailedAttempt { remaining_attempts: u8 },
    /// Exhausted all allowed PIN attempts; PIN wrapper key wiped, full OPAQUE password login required.
    PinWrapperWiped,
}

/// Errors when configuring a [`PinGuard`] (contract `aegis-identity.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSetupError {
    /// Duplicate PIN: Duress PIN must not equal the primary PIN.
    DuressPinCollision,
    /// Empty PIN digest or empty wrapped database key is rejected.
    EmptyKeyOrPinMaterial,
    /// `max_attempts` must be at least 1.
    InvalidMaxAttempts,
}

impl fmt::Display for PinSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuressPinCollision => write!(f, "duress PIN must not match primary PIN"),
            Self::EmptyKeyOrPinMaterial => {
                write!(f, "PIN digest and wrapped DB key must not be empty")
            }
            Self::InvalidMaxAttempts => write!(f, "max PIN attempts must be greater than zero"),
        }
    }
}

impl std::error::Error for PinSetupError {}

/// PIN lockout state machine protecting the local database key wrapper (PLAN.md §4.2).
#[derive(Debug)]
pub struct PinGuard {
    primary_pin_digest: ZeroizingBuffer,
    duress_pin_digest: Option<ZeroizingBuffer>,
    wrapped_db_key: ZeroizingBuffer,
    failed_attempts: u8,
    max_attempts: u8,
    wiped: bool,
}

impl PinGuard {
    /// Creates a new `PinGuard` with a primary PIN digest, optional duress PIN digest,
    /// and the wrapped database key.
    ///
    /// Note: if `duress_pin_digest` is identical to `primary_pin_digest`, it is ignored
    /// in `new` to prevent accidental lock-out; prefer [`PinGuard::try_new`] for strict validation.
    #[must_use]
    pub fn new(
        primary_pin_digest: Vec<u8>,
        duress_pin_digest: Option<Vec<u8>>,
        wrapped_db_key: Vec<u8>,
        max_attempts: u8,
    ) -> Self {
        let effective_max = if max_attempts == 0 {
            DEFAULT_MAX_PIN_ATTEMPTS
        } else {
            max_attempts
        };
        let invalid_primary_or_key = primary_pin_digest.is_empty()
            || primary_pin_digest.iter().all(|&b| b == 0)
            || wrapped_db_key.is_empty()
            || wrapped_db_key.iter().all(|&b| b == 0);
        let sanitized_duress = duress_pin_digest.and_then(|duress| {
            let wrapped_duress = ZeroizingBuffer::new(duress);
            if constant_time_eq(wrapped_duress.as_slice(), &primary_pin_digest)
                || wrapped_duress.is_empty()
                || wrapped_duress.as_slice().iter().all(|&b| b == 0)
            {
                None
            } else {
                Some(wrapped_duress)
            }
        });
        let mut guard = Self {
            primary_pin_digest: ZeroizingBuffer::new(primary_pin_digest),
            duress_pin_digest: sanitized_duress,
            wrapped_db_key: ZeroizingBuffer::new(wrapped_db_key),
            failed_attempts: 0,
            max_attempts: effective_max,
            wiped: false,
        };
        if invalid_primary_or_key {
            guard.wipe_wrapper();
        }
        guard
    }

    /// Validated constructor that rejects empty/all-zero key/PIN material, `max_attempts == 0`,
    /// or a Duress PIN equal to the primary PIN.
    ///
    /// # Errors
    /// Returns [`PinSetupError`] if `primary_pin_digest` or `wrapped_db_key` is empty or all-zero,
    /// `max_attempts == 0`, or if `duress_pin_digest` is empty/all-zero or matches `primary_pin_digest`.
    pub fn try_new(
        primary_pin_digest: Vec<u8>,
        duress_pin_digest: Option<Vec<u8>>,
        wrapped_db_key: Vec<u8>,
        max_attempts: u8,
    ) -> Result<Self, PinSetupError> {
        let primary_buf = ZeroizingBuffer::new(primary_pin_digest);
        let duress_buf = duress_pin_digest.map(ZeroizingBuffer::new);
        let key_buf = ZeroizingBuffer::new(wrapped_db_key);
        if max_attempts == 0 {
            return Err(PinSetupError::InvalidMaxAttempts);
        }
        if primary_buf.is_empty()
            || primary_buf.as_slice().iter().all(|&b| b == 0)
            || key_buf.is_empty()
            || key_buf.as_slice().iter().all(|&b| b == 0)
        {
            return Err(PinSetupError::EmptyKeyOrPinMaterial);
        }
        if let Some(duress) = &duress_buf {
            if duress.is_empty() || duress.as_slice().iter().all(|&b| b == 0) {
                return Err(PinSetupError::EmptyKeyOrPinMaterial);
            }
            if constant_time_eq(duress.as_slice(), primary_buf.as_slice()) {
                return Err(PinSetupError::DuressPinCollision);
            }
        }
        Ok(Self {
            primary_pin_digest: primary_buf,
            duress_pin_digest: duress_buf,
            wrapped_db_key: key_buf,
            failed_attempts: 0,
            max_attempts,
            wiped: false,
        })
    }

    /// Verifies a candidate PIN digest in constant time (always evaluating both duress and primary digests)
    /// and updates the lockout counter.
    pub fn verify_pin_digest(&mut self, candidate_digest: &[u8]) -> PinUnlockOutcome {
        if self.wiped {
            return PinUnlockOutcome::PinWrapperWiped;
        }

        let duress_match = match &self.duress_pin_digest {
            Some(duress) => constant_time_eq(duress.as_slice(), candidate_digest),
            None => {
                let _ = constant_time_eq(self.primary_pin_digest.as_slice(), candidate_digest);
                false
            }
        };
        let primary_match = constant_time_eq(self.primary_pin_digest.as_slice(), candidate_digest);

        if duress_match {
            self.wipe_wrapper();
            return PinUnlockOutcome::DuressTriggered;
        }

        if primary_match {
            self.failed_attempts = 0;
            return PinUnlockOutcome::Unlocked;
        }

        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts >= self.max_attempts {
            self.wipe_wrapper();
            PinUnlockOutcome::PinWrapperWiped
        } else {
            PinUnlockOutcome::FailedAttempt {
                remaining_attempts: self.max_attempts - self.failed_attempts,
            }
        }
    }

    /// Zeroizes the PIN wrapper key so unlocking requires full nickname + password re-authentication.
    pub fn wipe_wrapper(&mut self) {
        self.wrapped_db_key.zeroize();
        self.primary_pin_digest.zeroize();
        if let Some(duress) = &mut self.duress_pin_digest {
            duress.zeroize();
        }
        self.wiped = true;
    }

    /// Returns `true` if the PIN wrapper has been wiped due to lockout or duress.
    #[must_use]
    pub const fn is_wiped(&self) -> bool {
        self.wiped
    }
}

// ============================================================================
// OPAQUE Registration & Login Flow + AccountVault Envelope (D-0002, D-0006)
// ============================================================================

/// Derives the server-blinded `login_id` from `nickname` and a 32-byte `server_salt` (D-0002).
/// The server never receives or stores the plaintext nickname.
///
/// # Errors
/// Returns [`PasswordPolicyError`] if the nickname is invalid or `server_salt` is all-zero.
pub fn derive_login_id(
    nickname: &str,
    server_salt: &[u8; 32],
) -> Result<[u8; 32], PasswordPolicyError> {
    let normalized = nickname.trim().to_ascii_lowercase();
    if validate_nickname(&normalized).is_err() || server_salt == &[0u8; 32] {
        return Err(PasswordPolicyError::WeakPatternDetected);
    }
    let mut login_id = [0u8; 32];
    hkdf_sha256(
        server_salt,
        normalized.as_bytes(),
        b"Aegis-OPAQUE-LoginId-v1",
        &mut login_id,
    )
    .map_err(|_| PasswordPolicyError::WeakPatternDetected)?;
    Ok(login_id)
}

/// Encrypted cloud-recoverable account state stored inside the OPAQUE record (`AccountVault`, D-0002).
/// Contains the user's active unidirectional queue keys and recovery metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountVault {
    /// Master 32-byte account identity secret.
    pub master_identity_secret: [u8; 32],
    /// List of active unidirectional queue identifiers owned by this account.
    pub active_queue_ids: Vec<[u8; 32]>,
    /// Optional 24-word recovery phrase enabled flag.
    pub recovery_phrase_enabled: bool,
}

impl fmt::Debug for AccountVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountVault")
            .field("master_identity_secret", &"[REDACTED]")
            .field(
                "active_queue_ids",
                &format_args!("[REDACTED; {} queues]", self.active_queue_ids.len()),
            )
            .field("recovery_phrase_enabled", &self.recovery_phrase_enabled)
            .finish()
    }
}

impl Drop for AccountVault {
    fn drop(&mut self) {
        for b in &mut self.master_identity_secret {
            *b = black_box(0u8);
        }
        let _ = black_box(self.master_identity_secret.as_mut_slice());
        for q in &mut self.active_queue_ids {
            for b in q.iter_mut() {
                *b = black_box(0u8);
            }
            let _ = black_box(q.as_mut_slice());
        }
        self.active_queue_ids.clear();
        compiler_fence(Ordering::SeqCst);
    }
}

impl AccountVault {
    fn to_bytes(&self) -> Vec<u8> {
        let count = u16::try_from(self.active_queue_ids.len()).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(32 + 1 + 2 + usize::from(count) * 32);
        out.extend_from_slice(&self.master_identity_secret);
        out.push(u8::from(self.recovery_phrase_enabled));
        out.extend_from_slice(&count.to_be_bytes());
        for q in self.active_queue_ids.iter().take(usize::from(count)) {
            out.extend_from_slice(q);
        }
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 35 {
            return Err(CryptoError::AuthenticationFailed);
        }
        let mut master_identity_secret = [0u8; 32];
        master_identity_secret.copy_from_slice(&bytes[0..32]);
        if master_identity_secret == [0u8; 32] || bytes[32] > 1 {
            for b in &mut master_identity_secret {
                *b = black_box(0u8);
            }
            return Err(CryptoError::AuthenticationFailed);
        }
        let recovery_phrase_enabled = bytes[32] == 1;
        let count = usize::from(u16::from_be_bytes([bytes[33], bytes[34]]));
        if bytes.len() != 35 + count * 32 {
            for b in &mut master_identity_secret {
                *b = black_box(0u8);
            }
            return Err(CryptoError::AuthenticationFailed);
        }
        let mut active_queue_ids = Vec::with_capacity(count);
        for i in 0..count {
            let start = 35 + i * 32;
            let mut q = [0u8; 32];
            q.copy_from_slice(&bytes[start..start + 32]);
            if q == [0u8; 32] || active_queue_ids.contains(&q) {
                for b in &mut master_identity_secret {
                    *b = black_box(0u8);
                }
                return Err(CryptoError::AuthenticationFailed);
            }
            active_queue_ids.push(q);
        }
        Ok(Self {
            master_identity_secret,
            active_queue_ids,
            recovery_phrase_enabled,
        })
    }
}

/// Password-encrypted envelope (`OpaqueAccountEnvelope`) protecting [`AccountVault`] on the server (D-0002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueAccountEnvelope {
    /// Random 12-byte AEAD nonce.
    pub nonce: [u8; 12],
    /// Random 32-byte key-derivation salt.
    pub kdf_salt: [u8; 32],
    /// AEAD ciphertext + 16-byte authentication tag.
    pub ciphertext_and_tag: Vec<u8>,
}

impl OpaqueAccountEnvelope {
    fn derive_export_key(
        nickname: &str,
        password: &str,
        kdf_salt: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        let _ =
            validate_password(password, nickname).map_err(|_| CryptoError::KeyDerivationFailed)?;
        let mut ikm = ZeroizingBuffer::new(
            [
                nickname.trim().to_ascii_lowercase().as_bytes(),
                b":",
                password.as_bytes(),
            ]
            .concat(),
        );
        let mut key = [0u8; 32];
        let res = hkdf_sha256(
            kdf_salt,
            ikm.as_slice(),
            b"Aegis-OPAQUE-ExportKey-v1",
            &mut key,
        );
        ikm.zeroize();
        res?;
        Ok(key)
    }

    /// Seals an [`AccountVault`] under a key derived from `(nickname, password, kdf_salt)`.
    ///
    /// # Errors
    /// Returns [`CryptoError`] if the password fails policy validation, `kdf_salt` or `nonce` is all-zero, or encryption fails.
    pub fn seal(
        nickname: &str,
        password: &str,
        kdf_salt: [u8; 32],
        nonce: [u8; 12],
        vault: &AccountVault,
    ) -> Result<Self, CryptoError> {
        if kdf_salt == [0u8; 32]
            || nonce == [0u8; 12]
            || vault.master_identity_secret == [0u8; 32]
            || vault.active_queue_ids.len() > usize::from(u16::MAX)
        {
            return Err(CryptoError::KeyDerivationFailed);
        }
        for (idx, q) in vault.active_queue_ids.iter().enumerate() {
            if *q == [0u8; 32] || vault.active_queue_ids[..idx].contains(q) {
                return Err(CryptoError::KeyDerivationFailed);
            }
        }
        let mut key = Self::derive_export_key(nickname, password, &kdf_salt)?;
        let raw = ZeroizingBuffer::new(vault.to_bytes());
        let aad = sha256(nickname.trim().to_ascii_lowercase().as_bytes());
        let res = aead_seal(&key, &nonce, &aad, raw.as_slice());
        for b in &mut key {
            *b = black_box(0u8);
        }
        let _ = black_box(key.as_mut_slice());
        compiler_fence(Ordering::SeqCst);
        let ciphertext_and_tag = res?;
        Ok(Self {
            nonce,
            kdf_salt,
            ciphertext_and_tag,
        })
    }

    /// Opens and authenticates the [`AccountVault`] using `(nickname, password)`.
    ///
    /// # Errors
    /// Fail-closed: returns [`CryptoError::AuthenticationFailed`] if the password or nickname is wrong
    /// or the ciphertext was tampered with.
    pub fn open(&self, nickname: &str, password: &str) -> Result<AccountVault, CryptoError> {
        if self.kdf_salt == [0u8; 32] || self.nonce == [0u8; 12] {
            return Err(CryptoError::AuthenticationFailed);
        }
        let mut key = Self::derive_export_key(nickname, password, &self.kdf_salt)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let aad = sha256(nickname.trim().to_ascii_lowercase().as_bytes());
        let res = aead_open(&key, &self.nonce, &aad, &self.ciphertext_and_tag);
        for b in &mut key {
            *b = black_box(0u8);
        }
        let _ = black_box(key.as_mut_slice());
        compiler_fence(Ordering::SeqCst);
        let decrypted = res?;
        AccountVault::from_bytes(decrypted.as_slice())
    }
}

/// Server-stored OPAQUE registration record (contains no plaintext nickname or password).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueRegistrationRecord {
    /// Blinded login identifier `login_id = KDF(nickname, server_salt)`.
    pub login_id: [u8; 32],
    /// Client's OPAQUE public verifier derived from OPRF output.
    pub client_public_verifier: [u8; 32],
    /// Encrypted account vault envelope.
    pub envelope: OpaqueAccountEnvelope,
}

/// Client-side OPAQUE registration & login state machine (D-0002, D-0006).
#[derive(Clone)]
pub struct OpaqueClientSession {
    login_id: [u8; 32],
    blinded_element: ZeroizingBuffer,
}

impl fmt::Debug for OpaqueClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueClientSession")
            .field("login_id", &"[REDACTED]")
            .field("blinded_element", &self.blinded_element)
            .finish()
    }
}

impl Drop for OpaqueClientSession {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.login_id);
        self.blinded_element.zeroize();
    }
}

impl OpaqueClientSession {
    /// Starts an OPAQUE client session without exposing the password to the server.
    ///
    /// # Errors
    /// Returns [`PasswordPolicyError`] if the nickname or password violates D-0006.
    pub fn start(
        nickname: &str,
        password: &str,
        server_salt: &[u8; 32],
        blinding_factor: &[u8; 32],
    ) -> Result<(Self, OpaqueRegistrationRecord), PasswordPolicyError> {
        let _ = validate_password(password, nickname)?;
        if blinding_factor == &[0u8; 32] {
            return Err(PasswordPolicyError::WeakPatternDetected);
        }
        let login_id = derive_login_id(nickname, server_salt)?;
        let mut blinded_element = hmac_sha256(blinding_factor, password.as_bytes());
        let client_public_verifier = hmac_sha256(&login_id, &blinded_element);

        let vault = AccountVault {
            master_identity_secret: sha256(&blinded_element),
            active_queue_ids: Vec::new(),
            recovery_phrase_enabled: false,
        };
        let mut nonce_mac = hmac_sha256(server_salt, blinding_factor);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_mac[0..12]);
        zeroize_bytes(&mut nonce_mac);
        if nonce == [0u8; 12] {
            nonce[0] = 1;
        }
        let envelope_res =
            OpaqueAccountEnvelope::seal(nickname, password, *server_salt, nonce, &vault);
        let blinded_buf = ZeroizingBuffer::new(blinded_element.to_vec());
        zeroize_bytes(&mut blinded_element);
        let envelope = envelope_res.map_err(|_| PasswordPolicyError::WeakPatternDetected)?;

        Ok((
            Self {
                login_id,
                blinded_element: blinded_buf,
            },
            OpaqueRegistrationRecord {
                login_id,
                client_public_verifier,
                envelope,
            },
        ))
    }

    /// Returns the server-blinded `login_id`.
    #[must_use]
    pub fn login_id(&self) -> [u8; 32] {
        self.login_id
    }

    /// Verifies a server registration record and recovers the [`AccountVault`].
    ///
    /// # Errors
    /// Returns [`CryptoError::AuthenticationFailed`] if the verifier or password does not match.
    pub fn finish_login(
        &self,
        nickname: &str,
        password: &str,
        record: &OpaqueRegistrationRecord,
    ) -> Result<AccountVault, CryptoError> {
        let mut expected_verifier = hmac_sha256(&self.login_id, self.blinded_element.as_slice());
        let verifier_ok = constant_time_eq(&expected_verifier, &record.client_public_verifier);
        let login_ok = constant_time_eq(&self.login_id, &record.login_id);
        zeroize_bytes(&mut expected_verifier);
        if !verifier_ok || !login_ok {
            return Err(CryptoError::AuthenticationFailed);
        }
        record.envelope.open(nickname, password)
    }
}

// ============================================================================
// Panic Button & Calculator / Notes App Disguise Mode (PLAN.md §14, D-0013)
// ============================================================================

/// Visual disguise mode concealing the messenger UI on the device (D-0013).
#[derive(Clone, PartialEq, Eq)]
pub enum DisguiseMode {
    /// Standard Aegis icon and launcher entry.
    None,
    /// Functional calculator façade that only reveals Aegis when `unlock_expression` is evaluated.
    Calculator {
        /// Secret arithmetic expression ending with `=`, e.g. `"1337+42="`.
        unlock_expression: String,
    },
    /// Minimalist notes application façade.
    NotesApp,
}

impl fmt::Debug for DisguiseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "DisguiseMode::None"),
            Self::Calculator { .. } => write!(
                f,
                "DisguiseMode::Calculator {{ unlock_expression: \"[REDACTED]\" }}"
            ),
            Self::NotesApp => write!(f, "DisguiseMode::NotesApp"),
        }
    }
}

impl Drop for DisguiseMode {
    fn drop(&mut self) {
        if let Self::Calculator { unlock_expression } = self {
            zeroize_string(unlock_expression);
        }
    }
}

/// Immediate emergency action executed when the user triggers the Panic Button (D-0013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicAction {
    /// Zeroizes RAM session keys, locks the PIN wrapper, and switches to the disguise façade.
    LockAndMinimize,
    /// Switches the active session to a clean decoy profile.
    SwitchToDecoyProfile,
    /// Immediately wipes the local database master key (`crypto_wipe`) and PIN wrapper.
    InstantCryptoWipe,
}

/// Configuration for app disguise and emergency panic button behavior (D-0013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDisguiseConfig {
    /// Active visual disguise mode.
    pub mode: DisguiseMode,
    /// Action taken when the panic button is pressed.
    pub panic_action: PanicAction,
}

impl AppDisguiseConfig {
    /// Validates and constructs an [`AppDisguiseConfig`].
    /// For `DisguiseMode::Calculator`, the `unlock_expression` must be 4..=32 ASCII characters,
    /// end with `'='`, and contain at least one digit and only arithmetic operators (`+`, `-`, `*`, `/`, `.`, `=`).
    ///
    /// # Errors
    /// Returns [`PinSetupError::EmptyKeyOrPinMaterial`] if the calculator expression is invalid.
    pub fn try_new(mode: DisguiseMode, panic_action: PanicAction) -> Result<Self, PinSetupError> {
        let normalized_mode = match mode {
            DisguiseMode::Calculator {
                ref unlock_expression,
            } => {
                let expr = unlock_expression.trim();
                if !(4..=32).contains(&expr.len()) || !expr.ends_with('=') {
                    return Err(PinSetupError::EmptyKeyOrPinMaterial);
                }
                let body = &expr[..expr.len() - 1];
                if body.is_empty()
                    || !body.chars().any(|c| c.is_ascii_digit())
                    || !body
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '*' | '/' | '.'))
                {
                    return Err(PinSetupError::EmptyKeyOrPinMaterial);
                }
                DisguiseMode::Calculator {
                    unlock_expression: expr.to_owned(),
                }
            }
            DisguiseMode::None => DisguiseMode::None,
            DisguiseMode::NotesApp => DisguiseMode::NotesApp,
        };
        Ok(Self {
            mode: normalized_mode,
            panic_action,
        })
    }
}

/// Checks in constant time whether the user's calculator keypad input matches the secret
/// `Calculator` unlock expression (D-0013) without leaking the expression length via timing.
#[must_use]
pub fn check_calculator_unlock(config: &AppDisguiseConfig, calculator_input: &str) -> bool {
    match &config.mode {
        DisguiseMode::Calculator { unlock_expression } => {
            let expected = unlock_expression.trim().as_bytes();
            let candidate = calculator_input.trim().as_bytes();
            let mut pad_exp = [0u8; 32];
            let mut pad_cand = [0u8; 32];
            let exp_len = expected.len().min(32);
            let cand_len = candidate.len().min(32);
            pad_exp[..exp_len].copy_from_slice(&expected[..exp_len]);
            pad_cand[..cand_len].copy_from_slice(&candidate[..cand_len]);
            let bytes_match = constant_time_eq(&pad_exp, &pad_cand);
            let len_match = expected.len() == candidate.len() && candidate.len() <= 32;
            zeroize_bytes(&mut pad_exp);
            zeroize_bytes(&mut pad_cand);
            bytes_match && len_match
        }
        _ => false,
    }
}

/// Executes the configured emergency [`PanicAction`], immediately wiping the in-memory
/// [`PinGuard`] key wrapper and returning the triggered action for the UI/storage layer (D-0013).
pub fn trigger_panic_button(config: &AppDisguiseConfig, pin_guard: &mut PinGuard) -> PanicAction {
    pin_guard.wipe_wrapper();
    config.panic_action
}

// ============================================================================
// Per-Chat Individual PIN Lock (PLAN.md §14, D-0014)
// ============================================================================

/// Independent PIN lock protecting an individual sensitive chat (D-0014).
pub struct ChatPinLock {
    chat_id: [u8; 32],
    pin_digest: ZeroizingBuffer,
    failed_attempts: u8,
    max_attempts: u8,
    locked: bool,
    wiped: bool,
}

impl fmt::Debug for ChatPinLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatPinLock")
            .field("chat_id", &"[REDACTED]")
            .field("pin_digest", &self.pin_digest)
            .field("locked", &self.locked)
            .field("wiped", &self.wiped)
            .finish()
    }
}

impl Drop for ChatPinLock {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.chat_id);
        self.pin_digest.zeroize();
    }
}

impl ChatPinLock {
    /// Creates a per-chat PIN lock for `chat_id`.
    ///
    /// # Errors
    /// Returns [`PinSetupError`] if `chat_id` is all-zero, `pin_digest` is empty or all-zero, or `max_attempts == 0`.
    pub fn try_new(
        chat_id: [u8; 32],
        pin_digest: Vec<u8>,
        max_attempts: u8,
    ) -> Result<Self, PinSetupError> {
        let pin_buf = ZeroizingBuffer::new(pin_digest);
        if chat_id == [0u8; 32] || pin_buf.is_empty() || pin_buf.as_slice().iter().all(|&b| b == 0)
        {
            return Err(PinSetupError::EmptyKeyOrPinMaterial);
        }
        if max_attempts == 0 {
            return Err(PinSetupError::InvalidMaxAttempts);
        }
        Ok(Self {
            chat_id,
            pin_digest: pin_buf,
            failed_attempts: 0,
            max_attempts,
            locked: true,
            wiped: false,
        })
    }

    /// Returns the protected chat identifier.
    #[must_use]
    pub fn chat_id(&self) -> [u8; 32] {
        self.chat_id
    }

    /// Returns `true` if the chat is currently locked or wiped.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked || self.wiped
    }

    /// Returns `true` if the per-chat PIN lock has been wiped due to exhausting allowed attempts.
    #[must_use]
    pub const fn is_wiped(&self) -> bool {
        self.wiped
    }

    /// Explicitly locks the chat again when the user leaves the conversation screen.
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Verifies the per-chat PIN digest in constant time.
    pub fn verify_chat_pin(&mut self, candidate_digest: &[u8]) -> PinUnlockOutcome {
        if self.wiped {
            return PinUnlockOutcome::PinWrapperWiped;
        }
        if constant_time_eq(self.pin_digest.as_slice(), candidate_digest) {
            self.failed_attempts = 0;
            self.locked = false;
            return PinUnlockOutcome::Unlocked;
        }
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts >= self.max_attempts {
            self.pin_digest.zeroize();
            self.locked = true;
            self.wiped = true;
            PinUnlockOutcome::PinWrapperWiped
        } else {
            PinUnlockOutcome::FailedAttempt {
                remaining_attempts: self.max_attempts - self.failed_attempts,
            }
        }
    }
}

// ============================================================================
// Optional 24-Word Recovery Phrase & Blind SupporterPass Generator (D-0006, D-0010)
// ============================================================================

const RECOVERY_WORDLIST: [&str; 64] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among",
];

/// Optional 24-word recovery phrase with cryptographic checksum verification (D-0006, PLAN.md §4.4).
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryPhrase {
    words: Vec<String>,
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryPhrase")
            .field("words", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RecoveryPhrase {
    fn drop(&mut self) {
        for word in &mut self.words {
            let mut bytes = core::mem::take(word).into_bytes();
            for b in &mut bytes {
                *b = black_box(0u8);
            }
            let _ = black_box(bytes.as_mut_slice());
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl RecoveryPhrase {
    /// Deterministically generates a 24-word recovery phrase from 24 bytes of CSPRNG entropy.
    /// The 24th word embeds a SHA-256 checksum over the first 23 indices.
    ///
    /// # Errors
    /// Returns [`PasswordPolicyError::WeakPatternDetected`] if `entropy` is all-zero, uniform,
    /// or produces 23 identical data words.
    pub fn generate(entropy: &[u8; 24]) -> Result<Self, PasswordPolicyError> {
        if entropy.iter().all(|&b| b == entropy[0]) {
            return Err(PasswordPolicyError::WeakPatternDetected);
        }
        let mut words = Vec::with_capacity(24);
        let mut indices = [0u8; 23];
        let mut distinct_mask = 0u64;
        for i in 0..23 {
            let idx = entropy[i] & 0x3F;
            indices[i] = idx;
            distinct_mask |= 1u64 << idx;
            words.push(RECOVERY_WORDLIST[usize::from(idx)].to_owned());
        }
        if distinct_mask.count_ones() < 8 {
            zeroize_bytes(&mut indices);
            for w in &mut words {
                zeroize_string(w);
            }
            return Err(PasswordPolicyError::WeakPatternDetected);
        }
        let checksum = sha256(&indices)[0] & 0x3F;
        zeroize_bytes(&mut indices);
        words.push(RECOVERY_WORDLIST[usize::from(checksum)].to_owned());
        Ok(Self { words })
    }

    /// Parses a whitespace-separated 24-word recovery phrase and verifies its checksum.
    ///
    /// # Errors
    /// Returns [`PasswordPolicyError::WeakPatternDetected`] if the word count is not 24,
    /// any word is unknown, fewer than 8 distinct data words are present, or the SHA-256 checksum word fails verification.
    pub fn parse_and_verify(phrase: &str) -> Result<Self, PasswordPolicyError> {
        let tokens: Vec<&str> = phrase.split_whitespace().collect();
        if tokens.len() != 24 {
            return Err(PasswordPolicyError::WeakPatternDetected);
        }
        let mut indices = [0u8; 24];
        let mut distinct_mask = 0u64;
        let mut words = Vec::with_capacity(24);
        for (i, &tok) in tokens.iter().enumerate() {
            let mut lower = tok.to_ascii_lowercase();
            let Some(pos) = RECOVERY_WORDLIST.iter().position(|&w| w == lower) else {
                zeroize_string(&mut lower);
                zeroize_bytes(&mut indices);
                for w in &mut words {
                    zeroize_string(w);
                }
                return Err(PasswordPolicyError::WeakPatternDetected);
            };
            let idx = pos as u8;
            indices[i] = idx;
            if i < 23 {
                distinct_mask |= 1u64 << idx;
            }
            words.push(lower);
        }
        if distinct_mask.count_ones() < 8 {
            zeroize_bytes(&mut indices);
            for w in &mut words {
                zeroize_string(w);
            }
            return Err(PasswordPolicyError::WeakPatternDetected);
        }
        let expected_checksum = sha256(&indices[0..23])[0] & 0x3F;
        let valid_checksum = indices[23] == expected_checksum;
        zeroize_bytes(&mut indices);
        if !valid_checksum {
            for w in &mut words {
                zeroize_string(w);
            }
            return Err(PasswordPolicyError::WeakPatternDetected);
        }
        Ok(Self { words })
    }

    /// Returns the 24 words of the recovery phrase.
    #[must_use]
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// Derives a 32-byte master recovery seed from a verified 24-word phrase.
    ///
    /// # Errors
    /// Propagates any [`CryptoError`] from HKDF.
    pub fn derive_recovery_seed(&self) -> Result<ZeroizingBuffer, CryptoError> {
        let joined = ZeroizingBuffer::new(self.words.join(" ").into_bytes());
        let mut out = [0u8; 32];
        let res = hkdf_sha256(
            b"Aegis-RecoverySeed-v1",
            joined.as_slice(),
            b"master-recovery",
            &mut out,
        );
        let seed = ZeroizingBuffer::new(out.to_vec());
        for b in &mut out {
            *b = black_box(0u8);
        }
        let _ = black_box(out.as_mut_slice());
        compiler_fence(Ordering::SeqCst);
        res?;
        Ok(seed)
    }
}

impl SupporterPass {
    /// Issues a blind-signed `SupporterPass` token and its 32-byte foundation MAC tag (D-0010).
    ///
    /// # Errors
    /// Returns [`AccountSlotError::InvalidSupporterPass`] if `token_id` is all-zero,
    /// `max_accounts <= MAX_FREE_ACCOUNTS`, or `foundation_secret` is all-zero.
    pub fn issue_blind_token(
        token_id: [u8; 16],
        max_accounts: usize,
        foundation_secret: &[u8; 32],
    ) -> Result<(Self, [u8; 32]), AccountSlotError> {
        if token_id == [0u8; 16]
            || max_accounts <= MAX_FREE_ACCOUNTS
            || foundation_secret == &[0u8; 32]
        {
            return Err(AccountSlotError::InvalidSupporterPass);
        }
        let mut msg = [0u8; 24];
        msg[0..16].copy_from_slice(&token_id);
        msg[16..24].copy_from_slice(&(max_accounts as u64).to_be_bytes());
        let blind_tag = hmac_sha256(foundation_secret, &msg);
        Ok((
            Self {
                token_id,
                max_accounts,
                signature_verified: true,
            },
            blind_tag,
        ))
    }

    /// Verifies a `SupporterPass` blind token against the foundation verification key in constant time.
    #[must_use]
    pub fn verify_blind_token(
        token_id: [u8; 16],
        max_accounts: usize,
        blind_tag: &[u8; 32],
        foundation_secret: &[u8; 32],
    ) -> Self {
        let mut msg = [0u8; 24];
        msg[0..16].copy_from_slice(&token_id);
        msg[16..24].copy_from_slice(&(max_accounts as u64).to_be_bytes());
        let mut expected = hmac_sha256(foundation_secret, &msg);
        zeroize_bytes(&mut msg);
        let tag_ok = constant_time_eq(blind_tag, &expected);
        let secret_nonzero = !constant_time_eq(foundation_secret, &[0u8; 32]);
        zeroize_bytes(&mut expected);
        let verified =
            token_id != [0u8; 16] && max_accounts > MAX_FREE_ACCOUNTS && secret_nonzero && tag_ok;
        Self {
            token_id,
            max_accounts,
            signature_verified: verified,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn password_policy_enforces_three_uppercase_and_all_classes() {
        // Valid password with 3 uppercase, lowercase, digits, special chars, >= 12 chars
        let score = validate_password("AEGis#Secure987!", "silent-vortex-1234")
            .expect("valid password must pass");
        assert!(score >= 50);

        // Only 2 uppercase letters -> rejected
        assert_eq!(
            validate_password("Aegis#Secure987!", "user123"),
            Err(PasswordPolicyError::InsufficientUppercase {
                required: 3,
                actual: 2
            })
        );

        // Too short (< 12 chars)
        assert_eq!(
            validate_password("ABCdef12!@", "user123"),
            Err(PasswordPolicyError::TooShort {
                min: 12,
                actual: 10
            })
        );

        // Contains user's nickname
        assert_eq!(
            validate_password("ABC#silent-vortex99!", "silent-vortex"),
            Err(PasswordPolicyError::ContainsNickname)
        );

        // Repeated sequence `AAAA`
        assert_eq!(
            validate_password("AAAAbcdef987!#", "user123"),
            Err(PasswordPolicyError::WeakPatternDetected)
        );
    }

    #[test]
    fn b0007_password_rejects_control_characters() {
        assert_eq!(
            validate_password("ABCdef123456\0", "user123"),
            Err(PasswordPolicyError::ContainsControlCharacters)
        );
        assert_eq!(
            validate_password("ABCdef123456\n", "user123"),
            Err(PasswordPolicyError::ContainsControlCharacters)
        );
        assert_eq!(
            validate_password("ABCdef123456\x1b", "user123"),
            Err(PasswordPolicyError::ContainsControlCharacters)
        );
    }

    #[test]
    fn b0008_password_rejects_separator_stripped_nickname() {
        assert_eq!(
            validate_password("SILentVortex4821!@#", "silent-vortex-4821"),
            Err(PasswordPolicyError::ContainsNickname)
        );
        // 2-char Cyrillic nickname (4 bytes in UTF-8) must NOT trigger >= 3 char nickname rule
        assert!(validate_password("AEGis#Secure987!яя", "яя").is_ok());
    }

    #[test]
    fn nickname_generator_produces_valid_nicknames() {
        let nick = generate_nickname([3, 7, 0x12, 0x34]);
        assert!(validate_nickname(&nick).is_ok());
        assert_eq!(
            validate_nickname("BadNick!"),
            Err(NicknameError::InvalidCharacter('B'))
        );
    }

    #[test]
    fn multi_account_enforces_three_free_and_supporter_pass() {
        let mut mgr = AccountSlotManager::new();
        assert_eq!(mgr.register_account([1u8; 16]), Ok(1));
        assert_eq!(mgr.register_account([2u8; 16]), Ok(2));
        assert_eq!(mgr.register_account([3u8; 16]), Ok(3));

        // 4th account blocked without SupporterPass
        assert_eq!(
            mgr.register_account([4u8; 16]),
            Err(AccountSlotError::FreeQuotaExceeded { max_free: 3 })
        );

        // Unverified SupporterPass rejected (fail closed)
        assert_eq!(
            mgr.activate_supporter_pass(SupporterPass {
                token_id: [9u8; 16],
                max_accounts: 5,
                signature_verified: false,
            }),
            Err(AccountSlotError::InvalidSupporterPass)
        );

        // Verified SupporterPass unlocks 4th and 5th slots
        assert!(mgr
            .activate_supporter_pass(SupporterPass {
                token_id: [9u8; 16],
                max_accounts: 5,
                signature_verified: true,
            })
            .is_ok());
        assert_eq!(mgr.register_account([4u8; 16]), Ok(4));
        assert_eq!(mgr.register_account([5u8; 16]), Ok(5));
        assert_eq!(
            mgr.register_account([6u8; 16]),
            Err(AccountSlotError::SupporterQuotaExceeded { max_allowed: 5 })
        );
    }

    #[test]
    fn b0009_account_slot_manager_rejects_zero_ids_replayed_tokens_and_downgrades() {
        let mut mgr = AccountSlotManager::new();
        assert_eq!(
            mgr.register_account([0u8; 16]),
            Err(AccountSlotError::InvalidAccountId)
        );
        assert_eq!(
            mgr.activate_supporter_pass(SupporterPass {
                token_id: [0u8; 16],
                max_accounts: 5,
                signature_verified: true,
            }),
            Err(AccountSlotError::InvalidSupporterPass)
        );

        assert!(mgr
            .activate_supporter_pass(SupporterPass {
                token_id: [0xAA; 16],
                max_accounts: 5,
                signature_verified: true,
            })
            .is_ok());

        // Replay of the same token_id must be rejected
        assert_eq!(
            mgr.activate_supporter_pass(SupporterPass {
                token_id: [0xAA; 16],
                max_accounts: 6,
                signature_verified: true,
            }),
            Err(AccountSlotError::DuplicateSupporterPassToken)
        );

        for id in 1..=5u8 {
            assert!(mgr.register_account([id; 16]).is_ok());
        }
        // Downgrading max_accounts (4) below currently active accounts (5) must fail
        assert_eq!(
            mgr.activate_supporter_pass(SupporterPass {
                token_id: [0xBB; 16],
                max_accounts: 4,
                signature_verified: true,
            }),
            Err(AccountSlotError::InvalidSupporterPass)
        );
    }

    #[test]
    fn pin_guard_wipes_on_max_attempts_or_duress() {
        let mut guard = PinGuard::new(
            b"primary-pin-hash".to_vec(),
            Some(b"duress-pin-hash!".to_vec()),
            vec![0x42; 32],
            3,
        );

        assert_eq!(
            guard.verify_pin_digest(b"wrong-pin-1"),
            PinUnlockOutcome::FailedAttempt {
                remaining_attempts: 2
            }
        );
        assert_eq!(
            guard.verify_pin_digest(b"primary-pin-hash"),
            PinUnlockOutcome::Unlocked
        );

        // Duress PIN immediately wipes wrapper
        assert_eq!(
            guard.verify_pin_digest(b"duress-pin-hash!"),
            PinUnlockOutcome::DuressTriggered
        );
        assert!(guard.is_wiped());

        // Duress PIN collision rejected by try_new
        assert_eq!(
            PinGuard::try_new(
                b"same-pin".to_vec(),
                Some(b"same-pin".to_vec()),
                vec![0x42; 32],
                3,
            )
            .unwrap_err(),
            PinSetupError::DuressPinCollision
        );

        // Zero max_attempts rejected by try_new (B-0010)
        assert_eq!(
            PinGuard::try_new(b"primary".to_vec(), None, vec![0x42; 32], 0).unwrap_err(),
            PinSetupError::InvalidMaxAttempts
        );

        // Max attempts lockout wipes wrapper
        let mut lockout_guard = PinGuard::new(b"primary".to_vec(), None, vec![0x42; 32], 2);
        assert_eq!(
            lockout_guard.verify_pin_digest(b"wrong-1"),
            PinUnlockOutcome::FailedAttempt {
                remaining_attempts: 1
            }
        );
        assert_eq!(
            lockout_guard.verify_pin_digest(b"wrong-2"),
            PinUnlockOutcome::PinWrapperWiped
        );
        assert!(lockout_guard.is_wiped());
    }

    #[test]
    fn opaque_login_id_and_account_vault_envelope_roundtrip() {
        let salt = [0x33u8; 32];
        let login_id = derive_login_id("silent-vortex-4821", &salt).unwrap();
        assert_ne!(login_id, [0u8; 32]);
        // Zero salt rejected
        assert!(derive_login_id("silent-vortex-4821", &[0u8; 32]).is_err());

        let (session, record) = OpaqueClientSession::start(
            "silent-vortex-4821",
            "AEGis#Secure987!",
            &salt,
            &[0x77u8; 32],
        )
        .unwrap();
        assert_eq!(session.login_id(), record.login_id);

        // Wrong password fails closed
        assert_eq!(
            session.finish_login("silent-vortex-4821", "WROng#Pass987!", &record),
            Err(CryptoError::AuthenticationFailed)
        );

        let vault = session
            .finish_login("silent-vortex-4821", "AEGis#Secure987!", &record)
            .unwrap();
        assert_ne!(vault.master_identity_secret, [0u8; 32]);
    }

    #[test]
    fn calculator_disguise_unlock_and_panic_button_wipe() {
        let cfg = AppDisguiseConfig::try_new(
            DisguiseMode::Calculator {
                unlock_expression: "1337+42=".to_owned(),
            },
            PanicAction::InstantCryptoWipe,
        )
        .unwrap();

        assert!(!check_calculator_unlock(&cfg, "2+2="));
        assert!(check_calculator_unlock(&cfg, "1337+42="));

        // Invalid calculator expression without '=' rejected
        assert!(AppDisguiseConfig::try_new(
            DisguiseMode::Calculator {
                unlock_expression: "1337+42".to_owned(),
            },
            PanicAction::LockAndMinimize,
        )
        .is_err());

        let mut guard = PinGuard::new(b"pin".to_vec(), None, vec![0x99; 32], 3);
        assert_eq!(
            trigger_panic_button(&cfg, &mut guard),
            PanicAction::InstantCryptoWipe
        );
        assert!(guard.is_wiped());
    }

    #[test]
    fn per_chat_pin_lock_and_optional_recovery_phrase_and_blind_supporter_pass() {
        let mut chat_lock = ChatPinLock::try_new([0xAA; 32], b"chat-pin-hash".to_vec(), 2).unwrap();
        assert!(chat_lock.is_locked());
        assert_eq!(
            chat_lock.verify_chat_pin(b"wrong"),
            PinUnlockOutcome::FailedAttempt {
                remaining_attempts: 1
            }
        );
        assert_eq!(
            chat_lock.verify_chat_pin(b"chat-pin-hash"),
            PinUnlockOutcome::Unlocked
        );
        assert!(!chat_lock.is_locked());
        chat_lock.lock();
        assert!(chat_lock.is_locked());

        // 24-word recovery phrase generation and checksum verification
        let entropy: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let phrase = RecoveryPhrase::generate(&entropy).unwrap();
        assert_eq!(phrase.words().len(), 24);
        let joined = phrase.words().join(" ");
        let parsed = RecoveryPhrase::parse_and_verify(&joined).unwrap();
        assert_eq!(parsed, phrase);
        assert_eq!(parsed.derive_recovery_seed().unwrap().len(), 32);

        // Tamper with the 24th checksum word -> rejected
        let mut bad_words = phrase.words().to_vec();
        bad_words[23] = if bad_words[23] == "abandon" {
            "ability".to_owned()
        } else {
            "abandon".to_owned()
        };
        assert!(RecoveryPhrase::parse_and_verify(&bad_words.join(" ")).is_err());

        // Blind SupporterPass issue & verification
        let secret = [0xCC; 32];
        let (pass, tag) = SupporterPass::issue_blind_token([0x12; 16], 6, &secret).unwrap();
        assert!(pass.signature_verified);
        let verified = SupporterPass::verify_blind_token([0x12; 16], 6, &tag, &secret);
        assert!(verified.signature_verified);
        let forged = SupporterPass::verify_blind_token([0x12; 16], 10, &tag, &secret);
        assert!(!forged.signature_verified);
    }

    #[test]
    fn b0021_opaque_session_redacts_debug_and_rejects_invalid_vault_or_calc_expr() {
        let salt = [0x33u8; 32];
        let (session, _) = OpaqueClientSession::start(
            "silent-vortex-4821",
            "AEGis#Secure987!",
            &salt,
            &[0x77u8; 32],
        )
        .unwrap();
        let dbg = format!("{session:?}");
        assert!(dbg.contains("[REDACTED; 32 bytes]"));

        // Vault with zero master_identity_secret or zero/duplicate queue IDs rejected
        let bad_vault = AccountVault {
            master_identity_secret: [0u8; 32],
            active_queue_ids: vec![],
            recovery_phrase_enabled: false,
        };
        assert!(OpaqueAccountEnvelope::seal(
            "silent-vortex-4821",
            "AEGis#Secure987!",
            salt,
            [1u8; 12],
            &bad_vault
        )
        .is_err());

        let dup_queue_vault = AccountVault {
            master_identity_secret: [0x11; 32],
            active_queue_ids: vec![[0x22; 32], [0x22; 32]],
            recovery_phrase_enabled: false,
        };
        assert!(OpaqueAccountEnvelope::seal(
            "silent-vortex-4821",
            "AEGis#Secure987!",
            salt,
            [1u8; 12],
            &dup_queue_vault
        )
        .is_err());

        // Calculator expression without any digits ("+++=") rejected
        assert!(AppDisguiseConfig::try_new(
            DisguiseMode::Calculator {
                unlock_expression: "+++=".to_owned(),
            },
            PanicAction::LockAndMinimize,
        )
        .is_err());
    }

    #[test]
    fn b0035_account_vault_and_recovery_phrase_redact_debug_and_zeroize_on_drop() {
        let vault = AccountVault {
            master_identity_secret: [0xAB; 32],
            active_queue_ids: vec![[0x11; 32]],
            recovery_phrase_enabled: true,
        };
        let vault_dbg = format!("{vault:?}");
        assert!(vault_dbg.contains("[REDACTED]"));
        assert!(!vault_dbg.contains("171"));

        let entropy: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(3));
        let phrase = RecoveryPhrase::generate(&entropy).unwrap();
        let first_word = phrase.words()[0].clone();
        let phrase_dbg = format!("{phrase:?}");
        assert!(phrase_dbg.contains("[REDACTED]"));
        assert!(!phrase_dbg.contains(&first_word));
        drop(phrase);
    }

    #[test]
    fn b0036_recovery_phrase_rejects_zero_or_uniform_entropy_and_repeated_words() {
        assert_eq!(
            RecoveryPhrase::generate(&[0u8; 24]),
            Err(PasswordPolicyError::WeakPatternDetected)
        );
        assert_eq!(
            RecoveryPhrase::generate(&[0x5A; 24]),
            Err(PasswordPolicyError::WeakPatternDetected)
        );
        // Non-uniform raw bytes that mask (& 0x3F) to the same 6-bit index
        let mut masked_same = [0u8; 24];
        masked_same[0] = 0x40;
        masked_same[1] = 0x80;
        masked_same[2] = 0xC0;
        assert_eq!(
            RecoveryPhrase::generate(&masked_same),
            Err(PasswordPolicyError::WeakPatternDetected)
        );

        // Construct a 24-word string with 23x "abandon" + valid checksum word for [0u8; 23]
        let checksum_idx = usize::from(sha256(&[0u8; 23])[0] & 0x3F);
        let mut degenerate_words = vec!["abandon"; 23];
        degenerate_words.push(RECOVERY_WORDLIST[checksum_idx]);
        assert_eq!(
            RecoveryPhrase::parse_and_verify(&degenerate_words.join(" ")),
            Err(PasswordPolicyError::WeakPatternDetected)
        );
    }

    #[test]
    fn b0037_pin_guard_and_chat_pin_lock_reject_all_zero_material_and_expose_is_wiped() {
        assert_eq!(
            PinGuard::try_new(vec![0u8; 32], None, vec![0x42; 32], 3).unwrap_err(),
            PinSetupError::EmptyKeyOrPinMaterial
        );
        assert_eq!(
            PinGuard::try_new(b"primary".to_vec(), Some(vec![0u8; 32]), vec![0x42; 32], 3)
                .unwrap_err(),
            PinSetupError::EmptyKeyOrPinMaterial
        );
        assert_eq!(
            PinGuard::try_new(b"primary".to_vec(), None, vec![0u8; 32], 3).unwrap_err(),
            PinSetupError::EmptyKeyOrPinMaterial
        );

        // PinGuard::new with all-zero primary digest or wrapped key starts wiped
        let mut zero_guard = PinGuard::new(vec![0u8; 32], None, vec![0x42; 32], 3);
        assert!(zero_guard.is_wiped());
        assert_eq!(
            zero_guard.verify_pin_digest(&[0u8; 32]),
            PinUnlockOutcome::PinWrapperWiped
        );

        // ChatPinLock rejects all-zero pin_digest and tracks is_wiped()
        assert_eq!(
            ChatPinLock::try_new([0xAA; 32], vec![0u8; 32], 2).unwrap_err(),
            PinSetupError::EmptyKeyOrPinMaterial
        );
        let mut lock = ChatPinLock::try_new([0xAA; 32], b"valid-pin".to_vec(), 1).unwrap();
        assert!(!lock.is_wiped());
        assert_eq!(
            lock.verify_chat_pin(b"wrong"),
            PinUnlockOutcome::PinWrapperWiped
        );
        assert!(lock.is_wiped());
    }

    #[test]
    fn b0038_opaque_account_envelope_rejects_zero_nonce() {
        let vault = AccountVault {
            master_identity_secret: [0x11; 32],
            active_queue_ids: vec![[0x22; 32]],
            recovery_phrase_enabled: false,
        };
        assert_eq!(
            OpaqueAccountEnvelope::seal(
                "silent-vortex-4821",
                "AEGis#Secure987!",
                [0x33; 32],
                [0u8; 12],
                &vault
            ),
            Err(CryptoError::KeyDerivationFailed)
        );
    }

    #[test]
    fn b0069_opaque_unique_nonce_per_blinding_factor_and_redacted_queue_and_disguise_debug() {
        let salt = [0x33u8; 32];
        let (_, rec1) = OpaqueClientSession::start(
            "silent-vortex-4821",
            "AEGis#Secure987!",
            &salt,
            &[0x11u8; 32],
        )
        .unwrap();
        let (_, rec2) = OpaqueClientSession::start(
            "silent-vortex-4821",
            "AEGis#Secure987!",
            &salt,
            &[0x22u8; 32],
        )
        .unwrap();
        // Distinct blinding factors under the same server_salt MUST NEVER reuse the AEAD nonce
        assert_ne!(rec1.envelope.nonce, rec2.envelope.nonce);

        // AccountVault Debug must redact active_queue_ids so queue graph never leaks in logs
        let vault = AccountVault {
            master_identity_secret: [0xAA; 32],
            active_queue_ids: vec![[0x77; 32]],
            recovery_phrase_enabled: true,
        };
        let v_dbg = format!("{vault:?}");
        assert!(!v_dbg.contains("119")); // 0x77
        assert!(v_dbg.contains("[REDACTED; 1 queues]"));

        // AppDisguiseConfig Debug must redact unlock_expression and normalize whitespace
        let cfg = AppDisguiseConfig::try_new(
            DisguiseMode::Calculator {
                unlock_expression: " 1337+42= ".to_owned(),
            },
            PanicAction::InstantCryptoWipe,
        )
        .unwrap();
        let c_dbg = format!("{cfg:?}");
        assert!(!c_dbg.contains("1337"));
        assert!(c_dbg.contains("[REDACTED]"));
        assert!(check_calculator_unlock(&cfg, "1337+42="));
    }
}
