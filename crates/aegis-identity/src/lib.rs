//! `aegis-identity` — Nickname + password validation (D-0006), anonymous nickname generator,
//! multi-account slot enforcement with `SupporterPass` blind-token quota (D-0010),
//! and hardware-backed PIN lockout state machine with Duress PIN support (PLAN.md §4).

use aegis_crypto::{constant_time_eq, ZeroizingBuffer};
use core::fmt;

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

    let lower_pwd = password.to_lowercase();
    let trimmed_nick = nickname.trim().to_lowercase();
    if trimmed_nick.chars().count() >= 3 && lower_pwd.contains(&trimmed_nick) {
        return Err(PasswordPolicyError::ContainsNickname);
    }

    let stripped_nick: String = trimmed_nick
        .chars()
        .filter(|&c| c != '-' && c != '_' && !c.is_whitespace())
        .collect();
    let stripped_pwd: String = lower_pwd
        .chars()
        .filter(|&c| c != '-' && c != '_' && !c.is_whitespace())
        .collect();
    if stripped_nick.chars().count() >= 3 && stripped_pwd.contains(&stripped_nick) {
        return Err(PasswordPolicyError::ContainsNickname);
    }

    const WEAK_PATTERNS: [&str; 6] = ["qwerty", "123456", "password", "admin", "abcdef", "qwertz"];
    if WEAK_PATTERNS.iter().any(|pat| lower_pwd.contains(pat)) {
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
#[derive(Debug, Default, Clone)]
pub struct AccountSlotManager {
    active_account_ids: Vec<[u8; 16]>,
    redeemed_token_ids: Vec<[u8; 16]>,
    supporter_pass: Option<SupporterPass>,
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
        let sanitized_duress = duress_pin_digest.and_then(|duress| {
            if constant_time_eq(&duress, &primary_pin_digest) || duress.is_empty() {
                None
            } else {
                Some(ZeroizingBuffer::new(duress))
            }
        });
        Self {
            primary_pin_digest: ZeroizingBuffer::new(primary_pin_digest),
            duress_pin_digest: sanitized_duress,
            wrapped_db_key: ZeroizingBuffer::new(wrapped_db_key),
            failed_attempts: 0,
            max_attempts: effective_max,
            wiped: false,
        }
    }

    /// Validated constructor that rejects empty key/PIN material, `max_attempts == 0`,
    /// or a Duress PIN equal to the primary PIN.
    ///
    /// # Errors
    /// Returns [`PinSetupError`] if `primary_pin_digest` or `wrapped_db_key` is empty,
    /// `max_attempts == 0`, or if `duress_pin_digest` matches `primary_pin_digest`.
    pub fn try_new(
        primary_pin_digest: Vec<u8>,
        duress_pin_digest: Option<Vec<u8>>,
        wrapped_db_key: Vec<u8>,
        max_attempts: u8,
    ) -> Result<Self, PinSetupError> {
        if max_attempts == 0 {
            return Err(PinSetupError::InvalidMaxAttempts);
        }
        if primary_pin_digest.is_empty() || wrapped_db_key.is_empty() {
            return Err(PinSetupError::EmptyKeyOrPinMaterial);
        }
        if let Some(duress) = &duress_pin_digest {
            if duress.is_empty() {
                return Err(PinSetupError::EmptyKeyOrPinMaterial);
            }
            if constant_time_eq(duress, &primary_pin_digest) {
                return Err(PinSetupError::DuressPinCollision);
            }
        }
        Ok(Self::new(
            primary_pin_digest,
            duress_pin_digest,
            wrapped_db_key,
            max_attempts,
        ))
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
    pub fn is_wiped(&self) -> bool {
        self.wiped
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
}
