//! `aegis-ffi` — Unified FFI/UniFFI boundary for UI platforms (`AGENTS.md §4`).
//! UI layers (`aegis-ui-android`, `aegis-ui-desktop`, `aegis-ui-ios`) communicate exclusively
//! through this crate and never touch cryptographic internals or keys directly (`AGENTS.md §2.6`).

pub use aegis_crypto::{
    combine_pqxdh_secrets, constant_time_eq, memory_hard_kdf_sha256, solve_pow, x25519,
    x25519_basepoint, CryptoError, DeterministicPowVerifier, PowChallenge, PowSolution,
    PowVerifier, RatchetHeader, RatchetSession, CRYPTO_SUITE_VERSION,
};
pub use aegis_directory::{
    verify_server_badge, verify_support_certificate, verify_threshold_attestations,
    BuiltInDirectory, DirectoryError, DirectoryServerEntry, ServerBadge, SignerAttestation,
    SupportCertificate, ThresholdPolicy,
};
pub use aegis_identity::{
    check_calculator_unlock, derive_login_id, generate_nickname, trigger_panic_button,
    validate_nickname, validate_password, AccountSlotError, AccountSlotManager, AccountVault,
    AppDisguiseConfig, ChatPinLock, DisguiseMode, NicknameError, OpaqueAccountEnvelope,
    OpaqueClientSession, OpaqueRegistrationRecord, PanicAction, PasswordPolicyError, PinGuard,
    PinSetupError, PinUnlockOutcome, RecoveryPhrase, SupporterPass,
};
pub use aegis_launcher::{
    build_launch_plan, format_server_invite_uri, generate_cloud_init_script,
    generate_docker_compose, generate_static_ip_vps_script, generate_torrc_hidden_service,
    validate_launch_config, LaunchPlan, LaunchTarget, LauncherError, ServerLaunchPlan,
};
pub use aegis_plugins::{
    validate_manifest, BotBridgeConfig, BotBridgeDescriptor, BuiltInThemes, PluginError,
    PluginManifest, ThemePack,
};
pub use aegis_protocol::{
    compute_inbox_auth_hash, compute_safety_number, derive_channel_key_and_queue,
    derive_queue_read_token, detect_identity_key_change, hex_decode_bytes, hex_encode_bytes,
    normalize_channel_code, open_cross_border_capsule, open_view_once_payload, pad_frame,
    passes_luhn, redact_leaks, scan_message_for_leaks, seal_cross_border_capsule,
    strip_media_metadata, unpad_frame, ChatMessageEnvelope, CleanedMedia, ContactInvite,
    GroupChatSession, KeyChangeWarning, LeakKind, LeakWarning, MessageContent,
    MessageExpirationPolicy, ProtocolError, SealedSenderEnvelope, SupportTicket,
    SupportTicketCategory, UnsealedSenderMessage, ViewOncePayload, CHANNEL_KDF_ROUNDS,
    CROSS_BORDER_CAPSULE_MAGIC, PADDING_BUCKETS, PROTOCOL_VERSION,
};
pub use aegis_server::{
    compute_pow_difficulty, handle_http_request, render_support_portal_html, seal_tunnel_request,
    BlindSupporterPassGrant, FederationServerState, QueueQuota, ServerError, SupportPortalState,
};
pub use aegis_storage::{
    EncryptedNote, EncryptedStoreHeader, EncryptedVaultDb, StorageError, StoredContact,
    StoredMessage, BACKUP_MAGIC, DB_KEY_LEN, SCHEMA_VERSION,
};
pub use aegis_transport::{
    connect_via_socks5h, derive_circuit_isolation_token, evaluate_network_shield,
    format_static_ipv4_endpoint, poll_capsules_over_tcp, poll_capsules_via_blind_relay,
    poll_capsules_via_multihop_chain, poll_capsules_via_socks5, send_capsule_over_tcp,
    send_capsule_via_blind_relay, send_capsule_via_multihop_chain, send_capsule_via_socks5,
    CoverTrafficConfig, CoverTrafficScheduler, IsolatedCircuitTag, NetworkRouteStatus, ProxyConfig,
    RouteProbe, ServerMigrationNotice, ShieldEvaluation, TransportError, TransportProfile,
};

use core::fmt;
use core::hint::black_box;
use core::sync::atomic::{compiler_fence, Ordering};

fn zeroize_string(s: &mut String) {
    let mut bytes = core::mem::take(s).into_bytes();
    let cap = bytes.capacity();
    bytes.resize(cap, 0u8);
    for b in &mut bytes {
        *b = black_box(0u8);
    }
    let _ = black_box(bytes.as_mut_slice());
    compiler_fence(Ordering::SeqCst);
}

/// Supported UI languages at launch (D-0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    /// Russian (`RU`).
    Ru,
    /// English (`EN`).
    En,
}

/// High-level core version snapshot exposed to UI clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreVersionInfo {
    /// Cryptographic suite version (`aegis-crypto`).
    pub crypto_suite_version: u16,
    /// Wire protocol version (`aegis-protocol`).
    pub protocol_version: u16,
    /// Local storage schema version (`aegis-storage`).
    pub storage_schema_version: u32,
}

/// Returns the version numbers of all core subsystems.
#[must_use]
pub fn core_version_info() -> CoreVersionInfo {
    CoreVersionInfo {
        crypto_suite_version: aegis_crypto::CRYPTO_SUITE_VERSION,
        protocol_version: aegis_protocol::PROTOCOL_VERSION,
        storage_schema_version: aegis_storage::SCHEMA_VERSION,
    }
}

/// High-level unified client core facade (`AegisClientCore`) for Desktop and Android UIs (`AGENTS.md §4`).
/// Coordinates multi-account slots, Network Anonymity Shield, cover traffic, themes,
/// LeakGuard DLP scanning, and built-in directory verification without exposing raw cryptographic keys.
#[derive(Clone)]
pub struct AegisClientCore {
    locale: Locale,
    active_theme: ThemePack,
    account_slots: AccountSlotManager,
    directory: BuiltInDirectory,
    cover_scheduler: CoverTrafficScheduler,
    active_nickname: Option<String>,
    registered_nicknames: Vec<String>,
}

impl fmt::Debug for AegisClientCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AegisClientCore")
            .field("locale", &self.locale)
            .field("active_theme", &self.active_theme.theme_id)
            .field("active_nickname", &"[REDACTED]")
            .field(
                "registered_accounts_count",
                &self.registered_nicknames.len(),
            )
            .finish()
    }
}

impl Drop for AegisClientCore {
    fn drop(&mut self) {
        self.trigger_panic_wipe();
    }
}

impl Default for AegisClientCore {
    fn default() -> Self {
        Self::new(Locale::Ru)
    }
}

impl AegisClientCore {
    /// Creates a new `AegisClientCore` facade initialized with secure defaults.
    #[must_use]
    pub fn new(locale: Locale) -> Self {
        Self {
            locale,
            active_theme: ThemePack::from_builtin(BuiltInThemes::ObsidianDark),
            account_slots: AccountSlotManager::new(),
            directory: BuiltInDirectory::embedded_catalog(),
            cover_scheduler: CoverTrafficScheduler::default_scheduler(),
            active_nickname: None,
            registered_nicknames: Vec::new(),
        }
    }

    /// Returns the active UI locale.
    #[must_use]
    pub fn locale(&self) -> Locale {
        self.locale
    }

    /// Switches the active UI locale (`Ru` / `En`).
    pub fn set_locale(&mut self, locale: Locale) {
        self.locale = locale;
    }

    /// Applies a built-in theme preset (including `CalculatorStealth` app disguise).
    pub fn set_builtin_theme(&mut self, preset: BuiltInThemes) {
        self.active_theme = ThemePack::from_builtin(preset);
    }

    /// Returns the currently active declarative [`ThemePack`].
    #[must_use]
    pub fn active_theme(&self) -> &ThemePack {
        &self.active_theme
    }

    /// Registers a new local account profile on this device (enforcing the 3-free + `SupporterPass` limit).
    ///
    /// # Errors
    /// Returns [`AccountSlotError`] if the nickname is invalid, the free quota is exceeded, or the account ID is invalid.
    pub fn register_local_account(
        &mut self,
        account_id: [u8; 16],
        login_nickname: &str,
    ) -> Result<usize, AccountSlotError> {
        let mut normalized = login_nickname.trim().to_ascii_lowercase();
        if validate_nickname(&normalized).is_err() {
            zeroize_string(&mut normalized);
            return Err(AccountSlotError::InvalidAccountId);
        }
        if self.registered_nicknames.contains(&normalized) {
            zeroize_string(&mut normalized);
            return Err(AccountSlotError::DuplicateAccountId);
        }
        let count = match self.account_slots.register_account(account_id) {
            Ok(c) => c,
            Err(err) => {
                zeroize_string(&mut normalized);
                return Err(err);
            }
        };
        if let Some(prev) = &mut self.active_nickname {
            zeroize_string(prev);
        }
        self.registered_nicknames.push(normalized.clone());
        self.active_nickname = Some(normalized);
        Ok(count)
    }

    /// Unlocks 4+ multi-account slots using a blind-signed [`SupporterPass`].
    ///
    /// # Errors
    /// Fail-closed: rejects unverified or replayed passes.
    pub fn activate_supporter_pass(&mut self, pass: SupporterPass) -> Result<(), AccountSlotError> {
        self.account_slots.activate_supporter_pass(pass)
    }

    /// Scans an outgoing plaintext message with `LeakGuard` across all local account nicknames on this device.
    #[must_use]
    pub fn scan_outgoing_message(&self, message: &str) -> Vec<LeakWarning> {
        if self.registered_nicknames.is_empty() {
            return scan_message_for_leaks(message, self.active_nickname.as_deref());
        }
        let mut combined = scan_message_for_leaks(message, None);
        for nick in &self.registered_nicknames {
            for w in scan_message_for_leaks(message, Some(nick.as_str())) {
                if !combined.contains(&w) {
                    combined.push(w);
                }
            }
        }
        combined
    }

    /// Immediately zeroizes all in-memory nicknames and resets account slot state on emergency panic wipe.
    pub fn trigger_panic_wipe(&mut self) {
        if let Some(nick) = &mut self.active_nickname {
            zeroize_string(nick);
        }
        self.active_nickname = None;
        for nick in &mut self.registered_nicknames {
            zeroize_string(nick);
        }
        self.registered_nicknames.clear();
        self.account_slots = AccountSlotManager::new();
        self.active_theme = ThemePack::from_builtin(BuiltInThemes::ObsidianDark);
        self.cover_scheduler = CoverTrafficScheduler::default_scheduler();
    }

    /// Polls the background cover traffic scheduler at `now_ms`.
    pub fn poll_cover_traffic(&mut self, now_ms: u64, jitter_seed: u64) -> Option<Vec<u8>> {
        self.cover_scheduler.poll_cover_frame(now_ms, jitter_seed)
    }

    /// Returns the verified server entries from the embedded directory.
    #[must_use]
    pub fn verified_directory_servers(&self) -> Vec<&DirectoryServerEntry> {
        self.directory.verified_entries()
    }

    /// Returns the verified direct static-IPv4 starter servers (no Tor required, D-0019).
    #[must_use]
    pub fn direct_static_ip_servers(&self) -> Vec<&DirectoryServerEntry> {
        self.directory.direct_static_ip_entries()
    }
}

/// C-ABI / JNI-ready helper: returns the encoded core protocol version (`u32`).
#[must_use]
pub extern "C" fn aegis_ffi_protocol_version() -> u32 {
    u32::from(aegis_protocol::PROTOCOL_VERSION)
}

/// C-ABI / JNI-ready helper: returns the number of sensitive leaks detected by `LeakGuard` in a UTF-8 buffer.
/// Fail-closed (`AGENTS.md §2.5`): returns `usize::MAX` if `utf8_bytes` or `own_nick_utf8` contains invalid UTF-8.
/// Never panics and never uses `unsafe` code (`#[forbid(unsafe_code)]`).
#[must_use]
pub fn aegis_ffi_scan_utf8_leak_count(utf8_bytes: &[u8], own_nick_utf8: Option<&[u8]>) -> usize {
    let Ok(msg) = core::str::from_utf8(utf8_bytes) else {
        return usize::MAX;
    };
    let nick = match own_nick_utf8 {
        Some(b) => match core::str::from_utf8(b) {
            Ok(s) => Some(s),
            Err(_) => return usize::MAX,
        },
        None => None,
    };
    scan_message_for_leaks(msg, nick).len()
}

/// C-ABI / JNI-ready helper: renders the self-contained Support & Donation Web Portal HTML for Android/Desktop WebViews.
#[must_use]
pub fn aegis_ffi_render_support_portal(locale: Locale) -> String {
    match locale {
        Locale::Ru => render_support_portal_html("ru"),
        Locale::En => render_support_portal_html("en"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ffi_exposes_consistent_core_versions() {
        let info = core_version_info();
        assert_eq!(info.crypto_suite_version, 1);
        assert_eq!(info.protocol_version, 1);
        assert_eq!(info.storage_schema_version, 1);
        assert_eq!(aegis_ffi_protocol_version(), 1);
    }

    #[test]
    fn b0019_ffi_reexports_all_subsystem_validators() {
        assert!(validate_launch_config(LaunchTarget::VpsDocker, 8443, 30).is_ok());
        assert_eq!(compute_pow_difficulty(10, false), 12);
    }

    #[test]
    fn aegis_client_core_facade_integrates_all_subsystems() {
        let mut client = AegisClientCore::new(Locale::Ru);
        assert_eq!(client.locale(), Locale::Ru);
        assert_eq!(client.verified_directory_servers().len(), 4);
        assert_eq!(client.direct_static_ip_servers().len(), 3);

        // Switch theme to CalculatorStealth
        client.set_builtin_theme(BuiltInThemes::CalculatorStealth);
        assert!(client.active_theme().stealth_calculator_disguise);

        // Register account and verify LeakGuard catches own nickname
        assert_eq!(
            client.register_local_account([0x01; 16], "silent-vortex-4821"),
            Ok(1)
        );
        let leaks = client.scan_outgoing_message("My login is silent-vortex-4821");
        assert_eq!(leaks.len(), 1);

        // Cover traffic via facade
        let dummy = client
            .poll_cover_traffic(20_000, 77)
            .expect("must emit cover frame");
        assert_eq!(dummy.len(), 256);

        // JNI/C-ABI helpers
        assert_eq!(
            aegis_ffi_scan_utf8_leak_count(b"Contact alice@proton.me", Some(b"silent-vortex-4821")),
            1
        );
        assert!(aegis_ffi_render_support_portal(Locale::En).contains("SupporterPass"));

        // B-0029: Reject invalid login_nickname before consuming an account slot
        assert_eq!(
            client.register_local_account([0x02; 16], "Bad Nick!"),
            Err(AccountSlotError::InvalidAccountId)
        );

        // B-0076: Multi-account LeakGuard checks all registered nicknames, rejects duplicate nicknames,
        // redacts Debug, wipes state on panic, and fails closed on invalid UTF-8
        assert_eq!(
            client.register_local_account([0x02; 16], "silent-vortex-4821"),
            Err(AccountSlotError::DuplicateAccountId)
        );
        assert_eq!(
            client.register_local_account([0x02; 16], "frosty-falcon-9001"),
            Ok(2)
        );
        // Both first and second account nicknames must be caught by LeakGuard!
        assert_eq!(
            client
                .scan_outgoing_message(
                    "first nick silent-vortex-4821 and second frosty-falcon-9001"
                )
                .len(),
            2
        );
        let ffi_dbg = format!("{client:?}");
        assert!(!ffi_dbg.contains("silent-vortex-4821"));
        assert!(ffi_dbg.contains("[REDACTED]"));

        assert_eq!(
            aegis_ffi_scan_utf8_leak_count(&[0xFF, 0xFE], None),
            usize::MAX
        );
        assert_eq!(
            aegis_ffi_scan_utf8_leak_count(b"hello", Some(&[0xFF, 0xFE])),
            usize::MAX
        );

        client.trigger_panic_wipe();
        assert!(client
            .scan_outgoing_message("silent-vortex-4821")
            .is_empty());
    }
}
