//! `aegis-ffi` — Unified FFI/UniFFI boundary for UI platforms (`AGENTS.md §4`).
//! UI layers (`aegis-ui-android`, `aegis-ui-desktop`, `aegis-ui-ios`) communicate exclusively
//! through this crate and never touch cryptographic internals or keys directly (`AGENTS.md §2.6`).

pub use aegis_calls::{
    adapt_call_bitrate, anonymize_audio_pcm16, filter_ice_candidate, validate_call_config,
    CallConfig, CallError, CallQualityMetrics, MediaFrameHeader, VoicePitchMode,
};
pub use aegis_crypto::{
    constant_time_eq, solve_pow, CryptoError, DeterministicPowVerifier, PowChallenge, PowSolution,
    CRYPTO_SUITE_VERSION,
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
    compute_safety_number, detect_identity_key_change, open_view_once_payload, pad_frame,
    passes_luhn, redact_leaks, scan_message_for_leaks, strip_media_metadata, unpad_frame,
    ChatMessageEnvelope, CleanedMedia, ContactInvite, GroupChatSession, KeyChangeWarning, LeakKind,
    LeakWarning, MessageContent, MessageExpirationPolicy, ProtocolError, SupportTicket,
    SupportTicketCategory, ViewOncePayload, PADDING_BUCKETS, PROTOCOL_VERSION,
};
pub use aegis_server::{
    compute_pow_difficulty, handle_http_request, render_support_portal_html,
    BlindSupporterPassGrant, FederationServerState, QueueQuota, ServerError, SupportPortalState,
};
pub use aegis_storage::{
    EncryptedNote, EncryptedStoreHeader, EncryptedVaultDb, StorageError, StoredContact,
    StoredMessage, BACKUP_MAGIC, DB_KEY_LEN, SCHEMA_VERSION,
};
pub use aegis_transport::{
    evaluate_network_shield, format_static_ipv4_endpoint, CoverTrafficConfig,
    CoverTrafficScheduler, NetworkRouteStatus, ProxyConfig, RouteProbe, ServerMigrationNotice,
    ShieldEvaluation, TransportError, TransportProfile,
};

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
/// Coordinates multi-account slots, Network Anonymity Shield, cover traffic, themes, voice anonymization,
/// LeakGuard DLP scanning, and built-in directory verification without exposing raw cryptographic keys.
#[derive(Debug, Clone)]
pub struct AegisClientCore {
    locale: Locale,
    active_theme: ThemePack,
    voice_pitch_mode: VoicePitchMode,
    call_config: CallConfig,
    account_slots: AccountSlotManager,
    directory: BuiltInDirectory,
    cover_scheduler: CoverTrafficScheduler,
    active_nickname: Option<String>,
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
            voice_pitch_mode: VoicePitchMode::Natural,
            call_config: CallConfig::default(),
            account_slots: AccountSlotManager::new(),
            directory: BuiltInDirectory::embedded_catalog(),
            cover_scheduler: CoverTrafficScheduler::default_scheduler(),
            active_nickname: None,
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

    /// Configures the voice biometric anonymizer pitch mode for calls and voice notes.
    pub fn set_voice_pitch_mode(&mut self, mode: VoicePitchMode) {
        self.voice_pitch_mode = mode;
    }

    /// Anonymizes 16-bit PCM voice audio using the currently selected [`VoicePitchMode`].
    #[must_use]
    pub fn process_voice_pcm16(&self, samples: &[i16]) -> Vec<i16> {
        anonymize_audio_pcm16(samples, self.voice_pitch_mode)
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
        let normalized = login_nickname.trim().to_ascii_lowercase();
        validate_nickname(&normalized).map_err(|_| AccountSlotError::InvalidAccountId)?;
        let count = self.account_slots.register_account(account_id)?;
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

    /// Scans an outgoing plaintext message with `LeakGuard` (Luhn cards, CVV, phones, emails, own login nick).
    #[must_use]
    pub fn scan_outgoing_message(&self, message: &str) -> Vec<LeakWarning> {
        scan_message_for_leaks(message, self.active_nickname.as_deref())
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

    /// Returns the active [`CallConfig`] (guaranteed `relay_only: true` and `require_e2ee_media: true`).
    #[must_use]
    pub fn call_config(&self) -> &CallConfig {
        &self.call_config
    }
}

/// C-ABI / JNI-ready helper: returns the encoded core protocol version (`u32`).
#[must_use]
pub extern "C" fn aegis_ffi_protocol_version() -> u32 {
    u32::from(aegis_protocol::PROTOCOL_VERSION)
}

/// C-ABI / JNI-ready helper: returns the number of sensitive leaks detected by `LeakGuard` in a UTF-8 buffer.
/// Never panics and never uses `unsafe` code (`#[forbid(unsafe_code)]`).
#[must_use]
pub fn aegis_ffi_scan_utf8_leak_count(utf8_bytes: &[u8], own_nick_utf8: Option<&[u8]>) -> usize {
    let Ok(msg) = core::str::from_utf8(utf8_bytes) else {
        return 0;
    };
    let nick = own_nick_utf8.and_then(|b| core::str::from_utf8(b).ok());
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
        assert!(validate_call_config(&CallConfig::default()).is_ok());
        assert!(validate_launch_config(LaunchTarget::VpsDocker, 8443, 30).is_ok());
        assert_eq!(compute_pow_difficulty(10, false), 12);
    }

    #[test]
    fn aegis_client_core_facade_integrates_all_subsystems() {
        let mut client = AegisClientCore::new(Locale::Ru);
        assert_eq!(client.locale(), Locale::Ru);
        assert_eq!(client.verified_directory_servers().len(), 4);
        assert_eq!(client.direct_static_ip_servers().len(), 3);
        assert!(client.call_config().is_privacy_preserving());

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

        // Voice anonymizer via facade
        client.set_voice_pitch_mode(VoicePitchMode::DeepShadow);
        let pcm = client.process_voice_pcm16(&[1000, -1000, 2000, -2000]);
        assert_eq!(pcm.len(), 4);

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
    }
}
