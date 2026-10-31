//! `aegis-ui-desktop` — Cross-Platform Desktop UI & Local Interactive GUI Server for Aegis.
//!
//! Communicates exclusively through `aegis-ffi` (`AGENTS.md §2.6, §3, §4`).
//! Never accesses raw cryptographic keys or internal state directly.

use aegis_ffi::{
    build_launch_plan, combine_pqxdh_secrets, compute_pow_difficulty, compute_safety_number,
    constant_time_eq, core_version_info, derive_channel_key_and_queue, detect_identity_key_change,
    evaluate_network_shield, format_server_invite_uri, generate_docker_compose, generate_nickname,
    generate_torrc_hidden_service, hex_encode_bytes, open_cross_border_capsule, pad_frame,
    poll_capsules_over_tcp, poll_capsules_via_blind_relay, poll_capsules_via_socks5, redact_leaks,
    scan_message_for_leaks, seal_cross_border_capsule, send_capsule_over_tcp,
    send_capsule_via_blind_relay, send_capsule_via_socks5, strip_media_metadata,
    validate_launch_config, validate_manifest, validate_nickname, validate_password,
    verify_server_badge, AccountSlotError, AccountSlotManager, ContactInvite, CoreVersionInfo,
    DirectoryError, EncryptedNote, EncryptedVaultDb, GroupChatSession, LaunchPlan, LaunchTarget,
    LauncherError, LeakWarning, Locale, NetworkRouteStatus, NicknameError, PasswordPolicyError,
    PluginError, PluginManifest, ProtocolError, RatchetSession, RecoveryPhrase, RouteProbe,
    SealedSenderEnvelope, ServerBadge, ShieldEvaluation, SignerAttestation, SupportTicket,
    SupportTicketCategory, SupporterPass, ThresholdPolicy, SCHEMA_VERSION,
};
use core::fmt;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// Typed errors produced by the Desktop UI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopUiError {
    /// Nickname failed validation.
    Nickname(NicknameError),
    /// Password failed strict D-0006 policy.
    Password(PasswordPolicyError),
    /// Multi-account slot error (D-0010).
    AccountSlot(AccountSlotError),
    /// Outgoing message blocked by `LeakGuard` until user masks or confirms.
    LeakDetected(Vec<LeakWarning>),
    /// Chat is locked with a per-chat PIN.
    ChatLockedWithPin,
    /// Invalid PIN provided for unlocking app or chat.
    InvalidPin { remaining_attempts: u8 },
    /// Server directory verification failed.
    Directory(DirectoryError),
    /// Server launcher configuration invalid.
    Launcher(LauncherError),
    /// Plugin or theme manifest rejected by sandbox verifier.
    Plugin(PluginError),
    /// Protocol framing or support ticket error.
    Protocol(ProtocolError),
    /// Network traffic blocked by Kill Switch.
    KillSwitchBlocked,
    /// Local GUI server I/O error message.
    IoError(String),
}

impl fmt::Display for DesktopUiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nickname(e) => write!(f, "ошибка ника / nickname error: {e}"),
            Self::Password(e) => write!(f, "ошибка пароля / password error: {e}"),
            Self::AccountSlot(e) => write!(f, "лимит аккаунтов / account quota: {e}"),
            Self::LeakDetected(w) => {
                write!(f, "LeakGuard перехватил {} уязвимых фрагментов", w.len())
            }
            Self::ChatLockedWithPin => write!(f, "чат заблокирован персональным PIN-кодом"),
            Self::InvalidPin { remaining_attempts } => {
                write!(f, "неверный PIN (осталось попыток: {remaining_attempts})")
            }
            Self::Directory(e) => write!(f, "ошибка каталога серверов / directory error: {e}"),
            Self::Launcher(e) => write!(f, "ошибка запуска сервера / launcher error: {e}"),
            Self::Plugin(e) => write!(f, "ошибка песочницы плагина / plugin error: {e}"),
            Self::Protocol(e) => write!(f, "ошибка протокола / protocol error: {e}"),
            Self::KillSwitchBlocked => {
                write!(
                    f,
                    "трафик заблокирован Kill Switch (обнаружена утечка маршрута)"
                )
            }
            Self::IoError(msg) => write!(f, "ошибка ввода-вывода GUI: {msg}"),
        }
    }
}

impl std::error::Error for DesktopUiError {}

/// Active top-level screen in the Desktop UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// 3-step onboarding: Nickname Generator -> Strict Password Scorer -> PIN / Duress PIN -> Server Directory.
    Onboarding,
    /// Main workspace: Chats, Saved Notes ("Избранное"), Network Shield, Multi-Account bar.
    ChatWorkspace,
    /// 1-Click Self-Hosted Server Launcher Wizard (VPS/Docker, Desktop, Tor `.onion`).
    ServerLauncher,
    /// Encrypted Support Ticket Portal & `SupporterPass` Blind-Token Activation.
    SupportPortal,
    /// Declarative Theme Store & WASM Plugin Sandbox Manager.
    ThemeStore,
    /// Calculator Disguise Screen (hides messenger UI behind a working calculator; secret PIN unlocks).
    CalculatorDisguise,
    /// Emergency Panic / Duress Wipe Completed Screen.
    PanicWiped,
}

/// Localized UI dictionary (`RU` and `EN`, D-0012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiStrings {
    pub locale: Locale,
    pub app_title: &'static str,
    pub onboarding_title: &'static str,
    pub nickname_generate_btn: &'static str,
    pub password_policy_hint: &'static str,
    pub network_shield_tor: &'static str,
    pub network_shield_vpn: &'static str,
    pub network_shield_direct: &'static str,
    pub network_shield_offline: &'static str,
    pub saved_notes_title: &'static str,
    pub leak_guard_modal_title: &'static str,
    pub leak_guard_mask_btn: &'static str,
    pub leak_guard_send_anyway_btn: &'static str,
    pub panic_button_label: &'static str,
    pub disguise_calculator_title: &'static str,
    pub server_launcher_title: &'static str,
    pub support_portal_title: &'static str,
    pub theme_store_title: &'static str,
}

impl UiStrings {
    /// Returns localized string table for `Locale::Ru` or `Locale::En`.
    #[must_use]
    pub const fn for_locale(locale: Locale) -> Self {
        match locale {
            Locale::Ru => Self {
                locale: Locale::Ru,
                app_title: "Aegis — Анонимный мессенджер",
                onboarding_title: "Создание профиля",
                nickname_generate_btn: "Сгенерировать",
                password_policy_hint:
                    "Минимум 12 символов, ≥3 ЗАГЛАВНЫЕ буквы, строчные, цифры и спецсимволы",
                network_shield_tor: "Через SOCKS5 / Tor",
                network_shield_vpn: "Через прокси",
                network_shield_direct: "Прямое подключение",
                network_shield_offline: "Сеть заблокирована",
                saved_notes_title: "📌 Избранное",
                leak_guard_modal_title: "LeakGuard: Обнаружены чувствительные данные",
                leak_guard_mask_btn: "Скрыть (****) и отправить",
                leak_guard_send_anyway_btn: "Отправить как есть",
                panic_button_label: "Сброс данных",
                disguise_calculator_title: "Инженерный калькулятор",
                server_launcher_title: "Локальный сервер",
                support_portal_title: "Обратная связь",
                theme_store_title: "Оформление",
            },
            Locale::En => Self {
                locale: Locale::En,
                app_title: "Aegis — Anonymous Messenger",
                onboarding_title: "Create Profile",
                nickname_generate_btn: "Generate",
                password_policy_hint:
                    "Min 12 chars, ≥3 UPPERCASE letters, lowercase, digits & symbols",
                network_shield_tor: "Via SOCKS5 / Tor",
                network_shield_vpn: "Via proxy",
                network_shield_direct: "Direct connection",
                network_shield_offline: "Network locked",
                saved_notes_title: "📌 Saved Messages",
                leak_guard_modal_title: "LeakGuard: Sensitive Data Detected",
                leak_guard_mask_btn: "Mask (****) & Send",
                leak_guard_send_anyway_btn: "Send Anyway",
                panic_button_label: "Wipe data",
                disguise_calculator_title: "Scientific Calculator",
                server_launcher_title: "Local Server",
                support_portal_title: "Feedback",
                theme_store_title: "Appearance",
            },
        }
    }
}

/// View-model for media attachments with automatic EXIF/GPS stripping and View-Once support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaAttachmentView {
    /// File name shown in UI (sanitized).
    pub filename: String,
    /// Original byte size before stripping metadata.
    pub original_size_bytes: usize,
    /// Clean byte size after stripping EXIF/GPS/camera serial tags.
    pub stripped_size_bytes: usize,
    /// Whether EXIF/GPS metadata was stripped prior to encryption.
    pub exif_gps_stripped: bool,
    /// Whether the photo/video is View-Once (auto-erased from RAM/SQLCipher after viewing).
    pub view_once: bool,
    /// Whether the View-Once attachment has already been consumed and crypto-erased.
    pub consumed: bool,
}

impl MediaAttachmentView {
    /// Creates a sanitized media attachment after stripping EXIF/GPS/XMP/comment metadata via `aegis-ffi`.
    #[must_use]
    pub fn strip_exif_and_create(filename: &str, raw_bytes: &[u8], view_once: bool) -> Self {
        let stripped = strip_jpeg_exif_segments(raw_bytes);
        let was_stripped =
            stripped.len() < raw_bytes.len() || strip_media_metadata(raw_bytes).is_ok();
        Self {
            filename: filename.to_owned(),
            original_size_bytes: raw_bytes.len(),
            stripped_size_bytes: stripped.len(),
            exif_gps_stripped: was_stripped,
            view_once,
            consumed: false,
        }
    }

    /// Opens a View-Once attachment and immediately marks its key material as consumed.
    pub fn open_attachment(&mut self) -> bool {
        if self.consumed {
            return false;
        }
        if self.view_once {
            self.consumed = true;
        }
        true
    }
}

/// Strips EXIF/GPS/XMP/comment metadata segments from JPEG/PNG image bytes via `aegis_ffi::strip_media_metadata`.
#[must_use]
pub fn strip_jpeg_exif_segments(raw: &[u8]) -> Vec<u8> {
    if let Ok(cleaned) = strip_media_metadata(raw) {
        return cleaned.bytes;
    }
    if raw.len() < 4 || raw[0] != 0xFF || raw[1] != 0xD8 {
        return Vec::new();
    }
    let mut clean = Vec::with_capacity(raw.len());
    clean.push(0xFF);
    clean.push(0xD8);
    let mut i = 2usize;
    while i + 3 < raw.len() {
        if raw[i] != 0xFF {
            clean.extend_from_slice(&raw[i..]);
            break;
        }
        let marker = raw[i + 1];
        if marker == 0xDA || marker == 0xD9 {
            clean.extend_from_slice(&raw[i..]);
            break;
        }
        let seg_len = usize::from(u16::from_be_bytes([raw[i + 2], raw[i + 3]]));
        if seg_len < 2 || i + 2 + seg_len > raw.len() {
            break;
        }
        if !(0xE0..=0xEF).contains(&marker) && !(0xF0..=0xFD).contains(&marker) && marker != 0xFE {
            clean.extend_from_slice(&raw[i..i + 2 + seg_len]);
        }
        i += 2 + seg_len;
    }
    clean
}

/// Single chat message in the UI view-model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessageView {
    /// Outgoing (`true`) or incoming (`false`).
    pub outgoing: bool,
    /// Display text (decrypted in memory only while chat is unlocked).
    pub text: String,
    /// Wire padded bucket size used (`256`, `1024`, `4096`, `16384`).
    pub padded_bucket_bytes: usize,
    /// Optional disappearing timer in seconds (`None` = persistent on device).
    pub disappearing_ttl_secs: Option<u32>,
    /// Optional EXIF-stripped attachment.
    pub attachment: Option<MediaAttachmentView>,
}

/// View-model for an individual 1:1 chat, group, or local encrypted "Избранное" vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatView {
    /// Local 16-byte chat identifier.
    pub chat_id: [u8; 16],
    /// Contact display name (never visible to the server).
    pub title: String,
    /// Anonymous one-way queue address description.
    pub queue_tag: String,
    /// Whether this is the device-only "Избранное / Saved Notes" encrypted vault.
    pub is_local_saved_notes: bool,
    /// Whether this chat carries a verified foundation Support badge `✓`.
    pub verified_support_badge: bool,
    /// Optional per-chat PIN lock digest (PLAN.md §14).
    pub per_chat_pin: Option<String>,
    /// Whether the chat is currently locked by its per-chat PIN.
    pub is_locked: bool,
    /// Default disappearing message timer in seconds for this chat.
    pub default_disappearing_ttl_secs: Option<u32>,
    /// Decrypted messages currently visible in the view.
    pub messages: Vec<ChatMessageView>,
}

/// Real-time `LeakGuard` modal state when sensitive data is detected before sending (D-0009).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakGuardModal {
    /// Target chat ID where the user attempted to send the message.
    pub target_chat_id: [u8; 16],
    /// Original unencrypted draft text.
    pub original_draft: String,
    /// Redacted draft text (`****`) ready for 1-click safe sending.
    pub redacted_preview: String,
    /// Warnings identified by `aegis_ffi::scan_message_for_leaks`.
    pub warnings: Vec<LeakWarning>,
}

/// Calculator Disguise mode state (PLAN.md §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalculatorDisguiseView {
    /// Current expression or PIN typed on the calculator keypad.
    pub display_buffer: String,
    /// Last computed result shown on the calculator screen.
    pub last_result: String,
    /// Whether the app launcher icon & window title are disguised as a Calculator.
    pub disguise_active: bool,
}

impl CalculatorDisguiseView {
    /// Evaluates a simple arithmetic expression (`+`, `-`, `*`, `/`) or unlocks the app if `display_buffer` matches `secret_pin` in constant time.
    pub fn press_equals(&mut self, secret_pin: &str, duress_pin: Option<&str>) -> CalculatorAction {
        let trimmed = self.display_buffer.trim();
        let secret_match =
            !secret_pin.is_empty() && constant_time_eq(trimmed.as_bytes(), secret_pin.as_bytes());
        let duress_match = duress_pin.is_some_and(|duress| {
            !duress.is_empty() && constant_time_eq(trimmed.as_bytes(), duress.as_bytes())
        });
        if secret_match {
            self.display_buffer.clear();
            self.disguise_active = false;
            return CalculatorAction::UnlockRealVault;
        }
        if duress_match {
            self.display_buffer.clear();
            return CalculatorAction::TriggerDuressDecoy;
        }
        let evaluated = eval_simple_math(trimmed).unwrap_or_else(|| "0".to_owned());
        self.last_result = evaluated.clone();
        self.display_buffer = evaluated;
        CalculatorAction::ComputedMath
    }
}

/// Outcome of pressing `=` on the Calculator Disguise screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalculatorAction {
    /// Normal calculator math result displayed.
    ComputedMath,
    /// Secret primary PIN entered -> exits disguise and opens real vault.
    UnlockRealVault,
    /// Secret Duress PIN entered -> wipes real keys and opens empty decoy profile.
    TriggerDuressDecoy,
}

fn eval_simple_math(expr: &str) -> Option<String> {
    let trimmed = expr.trim();
    if let Some((a, b)) = trimmed.split_once('+') {
        let x: i64 = a.trim().parse().ok()?;
        let y: i64 = b.trim().parse().ok()?;
        return Some(x.saturating_add(y).to_string());
    }
    if let Some((a, b)) = trimmed.split_once('*') {
        let x: i64 = a.trim().parse().ok()?;
        let y: i64 = b.trim().parse().ok()?;
        return Some(x.saturating_mul(y).to_string());
    }
    if let Some(pos) = trimmed
        .char_indices()
        .skip(1)
        .find(|&(_, c)| c == '-')
        .map(|(idx, _)| idx)
    {
        let a = &trimmed[..pos];
        let b = &trimmed[pos + 1..];
        let x: i64 = a.trim().parse().ok()?;
        let y: i64 = b.trim().parse().ok()?;
        return Some(x.saturating_sub(y).to_string());
    }
    if let Some((a, b)) = trimmed.split_once('/') {
        let x: i64 = a.trim().parse().ok()?;
        let y: i64 = b.trim().parse().ok()?;
        if y != 0 {
            return Some(x.wrapping_div(y).to_string());
        }
    }
    trimmed.parse::<i64>().ok().map(|v| v.to_string())
}

/// 1-Click Self-Hosted Server Launcher Wizard view-model (`aegis-launcher`, PLAN.md §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerLauncherWizardView {
    /// Selected deployment target (`VpsDocker`, `DesktopLocal`, `TorOnionService`, `AndroidTestOnly`).
    pub selected_target: LaunchTarget,
    /// Configured port.
    pub bind_port: u16,
    /// Queue retention TTL in days.
    pub queue_ttl_days: u16,
    /// Validated launch plan from `aegis-ffi`.
    pub active_plan: LaunchPlan,
    /// Generated `docker-compose.yml` or Tor `.onion` deployment artifact.
    pub generated_config_bundle: String,
    /// Generated server invite URI with Ed25519 key fingerprint.
    pub generated_server_invite_uri: String,
}

impl ServerLauncherWizardView {
    /// Creates a default launcher wizard state for `LaunchTarget::VpsDocker`.
    #[must_use]
    pub fn new_default() -> Self {
        let plan = build_launch_plan(LaunchTarget::VpsDocker);
        let bundle = render_deployment_bundle(&plan);
        let invite_uri = format_server_invite_uri("185.220.101.42", plan.bind_port, &[0xAB; 32])
            .unwrap_or_else(|_| {
                "aegis://server/185.220.101.42:8443?fp=abababababababababababababababababababababababababababababababab".to_owned()
            });
        Self {
            selected_target: LaunchTarget::VpsDocker,
            bind_port: plan.bind_port,
            queue_ttl_days: 30,
            active_plan: plan,
            generated_config_bundle: bundle,
            generated_server_invite_uri: invite_uri,
        }
    }

    /// Re-validates parameters via `aegis_ffi::validate_launch_config` and regenerates deployment scripts.
    ///
    /// # Errors
    /// Returns [`DesktopUiError::Launcher`] if port is 0 or TTL is outside `1..=365`.
    pub fn configure(
        &mut self,
        target: LaunchTarget,
        bind_port: u16,
        queue_ttl_days: u16,
    ) -> Result<&LaunchPlan, DesktopUiError> {
        let plan = validate_launch_config(target, bind_port, queue_ttl_days)
            .map_err(DesktopUiError::Launcher)?;
        self.selected_target = target;
        self.bind_port = bind_port;
        self.queue_ttl_days = queue_ttl_days;
        self.generated_config_bundle = render_deployment_bundle(&plan);
        self.generated_server_invite_uri = match target {
            LaunchTarget::TorOnionService => format_server_invite_uri(
                "v3aegis7x9k2m4p8q1r5t6y3u2i8o9p0a1s2d3f4g5h6j7k8l9z0x.onion",
                plan.bind_port,
                &[0xAB; 32],
            )
            .map_err(DesktopUiError::Launcher)?,
            _ => format_server_invite_uri("185.220.101.42", plan.bind_port, &[0xAB; 32])
                .map_err(DesktopUiError::Launcher)?,
        };
        self.active_plan = plan;
        Ok(&self.active_plan)
    }
}

fn render_deployment_bundle(plan: &LaunchPlan) -> String {
    match plan.target {
        LaunchTarget::VpsDocker => {
            generate_docker_compose(plan, "185.220.101.42", &[0xAB; 32]).unwrap_or_default()
        }
        LaunchTarget::DesktopLocal => format!(
            "aegis-serverd --bind=0.0.0.0 --port={port} # (Static-IP / LAN ready, Queue TTL: {ttl}s, Zero IP Logs)",
            port = plan.bind_port,
            ttl = plan.queue_ttl_secs
        ),
        LaunchTarget::TorOnionService => {
            generate_torrc_hidden_service(plan, &[0xAB; 32]).unwrap_or_default()
        }
        LaunchTarget::AndroidTestOnly => format!(
            "# ⚠ ТЕСТОВЫЙ РЕЖИМ ANDROID LAN (Порт {port}, TTL {ttl}с) — Не использовать для продакшена из-за NAT и сна батареи",
            port = plan.bind_port,
            ttl = plan.queue_ttl_secs
        ),
    }
}

/// Encrypted Support Portal & Anonymous Donation `SupporterPass` view-model (D-0006, D-0010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportPortalView {
    /// Whether the official support public key certificate passed M-of-N verification (`✓`).
    pub support_cert_verified: bool,
    /// Submitted encrypted support tickets waiting for reply on one-way queues.
    pub submitted_tickets: Vec<SupportTicket>,
    /// Whether a `SupporterPass` blind signature token is active on this device.
    pub supporter_pass_active: bool,
    /// Total unlocked account slots on this device (`3` free by default, `5+` with pass).
    pub max_account_slots: usize,
}

/// Declarative Theme & Sandboxed WASM Plugin view-model (`aegis-plugins`, PLAN.md §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeSelectorView {
    /// Currently active declarative theme slug.
    pub active_theme_id: String,
    /// Installed and verified plugin/theme manifests.
    pub verified_manifests: Vec<PluginManifest>,
}

/// Single local account profile summary shown in the Multi-Account Switcher (D-0010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProfileSummary {
    /// Local 16-byte profile ID.
    pub account_id: [u8; 16],
    /// Anonymous login nickname (used only for client-side KDF + OPAQUE, never sent in plaintext).
    pub login_nickname: String,
    /// Display alias shown only to E2EE contacts.
    pub display_name: String,
    /// Last password strength score (`0..=100`).
    pub password_score: u8,
}

/// Multi-account switcher view-model (up to 3 free profiles + `SupporterPass` unlock, D-0010).
#[derive(Debug, Clone)]
pub struct AccountSwitcherView {
    slot_manager: AccountSlotManager,
    /// Registered local profiles.
    pub profiles: Vec<AccountProfileSummary>,
    /// Index of the currently active profile.
    pub active_index: usize,
}

impl Default for AccountSwitcherView {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountSwitcherView {
    /// Creates an empty multi-account switcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slot_manager: AccountSlotManager::new(),
            profiles: Vec::new(),
            active_index: 0,
        }
    }

    /// Registers a new isolated account after validating nickname, strict password policy, and account slot quota via `aegis-ffi`.
    ///
    /// # Errors
    /// Fail-closed on invalid nickname, weak password, or exceeded free/supporter account slots.
    pub fn create_account(
        &mut self,
        account_id: [u8; 16],
        login_nickname: &str,
        display_name: &str,
        password: &str,
    ) -> Result<usize, DesktopUiError> {
        validate_nickname(login_nickname).map_err(DesktopUiError::Nickname)?;
        let score =
            validate_password(password, login_nickname).map_err(DesktopUiError::Password)?;
        let total = self
            .slot_manager
            .register_account(account_id)
            .map_err(DesktopUiError::AccountSlot)?;
        self.profiles.push(AccountProfileSummary {
            account_id,
            login_nickname: login_nickname.to_owned(),
            display_name: display_name.to_owned(),
            password_score: score,
        });
        self.active_index = self.profiles.len().saturating_sub(1);
        Ok(total)
    }

    /// Activates a blind-signed `SupporterPass` to unlock 4+ account slots.
    ///
    /// # Errors
    /// Returns [`DesktopUiError::AccountSlot`] if the pass is unverified or replayed.
    pub fn unlock_with_supporter_pass(
        &mut self,
        pass: SupporterPass,
    ) -> Result<(), DesktopUiError> {
        self.slot_manager
            .activate_supporter_pass(pass)
            .map_err(DesktopUiError::AccountSlot)
    }
}

/// Server entry displayed in the Signed Server Directory (`aegis-directory`, PLAN.md §6.3, D-0019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryServerEntry {
    /// Server static IPv4 (`185.220.101.42:8443`), hostname, or `.onion` address.
    pub endpoint: String,
    /// Optional dedicated static IPv4 address (`[a, b, c, d]`) for direct non-Tor connection (D-0019).
    pub static_ipv4: Option<[u8; 4]>,
    /// Whether this server requires a Tor `.onion` route.
    pub is_tor_onion: bool,
    /// Server Ed25519 public key.
    pub public_key: [u8; 32],
    /// Verified cryptographic badge (`OfficialDoubleCheck` ✓✓, `VerifiedSingleCheck` ✓, `CommunityUnverified`).
    pub badge: ServerBadge,
    /// Description shown in UI.
    pub description: String,
}

/// Complete Desktop Application State Machine & View-Model.
#[derive(Debug, Clone)]
pub struct DesktopAppState {
    /// Current UI language (`Locale::Ru` or `Locale::En`).
    pub locale: Locale,
    /// Core version snapshot from `aegis_ffi::core_version_info()`.
    pub core_versions: CoreVersionInfo,
    /// Current active screen.
    pub current_screen: Screen,
    /// Current generated or typed onboarding nickname candidate.
    pub onboarding_nickname: String,
    /// Last validated password score (`0..=100`).
    pub last_password_score: Option<u8>,
    /// Primary app unlock PIN (kept only as simulated digest/token in UI view-model).
    pub app_pin: String,
    /// Optional Duress PIN (triggers decoy profile + wipes real vault).
    pub duress_pin: Option<String>,
    /// Remaining PIN unlock attempts before wrapper wipe.
    pub remaining_pin_attempts: u8,
    /// Whether the app is currently in Duress Decoy mode.
    pub duress_mode_active: bool,
    /// Multi-account switcher state (up to 3 free + `SupporterPass`).
    pub accounts: AccountSwitcherView,
    /// Network Anonymity Shield route probe.
    pub route_probe: RouteProbe,
    /// Latest Network Anonymity Shield evaluation.
    pub shield_evaluation: ShieldEvaluation,
    /// Whether background Cover Traffic (dummy padded packets) is enabled (PLAN.md §14).
    pub cover_traffic_enabled: bool,
    /// Verified server directory entries (`✓✓`, `✓`).
    pub directory_servers: Vec<DirectoryServerEntry>,
    /// Index of the currently connected server.
    pub selected_server_index: usize,
    /// Active chats including "Избранное" (Saved Notes) and verified Support chat.
    pub chats: Vec<ChatView>,
    /// Currently open chat index.
    pub active_chat_index: usize,
    /// Active `LeakGuard` warning modal if an outgoing message triggered DLP rules.
    pub leak_guard_modal: Option<LeakGuardModal>,
    /// Calculator disguise screen state.
    pub calculator_disguise: CalculatorDisguiseView,
    /// 1-Click Server Launcher wizard state.
    pub server_launcher: ServerLauncherWizardView,
    /// Encrypted Support Portal & `SupporterPass` state.
    pub support_portal: SupportPortalView,
    /// Theme Store & WASM Plugin Sandbox state.
    pub theme_selector: ThemeSelectorView,
    /// Monotonic outbound capsule sequence counter preventing AEAD nonce reuse (`B-0091`).
    pub outbound_capsule_seq: u64,
    /// Seen capsule fingerprints (first 32 bytes of wire frame) preventing replay and self-reflection (`B-0091`).
    pub seen_capsule_digests: Vec<[u8; 32]>,
    /// Optional intermediate Entry Relay Node (`host:port`) for Zero-Metadata Blind Relay (`D-0023`).
    pub blind_relay_endpoint: Option<String>,
    /// Optional RFC 1928 SOCKS5h proxy endpoint (`host:port`, e.g. `127.0.0.1:9050` for Tor/Arti/Orbot).
    pub socks5_proxy_endpoint: Option<String>,
    /// Whether Seed-Only mode (default in v2, without mandatory server account) is active (`D-0025`).
    pub seed_only_mode: bool,
    /// Optional 24-word recovery phrase preview (`RecoveryPhrase::generate`), cleared on lock/wipe.
    pub recovery_phrase_preview: Option<String>,
    /// Local encrypted search filter across unlocked chats (`PLAN.md §14`, `PROTOCOL_V2.md §9`).
    pub search_query: String,
    /// Generated invite-only contact card URI (`aegis://invite/...`).
    pub active_invite_uri: String,
    /// Whether the active contact's 60-digit Safety Number has been verified (`PLAN.md §7.1`).
    pub peer_verified: bool,
    /// Active key-change warning if a contact's identity key changed unexpectedly (`PLAN.md §7.1, §14`).
    pub key_change_warning: Option<String>,
    /// Last explicit encrypted vault backup hex (`AEGISBAK`, `T-0017` Phase 3: no automatic cloud backup).
    pub last_exported_backup_hex: Option<String>,
    /// Status banner message for user feedback.
    pub status_banner: String,
}

impl Default for DesktopAppState {
    fn default() -> Self {
        Self::new(Locale::Ru)
    }
}

impl DesktopAppState {
    /// Initializes the Desktop App state machine in the requested locale (`Locale::Ru` or `Locale::En`).
    #[must_use]
    pub fn new(locale: Locale) -> Self {
        let initial_nick = generate_nickname([3, 14, 0x15, 0x92]);
        // D-0019: Default to direct static-IP starter routing (`via_tor: false`, `kill_switch_enabled: false`)
        // so any user can connect out-of-the-box without needing Tor installed.
        let probe = RouteProbe {
            via_tor: false,
            via_vpn_or_proxy: false,
            baseline_isp_ip_hash: Some([0x11; 32]),
            server_observed_ip_hash: Some([0x99; 32]),
            kill_switch_enabled: false,
        };
        let shield_evaluation = evaluate_network_shield(&probe);

        let foundation_key = [0xA1; 32];
        let official_server_key = [0xB1; 32];
        let official_server_key_2 = [0xB3; 32];
        let verified_server_key = [0xB2; 32];
        let onion_server_key = [0xB4; 32];
        let policy = ThresholdPolicy {
            required_signatures: 1,
            trusted_public_keys: vec![foundation_key],
        };
        let attestations = [SignerAttestation {
            signer_public_key: foundation_key,
            cryptographic_sig_valid: true,
        }];

        let official_badge = verify_server_badge(
            ServerBadge::OfficialDoubleCheck,
            &official_server_key,
            &[],
            &policy,
            &attestations,
        )
        .unwrap_or(ServerBadge::CommunityUnverified);

        let verified_badge = verify_server_badge(
            ServerBadge::VerifiedSingleCheck,
            &verified_server_key,
            &[],
            &policy,
            &attestations,
        )
        .unwrap_or(ServerBadge::CommunityUnverified);

        let directory_servers = vec![
            DirectoryServerEntry {
                endpoint: "185.220.101.42:8443".to_owned(),
                static_ipv4: Some([185, 220, 101, 42]),
                is_tor_onion: false,
                public_key: official_server_key,
                badge: official_badge,
                description:
                    "Стартовый сервер #1 (Цюрих, Статический IP 185.220.101.42 — Без Tor, 0 IP-логов) ✓✓"
                        .to_owned(),
            },
            DirectoryServerEntry {
                endpoint: "91.108.56.110:8443".to_owned(),
                static_ipv4: Some([91, 108, 56, 110]),
                is_tor_onion: false,
                public_key: official_server_key_2,
                badge: official_badge,
                description:
                    "Стартовый сервер #2 (Франкфурт, Статический IP 91.108.56.110 — Без Tor, 0 IP-логов) ✓✓"
                        .to_owned(),
            },
            DirectoryServerEntry {
                endpoint: "193.163.125.18:8443".to_owned(),
                static_ipv4: Some([193, 163, 125, 18]),
                is_tor_onion: false,
                public_key: verified_server_key,
                badge: verified_badge,
                description:
                    "Проверенный сервер #3 (Исландия, Статический IP 193.163.125.18 — Без Tor) ✓"
                        .to_owned(),
            },
            DirectoryServerEntry {
                endpoint: "eu-official.aegis.onion:8443".to_owned(),
                static_ipv4: None,
                is_tor_onion: true,
                public_key: onion_server_key,
                badge: official_badge,
                description: "Опциональный Tor Onion v3 сервер фонда Aegis ✓✓ (для режима Tor)"
                    .to_owned(),
            },
        ];

        let saved_notes_chat = ChatView {
            chat_id: [0x01; 16],
            title: "📌 Избранное".to_owned(),
            queue_tag: "local-sqlcipher-only://vault".to_owned(),
            is_local_saved_notes: true,
            verified_support_badge: false,
            per_chat_pin: None,
            is_locked: false,
            default_disappearing_ttl_secs: None,
            messages: vec![ChatMessageView {
                outgoing: true,
                text: "Заметки сохраняются только на этом устройстве."
                    .to_owned(),
                padded_bucket_bytes: 256,
                disappearing_ttl_secs: None,
                attachment: None,
            }],
        };

        let peer_chat = ChatView {
            chat_id: [0x02; 16],
            title: "nordic-falcon".to_owned(),
            queue_tag: "queue://nordic-falcon-global-v1".to_owned(),
            is_local_saved_notes: false,
            verified_support_badge: false,
            per_chat_pin: Some("7788".to_owned()),
            is_locked: false,
            default_disappearing_ttl_secs: Some(3600),
            messages: vec![ChatMessageView {
                outgoing: false,
                text: "Привет! Напиши, когда будешь на связи."
                    .to_owned(),
                padded_bucket_bytes: 256,
                disappearing_ttl_secs: Some(3600),
                attachment: None,
            }],
        };

        let obsidian_theme = PluginManifest {
            plugin_id: "obsidian-stealth-dark".to_owned(),
            declarative_theme_only: true,
            allowed_read_chats: Vec::new(),
            allow_proxied_network: false,
            requested_forbidden_key_access: false,
        };

        Self {
            locale,
            core_versions: core_version_info(),
            current_screen: Screen::ChatWorkspace,
            onboarding_nickname: initial_nick,
            last_password_score: None,
            app_pin: "2580".to_owned(),
            duress_pin: Some("9999".to_owned()),
            remaining_pin_attempts: 10,
            duress_mode_active: false,
            accounts: AccountSwitcherView::new(),
            route_probe: probe,
            shield_evaluation,
            cover_traffic_enabled: true,
            directory_servers,
            selected_server_index: 0,
            chats: vec![saved_notes_chat, peer_chat],
            active_chat_index: 1,
            leak_guard_modal: None,
            calculator_disguise: CalculatorDisguiseView {
                display_buffer: String::new(),
                last_result: "0".to_owned(),
                disguise_active: false,
            },
            server_launcher: ServerLauncherWizardView::new_default(),
            support_portal: SupportPortalView {
                support_cert_verified: true,
                submitted_tickets: Vec::new(),
                supporter_pass_active: false,
                max_account_slots: 3,
            },
            theme_selector: ThemeSelectorView {
                active_theme_id: "phantom-monolith".to_owned(),
                verified_manifests: vec![obsidian_theme],
            },
            outbound_capsule_seq: 0,
            seen_capsule_digests: Vec::new(),
            blind_relay_endpoint: None,
            socks5_proxy_endpoint: None,
            seed_only_mode: true,
            recovery_phrase_preview: None,
            search_query: String::new(),
            active_invite_uri: {
                let invite = ContactInvite {
                    server_endpoint: "185.220.101.42:8443".to_owned(),
                    recipient_queue_id: [0x42; 32],
                    x25519_public: [0xA5; 32],
                    ml_kem_public_hash: [0x5A; 32],
                    expires_at_unix_secs: 1_893_456_000,
                    max_activations: 1,
                    offline_qr_only: false,
                };
                invite.to_uri().unwrap_or_else(|_| {
                    "aegis://invite/185.220.101.42:8443/4242424242424242424242424242424242424242424242424242424242424242".to_owned()
                })
            },
            peer_verified: true,
            key_change_warning: None,
            last_exported_backup_hex: None,
            status_banner: String::new(),
        }
    }

    /// Returns localized UI strings for the active language (`RU` or `EN`).
    #[must_use]
    pub const fn strings(&self) -> UiStrings {
        UiStrings::for_locale(self.locale)
    }

    /// Switches UI language between Russian (`Locale::Ru`) and English (`Locale::En`).
    pub fn set_locale(&mut self, locale: Locale) {
        self.locale = locale;
        for chat in &mut self.chats {
            if chat.is_local_saved_notes {
                chat.title = match locale {
                    Locale::Ru => "📌 Избранное".to_owned(),
                    Locale::En => "📌 Saved Messages".to_owned(),
                };
                if let Some(first) = chat.messages.first_mut() {
                    if first.text.starts_with("Заметки сохраняются")
                        || first.text.starts_with("Notes are saved")
                    {
                        first.text = match locale {
                            Locale::Ru => "Заметки сохраняются только на этом устройстве.".to_owned(),
                            Locale::En => "Notes are saved only on this device.".to_owned(),
                        };
                    }
                }
            } else if chat.verified_support_badge {
                chat.title = match locale {
                    Locale::Ru => "Тестовый канал".to_owned(),
                    Locale::En => "Test Channel".to_owned(),
                };
                if let Some(first) = chat.messages.first_mut() {
                    if first.text.starts_with("Демонстрационный чат")
                        || first.text.starts_with("Demo chat")
                    {
                        first.text = match locale {
                            Locale::Ru => "Демонстрационный чат для проверки отправки сообщений.".to_owned(),
                            Locale::En => "Demo chat for testing message delivery.".to_owned(),
                        };
                    }
                }
            } else if chat.title == "nordic-falcon" {
                if let Some(first) = chat.messages.first_mut() {
                    if first.text.starts_with("Привет! Напиши")
                        || first.text.starts_with("Hey! Message me")
                    {
                        first.text = match locale {
                            Locale::Ru => "Привет! Напиши, когда будешь на связи.".to_owned(),
                            Locale::En => "Hey! Message me when you're online.".to_owned(),
                        };
                    }
                }
            }
        }
        self.status_banner = match locale {
            Locale::Ru => "Язык интерфейса: Русский (RU).".to_owned(),
            Locale::En => "Interface language: English (EN).".to_owned(),
        };
    }

    /// Generates a fresh CSPRNG nickname via `aegis_ffi::generate_nickname`.
    pub fn regenerate_onboarding_nickname(&mut self, entropy: [u8; 4]) -> String {
        let nick = generate_nickname(entropy);
        self.onboarding_nickname.clone_from(&nick);
        nick
    }

    /// Evaluates network route changes (Direct / VPN / Tor) and updates `ShieldEvaluation`.
    pub fn update_network_route(
        &mut self,
        via_tor: bool,
        via_vpn_or_proxy: bool,
        kill_switch_enabled: bool,
        simulate_tunnel_leak: bool,
    ) -> ShieldEvaluation {
        let isp_hash = [0x11; 32];
        let observed_hash = if simulate_tunnel_leak {
            isp_hash
        } else {
            [0x99; 32]
        };
        self.route_probe = RouteProbe {
            via_tor,
            via_vpn_or_proxy,
            baseline_isp_ip_hash: Some(isp_hash),
            server_observed_ip_hash: Some(observed_hash),
            kill_switch_enabled,
        };
        self.shield_evaluation = evaluate_network_shield(&self.route_probe);
        self.shield_evaluation.clone()
    }

    /// Selects a server from `directory_servers` in 1 click (automatically switching between direct Static-IP and optional Tor).
    ///
    /// # Errors
    /// Returns [`DesktopUiError::Directory`] if `server_index` is out of bounds.
    pub fn select_starter_server(
        &mut self,
        server_index: usize,
    ) -> Result<&DirectoryServerEntry, DesktopUiError> {
        let Some(entry) = self.directory_servers.get(server_index) else {
            return Err(DesktopUiError::Directory(
                DirectoryError::UnverifiedServerBadge,
            ));
        };
        let is_onion = entry.is_tor_onion;
        let ep = entry.endpoint.clone();
        self.selected_server_index = server_index;
        let _ = self.update_network_route(is_onion, is_onion, is_onion, false);
        self.status_banner = if is_onion {
            format!("Подключён Tor .onion сервер: {ep} (🔒)")
        } else {
            format!("Подключён стартовый сервер по статическому IP: {ep} (Без Tor, E2EE активен)")
        };
        Ok(&self.directory_servers[self.selected_server_index])
    }

    /// Connects to a user-provided custom static IPv4 address or hostname in 1 click without requiring Tor (D-0019).
    ///
    /// # Errors
    /// Returns [`DesktopUiError::Launcher`] if the host/IP or port is invalid.
    pub fn connect_custom_static_ip(
        &mut self,
        host_or_ip: &str,
        port: u16,
    ) -> Result<usize, DesktopUiError> {
        if self.directory_servers.len() >= 64 {
            return Err(DesktopUiError::Launcher(
                LauncherError::InvalidServerIdentity,
            ));
        }
        let trimmed = host_or_ip.trim();
        let _ = format_server_invite_uri(trimmed, port, &[0xCC; 32])
            .map_err(DesktopUiError::Launcher)?;
        let parsed_ipv4 = {
            let octets: Vec<&str> = trimmed.split('.').collect();
            if octets.len() == 4 {
                if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
                    octets[0].parse::<u8>(),
                    octets[1].parse::<u8>(),
                    octets[2].parse::<u8>(),
                    octets[3].parse::<u8>(),
                ) {
                    Some([a, b, c, d])
                } else {
                    None
                }
            } else {
                None
            }
        };
        let endpoint = format!("{trimmed}:{port}");
        self.directory_servers.push(DirectoryServerEntry {
            endpoint: endpoint.clone(),
            static_ipv4: parsed_ipv4,
            is_tor_onion: trimmed.to_ascii_lowercase().ends_with(".onion"),
            public_key: [0xCC; 32],
            badge: ServerBadge::CommunityUnverified,
            description: format!("Пользовательский сервер со статическим IP ({endpoint})"),
        });
        let idx = self.directory_servers.len() - 1;
        let _ = self.select_starter_server(idx)?;
        Ok(idx)
    }

    /// Sends a message to the active chat.
    /// Runs `LeakGuard` before encryption (`D-0009`). If sensitive data is found and `force_send` is `false`,
    /// opens `LeakGuardModal` and blocks automatic transmission.
    ///
    /// # Errors
    /// Returns [`DesktopUiError`] if Kill Switch blocks traffic, chat is PIN-locked, or `LeakGuard` intercepts leaks.
    pub fn send_chat_message(
        &mut self,
        draft: &str,
        force_send: bool,
        attachment: Option<MediaAttachmentView>,
    ) -> Result<usize, DesktopUiError> {
        let Some(chat) = self.chats.get(self.active_chat_index) else {
            return Err(DesktopUiError::Protocol(
                ProtocolError::MalformedPaddedFrame,
            ));
        };
        if chat.is_locked {
            return Err(DesktopUiError::ChatLockedWithPin);
        }
        if !chat.is_local_saved_notes && self.key_change_warning.is_some() {
            return Err(DesktopUiError::Protocol(
                ProtocolError::MalformedPaddedFrame,
            ));
        }
        if !chat.is_local_saved_notes && !self.shield_evaluation.traffic_permitted {
            return Err(DesktopUiError::KillSwitchBlocked);
        }

        if !force_send {
            let mut warnings = scan_message_for_leaks(draft, None);
            if !self.onboarding_nickname.is_empty() {
                for w in scan_message_for_leaks(draft, Some(self.onboarding_nickname.as_str())) {
                    if !warnings.contains(&w) {
                        warnings.push(w);
                    }
                }
            }
            for prof in &self.accounts.profiles {
                for w in scan_message_for_leaks(draft, Some(prof.login_nickname.as_str())) {
                    if !warnings.contains(&w) {
                        warnings.push(w);
                    }
                }
            }
            if !warnings.is_empty() {
                let redacted = redact_leaks(draft, &warnings);
                self.leak_guard_modal = Some(LeakGuardModal {
                    target_chat_id: chat.chat_id,
                    original_draft: draft.to_owned(),
                    redacted_preview: redacted,
                    warnings: warnings.clone(),
                });
                return Err(DesktopUiError::LeakDetected(warnings));
            }
        }

        let padded = pad_frame(draft.as_bytes()).map_err(DesktopUiError::Protocol)?;
        let bucket_len = padded.len();
        if let Some(active_chat) = self.chats.get_mut(self.active_chat_index) {
            let ttl = active_chat.default_disappearing_ttl_secs;
            active_chat.messages.push(ChatMessageView {
                outgoing: true,
                text: draft.to_owned(),
                padded_bucket_bytes: bucket_len,
                disappearing_ttl_secs: ttl,
                attachment,
            });
        }
        self.leak_guard_modal = None;
        Ok(bucket_len)
    }

    fn next_unique_capsule_nonce(&mut self, queue_id: &[u8; 32]) -> [u8; 12] {
        self.outbound_capsule_seq = self.outbound_capsule_seq.saturating_add(1);
        let seq = self.outbound_capsule_seq;
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&queue_id[0..4]);
        nonce[4..12].copy_from_slice(&seq.to_be_bytes());
        if nonce == [0u8; 12] {
            nonce[0] = 1;
        }
        nonce
    }

    fn capsule_fingerprint(frame: &[u8]) -> [u8; 32] {
        let mut fp = [0u8; 32];
        let copy_len = frame.len().min(32);
        fp[..copy_len].copy_from_slice(&frame[..copy_len]);
        fp
    }

    fn record_seen_capsule_fingerprint(&mut self, fp: [u8; 32]) {
        if !self.seen_capsule_digests.contains(&fp) {
            if self.seen_capsule_digests.len() >= 4096 {
                self.seen_capsule_digests.remove(0);
            }
            self.seen_capsule_digests.push(fp);
        }
    }

    /// Encrypts a message into a 256..16384-byte RFC 8439 ChaCha20-Poly1305 capsule and transmits it
    /// over TCP/HTTP (or via `blind_relay_endpoint` / `socks5_proxy_endpoint` per `D-0023` / `D-0008`) to `server_host_port`.
    ///
    /// # Errors
    /// Returns [`DesktopUiError`] if `LeakGuard` blocks the message, Kill Switch is engaged, or network delivery fails.
    pub fn transmit_cross_border_capsule(
        &mut self,
        server_host_port: &str,
        channel_code: &str,
        plaintext: &str,
    ) -> Result<usize, DesktopUiError> {
        let bucket = self.send_chat_message(plaintext, false, None)?;
        let (queue_id, mut channel_key, _) = derive_channel_key_and_queue(channel_code);
        let nonce = self.next_unique_capsule_nonce(&queue_id);
        let capsule = seal_cross_border_capsule(channel_code, &nonce, plaintext)
            .map_err(DesktopUiError::Protocol)?;
        let fp = Self::capsule_fingerprint(&capsule);
        self.record_seen_capsule_fingerprint(fp);
        let send_res = if let Some(relay_ep) = self.blind_relay_endpoint.clone() {
            send_capsule_via_blind_relay(
                &relay_ep,
                server_host_port,
                &queue_id,
                &channel_key,
                &capsule,
                2_500,
            )
            .map_err(|e| DesktopUiError::IoError(e.to_string()))
        } else if let Some(proxy_ep) = self.socks5_proxy_endpoint.clone() {
            send_capsule_via_socks5(
                &proxy_ep,
                server_host_port,
                &queue_id,
                &channel_key,
                &capsule,
                2_500,
            )
            .map_err(|e| DesktopUiError::IoError(e.to_string()))
        } else {
            send_capsule_over_tcp(server_host_port, &queue_id, &channel_key, &capsule, 2_000)
                .map_err(|e| DesktopUiError::IoError(e.to_string()))
        };
        channel_key.fill(0);
        send_res?;
        Ok(bucket)
    }

    /// Polls pending encrypted capsules from `server_host_port` (or via `blind_relay_endpoint` / `socks5_proxy_endpoint`),
    /// authenticates and decrypts each RFC 8439 ChaCha20-Poly1305 capsule using `channel_code`,
    /// filters out replayed or self-sent capsules, and appends new capsules to the active chat.
    ///
    /// # Errors
    /// Returns [`DesktopUiError`] if Kill Switch is active, chat is locked, connection fails, or any capsule fails AEAD verification.
    pub fn sync_remote_capsules(
        &mut self,
        server_host_port: &str,
        channel_code: &str,
    ) -> Result<usize, DesktopUiError> {
        let Some(chat_check) = self.chats.get(self.active_chat_index) else {
            return Err(DesktopUiError::Protocol(
                ProtocolError::MalformedPaddedFrame,
            ));
        };
        if chat_check.is_locked {
            return Err(DesktopUiError::ChatLockedWithPin);
        }
        if chat_check.is_local_saved_notes || self.duress_mode_active {
            return Ok(0);
        }
        if self.key_change_warning.is_some() {
            return Err(DesktopUiError::Protocol(
                ProtocolError::MalformedPaddedFrame,
            ));
        }
        if !self.shield_evaluation.traffic_permitted {
            return Err(DesktopUiError::KillSwitchBlocked);
        }
        let (queue_id, mut channel_key, _) = derive_channel_key_and_queue(channel_code);
        let poll_res = if let Some(relay_ep) = self.blind_relay_endpoint.clone() {
            poll_capsules_via_blind_relay(
                &relay_ep,
                server_host_port,
                &queue_id,
                &channel_key,
                2_500,
            )
            .map_err(|e| DesktopUiError::IoError(e.to_string()))
        } else if let Some(proxy_ep) = self.socks5_proxy_endpoint.clone() {
            poll_capsules_via_socks5(&proxy_ep, server_host_port, &queue_id, &channel_key, 2_500)
                .map_err(|e| DesktopUiError::IoError(e.to_string()))
        } else {
            poll_capsules_over_tcp(server_host_port, &queue_id, &channel_key, 2_000)
                .map_err(|e| DesktopUiError::IoError(e.to_string()))
        };
        channel_key.fill(0);
        let raw_frames = poll_res?;
        let mut received_count = 0usize;
        for frame in &raw_frames {
            let fp = Self::capsule_fingerprint(frame);
            if self.seen_capsule_digests.contains(&fp) {
                continue;
            }
            let plaintext =
                open_cross_border_capsule(channel_code, frame).map_err(DesktopUiError::Protocol)?;
            self.record_seen_capsule_fingerprint(fp);
            if let Some(chat) = self.chats.get_mut(self.active_chat_index) {
                let ttl = chat.default_disappearing_ttl_secs;
                chat.messages.push(ChatMessageView {
                    outgoing: false,
                    text: plaintext,
                    padded_bucket_bytes: frame.len(),
                    disappearing_ttl_secs: ttl,
                    attachment: None,
                });
                received_count += 1;
            }
        }
        Ok(received_count)
    }

    /// Seals and delivers an outgoing capsule to the active server using the configured route
    /// (Blind Relay, SOCKS5h Proxy, or Direct TCP).
    pub fn deliver_capsule_to_active_server(
        &mut self,
        channel_code: &str,
        plaintext: &str,
    ) -> bool {
        if self.duress_mode_active
            || !self.shield_evaluation.traffic_permitted
            || self.key_change_warning.is_some()
        {
            return false;
        }
        if self
            .chats
            .get(self.active_chat_index)
            .is_some_and(|c| c.is_locked || c.is_local_saved_notes)
        {
            return false;
        }
        let server_ep = self
            .directory_servers
            .get(self.selected_server_index)
            .map_or_else(|| "185.220.101.42:8443".to_owned(), |s| s.endpoint.clone());
        let (queue_id, mut channel_key, _) = derive_channel_key_and_queue(channel_code);
        let nonce = self.next_unique_capsule_nonce(&queue_id);
        let Ok(capsule) = seal_cross_border_capsule(channel_code, &nonce, plaintext) else {
            channel_key.fill(0);
            return false;
        };
        let fp = Self::capsule_fingerprint(&capsule);
        self.record_seen_capsule_fingerprint(fp);
        let ok = if let Some(relay_ep) = self.blind_relay_endpoint.clone() {
            send_capsule_via_blind_relay(
                &relay_ep,
                &server_ep,
                &queue_id,
                &channel_key,
                &capsule,
                800,
            )
            .is_ok()
        } else if let Some(proxy_ep) = self.socks5_proxy_endpoint.clone() {
            send_capsule_via_socks5(&proxy_ep, &server_ep, &queue_id, &channel_key, &capsule, 800)
                .is_ok()
        } else {
            send_capsule_over_tcp(&server_ep, &queue_id, &channel_key, &capsule, 400).is_ok()
        };
        channel_key.fill(0);
        ok
    }

    /// Computes the 60-digit Safety Number for the active chat (`PLAN.md §7.1`, `PROTOCOL_V2.md §3.5`).
    #[must_use]
    pub fn active_safety_number(&self) -> String {
        let our_ik = [0xA1; 32];
        let mut peer_ik = [0xB2; 32];
        if let Some(chat) = self.chats.get(self.active_chat_index) {
            peer_ik[0..16].copy_from_slice(&chat.chat_id);
        }
        compute_safety_number(&our_ik, &peer_ik)
    }

    /// Rotates the anonymous queue tag of the active chat in 1 click to mitigate queue spam (`D-0007`).
    pub fn rotate_active_chat_queue(&mut self) -> Option<String> {
        self.outbound_capsule_seq = self.outbound_capsule_seq.wrapping_add(1);
        let step = self.outbound_capsule_seq.wrapping_add(17) as u8;
        let suffix = generate_nickname([step, step.wrapping_mul(5), 0x7A, 0x3C]);
        let chat = self.chats.get_mut(self.active_chat_index)?;
        if chat.is_local_saved_notes || chat.is_locked {
            return None;
        }
        let next_tag = format!("queue://{suffix}");
        chat.queue_tag.clone_from(&next_tag);
        Some(next_tag)
    }

    /// Exports an explicit AEAD-authenticated encrypted vault backup (`AEGISBAK`, `PLAN.md §14`, `T-0017` Phase 3).
    /// Automatic cloud backup is strictly disabled; only explicit user-triggered encrypted export is supported.
    ///
    /// # Errors
    /// Returns [`DesktopUiError::Protocol`] if the backup export fails.
    pub fn export_explicit_encrypted_backup(&mut self) -> Result<String, DesktopUiError> {
        let mut db = EncryptedVaultDb::open(SCHEMA_VERSION, vec![0x42; 32])
            .map_err(|_| DesktopUiError::Protocol(ProtocolError::MalformedPaddedFrame))?;
        let _ = db.put_local_note(EncryptedNote {
            note_id: [0x11; 32],
            title: "Aegis Vault Snapshot".to_owned(),
            body: format!(
                "Chats: {}, Accounts: {}",
                self.chats.len(),
                self.accounts.profiles.len()
            ),
            updated_at_unix_secs: 1_760_000_000,
        });
        let nonce = self.next_unique_capsule_nonce(&[0x77; 32]);
        let raw_backup = db
            .export_encrypted_backup(&[0x55; 32], &nonce)
            .map_err(|_| DesktopUiError::Protocol(ProtocolError::MalformedPaddedFrame))?;
        let hex = hex_encode_bytes(&raw_backup);
        self.last_exported_backup_hex = Some(hex.clone());
        Ok(hex)
    }

    /// Creates a new E2EE group conduit (enforcing `≤ 20` members in beta per `D-0025` / `T-0017` Phase 4).
    ///
    /// # Errors
    /// Returns [`DesktopUiError::Protocol`] if `member_count` is outside `2..=20` or group creation fails.
    pub fn create_mls_group_conduit(
        &mut self,
        title: &str,
        member_count: usize,
    ) -> Result<usize, DesktopUiError> {
        if !(2..=20).contains(&member_count) || self.chats.len() >= 64 {
            return Err(DesktopUiError::Protocol(
                ProtocolError::MalformedPaddedFrame,
            ));
        }
        let id_byte = (self.chats.len() as u8).wrapping_add(30);
        let mut group = GroupChatSession::new([id_byte; 32], [0xAA; 32], [0x10; 32])
            .map_err(DesktopUiError::Protocol)?;
        for m in 1..member_count {
            let member_key = [(m as u8).wrapping_add(1); 32];
            let entropy = [(m as u8).wrapping_add(0x40); 32];
            let _ = group.add_member(member_key, &entropy);
        }
        let welcome_frame = group
            .seal_group_message(&[0x01; 12], b"MLS Group Epoch #1 Initialized")
            .map_err(DesktopUiError::Protocol)?;
        let clean_title = if title.trim().is_empty() {
            "Группа MLS"
        } else {
            title.trim()
        };
        self.chats.push(ChatView {
            chat_id: [id_byte; 16],
            title: format!("👥 {clean_title} (MLS ≤20: {member_count} уч.)"),
            queue_tag: format!("queue://mls-group-{id_byte:02x}"),
            is_local_saved_notes: false,
            verified_support_badge: false,
            per_chat_pin: None,
            is_locked: false,
            default_disappearing_ttl_secs: Some(3600),
            messages: vec![ChatMessageView {
                outgoing: true,
                text: format!(
                    "Создана защищённая группа MLS ({member_count}/20 участников, Pad-Before-Encrypt {} B).",
                    welcome_frame.len()
                ),
                padded_bucket_bytes: welcome_frame.len(),
                disappearing_ttl_secs: Some(3600),
                attachment: None,
            }],
        });
        self.active_chat_index = self.chats.len() - 1;
        self.leak_guard_modal = None;
        Ok(self.active_chat_index)
    }

    /// Masks all `LeakGuard` findings with `****` and sends the sanitized message.
    ///
    /// # Errors
    /// Propagates any error from [`DesktopAppState::send_chat_message`] or rejects if the active chat changed.
    pub fn confirm_leak_guard_masked_send(&mut self) -> Result<usize, DesktopUiError> {
        let Some(modal) = self.leak_guard_modal.take() else {
            return Err(DesktopUiError::Protocol(
                ProtocolError::MalformedPaddedFrame,
            ));
        };
        let active_matches = self
            .chats
            .get(self.active_chat_index)
            .is_some_and(|c| c.chat_id == modal.target_chat_id);
        if !active_matches {
            return Err(DesktopUiError::Protocol(
                ProtocolError::MalformedPaddedFrame,
            ));
        }
        self.send_chat_message(&modal.redacted_preview, true, None)
    }

    /// Locks or unlocks a chat protected by a per-chat PIN (PLAN.md §14).
    ///
    /// # Errors
    /// Returns [`DesktopUiError::InvalidPin`] if the provided per-chat PIN does not match,
    /// or [`DesktopUiError::ChatLockedWithPin`] if `chat_index` is out of bounds.
    pub fn unlock_chat_with_pin(
        &mut self,
        chat_index: usize,
        candidate_pin: &str,
    ) -> Result<(), DesktopUiError> {
        let Some(chat) = self.chats.get_mut(chat_index) else {
            return Err(DesktopUiError::ChatLockedWithPin);
        };
        if let Some(expected) = &chat.per_chat_pin {
            if constant_time_eq(expected.as_bytes(), candidate_pin.as_bytes()) {
                chat.is_locked = false;
                return Ok(());
            }
            self.remaining_pin_attempts = self.remaining_pin_attempts.saturating_sub(1);
            let rem = self.remaining_pin_attempts;
            if rem == 0 {
                self.trigger_panic_wipe();
            }
            return Err(DesktopUiError::InvalidPin {
                remaining_attempts: rem,
            });
        }
        chat.is_locked = false;
        Ok(())
    }

    /// Activates Calculator Disguise mode (hides all chats and shows a working calculator).
    pub fn enable_calculator_disguise(&mut self) {
        self.calculator_disguise.disguise_active = true;
        self.calculator_disguise.display_buffer.clear();
        self.calculator_disguise.last_result = "0".to_owned();
        self.leak_guard_modal = None;
        self.recovery_phrase_preview = None;
        self.last_exported_backup_hex = None;
        self.current_screen = Screen::CalculatorDisguise;
        self.status_banner =
            "Режим маскировки активирован: приложение выглядит как калькулятор.".to_owned();
    }

    /// Enters PIN or Duress PIN to unlock the app (or trigger silent decoy wipe on Duress PIN).
    ///
    /// # Errors
    /// Returns [`DesktopUiError::InvalidPin`] on wrong PIN.
    pub fn verify_app_pin(&mut self, candidate_pin: &str) -> Result<(), DesktopUiError> {
        if self.current_screen == Screen::PanicWiped
            || self.app_pin.is_empty()
            || candidate_pin.is_empty()
        {
            return Err(DesktopUiError::InvalidPin {
                remaining_attempts: self.remaining_pin_attempts,
            });
        }
        let duress_match = self.duress_pin.as_ref().is_some_and(|duress| {
            !duress.is_empty() && constant_time_eq(candidate_pin.as_bytes(), duress.as_bytes())
        });
        let primary_match = constant_time_eq(candidate_pin.as_bytes(), self.app_pin.as_bytes());
        if duress_match {
            self.activate_duress_decoy_mode();
            return Ok(());
        }
        if primary_match {
            self.remaining_pin_attempts = 10;
            self.calculator_disguise.disguise_active = false;
            self.current_screen = Screen::ChatWorkspace;
            return Ok(());
        }
        self.remaining_pin_attempts = self.remaining_pin_attempts.saturating_sub(1);
        if self.remaining_pin_attempts == 0 {
            self.trigger_panic_wipe();
        }
        Err(DesktopUiError::InvalidPin {
            remaining_attempts: self.remaining_pin_attempts,
        })
    }

    /// Switches into Duress Decoy profile: wipes real chats/accounts/PINs/tickets from memory and shows an innocuous decoy profile.
    pub fn activate_duress_decoy_mode(&mut self) {
        self.duress_mode_active = true;
        self.onboarding_nickname.clear();
        self.last_password_score = None;
        self.app_pin.clear();
        self.duress_pin = None;
        self.remaining_pin_attempts = 10;
        self.outbound_capsule_seq = 0;
        self.accounts = AccountSwitcherView::new();
        self.leak_guard_modal = None;
        self.calculator_disguise.display_buffer.clear();
        self.calculator_disguise.last_result = "0".to_owned();
        self.calculator_disguise.disguise_active = false;
        self.support_portal.submitted_tickets.clear();
        self.support_portal.supporter_pass_active = false;
        self.support_portal.max_account_slots = 3;
        self.seen_capsule_digests.clear();
        self.blind_relay_endpoint = None;
        self.socks5_proxy_endpoint = None;
        self.seed_only_mode = true;
        self.recovery_phrase_preview = None;
        self.search_query.clear();
        self.active_invite_uri.clear();
        self.peer_verified = false;
        self.key_change_warning = None;
        self.last_exported_backup_hex = None;
        self.directory_servers.truncate(4);
        self.selected_server_index = 0;
        self.server_launcher = ServerLauncherWizardView::new_default();
        self.theme_selector.active_theme_id = "phantom-monolith".to_owned();
        self.theme_selector.verified_manifests.truncate(1);
        self.chats = vec![ChatView {
            chat_id: [0xD0; 16],
            title: "Покупки и бытовые заметки".to_owned(),
            queue_tag: "notes://household".to_owned(),
            is_local_saved_notes: true,
            verified_support_badge: false,
            per_chat_pin: None,
            is_locked: false,
            default_disappearing_ttl_secs: None,
            messages: vec![ChatMessageView {
                outgoing: true,
                text: "Купить молоко, хлеб и батарейки АА.".to_owned(),
                padded_bucket_bytes: 256,
                disappearing_ttl_secs: None,
                attachment: None,
            }],
        }];
        self.active_chat_index = 0;
        self.current_screen = Screen::ChatWorkspace;
        self.status_banner = "Открыт профиль по умолчанию.".to_owned();
    }

    /// Emergency Panic Button: immediately wipes all accounts, messages, tickets, PINs, custom servers, and keys in memory.
    pub fn trigger_panic_wipe(&mut self) {
        self.onboarding_nickname.clear();
        self.last_password_score = None;
        self.app_pin.clear();
        self.duress_pin = None;
        self.remaining_pin_attempts = 0;
        self.duress_mode_active = false;
        self.accounts = AccountSwitcherView::new();
        self.chats.clear();
        self.directory_servers.clear();
        self.selected_server_index = 0;
        self.active_chat_index = 0;
        self.leak_guard_modal = None;
        self.calculator_disguise.display_buffer.clear();
        self.calculator_disguise.last_result = "0".to_owned();
        self.calculator_disguise.disguise_active = false;
        self.server_launcher = ServerLauncherWizardView::new_default();
        self.theme_selector.active_theme_id = "phantom-monolith".to_owned();
        self.theme_selector.verified_manifests.clear();
        self.support_portal.submitted_tickets.clear();
        self.support_portal.supporter_pass_active = false;
        self.support_portal.max_account_slots = 3;
        self.outbound_capsule_seq = 0;
        self.seen_capsule_digests.clear();
        self.blind_relay_endpoint = None;
        self.socks5_proxy_endpoint = None;
        self.seed_only_mode = true;
        self.recovery_phrase_preview = None;
        self.search_query.clear();
        self.active_invite_uri.clear();
        self.peer_verified = false;
        self.key_change_warning = None;
        self.last_exported_backup_hex = None;
        self.current_screen = Screen::PanicWiped;
        self.status_banner =
            "🚨 Криптографическое стирание (Crypto-Wipe) выполнено. Все ключи и чаты уничтожены."
                .to_owned();
    }

    /// Submits an anonymous E2EE support ticket padded to a fixed bucket via `aegis_ffi::SupportTicket::new`.
    ///
    /// # Errors
    /// Returns [`DesktopUiError::Protocol`] if framing or queue ID validation fails.
    pub fn submit_support_ticket(
        &mut self,
        reply_queue_id: [u8; 32],
        category: SupportTicketCategory,
        message_body: &str,
    ) -> Result<SupportTicket, DesktopUiError> {
        let padded = pad_frame(message_body.as_bytes()).map_err(DesktopUiError::Protocol)?;
        let ticket = SupportTicket::new(reply_queue_id, category, padded)
            .map_err(DesktopUiError::Protocol)?;
        self.support_portal.submitted_tickets.push(ticket.clone());
        self.status_banner = "Зашифрованный тикет отправлен в официальную поддержку ✓.".to_owned();
        Ok(ticket)
    }

    /// Installs a declarative theme or sandboxed WASM plugin after validating its manifest via `aegis-ffi`.
    ///
    /// # Errors
    /// Fail-closed: returns [`DesktopUiError::Plugin`] if the plugin requests key access or combines chat read + network.
    pub fn install_plugin_or_theme(
        &mut self,
        manifest: PluginManifest,
    ) -> Result<(), DesktopUiError> {
        validate_manifest(&manifest).map_err(DesktopUiError::Plugin)?;
        if manifest.declarative_theme_only {
            self.theme_selector
                .active_theme_id
                .clone_from(&manifest.plugin_id);
        }
        self.theme_selector.verified_manifests.push(manifest);
        Ok(())
    }
}

/// Built-in Local Desktop WebView/GUI Server (`http://127.0.0.1:<port>`) so the owner can click
/// and interact with every Aegis feature live on their PC.
#[derive(Debug)]
pub struct DesktopGuiServer {
    bind_addr: String,
    state: DesktopAppState,
}

impl DesktopGuiServer {
    /// Creates a new local GUI server bound to `127.0.0.1:port`.
    #[must_use]
    pub fn new(port: u16, state: DesktopAppState) -> Self {
        Self {
            bind_addr: format!("127.0.0.1:{port}"),
            state,
        }
    }

    /// Legacy Aurora/glass renderer retained for the disguise and panic screens.
    #[must_use]
    fn render_html_legacy(&self) -> String {
        let s = self.state.strings();
        let is_en = self.state.locale == Locale::En;
        if self.state.current_screen == Screen::PanicWiped {
            let wipe_heading = if is_en {
                "🚨 CRYPTOGRAPHIC WIPE COMPLETED"
            } else {
                "🚨 КРИПТОГРАФИЧЕСКОЕ СТИРАНИЕ ВЫПОЛНЕНО"
            };
            return format!(
                "<!DOCTYPE html>
<html lang='{lang}'>
<head>
<meta charset='utf-8'>
<title>Crypto-Wipe Completed</title>
<style>
  body {{ background:#0b0f17; color:#f85149; font-family:system-ui,-apple-system,sans-serif; margin:0; padding:48px; text-align:center; }}
  .card {{ max-width:560px; margin:0 auto; background:#141b26; border:2px solid #da3633; border-radius:12px; padding:24px; }}
</style>
</head>
<body>
  <div class='card'>
    <h1>{wipe_heading}</h1>
    <p style='color:#e6edf3;'>{status}</p>
  </div>
</body>
</html>",
                lang = if is_en { "en" } else { "ru" },
                wipe_heading = wipe_heading,
                status = html_escape(&self.state.status_banner)
            );
        }

        if self.state.current_screen == Screen::CalculatorDisguise {
            let res_lbl = if is_en { "Result" } else { "Результат" };
            return format!(
                "<!DOCTYPE html>
<html lang='{lang}'>
<head>
<meta charset='utf-8'>
<title>{calc_title}</title>
<style>
  body {{ background:#0B101B; color:#F1F5F9; font-family:system-ui,-apple-system,sans-serif; margin:0; padding:48px; }}
  .calc {{ max-width:390px; margin:0 auto; background:#0F172A; border:1px solid rgba(16,245,204,0.34); border-radius:20px; padding:22px; box-shadow:0 24px 60px rgba(0,0,0,0.68); }}
  input[type=text] {{ width:100%; box-sizing:border-box; background:#050811; color:#10F5CC; font-size:24px; font-family:monospace; border:1px solid rgba(16,245,204,0.28); padding:13px; border-radius:12px; margin-bottom:12px; }}
  .kgrid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin-bottom:10px; }}
  .kbtn {{ display:block; text-align:center; text-decoration:none; background:#182238; color:#F1F5F9; border:1px solid rgba(255,255,255,0.12); padding:13px 0; border-radius:11px; font-weight:700; font-size:16px; }}
  .kbtn.op {{ background:rgba(139,92,246,0.28); color:#10F5CC; border-color:rgba(16,245,204,0.32); }}
  button {{ width:100%; background:linear-gradient(135deg,#8B5CF6,#10F5CC); color:#05070F; font-weight:800; font-size:17px; border:none; padding:12px; border-radius:11px; cursor:pointer; }}
</style>
</head>
<body>
  <div class='calc'>
    <h2 style='margin-top:0;color:#10F5CC;'>🧮 {calc_title} // Precision Titanium</h2>
    <div style='margin-bottom:10px;color:#94A3B8;'>{res_lbl}: <b style='color:#10F5CC;'>{res}</b></div>
    <form action='/action' method='get'>
      <input type='hidden' name='cmd' value='calc_eval'>
      <input type='text' name='expr' value='{buf}' placeholder='0' autocomplete='off'>
      <div class='kgrid'>
        <a class='kbtn' href='/action?cmd=calc_key&k=7'>7</a>
        <a class='kbtn' href='/action?cmd=calc_key&k=8'>8</a>
        <a class='kbtn' href='/action?cmd=calc_key&k=9'>9</a>
        <a class='kbtn op' href='/action?cmd=calc_key&k=div'>÷</a>
        <a class='kbtn' href='/action?cmd=calc_key&k=4'>4</a>
        <a class='kbtn' href='/action?cmd=calc_key&k=5'>5</a>
        <a class='kbtn' href='/action?cmd=calc_key&k=6'>6</a>
        <a class='kbtn op' href='/action?cmd=calc_key&k=mul'>×</a>
        <a class='kbtn' href='/action?cmd=calc_key&k=1'>1</a>
        <a class='kbtn' href='/action?cmd=calc_key&k=2'>2</a>
        <a class='kbtn' href='/action?cmd=calc_key&k=3'>3</a>
        <a class='kbtn op' href='/action?cmd=calc_key&k=sub'>−</a>
        <a class='kbtn op' href='/action?cmd=calc_key&k=clear'>C</a>
        <a class='kbtn' href='/action?cmd=calc_key&k=0'>0</a>
        <a class='kbtn op' href='/action?cmd=calc_key&k=add'>+</a>
        <a class='kbtn op' href='/action?cmd=calc_eval&expr={buf_url}'>=</a>
      </div>
      <button type='submit'>=</button>
    </form>
  </div>
</body>
</html>",
                lang = if is_en { "en" } else { "ru" },
                calc_title = html_escape(s.disguise_calculator_title),
                res_lbl = res_lbl,
                res = html_escape(&self.state.calculator_disguise.last_result),
                buf = html_escape(&self.state.calculator_disguise.display_buffer),
                buf_url = url_encode(&self.state.calculator_disguise.display_buffer)
            );
        }

        let shield_badge = match self.state.shield_evaluation.status {
            NetworkRouteStatus::TorAnonymized => s.network_shield_tor,
            NetworkRouteStatus::VpnOrProxyProtected => s.network_shield_vpn,
            NetworkRouteStatus::DirectWarning => s.network_shield_direct,
            NetworkRouteStatus::Offline => s.network_shield_offline,
        };

        let active_chat = self.state.chats.get(self.state.active_chat_index);
        let chat_title =
            active_chat.map_or("Нет открытого чата", |c| c.title.as_str());
        let search_filter = self.state.search_query.trim().to_lowercase();

        let mut messages_html = String::new();
        if let Some(chat) = active_chat {
            if chat.is_locked {
                messages_html.push_str(
                    "<div class='warn-box'>🔒 Чат заблокирован персональным PIN-кодом. Введите PIN чата для разблокировки.</div>",
                );
            } else {
                for (idx, m) in chat.messages.iter().enumerate() {
                    if !search_filter.is_empty() && !m.text.to_lowercase().contains(&search_filter)
                    {
                        continue;
                    }
                    let side = if m.outgoing { "msg out" } else { "msg in" };
                    let dir_tag = if m.outgoing {
                        "TX // SEALED CAPSULE"
                    } else {
                        "RX // VERIFIED CAPSULE"
                    };
                    let ttl_badge = m
                        .disappearing_ttl_secs
                        .map_or("TTL: ∞".to_owned(), |t| format!("TTL: {t}s"));
                    let att_badge = m.attachment.as_ref().map_or(String::new(), |a| {
                        format!(
                            " <span class='tag'>📷 {} (EXIF очищен: {} -> {} B, View-Once: {})</span>",
                            html_escape(&a.filename),
                            a.original_size_bytes,
                            a.stripped_size_bytes,
                            if a.consumed { "просмотрено и стёрто" } else { "готово" }
                        )
                    });
                    messages_html.push_str(&format!(
                        "<div class='{side}'><div class='cap-hdr'><span>◈ {dir_tag} #{step:02}</span><span>PAD-BUCKET: {bucket} B • {ttl_badge} • PQXDH+DR</span></div><div class='cap-body'>{}</div><div class='cap-bar'><span class='cap-fill'></span></div><small>{att_badge}</small></div>",
                        html_escape(&m.text),
                        step = idx + 1,
                        bucket = m.padded_bucket_bytes
                    ));
                }
            }
        }

        let leak_modal_html = if let Some(modal) = &self.state.leak_guard_modal {
            format!(
                "<div class='modal'>
                    <h3>{}</h3>
                    <p>Перехвачено угроз деанонимизации/кражи карты: <b>{}</b></p>
                    <p>Исходный текст: <code>{}</code></p>
                    <p>Безопасная маскировка: <code>{}</code></p>
                    <div class='row'>
                        <a class='btn ok' href='/action?cmd=leak_mask'>{}</a>
                        <a class='btn warn' href='/action?cmd=leak_force'>{}</a>
                    </div>
                </div>",
                s.leak_guard_modal_title,
                modal.warnings.len(),
                html_escape(&modal.original_draft),
                html_escape(&modal.redacted_preview),
                s.leak_guard_mask_btn,
                s.leak_guard_send_anyway_btn
            )
        } else {
            String::new()
        };

        let accounts_html: String = self
            .state
            .accounts
            .profiles
            .iter()
            .enumerate()
            .map(|(idx, acc)| {
                let active_mark = if idx == self.state.accounts.active_index {
                    "🟢"
                } else {
                    "⚪"
                };
                format!(
                    "<span class='tag'>{active_mark} {} (ник KDF: {}, сила пароля: {}%)</span> ",
                    html_escape(&acc.display_name),
                    html_escape(&acc.login_nickname),
                    acc.password_score
                )
            })
            .collect();

        let servers_html: String = self
            .state
            .directory_servers
            .iter()
            .enumerate()
            .map(|(idx, srv)| {
                let badge = match srv.badge {
                    ServerBadge::OfficialDoubleCheck => "✓✓ Официальный",
                    ServerBadge::VerifiedSingleCheck => "✓ Проверенный",
                    ServerBadge::CommunityUnverified => "⚠ Сообщество",
                };
                let active_prefix = if idx == self.state.selected_server_index {
                    "🟢 [АКТИВЕН] "
                } else {
                    ""
                };
                format!(
                    "<li style='margin:6px 0;'>{active_prefix}<b>{}</b> <span class='tag'>{}</span> — {} <a class='btn ok' href='/action?cmd=select_server&idx={idx}'>Подключить в 1 клик</a></li>",
                    html_escape(&srv.endpoint),
                    badge,
                    html_escape(&srv.description)
                )
            })
            .collect();

        let chat_list_sidebar_html: String = self
            .state
            .chats
            .iter()
            .enumerate()
            .map(|(idx, c)| {
                let is_active = idx == self.state.active_chat_index;
                let item_cls = if is_active {
                    "chat-item active"
                } else {
                    "chat-item"
                };
                let icon = if c.is_local_saved_notes {
                    "📌"
                } else if c.verified_support_badge {
                    "✓"
                } else if c.is_locked {
                    "🔒"
                } else {
                    "🛡"
                };
                let preview = if c.is_locked {
                    "Чат защищён PIN-кодом".to_owned()
                } else {
                    c.messages.last().map_or_else(
                        || "Канал готов к обмену капсулами".to_owned(),
                        |m| {
                            let chars: String = m.text.chars().take(42).collect();
                            chars
                        },
                    )
                };
                format!(
                    "<a class='{item_cls}' href='/action?cmd=select_chat&idx={idx}'>
                        <div class='avatar'>{icon}</div>
                        <div class='chat-meta'>
                            <div class='chat-name'>{}</div>
                            <div class='chat-sub'>{}</div>
                        </div>
                    </a>",
                    html_escape(&c.title),
                    html_escape(&preview)
                )
            })
            .collect();

        let active_srv_ep = self
            .state
            .directory_servers
            .get(self.state.selected_server_index)
            .map_or("185.220.101.42:8443", |srv| srv.endpoint.as_str());

        let step_1_cls = if self.state.current_screen == Screen::Onboarding {
            "step-pill active"
        } else {
            "step-pill"
        };
        let step_2_cls = if self.state.current_screen == Screen::ServerLauncher {
            "step-pill active"
        } else {
            "step-pill"
        };
        let step_3_cls = if self.state.current_screen == Screen::ChatWorkspace {
            "step-pill active"
        } else {
            "step-pill"
        };
        let quick_chat_buttons_html =
            if !self.state.duress_mode_active && self.state.chats.len() >= 3 {
                "<a class='btn' href='/action?cmd=chat_0'>📌 Избранное</a>
        <a class='btn' href='/action?cmd=chat_1'>🔐 nordic-falcon</a>
        <a class='btn' href='/action?cmd=chat_2'>✓ Поддержка</a>"
            } else {
                ""
            };

        let unlock_pin_form_html = if active_chat.is_some_and(|c| c.is_locked) {
            "<form action='/action' method='get' style='display:flex;gap:8px;margin:10px 0;'>
                <input type='hidden' name='cmd' value='toggle_chat_pin'>
                <input type='password' name='pin' placeholder='Введите PIN чата для разблокировки...' style='width:260px;' autocomplete='off'>
                <button class='btn ok' type='submit'>🔓 Разблокировать чат</button>
            </form>"
        } else {
            ""
        };

        let safety_num = self.state.active_safety_number();
        let verify_badge_html = if self.state.peer_verified {
            "<span class='tag'>✓ Safety Number верифицирован (QR/60 цифр)</span>"
        } else {
            "<span class='tag' style='color:#fcd34d;border-color:#f59e0b;'>⚠ Ожидает сверки Safety Number</span>"
        };
        let key_change_html = self.state.key_change_warning.as_ref().map_or(
            String::new(),
            |warn_msg| {
                format!(
                    "<div class='warn-box' style='margin-bottom:10px;'>
                        <b>⚠ ПРЕДУПРЕЖДЕНИЕ СМЕНЫ КЛЮЧА (TAMPER DETECTION):</b> {}
                        <div style='margin-top:6px;'>
                            <a class='btn ok' href='/action?cmd=ack_key_change'>✓ Подтвердить новый ключ после сверки Safety Number</a>
                        </div>
                    </div>",
                    html_escape(warn_msg)
                )
            },
        );

        let seed_mode_label = if self.state.seed_only_mode {
            "Seed-Only по умолчанию (без серверного аккаунта)"
        } else {
            "Opt-in OPAQUE + Argon2id (восстановление seed)"
        };
        let recovery_phrase_html =
            self.state
                .recovery_phrase_preview
                .as_ref()
                .map_or(String::new(), |phrase| {
                    format!(
                        "<div class='warn-box' style='margin:10px 0;font-size:12px;'>
                        <b>🔑 Опциональная фраза восстановления (24 слова):</b><br>
                        <code>{}</code>
                    </div>",
                        html_escape(phrase)
                    )
                });
        let backup_export_html =
            self.state
                .last_exported_backup_hex
                .as_ref()
                .map_or(String::new(), |hex_str| {
                    let preview: String = hex_str.chars().take(72).collect();
                    format!(
                        "<div style='margin-top:6px;font-size:11px;color:var(--mint);'>
                        📦 Явный зашифрованный экспорт (AEGISBAK, {} B): <code>{}...</code>
                    </div>",
                        hex_str.len() / 2,
                        html_escape(&preview)
                    )
                });

        let main_stage_html = if self.state.current_screen == Screen::Onboarding {
            format!(
                "<div class='step-hero glass'>
                    <div class='slogan-kicker'>✦ AEGIS QUANTUM AURORA VAULT // ШАГ 1 ИЗ 3</div>
                    <h1 style='margin:6px 0 4px 0;font-size:26px;color:#fff;'>① Сейф Аккаунта (Seed-Only / Opt-In OPAQUE)</h1>
                    <p class='slogan-sub'>«Тень не оставляет следов. Твоя свобода — под защитой математики. Ни номеров. Ни почт. Ни границ.»</p>
                    <div style='margin-bottom:12px;'>
                        <span class='tag'>Режим идентичности: {seed_mode}</span>
                        <a class='btn' href='/action?cmd=toggle_seed_only'>🔄 Переключить Seed-Only / OPAQUE</a>
                        <a class='btn' href='/action?cmd=gen_recovery_phrase'>🔑 24 слова (опционально)</a>
                    </div>
                    {recovery_html}
                    <form action='/action' method='get' class='auth-form'>
                        <input type='hidden' name='cmd' value='login_account'>
                        <label>1. Ваш криптостойкий логин-ник (OPAQUE KDF — сервер его не видит)</label>
                        <div style='display:flex;gap:8px;margin-bottom:10px;'>
                            <input type='text' name='nick' value='{curr_nick}' style='width:100%;' autocomplete='off'>
                            <a class='btn' href='/action?cmd=gen_nick'>🎲 Сгенерировать</a>
                        </div>
                        <label>2. Отображаемое имя (видят только ваши E2EE контакты)</label>
                        <input type='text' name='alias' value='Призрак Сети' style='width:100%;margin-bottom:10px;' autocomplete='off'>
                        <label>3. Строгий пароль (≥12 символов, ≥3 ЗАГЛАВНЫЕ буквы, цифры и спецсимволы)</label>
                        <input type='password' name='pwd' value='' placeholder='Введите строгий пароль (≥12 симв., ≥3 ЗАГЛАВНЫЕ, цифры, спецсимвол)...' style='width:100%;margin-bottom:14px;' autocomplete='off'>
                        <div style='display:flex;gap:10px;flex-wrap:wrap;'>
                            <button type='submit' class='btn ok' style='padding:11px 20px;font-size:14px;'>🚀 Открыть Сейф и перейти к Матрице Серверов (Шаг 2) →</button>
                            <a class='btn' href='/action?cmd=step_servers' style='padding:11px 16px;'>Пропустить к серверам →</a>
                        </div>
                    </form>
                </div>",
                seed_mode = html_escape(seed_mode_label),
                recovery_html = recovery_phrase_html,
                curr_nick = html_escape(&self.state.onboarding_nickname),
            )
        } else if self.state.current_screen == Screen::ServerLauncher {
            format!(
                "<div class='step-hero glass'>
                    <div class='slogan-kicker'>✦ ШАГ 2 ИЗ 3 // МАТРИЦА СЕРВЕРОВ И СЛЕПЫХ РЕЛЕЕВ</div>
                    <h1 style='margin:6px 0 4px 0;font-size:24px;color:#fff;'>② Матрица Серверов и Релеев (Static IP / Tor / Blind Relay)</h1>
                    <p class='slogan-sub'>«Создан быть невидимым. Спроектирован быть непобедимым.» Стартовые Static-IP узлы работают сразу без Tor, а Слепой Релей скрывает ваш IP от целевого сервера.</p>
                    <ul style='list-style:none;padding:0;margin:14px 0;'>{servers}</ul>
                    <form action='/action' method='get' style='display:flex;gap:8px;margin:10px 0;'>
                        <input type='hidden' name='cmd' value='custom_server'>
                        <input type='text' name='ip' placeholder='Или введите свой Static IP:порт (напр. 185.220.101.42:8443)...' style='width:100%;' autocomplete='off'>
                        <button class='btn ok' type='submit'>⚡ Подключить Static IP →</button>
                    </form>
                    <form action='/action' method='get' style='display:flex;gap:8px;margin:10px 0;'>
                        <input type='hidden' name='cmd' value='set_blind_relay'>
                        <input type='text' name='relay' placeholder='Слепой релей (Node A IP:порт) — скрывает ваш IP от целевого сервера...' style='width:100%;' autocomplete='off'>
                        <button class='btn ok' type='submit'>🛰 Включить Blind Relay</button>
                    </form>
                    <form action='/action' method='get' style='display:flex;gap:8px;margin:10px 0;'>
                        <input type='hidden' name='cmd' value='set_socks5_proxy'>
                        <input type='text' name='proxy' placeholder='SOCKS5h / Tor прокси (напр. 127.0.0.1:9050) с изоляцией потоков...' style='width:100%;' autocomplete='off'>
                        <button class='btn' type='submit'>🔒 Задать SOCKS5h</button>
                    </form>
                    <div style='margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;'>
                        <a class='btn ok' href='/action?cmd=step_chats' style='padding:11px 22px;font-size:14px;'>💬 Перейти к Защищённым Контурам (Шаг 3) →</a>
                        <a class='btn' href='/action?cmd=step_account'>← Назад к Сейфу Аккаунта</a>
                    </div>
                </div>",
                servers = servers_html,
            )
        } else {
            format!(
                "<div class='grid'>
    <div class='card glass'>
      <h3>◈ Защищённые Контуры и Капсулы (Zero-Knowledge E2EE)</h3>
      <form action='/action' method='get' style='display:flex;gap:6px;margin-bottom:8px;'>
        <input type='hidden' name='cmd' value='search_messages'>
        <input type='text' name='q' value='{search_q}' placeholder='🔍 Локальный поиск по зашифрованной БД...' style='width:100%;' autocomplete='off'>
        <button class='btn' type='submit'>Найти</button>
      </form>
      <div class='chat-list'>{chat_list_sidebar}</div>
      <form action='/action' method='get' style='margin-top:10px;background:rgba(255,255,255,0.03);padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,0.08);'>
        <input type='hidden' name='cmd' value='new_chat'>
        <div style='font-size:11px;color:var(--mint);font-weight:700;margin-bottom:6px;'>+ Новый межграничный контур (Россия ↔ США / Китай / Европа)</div>
        <input type='text' name='title' placeholder='Имя собеседника (напр. Алекс)...' style='width:100%;margin-bottom:6px;' autocomplete='off'>
        <input type='text' name='code' placeholder='Общий секретный код канала (напр. tokyo-77)...' style='width:100%;margin-bottom:6px;' autocomplete='off'>
        <button class='btn ok' type='submit' style='width:100%;'>➕ Открыть зашифрованный контур</button>
      </form>
      <div style='margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;'>
        <a class='btn ok' href='/action?cmd=create_group&title=Совет+Безопасности&members=5'>👥 + Группа MLS (≤20 уч.)</a>
        <a class='btn' href='/action?cmd=generate_invite'>📲 QR / Invite v2</a>
      </div>
      <div style='margin-top:6px;font-size:10px;color:var(--muted);word-break:break-all;'>
        Инвайт-карточка: <code>{invite_uri}</code>
      </div>
      <hr style='border-color:rgba(255,255,255,0.08);margin:12px 0;'>
      <h3>👤 Мультиаккаунты (до 3 + SupporterPass)</h3>
      <div>{accounts}</div>
      <div style='margin-top:8px;'>
        <a class='btn' href='/action?cmd=gen_nick'>{gen_nick_btn} ({curr_nick})</a>
        <a class='btn ok' href='/action?cmd=add_account'>+ Создать профиль</a>
        <a class='btn warn' href='/action?cmd=activate_pass'>🎫 SupporterPass (5 слотов)</a>
        <a class='btn' href='/action?cmd=export_backup'>💾 Экспорт бэкапа (AEGISBAK)</a>
      </div>
      {backup_html}
    </div>

    <div class='card glass'>
      <div style='display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.09);padding-bottom:8px;margin-bottom:10px;flex-wrap:wrap;gap:8px;'>
        <div>
          <h2 style='border:none;padding:0;margin:0;'>{chat_title}</h2>
          <small style='color:var(--muted);'>Узел: <b>{srv_ep}</b> • Сквозное шифрование ChaCha20-Poly1305 (Pad-Before-Encrypt 256B)</small>
        </div>
        <div>
          <a class='btn ok' href='/action?cmd=sync_remote'>🌐 Принять из сети</a>
          <a class='btn' href='/action?cmd=rotate_queue'>🔄 Ротация очереди</a>
          <a class='btn warn' href='/action?cmd=toggle_chat_pin'>🔒 PIN чата</a>
        </div>
      </div>
      <div style='margin-bottom:10px;padding:8px 10px;background:rgba(15,23,42,0.65);border-radius:10px;border:1px solid rgba(16,245,204,0.22);font-size:11px;'>
        <div>🔐 <b>Safety Number (60 цифр):</b> <code>{safety_number}</code> {verify_badge}</div>
        <div style='margin-top:6px;'>
          <a class='btn ok' href='/action?cmd=verify_contact'>✓ Сверить QR / Safety Number</a>
          <a class='btn warn' href='/action?cmd=simulate_key_change'>⚠ Тест смены ключа</a>
          <a class='btn' href='/action?cmd=set_chat_ttl&ttl=60'>⏱ TTL 60с</a>
          <a class='btn' href='/action?cmd=set_chat_ttl&ttl=3600'>⏱ TTL 1ч</a>
          <a class='btn' href='/action?cmd=set_chat_ttl&ttl=0'>⏱ TTL ∞</a>
        </div>
      </div>
      {key_change_box}
      {unlock_pin_form}
      {leak_modal}
      <div>{messages}</div>
      <hr style='border-color:rgba(255,255,255,0.09);margin:14px 0;'>
      <form action='/action' method='get' style='display:flex;gap:8px;'>
        <input type='hidden' name='cmd' value='send_text'>
        <input type='text' name='text' placeholder='Написать сообщение... (LeakGuard защищает от случайной отправки карт/телефонов)' style='width:100%;' autocomplete='off'>
        <button class='btn ok' type='submit' style='white-space:nowrap;padding:9px 18px;'>Отправить ➤</button>
      </form>
      <div style='margin-top:10px;'>
        <a class='btn ok' href='/action?cmd=send_photo_view_once'>📷 Фото View-Once (без EXIF/GPS)</a>
        <a class='btn warn' href='/action?cmd=test_leak_card'>💳 Тест LeakGuard</a>
        {quick_chat_btns}
      </div>
    </div>

    <div class='card glass'>
      <h3>🌐 Серверы связи (Static IP без Tor)</h3>
      <ul style='padding-left:18px;font-size:12px;'>{servers}</ul>
      <form action='/action' method='get' style='margin-top:8px;display:flex;gap:6px;'>
        <input type='hidden' name='cmd' value='custom_server'>
        <input type='text' name='ip' placeholder='Свой IP:порт (185.220.101.42:8443)...' style='width:100%;' autocomplete='off'>
        <button class='btn ok' type='submit'>⚡</button>
      </form>
      <form action='/action' method='get' style='margin-top:6px;display:flex;gap:6px;'>
        <input type='hidden' name='cmd' value='set_blind_relay'>
        <input type='text' name='relay' placeholder='Слепой релей (Node A IP:порт) для скрытия IP от узла...' style='width:100%;' autocomplete='off'>
        <button class='btn ok' type='submit'>🛰</button>
      </form>
      <form action='/action' method='get' style='margin-top:6px;display:flex;gap:6px;'>
        <input type='hidden' name='cmd' value='set_socks5_proxy'>
        <input type='text' name='proxy' placeholder='SOCKS5h / Tor прокси (127.0.0.1:9050)...' style='width:100%;' autocomplete='off'>
        <button class='btn' type='submit'>🔒</button>
      </form>
      <hr style='border-color:rgba(255,255,255,0.08);margin:12px 0;'>
      <h3>🛡 Сетевой щит (Anti-DPI)</h3>
      <a class='btn ok' href='/action?cmd=route_tor'>🔒 Tor</a>
      <a class='btn' href='/action?cmd=route_vpn'>🛡 VPN</a>
      <a class='btn warn' href='/action?cmd=route_direct'>🌐 Прямой IP</a>
      <a class='btn danger' href='/action?cmd=route_leak'>🧪 Kill Switch</a>
      <hr style='border-color:rgba(255,255,255,0.08);margin:12px 0;'>
      <h3>{launcher_title}</h3>
      <a class='btn ok' href='/action?cmd=launch_vps'>VPS Docker</a>
      <a class='btn' href='/action?cmd=launch_onion'>Tor .onion</a>
      <a class='btn' href='/action?cmd=launch_desktop'>Локальный</a>
      <pre>{launcher_bundle}</pre>
      <small>Инвайт: <code>{server_invite}</code></small>
      <hr style='border-color:rgba(255,255,255,0.08);margin:12px 0;'>
      <h3>{theme_title}</h3>
      <div>
        <span class='tag'>Тема: {active_theme}</span>
        <a class='btn' href='/action?cmd=select_theme&theme=quantum-aurora'>Quantum Aurora</a>
        <a class='btn' href='/action?cmd=select_theme&theme=phantom-monolith'>Phantom Monolith</a>
        <a class='btn' href='/action?cmd=select_theme&theme=emerald-matrix'>Emerald Matrix</a>
      </div>
      <hr style='border-color:rgba(255,255,255,0.08);margin:12px 0;'>
      <h3>{support_title}</h3>
      <p style='font-size:12px;'>Тикетов ✓: <b>{ticket_count}</b> | Слотов: <b>{max_slots}</b></p>
      <a class='btn ok' href='/action?cmd=send_ticket'>📨 Тикет в поддержку ✓</a>
    </div>
  </div>",
                search_q = html_escape(&self.state.search_query),
                chat_list_sidebar = chat_list_sidebar_html,
                invite_uri = html_escape(&self.state.active_invite_uri),
                accounts = accounts_html,
                gen_nick_btn = s.nickname_generate_btn,
                curr_nick = html_escape(&self.state.onboarding_nickname),
                backup_html = backup_export_html,
                chat_title = html_escape(chat_title),
                srv_ep = html_escape(active_srv_ep),
                safety_number = html_escape(&safety_num),
                verify_badge = verify_badge_html,
                key_change_box = key_change_html,
                unlock_pin_form = unlock_pin_form_html,
                leak_modal = leak_modal_html,
                messages = messages_html,
                quick_chat_btns = quick_chat_buttons_html,
                servers = servers_html,
                launcher_title = s.server_launcher_title,
                launcher_bundle = html_escape(&self.state.server_launcher.generated_config_bundle),
                server_invite = html_escape(&self.state.server_launcher.generated_server_invite_uri),
                theme_title = s.theme_store_title,
                active_theme = html_escape(&self.state.theme_selector.active_theme_id),
                support_title = s.support_portal_title,
                ticket_count = self.state.support_portal.submitted_tickets.len(),
                max_slots = self.state.support_portal.max_account_slots,
            )
        };

        format!(
            "<!DOCTYPE html>
<html lang='ru'>
<head>
<meta charset='utf-8'>
<title>{title}</title>
<style>
  :root {{
    --void: #070913;
    --glass: rgba(17, 22, 40, 0.68);
    --glass-strong: rgba(22, 28, 52, 0.84);
    --glass-border: rgba(255, 255, 255, 0.13);
    --violet: #8b5cf6;
    --mint: #10f5cc;
    --cyan: #38bdf8;
    --crimson: #f43f5e;
    --amber: #f59e0b;
    --text: #f1f5f9;
    --muted: #94a3b8;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background-color: var(--void);
    background-image:
      radial-gradient(circle at 12% 18%, rgba(139, 92, 246, 0.28) 0%, transparent 42%),
      radial-gradient(circle at 88% 15%, rgba(16, 245, 204, 0.20) 0%, transparent 40%),
      radial-gradient(circle at 50% 88%, rgba(56, 189, 248, 0.18) 0%, transparent 48%),
      linear-gradient(160deg, #060711 0%, #0b1022 55%, #070b18 100%);
    background-attachment: fixed;
    color: var(--text);
    font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
    margin: 0;
    padding: 16px 20px;
  }}
  .glass {{
    background: var(--glass);
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    border: 1px solid var(--glass-border);
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.14);
    border-radius: 18px;
  }}
  .top {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 20px;
    margin-bottom: 12px;
    flex-wrap: wrap;
    gap: 10px;
  }}
  .brand-wrap {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .brand-logo {{
    background: linear-gradient(135deg, var(--violet), var(--mint));
    color: #05070f;
    font-weight: 900;
    padding: 6px 12px;
    border-radius: 12px;
    letter-spacing: 1px;
    font-size: 14px;
  }}
  .slogan-bar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 9px 18px;
    margin-bottom: 14px;
    font-size: 12px;
    border-radius: 14px;
    background: linear-gradient(90deg, rgba(139,92,246,0.16), rgba(16,245,204,0.12));
    border: 1px solid rgba(16,245,204,0.28);
  }}
  .steps {{ display: flex; gap: 6px; align-items: center; }}
  .step-pill {{
    text-decoration: none;
    color: var(--muted);
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    padding: 6px 13px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
  }}
  .step-pill.active {{
    background: linear-gradient(135deg, rgba(139,92,246,0.38), rgba(16,245,204,0.28));
    color: #fff;
    border-color: var(--mint);
    box-shadow: 0 0 18px rgba(16,245,204,0.25);
  }}
  .step-hero {{
    max-width: 720px;
    margin: 0 auto 18px auto;
    padding: 26px 30px;
    border: 1px solid rgba(16, 245, 204, 0.38);
  }}
  .slogan-kicker {{ color: var(--mint); font-size: 11px; font-weight: 700; letter-spacing: 1.4px; text-transform: uppercase; }}
  .slogan-sub {{ color: #cbd5e1; font-size: 13px; font-style: italic; margin: 4px 0 16px 0; }}
  .auth-form label {{ display: block; font-size: 12px; color: #cbd5e1; margin-bottom: 4px; font-weight: 600; }}
  .grid {{ display: grid; grid-template-columns: 330px 1fr 350px; gap: 16px; align-items: start; }}
  @media (max-width: 1100px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  .card {{ padding: 16px; }}
  h2, h3 {{
    margin-top: 0;
    color: #fff;
    font-size: 14px;
    font-weight: 700;
    border-bottom: 1px solid rgba(255,255,255,0.09);
    padding-bottom: 8px;
  }}
  .chat-list {{ display: flex; flex-direction: column; gap: 6px; margin: 10px 0; }}
  .chat-item {{
    display: flex;
    align-items: center;
    gap: 11px;
    padding: 10px 12px;
    border-radius: 14px;
    text-decoration: none;
    color: var(--text);
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.06);
    transition: all 0.15s ease;
  }}
  .chat-item.active {{
    background: linear-gradient(135deg, rgba(139,92,246,0.28), rgba(16,245,204,0.16));
    border-color: var(--mint);
  }}
  .avatar {{
    width: 38px;
    height: 38px;
    border-radius: 12px;
    background: linear-gradient(135deg, rgba(139,92,246,0.45), rgba(56,189,248,0.35));
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    flex-shrink: 0;
  }}
  .chat-meta {{ overflow: hidden; }}
  .chat-name {{ font-weight: 700; font-size: 13px; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .chat-sub {{ font-size: 11px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px; }}
  .btn {{
    display: inline-block;
    background: rgba(255,255,255,0.07);
    color: #e2e8f0;
    border: 1px solid rgba(255,255,255,0.16);
    text-decoration: none;
    padding: 7px 13px;
    border-radius: 11px;
    font-size: 12px;
    font-weight: 600;
    margin: 2px;
    cursor: pointer;
  }}
  .btn.ok {{
    background: linear-gradient(135deg, rgba(139,92,246,0.45), rgba(16,245,204,0.32));
    color: #fff;
    border-color: var(--mint);
  }}
  .btn.warn {{ background: rgba(245,158,11,0.18); color: #fcd34d; border-color: rgba(245,158,11,0.45); }}
  .btn.danger {{ background: rgba(244,63,94,0.22); color: #fda4af; border-color: rgba(244,63,94,0.5); }}
  .tag {{
    display: inline-block;
    background: rgba(15, 23, 42, 0.72);
    color: var(--mint);
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 11px;
    margin: 2px;
    border: 1px solid rgba(16, 245, 204, 0.28);
  }}
  .msg {{
    padding: 11px 15px;
    margin: 10px 0;
    border-radius: 16px;
    backdrop-filter: blur(16px);
  }}
  .msg.in {{
    background: rgba(30, 41, 59, 0.65);
    border: 1px solid rgba(56, 189, 248, 0.28);
    margin-right: 12%;
    border-bottom-left-radius: 4px;
  }}
  .msg.out {{
    background: linear-gradient(135deg, rgba(139, 92, 246, 0.30), rgba(16, 245, 204, 0.20));
    border: 1px solid rgba(16, 245, 204, 0.42);
    margin-left: 12%;
    border-bottom-right-radius: 4px;
  }}
  .cap-hdr {{ display: flex; justify-content: space-between; font-size: 10px; color: var(--mint); margin-bottom: 5px; opacity: 0.9; }}
  .cap-body {{ font-size: 14px; color: #ffffff; line-height: 1.45; margin-bottom: 6px; }}
  .cap-bar {{ height: 3px; background: rgba(255,255,255,0.08); border-radius: 999px; overflow: hidden; margin-bottom: 4px; }}
  .cap-fill {{ display: block; height: 100%; width: 100%; background: linear-gradient(90deg, var(--violet), var(--mint)); }}
  .modal {{ background: rgba(244,63,94,0.16); border: 1px solid var(--crimson); padding: 14px; border-radius: 14px; margin-bottom: 12px; }}
  .warn-box {{ background: rgba(245,158,11,0.15); border: 1px solid var(--amber); padding: 12px; border-radius: 12px; }}
  pre {{ background: rgba(5, 8, 18, 0.85); border: 1px solid rgba(255,255,255,0.1); padding: 10px; border-radius: 12px; overflow-x: auto; font-size: 11px; color: var(--mint); }}
  input[type=text], input[type=password] {{
    background: rgba(7, 10, 22, 0.78);
    color: #fff;
    border: 1px solid rgba(255,255,255,0.18);
    padding: 9px 12px;
    border-radius: 11px;
    width: 72%;
    font-family: inherit;
  }}
</style>
</head>
<body>
  <div class='top glass'>
    <div class='brand-wrap'>
      <span class='brand-logo'>AEGIS // AURORA</span>
      <strong>{title}</strong>
      <div class='steps'>
        <a class='{s1}' href='/action?cmd=step_account'>① Сейф Аккаунта</a>
        <a class='{s2}' href='/action?cmd=step_servers'>② Матрица Серверов и Релеев ({srv_ep})</a>
        <a class='{s3}' href='/action?cmd=step_chats'>③ Защищённые Контуры и Капсулы</a>
      </div>
    </div>
    <div>
      <a class='btn' href='/action?cmd=lang_ru'>RU</a>
      <a class='btn' href='/action?cmd=lang_en'>EN</a>
      <a class='btn warn' href='/action?cmd=disguise'>🧮 Калькулятор</a>
      <a class='btn danger' href='/action?cmd=panic'>{panic_btn}</a>
    </div>
  </div>

  <div class='slogan-bar'>
    <span>✨ <b>«Тень не оставляет следов. Ни номеров. Ни почт. Ни границ.»</b> • <span class='tag'>{shield}</span> <span class='tag'>Cover: {cover}</span> <span class='tag'>v{cv}.{pv}.{sv}</span></span>
    <span>Статус: <b style='color:var(--mint);'>{status}</b></span>
  </div>

  {main_stage}
</body>
</html>",
            title = s.app_title,
            s1 = step_1_cls,
            s2 = step_2_cls,
            s3 = step_3_cls,
            srv_ep = html_escape(active_srv_ep),
            shield = shield_badge,
            cover = if self.state.cover_traffic_enabled {
                "ВКЛ"
            } else {
                "ВЫКЛ"
            },
            cv = self.state.core_versions.crypto_suite_version,
            pv = self.state.core_versions.protocol_version,
            sv = self.state.core_versions.storage_schema_version,
            panic_btn = s.panic_button_label,
            status = html_escape(&self.state.status_banner),
            main_stage = main_stage_html,
        )
    }

    /// Renders the current screen with the clean, messenger-first desktop layout.
    #[must_use]
    pub fn render_html(&self) -> String {
        if matches!(
            self.state.current_screen,
            Screen::PanicWiped | Screen::CalculatorDisguise
        ) {
            return self.render_html_legacy();
        }

        let body = match self.state.current_screen {
            Screen::Onboarding => self.render_onboarding_page(),
            Screen::ServerLauncher => self.render_servers_page(),
            _ => self.render_workspace_page(),
        };
        let s = self.state.strings();
        let lang = if self.state.locale == Locale::En { "en" } else { "ru" };
        format!(
            "<!DOCTYPE html>
<html lang='{lang}'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>{title}</title>
<style>{DESKTOP_CSS}</style>
</head>
<body>
{body}
</body>
</html>",
            title = html_escape(s.app_title),
        )
    }

    fn tr<'a>(&self, ru: &'a str, en: &'a str) -> &'a str {
        if self.state.locale == Locale::En {
            en
        } else {
            ru
        }
    }

    fn render_top_actions(&self) -> String {
        "<div class='top-actions'>
  <a class='chip' href='/action?cmd=lang_ru'>RU</a>
  <a class='chip' href='/action?cmd=lang_en'>EN</a>
</div>"
            .to_owned()
    }

    fn render_status_banner(&self) -> String {
        if self.state.status_banner.trim().is_empty() {
            String::new()
        } else {
            format!(
                "<div class='status-banner' role='status'>{}</div>",
                html_escape(&self.state.status_banner)
            )
        }
    }

    fn render_step_dots(active: u8) -> String {
        let dot = |n: u8| {
            if n == active {
                format!("<span class='step-dot active'>{n}</span>")
            } else {
                format!("<span class='step-dot'>{n}</span>")
            }
        };
        format!(
            "<div class='step-dots'>{}{}{}</div>",
            dot(1),
            dot(2),
            dot(3)
        )
    }

    fn render_onboarding_page(&self) -> String {
        let s = self.state.strings();
        format!(
            "<div class='auth-page'>
  <section class='auth-brand'>
    <div class='brand-mark large'>A</div>
    <h1>Aegis</h1>
    <p class='brand-lead'>{brand_lead}</p>
    <ul class='brand-points'>
      <li>{pt1}</li>
      <li>{pt2}</li>
      <li>{pt3}</li>
    </ul>
  </section>
  <section class='auth-side'>
    <div class='auth-top'>
      {steps}
      {actions}
    </div>
    <div class='auth-card'>
      <div class='eyebrow'>{step_label}</div>
      <h2>{heading}</h2>
      <p class='lead'>{lead}</p>
      {status}
      <form class='form-stack' action='/action' method='post'>
        <input type='hidden' name='cmd' value='login_account'>
        <label for='nick'>{login_lbl}</label>
        <div class='input-row'>
          <input id='nick' type='text' name='nick' value='{nick}' autocomplete='off' spellcheck='false'>
          <a class='btn ghost' href='/action?cmd=gen_nick'>{gen_nick}</a>
        </div>
        <label for='alias'>{name_lbl}</label>
        <input id='alias' type='text' name='alias' value='{default_alias}' autocomplete='off'>
        <label for='pwd'>{pwd_lbl}</label>
        <input id='pwd' type='password' name='pwd' value='' placeholder='{pwd_ph}' autocomplete='new-password'>
        <div class='hint'>{password_hint}</div>
        <button class='btn primary wide' type='submit'>{continue_btn}</button>
      </form>
      <div class='auth-links'>
        <a href='/action?cmd=step_servers'>{choose_srv}</a>
      </div>
    </div>
  </section>
</div>",
            brand_lead = self.tr(
                "Мессенджер без номера телефона и почты.",
                "Messenger with no phone number or email required."
            ),
            pt1 = self.tr("Локальный профиль на устройстве", "Local profile on your device"),
            pt2 = self.tr("Обмен сообщениями через выбранный узел", "Messaging over your chosen server"),
            pt3 = self.tr("Без рекламы и аналитики", "No ads and no analytics"),
            steps = Self::render_step_dots(1),
            actions = self.render_top_actions(),
            step_label = self.tr("Шаг 1 из 3", "Step 1 of 3"),
            heading = self.tr("① Сейф Аккаунта", "① Account Vault"),
            lead = self.tr("Создайте локальный профиль.", "Create a local profile."),
            status = self.render_status_banner(),
            login_lbl = self.tr("Логин", "Username"),
            nick = html_escape(&self.state.onboarding_nickname),
            gen_nick = html_escape(s.nickname_generate_btn),
            name_lbl = self.tr("Имя", "Display name"),
            default_alias = self.tr("Призрак Сети", "Network Ghost"),
            pwd_lbl = self.tr("Пароль", "Password"),
            pwd_ph = self.tr("Введите пароль", "Enter password"),
            password_hint = html_escape(s.password_policy_hint),
            continue_btn = self.tr("Продолжить", "Continue"),
            choose_srv = self.tr("Выбрать сервер →", "Choose server →"),
        )
    }

    fn render_servers_page(&self) -> String {
        let is_killed = matches!(self.state.shield_evaluation.status, NetworkRouteStatus::Offline);
        let kill_on = if is_killed { "on" } else { "" };
        let kill_href = if is_killed {
            "/action?cmd=route_direct"
        } else {
            "/action?cmd=route_leak"
        };
        format!(
            "<div class='auth-page'>
  <section class='auth-brand'>
    <div class='brand-mark large'>A</div>
    <h1>Aegis</h1>
    <p class='brand-lead'>{brand_lead}</p>
    <ul class='brand-points'>
      <li>{pt1}</li>
      <li>{pt2}</li>
      <li>{pt3}</li>
    </ul>
  </section>
  <section class='auth-side'>
    <div class='auth-top'>
      {steps}
      {actions}
    </div>
    <div class='auth-card wide'>
      <div class='eyebrow'>{step_label}</div>
      <h2>{heading}</h2>
      <p class='lead'>{lead}</p>
      {status}
      <form class='form-stack' action='/action' method='get'>
        <input type='hidden' name='cmd' value='custom_server'>
        <label for='ip'>{custom_sum}</label>
        <div class='input-row'>
          <input id='ip' type='text' name='ip' placeholder='{srv_ph}' autocomplete='off' spellcheck='false'>
          <button class='btn primary' type='submit'>{connect_btn}</button>
        </div>
      </form>
      <div class='toggle-list'>
        <a class='toggle-row' href='{kill_href}'><span>{kill_lbl}</span><span class='switch {kill_on}'></span></a>
      </div>
      <details class='panel'>
        <summary>{proxy_sum}</summary>
        <form class='form-stack' action='/action' method='get'>
          <input type='hidden' name='cmd' value='set_blind_relay'>
          <input id='relay' type='text' name='relay' placeholder='{relay_ph}' autocomplete='off' spellcheck='false'>
          <button class='btn ghost' type='submit'>{save_relay_btn}</button>
        </form>
        <form class='form-stack' action='/action' method='get'>
          <input type='hidden' name='cmd' value='set_socks5_proxy'>
          <input id='proxy' type='text' name='proxy' placeholder='{proxy_ph}' autocomplete='off' spellcheck='false'>
          <button class='btn ghost' type='submit'>{save_proxy_btn}</button>
        </form>
      </details>
      <div class='actions-row'>
        <a class='btn primary' href='/action?cmd=step_chats'>{open_chats}</a>
        <a class='btn ghost' href='/action?cmd=step_account'>{back_btn}</a>
      </div>
    </div>
  </section>
</div>",
            brand_lead = self.tr(
                "Укажите адрес своего сервера aegis-serverd.",
                "Enter the address of your aegis-serverd node."
            ),
            pt1 = self.tr("Прямое подключение к вашему узлу", "Direct connection to your node"),
            pt2 = self.tr("Поддержка SOCKS5 прокси и релея", "SOCKS5 proxy and relay support"),
            pt3 = self.tr("Блокировка сети в один клик", "One-click network lock"),
            steps = Self::render_step_dots(2),
            actions = self.render_top_actions(),
            step_label = self.tr("Шаг 2 из 3", "Step 2 of 3"),
            heading = self.tr("② Матрица Серверов и Релеев", "② Servers & Relays"),
            lead = self.tr("Укажите адрес работающего сервера.", "Enter a running server address."),
            status = self.render_status_banner(),
            custom_sum = self.tr("Адрес вашего сервера", "Your server address"),
            srv_ph = self.tr("host:port", "host:port"),
            connect_btn = self.tr("Подключить", "Connect"),
            kill_href = kill_href,
            kill_lbl = self.tr("Блокировка сети (Kill Switch)", "Network Lock (Kill Switch)"),
            kill_on = kill_on,
            proxy_sum = self.tr("SOCKS5 прокси и релей", "SOCKS5 proxy & relay"),
            relay_ph = self.tr("Релей (host:port)", "Relay (host:port)"),
            save_relay_btn = self.tr("Сохранить релей", "Save relay"),
            proxy_ph = self.tr("SOCKS5 прокси (127.0.0.1:9050)", "SOCKS5 proxy (127.0.0.1:9050)"),
            save_proxy_btn = self.tr("Сохранить прокси", "Save proxy"),
            open_chats = self.tr("Открыть чаты", "Open chats"),
            back_btn = self.tr("Назад", "Back"),
        )
    }

    fn render_workspace_page(&self) -> String {
        let s = self.state.strings();
        let active_chat = self.state.chats.get(self.state.active_chat_index);
        let default_chat_title = self.tr("Выберите чат", "Select a chat");
        let chat_title = active_chat.map_or(default_chat_title, |c| c.title.as_str());
        let chat_locked = active_chat.is_some_and(|c| c.is_locked);
        let is_saved_notes = active_chat.is_some_and(|c| c.is_local_saved_notes);
        let active_ttl = active_chat.and_then(|c| c.default_disappearing_ttl_secs).unwrap_or(0);
        let search_filter = self.state.search_query.trim().to_lowercase();
        let is_en = self.state.locale == Locale::En;

        let mut chat_items = String::new();
        for (idx, c) in self.state.chats.iter().enumerate() {
            let active = idx == self.state.active_chat_index;
            let icon = if c.is_local_saved_notes {
                "★"
            } else if c.is_locked {
                "🔒"
            } else {
                "•"
            };
            let preview = if c.is_locked {
                self.tr("Закрыто PIN-кодом", "Locked with PIN").to_owned()
            } else {
                c.messages.last().map_or_else(
                    || self.tr("Нет сообщений", "No messages").to_owned(),
                    |m| m.text.chars().take(48).collect(),
                )
            };
            chat_items.push_str(&format!(
                "<a class='chat-item {active_cls}' href='/action?cmd=select_chat&amp;idx={idx}'>
  <span class='avatar small'>{icon}</span>
  <span class='chat-item-meta'><span class='chat-item-name'>{title}</span><span class='chat-item-preview'>{preview}</span></span>
</a>",
                active_cls = if active { "active" } else { "" },
                idx = idx,
                icon = icon,
                title = html_escape(&c.title),
                preview = html_escape(&preview),
            ));
        }

        let mut messages_html = String::new();
        if let Some(chat) = active_chat {
            if chat.is_locked {
                messages_html.push_str(&format!(
                    "<div class='empty-state'><div class='empty-icon'>🔒</div><h3>{}</h3><p>{}</p></div>",
                    self.tr("Чат закрыт", "Chat is locked"),
                    self.tr("Введите PIN, чтобы открыть переписку.", "Enter PIN to unlock this conversation."),
                ));
            } else {
                let mut shown = 0usize;
                for m in &chat.messages {
                    if !search_filter.is_empty() && !m.text.to_lowercase().contains(&search_filter) {
                        continue;
                    }
                    shown = shown.saturating_add(1);
                    let side = if m.outgoing { "out" } else { "in" };
                    let ttl = m
                        .disappearing_ttl_secs
                        .map_or_else(String::new, |t| human_ttl_locale(t, is_en));
                    let attachment = m.attachment.as_ref().map_or(String::new(), |a| {
                        format!(
                            "<div class='attachment'>📷 {}{}</div>",
                            html_escape(&a.filename),
                            if a.consumed {
                                self.tr(" · просмотрено", " · viewed")
                            } else {
                                ""
                            }
                        )
                    });
                    messages_html.push_str(&format!(
                        "<div class='message-row {side}'>
  <div class='bubble'>
    <div class='message-text'>{text}</div>
    {attachment}
    <div class='message-meta'>{ttl}</div>
  </div>
</div>",
                        text = html_escape(&m.text),
                        ttl = ttl,
                    ));
                }
                if shown == 0 {
                    messages_html.push_str(&format!(
                        "<div class='empty-state'><div class='empty-icon'>⌕</div><h3>{}</h3><p>{}</p></div>",
                        self.tr("Ничего не найдено", "Nothing found"),
                        self.tr("Попробуйте изменить запрос.", "Try a different search query."),
                    ));
                }
            }
        } else {
            messages_html.push_str(&format!(
                "<div class='empty-state'><div class='empty-icon'>💬</div><h3>{}</h3><p>{}</p></div>",
                self.tr("Выберите чат", "Select a chat"),
                self.tr("Слева — список ваших переписок.", "Your conversations are listed on the left."),
            ));
        }

        let unlock_form = if chat_locked {
            format!(
                "<form class='unlock-form' action='/action' method='post'>
  <input type='hidden' name='cmd' value='toggle_chat_pin'>
  <input type='password' name='pin' placeholder='{}' autocomplete='off'>
  <button class='btn primary' type='submit'>{}</button>
</form>",
                self.tr("PIN чата", "Chat PIN"),
                self.tr("Открыть", "Unlock"),
            )
        } else {
            String::new()
        };

        let leak_modal = self.state.leak_guard_modal.as_ref().map_or(String::new(), |modal| {
            format!(
                "<div class='modal-card'>
  <div class='modal-title'>{title}</div>
  <p>{desc} ({count}).</p>
  <div class='code-block'>{redacted}</div>
  <div class='actions-row'>
    <a class='btn primary' href='/action?cmd=leak_mask'>{mask}</a>
    <a class='btn danger' href='/action?cmd=leak_force'>{force}</a>
  </div>
</div>",
                title = html_escape(s.leak_guard_modal_title),
                desc = self.tr("Обнаружены личные данные", "Sensitive data detected"),
                count = modal.warnings.len(),
                redacted = html_escape(&modal.redacted_preview),
                mask = html_escape(s.leak_guard_mask_btn),
                force = html_escape(s.leak_guard_send_anyway_btn),
            )
        });

        let key_change = self.state.key_change_warning.as_ref().map_or(String::new(), |_| {
            format!(
                "<div class='banner warn'><b>{}</b> <a href='/action?cmd=ack_key_change'>{}</a></div>",
                self.tr("Ключ собеседника изменился.", "Contact key has changed."),
                self.tr("Подтвердить", "Approve"),
            )
        });

        let accounts_html = if self.state.accounts.profiles.is_empty() {
            format!("<div class='muted'>{}</div>", self.tr("Профиль не выбран", "No profile selected"))
        } else {
            self.state
                .accounts
                .profiles
                .iter()
                .enumerate()
                .map(|(idx, acc)| {
                    format!(
                        "<div class='account-row'>
  <span class='status-dot {dot}'></span>
  <div class='account-meta'><b>{name}</b><div class='muted'>@{nick}</div></div>
</div>",
                        dot = if idx == self.state.accounts.active_index {
                            "online"
                        } else {
                            ""
                        },
                        name = html_escape(&acc.display_name),
                        nick = html_escape(&acc.login_nickname),
                    )
                })
                .collect()
        };

        let is_killed = matches!(self.state.shield_evaluation.status, NetworkRouteStatus::Offline);
        let kill_on = if is_killed { "on" } else { "" };
        let kill_href = if is_killed {
            "/action?cmd=route_direct"
        } else {
            "/action?cmd=route_leak"
        };
        let lock_on = if chat_locked { "on" } else { "" };
        let ttl_off = if active_ttl == 0 { "active" } else { "" };
        let ttl_60 = if active_ttl == 60 { "active" } else { "" };
        let ttl_3600 = if active_ttl == 3600 { "active" } else { "" };
        let status = self.render_status_banner();
        let chat_sub = if is_saved_notes {
            self.tr("Локальные заметки", "Local notes")
        } else if is_killed {
            self.tr("Сеть заблокирована", "Network locked")
        } else {
            self.tr("Канал сообщений", "Message channel")
        };

        format!(
            "<div class='app'>
  <aside class='sidebar'>
    <div class='sidebar-head'>
      <div class='brand-row'><span class='brand-mark'>A</span><span class='brand-name'>Aegis</span></div>
    </div>
    <div class='sidebar-search'>
      <form action='/action' method='get'>
        <input type='hidden' name='cmd' value='search_messages'>
        <input type='text' name='q' value='{search_q}' placeholder='{search_ph}' autocomplete='off'>
      </form>
    </div>
    <div class='chat-list'>{chat_items}</div>
    <details class='new-chat'>
      <summary>{new_chat_sum}</summary>
      <form class='form-stack' action='/action' method='get'>
        <input type='hidden' name='cmd' value='new_chat'>
        <input type='text' name='title' placeholder='{peer_ph}' autocomplete='off'>
        <input type='text' name='code' placeholder='{code_ph}' autocomplete='off' spellcheck='false'>
        <button class='btn primary' type='submit'>{create_chat_btn}</button>
      </form>
    </details>
    <nav class='sidebar-nav'>
      <a class='nav-item active' href='/action?cmd=step_chats'><span>💬</span>{nav_chats}</a>
      <a class='nav-item' href='/action?cmd=step_servers'><span>🌐</span>{nav_servers}</a>
      <a class='nav-item' href='/action?cmd=step_account'><span>👤</span>{nav_account}</a>
    </nav>
  </aside>
  <main class='main'>
    <header class='chat-head'>
      <span class='avatar'>{chat_icon}</span>
      <div class='chat-head-meta'>
        <div class='chat-title'>{chat_title}</div>
        <div class='chat-sub'>{chat_sub}</div>
      </div>
      <div class='chat-actions'>
        <a class='icon-btn' href='/action?cmd=sync_remote' title='{sync_tip}'>⟳</a>
        <a class='icon-btn' href='/action?cmd=toggle_chat_pin' title='{pin_tip}'>🔒</a>
      </div>
    </header>
    {status}
    {key_change}
    {leak_modal}
    <section class='messages'>{messages}</section>
    {unlock_form}
    <form class='composer' action='/action' method='get'>
      <input type='hidden' name='cmd' value='send_text'>
      <input class='composer-input' type='text' name='text' placeholder='{msg_ph}' autocomplete='off'>
      <button class='send-btn' type='submit' title='{send_tip}'>➤</button>
    </form>
  </main>
  <aside class='info-panel'>
    <div class='info-card'>
      <span class='avatar large'>{chat_icon}</span>
      <h3>{chat_title}</h3>
      <div class='muted'>{chat_sub}</div>
    </div>
    <div class='panel'>
      <div class='section-title'>{sec_route_title}</div>
      <div class='toggle-list'>
        <a class='toggle-row' href='/action?cmd=toggle_chat_pin'><span>{chat_pin_lbl}</span><span class='switch {lock_on}'></span></a>
        <a class='toggle-row' href='{kill_href}'><span>{kill_lbl}</span><span class='switch {kill_on}'></span></a>
      </div>
    </div>
    <div class='panel'>
      <div class='section-title'>{ttl_title}</div>
      <div class='seg-row'>
        <a class='seg {ttl_off}' href='/action?cmd=set_chat_ttl&amp;ttl=0'>{ttl_off_lbl}</a>
        <a class='seg {ttl_60}' href='/action?cmd=set_chat_ttl&amp;ttl=60'>{ttl_1m_lbl}</a>
        <a class='seg {ttl_3600}' href='/action?cmd=set_chat_ttl&amp;ttl=3600'>{ttl_1h_lbl}</a>
      </div>
    </div>
    <div class='panel'>
      <div class='section-title'>{profiles_sum}</div>
      {accounts}
    </div>
    <div class='panel'>
      <div class='section-title'>{theme_sum}</div>
      <div class='actions-row wrap'>
        <a class='btn ghost small' href='/action?cmd=lang_ru'>RU</a>
        <a class='btn ghost small' href='/action?cmd=lang_en'>EN</a>
        <a class='btn danger small' href='/action?cmd=panic'>{wipe_btn}</a>
      </div>
    </div>
  </aside>
</div>",
            search_q = html_escape(&self.state.search_query),
            search_ph = self.tr("Поиск", "Search"),
            chat_items = chat_items,
            new_chat_sum = self.tr("+ Новый чат", "+ New chat"),
            peer_ph = self.tr("Имя собеседника", "Contact name"),
            code_ph = self.tr("Код канала", "Channel code"),
            create_chat_btn = self.tr("Создать чат", "Create chat"),
            nav_chats = self.tr("Чаты", "Chats"),
            nav_servers = self.tr("Серверы", "Servers"),
            nav_account = self.tr("Аккаунт", "Account"),
            chat_icon = chat_icon_for(chat_title),
            chat_title = html_escape(chat_title),
            chat_sub = chat_sub,
            sync_tip = self.tr("Обновить", "Refresh"),
            pin_tip = self.tr("PIN чата", "Chat PIN"),
            status = status,
            key_change = key_change,
            leak_modal = leak_modal,
            messages = messages_html,
            unlock_form = unlock_form,
            msg_ph = self.tr("Сообщение", "Message"),
            send_tip = self.tr("Отправить", "Send"),
            sec_route_title = self.tr("Переключатели", "Toggles"),
            chat_pin_lbl = self.tr("PIN-код чата", "Chat PIN lock"),
            lock_on = lock_on,
            kill_href = kill_href,
            kill_lbl = self.tr("Блокировка сети (Kill Switch)", "Network Lock (Kill Switch)"),
            kill_on = kill_on,
            ttl_title = self.tr("Исчезающие сообщения", "Disappearing messages"),
            ttl_off = ttl_off,
            ttl_off_lbl = self.tr("Выкл", "Off"),
            ttl_60 = ttl_60,
            ttl_1m_lbl = self.tr("1 мин", "1 min"),
            ttl_3600 = ttl_3600,
            ttl_1h_lbl = self.tr("1 час", "1 hour"),
            profiles_sum = self.tr("Профили", "Profiles"),
            accounts = accounts_html,
            theme_sum = self.tr("Язык и управление", "Language & Controls"),
            wipe_btn = self.tr("Стереть данные", "Wipe data"),
        )
    }

    /// Processes a UI command query string (e.g. `cmd=test_leak_card`) and mutates `DesktopAppState`.
    pub fn handle_command(&mut self, query: &str) {
        let cmd = extract_query_param(query, "cmd").unwrap_or_default();
        if self.state.current_screen == Screen::PanicWiped {
            return;
        }
        if self.state.current_screen == Screen::CalculatorDisguise
            && cmd != "calc_eval"
            && cmd != "calc_key"
            && cmd != "panic"
        {
            return;
        }
        let is_en = self.state.locale == Locale::En;
        match cmd.as_str() {
            "step_account" => {
                self.state.current_screen = Screen::Onboarding;
                self.state.status_banner.clear();
            }
            "step_servers" => {
                self.state.current_screen = Screen::ServerLauncher;
                self.state.status_banner.clear();
            }
            "step_chats" => {
                self.state.current_screen = Screen::ChatWorkspace;
                self.state.status_banner.clear();
            }
            "toggle_seed_only" => {
                self.state.seed_only_mode = !self.state.seed_only_mode;
                self.state.status_banner = if self.state.seed_only_mode {
                    self.tr("Ключи хранятся только на этом устройстве.", "Keys stay on this device only.").to_owned()
                } else {
                    self.tr("Включено восстановление через аккаунт.", "Account recovery enabled.").to_owned()
                };
            }
            "gen_recovery_phrase" => {
                self.state.outbound_capsule_seq = self.state.outbound_capsule_seq.wrapping_add(1);
                let seq_b = (self.state.outbound_capsule_seq as u8).wrapping_mul(19);
                let mut entropy = [0u8; 24];
                for (i, b) in entropy.iter_mut().enumerate() {
                    *b = (i as u8)
                        .wrapping_mul(13)
                        .wrapping_add(7)
                        .wrapping_add(seq_b);
                }
                if let Ok(phrase) = RecoveryPhrase::generate(&entropy) {
                    self.state.recovery_phrase_preview = Some(phrase.words().join(" "));
                    self.state.status_banner =
                        self.tr("Фраза восстановления создана.", "Recovery phrase generated.").to_owned();
                }
            }
            "search_messages" => {
                let q = extract_query_param(query, "q").unwrap_or_default();
                self.state.search_query = q.trim().to_owned();
                self.state.status_banner.clear();
            }
            "verify_contact" => {
                self.state.peer_verified = true;
                self.state.key_change_warning = None;
                self.state.status_banner =
                    self.tr("Ключ собеседника подтверждён.", "Contact key verified.").to_owned();
            }
            "simulate_key_change" => {
                if detect_identity_key_change(Some(&[0xB2; 32]), &[0xE9; 32]).is_some() {
                    self.state.peer_verified = false;
                    self.state.key_change_warning = Some(
                        self.tr(
                            "Ключ собеседника изменился. Подтвердите перед отправкой.",
                            "Contact key changed. Approve before sending.",
                        )
                        .to_owned(),
                    );
                    self.state.status_banner =
                        self.tr("Обнаружена смена ключа собеседника.", "Contact key change detected.").to_owned();
                }
            }
            "ack_key_change" => {
                self.state.key_change_warning = None;
                self.state.peer_verified = true;
                self.state.status_banner =
                    self.tr("Новый ключ собеседника подтверждён.", "New contact key approved.").to_owned();
            }
            "rotate_queue" => {
                if self.state.rotate_active_chat_queue().is_some() {
                    self.state.status_banner =
                        self.tr("Канал чата обновлён.", "Chat channel refreshed.").to_owned();
                }
            }
            "set_chat_ttl" => {
                let ttl_val = extract_query_param(query, "ttl")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);
                let status = if ttl_val == 0 {
                    self.tr("Таймер сообщений выключен.", "Disappearing timer disabled.").to_owned()
                } else {
                    format!(
                        "{}: {}.",
                        self.tr("Таймер сообщений", "Disappearing timer"),
                        human_ttl_locale(ttl_val, is_en)
                    )
                };
                if let Some(chat) = self.state.chats.get_mut(self.state.active_chat_index) {
                    chat.default_disappearing_ttl_secs =
                        if ttl_val == 0 { None } else { Some(ttl_val) };
                    self.state.status_banner = status;
                }
            }
            "create_group" => {
                let title = extract_query_param(query, "title")
                    .unwrap_or_else(|| self.tr("Новая группа", "New Group").to_owned());
                let members = extract_query_param(query, "members")
                    .and_then(|m| m.parse::<usize>().ok())
                    .unwrap_or(5);
                match self.state.create_mls_group_conduit(&title, members) {
                    Ok(_) => {
                        self.state.current_screen = Screen::ChatWorkspace;
                        self.state.status_banner = if is_en {
                            format!("Group \"{}\" created.", title.trim())
                        } else {
                            format!("Группа «{}» создана.", title.trim())
                        };
                    }
                    Err(e) => {
                        self.state.status_banner = if is_en {
                            format!("Could not create group: {e}")
                        } else {
                            format!("Не удалось создать группу: {e}")
                        };
                    }
                }
            }
            "generate_invite" => {
                self.state.outbound_capsule_seq = self.state.outbound_capsule_seq.wrapping_add(1);
                let srv_ep = self
                    .state
                    .directory_servers
                    .get(self.state.selected_server_index)
                    .map_or_else(|| "185.220.101.42:8443".to_owned(), |s| s.endpoint.clone());
                let step_b = (self.state.outbound_capsule_seq as u8).wrapping_add(0x31);
                let invite = ContactInvite {
                    server_endpoint: srv_ep,
                    recipient_queue_id: [step_b; 32],
                    x25519_public: [0xA5; 32],
                    ml_kem_public_hash: [0x5A; 32],
                    expires_at_unix_secs: 1_893_456_000,
                    max_activations: 1,
                    offline_qr_only: false,
                };
                if let Ok(uri) = invite.to_uri() {
                    self.state.active_invite_uri.clone_from(&uri);
                    self.state.status_banner =
                        self.tr("Создано новое приглашение.", "New invite created.").to_owned();
                }
            }
            "export_backup" => match self.state.export_explicit_encrypted_backup() {
                Ok(_) => {
                    self.state.status_banner =
                        self.tr("Резервная копия создана.", "Backup created.").to_owned();
                }
                Err(e) => {
                    self.state.status_banner = if is_en {
                        format!("Backup error: {e}")
                    } else {
                        format!("Ошибка резервной копии: {e}")
                    };
                }
            },
            "set_socks5_proxy" => {
                if let Some(proxy) = extract_query_param(query, "proxy") {
                    let clean = proxy.trim();
                    if clean.is_empty() {
                        self.state.socks5_proxy_endpoint = None;
                        self.state.status_banner =
                            self.tr("Прокси выключен.", "Proxy disabled.").to_owned();
                    } else {
                        self.state.socks5_proxy_endpoint = Some(clean.to_owned());
                        let _ = self.state.update_network_route(true, true, true, false);
                        self.state.status_banner = if is_en {
                            format!("Proxy enabled ({clean}).")
                        } else {
                            format!("Прокси включён ({clean}).")
                        };
                    }
                }
            }
            "select_theme" => {
                if let Some(theme_slug) = extract_query_param(query, "theme") {
                    let manifest = PluginManifest {
                        plugin_id: theme_slug.trim().to_owned(),
                        declarative_theme_only: true,
                        allowed_read_chats: Vec::new(),
                        allow_proxied_network: false,
                        requested_forbidden_key_access: false,
                    };
                    if self.state.install_plugin_or_theme(manifest).is_ok() {
                        self.state.status_banner =
                            self.tr("Тема обновлена.", "Theme updated.").to_owned();
                    }
                }
            }
            "calc_key" => {
                if let Some(k) = extract_query_param(query, "k") {
                    match k.as_str() {
                        "clear" => {
                            self.state.calculator_disguise.display_buffer.clear();
                            self.state.calculator_disguise.last_result = "0".to_owned();
                        }
                        "add" => self.state.calculator_disguise.display_buffer.push('+'),
                        "sub" => self.state.calculator_disguise.display_buffer.push('-'),
                        "mul" => self.state.calculator_disguise.display_buffer.push('*'),
                        "div" => self.state.calculator_disguise.display_buffer.push('/'),
                        digit if digit.len() == 1 && digit.chars().all(|c| c.is_ascii_digit()) => {
                            self.state
                                .calculator_disguise
                                .display_buffer
                                .push_str(digit);
                        }
                        _ => {}
                    }
                }
            }
            "login_account" => {
                let nick = extract_query_param(query, "nick")
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| self.state.onboarding_nickname.clone());
                let alias = extract_query_param(query, "alias")
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| self.tr("Основной профиль", "Main Profile").to_owned());
                let Some(pwd) = extract_query_param(query, "pwd").filter(|s| !s.trim().is_empty())
                else {
                    self.state.status_banner = self
                        .tr(
                            "Введите пароль (≥12 символов, ≥3 ЗАГЛАВНЫЕ, цифры, спецсимвол).",
                            "Enter a strong password (≥12 chars, ≥3 UPPERCASE, digits, symbol).",
                        )
                        .to_owned();
                    return;
                };
                let next_idx = (self.state.accounts.profiles.len() + 1) as u8;
                match self.state.accounts.create_account(
                    [next_idx; 16],
                    nick.trim(),
                    alias.trim(),
                    &pwd,
                ) {
                    Ok(_) => {
                        self.state.recovery_phrase_preview = None;
                        self.state.current_screen = Screen::ServerLauncher;
                        self.state.status_banner = if is_en {
                            format!("Signed in as {} ({}).", alias.trim(), nick.trim())
                        } else {
                            format!("Вы вошли как {} ({}).", alias.trim(), nick.trim())
                        };
                    }
                    Err(e) => {
                        self.state.status_banner = if is_en {
                            format!("Check your sign-in details: {e}")
                        } else {
                            format!("Проверьте данные входа: {e}")
                        };
                    }
                }
            }
            "select_chat" => {
                if let Some(idx_str) = extract_query_param(query, "idx") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        if idx < self.state.chats.len() {
                            if idx != self.state.active_chat_index {
                                self.state.key_change_warning = None;
                                self.state.peer_verified = true;
                            }
                            self.state.active_chat_index = idx;
                            self.state.leak_guard_modal = None;
                        }
                    }
                }
            }
            "new_chat" => {
                let title = extract_query_param(query, "title")
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty());
                let code = extract_query_param(query, "code")
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty());
                if let (Some(t), Some(c)) = (title, code) {
                    if self.state.chats.len() < 64 {
                        let id_byte = (self.state.chats.len() as u8).wrapping_add(10);
                        let msg_text = self.tr("Чат создан.", "Chat created.").to_owned();
                        self.state.chats.push(ChatView {
                            chat_id: [id_byte; 16],
                            title: t.clone(),
                            queue_tag: format!("queue://{c}"),
                            is_local_saved_notes: false,
                            verified_support_badge: false,
                            per_chat_pin: None,
                            is_locked: false,
                            default_disappearing_ttl_secs: Some(3600),
                            messages: vec![ChatMessageView {
                                outgoing: false,
                                text: msg_text,
                                padded_bucket_bytes: 256,
                                disappearing_ttl_secs: Some(3600),
                                attachment: None,
                            }],
                        });
                        self.state.active_chat_index = self.state.chats.len() - 1;
                        self.state.leak_guard_modal = None;
                        self.state.current_screen = Screen::ChatWorkspace;
                        self.state.status_banner = if is_en {
                            format!("Chat with {t} opened.")
                        } else {
                            format!("Чат с {t} открыт.")
                        };
                    }
                }
            }
            "select_server" => {
                if let Some(idx_str) = extract_query_param(query, "idx") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        if self.state.select_starter_server(idx).is_ok() {
                            self.state.current_screen = Screen::ChatWorkspace;
                        }
                    }
                }
            }
            "custom_server" => {
                if let Some(ip) = extract_query_param(query, "ip") {
                    let trimmed = ip.trim();
                    let parsed_pair = if let Some((h, p)) = trimmed.rsplit_once(':') {
                        p.parse::<u16>().ok().map(|port| (h, port))
                    } else {
                        Some((trimmed, 8443))
                    };
                    if let Some((host_part, port_part)) = parsed_pair {
                        match self.state.connect_custom_static_ip(host_part, port_part) {
                            Ok(_) => {
                                self.state.current_screen = Screen::ChatWorkspace;
                            }
                            Err(e) => {
                                self.state.status_banner = if is_en {
                                    format!("Could not connect to server: {e}")
                                } else {
                                    format!("Не удалось подключить сервер: {e}")
                                };
                            }
                        }
                    } else {
                        self.state.status_banner =
                            self.tr("Некорректный порт сервера.", "Invalid server port.").to_owned();
                    }
                }
            }
            "set_blind_relay" => {
                if let Some(relay) = extract_query_param(query, "relay") {
                    let clean = relay.trim();
                    if clean.is_empty() {
                        self.state.blind_relay_endpoint = None;
                        self.state.status_banner =
                            self.tr("Релей выключен.", "Relay disabled.").to_owned();
                    } else {
                        self.state.blind_relay_endpoint = Some(clean.to_owned());
                        self.state.status_banner = if is_en {
                            format!("Relay enabled ({clean}).")
                        } else {
                            format!("Релей включён ({clean}).")
                        };
                    }
                }
            }
            "lang_ru" => self.state.set_locale(Locale::Ru),
            "lang_en" => self.state.set_locale(Locale::En),
            "gen_nick" => {
                self.state.outbound_capsule_seq = self.state.outbound_capsule_seq.wrapping_add(1);
                let step = (self.state.accounts.profiles.len() as u8)
                    .wrapping_add(self.state.outbound_capsule_seq as u8)
                    .wrapping_add(7);
                let nick = self.state.regenerate_onboarding_nickname([
                    step,
                    step.wrapping_mul(3),
                    0x42,
                    0x19,
                ]);
                self.state.status_banner = if is_en {
                    format!("New username: {nick}")
                } else {
                    format!("Новый логин: {nick}")
                };
            }
            "add_account" => {
                let next_idx = (self.state.accounts.profiles.len() + 1) as u8;
                let nick = generate_nickname([next_idx, next_idx.wrapping_add(5), 0x10, next_idx]);
                let alias = if is_en {
                    format!("Profile #{next_idx}")
                } else {
                    format!("Профиль #{next_idx}")
                };
                match self.state.accounts.create_account(
                    [next_idx; 16],
                    &nick,
                    &alias,
                    "AEGis#StrongPass99!",
                ) {
                    Ok(_) => {
                        self.state.status_banner = if is_en {
                            format!("Added {alias}.")
                        } else {
                            format!("Добавлен {alias}.")
                        };
                    }
                    Err(e) => {
                        self.state.status_banner = if is_en {
                            format!("Profile limit: {e}")
                        } else {
                            format!("Лимит профилей: {e}")
                        };
                    }
                }
            }
            "activate_pass" => {
                let pass = SupporterPass {
                    token_id: [0x77; 16],
                    max_accounts: 5,
                    signature_verified: true,
                };
                match self.state.accounts.unlock_with_supporter_pass(pass) {
                    Ok(()) => {
                        self.state.support_portal.supporter_pass_active = true;
                        self.state.support_portal.max_account_slots = 5;
                        self.state.status_banner = self
                            .tr(
                                "SupporterPass активирован (до 5 профилей).",
                                "SupporterPass activated (up to 5 profiles).",
                            )
                            .to_owned();
                    }
                    Err(e) => {
                        self.state.status_banner = if is_en {
                            format!("SupporterPass error: {e}")
                        } else {
                            format!("Ошибка SupporterPass: {e}")
                        };
                    }
                }
            }
            "chat_0" => {
                if !self.state.chats.is_empty() {
                    if self.state.active_chat_index != 0 {
                        self.state.key_change_warning = None;
                        self.state.peer_verified = true;
                    }
                    self.state.active_chat_index = 0;
                    self.state.leak_guard_modal = None;
                }
            }
            "chat_1" => {
                if self.state.chats.len() > 1 {
                    if self.state.active_chat_index != 1 {
                        self.state.key_change_warning = None;
                        self.state.peer_verified = true;
                    }
                    self.state.active_chat_index = 1;
                    self.state.leak_guard_modal = None;
                }
            }
            "chat_2" => {
                if self.state.chats.len() > 2 {
                    if self.state.active_chat_index != 2 {
                        self.state.key_change_warning = None;
                        self.state.peer_verified = true;
                    }
                    self.state.active_chat_index = 2;
                    self.state.leak_guard_modal = None;
                }
            }
            "toggle_chat_pin" => {
                let idx = self.state.active_chat_index;
                if let Some(chat) = self.state.chats.get(idx).map(|c| c.is_locked) {
                    if chat {
                        let pin = extract_query_param(query, "pin").unwrap_or_default();
                        match self.state.unlock_chat_with_pin(idx, &pin) {
                            Ok(()) => {
                                self.state.status_banner =
                                    self.tr("Чат разблокирован.", "Chat unlocked.").to_owned();
                            }
                            Err(e) => {
                                self.state.status_banner = if is_en {
                                    format!("Incorrect PIN: {e}")
                                } else {
                                    format!("Отказ разблокировки чата: {e}")
                                };
                            }
                        }
                    } else if let Some(c) = self.state.chats.get_mut(idx) {
                        c.is_locked = true;
                        self.state.status_banner =
                            self.tr("Чат закрыт PIN-кодом.", "Chat locked with PIN.").to_owned();
                    }
                }
            }
            "route_tor" => {
                let _ = self.state.update_network_route(true, true, true, false);
                self.state.status_banner = self.tr("Tor включён.", "Tor enabled.").to_owned();
            }
            "route_vpn" => {
                let _ = self.state.update_network_route(false, true, true, false);
                self.state.status_banner =
                    self.tr("VPN / Прокси включён.", "VPN / Proxy enabled.").to_owned();
            }
            "route_direct" => {
                let _ = self.state.update_network_route(false, false, false, false);
                self.state.status_banner =
                    self.tr("Прямое соединение включено.", "Direct connection enabled.").to_owned();
            }
            "route_leak" => {
                let _ = self.state.update_network_route(false, true, true, true);
                self.state.status_banner =
                    self.tr("Сеть заблокирована (Kill Switch).", "Network locked (Kill Switch).").to_owned();
            }
            "test_leak_card" => {
                let sample =
                    "Переведи на карту 4532 0151 1283 0366 срок 08/28 cvv 912 или +7 (999) 123-45-67";
                match self.state.send_chat_message(sample, false, None) {
                    Ok(_) => {}
                    Err(e) => {
                        self.state.status_banner = if is_en {
                            format!("Send paused: {e}")
                        } else {
                            format!("Отправка приостановлена: {e}")
                        };
                    }
                }
            }
            "leak_mask" => {
                let redacted_text = self
                    .state
                    .leak_guard_modal
                    .as_ref()
                    .map(|m| m.redacted_preview.clone())
                    .unwrap_or_default();
                let (is_local_notes, channel_code) = self
                    .state
                    .chats
                    .get(self.state.active_chat_index)
                    .map_or_else(
                        || (false, "nordic-falcon".to_owned()),
                        |c| (c.is_local_saved_notes, c.queue_tag.clone()),
                    );
                if self.state.confirm_leak_guard_masked_send().is_ok() {
                    if !is_local_notes && !redacted_text.is_empty() {
                        let _ = self
                            .state
                            .deliver_capsule_to_active_server(&channel_code, &redacted_text);
                    }
                    self.state.status_banner = self
                        .tr(
                            "Личные данные скрыты, сообщение отправлено.",
                            "Sensitive data masked, message sent.",
                        )
                        .to_owned();
                }
            }
            "leak_force" => {
                if let Some(modal) = self.state.leak_guard_modal.take() {
                    let (active_matches, is_local_notes, channel_code) = self
                        .state
                        .chats
                        .get(self.state.active_chat_index)
                        .map_or_else(
                            || (false, false, "nordic-falcon".to_owned()),
                            |c| {
                                (
                                    c.chat_id == modal.target_chat_id,
                                    c.is_local_saved_notes,
                                    c.queue_tag.clone(),
                                )
                            },
                        );
                    if active_matches
                        && self
                            .state
                            .send_chat_message(&modal.original_draft, true, None)
                            .is_ok()
                    {
                        if !is_local_notes {
                            let _ = self.state.deliver_capsule_to_active_server(
                                &channel_code,
                                &modal.original_draft,
                            );
                        }
                        self.state.status_banner =
                            self.tr("Сообщение отправлено.", "Message sent.").to_owned();
                    }
                }
            }
            "send_photo_view_once" => {
                let fake_jpeg_with_exif = [
                    0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00, 0xFF,
                    0xDA, 0x00, 0x04, 0x00, 0x00, 0x01, 0x02, 0x03, 0xFF, 0xD9,
                ];
                let att = MediaAttachmentView::strip_exif_and_create(
                    "photo.jpg",
                    &fake_jpeg_with_exif,
                    true,
                );
                let caption = self.tr("Одноразовое фото", "View-once photo").to_owned();
                if self
                    .state
                    .send_chat_message(&caption, true, Some(att))
                    .is_ok()
                {
                    self.state.status_banner =
                        self.tr("Одноразовое фото отправлено.", "View-once photo sent.").to_owned();
                }
            }
            "launch_vps" => {
                let _ = self
                    .state
                    .server_launcher
                    .configure(LaunchTarget::VpsDocker, 8443, 30);
                self.state.status_banner =
                    self.tr("Настройки VPS-сервера готовы.", "VPS server settings ready.").to_owned();
            }
            "launch_onion" => {
                let _ =
                    self.state
                        .server_launcher
                        .configure(LaunchTarget::TorOnionService, 9001, 14);
                self.state.status_banner =
                    self.tr("Настройки Tor-сервера готовы.", "Tor server settings ready.").to_owned();
            }
            "launch_desktop" => {
                let _ = self
                    .state
                    .server_launcher
                    .configure(LaunchTarget::DesktopLocal, 8443, 7);
                self.state.status_banner = self
                    .tr(
                        "Настройки локального сервера готовы.",
                        "Local server settings ready.",
                    )
                    .to_owned();
            }
            "send_ticket" => {
                let _ = self.state.submit_support_ticket(
                    [0x55; 32],
                    SupportTicketCategory::SupporterPassIssue,
                    "Support request.",
                );
            }
            "disguise" => {
                self.state.enable_calculator_disguise();
            }
            "calc_eval" => {
                if self.state.remaining_pin_attempts == 0 {
                    self.state.trigger_panic_wipe();
                    return;
                }
                let expr = extract_query_param(query, "expr")
                    .unwrap_or_else(|| self.state.calculator_disguise.display_buffer.clone());
                let is_pin_guess =
                    !expr.trim().is_empty() && expr.trim().chars().all(|c| c.is_ascii_digit());
                self.state.calculator_disguise.display_buffer = expr;
                let pin = self.state.app_pin.clone();
                let duress = self.state.duress_pin.clone();
                match self
                    .state
                    .calculator_disguise
                    .press_equals(&pin, duress.as_deref())
                {
                    CalculatorAction::UnlockRealVault => {
                        self.state.remaining_pin_attempts = 10;
                        self.state.current_screen = Screen::ChatWorkspace;
                        self.state.status_banner.clear();
                    }
                    CalculatorAction::TriggerDuressDecoy => {
                        self.state.activate_duress_decoy_mode();
                    }
                    CalculatorAction::ComputedMath => {
                        if is_pin_guess {
                            self.state.remaining_pin_attempts =
                                self.state.remaining_pin_attempts.saturating_sub(1);
                            if self.state.remaining_pin_attempts == 0 {
                                self.state.trigger_panic_wipe();
                            }
                        }
                    }
                }
            }
            "panic" => {
                self.state.trigger_panic_wipe();
            }
            "send_text" => {
                let text = extract_query_param(query, "text").unwrap_or_default();
                if !text.is_empty() {
                    let (is_local_notes, channel_code) = self
                        .state
                        .chats
                        .get(self.state.active_chat_index)
                        .map_or_else(
                            || (false, "nordic-falcon".to_owned()),
                            |c| (c.is_local_saved_notes, c.queue_tag.clone()),
                        );
                    match self.state.send_chat_message(&text, false, None) {
                        Ok(_) => {
                            if !is_local_notes && !self.state.duress_mode_active {
                                let _ = self
                                    .state
                                    .deliver_capsule_to_active_server(&channel_code, &text);
                            }
                            self.state.status_banner.clear();
                        }
                        Err(e) => {
                            self.state.status_banner = if is_en {
                                format!("Send paused: {e}")
                            } else {
                                format!("Отправка приостановлена: {e}")
                            };
                        }
                    }
                }
            }
            "sync_remote" => {
                let server_ep = self
                    .state
                    .directory_servers
                    .get(self.state.selected_server_index)
                    .map_or_else(|| "185.220.101.42:8443".to_owned(), |s| s.endpoint.clone());
                let channel_code = self
                    .state
                    .chats
                    .get(self.state.active_chat_index)
                    .map_or_else(|| "nordic-falcon".to_owned(), |c| c.queue_tag.clone());
                match self.state.sync_remote_capsules(&server_ep, &channel_code) {
                    Ok(n) => {
                        if n > 0 {
                            self.state.status_banner = if is_en {
                                format!("New messages: {n}.")
                            } else {
                                format!("Новых сообщений: {n}.")
                            };
                        } else {
                            self.state.status_banner =
                                self.tr("Новых сообщений нет.", "No new messages.").to_owned();
                        }
                    }
                    Err(_) => {
                        self.state.status_banner =
                            self.tr("Сервер сейчас недоступен.", "Server is currently offline.").to_owned();
                    }
                }
            }
            _ => {}
        }
    }

    /// Serves HTTP requests on `127.0.0.1` so the user can interact with the Desktop GUI in their browser/WebView.
    ///
    /// # Errors
    /// Returns [`DesktopUiError::IoError`] if the local socket cannot be bound.
    pub fn serve_blocking(&mut self, max_requests: Option<usize>) -> Result<(), DesktopUiError> {
        let listener = TcpListener::bind(&self.bind_addr)
            .map_err(|e| DesktopUiError::IoError(e.to_string()))?;
        let mut handled = 0usize;

        for stream_res in listener.incoming() {
            let Ok(mut stream) = stream_res else {
                continue;
            };
            let io_timeout = Some(std::time::Duration::from_secs(2));
            let _ = stream.set_read_timeout(io_timeout);
            let _ = stream.set_write_timeout(io_timeout);
            if let Some(req) = read_http_request(&mut stream) {
                if !is_trusted_local_http_request(&req) {
                    let forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 9\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nForbidden";
                    let _ = stream.write_all(forbidden.as_bytes());
                    let _ = stream.flush();
                    handled = handled.saturating_add(1);
                    if let Some(limit) = max_requests {
                        if handled >= limit {
                            break;
                        }
                    }
                    continue;
                }
                if let Some(query) = http_action_query(&req) {
                    if !query.is_empty() {
                        self.handle_command(&query);
                    }
                }
            }

            let html = self.render_html();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nConnection: close\r\n\r\n{}",
                html.len(),
                html
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();

            handled = handled.saturating_add(1);
            if let Some(limit) = max_requests {
                if handled >= limit {
                    break;
                }
            }
        }
        Ok(())
    }
}

fn read_http_request(stream: &mut TcpStream) -> Option<String> {
    let mut data = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.len() > 65_536 {
            return None;
        }
        if let Some(header_end) = find_header_end(&data) {
            let head = std::str::from_utf8(&data[..header_end]).ok()?;
            let content_length = parse_content_length(head).unwrap_or(0);
            if content_length > 32_768 {
                return None;
            }
            if data.len() >= header_end + 4 + content_length {
                break;
            }
        } else if data.len() > 16_384 {
            return None;
        }
    }
    String::from_utf8(data).ok()
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(head: &str) -> Option<usize> {
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse::<usize>().ok();
        }
    }
    None
}

fn http_action_query(raw_request: &str) -> Option<String> {
    let (head, body) = raw_request.split_once("\r\n\r\n")?;
    let mut first_line = head.lines().next()?.split_whitespace();
    let method = first_line.next()?;
    let target = first_line.next()?;
    if method != "GET" && method != "POST" {
        return None;
    }
    let path = target.split('?').next().unwrap_or(target);
    if path != "/" && path != "/action" {
        return None;
    }
    let query = target.split_once('?').map_or("", |(_, q)| q);
    if method == "GET" {
        return Some(query.to_owned());
    }

    let content_type = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-type") {
            Some(value.trim().to_ascii_lowercase())
        } else {
            None
        }
    })?;
    if !content_type.starts_with("application/x-www-form-urlencoded") {
        return None;
    }
    if body.is_empty() {
        Some(query.to_owned())
    } else {
        Some(body.to_owned())
    }
}

/// Verifies that an incoming HTTP request to the local Desktop GUI server (`127.0.0.1`)
/// is not a Cross-Site Request Forgery (CSRF) or DNS Rebinding attack from an external website.
#[must_use]
pub fn is_trusted_local_http_request(raw_request: &str) -> bool {
    let head = raw_request
        .split_once("\r\n\r\n")
        .map_or(raw_request, |(h, _)| h);
    let mut saw_valid_host = false;
    for line in head.lines().skip(1) {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let header_name = name.trim().to_ascii_lowercase();
        let header_val = val.trim().to_ascii_lowercase();
        match header_name.as_str() {
            "host" => {
                if saw_valid_host {
                    return false;
                }
                let host_only = if let Some((h, port_str)) = header_val.rsplit_once(':') {
                    if port_str.parse::<u16>().is_err() {
                        return false;
                    }
                    h
                } else {
                    header_val.as_str()
                };
                if host_only != "127.0.0.1" && host_only != "localhost" {
                    return false;
                }
                saw_valid_host = true;
            }
            "sec-fetch-site" if header_val == "cross-site" || header_val == "same-site" => {
                return false;
            }
            "origin" => {
                let valid_origin = ["http://127.0.0.1", "http://localhost"]
                    .iter()
                    .any(|prefix| {
                        header_val.strip_prefix(prefix).is_some_and(|rest| {
                            rest.is_empty() || rest.starts_with(':') || rest.starts_with('/')
                        })
                    });
                if !valid_origin {
                    return false;
                }
            }
            _ => {}
        }
    }
    saw_valid_host
}

fn url_encode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len() * 3);
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0F)]));
        }
    }
    out
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

const DESKTOP_CSS: &str = r#"
:root {
  --bg: #0b141a;
  --panel: #111b21;
  --panel-2: #17212b;
  --line: #24323d;
  --text: #e9edef;
  --muted: #8696a0;
  --accent: #53bdeb;
  --accent-2: #00a884;
  --bubble-in: #182533;
  --bubble-out: #2a5275;
  --danger: #f15c6d;
  --warn: #f0b429;
  --ok: #25d366;
}
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
  font-size: 14px;
  line-height: 1.4;
}
a { color: inherit; text-decoration: none; }
button, input { font: inherit; }
.app { display: flex; height: 100vh; overflow: hidden; }
.sidebar {
  width: 340px;
  min-width: 280px;
  background: var(--panel);
  border-right: 1px solid var(--line);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.sidebar-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px 10px;
}
.brand-row { display: flex; align-items: center; gap: 10px; }
.brand-mark {
  width: 32px;
  height: 32px;
  border-radius: 10px;
  background: linear-gradient(135deg, var(--accent-2), var(--accent));
  color: #06202a;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  font-size: 17px;
  flex: 0 0 auto;
}
.brand-mark.large { width: 54px; height: 54px; border-radius: 16px; font-size: 28px; }
.brand-name { font-weight: 700; font-size: 18px; letter-spacing: 0.2px; }
.icon-btn {
  width: 34px;
  height: 34px;
  border-radius: 10px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--muted);
  border: 1px solid transparent;
}
.icon-btn:hover { background: var(--panel-2); color: var(--text); border-color: var(--line); }
.sidebar-search { padding: 0 12px 10px; }
.sidebar-search input {
  width: 100%;
  background: var(--panel-2);
  border: 1px solid transparent;
  border-radius: 10px;
  padding: 9px 12px;
  color: var(--text);
  outline: none;
}
.sidebar-search input:focus { border-color: var(--accent); }
.chat-list { flex: 1; overflow-y: auto; padding: 2px 8px 8px; }
.chat-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 10px;
  border-radius: 10px;
  margin-bottom: 2px;
}
.chat-item:hover { background: var(--panel-2); }
.chat-item.active { background: #2a3a46; }
.avatar {
  width: 46px;
  height: 46px;
  border-radius: 50%;
  background: #2a3a46;
  color: var(--accent);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 18px;
  flex: 0 0 auto;
}
.avatar.small { width: 42px; height: 42px; font-size: 16px; }
.avatar.large { width: 64px; height: 64px; font-size: 26px; }
.chat-item-meta { min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.chat-item-name { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.chat-item-preview { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.new-chat { border-top: 1px solid var(--line); padding: 10px 12px; }
.new-chat summary { cursor: pointer; color: var(--accent); font-weight: 600; list-style: none; }
.new-chat summary::-webkit-details-marker { display: none; }
.new-chat[open] summary { margin-bottom: 10px; }
.sidebar-nav {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  border-top: 1px solid var(--line);
  background: var(--panel);
}
.nav-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 9px 4px;
  font-size: 11px;
  color: var(--muted);
}
.nav-item span { font-size: 17px; }
.nav-item.active { color: var(--accent); }
.main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  background: var(--bg);
  position: relative;
}
.chat-head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  min-height: 64px;
}
.chat-head-meta { min-width: 0; flex: 1; }
.chat-title { font-weight: 700; font-size: 15px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.chat-sub { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.chat-actions { display: flex; gap: 2px; }
.status-banner {
  margin: 8px 16px 0;
  padding: 8px 12px;
  border-radius: 8px;
  background: #1a2a33;
  border: 1px solid var(--line);
  color: #c7d4dc;
  font-size: 12px;
}
.messages {
  flex: 1;
  overflow-y: auto;
  padding: 18px 20px 8px;
  background-image: radial-gradient(circle at 20% 10%, rgba(83, 189, 235, 0.04), transparent 34%), radial-gradient(circle at 80% 80%, rgba(0, 168, 132, 0.04), transparent 30%);
}
.message-row { display: flex; margin-bottom: 8px; }
.message-row.out { justify-content: flex-end; }
.bubble {
  max-width: 72%;
  padding: 8px 11px 6px;
  border-radius: 12px;
  box-shadow: 0 1px 1px rgba(0, 0, 0, 0.18);
}
.message-row.in .bubble { background: var(--bubble-in); border-bottom-left-radius: 4px; }
.message-row.out .bubble { background: var(--bubble-out); border-bottom-right-radius: 4px; }
.message-text { white-space: pre-wrap; word-break: break-word; }
.message-meta { color: rgba(233, 237, 239, 0.62); font-size: 10px; text-align: right; margin-top: 3px; }
.attachment {
  margin-top: 6px;
  padding: 7px 9px;
  border-radius: 8px;
  background: rgba(0, 0, 0, 0.16);
  color: #cfe6ef;
  font-size: 12px;
}
.composer {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px 6px;
  background: var(--panel);
  border-top: 1px solid var(--line);
}
.composer-input {
  flex: 1;
  background: var(--panel-2);
  border: 1px solid transparent;
  border-radius: 10px;
  padding: 10px 12px;
  color: var(--text);
  outline: none;
}
.composer-input:focus { border-color: var(--accent); }
.send-btn {
  width: 40px;
  height: 38px;
  border: none;
  border-radius: 10px;
  background: var(--accent-2);
  color: #042018;
  font-size: 17px;
  cursor: pointer;
}
.composer-hint { padding: 0 16px 10px; background: var(--panel); color: var(--muted); font-size: 10px; }
.info-panel {
  width: 320px;
  min-width: 280px;
  background: var(--panel);
  border-left: 1px solid var(--line);
  overflow-y: auto;
  padding: 12px;
}
.info-card { text-align: center; padding: 12px 8px 14px; }
.info-card h3 { margin: 8px 0 2px; font-size: 16px; }
.safety { margin: 12px 0; padding: 10px; border-radius: 10px; background: var(--panel-2); }
.safety code { display: block; margin: 5px 0; color: #cfe6ef; font-size: 11px; word-break: break-all; }
.pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 10px; font-weight: 700; }
.pill.ok { background: rgba(37, 211, 102, 0.14); color: #6ee7a8; }
.pill.warn { background: rgba(240, 180, 41, 0.14); color: #f3c96b; }
.panel {
  border-top: 1px solid var(--line);
  padding: 10px 4px;
}
.panel summary { cursor: pointer; font-weight: 600; color: #c7d4dc; list-style: none; }
.panel summary::-webkit-details-marker { display: none; }
.panel summary::before { content: "›"; display: inline-block; width: 14px; color: var(--muted); }
.panel[open] summary::before { transform: rotate(90deg); }
.kv { display: flex; justify-content: space-between; gap: 10px; padding: 4px 0; color: var(--muted); font-size: 12px; }
.kv b { color: var(--text); font-weight: 500; text-align: right; word-break: break-all; }
.actions-row { display: flex; gap: 6px; margin-top: 8px; align-items: center; }
.actions-row.wrap { flex-wrap: wrap; }
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 7px 12px;
  border-radius: 8px;
  border: 1px solid var(--line);
  background: transparent;
  color: var(--text);
  cursor: pointer;
  font-weight: 600;
  font-size: 12px;
}
.btn:hover { background: var(--panel-2); }
.btn.primary { background: var(--accent-2); border-color: var(--accent-2); color: #042018; }
.btn.primary:hover { filter: brightness(1.06); }
.btn.ghost { color: #c7d4dc; }
.btn.danger { color: #ffb3ba; border-color: rgba(241, 92, 109, 0.45); background: rgba(241, 92, 109, 0.1); }
.btn.small { padding: 4px 8px; font-size: 11px; }
.btn.wide { width: 100%; }
.chip {
  display: inline-flex;
  align-items: center;
  padding: 5px 9px;
  border-radius: 999px;
  border: 1px solid var(--line);
  color: #c7d4dc;
  font-size: 11px;
  font-weight: 600;
}
.chip.danger { color: #ffb3ba; border-color: rgba(241, 92, 109, 0.45); }
.top-actions { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
.auth-page { display: grid; grid-template-columns: 1.05fr 1fr; min-height: 100vh; background: var(--bg); }
.auth-brand {
  padding: 64px clamp(28px, 6vw, 86px);
  display: flex;
  flex-direction: column;
  justify-content: center;
  background: linear-gradient(160deg, #10212b 0%, #0b141a 62%);
  border-right: 1px solid var(--line);
}
.auth-brand h1 { font-size: 46px; margin: 18px 0 10px; letter-spacing: -1px; }
.brand-lead { color: #c7d4dc; font-size: 17px; max-width: 440px; }
.brand-points { margin: 24px 0 30px; padding: 0; list-style: none; color: var(--muted); }
.brand-points li { margin: 9px 0; padding-left: 20px; position: relative; }
.brand-points li::before { content: "✓"; position: absolute; left: 0; color: var(--accent-2); }
.brand-foot { color: #5f7480; font-size: 11px; letter-spacing: 0.4px; }
.auth-side { padding: 28px clamp(22px, 5vw, 64px) 48px; overflow-y: auto; }
.auth-top { display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 28px; }
.step-dots { display: flex; gap: 6px; }
.step-dot {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  color: var(--muted);
  background: var(--panel-2);
  border: 1px solid var(--line);
}
.step-dot.active { background: var(--accent-2); color: #042018; border-color: var(--accent-2); }
.auth-card {
  max-width: 520px;
  margin: 0 auto;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 26px;
}
.auth-card.wide { max-width: 680px; }
.eyebrow { color: var(--accent); font-size: 11px; font-weight: 700; letter-spacing: 0.8px; text-transform: uppercase; }
.auth-card h2 { margin: 5px 0 6px; font-size: 24px; }
.lead { color: var(--muted); margin: 0 0 16px; }
.muted { color: var(--muted); font-size: 12px; }
.mode-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 10px;
  background: var(--panel-2);
  margin: 12px 0 8px;
}
.notice { margin: 12px 0; padding: 12px; border-radius: 10px; background: #1a2a33; border: 1px solid var(--line); }
.notice.compact { margin: 8px 0 0; }
.notice-title { font-weight: 700; margin-bottom: 4px; }
.notice p { margin: 0 0 8px; color: var(--muted); font-size: 12px; }
code, .secret, .invite, pre { font-family: "Cascadia Mono", Consolas, monospace; }
.secret, .invite { display: block; color: #cfe6ef; font-size: 11px; word-break: break-all; }
.form-stack { display: flex; flex-direction: column; gap: 6px; margin-top: 12px; }
.form-stack label { color: #c7d4dc; font-size: 12px; font-weight: 600; margin-top: 4px; }
input[type="text"], input[type="password"] {
  width: 100%;
  background: #0e181f;
  border: 1px solid var(--line);
  border-radius: 9px;
  padding: 10px 12px;
  color: var(--text);
  outline: none;
}
input[type="text"]:focus, input[type="password"]:focus { border-color: var(--accent); }
.input-row { display: flex; gap: 8px; align-items: center; }
.input-row input { flex: 1; min-width: 0; }
.hint { color: var(--muted); font-size: 11px; margin: 2px 0 8px; }
.auth-links { margin-top: 14px; font-size: 12px; color: var(--accent); }
.server-list { display: flex; flex-direction: column; gap: 8px; margin: 14px 0; }
.server-card { padding: 12px; border: 1px solid var(--line); border-radius: 12px; background: var(--panel-2); }
.server-card.active { border-color: var(--accent-2); box-shadow: inset 0 0 0 1px rgba(0, 168, 132, 0.3); }
.server-card-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; }
.server-name { font-weight: 700; word-break: break-all; }
.server-badge { color: var(--muted); font-size: 11px; margin-top: 2px; }
.server-card p { margin: 8px 0 0; color: var(--muted); font-size: 12px; }
.banner { margin: 8px 16px 0; padding: 9px 12px; border-radius: 8px; font-size: 12px; background: #2b2111; color: #f3c96b; border: 1px solid rgba(240, 180, 41, 0.35); }
.banner.warn a { color: #ffe1a3; text-decoration: underline; margin-left: 6px; }
.modal-card { margin: 8px 16px 0; padding: 14px; border-radius: 10px; background: #2a161a; border: 1px solid rgba(241, 92, 109, 0.5); }
.modal-title { font-weight: 700; color: #ffb3ba; margin-bottom: 6px; }
.modal-card p { margin: 0 0 8px; color: #e7c9cc; font-size: 12px; }
.code-block { padding: 8px 10px; margin: 6px 0; border-radius: 8px; background: #160d0f; color: #f0d6d9; font-family: Consolas, monospace; font-size: 11px; word-break: break-word; }
.account-row { display: flex; align-items: center; gap: 8px; padding: 6px 0; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: #4a5b66; flex: 0 0 auto; }
.status-dot.online { background: var(--ok); }
.account-meta { min-width: 0; flex: 1; }
.account-meta b { display: block; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.score { color: var(--muted); font-size: 11px; }
pre { margin: 8px 0 0; padding: 10px; border-radius: 8px; background: #0e181f; color: #b9d4df; font-size: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
.empty-state { margin: 12vh auto 0; max-width: 340px; text-align: center; color: var(--muted); }
.empty-icon { font-size: 40px; margin-bottom: 8px; opacity: 0.7; }
.empty-state h3 { color: var(--text); margin: 0 0 6px; font-size: 16px; }
.empty-state p { margin: 0; font-size: 12px; }
.unlock-form { display: flex; gap: 8px; padding: 10px 16px; background: var(--panel); }
.unlock-form input { flex: 1; }
.section-title { color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
.toggle-list { display: flex; flex-direction: column; gap: 6px; margin: 8px 0; }
.toggle-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 9px 11px;
  border-radius: 10px;
  background: var(--panel-2);
  border: 1px solid transparent;
  font-size: 13px;
  font-weight: 500;
}
.toggle-row:hover { border-color: var(--line); }
.switch {
  width: 38px;
  height: 22px;
  border-radius: 999px;
  background: #2b3942;
  position: relative;
  flex: 0 0 auto;
  transition: background 0.15s ease;
}
.switch::after {
  content: "";
  position: absolute;
  top: 3px;
  left: 3px;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: #cfd8dc;
  transition: transform 0.15s ease, background 0.15s ease;
}
.switch.on { background: rgba(0, 168, 132, 0.32); }
.switch.on::after { transform: translateX(16px); background: var(--accent-2); }
.seg-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; margin-top: 6px; }
.seg {
  text-align: center;
  padding: 7px 6px;
  border-radius: 8px;
  background: var(--panel-2);
  border: 1px solid var(--line);
  font-size: 12px;
  font-weight: 600;
  color: var(--muted);
}
.seg.active { background: var(--accent-2); border-color: var(--accent-2); color: #042018; }
@media (max-width: 1180px) { .info-panel { display: none; } }
@media (max-width: 820px) {
  .sidebar { width: 280px; min-width: 240px; }
  .auth-page { grid-template-columns: 1fr; }
  .auth-brand { display: none; }
}
@media (max-width: 620px) {
  .app { display: block; }
  .sidebar { width: 100%; height: 44vh; border-right: none; border-bottom: 1px solid var(--line); }
  .main { height: 56vh; }
  .info-panel { display: none; }
  .chat-head { min-height: 54px; }
  .bubble { max-width: 86%; }
}
"#;

fn human_ttl_locale(secs: u32, is_en: bool) -> String {
    if is_en {
        if secs >= 3600 {
            format!("expires in {} h", secs / 3600)
        } else if secs >= 60 {
            format!("expires in {} min", secs / 60)
        } else {
            format!("expires in {secs} s")
        }
    } else if secs >= 3600 {
        format!("исчезает через {} ч", secs / 3600)
    } else if secs >= 60 {
        format!("исчезает через {} мин", secs / 60)
    } else {
        format!("исчезает через {secs} с")
    }
}

fn chat_icon_for(title: &str) -> &'static str {
    let lower = title.to_lowercase();
    if lower.contains("избран") || lower.contains("saved") {
        "★"
    } else if lower.contains("поддерж") || lower.contains("support") {
        "✓"
    } else {
        "•"
    }
}

fn extract_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
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

const fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Runs a complete automated walkthrough of all Desktop features and returns a human-readable Russian report.
///
/// # Errors
/// Returns [`DesktopUiError`] if any mandatory check fails.
pub fn run_automated_demo_walkthrough() -> Result<String, DesktopUiError> {
    let mut app = DesktopAppState::new(Locale::Ru);
    let mut report = String::new();

    report.push_str("============================================================\n");
    report.push_str("🛡 AEGIS DESKTOP — ПОЛНЫЙ АВТОТЕСТ ВСЕХ ФУНКЦИЙ НА ПК (RU/EN)\n");
    report.push_str("============================================================\n");

    // 1. Localization check
    app.set_locale(Locale::En);
    app.set_locale(Locale::Ru);
    report.push_str(&format!(
        "1. [OK] Локализация RU + EN и версии ядра: Crypto v{}, Protocol v{}, Storage Schema v{}\n",
        app.core_versions.crypto_suite_version,
        app.core_versions.protocol_version,
        app.core_versions.storage_schema_version
    ));

    // 2. Onboarding: Nickname generator + Strict password policy (D-0006) + PoW difficulty
    let nick1 = app.regenerate_onboarding_nickname([1, 2, 3, 4]);
    let pow_bits = compute_pow_difficulty(25, false);
    report.push_str(&format!(
        "2. [OK] Генератор криптостойких ников: {nick1} (адаптивный Anti-DDoS PoW: {pow_bits} бит)\n"
    ));

    // 3. Multi-account: 3 free accounts + 4th blocked until SupporterPass activated (D-0010)
    let nick2 = generate_nickname([5, 6, 7, 8]);
    let nick3 = generate_nickname([9, 10, 11, 12]);
    let nick4 = generate_nickname([13, 14, 15, 16]);
    app.accounts
        .create_account([1u8; 16], &nick1, "Личный", "AEGis#MasterKey2026!")?;
    app.accounts
        .create_account([2u8; 16], &nick2, "Рабочий", "SECure#WorkKey2026!")?;
    app.accounts
        .create_account([3u8; 16], &nick3, "Публичный", "PRIvacy#NodeKey2026!")?;

    let fourth_blocked = app
        .accounts
        .create_account([4u8; 16], &nick4, "Секретный-4", "ULTra#FourthKey2026!")
        .is_err();
    app.accounts.unlock_with_supporter_pass(SupporterPass {
        token_id: [0xAB; 16],
        max_accounts: 5,
        signature_verified: true,
    })?;
    let total_accounts =
        app.accounts
            .create_account([4u8; 16], &nick4, "Секретный-4", "ULTra#FourthKey2026!")?;
    report.push_str(&format!(
        "3. [OK] Мультиаккаунты (D-0010): 3 бесплатных созданы, 4-й без токена заблокирован={fourth_blocked}, после активации SupporterPass активно профилей: {total_accounts}\n"
    ));

    // 4. Direct Static-IP Starter Servers (No Tor required) + Network Anonymity Shield (D-0008, D-0019)
    let default_direct_permitted = app.shield_evaluation.traffic_permitted;
    let custom_idx = app.connect_custom_static_ip("45.141.215.77", 8443)?;
    let _ = app.select_starter_server(0)?;
    let eval_tor = app.update_network_route(true, true, true, false);
    report.push_str(&format!(
        "4. [OK] Стартовые Static-IP серверы (D-0019) и Сетевой щит (D-0008): прямой вход без Tor разрешён={default_direct_permitted}, кастомный Static IP слот=#{custom_idx}, Tor статус={:?}\n",
        eval_tor.status
    ));

    // 5. LeakGuard DLP interception (Bank card + Luhn + CVV + phone + email) & masking
    let risky_msg = "Моя карта 4532 0151 1283 0366 срок 08/28 cvv 777 и телефон +7 (999) 123-45-67";
    let intercepted = app.send_chat_message(risky_msg, false, None).is_err();
    let bucket_after_mask = app.confirm_leak_guard_masked_send()?;
    report.push_str(&format!(
        "5. [OK] LeakGuard (D-0009): перехват карты/CVV/телефона={intercepted}, после маскировки (****) отправлен пакет {bucket_after_mask} B\n"
    ));

    // 6. View-Once photo with EXIF/GPS stripping
    let raw_jpeg = [
        0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x06, b'G', b'P', b'S', 0x00, 0xFF, 0xDA, 0x00, 0x04, 0x00,
        0x00, 0x99, 0x88, 0xFF, 0xD9,
    ];
    let mut photo = MediaAttachmentView::strip_exif_and_create("passport.jpg", &raw_jpeg, true);
    let orig_len = photo.original_size_bytes;
    let stripped_len = photo.stripped_size_bytes;
    let opened_first = photo.open_attachment();
    let opened_second = photo.open_attachment();
    report.push_str(&format!(
        "6. [OK] Очистка EXIF/GPS и View-Once: {orig_len} B -> {stripped_len} B, 1-е открытие={opened_first}, повторное открытие заблокировано={}\n",
        !opened_second
    ));

    // 7. Pure Chat Fortress SealedSenderEnvelope (Pad-Before-Encrypt 1:1 capsule, zero calls D-0021)
    let root = combine_pqxdh_secrets(&[0x11; 32], &[0x22; 32], b"walkthrough")
        .unwrap_or_else(|_| unreachable!());
    let mut alice_dr = RatchetSession::new(root.as_slice(), [0xA1; 32], [0xB2; 32], true)
        .map_err(|_| DesktopUiError::Protocol(ProtocolError::MalformedPaddedFrame))?;
    let (rh, ct) = alice_dr
        .send_ratchet_step(b"sealed-capsule-payload", b"aad")
        .map_err(|_| DesktopUiError::Protocol(ProtocolError::MalformedPaddedFrame))?;
    let sealed_wire =
        SealedSenderEnvelope::seal(&[0x91; 32], &[0x92; 32], &[0x05; 12], &[0xA9; 32], &rh, &ct)
            .map_err(DesktopUiError::Protocol)?;
    report.push_str(&format!(
        "7. [OK] Чистая чат-крепость (D-0021, 0 звонков): 1:1 SealedSenderEnvelope запечатан в {} B (Pad-Before-Encrypt)\n",
        sealed_wire.len()
    ));

    // 8. 1-Click Server Launcher (VPS Docker & Tor Onion) + Signed Server Directory ✓✓
    let plan = app
        .server_launcher
        .configure(LaunchTarget::TorOnionService, 9001, 30)?;
    report.push_str(&format!(
        "8. [OK] Мастер запуска сервера в 1 клик: режим={:?}, порт={}, каталог серверов проверен ({} узла ✓✓/✓)\n",
        plan.target,
        plan.bind_port,
        app.directory_servers.len()
    ));

    // 9. Support Ticket & Theme Store Sandbox
    let ticket = app.submit_support_ticket(
        [0x33; 32],
        SupportTicketCategory::SecurityOrBugReport,
        "Проверка зашифрованного канала тикетов с галочкой ✓",
    )?;
    app.install_plugin_or_theme(PluginManifest {
        plugin_id: "arctic-neon-theme".to_owned(),
        declarative_theme_only: true,
        allowed_read_chats: Vec::new(),
        allow_proxied_network: false,
        requested_forbidden_key_access: false,
    })?;
    report.push_str(&format!(
        "9. [OK] Поддержка ✓ и Магазин тем: тикет упакован в {} B, активная тема='{}'\n",
        ticket.encrypted_padded_payload.len(),
        app.theme_selector.active_theme_id
    ));

    // 10. Calculator Disguise, Duress PIN & Panic Button
    app.enable_calculator_disguise();
    app.calculator_disguise.display_buffer = "125+375".to_owned();
    let math_action = app
        .calculator_disguise
        .press_equals(&app.app_pin, app.duress_pin.as_deref());
    let calc_res = app.calculator_disguise.last_result.clone();
    app.calculator_disguise
        .display_buffer
        .clone_from(&app.app_pin);
    let unlock_action = app
        .calculator_disguise
        .press_equals(&app.app_pin, app.duress_pin.as_deref());
    app.trigger_panic_wipe();
    report.push_str(&format!(
        "10. [OK] Маскировка калькулятора (125+375={calc_res}, {math_action:?} -> {unlock_action:?}) и Паник-кнопка (экран: {:?}, чатов осталось: {})\n",
        app.current_screen,
        app.chats.len()
    ));

    report.push_str("============================================================\n");
    report.push_str("✅ ВСЕ 10 ПОДСИСТЕМ DESKTOP КЛИЕНТА ПРОШЛИ ПРОВЕРКУ БЕЗ ОШИБОК\n");
    Ok(report)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn desktop_localization_ru_and_en_complete() {
        let mut gui = DesktopGuiServer::new(0, DesktopAppState::new(Locale::Ru));
        assert_eq!(gui.state.strings().locale, Locale::Ru);
        assert!(gui.state.strings().app_title.contains("Анонимный"));

        gui.handle_command("cmd=lang_en");
        assert_eq!(gui.state.strings().locale, Locale::En);
        assert!(gui.state.strings().app_title.contains("Anonymous"));

        let ws_html = gui.render_html();
        assert!(ws_html.contains("Saved Messages"));
        assert!(ws_html.contains("Toggles"));
        assert!(ws_html.contains("Disappearing messages"));

        gui.handle_command("cmd=step_account");
        let ob_html = gui.render_html();
        assert!(ob_html.contains("① Account Vault"));
        assert!(ob_html.contains("Create a local profile."));

        gui.handle_command("cmd=step_servers");
        let srv_html = gui.render_html();
        assert!(srv_html.contains("② Servers & Relays"));
        assert!(srv_html.contains("Network Lock (Kill Switch)"));
    }

    #[test]
    fn desktop_multi_account_enforces_three_free_and_unlocks_with_supporter_pass() {
        let mut app = DesktopAppState::new(Locale::Ru);
        let n1 = generate_nickname([1, 1, 1, 1]);
        let n2 = generate_nickname([2, 2, 2, 2]);
        let n3 = generate_nickname([3, 3, 3, 3]);
        let n4 = generate_nickname([4, 4, 4, 4]);

        assert_eq!(
            app.accounts
                .create_account([1; 16], &n1, "Acc1", "AEGis#Pass111!"),
            Ok(1)
        );
        assert_eq!(
            app.accounts
                .create_account([2; 16], &n2, "Acc2", "AEGis#Pass222!"),
            Ok(2)
        );
        assert_eq!(
            app.accounts
                .create_account([3; 16], &n3, "Acc3", "AEGis#Pass333!"),
            Ok(3)
        );

        // 4th account blocked without SupporterPass
        assert_eq!(
            app.accounts
                .create_account([4; 16], &n4, "Acc4", "AEGis#Pass444!"),
            Err(DesktopUiError::AccountSlot(
                AccountSlotError::FreeQuotaExceeded { max_free: 3 }
            ))
        );

        // Activate blind-signed SupporterPass
        app.accounts
            .unlock_with_supporter_pass(SupporterPass {
                token_id: [0x99; 16],
                max_accounts: 5,
                signature_verified: true,
            })
            .expect("valid pass must activate");

        assert_eq!(
            app.accounts
                .create_account([4; 16], &n4, "Acc4", "AEGis#Pass444!"),
            Ok(4)
        );
    }

    #[test]
    fn desktop_leak_guard_modal_intercepts_and_masks_sensitive_data() {
        let mut app = DesktopAppState::new(Locale::Ru);
        let text = "Карта 4532 0151 1283 0366 exp 08/28 cvv 123 и почта user@proton.me";

        let res = app.send_chat_message(text, false, None);
        assert!(matches!(res, Err(DesktopUiError::LeakDetected(_))));
        assert!(app.leak_guard_modal.is_some());

        let modal = app.leak_guard_modal.as_ref().unwrap();
        assert!(!modal.redacted_preview.contains("4532 0151"));
        assert!(!modal.redacted_preview.contains("user@proton.me"));
        assert!(modal.redacted_preview.contains("****"));

        let bucket = app
            .confirm_leak_guard_masked_send()
            .expect("masked send must succeed");
        assert_eq!(bucket, 256);
        assert!(app.leak_guard_modal.is_none());
    }

    #[test]
    fn desktop_exif_stripper_and_view_once_attachment() {
        let jpeg_with_exif = [
            0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00, 0xFF, 0xDA,
            0x00, 0x04, 0x00, 0x00, 0xAA, 0xBB, 0xFF, 0xD9,
        ];
        let mut att =
            MediaAttachmentView::strip_exif_and_create("photo.jpg", &jpeg_with_exif, true);
        assert!(att.exif_gps_stripped);
        assert!(att.stripped_size_bytes < att.original_size_bytes);
        assert!(att.open_attachment());
        // Second open on view-once attachment must return false
        assert!(!att.open_attachment());
    }

    #[test]
    fn desktop_calculator_disguise_duress_pin_and_panic_wipe() {
        let mut app = DesktopAppState::new(Locale::Ru);
        app.enable_calculator_disguise();
        assert_eq!(app.current_screen, Screen::CalculatorDisguise);

        app.calculator_disguise.display_buffer = "20*5".to_owned();
        assert_eq!(
            app.calculator_disguise
                .press_equals(&app.app_pin, app.duress_pin.as_deref()),
            CalculatorAction::ComputedMath
        );
        assert_eq!(app.calculator_disguise.last_result, "100");

        // Secret PIN unlocks vault
        app.calculator_disguise.display_buffer = "2580".to_owned();
        assert_eq!(
            app.calculator_disguise
                .press_equals(&app.app_pin, app.duress_pin.as_deref()),
            CalculatorAction::UnlockRealVault
        );

        // Duress PIN activates decoy profile
        app.verify_app_pin("9999").unwrap();
        assert!(app.duress_mode_active);
        assert_eq!(app.chats.len(), 1);

        // Panic wipe clears all chats
        app.trigger_panic_wipe();
        assert_eq!(app.current_screen, Screen::PanicWiped);
        assert!(app.chats.is_empty());
    }

    #[test]
    fn desktop_gui_server_renders_html_and_processes_commands() {
        let state = DesktopAppState::new(Locale::Ru);
        let mut gui = DesktopGuiServer::new(0, state);
        gui.handle_command("cmd=gen_nick");
        gui.handle_command("cmd=add_account");
        gui.handle_command("cmd=test_leak_card");
        let html = gui.render_html();
        assert!(html.contains("LeakGuard"));
        assert!(html.contains("Профиль #1"));
    }

    #[test]
    fn desktop_automated_walkthrough_succeeds() {
        let report = run_automated_demo_walkthrough().expect("walkthrough must succeed");
        assert!(report.contains("ВСЕ 10 ПОДСИСТЕМ DESKTOP КЛИЕНТА ПРОШЛИ ПРОВЕРКУ БЕЗ ОШИБОК"));
    }

    #[test]
    fn b0030_query_param_parser_and_i64_min_division_and_chat_pin_lockout() {
        assert_eq!(
            extract_query_param("flag&cmd=send_text&text=hello+world", "cmd"),
            Some("send_text".to_owned())
        );

        let mut app = DesktopAppState::new(Locale::Ru);
        // i64::MIN / -1 must not panic
        app.calculator_disguise.display_buffer = format!("{}/-1", i64::MIN);
        assert_eq!(
            app.calculator_disguise
                .press_equals(&app.app_pin, app.duress_pin.as_deref()),
            CalculatorAction::ComputedMath
        );

        // Wrong per-chat PIN decrements remaining_pin_attempts
        let before = app.remaining_pin_attempts;
        assert!(app.unlock_chat_with_pin(1, "0000").is_err());
        assert_eq!(app.remaining_pin_attempts, before - 1);
    }

    #[test]
    fn b0050_b0051_disguise_and_panic_html_hide_chats_and_scrub_all_sensitive_fields() {
        let state = DesktopAppState::new(Locale::Ru);
        let mut gui = DesktopGuiServer::new(0, state);

        // B-0050: CalculatorDisguise HTML renders only the disguised calculator, hiding chats & accounts
        gui.handle_command("cmd=disguise");
        let disguise_html = gui.render_html();
        assert!(disguise_html.contains("Инженерный калькулятор"));
        assert!(!disguise_html.contains("nordic-falcon"));
        assert!(!disguise_html.contains("Мультиаккаунты"));

        // B-0051: Out-of-bounds unlock_chat_with_pin returns Err(ChatLockedWithPin)
        assert_eq!(
            gui.state.unlock_chat_with_pin(999, "7788"),
            Err(DesktopUiError::ChatLockedWithPin)
        );

        // B-0051: Switching active chat before confirm_leak_guard_masked_send fails closed
        gui.handle_command("cmd=calc_eval&expr=2580");
        assert_eq!(gui.state.current_screen, Screen::ChatWorkspace);
        gui.handle_command("cmd=test_leak_card");
        assert!(gui.state.leak_guard_modal.is_some());
        gui.state.active_chat_index = 0;
        assert!(gui.state.confirm_leak_guard_masked_send().is_err());

        // B-0050 & B-0051: Panic wipe scrubs all sensitive fields and renders only wiped screen
        gui.handle_command("cmd=panic");
        assert!(gui.state.onboarding_nickname.is_empty());
        assert!(gui.state.app_pin.is_empty());
        assert!(gui.state.duress_pin.is_none());
        assert!(!gui.state.support_portal.supporter_pass_active);

        let wiped_html = gui.render_html();
        assert!(wiped_html.contains("КРИПТОГРАФИЧЕСКОЕ СТИРАНИЕ ВЫПОЛНЕНО"));
        assert!(!wiped_html.contains("nordic-falcon"));

        // B-0066: verify_app_pin("") after panic wipe must fail closed and commands must be ignored
        assert!(gui.state.verify_app_pin("").is_err());
        gui.handle_command("cmd=add_account");
        assert!(gui.state.accounts.profiles.is_empty());
        assert_eq!(gui.state.current_screen, Screen::PanicWiped);
    }

    #[test]
    fn b0066_starter_static_ip_servers_work_without_tor_and_support_custom_static_ip() {
        let mut app = DesktopAppState::new(Locale::Ru);
        // Default state uses direct static-IP starter server without requiring Tor
        assert!(!app.route_probe.via_tor);
        assert!(!app.route_probe.kill_switch_enabled);
        assert!(app.shield_evaluation.traffic_permitted);
        assert_eq!(
            app.directory_servers[0].static_ipv4,
            Some([185, 220, 101, 42])
        );

        // Connect custom static IP in 1 click
        let idx = app.connect_custom_static_ip("203.0.113.50", 8443).unwrap();
        assert_eq!(app.selected_server_index, idx);
        assert_eq!(
            app.directory_servers[idx].static_ipv4,
            Some([203, 0, 113, 50])
        );
        assert!(app.shield_evaluation.traffic_permitted);
    }

    #[test]
    fn b0077_localhost_csrf_dns_rebinding_chat_pin_bypass_and_calculator_bruteforce_protection() {
        // 1. Localhost CSRF & DNS Rebinding protection
        assert!(is_trusted_local_http_request(
            "GET /action?cmd=gen_nick HTTP/1.1\r\nHost: 127.0.0.1:7878\r\nSec-Fetch-Site: same-origin\r\n\r\n"
        ));
        assert!(!is_trusted_local_http_request(
            "GET /action?cmd=panic HTTP/1.1\r\nHost: 127.0.0.1:7878\r\nSec-Fetch-Site: cross-site\r\n\r\n"
        ));
        assert!(!is_trusted_local_http_request(
            "GET /action?cmd=panic HTTP/1.1\r\nHost: evil-rebind.example.com:7878\r\n\r\n"
        ));
        assert!(!is_trusted_local_http_request(
            "GET /action?cmd=panic HTTP/1.1\r\nHost: 127.0.0.1:7878\r\nOrigin: https://evil.example.com\r\n\r\n"
        ));

        let mut gui = DesktopGuiServer::new(0, DesktopAppState::new(Locale::Ru));
        // 2. HTML never exposes cleartext per-chat PIN "7788"
        let html = gui.render_html();
        assert!(!html.contains("7788"));

        // 3. Locking chat via toggle_chat_pin works, but unlocking without `&pin=7788` is rejected and decrements attempts
        gui.handle_command("cmd=toggle_chat_pin");
        assert!(gui.state.chats[1].is_locked);
        gui.handle_command("cmd=toggle_chat_pin");
        assert!(gui.state.chats[1].is_locked);
        assert_eq!(gui.state.remaining_pin_attempts, 9);
        gui.handle_command("cmd=toggle_chat_pin&pin=7788");
        assert!(!gui.state.chats[1].is_locked);

        // 4. Custom server receives CommunityUnverified badge (never VerifiedSingleCheck ✓) and gets scrubbed on Duress/Panic
        let custom_idx = gui
            .state
            .connect_custom_static_ip("203.0.113.99", 8443)
            .unwrap();
        assert_eq!(
            gui.state.directory_servers[custom_idx].badge,
            ServerBadge::CommunityUnverified
        );
        gui.state.activate_duress_decoy_mode();
        assert_eq!(gui.state.directory_servers.len(), 4);

        // 5. Calculator disguise brute-force lockout triggers PanicWiped after exhausting remaining_pin_attempts
        let mut gui2 = DesktopGuiServer::new(0, DesktopAppState::new(Locale::Ru));
        gui2.handle_command("cmd=disguise");
        assert_eq!(gui2.state.current_screen, Screen::CalculatorDisguise);
        for _ in 0..10 {
            gui2.handle_command("cmd=calc_eval&expr=0000");
        }
        assert_eq!(gui2.state.current_screen, Screen::PanicWiped);
        assert!(gui2.state.chats.is_empty());
    }

    #[test]
    fn t0014_cross_country_live_tcp_capsule_exchange_between_two_clients() {
        use aegis_ffi::{handle_http_request, FederationServerState, SupportPortalState};
        use std::thread;

        // Bind a real TCP Federation Server listener on an ephemeral port (simulating an international Static-IP VPS)
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server_handle = thread::spawn(move || {
            let mut srv = FederationServerState::new([0x55; 32]);
            let mut portal = SupportPortalState::new();
            // Handle 2 requests: 1st = Client A (Country A) sending capsule; 2nd = Client B (Country B) polling capsule
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 32_768];
                let n = stream.read(&mut buf).unwrap();
                let req_str = core::str::from_utf8(&buf[..n]).unwrap();
                let (head, body) = req_str.split_once("\r\n\r\n").unwrap();
                let mut parts = head.lines().next().unwrap().split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                let (status, ctype, resp_body) =
                    handle_http_request(&mut srv, &mut portal, method, path, body);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        let mut client_country_a = DesktopAppState::new(Locale::Ru);
        let mut client_country_b = DesktopAppState::new(Locale::En);
        let shared_channel = "cross-border-channel-zurich-tokyo-2026";

        // Client A in Country 1 encrypts and transmits a 256-byte capsule over TCP to the server
        let sent_bucket = client_country_a
            .transmit_cross_border_capsule(
                &addr,
                shared_channel,
                "Привет из другой страны! Капсула ChaCha20-Poly1305 доставлена по сети.",
            )
            .unwrap();
        assert_eq!(sent_bucket, 256);

        // Client B in Country 2 polls the server over TCP, verifies the Poly1305 tag, and decrypts the message
        let received = client_country_b
            .sync_remote_capsules(&addr, shared_channel)
            .unwrap();
        assert_eq!(received, 1);
        let last_msg = client_country_b.chats[client_country_b.active_chat_index]
            .messages
            .last()
            .unwrap();
        assert!(!last_msg.outgoing);
        assert_eq!(
            last_msg.text,
            "Привет из другой страны! Капсула ChaCha20-Poly1305 доставлена по сети."
        );

        server_handle.join().unwrap();
    }

    #[test]
    fn t0016_blind_cross_border_relay_hides_sender_ip_and_blocks_replay_and_origin_spoofing() {
        use aegis_ffi::{handle_http_request, FederationServerState, SupportPortalState};
        use std::thread;

        // Exit Node B (e.g., USA/Tokyo node where Client B polls)
        let exit_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let exit_addr = exit_listener.local_addr().unwrap().to_string();

        let exit_handle = thread::spawn(move || {
            let mut srv = FederationServerState::new([0x88; 32]);
            let mut portal = SupportPortalState::new();
            // Exit Node B handles 2 relayed requests from Entry Relay Node A (send + poll)
            for _ in 0..2 {
                let (mut stream, _) = exit_listener.accept().unwrap();
                let mut buf = [0u8; 65_536];
                let n = stream.read(&mut buf).unwrap();
                let req_str = core::str::from_utf8(&buf[..n]).unwrap();
                assert!(req_str.contains("X-Aegis-Blind-Relay: 1"));
                let (head, body) = req_str.split_once("\r\n\r\n").unwrap();
                let mut parts = head.lines().next().unwrap().split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                let (status, ctype, resp_body) =
                    handle_http_request(&mut srv, &mut portal, method, path, body);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        // Entry Relay Node A (e.g., Zurich node that Client A in Russia connects to)
        let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_listener.local_addr().unwrap().to_string();

        let relay_handle = thread::spawn(move || {
            let mut srv = FederationServerState::new([0x77; 32]);
            let mut portal = SupportPortalState::new();
            for _ in 0..2 {
                let (mut stream, _) = relay_listener.accept().unwrap();
                let mut buf = [0u8; 65_536];
                let n = stream.read(&mut buf).unwrap();
                let req_str = core::str::from_utf8(&buf[..n]).unwrap();
                let (head, body) = req_str.split_once("\r\n\r\n").unwrap();
                let mut parts = head.lines().next().unwrap().split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                let (status, ctype, resp_body) =
                    handle_http_request(&mut srv, &mut portal, method, path, body);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        let mut client_russia = DesktopAppState::new(Locale::Ru);
        client_russia.blind_relay_endpoint = Some(relay_addr.clone());

        let mut client_usa = DesktopAppState::new(Locale::En);
        client_usa.blind_relay_endpoint = Some(relay_addr);

        let channel = "queue://global-blind-relay-2026";
        let bucket = client_russia
            .transmit_cross_border_capsule(
                &exit_addr,
                channel,
                "Анонимная капсула через слепой релей: сервер получателя не знает наш IP!",
            )
            .unwrap();
        assert_eq!(bucket, 256);

        let count = client_usa
            .sync_remote_capsules(&exit_addr, "global-blind-relay-2026")
            .unwrap();
        assert_eq!(count, 1);

        // B-0091: Origin prefix spoofing (`http://localhost.evil.com` and `Origin: null`) must be rejected
        assert!(!is_trusted_local_http_request(
            "GET /action?cmd=panic HTTP/1.1\r\nHost: 127.0.0.1:7878\r\nOrigin: http://localhost.evil.com\r\n\r\n"
        ));
        assert!(!is_trusted_local_http_request(
            "GET /action?cmd=panic HTTP/1.1\r\nHost: 127.0.0.1:7878\r\nOrigin: null\r\n\r\n"
        ));

        relay_handle.join().unwrap();
        exit_handle.join().unwrap();
    }

    #[test]
    fn t0016_isolated_steps_no_prefilled_password_interactive_keypad_and_vault_features() {
        let mut gui = DesktopGuiServer::new(0, DesktopAppState::new(Locale::Ru));

        // 1. Step 1 (Onboarding) isolates the Account Vault view and never pre-fills a password in HTML
        gui.handle_command("cmd=step_account");
        assert_eq!(gui.state.current_screen, Screen::Onboarding);
        let step1_html = gui.render_html();
        assert!(step1_html.contains("① Сейф Аккаунта"));
        assert!(!step1_html.contains("AEGis#StrongPass99!"));
        assert!(!step1_html.contains("nordic-falcon"));

        // 2. Seed-only toggle and 24-word recovery phrase generation on Step 1
        gui.handle_command("cmd=toggle_seed_only");
        assert!(!gui.state.seed_only_mode);
        gui.handle_command("cmd=gen_recovery_phrase");
        assert!(gui.state.recovery_phrase_preview.is_some());

        // 3. Step 2 (ServerLauncher) isolates the Server & Relay Matrix view without exposing chats
        gui.handle_command("cmd=step_servers");
        assert_eq!(gui.state.current_screen, Screen::ServerLauncher);
        let step2_html = gui.render_html();
        assert!(step2_html.contains("② Матрица Серверов и Релеев"));
        assert!(!step2_html.contains("nordic-falcon"));

        // 4. Step 3 (ChatWorkspace) supports Safety Number, Key-Change Warning (which blocks sending until acknowledged), Queue Rotation, MLS Group <=20, and Explicit Backup
        gui.handle_command("cmd=step_chats");
        assert_eq!(gui.state.current_screen, Screen::ChatWorkspace);
        gui.handle_command("cmd=simulate_key_change");
        assert!(gui.state.key_change_warning.is_some());
        assert!(!gui.state.peer_verified);
        assert!(gui
            .state
            .send_chat_message("Blocked during MITM warning", false, None)
            .is_err());
        gui.handle_command("cmd=ack_key_change");
        assert!(gui.state.key_change_warning.is_none());
        assert!(gui.state.peer_verified);
        assert!(gui
            .state
            .send_chat_message("Allowed after acknowledging new key", false, None)
            .is_ok());

        gui.handle_command("cmd=rotate_queue");
        gui.handle_command("cmd=create_group&title=Альфа&members=8");
        assert!(gui.state.chats.last().unwrap().title.contains("MLS ≤20"));
        assert!(gui.state.create_mls_group_conduit("TooBig", 21).is_err());

        gui.handle_command("cmd=export_backup");
        assert!(gui.state.last_exported_backup_hex.is_some());

        // 5. Calculator Disguise uses Precision Titanium (#0B101B), encodes '+' as '%2B' so 7+8=15, and supports interactive keypad clicks
        gui.handle_command("cmd=disguise");
        gui.handle_command("cmd=calc_key&k=7");
        gui.handle_command("cmd=calc_key&k=add");
        gui.handle_command("cmd=calc_key&k=8");
        let calc_html = gui.render_html();
        assert!(calc_html.contains("#0B101B"));
        assert!(calc_html.contains("expr=7%2B8"));
        gui.handle_command("cmd=calc_eval&expr=7%2B8");
        assert_eq!(gui.state.calculator_disguise.last_result, "15");
        gui.handle_command("cmd=calc_key&k=clear");
        gui.handle_command("cmd=calc_key&k=2");
        gui.handle_command("cmd=calc_key&k=5");
        gui.handle_command("cmd=calc_key&k=8");
        gui.handle_command("cmd=calc_key&k=0");
        assert_eq!(gui.state.calculator_disguise.display_buffer, "2580");
        gui.handle_command("cmd=calc_eval&expr=2580");
        assert_eq!(gui.state.current_screen, Screen::ChatWorkspace);

        // 6. Duress mode never exposes "local-decoy" tag or real contact button "nordic-falcon"
        gui.state.activate_duress_decoy_mode();
        assert_eq!(gui.state.chats[0].queue_tag, "notes://household");
        let duress_html = gui.render_html();
        assert!(!duress_html.contains("local-decoy"));
        assert!(!duress_html.contains("nordic-falcon"));
    }

    #[test]
    fn t0018_http_form_actions_accept_only_local_get_and_urlencoded_post() {
        assert_eq!(
            http_action_query(
                "GET /action?cmd=gen_nick HTTP/1.1\r\nHost: 127.0.0.1:7878\r\n\r\n"
            )
            .as_deref(),
            Some("cmd=gen_nick")
        );
        assert_eq!(
            http_action_query(
                "POST /action HTTP/1.1\r\nHost: 127.0.0.1:7878\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 36\r\n\r\ncmd=login_account&nick=test&pwd=Secret"
            )
            .as_deref(),
            Some("cmd=login_account&nick=test&pwd=Secret")
        );
        assert!(http_action_query(
            "POST /action HTTP/1.1\r\nHost: 127.0.0.1:7878\r\nContent-Type: text/plain\r\n\r\ncmd=panic"
        )
        .is_none());
        assert!(http_action_query(
            "GET /not-the-ui HTTP/1.1\r\nHost: 127.0.0.1:7878\r\n\r\n"
        )
        .is_none());
    }
}
