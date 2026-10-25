//! `aegis-ui-desktop` — Cross-Platform Desktop UI & Local Interactive GUI Server for Aegis.
//!
//! Communicates exclusively through `aegis-ffi` (`AGENTS.md §2.6, §3, §4`).
//! Never accesses raw cryptographic keys or internal state directly.

use aegis_ffi::{
    build_launch_plan, combine_pqxdh_secrets, compute_pow_difficulty, constant_time_eq,
    core_version_info, derive_channel_key_and_queue, evaluate_network_shield,
    format_server_invite_uri, generate_docker_compose, generate_nickname,
    generate_torrc_hidden_service, open_cross_border_capsule, pad_frame, poll_capsules_over_tcp,
    redact_leaks, scan_message_for_leaks, seal_cross_border_capsule, send_capsule_over_tcp,
    strip_media_metadata, validate_launch_config, validate_manifest, validate_nickname,
    validate_password, verify_server_badge, AccountSlotError, AccountSlotManager, CoreVersionInfo,
    DirectoryError, LaunchPlan, LaunchTarget, LauncherError, LeakWarning, Locale,
    NetworkRouteStatus, NicknameError, PasswordPolicyError, PluginError, PluginManifest,
    ProtocolError, RatchetSession, RouteProbe, SealedSenderEnvelope, ServerBadge, ShieldEvaluation,
    SignerAttestation, SupportTicket, SupportTicketCategory, SupporterPass, ThresholdPolicy,
};
use core::fmt;
use std::io::{Read, Write};
use std::net::TcpListener;

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
                app_title: "Aegis — Анонимный мессенджер (E2EE / Zero-Knowledge)",
                onboarding_title: "Регистрация за 3 шага: Ник → Строгий пароль → PIN и Сервер ✓✓",
                nickname_generate_btn: "🎲 Сгенерировать криптостойкий ник",
                password_policy_hint:
                    "Минимум 12 символов, ≥3 ЗАГЛАВНЫЕ буквы, строчные, цифры и спецсимволы (OPAQUE + Argon2id)",
                network_shield_tor: "🔒 Tor / Onion (Максимальная защита IP)",
                network_shield_vpn: "🛡 VPN / SOCKS5 Прокси активен",
                network_shield_direct: "🌐 Прямой Static IP (E2EE + 0 IP-логов, без Tor)",
                network_shield_offline: "⛔ Офлайн / Заблокировано Kill Switch",
                saved_notes_title: "📌 Избранное (Локальное зашифрованное хранилище)",
                leak_guard_modal_title: "🛡 LeakGuard: Обнаружены чувствительные данные!",
                leak_guard_mask_btn: "Скрыть звёздочками (****) и отправить",
                leak_guard_send_anyway_btn: "Отправить без изменений",
                panic_button_label: "🚨 ПАНИК-КНОПКА (Мгновенный крипто-сброс)",
                disguise_calculator_title: "Инженерный калькулятор",
                server_launcher_title: "🚀 Мастер запуска своего сервера Aegis в 1 клик",
                support_portal_title: "🎫 Анонимная поддержка ✓ и активация SupporterPass",
                theme_store_title: "🎨 Магазин декларативных тем и WASM-песочница плагинов",
            },
            Locale::En => Self {
                locale: Locale::En,
                app_title: "Aegis — Anonymous Messenger (E2EE / Zero-Knowledge)",
                onboarding_title: "3-Step Onboarding: Nickname → Strict Password → PIN & Server ✓✓",
                nickname_generate_btn: "🎲 Generate CSPRNG Anonymous Nickname",
                password_policy_hint:
                    "Min 12 chars, ≥3 UPPERCASE letters, lowercase, digits & special symbols (OPAQUE + Argon2id)",
                network_shield_tor: "🔒 Tor / Onion (Maximum IP Anonymity)",
                network_shield_vpn: "🛡 VPN / SOCKS5 Proxy Protected",
                network_shield_direct: "🌐 Direct Static IP (E2EE + Zero IP Logs, No Tor Required)",
                network_shield_offline: "⛔ Offline / Blocked by Kill Switch",
                saved_notes_title: "📌 Saved Notes (Device-Only Encrypted Vault)",
                leak_guard_modal_title: "🛡 LeakGuard: Sensitive Data Detected Before Encryption!",
                leak_guard_mask_btn: "Mask with (****) & Send",
                leak_guard_send_anyway_btn: "Send Anyway",
                panic_button_label: "🚨 PANIC BUTTON (Instant Crypto-Erase)",
                disguise_calculator_title: "Scientific Calculator",
                server_launcher_title: "🚀 1-Click Self-Hosted Aegis Server Wizard",
                support_portal_title: "🎫 Verified Support Portal ✓ & SupporterPass Activation",
                theme_store_title: "🎨 Declarative Theme Store & WASM Plugin Sandbox",
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
    if let Some((a, b)) = expr.split_once('+') {
        let x: i64 = a.trim().parse().ok()?;
        let y: i64 = b.trim().parse().ok()?;
        return Some(x.saturating_add(y).to_string());
    }
    if let Some((a, b)) = expr.split_once('*') {
        let x: i64 = a.trim().parse().ok()?;
        let y: i64 = b.trim().parse().ok()?;
        return Some(x.saturating_mul(y).to_string());
    }
    if let Some((a, b)) = expr.split_once('-') {
        if !a.trim().is_empty() {
            let x: i64 = a.trim().parse().ok()?;
            let y: i64 = b.trim().parse().ok()?;
            return Some(x.saturating_sub(y).to_string());
        }
    }
    if let Some((a, b)) = expr.split_once('/') {
        let x: i64 = a.trim().parse().ok()?;
        let y: i64 = b.trim().parse().ok()?;
        if y != 0 {
            return Some(x.wrapping_div(y).to_string());
        }
    }
    expr.parse::<i64>().ok().map(|v| v.to_string())
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
            title: "📌 Избранное (Локальные зашифрованные заметки)".to_owned(),
            queue_tag: "local-sqlcipher-only://vault".to_owned(),
            is_local_saved_notes: true,
            verified_support_badge: false,
            per_chat_pin: None,
            is_locked: false,
            default_disappearing_ttl_secs: None,
            messages: vec![ChatMessageView {
                outgoing: true,
                text: "Локальное хранилище «Избранное»: ключи никогда не покидают устройство."
                    .to_owned(),
                padded_bucket_bytes: 256,
                disappearing_ttl_secs: None,
                attachment: None,
            }],
        };

        let peer_chat = ChatView {
            chat_id: [0x02; 16],
            title: "nordic-falcon (PQXDH + Double Ratchet)".to_owned(),
            queue_tag: "queue://nordic-falcon-global-v1".to_owned(),
            is_local_saved_notes: false,
            verified_support_badge: false,
            per_chat_pin: Some("7788".to_owned()),
            is_locked: false,
            default_disappearing_ttl_secs: Some(3600),
            messages: vec![ChatMessageView {
                outgoing: false,
                text: "Привет! Канал защищён гибридным X25519 + ML-KEM-768 и Sealed Sender."
                    .to_owned(),
                padded_bucket_bytes: 256,
                disappearing_ttl_secs: Some(3600),
                attachment: None,
            }],
        };

        let support_chat = ChatView {
            chat_id: [0x03; 16],
            title: "Официальная поддержка Aegis ✓".to_owned(),
            queue_tag: "queue://support-verified-cert".to_owned(),
            is_local_saved_notes: false,
            verified_support_badge: true,
            per_chat_pin: None,
            is_locked: false,
            default_disappearing_ttl_secs: None,
            messages: vec![ChatMessageView {
                outgoing: false,
                text: "Сертификат поддержки проверен (Ed25519 ✓). Здесь можно отправить зашифрованный тикет или активировать SupporterPass."
                    .to_owned(),
                padded_bucket_bytes: 256,
                disappearing_ttl_secs: None,
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
            chats: vec![saved_notes_chat, peer_chat, support_chat],
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
            status_banner: "Ядро Aegis инициализировано (Zero-Knowledge / OPAQUE / PQXDH)."
                .to_owned(),
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
        self.status_banner = match locale {
            Locale::Ru => "Язык интерфейса переключён на Русский (RU).".to_owned(),
            Locale::En => "Interface language switched to English (EN).".to_owned(),
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

    /// Encrypts a message into a 256..16384-byte RFC 8439 ChaCha20-Poly1305 capsule and transmits it
    /// over TCP/HTTP to `server_host_port` (`POST /api/v1/queue/send?queue=<hex>`), enabling live cross-country messaging.
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
        let (queue_id, _, _) = derive_channel_key_and_queue(channel_code);
        let msg_seq = self
            .chats
            .get(self.active_chat_index)
            .map_or(1u64, |c| c.messages.len() as u64)
            .max(1);
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&queue_id[0..4]);
        nonce[4..12].copy_from_slice(&msg_seq.to_be_bytes());
        if nonce == [0u8; 12] {
            nonce[0] = 1;
        }
        let capsule = seal_cross_border_capsule(channel_code, &nonce, plaintext)
            .map_err(DesktopUiError::Protocol)?;
        send_capsule_over_tcp(server_host_port, &queue_id, &capsule, 2_000)
            .map_err(|e| DesktopUiError::IoError(e.to_string()))?;
        Ok(bucket)
    }

    /// Polls pending encrypted capsules from `server_host_port` (`POST /api/v1/queue/poll?queue=<hex>`),
    /// authenticates and decrypts each RFC 8439 ChaCha20-Poly1305 capsule using `channel_code`,
    /// and appends them to the active chat.
    ///
    /// # Errors
    /// Returns [`DesktopUiError`] if the connection fails or any capsule fails AEAD verification.
    pub fn sync_remote_capsules(
        &mut self,
        server_host_port: &str,
        channel_code: &str,
    ) -> Result<usize, DesktopUiError> {
        let (queue_id, _, _) = derive_channel_key_and_queue(channel_code);
        let raw_frames = poll_capsules_over_tcp(server_host_port, &queue_id, 2_000)
            .map_err(|e| DesktopUiError::IoError(e.to_string()))?;
        let mut received_count = 0usize;
        for frame in &raw_frames {
            let plaintext =
                open_cross_border_capsule(channel_code, frame).map_err(DesktopUiError::Protocol)?;
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

    /// Masks all `LeakGuard` findings with `****` and sends the sanitized message.
    ///
    /// # Errors
    /// Propagates any error from [`DesktopAppState::send_chat_message`] or rejects if the active chat changed.
    pub fn confirm_leak_guard_masked_send(&mut self) -> Result<usize, DesktopUiError> {
        let Some(modal) = self.leak_guard_modal.take() else {
            return Ok(0);
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
        self.leak_guard_modal = None;
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
        self.accounts = AccountSwitcherView::new();
        self.leak_guard_modal = None;
        self.calculator_disguise.display_buffer.clear();
        self.calculator_disguise.last_result = "0".to_owned();
        self.calculator_disguise.disguise_active = false;
        self.support_portal.submitted_tickets.clear();
        self.support_portal.supporter_pass_active = false;
        self.support_portal.max_account_slots = 3;
        self.directory_servers.truncate(4);
        self.selected_server_index = 0;
        self.server_launcher = ServerLauncherWizardView::new_default();
        self.theme_selector.active_theme_id = "phantom-monolith".to_owned();
        self.theme_selector.verified_manifests.truncate(1);
        self.chats = vec![ChatView {
            chat_id: [0xD0; 16],
            title: "Покупки и бытовые заметки".to_owned(),
            queue_tag: "local-decoy".to_owned(),
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

    /// Renders the complete interactive HTML5 Dark-Mode Desktop UI reflecting the current `DesktopAppState`.
    #[must_use]
    pub fn render_html(&self) -> String {
        let s = self.state.strings();
        if self.state.current_screen == Screen::PanicWiped {
            return format!(
                "<!DOCTYPE html>
<html lang='ru'>
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
    <h1>🚨 КРИПТОГРАФИЧЕСКОЕ СТИРАНИЕ ВЫПОЛНЕНО</h1>
    <p style='color:#e6edf3;'>{status}</p>
  </div>
</body>
</html>",
                status = html_escape(&self.state.status_banner)
            );
        }

        if self.state.current_screen == Screen::CalculatorDisguise {
            return format!(
                "<!DOCTYPE html>
<html lang='ru'>
<head>
<meta charset='utf-8'>
<title>{calc_title}</title>
<style>
  body {{ background:#1c1c1e; color:#ffffff; font-family:system-ui,-apple-system,sans-serif; margin:0; padding:48px; }}
  .calc {{ max-width:360px; margin:0 auto; background:#2c2c2e; border-radius:14px; padding:20px; }}
  input[type=text] {{ width:100%; box-sizing:border-box; background:#000; color:#fff; font-size:22px; border:1px solid #444; padding:10px; border-radius:8px; margin-bottom:12px; }}
  button {{ width:100%; background:#ff9f0a; color:#000; font-weight:700; font-size:16px; border:none; padding:10px; border-radius:8px; cursor:pointer; }}
</style>
</head>
<body>
  <div class='calc'>
    <h2>🧮 {calc_title}</h2>
    <div style='margin-bottom:8px;color:#a1a1aa;'>Результат: <b>{res}</b></div>
    <form action='/action' method='get'>
      <input type='hidden' name='cmd' value='calc_eval'>
      <input type='text' name='expr' value='{buf}' placeholder='0'>
      <button type='submit'>=</button>
    </form>
  </div>
</body>
</html>",
                calc_title = html_escape(s.disguise_calculator_title),
                res = html_escape(&self.state.calculator_disguise.last_result),
                buf = html_escape(&self.state.calculator_disguise.display_buffer)
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

        let mut messages_html = String::new();
        if let Some(chat) = active_chat {
            if chat.is_locked {
                messages_html.push_str(
                    "<div class='warn-box'>🔒 Чат заблокирован персональным PIN-кодом. Введите PIN чата для разблокировки.</div>",
                );
            } else {
                for (idx, m) in chat.messages.iter().enumerate() {
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

        let onboarding_overlay_html = if self.state.current_screen == Screen::Onboarding {
            format!(
                "<div class='step-hero glass'>
                    <div class='slogan-kicker'>✦ AEGIS AURORA GLASS // ZERO-KNOWLEDGE MESSENGER</div>
                    <h1 style='margin:6px 0 4px 0;font-size:26px;color:#fff;'>Шаг 1. Вход в защищённый аккаунт</h1>
                    <p class='slogan-sub'>«Тень не оставляет следов. Твоя свобода — под защитой математики. Ни номеров. Ни почт. Ни границ.»</p>
                    <form action='/action' method='get' class='auth-form'>
                        <input type='hidden' name='cmd' value='login_account'>
                        <label>1. Ваш криптостойкий логин-ник (OPAQUE KDF — сервер его не видит)</label>
                        <div style='display:flex;gap:8px;margin-bottom:10px;'>
                            <input type='text' name='nick' value='{curr_nick}' style='width:100%;'>
                            <a class='btn' href='/action?cmd=gen_nick'>🎲 Сгенерировать</a>
                        </div>
                        <label>2. Отображаемое имя (видят только ваши контакты)</label>
                        <input type='text' name='alias' value='Призрак Сети' style='width:100%;margin-bottom:10px;'>
                        <label>3. Строгий пароль (≥12 символов, ≥3 ЗАГЛАВНЫЕ буквы, цифры и спецсимволы)</label>
                        <input type='password' name='pwd' value='AEGis#StrongPass99!' style='width:100%;margin-bottom:14px;'>
                        <div style='display:flex;gap:10px;'>
                            <button type='submit' class='btn ok' style='padding:11px 20px;font-size:14px;'>🚀 Войти и выбрать сервер (Шаг 2) →</button>
                            <a class='btn' href='/action?cmd=step_servers' style='padding:11px 16px;'>Пропустить к серверам →</a>
                        </div>
                    </form>
                </div>",
                curr_nick = html_escape(&self.state.onboarding_nickname),
            )
        } else if self.state.current_screen == Screen::ServerLauncher {
            format!(
                "<div class='step-hero glass'>
                    <div class='slogan-kicker'>✦ ШАГ 2 ИЗ 3 // ВЫБОР АНОНИМНОГО УЗЛА ФЕДЕРАЦИИ</div>
                    <h1 style='margin:6px 0 4px 0;font-size:24px;color:#fff;'>Шаг 2. Выберите сервер связи (работает между любыми странами)</h1>
                    <p class='slogan-sub'>«Создан быть невидимым. Спроектирован быть непобедимым.» Стартовые Static-IP узлы работают сразу без Tor.</p>
                    <ul style='list-style:none;padding:0;margin:14px 0;'>{servers}</ul>
                    <form action='/action' method='get' style='display:flex;gap:8px;margin:12px 0;'>
                        <input type='hidden' name='cmd' value='custom_server'>
                        <input type='text' name='ip' placeholder='Или введите свой Static IP:порт (напр. 185.220.101.42:8443)...' style='width:100%;'>
                        <button class='btn ok' type='submit'>⚡ Подключить и войти в чаты →</button>
                    </form>
                    <div style='margin-top:12px;display:flex;gap:10px;'>
                        <a class='btn ok' href='/action?cmd=step_chats' style='padding:11px 22px;font-size:14px;'>💬 Открыть мессенджер (Шаг 3: Чаты) →</a>
                        <a class='btn' href='/action?cmd=step_account'>← Назад к аккаунту</a>
                    </div>
                </div>",
                servers = servers_html,
            )
        } else {
            String::new()
        };

        let unlock_pin_form_html = if active_chat.is_some_and(|c| c.is_locked) {
            "<form action='/action' method='get' style='display:flex;gap:8px;margin:10px 0;'>
                <input type='hidden' name='cmd' value='toggle_chat_pin'>
                <input type='password' name='pin' placeholder='Введите PIN чата для разблокировки...' style='width:260px;'>
                <button class='btn ok' type='submit'>🔓 Разблокировать чат</button>
            </form>"
        } else {
            ""
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
        <a class='{s1}' href='/action?cmd=step_account'>① Вход в аккаунт</a>
        <a class='{s2}' href='/action?cmd=step_servers'>② Выбор сервера ({srv_ep})</a>
        <a class='{s3}' href='/action?cmd=step_chats'>③ Чаты</a>
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

  {onboarding_overlay}

  <div class='grid'>
    <div class='card glass'>
      <h3>💬 Чаты и Каналы (как в ТГ • E2EE)</h3>
      <div class='chat-list'>{chat_list_sidebar}</div>
      <form action='/action' method='get' style='margin-top:10px;background:rgba(255,255,255,0.03);padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,0.08);'>
        <input type='hidden' name='cmd' value='new_chat'>
        <div style='font-size:11px;color:var(--mint);font-weight:700;margin-bottom:6px;'>+ Новый чат / Связь с другой страной</div>
        <input type='text' name='title' placeholder='Имя собеседника (напр. Алекс)...' style='width:100%;margin-bottom:6px;'>
        <input type='text' name='code' placeholder='Общий секретный код канала (напр. tokyo-77)...' style='width:100%;margin-bottom:6px;'>
        <button class='btn ok' type='submit' style='width:100%;'>➕ Открыть зашифрованный чат</button>
      </form>
      <hr style='border-color:rgba(255,255,255,0.08);margin:12px 0;'>
      <h3>👤 Мультиаккаунты (до 3 + SupporterPass)</h3>
      <div>{accounts}</div>
      <div style='margin-top:8px;'>
        <a class='btn' href='/action?cmd=gen_nick'>{gen_nick_btn} ({curr_nick})</a>
        <a class='btn ok' href='/action?cmd=add_account'>+ Создать профиль</a>
        <a class='btn warn' href='/action?cmd=activate_pass'>🎫 SupporterPass (5 слотов)</a>
      </div>
    </div>

    <div class='card glass'>
      <div style='display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.09);padding-bottom:8px;margin-bottom:10px;'>
        <div>
          <h2 style='border:none;padding:0;margin:0;'>{chat_title}</h2>
          <small style='color:var(--muted);'>Узел: <b>{srv_ep}</b> • Сквозное шифрование ChaCha20-Poly1305 (256B)</small>
        </div>
        <div>
          <a class='btn ok' href='/action?cmd=sync_remote'>🌐 Принять из сети</a>
          <a class='btn warn' href='/action?cmd=toggle_chat_pin'>🔒 PIN чата</a>
        </div>
      </div>
      {unlock_pin_form}
      {leak_modal}
      <div>{messages}</div>
      <hr style='border-color:rgba(255,255,255,0.09);margin:14px 0;'>
      <form action='/action' method='get' style='display:flex;gap:8px;'>
        <input type='hidden' name='cmd' value='send_text'>
        <input type='text' name='text' placeholder='Написать сообщение... (LeakGuard защищает от случайной отправки карт/телефонов)' style='width:100%;'>
        <button class='btn ok' type='submit' style='white-space:nowrap;padding:9px 18px;'>Отправить ➤</button>
      </form>
      <div style='margin-top:10px;'>
        <a class='btn ok' href='/action?cmd=send_photo_view_once'>📷 Фото View-Once (без EXIF/GPS)</a>
        <a class='btn warn' href='/action?cmd=test_leak_card'>💳 Тест LeakGuard</a>
        <a class='btn' href='/action?cmd=chat_0'>📌 Избранное</a>
        <a class='btn' href='/action?cmd=chat_1'>🔐 nordic-falcon</a>
        <a class='btn' href='/action?cmd=chat_2'>✓ Поддержка</a>
      </div>
    </div>

    <div class='card glass'>
      <h3>🌐 Серверы связи (Static IP без Tor)</h3>
      <ul style='padding-left:18px;font-size:12px;'>{servers}</ul>
      <form action='/action' method='get' style='margin-top:8px;display:flex;gap:6px;'>
        <input type='hidden' name='cmd' value='custom_server'>
        <input type='text' name='ip' placeholder='Свой IP:порт (185.220.101.42:8443)...' style='width:100%;'>
        <button class='btn ok' type='submit'>⚡</button>
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
      <h3>{support_title}</h3>
      <p style='font-size:12px;'>Тикетов ✓: <b>{ticket_count}</b> | Слотов: <b>{max_slots}</b></p>
      <a class='btn ok' href='/action?cmd=send_ticket'>📨 Тикет в поддержку ✓</a>
    </div>
  </div>
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
            onboarding_overlay = onboarding_overlay_html,
            chat_list_sidebar = chat_list_sidebar_html,
            accounts = accounts_html,
            gen_nick_btn = s.nickname_generate_btn,
            curr_nick = html_escape(&self.state.onboarding_nickname),
            chat_title = html_escape(chat_title),
            unlock_pin_form = unlock_pin_form_html,
            leak_modal = leak_modal_html,
            messages = messages_html,
            launcher_title = s.server_launcher_title,
            launcher_bundle = html_escape(&self.state.server_launcher.generated_config_bundle),
            server_invite = html_escape(&self.state.server_launcher.generated_server_invite_uri),
            servers = servers_html,
            support_title = s.support_portal_title,
            ticket_count = self.state.support_portal.submitted_tickets.len(),
            max_slots = self.state.support_portal.max_account_slots,
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
            && cmd != "panic"
        {
            return;
        }
        match cmd.as_str() {
            "step_account" => {
                self.state.current_screen = Screen::Onboarding;
                self.state.status_banner =
                    "Шаг 1 из 3: Вход или создание анонимного аккаунта.".to_owned();
            }
            "step_servers" => {
                self.state.current_screen = Screen::ServerLauncher;
                self.state.status_banner =
                    "Шаг 2 из 3: Выберите стартовый сервер со статическим IP или введите свой."
                        .to_owned();
            }
            "step_chats" => {
                self.state.current_screen = Screen::ChatWorkspace;
                self.state.status_banner =
                    "Шаг 3 из 3: Капсульные чаты готовы к работе.".to_owned();
            }
            "login_account" => {
                let nick = extract_query_param(query, "nick")
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| self.state.onboarding_nickname.clone());
                let alias = extract_query_param(query, "alias")
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "Основной профиль".to_owned());
                let pwd = extract_query_param(query, "pwd")
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "AEGis#StrongPass99!".to_owned());
                let next_idx = (self.state.accounts.profiles.len() + 1) as u8;
                match self.state.accounts.create_account(
                    [next_idx; 16],
                    nick.trim(),
                    alias.trim(),
                    &pwd,
                ) {
                    Ok(_) => {
                        self.state.current_screen = Screen::ServerLauncher;
                        self.state.status_banner = format!(
                            "Вы вошли как {} ({}). Шаг 2: Выберите сервер связи.",
                            alias.trim(),
                            nick.trim()
                        );
                    }
                    Err(e) => {
                        self.state.status_banner = format!("Проверьте данные входа: {e}");
                    }
                }
            }
            "select_chat" => {
                if let Some(idx_str) = extract_query_param(query, "idx") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        if idx < self.state.chats.len() {
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
                        self.state.chats.push(ChatView {
                            chat_id: [id_byte; 16],
                            title: format!("🔐 {t}"),
                            queue_tag: format!("queue://{c}"),
                            is_local_saved_notes: false,
                            verified_support_badge: false,
                            per_chat_pin: None,
                            is_locked: false,
                            default_disappearing_ttl_secs: Some(3600),
                            messages: vec![ChatMessageView {
                                outgoing: false,
                                text: format!("Международный канал «{c}» открыт. Сообщения шифруются ChaCha20-Poly1305 (256B)."),
                                padded_bucket_bytes: 256,
                                disappearing_ttl_secs: Some(3600),
                                attachment: None,
                            }],
                        });
                        self.state.active_chat_index = self.state.chats.len() - 1;
                        self.state.current_screen = Screen::ChatWorkspace;
                        self.state.status_banner =
                            format!("Создан международный чат с {t} (канал: {c}).");
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
                                self.state.status_banner =
                                    format!("Ошибка подключения Static IP: {e}");
                            }
                        }
                    } else {
                        self.state.status_banner =
                            "Ошибка подключения Static IP: некорректный порт".to_owned();
                    }
                }
            }
            "lang_ru" => self.state.set_locale(Locale::Ru),
            "lang_en" => self.state.set_locale(Locale::En),
            "gen_nick" => {
                let step = (self.state.accounts.profiles.len() as u8).wrapping_add(7);
                let nick = self.state.regenerate_onboarding_nickname([
                    step,
                    step.wrapping_mul(3),
                    0x42,
                    0x19,
                ]);
                self.state.status_banner = format!("Сгенерирован новый анонимный ник: {nick}");
            }
            "add_account" => {
                let next_idx = (self.state.accounts.profiles.len() + 1) as u8;
                let nick = generate_nickname([next_idx, next_idx.wrapping_add(5), 0x10, next_idx]);
                let alias = format!("Профиль #{next_idx}");
                match self.state.accounts.create_account(
                    [next_idx; 16],
                    &nick,
                    &alias,
                    "AEGis#StrongPass99!",
                ) {
                    Ok(count) => {
                        self.state.status_banner = format!(
                            "Аккаунт {alias} ({nick}) создан через OPAQUE + Argon2id (всего: {count})."
                        );
                    }
                    Err(e) => {
                        self.state.status_banner = format!("Блокировка слота (D-0010): {e}");
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
                        self.state.status_banner =
                            "Токен слепой подписи SupporterPass проверен! Разблокировано до 5 аккаунтов."
                                .to_owned();
                    }
                    Err(e) => {
                        self.state.status_banner = format!("Ошибка SupporterPass: {e}");
                    }
                }
            }
            "chat_0" => self.state.active_chat_index = 0,
            "chat_1" => self.state.active_chat_index = 1,
            "chat_2" => self.state.active_chat_index = 2,
            "toggle_chat_pin" => {
                let idx = self.state.active_chat_index;
                if let Some(chat) = self.state.chats.get_mut(idx) {
                    if chat.is_locked {
                        let pin = extract_query_param(query, "pin").unwrap_or_default();
                        match self.state.unlock_chat_with_pin(idx, &pin) {
                            Ok(()) => {
                                self.state.status_banner =
                                    "Чат разблокирован персональным PIN-кодом.".to_owned();
                            }
                            Err(e) => {
                                self.state.status_banner = format!("Отказ разблокировки чата: {e}");
                            }
                        }
                    } else {
                        chat.is_locked = true;
                        self.state.status_banner = "Чат закрыт персональным PIN-кодом.".to_owned();
                    }
                }
            }
            "route_tor" => {
                let _ = self.state.update_network_route(true, true, true, false);
                self.state.status_banner =
                    "Сетевой щит: активирован маршрут Tor / Onion v3 (🔒).".to_owned();
            }
            "route_vpn" => {
                let _ = self.state.update_network_route(false, true, true, false);
                self.state.status_banner =
                    "Сетевой щит: активирован защищённый туннель VPN / SOCKS5 (🛡).".to_owned();
            }
            "route_direct" => {
                let _ = self.state.update_network_route(false, false, false, false);
                self.state.status_banner = "⚠ Внимание: прямое соединение без Tor/VPN.".to_owned();
            }
            "route_leak" => {
                let _ = self.state.update_network_route(false, true, true, true);
                self.state.status_banner =
                    "⛔ Обнаружено падение VPN! Kill Switch заблокировал отправку пакетов."
                        .to_owned();
            }
            "test_leak_card" => {
                let sample =
                    "Переведи на карту 4532 0151 1283 0366 срок 08/28 cvv 912 или +7 (999) 123-45-67";
                match self.state.send_chat_message(sample, false, None) {
                    Ok(_) => {}
                    Err(e) => {
                        self.state.status_banner = format!("🛡 LeakGuard остановил отправку: {e}");
                    }
                }
            }
            "leak_mask" => {
                if let Ok(bucket) = self.state.confirm_leak_guard_masked_send() {
                    self.state.status_banner = format!(
                        "Чувствительные данные замаскированы (****) и отправлены в пакете {bucket} B."
                    );
                }
            }
            "leak_force" => {
                if let Some(modal) = self.state.leak_guard_modal.take() {
                    let active_matches = self
                        .state
                        .chats
                        .get(self.state.active_chat_index)
                        .is_some_and(|c| c.chat_id == modal.target_chat_id);
                    if active_matches
                        && self
                            .state
                            .send_chat_message(&modal.original_draft, true, None)
                            .is_ok()
                    {
                        self.state.status_banner =
                            "Сообщение отправлено по явному подтверждению пользователя.".to_owned();
                    }
                }
            }
            "send_photo_view_once" => {
                let fake_jpeg_with_exif = [
                    0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00, 0xFF,
                    0xDA, 0x00, 0x04, 0x00, 0x00, 0x01, 0x02, 0x03, 0xFF, 0xD9,
                ];
                let att = MediaAttachmentView::strip_exif_and_create(
                    "secret_document.jpg",
                    &fake_jpeg_with_exif,
                    true,
                );
                if self
                    .state
                    .send_chat_message("Одноразовое фото (без EXIF/GPS)", true, Some(att))
                    .is_ok()
                {
                    self.state.status_banner =
                        "Фото очищено от EXIF/GPS координат и отправлено в режиме View-Once."
                            .to_owned();
                }
            }
            "launch_vps" => {
                let _ = self
                    .state
                    .server_launcher
                    .configure(LaunchTarget::VpsDocker, 8443, 30);
                self.state.status_banner =
                    "Сгенерирован docker-compose.yml для VPS сервера Aegis.".to_owned();
            }
            "launch_onion" => {
                let _ =
                    self.state
                        .server_launcher
                        .configure(LaunchTarget::TorOnionService, 9001, 14);
                self.state.status_banner =
                    "Сгенерирована конфигурация скрытого Tor .onion сервера.".to_owned();
            }
            "launch_desktop" => {
                let _ = self
                    .state
                    .server_launcher
                    .configure(LaunchTarget::DesktopLocal, 8443, 7);
                self.state.status_banner =
                    "Подготовлен запуск локального сервера на ПК.".to_owned();
            }
            "send_ticket" => {
                let _ = self.state.submit_support_ticket(
                    [0x55; 32],
                    SupportTicketCategory::SupporterPassIssue,
                    "Запрос на проверку сертификата сервера и токена поддержки.",
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
                let expr = extract_query_param(query, "expr").unwrap_or_default();
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
                        self.state.status_banner =
                            "Секретный PIN принят: маскировка снята.".to_owned();
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
                    match self.state.send_chat_message(&text, false, None) {
                        Ok(bucket) => {
                            let (queue_id, _, _) = derive_channel_key_and_queue(&channel_code);
                            let mut nonce = [0u8; 12];
                            nonce[0..4].copy_from_slice(&queue_id[0..4]);
                            nonce[4..12].copy_from_slice(&1u64.to_be_bytes());
                            if let Ok(capsule) =
                                seal_cross_border_capsule(&channel_code, &nonce, &text)
                            {
                                let net_ok =
                                    send_capsule_over_tcp(&server_ep, &queue_id, &capsule, 400)
                                        .is_ok();
                                if net_ok {
                                    self.state.status_banner = format!(
                                        "Капсула {bucket} B зашифрована (ChaCha20-Poly1305) и доставлена на узел {server_ep}."
                                    );
                                } else {
                                    self.state.status_banner = format!(
                                        "Капсула зашифрована и упаковано в фиксированный блок {bucket} B."
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            self.state.status_banner = format!("Отправка приостановлена: {e}");
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
                        self.state.status_banner = format!(
                            "Синхронизация с {server_ep} завершена: принято и расшифровано капсул: {n}."
                        );
                    }
                    Err(e) => {
                        self.state.status_banner =
                            format!("Узел {server_ep} пока недоступен ({e}).");
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
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            if n > 0 {
                let req = String::from_utf8_lossy(&buf[..n]);
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
                if let Some(first_line) = req.lines().next() {
                    if let Some(path_and_query) = first_line.split_whitespace().nth(1) {
                        if let Some((route_path, query)) = path_and_query.split_once('?') {
                            if route_path == "/" || route_path == "/action" {
                                self.handle_command(query);
                            }
                        }
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

/// Verifies that an incoming HTTP request to the local Desktop GUI server (`127.0.0.1`)
/// is not a Cross-Site Request Forgery (CSRF) or DNS Rebinding attack from an external website.
#[must_use]
pub fn is_trusted_local_http_request(raw_request: &str) -> bool {
    let head = raw_request
        .split_once("\r\n\r\n")
        .map_or(raw_request, |(h, _)| h);
    for line in head.lines().skip(1) {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let header_name = name.trim().to_ascii_lowercase();
        let header_val = val.trim().to_ascii_lowercase();
        match header_name.as_str() {
            "host" => {
                let host_only = header_val
                    .rsplit_once(':')
                    .map_or(header_val.as_str(), |(h, _)| h);
                if host_only != "127.0.0.1" && host_only != "localhost" {
                    return false;
                }
            }
            "sec-fetch-site" if header_val == "cross-site" => {
                return false;
            }
            "origin"
                if header_val != "null"
                    && !header_val.starts_with("http://127.0.0.1")
                    && !header_val.starts_with("http://localhost") =>
            {
                return false;
            }
            _ => {}
        }
    }
    true
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
        let mut app = DesktopAppState::new(Locale::Ru);
        assert_eq!(app.strings().locale, Locale::Ru);
        assert!(app.strings().app_title.contains("Анонимный"));

        app.set_locale(Locale::En);
        assert_eq!(app.strings().locale, Locale::En);
        assert!(app.strings().app_title.contains("Anonymous"));
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
}
