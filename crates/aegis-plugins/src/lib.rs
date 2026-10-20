//! `aegis-plugins` — Declarative themes and WASM plugin sandbox manifest verifier (PLAN.md §10).
//! Plugins NEVER gain access to cryptographic keys or raw storage (`AGENTS.md §2.6`).

use core::fmt;

/// Manifest permissions that a sandboxed WASM plugin may request (PLAN.md §10).
/// Key access is structurally unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManifest {
    /// Plugin identifier (`3..=64` lowercase ASCII alphanumeric/hyphen slug).
    pub plugin_id: String,
    /// Whether this is a pure declarative theme (no executable WASM code).
    pub declarative_theme_only: bool,
    /// Scoped chat IDs the plugin is permitted to read (empty by default).
    pub allowed_read_chats: Vec<[u8; 16]>,
    /// Whether outbound network via proxy is requested (disabled by default per PLAN.md §10).
    pub allow_proxied_network: bool,
    /// Whether the plugin attempted to request forbidden key/storage access in raw metadata.
    pub requested_forbidden_key_access: bool,
}

/// Plugin sandbox validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginError {
    /// Plugin identifier is not a valid `3..=64` lowercase ASCII slug (prevents path traversal).
    InvalidPluginIdentifier,
    /// Plugin attempted to request access to cryptographic keys or raw database.
    ForbiddenKeyAccessRequested,
    /// Declarative theme cannot request chat read or network permissions.
    ThemeCannotRequestRuntimePermissions,
    /// WASM plugin cannot simultaneously read chat plaintext and make outbound network requests.
    ExfiltrationRiskChatAndNetworkCombined,
    /// `allowed_read_chats` contains an all-zero chat ID (`[0u8; 16]`) or duplicate entries.
    InvalidChatScope,
    /// Theme color token is not a valid `#RRGGBB` hex color or theme metadata is invalid.
    InvalidThemeColorToken,
    /// Bot or Matrix/XMPP bridge configuration violates sandbox isolation.
    InvalidBotBridgeConfig,
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPluginIdentifier => {
                write!(
                    f,
                    "plugin identifier must be a valid 3..=64 lowercase ASCII slug"
                )
            }
            Self::ForbiddenKeyAccessRequested => {
                write!(f, "plugins are strictly forbidden from accessing keys")
            }
            Self::ThemeCannotRequestRuntimePermissions => {
                write!(f, "declarative themes cannot request runtime permissions")
            }
            Self::ExfiltrationRiskChatAndNetworkCombined => write!(
                f,
                "plugin cannot combine chat read permissions with outbound network access"
            ),
            Self::InvalidChatScope => {
                write!(
                    f,
                    "allowed_read_chats contains all-zero or duplicate chat IDs"
                )
            }
            Self::InvalidThemeColorToken => {
                write!(f, "theme color token must be a valid #RRGGBB hex string")
            }
            Self::InvalidBotBridgeConfig => {
                write!(
                    f,
                    "bot or bridge configuration violates sandbox isolation rules"
                )
            }
        }
    }
}

impl std::error::Error for PluginError {}

fn is_valid_plugin_slug(id: &str) -> bool {
    let len = id.len();
    if !(3..=64).contains(&len) || id.starts_with('-') || id.ends_with('-') || id.contains("--") {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Validates a plugin manifest before loading into the sandbox (AGENTS.md §2.6, PLAN.md §10).
///
/// # Errors
/// Fail-closed: rejects invalid plugin slugs, key access, impure themes, combined chat+network
/// exfiltration vectors, and all-zero/duplicate chat scopes.
pub fn validate_manifest(manifest: &PluginManifest) -> Result<(), PluginError> {
    if !is_valid_plugin_slug(&manifest.plugin_id) {
        return Err(PluginError::InvalidPluginIdentifier);
    }
    if manifest.requested_forbidden_key_access {
        return Err(PluginError::ForbiddenKeyAccessRequested);
    }
    if manifest.declarative_theme_only
        && (!manifest.allowed_read_chats.is_empty() || manifest.allow_proxied_network)
    {
        return Err(PluginError::ThemeCannotRequestRuntimePermissions);
    }
    if !manifest.allowed_read_chats.is_empty() && manifest.allow_proxied_network {
        return Err(PluginError::ExfiltrationRiskChatAndNetworkCombined);
    }
    for (idx, chat_id) in manifest.allowed_read_chats.iter().enumerate() {
        if *chat_id == [0u8; 16] || manifest.allowed_read_chats[..idx].contains(chat_id) {
            return Err(PluginError::InvalidChatScope);
        }
    }
    Ok(())
}

/// Built-in Theme Store presets (PLAN.md §10, §14), including `CalculatorStealth` app disguise mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltInThemes {
    /// Default deep-slate security theme (`#0B0F17`).
    ObsidianDark,
    /// Terminal emerald-on-black theme (`#050B08`).
    EmeraldMatrix,
    /// High-contrast daylight theme (`#F8FAFC`).
    ArcticLight,
    /// Neon cyan/magenta night theme (`#0D071A`).
    CyberpunkNeon,
    /// Stealth calculator disguise theme (`CalculatorStealth`, PLAN.md §14).
    CalculatorStealth,
}

/// Pure declarative UI theme package (color tokens + stealth disguise flag, zero executable code per PLAN.md §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemePack {
    /// Theme slug identifier.
    pub theme_id: String,
    /// Human-readable display title.
    pub display_name: String,
    /// Primary background hex token (`#RRGGBB`).
    pub bg_primary_hex: String,
    /// Secondary panel/surface hex token (`#RRGGBB`).
    pub bg_surface_hex: String,
    /// Accent color hex token (`#RRGGBB`).
    pub accent_hex: String,
    /// Primary foreground text hex token (`#RRGGBB`).
    pub text_primary_hex: String,
    /// Whether this theme enables the stealth calculator app icon/title disguise (PLAN.md §14).
    pub stealth_calculator_disguise: bool,
}

fn is_valid_hex_color(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(u8::is_ascii_hexdigit)
}

fn is_valid_bridge_host(host: &str) -> bool {
    let trimmed = host.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 253
        && !trimmed.starts_with('.')
        && !trimmed.ends_with('.')
        && !trimmed.starts_with('-')
        && !trimmed.ends_with('-')
        && !trimmed.contains("..")
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

impl ThemePack {
    /// Returns the declarative [`ThemePack`] for a built-in theme preset.
    #[must_use]
    pub fn from_builtin(preset: BuiltInThemes) -> Self {
        match preset {
            BuiltInThemes::ObsidianDark => Self {
                theme_id: "obsidian-dark".to_owned(),
                display_name: "Obsidian Dark".to_owned(),
                bg_primary_hex: "#0B0F17".to_owned(),
                bg_surface_hex: "#131B2E".to_owned(),
                accent_hex: "#10B981".to_owned(),
                text_primary_hex: "#E2E8F0".to_owned(),
                stealth_calculator_disguise: false,
            },
            BuiltInThemes::EmeraldMatrix => Self {
                theme_id: "emerald-matrix".to_owned(),
                display_name: "Emerald Matrix".to_owned(),
                bg_primary_hex: "#050B08".to_owned(),
                bg_surface_hex: "#0A1912".to_owned(),
                accent_hex: "#00FF9C".to_owned(),
                text_primary_hex: "#D1FAE5".to_owned(),
                stealth_calculator_disguise: false,
            },
            BuiltInThemes::ArcticLight => Self {
                theme_id: "arctic-light".to_owned(),
                display_name: "Arctic Light".to_owned(),
                bg_primary_hex: "#F8FAFC".to_owned(),
                bg_surface_hex: "#FFFFFF".to_owned(),
                accent_hex: "#0284C7".to_owned(),
                text_primary_hex: "#0F172A".to_owned(),
                stealth_calculator_disguise: false,
            },
            BuiltInThemes::CyberpunkNeon => Self {
                theme_id: "cyberpunk-neon".to_owned(),
                display_name: "Cyberpunk Neon".to_owned(),
                bg_primary_hex: "#0D071A".to_owned(),
                bg_surface_hex: "#1B0F33".to_owned(),
                accent_hex: "#F43F5E".to_owned(),
                text_primary_hex: "#F5D0FE".to_owned(),
                stealth_calculator_disguise: false,
            },
            BuiltInThemes::CalculatorStealth => Self {
                theme_id: "calculator-stealth".to_owned(),
                display_name: "SciCalc Pro (Stealth Disguise)".to_owned(),
                bg_primary_hex: "#1C1C1E".to_owned(),
                bg_surface_hex: "#2C2C2E".to_owned(),
                accent_hex: "#FF9F0A".to_owned(),
                text_primary_hex: "#FFFFFF".to_owned(),
                stealth_calculator_disguise: true,
            },
        }
    }

    /// Returns all 5 built-in themes for the Theme Store catalog.
    #[must_use]
    pub fn builtin_catalog() -> Vec<Self> {
        vec![
            Self::from_builtin(BuiltInThemes::ObsidianDark),
            Self::from_builtin(BuiltInThemes::EmeraldMatrix),
            Self::from_builtin(BuiltInThemes::ArcticLight),
            Self::from_builtin(BuiltInThemes::CyberpunkNeon),
            Self::from_builtin(BuiltInThemes::CalculatorStealth),
        ]
    }

    /// Validates that the theme is purely declarative and all color tokens are valid `#RRGGBB` values.
    ///
    /// # Errors
    /// Returns [`PluginError`] if the slug or any hex color token is invalid.
    pub fn validate(&self) -> Result<PluginManifest, PluginError> {
        let name = self.display_name.trim();
        if name.is_empty()
            || name.len() > 64
            || name.chars().any(char::is_control)
            || !is_valid_hex_color(&self.bg_primary_hex)
            || !is_valid_hex_color(&self.bg_surface_hex)
            || !is_valid_hex_color(&self.accent_hex)
            || !is_valid_hex_color(&self.text_primary_hex)
        {
            return Err(PluginError::InvalidThemeColorToken);
        }
        let manifest = PluginManifest {
            plugin_id: self.theme_id.clone(),
            declarative_theme_only: true,
            allowed_read_chats: Vec::new(),
            allow_proxied_network: false,
            requested_forbidden_key_access: false,
        };
        validate_manifest(&manifest)?;
        Ok(manifest)
    }
}

/// Supported external bridge protocols for sandboxed bot/bridge plugins (PLAN.md §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotBridgeConfig {
    /// Local-only offline bot (auto-responder, translator, local notes assistant) scoped to specific chats.
    LocalSandboxedBot {
        /// Scoped chat IDs the local bot is permitted to read/respond in.
        scoped_chat_ids: Vec<[u8; 16]>,
    },
    /// Matrix federation bridge running through a dedicated one-way relay queue (no raw chat read scope!).
    MatrixBridge {
        /// Matrix homeserver URL via SOCKS5/Tor proxy.
        homeserver_host: String,
        /// Dedicated isolated bridge queue ID.
        isolated_bridge_queue_id: [u8; 32],
    },
    /// XMPP (Jabber) OMEMO bridge running through a dedicated one-way relay queue.
    XmppBridge {
        /// XMPP server domain via SOCKS5/Tor proxy.
        xmpp_domain: String,
        /// Dedicated isolated bridge queue ID.
        isolated_bridge_queue_id: [u8; 32],
    },
}

/// Sandboxed Bot & Matrix/XMPP Bridge descriptor enforcing permission manifests (PLAN.md §10, §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotBridgeDescriptor {
    /// Plugin manifest governing sandbox capabilities.
    pub manifest: PluginManifest,
    /// Bot or Matrix/XMPP bridge configuration.
    pub config: BotBridgeConfig,
}

impl BotBridgeDescriptor {
    /// Validates both the [`PluginManifest`] and the [`BotBridgeConfig`] to guarantee that
    /// networked Matrix/XMPP bridges only access their isolated bridge queue and never combine
    /// arbitrary chat-read scopes with outbound network access.
    ///
    /// # Errors
    /// Fail-closed: returns [`PluginError`] on any manifest or isolation violation.
    pub fn validate(&self) -> Result<(), PluginError> {
        validate_manifest(&self.manifest)?;
        if self.manifest.declarative_theme_only {
            return Err(PluginError::InvalidBotBridgeConfig);
        }
        match &self.config {
            BotBridgeConfig::LocalSandboxedBot { scoped_chat_ids } => {
                if self.manifest.allow_proxied_network
                    || scoped_chat_ids.is_empty()
                    || scoped_chat_ids != &self.manifest.allowed_read_chats
                {
                    return Err(PluginError::InvalidBotBridgeConfig);
                }
                Ok(())
            }
            BotBridgeConfig::MatrixBridge {
                homeserver_host,
                isolated_bridge_queue_id,
            } => {
                if !self.manifest.allowed_read_chats.is_empty()
                    || !self.manifest.allow_proxied_network
                    || *isolated_bridge_queue_id == [0u8; 32]
                    || !is_valid_bridge_host(homeserver_host)
                {
                    return Err(PluginError::InvalidBotBridgeConfig);
                }
                Ok(())
            }
            BotBridgeConfig::XmppBridge {
                xmpp_domain,
                isolated_bridge_queue_id,
            } => {
                if !self.manifest.allowed_read_chats.is_empty()
                    || !self.manifest.allow_proxied_network
                    || *isolated_bridge_queue_id == [0u8; 32]
                    || !is_valid_bridge_host(xmpp_domain)
                {
                    return Err(PluginError::InvalidBotBridgeConfig);
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn plugin_manifest_rejects_key_access_and_impure_themes() {
        let forbidden = PluginManifest {
            plugin_id: "bad-plugin".to_owned(),
            declarative_theme_only: false,
            allowed_read_chats: vec![],
            allow_proxied_network: false,
            requested_forbidden_key_access: true,
        };
        assert_eq!(
            validate_manifest(&forbidden),
            Err(PluginError::ForbiddenKeyAccessRequested)
        );

        let clean_theme = PluginManifest {
            plugin_id: "obsidian-dark".to_owned(),
            declarative_theme_only: true,
            allowed_read_chats: vec![],
            allow_proxied_network: false,
            requested_forbidden_key_access: false,
        };
        assert!(validate_manifest(&clean_theme).is_ok());
    }

    #[test]
    fn b0018_plugin_manifest_blocks_path_traversal_exfiltration_and_invalid_chat_ids() {
        // Path traversal in plugin_id must be rejected
        let traversal = PluginManifest {
            plugin_id: "../../etc/shadow".to_owned(),
            declarative_theme_only: true,
            allowed_read_chats: vec![],
            allow_proxied_network: false,
            requested_forbidden_key_access: false,
        };
        assert_eq!(
            validate_manifest(&traversal),
            Err(PluginError::InvalidPluginIdentifier)
        );

        // Combining chat read access and proxied network access is an exfiltration vector
        let exfil = PluginManifest {
            plugin_id: "sneaky-bot".to_owned(),
            declarative_theme_only: false,
            allowed_read_chats: vec![[0x11; 16]],
            allow_proxied_network: true,
            requested_forbidden_key_access: false,
        };
        assert_eq!(
            validate_manifest(&exfil),
            Err(PluginError::ExfiltrationRiskChatAndNetworkCombined)
        );

        // All-zero or duplicate chat IDs must be rejected
        let zero_chat = PluginManifest {
            plugin_id: "local-helper".to_owned(),
            declarative_theme_only: false,
            allowed_read_chats: vec![[0u8; 16]],
            allow_proxied_network: false,
            requested_forbidden_key_access: false,
        };
        assert_eq!(
            validate_manifest(&zero_chat),
            Err(PluginError::InvalidChatScope)
        );
    }

    #[test]
    fn builtin_theme_store_and_bot_bridge_sandbox_descriptors_validate() {
        let catalog = ThemePack::builtin_catalog();
        assert_eq!(catalog.len(), 5);
        for theme in &catalog {
            let manifest = theme.validate().expect("built-in theme must be valid");
            assert!(manifest.declarative_theme_only);
        }
        assert!(
            ThemePack::from_builtin(BuiltInThemes::CalculatorStealth).stealth_calculator_disguise
        );

        // Local sandboxed bot (chat-scoped, no network)
        let local_bot = BotBridgeDescriptor {
            manifest: PluginManifest {
                plugin_id: "offline-translator-bot".to_owned(),
                declarative_theme_only: false,
                allowed_read_chats: vec![[0x22; 16]],
                allow_proxied_network: false,
                requested_forbidden_key_access: false,
            },
            config: BotBridgeConfig::LocalSandboxedBot {
                scoped_chat_ids: vec![[0x22; 16]],
            },
        };
        assert!(local_bot.validate().is_ok());

        // Matrix bridge (isolated bridge queue + proxied network, zero arbitrary chat-read scope)
        let matrix_bridge = BotBridgeDescriptor {
            manifest: PluginManifest {
                plugin_id: "matrix-relay-bridge".to_owned(),
                declarative_theme_only: false,
                allowed_read_chats: vec![],
                allow_proxied_network: true,
                requested_forbidden_key_access: false,
            },
            config: BotBridgeConfig::MatrixBridge {
                homeserver_host: "matrix.org".to_owned(),
                isolated_bridge_queue_id: [0x77; 32],
            },
        };
        assert!(matrix_bridge.validate().is_ok());

        // B-0028: Reject malicious bridge hostnames and control chars in theme display_name
        let bad_bridge = BotBridgeDescriptor {
            manifest: matrix_bridge.manifest.clone(),
            config: BotBridgeConfig::MatrixBridge {
                homeserver_host: "evil.org/../../ssrf".to_owned(),
                isolated_bridge_queue_id: [0x77; 32],
            },
        };
        assert_eq!(
            bad_bridge.validate(),
            Err(PluginError::InvalidBotBridgeConfig)
        );
    }
}
