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
}
