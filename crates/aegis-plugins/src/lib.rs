//! `aegis-plugins` — Declarative themes and WASM plugin sandbox manifest verifier (PLAN.md §10).
//! Plugins NEVER gain access to cryptographic keys or raw storage (`AGENTS.md §2.6`).

use core::fmt;

/// Manifest permissions that a sandboxed WASM plugin may request (PLAN.md §10).
/// Key access is structurally unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManifest {
    /// Plugin identifier.
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
    /// Plugin identifier is empty or contains invalid characters.
    InvalidPluginIdentifier,
    /// Plugin attempted to request access to cryptographic keys or raw database.
    ForbiddenKeyAccessRequested,
    /// Declarative theme cannot request chat read or network permissions.
    ThemeCannotRequestRuntimePermissions,
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPluginIdentifier => write!(f, "plugin identifier must not be empty"),
            Self::ForbiddenKeyAccessRequested => {
                write!(f, "plugins are strictly forbidden from accessing keys")
            }
            Self::ThemeCannotRequestRuntimePermissions => {
                write!(f, "declarative themes cannot request runtime permissions")
            }
        }
    }
}

impl std::error::Error for PluginError {}

/// Validates a plugin manifest before loading into the sandbox (AGENTS.md §2.6, PLAN.md §10).
///
/// # Errors
/// Fail-closed: rejects any manifest with an empty ID, requesting key access, or invalid theme permissions.
pub fn validate_manifest(manifest: &PluginManifest) -> Result<(), PluginError> {
    if manifest.plugin_id.trim().is_empty() {
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
}
