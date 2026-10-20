//! `aegis-ffi` — Unified FFI/UniFFI boundary for UI platforms (`AGENTS.md §4`).
//! UI layers (`aegis-ui-android`, `aegis-ui-desktop`, `aegis-ui-ios`) communicate exclusively
//! through this crate and never touch cryptographic internals or keys directly (`AGENTS.md §2.6`).

pub use aegis_identity::{
    generate_nickname, validate_nickname, validate_password, NicknameError, PasswordPolicyError,
};
pub use aegis_protocol::{redact_leaks, scan_message_for_leaks, LeakKind, LeakWarning};
pub use aegis_transport::{
    evaluate_network_shield, NetworkRouteStatus, RouteProbe, ShieldEvaluation,
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
    }
}
