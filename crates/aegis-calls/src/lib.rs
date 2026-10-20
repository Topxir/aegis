//! `aegis-calls` — Voice and video call configuration, E2EE media frame policy,
//! and mandatory TURN Relay-Only enforcement to prevent peer IP leaks (D-0008, PLAN.md §8.2).

use core::fmt;

/// Maximum allowed one-way latency target in milliseconds.
pub const MAX_CALL_LATENCY_MS: u16 = 5_000;

/// Minimum allowed adaptive bitrate ceiling in kbps.
pub const MIN_CALL_BITRATE_KBPS: u32 = 8;

/// Maximum allowed adaptive bitrate ceiling in kbps.
pub const MAX_CALL_BITRATE_KBPS: u32 = 50_000;

/// Call policy validation errors (fail-closed per AGENTS.md §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// End-to-end media encryption (`require_e2ee_media`) must be enabled.
    UnencryptedMediaForbidden,
    /// Direct peer-to-peer ICE candidates (`relay_only == false`) leak caller IP.
    DirectPeerCandidateRejected,
    /// Target latency must be within `1..=5_000` ms.
    InvalidLatencyTarget,
    /// Bitrate ceiling must be within `8..=50_000` kbps.
    InvalidBitrateCeiling,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnencryptedMediaForbidden => {
                write!(f, "end-to-end media encryption is mandatory")
            }
            Self::DirectPeerCandidateRejected => {
                write!(f, "direct P2P ICE candidates are forbidden; TURN relay-only is required")
            }
            Self::InvalidLatencyTarget => {
                write!(f, "call latency target must be within 1..={MAX_CALL_LATENCY_MS} ms")
            }
            Self::InvalidBitrateCeiling => write!(
                f,
                "call bitrate ceiling must be within {MIN_CALL_BITRATE_KBPS}..={MAX_CALL_BITRATE_KBPS} kbps"
            ),
        }
    }
}

impl std::error::Error for CallError {}

/// Call media and ICE/TURN routing configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallConfig {
    /// Forces all ICE candidates through the server's TURN relay (`relay-only: true` by default)
    /// so the remote peer never learns the caller's IP address (D-0008).
    pub relay_only: bool,
    /// Requires end-to-end media frame encryption (SFrame) on top of SRTP.
    pub require_e2ee_media: bool,
    /// Target maximum one-way latency in milliseconds (PLAN.md §8.2: 150 ms).
    pub target_max_latency_ms: u16,
    /// Adaptive bitrate ceiling in kbps.
    pub max_bitrate_kbps: u32,
}

impl Default for CallConfig {
    fn default() -> Self {
        Self {
            relay_only: true,
            require_e2ee_media: true,
            target_max_latency_ms: 150,
            max_bitrate_kbps: 1_500,
        }
    }
}

impl CallConfig {
    /// Validates the call configuration against mandatory privacy and E2EE invariants.
    ///
    /// # Errors
    /// Returns [`CallError`] if E2EE is disabled, `relay_only` is disabled, or latency/bitrate are out of range.
    pub fn validate(&self) -> Result<(), CallError> {
        if !self.require_e2ee_media {
            return Err(CallError::UnencryptedMediaForbidden);
        }
        if !self.relay_only {
            return Err(CallError::DirectPeerCandidateRejected);
        }
        if self.target_max_latency_ms == 0 || self.target_max_latency_ms > MAX_CALL_LATENCY_MS {
            return Err(CallError::InvalidLatencyTarget);
        }
        if !(MIN_CALL_BITRATE_KBPS..=MAX_CALL_BITRATE_KBPS).contains(&self.max_bitrate_kbps) {
            return Err(CallError::InvalidBitrateCeiling);
        }
        Ok(())
    }

    /// Returns `true` if the call configuration preserves IP anonymity, E2EE guarantees, and valid bounds.
    #[must_use]
    pub fn is_privacy_preserving(&self) -> bool {
        self.validate().is_ok()
    }
}

/// Validates a [`CallConfig`] before media session initialization.
///
/// # Errors
/// Fail-closed: returns [`CallError`] on any privacy or media parameter violation.
pub fn validate_call_config(config: &CallConfig) -> Result<(), CallError> {
    config.validate()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_call_config_enforces_relay_only_and_e2ee() {
        let cfg = CallConfig::default();
        assert!(cfg.relay_only);
        assert!(cfg.require_e2ee_media);
        assert_eq!(cfg.target_max_latency_ms, 150);
        assert!(cfg.is_privacy_preserving());
        assert_eq!(validate_call_config(&cfg), Ok(()));
    }

    #[test]
    fn b0014_call_config_rejects_unencrypted_direct_p2p_or_zero_bounds() {
        assert_eq!(
            validate_call_config(&CallConfig {
                require_e2ee_media: false,
                ..CallConfig::default()
            }),
            Err(CallError::UnencryptedMediaForbidden)
        );
        assert_eq!(
            validate_call_config(&CallConfig {
                relay_only: false,
                ..CallConfig::default()
            }),
            Err(CallError::DirectPeerCandidateRejected)
        );
        assert_eq!(
            validate_call_config(&CallConfig {
                target_max_latency_ms: 0,
                ..CallConfig::default()
            }),
            Err(CallError::InvalidLatencyTarget)
        );
        assert_eq!(
            validate_call_config(&CallConfig {
                max_bitrate_kbps: 0,
                ..CallConfig::default()
            }),
            Err(CallError::InvalidBitrateCeiling)
        );
    }
}
