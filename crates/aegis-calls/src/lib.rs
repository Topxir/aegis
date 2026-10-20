//! `aegis-calls` — Voice and video call configuration, E2EE media frame policy,
//! and mandatory TURN Relay-Only enforcement to prevent peer IP leaks (D-0008, PLAN.md §8.2).

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
    /// Returns `true` if the call configuration preserves IP anonymity and E2EE guarantees.
    #[must_use]
    pub fn is_privacy_preserving(&self) -> bool {
        self.relay_only && self.require_e2ee_media
    }
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
    }
}
