//! `aegis-launcher` — Wizard for launching a self-hosted Aegis server from the client
//! (VPS Docker/cloud-init, Desktop local daemon, Tor `.onion` hidden service, Android LAN test).

use core::fmt;

/// Default TLS/QUIC bind port for a self-hosted Aegis server.
pub const DEFAULT_BIND_PORT: u16 = 8_443;

/// Maximum allowed message queue retention in days.
pub const MAX_QUEUE_TTL_DAYS: u16 = 365;

/// Target deployment mode for a user-launched server (PLAN.md §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchTarget {
    /// Generates reproducible `docker-compose.yml` / cloud-init bundle for a VPS.
    VpsDocker,
    /// Runs local server binary on Desktop.
    DesktopLocal,
    /// Runs server behind a Tor `.onion` hidden service (IP never exposed).
    TorOnionService,
    /// Temporary local-network test mode on Android (warns user about battery/NAT limits).
    AndroidTestOnly,
}

/// Errors when validating a user-supplied server launch configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LauncherError {
    /// Port `0` is not a valid deterministic bind port for server deployment.
    InvalidBindPort,
    /// Queue TTL in days must be in `1..=365`.
    InsecureQueueTtl { days: u16 },
}

impl fmt::Display for LauncherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBindPort => write!(f, "server bind port must be non-zero"),
            Self::InsecureQueueTtl { days } => {
                write!(
                    f,
                    "queue TTL must be between 1 and {MAX_QUEUE_TTL_DAYS} days, got {days}"
                )
            }
        }
    }
}

impl std::error::Error for LauncherError {}

/// Generated launch specification returned to the UI wizard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// Selected deployment target.
    pub target: LaunchTarget,
    /// Configured listening port.
    pub bind_port: u16,
    /// Whether the UI must display a persistent battery/NAT reliability warning (PLAN.md §2, §6.2).
    pub requires_ephemeral_warning: bool,
    /// Queue TTL in seconds.
    pub queue_ttl_secs: u64,
}

/// Type alias for FFI and contract consumers.
pub type ServerLaunchPlan = LaunchPlan;

/// Builds a default server launch plan for the requested target.
#[must_use]
pub fn build_launch_plan(target: LaunchTarget) -> LaunchPlan {
    LaunchPlan {
        target,
        bind_port: DEFAULT_BIND_PORT,
        requires_ephemeral_warning: matches!(target, LaunchTarget::AndroidTestOnly),
        queue_ttl_secs: aegis_server::DEFAULT_QUEUE_TTL_SECS,
    }
}

/// Validates explicit launch wizard parameters (`bind_port` and `queue_ttl_days`) and builds a [`ServerLaunchPlan`].
///
/// # Errors
/// Returns [`LauncherError::InvalidBindPort`] if `bind_port == 0`, or [`LauncherError::InsecureQueueTtl`]
/// if `queue_ttl_days == 0 || queue_ttl_days > 365`.
pub fn validate_launch_config(
    target: LaunchTarget,
    bind_port: u16,
    queue_ttl_days: u16,
) -> Result<ServerLaunchPlan, LauncherError> {
    if bind_port == 0 {
        return Err(LauncherError::InvalidBindPort);
    }
    if queue_ttl_days == 0 || queue_ttl_days > MAX_QUEUE_TTL_DAYS {
        return Err(LauncherError::InsecureQueueTtl {
            days: queue_ttl_days,
        });
    }
    Ok(LaunchPlan {
        target,
        bind_port,
        requires_ephemeral_warning: matches!(target, LaunchTarget::AndroidTestOnly),
        queue_ttl_secs: u64::from(queue_ttl_days) * 24 * 60 * 60,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn android_target_sets_ephemeral_warning() {
        let plan = build_launch_plan(LaunchTarget::AndroidTestOnly);
        assert!(plan.requires_ephemeral_warning);

        let onion = build_launch_plan(LaunchTarget::TorOnionService);
        assert!(!onion.requires_ephemeral_warning);
    }

    #[test]
    fn b0017_validate_launch_config_rejects_port_zero_and_invalid_ttl() {
        assert_eq!(
            validate_launch_config(LaunchTarget::VpsDocker, 0, 30),
            Err(LauncherError::InvalidBindPort)
        );
        assert_eq!(
            validate_launch_config(LaunchTarget::VpsDocker, 8443, 0),
            Err(LauncherError::InsecureQueueTtl { days: 0 })
        );
        assert_eq!(
            validate_launch_config(LaunchTarget::VpsDocker, 8443, 366),
            Err(LauncherError::InsecureQueueTtl { days: 366 })
        );
        let ok_plan = validate_launch_config(LaunchTarget::TorOnionService, 9001, 14).unwrap();
        assert_eq!(ok_plan.bind_port, 9001);
        assert_eq!(ok_plan.queue_ttl_secs, 14 * 24 * 60 * 60);
    }
}
