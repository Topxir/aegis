//! `aegis-launcher` — Wizard for launching a self-hosted Aegis server from the client
//! (VPS Docker/cloud-init, Desktop local daemon, Tor `.onion` hidden service, Android LAN test).

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

/// Generated launch specification returned to the UI wizard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// Selected deployment target.
    pub target: LaunchTarget,
    /// Whether the UI must display a persistent battery/NAT reliability warning (PLAN.md §2, §6.2).
    pub requires_ephemeral_warning: bool,
    /// Default queue TTL in seconds inherited from `aegis-server`.
    pub queue_ttl_secs: u64,
}

/// Builds a validated server launch plan for the requested target.
#[must_use]
pub fn build_launch_plan(target: LaunchTarget) -> LaunchPlan {
    LaunchPlan {
        target,
        requires_ephemeral_warning: matches!(target, LaunchTarget::AndroidTestOnly),
        queue_ttl_secs: aegis_server::DEFAULT_QUEUE_TTL_SECS,
    }
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
}
