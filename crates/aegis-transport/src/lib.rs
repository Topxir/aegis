//! `aegis-transport` — Client-server transport policy, Network Anonymity Shield (D-0008),
//! VPN/proxy/Tor route verification, and kill-switch enforcement.

/// Real-time network route anonymity classification (D-0008, PLAN.md §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkRouteStatus {
    /// No active connection.
    Offline,
    /// Direct connection without proxy/VPN; client IP is visible to the target server (⚠).
    DirectWarning,
    /// Traffic is routed through a verified VPN tunnel or SOCKS5 proxy (🛡).
    VpnOrProxyProtected,
    /// Traffic is routed through Tor or to a `.onion` hidden service (🔒 maximum anonymity).
    TorAnonymized,
}

/// Snapshot of local route configuration and server-observed echo metadata (D-0008).
/// Never queries third-party IP trackers; uses only the encrypted echo of the active Aegis server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProbe {
    /// Whether the target server is a `.onion` hidden service or local Tor SOCKS port is active.
    pub via_tor: bool,
    /// Whether a SOCKS5 proxy or local VPN tunnel interface (`tun`/`wg`/`utun`) is active.
    pub via_vpn_or_proxy: bool,
    /// Hash of the client's baseline ISP exit IP (if known locally) to detect tunnel drops.
    pub baseline_isp_ip_hash: Option<[u8; 32]>,
    /// Hash of the exit IP observed by the Aegis server's encrypted echo response.
    pub server_observed_ip_hash: Option<[u8; 32]>,
    /// Whether kill-switch mode is enabled (blocks traffic on DirectWarning).
    pub kill_switch_enabled: bool,
}

/// Result of evaluating the Network Anonymity Shield.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldEvaluation {
    /// Determined route protection status.
    pub status: NetworkRouteStatus,
    /// `true` if a configured VPN/proxy leaked the baseline ISP IP.
    pub tunnel_leak_detected: bool,
    /// `true` if outgoing traffic is permitted under the active kill-switch policy.
    pub traffic_permitted: bool,
}

/// Evaluates the current network anonymity status and kill-switch policy (D-0008).
#[must_use]
pub fn evaluate_network_shield(probe: &RouteProbe) -> ShieldEvaluation {
    // Fail-closed: missing or all-zero server-observed IP hash means no verified circuit / offline.
    let Some(observed) = probe.server_observed_ip_hash else {
        return ShieldEvaluation {
            status: NetworkRouteStatus::Offline,
            tunnel_leak_detected: false,
            traffic_permitted: false,
        };
    };

    if observed == [0u8; 32] {
        return ShieldEvaluation {
            status: NetworkRouteStatus::Offline,
            tunnel_leak_detected: false,
            traffic_permitted: false,
        };
    }

    // Fail-closed: all-zero baseline ISP hash is invalid and treated as a potential leak.
    if probe.baseline_isp_ip_hash == Some([0u8; 32]) {
        return ShieldEvaluation {
            status: NetworkRouteStatus::DirectWarning,
            tunnel_leak_detected: true,
            traffic_permitted: false,
        };
    }

    // Under kill-switch, a VPN/proxy/Tor tunnel without a known baseline ISP hash cannot verify non-leakage.
    if (probe.via_vpn_or_proxy || probe.via_tor)
        && probe.kill_switch_enabled
        && probe.baseline_isp_ip_hash.is_none()
    {
        return ShieldEvaluation {
            status: NetworkRouteStatus::DirectWarning,
            tunnel_leak_detected: false,
            traffic_permitted: false,
        };
    }

    let leak_detected =
        (probe.via_vpn_or_proxy || probe.via_tor) && probe.baseline_isp_ip_hash == Some(observed);

    if leak_detected {
        return ShieldEvaluation {
            status: NetworkRouteStatus::DirectWarning,
            tunnel_leak_detected: true,
            traffic_permitted: !probe.kill_switch_enabled,
        };
    }

    let status = if probe.via_tor {
        NetworkRouteStatus::TorAnonymized
    } else if probe.via_vpn_or_proxy {
        NetworkRouteStatus::VpnOrProxyProtected
    } else {
        NetworkRouteStatus::DirectWarning
    };

    let traffic_permitted = match status {
        NetworkRouteStatus::DirectWarning => !probe.kill_switch_enabled,
        NetworkRouteStatus::VpnOrProxyProtected | NetworkRouteStatus::TorAnonymized => true,
        NetworkRouteStatus::Offline => false,
    };

    ShieldEvaluation {
        status,
        tunnel_leak_detected: false,
        traffic_permitted,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn shield_detects_vpn_drop_leak_and_triggers_kill_switch() {
        let isp_hash = [0x11; 32];
        let vpn_hash = [0x22; 32];

        // Healthy VPN route
        let ok_eval = evaluate_network_shield(&RouteProbe {
            via_tor: false,
            via_vpn_or_proxy: true,
            baseline_isp_ip_hash: Some(isp_hash),
            server_observed_ip_hash: Some(vpn_hash),
            kill_switch_enabled: true,
        });
        assert_eq!(ok_eval.status, NetworkRouteStatus::VpnOrProxyProtected);
        assert!(!ok_eval.tunnel_leak_detected);
        assert!(ok_eval.traffic_permitted);

        // VPN dropped: server sees baseline ISP IP hash -> leak detected & blocked by kill switch
        let leak_eval = evaluate_network_shield(&RouteProbe {
            via_tor: false,
            via_vpn_or_proxy: true,
            baseline_isp_ip_hash: Some(isp_hash),
            server_observed_ip_hash: Some(isp_hash),
            kill_switch_enabled: true,
        });
        assert_eq!(leak_eval.status, NetworkRouteStatus::DirectWarning);
        assert!(leak_eval.tunnel_leak_detected);
        assert!(!leak_eval.traffic_permitted);
    }

    #[test]
    fn b0013_shield_blocks_missing_echo_zero_hashes_and_unverified_baseline() {
        // Missing server echo even when via_tor == true must be Offline & blocked
        let no_echo = evaluate_network_shield(&RouteProbe {
            via_tor: true,
            via_vpn_or_proxy: false,
            baseline_isp_ip_hash: Some([0x11; 32]),
            server_observed_ip_hash: None,
            kill_switch_enabled: true,
        });
        assert_eq!(no_echo.status, NetworkRouteStatus::Offline);
        assert!(!no_echo.traffic_permitted);

        // All-zero server observed hash must be rejected
        let zero_echo = evaluate_network_shield(&RouteProbe {
            via_tor: true,
            via_vpn_or_proxy: false,
            baseline_isp_ip_hash: Some([0x11; 32]),
            server_observed_ip_hash: Some([0u8; 32]),
            kill_switch_enabled: false,
        });
        assert_eq!(zero_echo.status, NetworkRouteStatus::Offline);
        assert!(!zero_echo.traffic_permitted);

        // Missing baseline ISP hash with kill_switch_enabled must block unverified tunnel
        let missing_baseline = evaluate_network_shield(&RouteProbe {
            via_tor: false,
            via_vpn_or_proxy: true,
            baseline_isp_ip_hash: None,
            server_observed_ip_hash: Some([0x22; 32]),
            kill_switch_enabled: true,
        });
        assert!(!missing_baseline.traffic_permitted);
    }
}
