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
    /// Server public key fingerprint is all-zero or hostname is malformed.
    InvalidServerIdentity,
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
            Self::InvalidServerIdentity => {
                write!(f, "server public key or hostname is invalid")
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

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for &b in bytes {
        let _ = fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
    }
    out
}

fn is_safe_host(host: &str) -> bool {
    let trimmed = host.trim();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || trimmed.starts_with('-')
        || trimmed.ends_with('-')
        || trimmed.contains("..")
        || trimmed == "0.0.0.0"
        || trimmed == "255.255.255.255"
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return false;
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    for label in &labels {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    if labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit()))
        && (labels.len() != 4 || labels.iter().any(|l| l.parse::<u8>().is_err()))
    {
        return false;
    }
    true
}

fn validate_ttl_secs(ttl_secs: u64) -> Result<(), LauncherError> {
    if ttl_secs < 86_400 || ttl_secs > u64::from(MAX_QUEUE_TTL_DAYS) * 86_400 {
        let days = u16::try_from(ttl_secs / 86_400).unwrap_or(u16::MAX);
        return Err(LauncherError::InsecureQueueTtl { days });
    }
    Ok(())
}

/// Formats a canonical `aegis://server/<host>:<port>?fp=<hex_key>` invite URI with pinned server key (PLAN.md §6.2).
///
/// # Errors
/// Rejects all-zero server keys, port `0`, or unsafe host strings.
pub fn format_server_invite_uri(
    host: &str,
    port: u16,
    server_public_key: &[u8; 32],
) -> Result<String, LauncherError> {
    if port == 0 {
        return Err(LauncherError::InvalidBindPort);
    }
    if *server_public_key == [0u8; 32] || !is_safe_host(host) {
        return Err(LauncherError::InvalidServerIdentity);
    }
    let fp = hex_encode_32(server_public_key);
    Ok(format!("aegis://server/{}:{port}?fp={fp}", host.trim()))
}

/// Generates a reproducible, hardened `docker-compose.yml` for 1-click VPS deployment (PLAN.md §6.2).
/// Includes pinned server public key fingerprint, `read_only: true`, `no-new-privileges`, and `aegis://server/...` invite URI.
///
/// # Errors
/// Rejects invalid plans (`bind_port == 0`), all-zero server keys, or unsafe hostnames.
pub fn generate_docker_compose(
    plan: &LaunchPlan,
    public_host: &str,
    server_public_key: &[u8; 32],
) -> Result<String, LauncherError> {
    validate_ttl_secs(plan.queue_ttl_secs)?;
    let invite_uri = format_server_invite_uri(public_host, plan.bind_port, server_public_key)?;
    let fp = hex_encode_32(server_public_key);
    let port = plan.bind_port;
    let ttl = plan.queue_ttl_secs;

    Ok(format!(
        r#"# Aegis 1-Click Self-Hosted Zero-Knowledge Server (Static IP / Direct & Optional Tor)
# Server Key Fingerprint (Ed25519): {fp}
# Client Invite URI: {invite_uri}
services:
  aegis-server:
    image: ghcr.io/aegis-project/aegis-server:0.1.0
    container_name: aegis-server
    restart: unless-stopped
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    ports:
      - "0.0.0.0:{port}:{port}/tcp"
      - "0.0.0.0:{port}:{port}/udp"
    environment:
      AEGIS_BIND_HOST: "0.0.0.0"
      AEGIS_BIND_PORT: "{port}"
      AEGIS_QUEUE_TTL_SECS: "{ttl}"
      AEGIS_SERVER_PUBKEY_HEX: "{fp}"
      AEGIS_IP_LOGGING: "false"
      AEGIS_TURN_RELAY_ONLY: "true"
    volumes:
      - aegis_data:/var/lib/aegis
volumes:
  aegis_data:
"#
    ))
}

/// Generates a ready-to-paste Linux VPS `cloud-init.yaml` provisioning script (PLAN.md §6.2).
///
/// # Errors
/// Rejects invalid plans, all-zero server keys, or unsafe hostnames.
pub fn generate_cloud_init_script(
    plan: &LaunchPlan,
    public_host: &str,
    server_public_key: &[u8; 32],
) -> Result<String, LauncherError> {
    let compose = generate_docker_compose(plan, public_host, server_public_key)?;
    let invite_uri = format_server_invite_uri(public_host, plan.bind_port, server_public_key)?;
    let fp = hex_encode_32(server_public_key);
    let mut indented_compose = String::new();
    for line in compose.lines() {
        indented_compose.push_str("      ");
        indented_compose.push_str(line);
        indented_compose.push('\n');
    }

    Ok(format!(
        r#"#cloud-config
# Aegis Zero-Knowledge VPS Auto-Provisioning (cloud-init)
# Pinned Server Key: {fp}
# Invite URI: {invite_uri}
package_update: true
packages:
  - docker.io
  - docker-compose-v2
  - ufw
write_files:
  - path: /opt/aegis/docker-compose.yml
    permissions: "0600"
    content: |
{indented_compose}runcmd:
  - ufw default deny incoming
  - ufw allow {port}/tcp
  - ufw allow {port}/udp
  - ufw --force enable
  - systemctl enable --now docker
  - docker compose -f /opt/aegis/docker-compose.yml up -d
"#,
        port = plan.bind_port
    ))
}

/// Generates a hardened Tor `torrc` Hidden Service configuration so the server can run
/// as a `.onion` service without exposing any public IP address (PLAN.md §6.2, §14).
///
/// # Errors
/// Rejects port `0` or all-zero server keys.
pub fn generate_torrc_hidden_service(
    plan: &LaunchPlan,
    server_public_key: &[u8; 32],
) -> Result<String, LauncherError> {
    if plan.bind_port == 0 {
        return Err(LauncherError::InvalidBindPort);
    }
    validate_ttl_secs(plan.queue_ttl_secs)?;
    if *server_public_key == [0u8; 32] {
        return Err(LauncherError::InvalidServerIdentity);
    }
    let fp = hex_encode_32(server_public_key);
    let port = plan.bind_port;
    Ok(format!(
        r#"# Aegis Tor v3 Hidden Service Configuration (Onion-Only Mode)
# Pinned Server Key Fingerprint: {fp}
# Connect via: aegis://server/<generated-v3-address>.onion:{port}?fp={fp}
SocksPort 0
HiddenServiceDir /var/lib/tor/aegis_hidden_service/
HiddenServiceVersion 3
HiddenServicePort {port} 127.0.0.1:{port}
SafeLogging 1
"#
    ))
}

/// Generates a 1-click shell script to deploy an anonymous Aegis starter node on any VPS with a static IPv4 address (D-0019).
/// Clients can connect directly via `aegis://<STATIC_IP>:<port>` without needing Tor installed.
///
/// # Errors
/// Rejects invalid plans, non-routable IPv4 addresses (`0.0.0.0`, `127.x.x.x`, `255.255.255.255`), or all-zero server keys.
pub fn generate_static_ip_vps_script(
    plan: &LaunchPlan,
    static_ipv4: [u8; 4],
    server_public_key: &[u8; 32],
) -> Result<String, LauncherError> {
    if static_ipv4 == [0, 0, 0, 0]
        || static_ipv4[0] == 0
        || static_ipv4[0] == 127
        || static_ipv4 == [255, 255, 255, 255]
    {
        return Err(LauncherError::InvalidServerIdentity);
    }
    let ip_str = format!(
        "{}.{}.{}.{}",
        static_ipv4[0], static_ipv4[1], static_ipv4[2], static_ipv4[3]
    );
    let compose = generate_docker_compose(plan, &ip_str, server_public_key)?;
    let invite_uri = format_server_invite_uri(&ip_str, plan.bind_port, server_public_key)?;
    let port = plan.bind_port;
    Ok(format!(
        r#"#!/usr/bin/env bash
set -euo pipefail
# Aegis 1-Click Anonymous Static-IP Starter Server Installer (No Tor Required for Clients)
# Static IPv4: {ip_str}:{port}
# Direct Invite URI: {invite_uri}

mkdir -p /opt/aegis
cat <<'EOF' > /opt/aegis/docker-compose.yml
{compose}EOF

chmod 600 /opt/aegis/docker-compose.yml
if command -v ufw >/dev/null 2>&1; then
  ufw allow {port}/tcp
  ufw allow {port}/udp
fi
docker compose -f /opt/aegis/docker-compose.yml up -d
echo "=========================================================="
echo "Aegis Static-IP Node is LIVE on {ip_str}:{port} (Zero IP Logs)"
echo "Client Connection URI: {invite_uri}"
echo "=========================================================="
"#
    ))
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

    #[test]
    fn launcher_generates_docker_compose_cloud_init_and_torrc_with_pinned_key() {
        let plan = validate_launch_config(LaunchTarget::VpsDocker, 8443, 30).unwrap();
        let pubkey = [0xAB; 32];

        let compose = generate_docker_compose(&plan, "node1.aegis.example", &pubkey).unwrap();
        assert!(compose.contains("aegis://server/node1.aegis.example:8443?fp=abab"));
        assert!(compose.contains("AEGIS_IP_LOGGING: \"false\""));

        let cloud_init = generate_cloud_init_script(&plan, "node1.aegis.example", &pubkey).unwrap();
        assert!(cloud_init.starts_with("#cloud-config"));
        assert!(cloud_init.contains("/opt/aegis/docker-compose.yml"));

        let torrc = generate_torrc_hidden_service(&plan, &pubkey).unwrap();
        assert!(torrc.contains("HiddenServiceVersion 3"));
        assert!(torrc.contains("SafeLogging 1"));

        // All-zero key or shell-injection hostname must be rejected
        assert_eq!(
            generate_docker_compose(&plan, "node1.aegis.example", &[0u8; 32]),
            Err(LauncherError::InvalidServerIdentity)
        );
        assert_eq!(
            generate_docker_compose(&plan, "bad host; rm -rf /", &pubkey),
            Err(LauncherError::InvalidServerIdentity)
        );
        // B-0027: Reject `..` hostnames and plans with zero/excessive queue_ttl_secs
        assert_eq!(
            generate_docker_compose(&plan, "..", &pubkey),
            Err(LauncherError::InvalidServerIdentity)
        );
        let zero_ttl_plan = LaunchPlan {
            queue_ttl_secs: 0,
            ..plan
        };
        assert_eq!(
            generate_docker_compose(&zero_ttl_plan, "node1.aegis.example", &pubkey),
            Err(LauncherError::InsecureQueueTtl { days: 0 })
        );

        // B-0063: Static-IP VPS script generator & large u64 TTL overflow protection
        let static_script =
            generate_static_ip_vps_script(&plan, [185, 220, 101, 42], &pubkey).unwrap();
        assert!(static_script.contains("185.220.101.42:8443"));
        assert!(static_script.contains("AEGIS_BIND_HOST: \"0.0.0.0\""));
        assert_eq!(
            generate_static_ip_vps_script(&plan, [127, 0, 0, 1], &pubkey),
            Err(LauncherError::InvalidServerIdentity)
        );
        let huge_ttl_plan = LaunchPlan {
            queue_ttl_secs: 65_566 * 86_400,
            ..plan
        };
        assert_eq!(
            generate_docker_compose(&huge_ttl_plan, "node1.aegis.example", &pubkey),
            Err(LauncherError::InsecureQueueTtl { days: u16::MAX })
        );
    }
}
