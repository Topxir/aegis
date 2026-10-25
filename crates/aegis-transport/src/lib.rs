//! `aegis-transport` — Client-server transport policy, Network Anonymity Shield (D-0008),
//! VPN/proxy/Tor route verification, kill-switch enforcement, cover traffic scheduler (PLAN.md §14),
//! censorship-resistant proxy/bridge profiles, and live server migration (PLAN.md §14).

use aegis_crypto::{hmac_sha256, sha256};
use aegis_protocol::{
    hex_decode_bytes, hex_encode_bytes, pad_frame, ProtocolError, PADDING_BUCKETS,
};
use core::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Size in bytes of indistinguishable dummy cover traffic frames (smallest bucket: `256` bytes).
pub const COVER_TRAFFIC_FRAME_BYTES: usize = PADDING_BUCKETS[0];

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
            traffic_permitted: false,
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

/// Transport configuration and routing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Hostname or bridge endpoint is empty or contains invalid characters.
    InvalidEndpoint,
    /// Port `0` is not allowed for network connections.
    InvalidPort,
    /// Cover traffic interval bounds are invalid (`min_interval_ms == 0` or `min > max`).
    InvalidCoverTrafficInterval,
    /// Server migration notice has invalid or identical source/target servers or empty signature.
    InvalidMigrationNotice,
    /// Underlying protocol framing error.
    Protocol(ProtocolError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => write!(f, "transport endpoint host or bridge is invalid"),
            Self::InvalidPort => write!(f, "transport port must be non-zero"),
            Self::InvalidCoverTrafficInterval => {
                write!(f, "cover traffic interval bounds are invalid")
            }
            Self::InvalidMigrationNotice => {
                write!(f, "server migration notice is invalid or unverified")
            }
            Self::Protocol(e) => write!(f, "protocol framing error: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Censorship-resistant proxy, Tor, and bridge routing profiles (PLAN.md §7.3, §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportProfile {
    /// Direct TLS 1.3 / QUIC connection with server key pinning.
    DirectTls,
    /// Standard SOCKS5 proxy (e.g., local VPN/SSH/Shadowsocks SOCKS5 listener).
    Socks5Proxy {
        /// Proxy hostname or IP literal.
        host: String,
        /// Proxy listening port.
        port: u16,
    },
    /// Embedded Arti Tor client running in-process.
    TorArtiEmbedded,
    /// External Orbot / Tor daemon on local SOCKS5 port (default `9050` or `9150`).
    TorOrbotLocal {
        /// Local Tor SOCKS port.
        socks_port: u16,
    },
    /// Censorship-resistant obfuscated bridge (QUIC/TLS mimicry + padding).
    ObfuscatedBridge {
        /// Bridge endpoint (`host:port`).
        bridge_endpoint: String,
        /// Pinned 32-byte bridge public key fingerprint.
        bridge_public_key: [u8; 32],
    },
}

fn is_public_routable_ipv4(octets: [u8; 4]) -> bool {
    let [a, b, c, _] = octets;
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 224)
}

fn is_valid_transport_host(host: &str) -> bool {
    if host != host.trim()
        || host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.starts_with('-')
        || host.ends_with('-')
        || host.contains("..")
        || host == "0.0.0.0"
        || host == "255.255.255.255"
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || (label.len() >= 2 && label.as_bytes()[..2].eq_ignore_ascii_case(b"0x"))
        {
            return false;
        }
    }
    if labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit())) {
        if labels.len() != 4 {
            return false;
        }
        for l in &labels {
            if (l.len() > 1 && l.starts_with('0')) || l.parse::<u8>().is_err() {
                return false;
            }
        }
    }
    true
}

fn is_valid_remote_public_host(host: &str) -> bool {
    if !is_valid_transport_host(host) || host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let last_label = labels[labels.len() - 1];
    if matches!(
        last_label.to_ascii_lowercase().as_str(),
        "localhost" | "local" | "internal" | "lan" | "home" | "localdomain" | "arpa" | "invalid"
    ) {
        return false;
    }
    if labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit())) {
        let mut octets = [0u8; 4];
        for (idx, l) in labels.iter().enumerate() {
            let Ok(v) = l.parse::<u8>() else {
                return false;
            };
            octets[idx] = v;
        }
        return is_public_routable_ipv4(octets);
    }
    last_label.len() >= 2 && last_label.chars().all(|c| c.is_ascii_alphabetic())
}

impl TransportProfile {
    /// Validates the transport profile parameters.
    ///
    /// # Errors
    /// Fail-closed: rejects port `0`, untrimmed or oversized hostnames (`> 253` bytes),
    /// control/whitespace characters, or all-zero `bridge_public_key`.
    pub fn validate(&self) -> Result<(), TransportError> {
        match self {
            Self::DirectTls | Self::TorArtiEmbedded => Ok(()),
            Self::Socks5Proxy { host, port } => {
                if *port == 0 {
                    return Err(TransportError::InvalidPort);
                }
                if !is_valid_transport_host(host) {
                    return Err(TransportError::InvalidEndpoint);
                }
                Ok(())
            }
            Self::TorOrbotLocal { socks_port } => {
                if *socks_port == 0 {
                    return Err(TransportError::InvalidPort);
                }
                Ok(())
            }
            Self::ObfuscatedBridge {
                bridge_endpoint,
                bridge_public_key,
            } => {
                if *bridge_public_key == [0u8; 32] || bridge_endpoint != bridge_endpoint.trim() {
                    return Err(TransportError::InvalidEndpoint);
                }
                let Some((host, port_str)) = bridge_endpoint.rsplit_once(':') else {
                    return Err(TransportError::InvalidEndpoint);
                };
                if !is_valid_remote_public_host(host) {
                    return Err(TransportError::InvalidEndpoint);
                }
                let port: u16 = port_str.parse().map_err(|_| TransportError::InvalidPort)?;
                if port == 0 {
                    return Err(TransportError::InvalidPort);
                }
                Ok(())
            }
        }
    }
}

/// Formats a canonical direct static-IPv4 server endpoint (`aegis://<a>.<b>.<c>.<d>:<port>`) that works without Tor (D-0019).
///
/// # Errors
/// Rejects port `0` or non-routable / private / loopback IPv4 addresses.
pub fn format_static_ipv4_endpoint(ipv4: [u8; 4], port: u16) -> Result<String, TransportError> {
    if port == 0 {
        return Err(TransportError::InvalidPort);
    }
    if !is_public_routable_ipv4(ipv4) {
        return Err(TransportError::InvalidEndpoint);
    }
    Ok(format!(
        "aegis://{}.{}.{}.{}:{port}",
        ipv4[0], ipv4[1], ipv4[2], ipv4[3]
    ))
}

/// Stream isolation circuit tag preventing server/Tor correlation between `OPAQUE AccountVault` sync
/// and anonymous one-way message queues (`docs/contracts/aegis-transport.md` Guarantee #3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolatedCircuitTag {
    /// Dedicated circuit for `OPAQUE AccountVault` authentication and sync.
    VaultSyncCircuit,
    /// Dedicated circuit for polling an anonymous incoming queue.
    QueueReadCircuit([u8; 16]),
    /// Dedicated circuit for posting a Sealed Sender packet to a contact's queue.
    DirectWriteCircuit([u8; 16]),
}

/// Derives an unlinkable 32-byte SOCKS5/Tor stream isolation token for `circuit` so
/// `AccountVault` operations and anonymous queue operations never share a network circuit.
#[must_use]
pub fn derive_circuit_isolation_token(
    circuit: &IsolatedCircuitTag,
    session_seed: &[u8; 32],
) -> [u8; 32] {
    let mut info = [0u8; 17];
    match circuit {
        IsolatedCircuitTag::VaultSyncCircuit => {
            info[0] = 0x01;
        }
        IsolatedCircuitTag::QueueReadCircuit(id) => {
            info[0] = 0x02;
            info[1..17].copy_from_slice(id);
        }
        IsolatedCircuitTag::DirectWriteCircuit(id) => {
            info[0] = 0x03;
            info[1..17].copy_from_slice(id);
        }
    }
    hmac_sha256(session_seed, &info)
}

/// Full client proxy and censorship-bypass configuration (D-0008, D-0019, PLAN.md §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Selected transport routing profile.
    pub profile: TransportProfile,
    /// Whether kill-switch blocks all traffic if the proxy/Tor circuit drops.
    pub kill_switch_enabled: bool,
    /// Pinned 32-byte Ed25519/X25519 key of the target Aegis server.
    pub pinned_server_key: [u8; 32],
}

impl ProxyConfig {
    /// Creates a direct TLS/QUIC starter configuration (`kill_switch_enabled: false`) so any user
    /// can connect out-of-the-box to a static-IP starter server without requiring Tor or VPN (D-0019).
    ///
    /// # Errors
    /// Rejects an all-zero `pinned_server_key`.
    pub fn direct_starter(pinned_server_key: [u8; 32]) -> Result<Self, TransportError> {
        let cfg = Self {
            profile: TransportProfile::DirectTls,
            kill_switch_enabled: false,
            pinned_server_key,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates the proxy configuration before establishing a connection.
    ///
    /// # Errors
    /// Fail-closed: rejects all-zero `pinned_server_key`, port `0`, or empty/malformed hostnames.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.pinned_server_key == [0u8; 32] {
            return Err(TransportError::InvalidEndpoint);
        }
        self.profile.validate()
    }

    /// Builds a [`RouteProbe`] from the active proxy configuration and IP echo hashes.
    #[must_use]
    pub fn to_route_probe(
        &self,
        baseline_isp_ip_hash: Option<[u8; 32]>,
        server_observed_ip_hash: Option<[u8; 32]>,
    ) -> RouteProbe {
        let via_tor = matches!(
            self.profile,
            TransportProfile::TorArtiEmbedded | TransportProfile::TorOrbotLocal { .. }
        );
        let via_vpn_or_proxy = matches!(
            self.profile,
            TransportProfile::Socks5Proxy { .. } | TransportProfile::ObfuscatedBridge { .. }
        );
        RouteProbe {
            via_tor,
            via_vpn_or_proxy,
            baseline_isp_ip_hash,
            server_observed_ip_hash,
            kill_switch_enabled: self.kill_switch_enabled,
        }
    }
}

/// Configuration for background cover traffic (фоновый шумовой трафик, PLAN.md §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverTrafficConfig {
    /// Whether dummy cover traffic generation is enabled.
    pub enabled: bool,
    /// Minimum adaptive interval between dummy frames in milliseconds.
    pub min_interval_ms: u64,
    /// Maximum adaptive interval between dummy frames in milliseconds.
    pub max_interval_ms: u64,
    /// Idle threshold in milliseconds after a real message before dummy frames resume.
    pub idle_grace_ms: u64,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_interval_ms: 2_000,
            max_interval_ms: 10_000,
            idle_grace_ms: 2_000,
        }
    }
}

impl CoverTrafficConfig {
    /// Validates the cover traffic interval bounds.
    ///
    /// # Errors
    /// Returns [`TransportError::InvalidCoverTrafficInterval`] if `min_interval_ms == 0`, `min > max`,
    /// `max_interval_ms > 3_600_000`, or `idle_grace_ms > 3_600_000`.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.min_interval_ms == 0
            || self.min_interval_ms > self.max_interval_ms
            || self.max_interval_ms > 3_600_000
            || self.idle_grace_ms > 3_600_000
        {
            return Err(TransportError::InvalidCoverTrafficInterval);
        }
        Ok(())
    }
}

/// Scheduler that emits indistinguishable `256`-byte padded dummy frames when the user is idle,
/// hiding real message send times from network observers (PLAN.md §2, §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverTrafficScheduler {
    config: CoverTrafficConfig,
    last_activity_ms: u64,
    emitted_count: u64,
    schedule_step: u64,
}

impl CoverTrafficScheduler {
    /// Creates a cover traffic scheduler using the default safe intervals.
    #[must_use]
    pub fn default_scheduler() -> Self {
        Self {
            config: CoverTrafficConfig::default(),
            last_activity_ms: 0,
            emitted_count: 0,
            schedule_step: 0,
        }
    }

    /// Creates a validated cover traffic scheduler.
    ///
    /// # Errors
    /// Returns [`TransportError::InvalidCoverTrafficInterval`] if `config` bounds are invalid.
    pub fn new(config: CoverTrafficConfig) -> Result<Self, TransportError> {
        config.validate()?;
        Ok(Self {
            config,
            last_activity_ms: 0,
            emitted_count: 0,
            schedule_step: 0,
        })
    }

    /// Records that a real user message was sent at `now_ms`, resetting the idle timer and advancing the schedule step.
    pub fn record_real_message(&mut self, now_ms: u64) {
        if now_ms > self.last_activity_ms {
            self.last_activity_ms = now_ms;
        }
        self.schedule_step = self.schedule_step.saturating_add(1);
    }

    /// Computes the next deterministic adaptive delay in milliseconds using a cryptographic SHA-256 PRF over `jitter_seed` and `schedule_step`.
    #[must_use]
    pub fn next_delay_ms(&self, jitter_seed: u64) -> u64 {
        let span = self
            .config
            .max_interval_ms
            .saturating_sub(self.config.min_interval_ms);
        if span == 0 {
            return self.config.min_interval_ms;
        }
        let mut preimage = [0u8; 32];
        preimage[0..8].copy_from_slice(b"AegisCov");
        preimage[8..16].copy_from_slice(&jitter_seed.to_le_bytes());
        preimage[16..24].copy_from_slice(&self.emitted_count.to_be_bytes());
        preimage[24..32].copy_from_slice(&self.schedule_step.to_be_bytes());
        let digest = sha256(&preimage);
        let mut word = [0u8; 8];
        word.copy_from_slice(&digest[0..8]);
        let mixed = u64::from_le_bytes(word);
        self.config
            .min_interval_ms
            .saturating_add(mixed % (span.saturating_add(1)))
    }

    /// Checks whether a dummy cover frame should be emitted at `now_ms`, and if so returns
    /// a `256`-byte high-entropy dummy frame with zero trailing `0x00` bytes.
    pub fn poll_cover_frame(&mut self, now_ms: u64, jitter_seed: u64) -> Option<Vec<u8>> {
        if !self.config.enabled {
            return None;
        }
        let required_wait = self
            .config
            .idle_grace_ms
            .max(self.next_delay_ms(jitter_seed));
        let next_ready_ms = self.last_activity_ms.checked_add(required_wait)?;
        if now_ms < next_ready_ms {
            return None;
        }

        self.last_activity_ms = now_ms;
        self.emitted_count = self.emitted_count.saturating_add(1);
        self.schedule_step = self.schedule_step.saturating_add(1);

        // Fill all 254 payload bytes of the 256-byte bucket with cryptographic HMAC-SHA256 stream blocks
        // so there are zero trailing 0x00 bytes and zero linear byte relationships on the wire.
        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&jitter_seed.to_le_bytes());
        key[8..16].copy_from_slice(&self.emitted_count.to_be_bytes());
        key[16..32].copy_from_slice(b"AegisCoverChaff1");

        let mut chaff = [0u8; COVER_TRAFFIC_FRAME_BYTES - 2];
        let mut offset = 0usize;
        let mut block_idx = 0u8;
        while offset < chaff.len() {
            let block = hmac_sha256(&key, &[block_idx]);
            let take = (chaff.len() - offset).min(32);
            chaff[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
            block_idx = block_idx.wrapping_add(1);
        }
        pad_frame(&chaff).ok()
    }

    /// Returns the total number of dummy cover frames emitted by this scheduler.
    #[must_use]
    pub fn emitted_count(&self) -> u64 {
        self.emitted_count
    }
}

/// Signed notice allowing live migration of a contact's unidirectional queue to a new
/// federation server without losing the contact relationship (PLAN.md §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerMigrationNotice {
    /// Previous server's Ed25519 public key.
    pub old_server_public_key: [u8; 32],
    /// New server's Ed25519 public key.
    pub new_server_public_key: [u8; 32],
    /// New server's connection URI (e.g. `aegis://server/...` or `.onion` endpoint).
    pub new_server_endpoint: String,
    /// Fresh unidirectional queue ID allocated for this contact on the new server.
    pub new_write_queue_id: [u8; 32],
    /// Contact's identity signature authenticating the migration notice.
    pub contact_signature_verified: bool,
}

impl ServerMigrationNotice {
    /// Creates and validates a live server migration notice.
    ///
    /// # Errors
    /// Fail-closed: rejects unverified signatures, all-zero keys/queue IDs, identical old/new server keys,
    /// or empty endpoints.
    pub fn new_verified(
        old_server_public_key: [u8; 32],
        new_server_public_key: [u8; 32],
        new_server_endpoint: String,
        new_write_queue_id: [u8; 32],
        contact_signature_verified: bool,
    ) -> Result<Self, TransportError> {
        let notice = Self {
            old_server_public_key,
            new_server_public_key,
            new_server_endpoint,
            new_write_queue_id,
            contact_signature_verified,
        };
        notice.validate()?;
        Ok(notice)
    }

    /// Returns the new write queue identifier on the migrated server.
    #[must_use]
    pub fn new_write_queue_id(&self) -> [u8; 32] {
        self.new_write_queue_id
    }

    /// Validates the migration notice invariants.
    ///
    /// # Errors
    /// Returns [`TransportError::InvalidMigrationNotice`] if any key/queue is zero, old == new server,
    /// endpoint is invalid, or `contact_signature_verified` is false.
    pub fn validate(&self) -> Result<(), TransportError> {
        if !self.contact_signature_verified
            || self.old_server_public_key == [0u8; 32]
            || self.new_server_public_key == [0u8; 32]
            || self.old_server_public_key == self.new_server_public_key
            || self.new_write_queue_id == [0u8; 32]
        {
            return Err(TransportError::InvalidMigrationNotice);
        }
        let ep = &self.new_server_endpoint;
        if ep != ep.trim()
            || !ep.starts_with("aegis://")
            || ep.len() <= "aegis://".len()
            || ep.len() > 256
            || ep.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(TransportError::InvalidMigrationNotice);
        }
        let rest = &ep["aegis://".len()..];
        let host_port = rest.strip_prefix("server/").unwrap_or(rest);
        let Some((host, port_str)) = host_port.rsplit_once(':') else {
            return Err(TransportError::InvalidMigrationNotice);
        };
        if !is_valid_remote_public_host(host) {
            return Err(TransportError::InvalidMigrationNotice);
        }
        let Ok(port) = port_str.parse::<u16>() else {
            return Err(TransportError::InvalidMigrationNotice);
        };
        if port == 0 {
            return Err(TransportError::InvalidMigrationNotice);
        }
        Ok(())
    }
}

fn open_timed_tcp_stream(host_port: &str, timeout_ms: u64) -> Result<TcpStream, TransportError> {
    let clean = host_port
        .trim()
        .strip_prefix("aegis://")
        .unwrap_or(host_port.trim());
    let clean = clean.strip_prefix("server/").unwrap_or(clean);
    let dur = Duration::from_millis(timeout_ms.clamp(100, 30_000));
    let addr: SocketAddr = clean
        .to_socket_addrs()
        .map_err(|_| TransportError::InvalidEndpoint)?
        .next()
        .ok_or(TransportError::InvalidEndpoint)?;
    let stream =
        TcpStream::connect_timeout(&addr, dur).map_err(|_| TransportError::InvalidEndpoint)?;
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));
    Ok(stream)
}

/// Establishes a TCP tunnel through an RFC 1928 SOCKS5h proxy (e.g., local Tor daemon `127.0.0.1:9050`
/// or Orbot `127.0.0.1:9150`) using remote hostname resolution (`ATYP = 0x03`) so `.onion` addresses
/// and cross-country endpoints resolve on the remote exit without local DNS leaks.
///
/// # Errors
/// Returns [`TransportError`] if the proxy connection or SOCKS5 handshake fails.
pub fn connect_via_socks5h(
    proxy_host_port: &str,
    target_host: &str,
    target_port: u16,
    timeout_ms: u64,
) -> Result<TcpStream, TransportError> {
    if target_port == 0 {
        return Err(TransportError::InvalidPort);
    }
    let host_bytes = target_host.trim().as_bytes();
    if host_bytes.is_empty() || host_bytes.len() > 253 {
        return Err(TransportError::InvalidEndpoint);
    }
    let mut stream = open_timed_tcp_stream(proxy_host_port, timeout_ms)?;
    // 1. Greeting: SOCKS v5, 1 auth method (0x00 = No Authentication)
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|_| TransportError::InvalidEndpoint)?;
    let mut greeting_resp = [0u8; 2];
    stream
        .read_exact(&mut greeting_resp)
        .map_err(|_| TransportError::InvalidEndpoint)?;
    if greeting_resp != [0x05, 0x00] {
        return Err(TransportError::InvalidEndpoint);
    }

    // 2. CONNECT request with ATYP = 0x03 (Domain name resolved remotely by SOCKS5h/Tor)
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&req)
        .map_err(|_| TransportError::InvalidEndpoint)?;

    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .map_err(|_| TransportError::InvalidEndpoint)?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(TransportError::InvalidEndpoint);
    }
    let skip_len = match hdr[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            stream
                .read_exact(&mut l)
                .map_err(|_| TransportError::InvalidEndpoint)?;
            usize::from(l[0]) + 2
        }
        _ => return Err(TransportError::InvalidEndpoint),
    };
    let mut drain = vec![0u8; skip_len];
    stream
        .read_exact(&mut drain)
        .map_err(|_| TransportError::InvalidEndpoint)?;
    Ok(stream)
}

/// Sends a fixed-size (`256`..`16384` B) encrypted capsule over TCP/HTTP to a remote `aegis-serverd` node
/// anywhere in the world (`POST /api/v1/queue/send?queue=<hex>`).
///
/// # Errors
/// Returns [`TransportError`] if `queue_id` is all-zero, `padded_frame` is not a valid bucket size,
/// or the remote server rejects the request.
pub fn send_capsule_over_tcp(
    server_host_port: &str,
    queue_id: &[u8; 32],
    padded_frame: &[u8],
    timeout_ms: u64,
) -> Result<(), TransportError> {
    if *queue_id == [0u8; 32] {
        return Err(TransportError::InvalidEndpoint);
    }
    if !PADDING_BUCKETS.contains(&padded_frame.len()) {
        return Err(TransportError::Protocol(
            ProtocolError::MalformedPaddedFrame,
        ));
    }
    let mut stream = open_timed_tcp_stream(server_host_port, timeout_ms)?;
    let queue_hex = hex_encode_bytes(queue_id);
    let body_hex = hex_encode_bytes(padded_frame);
    let req = format!(
        "POST /api/v1/queue/send?queue={queue_hex} HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_hex}",
        body_hex.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|_| TransportError::InvalidEndpoint)?;
    let _ = stream.flush();

    let mut resp = Vec::with_capacity(512);
    let _ = stream.read_to_end(&mut resp);
    let text = core::str::from_utf8(&resp).map_err(|_| TransportError::InvalidEndpoint)?;
    if text.starts_with("HTTP/1.1 200") && text.contains("\"queued\"") {
        Ok(())
    } else {
        Err(TransportError::InvalidEndpoint)
    }
}

/// Polls and drains all pending encrypted capsules for `queue_id` over TCP/HTTP from a remote `aegis-serverd` node
/// (`POST /api/v1/queue/poll?queue=<hex>`).
///
/// # Errors
/// Returns [`TransportError`] if `queue_id` is all-zero, the connection fails, or any frame violates bucket padding.
pub fn poll_capsules_over_tcp(
    server_host_port: &str,
    queue_id: &[u8; 32],
    timeout_ms: u64,
) -> Result<Vec<Vec<u8>>, TransportError> {
    if *queue_id == [0u8; 32] {
        return Err(TransportError::InvalidEndpoint);
    }
    let mut stream = open_timed_tcp_stream(server_host_port, timeout_ms)?;
    let queue_hex = hex_encode_bytes(queue_id);
    let req = format!(
        "POST /api/v1/queue/poll?queue={queue_hex} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|_| TransportError::InvalidEndpoint)?;
    let _ = stream.flush();

    let mut resp = Vec::with_capacity(4096);
    let _ = stream.read_to_end(&mut resp);
    let text = core::str::from_utf8(&resp).map_err(|_| TransportError::InvalidEndpoint)?;
    if !text.starts_with("HTTP/1.1 200") {
        return Err(TransportError::InvalidEndpoint);
    }
    let Some((_, body)) = text.split_once("\r\n\r\n") else {
        return Err(TransportError::InvalidEndpoint);
    };
    let Some(arr_start) = body.find("\"frames_hex\":[") else {
        return Ok(Vec::new());
    };
    let after = &body[arr_start + "\"frames_hex\":[".len()..];
    let Some(arr_end) = after.find(']') else {
        return Err(TransportError::InvalidEndpoint);
    };
    let inner_list = after[..arr_end].trim();
    if inner_list.is_empty() {
        return Ok(Vec::new());
    }
    let mut frames = Vec::new();
    for item in inner_list.split(',') {
        let hex_str = item.trim().trim_matches('"');
        if hex_str.is_empty() {
            continue;
        }
        let raw = hex_decode_bytes(hex_str).map_err(TransportError::Protocol)?;
        if !PADDING_BUCKETS.contains(&raw.len()) {
            return Err(TransportError::Protocol(
                ProtocolError::MalformedPaddedFrame,
            ));
        }
        frames.push(raw);
    }
    Ok(frames)
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

    #[test]
    fn cover_traffic_scheduler_emits_256_byte_padded_frames_when_idle() {
        let cfg = CoverTrafficConfig::default();
        let mut sched = CoverTrafficScheduler::new(cfg).unwrap();

        sched.record_real_message(1_000);
        // Immediate poll at 1_500ms (still within idle_grace_ms / min_interval_ms) emits nothing
        assert!(sched.poll_cover_frame(1_500, 42).is_none());

        // Poll after max_interval_ms emits a 256-byte padded dummy frame
        let frame = sched
            .poll_cover_frame(15_000, 42)
            .expect("must emit cover frame when idle");
        assert_eq!(frame.len(), COVER_TRAFFIC_FRAME_BYTES);
        assert_eq!(sched.emitted_count(), 1);
    }

    #[test]
    fn proxy_config_and_transport_profiles_validate_and_map_to_shield() {
        let tor_cfg = ProxyConfig {
            profile: TransportProfile::TorArtiEmbedded,
            kill_switch_enabled: true,
            pinned_server_key: [0xAA; 32],
        };
        assert!(tor_cfg.validate().is_ok());
        let probe = tor_cfg.to_route_probe(Some([0x11; 32]), Some([0x99; 32]));
        let eval = evaluate_network_shield(&probe);
        assert_eq!(eval.status, NetworkRouteStatus::TorAnonymized);
        assert!(eval.traffic_permitted);

        let bridge_cfg = ProxyConfig {
            profile: TransportProfile::ObfuscatedBridge {
                bridge_endpoint: "bridge.aegis.example:8443".to_owned(),
                bridge_public_key: [0xBB; 32],
            },
            kill_switch_enabled: true,
            pinned_server_key: [0xAA; 32],
        };
        assert!(bridge_cfg.validate().is_ok());

        let bad_socks = ProxyConfig {
            profile: TransportProfile::Socks5Proxy {
                host: "127.0.0.1".to_owned(),
                port: 0,
            },
            kill_switch_enabled: true,
            pinned_server_key: [0xAA; 32],
        };
        assert_eq!(bad_socks.validate(), Err(TransportError::InvalidPort));
    }

    #[test]
    fn live_server_migration_notice_validates_keys_and_signature() {
        let notice = ServerMigrationNotice::new_verified(
            [0x11; 32],
            [0x22; 32],
            "aegis://relay-eu.aegis.example:8443".to_owned(),
            [0x33; 32],
            true,
        )
        .unwrap();
        assert_eq!(notice.new_write_queue_id(), [0x33; 32]);

        // Unverified signature or identical server keys must fail closed
        assert_eq!(
            ServerMigrationNotice::new_verified(
                [0x11; 32],
                [0x11; 32],
                "aegis://same.example:8443".to_owned(),
                [0x33; 32],
                true,
            ),
            Err(TransportError::InvalidMigrationNotice)
        );
        assert_eq!(
            ServerMigrationNotice::new_verified(
                [0x11; 32],
                [0x22; 32],
                "aegis://relay-eu.aegis.example:8443".to_owned(),
                [0x33; 32],
                false,
            ),
            Err(TransportError::InvalidMigrationNotice)
        );
    }

    #[test]
    fn b0044_b0045_transport_rejects_untrimmed_oversized_bridge_non_aegis_uri_and_excessive_idle_grace(
    ) {
        // B-0044: Untrimmed Socks5Proxy host and ObfuscatedBridge endpoint rejected
        assert_eq!(
            TransportProfile::Socks5Proxy {
                host: " 127.0.0.1 ".to_owned(),
                port: 9050,
            }
            .validate(),
            Err(TransportError::InvalidEndpoint)
        );
        let long_host = format!("{}:8443", "a".repeat(254));
        assert_eq!(
            TransportProfile::ObfuscatedBridge {
                bridge_endpoint: long_host,
                bridge_public_key: [0xBB; 32],
            }
            .validate(),
            Err(TransportError::InvalidEndpoint)
        );

        // B-0044: ServerMigrationNotice requires trimmed `aegis://` URI
        assert_eq!(
            ServerMigrationNotice::new_verified(
                [0x11; 32],
                [0x22; 32],
                "https://relay.example:8443".to_owned(),
                [0x33; 32],
                true,
            ),
            Err(TransportError::InvalidMigrationNotice)
        );
        assert_eq!(
            ServerMigrationNotice::new_verified(
                [0x11; 32],
                [0x22; 32],
                " aegis://relay.example:8443 ".to_owned(),
                [0x33; 32],
                true,
            ),
            Err(TransportError::InvalidMigrationNotice)
        );

        // B-0045: CoverTrafficConfig rejects idle_grace_ms > 3_600_000
        let bad_cover = CoverTrafficConfig {
            enabled: true,
            min_interval_ms: 2_000,
            max_interval_ms: 10_000,
            idle_grace_ms: 3_600_001,
        };
        assert_eq!(
            bad_cover.validate(),
            Err(TransportError::InvalidCoverTrafficInterval)
        );
    }

    #[test]
    fn b0072_cover_traffic_high_entropy_circuit_stream_isolation_and_ssrf_rejection() {
        // 1. Cover traffic fills all 254 payload bytes with HMAC-SHA256 stream (no trailing 0x00 run, no linear invariant)
        let mut sched = CoverTrafficScheduler::default_scheduler();
        let frame1 = sched.poll_cover_frame(20_000, 99).unwrap();
        let frame2 = sched.poll_cover_frame(40_000, 99).unwrap();
        assert_eq!(frame1.len(), 256);
        assert_ne!(frame1, frame2);
        assert!(frame1[34..256].iter().any(|&b| b != 0));
        assert_ne!(frame1[2 + 8], frame1[2].rotate_left(1));

        // 2. Stream isolation produces distinct unlinkable circuit tokens for VaultSync vs QueueRead vs DirectWrite
        let seed = [0x42u8; 32];
        let t_vault = derive_circuit_isolation_token(&IsolatedCircuitTag::VaultSyncCircuit, &seed);
        let t_read = derive_circuit_isolation_token(
            &IsolatedCircuitTag::QueueReadCircuit([0x11; 16]),
            &seed,
        );
        let t_write = derive_circuit_isolation_token(
            &IsolatedCircuitTag::DirectWriteCircuit([0x11; 16]),
            &seed,
        );
        assert_ne!(t_vault, t_read);
        assert_ne!(t_read, t_write);
        assert_ne!(t_vault, t_write);

        // 3. Confirmed tunnel leak ALWAYS blocks traffic even if kill_switch_enabled is false
        let leak_no_ks = evaluate_network_shield(&RouteProbe {
            via_tor: true,
            via_vpn_or_proxy: false,
            baseline_isp_ip_hash: Some([0x11; 32]),
            server_observed_ip_hash: Some([0x11; 32]),
            kill_switch_enabled: false,
        });
        assert!(leak_no_ks.tunnel_leak_detected);
        assert!(!leak_no_ks.traffic_permitted);

        // 4. SSRF private/loopback/metadata IPs rejected in format_static_ipv4_endpoint, ObfuscatedBridge, and ServerMigrationNotice
        for bad_ip in [
            [10, 0, 0, 1],
            [172, 16, 0, 1],
            [192, 168, 1, 1],
            [169, 254, 169, 254],
            [100, 64, 0, 1],
            [224, 0, 0, 1],
        ] {
            assert_eq!(
                format_static_ipv4_endpoint(bad_ip, 8443),
                Err(TransportError::InvalidEndpoint)
            );
        }
        assert_eq!(
            ServerMigrationNotice::new_verified(
                [0x11; 32],
                [0x22; 32],
                "aegis://169.254.169.254:8443".to_owned(),
                [0x33; 32],
                true,
            ),
            Err(TransportError::InvalidMigrationNotice)
        );
    }
}
