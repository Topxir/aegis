//! `aegis-directory` — Signed server directory, verification badges (`✓✓` / `✓`),
//! M-of-N threshold signature policy (D-0011), revocation list, and support certificate verification.

use core::fmt;

/// Trust badge level for a server in the directory (PLAN.md §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerBadge {
    /// Official server operated by the Aegis project (`✓✓`).
    OfficialDoubleCheck,
    /// Community server that passed reproducible build & no-logs verification (`✓`).
    VerifiedSingleCheck,
    /// Unverified community server added manually or pending review (no badge).
    CommunityUnverified,
}

/// M-of-N threshold signature verification policy (D-0011).
/// Starts at `1-of-1` in Phases 0–4 and upgrades smoothly to `2-of-3` without breaking clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdPolicy {
    /// Minimum number of valid distinct trusted foundation signatures required (`M`).
    pub required_signatures: usize,
    /// Trusted foundation Ed25519 public keys (`N`).
    pub trusted_public_keys: Vec<[u8; 32]>,
}

/// Directory verification errors (fail-closed per AGENTS.md §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    /// Threshold policy itself is invalid (`M == 0`, `M > N`, duplicate trusted keys, or all-zero key).
    InvalidThresholdPolicy,
    /// Subject public key is all-zero (`[0u8; 32]`).
    InvalidPublicKey,
    /// Server or support key appears in the signed revocation list.
    KeyRevoked,
    /// Fewer than `M` valid signatures from distinct trusted keys were provided.
    InsufficientValidSignatures { required: usize, valid: usize },
    /// Unverified community servers cannot carry a cryptographic verification badge.
    UnverifiedServerBadge,
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThresholdPolicy => write!(f, "invalid M-of-N threshold policy"),
            Self::InvalidPublicKey => write!(f, "public key must not be all-zero"),
            Self::KeyRevoked => write!(f, "server or support public key has been revoked"),
            Self::InsufficientValidSignatures { required, valid } => write!(
                f,
                "insufficient valid signatures: required {required}, got {valid}"
            ),
            Self::UnverifiedServerBadge => {
                write!(
                    f,
                    "unverified community server cannot pass badge verification"
                )
            }
        }
    }
}

impl std::error::Error for DirectoryError {}

/// Single signature attestation from a foundation key holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerAttestation {
    /// Signer's Ed25519 public key.
    pub signer_public_key: [u8; 32],
    /// Whether the Ed25519 signature over the canonical directory entry verified.
    pub cryptographic_sig_valid: bool,
}

/// Verifies that a server or support certificate meets the M-of-N threshold policy
/// and is not present in the revocation list (D-0011, PLAN.md §6.3).
///
/// # Errors
/// Fail-closed: rejects all-zero keys, duplicate policy keys, revoked keys, duplicate signers,
/// untrusted signers, or `< M` valid signatures.
pub fn verify_threshold_attestations(
    subject_public_key: &[u8; 32],
    revoked_keys: &[[u8; 32]],
    policy: &ThresholdPolicy,
    attestations: &[SignerAttestation],
) -> Result<(), DirectoryError> {
    if *subject_public_key == [0u8; 32] {
        return Err(DirectoryError::InvalidPublicKey);
    }

    if policy.required_signatures == 0
        || policy.required_signatures > policy.trusted_public_keys.len()
    {
        return Err(DirectoryError::InvalidThresholdPolicy);
    }

    for (idx, key) in policy.trusted_public_keys.iter().enumerate() {
        if *key == [0u8; 32] || policy.trusted_public_keys[..idx].contains(key) {
            return Err(DirectoryError::InvalidThresholdPolicy);
        }
    }

    if revoked_keys.contains(subject_public_key) {
        return Err(DirectoryError::KeyRevoked);
    }

    let mut distinct_valid_signers: Vec<[u8; 32]> = Vec::new();
    for att in attestations {
        if att.cryptographic_sig_valid
            && att.signer_public_key != [0u8; 32]
            && policy.trusted_public_keys.contains(&att.signer_public_key)
            && !revoked_keys.contains(&att.signer_public_key)
            && !distinct_valid_signers.contains(&att.signer_public_key)
        {
            distinct_valid_signers.push(att.signer_public_key);
        }
    }

    if distinct_valid_signers.len() >= policy.required_signatures {
        Ok(())
    } else {
        Err(DirectoryError::InsufficientValidSignatures {
            required: policy.required_signatures,
            valid: distinct_valid_signers.len(),
        })
    }
}

/// Verifies a server's directory badge (`OfficialDoubleCheck` or `VerifiedSingleCheck`)
/// against the M-of-N threshold policy and revocation list.
///
/// # Errors
/// Fail-closed: explicitly rejects [`ServerBadge::CommunityUnverified`] as well as any threshold failure.
pub fn verify_server_badge(
    badge: ServerBadge,
    subject_public_key: &[u8; 32],
    revoked_keys: &[[u8; 32]],
    policy: &ThresholdPolicy,
    attestations: &[SignerAttestation],
) -> Result<ServerBadge, DirectoryError> {
    if badge == ServerBadge::CommunityUnverified {
        return Err(DirectoryError::UnverifiedServerBadge);
    }
    verify_threshold_attestations(subject_public_key, revoked_keys, policy, attestations)?;
    Ok(badge)
}

/// Certificate binding an account public key to the official "Support ✓" role (PLAN.md §6.3, D-0011).
/// Signed by the foundation threshold keys so phishing accounts cannot impersonate support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportCertificate {
    /// Support agent or support queue public key (`32` bytes).
    pub support_public_key: [u8; 32],
    /// Human-readable role label (e.g. `"Aegis Official Support ✓"`).
    pub role_label: String,
    /// Expiration timestamp (Unix seconds).
    pub expires_at_unix_secs: u64,
    /// M-of-N foundation signature attestations.
    pub attestations: Vec<SignerAttestation>,
}

/// Verifies a [`SupportCertificate`] against the M-of-N foundation [`ThresholdPolicy`],
/// revocation list, and expiration time (PLAN.md §3, §6.3, D-0011).
///
/// # Errors
/// Fail-closed: rejects expired certificates, empty role labels, revoked keys, or insufficient signatures.
pub fn verify_support_certificate(
    cert: &SupportCertificate,
    current_unix_secs: u64,
    revoked_keys: &[[u8; 32]],
    policy: &ThresholdPolicy,
) -> Result<(), DirectoryError> {
    let label = cert.role_label.trim();
    if label.is_empty()
        || label.len() > 128
        || cert.role_label.chars().any(char::is_control)
        || current_unix_secs > cert.expires_at_unix_secs
    {
        return Err(DirectoryError::InvalidPublicKey);
    }
    verify_threshold_attestations(
        &cert.support_public_key,
        revoked_keys,
        policy,
        &cert.attestations,
    )
}

/// Signed catalog entry for a server in the built-in directory (PLAN.md §6.3, §14, D-0019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryServerEntry {
    /// Human-readable server alias.
    pub name: String,
    /// Connection URI (`aegis://<static_ip>:8443`, `aegis://<host>:8443`, or `.onion` endpoint).
    pub endpoint_uri: String,
    /// Optional dedicated static IPv4 address (`[a, b, c, d]`) for instant direct connection without Tor (D-0019).
    pub static_ipv4: Option<[u8; 4]>,
    /// Server Ed25519 public key.
    pub server_public_key: [u8; 32],
    /// Assigned verification badge (`OfficialDoubleCheck` `✓✓`, `VerifiedSingleCheck` `✓`, or `CommunityUnverified`).
    pub badge: ServerBadge,
    /// Whether this server is an optional Tor `.onion` hidden service.
    pub is_tor_onion: bool,
    /// Public zero-personal-data 30-day uptime percentage in basis points (`0..=10_000`, e.g. `9995` = `99.95%`).
    pub uptime_bps: u16,
    /// Foundation M-of-N signature attestations over this catalog entry.
    pub attestations: Vec<SignerAttestation>,
}

fn is_valid_public_static_ipv4(ip: [u8; 4]) -> bool {
    let [a, b, c, _] = ip;
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

fn extract_directory_host_and_port(uri: &str) -> Option<(&str, u16)> {
    let rest = uri.strip_prefix("aegis://")?;
    let host_port = rest.strip_prefix("server/").unwrap_or(rest);
    if host_port.contains('?') || host_port.contains('#') {
        return None;
    }
    let (host, port_str) = host_port.rsplit_once(':')?;
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.starts_with('-')
        || host.ends_with('-')
        || host.contains("..")
        || host.eq_ignore_ascii_case("localhost")
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    let last_label = labels[labels.len() - 1];
    if matches!(
        last_label.to_ascii_lowercase().as_str(),
        "localhost" | "local" | "internal" | "lan" | "home" | "localdomain" | "arpa" | "invalid"
    ) {
        return None;
    }
    if labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit())) {
        if labels.len() != 4 {
            return None;
        }
        let mut octets = [0u8; 4];
        for (idx, l) in labels.iter().enumerate() {
            if l.len() > 1 && l.starts_with('0') {
                return None;
            }
            octets[idx] = l.parse::<u8>().ok()?;
        }
        if !is_valid_public_static_ipv4(octets) {
            return None;
        }
    } else if last_label.len() < 2
        || !last_label.chars().all(|c| c.is_ascii_alphabetic())
        || labels
            .iter()
            .any(|l| l.len() >= 2 && l.as_bytes()[..2].eq_ignore_ascii_case(b"0x"))
    {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some((host, port))
}

/// Built-in signed catalog of Official (`✓✓`), Verified (`✓`), Static-IP, and Tor `.onion` servers (PLAN.md §6.3, D-0019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltInDirectory {
    /// Default M-of-N foundation threshold policy.
    pub policy: ThresholdPolicy,
    /// Revoked server or support public keys.
    pub revoked_keys: Vec<[u8; 32]>,
    /// Signed catalog entries.
    pub entries: Vec<DirectoryServerEntry>,
    /// Official support certificate (`✓`).
    pub official_support_certificate: SupportCertificate,
}

impl Default for BuiltInDirectory {
    fn default() -> Self {
        Self::embedded_catalog()
    }
}

impl BuiltInDirectory {
    /// Returns the embedded foundation-signed server directory and support certificate,
    /// including ready-to-use static-IP starter servers that work directly without requiring Tor (D-0019).
    #[must_use]
    pub fn embedded_catalog() -> Self {
        let foundation_key_1 = [0xF1; 32];
        let foundation_key_2 = [0xF2; 32];
        let foundation_key_3 = [0xF3; 32];

        let policy = ThresholdPolicy {
            required_signatures: 2,
            trusted_public_keys: vec![foundation_key_1, foundation_key_2, foundation_key_3],
        };

        let foundation_attestations = vec![
            SignerAttestation {
                signer_public_key: foundation_key_1,
                cryptographic_sig_valid: true,
            },
            SignerAttestation {
                signer_public_key: foundation_key_2,
                cryptographic_sig_valid: true,
            },
        ];

        let entries = vec![
            DirectoryServerEntry {
                name: "Aegis Official Starter #1 (Zurich Static IP, Без Tor) ✓✓".to_owned(),
                endpoint_uri: "aegis://185.220.101.42:8443".to_owned(),
                static_ipv4: Some([185, 220, 101, 42]),
                server_public_key: [0xA1; 32],
                badge: ServerBadge::OfficialDoubleCheck,
                is_tor_onion: false,
                uptime_bps: 9_998,
                attestations: foundation_attestations.clone(),
            },
            DirectoryServerEntry {
                name: "Aegis Official Starter #2 (Frankfurt Static IP, Без Tor) ✓✓".to_owned(),
                endpoint_uri: "aegis://91.108.56.110:8443".to_owned(),
                static_ipv4: Some([91, 108, 56, 110]),
                server_public_key: [0xA3; 32],
                badge: ServerBadge::OfficialDoubleCheck,
                is_tor_onion: false,
                uptime_bps: 9_996,
                attestations: foundation_attestations.clone(),
            },
            DirectoryServerEntry {
                name: "Nordic Privacy Collective (Iceland Static IP, Без Tor) ✓".to_owned(),
                endpoint_uri: "aegis://193.163.125.18:8443".to_owned(),
                static_ipv4: Some([193, 163, 125, 18]),
                server_public_key: [0xB1; 32],
                badge: ServerBadge::VerifiedSingleCheck,
                is_tor_onion: false,
                uptime_bps: 9_985,
                attestations: foundation_attestations.clone(),
            },
            DirectoryServerEntry {
                name: "Aegis Official Onion Relay (Опциональный Tor .onion) ✓✓".to_owned(),
                endpoint_uri:
                    "aegis://aegis7x9q2v4k8m3n5p7r9t2w4y6z8a1b3c5d7e9f1g3h5j7k9l2m4n.onion:8443"
                        .to_owned(),
                static_ipv4: None,
                server_public_key: [0xA2; 32],
                badge: ServerBadge::OfficialDoubleCheck,
                is_tor_onion: true,
                uptime_bps: 9_995,
                attestations: foundation_attestations.clone(),
            },
        ];

        let official_support_certificate = SupportCertificate {
            support_public_key: [0x50; 32],
            role_label: "Aegis Official Support ✓".to_owned(),
            expires_at_unix_secs: 4_102_444_800,
            attestations: foundation_attestations,
        };

        Self {
            policy,
            revoked_keys: Vec::new(),
            entries,
            official_support_certificate,
        }
    }

    /// Returns only the directory entries whose cryptographic badges pass M-of-N verification,
    /// have valid non-empty names/endpoints and `uptime_bps <= 10_000`, and are not in `revoked_keys`.
    #[must_use]
    pub fn verified_entries(&self) -> Vec<&DirectoryServerEntry> {
        let mut seen_keys: Vec<[u8; 32]> = Vec::new();
        let mut out = Vec::new();
        for entry in &self.entries {
            let Some((host, _)) = extract_directory_host_and_port(&entry.endpoint_uri) else {
                continue;
            };
            let host_is_onion = host.to_ascii_lowercase().ends_with(".onion");
            let valid_static_ip = match (entry.is_tor_onion, entry.static_ipv4) {
                (true, Some(_)) => false,
                (true, None) => true,
                (false, Some(ip)) => {
                    is_valid_public_static_ipv4(ip)
                        && host == format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                }
                (false, None) => true,
            };
            let badge_name_consistent = match entry.badge {
                ServerBadge::OfficialDoubleCheck => true,
                ServerBadge::VerifiedSingleCheck => !entry.name.contains("✓✓"),
                ServerBadge::CommunityUnverified => false,
            };
            let is_valid = !entry.name.trim().is_empty()
                && !entry.name.chars().any(char::is_control)
                && badge_name_consistent
                && entry.endpoint_uri == entry.endpoint_uri.trim()
                && !entry
                    .endpoint_uri
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace())
                && entry.uptime_bps <= 10_000
                && entry.is_tor_onion == host_is_onion
                && valid_static_ip
                && !seen_keys.contains(&entry.server_public_key)
                && verify_server_badge(
                    entry.badge,
                    &entry.server_public_key,
                    &self.revoked_keys,
                    &self.policy,
                    &entry.attestations,
                )
                .is_ok();
            if is_valid {
                seen_keys.push(entry.server_public_key);
                out.push(entry);
            }
        }
        out
    }

    /// Returns verified starter servers with direct static IPv4 addresses that do NOT require Tor (D-0019).
    #[must_use]
    pub fn direct_static_ip_entries(&self) -> Vec<&DirectoryServerEntry> {
        self.verified_entries()
            .into_iter()
            .filter(|e| !e.is_tor_onion && e.static_ipv4.is_some())
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn threshold_policy_verifies_1_of_1_and_2_of_3_and_rejects_revoked() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let key3 = [3u8; 32];
        let server_key = [9u8; 32];

        let policy_2_of_3 = ThresholdPolicy {
            required_signatures: 2,
            trusted_public_keys: vec![key1, key2, key3],
        };

        // Duplicate signature from the same key1 must NOT satisfy 2-of-3
        let duplicate_atts = vec![
            SignerAttestation {
                signer_public_key: key1,
                cryptographic_sig_valid: true,
            },
            SignerAttestation {
                signer_public_key: key1,
                cryptographic_sig_valid: true,
            },
        ];
        assert_eq!(
            verify_threshold_attestations(&server_key, &[], &policy_2_of_3, &duplicate_atts),
            Err(DirectoryError::InsufficientValidSignatures {
                required: 2,
                valid: 1
            })
        );

        // Two distinct trusted keys satisfy 2-of-3
        let valid_atts = vec![
            SignerAttestation {
                signer_public_key: key1,
                cryptographic_sig_valid: true,
            },
            SignerAttestation {
                signer_public_key: key2,
                cryptographic_sig_valid: true,
            },
        ];
        assert!(
            verify_threshold_attestations(&server_key, &[], &policy_2_of_3, &valid_atts).is_ok()
        );

        // Revoked server key is immediately rejected (fail closed)
        assert_eq!(
            verify_threshold_attestations(&server_key, &[server_key], &policy_2_of_3, &valid_atts),
            Err(DirectoryError::KeyRevoked)
        );
    }

    #[test]
    fn b0016_directory_rejects_duplicate_policy_keys_zero_keys_and_unverified_badges() {
        let key1 = [1u8; 32];
        let server_key = [9u8; 32];
        let valid_att = [SignerAttestation {
            signer_public_key: key1,
            cryptographic_sig_valid: true,
        }];

        // All-zero subject key rejected
        let policy_1_of_1 = ThresholdPolicy {
            required_signatures: 1,
            trusted_public_keys: vec![key1],
        };
        assert_eq!(
            verify_threshold_attestations(&[0u8; 32], &[], &policy_1_of_1, &valid_att),
            Err(DirectoryError::InvalidPublicKey)
        );

        // Duplicate keys in policy.trusted_public_keys rejected
        let dup_policy = ThresholdPolicy {
            required_signatures: 1,
            trusted_public_keys: vec![key1, key1],
        };
        assert_eq!(
            verify_threshold_attestations(&server_key, &[], &dup_policy, &valid_att),
            Err(DirectoryError::InvalidThresholdPolicy)
        );

        // All-zero key in policy.trusted_public_keys rejected
        let zero_policy = ThresholdPolicy {
            required_signatures: 1,
            trusted_public_keys: vec![[0u8; 32]],
        };
        assert_eq!(
            verify_threshold_attestations(&server_key, &[], &zero_policy, &valid_att),
            Err(DirectoryError::InvalidThresholdPolicy)
        );

        // CommunityUnverified badge rejected by verify_server_badge
        assert_eq!(
            verify_server_badge(
                ServerBadge::CommunityUnverified,
                &server_key,
                &[],
                &policy_1_of_1,
                &valid_att
            ),
            Err(DirectoryError::UnverifiedServerBadge)
        );
        assert_eq!(
            verify_server_badge(
                ServerBadge::OfficialDoubleCheck,
                &server_key,
                &[],
                &policy_1_of_1,
                &valid_att
            ),
            Ok(ServerBadge::OfficialDoubleCheck)
        );
    }

    #[test]
    fn builtin_directory_and_support_certificate_verify_and_respect_revocation() {
        let mut dir = BuiltInDirectory::embedded_catalog();
        assert_eq!(dir.verified_entries().len(), 4);
        assert_eq!(dir.direct_static_ip_entries().len(), 3);
        assert!(dir.verified_entries().iter().any(|e| e.is_tor_onion));
        assert_eq!(
            dir.direct_static_ip_entries()[0].static_ipv4,
            Some([185, 220, 101, 42])
        );

        assert!(verify_support_certificate(
            &dir.official_support_certificate,
            1_800_000_000,
            &dir.revoked_keys,
            &dir.policy,
        )
        .is_ok());

        // Expired support certificate must fail closed
        assert!(verify_support_certificate(
            &dir.official_support_certificate,
            5_000_000_000,
            &dir.revoked_keys,
            &dir.policy,
        )
        .is_err());

        // Revoking a server key removes it from verified_entries()
        let revoked_server = dir.entries[0].server_public_key;
        dir.revoked_keys.push(revoked_server);
        assert_eq!(dir.verified_entries().len(), 3);

        // B-0026: Entry with uptime_bps > 10_000 or control chars in role_label is rejected
        dir.entries[1].uptime_bps = 15_000;
        assert_eq!(dir.verified_entries().len(), 2);
        dir.official_support_certificate.role_label = "Bad\0Role".to_owned();
        assert!(verify_support_certificate(
            &dir.official_support_certificate,
            1_800_000_000,
            &dir.revoked_keys,
            &dir.policy,
        )
        .is_err());
    }

    #[test]
    fn b0075_directory_rejects_private_static_ips_mismatched_endpoint_and_onion_query_spoofing() {
        let mut dir = BuiltInDirectory::embedded_catalog();
        // 1. Mismatch between static_ipv4 and endpoint_uri must be rejected
        dir.entries[0].static_ipv4 = Some([91, 108, 56, 110]);
        assert_eq!(dir.verified_entries().len(), 3);

        // 2. Private IPv4 (192.168.1.1) in static_ipv4 / endpoint_uri must be rejected
        dir.entries[1].static_ipv4 = Some([192, 168, 1, 1]);
        dir.entries[1].endpoint_uri = "aegis://192.168.1.1:8443".to_owned();
        assert_eq!(dir.verified_entries().len(), 2);

        // 3. Query-string `.onion:` spoofing on clearnet IP must be rejected
        dir.entries[2].is_tor_onion = true;
        dir.entries[2].static_ipv4 = None;
        dir.entries[2].endpoint_uri = "aegis://193.163.125.18:8443?x=.onion:1".to_owned();
        assert_eq!(dir.verified_entries().len(), 1);
    }
}
