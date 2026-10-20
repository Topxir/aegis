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
}
