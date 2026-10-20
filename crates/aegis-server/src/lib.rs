//! `aegis-server` — Zero-knowledge federation server policies, unidirectional queue TTLs,
//! and anti-DDoS adaptive Proof-of-Work difficulty calculation without IP logging (D-0007, PLAN.md §6).

use aegis_protocol::PADDING_BUCKETS;

/// Default message queue time-to-live on the server: 30 days in seconds (PLAN.md §5).
pub const DEFAULT_QUEUE_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Baseline PoW difficulty in leading zero bits under normal server load.
pub const BASE_POW_DIFFICULTY_BITS: u8 = 12;

/// Maximum PoW difficulty in leading zero bits under heavy DDoS attack.
pub const MAX_POW_DIFFICULTY_BITS: u8 = 24;

/// Computes the adaptive Proof-of-Work difficulty (in leading zero bits) based on
/// the current in-memory sliding window request rate (D-0007).
/// No client IP addresses are stored on disk.
#[must_use]
pub fn compute_pow_difficulty(requests_per_minute: u32, suspicious_burst: bool) -> u8 {
    let mut bits = match requests_per_minute {
        0..=60 => BASE_POW_DIFFICULTY_BITS,
        61..=300 => BASE_POW_DIFFICULTY_BITS + 4,
        301..=1_500 => BASE_POW_DIFFICULTY_BITS + 8,
        _ => MAX_POW_DIFFICULTY_BITS,
    };
    if suspicious_burst {
        bits = bits.saturating_add(4).min(MAX_POW_DIFFICULTY_BITS);
    }
    bits
}

/// Per-queue quota configuration so a spammed invite or contact queue can be rotated
/// or deleted in 1 click without affecting other contacts (D-0007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueQuota {
    /// Ephemeral one-way queue identifier.
    pub queue_id: [u8; 32],
    /// Maximum buffered frames allowed in this queue.
    pub max_buffered_frames: usize,
    /// Current buffered frame count.
    pub current_buffered_frames: usize,
    /// TTL in seconds for undelivered frames.
    pub ttl_secs: u64,
}

impl QueueQuota {
    /// Returns `true` if the queue configuration is valid and has capacity for another frame.
    #[must_use]
    pub fn can_enqueue(&self) -> bool {
        self.queue_id != [0u8; 32]
            && self.max_buffered_frames > 0
            && self.ttl_secs > 0
            && self.ttl_secs <= DEFAULT_QUEUE_TTL_SECS
            && self.current_buffered_frames < self.max_buffered_frames
    }

    /// Returns `true` if the queue can accept an incoming frame of `frame_len_bytes`,
    /// enforcing fixed metadata-hiding padding buckets (`[256, 1024, 4096, 16384]`).
    #[must_use]
    pub fn can_accept_frame(&self, frame_len_bytes: usize) -> bool {
        self.can_enqueue() && PADDING_BUCKETS.contains(&frame_len_bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_pow_scales_with_load_and_caps_at_max() {
        assert_eq!(compute_pow_difficulty(10, false), 12);
        assert_eq!(compute_pow_difficulty(10, true), 16);
        assert_eq!(compute_pow_difficulty(500, false), 20);
        assert_eq!(
            compute_pow_difficulty(10_000, true),
            MAX_POW_DIFFICULTY_BITS
        );
    }

    #[test]
    fn b0015_queue_quota_enforces_valid_queue_id_ttl_and_padding_buckets() {
        let valid_quota = QueueQuota {
            queue_id: [0x11; 32],
            max_buffered_frames: 100,
            current_buffered_frames: 10,
            ttl_secs: DEFAULT_QUEUE_TTL_SECS,
        };
        assert!(valid_quota.can_enqueue());
        assert!(valid_quota.can_accept_frame(256));
        assert!(valid_quota.can_accept_frame(16384));
        assert!(!valid_quota.can_accept_frame(0));
        assert!(!valid_quota.can_accept_frame(512));

        // All-zero queue_id or zero TTL must be rejected
        let zero_id = QueueQuota {
            queue_id: [0u8; 32],
            ..valid_quota
        };
        assert!(!zero_id.can_enqueue());

        let zero_ttl = QueueQuota {
            ttl_secs: 0,
            ..valid_quota
        };
        assert!(!zero_ttl.can_enqueue());
    }
}
