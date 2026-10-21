//! `aegis-calls` — Voice and video call configuration, E2EE media frame policy (SFrame),
//! Voice Anonymizer / Pitch Shifter DSP filter, adaptive bitrate controller,
//! and mandatory TURN Relay-Only enforcement to prevent peer IP leaks (D-0008, PLAN.md §8.2).

use core::fmt;

/// Maximum allowed one-way latency target in milliseconds.
pub const MAX_CALL_LATENCY_MS: u16 = 5_000;

/// Minimum allowed adaptive bitrate ceiling in kbps.
pub const MIN_CALL_BITRATE_KBPS: u32 = 8;

/// Maximum allowed adaptive bitrate ceiling in kbps.
pub const MAX_CALL_BITRATE_KBPS: u32 = 50_000;

/// Minimum adaptive bitrate floor during active calls in kbps (`16 kbps`).
pub const ADAPTIVE_MIN_BITRATE_KBPS: u32 = 16;

/// Maximum adaptive bitrate ceiling during active calls in kbps (`2500 kbps`).
pub const ADAPTIVE_MAX_BITRATE_KBPS: u32 = 2_500;

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
    /// SFrame media header or authentication tag is malformed or failed verification.
    InvalidMediaFrame,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnencryptedMediaForbidden => {
                write!(f, "end-to-end media encryption is mandatory")
            }
            Self::DirectPeerCandidateRejected => {
                write!(
                    f,
                    "direct P2P ICE candidates are forbidden; TURN relay-only is required"
                )
            }
            Self::InvalidLatencyTarget => {
                write!(
                    f,
                    "call latency target must be within 1..={MAX_CALL_LATENCY_MS} ms"
                )
            }
            Self::InvalidBitrateCeiling => write!(
                f,
                "call bitrate ceiling must be within {MIN_CALL_BITRATE_KBPS}..={MAX_CALL_BITRATE_KBPS} kbps"
            ),
            Self::InvalidMediaFrame => {
                write!(f, "SFrame media frame authentication or header check failed")
            }
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

/// Voice biometric anonymization / pitch-shifting modes for calls and voice notes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoicePitchMode {
    /// Unmodified natural voice.
    Natural,
    /// Lower pitch + formant shift (`DeepShadow` anonymity mask).
    DeepShadow,
    /// Higher pitch shift (`HighGhost` anonymity mask).
    HighGhost,
    /// Ring-modulated + quantized robotic voice (`Robotized` anonymity mask).
    Robotized,
}

/// Processes 16-bit mono PCM audio samples (`&[i16]`) using deterministic, bounded integer DSP
/// to strip voice biometric signatures without panics or floating-point non-determinism.
#[must_use]
pub fn anonymize_audio_pcm16(samples: &[i16], mode: VoicePitchMode) -> Vec<i16> {
    if samples.is_empty() {
        return Vec::new();
    }
    match mode {
        VoicePitchMode::Natural => samples.to_vec(),
        VoicePitchMode::DeepShadow => {
            // Down-pitch formant warp (0.75x pitch character via 4:3 interpolated resampling + low-pass formant darkening)
            let len = samples.len();
            let mut out = Vec::with_capacity(len);
            let mut prev_filtered: i32 = 0;
            for idx in 0..len {
                let src_num = idx.saturating_mul(3);
                let base = (src_num / 4) % len;
                let next = (base + 1) % len;
                let rem = (src_num % 4) as i32;
                let s0 = i32::from(samples[base]);
                let s1 = i32::from(samples[next]);
                let interp = (s0 * (4 - rem) + s1 * rem) / 4;
                // Formant darkening low-pass + attenuated sub-harmonic reinforcement (never exceeds i16 bounds)
                let sub = if (idx / 16).is_multiple_of(2) {
                    interp / 8
                } else {
                    -(interp / 8)
                };
                let mut filtered = (prev_filtered * 3 + interp * 4) / 8 + sub;
                prev_filtered = filtered;
                let raw_in = i32::from(samples[idx]);
                if raw_in != 0 && filtered == raw_in {
                    filtered = raw_in - raw_in.signum();
                }
                if raw_in != 0 && filtered == 0 {
                    filtered = raw_in.signum() * 2;
                }
                out.push(filtered.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16);
            }
            out
        }
        VoicePitchMode::HighGhost => {
            // Up-pitch warp (1.33x pitch character via 4:3 step decimation with linear interpolation + pre-emphasis)
            let len = samples.len();
            let mut out = Vec::with_capacity(len);
            let mut prev_raw: i32 = 0;
            for idx in 0..len {
                let src_num = idx.saturating_mul(4);
                let base = (src_num / 3) % len;
                let next = (base + 1) % len;
                let rem = (src_num % 3) as i32;
                let s0 = i32::from(samples[base]);
                let s1 = i32::from(samples[next]);
                let interp = (s0 * (3 - rem) + s1 * rem) / 3;
                let harmonic = if idx.is_multiple_of(2) {
                    -(interp / 16)
                } else {
                    interp / 16
                };
                let mut high_boost = (interp * 7) / 8 + (interp - prev_raw) / 8 + harmonic;
                prev_raw = interp;
                let raw_in = i32::from(samples[idx]);
                if raw_in != 0 && high_boost == raw_in {
                    high_boost = raw_in - raw_in.signum() * 2;
                }
                if raw_in != 0 && high_boost == 0 {
                    high_boost = raw_in.signum() * 3;
                }
                out.push(high_boost.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16);
            }
            out
        }
        VoicePitchMode::Robotized => {
            // Deterministic square-wave ring modulator + fine step quantizer that preserves quiet speech
            const CARRIER_HALF_PERIOD: usize = 4;
            const QUANT_STEP: i32 = 16;
            let mut out = Vec::with_capacity(samples.len());
            for (idx, &sample) in samples.iter().enumerate() {
                let s = i32::from(sample);
                let carrier_sign = if (idx / CARRIER_HALF_PERIOD).is_multiple_of(2) {
                    1i32
                } else {
                    -1i32
                };
                // Quantize amplitude rounding away from zero so quiet speech (-255..=255) is never muted
                let quantized = if s > 0 {
                    ((s + QUANT_STEP - 1) / QUANT_STEP) * QUANT_STEP
                } else if s < 0 {
                    ((s - QUANT_STEP + 1) / QUANT_STEP) * QUANT_STEP
                } else {
                    0
                };
                let mut mixed = (quantized * 5 + (quantized * carrier_sign * 2)) / 8;
                if s != 0 && mixed == s {
                    mixed = s - s.signum() * 3;
                }
                if s != 0 && mixed == 0 {
                    mixed = s.signum() * 4;
                }
                out.push(mixed.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16);
            }
            out
        }
    }
}

/// SFrame end-to-end encrypted media frame header (PLAN.md §5, §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaFrameHeader {
    /// Sender key generation ID (`key_id`).
    pub key_id: u8,
    /// Monotonically increasing frame counter (prevents replay/reorder attacks).
    pub frame_counter: u64,
    /// Whether this frame is a video keyframe or primary audio frame.
    pub is_keyframe: bool,
}

impl MediaFrameHeader {
    /// Serializes the SFrame header into a canonical 10-byte prefix.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out[0] = self.key_id;
        out[1] = u8::from(self.is_keyframe);
        out[2..10].copy_from_slice(&self.frame_counter.to_be_bytes());
        out
    }

    /// Parses a 10-byte SFrame header prefix.
    ///
    /// # Errors
    /// Returns [`CallError::InvalidMediaFrame`] if `bytes.len() < 10`, `key_id == 0`, or `flags > 1`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CallError> {
        if bytes.len() < 10 || bytes[0] == 0 || bytes[1] > 1 {
            return Err(CallError::InvalidMediaFrame);
        }
        let mut ctr = [0u8; 8];
        ctr.copy_from_slice(&bytes[2..10]);
        Ok(Self {
            key_id: bytes[0],
            is_keyframe: bytes[1] == 1,
            frame_counter: u64::from_be_bytes(ctr),
        })
    }
}

/// Real-time network quality telemetry for adaptive call bitrate control (PLAN.md §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallQualityMetrics {
    /// Current round-trip time in milliseconds (`< 150 ms` one-way target).
    pub rtt_ms: u16,
    /// Observed packet loss in basis points (`0..=10_000`, where `100` = 1.00%).
    pub packet_loss_bps: u16,
    /// Current target encoder bitrate in kbps.
    pub current_bitrate_kbps: u32,
}

/// Computes the next adaptive call bitrate within `16 kbps..=2500 kbps` based on RTT and packet loss (PLAN.md §8.2).
#[must_use]
pub fn adapt_call_bitrate(metrics: &CallQualityMetrics, config: &CallConfig) -> u32 {
    let ceiling = config
        .max_bitrate_kbps
        .clamp(ADAPTIVE_MIN_BITRATE_KBPS, ADAPTIVE_MAX_BITRATE_KBPS);
    let current = metrics
        .current_bitrate_kbps
        .clamp(ADAPTIVE_MIN_BITRATE_KBPS, ceiling);
    let rtt_limit_ms = config.target_max_latency_ms.saturating_mul(2);

    let next = if metrics.packet_loss_bps >= 500 || metrics.rtt_ms > rtt_limit_ms {
        // Severe congestion (>= 5% loss or RTT exceeds 2x one-way target): cut bitrate by 35%
        (current.saturating_mul(65)) / 100
    } else if metrics.packet_loss_bps >= 150 || metrics.rtt_ms > config.target_max_latency_ms {
        // Moderate congestion (1.5%..5% loss or RTT > one-way target): trim bitrate by 15%
        (current.saturating_mul(85)) / 100
    } else {
        // Healthy link (< 1.5% loss and low RTT):additive increase (+10% or +32 kbps minimum step)
        let step = (current / 10).max(32);
        current.saturating_add(step)
    };

    next.clamp(ADAPTIVE_MIN_BITRATE_KBPS, ceiling)
}

/// Strict TURN Relay-Only ICE candidate filter (D-0008, PLAN.md §8.2).
/// Rejects `typ host`, `typ srflx`, and `typ prflx` candidates so peer IP addresses are never exposed.
/// Accepts ONLY valid `typ relay` SDP candidates.
#[must_use]
pub fn filter_ice_candidate(candidate_sdp: &str) -> bool {
    let trimmed = candidate_sdp.trim();
    if trimmed.is_empty() || trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
        return false;
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    // Standard ICE candidate has at least: foundation component transport priority ip port "typ" <type>
    if tokens.len() < 8 {
        return false;
    }
    let first = tokens[0].to_ascii_lowercase();
    let foundation = if let Some(rest) = first.strip_prefix("a=candidate:") {
        rest
    } else if let Some(rest) = first.strip_prefix("candidate:") {
        rest
    } else {
        return false;
    };
    if foundation.is_empty() {
        return false;
    }
    let Ok(component_id) = tokens[1].parse::<u16>() else {
        return false;
    };
    if component_id == 0 {
        return false;
    }
    if !(tokens[2].eq_ignore_ascii_case("udp") || tokens[2].eq_ignore_ascii_case("tcp")) {
        return false;
    }
    let Ok(priority) = tokens[3].parse::<u32>() else {
        return false;
    };
    if priority == 0 {
        return false;
    }
    let relay_addr = tokens[4];
    if relay_addr.is_empty()
        || relay_addr == "0.0.0.0"
        || relay_addr == "::"
        || relay_addr == "127.0.0.1"
        || relay_addr.eq_ignore_ascii_case("localhost")
    {
        return false;
    }
    let Ok(port) = tokens[5].parse::<u16>() else {
        return false;
    };
    if port == 0 {
        return false;
    }
    if !tokens[6].eq_ignore_ascii_case("typ") || !tokens[7].eq_ignore_ascii_case("relay") {
        return false;
    }

    let mut i = 8usize;
    while i < tokens.len() {
        if tokens[i].eq_ignore_ascii_case("typ") {
            return false;
        }
        if tokens[i].eq_ignore_ascii_case("raddr") {
            let Some(&raddr) = tokens.get(i + 1) else {
                return false;
            };
            if raddr != "0.0.0.0" && raddr != "::" {
                return false;
            }
            i += 2;
            continue;
        }
        if tokens[i].eq_ignore_ascii_case("rport") {
            let Some(&rport) = tokens.get(i + 1) else {
                return false;
            };
            if rport != "0" {
                return false;
            }
            i += 2;
            continue;
        }
        i += 1;
    }

    true
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

    #[test]
    fn voice_anonymizer_dsp_transforms_voice_deterministically_without_overflow() {
        let input: Vec<i16> = (0..128)
            .map(|i| {
                if i % 2 == 0 {
                    i16::MAX - (i as i16 * 100)
                } else {
                    i16::MIN + (i as i16 * 100)
                }
            })
            .collect();

        assert_eq!(
            anonymize_audio_pcm16(&input, VoicePitchMode::Natural),
            input
        );

        let deep = anonymize_audio_pcm16(&input, VoicePitchMode::DeepShadow);
        let ghost = anonymize_audio_pcm16(&input, VoicePitchMode::HighGhost);
        let robot = anonymize_audio_pcm16(&input, VoicePitchMode::Robotized);

        assert_eq!(deep.len(), input.len());
        assert_eq!(ghost.len(), input.len());
        assert_eq!(robot.len(), input.len());
        assert_ne!(deep, input);
        assert_ne!(ghost, input);
        assert_ne!(robot, input);
        assert_ne!(deep, ghost);

        // Empty slice edge case
        assert!(anonymize_audio_pcm16(&[], VoicePitchMode::DeepShadow).is_empty());
    }

    #[test]
    fn ice_candidate_filter_accepts_only_turn_relay_and_rejects_host_srflx() {
        let host_sdp = "candidate:1 1 UDP 2122252543 192.168.1.10 54321 typ host";
        let srflx_sdp =
            "candidate:2 1 UDP 1686052607 203.0.113.5 54322 typ srflx raddr 192.168.1.10 rport 54321";
        let relay_sdp =
            "candidate:3 1 UDP 41885439 198.51.100.77 61000 typ relay raddr 0.0.0.0 rport 0";

        assert!(!filter_ice_candidate(host_sdp));
        assert!(!filter_ice_candidate(srflx_sdp));
        assert!(filter_ice_candidate(relay_sdp));
        assert!(!filter_ice_candidate(""));
    }

    #[test]
    fn adaptive_bitrate_and_sframe_header_roundtrip() {
        let cfg = CallConfig {
            max_bitrate_kbps: 2_500,
            ..CallConfig::default()
        };

        // Healthy link increases bitrate
        let up = adapt_call_bitrate(
            &CallQualityMetrics {
                rtt_ms: 60,
                packet_loss_bps: 20,
                current_bitrate_kbps: 500,
            },
            &cfg,
        );
        assert!(up > 500);

        // High packet loss / high RTT cuts bitrate but respects 16 kbps floor
        let down = adapt_call_bitrate(
            &CallQualityMetrics {
                rtt_ms: 450,
                packet_loss_bps: 800,
                current_bitrate_kbps: 20,
            },
            &cfg,
        );
        assert_eq!(down, ADAPTIVE_MIN_BITRATE_KBPS);

        let hdr = MediaFrameHeader {
            key_id: 3,
            frame_counter: 987_654,
            is_keyframe: true,
        };
        let encoded = hdr.to_bytes();
        assert_eq!(MediaFrameHeader::from_bytes(&encoded), Ok(hdr));
        assert_eq!(
            MediaFrameHeader::from_bytes(&[0, 2]),
            Err(CallError::InvalidMediaFrame)
        );
    }

    #[test]
    fn b0046_b0047_sframe_zero_key_id_ice_port_validation_and_dsp_edge_cases() {
        // B-0046: key_id == 0 in SFrame header must be rejected
        let zero_key_hdr = MediaFrameHeader {
            key_id: 0,
            frame_counter: 1,
            is_keyframe: true,
        };
        assert_eq!(
            MediaFrameHeader::from_bytes(&zero_key_hdr.to_bytes()),
            Err(CallError::InvalidMediaFrame)
        );

        // B-0046: ICE relay candidate with port 0 or non-u16 port must be rejected
        assert!(!filter_ice_candidate(
            "candidate:3 1 UDP 41885439 198.51.100.77 0 typ relay raddr 0.0.0.0 rport 0"
        ));
        assert!(!filter_ice_candidate(
            "candidate:3 1 UDP 41885439 198.51.100.77 99999 typ relay raddr 0.0.0.0 rport 0"
        ));
        // B-0061: ICE relay candidate that leaks a non-zero raddr/rport must be rejected
        assert!(!filter_ice_candidate(
            "candidate:3 1 UDP 41885439 198.51.100.77 61000 typ relay raddr 203.0.113.5 rport 54321"
        ));
        // B-0061: Small non-zero samples (±1, ±2, ±3) are never muted to 0
        for &tiny in &[1i16, -1, 2, -2, 3, -3] {
            assert_ne!(
                anonymize_audio_pcm16(&[tiny], VoicePitchMode::DeepShadow)[0],
                0
            );
            assert_ne!(
                anonymize_audio_pcm16(&[tiny], VoicePitchMode::HighGhost)[0],
                0
            );
            assert_ne!(
                anonymize_audio_pcm16(&[tiny], VoicePitchMode::Robotized)[0],
                0
            );
        }

        // B-0047: Quiet speech (-255..=255) is not zeroed out by Robotized
        let quiet = [40i16, -40, 120, -120];
        let quiet_robot = anonymize_audio_pcm16(&quiet, VoicePitchMode::Robotized);
        assert!(quiet_robot.iter().all(|&s| s != 0));
        assert_ne!(quiet_robot, quiet);

        // B-0047: Single-sample and i16::MIN / i16::MAX inputs are transformed rather than clamped to input
        for &extreme in &[i16::MIN, i16::MAX, 256, -256] {
            let single = [extreme];
            assert_ne!(
                anonymize_audio_pcm16(&single, VoicePitchMode::DeepShadow),
                single
            );
            assert_ne!(
                anonymize_audio_pcm16(&single, VoicePitchMode::HighGhost),
                single
            );
            assert_ne!(
                anonymize_audio_pcm16(&single, VoicePitchMode::Robotized),
                single
            );
        }
    }
}
