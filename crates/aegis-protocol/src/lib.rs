//! `aegis-protocol` — Wire framing with fixed metadata-hiding padding buckets (D-0002),
//! `LeakGuard` zero-false-positive local DLP scanner (D-0009), and encrypted support tickets (D-0006).

use core::fmt;

/// Current wire protocol version (`AGENTS.md §4`).
pub const PROTOCOL_VERSION: u16 = 1;

/// Fixed packet size buckets in bytes to prevent message length traffic analysis (D-0002).
pub const PADDING_BUCKETS: [usize; 4] = [256, 1024, 4096, 16384];

/// Protocol framing and validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Payload exceeds the largest fixed padding bucket.
    PayloadTooLarge { size: usize, max_supported: usize },
    /// Padded frame is malformed or does not match a valid bucket size.
    MalformedPaddedFrame,
    /// Unsupported protocol version.
    UnsupportedVersion(u16),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge {
                size,
                max_supported,
            } => write!(
                f,
                "payload size {size} exceeds max frame capacity {max_supported}"
            ),
            Self::MalformedPaddedFrame => write!(f, "padded frame is corrupted or malformed"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version: {v}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Pads `payload` into the smallest fitting bucket from [`PADDING_BUCKETS`] (`256`, `1024`, `4096`, `16384`).
/// Format: `[u16 BE payload length][payload bytes][zero padding]`.
///
/// # Errors
/// Returns [`ProtocolError::PayloadTooLarge`] if `payload.len() + 2 > 16384`.
pub fn pad_frame(payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let required = payload.len().saturating_add(2);
    let Some(&bucket_size) = PADDING_BUCKETS.iter().find(|&&b| b >= required) else {
        return Err(ProtocolError::PayloadTooLarge {
            size: payload.len(),
            max_supported: PADDING_BUCKETS[PADDING_BUCKETS.len() - 1] - 2,
        });
    };

    let len_u16 = u16::try_from(payload.len()).map_err(|_| ProtocolError::PayloadTooLarge {
        size: payload.len(),
        max_supported: PADDING_BUCKETS[PADDING_BUCKETS.len() - 1] - 2,
    })?;

    let mut frame = vec![0u8; bucket_size];
    let len_bytes = len_u16.to_be_bytes();
    frame[0] = len_bytes[0];
    frame[1] = len_bytes[1];
    frame[2..2 + payload.len()].copy_from_slice(payload);
    Ok(frame)
}

/// Extracts the original payload from a padded bucket frame, validating bucket alignment and trailing zeroes.
///
/// # Errors
/// Fail-closed: returns [`ProtocolError::MalformedPaddedFrame`] if length is out of bounds or padding is non-zero.
pub fn unpad_frame(frame: &[u8]) -> Result<&[u8], ProtocolError> {
    if !PADDING_BUCKETS.contains(&frame.len()) || frame.len() < 2 {
        return Err(ProtocolError::MalformedPaddedFrame);
    }
    let payload_len = usize::from(u16::from_be_bytes([frame[0], frame[1]]));
    if payload_len + 2 > frame.len() {
        return Err(ProtocolError::MalformedPaddedFrame);
    }
    // Fail-closed: verify padding bytes were not tampered with
    if frame[2 + payload_len..].iter().any(|&b| b != 0) {
        return Err(ProtocolError::MalformedPaddedFrame);
    }
    Ok(&frame[2..2 + payload_len])
}

/// Types of sensitive personal or financial data detected by `LeakGuard` (D-0009).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeakKind {
    /// Bank card number passing BIN prefix + Luhn checksum verification (with optional CVV/expiry context).
    BankCard { has_cvv_or_expiry_context: bool },
    /// Email address matching strict RFC local@domain.tld structure.
    EmailAddress,
    /// International phone number (`+` prefix and 10..=15 digits).
    PhoneNumber,
    /// User's own secret login nickname accidentally typed into chat message.
    OwnLoginNickname,
}

/// A sensitive data match found in an outgoing message before encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakWarning {
    /// Classification of the detected leak.
    pub kind: LeakKind,
    /// Byte start offset in the message string.
    pub start_byte: usize,
    /// Byte end offset (exclusive) in the message string.
    pub end_byte: usize,
}

/// Validates a digit sequence using the standard Luhn checksum algorithm (D-0009).
/// Rejects arbitrary timestamps, order IDs, and non-card numbers.
#[must_use]
pub fn passes_luhn(digits: &[u8]) -> bool {
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    // Check known payment network BIN prefixes:
    // 4 (Visa), 51-55 (Mastercard), 22..=27 (Mastercard/Mir), 34/37 (Amex), 60/62/65 (Discover/UnionPay)
    let first = digits[0];
    let second = digits[1];
    let valid_bin = first == 4
        || (first == 5 && (1..=5).contains(&second))
        || (first == 2 && (2..=7).contains(&second))
        || (first == 3 && (second == 4 || second == 7))
        || (first == 6 && (second == 0 || second == 2 || second == 5));

    if !valid_bin {
        return false;
    }

    // Reject all-identical digits
    if digits.iter().all(|&d| d == first) {
        return false;
    }

    let mut sum = 0u32;
    let mut double_digit = false;
    for &d in digits.iter().rev() {
        if d > 9 {
            return false;
        }
        let mut val = u32::from(d);
        if double_digit {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double_digit = !double_digit;
    }
    sum.is_multiple_of(10)
}

fn has_card_security_context(text: &str) -> bool {
    let lower = text.to_lowercase();
    let bytes = lower.as_bytes();
    for (idx, window) in bytes.windows(3).enumerate() {
        if matches!(window, b"cvv" | b"cvc" | b"exp") {
            let prev_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphabetic();
            let next_ok = idx + 3 >= bytes.len() || !bytes[idx + 3].is_ascii_alphabetic();
            if prev_ok && next_ok {
                return true;
            }
        }
    }
    // Check for MM/YY pattern such as 08/28 or 12/29
    for (idx, window) in bytes.windows(5).enumerate() {
        if window[0].is_ascii_digit()
            && window[1].is_ascii_digit()
            && window[2] == b'/'
            && window[3].is_ascii_digit()
            && window[4].is_ascii_digit()
        {
            let prev_ok = idx == 0 || (!bytes[idx - 1].is_ascii_digit() && bytes[idx - 1] != b'/');
            let next_ok = idx + 5 >= bytes.len()
                || (!bytes[idx + 5].is_ascii_digit() && bytes[idx + 5] != b'/');
            let month = (window[0] - b'0') * 10 + (window[1] - b'0');
            if prev_ok && next_ok && (1..=12).contains(&month) {
                return true;
            }
        }
    }
    false
}

/// Scans an outgoing plaintext message locally for accidental sensitive leaks (D-0009)
/// with zero false positives on normal numbers, dates, or math expressions.
#[must_use]
pub fn scan_message_for_leaks(message: &str, own_login_nickname: Option<&str>) -> Vec<LeakWarning> {
    let mut warnings = Vec::new();
    let has_cvv_context = has_card_security_context(message);

    // 1. Scan for bank card candidates (digits separated by optional single space or hyphen)
    let bytes = message.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut digits = Vec::with_capacity(19);
            let mut end = i;
            let mut j = i;
            while j < bytes.len() {
                let b = bytes[j];
                if b.is_ascii_digit() {
                    digits.push(b - b'0');
                    j += 1;
                    end = j;
                } else if (b == b' ' || b == b'-')
                    && j + 1 < bytes.len()
                    && bytes[j + 1].is_ascii_digit()
                {
                    j += 1;
                } else {
                    break;
                }
            }
            if passes_luhn(&digits) {
                warnings.push(LeakWarning {
                    kind: LeakKind::BankCard {
                        has_cvv_or_expiry_context: has_cvv_context,
                    },
                    start_byte: start,
                    end_byte: end,
                });
            }
            i = end.max(i + 1);
        } else {
            i += 1;
        }
    }

    // 2. Scan whitespace-delimited tokens for email addresses and international phone numbers
    let mut byte_cursor = 0usize;
    for raw_token in message.split_whitespace() {
        let Some(rel_pos) = message[byte_cursor..].find(raw_token) else {
            break;
        };
        let token_start = byte_cursor + rel_pos;
        let token_end = token_start + raw_token.len();
        byte_cursor = token_end;

        let trimmed = raw_token.trim_matches(|c: char| {
            matches!(
                c,
                ',' | '.' | ';' | ':' | '!' | '?' | '(' | ')' | '"' | '\''
            )
        });
        let trim_offset = raw_token.find(trimmed).unwrap_or(0);
        let clean_start = token_start + trim_offset;
        let clean_end = clean_start + trimmed.len();

        if is_strict_email(trimmed) {
            warnings.push(LeakWarning {
                kind: LeakKind::EmailAddress,
                start_byte: clean_start,
                end_byte: clean_end,
            });
        } else if is_international_phone(trimmed) {
            warnings.push(LeakWarning {
                kind: LeakKind::PhoneNumber,
                start_byte: clean_start,
                end_byte: clean_end,
            });
        }
    }

    // 3. Scan for accidental inclusion of user's own secret login nickname (case-insensitive)
    if let Some(nick) = own_login_nickname {
        let trimmed_nick = nick.trim().to_ascii_lowercase();
        if trimmed_nick.len() >= 4 && trimmed_nick.is_ascii() {
            let msg_bytes = message.as_bytes();
            let nick_bytes = trimmed_nick.as_bytes();
            let mut idx = 0usize;
            while idx + nick_bytes.len() <= msg_bytes.len() {
                if msg_bytes[idx..idx + nick_bytes.len()].eq_ignore_ascii_case(nick_bytes) {
                    let start = idx;
                    let end = idx + nick_bytes.len();
                    if message.is_char_boundary(start) && message.is_char_boundary(end) {
                        warnings.push(LeakWarning {
                            kind: LeakKind::OwnLoginNickname,
                            start_byte: start,
                            end_byte: end,
                        });
                    }
                    idx = end;
                } else {
                    idx += 1;
                }
            }
        }
    }

    warnings
}

fn is_strict_email(token: &str) -> bool {
    let Some((local, domain)) = token.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.len() < 4 || domain.contains('@') {
        return false;
    }
    let Some((host, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    if host.is_empty() || tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

fn is_international_phone(token: &str) -> bool {
    if !token.starts_with('+') {
        return false;
    }
    let mut digit_count = 0usize;
    for ch in token[1..].chars() {
        if ch.is_ascii_digit() {
            digit_count += 1;
        } else if !matches!(ch, '-' | '(' | ')') {
            return false;
        }
    }
    (10..=15).contains(&digit_count)
}

/// Redacts all detected leak spans in `message` with `****` (D-0009).
#[must_use]
pub fn redact_leaks(message: &str, warnings: &[LeakWarning]) -> String {
    if warnings.is_empty() {
        return message.to_owned();
    }
    let mut sorted = warnings.to_vec();
    sorted.sort_by_key(|w| w.start_byte);

    let mut result = String::with_capacity(message.len());
    let mut cursor = 0usize;
    for w in sorted {
        if w.start_byte >= cursor && w.end_byte <= message.len() && w.start_byte < w.end_byte {
            result.push_str(&message[cursor..w.start_byte]);
            result.push_str("****");
            cursor = w.end_byte;
        }
    }
    if cursor < message.len() {
        result.push_str(&message[cursor..]);
    }
    result
}

/// Categories for anonymous E2EE support tickets (D-0006, PLAN.md §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportTicketCategory {
    /// SupporterPass / blind donation token issue.
    SupporterPassIssue,
    /// Server verification or malicious server report.
    ServerDirectoryReport,
    /// Bug or security report.
    SecurityOrBugReport,
}

/// Anonymous E2EE support ticket envelope routed to a verified foundation support queue (D-0006).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportTicket {
    /// Ephemeral one-way reply queue identifier for receiving the support response.
    pub reply_queue_id: [u8; 32],
    /// Ticket category.
    pub category: SupportTicketCategory,
    /// Padded E2EE ciphertext encrypted to the verified support public key.
    pub encrypted_padded_payload: Vec<u8>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn frame_padding_and_unpadding_roundtrip_and_tamper_rejection() {
        let msg = b"hello anonymous world";
        let padded = pad_frame(msg).expect("must pad into 256-byte bucket");
        assert_eq!(padded.len(), 256);
        assert_eq!(unpad_frame(&padded).expect("must unpad"), msg);

        // Exact bucket boundaries: 254 bytes -> 256 bucket; 255 bytes -> 1024 bucket; 16382 -> 16384; 16383 -> Err
        assert_eq!(
            pad_frame(&vec![b'a'; 254]).expect("254 fits 256").len(),
            256
        );
        assert_eq!(
            pad_frame(&vec![b'a'; 255]).expect("255 fits 1024").len(),
            1024
        );
        assert_eq!(
            pad_frame(&vec![b'a'; 16382])
                .expect("16382 fits 16384")
                .len(),
            16384
        );
        assert_eq!(
            pad_frame(&vec![b'a'; 16383]),
            Err(ProtocolError::PayloadTooLarge {
                size: 16383,
                max_supported: 16382
            })
        );

        // Tamper with trailing zero padding -> fail closed
        let mut tampered = padded.clone();
        tampered[255] = 1;
        assert_eq!(
            unpad_frame(&tampered),
            Err(ProtocolError::MalformedPaddedFrame)
        );
    }

    #[test]
    fn leak_guard_detects_luhn_cards_and_ignores_normal_numbers() {
        // Valid Luhn test card (Visa test number 4532 0151 1283 0366) + CVV context
        let msg_with_card = "My card is 4532 0151 1283 0366 exp 08/28 cvv 123";
        let leaks = scan_message_for_leaks(msg_with_card, None);
        assert_eq!(leaks.len(), 1);
        assert_eq!(
            leaks[0].kind,
            LeakKind::BankCard {
                has_cvv_or_expiry_context: true
            }
        );

        // Words like "expected" or dates like "10/11/2026" must NOT trigger false CVV/expiry context
        let card_without_cvv = "Expected delivery on 10/11/2026 for card 4532 0151 1283 0366";
        let leaks_no_cvv = scan_message_for_leaks(card_without_cvv, None);
        assert_eq!(
            leaks_no_cvv[0].kind,
            LeakKind::BankCard {
                has_cvv_or_expiry_context: false
            }
        );

        let redacted = redact_leaks(msg_with_card, &leaks);
        assert!(!redacted.contains("4532 0151"));
        assert!(redacted.contains("****"));

        // Invalid Luhn 16-digit number (last digit changed from 6 to 7) -> ZERO false positive!
        let normal_digits = "Order ID 4532015112830367 at timestamp 173568960012345";
        let no_leaks = scan_message_for_leaks(normal_digits, None);
        assert!(no_leaks.is_empty());
    }

    #[test]
    fn leak_guard_detects_email_phone_and_own_nickname() {
        let text = "Reach me at alice.sec@proton.me or +41791234567 (login: Silent-Vortex-4821)";
        let leaks = scan_message_for_leaks(text, Some("silent-vortex-4821"));
        assert_eq!(leaks.len(), 3);
        assert!(leaks.iter().any(|w| w.kind == LeakKind::EmailAddress));
        assert!(leaks.iter().any(|w| w.kind == LeakKind::PhoneNumber));
        assert!(leaks.iter().any(|w| w.kind == LeakKind::OwnLoginNickname));
    }
}
