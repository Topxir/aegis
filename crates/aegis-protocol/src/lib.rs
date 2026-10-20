//! `aegis-protocol` — Wire framing with fixed metadata-hiding padding buckets (D-0002),
//! `LeakGuard` zero-false-positive local DLP scanner (D-0009), and encrypted support tickets (D-0006).

use core::cmp::Reverse;
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
    /// Ephemeral reply queue identifier must not be all-zero.
    InvalidReplyQueueId,
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
            Self::InvalidReplyQueueId => write!(f, "reply queue identifier must not be all-zero"),
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
    for word in lower.split(|c: char| !c.is_alphanumeric()) {
        if matches!(
            word,
            "cvv" | "cvc" | "cvv2" | "cvc2" | "exp" | "expiry" | "свв" | "код" | "срок"
        ) {
            return true;
        }
    }

    let bytes = lower.as_bytes();
    // Check for MM/YY pattern such as 08/28 or 12/29 with Unicode-safe boundaries
    for (idx, window) in bytes.windows(5).enumerate() {
        if window[0].is_ascii_digit()
            && window[1].is_ascii_digit()
            && window[2] == b'/'
            && window[3].is_ascii_digit()
            && window[4].is_ascii_digit()
            && lower.is_char_boundary(idx)
            && lower.is_char_boundary(idx + 5)
        {
            let prev_ok = idx == 0
                || !lower[..idx]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '/');
            let next_ok = idx + 5 >= lower.len()
                || !lower[idx + 5..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '/');
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
    let bytes = message.as_bytes();

    // 1. Scan for bank card candidates (digits separated by optional single space or hyphen)
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let left_ok = start == 0
                || !message[..start]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '+');

            if !left_ok {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                continue;
            }

            let mut digits = Vec::with_capacity(20);
            let mut end_offsets = Vec::with_capacity(20);
            let mut j = i;
            while j < bytes.len() && digits.len() < 19 {
                let b = bytes[j];
                if b.is_ascii_digit() {
                    digits.push(b - b'0');
                    j += 1;
                    end_offsets.push(j);
                } else if (b == b' ' || b == b'-')
                    && j + 1 < bytes.len()
                    && bytes[j + 1].is_ascii_digit()
                {
                    j += 1;
                } else {
                    break;
                }
            }

            // Prefer standard payment card lengths at token boundaries so a trailing 3-digit CVV
            // ("4532 0151 1283 0366 123") or expiry ("4532 0151 1283 0366 08/28") never hides the card.
            const PREFERRED_CARD_LENS: [usize; 7] = [16, 15, 19, 14, 13, 18, 17];
            let mut matched_end: Option<usize> = None;
            for &cand_len in &PREFERRED_CARD_LENS {
                if cand_len <= digits.len() {
                    let cand_end = end_offsets[cand_len - 1];
                    let right_ok = cand_end == message.len()
                        || !message[cand_end..]
                            .chars()
                            .next()
                            .is_some_and(char::is_alphanumeric);
                    if right_ok && passes_luhn(&digits[..cand_len]) {
                        matched_end = Some(cand_end);
                        break;
                    }
                }
            }

            if let Some(card_end) = matched_end {
                warnings.push(LeakWarning {
                    kind: LeakKind::BankCard {
                        has_cvv_or_expiry_context: has_cvv_context,
                    },
                    start_byte: start,
                    end_byte: card_end,
                });
                i = card_end;
            } else {
                // Advance only past the current contiguous digit run so subsequent groups are still checked.
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
        } else {
            i += 1;
        }
    }

    // 2. Scan for international phone numbers across the text (supporting spaces, hyphens, and balanced parens)
    let mut p = 0usize;
    while p < bytes.len() {
        if bytes[p] == b'+' {
            let left_ok = p == 0
                || !message[..p]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '+');
            if left_ok && p + 1 < bytes.len() && (b'1'..=b'9').contains(&bytes[p + 1]) {
                let mut cur = p + 1;
                let mut digit_count = 0usize;
                let mut in_parens = false;
                let mut digits_in_parens = 0usize;
                let mut best_end: Option<usize> = None;

                while cur < bytes.len() {
                    let b = bytes[cur];
                    if b.is_ascii_digit() {
                        digit_count += 1;
                        if digit_count > 15 {
                            break;
                        }
                        if in_parens {
                            digits_in_parens += 1;
                        }
                        cur += 1;
                        if !in_parens && (10..=15).contains(&digit_count) {
                            let next_is_alnum_or_decimal = cur < message.len()
                                && (message[cur..]
                                    .chars()
                                    .next()
                                    .is_some_and(char::is_alphanumeric)
                                    || (bytes[cur] == b'.'
                                        && cur + 1 < bytes.len()
                                        && bytes[cur + 1].is_ascii_digit()));
                            if !next_is_alnum_or_decimal {
                                best_end = Some(cur);
                            }
                        }
                    } else if b == b'('
                        && !in_parens
                        && cur > p + 1
                        && matches!(bytes[cur - 1], b' ' | b'-' | b'0'..=b'9')
                        && cur + 1 < bytes.len()
                        && bytes[cur + 1].is_ascii_digit()
                    {
                        in_parens = true;
                        digits_in_parens = 0;
                        cur += 1;
                    } else if b == b')'
                        && in_parens
                        && (1..=5).contains(&digits_in_parens)
                        && cur + 1 < bytes.len()
                        && matches!(bytes[cur + 1], b' ' | b'-' | b'0'..=b'9')
                    {
                        in_parens = false;
                        cur += 1;
                    } else if (b == b' ' || b == b'-')
                        && !in_parens
                        && cur > p + 1
                        && matches!(bytes[cur - 1], b'0'..=b'9' | b')')
                        && cur + 1 < bytes.len()
                        && (bytes[cur + 1].is_ascii_digit() || bytes[cur + 1] == b'(')
                    {
                        cur += 1;
                    } else {
                        break;
                    }
                }

                // Only accept if we didn't overflow 15 contiguous digits in the same number
                let overflowed_digits = digit_count > 15;
                if !overflowed_digits {
                    if let Some(phone_end) = best_end {
                        if is_international_phone(&message[p..phone_end]) {
                            warnings.push(LeakWarning {
                                kind: LeakKind::PhoneNumber,
                                start_byte: p,
                                end_byte: phone_end,
                            });
                            p = phone_end;
                            continue;
                        }
                    }
                }
            }
        }
        p += 1;
    }

    // 3. Scan whitespace-delimited tokens for email addresses
    let mut byte_cursor = 0usize;
    for raw_token in message.split_whitespace() {
        let Some(rel_pos) = message[byte_cursor..].find(raw_token) else {
            break;
        };
        let token_start = byte_cursor + rel_pos;
        let token_end = token_start + raw_token.len();
        byte_cursor = token_end;

        let left_trimmed = raw_token.trim_start_matches(|c: char| {
            matches!(
                c,
                ',' | ';' | ':' | '!' | '?' | '(' | '[' | '<' | '"' | '\''
            )
        });
        let right_trimmed = left_trimmed.trim_end_matches(|c: char| {
            matches!(
                c,
                ',' | ';' | ':' | '!' | '?' | ')' | ']' | '>' | '"' | '\''
            )
        });
        // Strip at most a single sentence-ending period so `..` remains invalid
        let trimmed = right_trimmed.strip_suffix('.').unwrap_or(right_trimmed);
        let trim_offset = raw_token.len() - left_trimmed.len();
        let clean_start = token_start + trim_offset;
        let clean_end = clean_start + trimmed.len();

        if is_strict_email(trimmed) {
            warnings.push(LeakWarning {
                kind: LeakKind::EmailAddress,
                start_byte: clean_start,
                end_byte: clean_end,
            });
        }
    }

    // 4. Scan for accidental inclusion of user's own secret login nickname (case-insensitive, word-bounded)
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
                        let left_ok = start == 0
                            || !message[..start]
                                .chars()
                                .next_back()
                                .is_some_and(char::is_alphanumeric);
                        let right_ok = end == message.len()
                            || !message[end..]
                                .chars()
                                .next()
                                .is_some_and(char::is_alphanumeric);
                        if left_ok && right_ok {
                            warnings.push(LeakWarning {
                                kind: LeakKind::OwnLoginNickname,
                                start_byte: start,
                                end_byte: end,
                            });
                            idx = end;
                            continue;
                        }
                    }
                }
                idx += 1;
            }
        }
    }

    warnings
}

fn is_strict_email(token: &str) -> bool {
    let Some((local, domain)) = token.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || local.len() > 64
        || domain.len() < 4
        || domain.len() > 253
        || domain.contains('@')
    {
        return false;
    }
    if local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
    {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return false;
        }
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn is_international_phone(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.len() < 11
        || bytes[0] != b'+'
        || !(b'1'..=b'9').contains(&bytes[1])
        || !bytes[bytes.len() - 1].is_ascii_digit()
    {
        return false;
    }

    let mut digit_count = 0usize;
    let mut in_parens = false;
    let mut digits_in_parens = 0usize;
    let mut prev_sep = false;

    for &b in &bytes[1..] {
        if b.is_ascii_digit() {
            digit_count += 1;
            if in_parens {
                digits_in_parens += 1;
            }
            prev_sep = false;
        } else if b == b'(' {
            if in_parens {
                return false;
            }
            in_parens = true;
            digits_in_parens = 0;
            prev_sep = true;
        } else if b == b')' {
            if !in_parens || !(1..=5).contains(&digits_in_parens) {
                return false;
            }
            in_parens = false;
            prev_sep = false;
        } else if b == b' ' || b == b'-' {
            if in_parens || prev_sep {
                return false;
            }
            prev_sep = true;
        } else {
            return false;
        }
    }

    !in_parens && !prev_sep && (10..=15).contains(&digit_count)
}

/// Redacts all detected leak spans in `message` with `****` (D-0009).
/// Safely merges overlapping/adjacent spans and ignores out-of-bounds or non-UTF-8 boundary offsets.
#[must_use]
pub fn redact_leaks(message: &str, warnings: &[LeakWarning]) -> String {
    let mut valid_spans: Vec<(usize, usize)> = warnings
        .iter()
        .filter(|w| {
            w.start_byte < w.end_byte
                && w.end_byte <= message.len()
                && message.is_char_boundary(w.start_byte)
                && message.is_char_boundary(w.end_byte)
        })
        .map(|w| (w.start_byte, w.end_byte))
        .collect();

    if valid_spans.is_empty() {
        return message.to_owned();
    }

    valid_spans.sort_by_key(|&(start, end)| (start, Reverse(end)));

    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(valid_spans.len());
    for (start, end) in valid_spans {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }

    let mut result = String::with_capacity(message.len());
    let mut cursor = 0usize;
    for (start, end) in merged {
        result.push_str(&message[cursor..start]);
        result.push_str("****");
        cursor = end;
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

impl SupportTicket {
    /// Constructs a validated anonymous support ticket envelope.
    ///
    /// # Errors
    /// Fail-closed: rejects all-zero `reply_queue_id` (`[0u8; 32]`) and payloads whose length
    /// does not match one of [`PADDING_BUCKETS`].
    pub fn new(
        reply_queue_id: [u8; 32],
        category: SupportTicketCategory,
        encrypted_padded_payload: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if reply_queue_id == [0u8; 32] {
            return Err(ProtocolError::InvalidReplyQueueId);
        }
        if !PADDING_BUCKETS.contains(&encrypted_padded_payload.len()) {
            return Err(ProtocolError::MalformedPaddedFrame);
        }
        Ok(Self {
            reply_queue_id,
            category,
            encrypted_padded_payload,
        })
    }
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

    #[test]
    fn b0001_card_detected_when_followed_by_space_and_cvv_or_expiry() {
        let msg_cvv = "Моя карта 4532 0151 1283 0366 123";
        let leaks_cvv = scan_message_for_leaks(msg_cvv, None);
        assert_eq!(leaks_cvv.len(), 1);
        assert_eq!(
            &msg_cvv[leaks_cvv[0].start_byte..leaks_cvv[0].end_byte],
            "4532 0151 1283 0366"
        );

        let msg_exp = "Card: 4532 0151 1283 0366 08/28";
        let leaks_exp = scan_message_for_leaks(msg_exp, None);
        assert_eq!(leaks_exp.len(), 1);
        assert_eq!(
            leaks_exp[0].kind,
            LeakKind::BankCard {
                has_cvv_or_expiry_context: true
            }
        );
        assert_eq!(
            &msg_exp[leaks_exp[0].start_byte..leaks_exp[0].end_byte],
            "4532 0151 1283 0366"
        );
    }

    #[test]
    fn b0002_international_phone_with_spaces_detected_and_malformed_rejected() {
        let msg = "Звони на +7 (999) 123-45-67 или +1 800 555 0199.";
        let leaks = scan_message_for_leaks(msg, None);
        let phones: Vec<&str> = leaks
            .iter()
            .filter(|w| w.kind == LeakKind::PhoneNumber)
            .map(|w| &msg[w.start_byte..w.end_byte])
            .collect();
        assert_eq!(phones, vec!["+7 (999) 123-45-67", "+1 800 555 0199"]);

        // Reject +0..., unbalanced parentheses, and float literals
        let invalid = "Not phones: +01234567890 +(((1234567890 +1234567890.5";
        assert!(scan_message_for_leaks(invalid, None).is_empty());
    }

    #[test]
    fn b0003_redact_leaks_merges_overlapping_spans_and_ignores_non_char_boundaries() {
        let msg = "Write to silent-vortex-4821@proton.me now";
        let leaks = scan_message_for_leaks(msg, Some("silent-vortex-4821"));
        assert_eq!(leaks.len(), 2); // EmailAddress + OwnLoginNickname overlap
        let redacted = redact_leaks(msg, &leaks);
        assert_eq!(redacted, "Write to **** now");
        assert!(!redacted.contains("proton.me"));

        // Non-UTF8 char boundary inside Cyrillic text must never panic
        let cyrillic = "Привет";
        let bad_warning = LeakWarning {
            kind: LeakKind::OwnLoginNickname,
            start_byte: 1, // mid-character in 2-byte UTF-8 'П'
            end_byte: 3,
        };
        assert_eq!(redact_leaks(cyrillic, &[bad_warning]), "Привет");
    }

    #[test]
    fn b0004_card_security_context_unicode_boundaries_and_russian_keywords() {
        // Russian CVV keyword "свв" and "код"
        let ru_card = "Карта 4532 0151 1283 0366 свв 999";
        let leaks = scan_message_for_leaks(ru_card, None);
        assert_eq!(
            leaks[0].kind,
            LeakKind::BankCard {
                has_cvv_or_expiry_context: true
            }
        );

        // Cyrillic character immediately preceding "exp" must NOT count as a word boundary
        let glued = "Приветexp 4532 0151 1283 0366";
        let leaks_glued = scan_message_for_leaks(glued, None);
        assert_eq!(
            leaks_glued[0].kind,
            LeakKind::BankCard {
                has_cvv_or_expiry_context: false
            }
        );
    }

    #[test]
    fn b0005_nickname_word_boundaries_and_strict_email_dots_and_hyphens() {
        // Nickname "mark" must not trigger inside "supermarket"
        let msg = "Going to the supermarket today";
        assert!(scan_message_for_leaks(msg, Some("mark")).is_empty());

        // Malformed emails with leading/trailing/consecutive dots or hyphen labels must be rejected
        for bad_email in [
            "..@a.com",
            ".user@a.com",
            "user.@a.com",
            "us..er@a.com",
            "user@-domain.com",
            "user@domain-.com",
            "user@domain..com",
        ] {
            assert!(
                scan_message_for_leaks(bad_email, None).is_empty(),
                "must reject {bad_email}"
            );
        }
    }

    #[test]
    fn b0006_support_ticket_validates_queue_id_and_padding_bucket() {
        let valid_payload = pad_frame(b"encrypted ticket body").unwrap();
        assert_eq!(
            SupportTicket::new(
                [0u8; 32],
                SupportTicketCategory::SecurityOrBugReport,
                valid_payload.clone()
            ),
            Err(ProtocolError::InvalidReplyQueueId)
        );
        assert_eq!(
            SupportTicket::new(
                [0x11; 32],
                SupportTicketCategory::SecurityOrBugReport,
                vec![1, 2, 3]
            ),
            Err(ProtocolError::MalformedPaddedFrame)
        );
        assert!(SupportTicket::new(
            [0x11; 32],
            SupportTicketCategory::SecurityOrBugReport,
            valid_payload
        )
        .is_ok());
    }
}
