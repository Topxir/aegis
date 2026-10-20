//! `aegis-protocol` — Wire framing with fixed metadata-hiding padding buckets (D-0002),
//! `LeakGuard` zero-false-positive local DLP scanner (D-0009), and encrypted support tickets (D-0006).

use aegis_crypto::{aead_open, aead_seal, constant_time_eq, hkdf_sha256, sha256, ZeroizingBuffer};
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

// ============================================================================
// EXIF / GPS / XMP Media Metadata Stripper (D-0015)
// ============================================================================

/// Result of stripping EXIF/GPS/XMP/comment metadata from an outgoing media file (D-0015).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanedMedia {
    /// Sanitized media bytes with all privacy-leaking metadata segments removed.
    pub bytes: Vec<u8>,
    /// Number of metadata segments/chunks stripped from the file.
    pub stripped_segments_count: usize,
}

/// Strips EXIF, GPS, XMP, ICC, and comment metadata segments from JPEG (`0xFF 0xD8`)
/// and PNG (`\x89PNG\r\n\x1a\n`) images before encryption so camera serial numbers
/// and GPS coordinates never leak to contacts (D-0015).
///
/// # Errors
/// Fail-closed: returns [`ProtocolError::MalformedPaddedFrame`] if the media container is empty or truncated.
pub fn strip_media_metadata(media_bytes: &[u8]) -> Result<CleanedMedia, ProtocolError> {
    if media_bytes.is_empty() {
        return Err(ProtocolError::MalformedPaddedFrame);
    }

    // 1. JPEG container: SOI = 0xFF 0xD8
    if media_bytes.len() >= 4 && media_bytes[0] == 0xFF && media_bytes[1] == 0xD8 {
        let mut out = Vec::with_capacity(media_bytes.len());
        out.push(0xFF);
        out.push(0xD8);
        let mut stripped = 0usize;
        let mut i = 2usize;
        let mut saw_sos = false;
        let mut saw_eoi = false;

        while i < media_bytes.len() {
            if media_bytes[i] != 0xFF {
                return Err(ProtocolError::MalformedPaddedFrame);
            }
            while i < media_bytes.len() && media_bytes[i] == 0xFF {
                i += 1;
            }
            if i >= media_bytes.len() {
                return Err(ProtocolError::MalformedPaddedFrame);
            }
            let marker = media_bytes[i];
            i += 1;

            if marker == 0x00 || marker == 0xD8 {
                return Err(ProtocolError::MalformedPaddedFrame);
            }

            // EOI (End of Image)
            if marker == 0xD9 {
                if !saw_sos || i != media_bytes.len() {
                    return Err(ProtocolError::MalformedPaddedFrame);
                }
                out.push(0xFF);
                out.push(0xD9);
                saw_eoi = true;
                break;
            }
            // Standalone markers without length (RST0..RST7, TEM)
            if (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
                out.push(0xFF);
                out.push(marker);
                continue;
            }

            let len_end = i
                .checked_add(2)
                .ok_or(ProtocolError::MalformedPaddedFrame)?;
            if len_end > media_bytes.len() {
                return Err(ProtocolError::MalformedPaddedFrame);
            }
            let seg_len = usize::from(u16::from_be_bytes([media_bytes[i], media_bytes[i + 1]]));
            let next_i = i
                .checked_add(seg_len)
                .ok_or(ProtocolError::MalformedPaddedFrame)?;
            if seg_len < 2 || next_i > media_bytes.len() {
                return Err(ProtocolError::MalformedPaddedFrame);
            }

            // Strip APP0..APP15 (0xE0..=0xEF: JFIF, EXIF, GPS, XMP, Adobe, ICC) and COM (0xFE)
            if (0xE0..=0xEF).contains(&marker) || marker == 0xFE {
                stripped = stripped.saturating_add(1);
                i = next_i;
                continue;
            }

            out.push(0xFF);
            out.push(marker);
            out.extend_from_slice(&media_bytes[i..next_i]);
            i = next_i;

            // SOS (Start of Scan, 0xDA): scan entropy-coded data (skipping 0xFF 0x00 and RST0..RST7)
            // until the next real marker so post-SOS or inter-scan APPn/COM segments are also stripped.
            if marker == 0xDA {
                saw_sos = true;
                while i < media_bytes.len() {
                    let b = media_bytes[i];
                    if b != 0xFF {
                        out.push(b);
                        i += 1;
                        continue;
                    }
                    if i + 1 >= media_bytes.len() {
                        return Err(ProtocolError::MalformedPaddedFrame);
                    }
                    let next_b = media_bytes[i + 1];
                    if next_b == 0x00 || (0xD0..=0xD7).contains(&next_b) {
                        out.push(0xFF);
                        out.push(next_b);
                        i += 2;
                    } else {
                        break;
                    }
                }
            }
        }

        if !saw_sos || !saw_eoi {
            return Err(ProtocolError::MalformedPaddedFrame);
        }

        return Ok(CleanedMedia {
            bytes: out,
            stripped_segments_count: stripped,
        });
    }

    // 2. PNG container: \x89PNG\r\n\x1a\n
    const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if media_bytes.len() >= 8 && media_bytes[0..8] == PNG_SIG {
        let mut out = Vec::with_capacity(media_bytes.len());
        out.extend_from_slice(&PNG_SIG);
        let mut stripped = 0usize;
        let mut i = 8usize;
        let mut chunk_index = 0usize;
        let mut saw_idat = false;
        let mut saw_iend = false;

        while i < media_bytes.len() {
            let header_end = i
                .checked_add(12)
                .ok_or(ProtocolError::MalformedPaddedFrame)?;
            if header_end > media_bytes.len() {
                return Err(ProtocolError::MalformedPaddedFrame);
            }
            let data_len = u32::from_be_bytes([
                media_bytes[i],
                media_bytes[i + 1],
                media_bytes[i + 2],
                media_bytes[i + 3],
            ]) as usize;
            let chunk_type = &media_bytes[i + 4..i + 8];
            if chunk_index == 0 {
                if chunk_type != b"IHDR" || data_len != 13 {
                    return Err(ProtocolError::MalformedPaddedFrame);
                }
            } else if chunk_type == b"IHDR" {
                return Err(ProtocolError::MalformedPaddedFrame);
            }
            let total_chunk = 12usize
                .checked_add(data_len)
                .ok_or(ProtocolError::MalformedPaddedFrame)?;
            let next_i = i
                .checked_add(total_chunk)
                .ok_or(ProtocolError::MalformedPaddedFrame)?;
            if next_i > media_bytes.len() {
                return Err(ProtocolError::MalformedPaddedFrame);
            }

            if chunk_type == b"IDAT" {
                if data_len == 0 {
                    return Err(ProtocolError::MalformedPaddedFrame);
                }
                saw_idat = true;
            }

            if matches!(chunk_type, b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt" | b"tIME") {
                stripped = stripped.saturating_add(1);
            } else {
                out.extend_from_slice(&media_bytes[i..next_i]);
            }
            i = next_i;
            chunk_index += 1;
            if chunk_type == b"IEND" {
                if data_len != 0 || i != media_bytes.len() {
                    return Err(ProtocolError::MalformedPaddedFrame);
                }
                saw_iend = true;
                break;
            }
        }

        if !saw_iend || !saw_idat {
            return Err(ProtocolError::MalformedPaddedFrame);
        }

        return Ok(CleanedMedia {
            bytes: out,
            stripped_segments_count: stripped,
        });
    }

    // Fail-closed: unknown/unhandled media formats are rejected so unparsed metadata (WebP/HEIC/TIFF/PDF) never leaks
    Err(ProtocolError::MalformedPaddedFrame)
}

// ============================================================================
// View-Once Media, Disappearing Timers, and Rich Message Types (D-0015, D-0016)
// ============================================================================

/// Per-message or per-chat expiration policy (D-0015, PLAN.md §9, §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageExpirationPolicy {
    /// Message does not expire automatically.
    Never,
    /// Message expires `seconds` after being read (e.g., 5s, 60s, 3600s, 86400s, 604800s).
    AfterReadSecs(u32),
    /// View-once payload: immediately zeroized and destroyed after the first read.
    ViewOnce,
}

/// Self-destructing container for a `ViewOnce` media or text payload (D-0015).
#[derive(Debug)]
pub struct ViewOncePayload {
    secret_payload: ZeroizingBuffer,
    consumed: bool,
}

impl ViewOncePayload {
    /// Wraps plaintext bytes in a view-once self-destructing container.
    #[must_use]
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            secret_payload: ZeroizingBuffer::new(payload),
            consumed: false,
        }
    }

    /// Returns `true` if the payload has already been opened and zeroized.
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
}

/// Opens a [`ViewOncePayload`] exactly once, immediately zeroizing the stored buffer so it can
/// never be read a second time (D-0015).
///
/// # Errors
/// Returns [`ProtocolError::MalformedPaddedFrame`] if the payload was already viewed.
pub fn open_view_once_payload(
    container: &mut ViewOncePayload,
) -> Result<ZeroizingBuffer, ProtocolError> {
    if container.consumed {
        return Err(ProtocolError::MalformedPaddedFrame);
    }
    let extracted = ZeroizingBuffer::new(container.secret_payload.as_slice().to_vec());
    container.secret_payload.zeroize();
    container.consumed = true;
    Ok(extracted)
}

/// Rich E2EE message content variants supported by Aegis (PLAN.md §14, D-0015, D-0016).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageContent {
    /// Standard UTF-8 text message.
    Text(String),
    /// Encrypted voice message with waveform preview and optional pitch-shift anonymization (D-0016).
    VoiceNote {
        /// Duration in milliseconds.
        duration_ms: u32,
        /// Normalized 0..=100 waveform amplitude bars.
        waveform_peaks: Vec<u8>,
        /// True if formant/pitch voice anonymization was applied before encoding (D-0016).
        pitch_anonymized: bool,
        /// Per-attachment encrypted audio payload.
        encrypted_audio: Vec<u8>,
    },
    /// Circular instant video message ("видео-кружок").
    VideoCircle {
        /// Duration in milliseconds.
        duration_ms: u32,
        /// Display diameter in pixels.
        diameter_px: u16,
        /// Per-attachment encrypted video payload.
        encrypted_video: Vec<u8>,
    },
    /// Separately encrypted file attachment with per-file AEAD key and SHA-256 integrity digest (PLAN.md §9).
    FileAttachment {
        /// Sanitized filename without path traversal characters.
        filename: String,
        /// MIME type.
        mime_type: String,
        /// Unique 32-byte per-file AEAD encryption key.
        file_key: [u8; 32],
        /// SHA-256 digest of the encrypted file blob.
        sha256_digest: [u8; 32],
        /// Encrypted file size in bytes.
        size_bytes: u64,
    },
    /// Deterministic sticker reference.
    Sticker {
        /// Sticker pack identifier.
        pack_id: [u8; 16],
        /// Sticker index within the pack.
        sticker_id: u32,
    },
    /// Reaction to an existing message in the chat.
    Reaction {
        /// Target message identifier.
        target_message_id: [u8; 32],
        /// Reaction emoji.
        emoji: String,
    },
    /// Quoted reply to a specific message.
    Reply {
        /// Referenced message identifier.
        reply_to_message_id: [u8; 32],
        /// Reply body text.
        text: String,
    },
    /// In-place edit of a previously sent message.
    Edit {
        /// Target message identifier.
        target_message_id: [u8; 32],
        /// Updated message text.
        new_text: String,
    },
    /// Notification that the conversation's disappearing message timer was updated.
    DisappearingTimerChange {
        /// New expiration policy for the chat.
        new_policy: MessageExpirationPolicy,
    },
}

/// High-level E2EE chat message envelope combining rich content and expiration policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessageEnvelope {
    /// Unique message identifier.
    pub message_id: [u8; 32],
    /// Rich message content.
    pub content: MessageContent,
    /// Expiration policy (`Never`, `AfterReadSecs`, `ViewOnce`).
    pub expiration: MessageExpirationPolicy,
    /// Sender timestamp (Unix seconds).
    pub sent_at_unix_secs: u64,
}

// ============================================================================
// One-Time Invite Links / QR Payloads & 60-Digit Safety Numbers (PLAN.md §7.1)
// ============================================================================

/// One-time or bounded-use contact invitation payload encoded in `aegis://invite/...` links and QR codes (PLAN.md §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactInvite {
    /// Recipient's federation server endpoint (hostname:port or `.onion`).
    pub server_endpoint: String,
    /// Anonymous unidirectional queue identifier for initial handshake delivery.
    pub recipient_queue_id: [u8; 32],
    /// Classical X25519 ephemeral prekey.
    pub x25519_public: [u8; 32],
    /// SHA-256 commitment of the post-quantum ML-KEM-768 encapsulation key.
    pub ml_kem_public_hash: [u8; 32],
    /// Expiration timestamp (Unix seconds).
    pub expires_at_unix_secs: u64,
    /// Maximum allowed activations (1 = strict one-time link).
    pub max_activations: u16,
    /// If true, this invite may only be scanned via in-person offline QR (PLAN.md §14).
    pub offline_qr_only: bool,
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0F)]));
    }
    s
}

fn hex_decode_32(hex_str: &str) -> Result<[u8; 32], ProtocolError> {
    if hex_str.len() != 64 {
        return Err(ProtocolError::MalformedPaddedFrame);
    }
    let mut out = [0u8; 32];
    let bytes = hex_str.as_bytes();
    for i in 0..32 {
        let hi = (bytes[i * 2] as char)
            .to_digit(16)
            .ok_or(ProtocolError::MalformedPaddedFrame)?;
        let lo = (bytes[i * 2 + 1] as char)
            .to_digit(16)
            .ok_or(ProtocolError::MalformedPaddedFrame)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

fn is_valid_invite_endpoint(endpoint: &str) -> bool {
    if endpoint.is_empty() || endpoint.len() > 253 {
        return false;
    }
    let Some((host, port_str)) = endpoint.rsplit_once(':') else {
        return false;
    };
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return false;
    }
    let Ok(port) = port_str.parse::<u16>() else {
        return false;
    };
    port > 0
}

impl ContactInvite {
    /// Serializes the invite into a self-contained `aegis://invite/v1/...` URI string.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if any key/queue is all-zero, `max_activations == 0`, or the server endpoint is empty/invalid.
    pub fn to_uri(&self) -> Result<String, ProtocolError> {
        let endpoint = self.server_endpoint.trim();
        if !is_valid_invite_endpoint(endpoint)
            || self.recipient_queue_id == [0u8; 32]
            || self.x25519_public == [0u8; 32]
            || self.ml_kem_public_hash == [0u8; 32]
            || self.max_activations == 0
        {
            return Err(ProtocolError::InvalidReplyQueueId);
        }
        let qr_flag = u8::from(self.offline_qr_only);
        Ok(format!(
            "aegis://invite/v1/{}/{}/{}/{}/{}/{}/{}",
            endpoint,
            hex_encode(&self.recipient_queue_id),
            hex_encode(&self.x25519_public),
            hex_encode(&self.ml_kem_public_hash),
            self.expires_at_unix_secs,
            self.max_activations,
            qr_flag
        ))
    }

    /// Parses and validates an `aegis://invite/v1/...` URI string at `current_unix_secs`.
    ///
    /// # Errors
    /// Fail-closed: rejects expired invites, zero keys, or malformed URI segments.
    pub fn from_uri(uri: &str, current_unix_secs: u64) -> Result<Self, ProtocolError> {
        let Some(rest) = uri.trim().strip_prefix("aegis://invite/v1/") else {
            return Err(ProtocolError::MalformedPaddedFrame);
        };
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() != 7 || !is_valid_invite_endpoint(parts[0]) {
            return Err(ProtocolError::MalformedPaddedFrame);
        }
        let recipient_queue_id = hex_decode_32(parts[1])?;
        let x25519_public = hex_decode_32(parts[2])?;
        let ml_kem_public_hash = hex_decode_32(parts[3])?;
        let expires_at_unix_secs = parts[4]
            .parse::<u64>()
            .map_err(|_| ProtocolError::MalformedPaddedFrame)?;
        let max_activations = parts[5]
            .parse::<u16>()
            .map_err(|_| ProtocolError::MalformedPaddedFrame)?;
        let offline_qr_only = match parts[6] {
            "0" => false,
            "1" => true,
            _ => return Err(ProtocolError::MalformedPaddedFrame),
        };

        if recipient_queue_id == [0u8; 32]
            || x25519_public == [0u8; 32]
            || ml_kem_public_hash == [0u8; 32]
            || max_activations == 0
            || current_unix_secs > expires_at_unix_secs
        {
            return Err(ProtocolError::InvalidReplyQueueId);
        }

        Ok(Self {
            server_endpoint: parts[0].to_owned(),
            recipient_queue_id,
            x25519_public,
            ml_kem_public_hash,
            expires_at_unix_secs,
            max_activations,
            offline_qr_only,
        })
    }
}

/// Computes an order-independent 60-digit numeric Safety Number (12 groups of 5 digits)
/// from two peers' 32-byte identity public keys for QR/manual verification (PLAN.md §7.1).
#[must_use]
pub fn compute_safety_number(our_ik: &[u8; 32], peer_ik: &[u8; 32]) -> String {
    let (first, second) = if our_ik <= peer_ik {
        (our_ik, peer_ik)
    } else {
        (peer_ik, our_ik)
    };
    let mut combined = [0u8; 64];
    combined[0..32].copy_from_slice(first);
    combined[32..64].copy_from_slice(second);

    let d1 = sha256(&combined);
    let d2 = sha256(&d1);

    let mut groups = Vec::with_capacity(12);
    for i in 0..12 {
        let src = if i < 6 { &d1 } else { &d2 };
        let offset = (i % 6) * 5;
        let chunk = u32::from_be_bytes([
            src[offset],
            src[offset + 1],
            src[offset + 2],
            src[offset + 3],
        ]) % 100_000;
        groups.push(format!("{chunk:05}"));
    }
    groups.join(" ")
}

/// Tamper-detection warning emitted when a contact's identity key changes unexpectedly (PLAN.md §7.1, §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChangeWarning {
    /// Previously pinned 32-byte identity key.
    pub previous_identity_key: [u8; 32],
    /// Newly presented 32-byte identity key.
    pub new_identity_key: [u8; 32],
}

/// Checks if a peer's identity key changed compared to the pinned key in storage.
#[must_use]
pub fn detect_identity_key_change(
    pinned_key: Option<&[u8; 32]>,
    presented_key: &[u8; 32],
) -> Option<KeyChangeWarning> {
    let prev = pinned_key?;
    if constant_time_eq(prev, presented_key) {
        None
    } else {
        Some(KeyChangeWarning {
            previous_identity_key: *prev,
            new_identity_key: *presented_key,
        })
    }
}

// ============================================================================
// MLS-Style Epoch Group Chat Session (PLAN.md §5, §13 Phase 6)
// ============================================================================

/// MLS-style epoch-based E2EE group chat state with automatic key rotation on membership changes.
#[derive(Debug, Clone)]
pub struct GroupChatSession {
    group_id: [u8; 32],
    epoch: u64,
    members: Vec<[u8; 32]>,
    epoch_secret: ZeroizingBuffer,
}

impl GroupChatSession {
    /// Creates a new E2EE group session at `epoch = 1` with `creator_ik` as the initial member.
    ///
    /// # Errors
    /// Returns [`ProtocolError::InvalidReplyQueueId`] if `group_id`, `creator_ik`, or `initial_secret` is all-zero.
    pub fn new(
        group_id: [u8; 32],
        creator_ik: [u8; 32],
        initial_secret: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        if group_id == [0u8; 32] || creator_ik == [0u8; 32] || initial_secret == [0u8; 32] {
            return Err(ProtocolError::InvalidReplyQueueId);
        }
        Ok(Self {
            group_id,
            epoch: 1,
            members: vec![creator_ik],
            epoch_secret: ZeroizingBuffer::new(initial_secret.to_vec()),
        })
    }

    /// Returns the current MLS epoch counter.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the current member identity keys.
    #[must_use]
    pub fn members(&self) -> &[[u8; 32]] {
        &self.members
    }

    fn rotate_epoch_secret(&mut self, update_entropy: &[u8; 32]) -> Result<u64, ProtocolError> {
        if update_entropy == &[0u8; 32] {
            return Err(ProtocolError::InvalidReplyQueueId);
        }
        let next_epoch = self.epoch.saturating_add(1);
        let mut next_secret = [0u8; 32];
        hkdf_sha256(
            self.epoch_secret.as_slice(),
            update_entropy,
            &next_epoch.to_be_bytes(),
            &mut next_secret,
        )
        .map_err(|_| ProtocolError::MalformedPaddedFrame)?;
        self.epoch = next_epoch;
        self.epoch_secret = ZeroizingBuffer::new(next_secret.to_vec());
        next_secret.fill(0);
        Ok(self.epoch)
    }

    /// Adds a member and advances the group to `epoch + 1` with a freshly derived epoch key.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if `member_ik` or `update_entropy` is all-zero or already a member.
    pub fn add_member(
        &mut self,
        member_ik: [u8; 32],
        update_entropy: &[u8; 32],
    ) -> Result<u64, ProtocolError> {
        if member_ik == [0u8; 32]
            || update_entropy == &[0u8; 32]
            || self.members.contains(&member_ik)
        {
            return Err(ProtocolError::InvalidReplyQueueId);
        }
        let epoch = self.rotate_epoch_secret(update_entropy)?;
        self.members.push(member_ik);
        Ok(epoch)
    }

    /// Removes a member and advances the group to `epoch + 1` so the removed member cannot decrypt
    /// any future messages (post-compromise & forward secrecy).
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if the member is not found, `update_entropy` is all-zero, or would leave the group empty.
    pub fn remove_member(
        &mut self,
        member_ik: &[u8; 32],
        update_entropy: &[u8; 32],
    ) -> Result<u64, ProtocolError> {
        if self.members.len() <= 1 || update_entropy == &[0u8; 32] {
            return Err(ProtocolError::InvalidReplyQueueId);
        }
        let Some(pos) = self.members.iter().position(|m| m == member_ik) else {
            return Err(ProtocolError::InvalidReplyQueueId);
        };
        let epoch = self.rotate_epoch_secret(update_entropy)?;
        self.members.remove(pos);
        Ok(epoch)
    }

    /// Encrypts and pads a group message bound to the current `(group_id, epoch)`.
    ///
    /// # Errors
    /// Propagates any [`ProtocolError`] from encryption or bucket padding.
    pub fn seal_group_message(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut key = [0u8; 32];
        key.copy_from_slice(self.epoch_secret.as_slice());
        let mut aad = [0u8; 40];
        aad[0..32].copy_from_slice(&self.group_id);
        aad[32..40].copy_from_slice(&self.epoch.to_be_bytes());
        let ct = aead_seal(&key, nonce, &aad, plaintext)
            .map_err(|_| ProtocolError::MalformedPaddedFrame)?;
        key.fill(0);
        pad_frame(&ct)
    }

    /// Unpads, verifies, and decrypts a group message for the current `(group_id, epoch)`.
    ///
    /// # Errors
    /// Fail-closed: rejects messages from a different epoch or tampered frames.
    pub fn open_group_message(
        &self,
        nonce: &[u8; 12],
        padded_frame: &[u8],
    ) -> Result<ZeroizingBuffer, ProtocolError> {
        let ct = unpad_frame(padded_frame)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(self.epoch_secret.as_slice());
        let mut aad = [0u8; 40];
        aad[0..32].copy_from_slice(&self.group_id);
        aad[32..40].copy_from_slice(&self.epoch.to_be_bytes());
        let res = aead_open(&key, nonce, &aad, ct).map_err(|_| ProtocolError::MalformedPaddedFrame);
        key.fill(0);
        res
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

    #[test]
    fn exif_and_gps_metadata_stripper_cleans_jpeg_and_png() {
        // Synthetic JPEG: SOI (FF D8) + APP1 EXIF/GPS (FF E1 00 08 "Exif\0\0") + COM (FF FE 00 05 "gps")
        // + DQT (FF DB 00 04 01 02) + SOS (FF DA 00 04 00 00) + scan bytes (AA BB) + EOI (FF D9)
        let jpeg_with_exif: Vec<u8> = vec![
            0xFF, 0xD8, // SOI
            0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00, // APP1 EXIF
            0xFF, 0xFE, 0x00, 0x05, b'g', b'p', b's', // COM comment
            0xFF, 0xDB, 0x00, 0x04, 0x01, 0x02, // DQT kept
            0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00, // SOS kept
            0xAA, 0xBB, 0xFF, 0xD9, // scan data + EOI
        ];
        let cleaned_jpeg = strip_media_metadata(&jpeg_with_exif).unwrap();
        assert_eq!(cleaned_jpeg.stripped_segments_count, 2);
        assert!(!cleaned_jpeg.bytes.windows(4).any(|w| w == b"Exif"));
        assert!(!cleaned_jpeg.bytes.windows(3).any(|w| w == b"gps"));
        assert!(cleaned_jpeg.bytes.ends_with(&[0xAA, 0xBB, 0xFF, 0xD9]));

        // Synthetic PNG: Signature + IHDR (13 bytes) + eXIf (4 bytes "GPS!") + IDAT (4 bytes) + IEND (0 bytes)
        let mut png_with_exif = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        // IHDR chunk: len=13, type=IHDR, data=[13 bytes], crc=[0,0,0,0]
        png_with_exif.extend_from_slice(&13u32.to_be_bytes());
        png_with_exif.extend_from_slice(b"IHDR");
        png_with_exif.extend_from_slice(&[0u8; 13]);
        png_with_exif.extend_from_slice(&[0, 0, 0, 0]);
        // eXIf chunk: len=4, type=eXIf, data=b"GPS!", crc=[0,0,0,0]
        png_with_exif.extend_from_slice(&4u32.to_be_bytes());
        png_with_exif.extend_from_slice(b"eXIf");
        png_with_exif.extend_from_slice(b"GPS!");
        png_with_exif.extend_from_slice(&[0, 0, 0, 0]);
        // IDAT chunk: len=4, type=IDAT, data=[1,2,3,4], crc=[0,0,0,0]
        png_with_exif.extend_from_slice(&4u32.to_be_bytes());
        png_with_exif.extend_from_slice(b"IDAT");
        png_with_exif.extend_from_slice(&[1, 2, 3, 4, 0, 0, 0, 0]);
        // IEND chunk: len=0, type=IEND, crc=[0,0,0,0]
        png_with_exif.extend_from_slice(&0u32.to_be_bytes());
        png_with_exif.extend_from_slice(b"IEND");
        png_with_exif.extend_from_slice(&[0, 0, 0, 0]);

        let cleaned_png = strip_media_metadata(&png_with_exif).unwrap();
        assert_eq!(cleaned_png.stripped_segments_count, 1);
        assert!(!cleaned_png.bytes.windows(4).any(|w| w == b"GPS!"));

        // B-0023: Unknown format (e.g., WebP/TIFF with unparsed EXIF) must fail closed
        assert_eq!(
            strip_media_metadata(b"RIFF\x00\x00\x00\x00WEBPVP8 "),
            Err(ProtocolError::MalformedPaddedFrame)
        );
    }

    #[test]
    fn view_once_payload_destroys_secret_after_first_read() {
        let mut vo = ViewOncePayload::new(b"one-time-photo-bytes".to_vec());
        assert!(!vo.is_consumed());
        let first = open_view_once_payload(&mut vo).unwrap();
        assert_eq!(first.as_slice(), b"one-time-photo-bytes");
        assert!(vo.is_consumed());
        // Second read must fail closed
        assert_eq!(
            open_view_once_payload(&mut vo),
            Err(ProtocolError::MalformedPaddedFrame)
        );
    }

    #[test]
    fn contact_invite_uri_safety_number_and_group_chat_epoch_rotation() {
        let invite = ContactInvite {
            server_endpoint: "relay.aegis.example:443".to_owned(),
            recipient_queue_id: [0x11; 32],
            x25519_public: [0x22; 32],
            ml_kem_public_hash: [0x33; 32],
            expires_at_unix_secs: 5_000,
            max_activations: 1,
            offline_qr_only: true,
        };
        let uri = invite.to_uri().unwrap();
        assert!(uri.starts_with("aegis://invite/v1/"));
        let decoded = ContactInvite::from_uri(&uri, 4_000).unwrap();
        assert_eq!(decoded, invite);
        // Expired invite rejected
        assert!(ContactInvite::from_uri(&uri, 5_001).is_err());

        // Order-independent 60-digit safety number (12 groups of 5 digits)
        let alice_ik = [0xAA; 32];
        let bob_ik = [0xBB; 32];
        let sn_ab = compute_safety_number(&alice_ik, &bob_ik);
        let sn_ba = compute_safety_number(&bob_ik, &alice_ik);
        assert_eq!(sn_ab, sn_ba);
        assert_eq!(sn_ab.split(' ').count(), 12);
        assert!(detect_identity_key_change(Some(&alice_ik), &alice_ik).is_none());
        assert!(detect_identity_key_change(Some(&alice_ik), &bob_ik).is_some());

        // MLS-style GroupChatSession key rotation on add/remove member
        let mut group = GroupChatSession::new([0x99; 32], alice_ik, [0x77; 32]).unwrap();
        assert_eq!(group.epoch(), 1);
        assert_eq!(group.add_member(bob_ik, &[0x55; 32]).unwrap(), 2);

        let old_group_snapshot = group.clone();
        let frame_e2 = group
            .seal_group_message(&[0x01; 12], b"epoch-2-secret")
            .unwrap();
        assert_eq!(
            old_group_snapshot
                .open_group_message(&[0x01; 12], &frame_e2)
                .unwrap()
                .as_slice(),
            b"epoch-2-secret"
        );

        // Remove Bob -> rotates to epoch 3; Bob's epoch 2 snapshot cannot decrypt epoch 3 messages!
        assert_eq!(group.remove_member(&bob_ik, &[0x66; 32]).unwrap(), 3);
        let frame_e3 = group
            .seal_group_message(&[0x02; 12], b"epoch-3-post-bob")
            .unwrap();
        assert!(old_group_snapshot
            .open_group_message(&[0x02; 12], &frame_e3)
            .is_err());
        assert_eq!(
            group
                .open_group_message(&[0x02; 12], &frame_e3)
                .unwrap()
                .as_slice(),
            b"epoch-3-post-bob"
        );

        // B-0024: ContactInvite rejects control characters, whitespace, and missing/zero port in endpoint
        let bad_invite = ContactInvite {
            server_endpoint: "bad host:0".to_owned(),
            ..invite
        };
        assert!(bad_invite.to_uri().is_err());
        assert!(ContactInvite::from_uri(
            "aegis://invite/v1/bad\nhost:443/1111111111111111111111111111111111111111111111111111111111111111/2222222222222222222222222222222222222222222222222222222222222222/3333333333333333333333333333333333333333333333333333333333333333/5000/1/1",
            4_000
        )
        .is_err());
    }

    #[test]
    fn b0041_jpeg_metadata_stripper_scans_post_sos_segments_and_requires_sos_and_clean_eoi() {
        // Progressive JPEG with stuffed 0xFF 0x00 and RST0 (0xFF 0xD0) inside scan 1,
        // followed by an injected APP1 EXIF segment and COM segment before scan 2 and EOI.
        let progressive_jpeg: Vec<u8> = vec![
            0xFF, 0xD8, // SOI
            0xFF, 0xE0, 0x00, 0x06, b'J', b'F', b'I', b'F', // APP0 stripped
            0xFF, 0xDA, 0x00, 0x04, 0x01, 0x02, // SOS #1
            0x11, 0xFF, 0x00, 0x22, 0xFF, 0xD0, 0x33, // entropy with stuffed FF 00 and RST0
            0xFF, 0xE1, 0x00, 0x06, b'L', b'E', b'A', b'K', // Post-SOS APP1 EXIF
            0xFF, 0xFE, 0x00, 0x05, b'G', b'P', b'S', // Post-SOS COM
            0xFF, 0xDA, 0x00, 0x04, 0x03, 0x04, // SOS #2
            0x44, 0x55, // entropy #2
            0xFF, 0xD9, // EOI
        ];
        let cleaned = strip_media_metadata(&progressive_jpeg).unwrap();
        assert_eq!(cleaned.stripped_segments_count, 3);
        assert!(!cleaned.bytes.windows(4).any(|w| w == b"JFIF"));
        assert!(!cleaned.bytes.windows(4).any(|w| w == b"LEAK"));
        assert!(!cleaned.bytes.windows(3).any(|w| w == b"GPS"));
        assert!(cleaned.bytes.ends_with(&[0x44, 0x55, 0xFF, 0xD9]));

        // Reject JPEG without SOS (only SOI + EOI)
        assert_eq!(
            strip_media_metadata(&[0xFF, 0xD8, 0xFF, 0xD9]),
            Err(ProtocolError::MalformedPaddedFrame)
        );

        // Reject JPEG with trailing garbage after EOI
        let mut trailing_garbage = progressive_jpeg.clone();
        trailing_garbage.extend_from_slice(b"HIDDEN_EXIF");
        assert_eq!(
            strip_media_metadata(&trailing_garbage),
            Err(ProtocolError::MalformedPaddedFrame)
        );
    }

    #[test]
    fn b0042_png_metadata_stripper_requires_13_byte_ihdr_and_idat_chunk() {
        let png_sig = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

        // 1. Reject PNG where IHDR length != 13
        let mut bad_ihdr = png_sig.to_vec();
        bad_ihdr.extend_from_slice(&4u32.to_be_bytes());
        bad_ihdr.extend_from_slice(b"IHDR");
        bad_ihdr.extend_from_slice(&[1, 2, 3, 4, 0, 0, 0, 0]);
        bad_ihdr.extend_from_slice(&4u32.to_be_bytes());
        bad_ihdr.extend_from_slice(b"IDAT");
        bad_ihdr.extend_from_slice(&[1, 2, 3, 4, 0, 0, 0, 0]);
        bad_ihdr.extend_from_slice(&0u32.to_be_bytes());
        bad_ihdr.extend_from_slice(b"IEND");
        bad_ihdr.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            strip_media_metadata(&bad_ihdr),
            Err(ProtocolError::MalformedPaddedFrame)
        );

        // 2. Reject PNG with valid 13-byte IHDR + IEND but missing IDAT
        let mut no_idat = png_sig.to_vec();
        no_idat.extend_from_slice(&13u32.to_be_bytes());
        no_idat.extend_from_slice(b"IHDR");
        no_idat.extend_from_slice(&[0u8; 13]);
        no_idat.extend_from_slice(&[0, 0, 0, 0]);
        no_idat.extend_from_slice(&0u32.to_be_bytes());
        no_idat.extend_from_slice(b"IEND");
        no_idat.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            strip_media_metadata(&no_idat),
            Err(ProtocolError::MalformedPaddedFrame)
        );
    }

    #[test]
    fn b0043_group_chat_does_not_mutate_members_when_update_entropy_is_invalid() {
        let alice = [0xAA; 32];
        let bob = [0xBB; 32];
        let mut group = GroupChatSession::new([0x99; 32], alice, [0x77; 32]).unwrap();

        // Attempting to add Bob with all-zero entropy must fail AND leave members untouched
        assert_eq!(
            group.add_member(bob, &[0u8; 32]),
            Err(ProtocolError::InvalidReplyQueueId)
        );
        assert_eq!(group.members(), &[alice]);
        assert_eq!(group.epoch(), 1);

        // Valid add succeeds
        assert_eq!(group.add_member(bob, &[0x55; 32]).unwrap(), 2);
        assert_eq!(group.members(), &[alice, bob]);

        // Attempting to remove Bob with all-zero entropy must fail AND keep Bob in members at epoch 2
        assert_eq!(
            group.remove_member(&bob, &[0u8; 32]),
            Err(ProtocolError::InvalidReplyQueueId)
        );
        assert_eq!(group.members(), &[alice, bob]);
        assert_eq!(group.epoch(), 2);
    }
}
