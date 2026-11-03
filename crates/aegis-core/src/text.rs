//! Percent-encoding and display text helpers.

use crate::{Error, Result};

const HEX_UP: &[u8; 16] = b"0123456789ABCDEF";

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// Percent-encodes every byte outside `A-Z a-z 0-9 - _ . ~` as uppercase `%XX`.
pub fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if unreserved(b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX_UP[usize::from(b >> 4)]));
            out.push(char::from(HEX_UP[usize::from(b & 15)]));
        }
    }
    out
}

fn up_nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Strict inverse of [`pct_encode`]: raw bytes outside the unreserved set,
/// lowercase escapes and truncated escapes are rejected.
pub fn pct_decode_strict(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            let (Some(&h), Some(&l)) = (b.get(i + 1), b.get(i + 2)) else {
                return Err(Error::InvalidText);
            };
            match (up_nib(h), up_nib(l)) {
                (Some(h), Some(l)) => out.push((h << 4) | l),
                _ => return Err(Error::InvalidText),
            }
            i += 3;
        } else if unreserved(c) {
            out.push(c);
            i += 1;
        } else {
            return Err(Error::InvalidText);
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidText)
}

/// Lenient decode for URL query strings and forms (`+` is a space, any hex case).
pub fn form_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let (Some(&h), Some(&l)) = (b.get(i + 1), b.get(i + 2)) else {
                    return Err(Error::InvalidText);
                };
                let n = |c: u8| up_nib(c.to_ascii_uppercase());
                match (n(h), n(l)) {
                    (Some(h), Some(l)) => out.push((h << 4) | l),
                    _ => return Err(Error::InvalidText),
                }
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidText)
}

/// Splits `a=b&c=d` into decoded pairs.
pub fn parse_pairs(s: &str) -> Result<Vec<(String, String)>> {
    let mut v = Vec::new();
    for part in s.split('&').filter(|p| !p.is_empty()) {
        let (k, val) = part.split_once('=').unwrap_or((part, ""));
        v.push((form_decode(k)?, form_decode(val)?));
    }
    Ok(v)
}

/// Canonical unsigned decimal: ASCII digits only, no sign, no leading zeros.
pub fn parse_u64(s: &str) -> Result<u64> {
    let canonical = !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if !canonical {
        return Err(Error::InvalidText);
    }
    s.parse().map_err(|_| Error::InvalidText)
}

fn is_hidden_format_char(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{FEFF}'
        | '\u{00AD}'
        | '\u{061C}'
        | '\u{180E}')
}

/// Cleans a peer-supplied display name or title: drops control characters and
/// invisible or bidi-formatting characters, then keeps at most 64 characters.
/// Escaping for the output context (HTML etc.) remains the UI's job.
pub fn sanitize_display_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_hidden_format_char(*c))
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pct_roundtrip() {
        let s = "a b\n%é<>\"'~-_.";
        let e = pct_encode(s);
        assert_eq!(e, "a%20b%0A%25%C3%A9%3C%3E%22%27~-_.");
        assert_eq!(pct_decode_strict(&e).unwrap(), s);
        assert!(pct_decode_strict("a b").is_err());
        assert!(pct_decode_strict("%2a").is_err());
        assert!(pct_decode_strict("%2").is_err());
        assert!(pct_decode_strict("%FF").is_err());
    }

    #[test]
    fn form() {
        assert_eq!(form_decode("a+b%2ac").unwrap(), "a b*c");
        let p = parse_pairs("u=bob&title=A%20B&x").unwrap();
        assert_eq!(p[1], ("title".into(), "A B".into()));
        assert_eq!(p[2], ("x".into(), String::new()));
    }

    #[test]
    fn sanitize() {
        assert_eq!(
            sanitize_display_text("a\u{202E}b\u{200B}c\u{0007}d\n\u{FEFF}"),
            "abcd"
        );
        assert_eq!(sanitize_display_text("\u{2066}x\u{2069}"), "x");
        let long: String = "я".repeat(100);
        assert_eq!(sanitize_display_text(&long).chars().count(), 64);
        assert_eq!(sanitize_display_text("<b>ok</b>"), "<b>ok</b>");
    }
}
