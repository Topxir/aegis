//! Directory registration (spec section 3): signed message, form body, checks.

use crate::identity::{ed25519_verify, is_valid_username, Identity};
use crate::text::{parse_pairs, parse_u64, pct_encode};
use crate::{hex, pow, Error, Result};

pub const MAX_TITLE_CHARS: usize = 64;

/// A title the server accepts: at most 64 characters and no control characters.
pub fn is_valid_title(t: &str) -> bool {
    t.chars().count() <= MAX_TITLE_CHARS && !t.chars().any(char::is_control)
}

/// The bytes covered by the registration signature.
pub fn signed_message(u: &str, title: &str, x_hex: &str, ed_hex: &str, ts: u64) -> Vec<u8> {
    format!("aegis-v2 dir\n{u}\n{title}\n{x_hex}\n{ed_hex}\n{ts}").into_bytes()
}

/// Proof-of-work scope for a registration.
pub fn pow_scope(u: &str) -> String {
    format!("dir:{u}")
}

/// A decoded `POST /api/v2/dir/register` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub u: String,
    pub title: String,
    pub x: [u8; 32],
    pub ed: [u8; 32],
    pub ts: u64,
    pub sig: [u8; 64],
    pub pow: u64,
}

impl Registration {
    /// Signs a registration for `identity`; `pow` is left at zero until mined.
    pub fn sign(identity: &Identity, u: &str, title: &str, ts: u64) -> Result<Self> {
        if !is_valid_username(u) {
            return Err(Error::InvalidUsername);
        }
        if !is_valid_title(title) {
            return Err(Error::InvalidText);
        }
        let x = identity.x_public();
        let ed = identity.ed_public();
        let msg = signed_message(u, title, &hex::encode(&x), &hex::encode(&ed), ts);
        Ok(Self {
            u: u.to_owned(),
            title: title.to_owned(),
            x,
            ed,
            ts,
            sig: identity.sign(&msg),
            pow: 0,
        })
    }

    pub fn message(&self) -> Vec<u8> {
        signed_message(
            &self.u,
            &self.title,
            &hex::encode(&self.x),
            &hex::encode(&self.ed),
            self.ts,
        )
    }

    /// Hex SHA-256 of the signed message, the proof-of-work `body_hash`.
    pub fn body_hash(&self) -> String {
        pow::body_hash_hex(&self.message())
    }

    pub fn mine(&mut self, bits: u32) {
        self.pow = pow::mine(&pow_scope(&self.u), self.ts, &self.body_hash(), bits);
    }

    pub fn pow_ok(&self, bits: u32) -> bool {
        pow::verify(&pow_scope(&self.u), self.ts, &self.body_hash(), self.pow, bits)
    }

    pub fn signature_ok(&self) -> bool {
        ed25519_verify(&self.ed, &self.message(), &self.sig)
    }

    pub fn to_form(&self) -> String {
        format!(
            "u={}&title={}&x={}&ed={}&ts={}&sig={}&pow={}",
            pct_encode(&self.u),
            pct_encode(&self.title),
            hex::encode(&self.x),
            hex::encode(&self.ed),
            self.ts,
            hex::encode(&self.sig),
            self.pow
        )
    }

    /// Strict form parser: all seven fields exactly once, no extras.
    pub fn from_form(body: &str) -> Result<Self> {
        let pairs = parse_pairs(body)?;
        let mut vals: [Option<String>; 7] = Default::default();
        const KEYS: [&str; 7] = ["u", "title", "x", "ed", "ts", "sig", "pow"];
        for (k, v) in pairs {
            let i = KEYS.iter().position(|n| *n == k).ok_or(Error::InvalidText)?;
            if vals[i].replace(v).is_some() {
                return Err(Error::InvalidText);
            }
        }
        let [Some(u), Some(title), Some(x), Some(ed), Some(ts), Some(sig), Some(pw)] = vals else {
            return Err(Error::InvalidText);
        };
        if !is_valid_username(&u) {
            return Err(Error::InvalidUsername);
        }
        if !is_valid_title(&title) {
            return Err(Error::InvalidText);
        }
        Ok(Self {
            u,
            title,
            x: hex::decode_array(&x)?,
            ed: hex::decode_array(&ed)?,
            ts: parse_u64(&ts)?,
            sig: hex::decode_array(&sig)?,
            pow: parse_u64(&pw)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> Registration {
        let id = Identity::from_secrets([1; 32], [2; 32]);
        let mut r = Registration::sign(&id, "alice", "Alice A", 1_700_000_000).unwrap();
        r.mine(8);
        r
    }

    #[test]
    fn sign_form_roundtrip() {
        let r = reg();
        assert!(r.signature_ok());
        assert!(r.pow_ok(8));
        let back = Registration::from_form(&r.to_form()).unwrap();
        assert_eq!(back, r);
        assert!(back.signature_ok());
    }

    #[test]
    fn tamper_and_bad_forms() {
        let mut r = reg();
        r.title = "Mallory".into();
        assert!(!r.signature_ok());
        let f = reg().to_form();
        assert!(Registration::from_form(&format!("{f}&u=bob")).is_err());
        assert!(Registration::from_form(&format!("{f}&extra=1")).is_err());
        assert!(Registration::from_form(&f.replace("u=alice&", "")).is_err());
        assert!(Registration::from_form(&f.replace("u=alice", "u=AL")).is_err());
        assert!(Registration::from_form(&f.replace("title=Alice%20A", "title=a%0Ab")).is_err());
        assert!(Registration::from_form(&f.replace("&ts=1700000000", "&ts=01700000000")).is_err());
    }

    #[test]
    fn title_rules() {
        assert!(is_valid_title(""));
        assert!(is_valid_title(&"x".repeat(64)));
        assert!(!is_valid_title(&"x".repeat(65)));
        assert!(!is_valid_title("a\nb"));
    }
}
