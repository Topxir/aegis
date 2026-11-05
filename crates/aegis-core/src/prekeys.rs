//! Prekey messages and forms (spec section 27.1): signing, strict form encoding, proof-of-work scope.

use crate::identity::{ed25519_verify, is_valid_username, Identity};
use crate::text::{parse_pairs, parse_u64, pct_encode};
use crate::{hex, pow, Error, Result};

/// Most one-time prekeys per request and per user.
pub const MAX_OPKS: usize = 100;

/// Message signed by the identity key over a signed prekey.
pub fn spk_message(spk_hex: &str, spk_ts: u64) -> Vec<u8> {
    format!("aegis-v2 spk\n{spk_hex}\n{spk_ts}").into_bytes()
}

/// Message signed over a whole `prekeys/put` request.
pub fn put_message(u: &str, spk_hex: &str, spk_ts: u64, spk_sig_hex: &str, opks_csv: &str, ts: u64) -> Vec<u8> {
    format!("aegis-v2 prekeys\n{u}\n{spk_hex}\n{spk_ts}\n{spk_sig_hex}\n{opks_csv}\n{ts}").into_bytes()
}

/// Proof-of-work scope of `prekeys/take`.
pub fn take_scope(u: &str) -> String {
    format!("pk:{u}")
}

/// Proof-of-work `body_hash` of `prekeys/take`: hex SHA-256 of `u || "\n" || ts`.
pub fn take_body_hash(u: &str, ts: u64) -> String {
    pow::body_hash_hex(format!("{u}\n{ts}").as_bytes())
}

fn strict_pairs<const N: usize>(body: &str, keys: [&str; N]) -> Result<[String; N]> {
    if body.split('&').any(str::is_empty) {
        return Err(Error::InvalidText);
    }
    let mut vals: [Option<String>; N] = std::array::from_fn(|_| None);
    for (k, v) in parse_pairs(body)? {
        let i = keys.iter().position(|n| *n == k).ok_or(Error::InvalidText)?;
        if vals[i].replace(v).is_some() {
            return Err(Error::InvalidText);
        }
    }
    let mut out = Vec::with_capacity(N);
    for v in vals {
        out.push(v.ok_or(Error::InvalidText)?);
    }
    out.try_into().map_err(|_| Error::InvalidText)
}

/// A decoded `POST /api/v2/prekeys/put` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrekeyPut {
    pub u: String,
    pub spk: [u8; 32],
    pub spk_ts: u64,
    pub spk_sig: [u8; 64],
    pub opks: Vec<[u8; 32]>,
    pub ts: u64,
    pub sig: [u8; 64],
}

impl PrekeyPut {
    /// Signs `spk` and the request with `identity`.
    pub fn sign(identity: &Identity, u: &str, spk: [u8; 32], spk_ts: u64, opks: Vec<[u8; 32]>, ts: u64) -> Result<Self> {
        if !is_valid_username(u) {
            return Err(Error::InvalidUsername);
        }
        if opks.len() > MAX_OPKS {
            return Err(Error::Length);
        }
        let spk_sig = identity.sign(&spk_message(&hex::encode(&spk), spk_ts));
        let mut p = Self { u: u.to_owned(), spk, spk_ts, spk_sig, opks, ts, sig: [0; 64] };
        p.sig = identity.sign(&p.message());
        Ok(p)
    }

    pub fn opks_csv(&self) -> String {
        self.opks.iter().map(|o| hex::encode(o)).collect::<Vec<_>>().join(",")
    }

    pub fn message(&self) -> Vec<u8> {
        put_message(
            &self.u,
            &hex::encode(&self.spk),
            self.spk_ts,
            &hex::encode(&self.spk_sig),
            &self.opks_csv(),
            self.ts,
        )
    }

    /// Checks the outer signature against the directory key `ed`.
    pub fn sig_ok(&self, ed: &[u8; 32]) -> bool {
        ed25519_verify(ed, &self.message(), &self.sig)
    }

    /// Checks `spk_sig` against the directory key `ed`.
    pub fn spk_sig_ok(&self, ed: &[u8; 32]) -> bool {
        ed25519_verify(ed, &spk_message(&hex::encode(&self.spk), self.spk_ts), &self.spk_sig)
    }

    pub fn to_form(&self) -> String {
        format!(
            "u={}&spk={}&spk_ts={}&spk_sig={}&opks={}&ts={}&sig={}",
            pct_encode(&self.u),
            hex::encode(&self.spk),
            self.spk_ts,
            hex::encode(&self.spk_sig),
            self.opks_csv(),
            self.ts,
            hex::encode(&self.sig)
        )
    }

    /// Strict parser: seven fields exactly once, lowercase hex, at most 100 one-time prekeys.
    pub fn from_form(body: &str) -> Result<Self> {
        let [u, spk, spk_ts, spk_sig, opks, ts, sig] =
            strict_pairs(body, ["u", "spk", "spk_ts", "spk_sig", "opks", "ts", "sig"])?;
        if !is_valid_username(&u) {
            return Err(Error::InvalidUsername);
        }
        let opks = if opks.is_empty() {
            Vec::new()
        } else {
            opks.split(',').map(hex::decode_array::<32>).collect::<Result<Vec<_>>>()?
        };
        if opks.len() > MAX_OPKS {
            return Err(Error::Length);
        }
        Ok(Self {
            u,
            spk: hex::decode_array(&spk)?,
            spk_ts: parse_u64(&spk_ts)?,
            spk_sig: hex::decode_array(&spk_sig)?,
            opks,
            ts: parse_u64(&ts)?,
            sig: hex::decode_array(&sig)?,
        })
    }
}

/// A decoded `POST /api/v2/prekeys/take` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrekeyTake {
    pub u: String,
    pub ts: u64,
    pub pow: u64,
}

impl PrekeyTake {
    /// Mines the proof of work for `u` at time `ts`.
    pub fn mine(u: &str, ts: u64, bits: u32) -> Self {
        let pow = pow::mine(&take_scope(u), ts, &take_body_hash(u, ts), bits);
        Self { u: u.to_owned(), ts, pow }
    }

    pub fn pow_ok(&self, bits: u32) -> bool {
        pow::verify(&take_scope(&self.u), self.ts, &take_body_hash(&self.u, self.ts), self.pow, bits)
    }

    pub fn to_form(&self) -> String {
        format!("u={}&ts={}&pow={}", pct_encode(&self.u), self.ts, self.pow)
    }

    pub fn from_form(body: &str) -> Result<Self> {
        let [u, ts, pw] = strict_pairs(body, ["u", "ts", "pow"])?;
        if !is_valid_username(&u) {
            return Err(Error::InvalidUsername);
        }
        Ok(Self { u, ts: parse_u64(&ts)?, pow: parse_u64(&pw)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PrekeyPut {
        let id = Identity::from_secrets([1; 32], [2; 32]);
        PrekeyPut::sign(&id, "alice", [3; 32], 1_700_000_000, vec![[4; 32], [5; 32]], 1_700_000_100).unwrap()
    }

    #[test]
    fn put_roundtrip_and_signatures() {
        let p = sample();
        let ed = Identity::from_secrets([1; 32], [2; 32]).ed_public();
        assert!(p.sig_ok(&ed) && p.spk_sig_ok(&ed));
        assert_eq!(PrekeyPut::from_form(&p.to_form()).unwrap(), p);
        let mut bad = p.clone();
        bad.opks.push([6; 32]);
        assert!(!bad.sig_ok(&ed));
        let mut bad = p;
        bad.spk_ts += 1;
        assert!(!bad.spk_sig_ok(&ed));
    }

    #[test]
    fn strict_forms() {
        let f = sample().to_form();
        assert!(PrekeyPut::from_form(&format!("{f}&u=bob")).is_err());
        assert!(PrekeyPut::from_form(&f.replace("&ts=", "&tz=")).is_err());
        assert!(PrekeyPut::from_form(&f.to_uppercase()).is_err());
        assert!(PrekeyPut::from_form(&format!("{f}&")).is_err());
        let id = Identity::from_secrets([1; 32], [2; 32]);
        let none = PrekeyPut::sign(&id, "alice", [3; 32], 1, vec![], 2).unwrap();
        assert_eq!(PrekeyPut::from_form(&none.to_form()).unwrap(), none);
        assert!(PrekeyPut::sign(&id, "alice", [3; 32], 1, vec![[0; 32]; 101], 2).is_err());
        let many = (0..101).map(|_| hex::encode(&[1u8; 32])).collect::<Vec<_>>().join(",");
        let form = f.replace(&sample().opks_csv(), &many);
        assert!(PrekeyPut::from_form(&form).is_err());
        let t = PrekeyTake::mine("alice", 1_700_000_000, 6);
        assert!(t.pow_ok(6));
        assert_eq!(PrekeyTake::from_form(&t.to_form()).unwrap(), t);
        assert!(PrekeyTake::from_form("u=alice&ts=1").is_err());
    }

    #[test]
    fn fixed_input_vector() {
        let p = sample();
        // Run with `-- --nocapture` to export these as vectors.
        println!("prekeys-spk-msg {}", hex::encode(&spk_message(&hex::encode(&p.spk), p.spk_ts)));
        println!("prekeys-spk-sig {}", hex::encode(&p.spk_sig));
        println!("prekeys-put-msg {}", hex::encode(&p.message()));
        println!("prekeys-put-sig {}", hex::encode(&p.sig));
        println!("prekeys-take-body-hash {}", take_body_hash("alice", 1_700_000_000));
        assert_eq!(p.sig, sample().sig);
    }
}
