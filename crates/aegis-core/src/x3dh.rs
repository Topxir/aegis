//! X3DH key agreement (spec section 27.2) and prekey generation (section 27.1).

use crate::identity::{dh, ed25519_verify, x25519_public, Identity};
use crate::prekeys::{spk_message, MAX_OPKS};
use crate::{hex, hkdf32, Error, Result};
use zeroize::Zeroizing;

pub const SPK_ROTATE_SECS: u64 = 7 * 24 * 3600;
pub const SPK_KEEP_SECS: u64 = 14 * 24 * 3600;
pub const SPK_MAX_AGE_SECS: u64 = 30 * 24 * 3600;
pub const OPK_REFILL_TO: usize = 50;
pub const OPK_LOW: usize = 10;
const FUTURE_SKEW_SECS: u64 = 600;

/// A signed prekey pair with its signature.
pub struct SignedPrekey {
    pub sk: Zeroizing<[u8; 32]>,
    pub pk: [u8; 32],
    pub ts: u64,
    pub sig: [u8; 64],
}

impl core::fmt::Debug for SignedPrekey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedPrekey").field("ts", &self.ts).finish_non_exhaustive()
    }
}

impl SignedPrekey {
    pub fn generate(identity: &Identity, ts: u64) -> Result<Self> {
        Ok(Self::from_secret(identity, crate::random_bytes::<32>()?, ts))
    }

    /// Deterministic variant with an injected secret.
    pub fn from_secret(identity: &Identity, sk: [u8; 32], ts: u64) -> Self {
        let pk = x25519_public(&sk);
        let sig = identity.sign(&spk_message(&hex::encode(&pk), ts));
        Self { sk: Zeroizing::new(sk), pk, ts, sig }
    }
}

/// `n` fresh one-time prekey secrets (at most 100).
pub fn generate_opks(n: usize) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    if n > MAX_OPKS {
        return Err(Error::Length);
    }
    (0..n).map(|_| Ok(Zeroizing::new(crate::random_bytes::<32>()?))).collect()
}

/// How many one-time prekeys to upload given how many remain on the server.
pub fn opks_needed(remaining: usize) -> usize {
    if remaining < OPK_LOW {
        OPK_REFILL_TO.saturating_sub(remaining)
    } else {
        0
    }
}

/// The reply of `prekeys/take`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub spk: [u8; 32],
    pub spk_ts: u64,
    pub spk_sig: [u8; 64],
    pub opk: Option<[u8; 32]>,
}

impl Bundle {
    /// Parses the JSON body of a `prekeys/take` answer.
    pub fn from_json(body: &[u8]) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| Error::BadResponse)?;
        let s = |k: &str| v[k].as_str().ok_or(Error::BadResponse);
        let opk = s("opk")?;
        Ok(Self {
            spk: hex::decode_array(s("spk")?).map_err(|_| Error::BadResponse)?,
            spk_ts: v["spk_ts"].as_u64().ok_or(Error::BadResponse)?,
            spk_sig: hex::decode_array(s("spk_sig")?).map_err(|_| Error::BadResponse)?,
            opk: if opk.is_empty() {
                None
            } else {
                Some(hex::decode_array(opk).map_err(|_| Error::BadResponse)?)
            },
        })
    }

    /// Checks `spk_sig` against the pinned `ed_pk` and that `spk_ts` is within the last 30 days.
    pub fn check(&self, peer_ed: &[u8; 32], now: u64) -> Result<()> {
        if !ed25519_verify(peer_ed, &spk_message(&hex::encode(&self.spk), self.spk_ts), &self.spk_sig) {
            return Err(Error::BadSignature);
        }
        if self.spk_ts > now.saturating_add(FUTURE_SKEW_SECS) || now.saturating_sub(self.spk_ts) > SPK_MAX_AGE_SECS {
            return Err(Error::Session("signed prekey too old"));
        }
        Ok(())
    }
}

/// Long-term keys of both sides, used for `AD`.
#[derive(Debug, Clone, Copy)]
pub struct Parties {
    pub a_ed: [u8; 32],
    pub a_x: [u8; 32],
    pub b_ed: [u8; 32],
    pub b_x: [u8; 32],
}

impl Parties {
    /// `AD = A.ed_pk || A.x_pk || B.ed_pk || B.x_pk`.
    pub fn ad(&self) -> [u8; 128] {
        let mut ad = [0u8; 128];
        ad[..32].copy_from_slice(&self.a_ed);
        ad[32..64].copy_from_slice(&self.a_x);
        ad[64..96].copy_from_slice(&self.b_ed);
        ad[96..].copy_from_slice(&self.b_x);
        ad
    }
}

fn derive(dhs: &[&[u8; 32]]) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new(vec![0xFFu8; 32]);
    for d in dhs {
        ikm.extend_from_slice(*d);
    }
    hkdf32(&ikm, &[0; 32], b"aegis-v2 x3dh")
}

/// Initiator side: returns `SK`. `bundle` must already have passed [`Bundle::check`].
pub fn initiate_with(
    ek_sk: &[u8; 32],
    a_x_sk: &[u8; 32],
    b_x_pk: &[u8; 32],
    bundle: &Bundle,
) -> Result<Zeroizing<[u8; 32]>> {
    let dh1 = dh(a_x_sk, &bundle.spk)?;
    let dh2 = dh(ek_sk, b_x_pk)?;
    let dh3 = dh(ek_sk, &bundle.spk)?;
    match &bundle.opk {
        Some(opk) => {
            let dh4 = dh(ek_sk, opk)?;
            derive(&[&dh1, &dh2, &dh3, &dh4])
        }
        None => derive(&[&dh1, &dh2, &dh3]),
    }
}

pub fn initiate(a_x_sk: &[u8; 32], b_x_pk: &[u8; 32], bundle: &Bundle) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    let ek_sk = Zeroizing::new(crate::random_bytes::<32>()?);
    let sk = initiate_with(&ek_sk, a_x_sk, b_x_pk, bundle)?;
    Ok((sk, x25519_public(&ek_sk)))
}

/// Responder side: returns `SK` from the secrets of the referenced prekeys.
pub fn respond(
    b_x_sk: &[u8; 32],
    spk_sk: &[u8; 32],
    opk_sk: Option<&[u8; 32]>,
    a_x_pk: &[u8; 32],
    ek_pk: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let dh1 = dh(spk_sk, a_x_pk)?;
    let dh2 = dh(b_x_sk, ek_pk)?;
    let dh3 = dh(spk_sk, ek_pk)?;
    match opk_sk {
        Some(o) => {
            let dh4 = dh(o, ek_pk)?;
            derive(&[&dh1, &dh2, &dh3, &dh4])
        }
        None => derive(&[&dh1, &dh2, &dh3]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (Identity, Identity) {
        (Identity::from_secrets([1; 32], [2; 32]), Identity::from_secrets([3; 32], [4; 32]))
    }

    fn bundle(b: &Identity, with_opk: bool, ts: u64) -> (Bundle, SignedPrekey, [u8; 32]) {
        let spk = SignedPrekey::from_secret(b, [5; 32], ts);
        let opk_sk = [6u8; 32];
        let bundle = Bundle {
            spk: spk.pk,
            spk_ts: ts,
            spk_sig: spk.sig,
            opk: with_opk.then(|| x25519_public(&opk_sk)),
        };
        (bundle, spk, opk_sk)
    }

    #[test]
    fn both_sides_agree() {
        let (a, b) = ids();
        for with_opk in [true, false] {
            let (bn, spk, opk_sk) = bundle(&b, with_opk, 1_000_000);
            bn.check(&b.ed_public(), 1_000_100).unwrap();
            let ek = [7u8; 32];
            let sk_a = initiate_with(&ek, a.x_secret(), &b.x_public(), &bn).unwrap();
            let sk_b = respond(
                b.x_secret(),
                &spk.sk,
                with_opk.then_some(&opk_sk),
                &a.x_public(),
                &x25519_public(&ek),
            )
            .unwrap();
            assert_eq!(*sk_a, *sk_b);
        }
        let (with, _, _) = bundle(&b, true, 1);
        let (without, _, _) = bundle(&b, false, 1);
        let ek = [7u8; 32];
        let x = initiate_with(&ek, a.x_secret(), &b.x_public(), &with).unwrap();
        let y = initiate_with(&ek, a.x_secret(), &b.x_public(), &without).unwrap();
        assert_ne!(*x, *y);
    }

    #[test]
    fn bundle_checks() {
        let (_, b) = ids();
        let (bn, _, _) = bundle(&b, true, 10_000_000);
        let ed = b.ed_public();
        assert!(bn.check(&ed, 10_000_000).is_ok());
        assert!(bn.check(&ed, 10_000_000 + SPK_MAX_AGE_SECS).is_ok());
        assert!(bn.check(&ed, 10_000_000 + SPK_MAX_AGE_SECS + 1).is_err());
        assert!(bn.check(&ed, 10_000_000 - 601).is_err());
        assert!(bn.check(&[9; 32], 10_000_000).is_err());
        let mut forged = bn.clone();
        forged.spk[0] ^= 1;
        assert!(forged.check(&ed, 10_000_000).is_err());
        let mut late = bn;
        late.spk_ts += 1;
        assert!(late.check(&ed, 10_000_000).is_err());
    }

    #[test]
    fn all_zero_dh_aborts() {
        let (a, b) = ids();
        let (mut bn, spk, _) = bundle(&b, false, 1);
        let ek = [7u8; 32];
        bn.spk = [0; 32];
        assert!(initiate_with(&ek, a.x_secret(), &b.x_public(), &bn).is_err());
        assert!(respond(b.x_secret(), &spk.sk, None, &a.x_public(), &[0; 32]).is_err());
        let (bn, _, _) = bundle(&b, false, 1);
        assert!(initiate_with(&ek, a.x_secret(), &[0; 32], &bn).is_err());
    }

    #[test]
    fn bundle_json_and_counts() {
        let j = format!(
            r#"{{"spk":"{}","spk_ts":5,"spk_sig":"{}","opk":""}}"#,
            hex::encode(&[1u8; 32]),
            hex::encode(&[2u8; 64])
        );
        let bn = Bundle::from_json(j.as_bytes()).unwrap();
        assert_eq!((bn.spk_ts, bn.opk), (5, None));
        assert!(Bundle::from_json(b"{}").is_err());
        assert_eq!(opks_needed(9), 41);
        assert_eq!(opks_needed(10), 0);
        assert_eq!(opks_needed(0), 50);
        assert_eq!(generate_opks(3).unwrap().len(), 3);
        assert!(generate_opks(101).is_err());
    }

    #[test]
    fn ad_layout() {
        let p = Parties { a_ed: [1; 32], a_x: [2; 32], b_ed: [3; 32], b_x: [4; 32] };
        let ad = p.ad();
        assert_eq!((ad[0], ad[32], ad[64], ad[96], ad[127]), (1, 2, 3, 4, 4));
    }
}
