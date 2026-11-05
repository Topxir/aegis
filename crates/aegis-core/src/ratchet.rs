//! Double Ratchet (spec section 27.3) and the local state encoding.

use crate::identity::{dh, x25519_public};
use crate::seal::{aead_open, aead_seal};
use crate::{arr, Error, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const MAX_SKIP_STEP: u32 = 1000;
pub const MAX_SKIPPED: usize = 2000;
pub const SKIPPED_TTL_SECS: u64 = 30 * 24 * 3600;
pub const HEADER_LEN: usize = 40;

type Key = Zeroizing<[u8; 32]>;

/// HKDF-SHA256 to `N` bytes; an empty salt means no salt.
pub(crate) fn hkdf_n<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; N]>> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let mut out = Zeroizing::new([0u8; N]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out.as_mut())
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

fn hmac(key: &[u8; 32], data: u8) -> Result<Key> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Kdf)?;
    m.update(&[data]);
    Ok(Zeroizing::new(m.finalize().into_bytes().into()))
}

/// `KDF_CK`: returns `(mk, ck')`.
pub(crate) fn kdf_ck(ck: &[u8; 32]) -> Result<(Key, Key)> {
    Ok((hmac(ck, 0x01)?, hmac(ck, 0x02)?))
}

/// `key || nonce` from a message key with the given label.
pub(crate) fn msg_key(mk: &[u8; 32], info: &[u8]) -> Result<(Key, [u8; 12])> {
    let kn = hkdf_n::<44>(mk, &[0; 32], info)?;
    Ok((Zeroizing::new(arr(&kn[..32])?), arr(&kn[32..])?))
}

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<(Key, Key)> {
    let o = hkdf_n::<64>(dh_out, rk, b"aegis-v2 ratchet")?;
    Ok((Zeroizing::new(arr(&o[..32])?), Zeroizing::new(arr(&o[32..])?)))
}

#[derive(Clone)]
struct Skipped {
    dh: [u8; 32],
    n: u32,
    mk: Key,
    ts: u64,
}

/// One direction-pair of the ratchet. Clone is used for decrypt-then-commit.
#[derive(Clone)]
pub struct Ratchet {
    ad: [u8; 128],
    dhs_sk: Key,
    dhs_pk: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: Key,
    cks: Option<Key>,
    ckr: Option<Key>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: Vec<Skipped>,
}

impl core::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ratchet(..)")
    }
}

fn header(dh_pk: &[u8; 32], pn: u32, n: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..32].copy_from_slice(dh_pk);
    h[32..36].copy_from_slice(&pn.to_be_bytes());
    h[36..].copy_from_slice(&n.to_be_bytes());
    h
}

impl Ratchet {
    /// Initiator state: `DHr` is the responder's signed prekey.
    pub fn init_initiator(sk: &[u8; 32], ad: &[u8; 128], b_spk: &[u8; 32]) -> Result<Self> {
        Self::init_initiator_with(&crate::random_bytes::<32>()?, sk, ad, b_spk)
    }

    pub fn init_initiator_with(
        dhs_sk: &[u8; 32],
        sk: &[u8; 32],
        ad: &[u8; 128],
        b_spk: &[u8; 32],
    ) -> Result<Self> {
        let d = dh(dhs_sk, b_spk)?;
        let (rk, cks) = kdf_rk(sk, &d)?;
        Ok(Self {
            ad: *ad,
            dhs_sk: Zeroizing::new(*dhs_sk),
            dhs_pk: x25519_public(dhs_sk),
            dhr: Some(*b_spk),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
        })
    }

    /// Responder state: `DHs` is the signed prekey pair that the initiator used.
    pub fn init_responder(sk: &[u8; 32], ad: &[u8; 128], spk_sk: &[u8; 32]) -> Self {
        Self {
            ad: *ad,
            dhs_sk: Zeroizing::new(*spk_sk),
            dhs_pk: x25519_public(spk_sk),
            dhr: None,
            rk: Zeroizing::new(*sk),
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
        }
    }

    pub fn ad(&self) -> &[u8; 128] {
        &self.ad
    }

    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// True once a chain exists to send on (a responder has none before the first message).
    pub fn can_send(&self) -> bool {
        self.cks.is_some()
    }

    /// `ratchet_msg = header || AEAD(key, nonce, AD || header, plaintext)`.
    pub fn encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let cks = self.cks.as_ref().ok_or(Error::Session("no sending chain"))?;
        let (mk, next) = kdf_ck(cks)?;
        let h = header(&self.dhs_pk, self.pn, self.ns);
        let (key, nonce) = msg_key(&mk, b"aegis-v2 msg-key")?;
        let aad = [self.ad.as_slice(), &h].concat();
        let ct = aead_seal(&key, &nonce, &aad, plain)?;
        self.ns = self.ns.checked_add(1).ok_or(Error::Session("counter"))?;
        self.cks = Some(next);
        Ok([h.as_slice(), &ct].concat())
    }

    /// Decrypts on a copy and replaces `self` only if the AEAD check passes.
    pub fn decrypt(&mut self, msg: &[u8], now: u64) -> Result<Zeroizing<Vec<u8>>> {
        self.decrypt_with(&crate::random_bytes::<32>()?, msg, now)
    }

    /// `new_dhs_sk` is used only if this message triggers a DH ratchet step.
    pub fn decrypt_with(&mut self, new_dhs_sk: &[u8; 32], msg: &[u8], now: u64) -> Result<Zeroizing<Vec<u8>>> {
        let mut copy = self.clone();
        let plain = copy.decrypt_inner(new_dhs_sk, msg, now)?;
        *self = copy;
        Ok(plain)
    }

    /// Deletes skipped keys older than 30 days.
    pub fn expire(&mut self, now: u64) {
        self.skipped.retain(|s| now < s.ts.saturating_add(SKIPPED_TTL_SECS));
    }

    fn decrypt_inner(&mut self, new_dhs_sk: &[u8; 32], msg: &[u8], now: u64) -> Result<Zeroizing<Vec<u8>>> {
        if msg.len() < HEADER_LEN + 16 {
            return Err(Error::Length);
        }
        self.expire(now);
        let (h, ct) = msg.split_at(HEADER_LEN);
        let dh_pk: [u8; 32] = arr(&h[..32])?;
        let pn = u32::from_be_bytes(arr(&h[32..36])?);
        let n = u32::from_be_bytes(arr(&h[36..])?);
        let aad = [self.ad.as_slice(), h].concat();

        if let Some(i) = self.skipped.iter().position(|s| s.dh == dh_pk && s.n == n) {
            let (key, nonce) = msg_key(&self.skipped[i].mk, b"aegis-v2 msg-key")?;
            let plain = aead_open(&key, &nonce, &aad, ct)?;
            self.skipped.remove(i);
            return Ok(Zeroizing::new(plain));
        }
        if self.dhr != Some(dh_pk) {
            self.skip_until(pn, now)?;
            self.dh_step(&dh_pk, new_dhs_sk)?;
        }
        self.skip_until(n, now)?;
        let ckr = self.ckr.as_ref().ok_or(Error::Session("no receiving chain"))?;
        let (mk, next) = kdf_ck(ckr)?;
        let (key, nonce) = msg_key(&mk, b"aegis-v2 msg-key")?;
        let plain = aead_open(&key, &nonce, &aad, ct)?;
        self.ckr = Some(next);
        self.nr = self.nr.checked_add(1).ok_or(Error::Session("counter"))?;
        Ok(Zeroizing::new(plain))
    }

    fn skip_until(&mut self, until: u32, now: u64) -> Result<()> {
        let Some(mut ck) = self.ckr.clone() else {
            return Ok(());
        };
        if until <= self.nr {
            return Ok(());
        }
        let need = until - self.nr;
        if need > MAX_SKIP_STEP || self.skipped.len() + need as usize > MAX_SKIPPED {
            return Err(Error::Session("too many skipped messages"));
        }
        let dhr = self.dhr.ok_or(Error::Session("no receiving chain"))?;
        while self.nr < until {
            let (mk, next) = kdf_ck(&ck)?;
            self.skipped.push(Skipped { dh: dhr, n: self.nr, mk, ts: now });
            ck = next;
            self.nr += 1;
        }
        self.ckr = Some(ck);
        Ok(())
    }

    fn dh_step(&mut self, dh_pk: &[u8; 32], new_dhs_sk: &[u8; 32]) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(*dh_pk);
        let d = dh(&self.dhs_sk, dh_pk)?;
        let (rk, ckr) = kdf_rk(&self.rk, &d)?;
        self.dhs_sk = Zeroizing::new(*new_dhs_sk);
        self.dhs_pk = x25519_public(new_dhs_sk);
        let d = dh(&self.dhs_sk, dh_pk)?;
        let (rk, cks) = kdf_rk(&rk, &d)?;
        self.rk = rk;
        self.ckr = Some(ckr);
        self.cks = Some(cks);
        Ok(())
    }

    /// Local state encoding `AGR1` (spec section 27.3, "Local state").
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.raw(b"AGR1");
        w.raw(&self.ad);
        w.raw(self.dhs_sk.as_ref());
        w.opt32(self.dhr.as_ref());
        w.raw(self.rk.as_ref());
        w.opt32(self.cks.as_deref());
        w.opt32(self.ckr.as_deref());
        w.u32(self.ns);
        w.u32(self.nr);
        w.u32(self.pn);
        w.u16(u16::try_from(self.skipped.len()).unwrap_or(u16::MAX));
        for s in &self.skipped {
            w.raw(&s.dh);
            w.u32(s.n);
            w.raw(s.mk.as_ref());
            w.u64(s.ts);
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.magic(b"AGR1")?;
        let ad = r.array::<128>()?;
        let dhs_sk = Zeroizing::new(r.array::<32>()?);
        let dhr = r.opt32()?;
        let rk = Zeroizing::new(r.array::<32>()?);
        let cks = r.opt32()?.map(Zeroizing::new);
        let ckr = r.opt32()?.map(Zeroizing::new);
        let (ns, nr, pn) = (r.u32()?, r.u32()?, r.u32()?);
        let count = usize::from(r.u16()?);
        if count > MAX_SKIPPED {
            return Err(Error::Session("state"));
        }
        let mut skipped = Vec::with_capacity(count);
        for _ in 0..count {
            let dh = r.array::<32>()?;
            let n = r.u32()?;
            let mk = Zeroizing::new(r.array::<32>()?);
            skipped.push(Skipped { dh, n, mk, ts: r.u64()? });
        }
        r.end()?;
        Ok(Self { ad, dhs_pk: x25519_public(&dhs_sk), dhs_sk, dhr, rk, cks, ckr, ns, nr, pn, skipped })
    }
}

/// Append-only binary writer for the local state formats.
pub(crate) struct Writer(Zeroizing<Vec<u8>>);

impl Writer {
    pub fn new() -> Self {
        Self(Zeroizing::new(Vec::new()))
    }
    pub fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub fn u16(&mut self, v: u16) {
        self.raw(&v.to_be_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.raw(&v.to_be_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.raw(&v.to_be_bytes());
    }
    pub fn u8(&mut self, v: u8) {
        self.raw(&[v]);
    }
    pub fn opt32(&mut self, v: Option<&[u8; 32]>) {
        match v {
            Some(k) => {
                self.u8(1);
                self.raw(k);
            }
            None => self.u8(0),
        }
    }
    pub fn opt_u64(&mut self, v: Option<u64>) {
        match v {
            Some(t) => {
                self.u8(1);
                self.u64(t);
            }
            None => self.u8(0),
        }
    }
    pub fn str(&mut self, s: &str) {
        self.u8(u8::try_from(s.len()).unwrap_or(u8::MAX));
        self.raw(s.as_bytes());
    }
    pub fn finish(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self(b)
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::Session("state"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    pub fn magic(&mut self, m: &[u8; 4]) -> Result<()> {
        if self.take(4)? == m {
            Ok(())
        } else {
            Err(Error::Session("state"))
        }
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        arr(self.take(N)?)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn opt32(&mut self) -> Result<Option<[u8; 32]>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.array()?)),
            _ => Err(Error::Session("state")),
        }
    }
    pub fn flag(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Session("state")),
        }
    }
    pub fn opt_u64(&mut self) -> Result<Option<u64>> {
        if self.flag()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }
    pub fn str(&mut self) -> Result<String> {
        let n = usize::from(self.u8()?);
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Error::Session("state"))
    }
    pub fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Session("state"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AD: [u8; 128] = [7; 128];

    fn pair() -> (Ratchet, Ratchet) {
        let spk = [0x30u8; 32];
        let a = Ratchet::init_initiator_with(&[0x31; 32], &[9; 32], &AD, &x25519_public(&spk)).unwrap();
        let b = Ratchet::init_responder(&[9; 32], &AD, &spk);
        (a, b)
    }

    fn dec(r: &mut Ratchet, m: &[u8]) -> Result<Vec<u8>> {
        use std::sync::atomic::{AtomicU8, Ordering};
        static N: AtomicU8 = AtomicU8::new(0x40);
        let k = [N.fetch_add(1, Ordering::Relaxed); 32];
        r.decrypt_with(&k, m, 1000).map(|p| p.to_vec())
    }

    #[test]
    fn ping_pong_and_out_of_order() {
        let (mut a, mut b) = pair();
        assert!(!b.can_send());
        let m1 = a.encrypt(b"one").unwrap();
        let m2 = a.encrypt(b"two").unwrap();
        let m3 = a.encrypt(b"three").unwrap();
        assert_eq!(dec(&mut b, &m3).unwrap(), b"three");
        assert_eq!(b.skipped_len(), 2);
        assert_eq!(dec(&mut b, &m1).unwrap(), b"one");
        assert_eq!(dec(&mut b, &m2).unwrap(), b"two");
        assert_eq!(b.skipped_len(), 0);
        assert!(dec(&mut b, &m2).is_err(), "replay");
        let r1 = b.encrypt(b"reply").unwrap();
        assert_eq!(dec(&mut a, &r1).unwrap(), b"reply");
        let m4 = a.encrypt(b"four").unwrap();
        assert_eq!(dec(&mut b, &m4).unwrap(), b"four");
        let r2 = b.encrypt(b"r2").unwrap();
        let r3 = b.encrypt(b"r3").unwrap();
        assert_eq!(dec(&mut a, &r3).unwrap(), b"r3");
        assert_eq!(dec(&mut a, &r2).unwrap(), b"r2");
    }

    #[test]
    fn state_unchanged_on_failure() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"hello").unwrap();
        let before = b.encode();
        let mut bad = m.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(dec(&mut b, &bad).is_err());
        assert_eq!(*b.encode(), *before);
        assert_eq!(dec(&mut b, &m).unwrap(), b"hello");
        for i in 0..m.len() {
            let (mut a2, mut b2) = pair();
            let m = a2.encrypt(b"hello").unwrap();
            let mut t = m.clone();
            t[i] ^= 0x10;
            assert!(dec(&mut b2, &t).is_err(), "byte {i}");
        }
    }

    #[test]
    fn skip_limits_and_expiry() {
        let (mut a, mut b) = pair();
        let first = a.encrypt(b"x").unwrap();
        for _ in 0..1000 {
            a.encrypt(b"-").unwrap();
        }
        let far = a.encrypt(b"far").unwrap();
        assert!(dec(&mut b, &far).is_err(), "1001 messages ahead");
        let ok = {
            let (mut a, mut b) = pair();
            for _ in 0..1000 {
                a.encrypt(b"-").unwrap();
            }
            let m = a.encrypt(b"edge").unwrap();
            dec(&mut b, &m).map(|_| b.skipped_len())
        };
        assert_eq!(ok.unwrap(), 1000);
        assert_eq!(dec(&mut b, &first).unwrap(), b"x");

        let (mut a, mut b) = pair();
        let m0 = a.encrypt(b"0").unwrap();
        let m1 = a.encrypt(b"1").unwrap();
        b.decrypt_with(&[1; 32], &m1, 0).unwrap();
        assert_eq!(b.skipped_len(), 1);
        b.expire(SKIPPED_TTL_SECS - 1);
        assert_eq!(b.skipped_len(), 1);
        assert!(b.decrypt_with(&[1; 32], &m0, SKIPPED_TTL_SECS).is_err());
        b.expire(SKIPPED_TTL_SECS);
        assert_eq!(b.skipped_len(), 0);
    }

    #[test]
    fn encode_roundtrip_is_strict() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"x").unwrap();
        let m2 = a.encrypt(b"y").unwrap();
        dec(&mut b, &m2).unwrap();
        let bytes = b.encode();
        let mut b2 = Ratchet::decode(&bytes).unwrap();
        assert_eq!(*b2.encode(), *bytes);
        assert_eq!(dec(&mut b2, &m).unwrap(), b"x");
        assert!(Ratchet::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(Ratchet::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        let mut bad = bytes.to_vec();
        bad[0] = b'Z';
        assert!(Ratchet::decode(&bad).is_err());
        let mut bad = bytes.to_vec();
        bad[4 + 128 + 32] = 2;
        assert!(Ratchet::decode(&bad).is_err());
    }

    #[test]
    fn wrong_ad_fails() {
        let (mut a, _) = pair();
        let spk = [0x30u8; 32];
        let mut b = Ratchet::init_responder(&[9; 32], &[8; 128], &spk);
        let m = a.encrypt(b"x").unwrap();
        assert!(dec(&mut b, &m).is_err());
    }
}
