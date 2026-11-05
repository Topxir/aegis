//! Sender keys for groups and channels: frame type 0x05 (spec section 28).

use crate::channel::channel_id;
use crate::envelope::{parse_skey_body, random_msg_id, Envelope, Kind};
use crate::group::group_id;
use crate::identity::{ed25519_public, ed25519_sign, ed25519_verify};
use crate::ratchet::{kdf_ck, msg_key, Reader, Writer};
use crate::seal::{aead_open, aead_seal};
use crate::{arr, hex, hkdf32, Error, Result};
use zeroize::Zeroizing;

pub const FRAME_SENDER_KEY: u8 = 0x05;
pub const ROTATE_AFTER_SECS: u64 = 7 * 24 * 3600;
pub const ROTATE_AFTER_MESSAGES: u32 = 1000;
pub const MAX_SKIPPED: usize = 2000;
pub const SKIPPED_TTL_SECS: u64 = 30 * 24 * 3600;
pub const OLD_CHAIN_KEEP_SECS: u64 = 30 * 24 * 3600;
const HDR_LEN: usize = 12 + 16 + 4 + 16;
const MAX_CHAINS_PER_SENDER: usize = 8;
const MAX_CHAINS: usize = 1000;

type Key = Zeroizing<[u8; 32]>;

/// Whether the key `G` belongs to a group (section 7) or a channel (section 15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Group,
    Channel,
}

impl Scope {
    fn id(self, g: &[u8; 32]) -> String {
        match self {
            Scope::Group => group_id(g),
            Scope::Channel => channel_id(g),
        }
    }

    fn allows(self, k: Kind) -> bool {
        match self {
            Scope::Group => matches!(k, Kind::Gmsg | Kind::Gmf),
            Scope::Channel => matches!(k, Kind::Cmsg | Kind::Cmf),
        }
    }
}

fn header_key(g: &[u8; 32]) -> Result<Key> {
    hkdf32(g, &[], b"aegis-v2 group-hdr")
}

fn sig_input(envelope: &[u8]) -> Vec<u8> {
    [b"aegis-v2 gmsg\n".as_slice(), envelope].concat()
}

fn chain_aad(chain_id: &[u8; 16], n: u32) -> Vec<u8> {
    [[FRAME_SENDER_KEY].as_slice(), chain_id, &n.to_be_bytes()].concat()
}

/// Our own sending chain for one group or channel.
pub struct SendChain {
    chain_id: [u8; 16],
    n: u32,
    ck: Key,
    created_at: u64,
}

impl core::fmt::Debug for SendChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendChain").field("n", &self.n).finish_non_exhaustive()
    }
}

impl SendChain {
    pub fn new(now: u64) -> Result<Self> {
        Ok(Self::new_with(crate::random_bytes()?, crate::random_bytes()?, now))
    }

    pub fn new_with(chain_id: [u8; 16], ck: [u8; 32], now: u64) -> Self {
        Self { chain_id, n: 0, ck: Zeroizing::new(ck), created_at: now }
    }

    pub fn chain_id(&self) -> [u8; 16] {
        self.chain_id
    }

    pub fn n(&self) -> u32 {
        self.n
    }

    /// True after 7 days or 1000 messages, or when a member was removed.
    pub fn needs_rotation(&self, now: u64, member_removed: bool) -> bool {
        member_removed
            || self.n >= ROTATE_AFTER_MESSAGES
            || now >= self.created_at.saturating_add(ROTATE_AFTER_SECS)
    }

    /// The `skey` envelope that gives the current state of this chain to one recipient.
    #[allow(clippy::too_many_arguments)]
    pub fn skey_envelope_with(
        &self,
        msg_id: String,
        sender: &str,
        sender_name: &str,
        sender_ed: [u8; 32],
        group_id: &str,
        ts_ms: u64,
    ) -> Envelope {
        Envelope {
            kind: Kind::Skey,
            msg_id,
            sender: sender.to_owned(),
            sender_name: sender_name.to_owned(),
            sender_ed,
            ts_ms,
            ttl_s: 0,
            group_id: group_id.to_owned(),
            body: format!("{}:{}", hex::encode(&self.chain_id), self.n),
            group_key: Some(self.ck.clone()),
            members: Vec::new(),
        }
    }

    pub fn skey_envelope(
        &self,
        sender: &str,
        sender_name: &str,
        sender_ed: [u8; 32],
        group_id: &str,
        ts_ms: u64,
    ) -> Result<Envelope> {
        Ok(self.skey_envelope_with(random_msg_id()?, sender, sender_name, sender_ed, group_id, ts_ms))
    }

    /// Encrypts `env` (kind `gmsg`/`gmf` for groups, `cmsg`/`cmf` for channels) as a type 0x05 frame
    /// and advances the chain. On error the chain is unchanged.
    pub fn encrypt(&mut self, scope: Scope, g: &[u8; 32], ed_sk: &[u8; 32], env: &Envelope) -> Result<Vec<u8>> {
        self.encrypt_with(&crate::random_bytes::<12>()?, scope, g, ed_sk, env)
    }

    pub fn encrypt_with(
        &mut self,
        hnonce: &[u8; 12],
        scope: Scope,
        g: &[u8; 32],
        ed_sk: &[u8; 32],
        env: &Envelope,
    ) -> Result<Vec<u8>> {
        if !scope.allows(env.kind) {
            return Err(Error::BadFrameType);
        }
        if env.group_id != scope.id(g) {
            return Err(Error::GroupMismatch);
        }
        if env.sender_ed != ed25519_public(ed_sk) {
            return Err(Error::SenderMismatch);
        }
        let next_n = self.n.checked_add(1).ok_or(Error::Session("chain exhausted"))?;
        let (mk, next_ck) = kdf_ck(&self.ck)?;
        let (key, nonce) = msg_key(&mk, b"aegis-v2 group-key")?;
        let bytes = Zeroizing::new(env.encode()?);
        let sig = ed25519_sign(ed_sk, &sig_input(&bytes));
        let plain = Zeroizing::new([bytes.as_slice(), &sig].concat());
        let aad = chain_aad(&self.chain_id, self.n);
        let hk = header_key(g)?;
        let hdr = aead_seal(&hk, hnonce, &[FRAME_SENDER_KEY], &aad[1..])?;
        let ct = aead_seal(&key, &nonce, &aad, &plain)?;
        self.n = next_n;
        self.ck = next_ck;
        Ok([[FRAME_SENDER_KEY].as_slice(), hnonce, &hdr, &ct].concat())
    }

    /// Local encoding `AGC1`.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.raw(b"AGC1");
        w.raw(&self.chain_id);
        w.u32(self.n);
        w.raw(self.ck.as_ref());
        w.u64(self.created_at);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.magic(b"AGC1")?;
        let s = Self {
            chain_id: r.array()?,
            n: r.u32()?,
            ck: Zeroizing::new(r.array()?),
            created_at: r.u64()?,
        };
        r.end()?;
        Ok(s)
    }
}

struct RecvChain {
    chain_id: [u8; 16],
    sender: String,
    sender_ed: [u8; 32],
    next_n: u32,
    ck: Key,
    skipped: Vec<(u32, Key, u64)>,
    superseded_at: Option<u64>,
}

impl Clone for RecvChain {
    fn clone(&self) -> Self {
        Self {
            chain_id: self.chain_id,
            sender: self.sender.clone(),
            sender_ed: self.sender_ed,
            next_n: self.next_n,
            ck: self.ck.clone(),
            skipped: self.skipped.clone(),
            superseded_at: self.superseded_at,
        }
    }
}

/// The receive side for one group or channel: every sender's chain.
pub struct RecvSet {
    scope: Scope,
    g: Key,
    hk: Key,
    owner_ed: Option<[u8; 32]>,
    chains: Vec<RecvChain>,
}

impl core::fmt::Debug for RecvSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecvSet(..)")
    }
}

impl RecvSet {
    /// `owner_ed` is required for channels: only the owner's chains are accepted.
    pub fn new(scope: Scope, g: &[u8; 32], owner_ed: Option<[u8; 32]>) -> Result<Self> {
        if scope == Scope::Channel && owner_ed.is_none() {
            return Err(Error::Session("channel needs an owner key"));
        }
        Ok(Self { scope, g: Zeroizing::new(*g), hk: header_key(g)?, owner_ed, chains: Vec::new() })
    }

    pub fn chain_count(&self) -> usize {
        self.chains.len()
    }

    /// Registers the chain from an `skey` envelope. The caller has already verified that the
    /// envelope came through the pairwise session of `env.sender` ([`crate::session`]).
    pub fn add_from_skey(&mut self, env: &Envelope, now: u64) -> Result<()> {
        if env.kind != Kind::Skey || env.group_id != self.scope.id(&self.g) {
            return Err(Error::GroupMismatch);
        }
        let (chain_id, n) = parse_skey_body(&env.body)?;
        let ck = env.group_key.as_ref().ok_or(Error::InvalidEnvelope("skey key"))?;
        self.add_chain(&env.sender, env.sender_ed, chain_id, n, ck, now)
    }

    pub fn add_chain(
        &mut self,
        sender: &str,
        sender_ed: [u8; 32],
        chain_id: [u8; 16],
        n: u32,
        ck: &[u8; 32],
        now: u64,
    ) -> Result<()> {
        if self.scope == Scope::Channel && self.owner_ed != Some(sender_ed) {
            return Err(Error::SenderMismatch);
        }
        if let Some(c) = self.chains.iter().find(|c| c.chain_id == chain_id) {
            // A repeated distribution never rewinds a chain or moves it to another sender.
            return if c.sender_ed == sender_ed && c.sender == sender { Ok(()) } else { Err(Error::SenderMismatch) };
        }
        if self.chains.len() >= MAX_CHAINS {
            return Err(Error::Session("too many chains"));
        }
        for c in &mut self.chains {
            if c.sender_ed == sender_ed {
                c.superseded_at.get_or_insert(now);
            }
        }
        self.chains.push(RecvChain {
            chain_id,
            sender: sender.to_owned(),
            sender_ed,
            next_n: n,
            ck: Zeroizing::new(*ck),
            skipped: Vec::new(),
            superseded_at: None,
        });
        let mine: Vec<usize> =
            (0..self.chains.len()).filter(|&i| self.chains[i].sender_ed == sender_ed).collect();
        if mine.len() > MAX_CHAINS_PER_SENDER {
            self.chains.remove(mine[0]);
        }
        Ok(())
    }

    /// Decrypts a type 0x05 frame. State changes only if every check passes.
    pub fn decrypt(&mut self, frame: &[u8], now: u64) -> Result<Envelope> {
        self.purge(now);
        if frame.len() < 1 + HDR_LEN + 16 + 64 {
            return Err(Error::Length);
        }
        if frame[0] != FRAME_SENDER_KEY {
            return Err(Error::BadFrameType);
        }
        let hnonce: [u8; 12] = arr(&frame[1..13])?;
        let h = aead_open(&self.hk, &hnonce, &[FRAME_SENDER_KEY], &frame[13..1 + HDR_LEN])?;
        let chain_id: [u8; 16] = arr(&h[..16])?;
        let n = u32::from_be_bytes(arr(&h[16..])?);
        let i = self
            .chains
            .iter()
            .position(|c| c.chain_id == chain_id)
            .ok_or(Error::Session("unknown chain"))?;
        let mut chain = self.chains[i].clone();
        let key_nonce = chain.take_key(n, now)?;
        let (key, nonce) = key_nonce;
        let plain = Zeroizing::new(aead_open(&key, &nonce, &chain_aad(&chain_id, n), &frame[1 + HDR_LEN..])?);
        if plain.len() < 64 {
            return Err(Error::Length);
        }
        let (body, sig) = plain.split_at(plain.len() - 64);
        let env = Envelope::decode(body)?;
        if !self.scope.allows(env.kind) {
            return Err(Error::BadFrameType);
        }
        if env.group_id != self.scope.id(&self.g) {
            return Err(Error::GroupMismatch);
        }
        if env.sender_ed != chain.sender_ed || env.sender != chain.sender {
            return Err(Error::SenderMismatch);
        }
        if !ed25519_verify(&env.sender_ed, &sig_input(body), &arr(sig)?) {
            return Err(Error::BadSignature);
        }
        self.chains[i] = chain;
        Ok(env)
    }

    /// Drops skipped keys after 30 days and chains 30 days after a newer one arrived.
    pub fn purge(&mut self, now: u64) {
        for c in &mut self.chains {
            c.skipped.retain(|s| now < s.2.saturating_add(SKIPPED_TTL_SECS));
        }
        self.chains.retain(|c| c.superseded_at.is_none_or(|t| now < t.saturating_add(OLD_CHAIN_KEEP_SECS)));
    }

    /// Local encoding `AGK1`.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.raw(b"AGK1");
        w.u8(u8::from(self.scope == Scope::Channel));
        w.raw(self.g.as_ref());
        w.opt32(self.owner_ed.as_ref());
        w.u16(u16::try_from(self.chains.len()).unwrap_or(u16::MAX));
        for c in &self.chains {
            w.raw(&c.chain_id);
            w.str(&c.sender);
            w.raw(&c.sender_ed);
            w.u32(c.next_n);
            w.raw(c.ck.as_ref());
            w.opt_u64(c.superseded_at);
            w.u16(u16::try_from(c.skipped.len()).unwrap_or(u16::MAX));
            for (n, k, ts) in &c.skipped {
                w.u32(*n);
                w.raw(k.as_ref());
                w.u64(*ts);
            }
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.magic(b"AGK1")?;
        let scope = if r.flag()? { Scope::Channel } else { Scope::Group };
        let g: [u8; 32] = r.array()?;
        let mut set = Self::new(scope, &g, r.opt32()?)?;
        for _ in 0..r.u16()? {
            let mut c = RecvChain {
                chain_id: r.array()?,
                sender: r.str()?,
                sender_ed: r.array()?,
                next_n: r.u32()?,
                ck: Zeroizing::new(r.array()?),
                superseded_at: r.opt_u64()?,
                skipped: Vec::new(),
            };
            let count = usize::from(r.u16()?);
            if count > MAX_SKIPPED {
                return Err(Error::Session("state"));
            }
            for _ in 0..count {
                c.skipped.push((r.u32()?, Zeroizing::new(r.array()?), r.u64()?));
            }
            set.chains.push(c);
        }
        r.end()?;
        if set.chains.len() > MAX_CHAINS {
            return Err(Error::Session("state"));
        }
        Ok(set)
    }
}

impl RecvChain {
    /// Returns the key and nonce for message `n`, advancing the chain and storing skipped keys.
    fn take_key(&mut self, n: u32, now: u64) -> Result<(Key, [u8; 12])> {
        if n < self.next_n {
            let i = self
                .skipped
                .iter()
                .position(|s| s.0 == n)
                .ok_or(Error::Session("message key already used"))?;
            let (_, mk, _) = self.skipped.remove(i);
            return msg_key(&mk, b"aegis-v2 group-key");
        }
        let gap = (n - self.next_n) as usize;
        if self.skipped.len() + gap > MAX_SKIPPED {
            return Err(Error::Session("too many skipped messages"));
        }
        while self.next_n < n {
            let (mk, next) = kdf_ck(&self.ck)?;
            self.skipped.push((self.next_n, mk, now));
            self.ck = next;
            self.next_n += 1;
        }
        let (mk, next) = kdf_ck(&self.ck)?;
        self.ck = next;
        self.next_n = n.checked_add(1).ok_or(Error::Session("counter"))?;
        msg_key(&mk, b"aegis-v2 group-key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::dm;

    const G: [u8; 32] = [0x55; 32];
    const ED_SK: [u8; 32] = [0x66; 32];

    fn ed() -> [u8; 32] {
        ed25519_public(&ED_SK)
    }

    fn msg(scope: Scope, body: &str) -> Envelope {
        Envelope {
            kind: if scope == Scope::Group { Kind::Gmsg } else { Kind::Cmsg },
            sender: "alice".into(),
            sender_ed: ed(),
            group_id: scope.id(&G),
            body: body.into(),
            msg_id: random_msg_id().unwrap(),
            ..dm()
        }
    }

    fn setup(scope: Scope) -> (SendChain, RecvSet) {
        let chain = SendChain::new_with([1; 16], [2; 32], 100);
        let mut set = RecvSet::new(scope, &G, Some(ed())).unwrap();
        let skey = chain.skey_envelope("alice", "Alice", ed(), &scope.id(&G), 5).unwrap();
        set.add_from_skey(&skey, 100).unwrap();
        (chain, set)
    }

    #[test]
    fn roundtrip_out_of_order_for_both_scopes() {
        for scope in [Scope::Group, Scope::Channel] {
            let (mut chain, mut set) = setup(scope);
            let f: Vec<Vec<u8>> = (0..4)
                .map(|i| chain.encrypt(scope, &G, &ED_SK, &msg(scope, &format!("m{i}"))).unwrap())
                .collect();
            assert_eq!(f[0][0], 0x05);
            assert_eq!(set.decrypt(&f[2], 101).unwrap().body, "m2");
            assert_eq!(set.decrypt(&f[0], 101).unwrap().body, "m0");
            assert_eq!(set.decrypt(&f[3], 101).unwrap().body, "m3");
            assert_eq!(set.decrypt(&f[1], 101).unwrap().body, "m1");
            assert!(set.decrypt(&f[1], 101).is_err(), "replay");
            assert!(set.decrypt(&f[3], 101).is_err(), "replay");
        }
    }

    #[test]
    fn late_joiner_starts_at_current_n() {
        let (mut chain, _) = setup(Scope::Group);
        let old = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "old")).unwrap();
        let skey = chain.skey_envelope("alice", "Alice", ed(), &group_id(&G), 5).unwrap();
        let mut late = RecvSet::new(Scope::Group, &G, None).unwrap();
        late.add_from_skey(&skey, 100).unwrap();
        assert!(late.decrypt(&old, 100).is_err());
        let new = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "new")).unwrap();
        assert_eq!(late.decrypt(&new, 100).unwrap().body, "new");
    }

    #[test]
    fn sender_must_own_the_chain() {
        let (mut chain, mut set) = setup(Scope::Group);
        let mut e = msg(Scope::Group, "x");
        e.sender = "mallory".into();
        let f = chain.encrypt(Scope::Group, &G, &ED_SK, &e).unwrap();
        assert_eq!(set.decrypt(&f, 100).unwrap_err(), Error::SenderMismatch);

        // A different signer using the same chain bytes.
        let other = [0x77u8; 32];
        let mut chain2 = SendChain::new_with([1; 16], [2; 32], 100);
        let mut e = msg(Scope::Group, "x");
        e.sender_ed = ed25519_public(&other);
        let f = chain2.encrypt(Scope::Group, &G, &other, &e).unwrap();
        assert_eq!(set.decrypt(&f, 100).unwrap_err(), Error::SenderMismatch);

        // Failed frames leave the chain unchanged, so a good frame still decrypts.
        let ok = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "ok")).unwrap();
        assert_eq!(set.decrypt(&ok, 100).unwrap().body, "ok");
    }

    #[test]
    fn channel_accepts_only_owner_chains() {
        let mut set = RecvSet::new(Scope::Channel, &G, Some(ed())).unwrap();
        let chain = SendChain::new_with([3; 16], [4; 32], 0);
        let other = ed25519_public(&[9; 32]);
        assert!(set.add_chain("eve", other, [3; 16], 0, &[4; 32], 0).is_err());
        assert!(RecvSet::new(Scope::Channel, &G, None).is_err());
        let skey = chain.skey_envelope("alice", "Alice", ed(), &channel_id(&G), 5).unwrap();
        set.add_from_skey(&skey, 0).unwrap();
        let mut bad = skey.clone();
        bad.group_id = group_id(&G);
        assert!(set.add_from_skey(&bad, 0).is_err());
    }

    #[test]
    fn wrong_kind_scope_and_tampering() {
        let (mut chain, mut set) = setup(Scope::Group);
        assert!(chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Channel, "x")).is_err());
        assert!(chain.encrypt(Scope::Channel, &G, &ED_SK, &msg(Scope::Group, "x")).is_err());
        let mut wrong = msg(Scope::Group, "x");
        wrong.group_id = "00".repeat(32);
        assert!(chain.encrypt(Scope::Group, &G, &ED_SK, &wrong).is_err());
        assert_eq!(chain.n(), 0);
        let f = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "x")).unwrap();
        for i in 0..f.len() {
            let mut t = f.clone();
            t[i] ^= 1;
            assert!(set.decrypt(&t, 100).is_err(), "byte {i}");
        }
        let mut other = RecvSet::new(Scope::Group, &[0x56; 32], None).unwrap();
        assert!(other.decrypt(&f, 100).is_err(), "header key differs");
        assert_eq!(set.decrypt(&f, 100).unwrap().body, "x");
    }

    #[test]
    fn skipped_limits_and_expiry() {
        let (mut chain, mut set) = setup(Scope::Group);
        let first = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "first")).unwrap();
        for _ in 0..MAX_SKIPPED {
            chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "-")).unwrap();
        }
        let far = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "far")).unwrap();
        assert!(set.decrypt(&far, 100).is_err());
        let mid = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "mid")).unwrap();
        assert!(set.decrypt(&mid, 100).is_err());
        assert_eq!(set.decrypt(&first, 100).unwrap().body, "first");

        let (mut chain, mut set) = setup(Scope::Group);
        let a = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "a")).unwrap();
        let b = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "b")).unwrap();
        set.decrypt(&b, 100).unwrap();
        assert!(set.decrypt(&a, 100 + SKIPPED_TTL_SECS).is_err());
    }

    #[test]
    fn rotation_rules_and_old_chain_expiry() {
        let (mut chain, mut set) = setup(Scope::Group);
        assert!(!chain.needs_rotation(100, false));
        assert!(chain.needs_rotation(100, true));
        assert!(chain.needs_rotation(100 + ROTATE_AFTER_SECS, false));
        for _ in 0..ROTATE_AFTER_MESSAGES {
            chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "-")).unwrap();
        }
        assert!(chain.needs_rotation(100, false));
        let c2 = SendChain::new_with([8; 16], [9; 32], 200);
        set.add_from_skey(&c2.skey_envelope("alice", "A", ed(), &group_id(&G), 1).unwrap(), 200).unwrap();
        assert_eq!(set.chain_count(), 2);
        set.purge(200 + OLD_CHAIN_KEEP_SECS - 1);
        assert_eq!(set.chain_count(), 2);
        set.purge(200 + OLD_CHAIN_KEEP_SECS);
        assert_eq!(set.chain_count(), 1);
    }

    #[test]
    fn state_encoding() {
        let (mut chain, mut set) = setup(Scope::Group);
        let a = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "a")).unwrap();
        let b = chain.encrypt(Scope::Group, &G, &ED_SK, &msg(Scope::Group, "b")).unwrap();
        set.decrypt(&b, 100).unwrap();
        let bytes = set.encode();
        let mut again = RecvSet::decode(&bytes).unwrap();
        assert_eq!(*again.encode(), *bytes);
        assert_eq!(again.decrypt(&a, 100).unwrap().body, "a");
        assert!(RecvSet::decode(&bytes[..bytes.len() - 1]).is_err());
        let cb = chain.encode();
        assert_eq!(*SendChain::decode(&cb).unwrap().encode(), *cb);
        assert!(SendChain::decode(&cb[..cb.len() - 1]).is_err());
    }
}
