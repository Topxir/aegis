//! Attachments: descriptor and chunked encryption of sanitized media (spec section 13).

use crate::seal::{aead_open, aead_seal};
use crate::text::parse_u64;
use crate::{hex, sha256, Error, Result};
use zeroize::Zeroizing;

pub const CHUNK: usize = 1 << 20;
pub const MAX_CHUNKS: usize = 32;
/// Largest sanitized payload `m`.
pub const MAX_SIZE: usize = 31 * CHUNK;
const MIN_PADDED: usize = 1 << 16;
const TAG: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Video,
}

impl MediaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MediaKind::Image => "image",
            MediaKind::Video => "video",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "image" => Ok(MediaKind::Image),
            "video" => Ok(MediaKind::Video),
            _ => Err(Error::Media("kind")),
        }
    }

    /// Magic bytes check on sanitized media.
    pub fn has_magic(self, m: &[u8]) -> bool {
        match self {
            MediaKind::Image => m.starts_with(&[0xff, 0xd8, 0xff]),
            MediaKind::Video => m.get(4..8) == Some(b"ftyp".as_slice()),
        }
    }
}

/// Everything about an attachment except its bytes (what travels in the `dmf`/`gmf`/`cmf` body).
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentDescriptor {
    pub kind: MediaKind,
    pub size: u64,
    pub sha256: [u8; 32],
    pub key: Zeroizing<[u8; 32]>,
    pub width: u64,
    pub height: u64,
    pub duration_ms: u64,
    pub ids: Vec<[u8; 32]>,
    pub caption: String,
}

impl core::fmt::Debug for AttachmentDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachmentDescriptor")
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("chunks", &self.ids.len())
            .finish_non_exhaustive()
    }
}

/// Non-cryptographic descriptor fields chosen by the sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMeta {
    pub kind: MediaKind,
    pub width: u64,
    pub height: u64,
    pub duration_ms: u64,
    pub caption: String,
}

/// Result of sealing: the descriptor plus the ciphertext chunks (`chunks[i]` is stored under `ids[i]`).
#[derive(Debug)]
pub struct SealedAttachment {
    pub descriptor: AttachmentDescriptor,
    pub chunks: Vec<Vec<u8>>,
}

/// Total padded length for a payload of `size` bytes: `BE64(len) || m` rounded up to the
/// smallest power of two that is at least 65536. `None` when `size` exceeds [`MAX_SIZE`].
pub fn padded_len(size: u64) -> Option<usize> {
    let size = usize::try_from(size).ok().filter(|s| *s <= MAX_SIZE)?;
    (size + 8).checked_next_power_of_two().map(|p| p.max(MIN_PADDED))
}

/// Number of 1 MiB chunks for a payload of `size` bytes.
pub fn chunk_count(size: u64) -> Option<usize> {
    padded_len(size).map(|p| p.div_ceil(CHUNK))
}

fn chunk_nonce(i: usize) -> Result<[u8; 12]> {
    let i = u32::try_from(i).map_err(|_| Error::Media("chunk index"))?;
    let mut n = [0u8; 12];
    n[8..].copy_from_slice(&i.to_be_bytes());
    Ok(n)
}

fn chunk_aad(i: usize, n: usize) -> Result<Vec<u8>> {
    let i = u32::try_from(i).map_err(|_| Error::Media("chunk index"))?;
    let n = u32::try_from(n).map_err(|_| Error::Media("chunk count"))?;
    Ok([b"aegis-v2 blob".as_slice(), &i.to_be_bytes(), &n.to_be_bytes()].concat())
}

/// Seals `m` with an injected key and chunk ids (`ids.len()` must equal [`chunk_count`]).
pub fn seal_attachment_with(
    meta: &AttachmentMeta,
    m: &[u8],
    key: &[u8; 32],
    ids: &[[u8; 32]],
) -> Result<SealedAttachment> {
    let size = u64::try_from(m.len()).map_err(|_| Error::Media("size"))?;
    let n = chunk_count(size).ok_or(Error::Media("too large"))?;
    if ids.len() != n || m.is_empty() || !meta.kind.has_magic(m) {
        return Err(Error::Media("attachment"));
    }
    let total = padded_len(size).ok_or(Error::Media("too large"))?;
    let mut padded = Zeroizing::new(vec![0u8; total]);
    padded[..8].copy_from_slice(&size.to_be_bytes());
    padded[8..8 + m.len()].copy_from_slice(m);
    let mut chunks = Vec::with_capacity(n);
    for (i, part) in padded.chunks(CHUNK).enumerate() {
        chunks.push(aead_seal(key, &chunk_nonce(i)?, &chunk_aad(i, n)?, part)?);
    }
    let descriptor = AttachmentDescriptor {
        kind: meta.kind,
        size,
        sha256: sha256(&[m]),
        key: Zeroizing::new(*key),
        width: meta.width,
        height: meta.height,
        duration_ms: meta.duration_ms,
        ids: ids.to_vec(),
        caption: meta.caption.clone(),
    };
    descriptor.validate()?;
    Ok(SealedAttachment { descriptor, chunks })
}

/// Seals `m` with a fresh random key and unrelated random chunk ids.
pub fn seal_attachment(meta: &AttachmentMeta, m: &[u8]) -> Result<SealedAttachment> {
    let size = u64::try_from(m.len()).map_err(|_| Error::Media("size"))?;
    let n = chunk_count(size).ok_or(Error::Media("too large"))?;
    let key = Zeroizing::new(crate::random_bytes::<32>()?);
    let mut ids = Vec::with_capacity(n);
    for _ in 0..n {
        ids.push(crate::random_bytes::<32>()?);
    }
    seal_attachment_with(meta, m, &key, &ids)
}

/// Fetches nothing: decrypts chunks already downloaded in order, then verifies length, SHA-256
/// and magic bytes. Fails closed on any mismatch.
pub fn open_attachment(desc: &AttachmentDescriptor, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    desc.validate()?;
    let n = desc.ids.len();
    let total = padded_len(desc.size).ok_or(Error::Media("too large"))?;
    if chunks.len() != n {
        return Err(Error::Media("chunk count"));
    }
    let mut padded = Zeroizing::new(Vec::with_capacity(total));
    for (i, ct) in chunks.iter().enumerate() {
        let want = total.saturating_sub(i * CHUNK).min(CHUNK) + TAG;
        if ct.len() != want {
            return Err(Error::Media("chunk length"));
        }
        let pt = Zeroizing::new(aead_open(&desc.key, &chunk_nonce(i)?, &chunk_aad(i, n)?, ct)?);
        padded.extend_from_slice(&pt);
    }
    if padded.len() != total {
        return Err(Error::Media("padded length"));
    }
    let (len_bytes, rest) = padded.split_at(8);
    let len = u64::from_be_bytes(crate::arr::<8>(len_bytes)?);
    if len != desc.size || usize::try_from(len).map_err(|_| Error::Media("size"))? > rest.len() {
        return Err(Error::Media("length"));
    }
    let m = rest
        .get(..usize::try_from(len).map_err(|_| Error::Media("size"))?)
        .ok_or(Error::Media("length"))?;
    if sha256(&[m]) != desc.sha256 {
        return Err(Error::Media("sha256"));
    }
    if !desc.kind.has_magic(m) {
        return Err(Error::Media("magic bytes"));
    }
    Ok(m.to_vec())
}

fn dec(s: &str) -> Result<u64> {
    parse_u64(s).map_err(|_| Error::Media("number"))
}

impl AttachmentDescriptor {
    fn validate(&self) -> Result<()> {
        let n = chunk_count(self.size).ok_or(Error::Media("size"))?;
        if self.size == 0 || self.ids.len() != n || n > MAX_CHUNKS || n == 0 {
            return Err(Error::Media("chunk count"));
        }
        if self.caption.contains('\n') {
            return Err(Error::Media("caption"));
        }
        if self.kind == MediaKind::Image && self.duration_ms != 0 {
            return Err(Error::Media("duration"));
        }
        Ok(())
    }

    /// The 10-line envelope body (before percent-encoding).
    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let ids: Vec<String> = self.ids.iter().map(|i| hex::encode(i)).collect();
        Ok([
            "AT1".to_owned(),
            self.kind.as_str().to_owned(),
            self.size.to_string(),
            hex::encode(&self.sha256),
            hex::encode(self.key.as_ref()),
            self.width.to_string(),
            self.height.to_string(),
            self.duration_ms.to_string(),
            ids.join(","),
            self.caption.clone(),
        ]
        .join("\n"))
    }

    /// Strict parser: exactly 10 lines, header `AT1`, lowercase hex, canonical decimals.
    pub fn parse(body: &str) -> Result<Self> {
        let lines: Vec<&str> = body.split('\n').collect();
        let [hdr, kind, size, sha, key, w, h, dur, ids, caption] = lines.as_slice() else {
            return Err(Error::Media("line count"));
        };
        if *hdr != "AT1" {
            return Err(Error::Media("header"));
        }
        if !hex::is_hex_len(sha, 32) || !hex::is_hex_len(key, 32) {
            return Err(Error::Media("hex"));
        }
        let mut id_list = Vec::new();
        for id in ids.split(',') {
            if id_list.len() >= MAX_CHUNKS || !hex::is_hex_len(id, 32) {
                return Err(Error::Media("ids"));
            }
            id_list.push(hex::decode_array::<32>(id)?);
        }
        let d = AttachmentDescriptor {
            kind: MediaKind::parse(kind)?,
            size: dec(size)?,
            sha256: hex::decode_array(sha)?,
            key: Zeroizing::new(hex::decode_array(key)?),
            width: dec(w)?,
            height: dec(h)?,
            duration_ms: dec(dur)?,
            ids: id_list,
            caption: (*caption).to_owned(),
        };
        d.validate()?;
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg(len: usize) -> Vec<u8> {
        let mut m: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        m[..3].copy_from_slice(&[0xff, 0xd8, 0xff]);
        m
    }

    fn meta() -> AttachmentMeta {
        AttachmentMeta {
            kind: MediaKind::Image,
            width: 640,
            height: 480,
            duration_ms: 0,
            caption: "hi \u{202E}%".into(),
        }
    }

    fn ids(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [u8::try_from(i).unwrap() + 1; 32]).collect()
    }

    #[test]
    fn sizes() {
        assert_eq!(padded_len(1), Some(65536));
        assert_eq!(padded_len(65528), Some(65536));
        assert_eq!(padded_len(65529), Some(131_072));
        assert_eq!(chunk_count(1_048_568), Some(1));
        assert_eq!(chunk_count(1_048_569), Some(2));
        assert_eq!(chunk_count(MAX_SIZE as u64), Some(32));
        assert_eq!(padded_len(MAX_SIZE as u64 + 1), None);
    }

    #[test]
    fn roundtrip_single_and_multi_chunk() {
        for len in [3usize, 1000, 65528, 65529, 1_048_569, 3_000_000] {
            let m = jpeg(len);
            let n = chunk_count(len as u64).unwrap();
            let s = seal_attachment_with(&meta(), &m, &[7; 32], &ids(n)).unwrap();
            assert_eq!(s.chunks.len(), n);
            assert_eq!(open_attachment(&s.descriptor, &s.chunks).unwrap(), m);
            let body = s.descriptor.encode().unwrap();
            let d = AttachmentDescriptor::parse(&body).unwrap();
            assert_eq!(d, s.descriptor);
            assert_eq!(open_attachment(&d, &s.chunks).unwrap(), m);
        }
    }

    #[test]
    fn random_wrapper_uses_unrelated_ids() {
        let a = seal_attachment(&meta(), &jpeg(100)).unwrap();
        let b = seal_attachment(&meta(), &jpeg(100)).unwrap();
        assert_ne!(a.descriptor.ids, b.descriptor.ids);
        assert_ne!(*a.descriptor.key, *b.descriptor.key);
    }

    #[test]
    fn fails_closed() {
        let m = jpeg(2_000_000);
        let s = seal_attachment_with(&meta(), &m, &[7; 32], &ids(2)).unwrap();
        let d = &s.descriptor;
        // swapped, missing, extra, truncated, flipped chunks
        let swapped = vec![s.chunks[1].clone(), s.chunks[0].clone()];
        assert!(open_attachment(d, &swapped).is_err());
        assert!(open_attachment(d, &s.chunks[..1]).is_err());
        let mut extra = s.chunks.clone();
        extra.push(vec![0; 17]);
        assert!(open_attachment(d, &extra).is_err());
        let mut t = s.chunks.clone();
        t[1].pop();
        assert!(open_attachment(d, &t).is_err());
        let mut t = s.chunks.clone();
        t[0][100] ^= 1;
        assert!(open_attachment(d, &t).is_err());
        // wrong sha, wrong size, wrong key, wrong kind
        let mut bad = d.clone();
        bad.sha256[0] ^= 1;
        assert!(open_attachment(&bad, &s.chunks).is_err());
        let mut bad = d.clone();
        bad.size -= 1;
        assert!(open_attachment(&bad, &s.chunks).is_err());
        let mut bad = d.clone();
        *bad.key = [8; 32];
        assert!(open_attachment(&bad, &s.chunks).is_err());
        let mut bad = d.clone();
        bad.kind = MediaKind::Video;
        assert!(open_attachment(&bad, &s.chunks).is_err());
        // chunk replayed under a different chunk count (aad binds n)
        let one = seal_attachment_with(&meta(), &jpeg(100), &[7; 32], &ids(1)).unwrap();
        let mut bad = one.descriptor.clone();
        bad.size = m.len() as u64;
        assert!(open_attachment(&bad, &one.chunks).is_err());
    }

    #[test]
    fn rejects_bad_magic_and_sizes_at_seal() {
        let mut m = jpeg(100);
        m[0] = 0;
        assert!(seal_attachment_with(&meta(), &m, &[7; 32], &ids(1)).is_err());
        assert!(seal_attachment_with(&meta(), &jpeg(100), &[7; 32], &ids(2)).is_err());
        assert!(seal_attachment_with(&meta(), &[], &[7; 32], &ids(1)).is_err());
        let mut mp4 = vec![0, 0, 0, 16];
        mp4.extend_from_slice(b"ftypisom");
        mp4.extend_from_slice(&[0; 4]);
        let vm = AttachmentMeta { kind: MediaKind::Video, duration_ms: 1000, ..meta() };
        let s = seal_attachment_with(&vm, &mp4, &[7; 32], &ids(1)).unwrap();
        assert_eq!(open_attachment(&s.descriptor, &s.chunks).unwrap(), mp4);
        assert!(seal_attachment_with(&meta(), &mp4, &[7; 32], &ids(1)).is_err());
    }

    #[test]
    fn descriptor_parser_is_strict() {
        let s = seal_attachment_with(&meta(), &jpeg(100), &[7; 32], &ids(1)).unwrap();
        let body = s.descriptor.encode().unwrap();
        assert!(AttachmentDescriptor::parse(&body).is_ok());
        let lines: Vec<&str> = body.split('\n').collect();
        let with = |i: usize, v: &str| {
            let mut l = lines.clone();
            l[i] = v;
            l.join("\n")
        };
        let upper = lines[3].to_uppercase();
        let long_id = format!("{}00", lines[8]);
        let two_ids = format!("{},{}", lines[8], lines[8]);
        let bad = [
            format!("{body}\nextra"),
            lines[..9].join("\n"),
            with(0, "AT2"),
            with(1, "audio"),
            with(1, "Image"),
            with(2, "+100"),
            with(2, "0100"),
            with(2, "-1"),
            with(2, "0"),
            with(2, "1048569"),
            with(2, "32505857"),
            with(3, &upper),
            with(3, "ab"),
            with(4, &lines[4][2..]),
            with(5, "1.5"),
            with(6, ""),
            with(7, "5"),
            with(8, ""),
            with(8, &long_id),
            with(8, &two_ids),
            with(8, &format!("{},", lines[8])),
        ];
        for b in bad {
            assert!(AttachmentDescriptor::parse(&b).is_err(), "{b}");
        }
        // caption may be empty and may contain separators other than \n
        let ok = with(9, "");
        assert_eq!(AttachmentDescriptor::parse(&ok).unwrap().caption, "");
        let mut d = s.descriptor;
        d.caption = "a\nb".into();
        assert!(d.encode().is_err());
        // 33 chunks never allowed
        let many = vec![lines[8]; 33].join(",");
        assert!(AttachmentDescriptor::parse(&with(8, &many)).is_err());
    }

    #[test]
    fn descriptor_in_envelope_roundtrips() {
        use crate::envelope::{Envelope, Kind};
        let s = seal_attachment_with(&meta(), &jpeg(100), &[7; 32], &ids(1)).unwrap();
        let e = Envelope {
            kind: Kind::Dmf,
            body: s.descriptor.encode().unwrap(),
            ..crate::envelope::tests::dm()
        };
        let d = Envelope::decode(&e.encode().unwrap()).unwrap();
        assert_eq!(AttachmentDescriptor::parse(&d.body).unwrap(), s.descriptor);
    }
}
