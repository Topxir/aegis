//! MP4/MOV sanitizer (spec section 16, videos).
//!
//! The output has exactly the length of the input: everything that is not on the allowlist is
//! overwritten in place (a `free` box of the same size with a zeroed payload), so every
//! `stco`/`co64` offset stays valid. Pure safe Rust; every read is bounds-checked and no input
//! can make it panic. Nesting depth is fixed by the allowlist (no recursion).

use crate::{Error, Result};

/// Largest accepted input (31 MiB).
pub const MAX_VIDEO: usize = 31 * 1024 * 1024;
/// Per-container box limit, to bound memory on hostile input.
const MAX_BOXES: usize = 10_000;

/// Sanitized video and the values shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedVideo {
    pub bytes: Vec<u8>,
    /// Integer part of the 16.16 width of the first `vide` track's `tkhd`.
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
}

fn bad(why: &'static str) -> Error {
    Error::Media(why)
}

fn be32(b: &[u8], o: usize) -> Result<u32> {
    let end = o.checked_add(4).ok_or(bad("offset"))?;
    let s = b.get(o..end).ok_or(bad("truncated"))?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], o: usize) -> Result<u64> {
    let end = o.checked_add(8).ok_or(bad("offset"))?;
    let s = b.get(o..end).ok_or(bad("truncated"))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_be_bytes(a))
}

fn usz(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

#[derive(Clone, Copy, Debug)]
struct BoxRef {
    start: usize,
    /// Header length (8 or 16).
    hdr: usize,
    end: usize,
    typ: [u8; 4],
}

impl BoxRef {
    fn payload(&self) -> usize {
        self.start + self.hdr
    }
    fn payload_len(&self) -> usize {
        self.end - self.start - self.hdr
    }
}

/// Parses the boxes tiling `[start, end)` exactly. `size == 0` runs to `end`; `size == 1` uses
/// the 64-bit size.
fn parse_boxes(buf: &[u8], start: usize, end: usize) -> Result<Vec<BoxRef>> {
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        let left = end - pos;
        if left < 8 {
            return Err(bad("trailing bytes"));
        }
        let size32 = be32(buf, pos)?;
        let t = buf.get(pos + 4..pos + 8).ok_or(bad("truncated"))?;
        let typ = [t[0], t[1], t[2], t[3]];
        let (hdr, size) = match size32 {
            0 => (8, left),
            1 => {
                if left < 16 {
                    return Err(bad("box header"));
                }
                let s = usize::try_from(be64(buf, pos + 8)?).map_err(|_| bad("box size"))?;
                (16, s)
            }
            n => (8, usz(n)),
        };
        if size < hdr || size > left {
            return Err(bad("box size"));
        }
        out.push(BoxRef { start: pos, hdr, end: pos + size, typ });
        if out.len() > MAX_BOXES {
            return Err(bad("too many boxes"));
        }
        pos += size;
    }
    Ok(out)
}

fn children(buf: &[u8], b: &BoxRef) -> Result<Vec<BoxRef>> {
    parse_boxes(buf, b.payload(), b.end)
}

/// First child of `typ`; a second one is an error.
fn one(list: &[BoxRef], typ: &[u8; 4]) -> Result<Option<BoxRef>> {
    let mut it = list.iter().filter(|b| &b.typ == typ);
    let first = it.next().copied();
    if it.next().is_some() {
        return Err(bad("duplicate box"));
    }
    Ok(first)
}

#[derive(Default)]
struct Plan {
    /// Boxes turned into `free` (type rewritten, payload zeroed).
    free: Vec<BoxRef>,
    /// Allowlisted filler boxes whose payload is zeroed but keep their type.
    scrub: Vec<BoxRef>,
    /// Plain ranges to zero (timestamps, dropped-track samples).
    zero: Vec<(usize, usize)>,
}

impl Plan {
    fn zero_len(&mut self, start: usize, len: usize) -> Result<()> {
        let end = start.checked_add(len).ok_or(bad("offset"))?;
        self.zero.push((start, end));
        Ok(())
    }
}

/// Version-dependent layout of `mvhd`/`mdhd`: returns (timescale, duration) and schedules the
/// creation and modification times for zeroing.
fn zero_times_and_duration(buf: &[u8], b: &BoxRef, plan: &mut Plan) -> Result<(u32, u64)> {
    let p = b.payload();
    let ver = *buf.get(p).ok_or(bad("truncated"))?;
    match ver {
        0 if b.payload_len() >= 20 => {
            plan.zero_len(p + 4, 8)?;
            Ok((be32(buf, p + 12)?, u64::from(be32(buf, p + 16)?)))
        }
        1 if b.payload_len() >= 32 => {
            plan.zero_len(p + 4, 16)?;
            Ok((be32(buf, p + 20)?, be64(buf, p + 24)?))
        }
        _ => Err(bad("header version")),
    }
}

/// Zeroes the times of a `tkhd` and returns (width, height) in 16.16.
fn tkhd(buf: &[u8], b: &BoxRef, plan: &mut Plan) -> Result<(u32, u32)> {
    let p = b.payload();
    let ver = *buf.get(p).ok_or(bad("truncated"))?;
    let (zero, wo) = match ver {
        0 if b.payload_len() >= 84 => (8, 76),
        1 if b.payload_len() >= 96 => (16, 88),
        _ => return Err(bad("tkhd")),
    };
    plan.zero_len(p + 4, zero)?;
    Ok((be32(buf, p + wo)?, be32(buf, p + wo + 4)?))
}

fn handler(buf: &[u8], mdia: &[BoxRef]) -> Result<Option<[u8; 4]>> {
    let Some(h) = one(mdia, b"hdlr")? else {
        return Ok(None);
    };
    if h.payload_len() < 12 {
        return Err(bad("hdlr"));
    }
    let o = h.payload() + 8;
    let s = buf.get(o..o + 4).ok_or(bad("truncated"))?;
    Ok(Some([s[0], s[1], s[2], s[3]]))
}

/// Byte ranges of all samples of a track, through `stsc`, `stsz` and `stco`/`co64`.
fn sample_ranges(
    buf: &[u8],
    stbl: &BoxRef,
    budget: &mut usize,
    out: &mut Vec<(usize, usize)>,
) -> Result<()> {
    let kids = children(buf, stbl)?;
    if kids.iter().any(|k| &k.typ == b"stz2") {
        return Err(bad("stz2"));
    }
    let stsc = one(&kids, b"stsc")?.ok_or(bad("stsc missing"))?;
    let stsz = one(&kids, b"stsz")?.ok_or(bad("stsz missing"))?;
    let stco = one(&kids, b"stco")?;
    let co64 = one(&kids, b"co64")?;
    let (co, wide) = match (stco, co64) {
        (Some(c), None) => (c, false),
        (None, Some(c)) => (c, true),
        _ => return Err(bad("chunk offsets")),
    };

    let zp = stsz.payload();
    if stsz.payload_len() < 12 {
        return Err(bad("stsz"));
    }
    let const_size = u64::from(be32(buf, zp + 4)?);
    let count = u64::from(be32(buf, zp + 8)?);
    if const_size == 0 && (stsz.payload_len() as u64 - 12) / 4 < count {
        return Err(bad("stsz table"));
    }
    if count == 0 {
        return Ok(());
    }

    let sp = stsc.payload();
    if stsc.payload_len() < 8 {
        return Err(bad("stsc"));
    }
    let entries = usz(be32(buf, sp + 4)?);
    if entries == 0 || (stsc.payload_len() - 8) / 12 < entries {
        return Err(bad("stsc table"));
    }
    let entry = |i: usize| -> Result<(u64, u64)> {
        let o = sp + 8 + i * 12;
        Ok((u64::from(be32(buf, o)?), u64::from(be32(buf, o + 4)?)))
    };
    let mut prev = 0u64;
    for i in 0..entries {
        let (first, spc) = entry(i)?;
        if first <= prev || spc == 0 || (i == 0 && first != 1) {
            return Err(bad("stsc entries"));
        }
        prev = first;
    }

    let cp = co.payload();
    if co.payload_len() < 8 {
        return Err(bad("chunk offsets"));
    }
    let chunks = usz(be32(buf, cp + 4)?);
    let esz = if wide { 8 } else { 4 };
    if (co.payload_len() - 8) / esz < chunks {
        return Err(bad("chunk offset table"));
    }

    let mut consumed = 0u64;
    let mut idx = 0usize;
    for j in 0..chunks {
        let chunk_no = j as u64 + 1;
        while idx + 1 < entries && entry(idx + 1)?.0 <= chunk_no {
            idx += 1;
        }
        let spc = entry(idx)?.1;
        if spc > count - consumed {
            return Err(bad("samples exceed stsz"));
        }
        let bytes = if const_size != 0 {
            spc.checked_mul(const_size).ok_or(bad("sample size"))?
        } else {
            let mut sum = 0u64;
            for k in 0..spc {
                let idx = u32::try_from(consumed + k).map_err(|_| bad("sample index"))?;
                let o = usz(idx).saturating_mul(4).saturating_add(zp + 12);
                sum += u64::from(be32(buf, o)?);
            }
            sum
        };
        consumed += spc;
        let off = if wide {
            be64(buf, cp + 8 + j * 8)?
        } else {
            u64::from(be32(buf, cp + 8 + j * 4)?)
        };
        let end = off.checked_add(bytes).ok_or(bad("chunk range"))?;
        if end > buf.len() as u64 {
            return Err(bad("samples outside file"));
        }
        let bytes_us = usize::try_from(bytes).map_err(|_| bad("chunk range"))?;
        *budget = budget.checked_sub(bytes_us).ok_or(bad("overlapping samples"))?;
        if bytes_us > 0 {
            let s = usize::try_from(off).map_err(|_| bad("chunk range"))?;
            out.push((s, s + bytes_us));
        }
    }
    if consumed != count {
        return Err(bad("samples do not match stsz"));
    }
    Ok(())
}

struct TrackOut {
    dims: Option<(u32, u32)>,
}

fn keep_only(list: &[BoxRef], allowed: &[&[u8; 4]], plan: &mut Plan) {
    for b in list {
        if !allowed.iter().any(|a| **a == b.typ) {
            plan.free.push(*b);
        }
    }
}

fn process_track(
    buf: &[u8],
    trak: &BoxRef,
    plan: &mut Plan,
    budget: &mut usize,
    samples: &mut Vec<(usize, usize)>,
) -> Result<TrackOut> {
    let kids = children(buf, trak)?;
    let tk = one(&kids, b"tkhd")?;
    let mdia = one(&kids, b"mdia")?;
    let mdia_kids = match &mdia {
        Some(m) => children(buf, m)?,
        None => Vec::new(),
    };
    let hdlr = handler(buf, &mdia_kids)?;
    let minf = match one(&mdia_kids, b"minf")? {
        Some(m) => children(buf, &m)?,
        None => Vec::new(),
    };
    let stbl = one(&minf, b"stbl")?;

    let is_av = matches!(hdlr, Some(h) if &h == b"vide" || &h == b"soun");
    if !is_av {
        // Whole track goes; its samples are wiped through the sample tables.
        if let Some(s) = stbl {
            sample_ranges(buf, &s, budget, samples)?;
        }
        plan.free.push(*trak);
        return Ok(TrackOut { dims: None });
    }

    let tk = tk.ok_or(bad("tkhd missing"))?;
    let (w, h) = tkhd(buf, &tk, plan)?;
    keep_only(&kids, &[b"tkhd", b"edts", b"mdia"], plan);
    let mdhd = one(&mdia_kids, b"mdhd")?.ok_or(bad("mdhd missing"))?;
    zero_times_and_duration(buf, &mdhd, plan)?;
    keep_only(&mdia_kids, &[b"mdhd", b"hdlr", b"minf"], plan);
    keep_only(&minf, &[b"vmhd", b"smhd", b"dinf", b"stbl"], plan);
    let dims = (hdlr == Some(*b"vide")).then_some((w, h));
    Ok(TrackOut { dims })
}

/// Sanitizes an MP4/MOV file. See the module docs and spec section 16.
pub fn sanitize_video(input: &[u8]) -> Result<SanitizedVideo> {
    if input.len() > MAX_VIDEO {
        return Err(bad("video too large"));
    }
    let top = parse_boxes(input, 0, input.len())?;
    let mut plan = Plan::default();
    let mut moov = None;
    let mut ftyp = false;
    for b in &top {
        match &b.typ {
            b"ftyp" => {
                if b.payload_len() < 8 {
                    return Err(bad("ftyp"));
                }
                ftyp = true;
            }
            b"moov" => {
                if moov.replace(*b).is_some() {
                    return Err(bad("duplicate moov"));
                }
            }
            b"moof" => return Err(bad("fragmented video")),
            b"mdat" => {}
            b"free" | b"skip" | b"wide" => plan.scrub.push(*b),
            _ => plan.free.push(*b),
        }
    }
    let moov = moov.ok_or(bad("moov missing"))?;
    if !ftyp {
        return Err(bad("ftyp missing"));
    }

    let kids = children(input, &moov)?;
    let mvhd = one(&kids, b"mvhd")?.ok_or(bad("mvhd missing"))?;
    let (timescale, duration) = zero_times_and_duration(input, &mvhd, &mut plan)?;
    if timescale == 0 {
        return Err(bad("timescale"));
    }
    keep_only(&kids, &[b"mvhd", b"trak"], &mut plan);

    let mut budget = input.len();
    let mut samples = Vec::new();
    let mut dims = None;
    for t in kids.iter().filter(|k| &k.typ == b"trak") {
        let mut sub = Plan::default();
        let out = process_track(input, t, &mut sub, &mut budget, &mut samples)?;
        plan.free.append(&mut sub.free);
        plan.zero.append(&mut sub.zero);
        if dims.is_none() {
            dims = out.dims;
        }
    }
    let (width, height) = dims.ok_or(bad("no video track"))?;

    let mut out = input.to_vec();
    for b in &plan.free {
        if let Some(t) = out.get_mut(b.start + 4..b.start + 8) {
            t.copy_from_slice(b"free");
        }
        if let Some(p) = out.get_mut(b.payload()..b.end) {
            p.fill(0);
        }
    }
    for b in &plan.scrub {
        if let Some(p) = out.get_mut(b.payload()..b.end) {
            p.fill(0);
        }
    }
    for &(s, e) in plan.zero.iter().chain(samples.iter()) {
        if let Some(p) = out.get_mut(s..e) {
            p.fill(0);
        }
    }
    // Zeroing sample ranges must not have damaged the box structure.
    if parse_boxes(&out, 0, out.len())?.len() != top.len() {
        return Err(bad("structure damaged"));
    }

    let ms = u128::from(duration) * 1000 / u128::from(timescale);
    Ok(SanitizedVideo {
        bytes: out,
        width: width >> 16,
        height: height >> 16,
        duration_ms: u64::try_from(ms).unwrap_or(u64::MAX),
    })
}

/// Synthetic MP4 builder used by the tests and by `docs/test-vectors.json`.
#[doc(hidden)]
pub mod fixture {
    fn bx(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = u32::try_from(payload.len() + 8).unwrap_or(0);
        [size.to_be_bytes().as_slice(), typ, payload].concat()
    }

    fn fullbox(typ: &[u8; 4], ver: u8, payload: &[u8]) -> Vec<u8> {
        bx(typ, &[[ver, 0, 0, 0].as_slice(), payload].concat())
    }

    fn u32s(v: &[u32]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_be_bytes()).collect()
    }

    /// Marker written into every creation/modification time.
    pub const TIME_MARK: u8 = 0x5a;
    pub const GPS_SAMPLE: &[u8; 20] = b"GPS+55.7558+037.6173";
    pub const GPS_UDTA: &[u8; 18] = b"+55.7558+037.6173/";

    fn tkhd(ver: u8, id: u32, w: u32, h: u32) -> Vec<u8> {
        let t = |n: usize| vec![TIME_MARK; n];
        let mut p = if ver == 0 {
            [t(8), u32s(&[id, 0, 1000]).to_vec()].concat()
        } else {
            [t(16), u32s(&[id, 0]).to_vec(), vec![0, 0, 0, 0, 0, 0, 3, 0xe8]].concat()
        };
        p.extend_from_slice(&[0; 8 + 8 + 36]);
        p.extend_from_slice(&u32s(&[w << 16, h << 16]));
        fullbox(b"tkhd", ver, &p)
    }

    fn mdhd(ver: u8, timescale: u32, dur: u32) -> Vec<u8> {
        let p = if ver == 0 {
            [vec![TIME_MARK; 8], u32s(&[timescale, dur]), vec![0, 0, 0, 0]].concat()
        } else {
            [
                vec![TIME_MARK; 16],
                u32s(&[timescale]),
                u64::from(dur).to_be_bytes().to_vec(),
                vec![0, 0, 0, 0],
            ]
            .concat()
        };
        fullbox(b"mdhd", ver, &p)
    }

    fn hdlr(kind: &[u8; 4], name: &str) -> Vec<u8> {
        let p = [vec![0; 4], kind.to_vec(), vec![0; 12], name.as_bytes().to_vec(), vec![0]].concat();
        fullbox(b"hdlr", 0, &p)
    }

    /// One chunk with `sizes.len()` samples at file offset `off`.
    fn stbl(sizes: &[u32], off: u32) -> Vec<u8> {
        let n = u32::try_from(sizes.len()).unwrap_or(0);
        let stsd = fullbox(b"stsd", 0, &u32s(&[0]));
        let stsc = fullbox(b"stsc", 0, &u32s(&[1, 1, n, 1]));
        let stsz = fullbox(b"stsz", 0, &[u32s(&[0, n]), u32s(sizes)].concat());
        let stco = fullbox(b"stco", 0, &u32s(&[1, off]));
        bx(b"stbl", &[stsd, stsc, stsz, stco].concat())
    }

    fn trak(kind: &[u8; 4], tk_ver: u8, md_ver: u8, id: u32, sizes: &[u32], off: u32, extra: &[u8]) -> Vec<u8> {
        let media_hdr = if kind == b"vide" {
            fullbox(b"vmhd", 0, &[0; 8])
        } else if kind == b"soun" {
            fullbox(b"smhd", 0, &[0; 4])
        } else {
            fullbox(b"nmhd", 0, &[])
        };
        let dinf = bx(b"dinf", &fullbox(b"dref", 0, &u32s(&[0])));
        let minf = bx(b"minf", &[media_hdr, dinf, stbl(sizes, off)].concat());
        let mdia = bx(b"mdia", &[mdhd(md_ver, 90000, 225_000), hdlr(kind, "Handler"), minf].concat());
        let (w, h) = if kind == b"vide" { (320, 240) } else { (0, 0) };
        let edts = bx(b"edts", &fullbox(b"elst", 0, &u32s(&[0])));
        bx(b"trak", &[tkhd(tk_ver, id, w, h), edts, mdia, extra.to_vec()].concat())
    }

    /// Positions of interest in a built fixture.
    #[derive(Debug, Clone)]
    pub struct Fixture {
        pub bytes: Vec<u8>,
        pub video: Vec<(usize, usize)>,
        pub audio: (usize, usize),
        pub meta: (usize, usize),
        /// Start of the `mdat` box (it is the last box).
        pub mdat_pos: usize,
    }

    /// Video (2 samples) + audio + `mebx` timed metadata carrying a fake GPS fix, `udta` with a
    /// `©xyz` location, a top-level `meta` box and a 64-bit-size `free` box with junk.
    pub fn build() -> Fixture {
        let video_samples = [vec![0x11u8; 24], vec![0x12u8; 16]].concat();
        let audio_samples = vec![0x33u8; 32];
        let meta_samples = [GPS_SAMPLE.as_slice(), GPS_SAMPLE.as_slice()].concat();
        let sizes = |n: &[usize]| n.iter().map(|x| u32::try_from(*x).unwrap_or(0)).collect::<Vec<_>>();

        let xyz = bx(&[0xa9, b'x', b'y', b'z'], &[&[0, 0x12, 0x15, 0xc7][..], GPS_UDTA].concat());
        let udta = bx(b"udta", &xyz);
        let tref = bx(b"tref", &bx(b"cdsc", &[0, 0, 0, 1]));

        let moov = |ov: u32, om: u32, oa: u32| {
            let mvhd = {
                let p = [vec![TIME_MARK; 8], u32s(&[1000, 2500, 0x0001_0000]), vec![0; 4 + 10 + 36 + 24 + 4]].concat();
                fullbox(b"mvhd", 0, &p)
            };
            let v = trak(b"vide", 0, 0, 1, &sizes(&[24, 16]), ov, &[udta.clone(), tref.clone()].concat());
            let a = trak(b"soun", 1, 1, 2, &sizes(&[32]), oa, &[]);
            let m = trak(b"mebx", 0, 0, 3, &sizes(&[20, 20]), om, &[]);
            bx(b"moov", &[mvhd, v, a, m, udta.clone()].concat())
        };

        let ftyp = bx(b"ftyp", &[b"isom".as_slice(), &[0, 0, 2, 0], b"isommp41"].concat());
        let junk = {
            let payload = b"free-secret-bytes".to_vec();
            let size = (16 + payload.len()) as u64;
            [1u32.to_be_bytes().as_slice(), b"free", &size.to_be_bytes(), &payload].concat()
        };
        let meta_box = fullbox(b"meta", 0, &bx(b"keys", GPS_UDTA));
        let head = moov(0, 0, 0).len() + ftyp.len() + junk.len() + meta_box.len();
        let mdat_pos = head;
        let base = mdat_pos + 8;
        let off = |o: usize| u32::try_from(base + o).unwrap_or(0);
        let (ov, om, oa) = (off(0), off(video_samples.len()), off(video_samples.len() + meta_samples.len()));
        let moov = moov(ov, om, oa);
        let mdat = bx(b"mdat", &[video_samples.clone(), meta_samples.clone(), audio_samples.clone()].concat());
        let bytes = [ftyp, moov, junk, meta_box, mdat].concat();
        let (vs, ms) = (base, base + video_samples.len());
        Fixture {
            bytes,
            video: vec![(vs, vs + 24), (vs + 24, vs + 40)],
            audio: (oa as usize, oa as usize + 32),
            meta: (ms, ms + meta_samples.len()),
            mdat_pos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{build, GPS_SAMPLE, GPS_UDTA, TIME_MARK};
    use super::*;

    fn find(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn strips_metadata_keeps_media() {
        let f = build();
        assert!(find(&f.bytes, GPS_SAMPLE) && find(&f.bytes, GPS_UDTA));
        assert!(find(&f.bytes, &[TIME_MARK; 4]));
        assert!(find(&f.bytes, b"free-secret-bytes"));
        let v = sanitize_video(&f.bytes).unwrap();
        assert_eq!(v.bytes.len(), f.bytes.len());
        assert!(!find(&v.bytes, GPS_SAMPLE));
        assert!(!find(&v.bytes, b"GPS+"));
        assert!(!find(&v.bytes, GPS_UDTA));
        assert!(!find(&v.bytes, b"+55.7558"));
        assert!(!find(&v.bytes, &[TIME_MARK; 4]));
        assert!(!find(&v.bytes, b"free-secret-bytes"));
        for (s, e) in f.video.iter().chain([&f.audio]) {
            assert_eq!(v.bytes[*s..*e], f.bytes[*s..*e]);
        }
        assert!(v.bytes[f.meta.0..f.meta.1].iter().all(|b| *b == 0));
        assert_eq!((v.width, v.height, v.duration_ms), (320, 240, 2500));
        // Idempotent.
        assert_eq!(sanitize_video(&v.bytes).unwrap().bytes, v.bytes);
        // Dropped boxes are `free`, not removed.
        assert!(find(&v.bytes, b"free"));
        for dropped in [b"udta".as_slice(), b"tref", b"meta", &[0xa9, b'x', b'y', b'z']] {
            assert!(!find(&v.bytes, dropped));
        }
    }

    #[test]
    fn mdat_to_end_variant() {
        let f = build();
        let mut b = f.bytes.clone();
        b[f.mdat_pos..f.mdat_pos + 4].copy_from_slice(&[0; 4]);
        let v = sanitize_video(&b).unwrap();
        assert_eq!(v.bytes.len(), b.len());
        assert_eq!(v.bytes[f.audio.0..f.audio.1], b[f.audio.0..f.audio.1]);
        assert!(v.bytes[f.meta.0..f.meta.1].iter().all(|x| *x == 0));
    }

    #[test]
    fn rejects_structural_problems() {
        let f = build();
        let b = &f.bytes;
        // fragmented
        let mut frag = b.clone();
        frag.extend_from_slice(&[0, 0, 0, 8]);
        frag.extend_from_slice(b"moof");
        assert!(sanitize_video(&frag).is_err());
        // no ftyp / no moov
        let mut no_ftyp = b.clone();
        no_ftyp[4..8].copy_from_slice(b"skip");
        assert!(sanitize_video(&no_ftyp).is_err());
        let mut no_moov = b.clone();
        let p = b.windows(4).position(|w| w == b"moov").unwrap();
        no_moov[p..p + 4].copy_from_slice(b"moox");
        assert!(sanitize_video(&no_moov).is_err());
        // no vide track
        let mut no_vide = b.clone();
        let p = b.windows(4).position(|w| w == b"vide").unwrap();
        no_vide[p..p + 4].copy_from_slice(b"subt");
        assert!(sanitize_video(&no_vide).is_err());
        // sample tables pointing outside the file
        let mut far = b.clone();
        let om = u32::try_from(f.meta.0).unwrap().to_be_bytes();
        let from = b.windows(4).position(|w| w == b"mebx").unwrap();
        let p = from + b[from..].windows(4).position(|w| w == om).unwrap();
        far[p..p + 4].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
        assert!(sanitize_video(&far).is_err());
        // inconsistent size
        let mut size = b.clone();
        size[0..4].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
        assert!(sanitize_video(&size).is_err());
        let mut small = b.clone();
        small[0..4].copy_from_slice(&4u32.to_be_bytes());
        assert!(sanitize_video(&small).is_err());
        // too large, empty, garbage
        assert!(sanitize_video(&vec![0u8; MAX_VIDEO + 1]).is_err());
        assert!(sanitize_video(&[]).is_err());
        assert!(sanitize_video(&[0xff; 100]).is_err());
        assert!(sanitize_video(b"\0\0\0\x10ftypisom\0\0\0\0").is_err());
    }

    #[test]
    fn every_truncation_is_rejected() {
        let f = build();
        for n in 0..f.bytes.len() {
            assert!(sanitize_video(&f.bytes[..n]).is_err(), "len {n}");
        }
    }

    #[test]
    fn mutation_fuzz_never_panics() {
        let f = build();
        let mut x = 0x1234_5678_9abc_def1u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..30_000 {
            let mut b = f.bytes.clone();
            for _ in 0..=(next() % 4) {
                let i = (next() % b.len() as u64) as usize;
                b[i] = match next() % 3 {
                    0 => 0,
                    1 => 0xff,
                    _ => (next() & 0xff) as u8,
                };
            }
            if next() % 8 == 0 {
                b.truncate((next() % b.len() as u64) as usize);
            }
            if let Ok(v) = sanitize_video(&b) {
                assert_eq!(v.bytes.len(), b.len());
            }
        }
    }
}
