#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Video sanitizing: locale, encoder fingerprints, ICC profiles and box order.
use aegis_core::attach::MediaKind;
use aegis_core::mp4clean::{fixture::build, sanitize_video};

fn pos(hay: &[u8], n: &[u8]) -> usize {
    hay.windows(n.len()).position(|w| w == n).unwrap()
}

fn find(hay: &[u8], n: &[u8]) -> bool {
    hay.windows(n.len()).any(|w| w == n)
}

#[test]
fn mdhd_language_is_not_kept() {
    let mut b = build().bytes;
    let p = pos(&b, b"mdhd") + 4; // payload of the first (video, v0) mdhd
    assert_eq!(b[p], 0);
    // ISO-639-2/T "rus", packed 3x5 bits: 0x4AB3
    b[p + 20..p + 22].copy_from_slice(&0x4AB3u16.to_be_bytes());
    let out = sanitize_video(&b).unwrap().bytes;
    let q = pos(&out, b"mdhd") + 4;
    let lang = u16::from_be_bytes([out[q + 20], out[q + 21]]);
    assert!(lang == 0 || lang == 0x55C4, "locale survived: language = {lang:#06x}");
}

#[test]
fn visual_sample_entry_vendor_is_zeroed() {
    let mut b = build().bytes;
    let p = pos(&b, b"avc1") + 4; // sample entry payload
    // QuickTime ImageDescription: version(2) revision(2) vendor(4) temporal(4) spatial(4) at +8
    b[p + 12..p + 16].copy_from_slice(b"APPL");
    b[p + 16..p + 24].copy_from_slice(&[0, 0, 2, 0, 0, 0, 4, 0]);
    let out = sanitize_video(&b).unwrap().bytes;
    let q = pos(&out, b"avc1") + 4;
    assert_eq!(&out[q + 12..q + 16], &[0, 0, 0, 0], "video vendor survived");
}

#[test]
fn colr_icc_profile_does_not_survive() {
    let mut b = build().bytes;
    let e = b.windows(4).position(|w| w == b"avc1").unwrap();
    let j = e + b[e..].windows(4).position(|w| w == b"junk").unwrap(); // 10-byte child of avc1
    b[j..j + 4].copy_from_slice(b"colr");
    b[j + 4..j + 14].copy_from_slice(b"profICCdev"); // colour_type 'prof' + ICC bytes
    let out = sanitize_video(&b).unwrap().bytes;
    assert!(!find(&out, b"ICCdev"), "ICC profile bytes survived in colr");
}

#[test]
fn sanitized_output_always_passes_the_magic_check() {
    let b = build().bytes;
    let ftyp_len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let moov_len = u32::from_be_bytes([b[ftyp_len], b[ftyp_len + 1], b[ftyp_len + 2], b[ftyp_len + 3]]) as usize;
    let junk_end = ftyp_len + moov_len;
    let junk_len = 33; // 64-bit-size `free` box of the fixture
    assert_eq!(&b[junk_end + 4..junk_end + 8], b"free");
    // Same total length and same mdat position: [free, ftyp, moov, ...rest]
    let mut v = b[junk_end..junk_end + junk_len].to_vec();
    v.extend_from_slice(&b[..junk_end]);
    v.extend_from_slice(&b[junk_end + junk_len..]);
    assert_eq!(v.len(), b.len());
    if let Ok(s) = sanitize_video(&v) {
        assert!(MediaKind::Video.has_magic(&s.bytes), "sanitizer accepted a video that the attachment layer rejects");
    }
}

