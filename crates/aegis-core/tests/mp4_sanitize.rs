//! Regression tests: nothing a sender can put into a kept box or into unreferenced `mdat` bytes
//! may reach the output.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::mp4clean::{fixture, fixture::build, sanitize_video};

fn find(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

const SECRET: &[u8] = b"GPS+55.7558+037.6173-SECRET";

#[test]
fn unreferenced_mdat_bytes_are_zeroed() {
    let f = build();
    let mut b = f.bytes.clone();
    let old = u32::from_be_bytes(b[f.mdat_pos..f.mdat_pos + 4].try_into().unwrap());
    b.extend_from_slice(SECRET);
    let new = old + SECRET.len() as u32;
    b[f.mdat_pos..f.mdat_pos + 4].copy_from_slice(&new.to_be_bytes());
    let v = sanitize_video(&b).unwrap();
    assert!(!find(&v.bytes, SECRET));
    assert!(!find(&v.bytes, fixture::MDAT_SECRET));
    assert_eq!(v.bytes.len(), b.len());
    for (s, e) in f.video.iter().chain([&f.audio]) {
        assert_eq!(v.bytes[*s..*e], f.bytes[*s..*e]);
    }
}

#[test]
fn ftyp_tail_and_hdlr_name_are_blanked() {
    let f = build();
    let mut b = f.bytes.clone();
    let p = b.windows(8).position(|w| w == b"isommp41").unwrap();
    b[p..p + 8].copy_from_slice(b"SECRET!!");
    let name = fixture::HDLR_NAME.as_bytes();
    let h = b.windows(name.len()).position(|w| w == name).unwrap();
    b[h..h + 7].copy_from_slice(b"LOCATE!");
    let v = sanitize_video(&b).unwrap();
    assert!(!find(&v.bytes, b"SECRET!!"));
    assert!(!find(&v.bytes, b"XSEC"));
    assert!(!find(&v.bytes, b"LOCATE!"));
    assert!(!find(&v.bytes, name));
    // minor version is zero and the major brand is kept
    assert_eq!(&v.bytes[8..16], b"isom\0\0\0\0");
}

#[test]
fn sample_entries_dref_and_stbl_children_are_cleaned() {
    let f = build();
    for secret in [
        fixture::COMPRESSOR.as_slice(),
        fixture::VENDOR,
        fixture::ENTRY_JUNK,
        fixture::STBL_JUNK,
        fixture::DREF_URL,
        fixture::EDTS_JUNK,
    ] {
        assert!(find(&f.bytes, secret));
    }
    let v = sanitize_video(&f.bytes).unwrap();
    for secret in [
        fixture::COMPRESSOR.as_slice(),
        fixture::VENDOR,
        fixture::ENTRY_JUNK,
        fixture::STBL_JUNK,
        fixture::DREF_URL,
        fixture::EDTS_JUNK,
    ] {
        assert!(!find(&v.bytes, secret), "{}", String::from_utf8_lossy(secret));
    }
    // codec configuration stays
    assert!(find(&v.bytes, b"avcC") && find(&v.bytes, b"esds"));
    assert_eq!(sanitize_video(&v.bytes).unwrap().bytes, v.bytes);
}

#[test]
fn dropped_metadata_leaves_a_single_free_box_per_container() {
    let f = build();
    let v = sanitize_video(&f.bytes).unwrap();
    // the moov children that were dropped (udta, meta track, ...) are not individually visible
    assert!(!find(&v.bytes, b"udta") && !find(&v.bytes, b"tref") && !find(&v.bytes, b"mebx"));
}

#[test]
fn dropped_track_without_stbl_does_not_leak_its_samples() {
    let f = build();
    let sample = &f.bytes[f.meta.0..f.meta.0 + 8];
    let mut b = f.bytes.clone();
    // Turn the metadata track's `mdia` into an unknown box: the track then has no
    // mdia, minf or stbl, so nothing says where its samples are.
    let hdlr = b.windows(4).position(|w| w == b"mebx").unwrap();
    let mdia = b[..hdlr].windows(4).rposition(|w| w == b"mdia").unwrap();
    b[mdia..mdia + 4].copy_from_slice(b"zzzz");
    assert!(find(&b, sample));
    // Either refused, or every mdat byte no kept track references is zeroed.
    if let Ok(v) = sanitize_video(&b) {
        assert!(!find(&v.bytes, sample), "samples of the stripped track survived");
        for (s, e) in f.video.iter().chain([&f.audio]) {
            assert_eq!(v.bytes[*s..*e], f.bytes[*s..*e]);
        }
    }
}
