//! Photos and videos: sanitizing before sealing, the encrypted local store and
//! the replies served to the webview.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use aegis_core::{hex, random_bytes, sha256};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use image::imageops::FilterType;
use image::metadata::Orientation;
use image::{DynamicImage, ExtendedColorType, ImageDecoder, ImageFormat, ImageReader, Limits};

pub const MAX_INPUT: usize = 40 << 20;
pub const MAX_PIXELS: u64 = 50_000_000;
pub const MAX_EDGE: u32 = 2560;
const JPEG_QUALITY: u8 = 85;
const AAD: &[u8] = b"aegis-v2 media";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaError {
    TooLarge,
    Unsupported,
    Corrupt,
    Io,
}

#[derive(Debug)]
pub struct Clean {
    pub bytes: Vec<u8>,
    pub w: u32,
    pub h: u32,
}

/// Decodes a JPEG, PNG or WebP picture and re-encodes it as a plain JPEG:
/// orientation applied, at most 2560 px on the long side, no APPn or comment segments.
pub fn sanitize_image(input: &[u8]) -> Result<Clean, MediaError> {
    if input.len() > MAX_INPUT {
        return Err(MediaError::TooLarge);
    }
    let mut reader = ImageReader::new(Cursor::new(input))
        .with_guessed_format()
        .map_err(|_| MediaError::Corrupt)?;
    match reader.format() {
        Some(ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP) => {}
        _ => return Err(MediaError::Unsupported),
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(20_000);
    limits.max_image_height = Some(20_000);
    limits.max_alloc = Some(512 << 20);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().map_err(|_| MediaError::Corrupt)?;
    let (w, h) = decoder.dimensions();
    if w == 0 || h == 0 || u64::from(w) * u64::from(h) > MAX_PIXELS {
        return Err(MediaError::TooLarge);
    }
    let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
    let mut img = DynamicImage::from_decoder(decoder).map_err(|_| MediaError::Corrupt)?;
    img.apply_orientation(orientation);
    if img.width().max(img.height()) > MAX_EDGE {
        img = img.resize(MAX_EDGE, MAX_EDGE, FilterType::Lanczos3);
    }
    let rgb = flatten(&img);
    let (w, h) = (rgb.width(), rgb.height());
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY)
        .encode(rgb.as_raw(), w, h, ExtendedColorType::Rgb8)
        .map_err(|_| MediaError::Corrupt)?;
    let bytes = strip_segments(&out).ok_or(MediaError::Corrupt)?;
    Ok(Clean { bytes, w, h })
}

/// Transparent pixels go over white so the JPEG has no alpha to lose.
fn flatten(img: &DynamicImage) -> image::RgbImage {
    if !img.color().has_alpha() {
        return img.to_rgb8();
    }
    let rgba = img.to_rgba8();
    let mut out = image::RgbImage::new(rgba.width(), rgba.height());
    for (x, y, p) in rgba.enumerate_pixels() {
        let a = u32::from(p[3]);
        let mix = |c: u8| -> u8 { ((u32::from(c) * a + 255 * (255 - a) + 127) / 255) as u8 };
        out.put_pixel(x, y, image::Rgb([mix(p[0]), mix(p[1]), mix(p[2])]));
    }
    out
}

fn is_metadata_marker(marker: u8) -> bool {
    (0xe0..=0xef).contains(&marker) || marker == 0xfe
}

/// Removes APP0..APP15 and COM segments from the header part of a JPEG and
/// checks that none are left.
fn strip_segments(jpeg: &[u8]) -> Option<Vec<u8>> {
    if jpeg.get(..2)? != [0xff, 0xd8] {
        return None;
    }
    let mut out = vec![0xff, 0xd8];
    let mut i = 2;
    loop {
        if *jpeg.get(i)? != 0xff {
            return None;
        }
        let marker = *jpeg.get(i + 1)?;
        if marker == 0xff {
            i += 1;
            continue;
        }
        if marker == 0xda {
            out.extend_from_slice(jpeg.get(i..)?);
            break;
        }
        let len = usize::from(u16::from_be_bytes([*jpeg.get(i + 2)?, *jpeg.get(i + 3)?]));
        if len < 2 {
            return None;
        }
        let end = i.checked_add(2)?.checked_add(len)?;
        let seg = jpeg.get(i..end)?;
        if !is_metadata_marker(marker) {
            out.extend_from_slice(seg);
        }
        i = end;
    }
    if has_metadata_segments(&out) {
        return None;
    }
    Some(out)
}

/// True when an APPn or COM marker precedes the scan.
pub fn has_metadata_segments(jpeg: &[u8]) -> bool {
    let mut i = 2;
    while i + 4 <= jpeg.len() {
        if jpeg[i] != 0xff {
            return true;
        }
        let marker = jpeg[i + 1];
        if marker == 0xff {
            i += 1;
            continue;
        }
        if marker == 0xda {
            return false;
        }
        if is_metadata_marker(marker) {
            return true;
        }
        let len = usize::from(u16::from_be_bytes([jpeg[i + 2], jpeg[i + 3]]));
        i += 2 + len.max(2);
    }
    false
}

pub fn media_dir(vault: &Path) -> PathBuf {
    let mut name = vault
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".media");
    vault.with_file_name(name)
}

pub fn valid_file_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn new_file_id() -> Result<String, MediaError> {
    let r = random_bytes::<16>().map_err(|_| MediaError::Io)?;
    Ok(hex::encode(&r))
}

pub fn store(dir: &Path, key: &[u8; 32], file: &str, plain: &[u8]) -> Result<(), MediaError> {
    if !valid_file_id(file) {
        return Err(MediaError::Io);
    }
    let nonce = random_bytes::<12>().map_err(|_| MediaError::Io)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: AAD,
            },
        )
        .map_err(|_| MediaError::Io)?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    std::fs::create_dir_all(dir).map_err(|_| MediaError::Io)?;
    aegis_core::vault::write_atomic(&dir.join(format!("{file}.bin")), &blob)
        .map_err(|_| MediaError::Io)
}

pub fn load(dir: &Path, key: &[u8; 32], file: &str) -> Option<Vec<u8>> {
    if !valid_file_id(file) {
        return None;
    }
    let blob = std::fs::read(dir.join(format!("{file}.bin"))).ok()?;
    if blob.len() < 12 + 16 {
        return None;
    }
    let (nonce, ct) = blob.split_at(12);
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: AAD })
        .ok()
}

pub fn remove(dir: &Path, file: &str) {
    if valid_file_id(file) {
        let _ = std::fs::remove_file(dir.join(format!("{file}.bin")));
    }
}

/// Opaque id that the page uses in `/media/<id>`; changes at every unlock.
pub fn session_id(secret: &[u8; 32], file: &str) -> String {
    let h = sha256(&[b"aegis media sid", secret, file.as_bytes()]);
    hex::encode(&h)[..32].to_owned()
}

pub fn is_video(bytes: &[u8]) -> bool {
    bytes.get(4..8) == Some(b"ftyp".as_slice())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub mime: &'static str,
    pub content_range: Option<String>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn not_found() -> Self {
        Reply {
            status: 404,
            mime: "text/plain",
            content_range: None,
            body: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Range {
    Whole,
    Part(usize, usize),
    Bad,
}

/// One `bytes=` range; several ranges are served as the whole body.
pub fn parse_range(header: Option<&str>, len: usize) -> Range {
    let Some(h) = header else { return Range::Whole };
    let Some(spec) = h.trim().strip_prefix("bytes=") else {
        return Range::Whole;
    };
    if spec.contains(',') || len == 0 {
        return Range::Whole;
    }
    let Some((a, b)) = spec.split_once('-') else {
        return Range::Whole;
    };
    let (a, b) = (a.trim(), b.trim());
    let last = len - 1;
    if a.is_empty() {
        return match b.parse::<usize>() {
            Ok(n) if n > 0 => Range::Part(len.saturating_sub(n), last),
            _ => Range::Bad,
        };
    }
    let Ok(start) = a.parse::<usize>() else {
        return Range::Whole;
    };
    let end = if b.is_empty() {
        last
    } else {
        match b.parse::<usize>() {
            Ok(e) => e.min(last),
            Err(_) => return Range::Whole,
        }
    };
    if start > last || start > end {
        return Range::Bad;
    }
    Range::Part(start, end)
}

pub fn reply(plain: Vec<u8>, range: Option<&str>) -> Reply {
    let mime = if is_video(&plain) {
        "video/mp4"
    } else {
        "image/jpeg"
    };
    let len = plain.len();
    match parse_range(range, len) {
        Range::Whole => Reply {
            status: 200,
            mime,
            content_range: None,
            body: plain,
        },
        Range::Part(a, b) => Reply {
            status: 206,
            mime,
            content_range: Some(format!("bytes {a}-{b}/{len}")),
            body: plain[a..=b].to_vec(),
        },
        Range::Bad => Reply {
            status: 416,
            mime,
            content_range: Some(format!("bytes */{len}")),
            body: Vec::new(),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const GPS: &[u8] = b"GPS-55.7558N-37.6173E";

    #[test]
    fn unknown_media_is_404_and_empty() {
        let r = Reply::not_found();
        assert_eq!(r.status, 404);
        assert!(r.body.is_empty());
        assert!(r.content_range.is_none());
    }

    /// Plain JPEG, then an APP1 Exif segment (Orientation 6 and a GPS marker) after SOI.
    fn jpeg_with_exif(w: u32, h: u32) -> Vec<u8> {
        let img =
            image::RgbImage::from_fn(w, h, |x, y| image::Rgb([(x * 9) as u8, (y * 9) as u8, 90]));
        let mut plain = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut plain)
            .encode(img.as_raw(), w, h, ExtendedColorType::Rgb8)
            .unwrap();
        let mut exif = b"Exif\0\0MM\0\x2a\0\0\0\x08".to_vec();
        exif.extend_from_slice(&[0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0]);
        exif.extend_from_slice(GPS);
        let mut out = vec![0xff, 0xd8, 0xff, 0xe1];
        out.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&exif);
        out.extend_from_slice(&plain[2..]);
        out
    }

    fn find(h: &[u8], n: &[u8]) -> bool {
        h.windows(n.len()).any(|w| w == n)
    }

    #[test]
    fn exif_is_applied_and_removed() {
        let input = jpeg_with_exif(40, 24);
        assert!(find(&input, GPS));
        let out = sanitize_image(&input).unwrap();
        assert_eq!((out.w, out.h), (24, 40));
        assert!(!find(&out.bytes, GPS));
        assert!(!find(&out.bytes, b"Exif"));
        assert!(!has_metadata_segments(&out.bytes));
        assert_eq!(&out.bytes[..3], &[0xff, 0xd8, 0xff]);
        let back = image::load_from_memory(&out.bytes).unwrap();
        assert_eq!((back.width(), back.height()), (24, 40));
    }

    #[test]
    fn large_images_are_scaled_down() {
        let img = image::RgbImage::from_pixel(3000, 40, image::Rgb([1, 2, 3]));
        let mut png = Vec::new();
        img.write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
            .unwrap();
        let out = sanitize_image(&png).unwrap();
        assert_eq!(out.w, MAX_EDGE);
        assert!(!has_metadata_segments(&out.bytes));
    }

    #[test]
    fn other_formats_are_rejected() {
        let mut heic = vec![0, 0, 0, 24];
        heic.extend_from_slice(b"ftypheic\0\0\0\0mif1heic");
        assert_eq!(sanitize_image(&heic).err(), Some(MediaError::Unsupported));
        assert_eq!(
            sanitize_image(b"GIF89a\x01\0\x01\0\0\0\0;").err(),
            Some(MediaError::Unsupported)
        );
        assert!(sanitize_image(b"hello").is_err());
        assert!(sanitize_image(&[]).is_err());
    }

    #[test]
    fn store_roundtrip_and_tamper() {
        let dir = std::env::temp_dir().join(format!("aegis-media-{}", new_file_id().unwrap()));
        let key = [7u8; 32];
        let id = new_file_id().unwrap();
        store(&dir, &key, &id, b"hello").unwrap();
        assert_eq!(load(&dir, &key, &id).unwrap(), b"hello");
        assert!(load(&dir, &[8u8; 32], &id).is_none());
        assert!(load(&dir, &key, "../x").is_none());
        let p = dir.join(format!("{id}.bin"));
        let mut raw = std::fs::read(&p).unwrap();
        let n = raw.len() - 1;
        raw[n] ^= 1;
        std::fs::write(&p, raw).unwrap();
        assert!(load(&dir, &key, &id).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 10), Range::Whole);
        assert_eq!(parse_range(Some("bytes=0-3"), 10), Range::Part(0, 3));
        assert_eq!(parse_range(Some("bytes=4-"), 10), Range::Part(4, 9));
        assert_eq!(parse_range(Some("bytes=-3"), 10), Range::Part(7, 9));
        assert_eq!(parse_range(Some("bytes=2-99"), 10), Range::Part(2, 9));
        assert_eq!(parse_range(Some("bytes=10-"), 10), Range::Bad);
        assert_eq!(parse_range(Some("bytes=0-1,3-4"), 10), Range::Whole);
        assert_eq!(parse_range(Some("items=0-1"), 10), Range::Whole);
        let r = reply(vec![0xff, 0xd8, 0xff, 1, 2, 3], Some("bytes=1-2"));
        assert_eq!(r.status, 206);
        assert_eq!(r.content_range.as_deref(), Some("bytes 1-2/6"));
        assert_eq!(r.body, vec![0xd8, 0xff]);
        assert_eq!(reply(vec![1, 2], Some("bytes=5-")).status, 416);
    }
}
