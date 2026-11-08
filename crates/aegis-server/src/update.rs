//! Read-only update routes (spec section 29). The owner drops a signed manifest and the release
//! files into `<data-dir>/update/`; the server only reads them and never checks the signature,
//! clients do.

use crate::http::{BlobReply, Request, Response};
use aegis_core::update::{valid_name, CHUNK, MAX_FILE, MAX_MANIFEST};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Directory below the data directory that holds the published update.
pub const UPDATE_DIR: &str = "update";
/// Signed manifest file inside it.
pub const MANIFEST_FILE: &str = "manifest.signed";

fn err(status: u16, msg: &str) -> BlobReply {
    BlobReply::Json(Response { status, body: serde_json::json!({ "error": msg }).to_string() })
}

fn one<'a>(q: &'a [(String, String)], key: &str) -> Option<&'a str> {
    let mut it = q.iter().filter(|(k, _)| k == key);
    let first = it.next().map(|(_, v)| v.as_str());
    if it.next().is_some() {
        return None;
    }
    first
}

/// A regular file directly inside `dir`, not a link, at most `cap` bytes.
fn open_plain(dir: &Path, name: &str, cap: u64) -> Result<(std::fs::File, u64), BlobReply> {
    let path = dir.join(name);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(_) => return Err(err(404, "not found")),
    };
    if !meta.file_type().is_file() {
        return Err(err(404, "not found"));
    }
    if meta.len() > cap {
        return Err(err(413, "too large"));
    }
    match std::fs::File::open(&path) {
        Ok(f) => Ok((f, meta.len())),
        Err(_) => Err(err(404, "not found")),
    }
}

/// Handles `/api/v2/update/*`. `dir` is `None` for a server without a data directory.
pub fn handle_update(dir: Option<&Path>, req: &Request) -> BlobReply {
    let route = req.path.as_str();
    if route != "/api/v2/update/manifest" && route != "/api/v2/update/file" {
        return err(404, "not found");
    }
    if req.method != "GET" {
        return err(405, "method not allowed");
    }
    let Some(dir) = dir else { return err(404, "not found") };
    if route == "/api/v2/update/manifest" {
        let (mut f, len) = match open_plain(dir, MANIFEST_FILE, MAX_MANIFEST as u64) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let mut buf = Vec::with_capacity(len as usize);
        if f.by_ref().take(MAX_MANIFEST as u64).read_to_end(&mut buf).is_err() || buf.is_empty() {
            return err(404, "not found");
        }
        return BlobReply::Bytes(buf);
    }
    let Some(name) = one(&req.query, "name") else { return err(400, "bad name") };
    if !valid_name(name) || name == MANIFEST_FILE {
        return err(400, "bad name");
    }
    let off = match one(&req.query, "off").map(aegis_core::text::parse_u64) {
        None => 0,
        Some(Ok(n)) => n,
        Some(Err(_)) => return err(400, "bad off"),
    };
    let (mut f, len) = match open_plain(dir, name, MAX_FILE) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if off >= len {
        return err(416, "bad off");
    }
    let want = (len - off).min(CHUNK as u64);
    let mut buf = Vec::with_capacity(want as usize);
    if f.seek(SeekFrom::Start(off)).is_err() || f.take(want).read_to_end(&mut buf).is_err() || buf.is_empty() {
        return err(503, "storage error");
    }
    BlobReply::Bytes(buf)
}
