//! Blob store: files in `<data dir>/blobs/<64 lowercase hex>`, accounted in memory.
//!
//! The index has its own lock, so file I/O never runs under the lock of the main state and
//! quota accounting stays race-free: bytes are reserved before the write and released when
//! the write fails or the blob is purged.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

pub const BLOB_DIR: &str = "blobs";
/// Largest accepted blob body (1 MiB + tag).
pub const MAX_BLOB_BYTES: usize = 1_048_592;
pub const DEFAULT_BLOB_TTL_SECS: u64 = 14 * 24 * 3600;
pub const DEFAULT_BLOB_QUOTA_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const TMP_SUFFIX: &str = ".tmp";

pub fn is_blob_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Debug)]
pub enum Reserve {
    Exists,
    OverQuota,
}

#[derive(Default)]
struct Index {
    /// Committed blobs: id -> (size, upload time).
    stored: HashMap<String, (u64, u64)>,
    /// Ids being written right now.
    pending: HashSet<String>,
    /// Committed plus reserved bytes.
    total: u64,
}

impl std::fmt::Debug for BlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobStore").finish_non_exhaustive()
    }
}

pub struct BlobStore {
    dir: PathBuf,
    quota: u64,
    ttl: u64,
    index: Mutex<Index>,
}

impl BlobStore {
    /// Opens `<data_dir>/blobs`, deletes temp leftovers and indexes existing blobs.
    pub fn open(data_dir: &Path, quota: u64, ttl: u64) -> std::io::Result<Self> {
        let dir = data_dir.join(BLOB_DIR);
        let mut index = Index::default();
        // The directory is created on the first upload.
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => Some(e),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        for entry in entries.into_iter().flatten() {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            if name.ends_with(TMP_SUFFIX) {
                let _ = std::fs::remove_file(entry.path());
                continue;
            }
            if !is_blob_id(&name) {
                continue;
            }
            let at = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            index.total = index.total.saturating_add(meta.len());
            index.stored.insert(name, (meta.len(), at));
        }
        Ok(Self { dir, quota, ttl, index: Mutex::new(index) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Index> {
        self.index.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn path(&self, id: &str) -> PathBuf {
        debug_assert!(is_blob_id(id));
        self.dir.join(id)
    }

    /// Total bytes stored or reserved.
    pub fn total_bytes(&self) -> u64 {
        self.lock().total
    }

    pub fn count(&self) -> usize {
        self.lock().stored.len()
    }

    /// Reserves `len` bytes for a new blob. An expired blob with the same id is dropped first.
    pub fn reserve(&self, id: &str, len: u64, now: u64) -> Result<(), Reserve> {
        let mut ix = self.lock();
        if ix.pending.contains(id) {
            return Err(Reserve::Exists);
        }
        if let Some(&(size, at)) = ix.stored.get(id) {
            if at.saturating_add(self.ttl) > now {
                return Err(Reserve::Exists);
            }
            ix.stored.remove(id);
            ix.total = ix.total.saturating_sub(size);
            let _ = std::fs::remove_file(self.path(id));
        }
        if ix.total.saturating_add(len) > self.quota {
            return Err(Reserve::OverQuota);
        }
        ix.total += len;
        ix.pending.insert(id.to_owned());
        Ok(())
    }

    /// Writes a reserved blob (temp file, fsync, rename) and commits or releases the reservation.
    pub fn write_reserved(&self, id: &str, data: &[u8], now: u64) -> std::io::Result<()> {
        let final_path = self.path(id);
        let tmp = self.dir.join(format!("{id}{TMP_SUFFIX}"));
        let res = (|| {
            std::fs::create_dir_all(&self.dir)?;
            let mut f = File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &final_path)
        })();
        let mut ix = self.lock();
        ix.pending.remove(id);
        if res.is_ok() {
            ix.stored.insert(id.to_owned(), (data.len() as u64, now));
        } else {
            ix.total = ix.total.saturating_sub(data.len() as u64);
            let _ = std::fs::remove_file(&tmp);
        }
        res
    }

    /// Returns the blob bytes, or `None` when unknown or expired.
    pub fn get(&self, id: &str, now: u64) -> Option<Vec<u8>> {
        if !is_blob_id(id) {
            return None;
        }
        {
            let ix = self.lock();
            let &(_, at) = ix.stored.get(id)?;
            if at.saturating_add(self.ttl) <= now {
                return None;
            }
        }
        std::fs::read(self.path(id)).ok()
    }

    /// Deletes expired blobs. Returns how many were removed.
    pub fn purge(&self, now: u64) -> usize {
        let mut ix = self.lock();
        let ttl = self.ttl;
        let expired: Vec<String> = ix
            .stored
            .iter()
            .filter(|(_, &(_, at))| at.saturating_add(ttl) <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            if let Some((size, _)) = ix.stored.remove(id) {
                ix.total = ix.total.saturating_sub(size);
            }
            let _ = std::fs::remove_file(self.path(id));
        }
        expired.len()
    }
}
