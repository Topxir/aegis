//! Bucket padding: `BE32(len) || frame || zeros`.

use crate::{Error, Result};

pub const BUCKETS: [usize; 7] = [256, 512, 1024, 2048, 4096, 8192, 16384];
/// Largest frame that still fits the biggest bucket.
pub const MAX_FRAME: usize = 16384 - 4;

/// True if `n` is a padded length the server accepts.
pub fn is_bucket(n: usize) -> bool {
    BUCKETS.contains(&n)
}

/// Smallest bucket that holds a frame of `len` bytes.
pub fn bucket_for(len: usize) -> Result<usize> {
    if len > MAX_FRAME {
        return Err(Error::FrameTooLarge);
    }
    BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= len + 4)
        .ok_or(Error::FrameTooLarge)
}

pub fn pad(frame: &[u8]) -> Result<Vec<u8>> {
    let total = bucket_for(frame.len())?;
    let len = u32::try_from(frame.len()).map_err(|_| Error::FrameTooLarge)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(frame);
    out.resize(total, 0);
    Ok(out)
}

/// Strict inverse of [`pad`]: bucket length, minimal bucket and zero fill are enforced.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if !is_bucket(padded.len()) {
        return Err(Error::BadPadding);
    }
    let len = u32::from_be_bytes(crate::arr(&padded[..4])?) as usize;
    if len > MAX_FRAME || len + 4 > padded.len() {
        return Err(Error::BadPadding);
    }
    if bucket_for(len)? != padded.len() {
        return Err(Error::BadPadding);
    }
    if padded[4 + len..].iter().any(|&b| b != 0) {
        return Err(Error::BadPadding);
    }
    Ok(padded[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        assert_eq!(bucket_for(0).unwrap(), 256);
        assert_eq!(bucket_for(252).unwrap(), 256);
        assert_eq!(bucket_for(253).unwrap(), 512);
        assert_eq!(bucket_for(16380).unwrap(), 16384);
        assert_eq!(bucket_for(16381), Err(Error::FrameTooLarge));
        assert!(pad(&vec![1; 16381]).is_err());
    }

    #[test]
    fn roundtrip_all_sizes() {
        for n in [0usize, 1, 100, 252, 253, 508, 509, 1020, 5000, 16380] {
            let f: Vec<u8> = (0..n).map(|i| (i % 251) as u8 + 1).collect();
            let p = pad(&f).unwrap();
            assert!(is_bucket(p.len()));
            assert_eq!(unpad(&p).unwrap(), f);
        }
    }

    #[test]
    fn strict_unpad() {
        let mut p = pad(b"hello").unwrap();
        assert!(unpad(&p[..255]).is_err());
        p[100] = 1;
        assert!(unpad(&p).is_err());
        let mut p = pad(b"hello").unwrap();
        p[3] = 0xff;
        assert!(unpad(&p).is_err());
        let mut big = vec![0u8; 512];
        big[3] = 5;
        assert!(unpad(&big).is_err());
    }
}
