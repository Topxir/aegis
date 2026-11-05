//! Binds a small file to the signed-in operating system user (DPAPI on Windows), so it cannot be
//! read or replaced by someone who only has the disk. `.pinmeta` uses it: it names the server
//! the PIN verifier is sent to, and an edited copy must be refused.
//!
//! Elsewhere there is no such store; the data is kept as is (format byte 0) and only Windows
//! builds give the guarantee. A Windows build never accepts format 0.

#![allow(unsafe_code)]

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    #[repr(C)]
    struct Blob {
        len: u32,
        data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            input: *const Blob,
            descr: *const u16,
            entropy: *const Blob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            output: *mut Blob,
        ) -> i32;
        fn CryptUnprotectData(
            input: *const Blob,
            descr: *mut *mut u16,
            entropy: *const Blob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            output: *mut Blob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }

    const UI_FORBIDDEN: u32 = 1;

    fn run(
        data: &[u8],
        entropy: &[u8],
        f: impl FnOnce(*const Blob, *const Blob, *mut Blob) -> i32,
    ) -> Option<Vec<u8>> {
        let len = u32::try_from(data.len()).ok()?;
        let elen = u32::try_from(entropy.len()).ok()?;
        let input = Blob {
            len,
            data: data.as_ptr().cast_mut(),
        };
        let ent = Blob {
            len: elen,
            data: entropy.as_ptr().cast_mut(),
        };
        let mut out = Blob {
            len: 0,
            data: std::ptr::null_mut(),
        };
        if f(&input, &ent, &mut out) == 0 || out.data.is_null() {
            return None;
        }
        // SAFETY: on success the system returns `len` readable bytes at `data`, which we free.
        let v = unsafe { std::slice::from_raw_parts(out.data, out.len as usize) }.to_vec();
        unsafe { LocalFree(out.data.cast()) };
        Some(v)
    }

    pub fn protect(data: &[u8], entropy: &[u8]) -> Option<Vec<u8>> {
        run(data, entropy, |i, e, o| {
            // SAFETY: the pointers refer to live locals; the description is optional.
            unsafe {
                CryptProtectData(
                    i,
                    std::ptr::null(),
                    e,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    UI_FORBIDDEN,
                    o,
                )
            }
        })
    }

    pub fn unprotect(data: &[u8], entropy: &[u8]) -> Option<Vec<u8>> {
        run(data, entropy, |i, e, o| {
            // SAFETY: as above.
            unsafe {
                CryptUnprotectData(
                    i,
                    std::ptr::null_mut(),
                    e,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    UI_FORBIDDEN,
                    o,
                )
            }
        })
    }

    pub const FORMAT: u8 = 1;
}

#[cfg(not(windows))]
mod imp {
    pub fn protect(data: &[u8], _entropy: &[u8]) -> Option<Vec<u8>> {
        Some(data.to_vec())
    }

    pub fn unprotect(data: &[u8], _entropy: &[u8]) -> Option<Vec<u8>> {
        Some(data.to_vec())
    }

    pub const FORMAT: u8 = 0;
}

/// Seals `data`; `context` (the vault file name) is mixed in so a copy does not fit another vault.
pub fn seal(data: &[u8], context: &[u8]) -> Option<Vec<u8>> {
    let mut v = vec![imp::FORMAT];
    v.extend(imp::protect(data, context)?);
    Some(v)
}

/// The data of `seal`, or `None` when the file was not made here, was edited or is for another
/// context.
pub fn open(blob: &[u8], context: &[u8]) -> Option<Vec<u8>> {
    let (&fmt, rest) = blob.split_first()?;
    if fmt != imp::FORMAT {
        return None;
    }
    imp::unprotect(rest, context)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_context() {
        let b = seal(b"endpoint", b"a.vault").unwrap();
        assert_eq!(open(&b, b"a.vault").unwrap(), b"endpoint");
        #[cfg(windows)]
        {
            assert!(open(&b, b"b.vault").is_none(), "another vault");
            let mut t = b.clone();
            let n = t.len() - 3;
            t[n] ^= 1;
            assert!(open(&t, b"a.vault").is_none(), "edited");
            assert!(open(b"{\"endpoint\":\"x\"}", b"a.vault").is_none(), "plain json");
        }
    }
}
