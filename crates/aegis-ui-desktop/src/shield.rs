//! Keeps the window out of screenshots, screen recording and screen sharing.

#![allow(unsafe_code)]

#[link(name = "user32")]
extern "system" {
    fn SetWindowDisplayAffinity(hwnd: isize, affinity: u32) -> i32;
}

const WDA_NONE: u32 = 0;
const WDA_MONITOR: u32 = 1;
/// Windows 10 2004 and later: the window is left out of captures entirely.
const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11;

/// Turns capture protection of `hwnd` on or off. Systems without `WDA_EXCLUDEFROMCAPTURE`
/// get `WDA_MONITOR`, which shows a black window in captures. False if both were refused.
pub fn protect(hwnd: isize, on: bool) -> bool {
    // SAFETY: plain call on a window handle owned by this process; a stale handle only fails.
    unsafe {
        if !on {
            return SetWindowDisplayAffinity(hwnd, WDA_NONE) != 0;
        }
        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) != 0
            || SetWindowDisplayAffinity(hwnd, WDA_MONITOR) != 0
    }
}
