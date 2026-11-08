//! New-message notifications as a balloon from a notification-area icon. The icon exists only
//! while a notification is pending and is removed when the window is focused or locked.

#![allow(unsafe_code)]

use std::ffi::c_void;

#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}

/// `NOTIFYICONDATAW` as of Windows Vista.
#[repr(C)]
struct NotifyIconData {
    size: u32,
    hwnd: isize,
    id: u32,
    flags: u32,
    callback: u32,
    icon: *mut c_void,
    tip: [u16; 128],
    state: u32,
    state_mask: u32,
    info: [u16; 256],
    timeout: u32,
    info_title: [u16; 64],
    info_flags: u32,
    guid: Guid,
    balloon_icon: *mut c_void,
}

#[link(name = "shell32")]
extern "system" {
    fn Shell_NotifyIconW(msg: u32, data: *mut NotifyIconData) -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn LoadIconW(instance: *mut c_void, name: *const u16) -> *mut c_void;
}

const NIM_ADD: u32 = 0;
const NIM_MODIFY: u32 = 1;
const NIM_DELETE: u32 = 2;
const NIF_ICON: u32 = 0x02;
const NIF_TIP: u32 = 0x04;
const NIF_INFO: u32 = 0x10;
const NIIF_INFO: u32 = 0x01;
const NIIF_RESPECT_QUIET_TIME: u32 = 0x80;
const IDI_APPLICATION: usize = 32512;
const ICON_ID: u32 = 1;

fn copy(dst: &mut [u16], s: &str) {
    let max = dst.len() - 1;
    let mut n = 0;
    for u in s.encode_utf16().take(max) {
        dst[n] = u;
        n += 1;
    }
    // Do not leave half of a surrogate pair at the end.
    if n > 0 && (0xD800..0xDC00).contains(&dst[n - 1]) {
        n -= 1;
    }
    dst[n] = 0;
}

fn blank(hwnd: isize) -> NotifyIconData {
    NotifyIconData {
        size: u32::try_from(std::mem::size_of::<NotifyIconData>()).unwrap_or(0),
        hwnd,
        id: ICON_ID,
        flags: 0,
        callback: 0,
        icon: std::ptr::null_mut(),
        tip: [0; 128],
        state: 0,
        state_mask: 0,
        info: [0; 256],
        timeout: 0,
        info_title: [0; 64],
        info_flags: 0,
        guid: Guid {
            a: 0,
            b: 0,
            c: 0,
            d: [0; 8],
        },
        balloon_icon: std::ptr::null_mut(),
    }
}

/// The notification-area icon of one window.
#[derive(Debug)]
pub struct Tray {
    hwnd: isize,
    shown: bool,
}

impl Tray {
    pub fn new(hwnd: isize) -> Self {
        Self { hwnd, shown: false }
    }

    /// Shows a balloon with `title` and `body`, adding the icon first when needed.
    pub fn show(&mut self, title: &str, body: &str) {
        let mut d = blank(self.hwnd);
        d.flags = NIF_ICON | NIF_TIP | NIF_INFO;
        // SAFETY: loads a stock system icon; no instance handle is involved.
        d.icon = unsafe { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION as *const u16) };
        copy(&mut d.tip, "Aegis");
        copy(&mut d.info_title, title);
        copy(&mut d.info, body);
        d.info_flags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
        // SAFETY: `d` is a fully initialised structure whose size field matches its type.
        // A shown icon is gone after Explorer restarts, then it is added again.
        self.shown = unsafe {
            (self.shown && Shell_NotifyIconW(NIM_MODIFY, &mut d) != 0)
                || Shell_NotifyIconW(NIM_ADD, &mut d) != 0
        };
    }

    /// Removes the icon, and with it any balloon that is still on screen.
    pub fn clear(&mut self) {
        if !self.shown {
            return;
        }
        let mut d = blank(self.hwnd);
        // SAFETY: as in `show`; only the window handle and id are read.
        unsafe { Shell_NotifyIconW(NIM_DELETE, &mut d) };
        self.shown = false;
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        self.clear();
    }
}
