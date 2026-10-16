//! Keep a window out of screenshots and screen recordings.

use std::ffi::c_void;

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{
    SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR,
};

use crate::PlatformError;

/// How strongly the window is shielded from capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureProtection {
    /// The window is left out of captures entirely (Windows 10 version 2004 and later).
    ExcludedFromCapture,
    /// Older Windows: the window shows on screen but appears black in captures.
    MonitorOnly,
}

fn hwnd_from(raw: isize) -> HWND {
    HWND(raw as *mut c_void)
}

/// Shield the window with the given native handle from capture, preferring full exclusion and
/// falling back to a black rectangle on Windows builds that do not support it.
///
/// # Errors
/// [`PlatformError::Api`] if neither mode could be applied (for example, the handle is not a
/// window of this process).
pub fn protect_from_capture(hwnd: isize) -> Result<CaptureProtection, PlatformError> {
    let hwnd = hwnd_from(hwnd);
    // SAFETY: takes a window handle by value; Windows validates it and reports failure.
    if unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) }.is_ok() {
        return Ok(CaptureProtection::ExcludedFromCapture);
    }
    // SAFETY: same as above.
    if unsafe { SetWindowDisplayAffinity(hwnd, WDA_MONITOR) }.is_ok() {
        return Ok(CaptureProtection::MonitorOnly);
    }
    Err(PlatformError::Api)
}

#[cfg(test)]
mod tests {
    use windows::Win32::UI::WindowsAndMessaging::{DestroyWindow, GetWindowDisplayAffinity};

    use super::*;
    use crate::session::create_hidden_window;

    #[test]
    fn protects_a_real_window_from_capture() {
        let hwnd = create_hidden_window().unwrap();
        let mode = protect_from_capture(hwnd.0 as isize).unwrap();

        let mut affinity = 0u32;
        // SAFETY: `hwnd` is a live window of this process and `affinity` is a valid out pointer.
        unsafe { GetWindowDisplayAffinity(hwnd, &raw mut affinity) }.unwrap();
        let expected = match mode {
            CaptureProtection::ExcludedFromCapture => WDA_EXCLUDEFROMCAPTURE.0,
            CaptureProtection::MonitorOnly => WDA_MONITOR.0,
        };
        assert_eq!(affinity, expected);
        assert_eq!(mode, CaptureProtection::ExcludedFromCapture, "expected Windows 10 2004+");
        // SAFETY: `hwnd` was created on this thread and is destroyed exactly once.
        let _ = unsafe { DestroyWindow(hwnd) };
    }

    #[test]
    fn rejects_a_handle_that_is_not_a_window() {
        assert_eq!(protect_from_capture(0), Err(PlatformError::Api));
    }
}
