//! How long the user has been away from the keyboard and mouse.

use std::mem::size_of;
use std::time::Duration;

use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

use crate::PlatformError;

/// Time since the last keyboard or mouse input **anywhere in the current Windows session**, not
/// just in Argus Vault. Working in another program therefore counts as activity.
///
/// # Errors
/// [`PlatformError::Api`] if Windows cannot report the last input time.
pub fn idle_duration() -> Result<Duration, PlatformError> {
    let size = u32::try_from(size_of::<LASTINPUTINFO>()).map_err(|_| PlatformError::Api)?;
    let mut info = LASTINPUTINFO { cbSize: size, dwTime: 0 };
    // SAFETY: `info` is a valid, correctly sized LASTINPUTINFO that outlives the call.
    if !unsafe { GetLastInputInfo(&raw mut info) }.as_bool() {
        return Err(PlatformError::Api);
    }
    // SAFETY: no arguments and no pointers.
    let now = unsafe { GetTickCount() };
    // Both values are 32-bit millisecond tick counts that wrap together every ~49.7 days.
    Ok(Duration::from_millis(u64::from(now.wrapping_sub(info.dwTime))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_a_plausible_idle_time() {
        let idle = idle_duration().unwrap();
        // Longer than the machine could plausibly have been idle would mean a wrap bug.
        assert!(idle < Duration::from_secs(60 * 60 * 24 * 30), "implausible idle time: {idle:?}");
    }
}
