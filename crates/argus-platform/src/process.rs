//! Process-wide hardening.

use windows::Win32::System::ErrorReporting::{WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP};

use crate::PlatformError;

/// Ask Windows Error Reporting to leave the heap out of crash reports for this process, so a crash
/// does not ship decrypted vault contents inside a dump.
///
/// This is best effort and narrow: it does not stop a debugger, a local-dumps registry
/// configuration (`LocalDumps`) or an administrator from capturing memory, and the call itself
/// cannot prove the reports are smaller. Treat it as one layer, not a guarantee.
///
/// # Errors
/// [`PlatformError::Api`] if Windows rejects the flag.
pub fn exclude_heap_from_error_reports() -> Result<(), PlatformError> {
    // SAFETY: takes a flags value by value and has no pointers.
    unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) }.map_err(|_| PlatformError::Api)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_is_accepted() {
        assert_eq!(exclude_heap_from_error_reports(), Ok(()));
    }
}
