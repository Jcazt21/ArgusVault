//! How much memory the machine has and how much of it is free right now. Used to size key
//! derivation when a vault is created, and to check a vault fits before opening it.

use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

use crate::PlatformError;

/// A snapshot of the machine's memory, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryStatus {
    /// Installed physical memory.
    pub total: u64,
    /// Physical memory that is free right now.
    pub available_physical: u64,
    /// What the system will still let this process commit (physical memory plus page file).
    pub available_commit: u64,
}

impl MemoryStatus {
    /// Memory that can be used without paging out and without failing: the smaller of the free
    /// physical memory and the remaining commit. Key derivation must stay inside this, so its
    /// buffers (which hold key material) are not pushed to the page file.
    #[must_use]
    pub fn usable(&self) -> u64 {
        self.available_physical.min(self.available_commit)
    }
}

/// Read the current memory status.
///
/// # Errors
/// [`PlatformError::Api`] if Windows does not report it.
pub fn status() -> Result<MemoryStatus, PlatformError> {
    let mut raw = MEMORYSTATUSEX {
        dwLength: u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>())
            .map_err(|_| PlatformError::Api)?,
        ..Default::default()
    };
    // SAFETY: `raw` is a live, writable MEMORYSTATUSEX whose `dwLength` is set as required.
    unsafe { GlobalMemoryStatusEx(&raw mut raw) }.map_err(|_| PlatformError::Api)?;
    Ok(MemoryStatus {
        total: raw.ullTotalPhys,
        available_physical: raw.ullAvailPhys,
        available_commit: raw.ullAvailPageFile,
    })
}

/// Total physical memory in bytes.
///
/// # Errors
/// [`PlatformError::Api`] if Windows does not report it.
pub fn total_physical() -> Result<u64, PlatformError> {
    status().map(|s| s.total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_a_plausible_status() {
        let s = status().unwrap();
        // More than 1 GiB and less than 64 TiB installed on any machine this runs on.
        assert!(s.total > 1 << 30 && s.total < 1 << 46, "{s:?}");
        assert!(s.available_physical > 0 && s.available_physical <= s.total, "{s:?}");
        assert!(s.usable() <= s.available_physical && s.usable() <= s.available_commit);
    }

    #[test]
    fn usable_is_the_smaller_of_physical_and_commit() {
        let s = MemoryStatus { total: 100, available_physical: 40, available_commit: 25 };
        assert_eq!(s.usable(), 25);
        let s = MemoryStatus { total: 100, available_physical: 30, available_commit: 90 };
        assert_eq!(s.usable(), 30);
    }
}
