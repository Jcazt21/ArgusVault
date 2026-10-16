//! One open session per vault file.
//!
//! Two Argus Vault windows saving the same file would silently overwrite each other (the last
//! writer wins). [`VaultLock`] is a named mutex derived from the vault's path: holding it means
//! no other Argus Vault process in this Windows session has the same file open.
//!
//! Limits: the mutex lives in the per-session `Local\` namespace, so a second window in a
//! different Windows session (fast user switching, remote desktop) is not detected. Different
//! spellings of one path that Windows resolves differently (hard links, mapped drives) can also
//! produce different names.

use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;

use crate::PlatformError;

/// Holds the "this vault is open" mutex for as long as it is alive.
#[derive(Debug)]
pub struct VaultLock {
    handle: HANDLE,
}

// SAFETY: a mutex handle is a process-wide kernel handle, not tied to the thread that created it,
// and closing it from another thread is allowed. This lets the lock travel from the worker thread
// that opened the vault to the UI thread that keeps it.
unsafe impl Send for VaultLock {}

impl Drop for VaultLock {
    fn drop(&mut self) {
        // SAFETY: `handle` was returned by `CreateMutexW`, is owned by this value, and is closed
        // exactly once, here.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

/// Stable 64-bit FNV-1a, so the name does not change between builds or Rust versions.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Normalize a vault path so different spellings of the same file give the same key: absolute,
/// parent directory resolved, case-insensitive (Windows file names are).
fn path_key(path: &Path) -> String {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let resolved: PathBuf = match (
        absolute.parent().and_then(|dir| std::fs::canonicalize(dir).ok()),
        absolute.file_name(),
    ) {
        (Some(dir), Some(name)) => dir.join(name),
        _ => absolute,
    };
    resolved.to_string_lossy().to_lowercase()
}

fn mutex_name(path: &Path) -> Vec<u16> {
    let name = format!("Local\\ArgusVault-{:016x}", fnv1a(path_key(path).as_bytes()));
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

impl VaultLock {
    /// Claim the vault at `path` (which need not exist yet).
    ///
    /// # Errors
    /// [`PlatformError::AlreadyOpen`] if another window has it, [`PlatformError::Api`] if Windows
    /// refuses to create the mutex.
    pub fn acquire(path: &Path) -> Result<Self, PlatformError> {
        let name = mutex_name(path);
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call; no security
        // attributes and no initial ownership are requested.
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }
            .map_err(|_| PlatformError::Api)?;
        // SAFETY: reads this thread's last-error value, set by the `CreateMutexW` call above.
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let lock = Self { handle };
        if existed {
            // Dropping `lock` closes our handle to the other window's mutex.
            return Err(PlatformError::AlreadyOpen);
        }
        Ok(lock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("argus-instance-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn second_claim_on_the_same_vault_is_refused() {
        let dir = temp_dir("same");
        let vault = dir.join("v.argus");
        let first = VaultLock::acquire(&vault).unwrap();
        assert_eq!(VaultLock::acquire(&vault).unwrap_err(), PlatformError::AlreadyOpen);
        drop(first);
        assert!(VaultLock::acquire(&vault).is_ok(), "released lock must be claimable again");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn different_vaults_do_not_block_each_other() {
        let dir = temp_dir("different");
        let a = VaultLock::acquire(&dir.join("a.argus")).unwrap();
        let b = VaultLock::acquire(&dir.join("b.argus")).unwrap();
        drop((a, b));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn spelling_and_case_of_the_path_do_not_matter() {
        let dir = temp_dir("spelling");
        let vault = dir.join("Vault.ARGUS");
        let _first = VaultLock::acquire(&vault).unwrap();
        let lowercase = dir.join("vault.argus");
        let detour = dir.join(".").join("VAULT.argus");
        assert_eq!(VaultLock::acquire(&lowercase).unwrap_err(), PlatformError::AlreadyOpen);
        assert_eq!(VaultLock::acquire(&detour).unwrap_err(), PlatformError::AlreadyOpen);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(fnv1a(b"abc"), 0xe71f_a219_0541_574b);
    }
}
