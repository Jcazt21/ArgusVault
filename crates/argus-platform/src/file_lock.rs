//! Protection of the open vault file against changes made behind Argus's back.
//!
//! While a vault is unlocked, Argus keeps one handle to its file open with `FILE_SHARE_READ`
//! only. Windows then refuses every attempt by another process to open the file for **writing**
//! or to **delete or rename** it, so a text editor, a script or a misbehaving sync client cannot
//! corrupt or replace the vault underneath a running session.
//!
//! Reading stays allowed on purpose. The file is encrypted, so being read is no threat, and
//! blocking readers would stop Explorer from copying it and cloud-sync, backup and antivirus
//! programs from doing their job while the vault is open.
//!
//! This is protection against accidents and careless programs, not against an attacker who can
//! already run code as the user (they can end the process or work around it).
//!
//! Saving replaces the file by renaming a temporary file over it, which the open handle would
//! block, so a save releases the lock first and takes it again afterwards. In that short gap
//! another program can open the file; if that makes re-locking fail, the save itself has still
//! happened, and the caller keeps trying to re-lock (see [`ExclusiveFileLock::reacquire`]).

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::PlatformError;

/// Windows error 32: `ERROR_SHARING_VIOLATION`.
const ERROR_SHARING_VIOLATION: i32 = 32;
/// Windows error 33: `ERROR_LOCK_VIOLATION`.
const ERROR_LOCK_VIOLATION: i32 = 33;
/// `FILE_SHARE_READ`: other processes may read the file, but not write, delete or rename it.
const FILE_SHARE_READ: u32 = 1;

/// Open the file the way the lock needs it, mapping "someone else has it open" to
/// [`PlatformError::InUse`].
fn open_protected(path: &Path) -> Result<File, PlatformError> {
    OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path).map_err(|err| {
        match err.raw_os_error() {
            Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION) => PlatformError::InUse,
            _ => PlatformError::Api,
        }
    })
}

/// Keeps the vault file protected from modification while it is held.
#[derive(Debug)]
pub struct ExclusiveFileLock {
    path: PathBuf,
    file: Option<File>,
}

impl ExclusiveFileLock {
    /// Protect the existing file at `path` until the lock is dropped.
    ///
    /// # Errors
    /// [`PlatformError::InUse`] if another process already has the file open for writing (or
    /// without allowing others to read it); [`PlatformError::Api`] for other I/O errors.
    pub fn acquire(path: &Path) -> Result<Self, PlatformError> {
        Ok(Self { path: path.to_path_buf(), file: Some(open_protected(path)?) })
    }

    /// `true` while the file is protected.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.file.is_some()
    }

    /// Let go of the file so it can be replaced (a save, or a background re-key that rewrites it).
    /// Pair with [`reacquire`](Self::reacquire).
    pub fn release(&mut self) {
        self.file = None;
    }

    /// Protect the file again after [`release`](Self::release). Does nothing if it is already
    /// protected, so it is safe to call repeatedly until it succeeds.
    ///
    /// # Errors
    /// [`PlatformError::InUse`] if another program has the file open for writing meanwhile;
    /// [`PlatformError::Api`] on other I/O errors. The lock stays released.
    pub fn reacquire(&mut self) -> Result<(), PlatformError> {
        if self.file.is_none() {
            self.file = Some(open_protected(&self.path)?);
        }
        Ok(())
    }

    /// The protected file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn temp_file(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("argus-filelock-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.argus");
        std::fs::write(&file, b"content").unwrap();
        (dir, file)
    }

    #[test]
    fn others_can_read_but_not_write_delete_or_rename() {
        let (dir, file) = temp_file("modes");
        let lock = ExclusiveFileLock::acquire(&file).unwrap();
        assert!(lock.is_locked());

        // Sync clients, backups and Explorer copies keep working.
        assert_eq!(std::fs::read(&file).unwrap(), b"content");

        // Anything that would change the file is refused with a sharing violation.
        let write = OpenOptions::new().write(true).open(&file).unwrap_err();
        assert_eq!(write.raw_os_error(), Some(ERROR_SHARING_VIOLATION));
        assert!(OpenOptions::new().append(true).open(&file).is_err());
        assert!(std::fs::remove_file(&file).is_err(), "must not be deletable");
        let other = file.with_extension("moved");
        assert!(std::fs::rename(&file, &other).is_err(), "must not be renamable");
        let tmp = file.with_extension("tmp");
        std::fs::write(&tmp, b"x").unwrap();
        assert!(std::fs::rename(&tmp, &file).is_err(), "must not be replaceable");
        assert_eq!(std::fs::read(&file).unwrap(), b"content");

        // Dropping the lock frees the file.
        drop(lock);
        assert!(OpenOptions::new().write(true).open(&file).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_save_cycle_replaces_the_file_and_protects_the_new_one() {
        let (dir, file) = temp_file("save_cycle");
        let mut lock = ExclusiveFileLock::acquire(&file).unwrap();

        lock.release();
        assert!(!lock.is_locked());
        let tmp = file.with_extension("tmp");
        std::fs::write(&tmp, b"new content").unwrap();
        std::fs::rename(&tmp, &file).unwrap(); // what an atomic save does
        lock.reacquire().unwrap();

        assert!(lock.is_locked());
        assert_eq!(std::fs::read(&file).unwrap(), b"new content");
        assert!(OpenOptions::new().write(true).open(&file).is_err(), "protected again");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reacquire_is_idempotent_and_acquire_reports_a_writer_as_in_use() {
        let (dir, file) = temp_file("in_use");
        let mut lock = ExclusiveFileLock::acquire(&file).unwrap();
        assert!(lock.reacquire().is_ok(), "already locked: nothing to do");
        lock.release();

        // Another program holds the file open for writing: protecting it must fail, cleanly.
        let mut writer = OpenOptions::new().write(true).open(&file).unwrap();
        assert_eq!(lock.reacquire(), Err(PlatformError::InUse));
        assert!(!lock.is_locked(), "a failed re-lock leaves the lock released");
        assert!(matches!(ExclusiveFileLock::acquire(&file), Err(PlatformError::InUse)));

        // Once that program lets go, the lock can be taken again.
        writer.write_all(b"!").unwrap();
        drop(writer);
        assert!(lock.reacquire().is_ok());
        assert!(lock.is_locked());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_file_is_an_api_error_not_in_use() {
        let (dir, _) = temp_file("missing");
        let err = ExclusiveFileLock::acquire(&dir.join("nope.argus")).unwrap_err();
        assert_eq!(err, PlatformError::Api);
        let _ = std::fs::remove_dir_all(dir);
    }
}
