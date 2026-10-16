//! Filesystem helpers: bounded reads and crash-safe atomic writes.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Read a whole file, refusing anything larger than `max` bytes.
pub(crate) fn read_limited(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    let max64 = u64::try_from(max).map_err(|_| Error::LimitExceeded)?;
    if len > max64 {
        return Err(Error::LimitExceeded);
    }
    let cap = usize::try_from(len).map_err(|_| Error::LimitExceeded)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(cap.saturating_add(1)));
    file.take(max64 + 1).read_to_end(&mut buf)?;
    if buf.len() > max {
        return Err(Error::LimitExceeded);
    }
    Ok(buf)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Path of the backup kept next to the vault.
pub(crate) fn backup_path(path: &Path) -> PathBuf {
    sibling(path, ".bak")
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Crash-safe replace:
/// 1. write `<path>.tmp` and fsync it,
/// 2. copy the current file to `<path>.bak` and fsync it,
/// 3. atomically rename the temp file over `<path>`.
pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = sibling(path, ".tmp");
    remove_if_exists(&tmp)?;

    let result = (|| -> Result<()> {
        {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        if path.exists() {
            let bak = backup_path(path);
            fs::copy(path, &bak)?;
            OpenOptions::new().write(true).open(&bak)?.sync_all()?;
        }
        // On Windows this is MoveFileExW(MOVEFILE_REPLACE_EXISTING).
        fs::rename(&tmp, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Make `<path>.bak` a copy of the current `<path>`, or remove it if the
/// copy fails. Used after a re-key: the previous backup is encrypted with
/// the old credentials and must not survive the change.
pub(crate) fn replace_backup_with_current(path: &Path) -> Result<()> {
    let bak = backup_path(path);
    let tmp = sibling(&bak, ".tmp");
    remove_if_exists(&tmp)?;

    let result = (|| -> Result<()> {
        fs::copy(path, &tmp)?;
        OpenOptions::new().write(true).open(&tmp)?.sync_all()?;
        fs::rename(&tmp, &bak)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        // A missing backup is acceptable; one that opens with the old
        // credentials is not.
        return remove_if_exists(&bak);
    }
    result
}

/// Create a new file, failing if it already exists, and fsync it.
pub(crate) fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_util {
    use std::path::PathBuf;

    /// Unique scratch directory removed on drop (no external crate needed).
    pub(crate) struct TempDir(pub PathBuf);

    impl TempDir {
        pub(crate) fn new() -> Self {
            let mut rnd = [0u8; 8];
            crate::rng::fill(&mut rnd).unwrap();
            let name = format!("argus-test-{}", u64::from_le_bytes(rnd));
            let p = std::env::temp_dir().join(name);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::TempDir;
    use super::*;

    #[test]
    fn atomic_write_creates_backup() {
        let dir = TempDir::new();
        let p = dir.0.join("v.argus");
        atomic_write(&p, b"one").unwrap();
        assert!(!backup_path(&p).exists());
        atomic_write(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::read(backup_path(&p)).unwrap(), b"one");
        assert!(!sibling(&p, ".tmp").exists());
    }

    #[test]
    fn read_limited_enforces_cap() {
        let dir = TempDir::new();
        let p = dir.0.join("f");
        fs::write(&p, [0u8; 100]).unwrap();
        assert_eq!(read_limited(&p, 100).unwrap().len(), 100);
        assert!(matches!(read_limited(&p, 99), Err(Error::LimitExceeded)));
    }

    #[test]
    fn write_new_refuses_overwrite() {
        let dir = TempDir::new();
        let p = dir.0.join("k");
        write_new(&p, b"a").unwrap();
        assert!(write_new(&p, b"b").is_err());
    }
}
