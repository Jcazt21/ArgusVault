//! Domain model: vault, entries and settings.
//!
//! All secret-bearing types wipe their memory on drop and redact
//! themselves in `Debug` output.

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::rng;
use crate::totp::TotpConfig;

/// Random 128-bit entry identifier.
pub type EntryId = [u8; 16];

/// Maximum length (bytes) of any single text field.
pub const MAX_FIELD_LEN: usize = 1024 * 1024;
/// Maximum number of entries per vault.
pub const MAX_ENTRIES: usize = 100_000;

/// Current Unix time in seconds (0 if the clock is before 1970).
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// What an entry is for (PRD §3.3). Decides which fields are required and how the UI treats it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EntryKind {
    /// A website login: title, URL, username, password.
    #[default]
    Web,
    /// A server (typically RDP): title, host, username, password. Copying the password is the
    /// main action.
    Server,
}

impl EntryKind {
    /// Stable on-disk code.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Web => 0,
            Self::Server => 1,
        }
    }

    /// # Errors
    /// [`Error::InvalidFormat`] for an unknown code.
    pub fn from_u8(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Web),
            1 => Ok(Self::Server),
            _ => Err(Error::InvalidFormat),
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Web => "Website",
            Self::Server => "Server",
        }
    }
}

/// A single credential.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Entry {
    pub id: EntryId,
    #[zeroize(skip)]
    pub kind: EntryKind,
    /// Host or server name; required for [`EntryKind::Server`], empty otherwise.
    pub host: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp: Option<TotpConfig>,
    pub created: u64,
    pub modified: u64,
}

impl Entry {
    /// New empty entry with a fresh random id.
    ///
    /// # Errors
    /// [`Error::Rng`] if the OS RNG fails.
    pub fn new(title: impl Into<String>) -> Result<Self> {
        let mut id = [0u8; 16];
        rng::fill(&mut id)?;
        let now = now_unix();
        Ok(Self {
            id,
            kind: EntryKind::Web,
            host: String::new(),
            title: title.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp: None,
            created: now,
            modified: now,
        })
    }

    /// Validate field sizes.
    ///
    /// # Errors
    /// [`Error::LimitExceeded`] / [`Error::InvalidInput`].
    pub fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty() {
            return Err(Error::InvalidInput("title must not be empty"));
        }
        if self.kind == EntryKind::Server && self.host.trim().is_empty() {
            return Err(Error::InvalidInput("a server entry needs a host"));
        }
        for f in [&self.title, &self.host, &self.username, &self.password, &self.url, &self.notes] {
            if f.len() > MAX_FIELD_LEN {
                return Err(Error::LimitExceeded);
            }
        }
        Ok(())
    }

    /// Mark the entry as modified now.
    pub fn touch(&mut self) {
        self.modified = now_unix();
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("title", &self.title)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("notes", &"<redacted>")
            .field("totp", &self.totp.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// User preferences stored *inside* the encrypted vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Lock after this many seconds of inactivity.
    pub auto_lock_secs: u32,
    /// Clear the clipboard this many seconds after copying.
    pub clipboard_clear_secs: u32,
    /// Lock when the window is minimized.
    pub lock_on_minimize: bool,
}

impl Settings {
    pub const AUTO_LOCK_RANGE: std::ops::RangeInclusive<u32> = 30..=7200;
    pub const CLIPBOARD_RANGE: std::ops::RangeInclusive<u32> = 5..=300;

    /// # Errors
    /// [`Error::InvalidInput`] if a value is out of range.
    pub fn validate(&self) -> Result<()> {
        if !Self::AUTO_LOCK_RANGE.contains(&self.auto_lock_secs) {
            return Err(Error::InvalidInput("auto-lock must be 30-7200 s"));
        }
        if !Self::CLIPBOARD_RANGE.contains(&self.clipboard_clear_secs) {
            return Err(Error::InvalidInput("clipboard clear must be 5-300 s"));
        }
        Ok(())
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self { auto_lock_secs: 300, clipboard_clear_secs: 20, lock_on_minimize: true }
    }
}

/// Decrypted vault contents.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Vault {
    pub entries: Vec<Entry>,
    #[zeroize(skip)]
    pub settings: Settings,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("entries", &self.entries.len())
            .field("settings", &self.settings)
            .finish()
    }
}

impl Vault {
    /// Insert or replace (by id) an entry.
    ///
    /// # Errors
    /// Validation errors or [`Error::LimitExceeded`] when full.
    pub fn upsert(&mut self, entry: Entry) -> Result<()> {
        entry.validate()?;
        if let Some(slot) = self.entries.iter_mut().find(|e| e.id == entry.id) {
            *slot = entry;
            return Ok(());
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(Error::LimitExceeded);
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Remove an entry by id. Returns `true` if found.
    pub fn remove(&mut self, id: &EntryId) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| &e.id != id);
        before != self.entries.len()
    }

    #[must_use]
    pub fn get(&self, id: &EntryId) -> Option<&Entry> {
        self.entries.iter().find(|e| &e.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_and_remove() {
        let mut v = Vault::default();
        let mut e = Entry::new("GitHub").unwrap();
        v.upsert(e.clone()).unwrap();
        e.username = "alice".into();
        v.upsert(e.clone()).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.get(&e.id).unwrap().username, "alice");
        assert!(v.remove(&e.id));
        assert!(!v.remove(&e.id));
    }

    #[test]
    fn rejects_empty_title() {
        let mut v = Vault::default();
        assert!(v.upsert(Entry::new("  ").unwrap()).is_err());
    }

    #[test]
    fn server_entry_needs_a_host() {
        let mut v = Vault::default();
        let mut e = Entry::new("Prod DB").unwrap();
        e.kind = EntryKind::Server;
        assert!(v.upsert(e.clone()).is_err());
        e.host = "10.0.0.5".into();
        v.upsert(e).unwrap();
    }

    #[test]
    fn kind_codes_roundtrip_and_unknown_is_rejected() {
        for k in [EntryKind::Web, EntryKind::Server] {
            assert_eq!(EntryKind::from_u8(k.to_u8()).unwrap(), k);
        }
        assert!(EntryKind::from_u8(2).is_err());
    }

    #[test]
    fn debug_redacts_secrets() {
        let mut e = Entry::new("Bank").unwrap();
        e.password = "hunter2-secret".into();
        e.username = "my-login".into();
        let s = format!("{e:?}");
        assert!(!s.contains("hunter2") && !s.contains("my-login"));
    }
}
