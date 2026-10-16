//! Error type for the core crate.
//!
//! Errors intentionally carry **no secret data** and are coarse-grained:
//! a wrong password, a wrong keyfile and a tampered file all surface as
//! [`Error::AuthenticationFailed`] so the UI cannot leak which one occurred.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// All errors produced by `argus-core`.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Underlying filesystem error.
    Io(std::io::Error),
    /// The file is not a valid Argus vault (bad magic, truncated, malformed).
    InvalidFormat,
    /// The vault was written by an unsupported (newer) format version.
    UnsupportedVersion,
    /// KDF parameters in the header are outside the accepted range.
    /// Protects against downgrade attacks that weaken Argon2.
    WeakKdfParams,
    /// Wrong password, wrong keyfile, or the file was modified.
    AuthenticationFailed,
    /// A size limit was exceeded (file too big, too many entries, ...).
    LimitExceeded,
    /// Invalid argument supplied by the caller.
    InvalidInput(&'static str),
    /// The operating system CSPRNG failed.
    Rng,
    /// Internal key-derivation failure.
    Kdf,
}

impl Error {
    /// `true` when the error should be shown to the user as
    /// "wrong credentials or corrupted file".
    #[must_use]
    pub fn is_unlock_failure(&self) -> bool {
        matches!(self, Self::AuthenticationFailed | Self::InvalidFormat)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidFormat => f.write_str("not a valid Argus vault file"),
            Self::UnsupportedVersion => f.write_str("unsupported vault format version"),
            Self::WeakKdfParams => f.write_str("key-derivation parameters out of allowed range"),
            Self::AuthenticationFailed => {
                f.write_str("wrong password or keyfile, or the vault file was modified")
            }
            Self::LimitExceeded => f.write_str("size limit exceeded"),
            Self::InvalidInput(what) => write!(f, "invalid input: {what}"),
            Self::Rng => f.write_str("system random number generator failure"),
            Self::Kdf => f.write_str("key derivation failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
