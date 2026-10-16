//! # argus-platform
//!
//! Windows integration for Argus Vault. This is the **only** crate in the workspace that is
//! allowed to contain `unsafe` code: every block carries a `// SAFETY:` comment (enforced by
//! `clippy::undocumented_unsafe_blocks`) and holds a single unsafe operation
//! (`clippy::multiple_unsafe_ops_per_block`).
//!
//! * [`clipboard`] — copy secrets with history/cloud exclusion and a safe auto-clear,
//! * [`window`] — keep the window out of screenshots and screen recordings,
//! * [`dialog`] — native open / save-as file dialogs,
//! * [`idle`] — how long the user has been away,
//! * [`session`] — be told when Windows locks the session or goes to sleep,
//! * [`instance`] — refuse to open the same vault twice,
//! * [`memory`] — total physical memory (sizes key derivation),
//! * [`process`] — process-wide hardening.
//!
//! Nothing here touches the network or the vault format.

#[cfg(windows)]
pub mod clipboard;
#[cfg(windows)]
pub mod dialog;
#[cfg(windows)]
pub mod file_lock;
#[cfg(windows)]
pub mod idle;
#[cfg(windows)]
pub mod instance;
#[cfg(windows)]
pub mod memory;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
pub mod window;

use std::fmt;

/// Why a platform call failed. Never carries secret data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlatformError {
    /// A Windows API call failed.
    Api,
    /// Another Argus Vault window already has this vault open.
    AlreadyOpen,
    /// The vault file is locked or in use by another program.
    InUse,
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Api => "a Windows call failed",
            Self::AlreadyOpen => "this vault is already open in another Argus Vault window",
            Self::InUse => "the vault file is in use by another program",
        })
    }
}

impl std::error::Error for PlatformError {}
