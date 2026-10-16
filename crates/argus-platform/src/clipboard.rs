//! Protected clipboard for secrets.
//!
//! A secret is placed on the clipboard together with three marker formats that tell Windows not
//! to keep or sync it:
//!
//! * `ExcludeClipboardContentFromMonitorProcessing` — clipboard monitors and managers skip it,
//! * `CanIncludeInClipboardHistory` = 0 — kept out of the Win+V history,
//! * `CanUploadToCloudClipboard` = 0 — kept out of cross-device sync.
//!
//! Every copy also carries a private format, `ArgusVaultCopyId`, holding a random-looking
//! identifier that is not secret. [`copy_secret`] returns it as a [`ClipboardTicket`], and
//! [`clear_if_unchanged`] empties the clipboard only if that identifier is still there, i.e. the
//! clipboard still holds *this* copy. Copying anything else replaces the clipboard contents, so
//! the identifier disappears and the newer content is left alone. The secret itself is never read
//! back. The check and the clear happen while this process holds the clipboard open, so another
//! program cannot slip a copy in between.
//!
//! The clipboard sequence number is deliberately not used: closing the clipboard bumps it by a
//! variable amount (measured: +3 for these four formats), so a number captured around the copy
//! cannot be trusted and a wrong one would make the auto-clear silently do nothing.
//!
//! Limits: once the system owns the clipboard data, its copy of the text is not under our control
//! and is not wiped, only released by `EmptyClipboard`. Our own buffers are zeroized. The format
//! name `ArgusVaultCopyId` is visible to other programs and reveals that Argus Vault made the copy.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use zeroize::Zeroizing;

/// Another program may have the clipboard open; retry briefly before giving up.
const OPEN_ATTEMPTS: u32 = 20;
const OPEN_RETRY_DELAY: Duration = Duration::from_millis(15);

const FORMAT_EXCLUDE_MONITOR: PCWSTR = w!("ExcludeClipboardContentFromMonitorProcessing");
const FORMAT_NO_HISTORY: PCWSTR = w!("CanIncludeInClipboardHistory");
const FORMAT_NO_CLOUD: PCWSTR = w!("CanUploadToCloudClipboard");
const FORMAT_COPY_ID: PCWSTR = w!("ArgusVaultCopyId");

/// Why a clipboard operation failed. Never carries the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClipboardError {
    /// The clipboard stayed locked by another program.
    Open,
    /// Windows could not allocate memory for the clipboard data.
    Alloc,
    /// Windows refused to store or clear the clipboard data.
    Set,
}

impl fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "the clipboard is in use by another program",
            Self::Alloc => "not enough memory to use the clipboard",
            Self::Set => "Windows rejected the clipboard operation",
        })
    }
}

impl std::error::Error for ClipboardError {}

/// Identifies one specific copy, used to clear it later only if it is still on the clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardTicket(u64);

/// Unique per copy within this process. It only has to differ between copies; it is not secret.
fn next_copy_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or(0));
    nanos.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Holds the clipboard open; closes it on drop.
#[derive(Debug)]
struct OpenGuard;

impl OpenGuard {
    fn open() -> Result<Self, ClipboardError> {
        for attempt in 0..OPEN_ATTEMPTS {
            // SAFETY: no owner window is a valid argument and the call takes no pointers.
            if unsafe { OpenClipboard(None) }.is_ok() {
                return Ok(Self);
            }
            if attempt + 1 < OPEN_ATTEMPTS {
                std::thread::sleep(OPEN_RETRY_DELAY);
            }
        }
        Err(ClipboardError::Open)
    }
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        // SAFETY: this guard only exists while this thread has the clipboard open.
        let _ = unsafe { CloseClipboard() };
    }
}

fn empty() -> Result<(), ClipboardError> {
    // SAFETY: only called with the clipboard open (an `OpenGuard` is alive); no pointers.
    unsafe { EmptyClipboard() }.map_err(|_| ClipboardError::Set)
}

/// Zero a movable global block, then release it. Used when the system did not take ownership.
fn wipe_and_free(handle: HGLOBAL, len: usize) {
    // SAFETY: `handle` is a live movable block allocated by us; locking it yields its address.
    let ptr = unsafe { GlobalLock(handle) };
    if !ptr.is_null() {
        // SAFETY: the block is `len` bytes long and locked, so `len` bytes are writable at `ptr`.
        unsafe { std::ptr::write_bytes(ptr.cast::<u8>(), 0, len) };
        // SAFETY: matches the successful `GlobalLock` above.
        let _ = unsafe { GlobalUnlock(handle) };
    }
    // SAFETY: `handle` is a live block that nothing else owns; it is not used afterwards.
    let _ = unsafe { GlobalFree(Some(handle)) };
}

/// Copy `bytes` into a new movable global block.
fn alloc_global(bytes: &[u8]) -> Result<HGLOBAL, ClipboardError> {
    // SAFETY: plain allocation of `bytes.len()` bytes; failure is reported through `Result`.
    let handle =
        unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) }.map_err(|_| ClipboardError::Alloc)?;
    // SAFETY: `handle` is the live movable block just allocated.
    let ptr = unsafe { GlobalLock(handle) };
    if ptr.is_null() {
        // SAFETY: the block is live and unused; nothing was written to it.
        let _ = unsafe { GlobalFree(Some(handle)) };
        return Err(ClipboardError::Alloc);
    }
    // SAFETY: `ptr` addresses `bytes.len()` writable bytes of a fresh allocation, which cannot
    // overlap `bytes`.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len()) };
    // SAFETY: matches the successful `GlobalLock` above.
    let _ = unsafe { GlobalUnlock(handle) };
    Ok(handle)
}

/// Store `bytes` on the (already open and emptied) clipboard under `format`.
fn set_format(format: u32, bytes: &[u8]) -> Result<(), ClipboardError> {
    let handle = alloc_global(bytes)?;
    // SAFETY: the clipboard is open (callers hold an `OpenGuard`) and `handle` is a live movable
    // block; on success the system takes ownership of it.
    let result = unsafe { SetClipboardData(format, Some(HANDLE(handle.0))) };
    if result.is_err() {
        wipe_and_free(handle, bytes.len());
        return Err(ClipboardError::Set);
    }
    Ok(())
}

fn register_format(name: PCWSTR) -> Result<u32, ClipboardError> {
    // SAFETY: `name` comes from `w!`, a static NUL-terminated UTF-16 string.
    let id = unsafe { RegisterClipboardFormatW(name) };
    if id == 0 {
        return Err(ClipboardError::Set);
    }
    Ok(id)
}

fn is_available(format: u32) -> bool {
    // SAFETY: plain query with a format id; no pointers.
    unsafe { IsClipboardFormatAvailable(format) }.is_ok()
}

/// Read the copy identifier currently on the clipboard, if there is one. Needs the clipboard open.
fn read_copy_id(_open: &OpenGuard) -> Option<u64> {
    let format = register_format(FORMAT_COPY_ID).ok()?;
    if !is_available(format) {
        return None;
    }
    // SAFETY: the clipboard is open (`_open` proves it); the handle stays owned by the system.
    let handle = unsafe { GetClipboardData(format) }.ok()?;
    let block = HGLOBAL(handle.0);
    // SAFETY: clipboard data for a registered format set via `SetClipboardData` is a global block.
    let size = unsafe { GlobalSize(block) };
    if size < std::mem::size_of::<u64>() {
        return None;
    }
    // SAFETY: `block` is a live global block owned by the clipboard.
    let ptr = unsafe { GlobalLock(block) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the block is at least 8 bytes (checked above); the read tolerates any alignment.
    let id = unsafe { ptr.cast::<u64>().read_unaligned() };
    // SAFETY: matches the successful `GlobalLock` above.
    let _ = unsafe { GlobalUnlock(block) };
    Some(u64::from_le(id))
}

fn store_protected(text_utf16le: &[u8], id: u64) -> Result<(), ClipboardError> {
    empty()?;
    set_format(u32::from(CF_UNICODETEXT.0), text_utf16le)?;
    let zero = 0u32.to_le_bytes();
    for name in [FORMAT_EXCLUDE_MONITOR, FORMAT_NO_HISTORY, FORMAT_NO_CLOUD] {
        set_format(register_format(name)?, &zero)?;
    }
    set_format(register_format(FORMAT_COPY_ID)?, &id.to_le_bytes())
}

/// Put `text` on the clipboard, flagged to stay out of history, cloud sync and monitors.
///
/// # Errors
/// [`ClipboardError`] if the clipboard cannot be opened or written. On a partial failure the
/// clipboard is emptied so an unprotected copy of the secret is never left behind.
pub fn copy_secret(text: &str) -> Result<ClipboardTicket, ClipboardError> {
    // UTF-16LE with a terminating NUL, reserved up front so the buffer never reallocates.
    let mut bytes = Zeroizing::new(Vec::with_capacity((text.len() + 1) * 2));
    for unit in text.encode_utf16().chain(std::iter::once(0)) {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    let id = next_copy_id();
    let _guard = OpenGuard::open()?;
    if let Err(e) = store_protected(&bytes, id) {
        let _ = empty();
        return Err(e);
    }
    Ok(ClipboardTicket(id))
}

/// Empty the clipboard only if it still holds the copy `ticket` refers to.
///
/// Returns `Ok(true)` if it was cleared and `Ok(false)` if something else has been copied since
/// (in which case the newer content is left alone).
///
/// # Errors
/// [`ClipboardError`] if the clipboard cannot be opened or emptied; the ticket is still valid and
/// the call can be retried.
pub fn clear_if_unchanged(ticket: ClipboardTicket) -> Result<bool, ClipboardError> {
    let guard = OpenGuard::open()?;
    if read_copy_id(&guard) != Some(ticket.0) {
        return Ok(false);
    }
    empty()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// The clipboard is one global resource: tests must not run in parallel.
    static CLIPBOARD_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        CLIPBOARD_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn has_format(name: PCWSTR) -> bool {
        is_available(register_format(name).unwrap())
    }

    fn text_on_clipboard() -> Option<String> {
        let _guard = OpenGuard::open().unwrap();
        if !is_available(u32::from(CF_UNICODETEXT.0)) {
            return None;
        }
        // SAFETY: the clipboard is open (guard alive); the handle stays owned by the system.
        let handle = unsafe { GetClipboardData(u32::from(CF_UNICODETEXT.0)) }.ok()?;
        let hglobal = HGLOBAL(handle.0);
        // SAFETY: CF_UNICODETEXT data is a movable global block; locking yields its address.
        let ptr = unsafe { GlobalLock(hglobal) }.cast::<u16>();
        if ptr.is_null() {
            return None;
        }
        let mut units = Vec::new();
        let mut i = 0;
        loop {
            // SAFETY: CF_UNICODETEXT data is NUL-terminated and the loop stops at the terminator,
            // so `i` never moves past the end of the block.
            let at = unsafe { ptr.add(i) };
            // SAFETY: `at` is inside the block (see above); the read tolerates any alignment.
            let unit = unsafe { at.read_unaligned() };
            if unit == 0 {
                break;
            }
            units.push(unit);
            i += 1;
        }
        // SAFETY: matches the successful `GlobalLock` above.
        let _ = unsafe { GlobalUnlock(hglobal) };
        Some(String::from_utf16_lossy(&units))
    }

    #[test]
    fn copy_stores_text_and_all_protection_formats() {
        let _l = lock();
        let ticket = copy_secret("p\u{e1}ss-w\u{f6}rd \u{1f511} 42").unwrap();

        assert_eq!(text_on_clipboard().as_deref(), Some("p\u{e1}ss-w\u{f6}rd \u{1f511} 42"));
        for name in [FORMAT_EXCLUDE_MONITOR, FORMAT_NO_HISTORY, FORMAT_NO_CLOUD, FORMAT_COPY_ID] {
            assert!(has_format(name), "format missing from the clipboard");
        }
        let guard = OpenGuard::open().unwrap();
        assert_eq!(read_copy_id(&guard), Some(ticket.0));
        drop(guard);
        clear_if_unchanged(ticket).unwrap();
    }

    #[test]
    fn clear_empties_the_clipboard_when_unchanged() {
        let _l = lock();
        let ticket = copy_secret("temporary-secret").unwrap();
        assert!(clear_if_unchanged(ticket).unwrap());
        assert_eq!(text_on_clipboard(), None);
        assert!(!has_format(FORMAT_COPY_ID));
    }

    #[test]
    fn clear_leaves_newer_content_alone() {
        let _l = lock();
        let old = copy_secret("first-secret").unwrap();
        let newer = copy_secret("second-secret").unwrap();
        assert_ne!(old, newer);

        assert!(
            !clear_if_unchanged(old).unwrap(),
            "must not clear content copied after the ticket"
        );
        assert_eq!(text_on_clipboard().as_deref(), Some("second-secret"));
        assert!(clear_if_unchanged(newer).unwrap());
    }

    #[test]
    fn clear_leaves_content_from_other_programs_alone() {
        let _l = lock();
        let ticket = copy_secret("our-secret").unwrap();
        {
            // Simulate another program replacing the clipboard with plain text.
            let _g = OpenGuard::open().unwrap();
            empty().unwrap();
            set_format(u32::from(CF_UNICODETEXT.0), &[b'x', 0, 0, 0]).unwrap();
        }
        assert!(!clear_if_unchanged(ticket).unwrap());
        assert_eq!(text_on_clipboard().as_deref(), Some("x"));
        // Leave the clipboard empty for whoever runs next.
        let _g = OpenGuard::open().unwrap();
        empty().unwrap();
    }

    #[test]
    fn clearing_twice_is_harmless() {
        let _l = lock();
        let ticket = copy_secret("once").unwrap();
        assert!(clear_if_unchanged(ticket).unwrap());
        assert!(!clear_if_unchanged(ticket).unwrap());
    }

    #[test]
    fn copy_ids_are_unique() {
        let ids: std::collections::HashSet<u64> = (0..1000).map(|_| next_copy_id()).collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn error_messages_are_present() {
        for e in [ClipboardError::Open, ClipboardError::Alloc, ClipboardError::Set] {
            assert_ne!(e.to_string(), "");
        }
    }
}
