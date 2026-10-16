//! Native Windows "Open" and "Save as" file dialogs.
//!
//! Used for the vault file, keyfiles and import files, so nobody has to type a path by hand.
//! The dialogs are modal and block the calling thread while open; the system pumps messages
//! meanwhile. They only return a path: nothing is read or written here.

use std::ffi::c_void;
use std::path::PathBuf;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Controls::Dialogs::{
    CommDlgExtendedError, GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST,
    OFN_HIDEREADONLY, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW, OPEN_FILENAME_FLAGS,
};

use crate::PlatformError;

/// Longest path the dialog can return, in UTF-16 units (the Windows extended-length limit).
const PATH_CAPACITY: usize = 32_768;

/// What the dialog asks for.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Window title.
    pub title: &'a str,
    /// File type filters as `(label, pattern)`, e.g. `("Vault", "*.argus")`. The first one is
    /// selected. Include an "All files" entry if other files make sense.
    pub filters: &'a [(&'a str, &'a str)],
    /// Extension appended when the user types a name without one (no dot), e.g. `"argus"`.
    pub default_extension: Option<&'a str>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `label\0pattern\0label\0pattern\0\0`, the layout `OPENFILENAMEW::lpstrFilter` expects.
fn build_filter(filters: &[(&str, &str)]) -> Vec<u16> {
    let mut out = Vec::new();
    for (label, pattern) in filters {
        out.extend(label.encode_utf16());
        out.push(0);
        out.extend(pattern.encode_utf16());
        out.push(0);
    }
    out.push(0);
    out
}

fn show(owner: isize, req: &Request<'_>, save: bool) -> Result<Option<PathBuf>, PlatformError> {
    let title = wide(req.title);
    let filter = build_filter(req.filters);
    let ext = req.default_extension.map(wide);
    let mut buffer = vec![0u16; PATH_CAPACITY];

    let flags: OPEN_FILENAME_FLAGS = if save {
        OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR
    } else {
        OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR
    };
    let mut ofn = OPENFILENAMEW {
        lStructSize: u32::try_from(std::mem::size_of::<OPENFILENAMEW>())
            .map_err(|_| PlatformError::Api)?,
        hwndOwner: HWND(owner as *mut c_void),
        lpstrFilter: PCWSTR(filter.as_ptr()),
        nFilterIndex: 1,
        lpstrFile: PWSTR(buffer.as_mut_ptr()),
        nMaxFile: u32::try_from(buffer.len()).map_err(|_| PlatformError::Api)?,
        lpstrTitle: PCWSTR(title.as_ptr()),
        lpstrDefExt: ext.as_ref().map_or(PCWSTR::null(), |e| PCWSTR(e.as_ptr())),
        Flags: flags,
        ..Default::default()
    };

    let accepted = if save {
        // SAFETY: `ofn` is fully initialised and every pointer in it (filter, title, extension,
        // file buffer) refers to a live local that outlives the call; `nMaxFile` is the exact
        // length of the file buffer.
        unsafe { GetSaveFileNameW(&raw mut ofn) }
    } else {
        // SAFETY: same as above.
        unsafe { GetOpenFileNameW(&raw mut ofn) }
    };

    if !accepted.as_bool() {
        // SAFETY: plain query of the calling thread's last dialog error; no pointers involved.
        let code = unsafe { CommDlgExtendedError() };
        // 0 means the user cancelled.
        return if code.0 == 0 { Ok(None) } else { Err(PlatformError::Api) };
    }
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let path = String::from_utf16(buffer.get(..len).unwrap_or_default())
        .map_err(|_| PlatformError::Api)?;
    Ok(Some(PathBuf::from(path)))
}

/// Ask the user for an existing file. `Ok(None)` means they cancelled.
///
/// # Errors
/// [`PlatformError::Api`] if the dialog could not be shown.
pub fn open_file(owner: isize, req: &Request<'_>) -> Result<Option<PathBuf>, PlatformError> {
    show(owner, req, false)
}

/// Ask the user where to save a new file. The file need not exist, and there is **no**
/// overwrite prompt: Argus Vault never overwrites a vault or keyfile itself and reports an error
/// instead, so a prompt would only suggest something that does not happen. `Ok(None)` means
/// they cancelled.
///
/// # Errors
/// [`PlatformError::Api`] if the dialog could not be shown.
pub fn save_file(owner: isize, req: &Request<'_>) -> Result<Option<PathBuf>, PlatformError> {
    show(owner, req, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_is_double_nul_terminated_pairs() {
        let f = build_filter(&[("Vault", "*.argus"), ("All files", "*.*")]);
        let text = String::from_utf16(&f).unwrap();
        assert_eq!(text, "Vault\0*.argus\0All files\0*.*\0\0");
    }

    #[test]
    fn empty_filter_list_is_just_the_terminator() {
        assert_eq!(build_filter(&[]), vec![0]);
    }
}
