//! The operating-system half of the Windows path judgement
//! (`docs/adr/0035-windows-client.md` decision 26, `docs/adr/0029-file-copy.md`
//! decisions 6 and 23). The string rules are in `windows_path.rs`; this file
//! asks the system:
//!
//! - the serve account's profile directory ([`profile_dir`]), from the
//!   process token and never from `%USERPROFILE%`;
//! - the final path of an existing prefix ([`normalize`]), the Windows
//!   `realpath`: links and junctions followed to the end, short names
//!   expanded, the on-disk spelling of every existing component;
//! - the open that refuses a reparse point ([`open_nofollow`]) and checks the
//!   handle's own final path against the path it was asked for, so a
//!   directory swapped for a junction between normalization and open is a
//!   refusal here and not a surprise later;
//! - the final path of an open handle ([`handle_path`]) for the recheck.
//!
//! Like `guard.rs` this never calls the authorizer or the audit log and names
//! no transport or session type.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE,
};
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;

use super::windows_path::strip_verbatim_prefix as strip_verbatim;
use super::windows_path::{self, Resolved};
use super::{NormalizeError, same_path};

/// `ERROR_DIRECTORY`: the opened object is not a directory.
const ERROR_DIRECTORY: i32 = 267;
/// `ERROR_CANT_ACCESS_FILE`: what a refused reparse point, or a handle that
/// is not at the path it was opened for, is reported as. The same code the
/// local steps (`file/local/windows.rs`) use, so `classify` reads both.
const ERROR_CANT_ACCESS_FILE: i32 = 1920;

/// The profile directory of the process token, `None` when the system does
/// not say or it is not a drive path.
pub(super) fn profile_dir() -> Option<PathBuf> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle of the current process needs no closing; the
    // token handle is written on success and closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `OpenProcessToken`
            // and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
    let token = Token(token);
    let mut buf = vec![0u16; 260];
    loop {
        let mut len = u32::try_from(buf.len()).ok()?;
        // SAFETY: `token` is a live token handle with query access, `buf` is
        // a live buffer of `len` units and `len` is a live local.
        let ok = unsafe { GetUserProfileDirectoryW(token.0, buf.as_mut_ptr(), &mut len) };
        if ok != 0 {
            // `len` counts the terminator.
            buf.truncate((len as usize).saturating_sub(1));
            break;
        }
        // SAFETY: reads the calling thread's last error.
        if unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER && (len as usize) > buf.len() {
            buf.resize(len as usize, 0);
        } else {
            return None;
        }
    }
    let text = std::ffi::OsString::from_wide(&buf).into_string().ok()?;
    windows_path::split_drive_path(&text)?;
    Some(PathBuf::from(text))
}

/// Resolve one existing prefix: the final path of the object it names, links
/// followed, and whether that object is a directory.
fn resolve_prefix(prefix: &str) -> io::Result<Resolved> {
    let resolved = fs::canonicalize(prefix)?;
    let is_dir = fs::metadata(&resolved)?.is_dir();
    let text = resolved
        .into_os_string()
        .into_string()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(Resolved {
        path: strip_verbatim(&text),
        is_dir,
    })
}

/// The Windows normalizer ([`windows_path::normalize_with`] over the real
/// filesystem).
pub(super) fn normalize(absolute: &Path) -> Result<PathBuf, NormalizeError> {
    let Some(text) = absolute.to_str() else {
        return Err(NormalizeError::Io(io::ErrorKind::InvalidInput));
    };
    windows_path::normalize_with(text, &resolve_prefix).map(PathBuf::from)
}

/// The final path of an open handle, without the `\\?\` prefix. A path that
/// is not a drive path (a UNC share, a volume with no letter) is not a path
/// the policy can judge, so it is an error and the recheck refuses.
pub(super) fn handle_path(file: &File) -> io::Result<PathBuf> {
    let verbatim = crate::fsutil::final_path::of_file(file)?;
    let text = verbatim
        .into_os_string()
        .into_string()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let text = strip_verbatim(&text);
    if windows_path::split_drive_path(&text).is_none() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    Ok(PathBuf::from(text))
}

/// What the caller wants the opened object to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Want {
    /// Anything a read can start from (the caller checks the kind, as it
    /// does after an unix `O_RDONLY` open).
    File,
    /// A directory.
    Directory,
}

/// Open `path` as the object itself (`FILE_FLAG_OPEN_REPARSE_POINT`, with
/// backup semantics so a directory opens too) and refuse a symlink or
/// junction, the Windows reading of `O_NOFOLLOW`. The handle's final path
/// must then be `path` (compared per component, ignoring case): an
/// intermediate component swapped for a junction after normalization lands
/// the open somewhere else, and that is a refusal.
///
/// The share mode allows readers, writers and deletes of a file, so a
/// pending download does not block a replace of the file; a directory is
/// held without `FILE_SHARE_DELETE`, so it stays where it is while a copy
/// writes into it.
pub(super) fn open_nofollow(path: &Path, want: Want) -> io::Result<File> {
    let share = match want {
        Want::File => FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        Want::Directory => FILE_SHARE_READ | FILE_SHARE_WRITE,
    };
    let file = OpenOptions::new()
        .read(true)
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let md = file.metadata()?;
    if md.file_type().is_symlink() {
        return Err(io::Error::from_raw_os_error(ERROR_CANT_ACCESS_FILE));
    }
    if want == Want::Directory && !md.is_dir() {
        return Err(io::Error::from_raw_os_error(ERROR_DIRECTORY));
    }
    if !same_path(&handle_path(&file)?, path, true) {
        return Err(io::Error::from_raw_os_error(ERROR_CANT_ACCESS_FILE));
    }
    Ok(file)
}
