//! The Windows steps of the host-side filesystem, behind the platform-neutral
//! facade in `super` (`docs/adr/0035-windows-client.md` decision 26,
//! `docs/adr/0029-file-copy.md` decisions 7, 9, 13 and 23).
//!
//! Windows has no `*at` calls, so the steps that stat and make under a
//! directory are [`crate::file::local`]'s (and so are the write side's temp
//! file, attributes and placement, which `file::xfer` calls through
//! `local` on both platforms): a directory is
//! an open handle held without `FILE_SHARE_DELETE`, every step works by path
//! under that handle's final path, and a symlink or junction in the last
//! component is refused, which is the reading of `O_NOFOLLOW`. Both the
//! client's `qsh cp` and the host go through the same functions, so a fix to
//! one reaches the other.
//!
//! What only the host needs is here: the directory read behind a listing and
//! the free-space probe. Like the guard this never calls the authorizer,
//! never writes audit and names no transport or session type.

use std::ffi::OsString;
use std::fs::File;
use std::io;

use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

pub(crate) use crate::file::local::{fstat, mkdir_at, open_dir_at, stat_at};

use super::{FreeSpace, ListError, io_err};

/// All entry names of the directory behind `dir`, `.` and `..` left out, as
/// UTF-8 bytes in no particular order. A name that is not valid UTF-16 (an
/// unpaired surrogate) cannot be UTF-8 either, so it is listed as a single
/// byte that is never valid UTF-8 and is counted as unlistable. Fails with
/// [`ListError::TooManyEntries`] the moment more than `cap` names were read.
pub(super) fn read_names(dir: &File, cap: usize) -> Result<Vec<Vec<u8>>, ListError> {
    let path = crate::fsutil::final_path::of_file(dir).map_err(io_err)?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path).map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        if names.len() >= cap {
            return Err(ListError::TooManyEntries(cap));
        }
        names.push(match entry.file_name().into_string() {
            Ok(name) => name.into_bytes(),
            Err(_) => vec![0xff],
        });
    }
    Ok(names)
}

/// A directory entry name from the bytes [`read_names`] returned.
pub(super) fn name_from_bytes(bytes: Vec<u8>) -> OsString {
    OsString::from(String::from_utf8_lossy(&bytes).into_owned())
}

/// The real probe: `GetDiskFreeSpaceExW`, the bytes available to the caller
/// (which honours a disk quota) on the volume the directory is on.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiskFreeSpace;

/// The free-space probe the host uses by default on this platform.
pub type SystemFreeSpace = DiskFreeSpace;

impl FreeSpace for DiskFreeSpace {
    fn available_bytes(&self, dir: &File) -> io::Result<u64> {
        let path = crate::fsutil::final_path::of_file(dir)?;
        let wide = crate::fsutil::dacl::to_wide(&path)?;
        let mut available = 0u64;
        // SAFETY: `wide` is a NUL-terminated path that lives through the
        // call, `available` is a live local and the two optional outputs are
        // null.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(available)
    }
}
