//! Whether two handles, or a handle and a path, name the same file on
//! Windows: the (volume serial number, file index) pair that
//! `GetFileInformationByHandle` reports, the counterpart of unix's
//! (`st_dev`, `st_ino`) (ADR-0035 decision 24, ADR-0029 decision 23).
//!
//! The audit writer uses it to notice that the file it holds open is no
//! longer the one at its path (`audit/writer.rs`), and the file host uses it
//! to refuse a path that is another name for a protected file.
//!
//! On a volume that has 128-bit file IDs (ReFS) the 64-bit index is not
//! unique, so the 128-bit `FileIdInfo` is asked for first and the 64-bit
//! pair is the fallback for volumes that do not answer it. Both ends of one
//! comparison live on one volume and are read the same way, and two
//! identities of different widths never compare equal.

use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx,
};

/// Which file a handle or a path names, comparable with `==`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileIdentity {
    /// `FileIdInfo`: the volume serial number and the 128-bit file ID.
    Id128 { volume: u64, id: [u8; 16] },
    /// `GetFileInformationByHandle`: the 32-bit volume serial number and the
    /// 64-bit file index.
    Index64 { volume: u32, index: u64 },
}

/// The identity of the file `file` is open on.
pub(crate) fn of_file(file: &File) -> io::Result<FileIdentity> {
    of_handle(file.as_raw_handle())
}

/// The identity of the file (or directory) at `path`, following links. The
/// path is opened for its attributes only and with every share mode, so the
/// look neither blocks nor is blocked by a writer, a rename, or a delete.
pub(crate) fn of_path(path: &Path) -> io::Result<FileIdentity> {
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        // Needed to open a directory as well; harmless on a file.
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    of_file(&file)
}

fn of_handle(handle: *mut std::ffi::c_void) -> io::Result<FileIdentity> {
    let handle: HANDLE = handle;
    let mut wide = FILE_ID_INFO::default();
    // SAFETY: `handle` is a live file handle and the buffer is a `FILE_ID_INFO`
    // of the size passed.
    let wide_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut wide).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } != 0;
    if wide_ok {
        return Ok(FileIdentity::Id128 {
            volume: wide.VolumeSerialNumber,
            id: wide.FileId.Identifier,
        });
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is a live file handle and `info` is a plain out struct.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity::Index64 {
        volume: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

#[cfg(test)]
mod tests;
