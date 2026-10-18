//! The path an open handle really names on Windows: `GetFinalPathNameByHandleW`
//! with the DOS volume name and the normalized (long, on-disk) spelling. It is
//! the counterpart of `/proc/self/fd/<n>` on Linux and `fcntl(F_GETPATH)` on
//! macOS, and what the remote file ops use both to resolve a path and to
//! recheck an opened handle (ADR-0035 decision 26, ADR-0029 decisions 6-2 and
//! 6-4).
//!
//! The call reports a `\\?\` verbatim path. Taking that prefix off is a pure
//! string rule and lives with the path judgement
//! (`file::guard::strip_verbatim_prefix`); this module returns what the
//! system said.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
};

/// The final path of the file or directory `file` is open on, as the system
/// reports it now (`\\?\C:\...`). It follows the object if something renamed
/// it or an ancestor, which is the point of asking the handle and not
/// remembering a string.
pub(crate) fn of_file(file: &File) -> io::Result<PathBuf> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: `handle` is open for the call and `buf` is a live buffer
        // of the length passed.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if len < buf.len() {
            buf.truncate(len);
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        // Too small: `len` is the size needed, terminator included.
        buf.resize(len + 1, 0);
    }
}
