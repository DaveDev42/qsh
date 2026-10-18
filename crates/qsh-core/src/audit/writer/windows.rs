//! The Windows halves of the writer's co-writer protection (ADR-0035
//! decision 24): an exclusive `LockFileEx` lock on the sidecar lock file,
//! the counterpart of unix's `flock`, and the (volume serial number, file
//! index) comparison that tells a handle gone stale from a current one, the
//! counterpart of the (`st_dev`, `st_ino`) comparison.

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx, UnlockFileEx};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::fsutil::PrivateOpen;
use crate::fsutil::file_identity;

/// The sidecar lock file, open for the life of the writer. The lock is a
/// byte-range lock on a handle, and two handles exclude each other even
/// inside one process, so two sinks in one process (a test; `qsh serve`
/// next to a `qsh listen` controller in one binary) exclude each other as
/// two processes do.
pub(super) struct LockFile {
    file: File,
}

impl LockFile {
    /// Open (creating it owner-only if it is new) the lock file at `path`.
    /// Its directory exists.
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            file: crate::fsutil::open_private_file(PrivateOpen::Lock, path)?,
        })
    }

    /// Block until this handle holds the lock; the guard releases it.
    pub(super) fn lock(&self) -> io::Result<Guard<'_>> {
        // A blocking lock waits until it has the lock, so "held elsewhere"
        // should never come back; if it does, fail the write, not the thread.
        self.lock_with(LOCKFILE_EXCLUSIVE_LOCK)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "a blocking LockFileEx returned without the lock",
            )
        })
    }

    /// Take the lock if no other handle holds it, without waiting: `None`
    /// when another handle does. For tests, which must see "held" without
    /// waiting out a timer.
    #[cfg(test)]
    pub(super) fn try_lock(&self) -> io::Result<Option<Guard<'_>>> {
        use windows_sys::Win32::Storage::FileSystem::LOCKFILE_FAIL_IMMEDIATELY;
        self.lock_with(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)
    }

    fn lock_with(&self, flags: u32) -> io::Result<Option<Guard<'_>>> {
        // SAFETY: zero is the "no event, offset 0" state the call wants for
        // a handle opened without `FILE_FLAG_OVERLAPPED`.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open for the whole call and `overlapped`
        // lives on this stack frame; one byte at offset 0 is the lock.
        let locked =
            unsafe { LockFileEx(self.file.as_raw_handle(), flags, 0, 1, 0, &mut overlapped) };
        if locked != 0 {
            return Ok(Some(Guard { lock: self }));
        }
        let err = io::Error::last_os_error();
        // `ERROR_LOCK_VIOLATION`: held by another handle, and the caller
        // asked not to wait.
        if err.raw_os_error() == Some(33) {
            return Ok(None);
        }
        Err(err)
    }
}

/// The lock, held until this drops.
pub(super) struct Guard<'a> {
    lock: &'a LockFile,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        // SAFETY: as in `lock`; this releases the range that call took. A
        // failure leaves the lock to be released when the handle closes.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let _ = unsafe { UnlockFileEx(self.lock.file.as_raw_handle(), 0, 1, 0, &mut overlapped) };
    }
}

/// Whether `file` is no longer what is at `active_path`: the path names
/// another file, or none.
pub(super) fn is_stale(file: &File, active_path: &Path) -> io::Result<bool> {
    let held = file_identity::of_file(file)?;
    Ok(match file_identity::of_path(active_path) {
        Ok(at_path) => at_path != held,
        // The path is gone (mid-rotation elsewhere): reopen.
        Err(_) => true,
    })
}
