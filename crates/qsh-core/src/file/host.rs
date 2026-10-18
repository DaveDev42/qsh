//! The host-side filesystem steps of the remote file ops (`docs/adr/
//! 0029-file-copy.md` decisions 6-4, 6-6, 7 and 9), as pure blocking
//! functions over open directory handles.
//!
//! Like [`super::guard`] this module never calls the authorizer, never writes
//! audit and names no transport or session type (`cargo xtask arch` bans
//! those tokens in this file and in the two platform files below).
//! `Server::handle_file_op` owns the decision order of decision 8 and calls
//! these once a request has passed it. Every function here acts on a
//! directory handle and a single component name, so a path component swapped
//! after the check cannot redirect it.
//!
//! The write side (the temporary file next to its destination, the final
//! attributes, the replace or the no-clobber placement, the free-space
//! probe) lives here too: the `FILE_DATA` pump in `server/file_data.rs` owns
//! the stream and the order, and calls these blocking steps from
//! `spawn_blocking`.
//!
//! This file is the platform-neutral part: the types, the directory listing
//! (a sorted, cursor-paged read of the names) and the free-space seam. The
//! steps themselves are `host/posix.rs` (the `*at` calls) and
//! `host/windows.rs` (the handle-and-path equivalents of
//! `super::local`, ADR-0035 decision 26).

use std::ffi::OsString;
use std::fs::File;
use std::io;

pub use super::stat::{FsKind, MkdirOutcome, StatInfo, TempFile, WriteGate};

#[cfg(unix)]
mod posix;
#[cfg(unix)]
pub use posix::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(all(test, unix))]
mod tests;
#[cfg(all(test, windows))]
mod windows_tests;

/// One listed directory entry (`FileEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedEntry {
    /// The entry's name (UTF-8; other names are only counted).
    pub name: String,
    /// The `lstat` facts of the entry itself.
    pub info: StatInfo,
}

/// One page of a directory listing (`FileListed`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listing {
    /// Up to the page cap of entries, in name byte order, all greater than
    /// the cursor.
    pub entries: Vec<ListedEntry>,
    /// More names follow the last entry.
    pub more: bool,
    /// Names in the whole directory that are not UTF-8, so cannot be
    /// listed. The same number on every page.
    pub unlistable: u32,
}

/// Why [`list_dir`] failed.
#[derive(Debug, thiserror::Error)]
pub enum ListError {
    /// The directory holds more entries than the cap
    /// (`FILE_LIST_DIR_MAX`). Reported as `RESOURCE_EXHAUSTED`.
    #[error("directory has more than {0} entries")]
    TooManyEntries(usize),
    /// Reading the directory failed.
    #[error("directory cannot be read ({0:?})")]
    Io(io::ErrorKind),
}

fn io_err(e: io::Error) -> ListError {
    ListError::Io(e.kind())
}

/// One page of the directory behind `dir` (ADR-0029 decision 9): names in
/// byte order, only those greater than `after`, at most `page_max`, each
/// `lstat`ed through `dir`. The host keeps no state between pages: it reads
/// and sorts the names again, so the cap `dir_max` bounds the cost of a page
/// and, with the page size, the cost of walking a directory.
pub fn list_dir(
    dir: &File,
    after: &[u8],
    page_max: usize,
    dir_max: usize,
) -> Result<Listing, ListError> {
    let mut names = read_names(dir, dir_max)?;
    names.sort_unstable();
    let mut unlistable = 0u32;
    let mut listable: Vec<Vec<u8>> = Vec::with_capacity(names.len());
    for name in names {
        if std::str::from_utf8(&name).is_ok() {
            listable.push(name);
        } else {
            unlistable = unlistable.saturating_add(1);
        }
    }
    // Names are sorted, so the cursor is a partition point.
    let start = listable.partition_point(|name| name.as_slice() <= after);
    let rest = &listable[start..];
    let more = rest.len() > page_max;
    let mut entries = Vec::with_capacity(rest.len().min(page_max));
    for name in rest.iter().take(page_max) {
        let os: OsString = name_from_bytes(name.clone());
        // A name that vanished between the read and the stat is skipped.
        let Some(info) = stat_at(dir, &os).map_err(io_err)? else {
            continue;
        };
        entries.push(ListedEntry {
            name: String::from_utf8(name.clone()).expect("checked as UTF-8 above"),
            info,
        });
    }
    Ok(Listing {
        entries,
        more,
        unlistable,
    })
}

/// Free bytes on the filesystem a directory handle lives on (ADR-0029
/// decision 13). A trait so a test can make a disk look full or empty
/// without one.
pub trait FreeSpace: Send + Sync {
    /// Bytes an unprivileged writer can still use below `dir`.
    fn available_bytes(&self, dir: &File) -> io::Result<u64>;
}
