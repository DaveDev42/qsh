//! The platform-neutral vocabulary of the local filesystem steps: what a
//! stat reports, what a `mkdir` did, the temporary file a transfer writes
//! and the test seam on its writer.
//!
//! The unix steps that produce these values are in `super::host` (the
//! host and the client both use them); the Windows client's are in
//! `super::local`. Keeping the types here lets the transfer code in
//! `super::xfer` and the copy driver name them on either platform.

use std::ffi::OsString;
use std::fs::File;

/// The kind of a filesystem object as an `lstat` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link (on Windows also a junction).
    Symlink,
    /// A FIFO, socket, device or anything else.
    Other,
}

/// The facts of one `lstat`/`fstat` the wire reports (`FileEntry`,
/// `FileListed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatInfo {
    /// The object's kind.
    pub kind: FsKind,
    /// Size in bytes.
    pub size: u64,
    /// Permission bits, `st_mode & 0o777` (setuid, setgid and sticky are
    /// never reported, ADR-0029 decision 7). Windows synthesizes them
    /// (ADR-0035 decision 26): `0o444` for a read-only file, `0o644` for any
    /// other, `0o755` for a directory.
    pub mode: u32,
    /// Modification time, seconds since the epoch.
    pub mtime: i64,
}

/// What `mkdir_at` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkdirOutcome {
    /// A new directory was made.
    Created,
    /// A directory of that name already existed (merged into, ADR-0029
    /// decision 7).
    Existed,
    /// Something that is not a directory has that name.
    ExistsNotDirectory,
}

/// A freshly created temporary file and the name it has inside its
/// directory.
#[derive(Debug)]
pub struct TempFile {
    /// The open file, write-only, owner-only (mode `0600` on unix, an
    /// owner-only protected DACL on Windows).
    pub file: File,
    /// Its name inside the directory it was created through.
    pub name: OsString,
}

/// A seam on the blocking writer thread of a `file.write`: called before each
/// chunk is written to the temp file. Production sets none. A test uses it to
/// hold the disk write still, which is how a stalled local write (ADR-0037)
/// is made on demand.
pub trait WriteGate: Send + Sync {
    /// About to write the next chunk; `written` bytes are already in the
    /// file.
    fn before_write(&self, written: u64);
}
