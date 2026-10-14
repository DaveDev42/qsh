//! The host-side filesystem steps of the remote file ops (`docs/adr/
//! 0029-file-copy.md` decisions 6-4, 6-6, 7 and 9), as pure blocking
//! functions over open directory fds.
//!
//! Like [`super::guard`] this module never calls the authorizer, never writes
//! audit and names no transport or session type (`cargo xtask arch` bans
//! those tokens in this file). `Server::handle_file_op` owns the decision
//! order of decision 8 and calls these once a request has passed it. Every
//! function here acts on a directory fd and a single component name (`*at`
//! calls), so a path component swapped after the check cannot redirect it.
//!
//! Unix only: the whole module is compiled out elsewhere, where the ops are
//! refused at the shape check (Windows is M20).

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

/// The kind of a filesystem object as an `lstat` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link.
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
    /// never reported, ADR-0029 decision 7).
    pub mode: u32,
    /// Modification time, seconds since the epoch.
    pub mtime: i64,
}

fn kind_of(st_mode: libc::mode_t) -> FsKind {
    match st_mode & libc::S_IFMT {
        libc::S_IFREG => FsKind::Regular,
        libc::S_IFDIR => FsKind::Directory,
        libc::S_IFLNK => FsKind::Symlink,
        _ => FsKind::Other,
    }
}

// The `stat` field widths differ per platform (`st_mode` is `u16` on macOS), so
// the conversions are no-ops on some targets and needed on others.
#[allow(clippy::useless_conversion)]
fn info_of(st: &libc::stat) -> StatInfo {
    StatInfo {
        kind: kind_of(st.st_mode),
        size: u64::try_from(st.st_size).unwrap_or(0),
        mode: u32::from(st.st_mode) & 0o777,
        mtime: i64::from(st.st_mtime),
    }
}

fn cstring(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// `fstat` of an open fd.
pub fn fstat(file: &File) -> io::Result<StatInfo> {
    // SAFETY: an all-zero `stat` is a valid initial value that fstat
    // overwrites.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is open for the call and `st` is a live local.
    let rc = unsafe { libc::fstat(file.as_raw_fd(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info_of(&st))
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`: what `name` is inside `dir`,
/// without following a final symlink. `Ok(None)` when it does not exist.
pub fn stat_at(dir: &File, name: &OsStr) -> io::Result<Option<StatInfo>> {
    let name = cstring(name)?;
    // SAFETY: an all-zero `stat` is a valid initial value that fstatat
    // overwrites.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is open, `name` is a live NUL-terminated string and `st`
    // is a live local.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(Some(info_of(&st)));
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(err)
    }
}

/// `lstat` by path (a canonical path; the final component is not followed).
/// `Ok(None)` when it does not exist.
pub fn lstat(path: &Path) -> io::Result<Option<StatInfo>> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(md) => Ok(Some(StatInfo {
            kind: kind_of(md.mode() as libc::mode_t),
            size: md.len(),
            mode: md.mode() & 0o777,
            mtime: md.mtime(),
        })),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// `openat(dir, name, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`: a sub-directory
/// of an open directory, without following a final symlink.
pub fn open_dir_at(dir: &File, name: &OsStr) -> io::Result<File> {
    let name = cstring(name)?;
    // SAFETY: `dir` is open and `name` is a live NUL-terminated string.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// What [`mkdir_at`] did.
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

/// `file.mkdir`'s `mkdirat` (ADR-0029 decision 7): the directory is made
/// inside `dir` under `name`. Without `preserve` the mode is `(mode &
/// ~umask) | 0o700` (the kernel applies the umask; the owner bits are put
/// back if the umask cleared them), with it `mode | 0o700`. Owner rwx is
/// always on, so a read-only source directory still takes files.
pub fn mkdir_at(dir: &File, name: &OsStr, mode: u32, preserve: bool) -> io::Result<MkdirOutcome> {
    let cname = cstring(name)?;
    let wanted = (mode & 0o777) | 0o700;
    let initial = if preserve { 0o700 } else { wanted };
    // SAFETY: `dir` is open and `cname` is a live NUL-terminated string.
    let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), cname.as_ptr(), initial as libc::mode_t) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(err);
        }
        return Ok(match stat_at(dir, name)? {
            Some(StatInfo {
                kind: FsKind::Directory,
                ..
            }) => MkdirOutcome::Existed,
            _ => MkdirOutcome::ExistsNotDirectory,
        });
    }
    // Fix the mode through the new directory's own fd, so a swapped name
    // cannot take the chmod. Without `preserve` only a umask that cleared
    // owner bits needs the fix.
    let sub = open_dir_at(dir, name)?;
    let current = fstat(&sub)?.mode;
    let target = if preserve { wanted } else { current | 0o700 };
    if current != target {
        use std::os::unix::fs::PermissionsExt;
        sub.set_permissions(std::fs::Permissions::from_mode(target))?;
    }
    Ok(MkdirOutcome::Created)
}

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

/// All entry names of the directory behind `dir`, `.` and `..` left out, in
/// no particular order. Fails with [`ListError::TooManyEntries`] the moment
/// more than `cap` names were read (the cap bounds the memory and the sort).
fn read_names(dir: &File, cap: usize) -> Result<Vec<Vec<u8>>, ListError> {
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` on an open fd returns a new fd that
    // this function owns and hands to `fdopendir`.
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io_err(io::Error::last_os_error()));
    }
    // SAFETY: `fd` is a directory descriptor this call owns; on success the
    // returned stream owns it, on failure it is closed here.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: `fd` was not consumed by the failed fdopendir.
        unsafe { libc::close(fd) };
        return Err(io_err(err));
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: the stream came from `fdopendir` and is closed once.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(stream);
    // The dup shares the file offset with `dir`; start from the beginning.
    // SAFETY: the stream is open.
    unsafe { libc::rewinddir(stream.0) };
    let mut names = Vec::new();
    loop {
        // readdir signals the end and an error with the same null; errno
        // tells them apart.
        clear_errno();
        // SAFETY: the stream is open and not shared with another thread.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let err = io::Error::last_os_error();
            if err.raw_os_error().is_some_and(|code| code != 0) {
                return Err(io_err(err));
            }
            return Ok(names);
        }
        // SAFETY: a non-null dirent has a NUL-terminated `d_name`.
        let raw = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        if names.len() >= cap {
            return Err(ListError::TooManyEntries(cap));
        }
        names.push(raw.to_vec());
    }
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: `__errno_location` returns the thread's errno slot.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    // SAFETY: `__error` returns the thread's errno slot.
    unsafe { *libc::__error() = 0 };
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn clear_errno() {}

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
        let os = OsString::from_vec(name.clone());
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

#[cfg(test)]
mod tests;
