//! The Windows steps of the local filesystem interface
//! (`docs/adr/0035-windows-client.md` decision 26, `docs/adr/0029-file-copy.md`
//! decisions 7, 22 and 23).
//!
//! Windows has no `*at` calls, so a "directory" here is an open handle to it
//! and every step works by path under that handle's final path:
//!
//! - The handle is opened with `FILE_FLAG_BACKUP_SEMANTICS` and without
//!   `FILE_SHARE_DELETE`, so the directory cannot be renamed or removed
//!   while a copy writes into it.
//! - A name is one validated component (the callers check it), so the path
//!   under the handle cannot climb out of it. The last component is never
//!   followed: whatever is opened or created there is opened with
//!   `FILE_FLAG_OPEN_REPARSE_POINT` or `CREATE_NEW`, and a symlink or
//!   junction is refused, which is the reading of unix's `O_NOFOLLOW`.
//! - The temp file is created with the owner-only DACL of ADR-0035 decision
//!   9. Just before the rename its protection is dropped, so the finished
//!   file takes the ACL its directory hands down, as a unix file takes the
//!   mode `mode & ~umask` after being created `0600`.
//! - Mode bits are synthesized: a file is `0o444` when it carries the
//!   read-only attribute and `0o644` otherwise, a directory `0o755`. The
//!   read-only attribute is written only when the owner write bit of the
//!   mode is clear, and no other bit is written. `-p` sets the modification
//!   time with `SetFileTime`.

use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use rand::Rng as _;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileBasicInfo, GetFinalPathNameByHandleW, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    SetFileInformationByHandle, VOLUME_NAME_DOS,
};

use super::{FsKind, IoClass, MkdirOutcome, StatInfo};
use crate::file::stat::TempFile;

/// `ERROR_FILE_EXISTS`.
const ERROR_FILE_EXISTS: i32 = 80;
/// `ERROR_ALREADY_EXISTS`.
const ERROR_ALREADY_EXISTS: i32 = 183;
/// `ERROR_FILE_NOT_FOUND`.
const ERROR_FILE_NOT_FOUND: i32 = 2;
/// `ERROR_PATH_NOT_FOUND`.
const ERROR_PATH_NOT_FOUND: i32 = 3;
/// `ERROR_TOO_MANY_OPEN_FILES`.
const ERROR_TOO_MANY_OPEN_FILES: i32 = 4;
/// `ERROR_ACCESS_DENIED`.
const ERROR_ACCESS_DENIED: i32 = 5;
/// `ERROR_WRITE_PROTECT`.
const ERROR_WRITE_PROTECT: i32 = 19;
/// `ERROR_HANDLE_DISK_FULL`.
const ERROR_HANDLE_DISK_FULL: i32 = 39;
/// `ERROR_DISK_FULL`.
const ERROR_DISK_FULL: i32 = 112;
/// `ERROR_DIRECTORY`: the directory name is invalid (not a directory).
const ERROR_DIRECTORY: i32 = 267;
/// `ERROR_DISK_QUOTA_EXCEEDED`.
const ERROR_DISK_QUOTA_EXCEEDED: i32 = 1295;
/// `ERROR_CANT_ACCESS_FILE`: what a refused reparse point is reported as.
const ERROR_CANT_ACCESS_FILE: i32 = 1920;

/// The longest file name, in UTF-16 units, an NTFS component takes.
const NAME_MAX: usize = 255;

/// What a failed local I/O call was, from the Win32 error.
pub(crate) fn classify(err: &io::Error) -> IoClass {
    match err.raw_os_error() {
        Some(ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) => IoClass::Exists,
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => IoClass::NotFound,
        Some(ERROR_ACCESS_DENIED | ERROR_WRITE_PROTECT) => IoClass::Denied,
        Some(ERROR_DIRECTORY) => IoClass::NotDirectory,
        Some(ERROR_CANT_ACCESS_FILE) => IoClass::SymlinkRefused,
        Some(ERROR_DISK_FULL | ERROR_HANDLE_DISK_FULL | ERROR_DISK_QUOTA_EXCEEDED) => {
            IoClass::NoSpace
        }
        Some(ERROR_TOO_MANY_OPEN_FILES) => IoClass::TooManyOpen,
        _ => IoClass::Other,
    }
}

fn refused_reparse_point() -> io::Error {
    io::Error::from_raw_os_error(ERROR_CANT_ACCESS_FILE)
}

fn not_a_directory() -> io::Error {
    io::Error::from_raw_os_error(ERROR_DIRECTORY)
}

/// The destination directory the person typed: a symlink in the final
/// component is followed. The handle shares reads and writes but not
/// deletion, so the directory stays where it is while it is held.
pub(crate) fn open_dir(path: &Path) -> io::Result<File> {
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    if !dir.metadata()?.is_dir() {
        return Err(not_a_directory());
    }
    Ok(dir)
}

/// The final path of an open directory handle, as the system reports it now
/// (`\\?\C:\...`). It follows the directory if something renamed an
/// ancestor, which is the point of asking the handle and not remembering a
/// string.
fn dir_path(dir: &File) -> io::Result<PathBuf> {
    let handle = dir.as_raw_handle() as HANDLE;
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

/// The path of `name` inside `dir`. One plain component: callers validate
/// names first, and this refuses what would still step out of `dir`.
fn under(dir: &File, name: &OsStr) -> io::Result<PathBuf> {
    let name_ok = !name.is_empty()
        && name != "."
        && name != ".."
        && !name
            .encode_wide()
            .any(|unit| matches!(u8::try_from(unit), Ok(0 | b'\\' | b'/' | b':')));
    if !name_ok {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    Ok(dir_path(dir)?.join(name))
}

fn kind_of(md: &Metadata) -> FsKind {
    let file_type = md.file_type();
    if file_type.is_symlink() {
        FsKind::Symlink
    } else if file_type.is_dir() {
        FsKind::Directory
    } else if file_type.is_file() {
        FsKind::Regular
    } else {
        FsKind::Other
    }
}

/// The synthesized permission bits of an entry (ADR-0035 decision 26).
pub(crate) fn mode_of(md: &Metadata) -> u32 {
    if md.is_dir() {
        0o755
    } else if md.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
        0o444
    } else {
        0o644
    }
}

fn mtime_of(md: &Metadata) -> i64 {
    match md.modified() {
        Ok(time) => match time.duration_since(UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
            Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
        },
        Err(_) => 0,
    }
}

fn info_of(md: &Metadata) -> StatInfo {
    StatInfo {
        kind: kind_of(md),
        size: md.len(),
        mode: mode_of(md),
        mtime: mtime_of(md),
    }
}

/// What an open file is.
pub(crate) fn fstat(file: &File) -> io::Result<StatInfo> {
    Ok(info_of(&file.metadata()?))
}

/// What `name` is inside `dir`, without following a final symlink or
/// junction. `Ok(None)` when it does not exist.
pub(crate) fn stat_at(dir: &File, name: &OsStr) -> io::Result<Option<StatInfo>> {
    match std::fs::symlink_metadata(under(dir, name)?) {
        Ok(md) => Ok(Some(info_of(&md))),
        Err(e) if matches!(classify(&e), IoClass::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// A sub-directory of an open directory. A symlink or junction under that
/// name is refused, never followed.
pub(crate) fn open_dir_at(dir: &File, name: &OsStr) -> io::Result<File> {
    let sub = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(under(dir, name)?)?;
    let md = sub.metadata()?;
    if md.file_type().is_symlink() {
        return Err(refused_reparse_point());
    }
    if !md.is_dir() {
        return Err(not_a_directory());
    }
    Ok(sub)
}

/// Make a directory inside `dir`. The new directory takes the ACL its
/// parent hands down; Windows directories carry no mode, so `mode` and
/// `preserve` have nothing to set.
pub(crate) fn mkdir_at(
    dir: &File,
    name: &OsStr,
    _mode: u32,
    _preserve: bool,
) -> io::Result<MkdirOutcome> {
    match std::fs::create_dir(under(dir, name)?) {
        Ok(()) => Ok(MkdirOutcome::Created),
        Err(e) if matches!(classify(&e), IoClass::Exists) => Ok(match stat_at(dir, name)? {
            Some(StatInfo {
                kind: FsKind::Directory,
                ..
            }) => MkdirOutcome::Existed,
            _ => MkdirOutcome::ExistsNotDirectory,
        }),
        Err(e) => Err(e),
    }
}

/// `.<name>.qsh-<16 hex>.part`, the embedded name cut when the whole would
/// overrun [`NAME_MAX`] units.
fn temp_name(name: &OsStr) -> OsString {
    let mut random = [0u8; 8];
    rand::rng().fill_bytes(&mut random);
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let tail: Vec<u16> = format!(".qsh-{hex}.part").encode_utf16().collect();
    let room = NAME_MAX - 1 - tail.len();
    let units: Vec<u16> = name.encode_wide().collect();
    let mut cut = units.len().min(room);
    // Never end on the first half of a surrogate pair.
    if cut < units.len() && (0xD800..0xDC00).contains(&units[cut - 1]) {
        cut -= 1;
    }
    let mut out = Vec::with_capacity(1 + cut + tail.len());
    out.push(u16::from(b'.'));
    out.extend_from_slice(&units[..cut]);
    out.extend_from_slice(&tail);
    OsString::from_wide(&out)
}

/// Create the temporary file for a write to `name` inside `dir`, owner-only
/// from the moment it exists (ADR-0035 decision 9). `CREATE_NEW` makes an
/// existing entry of that name, a planted symlink included, a failure that
/// is retried under a new random name and never an open of someone else's
/// file.
///
/// A volume that stores no ACLs (FAT, exFAT) cannot hold a DACL: there the
/// temp file is created plain, because the finished file is as open as the
/// volume makes everything, and refusing the copy would protect nothing.
pub(crate) fn create_temp(dir: &File, name: &OsStr) -> io::Result<TempFile> {
    use crate::fsutil::{PrivateOpen, open_private_file};

    let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
    for _ in 0..4 {
        let temp = temp_name(name);
        let path = under(dir, &temp)?;
        let opened = match open_private_file(PrivateOpen::CreateNew, &path) {
            Err(e) if e.kind() == io::ErrorKind::Unsupported => std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path),
            other => other,
        };
        match opened {
            Ok(file) => return Ok(TempFile { file, name: temp }),
            Err(e) if matches!(classify(&e), IoClass::Exists) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Remove a (temporary) file by name. Never follows a symlink and never
/// removes a directory. A read-only file is made writable first, because a
/// temp file that was finished and then lost the race to be renamed carries
/// the attribute.
pub(crate) fn unlink_at(dir: &File, name: &OsStr) -> io::Result<()> {
    let path = under(dir, name)?;
    match std::fs::remove_file(&path) {
        Err(e) if matches!(classify(&e), IoClass::Denied) => {
            clear_read_only(&path)?;
            std::fs::remove_file(&path)
        }
        other => other,
    }
}

fn clear_read_only(path: &Path) -> io::Result<()> {
    let md = std::fs::symlink_metadata(path)?;
    let mut permissions = md.permissions();
    if !permissions.readonly() {
        return Err(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED));
    }
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions)
}

/// Apply the final attributes to the finished temp file through its own
/// handle (ADR-0035 decision 26): the read-only attribute only when the
/// owner write bit of `mode` is clear, no other bit, and with `preserve`
/// the modification time (`SetFileTime`, access time untouched).
pub(crate) fn apply_final_attrs(
    file: &File,
    mode: u32,
    preserve: bool,
    mtime: i64,
) -> io::Result<()> {
    if preserve {
        let time = if mtime >= 0 {
            UNIX_EPOCH + Duration::from_secs(mtime.unsigned_abs())
        } else {
            UNIX_EPOCH - Duration::from_secs(mtime.unsigned_abs())
        };
        file.set_times(std::fs::FileTimes::new().set_modified(time))?;
    }
    if mode & 0o200 == 0 {
        set_attributes(file, FILE_ATTRIBUTE_READONLY)?;
    }
    Ok(())
}

/// Set the attribute bits of an open file, leaving every time alone (a zero
/// time in `FILE_BASIC_INFO` means "unchanged"). The bits replace the
/// file's own, so callers pass the whole set they want.
fn set_attributes(file: &File, attributes: u32) -> io::Result<()> {
    let info = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: attributes,
    };
    // SAFETY: the handle is open with write-attributes access for the call
    // and `info` is a live `FILE_BASIC_INFO` of the size passed.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileBasicInfo,
            std::ptr::from_ref(&info).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Drop the owner-only protection of the finished temp file, so the rename
/// below puts in place a file that carries the ACL its destination
/// directory hands down.
fn inherit_destination_acl(path: &Path) -> io::Result<()> {
    crate::fsutil::dacl::inherit_parent_dacl(path)
}

/// Put the finished temp file in place, replacing whatever `name` was (a
/// symlink is replaced, not followed; a read-only file is replaced too, as
/// a unix rename ignores the mode of what it replaces).
pub(crate) fn replace_at(dir: &File, temp: &OsStr, name: &OsStr) -> io::Result<()> {
    let from = under(dir, temp)?;
    let to = under(dir, name)?;
    inherit_destination_acl(&from)?;
    match std::fs::rename(&from, &to) {
        Err(e) if matches!(classify(&e), IoClass::Denied) => {
            clear_read_only(&to)?;
            std::fs::rename(&from, &to)
        }
        other => other,
    }
}

/// Give the finished temp file its final name without replacing anything:
/// a rename that fails with `AlreadyExists` when the name is taken however
/// it came to be, which is what makes `--no-clobber` hold across the gap
/// between the existence check and the placement. The temp name is gone
/// afterwards, so this always reports `true`.
pub(crate) fn place_new(dir: &File, temp: &OsStr, name: &OsStr) -> io::Result<bool> {
    let from = under(dir, temp)?;
    let to = under(dir, name)?;
    inherit_destination_acl(&from)?;
    let from_wide = crate::fsutil::dacl::to_wide(&from)?;
    let to_wide = crate::fsutil::dacl::to_wide(&to)?;
    // SAFETY: both paths are NUL-terminated wide strings that live through
    // the call; flags 0 never replaces an existing name.
    let moved =
        unsafe { MoveFileExW(from_wide.as_ptr(), to_wide.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if moved == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

/// Windows has no directory `fsync`; the rename is written through by the
/// caller's flags where it matters.
pub(crate) fn sync_dir(_dir: &File) -> io::Result<()> {
    Ok(())
}

/// Open a source for reading. A source found while walking a tree
/// (`follow == false`) is opened as the reparse point itself, which
/// [`fstat`] then reports as a symlink; an operand the person typed is
/// followed.
pub(crate) fn open_source(path: &Path, follow: bool) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    // Backup semantics let a directory (or a directory link) be opened too,
    // as `O_RDONLY` does on unix, so the caller's `fstat` can tell what it is.
    options.read(true).custom_flags(if follow {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    });
    options.open(path)
}

/// Order names for the walk of a local tree. The wire carries UTF-8, so the
/// order is the byte order of the UTF-8 spelling, as the host orders its
/// listings.
pub(crate) fn sort_names(names: &mut [OsString]) {
    names.sort_by_cached_key(|name| name.to_string_lossy().into_owned().into_bytes());
}

/// Whether `name` may become a local file name on Windows
/// ([`super::windows_name_is_safe`]).
pub(crate) fn name_is_local_safe(name: &str) -> bool {
    super::windows_name_is_safe(name)
}

/// Whether `spelling` names a directory by its last character: either
/// separator does on Windows.
pub(crate) fn ends_with_separator(spelling: &str) -> bool {
    spelling.ends_with(['/', '\\'])
}

#[cfg(test)]
mod tests;
