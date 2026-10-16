//! The local filesystem steps of a `qsh cp` client (`docs/adr/0029-file-copy.md`
//! decision 7, `docs/adr/0035-windows-client.md` decision 26), behind one
//! interface for both clients.
//!
//! A get writes its destination through an open directory and one component
//! name: a temp file next to the destination, the final attributes, then a
//! rename (or a no-replace link) into place. A put reads sources and lists
//! directories. The unix steps are the `*at` calls of [`super::host`], which
//! the host side uses too, and are re-exported unchanged. The Windows steps
//! are in `windows.rs`: they hold a directory handle, work by path under it
//! and refuse reparse points, which is the Windows reading of `O_NOFOLLOW`.
//!
//! Nothing here names a transport or a session; the transfer code and the
//! copy driver call these from blocking threads.

pub(crate) use super::stat::{FsKind, MkdirOutcome, StatInfo};

#[cfg(unix)]
mod imp {
    use std::ffi::OsString;
    use std::fs::{File, Metadata};
    use std::io;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    pub(crate) use crate::file::host::{
        apply_final_attrs, create_temp, fstat, mkdir_at, open_dir_at, replace_at, stat_at,
        unlink_at,
    };

    use super::IoClass;

    /// The destination directory the person typed: a symlink in the final
    /// component is followed.
    pub(crate) fn open_dir(path: &Path) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
    }

    /// Open a source for reading. `follow` is true for an operand the
    /// person typed (a symlink there is followed, as `scp` does) and false
    /// for a file found while walking a tree.
    pub(crate) fn open_source(path: &Path, follow: bool) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(if follow {
            libc::O_CLOEXEC
        } else {
            libc::O_CLOEXEC | libc::O_NOFOLLOW
        });
        options.open(path)
    }

    /// Give the finished temp file its final name without replacing
    /// anything (`linkat`, then the temp name is removed). `AlreadyExists`
    /// when the name is taken. Returns whether the temp name is gone.
    pub(crate) fn place_new(
        dir: &File,
        temp: &std::ffi::OsStr,
        name: &std::ffi::OsStr,
    ) -> io::Result<bool> {
        crate::file::host::link_new_at(dir, temp, name)?;
        Ok(unlink_at(dir, temp).is_ok())
    }

    /// Make the directory entry durable.
    pub(crate) fn sync_dir(dir: &File) -> io::Result<()> {
        dir.sync_all()
    }

    /// The permission bits of a directory entry.
    pub(crate) fn mode_of(md: &Metadata) -> u32 {
        md.mode() & 0o777
    }

    /// Order names the way the host orders a listing: by byte.
    pub(crate) fn sort_names(names: &mut [OsString]) {
        names.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    }

    /// Whether `name` may become a local file name on top of the checks
    /// every platform makes. Unix accepts any name without `/` and NUL.
    pub(crate) fn name_is_local_safe(_name: &str) -> bool {
        true
    }

    /// Whether `spelling` (a destination as typed) names a directory by its
    /// last character.
    pub(crate) fn ends_with_separator(spelling: &str) -> bool {
        spelling.ends_with('/')
    }

    /// What a failed local I/O call was.
    pub(crate) fn classify(err: &io::Error) -> IoClass {
        match err.raw_os_error() {
            Some(libc::EEXIST) => IoClass::Exists,
            Some(libc::ENOENT) => IoClass::NotFound,
            Some(libc::EACCES | libc::EPERM | libc::EROFS) => IoClass::Denied,
            Some(libc::ENOTDIR) => IoClass::NotDirectory,
            Some(libc::EISDIR) => IoClass::IsDirectory,
            Some(libc::ELOOP) => IoClass::SymlinkRefused,
            Some(libc::ENOSPC | libc::EDQUOT) => IoClass::NoSpace,
            Some(libc::EMFILE | libc::ENFILE) => IoClass::TooManyOpen,
            _ => IoClass::Other,
        }
    }
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

pub(crate) use imp::*;

/// The kinds of local failure a copy tells apart. The mapping from an OS
/// error is per platform ([`classify`]); the words and codes the person sees
/// for each are the same everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IoClass {
    /// The name is taken.
    Exists,
    /// The path does not exist.
    NotFound,
    /// Not allowed (permissions, a read-only volume).
    Denied,
    /// A path component is not a directory.
    NotDirectory,
    /// A directory where a file was expected. Only unix reports this apart
    /// from a denial.
    #[cfg_attr(windows, allow(dead_code))]
    IsDirectory,
    /// A symbolic link or junction where none is allowed.
    SymlinkRefused,
    /// The disk or the quota is full.
    NoSpace,
    /// Out of file handles.
    TooManyOpen,
    /// Anything else; the OS text is shown.
    Other,
}

/// Whether `name` may be a Windows file name: one component, none of the
/// characters Windows reserves (which also closes the NTFS alternate-stream
/// spelling `name:stream`), no control characters, no trailing dot or
/// space (Win32 strips those, so the file would not be the one named), and
/// not a device name (`CON`, `NUL`, `COM1`, ...), with or without an
/// extension.
///
/// Pure, so the rule is tested on every platform. A host's entry name goes
/// through this on the Windows client before a local path is made from it
/// (decision 22); the unix client does not apply it.
#[cfg(any(windows, test))]
pub(crate) fn windows_name_is_safe(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '\\' | '/' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
    }) {
        return false;
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    let reserved = matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        upper.strip_prefix(prefix).is_some_and(|rest| {
            let mut chars = rest.chars();
            matches!(
                (chars.next(), chars.next()),
                (Some('1'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        })
    });
    !reserved
}

#[cfg(test)]
mod tests;
