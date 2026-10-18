//! The Windows reading of a remote file path as pure string functions
//! (`docs/adr/0035-windows-client.md` decision 26, `docs/adr/0029-file-copy.md`
//! decisions 6 and 23).
//!
//! Nothing here touches the filesystem or the operating system, so the rules
//! run on every build and a test on Linux pins what the Windows host does:
//!
//! - **Shape** ([`shape`]): `/` and `\` are the same separator; a path is a
//!   drive-absolute path (`C:\...`), `~` / `~\...`, or relative to the
//!   account's profile directory. UNC (`\\server\share`) and the device
//!   namespaces (`\\?\`, `\\.\`) would make the host reach a network share or
//!   a device on the peer's behalf, so they are refused before any
//!   authorization decision, like a path with no drive (`\x`, `/x`) or with a
//!   drive-relative drive (`C:x`). A `:` anywhere but the drive position names
//!   an NTFS alternate data stream, and a component Windows cannot store as
//!   written (a reserved device name such as `CON` or `NUL.txt`, a trailing dot
//!   or space that Win32 would strip, a reserved character) is refused for
//!   the same reason: the name the host checked would not be the name Win32
//!   opens.
//! - **Normalization** ([`normalize_with`]): `.` and `..` fold lexically (that
//!   is what Win32 does with the string before the kernel sees it), then the
//!   longest existing prefix is resolved by an injected function (the final
//!   path of an opened handle), and the components after it are appended.
//! - **Spelling** ([`strip_verbatim_prefix`], [`split_drive_path`]): the final
//!   path the system reports carries a `\\?\` prefix that is taken off, and
//!   only a drive path is an acceptable canonical result.

use std::io;
use std::path::PathBuf;

use super::{FileOp, NAME_MAX_BYTES, NormalizeError, PATH_MAX_BYTES, ShapeError, ShapedPath};
use crate::file::local::windows_name_is_safe;

/// A path split into its drive letter and the components after the root.
/// The letter is kept as written; comparisons fold case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DrivePath {
    /// The drive letter.
    pub(crate) drive: char,
    /// The components below the drive root, none empty.
    pub(crate) parts: Vec<String>,
}

impl DrivePath {
    /// The path as `C:\a\b` (`C:\` for the root).
    pub(crate) fn render(&self) -> String {
        if self.parts.is_empty() {
            format!("{}:\\", self.drive)
        } else {
            format!("{}:\\{}", self.drive, self.parts.join("\\"))
        }
    }
}

/// Split an absolute drive path (`C:\...` or `C:/...`; both separators
/// count) into its drive and components. `None` when `text` is anything
/// else: relative, rooted without a drive, drive-relative (`C:x`), UNC or a
/// device namespace.
pub(crate) fn split_drive_path(text: &str) -> Option<DrivePath> {
    let bytes = text.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
    {
        return None;
    }
    let parts = text[3..]
        .split(['\\', '/'])
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    Some(DrivePath {
        drive: char::from(bytes[0]),
        parts,
    })
}

/// Take the `\\?\` prefix off a final path: `\\?\C:\x` is `C:\x` and
/// `\\?\UNC\server\share\x` is `\\server\share\x`. A path without the prefix
/// is returned as it is. The result of a `\\?\Volume{...}\` path (a volume
/// with no drive letter) keeps its shape, and [`split_drive_path`] does not
/// accept it.
#[cfg_attr(
    not(any(windows, test)),
    expect(dead_code, reason = "only the Windows normalizer calls it")
)]
pub(crate) fn strip_verbatim_prefix(text: &str) -> String {
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) => rest.to_string(),
        None => text.to_string(),
    }
}

/// The profile directory as a drive path, when it is one.
fn usable_profile(profile: Option<&str>) -> Result<DrivePath, ShapeError> {
    profile.and_then(split_drive_path).ok_or(ShapeError::NoHome)
}

/// The shape check and home resolution for a Windows host (ADR-0029 decision
/// 6-1 with ADR-0035 decision 26). `text` is valid UTF-8 without NUL and not
/// longer than [`PATH_MAX_BYTES`] (the caller checked); `profile` is the serve
/// account's profile directory.
///
/// The result's `absolute` is spelled with `\` and has no empty component.
/// `.` and `..` stay, as on unix: normalization decides what they reach.
pub(super) fn shape(
    text: &str,
    op: FileOp,
    profile: Option<&str>,
) -> Result<ShapedPath, ShapeError> {
    let unified = text.replace('/', "\\");
    let must_be_dir = unified.ends_with('\\');

    if unified.starts_with("\\\\") {
        return Err(ShapeError::UncOrDevice);
    }

    let (base, rest): (DrivePath, &str) = if unified == "~" || unified.starts_with("~\\") {
        (usable_profile(profile)?, unified.get(2..).unwrap_or(""))
    } else if unified.starts_with('~') {
        return Err(ShapeError::TildeUser);
    } else if unified.starts_with('\\') {
        return Err(ShapeError::NoDrive);
    } else if let Some(drive_len) = drive_prefix_len(&unified) {
        let letter = char::from(unified.as_bytes()[0]);
        match unified.as_bytes().get(drive_len) {
            Some(b'\\') => (
                DrivePath {
                    drive: letter,
                    parts: Vec::new(),
                },
                &unified[drive_len + 1..],
            ),
            // `C:` and `C:x` are relative to the current directory of a
            // drive, which a host has no business keeping.
            _ => return Err(ShapeError::NoDrive),
        }
    } else {
        (usable_profile(profile)?, unified.as_str())
    };

    // A `:` below the drive position is an alternate data stream.
    if rest.contains(':') {
        return Err(ShapeError::AlternateStream);
    }
    let mut parts = base.parts;
    for part in rest.split('\\').filter(|part| !part.is_empty()) {
        if part != "." && part != ".." && !windows_name_is_safe(part) {
            return Err(ShapeError::BadComponent);
        }
        parts.push(part.to_string());
    }
    if op.creates() && matches!(parts.last().map(String::as_str), Some("." | "..")) {
        return Err(ShapeError::DotLastComponent);
    }
    let absolute = DrivePath {
        drive: base.drive,
        parts,
    }
    .render();
    if absolute.len() > PATH_MAX_BYTES {
        return Err(ShapeError::TooLong);
    }
    Ok(ShapedPath {
        absolute: PathBuf::from(absolute),
        must_be_dir,
    })
}

/// 2 when `text` starts with a drive designator (`X:`), else `None`.
fn drive_prefix_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':').then_some(2)
}

/// The `name_if_dir` check for a Windows host: one plain component that
/// Windows can store as written.
pub(super) fn shape_name_if_dir(name: &[u8]) -> Result<(), ShapeError> {
    let valid = std::str::from_utf8(name).is_ok_and(|name| {
        name.len() <= NAME_MAX_BYTES && !name.contains('\0') && windows_name_is_safe(name)
    });
    if valid {
        Ok(())
    } else {
        Err(ShapeError::BadName)
    }
}

/// What resolving one prefix of a path found: its final path (without the
/// `\\?\` prefix) and whether it is a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(any(windows, test)),
    expect(dead_code, reason = "only the Windows normalizer calls it")
)]
pub(crate) struct Resolved {
    /// The final path the system reports.
    pub(crate) path: String,
    /// Whether the object is a directory.
    pub(crate) is_dir: bool,
}

/// The normalization algorithm for a Windows host (ADR-0029 decision 6-2 with
/// ADR-0035 decision 26), with the resolution of one existing prefix injected.
///
/// `.` and `..` of the input fold first, lexically, and a `..` at the root
/// stays at the root: Win32 does the same to the string before it reaches the
/// kernel, so the path this function returns is the path an open would use.
/// The longest prefix that exists is then resolved by `resolve` (symlinks and
/// junctions followed to the end); only "does not exist" lets the search
/// shorten the prefix, and any other failure refuses. The components after the
/// prefix are appended as they are. A prefix that exists but is not a
/// directory, with components still to append, is a refusal, like a file used
/// as a directory on unix.
///
/// The result must be a drive path: a link that leads out to a UNC share or a
/// volume with no letter is a refusal, not a path to hand on.
#[cfg_attr(
    not(any(windows, test)),
    expect(dead_code, reason = "only the Windows normalizer calls it")
)]
pub(crate) fn normalize_with(
    path: &str,
    resolve: &dyn Fn(&str) -> io::Result<Resolved>,
) -> Result<String, NormalizeError> {
    let Some(drive) = split_drive_path(path) else {
        return Err(NormalizeError::NotAbsolute);
    };
    if path.len() > PATH_MAX_BYTES {
        return Err(NormalizeError::TooLong);
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in &drive.parts {
        match part.as_str() {
            "." => {}
            ".." => {
                parts.pop();
            }
            name => parts.push(name),
        }
    }
    let root = format!("{}:\\", drive.drive);
    for keep in (0..=parts.len()).rev() {
        let prefix = if keep == 0 {
            root.clone()
        } else {
            format!("{root}{}", parts[..keep].join("\\"))
        };
        match resolve(&prefix) {
            Ok(base) => {
                let rest = &parts[keep..];
                if !rest.is_empty() && !base.is_dir {
                    return Err(NormalizeError::Io(io::ErrorKind::NotADirectory));
                }
                let Some(base) = split_drive_path(&base.path) else {
                    // A UNC share, a device or a volume with no drive letter.
                    return Err(NormalizeError::Io(io::ErrorKind::InvalidInput));
                };
                let mut out = base;
                out.parts.extend(rest.iter().map(|part| part.to_string()));
                return Ok(out.render());
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && keep > 0 => continue,
            Err(e) => return Err(NormalizeError::Io(e.kind())),
        }
    }
    unreachable!("the loop returns at keep == 0")
}

#[cfg(test)]
mod tests;
