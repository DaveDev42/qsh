//! The `paths` key of an `[[acl]]` row (ADR-0029 결정 4): the lexical grammar
//! the loader enforces and the component-wise match the evaluator runs
//! (evaluation step ③-1).
//!
//! The grammar is lexical only. An entry is validated by looking at its
//! bytes, never at the filesystem, so a missing directory is not a load
//! error. Matching is the opposite: it normalizes the entry with the same
//! [`Normalizer`] that produced the request's canonical path, per request,
//! and an entry that cannot be normalized covers nothing.

use std::path::Path;

use crate::file::guard::{PATH_MAX_BYTES, path_within};

use super::CanonicalPath;

/// The path notation an `acl.toml` of this host uses (ADR-0029 결정 23).
/// POSIX hosts write `/`-rooted entries. A Windows host writes drive
/// entries with `/` separators only (`C:/Users/dave/share`) and has no `"/"`
/// entry. Taking the style as a value keeps both grammars testable on any
/// build; the loader passes [`PathStyle::HOST`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PathStyle {
    Posix,
    Windows,
}

impl PathStyle {
    /// The style of the host this binary runs on.
    pub(super) const HOST: PathStyle = if cfg!(windows) {
        PathStyle::Windows
    } else {
        PathStyle::Posix
    };
}

/// Why a `paths` entry is rejected. Each variant is a fixed reason: the
/// loader's error message names the row and the entry index but never the
/// entry's text (the `CONFIG_ERROR` carries no operator-written content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EntryError {
    NotAbsolute,
    Backslash,
    Nul,
    TooLong,
    EmptyComponent,
    DotComponent,
    TrailingSlash,
}

impl EntryError {
    pub(super) fn reason(self) -> &'static str {
        match self {
            EntryError::NotAbsolute => "is not an absolute path",
            EntryError::Backslash => "contains a backslash; use `/` separators",
            EntryError::Nul => "contains a NUL byte",
            EntryError::TooLong => "is longer than 4096 bytes",
            EntryError::EmptyComponent => "has an empty path component",
            EntryError::DotComponent => "has a `.` or `..` component",
            EntryError::TrailingSlash => "ends in `/`",
        }
    }
}

/// Validate one `paths` entry's shape (ADR-0029 결정 4-3): absolute, no NUL,
/// at most 4096 bytes, no `.`, `..` or empty component, and no trailing `/`
/// except the root itself (`"/"`, or a drive root `C:/` on Windows). One
/// spelling per path keeps `acl show`'s echo equal to the string matching
/// uses.
pub(super) fn validate_entry(entry: &str, style: PathStyle) -> Result<(), EntryError> {
    if entry.len() > PATH_MAX_BYTES {
        return Err(EntryError::TooLong);
    }
    if entry.contains('\0') {
        return Err(EntryError::Nul);
    }
    let rest = match style {
        PathStyle::Posix => entry.strip_prefix('/').ok_or(EntryError::NotAbsolute)?,
        PathStyle::Windows => {
            if entry.contains('\\') {
                return Err(EntryError::Backslash);
            }
            let bytes = entry.as_bytes();
            if !(bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'/')
            {
                return Err(EntryError::NotAbsolute);
            }
            &entry[3..]
        }
    };
    // The bare root (`/`, `C:/`) is the one entry that may end in `/`.
    if rest.is_empty() {
        return Ok(());
    }
    if rest.ends_with('/') {
        return Err(EntryError::TrailingSlash);
    }
    for component in rest.split('/') {
        match component {
            "" => return Err(EntryError::EmptyComponent),
            "." | ".." => return Err(EntryError::DotComponent),
            _ => {}
        }
    }
    Ok(())
}

/// Evaluation step ③-1: whether one of `entries` covers the request's
/// canonical path, component by component (`/srv/share` covers
/// `/srv/share/a.txt` but not `/srv/shared/a.txt`).
///
/// Each entry goes through the request's own normalizer, per request, so the
/// entry and the request are compared in the same canonical form; an entry
/// that cannot be normalized (missing, `EACCES`, a loop, no normalizer on
/// this platform) covers nothing. Matching folds case only on Windows. On
/// macOS both sides carry the on-disk spelling, so the comparison stays
/// exact there, unlike the protected-set check (ADR-0029 결정 23).
pub(super) fn entries_cover(entries: &[String], request: &CanonicalPath<'_>) -> bool {
    let fold = cfg!(windows);
    entries.iter().any(|entry| {
        request
            .normalizer
            .normalize(Path::new(entry))
            .is_ok_and(|root| path_within(request.path, &root, fold))
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::file::guard::{NormalizeError, Normalizer};

    struct Identity;

    impl Normalizer for Identity {
        fn normalize(&self, absolute: &Path) -> Result<PathBuf, NormalizeError> {
            Ok(absolute.to_path_buf())
        }
    }

    #[test]
    fn posix_entries_accept_the_documented_shapes() {
        for ok in ["/", "/srv", "/srv/share", "/a/b.c/d e", "/~"] {
            assert_eq!(validate_entry(ok, PathStyle::Posix), Ok(()), "{ok}");
        }
    }

    #[test]
    fn posix_entries_reject_every_documented_violation() {
        let long = format!("/{}", "a".repeat(PATH_MAX_BYTES));
        for (entry, why) in [
            ("", EntryError::NotAbsolute),
            ("srv", EntryError::NotAbsolute),
            ("~/share", EntryError::NotAbsolute),
            ("C:/srv", EntryError::NotAbsolute),
            ("/srv/", EntryError::TrailingSlash),
            ("//srv", EntryError::EmptyComponent),
            ("/srv//share", EntryError::EmptyComponent),
            ("/srv/./share", EntryError::DotComponent),
            ("/srv/../etc", EntryError::DotComponent),
            ("/..", EntryError::DotComponent),
            ("/srv/\0", EntryError::Nul),
            (long.as_str(), EntryError::TooLong),
        ] {
            assert_eq!(
                validate_entry(entry, PathStyle::Posix),
                Err(why),
                "{entry:?}"
            );
        }
    }

    #[test]
    fn windows_entries_use_drive_notation_with_forward_slashes() {
        for ok in ["C:/", "c:/Users", "D:/Users/dave/share"] {
            assert_eq!(validate_entry(ok, PathStyle::Windows), Ok(()), "{ok}");
        }
        for (entry, why) in [
            ("/", EntryError::NotAbsolute),
            ("/srv", EntryError::NotAbsolute),
            ("C:", EntryError::NotAbsolute),
            ("C:Users", EntryError::NotAbsolute),
            ("1:/x", EntryError::NotAbsolute),
            ("C:\\Users", EntryError::Backslash),
            ("C:/Users\\dave", EntryError::Backslash),
            ("C:/Users/", EntryError::TrailingSlash),
            ("C://Users", EntryError::EmptyComponent),
            ("C:/Users/../x", EntryError::DotComponent),
        ] {
            assert_eq!(
                validate_entry(entry, PathStyle::Windows),
                Err(why),
                "{entry:?}"
            );
        }
    }

    #[test]
    fn coverage_is_component_wise() {
        let entries = vec!["/srv/share".to_string()];
        let cover = |request: &str| {
            let path = PathBuf::from(request);
            entries_cover(
                &entries,
                &CanonicalPath {
                    path: &path,
                    normalizer: &Identity,
                },
            )
        };
        assert!(cover("/srv/share"));
        assert!(cover("/srv/share/x"));
        assert!(!cover("/srv/shared"));
        assert!(!cover("/srv"));
    }

    #[cfg(windows)]
    #[test]
    fn coverage_folds_case_on_windows() {
        let entries = vec!["C:/Users/Dave".to_string()];
        let path = PathBuf::from("c:/users/dave/a.txt");
        assert!(entries_cover(
            &entries,
            &CanonicalPath {
                path: &path,
                normalizer: &Identity,
            }
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn coverage_is_case_sensitive_off_windows() {
        let entries = vec!["/Srv".to_string()];
        let path = PathBuf::from("/srv/a.txt");
        assert!(!entries_cover(
            &entries,
            &CanonicalPath {
                path: &path,
                normalizer: &Identity,
            }
        ));
    }
}
