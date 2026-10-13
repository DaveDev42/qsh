//! The path judgement every remote file op shares (`docs/adr/0029-file-copy.md`
//! decisions 5, 6 and 23).
//!
//! A pure, blocking module: it never calls the authorizer, never touches the
//! audit log and names no transport or session type (`cargo xtask arch` bans
//! those tokens in this file). The op dispatch composes it later, in the
//! order decision 8 fixes: shape check, ACL, user hint, state-path check,
//! quota, open and recheck.
//!
//! - **Shape and home** ([`shape_path`], [`shape_name_if_dir`],
//!   [`serve_home_dir`], decision 6-1): lexical only, no filesystem access.
//!   Home comes from the serve account's passwd entry, never from `$HOME`.
//! - **Normalization** ([`Normalizer`], [`normalize_with`], decision 6-2): the
//!   longest existing ancestor is resolved with `realpath`, the rest folds
//!   lexically. The normalizer is a trait so a test can count calls.
//! - **Protected set** ([`ProtectedSet`], decisions 5 and 6-3): config, state
//!   and runtime directories (both the paths this process really uses and the
//!   `$HOME` defaults), the audit file outside them, the file-mode key. It is
//!   resolved per request and compares case-insensitively where the volume
//!   does (macOS; Windows is M20).
//! - **Open-handle recheck** ([`recheck_handle`], decision 6-4): the path an
//!   opened fd really points at, from `/proc/self/fd/<n>` (Linux) or
//!   `fcntl(F_GETPATH)` (macOS). Re-calling the evaluator is injected as a
//!   closure; the dispatch wires it later.
//! - **Inode set and file kind** ([`ProtectedInodes`], [`check_read_target`],
//!   decisions 6-5 and 6-6): a hard link outside the protected tree is still
//!   the same `(dev, ino)`, and `file.read` reads regular files only.
//!
//! Off unix the whole module is a stub that refuses every path; the Windows
//! implementation is M20 (ADR-0029 decision 23, ADR-0035 decision 26).
//!
//! **Deliberate gaps.** A dangling symlink is not followed during
//! normalization: every later open uses `O_NOFOLLOW` or the parent directory
//! fd, so the link itself is what a write replaces. A `/proc` that is not
//! mounted makes [`handle_path`] fail, and a failed recheck is a refusal
//! ([`HandleDenied::Unresolvable`]), so every file op is refused there
//! ([`HANDLE_RECHECK_UNAVAILABLE`]).

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::{AuditConfig, Paths};
use crate::identity::KEY_FILE;

#[cfg(test)]
mod tests;

/// Longest path, in bytes, the shape check and normalization accept
/// (ADR-0029 decision 6-1).
pub const PATH_MAX_BYTES: usize = 4096;
/// Longest `name_if_dir`, in bytes (ADR-0029 decision 6-1).
pub const NAME_MAX_BYTES: usize = 255;
/// Most entries [`ProtectedInodes::collect`] visits below the protected
/// directories before it gives up and the caller refuses (fail closed).
pub const INODE_SCAN_MAX_ENTRIES: usize = 4096;
/// Deepest nesting [`ProtectedInodes::collect`] descends to.
pub const INODE_SCAN_MAX_DEPTH: usize = 4;
/// Most rotated audit files `.1`..`.<retain>` whose inode is collected.
pub const INODE_SCAN_MAX_ROTATED: u32 = 1024;
/// The operator-facing note for a host that cannot resolve an open fd to a
/// path (Linux without `/proc`): the recheck fails closed, so every file op
/// is refused there.
pub const HANDLE_RECHECK_UNAVAILABLE: &str = "open-handle path resolution is unavailable (is /proc mounted?); \
     remote file operations are refused on this host";

/// Which remote file op a path is for (ADR-0029 decision 3). `file.list`
/// and `file.mkdir` authorize as `file.read` and `file.write`; the shape
/// check only cares whether the op creates something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    /// `file.read`.
    Read,
    /// `file.list`.
    List,
    /// `file.write`.
    Write,
    /// `file.mkdir`.
    Mkdir,
}

impl FileOp {
    /// Whether the op creates or replaces something (`file.write`,
    /// `file.mkdir`).
    pub fn creates(self) -> bool {
        matches!(self, Self::Write | Self::Mkdir)
    }
}

/// A shape violation (ADR-0029 decision 6-1). The caller reports every one
/// as `INVALID_ARGUMENT` before any ACL decision, audit line or filesystem
/// access. The variants carry no path text, so the message cannot echo the
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ShapeError {
    /// The path (or name) is empty.
    #[error("path must not be empty")]
    Empty,
    /// The path is not valid UTF-8.
    #[error("path must be valid UTF-8")]
    NotUtf8,
    /// The path holds a NUL byte.
    #[error("path must not contain a NUL byte")]
    Nul,
    /// The path is longer than [`PATH_MAX_BYTES`].
    #[error("path is longer than 4096 bytes")]
    TooLong,
    /// `~name`: another account's home is not supported.
    #[error("`~user` paths are not supported; only `~` and `~/...`")]
    TildeUser,
    /// A relative or `~` path needs the serve account's home and none is
    /// known (no passwd entry).
    #[error("the serve account has no home directory")]
    NoHome,
    /// A creating op whose last component is `.` or `..`.
    #[error("the last path component must not be `.` or `..`")]
    DotLastComponent,
    /// A `name_if_dir` that is not one plain component.
    #[error("name must be one plain path component of at most 255 bytes")]
    BadName,
    /// This platform has no path judgement yet (Windows is M20).
    #[error("remote file paths are not supported on this platform")]
    Unsupported,
}

/// A request path after the shape check: absolute, lexical (not
/// normalized), plus the trailing-slash assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapedPath {
    /// The absolute path. `..` and symlinks are untouched; normalization
    /// decides about them.
    pub absolute: PathBuf,
    /// The request ended in `/`: "this must be a directory" (ADR-0029
    /// decision 2). The op fails with `INVALID_ARGUMENT` if it is not.
    pub must_be_dir: bool,
}

/// The shape check and home resolution of ADR-0029 decision 6-1.
///
/// `raw` is the request path. `home` is the serve account's home
/// ([`serve_home_dir`]); it is only needed for `~`, `~/...` and relative
/// forms. Accepted forms are absolute, `~`, `~/...` and home-relative;
/// `~name` is refused. A `..` component is not a shape violation here
/// (normalization decides whether it escapes), except as the last component
/// of a creating op.
pub fn shape_path(raw: &[u8], op: FileOp, home: Option<&Path>) -> Result<ShapedPath, ShapeError> {
    if !cfg!(unix) {
        return Err(ShapeError::Unsupported);
    }
    if raw.is_empty() {
        return Err(ShapeError::Empty);
    }
    if raw.len() > PATH_MAX_BYTES {
        return Err(ShapeError::TooLong);
    }
    if raw.contains(&0) {
        return Err(ShapeError::Nul);
    }
    let text = std::str::from_utf8(raw).map_err(|_| ShapeError::NotUtf8)?;

    if op.creates() {
        let last = text.split('/').rfind(|segment| !segment.is_empty());
        if matches!(last, Some("." | "..")) {
            return Err(ShapeError::DotLastComponent);
        }
    }

    let usable_home = || home.filter(|h| h.is_absolute()).ok_or(ShapeError::NoHome);
    let absolute = if text.starts_with('/') {
        PathBuf::from(text)
    } else if text == "~" {
        usable_home()?.to_path_buf()
    } else if let Some(rest) = text.strip_prefix("~/") {
        join_relative(usable_home()?, rest)
    } else if text.starts_with('~') {
        return Err(ShapeError::TildeUser);
    } else {
        join_relative(usable_home()?, text)
    };
    if absolute.as_os_str().len() > PATH_MAX_BYTES {
        return Err(ShapeError::TooLong);
    }
    Ok(ShapedPath {
        absolute,
        must_be_dir: text.ends_with('/'),
    })
}

fn join_relative(home: &Path, rest: &str) -> PathBuf {
    if rest.is_empty() {
        home.to_path_buf()
    } else {
        home.join(rest)
    }
}

/// The `name_if_dir` check of ADR-0029 decision 6-1: one plain component.
pub fn shape_name_if_dir(name: &[u8]) -> Result<(), ShapeError> {
    if !cfg!(unix) {
        return Err(ShapeError::Unsupported);
    }
    let valid = !name.is_empty()
        && name.len() <= NAME_MAX_BYTES
        && std::str::from_utf8(name).is_ok()
        && !name.contains(&b'/')
        && !name.contains(&0)
        && name != b"."
        && name != b"..";
    if valid {
        Ok(())
    } else {
        Err(ShapeError::BadName)
    }
}

/// The serve account's home directory, from its passwd entry. `$HOME` is
/// never consulted (ADR-0029 decision 2): the environment is the caller's,
/// the passwd entry is the host's. Cached for the process lifetime. `None`
/// when there is no usable passwd entry (and always off unix).
pub fn serve_home_dir() -> Option<PathBuf> {
    static HOME: OnceLock<Option<PathBuf>> = OnceLock::new();
    HOME.get_or_init(passwd_home).clone()
}

#[cfg(unix)]
fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    // getpwuid_r needs a caller buffer for the strings; grow on ERANGE.
    let mut buf: Vec<libc::c_char> = vec![0; 1024];
    loop {
        // SAFETY: passwd is a plain C struct; all-zero is a valid initial
        // value that getpwuid_r overwrites.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call: `pwd` and `result` are
        // live locals, `buf` is a live allocation of `buf.len()` bytes, and
        // getpwuid_r is the reentrant (thread-safe) variant.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success `pw_dir` points at a NUL-terminated string
        // inside `buf`, which is still alive here.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        let home = PathBuf::from(OsStr::from_bytes(dir.to_bytes()));
        return home.is_absolute().then_some(home);
    }
}

#[cfg(not(unix))]
fn passwd_home() -> Option<PathBuf> {
    None
}

/// Why a path could not be normalized. Every variant is a refusal: a path
/// that cannot be resolved is never allowed through (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NormalizeError {
    /// The input is not absolute (run [`shape_path`] first).
    #[error("path is not absolute")]
    NotAbsolute,
    /// The input is longer than [`PATH_MAX_BYTES`].
    #[error("path is longer than 4096 bytes")]
    TooLong,
    /// A component could not be resolved for a reason other than "does not
    /// exist" (permission, symlink loop, a file used as a directory).
    #[error("path cannot be resolved ({0:?})")]
    Io(io::ErrorKind),
    /// No normalization on this platform yet (Windows is M20).
    #[error("path normalization is not supported on this platform")]
    Unsupported,
}

/// Turns a shaped absolute path into the canonical path the ACL `paths`
/// match and the protected-set comparison both use (ADR-0029 decision 6-2).
/// A trait so the dispatch can inject a normalizer and a test can count
/// calls ([`CountingNormalizer`]).
pub trait Normalizer: Send + Sync {
    /// The canonical path of `absolute`.
    fn normalize(&self, absolute: &Path) -> Result<PathBuf, NormalizeError>;
}

/// The real filesystem normalizer.
#[derive(Debug, Clone, Copy, Default)]
pub struct FsNormalizer;

impl Normalizer for FsNormalizer {
    fn normalize(&self, absolute: &Path) -> Result<PathBuf, NormalizeError> {
        if !cfg!(unix) {
            return Err(NormalizeError::Unsupported);
        }
        normalize_with(absolute, &|p| fs::canonicalize(p))
    }
}

/// Wraps a [`Normalizer`] and counts its calls. The pin
/// `file_request_without_a_file_grant_touches_no_filesystem` asserts the
/// count stays zero for a principal with no file grant.
#[derive(Debug, Default)]
pub struct CountingNormalizer<N = FsNormalizer> {
    inner: N,
    calls: AtomicUsize,
}

impl<N: Normalizer> CountingNormalizer<N> {
    /// Wrap `inner` with a zero count.
    pub fn new(inner: N) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }

    /// How many times [`Normalizer::normalize`] has been called.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl<N: Normalizer> Normalizer for CountingNormalizer<N> {
    fn normalize(&self, absolute: &Path) -> Result<PathBuf, NormalizeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.normalize(absolute)
    }
}

/// The normalization algorithm of ADR-0029 decision 6-2, with `realpath`
/// injected.
///
/// The longest prefix of the input that exists is resolved by `realpath`
/// (symlinks followed to the end, `..` interpreted by the kernel on the
/// way); the components after it fold lexically, a `..` removing the
/// component before it. Only "does not exist" lets the search shorten the
/// prefix; any other failure refuses. So `/srv/share/missing/../../x` and
/// `/a/link/../b` (where `link` is a symlink) come out the way the kernel
/// would resolve them, not the way a purely lexical fold would.
pub fn normalize_with(
    path: &Path,
    realpath: &dyn Fn(&Path) -> io::Result<PathBuf>,
) -> Result<PathBuf, NormalizeError> {
    if !path.is_absolute() {
        return Err(NormalizeError::NotAbsolute);
    }
    if path.as_os_str().len() > PATH_MAX_BYTES {
        return Err(NormalizeError::TooLong);
    }
    let parts: Vec<Component<'_>> = path
        .components()
        .filter(|c| matches!(c, Component::Normal(_) | Component::ParentDir))
        .collect();
    for keep in (0..=parts.len()).rev() {
        let mut prefix = PathBuf::from("/");
        prefix.extend(parts[..keep].iter().map(|c| c.as_os_str()));
        match realpath(&prefix) {
            Ok(base) => return Ok(fold_rest(base, &parts[keep..])),
            Err(e) if e.kind() == io::ErrorKind::NotFound && keep > 0 => continue,
            Err(e) => return Err(NormalizeError::Io(e.kind())),
        }
    }
    unreachable!("the loop returns at keep == 0")
}

/// Fold the components after the existing prefix lexically onto it.
fn fold_rest(mut base: PathBuf, rest: &[Component<'_>]) -> PathBuf {
    let mut pending: Vec<&OsStr> = Vec::new();
    for part in rest {
        match part {
            Component::Normal(name) => pending.push(name),
            // A `..` after missing components removes one (the guard's pop
            // is that removal); with none left it steps above the existing
            // prefix, which is a canonical directory, so its parent is the
            // physical parent.
            Component::ParentDir if pending.pop().is_none() => {
                base.pop();
            }
            _ => {}
        }
    }
    base.extend(pending);
    base
}

/// Fold `.` and `..` of an absolute path lexically (no filesystem access).
fn lexical_clean(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                out.push(part.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
        }
    }
    out
}

fn fold_case(name: &OsStr) -> String {
    name.to_string_lossy().to_lowercase()
}

fn name_eq(a: &OsStr, b: &OsStr, fold: bool) -> bool {
    a == b || (fold && fold_case(a) == fold_case(b))
}

/// Whether `path` is `root` or below it, compared component by component
/// (`/srv/share` does not cover `/srv/shared`).
fn is_under(path: &Path, root: &Path, fold: bool) -> bool {
    let mut path_parts = path.components();
    root.components().all(|r| {
        path_parts
            .next()
            .is_some_and(|p| name_eq(p.as_os_str(), r.as_os_str(), fold))
    })
}

fn same_path(a: &Path, b: &Path, fold: bool) -> bool {
    a.components().count() == b.components().count() && is_under(a, b, fold)
}

/// The audit file's family: `<name>`, `<name>.<n>` for any positive `n` and
/// the `<name>.lock` sidecar of the rotating writer, inside one directory.
#[derive(Debug, Clone)]
struct AuditFiles {
    dir: PathBuf,
    name: OsString,
    // Only the inode scan reads it, and that scan is unix-only.
    #[cfg_attr(not(unix), expect(dead_code))]
    retain: u32,
}

impl AuditFiles {
    fn matches(&self, canonical: &Path, fold: bool) -> bool {
        let (Some(parent), Some(file)) = (canonical.parent(), canonical.file_name()) else {
            return false;
        };
        if !same_path(parent, &self.dir, fold) {
            return false;
        }
        let file = file.to_string_lossy();
        let name = self.name.to_string_lossy();
        let (file, name) = if fold {
            (file.to_lowercase(), name.to_lowercase())
        } else {
            (file.into_owned(), name.into_owned())
        };
        if file == name || file == format!("{name}.lock") {
            return true;
        }
        // Any positive numeric suffix counts, not just `.1`..`.<retain>`: an
        // operator who lowers `[audit].retain` leaves `.N` files above it
        // behind until the writer's startup sweep removes them.
        file.strip_prefix(&format!("{name}.")).is_some_and(|n| {
            !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && n.bytes().any(|b| b != b'0')
        })
    }

    #[cfg(unix)]
    fn rotated_names(&self) -> Vec<OsString> {
        let mut names = vec![self.name.clone()];
        let mut lock = self.name.clone();
        lock.push(".lock");
        names.push(lock);
        for n in 1..=self.retain.min(INODE_SCAN_MAX_ROTATED) {
            let mut rotated = self.name.clone();
            rotated.push(format!(".{n}"));
            names.push(rotated);
        }
        names
    }
}

/// Why [`ProtectedSet::check_request`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StatePathDenied {
    /// The path could not be normalized.
    #[error("path cannot be normalized: {0}")]
    Unnormalizable(NormalizeError),
    /// The canonical path is in the protected set.
    #[error("path is in the protected set")]
    Protected,
}

/// The state tree no remote file op may reach, whatever a role or an
/// `acl.toml` row grants (ADR-0029 decision 5).
///
/// - Directories, everything below them and the directory itself: the
///   config, state and runtime directories this process really uses
///   (`$QSH_CONFIG_DIR`, `$XDG_*` applied) and the same three resolved the
///   default way below each given home, so another qsh instance of the same
///   uid is covered too. On Linux that includes `/run/user/<uid>/qsh`.
/// - Files: the file-mode key, the audit file, its rotations
///   (`<path>.<n>` for any positive `n`, so files left past a lowered
///   `[audit].retain` stay covered) and the writer's `.lock` sidecar. The
///   rotating writer renames and never uses a temporary name, so there is no
///   other name to list.
///
/// Every entry is held twice when they differ: as given (made absolute and
/// folded lexically) and normalized, so a config directory that is itself a
/// symlink is protected under both spellings. The set is resolved per
/// request ([`ProtectedSet::resolve`]) and never frozen at startup.
#[derive(Debug, Clone)]
pub struct ProtectedSet {
    dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
    audit: Vec<AuditFiles>,
    fold_case: bool,
}

impl ProtectedSet {
    /// Resolve the set for one request. `homes` are the account homes the
    /// default locations derive from (see [`ProtectedSet::for_process`]).
    pub fn resolve(
        paths: &Paths,
        audit: &AuditConfig,
        homes: &[PathBuf],
        normalizer: &dyn Normalizer,
    ) -> Self {
        let mut set = Self {
            dirs: Vec::new(),
            files: Vec::new(),
            audit: Vec::new(),
            fold_case: cfg!(any(target_os = "macos", windows)),
        };
        let mut dirs = vec![
            paths.config_dir.clone(),
            paths.state_dir.clone(),
            paths.runtime_dir(),
        ];
        for home in homes {
            dirs.push(home.join(".config/qsh"));
            dirs.push(home.join(".local/state/qsh"));
        }
        dirs.extend(default_runtime_dir());
        for dir in &dirs {
            set.add_spellings(dir, normalizer, |set, spelling| {
                if !set.dirs.contains(&spelling) {
                    set.dirs.push(spelling);
                }
            });
        }
        set.add_spellings(
            &paths.identity_dir().join(KEY_FILE),
            normalizer,
            |set, spelling| {
                if !set.files.contains(&spelling) {
                    set.files.push(spelling);
                }
            },
        );
        let audit_path = audit.path(paths);
        let retain = audit.retain();
        set.add_spellings(&audit_path, normalizer, |set, spelling| {
            if !set.files.contains(&spelling) {
                set.files.push(spelling);
            }
        });
        if let (Some(parent), Some(name)) = (audit_path.parent(), audit_path.file_name()) {
            let name = name.to_os_string();
            set.add_spellings(parent, normalizer, |set, dir| {
                set.audit.push(AuditFiles {
                    dir,
                    name: name.clone(),
                    retain,
                });
            });
        }
        set
    }

    /// [`ProtectedSet::resolve`] for the running process: the homes are the
    /// serve account's passwd home and the environment's home (what the
    /// process's own `Paths` default used), de-duplicated.
    pub fn for_process(paths: &Paths, audit: &AuditConfig, normalizer: &dyn Normalizer) -> Self {
        let mut homes = Vec::new();
        homes.extend(serve_home_dir());
        if let Some(env_home) = crate::config::home_dir()
            && !homes.contains(&env_home)
        {
            homes.push(env_home);
        }
        Self::resolve(paths, audit, &homes, normalizer)
    }

    /// Force case-insensitive (or case-sensitive) component comparison. The
    /// default follows the platform (insensitive on macOS and Windows,
    /// ADR-0029 decision 23). Exists so the folding can be tested on Linux.
    pub fn with_case_folding(mut self, fold: bool) -> Self {
        self.fold_case = fold;
        self
    }

    fn add_spellings(
        &mut self,
        path: &Path,
        normalizer: &dyn Normalizer,
        mut insert: impl FnMut(&mut Self, PathBuf),
    ) {
        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let lexical = lexical_clean(&absolute);
        insert(self, lexical.clone());
        if let Ok(normal) = normalizer.normalize(&absolute)
            && normal != lexical
        {
            insert(self, normal);
        }
    }

    /// Whether `canonical` (already normalized) is in the protected set. A
    /// nonexistent path below a protected directory counts, so the error
    /// shape cannot reveal which files exist there.
    pub fn denies(&self, canonical: &Path) -> bool {
        if !cfg!(unix) {
            return true;
        }
        let fold = self.fold_case;
        self.dirs.iter().any(|d| is_under(canonical, d, fold))
            || self.files.iter().any(|f| same_path(canonical, f, fold))
            || self.audit.iter().any(|a| a.matches(canonical, fold))
    }

    /// The state-path stage of ADR-0029 decision 8 for a request that has not
    /// been normalized yet (a role-only allow skips the ACL stage's
    /// normalization): normalize `absolute`, refuse when it cannot be
    /// resolved or lands in the set, and return the canonical path.
    pub fn check_request(
        &self,
        normalizer: &dyn Normalizer,
        absolute: &Path,
    ) -> Result<PathBuf, StatePathDenied> {
        let canonical = normalizer
            .normalize(absolute)
            .map_err(StatePathDenied::Unnormalizable)?;
        if self.denies(&canonical) {
            Err(StatePathDenied::Protected)
        } else {
            Ok(canonical)
        }
    }

    /// The protected directories, in both spellings.
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// The protected files (key and audit file), in both spellings. Rotated
    /// audit names are matched by rule, not listed.
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }
}

/// `/run/user/<uid>/qsh`: where a same-uid instance puts its sockets when
/// `$XDG_RUNTIME_DIR` is the systemd default.
#[cfg(target_os = "linux")]
fn default_runtime_dir() -> Option<PathBuf> {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    Some(PathBuf::from(format!("/run/user/{uid}/qsh")))
}

#[cfg(not(target_os = "linux"))]
fn default_runtime_dir() -> Option<PathBuf> {
    None
}

/// What kind of filesystem object a stat describes (ADR-0029 decision 6-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link (only from an lstat).
    Symlink,
    /// A FIFO.
    Fifo,
    /// A Unix-domain socket.
    Socket,
    /// A block device.
    BlockDevice,
    /// A character device.
    CharDevice,
    /// Anything else.
    Other,
}

/// Classify a stat result.
pub fn file_kind(md: &fs::Metadata) -> FileKind {
    let ft = md.file_type();
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            return FileKind::Fifo;
        }
        if ft.is_socket() {
            return FileKind::Socket;
        }
        if ft.is_block_device() {
            return FileKind::BlockDevice;
        }
        if ft.is_char_device() {
            return FileKind::CharDevice;
        }
    }
    if ft.is_file() {
        FileKind::Regular
    } else if ft.is_dir() {
        FileKind::Directory
    } else if ft.is_symlink() {
        FileKind::Symlink
    } else {
        FileKind::Other
    }
}

/// Why the opened-handle recheck refused (ADR-0029 decision 6-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandleDenied {
    /// The fd points into the protected set.
    #[error("the opened handle is in the protected set")]
    Protected,
    /// The evaluator, re-called for the path the fd really points at, no
    /// longer allows it.
    #[error("the opened handle is no longer allowed")]
    Reevaluation,
    /// The fd's path could not be resolved ([`HANDLE_RECHECK_UNAVAILABLE`]).
    /// A recheck that cannot run is a refusal.
    #[error("the opened handle's path cannot be resolved ({0:?})")]
    Unresolvable(io::ErrorKind),
}

/// The recheck itself, on an already resolved path.
///
/// `resolved` is what [`handle_path`] returned. The path must pass the
/// protected-set comparison and `reevaluate` (the dispatch passes the
/// authorizer call for that path; allowing on a different basis than the
/// first check is fine). On success it returns the path the fd points at.
pub fn recheck_handle_path(
    resolved: io::Result<PathBuf>,
    protected: &ProtectedSet,
    reevaluate: impl FnOnce(&Path) -> bool,
) -> Result<PathBuf, HandleDenied> {
    let path = resolved.map_err(|e| HandleDenied::Unresolvable(e.kind()))?;
    if protected.denies(&path) {
        return Err(HandleDenied::Protected);
    }
    if !reevaluate(&path) {
        return Err(HandleDenied::Reevaluation);
    }
    Ok(path)
}

/// Recheck an opened fd: resolve its real path ([`handle_path`]) and run
/// [`recheck_handle_path`]. The caller closes the fd on `Err`.
pub fn recheck_handle(
    file: &File,
    protected: &ProtectedSet,
    reevaluate: impl FnOnce(&Path) -> bool,
) -> Result<PathBuf, HandleDenied> {
    recheck_handle_path(handle_path(file), protected, reevaluate)
}

/// Why [`ProtectedInodes::collect`] failed. The caller refuses the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InodeScanError {
    /// The protected tree is larger or deeper than the scan limits.
    #[error("the protected tree is too large to scan")]
    TooLarge,
    /// An entry could not be inspected.
    #[error("the protected tree cannot be scanned ({0:?})")]
    Io(io::ErrorKind),
    /// No inode identity on this platform yet (Windows is M20).
    #[error("inode identity is not supported on this platform")]
    Unsupported,
}

/// The `(dev, ino)` of every existing protected file (ADR-0029 decision
/// 6-5). A hard link made outside the protected tree to `acl.toml` or
/// `device.key` has the same pair, so comparing the opened file closes that
/// bypass.
///
/// Coverage is every non-directory entry below the protected directories
/// (not just the files decision 5 names), the key, the audit file with its
/// rotations and lock. Symlink entries are skipped: a link is not an inode
/// to alias. Collected per request, like the set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProtectedInodes {
    ids: HashSet<(u64, u64)>,
}

impl ProtectedInodes {
    /// Collect with the default limits.
    pub fn collect(protected: &ProtectedSet) -> Result<Self, InodeScanError> {
        Self::collect_with_limits(protected, INODE_SCAN_MAX_ENTRIES, INODE_SCAN_MAX_DEPTH)
    }

    /// Whether `(dev, ino)` belongs to a protected file.
    pub fn contains(&self, dev: u64, ino: u64) -> bool {
        self.ids.contains(&(dev, ino))
    }

    /// How many protected inodes were found.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether none were found.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

#[cfg(unix)]
impl ProtectedInodes {
    /// [`ProtectedInodes::collect`] with explicit limits.
    pub fn collect_with_limits(
        protected: &ProtectedSet,
        max_entries: usize,
        max_depth: usize,
    ) -> Result<Self, InodeScanError> {
        use std::os::unix::fs::MetadataExt;
        let mut ids = HashSet::new();
        let mut visited = 0usize;
        let scan_err = |e: io::Error| InodeScanError::Io(e.kind());

        let mut stack: Vec<(PathBuf, usize)> = Vec::new();
        for dir in &protected.dirs {
            match fs::symlink_metadata(dir) {
                Ok(md) if md.is_dir() => stack.push((dir.clone(), 0)),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(scan_err(e)),
            }
        }
        while let Some((dir, depth)) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(scan_err(e)),
            };
            for entry in entries {
                let entry = entry.map_err(scan_err)?;
                visited += 1;
                if visited > max_entries {
                    return Err(InodeScanError::TooLarge);
                }
                let md = match entry.metadata() {
                    Ok(md) => md,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(scan_err(e)),
                };
                if md.is_dir() {
                    if depth >= max_depth {
                        return Err(InodeScanError::TooLarge);
                    }
                    stack.push((entry.path(), depth + 1));
                } else if !md.file_type().is_symlink() {
                    ids.insert((md.dev(), md.ino()));
                }
            }
        }

        let mut named: Vec<PathBuf> = protected.files.clone();
        for family in &protected.audit {
            named.extend(family.rotated_names().iter().map(|n| family.dir.join(n)));
            // Leftover `.N` files above a lowered `retain`. The audit
            // directory may be a busy one (`/var/log`), so this scan is
            // best effort: past the entry cap it stops without failing, and
            // the path match still covers those names.
            if let Ok(rd) = fs::read_dir(&family.dir) {
                for entry in rd.flatten().take(INODE_SCAN_MAX_ENTRIES) {
                    let path = entry.path();
                    if family.matches(&path, protected.fold_case) {
                        named.push(path);
                    }
                }
            }
        }
        for path in named {
            match fs::metadata(&path) {
                Ok(md) if !md.is_dir() => {
                    ids.insert((md.dev(), md.ino()));
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(scan_err(e)),
            }
        }
        Ok(Self { ids })
    }
}

#[cfg(not(unix))]
impl ProtectedInodes {
    /// [`ProtectedInodes::collect`] with explicit limits. Off unix this
    /// always refuses.
    pub fn collect_with_limits(
        _protected: &ProtectedSet,
        _max_entries: usize,
        _max_depth: usize,
    ) -> Result<Self, InodeScanError> {
        Err(InodeScanError::Unsupported)
    }
}

/// Why [`check_read_target`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReadTargetDenied {
    /// The opened file is a protected inode (a hard link into the state
    /// tree). Reported as `PERMISSION_DENIED`.
    #[error("the opened file is a protected inode")]
    ProtectedInode,
    /// The opened object is not a regular file. Reported as
    /// `INVALID_ARGUMENT`.
    #[error("the opened object is not a regular file")]
    NotRegular(FileKind),
    /// `fstat` failed.
    #[error("the opened file cannot be inspected ({0:?})")]
    Stat(io::ErrorKind),
    /// No inode identity on this platform yet (Windows is M20).
    #[error("inode identity is not supported on this platform")]
    Unsupported,
}

/// The `file.read` checks on an opened fd (ADR-0029 decisions 6-5 and 6-6):
/// not a protected `(dev, ino)`, and a regular file. The inode check comes
/// first, so a protected object never answers with a kind error. Returns the
/// `fstat` result.
#[cfg(unix)]
pub fn check_read_target(
    file: &File,
    inodes: &ProtectedInodes,
) -> Result<fs::Metadata, ReadTargetDenied> {
    use std::os::unix::fs::MetadataExt;
    let md = file
        .metadata()
        .map_err(|e| ReadTargetDenied::Stat(e.kind()))?;
    if inodes.contains(md.dev(), md.ino()) {
        return Err(ReadTargetDenied::ProtectedInode);
    }
    match file_kind(&md) {
        FileKind::Regular => Ok(md),
        kind => Err(ReadTargetDenied::NotRegular(kind)),
    }
}

/// Off unix: always refuses.
#[cfg(not(unix))]
pub fn check_read_target(
    _file: &File,
    _inodes: &ProtectedInodes,
) -> Result<fs::Metadata, ReadTargetDenied> {
    Err(ReadTargetDenied::Unsupported)
}

/// Open `path` for reading the way `file.read` does (ADR-0029 decision
/// 6-4): `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`. `O_NOFOLLOW`
/// guards the last component only; an intermediate component swapped for a
/// symlink after normalization is what [`recheck_handle`] catches.
#[cfg(unix)]
pub fn open_read_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

/// Open a directory the way `file.list`, `file.write` and `file.mkdir` do
/// (ADR-0029 decision 6-4): `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
#[cfg(unix)]
pub fn open_dir_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// Off unix: always fails.
#[cfg(not(unix))]
pub fn open_read_nofollow(_path: &Path) -> io::Result<File> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Off unix: always fails.
#[cfg(not(unix))]
pub fn open_dir_nofollow(_path: &Path) -> io::Result<File> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// The path an open fd really points at (ADR-0029 decision 6-4): Linux
/// reads `/proc/self/fd/<n>`, macOS asks `fcntl(F_GETPATH)`. A file
/// unlinked after the open reports its last path (the kernel's
/// ` (deleted)` suffix is removed), so a replaced protected file is still
/// recognized. Anywhere the path cannot be had this fails, and
/// [`recheck_handle`] turns that into a refusal.
#[cfg(target_os = "linux")]
pub fn handle_path(file: &File) -> io::Result<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let link = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    let mut bytes = link.into_os_string().into_vec();
    if bytes.ends_with(b" (deleted)") {
        bytes.truncate(bytes.len() - b" (deleted)".len());
    }
    let path = PathBuf::from(OsStr::from_bytes(&bytes));
    if path.is_absolute() {
        Ok(path)
    } else {
        // `pipe:[..]`, `anon_inode:[..]` and friends: not a filesystem path.
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

/// See the Linux variant.
#[cfg(target_os = "macos")]
pub fn handle_path(file: &File) -> io::Result<PathBuf> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut buf = [0 as libc::c_char; libc::PATH_MAX as usize];
    // SAFETY: `buf` is a live buffer of PATH_MAX bytes, which is what
    // F_GETPATH requires, and the fd is open for the duration of the call.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success F_GETPATH wrote a NUL-terminated string into `buf`.
    let bytes = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    Ok(PathBuf::from(OsStr::from_bytes(bytes)))
}

/// No fd-to-path primitive on this platform: always fails, so the recheck
/// refuses.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn handle_path(_file: &File) -> io::Result<PathBuf> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Whether [`handle_path`] can work on this host. False on Linux without
/// `/proc`; tests that need a real recheck skip on false, and the operator
/// sees [`HANDLE_RECHECK_UNAVAILABLE`].
pub fn handle_resolution_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/proc/self/fd").is_dir()
    }
    #[cfg(target_os = "macos")]
    {
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}
