//! The `-r` half of `file.copy` (ADR-0029 decisions 20 to 22): walking a
//! tree and turning it into the single-file operations of `copy.rs`.
//!
//! The walk is the client's. The host knows no trees: a get asks it for one
//! directory listing at a time (`file.list`), a put makes the directories
//! itself (`file.mkdir`), and every file is its own `file.read` or
//! `file.write`. Directories are visited depth first in name byte order, a
//! parent before its children, and the files found on the way go through the
//! same two-at-a-time transfer pool as top-level operands.
//!
//! Nothing a host says is trusted to name a local path (decision 22): an
//! entry name is checked before a local path is made from it, and a local
//! path is only ever made by creating one validated name inside a directory
//! that is already open, never from a string that could climb out of it.

use std::ffi::OsString;
use std::path::PathBuf;

use qsh_proto::wire::{FILE_LIST_DIR_MAX, FileKind};

use super::*;

/// The longest path (in bytes) an item of a tree may have; a longer one
/// fails its entry (decision 20).
const PATH_MAX_BYTES: usize = 4096;

/// Whether `name`, as a remote host listed it, may become one component of a
/// local path (decision 22): not empty, at most [`NAME_MAX`] bytes, no `/`
/// or NUL, and neither `.` nor `..`. The Windows client adds what Windows
/// reserves (`\`, `:`, `<>"|?*`, control characters, a trailing dot or
/// space, device names), so a host cannot name a stream or a device.
///
/// It does not detect names that differ only by case. On a case-insensitive
/// local filesystem (Windows, default macOS) a recursive get of a tree
/// holding both `B` and `b` ends with the second replacing the first, as
/// `scp -r` does.
pub(in crate::ops) fn valid_remote_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && !name.contains(['/', '\0'])
        && name != "."
        && name != ".."
        && local::name_is_local_safe(name)
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

/// One entry of a remote directory, waiting to be copied.
pub(super) struct GetItem {
    /// Its path on the wire, the parent's plus the name.
    remote: String,
    /// Its name as the host listed it (not yet validated).
    name: String,
    kind: FileKind,
    /// Permission bits the host reported.
    mode: u32,
    /// The local directory it goes into.
    dir: Arc<File>,
    /// That directory's path as shown.
    parent_display: String,
}

/// Where a remote directory lands locally.
struct DirPlace {
    /// The directory the new one is made in (or, with no `name`, the
    /// directory the contents go into).
    dir: Arc<File>,
    /// The new directory's name; `None` copies the contents straight into
    /// `dir` (a source with no name of its own, such as `.`).
    name: Option<OsString>,
    /// The directory's own path as shown.
    display: String,
}

impl Run<'_> {
    /// A top-level get source under `-r`: ask what it is, then copy the
    /// file or walk the tree.
    pub(super) async fn get_top_recursive(&mut self, src: &str) {
        let ctx = self.ctx;
        let cancel = self.cancel;
        let local = ctx.local.as_ref().expect("a get resolved its destination");
        let meta = ItemMeta::file(src.to_string(), top_local_display(ctx, src));
        let listed = match control(cancel, self.session.file_list_open(src, "", &ctx.user)).await {
            Ok(listed) => listed,
            Err(failure) => return self.fail(&meta, failure),
        };
        match listed.kind() {
            FileKind::File => self.get_top(src).await,
            FileKind::Dir => {
                let place = match local {
                    LocalDst::Dir { dir, display } => match operand::source_name(src) {
                        Some(name) if !usable_local_name(name) => {
                            let meta = ItemMeta::directory(src.to_string(), display.clone());
                            return self.fail(
                                &meta,
                                XferFailure::Local(
                                    ErrorCode::InvalidArgument,
                                    "file name is too long or malformed".to_string(),
                                ),
                            );
                        }
                        Some(name) => DirPlace {
                            dir: Arc::clone(dir),
                            name: Some(OsString::from(name)),
                            display: operand::join_local(display, name),
                        },
                        None => DirPlace {
                            dir: Arc::clone(dir),
                            name: None,
                            display: display.clone(),
                        },
                    },
                    LocalDst::File { dir, name, display } => {
                        if !usable_local_name_os(name) {
                            let meta = ItemMeta::directory(src.to_string(), display.clone());
                            return self.fail(
                                &meta,
                                XferFailure::Local(
                                    ErrorCode::InvalidArgument,
                                    "not a usable file name on this platform".to_string(),
                                ),
                            );
                        }
                        DirPlace {
                            dir: Arc::clone(dir),
                            name: Some(name.clone()),
                            display: display.clone(),
                        }
                    }
                };
                let mode = listed.mode;
                self.get_dir(src.to_string(), mode, Some(listed), place)
                    .await;
            }
            _ => {
                let failure = XferFailure::Remote(
                    ErrorCode::InvalidArgument,
                    "not a regular file or directory".to_string(),
                );
                self.fail(&meta, failure);
            }
        }
    }

    /// One entry found in a remote directory.
    pub(super) async fn get_item(&mut self, item: GetItem) {
        let display = operand::join_local(&item.parent_display, &item.name);
        let meta = if item.kind == FileKind::Dir {
            ItemMeta::directory(item.remote.clone(), display.clone())
        } else {
            ItemMeta::file(item.remote.clone(), display.clone())
        };
        if !valid_remote_name(&item.name) {
            let failure = XferFailure::Local(
                ErrorCode::InvalidArgument,
                "the host sent an entry name that cannot be a local file name".to_string(),
            );
            return self.fail(&meta, failure);
        }
        if item.remote.len() > PATH_MAX_BYTES {
            let failure = XferFailure::Local(
                ErrorCode::InvalidArgument,
                format!("path is longer than {PATH_MAX_BYTES} bytes"),
            );
            return self.fail(&meta, failure);
        }
        match item.kind {
            FileKind::File => {
                let name = OsString::from(&item.name);
                if let Err(failure) = check_file_dest(&item.dir, &name, self.ctx.no_clobber) {
                    return self.fail(&meta, failure);
                }
                self.get_file(GetFile {
                    remote: item.remote,
                    dir: item.dir,
                    name,
                    display,
                })
                .await;
            }
            FileKind::Dir => {
                let place = DirPlace {
                    dir: item.dir,
                    name: Some(OsString::from(&item.name)),
                    display,
                };
                self.get_dir(item.remote, item.mode, None, place).await;
            }
            FileKind::Symlink => self.skipped(&meta, "symlink"),
            _ => {
                let failure = XferFailure::Remote(
                    ErrorCode::InvalidArgument,
                    "not a regular file or directory".to_string(),
                );
                self.fail(&meta, failure);
            }
        }
    }

    /// Every entry of the remote directory `remote`, pages joined, in name
    /// byte order, with the count of names the host could not list.
    /// `first` is the first page when the caller already asked for it.
    async fn list_all(
        &mut self,
        remote: &str,
        first: Option<wire::FileListed>,
    ) -> Result<(Vec<wire::FileEntry>, u32), XferFailure> {
        let cancel = self.cancel;
        let user = &self.ctx.user;
        let mut page = match first {
            Some(page) => page,
            None => control(cancel, self.session.file_list_open(remote, "", user)).await?,
        };
        if page.kind() != FileKind::Dir {
            return Err(XferFailure::Remote(
                ErrorCode::InvalidArgument,
                "not a directory".to_string(),
            ));
        }
        let unlistable = page.unlistable;
        let mut entries: Vec<wire::FileEntry> = Vec::new();
        loop {
            let more = page.more;
            for entry in std::mem::take(&mut page.entries) {
                if entries
                    .last()
                    .is_some_and(|prev| entry.name.as_bytes() <= prev.name.as_bytes())
                {
                    return Err(XferFailure::Remote(
                        ErrorCode::RemoteError,
                        "the host listed a directory out of order".to_string(),
                    ));
                }
                entries.push(entry);
                if entries.len() > FILE_LIST_DIR_MAX {
                    return Err(XferFailure::Local(
                        ErrorCode::ResourceExhausted,
                        format!("directory has more than {FILE_LIST_DIR_MAX} entries"),
                    ));
                }
            }
            if !more {
                break;
            }
            let Some(after) = entries.last().map(|e| e.name.clone()) else {
                return Err(XferFailure::Remote(
                    ErrorCode::RemoteError,
                    "the host's directory listing did not advance".to_string(),
                ));
            };
            page = control(cancel, self.session.file_list_open(remote, &after, user)).await?;
        }
        Ok((entries, unlistable))
    }

    /// Copy the remote directory `remote` (a listed `first` page may
    /// already be in hand): list it, make its local twin and queue its
    /// entries.
    async fn get_dir(
        &mut self,
        remote: String,
        mode: u32,
        first: Option<wire::FileListed>,
        place: DirPlace,
    ) {
        let ctx = self.ctx;
        let meta = ItemMeta::directory(remote.clone(), place.display.clone());
        // List before making anything: a directory the host refuses to show
        // leaves no empty twin behind.
        let (entries, unlistable) = match self.list_all(&remote, first).await {
            Ok(listed) => listed,
            Err(failure) => return self.fail(&meta, failure),
        };
        let local = match &place.name {
            None => Arc::clone(&place.dir),
            Some(name) => {
                match local::mkdir_at(&place.dir, name, mode & 0o777, ctx.preserve) {
                    Ok(local::MkdirOutcome::Created) => self.created(&meta, mode & 0o777),
                    Ok(local::MkdirOutcome::Existed) => {}
                    Ok(local::MkdirOutcome::ExistsNotDirectory) => {
                        let failure = XferFailure::Local(
                            ErrorCode::InvalidArgument,
                            "destination exists and is not a directory".to_string(),
                        );
                        return self.fail(&meta, failure);
                    }
                    Err(e) => return self.fail(&meta, local_io_failure(&e)),
                }
                match local::open_dir_at(&place.dir, name) {
                    Ok(dir) => Arc::new(dir),
                    Err(e) => return self.fail(&meta, local_io_failure(&e)),
                }
            }
        };
        if unlistable > 0 {
            let failure = XferFailure::Remote(
                ErrorCode::InvalidArgument,
                format!(
                    "{unlistable} unrepresentable names (not valid UTF-8) in this directory \
                     cannot be copied"
                ),
            );
            self.fail(&meta, failure);
        }
        for entry in entries.into_iter().rev() {
            let kind = entry.kind();
            self.stack.push(Work::Get(GetItem {
                remote: operand::join_path(&remote, &entry.name),
                name: entry.name,
                kind,
                mode: entry.mode,
                dir: Arc::clone(&local),
                parent_display: place.display.clone(),
            }));
        }
    }
}

// ---------------------------------------------------------------------------
// put
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalKind {
    File,
    Dir,
    Symlink,
    Other,
}

/// One entry of a local directory, waiting to be sent.
pub(super) struct PutItem {
    local: PathBuf,
    /// The local path as shown.
    display: String,
    /// Its name when it is valid UTF-8 (the wire carries strings).
    name: Option<String>,
    /// Its path on the wire, the parent's (as the host answered) plus the
    /// name.
    remote: String,
    kind: LocalKind,
    mode: u32,
}

/// One directory to make on the host.
struct PutDir {
    local: PathBuf,
    display: String,
    remote: String,
    name_if_dir: String,
    mode: u32,
}

/// The entries of a local directory in name byte order, each `lstat`ed.
fn read_local_dir(dir: &std::path::Path) -> std::io::Result<Vec<(OsString, LocalKind, u32)>> {
    let mut names: Vec<OsString> = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<std::io::Result<_>>()?;
    local::sort_names(&mut names);
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let md = match std::fs::symlink_metadata(dir.join(&name)) {
            Ok(md) => md,
            // Gone since the directory was read.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let kind = if md.is_dir() {
            LocalKind::Dir
        } else if md.is_file() {
            LocalKind::File
        } else if md.file_type().is_symlink() {
            LocalKind::Symlink
        } else {
            LocalKind::Other
        };
        out.push((name, kind, local::mode_of(&md)));
    }
    Ok(out)
}

impl Run<'_> {
    /// A top-level put source under `-r`: a directory is walked, anything
    /// else goes the single-file way (which also reports what is wrong
    /// with it).
    pub(super) async fn put_top_recursive(&mut self, src: &str) {
        match std::fs::metadata(src) {
            Ok(md) if md.is_dir() => {
                let name = operand::local_source_name(src).unwrap_or("").to_string();
                self.put_dir(PutDir {
                    local: PathBuf::from(src),
                    display: src.to_string(),
                    remote: self.ctx.put_dst.clone(),
                    name_if_dir: name,
                    mode: local::mode_of(&md),
                })
                .await;
            }
            _ => self.put_top(src).await,
        }
    }

    /// One entry found in a local directory.
    pub(super) async fn put_item(&mut self, item: PutItem) {
        let meta = if item.kind == LocalKind::Dir {
            ItemMeta::directory(item.remote.clone(), item.display.clone())
        } else {
            ItemMeta::file(item.remote.clone(), item.display.clone())
        };
        if item.name.is_none() {
            let failure = XferFailure::Local(
                ErrorCode::InvalidArgument,
                "file name is not valid UTF-8".to_string(),
            );
            return self.fail(&meta, failure);
        }
        if item.remote.len() > PATH_MAX_BYTES {
            let failure = XferFailure::Local(
                ErrorCode::InvalidArgument,
                format!("path is longer than {PATH_MAX_BYTES} bytes"),
            );
            return self.fail(&meta, failure);
        }
        match item.kind {
            LocalKind::File => {
                self.put_file(PutFile {
                    local: item.local,
                    display: item.display,
                    remote: item.remote,
                    name_if_dir: String::new(),
                    follow: false,
                })
                .await;
            }
            LocalKind::Dir => {
                self.put_dir(PutDir {
                    local: item.local,
                    display: item.display,
                    remote: item.remote,
                    name_if_dir: String::new(),
                    mode: item.mode,
                })
                .await;
            }
            LocalKind::Symlink => self.skipped(&meta, "symlink"),
            LocalKind::Other => {
                let failure = XferFailure::Local(
                    ErrorCode::InvalidArgument,
                    "not a regular file or directory".to_string(),
                );
                self.fail(&meta, failure);
            }
        }
    }

    /// Send a local directory: read it, make it on the host (a parent
    /// before any child), queue its entries.
    async fn put_dir(&mut self, spec: PutDir) {
        let ctx = self.ctx;
        let cancel = self.cancel;
        let meta = ItemMeta::directory(spec.remote.clone(), spec.display.clone());
        // Read before making anything: a directory this machine cannot read
        // leaves no empty twin on the host.
        let local = spec.local.clone();
        let read = tokio::task::spawn_blocking(move || read_local_dir(&local)).await;
        let children = match read {
            Ok(Ok(children)) => children,
            Ok(Err(e)) => return self.fail(&meta, local_io_failure(&e)),
            Err(_) => {
                let failure =
                    XferFailure::Local(ErrorCode::Internal, "file operation failed".to_string());
                return self.fail(&meta, failure);
            }
        };
        let request = wire::FileMkdirOpen {
            path: spec.remote.clone(),
            mode: spec.mode & 0o777,
            name_if_dir: spec.name_if_dir.clone(),
            preserve: ctx.preserve,
            user: ctx.user.clone(),
        };
        let done = match control(cancel, self.session.file_mkdir_open(request)).await {
            Ok(done) => done,
            Err(failure) => return self.fail(&meta, failure),
        };
        let base = if done.into_dir && !spec.name_if_dir.is_empty() {
            operand::join_path(&spec.remote, &spec.name_if_dir)
        } else {
            spec.remote.clone()
        };
        if done.created {
            let made = ItemMeta::directory(base.clone(), spec.display.clone());
            self.created(&made, spec.mode & 0o777);
        }
        for (name, kind, mode) in children.into_iter().rev() {
            let text = name.to_str().map(str::to_string);
            let shown = text
                .clone()
                .unwrap_or_else(|| name.to_string_lossy().into_owned());
            self.stack.push(Work::Put(PutItem {
                local: spec.local.join(&name),
                display: operand::join_local(&spec.display, &shown),
                remote: operand::join_path(&base, &shown),
                name: text,
                kind,
                mode,
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remote_name_is_one_plain_path_component() {
        for ok in ["a", "with space", "ünï", ".hidden", "a.b", "-rf"] {
            assert!(valid_remote_name(ok), "{ok:?}");
        }
        // Three dots are a plain name on unix; Windows strips a trailing dot,
        // so the Windows client refuses the spelling.
        assert_eq!(valid_remote_name("..."), cfg!(unix));
        let longest = "x".repeat(NAME_MAX);
        assert!(valid_remote_name(&longest));
    }

    #[test]
    fn a_remote_name_that_could_leave_its_directory_is_refused() {
        for bad in [
            "", ".", "..", "a/b", "/", "/etc", "../x", "x/..", "a\0b", "\0",
        ] {
            assert!(!valid_remote_name(bad), "{bad:?}");
        }
        let too_long = "x".repeat(NAME_MAX + 1);
        assert!(!valid_remote_name(&too_long));
        // 128 two-byte characters are 256 bytes: the limit is bytes.
        assert!(!valid_remote_name(&"é".repeat(128)));
    }
}
