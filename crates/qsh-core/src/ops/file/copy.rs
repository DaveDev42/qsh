//! The unix body of `file.copy`: plan, connect, run the items, assemble the
//! result. See the parent module for the contract.

use std::ffi::OsString;
use std::fs::File;
use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use qsh_proto::types::{COPY_JSON_ENTRIES_MAX, COPY_JSON_FAILURES_MAX};
use qsh_proto::{
    ErrorCode, FileCopyData, FileCopyEntry, FileCopyErrorDetails, FileCopyFailure, FileCopyReq,
    wire,
};
use tokio::task::JoinSet;

use super::{CancelToken, FILE_COPY_PARALLEL, FileCopyError, FileCopyObserver, FileProgress};
use crate::client::file::{
    DownloadDest, UploadSource, XferFailure, download, local_io_failure, upload,
};
use crate::client::{ClientError, Session};
use crate::file::host::{self, FsKind};
use crate::file::operand::{self, CopyPlan, Direction};
use crate::ops::exec::map_client_error;
use crate::ops::{OpError, Ops, PeerRoute};

/// The longest file name a local destination accepts.
const NAME_MAX: usize = 255;

/// Where a get puts its files (decision 2's result-position rules).
enum LocalDst {
    /// An existing directory: every source lands inside it under its own
    /// name.
    Dir { dir: Arc<File>, display: String },
    /// One new or replaced file: `name` inside `dir`.
    File {
        dir: Arc<File>,
        name: OsString,
        display: String,
    },
}

struct Ctx {
    plan: CopyPlan,
    preserve: bool,
    no_clobber: bool,
    user: String,
    observer: Arc<dyn FileCopyObserver>,
    /// `Some` exactly for a get.
    local: Option<LocalDst>,
    /// A put's destination as it goes on the wire (a trailing `/` when
    /// there are several sources: the host then insists on a directory).
    put_dst: String,
    reverse: bool,
}

/// What one item left behind.
enum Outcome {
    Entry {
        entry: Box<FileCopyEntry>,
        /// `local` or `remote` for a failed item.
        side: &'static str,
        /// A connection-level failure the item surfaced: the copy ends.
        stop: Option<OpError>,
    },
    /// The item was in flight (or about to start) when the copy was
    /// canceled.
    NotAttempted { stop: OpError },
}

struct ItemMeta {
    remote: String,
    local: String,
}

struct Done {
    bytes: u64,
    blake3: String,
    mode: u32,
    overwritten: bool,
}

/// Everything a run needs besides the session: the destination resolved,
/// the host's `user@` hint settled.
fn build_ctx(
    plan: CopyPlan,
    req: &FileCopyReq,
    observer: Arc<dyn FileCopyObserver>,
    user: Option<String>,
    reverse: bool,
) -> Result<Ctx, OpError> {
    let local = match plan.direction {
        Direction::Get => Some(resolve_local_dst(
            &plan.destination,
            plan.sources.len() > 1,
        )?),
        Direction::Put => None,
    };
    let put_dst = if plan.direction == Direction::Put && plan.sources.len() > 1 {
        if plan.destination.ends_with('/') {
            plan.destination.clone()
        } else {
            format!("{}/", plan.destination)
        }
    } else {
        plan.destination.clone()
    };
    Ok(Ctx {
        plan,
        preserve: req.preserve,
        no_clobber: req.no_clobber,
        user: user.unwrap_or_default(),
        observer,
        local,
        put_dst,
        reverse,
    })
}

pub(super) fn file_copy(
    ops: &Ops,
    plan: CopyPlan,
    req: &FileCopyReq,
    observer: Arc<dyn FileCopyObserver>,
    cancel: &CancelToken,
) -> Result<FileCopyData, FileCopyError> {
    // The destination and the user hint are settled before anything is
    // dialed, so a bad operand never costs a connection.
    let user = ops.resolve_user_hint(&plan.host, plan.user.clone())?;
    let ctx = build_ctx(plan, req, observer, user, false)?;

    // The identity is loaded before the route, as `exec.run` does: an
    // uninitialized device is `CONFIG_ERROR` whatever the host name.
    let identity = ops.load_identity()?.ok_or_else(|| {
        OpError::new(
            ErrorCode::ConfigError,
            "no device identity; run `qsh init` first",
        )
    })?;
    let route = ops.resolve_exec_route(&ctx.plan.host, identity)?;
    let reverse = matches!(route, PeerRoute::Reverse(_));
    let mut connected = ops.connect_routed(route)?;
    let Some(mut session) = connected.take_session() else {
        return Err(OpError::new(ErrorCode::Internal, "connection already closed").into());
    };

    let ctx = Ctx { reverse, ..ctx };
    let started = Instant::now();
    let report = connected
        .runtime()
        .block_on(run(&mut session, &ctx, cancel));
    session.close();
    connected.close();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    report.into_result(&ctx, duration_ms)
}

/// [`file_copy`] over a session the caller already holds.
pub(super) async fn file_copy_on(
    session: &mut Session,
    plan: CopyPlan,
    req: &FileCopyReq,
    observer: Arc<dyn FileCopyObserver>,
    cancel: &CancelToken,
) -> Result<FileCopyData, FileCopyError> {
    let user = plan.user.clone();
    let ctx = build_ctx(plan, req, observer, user, false)?;
    let started = Instant::now();
    let report = run(session, &ctx, cancel).await;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    report.into_result(&ctx, duration_ms)
}

// ---------------------------------------------------------------------------
// The local destination of a get
// ---------------------------------------------------------------------------

fn open_dir(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
}

fn invalid(message: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message)
}

fn failure_to_op(failure: XferFailure) -> OpError {
    match failure {
        XferFailure::Local(code, message) | XferFailure::Remote(code, message) => {
            OpError::new(code, message)
        }
        _ => OpError::new(ErrorCode::Internal, "file operation failed"),
    }
}

/// Decide where a get's files go. DST itself is a path the person typed, so
/// a symlink there is followed; what is created under it never follows one
/// (decision 7).
fn resolve_local_dst(dst: &str, multiple: bool) -> Result<LocalDst, OpError> {
    let trailing = dst.ends_with('/');
    let path = Path::new(dst);
    match std::fs::metadata(path) {
        Ok(md) if md.is_dir() => {
            let dir = open_dir(path).map_err(|e| failure_to_op(local_io_failure(&e)))?;
            Ok(LocalDst::Dir {
                dir: Arc::new(dir),
                display: dst.to_string(),
            })
        }
        Ok(_) => {
            if trailing || multiple {
                return Err(invalid(format!("{dst}: not a directory")));
            }
            // An existing file: follow DST itself, then write next to the
            // real file.
            let real =
                std::fs::canonicalize(path).map_err(|e| failure_to_op(local_io_failure(&e)))?;
            split_file_dst(&real, dst)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if trailing || multiple {
                return Err(invalid(format!("{dst}: no such directory")));
            }
            split_file_dst(path, dst)
        }
        Err(e) => Err(failure_to_op(local_io_failure(&e))),
    }
}

fn split_file_dst(path: &Path, display: &str) -> Result<LocalDst, OpError> {
    let Some(name) = path.file_name() else {
        return Err(invalid(format!("{display}: cannot name a file there")));
    };
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let dir = open_dir(parent).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => invalid(format!("{display}: no such directory")),
        _ => failure_to_op(local_io_failure(&e)),
    })?;
    Ok(LocalDst::File {
        dir: Arc::new(dir),
        name: name.to_os_string(),
        display: display.to_string(),
    })
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

struct Report {
    total: u64,
    entries: Vec<FileCopyEntry>,
    entries_truncated: bool,
    copied: u64,
    created: u64,
    skipped: u64,
    failed: u64,
    not_attempted: u64,
    bytes: u64,
    failures: Vec<FileCopyFailure>,
    failures_truncated: bool,
    first_failure: Option<(ErrorCode, String)>,
    stop: Option<OpError>,
}

impl Report {
    fn new(total: usize) -> Self {
        Self {
            total: total as u64,
            entries: Vec::new(),
            entries_truncated: false,
            copied: 0,
            created: 0,
            skipped: 0,
            failed: 0,
            not_attempted: 0,
            bytes: 0,
            failures: Vec::new(),
            failures_truncated: false,
            first_failure: None,
            stop: None,
        }
    }

    fn stop(&mut self, error: OpError) {
        if self.stop.is_none() {
            self.stop = Some(error);
        }
    }

    fn record(&mut self, outcome: Outcome, observer: &dyn FileCopyObserver) {
        match outcome {
            Outcome::NotAttempted { stop } => {
                self.not_attempted += 1;
                self.stop(stop);
            }
            Outcome::Entry { entry, side, stop } => {
                match entry.status.as_str() {
                    "copied" => {
                        self.copied += 1;
                        self.bytes += entry.bytes.unwrap_or(0);
                    }
                    "created" => self.created += 1,
                    "skipped" => self.skipped += 1,
                    _ => {
                        self.failed += 1;
                        let code = entry.code.clone().unwrap_or(ErrorCode::Internal);
                        if self.first_failure.is_none() {
                            self.first_failure =
                                Some((code.clone(), entry.message.clone().unwrap_or_default()));
                        }
                        if self.failures.len() < COPY_JSON_FAILURES_MAX {
                            self.failures.push(FileCopyFailure {
                                side: side.to_string(),
                                path: if side == "local" {
                                    entry.local_path.clone()
                                } else {
                                    entry.remote_path.clone()
                                },
                                code,
                            });
                        } else {
                            self.failures_truncated = true;
                        }
                    }
                }
                observer.entry(&entry);
                if self.entries.len() < COPY_JSON_ENTRIES_MAX {
                    self.entries.push(*entry);
                } else {
                    self.entries_truncated = true;
                }
                if let Some(stop) = stop {
                    self.stop(stop);
                }
            }
        }
    }

    fn into_result(self, ctx: &Ctx, duration_ms: u64) -> Result<FileCopyData, FileCopyError> {
        if self.failed == 0 && self.stop.is_none() {
            return Ok(FileCopyData {
                host: ctx.plan.host.clone(),
                direction: ctx.plan.direction.as_str().to_string(),
                files: self.copied,
                directories: self.created,
                bytes: self.bytes,
                skipped: self.skipped,
                duration_ms,
                entries: self.entries,
                entries_truncated: self.entries_truncated,
            });
        }
        let (code, tail, retryable) = match &self.stop {
            Some(stop) => (
                stop.code.clone(),
                stop.message.clone(),
                stop.code == ErrorCode::ConnectionFailed,
            ),
            None => {
                let (code, message) = self
                    .first_failure
                    .clone()
                    .unwrap_or((ErrorCode::Internal, String::new()));
                (code, message, false)
            }
        };
        let message = format!(
            "{} of {} entries failed: {}",
            self.failed + self.not_attempted,
            self.total,
            tail
        );
        let details = FileCopyErrorDetails {
            copied: self.copied,
            created: self.created,
            skipped: self.skipped,
            failed: self.failed,
            not_attempted: self.not_attempted,
            failures: self.failures,
            failures_truncated: self.failures_truncated,
        };
        let error = OpError::new(code, message)
            .with_retryable(retryable)
            .with_details(serde_json::to_value(details).unwrap_or(serde_json::Value::Null));
        Err(FileCopyError::plain(error))
    }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

fn canceled_error() -> OpError {
    OpError::new(ErrorCode::Canceled, "copy canceled")
}

fn capability_error(reverse: bool) -> OpError {
    let message = if reverse {
        "this reverse route does not have file.v1: either the target's qsh predates file copy, \
         or this machine's `qsh listen` daemon started before this machine's own qsh was last \
         upgraded and is still relaying its old capability set; nothing was sent. Upgrade qsh \
         on the target, then restart `qsh listen` on this machine and retry."
    } else {
        "the peer does not advertise the file.v1 capability; nothing was sent. Upgrade qsh on \
         the peer."
    };
    OpError::new(ErrorCode::Unsupported, message)
}

async fn run(session: &mut Session, ctx: &Ctx, cancel: &CancelToken) -> Report {
    let sources = &ctx.plan.sources;
    let total = sources.len();
    let mut report = Report::new(total);
    if !session.has_file_capability() {
        report.not_attempted = total as u64;
        report.stop(capability_error(ctx.reverse));
        return report;
    }

    let mut tasks: JoinSet<Outcome> = JoinSet::new();
    for (index, source) in sources.iter().enumerate() {
        while tasks.len() >= FILE_COPY_PARALLEL {
            join_one(&mut tasks, &mut report, ctx).await;
        }
        if cancel.is_canceled() {
            report.stop(canceled_error());
        }
        if report.stop.is_some() {
            report.not_attempted += (total - index) as u64;
            break;
        }
        let immediate = match ctx.plan.direction {
            Direction::Put => prepare_put(session, ctx, cancel, &mut tasks, source).await,
            Direction::Get => prepare_get(session, ctx, cancel, &mut tasks, source).await,
        };
        if let Some(outcome) = immediate {
            report.record(outcome, &*ctx.observer);
        }
    }
    while !tasks.is_empty() {
        join_one(&mut tasks, &mut report, ctx).await;
    }
    report
}

async fn join_one(tasks: &mut JoinSet<Outcome>, report: &mut Report, ctx: &Ctx) {
    match tasks.join_next().await {
        Some(Ok(outcome)) => report.record(outcome, &*ctx.observer),
        Some(Err(_)) => report.record(
            Outcome::Entry {
                entry: Box::new(failed_entry(
                    &ItemMeta {
                        remote: String::new(),
                        local: String::new(),
                    },
                    ErrorCode::Internal,
                    "file operation failed".to_string(),
                )),
                side: "local",
                stop: None,
            },
            &*ctx.observer,
        ),
        None => {}
    }
}

fn base_entry(status: &str, meta: &ItemMeta) -> FileCopyEntry {
    FileCopyEntry {
        status: status.to_string(),
        kind: "file".to_string(),
        remote_path: meta.remote.clone(),
        local_path: meta.local.clone(),
        bytes: None,
        blake3: None,
        mode: None,
        overwritten: None,
        reason: None,
        code: None,
        message: None,
    }
}

fn failed_entry(meta: &ItemMeta, code: ErrorCode, message: String) -> FileCopyEntry {
    let mut entry = base_entry("failed", meta);
    entry.code = Some(code);
    entry.message = Some(message);
    entry
}

/// Turn a finished transfer into what the report records.
fn settle(meta: &ItemMeta, result: Result<Done, XferFailure>) -> Outcome {
    match result {
        Ok(done) => {
            let mut entry = base_entry("copied", meta);
            entry.bytes = Some(done.bytes);
            entry.blake3 = Some(done.blake3);
            entry.mode = Some(done.mode);
            entry.overwritten = Some(done.overwritten);
            Outcome::Entry {
                entry: Box::new(entry),
                side: "",
                stop: None,
            }
        }
        Err(XferFailure::Exists) => {
            let mut entry = base_entry("skipped", meta);
            entry.reason = Some("exists".to_string());
            Outcome::Entry {
                entry: Box::new(entry),
                side: "",
                stop: None,
            }
        }
        Err(XferFailure::Remote(code, message)) => Outcome::Entry {
            entry: Box::new(failed_entry(meta, code, message)),
            side: "remote",
            stop: None,
        },
        Err(XferFailure::Local(code, message)) => Outcome::Entry {
            entry: Box::new(failed_entry(meta, code, message)),
            side: "local",
            stop: None,
        },
        Err(XferFailure::Link(err)) => {
            let op = map_client_error(err);
            Outcome::Entry {
                entry: Box::new(failed_entry(meta, op.code.clone(), op.message.clone())),
                side: "remote",
                stop: Some(op),
            }
        }
        Err(XferFailure::Canceled) => Outcome::NotAttempted {
            stop: canceled_error(),
        },
    }
}

fn immediate(meta: &ItemMeta, failure: XferFailure) -> Option<Outcome> {
    Some(settle(meta, Err(failure)))
}

/// A control-plane failure of one request: the host's refusal belongs to the
/// item, anything else is the connection's.
fn classify(err: ClientError) -> XferFailure {
    match err {
        ClientError::Remote { .. } => {
            let op = map_client_error(err);
            XferFailure::Remote(op.code, op.message)
        }
        other => XferFailure::Link(other),
    }
}

async fn control<T>(
    cancel: &CancelToken,
    fut: impl Future<Output = Result<T, ClientError>>,
) -> Result<T, XferFailure> {
    tokio::select! {
        result = fut => result.map_err(classify),
        () = cancel.canceled() => Err(XferFailure::Canceled),
    }
}

fn progress_for(ctx: &Ctx, name: String, total: u64) -> impl Fn(u64) + Send + Sync + 'static {
    let observer = Arc::clone(&ctx.observer);
    move |bytes| {
        observer.progress(&FileProgress {
            name: name.clone(),
            bytes,
            total,
        });
    }
}

// ---------------------------------------------------------------------------
// put
// ---------------------------------------------------------------------------

fn open_source(src: &str) -> Result<(File, host::StatInfo), XferFailure> {
    // The source operand is what the person typed: a symlink there is
    // followed, as `scp` does.
    let md = std::fs::metadata(src).map_err(|e| local_io_failure(&e))?;
    if md.is_dir() {
        return Err(XferFailure::Local(
            ErrorCode::InvalidArgument,
            "is a directory; use -r".to_string(),
        ));
    }
    if !md.is_file() {
        return Err(XferFailure::Local(
            ErrorCode::InvalidArgument,
            "not a regular file".to_string(),
        ));
    }
    let file = File::open(src).map_err(|e| local_io_failure(&e))?;
    let info = host::fstat(&file).map_err(|e| local_io_failure(&e))?;
    if info.kind != FsKind::Regular {
        return Err(XferFailure::Local(
            ErrorCode::InvalidArgument,
            "not a regular file".to_string(),
        ));
    }
    Ok((file, info))
}

async fn prepare_put(
    session: &mut Session,
    ctx: &Ctx,
    cancel: &CancelToken,
    tasks: &mut JoinSet<Outcome>,
    src: &str,
) -> Option<Outcome> {
    let mut meta = ItemMeta {
        remote: ctx.put_dst.clone(),
        local: src.to_string(),
    };
    let (file, info) = match open_source(src) {
        Ok(opened) => opened,
        Err(failure) => return immediate(&meta, failure),
    };
    let name = operand::source_name(src).unwrap_or("").to_string();
    let request = wire::FileWriteOpen {
        path: ctx.put_dst.clone(),
        size: info.size,
        mode: info.mode,
        overwrite: !ctx.no_clobber,
        name_if_dir: name.clone(),
        preserve: ctx.preserve,
        mtime: info.mtime,
        user: ctx.user.clone(),
    };
    let opened = match control(cancel, session.file_write_open(request)).await {
        Ok(opened) => opened,
        Err(XferFailure::Remote(ErrorCode::InvalidArgument, message))
            if ctx.no_clobber && message == "destination exists" =>
        {
            return immediate(&meta, XferFailure::Exists);
        }
        Err(failure) => return immediate(&meta, failure),
    };
    if opened.into_dir && !name.is_empty() {
        meta.remote = operand::join_path(&ctx.put_dst, &name);
    }
    let conduit = match control(cancel, session.file_conduit(opened.ticket, None)).await {
        Ok(conduit) => conduit,
        Err(failure) => return immediate(&meta, failure),
    };
    let progress = progress_for(
        ctx,
        if name.is_empty() {
            src.to_string()
        } else {
            name
        },
        info.size,
    );
    let cancel_rx = cancel.subscribe();
    let mode = info.mode;
    tasks.spawn(async move {
        let result = upload(
            conduit,
            UploadSource {
                file,
                size: info.size,
            },
            &progress,
            cancel_rx,
        )
        .await
        .map(|up| Done {
            bytes: up.bytes,
            blake3: up.blake3,
            mode,
            overwritten: up.overwritten,
        });
        settle(&meta, result)
    });
    None
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

/// Where one source lands: the directory, the final name and the path to
/// show for it.
fn get_target(ctx: &Ctx, src: &str) -> Result<(Arc<File>, OsString, String), XferFailure> {
    let local = ctx.local.as_ref().expect("a get resolved its destination");
    let (dir, name, display) = match local {
        LocalDst::Dir { dir, display } => {
            let Some(name) = operand::source_name(src) else {
                return Err(XferFailure::Local(
                    ErrorCode::InvalidArgument,
                    format!("cannot derive a file name from {src}; name the destination"),
                ));
            };
            if name.len() > NAME_MAX || name.contains('\0') {
                return Err(XferFailure::Local(
                    ErrorCode::InvalidArgument,
                    "file name is too long or malformed".to_string(),
                ));
            }
            (
                Arc::clone(dir),
                OsString::from(name),
                operand::join_path(display, name),
            )
        }
        LocalDst::File { dir, name, display } => (Arc::clone(dir), name.clone(), display.clone()),
    };
    match host::stat_at(&dir, &name).map_err(|e| local_io_failure(&e))? {
        Some(info) => match info.kind {
            FsKind::Symlink => Err(XferFailure::Local(
                ErrorCode::InvalidArgument,
                "destination is a symbolic link".to_string(),
            )),
            FsKind::Directory => Err(XferFailure::Local(
                ErrorCode::InvalidArgument,
                "destination is a directory".to_string(),
            )),
            FsKind::Other => Err(XferFailure::Local(
                ErrorCode::InvalidArgument,
                "destination is not a regular file".to_string(),
            )),
            FsKind::Regular if ctx.no_clobber => Err(XferFailure::Exists),
            FsKind::Regular => Ok((dir, name, display)),
        },
        None => Ok((dir, name, display)),
    }
}

async fn prepare_get(
    session: &mut Session,
    ctx: &Ctx,
    cancel: &CancelToken,
    tasks: &mut JoinSet<Outcome>,
    src: &str,
) -> Option<Outcome> {
    let mut meta = ItemMeta {
        remote: src.to_string(),
        local: String::new(),
    };
    let (dir, name, display) = match get_target(ctx, src) {
        Ok(target) => target,
        Err(failure) => {
            // Show where it would have landed when the destination is
            // known.
            if let Some(LocalDst::File { display, .. }) = &ctx.local {
                meta.local = display.clone();
            } else if let Some(LocalDst::Dir { display, .. }) = &ctx.local {
                meta.local = match operand::source_name(src) {
                    Some(name) => operand::join_path(display, name),
                    None => display.clone(),
                };
            }
            return immediate(&meta, failure);
        }
    };
    meta.local = display;
    let opened = match control(cancel, session.file_read_open(src, &ctx.user)).await {
        Ok(opened) => opened,
        Err(failure) => return immediate(&meta, failure),
    };
    let conduit = match control(
        cancel,
        session.file_conduit(opened.ticket.clone(), Some("file.read")),
    )
    .await
    {
        Ok(conduit) => conduit,
        Err(failure) => return immediate(&meta, failure),
    };
    let label = name.to_string_lossy().into_owned();
    let progress = progress_for(ctx, label, opened.size);
    let cancel_rx = cancel.subscribe();
    let dest = DownloadDest {
        dir,
        name,
        overwrite: !ctx.no_clobber,
        preserve: ctx.preserve,
    };
    tasks.spawn(async move {
        let result = download(conduit, &opened, dest, None, &progress, cancel_rx)
            .await
            .map(|down| Done {
                bytes: down.bytes,
                blake3: down.blake3,
                mode: down.mode,
                overwritten: down.overwritten,
            });
        settle(&meta, result)
    });
    None
}
