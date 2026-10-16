//! The body of `file.copy` for both client platforms: plan, connect, run the items, assemble the
//! result. See the parent module for the contract. The `-r` half, the tree
//! walks of a get and a put, is in [`tree`].

use std::ffi::OsString;
use std::fs::File;
use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use crate::file::local::{self, FsKind};
use crate::file::operand::{self, CopyPlan, Direction};
use crate::file::stat::StatInfo;
use crate::ops::exec::map_client_error;
use crate::ops::{OpError, Ops, PeerRoute};

mod tree;

/// The longest file name a local destination accepts.
const NAME_MAX: usize = 255;

/// Whether `name`, derived from a source path, may be created locally: at
/// most [`NAME_MAX`] bytes, no NUL, and whatever else the platform's file
/// names require (the Windows client refuses the characters and device
/// names Windows reserves).
fn usable_local_name(name: &str) -> bool {
    name.len() <= NAME_MAX && !name.contains('\0') && local::name_is_local_safe(name)
}

/// [`usable_local_name`] for a name the person typed as the destination.
fn usable_local_name_os(name: &OsString) -> bool {
    match name.to_str() {
        Some(name) => usable_local_name(name),
        // Not UTF-8: the unix client takes any bytes it was given; the
        // Windows one has no spelling to check against.
        None => cfg!(unix),
    }
}

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
    /// `-r`.
    recursive: bool,
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
    /// `file` or `directory`.
    kind: &'static str,
}

impl ItemMeta {
    fn file(remote: String, local: String) -> Self {
        Self {
            remote,
            local,
            kind: "file",
        }
    }

    fn directory(remote: String, local: String) -> Self {
        Self {
            remote,
            local,
            kind: "directory",
        }
    }
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
        recursive: req.recursive,
    })
}

/// How long a canceled copy waits for the host to acknowledge before it
/// closes the connection (`Connected::settle_before_close`).
const CANCEL_CLOSE_GRACE: Duration = Duration::from_secs(2);

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
    // The dial and handshake give way to Ctrl-C (decision 11).
    let mut connected = ops.connect_routed(route, cancel)?;
    let Some(mut session) = connected.take_session() else {
        return Err(OpError::new(ErrorCode::Internal, "connection already closed").into());
    };

    let ctx = Ctx { reverse, ..ctx };
    let started = Instant::now();
    let report = connected
        .runtime()
        .block_on(run(&mut session, &ctx, cancel));
    if cancel.is_canceled() {
        // A canceled transfer still has data in flight; let the host
        // acknowledge before closing, or it never hears of the close.
        connected.settle_before_close(CANCEL_CLOSE_GRACE);
    }
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
    let trailing = local::ends_with_separator(dst);
    let path = Path::new(dst);
    match std::fs::metadata(path) {
        Ok(md) if md.is_dir() => {
            let dir = local::open_dir(path).map_err(|e| failure_to_op(local_io_failure(&e)))?;
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
    let dir = local::open_dir(parent).map_err(|e| match e.kind() {
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
    fn new() -> Self {
        Self {
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
            self.copied + self.created + self.skipped + self.failed + self.not_attempted,
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

/// One thing the run still has to do. The stack of them is walked
/// depth-first in name order: a directory's children are pushed in reverse,
/// so the first name pops first.
enum Work {
    /// An operand of the command line.
    Top(String),
    /// An item found while walking a remote tree (a get).
    Get(tree::GetItem),
    /// An item found while walking a local tree (a put).
    Put(tree::PutItem),
}

/// The state of one run: the session (control requests are made on it one at
/// a time), the transfers in flight, what has been reported and what is left
/// to do.
struct Run<'a> {
    session: &'a mut Session,
    ctx: &'a Ctx,
    cancel: &'a CancelToken,
    tasks: JoinSet<Outcome>,
    report: Report,
    stack: Vec<Work>,
}

async fn run(session: &mut Session, ctx: &Ctx, cancel: &CancelToken) -> Report {
    let sources = &ctx.plan.sources;
    let mut run = Run {
        session,
        ctx,
        cancel,
        tasks: JoinSet::new(),
        report: Report::new(),
        stack: sources.iter().rev().map(|s| Work::Top(s.clone())).collect(),
    };
    if !run.session.has_file_capability() {
        run.report.not_attempted = sources.len() as u64;
        run.report.stop(capability_error(ctx.reverse));
        return run.report;
    }
    while let Some(work) = run.stack.pop() {
        while run.tasks.len() >= FILE_COPY_PARALLEL {
            run.join_one().await;
        }
        if cancel.is_canceled() {
            run.report.stop(canceled_error());
        }
        if run.report.stop.is_some() {
            // What is still known and untried: this item and the ones
            // queued behind it (a directory counts as one).
            run.report.not_attempted += 1 + run.stack.len() as u64;
            run.stack.clear();
            break;
        }
        run.step(work).await;
    }
    while !run.tasks.is_empty() {
        run.join_one().await;
    }
    run.report
}

impl Run<'_> {
    async fn join_one(&mut self) {
        let outcome = match self.tasks.join_next().await {
            Some(Ok(outcome)) => outcome,
            Some(Err(_)) => Outcome::Entry {
                entry: Box::new(failed_entry(
                    &ItemMeta::file(String::new(), String::new()),
                    ErrorCode::Internal,
                    "file operation failed".to_string(),
                )),
                side: "local",
                stop: None,
            },
            None => return,
        };
        self.record(outcome);
    }

    fn record(&mut self, outcome: Outcome) {
        self.report.record(outcome, &*self.ctx.observer);
    }

    /// An item that ended before a transfer started.
    fn fail(&mut self, meta: &ItemMeta, failure: XferFailure) {
        let outcome = settle(meta, Err(failure));
        self.record(outcome);
    }

    /// Record a directory the copy made.
    fn created(&mut self, meta: &ItemMeta, mode: u32) {
        let mut entry = base_entry("created", meta);
        entry.mode = Some(mode);
        self.record(Outcome::Entry {
            entry: Box::new(entry),
            side: "",
            stop: None,
        });
    }

    /// Record an item skipped for `reason`.
    fn skipped(&mut self, meta: &ItemMeta, reason: &str) {
        let mut entry = base_entry("skipped", meta);
        entry.reason = Some(reason.to_string());
        self.record(Outcome::Entry {
            entry: Box::new(entry),
            side: "",
            stop: None,
        });
    }

    async fn step(&mut self, work: Work) {
        match work {
            Work::Top(src) => match (self.ctx.plan.direction, self.ctx.recursive) {
                (Direction::Put, false) => self.put_top(&src).await,
                (Direction::Get, false) => self.get_top(&src).await,
                (Direction::Put, true) => self.put_top_recursive(&src).await,
                (Direction::Get, true) => self.get_top_recursive(&src).await,
            },
            Work::Get(item) => self.get_item(item).await,
            Work::Put(item) => self.put_item(item).await,
        }
    }
}

fn base_entry(status: &str, meta: &ItemMeta) -> FileCopyEntry {
    FileCopyEntry {
        status: status.to_string(),
        kind: meta.kind.to_string(),
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

/// The host refused for lack of a transfer slot (its per-principal or
/// per-host quota, decision 12).
fn is_quota_refusal(failure: &XferFailure) -> bool {
    matches!(
        failure,
        XferFailure::Remote(ErrorCode::ResourceExhausted, _)
    )
}

// ---------------------------------------------------------------------------
// put
// ---------------------------------------------------------------------------

/// Open a local source file. A source operand is what the person typed, so a
/// symlink there is followed (`follow`), as `scp` does; a file found while
/// walking a tree is opened without following one.
fn open_source(src: &Path, follow: bool) -> Result<(File, StatInfo), XferFailure> {
    let md = if follow {
        std::fs::metadata(src)
    } else {
        std::fs::symlink_metadata(src)
    }
    .map_err(|e| local_io_failure(&e))?;
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
    let file = local::open_source(src, follow).map_err(|e| local_io_failure(&e))?;
    let info = local::fstat(&file).map_err(|e| local_io_failure(&e))?;
    if info.kind != FsKind::Regular {
        return Err(XferFailure::Local(
            ErrorCode::InvalidArgument,
            "not a regular file".to_string(),
        ));
    }
    Ok((file, info))
}

/// One file to send.
struct PutFile {
    /// The local path to open.
    local: std::path::PathBuf,
    /// The local path as shown.
    display: String,
    /// The path on the wire.
    remote: String,
    /// `FileWriteOpen.name_if_dir`: the source's name for a top-level file,
    /// empty for a file inside a tree.
    name_if_dir: String,
    /// Follow a symlink at `local` (an operand does, a tree entry does not).
    follow: bool,
}

impl Run<'_> {
    async fn put_top(&mut self, src: &str) {
        let name = operand::local_source_name(src).unwrap_or("").to_string();
        self.put_file(PutFile {
            local: std::path::PathBuf::from(src),
            display: src.to_string(),
            remote: self.ctx.put_dst.clone(),
            name_if_dir: name,
            follow: true,
        })
        .await;
    }

    async fn put_file(&mut self, spec: PutFile) {
        let ctx = self.ctx;
        let cancel = self.cancel;
        let mut meta = ItemMeta::file(spec.remote.clone(), spec.display.clone());
        let (file, info) = match open_source(&spec.local, spec.follow) {
            Ok(opened) => opened,
            Err(failure) => return self.fail(&meta, failure),
        };
        let request = wire::FileWriteOpen {
            path: spec.remote.clone(),
            size: info.size,
            mode: info.mode,
            overwrite: !ctx.no_clobber,
            name_if_dir: spec.name_if_dir.clone(),
            preserve: ctx.preserve,
            mtime: info.mtime,
            user: ctx.user.clone(),
        };
        // A refusal for lack of a transfer slot waits for one of this
        // copy's own transfers to end and asks again; with none in flight
        // the refusal stands (decision 12).
        let opened = loop {
            let attempt = control(cancel, self.session.file_write_open(request.clone())).await;
            match attempt {
                Err(failure) if is_quota_refusal(&failure) && !self.tasks.is_empty() => {
                    self.join_one().await;
                }
                other => break other,
            }
        };
        let opened = match opened {
            Ok(opened) => opened,
            Err(XferFailure::Remote(ErrorCode::InvalidArgument, message))
                if ctx.no_clobber && message == "destination exists" =>
            {
                return self.fail(&meta, XferFailure::Exists);
            }
            Err(failure) => return self.fail(&meta, failure),
        };
        if opened.into_dir && !spec.name_if_dir.is_empty() {
            meta.remote = operand::join_path(&spec.remote, &spec.name_if_dir);
        }
        let conduit = match control(cancel, self.session.file_conduit(opened.ticket, None)).await {
            Ok(conduit) => conduit,
            Err(failure) => return self.fail(&meta, failure),
        };
        let label = operand::local_source_name(&spec.display)
            .unwrap_or(&spec.display)
            .to_string();
        let progress = progress_for(ctx, label, info.size);
        let cancel_rx = cancel.subscribe();
        let mode = info.mode;
        self.tasks.spawn(async move {
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
    }
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
            if !usable_local_name(name) {
                return Err(XferFailure::Local(
                    ErrorCode::InvalidArgument,
                    "file name is too long or malformed".to_string(),
                ));
            }
            (
                Arc::clone(dir),
                OsString::from(name),
                operand::join_local(display, name),
            )
        }
        LocalDst::File { dir, name, display } => {
            if !usable_local_name_os(name) {
                return Err(XferFailure::Local(
                    ErrorCode::InvalidArgument,
                    format!("{display}: not a usable file name on this platform"),
                ));
            }
            (Arc::clone(dir), name.clone(), display.clone())
        }
    };
    check_file_dest(&dir, &name, ctx.no_clobber)?;
    Ok((dir, name, display))
}

/// What a get may do with the name it is about to write: nothing exists
/// there, or a regular file does and may be replaced (decision 7).
fn check_file_dest(dir: &File, name: &OsString, no_clobber: bool) -> Result<(), XferFailure> {
    match local::stat_at(dir, name).map_err(|e| local_io_failure(&e))? {
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
            FsKind::Regular if no_clobber => Err(XferFailure::Exists),
            FsKind::Regular => Ok(()),
        },
        None => Ok(()),
    }
}

/// The local side of a top-level get source, for an item that failed before
/// it had a destination of its own.
fn top_local_display(ctx: &Ctx, src: &str) -> String {
    match &ctx.local {
        Some(LocalDst::File { display, .. }) => display.clone(),
        Some(LocalDst::Dir { display, .. }) => match operand::source_name(src) {
            Some(name) => operand::join_local(display, name),
            None => display.clone(),
        },
        None => String::new(),
    }
}

/// One file to fetch.
struct GetFile {
    /// The path on the wire.
    remote: String,
    /// The directory it lands in.
    dir: Arc<File>,
    /// Its final name there (one validated component).
    name: OsString,
    /// The local path as shown.
    display: String,
}

impl Run<'_> {
    async fn get_top(&mut self, src: &str) {
        let meta = ItemMeta::file(src.to_string(), top_local_display(self.ctx, src));
        match get_target(self.ctx, src) {
            Ok((dir, name, display)) => {
                self.get_file(GetFile {
                    remote: src.to_string(),
                    dir,
                    name,
                    display,
                })
                .await;
            }
            Err(failure) => self.fail(&meta, failure),
        }
    }

    async fn get_file(&mut self, spec: GetFile) {
        let ctx = self.ctx;
        let cancel = self.cancel;
        let meta = ItemMeta::file(spec.remote.clone(), spec.display.clone());
        let opened = loop {
            let attempt =
                control(cancel, self.session.file_read_open(&spec.remote, &ctx.user)).await;
            match attempt {
                Err(failure) if is_quota_refusal(&failure) && !self.tasks.is_empty() => {
                    self.join_one().await;
                }
                other => break other,
            }
        };
        let opened = match opened {
            Ok(opened) => opened,
            Err(failure) => return self.fail(&meta, failure),
        };
        let conduit = match control(
            cancel,
            self.session
                .file_conduit(opened.ticket.clone(), Some("file.read")),
        )
        .await
        {
            Ok(conduit) => conduit,
            Err(failure) => return self.fail(&meta, failure),
        };
        let label = spec.name.to_string_lossy().into_owned();
        let progress = progress_for(ctx, label, opened.size);
        let cancel_rx = cancel.subscribe();
        let dest = DownloadDest {
            dir: spec.dir,
            name: spec.name,
            overwrite: !ctx.no_clobber,
            preserve: ctx.preserve,
        };
        self.tasks.spawn(async move {
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
    }
}
