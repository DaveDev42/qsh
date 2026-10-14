//! `file.copy`: the client-side synthetic operation behind `qsh cp`
//! (`docs/adr/0029-file-copy.md`, `docs/CLI.md` §6.21).
//!
//! It has no wire message of its own. It reads the operand list (decision
//! 2), resolves the host like `exec.run` does, and strings the wire ops
//! `file.read` and `file.write` together, two transfers at a time
//! ([`FILE_COPY_PARALLEL`]). A single connection carries every transfer, on
//! the forward route or through the `qsh listen` daemon's relay.
//!
//! Everything about one item that goes wrong stays with that item (decision
//! 21): it is reported and the copy goes on. A lost connection, a missing
//! capability or Ctrl-C ends the copy, and the items never tried are
//! counted.

use std::sync::Arc;

use qsh_proto::{FileCopyData, FileCopyEntry, FileCopyReq};
use tokio::sync::watch;

use crate::ops::{OpError, Operation, Ops};

#[cfg(unix)]
mod copy;

/// How many transfers one `file.copy` runs at the same time (ADR-0029
/// decision 15's parallelism: enough to hide a round trip between files,
/// few enough that a copy never fills a host's per-principal transfer
/// quota of 4 on its own).
pub const FILE_COPY_PARALLEL: usize = 2;

/// The `file.copy` operation.
pub struct FileCopyOp;

impl Operation for FileCopyOp {
    const COMMAND: &'static str = "file.copy";
}

/// Progress of the file being transferred.
#[derive(Debug, Clone)]
pub struct FileProgress {
    /// The file's name as the person knows it (the source's last
    /// component).
    pub name: String,
    /// Bytes moved so far.
    pub bytes: u64,
    /// The file's size as announced at open (advisory).
    pub total: u64,
}

/// What a frontend hears while a copy runs. Called from the copy's own
/// tasks, so implementations must be cheap and thread-safe. Machine
/// consumers get their `--jsonl` lines from [`Self::entry`].
pub trait FileCopyObserver: Send + Sync {
    /// A file moved more bytes. Called per chunk: a renderer throttles
    /// itself.
    fn progress(&self, _progress: &FileProgress) {}

    /// An item finished (copied, created, skipped or failed), in the order
    /// items finish.
    fn entry(&self, _entry: &FileCopyEntry) {}
}

/// An observer that hears nothing.
pub struct SilentObserver;

impl FileCopyObserver for SilentObserver {}

/// Cooperative cancellation of a running copy (Ctrl-C, decision 11). Clones
/// share one flag. A canceled copy resets its in-flight streams, removes
/// their temp files, tries nothing further and ends with `CANCELED`.
#[derive(Clone)]
pub struct CancelToken {
    tx: Arc<watch::Sender<bool>>,
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelToken {
    /// A token that has not been canceled.
    pub fn new() -> Self {
        Self {
            tx: Arc::new(watch::channel(false).0),
        }
    }

    /// Cancel the copy. Idempotent.
    pub fn cancel(&self) {
        self.tx.send_replace(true);
    }

    /// Whether [`Self::cancel`] was called.
    pub fn is_canceled(&self) -> bool {
        *self.tx.borrow()
    }

    /// A receiver the transfers watch.
    #[cfg(unix)]
    pub(crate) fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// Resolves once canceled.
    #[cfg(unix)]
    pub(crate) async fn canceled(&self) {
        let mut rx = self.tx.subscribe();
        loop {
            if *rx.borrow() {
                return;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// How a `file.copy` failed.
#[derive(Debug, Clone, PartialEq)]
pub struct FileCopyError {
    /// The error for the envelope. For a copy that started, `details` is a
    /// `FileCopyErrorDetails` (decision 21).
    pub error: OpError,
    /// A malformed command line: the frontend answers with exit `2`
    /// (`docs/CLI.md` §4) and nothing was changed.
    pub usage: bool,
}

impl FileCopyError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            error: OpError::new(qsh_proto::ErrorCode::InvalidArgument, message),
            usage: true,
        }
    }

    pub(crate) fn plain(error: OpError) -> Self {
        Self {
            error,
            usage: false,
        }
    }
}

impl From<OpError> for FileCopyError {
    fn from(error: OpError) -> Self {
        Self::plain(error)
    }
}

/// [`Ops::file_copy`] over a [`Session`](crate::client::Session) the caller
/// already holds, instead of one it dials. The session may carry other
/// streams (a PTY attach, tunnels): the acceptance harness
/// `file_copy_echo_under_load` uses this to measure echo latency while a copy
/// shares the connection. The host name in the operands is not resolved;
/// the copy goes over `session` whatever it says. Unix only.
#[cfg(unix)]
pub async fn file_copy_over(
    session: &mut crate::client::Session,
    req: &FileCopyReq,
    observer: Arc<dyn FileCopyObserver>,
    cancel: &CancelToken,
) -> Result<FileCopyData, FileCopyError> {
    let plan = crate::file::operand::plan(req).map_err(|e| FileCopyError::usage(e.message))?;
    if req.recursive {
        return Err(FileCopyError::plain(OpError::new(
            qsh_proto::ErrorCode::Unsupported,
            "recursive copy (-r) is not available in this build",
        )));
    }
    copy::file_copy_on(session, plan, req, observer, cancel).await
}

impl Ops {
    /// Copy files between this machine and one qsh host: the whole of
    /// `qsh cp` (`docs/CLI.md` §6.21). Blocking, on `Ops`' shared dial
    /// runtime like every other remote op.
    ///
    /// Operand and flag errors come back with the `usage` field of [`FileCopyError`] set
    /// before anything is resolved or dialed. Every other failure of an
    /// item, or of the copy, carries the decision-21 `details`.
    pub fn file_copy(
        &self,
        req: FileCopyReq,
        observer: Arc<dyn FileCopyObserver>,
        cancel: &CancelToken,
    ) -> Result<FileCopyData, FileCopyError> {
        let plan = crate::file::operand::plan(&req).map_err(|e| FileCopyError::usage(e.message))?;
        if req.recursive {
            return Err(FileCopyError::plain(OpError::new(
                qsh_proto::ErrorCode::Unsupported,
                "recursive copy (-r) is not available in this build",
            )));
        }
        self.file_copy_planned(plan, &req, observer, cancel)
    }

    #[cfg(unix)]
    fn file_copy_planned(
        &self,
        plan: crate::file::operand::CopyPlan,
        req: &FileCopyReq,
        observer: Arc<dyn FileCopyObserver>,
        cancel: &CancelToken,
    ) -> Result<FileCopyData, FileCopyError> {
        copy::file_copy(self, plan, req, observer, cancel)
    }

    #[cfg(not(unix))]
    fn file_copy_planned(
        &self,
        _plan: crate::file::operand::CopyPlan,
        _req: &FileCopyReq,
        _observer: Arc<dyn FileCopyObserver>,
        _cancel: &CancelToken,
    ) -> Result<FileCopyData, FileCopyError> {
        Err(FileCopyError::plain(OpError::new(
            qsh_proto::ErrorCode::Unsupported,
            "qsh cp is not available on this platform yet (ADR-0035 decision 1)",
        )))
    }
}
