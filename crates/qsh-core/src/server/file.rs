//! The remote file ops' control-stream handlers (`docs/adr/0029-file-copy.md`
//! decisions 3 and 8).
//!
//! Decision 8 fixes the host order and an earlier stage that fails stops
//! every later one:
//!
//! 1. shape check and home resolution (this file; lexical, no audit, no
//!    filesystem access);
//! 2. the ACL: (a) is there any ground for this principal to get this file
//!    action at all ([`Authorizer::has_file_grant`]), (b) only then
//!    normalize the path, (c) [`Authorizer::check`] plus one audit line;
//! 3. the `user` hint (`UNSUPPORTED`);
//! 4. the state-path check against the protected set, with one more audit
//!    line on a refusal;
//! 5. the transfer quota (`file.read`/`file.write` only);
//! 6. open through directory fds and recheck the opened handle (protected
//!    set, evaluator re-call, protected inode, file kind), with one more
//!    audit line on a refusal;
//! 7. respond.
//!
//! Stages 2 to 7 live in `file_host.rs` (unix only; Windows answers
//! `UNSUPPORTED` at stage 1, ADR-0029 decision 23). Every refusal that is a
//! policy outcome (no ground, outside `paths`, normalization failure, state
//! path, recheck mismatch, protected inode, an `EACCES` from the OS) is the
//! same `PERMISSION_DENIED` reply, byte for byte.
//!
//! This build issues the `file.read`/`file.write` tickets and answers
//! `file.list` and `file.mkdir`. The `FILE_DATA` stream that would redeem a
//! ticket is not accepted yet, so a ticket only ever expires and releases
//! what it holds.

use super::*;
#[cfg(unix)]
use crate::acl::Op;
use crate::file::guard::{
    FileOp, FsNormalizer, Normalizer, ShapeError, serve_home_dir, shape_name_if_dir, shape_path,
};

/// The default normalizer when none was injected.
static FS_NORMALIZER: FsNormalizer = FsNormalizer;

/// One of the four file requests, borrowed from the decoded control message.
pub(super) enum FileRequest<'a> {
    Read(&'a wire::FileReadOpen),
    Write(&'a wire::FileWriteOpen),
    List(&'a wire::FileListOpen),
    Mkdir(&'a wire::FileMkdirOpen),
}

impl FileRequest<'_> {
    /// The registry row, which names the action.
    #[cfg(unix)]
    pub(super) fn op(&self) -> Op {
        match self {
            Self::Read(_) => Op::FileRead,
            Self::Write(_) => Op::FileWrite,
            Self::List(_) => Op::FileList,
            Self::Mkdir(_) => Op::FileMkdir,
        }
    }

    /// The path rule of the shape check.
    fn shape(&self) -> FileOp {
        match self {
            Self::Read(_) => FileOp::Read,
            Self::Write(_) => FileOp::Write,
            Self::List(_) => FileOp::List,
            Self::Mkdir(_) => FileOp::Mkdir,
        }
    }

    /// The request path exactly as sent (also the audit `resource`,
    /// ADR-0029 decision 4-7).
    pub(super) fn path(&self) -> &str {
        match self {
            Self::Read(r) => &r.path,
            Self::Write(r) => &r.path,
            Self::List(r) => &r.path,
            Self::Mkdir(r) => &r.path,
        }
    }

    /// The optional single-component name (empty when absent). Only the
    /// creating ops carry one.
    pub(super) fn name_if_dir(&self) -> &str {
        match self {
            Self::Write(r) => &r.name_if_dir,
            Self::Mkdir(r) => &r.name_if_dir,
            Self::Read(_) | Self::List(_) => "",
        }
    }

    /// The `user@` assertion (empty when absent).
    #[cfg(unix)]
    pub(super) fn user(&self) -> &str {
        match self {
            Self::Read(r) => &r.user,
            Self::Write(r) => &r.user,
            Self::List(r) => &r.user,
            Self::Mkdir(r) => &r.user,
        }
    }
}

impl Server {
    /// Inject the path normalizer the file ops use (ADR-0029 decision 6-2).
    /// Production never calls this and gets [`FsNormalizer`]; a test injects
    /// a [`crate::file::guard::CountingNormalizer`] to count calls. No-op past
    /// the first call, same discipline as [`Self::set_pairing`].
    pub fn set_path_normalizer(&self, normalizer: Arc<dyn Normalizer>) {
        let _ = self.path_normalizer.set(normalizer);
    }

    /// The normalizer the file ops use: the injected one, or the real
    /// filesystem normalizer.
    pub fn path_normalizer(&self) -> &dyn Normalizer {
        match self.path_normalizer.get() {
            Some(n) => n.as_ref(),
            None => &FS_NORMALIZER,
        }
    }

    /// Tell the file ops where qsh's own config, state and runtime
    /// directories and its audit file are, so the protected set can be
    /// resolved per request (ADR-0029 decision 5). Production
    /// (`crate::serve::host_runtime`) calls this once; without it every
    /// file request that passes the ACL is refused (fail closed: a host that
    /// cannot say what is protected protects everything). No-op past the
    /// first call and off unix.
    pub fn set_file_host(&self, paths: crate::config::Paths, audit: crate::config::AuditConfig) {
        #[cfg(unix)]
        let _ = self.file_host.set(FileHostConfig { paths, audit });
        #[cfg(not(unix))]
        let _ = (paths, audit);
    }

    /// One of the four file ops. Stage 1 failures are `INVALID_ARGUMENT` (or
    /// `UNSUPPORTED` where the platform has no path judgement) before any
    /// ACL decision, audit line or filesystem access; the rest of the
    /// pipeline is `file_host.rs`.
    pub(super) async fn handle_file_op(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: FileRequest<'_>,
    ) -> ControlMessage {
        // ---- stage 1: shape check and home resolution (lexical only). ----
        let shaped = match shape_path(
            req.path().as_bytes(),
            req.shape(),
            serve_home_dir().as_deref(),
        ) {
            Ok(shaped) => shaped,
            Err(e) => return shape_error(request_id, e),
        };
        if req.shape().creates()
            && !req.name_if_dir().is_empty()
            && let Err(e) = shape_name_if_dir(req.name_if_dir().as_bytes())
        {
            return shape_error(request_id, e);
        }

        #[cfg(unix)]
        {
            self.file_op_after_shape(ctx, request_id, &req, shaped)
                .await
        }
        #[cfg(not(unix))]
        {
            // `shape_path` already answered `UNSUPPORTED`; this is the same
            // answer for a compiler that cannot see that.
            let _ = (ctx, shaped);
            shape_error(request_id, ShapeError::Unsupported)
        }
    }
}

pub(super) fn shape_error(request_id: u64, err: ShapeError) -> ControlMessage {
    let code = match err {
        ShapeError::Unsupported => ErrorCode::Unsupported,
        _ => ErrorCode::InvalidArgument,
    };
    // `ShapeError`'s text names the rule, never the path.
    ControlMessage::error(request_id, wire::Error::new(code, err.to_string(), false))
}
