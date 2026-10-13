//! The remote file ops' control-stream handlers (`docs/adr/0029-file-copy.md`
//! decisions 3 and 8).
//!
//! Decision 8 fixes the host order: (1) shape check and home resolution,
//! (2) ACL, (3) user hint, (4) state path, (5) quota, (6) open and recheck,
//! (7) respond. This build runs stage 1 and the `Authorizer::check` half of
//! stage 2 only. [`Action::is_always_denied`] still denies `file.read` and
//! `file.write` at the gate (ADR-0029 decision 8, ADR-0045 decision 5), so
//! every well-formed request ends in `PERMISSION_DENIED` plus one audit line,
//! and nothing that follows the decision exists yet: no grant-basis check, no
//! path normalization, no filesystem access, no ticket, no stream. The
//! injectable [`Normalizer`] ([`Server::set_path_normalizer`]) is the seam the
//! grant-basis stage will call, and the pin
//! `file_ops_are_denied_without_normalizing_or_touching_the_filesystem` holds
//! its call count at zero until then.

use super::*;
use crate::acl::Op;
use crate::file::guard::{
    FileOp, FsNormalizer, Normalizer, ShapeError, serve_home_dir, shape_name_if_dir, shape_path,
};

/// The default normalizer when none was injected.
static FS_NORMALIZER: FsNormalizer = FsNormalizer;

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

    /// One of the four file ops: `op` names the registry row (and so the
    /// action), `shape` the path rule, `path` is the request path exactly as
    /// sent (it is also the audit `resource`, ADR-0029 decision 4-7), and
    /// `name_if_dir` is the optional single-component name (empty when
    /// absent).
    ///
    /// Stage 1 failures are `INVALID_ARGUMENT` (or `UNSUPPORTED` where the
    /// platform has no path judgement) before any ACL decision, audit line or
    /// filesystem access. Stage 2 then asks the authorizer; today the answer
    /// is always a denial (module doc).
    pub(super) fn handle_file_op(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        op: Op,
        shape: FileOp,
        path: &str,
        name_if_dir: &str,
    ) -> ControlMessage {
        // ---- stage 1: shape check and home resolution (lexical only). ----
        if let Err(e) = shape_path(path.as_bytes(), shape, serve_home_dir().as_deref()) {
            return shape_error(request_id, e);
        }
        if shape.creates()
            && !name_if_dir.is_empty()
            && let Err(e) = shape_name_if_dir(name_if_dir.as_bytes())
        {
            return shape_error(request_id, e);
        }

        // ---- stage 2: ACL choke point, decide + audit. ----
        if let Err(denied) = self.authorize(ctx, request_id, op.action(), path) {
            return *denied;
        }

        // An allow needs `Action::is_always_denied` to stop covering the file
        // actions, which lands with the host control plane. Until then this
        // is unreachable; if it is ever reached early, refuse rather than
        // act: nothing past the decision exists in this build.
        ControlMessage::error(
            request_id,
            wire::Error::new(
                ErrorCode::Unsupported,
                "remote file operations are not available on this host",
                false,
            ),
        )
    }
}

fn shape_error(request_id: u64, err: ShapeError) -> ControlMessage {
    let code = match err {
        ShapeError::Unsupported => ErrorCode::Unsupported,
        _ => ErrorCode::InvalidArgument,
    };
    // `ShapeError`'s text names the rule, never the path.
    ControlMessage::error(request_id, wire::Error::new(code, err.to_string(), false))
}
