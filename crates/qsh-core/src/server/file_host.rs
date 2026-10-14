//! Stages 2 to 7 of the remote file ops (`docs/adr/0029-file-copy.md`
//! decision 8), unix only. `file.rs` documents the order; this file is the
//! implementation, composed from the pure pieces in `crate::file::guard` and
//! `crate::file::host`.
//!
//! What a refusal looks like from outside: the ACL (no ground, outside
//! `paths`, normalization failure), the state-path check, the opened-handle
//! recheck, a protected inode, an inode scan that could not finish and an OS
//! `EACCES` all answer the same `PERMISSION_DENIED` reply. The state-path,
//! recheck and protected-inode refusals add one audit line after the ACL's
//! own (`decision = "deny"`, no rule, no role).

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use qsh_proto::wire::{FILE_LIST_DIR_MAX, FILE_LIST_PAGE_MAX};

use super::file::FileRequest;
use super::*;
use crate::acl::ResourceRef;
use crate::file::guard::{
    self, NormalizeError, ProtectedInodes, ProtectedSet, ReadTargetDenied, ShapedPath,
};
use crate::file::host::{self, FsKind, ListError, MkdirOutcome, StatInfo};
use crate::quota::FilePermit;

/// What one request carries from stage to stage.
struct Stage<'a> {
    ctx: &'a ConnCtx,
    request_id: u64,
    action: Action,
    /// The request path as sent: the audit `resource` and the evaluator's
    /// resource id.
    request_path: &'a str,
    protected: ProtectedSet,
    canonical: PathBuf,
    /// The request ended in `/`.
    must_be_dir: bool,
}

/// The directory a creating op acts in, opened and rechecked, and the one
/// name inside it.
struct Target {
    dir: File,
    name: std::ffi::OsString,
    /// `path` was an existing directory and the target is `name_if_dir`
    /// inside it (ADR-0029 decision 20).
    into_dir: bool,
}

impl Server {
    pub(super) async fn file_op_after_shape(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &FileRequest<'_>,
        shaped: ShapedPath,
    ) -> ControlMessage {
        let action = req.op().action();
        let request_path = req.path();
        let normalizer = self.path_normalizer();

        // ---- stage 2: ACL. (a) is there any ground for this action at all?
        // Only then (b) look at the path, and (c) decide + audit. A
        // principal with no ground never makes the host touch a path. ----
        let requester = ctx.requester();
        let normalized: Option<Result<PathBuf, NormalizeError>> = self
            .authorizer
            .has_file_grant(&requester, action)
            .then(|| normalizer.normalize(&shaped.absolute));
        let canonical_for_acl: Option<&Path> = match &normalized {
            Some(Ok(path)) => Some(path.as_path()),
            _ => None,
        };
        let mut resource = ResourceRef::unowned(request_path);
        if let Some(path) = canonical_for_acl {
            resource = resource.with_canonical_path(path, normalizer);
        }
        if let Err(denied) = self.authorize_owned(ctx, request_id, action, resource) {
            return *denied;
        }

        // ---- stage 3: `user@` hint, only after an allow so an
        // unauthorized peer never learns the serve account's name. ----
        if !req.user().is_empty() && !user_hint_matches(req.user()) {
            return ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "user switching is not supported: file operations run as the qsh serve account",
                    false,
                ),
            );
        }

        // ---- stage 4: state paths. A role-only allow may not have been
        // normalized yet; this is where it is. Whatever cannot be resolved,
        // or lands in the protected set, ends here. ----
        let Some(host_cfg) = self.file_host.get() else {
            return self.deny_file(ctx, request_id, action, request_path);
        };
        let canonical = match normalized {
            Some(Ok(path)) => path,
            Some(Err(_)) => return self.deny_file(ctx, request_id, action, request_path),
            None => match normalizer.normalize(&shaped.absolute) {
                Ok(path) => path,
                Err(_) => return self.deny_file(ctx, request_id, action, request_path),
            },
        };
        let protected = ProtectedSet::for_process(&host_cfg.paths, &host_cfg.audit, normalizer);
        let name_if_dir = req.name_if_dir();
        if protected.denies(&canonical)
            || (!name_if_dir.is_empty() && protected.denies(&canonical.join(name_if_dir)))
        {
            return self.deny_file(ctx, request_id, action, request_path);
        }
        let st = Stage {
            ctx,
            request_id,
            action,
            request_path,
            protected,
            canonical,
            must_be_dir: shaped.must_be_dir,
        };

        // ---- stages 5 to 7: the transfer quota (`file.read` and
        // `file.write` only), then open, recheck, respond. The quota comes
        // after the ACL and the state-path check and before anything is
        // opened: an unauthorized principal sees PERMISSION_DENIED, never a
        // quota oracle. ----
        match req {
            FileRequest::Read(_) => match self.reserve_file_permit(ctx, request_id) {
                Ok(permit) => self.file_read(&st, permit).await,
                Err(reply) => *reply,
            },
            FileRequest::Write(r) => match self.reserve_file_permit(ctx, request_id) {
                Ok(permit) => self.file_write(&st, r, permit),
                Err(reply) => *reply,
            },
            FileRequest::List(r) => self.file_list(&st, r).await,
            FileRequest::Mkdir(r) => self.file_mkdir(&st, r),
        }
    }

    /// The refusal for everything that is a policy outcome after the ACL
    /// allowed: one more audit line (`deny`, no rule, no role) and the
    /// uniform reply.
    fn deny_file(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        resource: &str,
    ) -> ControlMessage {
        let _ = self.audit.record(&AuditRecord::now(
            request_id,
            &ctx.principal,
            ctx.auth_path,
            action,
            resource,
            Decision::Deny,
            None,
            ctx.peer_addr,
        ));
        Self::permission_denied(request_id, action)
    }

    fn deny(&self, st: &Stage<'_>) -> ControlMessage {
        self.deny_file(st.ctx, st.request_id, st.action, st.request_path)
    }

    /// `file.read`/`file.write`'s transfer slot: the connection's ticket
    /// budget, then the quota (ADR-0029 decision 12).
    fn reserve_file_permit(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
    ) -> Result<FilePermit, Box<ControlMessage>> {
        self.check_ticket_budget(ctx, request_id)?;
        let opener = opener_key(&ctx.principal, ctx.auth_path);
        self.quotas.reserve_file_transfer(&opener).map_err(|kind| {
            let records = self.quotas.record_rejection(
                kind,
                &opener,
                ctx.peer_addr,
                self.quotas.now(),
                Some(request_id),
                ctx.auth_path,
            );
            crate::audit::write_quota_audit(self.audit.as_ref(), &records);
            Box::new(broker_error(request_id, BrokerError::QuotaExceeded(kind)))
        })
    }

    /// The opened-handle recheck of ADR-0029 decision 6-4: the path `fd`
    /// really points at must not be protected and the evaluator, called
    /// again for it, must still allow. `child` is the one name the op acts
    /// on inside a directory fd; it is held to the protected set too. When
    /// `eval_child` the evaluator sees `fd path / child` (the request named
    /// the child), otherwise the fd path itself (the request named the
    /// directory).
    fn recheck(&self, st: &Stage<'_>, fd: &File, child: Option<&OsStr>, eval_child: bool) -> bool {
        let normalizer = self.path_normalizer();
        guard::recheck_handle(fd, &st.protected, |path| {
            if let Some(child) = child
                && st.protected.denies(&path.join(child))
            {
                return false;
            }
            let target = match child {
                Some(child) if eval_child => path.join(child),
                _ => path.to_path_buf(),
            };
            self.authorizer
                .check(
                    &st.ctx.requester(),
                    st.action,
                    ResourceRef::unowned(st.request_path).with_canonical_path(&target, normalizer),
                )
                .is_allow()
        })
        .is_ok()
    }

    /// Map an OS error to the wire. `ENOENT` is the one thing that is the
    /// caller's mistake (`INVALID_ARGUMENT`, only reachable past the ACL and
    /// the state-path check); `EACCES`/`EPERM` and the errors a swapped path
    /// component produces are the uniform denial (ADR-0029 decision 17).
    fn io_reply(&self, st: &Stage<'_>, err: &io::Error) -> ControlMessage {
        match err.raw_os_error() {
            Some(libc::ENOENT) => invalid(st.request_id, "no such file or directory"),
            Some(libc::EACCES | libc::EPERM | libc::ELOOP | libc::ENOTDIR) => {
                Self::permission_denied(st.request_id, st.action)
            }
            Some(libc::ENOSPC | libc::EDQUOT) => ControlMessage::error(
                st.request_id,
                wire::Error::new(ErrorCode::ResourceExhausted, "no space left", false),
            ),
            _ => {
                tracing::debug!(kind = ?err.kind(), "file operation failed");
                ControlMessage::error(
                    st.request_id,
                    wire::Error::new(ErrorCode::Internal, "file operation failed", false),
                )
            }
        }
    }

    // ------------------------------------------------------------------
    // file.read
    // ------------------------------------------------------------------

    async fn file_read(&self, st: &Stage<'_>, permit: FilePermit) -> ControlMessage {
        let file = match guard::open_read_nofollow(&st.canonical) {
            Ok(file) => file,
            Err(e) => return self.io_reply(st, &e),
        };
        if !self.recheck(st, &file, None, false) {
            return self.deny(st);
        }
        // A scan that cannot finish (the protected tree is bigger or deeper
        // than the limits, an entry cannot be inspected) refuses the read
        // with the same reply: it would be ambiguous whether the file is a
        // hard link into the state tree (threat-model section 7).
        // The scan walks up to `INODE_SCAN_MAX_ENTRIES` entries, so it runs
        // off the async worker like the directory listing.
        let protected = st.protected.clone();
        let Ok(Ok(inodes)) =
            tokio::task::spawn_blocking(move || ProtectedInodes::collect(&protected)).await
        else {
            return self.deny(st);
        };
        if let Err(denied) = guard::check_read_target(&file, &inodes) {
            return match denied {
                ReadTargetDenied::NotRegular(_) => {
                    invalid(st.request_id, "path is not a regular file")
                }
                _ => self.deny(st),
            };
        }
        if st.must_be_dir {
            return invalid(st.request_id, "path is not a directory");
        }
        let info = match host::fstat(&file) {
            Ok(info) => info,
            Err(e) => return self.io_reply(st, &e),
        };
        let ticket = self.issue_ticket(
            st.ctx.conn_id,
            TicketPurpose::File(PendingFile {
                op: PendingFileOp::Read {
                    file,
                    size: info.size,
                },
                permit,
            }),
        );
        ControlMessage::response(
            st.request_id,
            response::Body::FileReadOpened(wire::FileReadOpened {
                ticket: ticket.to_vec(),
                size: info.size,
                mode: info.mode,
                mtime: info.mtime,
            }),
        )
    }

    // ------------------------------------------------------------------
    // file.write and file.mkdir share the directory resolution
    // ------------------------------------------------------------------

    /// Open the directory a creating op acts in (ADR-0029 decisions 6-4 and
    /// 20) and recheck it. The path's parent is opened `O_DIRECTORY |
    /// O_NOFOLLOW`; if the path is itself an existing directory and the
    /// request carries a `name_if_dir`, that directory is opened instead and
    /// the target is the name inside it. Nothing is created here.
    #[allow(clippy::result_large_err)]
    fn open_target(&self, st: &Stage<'_>, name_if_dir: &str) -> Result<Target, ControlMessage> {
        let into_name = (!name_if_dir.is_empty()).then(|| std::ffi::OsString::from(name_if_dir));
        let Some(final_name) = st.canonical.file_name() else {
            // The root: it is a directory and has no parent to open.
            let dir = guard::open_dir_nofollow(&st.canonical).map_err(|e| self.io_reply(st, &e))?;
            let Some(name) = into_name else {
                return Err(invalid(st.request_id, "destination is a directory"));
            };
            if !self.recheck(st, &dir, Some(&name), false) {
                return Err(self.deny(st));
            }
            return Ok(Target {
                dir,
                name,
                into_dir: true,
            });
        };
        let parent_path = st.canonical.parent().unwrap_or(&st.canonical);
        let parent = guard::open_dir_nofollow(parent_path).map_err(|e| self.io_reply(st, &e))?;
        let existing = host::stat_at(&parent, final_name).map_err(|e| self.io_reply(st, &e))?;
        let is_dir = matches!(
            existing,
            Some(StatInfo {
                kind: FsKind::Directory,
                ..
            })
        );
        if let (true, Some(name)) = (is_dir, into_name) {
            let dir = host::open_dir_at(&parent, final_name).map_err(|e| self.io_reply(st, &e))?;
            if !self.recheck(st, &dir, Some(&name), false) {
                return Err(self.deny(st));
            }
            return Ok(Target {
                dir,
                name,
                into_dir: true,
            });
        }
        if !self.recheck(st, &parent, Some(final_name), true) {
            return Err(self.deny(st));
        }
        Ok(Target {
            dir: parent,
            name: final_name.to_os_string(),
            into_dir: false,
        })
    }

    // ------------------------------------------------------------------
    // file.write
    // ------------------------------------------------------------------

    fn file_write(
        &self,
        st: &Stage<'_>,
        req: &wire::FileWriteOpen,
        permit: FilePermit,
    ) -> ControlMessage {
        let target = match self.open_target(st, &req.name_if_dir) {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        let existing = match host::stat_at(&target.dir, &target.name) {
            Ok(existing) => existing,
            Err(e) => return self.io_reply(st, &e),
        };
        let existed = match existing {
            None => false,
            Some(StatInfo {
                kind: FsKind::Regular,
                ..
            }) => {
                if !req.overwrite {
                    return invalid(st.request_id, "destination exists");
                }
                true
            }
            Some(StatInfo {
                kind: FsKind::Directory,
                ..
            }) => return invalid(st.request_id, "destination is a directory"),
            Some(_) => return invalid(st.request_id, "destination is not a regular file"),
        };
        if st.must_be_dir && !target.into_dir {
            return invalid(st.request_id, "path is not a directory");
        }
        // ADR-0029 decision 13's free-space check (`statvfs`) belongs here,
        // between the destination checks and the ticket. It lands with the
        // data plane, which owns the reserve constant and the injectable
        // `statvfs`.
        let ticket = self.issue_ticket(
            st.ctx.conn_id,
            TicketPurpose::File(PendingFile {
                op: PendingFileOp::Write {
                    dir: target.dir,
                    name: target.name,
                    size: req.size,
                    mode: req.mode & 0o777,
                    overwrite: req.overwrite,
                    preserve: req.preserve,
                    mtime: req.mtime,
                    existed,
                },
                permit,
            }),
        );
        ControlMessage::response(
            st.request_id,
            response::Body::FileWriteOpened(wire::FileWriteOpened {
                ticket: ticket.to_vec(),
                into_dir: target.into_dir,
            }),
        )
    }

    // ------------------------------------------------------------------
    // file.mkdir
    // ------------------------------------------------------------------

    fn file_mkdir(&self, st: &Stage<'_>, req: &wire::FileMkdirOpen) -> ControlMessage {
        let target = match self.open_target(st, &req.name_if_dir) {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        // Stages 3 to 5 and the recheck are behind us: only now is a
        // directory made.
        let outcome = match host::mkdir_at(&target.dir, &target.name, req.mode, req.preserve) {
            Ok(outcome) => outcome,
            Err(e) => return self.io_reply(st, &e),
        };
        match outcome {
            MkdirOutcome::Created | MkdirOutcome::Existed => ControlMessage::response(
                st.request_id,
                response::Body::FileMkdirDone(wire::FileMkdirDone {
                    created: outcome == MkdirOutcome::Created,
                    into_dir: target.into_dir,
                }),
            ),
            MkdirOutcome::ExistsNotDirectory => {
                invalid(st.request_id, "a file with that name exists")
            }
        }
    }

    // ------------------------------------------------------------------
    // file.list
    // ------------------------------------------------------------------

    async fn file_list(&self, st: &Stage<'_>, req: &wire::FileListOpen) -> ControlMessage {
        match guard::open_dir_nofollow(&st.canonical) {
            Ok(dir) => {
                if !self.recheck(st, &dir, None, false) {
                    return self.deny(st);
                }
                let info = match host::fstat(&dir) {
                    Ok(info) => info,
                    Err(e) => return self.io_reply(st, &e),
                };
                let after = req.after.clone().into_bytes();
                // Bounded by `FILE_LIST_DIR_MAX`, but still a directory read
                // and a sort: off the async worker.
                let listing = tokio::task::spawn_blocking(move || {
                    host::list_dir(&dir, &after, FILE_LIST_PAGE_MAX, FILE_LIST_DIR_MAX)
                })
                .await;
                let listing = match listing {
                    Ok(Ok(listing)) => listing,
                    Ok(Err(ListError::TooManyEntries(_))) => {
                        return ControlMessage::error(
                            st.request_id,
                            wire::Error::new(
                                ErrorCode::ResourceExhausted,
                                "directory has too many entries",
                                false,
                            ),
                        );
                    }
                    Ok(Err(ListError::Io(kind))) => {
                        return self.io_reply(st, &io::Error::from(kind));
                    }
                    Err(_) => {
                        return ControlMessage::error(
                            st.request_id,
                            wire::Error::new(ErrorCode::Internal, "file operation failed", false),
                        );
                    }
                };
                ControlMessage::response(
                    st.request_id,
                    response::Body::FileListed(wire::FileListed {
                        kind: wire_kind(info.kind) as i32,
                        size: info.size,
                        mode: info.mode,
                        mtime: info.mtime,
                        entries: listing
                            .entries
                            .into_iter()
                            .map(|e| wire::FileEntry {
                                name: e.name,
                                kind: wire_kind(e.info.kind) as i32,
                                size: e.info.size,
                                mode: e.info.mode,
                                mtime: e.info.mtime,
                            })
                            .collect(),
                        more: listing.more,
                        unlistable: listing.unlistable,
                    }),
                )
            }
            // Not a directory (or a dangling link, which normalization does
            // not follow): report the object itself through its parent.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
                self.file_list_object(st)
            }
            Err(e) => self.io_reply(st, &e),
        }
    }

    /// `file.list` of something that is not a directory: its own facts, no
    /// entries.
    fn file_list_object(&self, st: &Stage<'_>) -> ControlMessage {
        let (Some(parent_path), Some(name)) = (st.canonical.parent(), st.canonical.file_name())
        else {
            return invalid(st.request_id, "no such file or directory");
        };
        let parent = match guard::open_dir_nofollow(parent_path) {
            Ok(parent) => parent,
            Err(e) => return self.io_reply(st, &e),
        };
        if !self.recheck(st, &parent, Some(name), true) {
            return self.deny(st);
        }
        let info = match host::stat_at(&parent, name) {
            Ok(Some(info)) => info,
            Ok(None) => return invalid(st.request_id, "no such file or directory"),
            Err(e) => return self.io_reply(st, &e),
        };
        if st.must_be_dir {
            return invalid(st.request_id, "path is not a directory");
        }
        ControlMessage::response(
            st.request_id,
            response::Body::FileListed(wire::FileListed {
                kind: wire_kind(info.kind) as i32,
                size: info.size,
                mode: info.mode,
                mtime: info.mtime,
                entries: Vec::new(),
                more: false,
                unlistable: 0,
            }),
        )
    }
}

fn wire_kind(kind: FsKind) -> wire::FileKind {
    match kind {
        FsKind::Regular => wire::FileKind::File,
        FsKind::Directory => wire::FileKind::Dir,
        FsKind::Symlink => wire::FileKind::Symlink,
        FsKind::Other => wire::FileKind::Other,
    }
}

fn invalid(request_id: u64, message: &str) -> ControlMessage {
    ControlMessage::error(
        request_id,
        wire::Error::new(ErrorCode::InvalidArgument, message, false),
    )
}
