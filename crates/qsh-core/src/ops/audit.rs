//! `audit.query` (`docs/CLI.md` §6.22, ADR-0033 결정 4~10) - the local,
//! authorization-free operation that reads this machine's own audit log
//! back in the `qsh.cli/v1` shape.
//!
//! **Local by construction** (ADR-0033 결정 4, `docs/CLI.md` §2.5's "인가 불요"
//! row). Nothing here is reachable from a remote peer: there is no
//! `qsh-proto` frame variant for it, no localctl request, and no ACL action,
//! so a peer cannot enumerate principals or denial history through it. The
//! caller already needs the same account that can read the file; this op
//! only hands that content back in a contracted shape.
//!
//! **Read only, and silent** (결정 7, 10). The op reads through
//! [`crate::audit::reader::query`], which opens every file read-only and has
//! no delete, truncate or rewrite path. It builds no [`crate::audit::AuditSink`]
//! and writes no audit record, so it works while the audit writer is latched
//! degraded and repeating a query never grows the log it reads.
//!
//! **Which file.** `[audit].path` and `[audit].retain` of the loaded
//! `config.toml`, the same values the writer in `qsh serve` and `qsh listen`
//! uses. A `config.toml` that does not parse is the existing `CONFIG_ERROR`:
//! guessing the default path would read the wrong file on a host that moved
//! its log.

use std::time::SystemTime;

use qsh_proto::{AuditQueryData, AuditQueryReq};

use crate::audit::reader;
use crate::ops::{OpError, Operation, Ops};

/// The `audit.query` operation (`qsh audit`, `docs/CLI.md` §6.22).
pub struct AuditQueryOp;

impl Operation for AuditQueryOp {
    const COMMAND: &'static str = "audit.query";
}

impl Ops {
    /// `audit.query` (`qsh audit`): the records of this machine's audit log
    /// that match `req`, newest first, with the skipped-line count, the
    /// retention horizon (`oldest_ts`) and whether `limit` cut the result.
    ///
    /// A missing log is an empty result, an unreadable one is `INTERNAL`
    /// naming the path and error kind, a bad `limit`, `decision`, `since` or
    /// `until` is `INVALID_ARGUMENT`, and an unusable `config.toml` is
    /// `CONFIG_ERROR`.
    pub fn audit_query(&self, req: AuditQueryReq) -> Result<AuditQueryData, OpError> {
        self.audit_query_at(&req, SystemTime::now())
    }

    /// [`Self::audit_query`] with the clock a relative `since` counts back
    /// from supplied by the caller, so tests stay deterministic.
    pub fn audit_query_at(
        &self,
        req: &AuditQueryReq,
        now: SystemTime,
    ) -> Result<AuditQueryData, OpError> {
        let config = self.config()?;
        let path = config.audit.path(self.paths());
        reader::query(&path, config.audit.retain(), req, now)
    }
}

#[cfg(test)]
mod tests;
