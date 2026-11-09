//! The `forward.jump` choke point (ADR-0056 decisions 18 and 19).
//!
//! A JUMP stream asks the middle peer to open a UDP socket toward the
//! `host:port` in its header. [`check_jump`] decides that **before the socket
//! or the channel exists** and records the decision. The caller turns
//! [`JumpVerdict::Denied`] into `PERMISSION_DENIED` and
//! [`JumpVerdict::AuditFailed`] into a refusal too: no durable record, no
//! channel.
//!
//! The audit record is structural: the request id, the principal, the action
//! `forward.jump`, the requested `host:port` as the resource (the same string
//! `forward.local` records), the decision and the rule. It has no field that
//! could hold a packet, a connection ID, a channel value or a resolved IP.

use std::net::SocketAddr;

use crate::audit::{AuditRecord, AuditSink};

use super::{Action, Authorizer, Decision, Requester, ResourceRef};

/// What [`check_jump`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpVerdict {
    /// Allowed and recorded: the caller may go on to the limits, the
    /// resolution and the socket.
    Allowed,
    /// The policy refused (`PERMISSION_DENIED`). A record says so.
    Denied,
    /// The policy allowed but the record could not be written: fail closed,
    /// no socket and no channel.
    AuditFailed,
}

/// Decide whether `requester` may jump through this host to `target`
/// (`host:port` exactly as the stream header carried it), and record the
/// decision, before the caller creates anything.
pub fn check_jump(
    authorizer: &dyn Authorizer,
    audit: &dyn AuditSink,
    request_id: u64,
    target: &str,
    requester: &Requester<'_>,
    peer_addr: SocketAddr,
) -> JumpVerdict {
    let action = Action::ForwardJump;
    let verdict = authorizer.check(requester, action, ResourceRef::unowned(target));
    let recorded = audit.record(
        &AuditRecord::now(
            request_id,
            requester.principal,
            requester.auth_path,
            action,
            target,
            verdict.decision,
            verdict.rule,
            peer_addr,
        )
        .with_verdict_role(verdict.role)
        .with_verdict_pin_grant(verdict.pin_grant),
    );
    match (verdict.decision, recorded.is_ok()) {
        (Decision::Deny, _) => JumpVerdict::Denied,
        (Decision::Allow, false) => JumpVerdict::AuditFailed,
        (Decision::Allow, true) => JumpVerdict::Allowed,
    }
}

#[cfg(test)]
mod tests;
