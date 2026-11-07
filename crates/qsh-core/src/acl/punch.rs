//! The `host.punch` choke point (ADR-0054 결정 6).
//!
//! Hole punching makes the rendezvous (R) keep signaling state and the
//! target (B) open a server window and send datagrams, so both decide **before
//! creating anything**. [`check_punch`] is that decision as one function: the
//! later steps (R's `PunchRequest` service, B's `PunchOffer` and
//! `RendezvousQuery` handling) call it first and build nothing until it
//! returns `Ok`.
//!
//! These three ops are deliberately not [`super::Op`] rows. `Op` and
//! [`super::DENY_SEAMS`] list seams that exist on the wire today, and each row
//! there is tied to a CLI.md §2.5 line and a uniformity driver. The punch
//! seams join them when the services land; until then [`PUNCH_OPS`] is the one
//! list of their names, and `acl::registry`'s coverage test counts
//! [`Action::HostPunch`] through it.

use qsh_proto::ErrorCode;

use crate::audit::{AuditRecord, AuditSink};
use crate::ops::OpError;

use super::{Action, Authorizer, Decision, PERMISSION_DENIED_MESSAGE, Requester, ResourceRef};

/// Which punch seam is deciding. The name is what the audit record's
/// `resource` carries; the `action` is always `host.punch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PunchOp {
    /// R received a `PunchRequest` from the initiator (A).
    Request,
    /// B received a `PunchOffer` (relayed by R) naming the initiator (A).
    Offer,
    /// B received a `RendezvousQuery` from the asking connection.
    Rendezvous,
}

/// Every punch seam, in a stable order.
pub const PUNCH_OPS: [PunchOp; 3] = [PunchOp::Request, PunchOp::Offer, PunchOp::Rendezvous];

impl PunchOp {
    /// The op name written to the audit record (`punch.request`,
    /// `punch.offer`, `punch.rendezvous`).
    pub const fn as_str(self) -> &'static str {
        match self {
            PunchOp::Request => "punch.request",
            PunchOp::Offer => "punch.offer",
            PunchOp::Rendezvous => "punch.rendezvous",
        }
    }

    /// The ACL action every punch seam authorizes against.
    pub const fn action(self) -> Action {
        Action::HostPunch
    }
}

/// Decide whether `requester` may punch through this end, and record the
/// decision, before the caller creates any state.
///
/// * The verdict comes from [`Authorizer::check`] with
///   [`Action::HostPunch`], so the always-deny gate, `[[acl]]` rows, the pin's
///   role and its grants apply exactly as for every other action, and an
///   unparseable `acl.toml` denies it with the rest.
/// * The decision is audited whether it allows or denies. The record is
///   structural (`principal`, `host.punch`, the op name, `allow`/`deny`, the
///   rule index, the role) and holds no address.
/// * Fail-closed: an allow whose audit record could not be written is a deny.
///
/// Every refusal is the same `PERMISSION_DENIED` with the uniform message, so
/// the answer says nothing about whether a registration exists or which of
/// the three reasons (no grant, deny row, audit failure) applied.
pub fn check_punch(
    authorizer: &dyn Authorizer,
    audit: &dyn AuditSink,
    op: PunchOp,
    requester: &Requester<'_>,
) -> Result<(), OpError> {
    let verdict = authorizer.check(requester, op.action(), ResourceRef::unowned(op.as_str()));
    let recorded = audit.record(
        &AuditRecord::punch_signal(
            requester.principal,
            requester.auth_path,
            op.as_str(),
            verdict.decision,
            verdict.rule,
        )
        .with_verdict_role(verdict.role)
        .with_verdict_pin_grant(verdict.pin_grant),
    );
    if verdict.decision == Decision::Allow && recorded.is_ok() {
        Ok(())
    } else {
        Err(punch_denied())
    }
}

/// The uniform refusal: `PERMISSION_DENIED`, not retryable, the fixed message.
fn punch_denied() -> OpError {
    OpError::new(ErrorCode::PermissionDenied, PERMISSION_DENIED_MESSAGE).with_retryable(false)
}

#[cfg(test)]
mod tests;
