//! The `forward.agent` choke point (ADR-0055 decisions 16 and 17).
//!
//! A request that carries an `agent_channel` makes the host create a socket
//! (or named pipe) for the session or exec. [`check_agent`] decides that
//! **before the socket exists**, after the request's own action was allowed.
//! Unlike every other choke point a refusal does not refuse the request: the
//! caller opens the session or exec without an agent and answers
//! `AGENT_GRANT_DENIED`, or `AGENT_GRANT_UNAVAILABLE` when the decision could
//! not be recorded. Agent forwarding is a convenience attached to a shell
//! whose own permission was judged separately.
//!
//! The audit record is structural: the request id, the principal, the action
//! `forward.agent`, the op name as the resource, the decision and the rule.
//! It has no field that could hold a socket path, a channel or an agent
//! message.

use qsh_transport::PeerAddr;

use crate::audit::{AuditRecord, AuditSink};

use super::{Action, Authorizer, Decision, Requester, ResourceRef};

/// Which request asked for the socket. The name is the audit record's
/// `resource`; the action is always `forward.agent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentOp {
    /// `SessionOpen` carried an `agent_channel`.
    SessionOpen,
    /// `SessionAttach` carried an `agent_channel`.
    SessionAttach,
    /// `ExecStart` carried an `agent_channel`.
    ExecRun,
}

/// Every request that can ask for an agent socket, in a stable order.
pub const AGENT_OPS: [AgentOp; 3] = [
    AgentOp::SessionOpen,
    AgentOp::SessionAttach,
    AgentOp::ExecRun,
];

impl AgentOp {
    /// The op name written to the audit record's `resource`.
    pub const fn as_str(self) -> &'static str {
        match self {
            AgentOp::SessionOpen => "session.open",
            AgentOp::SessionAttach => "session.attach",
            AgentOp::ExecRun => "exec.run",
        }
    }

    /// The ACL action every agent request authorizes against.
    pub const fn action(self) -> Action {
        Action::ForwardAgent
    }
}

/// What [`check_agent`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentVerdict {
    /// Allowed and recorded: the caller may create the socket.
    Allowed,
    /// The policy refused (`AGENT_GRANT_DENIED`). A record says so.
    Denied,
    /// The policy allowed but the record could not be written
    /// (`AGENT_GRANT_UNAVAILABLE`): fail closed, no socket.
    AuditFailed,
}

/// Decide whether `requester` may have an agent socket for `op`, and record
/// the decision, before the caller creates anything.
pub fn check_agent(
    authorizer: &dyn Authorizer,
    audit: &dyn AuditSink,
    request_id: u64,
    op: AgentOp,
    requester: &Requester<'_>,
    peer_addr: &PeerAddr,
) -> AgentVerdict {
    let verdict = authorizer.check(requester, op.action(), ResourceRef::unowned(op.as_str()));
    let recorded = audit.record(
        &AuditRecord::now(
            request_id,
            requester.principal,
            requester.auth_path,
            op.action(),
            op.as_str(),
            verdict.decision,
            verdict.rule,
            peer_addr,
        )
        .with_verdict_role(verdict.role)
        .with_verdict_pin_grant(verdict.pin_grant),
    );
    match (verdict.decision, recorded.is_ok()) {
        (Decision::Deny, _) => AgentVerdict::Denied,
        (Decision::Allow, false) => AgentVerdict::AuditFailed,
        (Decision::Allow, true) => AgentVerdict::Allowed,
    }
}

#[cfg(test)]
mod tests;
