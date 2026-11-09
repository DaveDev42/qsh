//! `exec.start` handler of [`Server`].

use super::*;

impl Server {
    pub(super) fn handle_exec_start(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &ExecStart,
    ) -> ControlMessage {
        if !ctx.has_capability(wire::CAP_EXEC) {
            return ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "peer did not negotiate the exec capability",
                    false,
                ),
            );
        }
        // Shape checks only: nothing here depends on who is asking, so they
        // can precede the ACL choke point like the `argv` check always did.
        let shell = match shell_request(ctx, req) {
            Ok(shell) => shell,
            Err(error) => return ControlMessage::error(request_id, error),
        };
        if shell.is_none() && req.argv.is_empty() {
            return ControlMessage::error(
                request_id,
                wire::Error::new(ErrorCode::InvalidArgument, "argv must not be empty", false),
            );
        }
        // Agent forwarding (ADR-0055 decision 3): a shape check, before the
        // ACL decision and with no audit record.
        let agent = match super::sessions::agent_grant(ctx, &req.agent_channel) {
            Ok(agent) => agent,
            Err(why) => {
                return ControlMessage::error(
                    request_id,
                    wire::Error::new(ErrorCode::InvalidArgument, why, false),
                );
            }
        };

        // ---- ACL choke point: decide + audit BEFORE any resource. ----
        if let Err(denied) =
            self.authorize(ctx, request_id, crate::acl::Op::ExecRun.action(), "exec")
        {
            return *denied;
        }

        // ---- Resource bound: no more outstanding tickets for this peer. ----
        //
        // After the ACL choke point above (main-session arbitration round,
        // item 3), *not* ahead of it the way the M8 Step 3a conformance
        // sweep's F4 had left it: `check_ticket_budget` creates nothing —
        // there was never a "never create a resource before authorization"
        // reason to run it first — and putting any capacity check ahead of
        // ACL makes `RESOURCE_EXHAUSTED` vs. `PERMISSION_DENIED` a
        // same-connection oracle for whether the *caller's own* prior
        // requests are what is being counted, which an unauthorized
        // principal has no business learning either way.
        // `exec_ticket_budget_follows_the_acl_choke_point_on_the_same_
        // connection` below pins the order this call site now has.
        if let Err(reply) = self.check_ticket_budget(ctx, request_id) {
            return *reply;
        }

        // ---- Drain gate (CLI.md §6.12, ADR-0003): after the ACL decision,
        // same placement as `session.open`/`session.attach` — otherwise
        // `exec.run` would keep admitting brand-new host processes for the
        // whole drain window while sessions are being torn down around it.
        if let Err(reply) = self.require_not_draining(request_id) {
            return *reply;
        }

        // ---- exec.run concurrency quota (`[serve].max_exec_per_principal`,
        // verdict arbitration item 5): after the ACL decision (an
        // unauthorized principal must see `PERMISSION_DENIED`, never a
        // quota oracle), before anything is issued. The ticket budget above
        // only bounds *unredeemed* tickets — a principal that keeps
        // redeeming and reaping children never accumulates an unbounded
        // backlog through that alone, so this reserves against *live*
        // children instead. ----
        let opener = opener_key(&ctx.principal, ctx.auth_path);
        let permit = match self.quotas.reserve_exec(&opener) {
            Ok(permit) => permit,
            Err(kind) => {
                let records = self.quotas.record_rejection(
                    kind,
                    &opener,
                    ctx.peer_addr,
                    self.quotas.now(),
                    Some(request_id),
                    ctx.auth_path,
                );
                crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                return broker_error(request_id, BrokerError::QuotaExceeded(kind));
            }
        };

        // ---- Allowed: issue a single-use ticket. Nothing spawned yet. ----
        let spec = ExecSpec {
            argv: req.argv.clone(),
            env: req
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            timeout: (req.timeout_ms > 0).then(|| Duration::from_millis(req.timeout_ms)),
            shell,
        };
        let exec_id = ulid::Ulid::generate().to_string();
        let ticket = self.issue_ticket(
            ctx.conn_id,
            TicketPurpose::Exec(PendingExec {
                exec_id: exec_id.clone(),
                spec,
                permit,
            }),
        );
        tracing::info!(
            principal = %ctx.principal,
            peer = %ctx.peer_addr,
            %exec_id,
            "exec.run authorized"
        );
        ControlMessage::response(
            request_id,
            response::Body::ExecStarted(ExecStarted {
                exec_id,
                ticket: ticket.to_vec(),
                agent: agent as i32,
            }),
        )
    }
}

/// The shell request of an `ExecStart` (`shell_command`/`login_shell`,
/// ADR-0051 decision 6), or `None` for a plain argv exec.
///
/// The fields are skipped as unknown by a host that predates
/// `shell-command.v1`, so this host answers `UNSUPPORTED` when the peer sets
/// one without having negotiated the capability (it cannot have learned the
/// semantics from this host). The shape rules live in
/// [`ExecStart::target`]. The text of an error never includes the command.
fn shell_request(
    ctx: &ConnCtx,
    req: &ExecStart,
) -> Result<Option<crate::shell::ShellRequest>, wire::Error> {
    use crate::shell::ShellRequest;
    use wire::ExecTarget;
    if req.uses_shell_fields() && !ctx.has_capability(wire::CAP_SHELL_COMMAND_V1) {
        return Err(wire::Error::new(
            ErrorCode::Unsupported,
            "peer did not negotiate the shell-command.v1 capability",
            false,
        ));
    }
    match req
        .target()
        .map_err(|e| wire::Error::new(ErrorCode::InvalidArgument, e.0, false))?
    {
        None | Some(ExecTarget::Argv) => Ok(None),
        Some(ExecTarget::ShellCommand(command)) => {
            Ok(Some(ShellRequest::Command(command.to_string())))
        }
        Some(ExecTarget::LoginShell) => Ok(Some(ShellRequest::Login)),
    }
}
