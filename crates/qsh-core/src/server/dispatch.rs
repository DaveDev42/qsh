//! The control-message dispatch choke point of [`Server`] and its authorization helpers.

use super::*;

impl Server {
    // ------------------------------------------------------------------
    // dispatch — the choke point
    // ------------------------------------------------------------------

    /// Decide and answer one control message. Returns `None` when no reply
    /// is due (e.g. an unsolicited `Pong`). Every handler authorizes and
    /// audits before its first `.await` and before touching any resource.
    pub async fn dispatch(&self, ctx: &ConnCtx, msg: &ControlMessage) -> Option<ControlMessage> {
        let request_id = msg.request_id;
        match &msg.body {
            Some(control_message::Body::ExecStart(req)) => {
                Some(self.handle_exec_start(ctx, request_id, req))
            }
            Some(control_message::Body::Ping(_)) => Some(ControlMessage::new(
                request_id,
                control_message::Body::Pong(wire::Pong {}),
            )),
            Some(control_message::Body::Pong(_)) | Some(control_message::Body::Response(_)) => None,
            Some(control_message::Body::SessionOpen(req)) => {
                Some(self.handle_session_open(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionList(_)) => {
                Some(self.handle_session_list(ctx, request_id))
            }
            Some(control_message::Body::SessionGet(req)) => {
                Some(self.handle_session_get(ctx, request_id, req))
            }
            Some(control_message::Body::SessionRead(req)) => {
                Some(self.handle_session_read(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionWrite(req)) => {
                Some(self.handle_session_write(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionResize(req)) => {
                Some(self.handle_session_resize(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionClose(req)) => {
                Some(self.handle_session_close(ctx, request_id, req).await)
            }
            Some(control_message::Body::SessionAttach(req)) => {
                Some(self.handle_session_attach(ctx, request_id, req).await)
            }
            // A host never consumes SessionEvent (it is the producer);
            // an unsolicited one is dropped like a stray Pong.
            Some(control_message::Body::SessionEvent(_)) => None,
            Some(control_message::Body::Hello(_)) => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::InvalidArgument,
                    "unexpected Hello after handshake",
                    false,
                ),
            )),
            // Pairing (ADR-0002, M7 Step 4) has its own, much smaller
            // dispatch loop (`Server::serve_pairing_connection`), reachable
            // only on a connection whose principal is `Principal::Pairing`
            // — `Server::serve_connection_inner` routes such a connection
            // there *before* it ever reaches this ordinary `Hello`/dispatch
            // path. A `PairingProof`/`PairingAccepted` arriving here means
            // an already-authenticated peer sent a pairing message on its
            // normal connection, which is never valid — refused exactly
            // like a stray `Hello`, above.
            Some(control_message::Body::PairingProof(_)) => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::InvalidArgument,
                    "unexpected PairingProof on an authenticated connection",
                    false,
                ),
            )),
            Some(control_message::Body::PairingAccepted(_)) => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::InvalidArgument,
                    "unexpected PairingAccepted on an authenticated connection",
                    false,
                ),
            )),
            // `RemoteForwardOpen` (M4 Step 4) needs a live `Connection` to
            // open the `TCP_ACCEPTED` streams its listener will hand out —
            // something no `dispatch` caller has (`dispatch`'s own module
            // doc: "pure with respect to transport"). `Server::serve_control`
            // intercepts it before it ever reaches this match, the same
            // shape as the `SessionWrite` special case just above in that
            // loop, and calls `Server::handle_rfwd_open` (which does have
            // one) directly. A caller that dispatches this body straight
            // (every unit test in this file included) has no connection to
            // open anything on, so it draws `UNSUPPORTED` here — the ACL +
            // loopback choke point itself is still fully unit-testable, via
            // `Server::authorize_and_bind_remote_forward` directly, which
            // needs no connection either.
            Some(control_message::Body::RfwdOpen(_)) => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "remote forward open requires a live connection; \
                     not answerable by direct dispatch",
                    false,
                ),
            )),
            // `RemoteForwardClose` needs no connection — it is an ACL
            // choke point (`Server::authorize_owned`, `PLAN.md` M5 Step 5)
            // over a `Server::remote_forwards` lookup plus an abort — so it
            // is handled inline here like every other control op.
            Some(control_message::Body::RfwdClose(req)) => {
                Some(self.handle_rfwd_close(ctx, request_id, req))
            }
            // No body this build understands. prost drops unknown fields,
            // so a reserved (25 `SessionSignal`) or future control number
            // decodes to `body: None` exactly like an empty message;
            // CLI.md §2.4 / protocol.md §9 require UNSUPPORTED for those,
            // and CLI.md §3.3 assigns un-negotiated features the same code.
            None => Some(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "unknown, reserved or empty control message",
                    false,
                ),
            )),
        }
    }

    /// The choke point proper: decide `action` on `resource` for this
    /// connection and write the audit line. `Err` is the ready-made
    /// `PERMISSION_DENIED` reply. Callers create nothing before this
    /// returns `Ok`.
    /// The ACL choke point for a path that has no control-stream reply to
    /// carry a denial: a peer-opened data stream. Decides and audits
    /// exactly like [`Server::authorize`], then answers yes/no — the caller
    /// resets the stream, which is non-distinguishing by construction.
    pub(super) fn authorize_stream(&self, ctx: &ConnCtx, action: Action, resource: &str) -> bool {
        let verdict = self.authorizer.check(
            &ctx.principal,
            ctx.auth_path,
            action,
            ResourceRef::unowned(resource),
        );
        // No request id: a stream is not a control-stream request, so this
        // is a connection-level record (`request_id: "-"`), same as
        // `reverse::admit`.
        let recorded = self.audit.record(&AuditRecord::connection_level(
            &ctx.principal,
            ctx.auth_path,
            action,
            resource,
            verdict.decision,
            verdict.rule,
            ctx.peer_addr,
        ));
        // Fail-closed (`CLAUDE.md` "never create a resource before
        // authorization succeeds"): an unrecorded allow is treated as a
        // deny, same as an unrecorded allow at every other choke point.
        verdict.is_allow() && recorded.is_ok()
    }

    pub(super) fn authorize(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        resource: &str,
    ) -> Result<(), Box<ControlMessage>> {
        let verdict = self.authorizer.check(
            &ctx.principal,
            ctx.auth_path,
            action,
            ResourceRef::unowned(resource),
        );
        let recorded = self.audit.record(&AuditRecord::now(
            request_id,
            &ctx.principal,
            ctx.auth_path,
            action,
            resource,
            verdict.decision,
            verdict.rule,
            ctx.peer_addr,
        ));
        // Fail-closed: an allow verdict that failed to make it into the
        // audit log is denied — never create the resource this authorizes
        // without a durable record of having authorized it.
        if !verdict.is_allow() || recorded.is_err() {
            return Err(Box::new(Self::permission_denied(request_id, action)));
        }
        Ok(())
    }

    /// `Action::SessionControl` on `id`, with ownership folded into the
    /// same decision as an ordinary `scope = "owned"` policy judgment
    /// (`PLAN.md` M5 Step 5 (a), `docs/design/architecture.md` §6's ④):
    /// [`Self::require_opener`] is now a thin broker lookup that fills
    /// [`ResourceRef::owner`] for [`Self::authorize_owned`], not a second
    /// gate run after the fact — so there is exactly one
    /// [`Authorizer::check`] call and exactly one terminal audit record per
    /// request, the same "single decision, single record" property the old
    /// two-step version (`Self::authorize` + a separate `require_opener`
    /// deny) had to work to preserve (`PLAN.md` Step 3.5 PR② review: a
    /// foreign principal's refused write must not also read as an `allow`
    /// in the audit log — see
    /// `crates/qsh-testkit/tests/session_loopback.rs`'s
    /// `session_control_binds_write_and_resize_to_the_opener`), now true by
    /// construction instead of by careful sequencing.
    /// `action` is the caller's own `crate::acl::Op::X.action()` lookup
    /// (`Op::SessionWrite`/`Op::SessionResize`, `PLAN.md` M5 Step 8) — both
    /// resolve to `Action::SessionControl` today, but sourcing it from the
    /// registry at each call site (rather than hardcoding the enum
    /// variant here) is what keeps this shared helper and `OP_REGISTRY`
    /// from being able to drift silently.
    pub(super) fn authorize_session_control(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        id: &SessionId,
    ) -> Result<(), Box<ControlMessage>> {
        // `require_opener` itself denies (and audits) on an ambiguous
        // broker lookup failure — see its own doc. A `NotFound` id passes
        // through as `owner: None`, same as any other unowned resource,
        // so the ACL decision below still runs and the caller's own
        // subsequent broker call is what eventually answers
        // `SESSION_NOT_FOUND` — this function never invents that answer.
        let owner = self.require_opener(ctx, request_id, action, id)?;
        self.authorize_owned(
            ctx,
            request_id,
            action,
            ResourceRef {
                id: &id.0,
                owner: owner.as_deref(),
            },
        )
    }

    /// [`Self::authorize`]'s owner-aware sibling (`PLAN.md` M5 Step 5): one
    /// [`Authorizer::check`] call over a [`ResourceRef`] that already
    /// carries `owner`, and exactly one terminal audit record either way.
    /// Its two callers are [`Self::authorize_session_control`] (owner from
    /// [`Self::require_opener`]'s broker lookup) and
    /// [`Self::handle_rfwd_close`] (owner from `Server::remote_forwards`'s
    /// own registration record) — both need a `ResourceRef` [`Self::
    /// authorize`] cannot build, since that helper always passes
    /// [`ResourceRef::unowned`].
    pub(super) fn authorize_owned(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> Result<(), Box<ControlMessage>> {
        let verdict = self
            .authorizer
            .check(&ctx.principal, ctx.auth_path, action, resource);
        let recorded = self.audit.record(&AuditRecord::now(
            request_id,
            &ctx.principal,
            ctx.auth_path,
            action,
            resource.id,
            verdict.decision,
            verdict.rule,
            ctx.peer_addr,
        ));
        // Fail-closed: this is the terminal record for the combined
        // policy + ownership decision — an allow that failed to land in
        // the audit log flips to denied, same as `Self::authorize`.
        if !verdict.is_allow() || recorded.is_err() {
            return Err(Box::new(Self::permission_denied(request_id, action)));
        }
        Ok(())
    }

    /// The `PERMISSION_DENIED` reply for `action`. The **only** place this
    /// wording is built, so [`Server::authorize`]'s policy deny,
    /// [`Server::require_opener`]'s ownership deny, and every audit-
    /// record-failure fail-closed deny are byte-identical — a peer must
    /// not be able to tell "the policy forbids this" from "this session
    /// exists but is someone else's" from "the audit log failed to write"
    /// (`PLAN.md` Step 3.5 PR②, M5 Step 4 §4.2). The reply body is always
    /// [`crate::acl::PERMISSION_DENIED_MESSAGE`] verbatim — `action` never
    /// reaches the wire (that would turn the message into a capability-
    /// enumeration oracle, see that constant's doc) and is used only for
    /// a host-side `tracing` diagnostic, never logged to the peer.
    fn permission_denied(request_id: u64, action: Action) -> ControlMessage {
        tracing::debug!(%request_id, %action, "denying: PERMISSION_DENIED");
        ControlMessage::error(
            request_id,
            wire::Error::new(
                ErrorCode::PermissionDenied,
                crate::acl::PERMISSION_DENIED_MESSAGE,
                false,
            ),
        )
    }

    /// `session.control`'s ownership *lookup* (audit A2 P0, `PLAN.md` Step
    /// 3.5 PR②, PRD §6, M5 Step 5 (a)): finds the session's recorded
    /// opener, for [`Self::authorize_session_control`] to fold into the
    /// `ResourceRef` it hands the ordinary `Authorizer::check` call — the
    /// actual `scope = "owned"` comparison against it now lives in the
    /// authorizer (`AllowAllPinned::check`/`Policy::decide`), not here.
    /// Named `require_opener` still: `PLAN.md` M5 Step 5 (a) keeps the name
    /// across this shrink from "the ownership gate itself" to "the thin
    /// broker lookup that feeds it".
    ///
    /// A session this host cannot find is left alone (`Ok(None)`):
    /// existence is decided by the caller's own subsequent broker call
    /// ([`SessionBackend::get`]/`take_lease`/`resize`), never invented here
    /// — inventing a denial for "no such session" would make this gate an
    /// oracle the ACL choke point deliberately is not (`session.write`/
    /// `resize` already answer `SESSION_NOT_FOUND` for an unknown id, same
    /// as before this check existed). `owner: None` also happens to be
    /// exactly the "no owner concept" shape every unowned resource uses
    /// (`ResourceRef`'s own doc), so the ACL decision that follows treats a
    /// not-yet-found session the same way it treats `exec.run` — never
    /// filtered by scope — which is what lets this passthrough work without
    /// a special case in the authorizer.
    ///
    /// Any *other* lookup failure (an out-of-process `SessionBackend`
    /// timing out, say) is ambiguous, not "no such session", and
    /// `CLAUDE.md`'s "fail closed on any ambiguous auth/ACL state" applies:
    /// this function denies (and writes the sole audit record for that
    /// denial itself — its caller never reaches its own `Authorizer::check`
    /// call in this branch, so there is still exactly one terminal record)
    /// rather than silently waving the request through.
    ///
    /// `session.get`/`read`/`close`/`list`, `session.open` and
    /// `session.attach` are **not** gated by ownership at all — PRD §6
    /// keeps them cross-device within ACL scope, and attach is already
    /// device-bound by its resume credential (ADR-0007) — so nothing calls
    /// this outside [`Self::authorize_session_control`].
    ///
    /// The returned owner is the session's recorded [`opener_key`] — a
    /// `(principal, auth_path)` pair folded at `session.open` time (see
    /// that handler's own call), not `ctx.principal` alone: `Principal` by
    /// itself cannot tell a pin from a CA leaf asserting the same name
    /// (`qsh-transport::tls::AuthPath`'s own doc), so a bare principal
    /// string would let a CA-issued leaf assert a pinned opener's identity
    /// the moment the authorizer that compares it admits any
    /// CA-authenticated peer for `session.control` at all.
    fn require_opener(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        action: Action,
        id: &SessionId,
    ) -> Result<Option<String>, Box<ControlMessage>> {
        match self.sessions.get(id) {
            Ok(info) => Ok(Some(info.opener)),
            // `NotFound` alone is left alone — existence is decided by the
            // caller's own subsequent broker call, per the doc above.
            Err(BrokerError::NotFound) => Ok(None),
            // Ambiguous, not "no such session": fail closed. Not a
            // policy-rule decision, so there is no rule index to carry.
            Err(_) => {
                let _ = self.audit.record(&AuditRecord::now(
                    request_id,
                    &ctx.principal,
                    ctx.auth_path,
                    action,
                    &id.0,
                    Decision::Deny,
                    None,
                    ctx.peer_addr,
                ));
                Err(Box::new(Self::permission_denied(request_id, action)))
            }
        }
    }
}
