//! Session control handlers of [`Server`] (`session.open` … `session.attach`) and the request guards they share.

use super::*;

impl Server {
    // ------------------------------------------------------------------
    // session ops (M2 Step 3) — CLI.md §6.2–6.7, action mapping §2.5
    // ------------------------------------------------------------------

    /// Shape check on a peer-supplied `session_id` before it becomes the
    /// ACL resource and an audit field: non-empty, URL-safe
    /// (`[A-Za-z0-9_-]`) and at most [`SESSION_ID_MAX_LEN`] bytes. The
    /// check does not consult the broker, so it discloses nothing about
    /// which sessions exist.
    fn require_session_id(request_id: u64, id: &str) -> Result<(), Box<ControlMessage>> {
        if valid_session_id(id) {
            Ok(())
        } else {
            Err(Box::new(invalid_argument(
                request_id,
                "session_id must be 1..=64 URL-safe characters",
            )))
        }
    }

    /// SIGTERM graceful drain (`docs/CLI.md` §6.12, ADR-0003): refuse every
    /// `session.open`/`session.attach` arriving on a connection this host
    /// already holds, from the moment [`Server::drain`] is called.
    /// `RESOURCE_EXHAUSTED` rather than a new code (CLI.md §3.3:
    /// "server-side limit exceeded") — the host's capacity for new sessions
    /// is now zero — and non-retryable, because retrying against this same
    /// process cannot ever succeed again.
    pub(super) fn require_not_draining(&self, request_id: u64) -> Result<(), Box<ControlMessage>> {
        if self.draining.load(Ordering::Acquire) {
            return Err(Box::new(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::ResourceExhausted,
                    "qsh serve is shutting down: refusing new sessions",
                    false,
                ),
            )));
        }
        Ok(())
    }

    /// Drain the host: refuse every new `session.open`/`session.attach`
    /// from this call forward, then close every live session through the
    /// same procedure `session.close` uses — signal escalation,
    /// `session.closed{reason:"closed"}` to every attached consumer,
    /// `close_grace_ms` per step (CLI.md §6.7) — so no PTY child outlives
    /// the process (§6.12, ADR-0003).
    ///
    /// Bounded by [`DRAIN_TIMEOUT`] as a last resort; not otherwise. Setting
    /// the flag before closing sessions (rather than relying on the accept
    /// loop having already stopped) is what covers a request racing in on a
    /// connection this host had already accepted. Idempotent — a second
    /// call finds nothing left to close.
    pub async fn drain(&self) {
        self.draining.store(true, Ordering::Release);
        if tokio::time::timeout(DRAIN_TIMEOUT, self.sessions.drain(CloseReason::Closed))
            .await
            .is_err()
        {
            tracing::warn!(
                timeout_secs = DRAIN_TIMEOUT.as_secs(),
                "qsh serve drain: timed out waiting for every session to close; exiting anyway"
            );
        }
        // See [`DRAIN_FLUSH_GRACE`]: every session is closed in the broker
        // at this point, but delivering that to an attached consumer is a
        // separate hop this call has not waited for.
        tokio::time::sleep(DRAIN_FLUSH_GRACE).await;
    }

    /// Common preamble of every session op: the peer must have negotiated
    /// the `session` capability. Not audited (no decision was made).
    fn require_session_capability(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
    ) -> Result<(), Box<ControlMessage>> {
        if ctx.has_capability(wire::CAP_SESSION) {
            Ok(())
        } else {
            Err(Box::new(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "peer did not negotiate the session capability",
                    false,
                ),
            )))
        }
    }

    pub(super) fn check_ticket_budget(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
    ) -> Result<(), Box<ControlMessage>> {
        if self.pending_tickets_for(ctx.conn_id) >= MAX_PENDING_TICKETS_PER_CONN {
            return Err(Box::new(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::ResourceExhausted,
                    "too many outstanding tickets on this connection",
                    true,
                ),
            )));
        }
        Ok(())
    }

    /// `session.open`: ACL `session.open` → `user` hint → spawn → ticket.
    pub(super) async fn handle_session_open(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionOpen,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        let Some((cols, rows)) = window_size(req.cols, req.rows) else {
            return invalid_argument(request_id, "cols/rows must fit in 16 bits");
        };

        // ---- ACL choke point: decide + audit BEFORE any resource. ----
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionOpen.action(),
            SESSION_RESOURCE,
        ) {
            return *denied;
        }

        // ---- Drain gate, same placement as `session.attach`: after the
        // ACL decision so `authorize`'s audit record is still written for a
        // request arriving during drain — the gate creates no resource
        // either way, so there is nothing to save by short-circuiting
        // earlier, and doing so would make `RESOURCE_EXHAUSTED` vs.
        // `PERMISSION_DENIED` an oracle for host shutdown state. ----
        if let Err(reply) = self.require_not_draining(request_id) {
            return *reply;
        }

        // ---- Resource bound: no more outstanding tickets for this peer. ----
        //
        // After the ACL choke point above (main-session arbitration round,
        // item 3) — not ahead of it the way the M8 Step 3a conformance
        // sweep had instead left this call site (adversary finding A1):
        // `check_ticket_budget` creates nothing, so there was never a
        // "never create a resource before authorization" reason to run it
        // first, and putting any capacity check ahead of ACL makes
        // `RESOURCE_EXHAUSTED` vs. `PERMISSION_DENIED` a same-connection
        // oracle for whether the *caller's own* prior requests are what is
        // being counted, which an unauthorized principal has no business
        // learning either way. Placed after the drain gate immediately
        // above, matching `session.attach`'s own ACL → drain → ticket-
        // budget order (see that handler's "same reasoning as
        // exec.run/session.open" comment) rather than `exec.run`'s ACL →
        // ticket-budget → drain order — `session.open` and
        // `session.attach` share a drain-gate rationale that `exec.run`
        // does not, so the two session ops stay in lockstep with each
        // other here.
        // `session_open_ticket_budget_follows_the_acl_choke_point_on_the_
        // same_connection` below pins the order this call site now has.
        if let Err(reply) = self.check_ticket_budget(ctx, request_id) {
            return *reply;
        }

        // ---- `user@` hint (CLI.md §7): only after the ACL decision, so an
        // unauthorized peer never learns the serve account's login name.
        if let Some(user) = req.user.as_deref()
            && !user_hint_matches(user)
        {
            return ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "user switching is not supported: sessions run as the qsh serve account",
                    false,
                ),
            );
        }

        // ---- Allowed: create the session, then a single-use ticket. ----
        let mut env: Vec<(String, String)> = req
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        env.sort();
        let spec = SessionSpec {
            argv: req.argv.clone(),
            env,
            term: (!req.term.is_empty()).then(|| req.term.clone()),
            cols,
            rows,
            user: req.user.clone(),
        };
        // The opener is recorded as this session's owner (`PLAN.md` Step
        // 3.5 PR②) — `session.write`/`session.resize` bind to it from here
        // on. `opener_key`, not `ctx.principal.to_string()` alone: see its
        // doc comment.
        let opener = opener_key(&ctx.principal, ctx.auth_path);
        let session_id = match self.sessions.open(&spec, &opener) {
            Ok(id) => id,
            // A session-count quota (`[serve].max_sessions`/
            // `max_sessions_per_principal`, `PLAN.md` M8 Step 3) was
            // already saturated when `Broker::open` reserved a slot for
            // this opener — reached strictly after the ACL `allow` above
            // was decided and audited, so this can never substitute for a
            // `PERMISSION_DENIED` an unauthorized principal should have
            // seen instead. The broker itself never touches an
            // `AuditSink` (`crate::quota` is leaf-most/connection-agnostic
            // — architecture.md §1), so the rejection is recorded here.
            Err(BrokerError::QuotaExceeded(kind)) => {
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
            Err(err) => return broker_error(request_id, err),
        };
        let ticket = self.issue_ticket(
            ctx.conn_id,
            TicketPurpose::Session {
                session_id: session_id.clone(),
                replay_from: 0,
                // `session.open` never steals: nobody else can hold the
                // lease of a session that did not exist a moment ago.
                no_steal: false,
                // Only `session.open` was authorized here; the attach the
                // data stream performs is decided when it arrives.
                attach_authorized: false,
                // A fresh session's first input stream, counting from zero.
                // The resume credential minted just below starts its
                // lineage on the same axis.
                input_stream: FIRST_INPUT_STREAM,
                input_from: 0,
            },
        );
        // The resume credential (protocol.md §10). Bound to the peer's SPKI:
        // without a verified leaf there is nothing to bind to, so no token
        // is issued at all and the session simply cannot be resumed — fail
        // closed rather than mint an unbound credential.
        let resume_token = match ctx.peer_fingerprint {
            Some(peer) => Some(self.sessions.issue_resume(&session_id, peer)),
            None => {
                tracing::warn!(
                    principal = %ctx.principal,
                    %session_id,
                    "no peer SPKI fingerprint: session opened without a resume credential"
                );
                None
            }
        };
        let expires_at = rfc3339_after(self.sessions.resume_ttl());
        tracing::info!(
            principal = %ctx.principal,
            peer = %ctx.peer_addr,
            %session_id,
            "session.open authorized"
        );
        ControlMessage::response(
            request_id,
            response::Body::SessionOpened(wire::SessionOpened {
                session_id: session_id.0,
                // The only time this plaintext ever leaves the host. It is
                // never logged, never audited and never rendered as JSON
                // (ADR-0007).
                resume_token: resume_token
                    .as_ref()
                    .map(|t| t.expose().to_vec())
                    .unwrap_or_default(),
                ticket: ticket.to_vec(),
                initial_seq: 0,
                expires_at,
            }),
        )
    }

    /// `session.list`: ACL `session.list` on the session namespace.
    pub(super) fn handle_session_list(&self, ctx: &ConnCtx, request_id: u64) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionList.action(),
            SESSION_RESOURCE,
        ) {
            return *denied;
        }
        let sessions = self
            .sessions
            .list()
            .into_iter()
            .map(session_info_to_wire)
            .collect();
        ControlMessage::response(
            request_id,
            response::Body::SessionListResult(wire::SessionListResult { sessions }),
        )
    }

    /// `session.get`: ACL `session.list` on the session id.
    pub(super) fn handle_session_get(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionGet,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionGet.action(),
            &req.session_id,
        ) {
            return *denied;
        }
        match self.sessions.get(&SessionId(req.session_id.clone())) {
            Ok(info) => ControlMessage::response(
                request_id,
                response::Body::SessionInfo(session_info_to_wire(info)),
            ),
            Err(err) => broker_error(request_id, err),
        }
    }

    /// `session.read`: ACL `session.attach` on the session id, then one
    /// cursor pull (the same primitive `--follow` and a long-running
    /// external process's, e.g. an agent tool, long-poll use).
    pub(super) async fn handle_session_read(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionRead,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionRead.action(),
            &req.session_id,
        ) {
            return *denied;
        }
        // Clamp, never reject (protocol.md §9): 0 = host default = the cap.
        let max_bytes = match usize::try_from(req.max_bytes) {
            Ok(0) | Err(_) => wire::SESSION_READ_MAX_BYTES,
            Ok(n) => n.min(wire::SESSION_READ_MAX_BYTES),
        };
        // Same treatment for the wait: clamp, never reject.
        let wait = Duration::from_millis(req.wait_ms).min(SESSION_READ_MAX_WAIT);
        // The cursor is (output offset, control id) — control entries are
        // zero-length, so `after` alone cannot say whether one positioned
        // exactly at `after` was already delivered. A caller that echoes
        // `next_ctl_after` back gets every control exactly once; one that
        // does not (`ctl_after: 0`) gets at-least-once (protocol.md §9).
        let out = match self
            .sessions
            .pull(
                &SessionId(req.session_id.clone()),
                Cursor {
                    after: req.after,
                    ctl_after: req.ctl_after,
                },
                max_bytes,
                wait,
            )
            .await
        {
            Ok(out) => out,
            Err(err) => return broker_error(request_id, err),
        };
        let next = out.next;
        let events = out
            .events
            .into_iter()
            .flat_map(replay_event_to_wire)
            .collect();
        ControlMessage::response(
            request_id,
            response::Body::SessionReadResult(wire::SessionReadResult {
                events,
                next_after: next.after,
                next_ctl_after: next.ctl_after,
            }),
        )
    }

    /// `session.write`: [`prepare_session_write`](Self::prepare_session_write)
    /// then [`finish_session_write`](Self::finish_session_write). The
    /// connection loop splits the two so the parking half never runs on the
    /// control stream; `dispatch` keeps them together.
    pub(super) async fn handle_session_write(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionWrite,
    ) -> ControlMessage {
        match self.prepare_session_write(ctx, request_id, req).await {
            Ok(pending) => self.finish_session_write(pending).await,
            Err(reply) => *reply,
        }
    }

    /// The non-parking half of `session.write`: ACL `session.control` on
    /// the session id and ownership
    /// ([`Server::authorize_session_control`], `PLAN.md` Step 3.5 PR②/M5
    /// Step 5), then take the writer lease with `no_steal: true` fixed
    /// (below) regardless of what the ACL layer decided. Under the default
    /// `scope = "owned"` (M3's P0, still what `AllowAllPinned` and every
    /// `acl.toml` row without an explicit `scope = "any"` enforce), the
    /// ownership check above already narrows every caller reaching this
    /// line to the session's own opener, so `TakeOutcome::Conflict` can
    /// never actually fire here — the lease's live holder is that same
    /// opener too (architecture.md §3 rule (b)'s amendment note). An
    /// explicit `scope = "any"` grant (M5 Step 5) reopens that path: a
    /// foreign principal can now pass the ACL gate above. Whether it then
    /// reaches `Conflict` here depends on the lease already being *live*
    /// (F3, M5 Step 5 adversarial review): if the opener has already
    /// written or attached first, the foreign principal's own write lands
    /// on that live lease and `no_steal: true` — unconditional — refuses it
    /// with `Conflict`, so `scope` widens ACL admission only, never the
    /// writer-lease's own never-silently-steal-from-someone-else guarantee.
    /// But a lease nobody has taken yet (fresh out of `session.open`,
    /// `WriterLease::new()`) has no live holder to conflict with, so a
    /// foreign principal that reaches this line *first* just takes it — and
    /// it is the **opener's own subsequent write** that then meets
    /// `Conflict` instead
    /// (`session_write_scope_any_lets_a_foreign_first_writer_take_the_free_lease`,
    /// `crates/qsh-testkit/tests/session_loopback.rs`). This residual
    /// window is the documented trade-off, not a bug: `scope` only ever
    /// decides who may *reach* the lease, never who wins a race for a free
    /// one. The two gates are independent on purpose.
    ///
    /// Everything here is bounded — the session actor's loop never blocks
    /// on the child — so this side is safe to run inline on the control
    /// stream, which is what keeps two pipelined writes in arrival order
    /// and keeps the lease from being taken after `purge_connection`.
    /// `Err` is the finished reply; `Ok` is a write still owed to the PTY.
    pub(super) async fn prepare_session_write(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionWrite,
    ) -> Result<PendingWrite, Box<ControlMessage>> {
        self.require_session_capability(ctx, request_id)?;
        Self::require_session_id(request_id, &req.session_id)?;
        if let Err(err) = req.validate() {
            return Err(Box::new(invalid_argument(request_id, err.to_string())));
        }
        let id = SessionId(req.session_id.clone());
        self.authorize_session_control(
            ctx,
            request_id,
            crate::acl::Op::SessionWrite.action(),
            &id,
        )?;
        let conn = ctx.connection_id();
        if req.data.is_empty() {
            // Nothing to write: answer without touching the lease, so an
            // empty write is not a side-channel for displacing (or
            // flapping) the current writer. Existence is still checked
            // (the ACL decision above already covers disclosure).
            return Err(Box::new(match self.sessions.get(&id) {
                Ok(_) => ControlMessage::response(
                    request_id,
                    response::Body::SessionWritten(wire::SessionWritten { bytes_written: 0 }),
                ),
                Err(err) => broker_error(request_id, err),
            }));
        }
        match self
            .sessions
            .take_lease(&id, ctx.principal.to_string(), conn, true)
            .await
        {
            Ok(TakeOutcome::Conflict { .. }) => {
                return Err(Box::new(ControlMessage::error(
                    request_id,
                    wire::Error::new(
                        ErrorCode::SessionConflict,
                        "another principal holds the session's writer lease",
                        true,
                    ),
                )));
            }
            Ok(_) => {}
            Err(err) => return Err(Box::new(broker_error(request_id, err))),
        }
        Ok(PendingWrite {
            request_id,
            id,
            conn,
            data: req.data.clone(),
        })
    }

    /// The parking half of `session.write`: hand the bytes to the session.
    /// This can wait indefinitely — a child that stops draining its PTY
    /// input buffer blocks its writer task — so the connection loop runs it
    /// on a per-connection queue, never inline.
    pub(super) async fn finish_session_write(&self, pending: PendingWrite) -> ControlMessage {
        let PendingWrite {
            request_id,
            id,
            conn,
            data,
        } = pending;
        let bytes_written = data.len() as u64;
        match self.sessions.write(&id, conn, data).await {
            Ok(()) => ControlMessage::response(
                request_id,
                response::Body::SessionWritten(wire::SessionWritten { bytes_written }),
            ),
            Err(err) => broker_error(request_id, err),
        }
    }

    /// `session.resize`: ACL `session.control` on the session id and the
    /// opener binding, combined
    /// ([`Server::authorize_session_control`], `PLAN.md` Step 3.5 PR②).
    pub(super) async fn handle_session_resize(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionResize,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        let Some((cols, rows)) = window_size(req.cols, req.rows) else {
            return invalid_argument(request_id, "cols/rows must fit in 16 bits");
        };
        if cols == 0 || rows == 0 {
            return invalid_argument(request_id, "cols and rows must be positive");
        }
        let id = SessionId(req.session_id.clone());
        if let Err(denied) = self.authorize_session_control(
            ctx,
            request_id,
            crate::acl::Op::SessionResize.action(),
            &id,
        ) {
            return *denied;
        }
        match self.sessions.resize(&id, cols, rows).await {
            Ok(()) => ControlMessage::response(
                request_id,
                response::Body::SessionResized(wire::SessionResized {
                    cols: u32::from(cols),
                    rows: u32::from(rows),
                }),
            ),
            Err(err) => broker_error(request_id, err),
        }
    }

    /// `session.close`: ACL `session.control` on the session id, then the
    /// HUP → TERM → KILL escalation (`--signal` overrides the first step).
    pub(super) async fn handle_session_close(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionClose,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        let signal = match req.signal.as_deref() {
            None => None,
            Some(name) => match Signal::parse(name) {
                Some(signal) => Some(signal),
                None => {
                    return invalid_argument(
                        request_id,
                        "signal must be one of HUP|INT|QUIT|TERM|USR1|USR2|KILL",
                    );
                }
            },
        };
        // Deliberately the *unowned* path — `Self::authorize`, not
        // `Self::authorize_session_control` — even though `close` shares
        // `Action::SessionControl` with `write`/`resize`. This is an
        // **exemption**, not a gap (F1, M5 Step 5 adversarial review,
        // arbitrated): PRD §6's 세션 복구 section is explicit that a device
        // without this session's resume credential can still act on it —
        // "다른 장비에서는 `qsh sessions`에 보이더라도 attach는
        // `SESSION_NOT_FOUND`이며, 조회·읽기·종료는 ACL 범위에서 가능하다" — and
        // M3 already shipped `close` cross-device
        // (`session_control_binding_does_not_reach_get_read_or_close`,
        // `crates/qsh-testkit/tests/session_loopback.rs`). This step's own
        // invariant is "no behavior change" to that: a `scope = "owned"`
        // rule still narrows `write`/`resize` to the opener
        // (`Self::authorize_session_control`, above) but never narrows
        // `close`, on purpose. The scenario this serves: a laptop that
        // opened a session goes dark (lid closed, battery dead, network
        // partition) and a desktop sharing the same principal set —
        // granted `session.control`, not necessarily the opener — needs to
        // reap the orphaned child rather than wait out `resume_ttl`. No
        // ACL vocabulary restricts *who* may close *whose* session today;
        // narrowing that would need a new action (e.g. splitting
        // `session.control` so `close` has its own scope-able name) decided
        // by its own ADR, not a silent reinterpretation of this choke
        // point.
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionClose.action(),
            &req.session_id,
        ) {
            return *denied;
        }
        let id = SessionId(req.session_id.clone());
        // `final_seq` is the offset at removal time (CLI.md §6.7): whatever
        // the child emitted while dying is included, and it equals the
        // `sequence` on the trailing `session.closed` entry.
        let result = self.sessions.close(&id, CloseReason::Closed, signal).await;
        if result.is_ok() {
            // A closed session's own unredeemed tickets are now ghosts —
            // no `SESSION_DATA` stream can attach to a session the broker
            // no longer has, so their `MAX_PENDING_TICKETS_PER_CONN` slots
            // would otherwise sit dead until `TICKET_TTL` (30 s) or a
            // connection-wide `purge_connection` reclaimed them. `handle_
            // session_attach` mints exactly one ticket per call but does
            // not invalidate a still-pending one from an earlier attach of
            // the *same* session (confirmed by reading it above — its only
            // ticket-map access before its own `issue_ticket` is
            // `check_ticket_budget`, which only sweeps expired tickets and
            // counts what is left; it invalidates nothing), so more than
            // one `TicketPurpose::Session` ticket can be outstanding for
            // one `session_id` at once; that is exactly why this matches
            // on `session_id` rather than assuming a single ticket.
            //
            // Deliberately *not* also scoped to `t.conn_id == ctx.conn_id`
            // (라운드 1 판정 (c)): `close` is the unowned path (see above) —
            // any connection may close a session it did not open — so
            // scoping to the closer's own connection would strand the
            // opener's ticket forever whenever a different device reaps
            // the session. A session that no longer exists cannot be
            // attached to from *any* connection, so every `Session` ticket
            // naming it is equally dead; all of them go, regardless of
            // which connection minted them. The one race this still
            // leaves open — `handle_session_attach` confirming the broker
            // still has the session, then this `close` running, then that
            // same attach's `issue_ticket` minting a ticket for a session
            // that is already gone — is real but narrow (single `.await`
            // wide) and self-healing: `TICKET_TTL` (30 s) is its upper
            // bound even if this exact interleaving is hit.
            let dropped = {
                let mut tickets = self.lock_tickets();
                extract_tickets(
                    &mut tickets,
                    |t| !matches!(&t.purpose, TicketPurpose::Session { session_id, .. } if *session_id == id),
                )
            };
            // Same "collect under the guard, drop outside" discipline
            // (ADR-0010 §9) as `issue_ticket`/`pending_tickets_for`'s
            // expiry sweep and `purge_connection`'s connection-close
            // sweep — even though the `TicketPurpose::Session` tickets
            // dropped here never carry a `crate::quota::ExecPermit` (only
            // `TicketPurpose::Exec` does), so this particular `drop` can
            // never re-take the quota lock today. Keeping the same shape
            // as those other three `extract_tickets` call sites anyway
            // means a future `TicketPurpose` variant that *does* carry a
            // permit cannot silently violate ADR-0010 §9 just because this
            // call site looked different.
            drop(dropped);
        }
        match result {
            Ok(final_seq) => ControlMessage::response(
                request_id,
                response::Body::SessionClosed(wire::SessionClosed { final_seq }),
            ),
            Err(err) => broker_error(request_id, err),
        }
    }

    /// `session.attach` (stream op), including **resume** (protocol.md §10).
    ///
    /// The order is the protocol's, and it is load-bearing:
    ///
    /// 1. the presented `resume_token` must hash to the stored credential
    ///    and not be expired, **and** the connection's peer SPKI must be
    ///    the one the session is bound to. Both are one non-distinguishing
    ///    `AUTH_FAILED`: an unauthorized peer must not be able to tell an
    ///    unknown session from a wrong token from a foreign device
    ///    (protocol.md §10-2);
    /// 2. the ACL choke point (`session.attach` on the id, audited like
    ///    every other session op);
    /// 3. **only then** the writer lease, the successor token — which
    ///    kills the presented one — and the single-use `SESSION_DATA`
    ///    ticket.
    ///
    /// `SESSION_NOT_FOUND` is reachable only past step 1, so it never
    /// discloses existence to a peer that failed the identity check.
    ///
    /// A `SessionAttach` carrying **no** credential is refused outright,
    /// with the same non-distinguishing `AUTH_FAILED`. The credential is
    /// what binds an attach to the device that opened the session
    /// (ADR-0007 결정 2, protocol.md §10), and a check the client performs
    /// on itself is not a boundary: making the field optional would let any
    /// peer the ACL admits — under the M1–M4 allow-all-pinned posture, any
    /// pinned device — take an RW PTY on somebody else's shell just by
    /// leaving the field empty. The first stream of a freshly opened
    /// session does not come through here: `session.open` mints its own
    /// `SESSION_DATA` ticket.
    pub(super) async fn handle_session_attach(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::SessionAttach,
    ) -> ControlMessage {
        if let Err(reply) = self.require_session_capability(ctx, request_id) {
            return *reply;
        }
        if let Err(reply) = Self::require_session_id(request_id, &req.session_id) {
            return *reply;
        }
        if req.attach_mode() != Some(wire::AttachMode::Rw) {
            return invalid_argument(request_id, "attach mode must be RW");
        }
        let id = SessionId(req.session_id.clone());
        // ---- Step 1: credential + bound identity, before anything else
        // touches the registry. ----
        let lineage = match ctx.peer_fingerprint {
            // An empty field never reaches `verify` as a token: it is
            // refused here, so the gate cannot be opted out of.
            Some(peer) if !req.resume_token.is_empty() => {
                self.sessions.verify_resume(&id, &req.resume_token, peer)
            }
            // No verified leaf to bind against, or no credential presented:
            // fail closed, and answer exactly as a bad credential does.
            _ => Err(ResumeDenied),
        };
        let lineage = match lineage {
            Ok(stream) => stream,
            Err(_) => {
                // Structural only — the record names the op, the principal
                // and the decision, never the credential (CLAUDE.md).
                // Already denying (same exception as `handshake_rejected`):
                // a failure to record this deny doesn't change the
                // outcome, only the diagnostic.
                let _ = self.audit.record(&AuditRecord::now(
                    request_id,
                    &ctx.principal,
                    ctx.auth_path,
                    crate::acl::Op::SessionAttach.action(),
                    &req.session_id,
                    crate::acl::Decision::Deny,
                    // Not a policy-rule decision — a credential-
                    // verification failure upstream of `Authorizer::
                    // check`, so no rule index applies.
                    None,
                    ctx.peer_addr,
                ));
                tracing::warn!(
                    principal = %ctx.principal,
                    peer = %ctx.peer_addr,
                    "session.attach rejected: resume credential did not verify"
                );
                return auth_failed(request_id);
            }
        };
        if let Err(denied) = self.authorize(
            ctx,
            request_id,
            crate::acl::Op::SessionAttach.action(),
            &req.session_id,
        ) {
            return *denied;
        }

        // ---- Resource bound and drain gate, same reasoning as
        // `exec.run`/`session.open`. ----
        //
        // Both placed *after* the credential and the ACL rather than
        // before them, unlike the capability check above: either answer
        // before the identity gate is one a peer with no credential could
        // tell apart from `AUTH_FAILED`, and protocol.md §10-2 requires
        // that every pre-identity refusal look the same. Placed before the
        // lease probe and the rotation, so a refused attach still spends
        // no credential and moves nothing.
        if let Err(reply) = self.require_not_draining(request_id) {
            return *reply;
        }
        if let Err(reply) = self.check_ticket_budget(ctx, request_id) {
            return *reply;
        }

        // ---- Allowed: lease, then a single-use ticket. ----
        //
        // `broker_error` here and at the two registry calls below can
        // spell `SESSION_NOT_FOUND`, which protocol.md §10-2 forbids on the
        // attach path — an unauthorized peer must not learn whether a
        // session exists. It stays unreachable rather than being mapped:
        // every removal path (`Broker::close`, the reaper) calls
        // `resume.forget` with the session, so a credential can only verify
        // in step 1 while the session is still registered, and the gap
        // between the two is not observable from outside the broker lock.
        // Left as-is deliberately — folding it into `AUTH_FAILED` would
        // hide a genuine broker bug behind a credential answer.
        let info = match self.sessions.get(&id) {
            Ok(info) => info,
            Err(err) => return broker_error(request_id, err),
        };
        // Interactive attach steals by default (architecture.md §3 rule b);
        // `no_steal` makes a live foreign lease a `SESSION_CONFLICT`.
        //
        // A **probe**, not a take: the redemption is not decided yet (the
        // rotation below can still lose a race), and CLAUDE.md's "never
        // create a resource before authorization succeeds" applies just as
        // much to moving one that already exists. Stealing here and failing
        // afterwards would leave the legitimate writer demoted in favour of
        // a connection that never attached. The real, actor-serialised take
        // happens where the data stream opens, which is also where a lease
        // that changed hands in between is caught.
        if req.no_steal
            && self
                .sessions
                .lease_conflict(&id, &ctx.principal.to_string())
        {
            return ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::SessionConflict,
                    "another principal holds the session's writer lease",
                    true,
                ),
            );
        }
        // A cursor past the end of the stream is `INVALID_ARGUMENT` at the
        // ring; clamp instead, so a client that over-reports simply gets
        // everything from the current end.
        let replay_from = req.last_output_seq.min(info.last_sequence);
        // The id of this attach's own input axis — reserved, not yet
        // created. The credential rotation below has to name the axis it
        // hands to the next generation, and the rotation is the point where
        // this redemption becomes final; creating the axis first would mint
        // session state for an attach that can still lose its race, which is
        // the same reason `no_steal` above is a probe rather than a take.
        // Reserving costs a counter value and no axis slot, so a lost race
        // cannot evict a live peer's axis from the bounded window.
        let input_stream = match self.sessions.reserve_input_stream(&id) {
            Ok(stream) => stream,
            Err(err) => return broker_error(request_id, err),
        };
        // The successor credential. Minted last, after every check passed:
        // the presented token dies here, so a redemption that got this far
        // is the one and only winner (protocol.md §10 "Rotation").
        let new_resume_token = {
            let Some(peer) = ctx.peer_fingerprint else {
                return auth_failed(request_id);
            };
            match self
                .sessions
                .rotate_resume(&id, &req.resume_token, peer, input_stream)
            {
                Ok(token) => token,
                // Lost the race with another redemption of the same token
                // between step 1 and here. Same non-distinguishing answer,
                // and no axis was created to leak.
                Err(_) => return auth_failed(request_id),
            }
        };
        // Won. Now create the axis, forked from the one the credential
        // named and seeded with that axis's applied offset: the un-acked
        // tail the client retransmits is deduplicated against what the child
        // already ran, and the attach this one succeeds — which may still be
        // connected and typing after its demotion — cannot move the cursor
        // (protocol.md §10-5).
        let input_from = match self
            .sessions
            .seed_input_stream(&id, input_stream, Some(lineage))
        {
            Ok(from) => from,
            Err(err) => return broker_error(request_id, err),
        };
        let ticket = self.issue_ticket(
            ctx.conn_id,
            TicketPurpose::Session {
                session_id: id.clone(),
                replay_from,
                no_steal: req.no_steal,
                attach_authorized: true,
                input_stream,
                input_from,
            },
        );
        let expires_at = rfc3339_after(self.sessions.resume_ttl());
        tracing::info!(
            principal = %ctx.principal,
            peer = %ctx.peer_addr,
            session_id = %id,
            replay_from,
            "session.attach authorized"
        );
        ControlMessage::response(
            request_id,
            response::Body::SessionAttached(wire::SessionAttached {
                ticket: ticket.to_vec(),
                new_resume_token: new_resume_token.expose().to_vec(),
                replay_from,
                writer_lease: true,
                expires_at,
                input_seq: input_from,
            }),
        )
    }
}
