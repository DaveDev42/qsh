//! Remote forward (`-R`) handlers of [`Server`]: `RemoteForwardOpen`/`Close` and the bind choke point.

use super::*;

impl Server {
    // ------------------------------------------------------------------
    // remote forward (`-R`), M4 Step 4 — `RemoteForwardOpen`/`Close`
    // ------------------------------------------------------------------

    /// The `forward.remote` choke point, factored out of
    /// [`Server::handle_rfwd_open`] so it is unit-testable with **no
    /// transport connection at all** — mirrors
    /// [`Server::authorize_and_dial_tunnel`]'s shape exactly, one gate
    /// later:
    ///
    /// 1. shape-check the request (nothing created, no decision made);
    /// 2. [`Server::authorize`] — `Authorizer::check` + one [`AuditRecord`]
    ///    line for allow *and* deny alike, `Action::ForwardRemote` on
    ///    `bind_host:bind_port` (`PLAN.md` M4 Step 4's choke point);
    /// 3. **loopback enforcement** —
    ///    `crate::tunnel::remote::resolve_loopback_bind_addr`, which
    ///    resolves `bind_host` **once** and hands back the very address it
    ///    validated, so step 4 binds exactly what step 3 approved (that
    ///    function's own doc explains why a second resolution would be a
    ///    peer-steerable bypass, not a theoretical one). Deliberately
    ///    **after** the ACL gate and **not itself one**: a principal that
    ///    holds `forward.remote` outright still cannot bind non-loopback,
    ///    because this is a request constraint the host applies to every
    ///    principal alike, never a per-principal permission
    ///    (`crate::acl::Action::ForwardRemote`'s own doc,
    ///    `crate::tunnel::remote`'s module doc). A failure here is
    ///    therefore [`ErrorCode::InvalidArgument`] — a bad request — never
    ///    `PermissionDenied`, which would claim this principal specifically
    ///    was refused;
    /// 4. `binder.bind(...)` — unreachable unless steps 2 *and* 3 both
    ///    passed. Nothing before this point ever creates a socket.
    ///
    /// Returns the bound listener; minting a `forward_id`, spawning the
    /// accept loop and registering it are [`Server::handle_rfwd_open`]'s
    /// job, because those need a [`Connection`] this function is
    /// deliberately never given (see that method's own doc).
    pub(crate) async fn authorize_and_bind_remote_forward(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::RemoteForwardOpen,
        resolver: &dyn BindHostResolver,
        binder: &dyn RemoteForwardBinder,
    ) -> Result<(tokio::net::TcpListener, crate::quota::RemoteForwardPermit), Box<ControlMessage>>
    {
        // (1) Shape. A malformed request never becomes an ACL decision or a
        // socket, same discipline as `authorize_and_dial_tunnel`'s own (1).
        let Ok(bind_port) = u16::try_from(req.bind_port) else {
            return Err(Box::new(invalid_argument(
                request_id,
                "bind_port out of range",
            )));
        };
        let Ok(forward_port) = u16::try_from(req.forward_port) else {
            return Err(Box::new(invalid_argument(
                request_id,
                "forward_port out of range",
            )));
        };
        if req.forward_host.is_empty() || forward_port == 0 {
            return Err(Box::new(invalid_argument(
                request_id,
                "forward_host and forward_port are required",
            )));
        }

        // (2) THE gate. `bind_host:bind_port` is the ACL resource — the
        // canonical bracketed form, same helper and same reasoning
        // `authorize_and_dial_tunnel`'s own resource string uses. An empty
        // `bind_host` (no `bind:` prefix — the ordinary `-R rport:host:
        // hport` shape) is the wire default for loopback
        // (`crate::tunnel::remote::resolve_loopback_bind_addr`'s own doc),
        // so it is displayed as the address it actually binds rather than
        // literally empty — the same substitution
        // `crate::ops::tunnel::remote_tunnel_dto` already makes, so the
        // audit line names the address this forward really binds instead
        // of a resource string no policy or operator could act on.
        //
        // `bind_host` is peer-supplied text on its way into an audit
        // record and a log line, so it is sanitized first: a raw one could
        // carry ANSI/OSC escapes into an operator's terminal or forge
        // extra lines in an audit sink
        // (`qsh_proto::wire::sanitize_peer_text`'s own doc, the same
        // treatment Step 3 gave peer tunnel text). Sanitizing cannot widen
        // what binds — a host name carrying control characters resolves to
        // nothing, and only the raw string is ever handed to the resolver.
        let display_bind_host = if req.bind_host.is_empty() {
            "127.0.0.1".to_string()
        } else {
            wire::sanitize_peer_text(&req.bind_host)
        };
        let resource = wire::format_host_port(&display_bind_host, bind_port);
        self.authorize(
            ctx,
            request_id,
            crate::acl::Op::ForwardRemote.action(),
            &resource,
        )?;

        // (3) Loopback-only bind — see this function's own doc for why
        // this is `InvalidArgument`, never `PermissionDenied`. One
        // resolution decides it, and the address it returns is the address
        // step (4) binds: no second lookup can slip a routable address in
        // behind the check. A resolve failure is folded into "not
        // loopback": there is nothing to bind either way, and the caller
        // learns the same thing a genuinely non-loopback answer would tell
        // it.
        let addr =
            crate::tunnel::remote::resolve_loopback_bind_addr(resolver, &req.bind_host, bind_port)
                .await
                .map_err(|err| Box::new(invalid_argument(request_id, err.to_string())))?;

        // (3.5) The remote-forward-listener concurrency quota (M8 Step 3b,
        // `[serve].max_remote_forwards_per_principal`): after the ACL
        // decision and the loopback shape check (an unauthorized principal
        // must see `PERMISSION_DENIED`, and a non-loopback bind must see
        // `INVALID_ARGUMENT` — neither should ever be shadowed by
        // `RESOURCE_EXHAUSTED`), strictly **before** `binder.bind` below:
        // nothing may be created before the reservation succeeds, same
        // shape as `authorize_and_dial_tunnel`'s own `reserve_tunnel_
        // stream` gate. A spy `binder` in this module's own unit tests
        // must observe zero `bind` calls on a refusal here.
        let opener = crate::acl::opener_key(&ctx.principal, ctx.auth_path);
        let quota = self
            .quotas
            .reserve_remote_forward(&opener)
            .map_err(|kind| {
                let records = self.quotas.record_rejection(
                    kind,
                    &opener,
                    ctx.peer_addr,
                    self.quotas.now(),
                    Some(request_id),
                    ctx.auth_path,
                );
                crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                Box::new(ControlMessage::error(
                    request_id,
                    wire::Error::new(ErrorCode::ResourceExhausted, kind.wire_message(), true),
                ))
            })?;

        // (4) Only now may a resource come into existence.
        let listener = binder.bind(addr).await.map_err(|err| {
            Box::new(ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::ConnectionFailed,
                    format!("failed to bind {addr}: {err}"),
                    false,
                ),
            ))
        })?;
        Ok((listener, quota))
    }

    /// Full production handling of `RemoteForwardOpen`: the choke point
    /// ([`Server::authorize_and_bind_remote_forward`]) plus the parts that
    /// need a live [`Connection`] — minting the `forward_id`, spawning
    /// [`crate::tunnel::remote::serve_remote_forward`], and registering it
    /// in [`Server::remote_forwards`] for [`Server::handle_rfwd_close`]/
    /// [`Server::purge_connection`] to find later.
    ///
    /// Called only from [`Server::serve_control`]'s message loop — the one
    /// place a [`Connection`] to open this forward's future `TCP_ACCEPTED`
    /// streams on is actually available (`dispatch`'s own RfwdOpen arm
    /// documents why it cannot do this itself).
    pub(super) async fn handle_rfwd_open(
        self: &Arc<Self>,
        ctx: &ConnCtx,
        conn: &Connection,
        request_id: u64,
        req: &wire::RemoteForwardOpen,
    ) -> ControlMessage {
        let (listener, quota) = match self
            .authorize_and_bind_remote_forward(ctx, request_id, req, &SystemResolver, &SystemBinder)
            .await
        {
            Ok(pair) => pair,
            Err(reply) => return *reply,
        };
        let actual_addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(err) => {
                // Bound but unreadable back — treat the listener as
                // unusable; dropping it here (end of scope) closes it, so
                // this is still a clean "nothing left running" failure.
                return ControlMessage::error(
                    request_id,
                    wire::Error::new(
                        ErrorCode::ConnectionFailed,
                        format!("bound remote-forward listener has no local address: {err}"),
                        false,
                    ),
                );
            }
        };
        let actual_port = actual_addr.port();

        // Structural record at bind success (`PLAN.md` §4.1's Step 4
        // adversarial-review carryover): the authorization record above
        // (`authorize_and_bind_remote_forward`'s step (2)) names the
        // *requested* `bind_host:bind_port` and has to — a kernel-assigned
        // ephemeral port is not knowable before a bind, and authorizing it
        // would mean creating the resource before authorization succeeds.
        // That leaves an incident reader unable to tell what was actually
        // opened from `localhost:0`. This is the other half: op,
        // principal, result, and the address the kernel actually handed
        // back — nothing payload-shaped ever reaches this line, only what
        // `TcpListener::local_addr` reports.
        tracing::info!(
            op = "forward.remote.bind",
            result = "ok",
            principal = %ctx.principal,
            %actual_addr,
            "tunnel: remote-forward listener bound"
        );

        let forward_id = ulid::Ulid::new().to_string();
        // Self-removal on a fatal accept error (M8 Step 3b) — factored
        // into `run_remote_forward_accept_loop` (this module's own free
        // fn, below, generic over the serve future) both so this spawn
        // stays short and so a test can drive the exact same production
        // self-removal tail with a cheap stand-in future instead of a
        // real listener (R10).
        let task = tokio::spawn(run_remote_forward_accept_loop(
            Arc::downgrade(self),
            crate::tunnel::remote::serve_remote_forward(
                listener,
                conn.clone(),
                forward_id.clone().into_bytes(),
                Arc::clone(&self.quotas),
                Arc::clone(&self.audit),
            ),
            forward_id.clone(),
        ));
        // Recorded under this connection's authenticated `(principal,
        // auth_path)`, not `ctx.conn_id` alone — the ACL ownership axis
        // `Server::handle_rfwd_close` checks (`Server::remote_forwards`'s
        // own doc, `PLAN.md` M5 Step 5 (a)).
        self.remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                forward_id.clone(),
                RemoteForwardEntry {
                    conn_id: ctx.conn_id,
                    owner: opener_key(&ctx.principal, ctx.auth_path),
                    task,
                    _quota: quota,
                },
            );

        // `bind_host` is peer-supplied text on its way to a log line, so
        // it is sanitized (`authorize_and_bind_remote_forward`'s step (2)
        // makes the same substitution for the audit resource, and for the
        // same reason). `forward_id` is host-minted here — a ULID, so
        // `wire::valid_forward_id` holds by construction; the test
        // `minted_forward_ids_satisfy_the_wire_shape` pins that.
        tracing::info!(
            principal = %ctx.principal,
            %forward_id,
            bind_host = %wire::sanitize_peer_text(&req.bind_host),
            actual_port,
            "tunnel: remote forward opened"
        );

        ControlMessage::response(
            request_id,
            response::Body::RfwdOpened(wire::RemoteForwardOpened {
                forward_id,
                actual_port: u32::from(actual_port),
            }),
        )
    }

    /// `RemoteForwardClose`: the `Action::ForwardRemote` choke point
    /// (`PLAN.md` M5 Step 5 (a)) over this `forward_id`'s registered
    /// owner, then — only on a pass — abort and drop it.
    ///
    /// In order:
    ///
    /// 1. **Shape** — before this peer-supplied string is used to look
    ///    anything up, tear anything down, reach an ACL decision, or reach
    ///    a log line (`qsh_proto::wire::valid_forward_id`, the same "check
    ///    shape before it becomes a resource or an audit field" discipline
    ///    `valid_host_name` states and `valid_session_id` follows).
    /// 2. **Owner lookup** — a read-only peek at `Server::remote_forwards`
    ///    for this `forward_id`'s recorded owner, `None` if this host has
    ///    no such forward at all (already closed, never opened, or a
    ///    peer-supplied id that never existed). This step decides nothing
    ///    by itself and changes no wire-visible behavior on its own — it
    ///    only fills [`ResourceRef::owner`] for step 3, so a `DenyAll`
    ///    host still answers `PERMISSION_DENIED` for an unknown
    ///    `forward_id` exactly as it would for a real one (the choke point
    ///    fires **before** the existence question is ever answered on the
    ///    wire — no "which failure mode" oracle).
    /// 3. **The choke point proper** — [`Self::authorize_owned`],
    ///    `Action::ForwardRemote` on `forward_id` with the owner from step
    ///    2. `owner: None` (no such forward) is never filtered by scope
    ///    (`ResourceRef`'s own doc), so this step's own verdict depends
    ///    only on the ordinary policy match for that case — never a
    ///    manufactured allow or deny. A different principal than the one
    ///    that opened it is refused here under `scope = "owned"`,
    ///    byte-identically to any other `PERMISSION_DENIED`
    ///    (`crate::acl::PERMISSION_DENIED_MESSAGE`'s own doc) — but the
    ///    *same* principal reconnected on a different `conn_id` is still
    ///    the forward's owner (`RemoteForwardEntry::owner`'s own doc) and
    ///    passes.
    /// 4. **Remove** — only reachable past a pass at step 3. `None` here
    ///    (nothing to remove) is `InvalidArgument`, not a second
    ///    `PermissionDenied`: by this point the request already cleared
    ///    the ACL choke point (owner was `None`, so `scope` admitted it
    ///    unconditionally), so "no such forward_id" is an ordinary bad
    ///    request, the same shape `session.write`/`resize` already give an
    ///    unknown `session_id` past their own ownership gate.
    ///
    /// `docs/CLI.md` §2.5's full owning-peer semantics for `tunnel.close`
    /// (as an `Ops` surface) are `PLAN.md` M4 Step 5 scope; this is the
    /// wire-level primitive that step builds on.
    pub(super) fn handle_rfwd_close(
        &self,
        ctx: &ConnCtx,
        request_id: u64,
        req: &wire::RemoteForwardClose,
    ) -> ControlMessage {
        // (1) Shape. Every id this map can hold is a host-minted ULID,
        // which satisfies the predicate by construction, so a malformed
        // one could only ever have missed — but it must miss *without*
        // being touched. Past this point the id is `[A-Za-z0-9_-]{1,64}`,
        // strictly stronger than sanitizing, so the success line below
        // logs it as it is.
        if !wire::valid_forward_id(&req.forward_id) {
            tracing::warn!(
                principal = %ctx.principal,
                forward_id_len = req.forward_id.len(),
                "tunnel: malformed forward_id on RemoteForwardClose"
            );
            return invalid_argument(request_id, "malformed forward_id");
        }

        // (2) Owner lookup — decides nothing, only fills `ResourceRef`.
        let owner = self
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&req.forward_id)
            .map(|entry| entry.owner.clone());

        // (3) THE gate.
        if let Err(reply) = self.authorize_owned(
            ctx,
            request_id,
            crate::acl::Op::ForwardRemoteClose.action(),
            ResourceRef {
                id: &req.forward_id,
                owner: owner.as_deref(),
            },
        ) {
            return *reply;
        }

        // (4) Allowed: remove and abort, or (an unknown id, which always
        // has `owner: None` and so always cleared step 3) answer that
        // there was nothing to close.
        let removed = self
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&req.forward_id);
        match removed {
            Some(entry) => {
                entry.task.abort();
                tracing::info!(
                    principal = %ctx.principal,
                    forward_id = req.forward_id,
                    "tunnel: remote forward closed"
                );
                // Bare success (`v1.proto`'s own comment on
                // `RemoteForwardClose`: "no dedicated payload").
                ControlMessage::new(
                    request_id,
                    control_message::Body::Response(wire::Response { body: None }),
                )
            }
            None => invalid_argument(request_id, "no such forward_id"),
        }
    }
}
