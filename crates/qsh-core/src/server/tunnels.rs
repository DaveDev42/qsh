//! Local port forward (`-L`) and the peer-opened data-stream admission path of [`Server`].

use super::*;

impl Server {
    /// Host side of a local forward (`-L`): a peer-opened `TCP_CONNECT`
    /// stream asking this host to dial `header.host:header.port` and splice
    /// the bytes.
    ///
    /// **Why the ACL check is inline here and not at the control-stream
    /// choke point** (`docs/design/protocol.md` §7, `PLAN.md` M4 Step 3):
    /// every other data stream must first redeem a ticket that a control
    /// request already got authorized for, which is what makes "no resource
    /// before authorization" structural. `TCP_CONNECT` is §7's *sole*
    /// exception — one TCP connection through the forward would otherwise
    /// cost a full control-stream RPC round-trip before its first byte,
    /// which is exactly the latency a port forward exists to avoid. The
    /// exception is to the *ticket*, never to the authorization: this
    /// function runs [`Authorizer::check`] + [`AuditRecord`] as the very
    /// first thing it does with the destination, and only a `Decision::
    /// Allow` can reach the dialer below. On a deny nothing is dialed, no
    /// socket exists, and the stream is refused — the same posture the
    /// ticket would have enforced, moved inline (`docs/PRD.md` §9,
    /// `docs/design/architecture.md` §6).
    ///
    /// **Concurrency bound.** Nothing here caps how many `TCP_CONNECT`
    /// streams one connection may have in flight, because the transport
    /// already does: `qsh_transport::endpoint::MAX_CONCURRENT_BIDI_STREAMS`
    /// (1024) is the peer's whole bidi-stream allowance, so concurrent
    /// tunnel splices — and the upstream fds they hold open — are bounded
    /// at 1024 per connection, on a peer that is mTLS-pinned to begin with
    /// (the M1-M4 interim allow-all-pinned posture). A tunnel-specific
    /// quota tighter than that connection-wide cap (per principal, per
    /// forward) **is** M8 Step 3b scope now:
    /// [`Server::authorize_and_dial_tunnel`]'s [`crate::quota::
    /// TunnelStreamPermit`] is held for this whole function's lifetime
    /// (bound below, released only when this function returns — normal
    /// completion, error, or task-abort unwind alike), so the splice
    /// itself never has to know the quota exists.
    pub(super) async fn handle_tcp_connect(
        &self,
        ctx: &ConnCtx,
        mut stream: FramedStream,
        header: &StreamHeader,
    ) {
        // Tunnel bytes must never outrank a PTY chunk in the local send
        // queue (`docs/design/protocol.md` §12). Set before anything is
        // written on this stream, including the `ConnectResult`.
        stream.send.set_priority(wire::PRIORITY_TUNNEL);

        // `SystemDialer::default()` carries the production
        // `TUNNEL_DIAL_TIMEOUT`; only tests ever build one with a
        // different bound.
        let dialed = self
            .authorize_and_dial_tunnel(ctx, header, &SystemDialer::default())
            .await;

        let (upstream, _permit) = match dialed {
            Err(rejection) => {
                // §7 requires the requester learn *why*, so the refusal is
                // a `ConnectResult` frame and a clean FIN — `reset()` here
                // would discard the frame we just wrote and leave the peer
                // guessing. The refusal is still terminal: the receive half
                // is stopped, nothing was dialed, nothing is spliced.
                // The teardown signal alongside it is picked to match the
                // reason, so a peer reading only the QUIC code is not
                // misinformed: a policy refusal is `FORBIDDEN`, a
                // malformed destination is `BAD_HEADER`, and a destination
                // that simply would not accept is nobody's protocol error
                // — code 0, "we are just done reading".
                let stop_code = match rejection.code.parse::<ErrorCode>() {
                    Ok(ErrorCode::PermissionDenied) => RESET_CODE_FORBIDDEN,
                    Ok(ErrorCode::InvalidArgument) => RESET_CODE_BAD_HEADER,
                    Ok(ErrorCode::ResourceExhausted) => RESET_CODE_RESOURCE_EXHAUSTED,
                    _ => 0,
                };
                let _ = stream.send.send(&rejection).await;
                let _ = stream.send.finish();
                stream.recv.stop(stop_code);
                return;
            }
            Ok((upstream, permit)) => {
                if stream
                    .send
                    .send(&wire::ConnectResult {
                        ok: true,
                        code: String::new(),
                        message: String::new(),
                    })
                    .await
                    .is_err()
                {
                    // Peer went away between the dial and the reply; drop
                    // the freshly-dialed socket (and the quota permit
                    // with it) rather than splice into nothing.
                    return;
                }
                // `permit` is carried out to the outer `let` below — held
                // until this function returns (see the doc comment above
                // `handle_tcp_connect`, `crate::quota::TunnelStreamPermit`).
                (upstream, permit)
            }
        };

        // Framing ends with the `ConnectResult{ok:true}` just written: from
        // here this stream is a raw, unframed byte pipe in both directions
        // (`docs/design/protocol.md` §5, §7), so both halves are
        // surrendered to `crate::tunnel::splice`, which copies bytes
        // without parsing or logging a single one of them (`CLAUDE.md`
        // "never log payload"). `into_raw` on the receive half also hands
        // back whatever the requester pipelined behind its `StreamHeader`
        // frame — bytes already read into the frame decoder, which the
        // splice must write to the destination *first* or the forwarded
        // connection loses its own first bytes.
        let (send, recv) = stream.split();
        let (raw_recv, residue) = recv.into_raw();
        let outcome = splice_tcp_quic(upstream, send.into_raw(), raw_recv, residue).await;

        // Structural only: destination and byte counts, never payload
        // (`PLAN.md` M4 §4 "터널 payload 로그 금지" — `SpliceStats` has no
        // field a payload byte could hide in).
        match outcome {
            // `sent`/`received` are **this end's** view of the tunnel, the
            // same convention the requester's own log uses
            // (`crate::tunnel::local::LocalForward::run`): `sent` is what
            // this process pushed into the tunnel stream, `received` is
            // what it took out of it. So the field-to-label mapping is
            // identical on both ends — `local_to_remote` is always the
            // splice's TCP-socket-to-tunnel direction, hence always
            // `sent` — even though "local" names a different socket on
            // each end (here the dialed destination, there the local
            // application). Reading one tunnel's two logs, this host's
            // `received` is the requester's `sent` and vice versa, which
            // is what endpoint-relative counters are supposed to say.
            Ok(stats) => tracing::debug!(
                principal = %ctx.principal,
                host = header.host,
                port = header.port,
                sent = stats.local_to_remote,
                received = stats.remote_to_local,
                "tunnel: local forward closed"
            ),
            Err(err) => tracing::debug!(
                principal = %ctx.principal,
                host = header.host,
                port = header.port,
                %err,
                "tunnel: local forward aborted"
            ),
        }
    }

    /// The `forward.local` gate, factored out of [`Server::handle_tcp_connect`]
    /// so it is testable with no transport at all: **authorize, then — and
    /// only then — dial**.
    ///
    /// Order is the whole contract of this function:
    /// 1. shape-check the destination (nothing created, no decision made);
    /// 2. [`Server::authorize_stream`] — `Authorizer::check` + one
    ///    [`AuditRecord`] line for allow *and* deny alike;
    /// 3. `dialer.dial(...)` — unreachable unless step 2 returned allow.
    ///
    /// A local forward's destination is chosen by the requester and is
    /// **not** restricted here (unlike `-R`'s loopback-only bind, Step 4):
    /// `host:port` is the ACL resource, so restricting destinations is the
    /// policy engine's job (M5), not this code's.
    ///
    /// `Err` is the [`wire::ConnectResult`] to hand the requester verbatim.
    pub(crate) async fn authorize_and_dial_tunnel(
        &self,
        ctx: &ConnCtx,
        header: &StreamHeader,
        dialer: &dyn TunnelDialer,
    ) -> Result<(tokio::net::TcpStream, crate::quota::TunnelStreamPermit), wire::ConnectResult>
    {
        // (1) Shape. A malformed destination never becomes an ACL decision
        // (there is nothing to decide *about*) and never becomes a socket
        // — same discipline as `docs/design/protocol.md` §9's "check the
        // shape of a session id before the choke point".
        let Ok(port) = u16::try_from(header.port) else {
            return Err(connect_rejected(
                ErrorCode::InvalidArgument,
                "destination port out of range",
            ));
        };
        if header.host.is_empty() || port == 0 {
            return Err(connect_rejected(
                ErrorCode::InvalidArgument,
                "destination host and port are required",
            ));
        }
        // A host this long is never a real DNS name (255-octet wire
        // limit, RFC 1035 §3.1) or a literal IP — nothing legitimate is
        // refused here, but an unbounded host string is an unbounded ACL
        // resource / audit field / quota map key (M8 Step 3b ruling: this
        // shape check belongs beside the others, before the ACL choke
        // point, same "nothing to decide about" reasoning).
        if header.host.len() > 255 {
            return Err(connect_rejected(
                ErrorCode::InvalidArgument,
                "destination host is too long",
            ));
        }
        // Canonical `host:port` — bracketed for an IPv6 literal, which
        // `parse_forward_spec` delivers bracket-stripped, so a plain
        // `format!` would build the unsplittable `::1:5432`. This string
        // is the ACL resource *and* the audit field, and M5's policy
        // engine will pattern-match rules against it, so the canonical
        // form is pinned in the contract crate rather than improvised
        // here (`qsh_proto::wire::format_host_port`).
        let resource = wire::format_host_port(&header.host, port);

        // (2) THE gate. Nothing exists yet: no socket, no resolver call, no
        // file descriptor of any kind. `authorize_stream` is the same
        // helper `SESSION_DATA`'s inline attach check uses — it decides and
        // writes the audit line for both outcomes (SC6: every privileged op
        // leaves an audit record).
        if !self.authorize_stream(ctx, crate::acl::Op::ForwardLocal.action(), &resource) {
            // The same constant the control-stream `PERMISSION_DENIED`
            // uses (`Server::permission_denied`): a denial must not tell
            // the peer *which* rule refused it.
            return Err(connect_rejected(
                ErrorCode::PermissionDenied,
                crate::acl::PERMISSION_DENIED_MESSAGE,
            ));
        }

        // (2.5) The tunnel-stream concurrency quota (M8 Step 3b,
        // `[serve].max_tunnel_streams_per_principal`/
        // `max_tunnel_streams_per_forward`): after the ACL decision (an
        // unauthorized principal must see `PERMISSION_DENIED`, never a
        // quota oracle — `crate::quota`'s own module doc), before the
        // dial (nothing is created before a reservation succeeds). Same
        // shape as `handle_exec_start`'s `reserve_exec` gate
        // (`server/mod.rs` exec path).
        let opener = crate::acl::opener_key(&ctx.principal, ctx.auth_path);
        let permit = match self.quotas.reserve_tunnel_stream(&opener, &resource) {
            Ok(permit) => permit,
            Err(kind) => {
                let records = self.quotas.record_rejection(
                    kind,
                    &opener,
                    ctx.peer_addr,
                    self.quotas.now(),
                    None,
                    ctx.auth_path,
                );
                crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                return Err(connect_rejected(
                    ErrorCode::ResourceExhausted,
                    kind.wire_message(),
                ));
            }
        };

        // (3) Only now may a resource come into existence.
        match dialer.dial(&header.host, port).await {
            Ok(upstream) => Ok((upstream, permit)),
            Err(err) => {
                // The destination, not the payload: safe to log, and the
                // only thing about this tunnel that ever is.
                tracing::debug!(principal = %ctx.principal, %resource, %err, "tunnel dial failed");
                Err(connect_rejected(err.code(), err.to_string()))
            }
        }
    }

    /// Admit a peer-opened data stream: read the header, redeem the ticket
    /// for that stream kind, run the exec. Anything else resets the stream
    /// without touching any resource.
    pub(super) async fn handle_data_stream(
        &self,
        ctx: ConnCtx,
        mut stream: FramedStream,
        conn: Connection,
        events: tokio::sync::mpsc::Sender<ControlMessage>,
    ) {
        let header =
            match tokio::time::timeout(HEADER_TIMEOUT, stream.recv.recv::<StreamHeader>()).await {
                Ok(Ok(Some(h))) => h,
                _ => {
                    stream.send.reset(RESET_CODE_BAD_HEADER);
                    stream.recv.stop(RESET_CODE_BAD_HEADER);
                    return;
                }
            };
        // `TCP_CONNECT` is the one stream kind that carries **no ticket**
        // (`docs/design/protocol.md` §7: "유일한 예외는 `TCP_CONNECT`"), so it
        // branches off before ticket redemption — see
        // [`Server::handle_tcp_connect`] for why the ACL check is inline
        // here instead of at the control-stream choke point.
        if header.stream_kind() == Some(StreamKind::TcpConnect) {
            self.handle_tcp_connect(&ctx, stream, &header).await;
            return;
        }
        let kind = match header.stream_kind() {
            Some(kind @ (StreamKind::ExecData | StreamKind::SessionData)) => kind,
            _ => {
                tracing::debug!(principal = %ctx.principal, kind = header.kind, "unsupported stream kind");
                stream.send.reset(RESET_CODE_BAD_HEADER);
                stream.recv.stop(RESET_CODE_BAD_HEADER);
                return;
            }
        };
        let Some(ticket) = self.redeem_ticket(ctx.conn_id, kind, &header.ticket) else {
            tracing::warn!(principal = %ctx.principal, ?kind, "data stream with invalid ticket");
            stream.send.reset(RESET_CODE_BAD_HEADER);
            stream.recv.stop(RESET_CODE_BAD_HEADER);
            return;
        };
        match ticket.purpose {
            TicketPurpose::Exec(pending) => {
                let exec_id = pending.exec_id.clone();
                stream.send.set_priority(wire::PRIORITY_EXEC_DATA);
                match run_exec(pending.spec, stream.send, stream.recv).await {
                    Ok(outcome) => tracing::info!(
                        principal = %ctx.principal,
                        %exec_id,
                        exit_code = outcome.exit_code,
                        timed_out = outcome.timed_out,
                        "exec finished"
                    ),
                    // The peer going away mid-exec (its own `--timeout`, a
                    // crash, a network drop) is ordinary operation, not a
                    // host-side fault: the child was killed and reaped,
                    // nothing to alarm about.
                    Err(err) if err.is_peer_gone() => tracing::info!(
                        principal = %ctx.principal,
                        %exec_id,
                        %err,
                        "exec aborted: peer went away; command killed"
                    ),
                    Err(err) => {
                        tracing::warn!(principal = %ctx.principal, %exec_id, %err, "exec failed")
                    }
                }
            }
            TicketPurpose::Session {
                session_id,
                replay_from,
                no_steal,
                attach_authorized,
                input_stream,
                input_from,
            } => {
                // Opening the session's data stream *is* the attach, and an
                // attach is RW (protocol.md §9), so it holds the writer
                // lease. A ticket minted by `session.attach` already passed
                // the ACL choke point; one minted by `session.open` did
                // not — `session.open` only authorized *opening*. Decide
                // and audit it here, before anything is taken, so a
                // principal allowed to open but not to attach cannot get an
                // interactive attach through the back door.
                //
                // Deliberately the literal `Action::SessionAttach`, not an
                // `acl::Op::SessionAttach.action()` lookup: this seam is
                // `DENY_SEAMS`'s `"session.attach@data-stream"` row, which
                // has no `OP_REGISTRY` entry of its own (`OpSpec`'s own
                // doc, `PLAN.md` M5 Step 8) — it shares the control-stream
                // `session.attach` op's `Action` but is a distinct wire
                // path with no CLI.md-documented name to look up.
                if !attach_authorized
                    && !self.authorize_stream(&ctx, Action::SessionAttach, session_id.as_str())
                {
                    stream.send.reset(RESET_CODE_FORBIDDEN);
                    stream.recv.stop(RESET_CODE_FORBIDDEN);
                    return;
                }
                // Steal-by-default is the interactive rule (architecture.md
                // §3 rule b); `no_steal` rides on the ticket so redeeming
                // cannot upgrade a careful attach into a stealing one. A
                // re-take on the connection that already holds the lease is
                // a no-op, so this is idempotent for an attach ticket — and
                // still honours `no_steal` if the lease changed hands
                // between the reply and this stream.
                //
                // `owner` is derived from the ticket, not
                // `ctx.connection_id()`, but **only** on a real reverse
                // registration (`ConnCtx::is_reverse_registration`'s own
                // doc): there, every local CLI process's data stream is
                // redeemed on the daemon's one shared registration
                // connection, so the physical connection alone cannot
                // tell two concurrent attaches apart
                // (`WriterLease::take_owned`'s own doc). Every other
                // connection this crate ever attaches over is already one
                // physical connection per attach, so `ctx.connection_id()`
                // is already a correct, stable identity there — and has
                // to stay `owner` on those routes, because a `session
                // write`/`session resize` value op issued on that *same*
                // connection (`Server::prepare_session_write`) derives its
                // own lease identity independently, straight from
                // `ctx.connection_id()`, with no ticket in sight to agree
                // on: diverging this attach's identity from that on a
                // route where they are the same physical asker would
                // desynchronize the two the moment either one re-takes
                // the lease (adversarial review fixer finding: exactly
                // this desync hung a steal-back on *both* the forward and
                // reverse variant of
                // `a_stolen_lease_demotes_the_attach_to_read_only_and_a_steal_back_resumes_it`,
                // neither of which actually multiplexes a connection).
                // `physical` stays `ctx.connection_id()` unconditionally
                // either way, so a dead connection — reverse registration
                // or forward attach alike — still releases whichever
                // attach currently holds the lease.
                let owner = if ctx.is_reverse_registration {
                    attach_lease_owner(&header.ticket)
                } else {
                    ctx.connection_id()
                };
                match self
                    .sessions
                    .take_lease_owned(
                        &session_id,
                        ctx.principal.to_string(),
                        owner,
                        ctx.connection_id(),
                        no_steal,
                    )
                    .await
                {
                    Ok(TakeOutcome::Conflict { .. }) => {
                        tracing::info!(
                            principal = %ctx.principal,
                            %session_id,
                            "session data stream refused: another principal holds the writer lease"
                        );
                        stream.send.reset(RESET_CODE_SESSION_CONFLICT);
                        stream.recv.stop(RESET_CODE_SESSION_CONFLICT);
                        return;
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::debug!(
                            principal = %ctx.principal,
                            %session_id,
                            %err,
                            "session data stream refused: lease unavailable"
                        );
                        stream.send.reset(RESET_CODE_BAD_HEADER);
                        stream.recv.stop(RESET_CODE_BAD_HEADER);
                        return;
                    }
                }
                let pump = SessionStream {
                    sessions: Arc::clone(&self.sessions),
                    session_id: session_id.clone(),
                    // The same `owner` `take_lease_owned` above just took
                    // the lease as (this is the `is_held_by` check on
                    // every subsequent `Input`/`Resize` frame on *this*
                    // stream) — ticket-derived on a real reverse
                    // registration, `ctx.connection_id()` everywhere else,
                    // matching whichever identity a `session write`/
                    // `session resize` value op on this same connection
                    // would also use.
                    conn: owner,
                    cursor: Cursor::from_offset(replay_from),
                    input_stream,
                    input_from,
                    events: Some(events),
                };
                match pump.run(stream, &conn).await {
                    Ok(()) => tracing::info!(
                        principal = %ctx.principal,
                        %session_id,
                        "session data stream finished"
                    ),
                    Err(err) if err.is_peer_gone() => tracing::info!(
                        principal = %ctx.principal,
                        %session_id,
                        %err,
                        "session data stream ended: peer went away"
                    ),
                    Err(err) => tracing::warn!(
                        principal = %ctx.principal,
                        %session_id,
                        %err,
                        "session data stream failed"
                    ),
                }
            }
        }
    }
}
