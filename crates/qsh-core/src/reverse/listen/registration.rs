//! Registration path of [`Listen`]: accept, admit, publish into the connection table, drive the registered session, and the per-hub tunnel accept loop.

use super::*;

impl Listen {
    /// Accept one inbound connection and run the registration handshake on
    /// it. Mirrors [`crate::server::Server::accept_and_serve`]'s
    /// verify-then-audit shape for a rejected TLS handshake. Reached only
    /// through [`Self::admit`], holding the handshake permit
    /// [`Self::admission`] handed out.
    /// M8 Step 3b (rulings R3/R6): this controller's own connection-count
    /// quota is reserved here — this is its outer role, exactly like
    /// `crate::server::Server::serve_connection` is for the `qsh serve`
    /// accept arm (same host→principal order, same [`crate::quota::
    /// Quotas::reserve_connection`] call) — before [`Self::register_connection`]
    /// (and the `Hello` exchange inside it) ever runs, and released only
    /// after this whole registered session has fully torn down
    /// (`Self::drive_registered_session`'s own `conns.remove_if`, deep
    /// inside the `register_connection(...).await` below — this task's
    /// own `.await` does not return until that has already run). `Listen`
    /// never sees `Principal::Pairing` (pairing is a `qsh serve`-only
    /// concept), so there is only ever this one axis to check, unlike
    /// `Server::serve_connection`'s pairing/regular split.
    pub(super) async fn accept_and_register_permitted(
        self: Arc<Self>,
        incoming: Incoming,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) {
        let peer = incoming.remote_address();
        let result = incoming.accept().await;
        drop(permit);
        match result {
            Ok(conn) => {
                let opener = crate::acl::opener_key(conn.principal(), conn.auth_path());
                let (quota_permit, refused) = match self.quotas.reserve_connection(&opener) {
                    Ok(permit) => (Some(permit), None),
                    Err(kind) => {
                        let records = self.quotas.record_rejection(
                            kind,
                            &opener,
                            peer,
                            self.quotas.now(),
                            None,
                            conn.auth_path(),
                        );
                        crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                        (None, Some(kind))
                    }
                };
                // B3 (type-pinned, M8 Step 3b arbitration): `quota_permit`
                // moves into `register_connection` by value rather than
                // being dropped here — the same "the callee holds it and
                // releases it last" shape `Server::serve_connection`'s two
                // arms now use for their own connection permits. A
                // trailing `drop(quota_permit)` here would compile fine
                // and release the slot before the registered session is
                // actually torn down; moving it in makes that ordering a
                // type error instead of a text convention.
                self.register_connection(conn, quota_permit, refused).await;
            }
            Err(err) => {
                let category = match &err {
                    AcceptError::Unverified(reason) => format!("{reason:?}").to_lowercase(),
                    _ => "handshake".to_string(),
                };
                // Already rejecting the connection outright: a failure to
                // record it doesn't change the outcome, only the
                // diagnostic — same exception as
                // `server::Server::accept_and_serve`.
                if let Err(audit_err) = self
                    .audit
                    .record(&AuditRecord::handshake_rejected(peer, &category))
                {
                    tracing::warn!(%peer, %audit_err, "failed to record handshake rejection");
                }
                tracing::warn!(%peer, %err, "connection rejected");
            }
        }
    }

    /// Run the `Hello` exchange as responder and, on a successful
    /// registration, hand the connection off to
    /// [`Listen::finish_registration`]. Every rejection path already wrote
    /// (and [`crate::handshake::respond`] already drained) its error frame
    /// before returning here — this only has to close.
    ///
    /// M8 Step 3b arbitration B3: `quota_permit` is owned here, not
    /// borrowed or dropped by the caller — released only at the very end
    /// of this function (see the `drop(quota_permit)` there), after the
    /// whole registered session this permit was reserved for has already
    /// run to completion. [`Listen::accept_and_register_permitted`]'s own
    /// doc comment already named the shape this enforces: the slot stays
    /// held for as long as the connection is live.
    pub(super) async fn register_connection(
        self: Arc<Self>,
        conn: Connection,
        quota_permit: Option<crate::quota::ConnectionPermit>,
        refused: Option<crate::quota::QuotaKind>,
    ) {
        // `Mutex`, not `RefCell`: this reference is captured by the
        // `make_local_hello` closure `handshake::respond` holds across an
        // `.await` inside a `tokio::spawn`ed task, so it must be `Sync`
        // (`RefCell` is not — the borrow-check failure is the compiler
        // catching exactly that). Never actually contended: the closure
        // runs synchronously, once, before `respond` returns.
        let outcome_cell: Mutex<Option<RegisterOutcome>> = Mutex::new(None);
        let result = crate::handshake::respond(&conn, |peer_hello| {
            self.decide_registration(&conn, peer_hello, &outcome_cell, refused)
        })
        .await;

        let (ctl, peer_hello) = match result {
            Ok(pair) => pair,
            Err(_err) => {
                // `decide_registration` may already have run `admit` and
                // stashed a `RegisterOutcome` here — reachable when the
                // `Hello` reply itself failed to send after admission
                // succeeded (`handshake::respond_on`'s `io.send_hello(..)`,
                // after the callback returns `Ok`). Left alone, that would
                // leave a `Live` registry entry with no connection behind
                // it, forever (`PLAN.md` M3 Step 3 review). Roll it back —
                // undoing exactly what `admit` did, nothing more.
                if let Some(outcome) = outcome_cell.into_inner().unwrap_or_else(|e| e.into_inner())
                {
                    // `rollback_target` drops `replaced_entry` back to
                    // `None` if the connection it describes is no longer
                    // `conns`'s live occupant for this name — see its own
                    // doc comment.
                    let replaced =
                        rollback_target(&self.conns, &outcome.entry.name, outcome.replaced_entry);
                    self.registry
                        .rollback(&outcome.entry.name, outcome.entry.generation, replaced);
                }
                conn.close(
                    qsh_transport::endpoint::CLOSE_CODE_PROTOCOL,
                    b"registration refused",
                );
                drop(quota_permit);
                return;
            }
        };
        let Some(outcome) = outcome_cell.into_inner().unwrap_or_else(|e| e.into_inner()) else {
            // Defensive: `decide_registration` always populates this on
            // every `Ok` it returns.
            conn.close(
                qsh_transport::endpoint::CLOSE_CODE_PROTOCOL,
                b"internal error",
            );
            drop(quota_permit);
            return;
        };
        self.finish_registration(conn, ctl, peer_hello, outcome)
            .await;
        drop(quota_permit);
    }

    /// The synchronous decision `crate::handshake::respond`'s
    /// `make_local_hello` callback needs: absent `Hello.reverse` is
    /// `UNSUPPORTED` (not an ACL decision — zero resources, zero audit);
    /// present is [`super::admit::admit`], verbatim, with its `Ok` stashed
    /// into `outcome_cell` for [`Listen::register_connection`] to pick up
    /// once the whole `Hello` exchange (this reply included) has actually
    /// gone out.
    ///
    /// M8 Step 3b arbitration (A2/B5, overturning R3 for this arm): the
    /// connection-count `refused` check is consulted only *after*
    /// [`admit`] — this arm's `host.reverse` ACL choke point — has run,
    /// never before it. Checking it first (R3's original placement, still
    /// correct for `crate::server::Server::serve_connection_inner`'s
    /// per-op ACL, which has no handshake-time "would this Hello even be
    /// authorized" concept) made a peer this registry would deny anyway
    /// able to fingerprint the controller's saturation: the exact same
    /// denied `Hello` got `PERMISSION_DENIED` while idle and
    /// `RESOURCE_EXHAUSTED(retryable)` once the connection cap filled —
    /// one bit of "is the host full right now" leaking to principals with
    /// zero authorization (`crate::quota` module doc, `adr-0010-draft.md`
    /// §6: unauthorized principals must never see a quota-shaped answer).
    /// `admit`'s own doc guarantees "every early return leaves the
    /// registry exactly as it was", so an ACL deny here costs nothing to
    /// unwind; an ACL *allow* that this method then discards for quota
    /// reasons does insert into the registry (`admit`'s step 4) and must
    /// be rolled back explicitly below — the same `rollback_target` +
    /// `Registry::rollback` pair `Listen::register_connection`'s own
    /// failed-`Hello`-reply path already uses for the identical shape
    /// (an admitted entry with nothing to drive it).
    pub(super) fn decide_registration(
        &self,
        conn: &Connection,
        peer_hello: &Hello,
        outcome_cell: &Mutex<Option<RegisterOutcome>>,
        refused: Option<crate::quota::QuotaKind>,
    ) -> Result<Hello, wire::Error> {
        let Some(reg) = peer_hello.reverse.as_ref() else {
            tracing::warn!(
                peer = %conn.remote_address(),
                "peer connected to qsh listen without Hello.reverse"
            );
            return Err(wire::Error::new(
                ErrorCode::Unsupported,
                "this endpoint only accepts reverse registrations",
                false,
            ));
        };

        let Some(fingerprint) = conn.peer_fingerprint() else {
            // Not reachable in practice (`Connection::peer_fingerprint`'s
            // own docs: only `None` if a verified leaf failed to
            // re-parse) — fail closed rather than register an entry with
            // nothing to bind a fingerprint to.
            return Err(wire::Error::new(
                ErrorCode::PermissionDenied,
                registry::host_reverse_denied().message,
                false,
            ));
        };
        // `ReverseRegistration.capabilities` empty means "same as
        // Hello.capabilities" (`v1.proto`'s field doc) — the negotiated
        // intersection this connection's general `Hello` already settled.
        let capabilities = if reg.capabilities.is_empty() {
            crate::handshake::negotiated_capabilities(peer_hello)
        } else {
            reg.capabilities.clone()
        };

        let req = AdmitRequest {
            principal: conn.principal(),
            auth_path: conn.auth_path(),
            fingerprint,
            address: conn.remote_address(),
            offered_name: &reg.offered_name,
            capabilities,
        };

        match admit(
            &self.registry,
            self.authorizer.as_ref(),
            self.audit.as_ref(),
            req,
        ) {
            Ok(outcome) => {
                // A2/B5: the ACL choke point above just allowed this
                // registration — only now is it safe to also apply the
                // connection-count refusal decided before this callback
                // ever ran. `refused` is ignored entirely on the `Err`
                // arm below: an ACL-denied peer must never learn whether
                // the controller happens to be at capacity.
                if let Some(kind) = refused {
                    let replaced =
                        rollback_target(&self.conns, &outcome.entry.name, outcome.replaced_entry);
                    self.registry
                        .rollback(&outcome.entry.name, outcome.entry.generation, replaced);
                    return Err(wire::Error::new(
                        ErrorCode::ResourceExhausted,
                        kind.wire_message(),
                        true,
                    ));
                }
                RegistrationEvent {
                    event: if outcome.replaced_generation.is_some() {
                        "replaced"
                    } else {
                        "registered"
                    },
                    host: &outcome.entry.name,
                    fingerprint: &outcome.entry.fingerprint,
                    generation: Some(outcome.entry.generation),
                    // Neither `replaced` nor `registered` is an ended
                    // registration — no `cause`/`since_registered_ms`
                    // (issue #4 item 6).
                    cause: None,
                    at: crate::config::now_rfc3339(),
                    since_registered_ms: None,
                }
                .emit();
                *outcome_cell.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
                Ok(self.local_hello())
            }
            Err(err) => {
                RegistrationEvent {
                    event: "denied",
                    host: diag_host(&reg.offered_name),
                    fingerprint: &fingerprint.to_string(),
                    generation: None,
                    // Fixed: every `denied` is the `host.reverse`
                    // ACL/registry choke point refusing the registration
                    // (issue #4 item 6).
                    cause: Some(crate::reverse::ReconnectCause::RegistrationDenied.as_str()),
                    at: crate::config::now_rfc3339(),
                    since_registered_ms: None,
                }
                .emit();
                Err(wire::Error::new(err.code, err.message, err.retryable))
            }
        }
    }

    /// Publish the registered connection into [`Listen::conns`], close
    /// whatever it replaced, then drive the connection as CLIENT role until
    /// it dies. Race-free regardless of what order two concurrent
    /// same-fingerprint registrations' calls to this method happen to run
    /// in — [`ConnTable::publish`]'s doc comment (`PLAN.md` M3 Step 4 (4),
    /// fixing the KNOWN RACE PR 3b left here — see git blame for that
    /// comment's history).
    async fn finish_registration(
        self: Arc<Self>,
        conn: Connection,
        ctl: FramedStream,
        peer_hello: Hello,
        outcome: RegisterOutcome,
    ) {
        let name = outcome.entry.name.clone();
        let fingerprint = outcome.entry.fingerprint.clone();
        let generation = outcome.entry.generation;
        #[cfg(unix)]
        let capabilities = outcome.entry.capabilities.clone();

        match self.conns.publish(name.clone(), generation, conn.clone()) {
            Published::Installed(Some(old_conn)) => {
                // `Connection::close` is idempotent — safe even if the old
                // connection is already mid-close on its own (e.g. the
                // peer hung up right as it reconnected).
                old_conn.close(CLOSE_CODE_REPLACED, b"replaced by a newer registration");
            }
            Published::Installed(None) => {}
            Published::Superseded(_) => {
                // A newer generation already published under `name` before
                // this call ran (`ConnTable::publish`'s doc comment) — this
                // connection lost the race and must never be driven as
                // this name's live connection. Closing it here, rather
                // than leaving it to be discovered later, is what keeps it
                // from leaking: nothing else references it.
                conn.close(CLOSE_CODE_REPLACED, b"superseded by a newer registration");
                return;
            }
        }

        // `Listen::hubs`'s own doc comment: a second, separately-locked
        // publish under the same generation guard — `Published::Superseded`
        // here (this generation's hub itself losing a race after `conns`
        // already won one) is left unhandled on purpose, nothing to do
        // either way; the hub is simply dropped unpublished.
        #[cfg(unix)]
        {
            let hub = ControlHub::new(name.clone(), fingerprint.clone(), generation, capabilities);
            if let Published::Installed(Some(old_hub)) =
                self.hubs.publish(name.clone(), generation, hub)
            {
                old_hub.mark_dead();
            }
        }

        let session = Session::from_control(conn, ctl, peer_hello);
        self.drive_registered_session(session, name, fingerprint, generation)
            .await;
    }

    /// The controller is CLIENT role on a registered connection
    /// (`docs/design/protocol.md` §11-3: registration grants reachability,
    /// never authority) — it never opens sessions, so the only things to
    /// do here are answer a peer `Ping` and refuse every request-shaped
    /// frame with `UNSUPPORTED`, creating nothing either way.
    ///
    /// **Step 4: the controller's own liveness watch.** This is the small
    /// probe driver `PLAN.md` M3 Step 4 (b) calls for — reusing
    /// [`PathWatchConfig`]'s judgment policy unchanged, watching this
    /// connection through Stage A's role-agnostic `ProbeSource` blanket
    /// impl on [`Connection`]. Shaped exactly like `ops/session.rs`'s
    /// `pump_attach_control`: [`watch_path`] runs as its own task and only
    /// ever *asks* for a probe via `probes`, this loop is the sole writer
    /// on `session`'s control stream (`Session::send_ping`/`send_pong`), a
    /// `Pong` is bare liveness (`PathWatch::inbound`) while everything else
    /// inbound is liveness *and* activity (`PathWatch::traffic`). When
    /// [`PathWatch::dead`] fires, the loop exits exactly like a read error
    /// would.
    ///
    /// On exit, this generation's [`Listen::conns`] entry is removed —
    /// unless a newer registration already replaced it
    /// ([`ConnTable::remove_if`] returning `false` is exactly that:
    /// [`Listen::finish_registration`] already emitted `"replaced"` for it,
    /// so this must not also emit `"lost"`) — and, only when it was still
    /// this generation's entry, [`Registry::mark_stale`] transitions the
    /// registry entry and a `"lost"` diagnostic is emitted. Actual removal
    /// after `[listen].stale_retention` is [`Listen::run_stale_sweeper`]'s
    /// job, not this method's.
    async fn drive_registered_session(
        self: Arc<Self>,
        mut session: Session,
        name: String,
        fingerprint: String,
        generation: u64,
    ) {
        // Issue #4 item 6: how long this registration lived, reported on
        // the eventual `"lost"` line's `since_registered_ms`.
        let registered_at = std::time::Instant::now();
        // Why the loop below eventually breaks (issue #4 item 6,
        // `docs/CLI.md` §6.13 bullet at :952). Deferred init, no `mut`:
        // every arm that can `break` assigns this exactly once, first —
        // the only way to reach the read after the loop.
        let loss_cause;
        let watch = PathWatch::new(PathWatchConfig::default());
        let probes = Arc::new(tokio::sync::Notify::new());
        let watchdog = tokio::spawn(watch_path(
            session.connection().clone(),
            watch.clone(),
            probes.clone(),
        ));
        // `PLAN.md` M4 Step 5 (a): the only kind of peer-initiated bidi
        // stream this connection legitimately carries is a `TCP_ACCEPTED`
        // the target opens for a `-R` this hub's own conduits registered
        // (module docs' kind table for every stream `serve_stream`
        // itself opens instead). Its own task, exactly like `watchdog` —
        // see [`Self::spawn_tunnel_accept_loop`]'s doc for the unix/
        // non-unix split.
        let tunnel_accept_task =
            self.spawn_tunnel_accept_loop(session.connection().clone(), &name, generation);

        // `M3 Step 6`: this loop is the one and only reader/writer of
        // `session`'s control stream (this method's own long-standing
        // contract), so it is also the natural sole relay point for every
        // `LOCAL_CONTROL` conduit of this host. `tokio::select!` has no
        // per-branch `#[cfg]` (unlike `futures::select!`), so rather than
        // duplicate this whole loop behind a platform split, every
        // `ControlHub`-touching step below goes through a same-signature
        // `#[cfg(unix)]`/`#[cfg(not(unix))]` twin method
        // (`Self::take_hub_outbound_receiver`/`Self::deliver_hub_response`/
        // `Self::deliver_hub_event`/`Self::mark_hub_dead`/
        // `Self::remove_hub_if`) — a no-op returning the same shape on a
        // non-unix build, where `ControlHub` does not exist at all — so
        // this method's own body stays platform-agnostic end to end.
        let mut outbound_rx = self.take_hub_outbound_receiver(&name, generation);

        loop {
            tokio::select! {
                biased;
                () = watch.dead() => {
                    // `CLOSE_CODE_PATH_DEAD`'s own doc: without this, a
                    // `LOCAL_STREAM` splice pump still reading on this
                    // connection blocks until quinn's 45 s idle timeout,
                    // not this watchdog's own detection budget.
                    // Issue #4 item 6: `watch.dead()` also resolves for a
                    // connection that was *already* closed (`target.rs`'s
                    // symmetric `watch.dead()` arm carries the full
                    // reasoning) — read `close_reason()` before this
                    // side's own close call so an already-peer-closed
                    // connection classifies as that, not `path_dead`.
                    let pre_close_reason = session.connection().close_reason();
                    session.connection().close(CLOSE_CODE_PATH_DEAD, b"path unresponsive");
                    loss_cause = match pre_close_reason {
                        Some(err) => crate::reverse::classify_connection_error(&err),
                        None => crate::reverse::ReconnectCause::PathDead,
                    };
                    break;
                }
                () = probes.notified() => {
                    if let Err(err) = session.send_ping().await {
                        // A write failure surfaces the same `ClientError`
                        // shapes a read failure would (issue #4 item 6) —
                        // classify it the same way rather than assuming
                        // `local`.
                        loss_cause = classify_client_error(&err);
                        break;
                    }
                }
                outbound = recv_outbound(&mut outbound_rx) => {
                    let Some((daemon_request_id, body)) = outbound else {
                        // Either there was no hub at all (`outbound_rx` was
                        // already `None`, so this can only be reached from
                        // the other arm below), or the hub's `outbound_tx`
                        // was just dropped — a *closed* `mpsc::UnboundedReceiver`
                        // resolves `recv().await` to `Ready(None)`
                        // immediately and forever, not `Pending`, so
                        // leaving `outbound_rx` as `Some(_)` here would
                        // make this `biased` branch win every iteration
                        // and spin at 100% CPU without ever reaching the
                        // `next_control_message()` arm below (adversarial
                        // review finding). Setting it to `None` switches
                        // `recv_outbound` to the `pending()` arm instead,
                        // so this branch truly never produces work again.
                        outbound_rx = None;
                        continue;
                    };
                    let msg = wire::ControlMessage::new(daemon_request_id, body);
                    if let Err(err) = session.send_control_message(&msg).await {
                        // Same reasoning as `send_ping` above.
                        loss_cause = classify_client_error(&err);
                        break;
                    }
                }
                message = session.next_control_message() => {
                    let msg = match message {
                        Ok(Some(msg)) => msg,
                        // A clean end of stream — the peer closed its
                        // send side (issue #4 item 6).
                        Ok(None) => {
                            loss_cause = crate::reverse::ReconnectCause::PeerClosed;
                            break;
                        }
                        Err(err) => {
                            loss_cause = classify_client_error(&err);
                            break;
                        }
                    };
                    let request_id = msg.request_id;
                    match msg.body {
                        // The answer to our own liveness probe — proof the
                        // path carries packets, nothing more (mirrors
                        // `pump_attach_control`'s identical comment: counting
                        // this as activity would keep the watchdog inside the
                        // active window forever).
                        Some(wire::control_message::Body::Pong(_)) => watch.inbound(),
                        // Symmetric probing (Step 4): with a `PathWatch`
                        // driving *both* ends of a registered connection,
                        // every `Ping` reaching this arm is the target's
                        // own probe loop (`server::drive_probes`) asking
                        // the same liveness question this side is asking
                        // it — never real session traffic. Counting it as
                        // activity (`PathWatch::traffic`) would re-arm
                        // `active_window` on every reply and pin this
                        // watch to the fast cadence forever — the same
                        // failure mode `PathState::observe_inbound`'s doc
                        // comment already names for an inbound `Pong`,
                        // just from the other message direction. Bare
                        // liveness only.
                        Some(wire::control_message::Body::Ping(_)) => {
                            watch.inbound();
                            if let Err(err) = session.send_pong(request_id).await {
                                loss_cause = classify_client_error(&err);
                                break;
                            }
                        }
                        // `M3 Step 6`: a correlated reply to something
                        // `ControlHub::send_request` forwarded on behalf of
                        // a `LOCAL_CONTROL` conduit — never anything this
                        // driver itself asked for (it only ever sends
                        // `Ping`, which gets a `Pong`, not a `Response`).
                        Some(wire::control_message::Body::Response(resp)) => {
                            watch.traffic();
                            self.deliver_hub_response(&name, generation, request_id, resp);
                        }
                        // `M3 Step 6`: an asynchronous `SessionEvent`
                        // (`request_id = 0`) owed to whichever conduits
                        // subscribed — fanned out via the hub, never this
                        // driver's own business (it opens nothing).
                        Some(wire::control_message::Body::SessionEvent(event)) => {
                            watch.traffic();
                            self.deliver_hub_event(&name, generation, event);
                        }
                        // Everything else the oneof can carry is
                        // request-shaped (`Hello`, every `session_*`/
                        // `exec_start`, or an unknown/reserved number
                        // decoding to `body: None`) — the controller
                        // itself never serves one; refuse rather than
                        // drop, exactly the zero-resource `UNSUPPORTED`
                        // contract `docs/design/protocol.md` §11-3
                        // documents.
                        _ => {
                            watch.traffic();
                            if let Err(err) = session.reject_unsupported(request_id).await {
                                loss_cause = classify_client_error(&err);
                                break;
                            }
                        }
                    }
                }
            }
        }
        watchdog.abort();
        if let Some(task) = tunnel_accept_task {
            task.abort();
        }

        self.mark_hub_dead(&name, generation);

        let still_live = self.conns.remove_if(&name, generation);
        self.remove_hub_if(&name, generation);
        if still_live && self.registry.mark_stale(&name, generation).is_some() {
            RegistrationEvent {
                event: "lost",
                host: &name,
                fingerprint: &fingerprint,
                generation: Some(generation),
                cause: Some(loss_cause.as_str()),
                at: crate::config::now_rfc3339(),
                since_registered_ms: Some(
                    u64::try_from(registered_at.elapsed().as_millis()).unwrap_or(u64::MAX),
                ),
            }
            .emit();
        }
    }

    // ------------------------------------------------------------------
    // `ControlHub` access for `Listen::drive_registered_session` — one
    // same-signature `#[cfg(unix)]`/`#[cfg(not(unix))]` pair per step, so
    // that method's own body needs no `#[cfg]` at all (this section's own
    // doc comment there). Every method here takes `(name, generation)`
    // rather than a cached `hub: Option<Arc<ControlHub>>`, trading one
    // extra `ConnTable` lookup per control message (never a hot path —
    // bounded by real CLI activity, not wire throughput) for a
    // `drive_registered_session` body that compiles identically on both
    // platforms.
    // ------------------------------------------------------------------

    /// Take this generation's hub's outbound-relay receiver, if it has a
    /// hub at all (`Listen::hubs`'s own doc comment on the tiny window
    /// where it might not). Called once, before the select loop starts.
    #[cfg(unix)]
    fn take_hub_outbound_receiver(
        &self,
        name: &str,
        generation: u64,
    ) -> Option<mpsc::UnboundedReceiver<(u64, wire::control_message::Body)>> {
        self.hubs
            .get_matching(name, generation)
            .and_then(|hub| hub.take_outbound_receiver())
    }

    #[cfg(not(unix))]
    fn take_hub_outbound_receiver(
        &self,
        _name: &str,
        _generation: u64,
    ) -> Option<mpsc::UnboundedReceiver<(u64, wire::control_message::Body)>> {
        None
    }

    /// Route one correlated `Response` through this generation's hub, if
    /// it still has one — see [`ControlHub::deliver_response`].
    #[cfg(unix)]
    fn deliver_hub_response(
        &self,
        name: &str,
        generation: u64,
        request_id: u64,
        resp: wire::Response,
    ) {
        if let Some(hub) = self.hubs.get_matching(name, generation) {
            hub.deliver_response(request_id, resp);
        }
    }

    #[cfg(not(unix))]
    fn deliver_hub_response(
        &self,
        _name: &str,
        _generation: u64,
        _request_id: u64,
        _resp: wire::Response,
    ) {
    }

    /// Fan one asynchronous `SessionEvent` out through this generation's
    /// hub, if it still has one — see [`ControlHub::deliver_event`].
    #[cfg(unix)]
    fn deliver_hub_event(&self, name: &str, generation: u64, event: wire::SessionEvent) {
        if let Some(hub) = self.hubs.get_matching(name, generation) {
            hub.deliver_event(event);
        }
    }

    #[cfg(not(unix))]
    fn deliver_hub_event(&self, _name: &str, _generation: u64, _event: wire::SessionEvent) {}

    /// End every conduit of this generation's hub together, if it still
    /// has one — see [`ControlHub::mark_dead`]. Called once, right after
    /// the select loop exits, before [`Self::conns`]/[`Self::hubs`] are
    /// cleaned up (so a conduit racing a lookup in between still finds a
    /// hub, just one already mid-teardown, rather than none at all).
    #[cfg(unix)]
    fn mark_hub_dead(&self, name: &str, generation: u64) {
        if let Some(hub) = self.hubs.get_matching(name, generation) {
            hub.mark_dead();
        }
    }

    #[cfg(not(unix))]
    fn mark_hub_dead(&self, _name: &str, _generation: u64) {}

    /// [`ConnTable::remove_if`] on [`Self::hubs`] — the hub-table
    /// counterpart to the `self.conns.remove_if(&name, generation)` this
    /// runs alongside.
    #[cfg(unix)]
    fn remove_hub_if(&self, name: &str, generation: u64) {
        let _ = self.hubs.remove_if(name, generation);
    }

    #[cfg(not(unix))]
    fn remove_hub_if(&self, _name: &str, _generation: u64) {}

    /// Spawn [`Self::run_tunnel_accept_loop`] for this generation's hub,
    /// if it still has one (the same tiny window [`Self::hubs`]'s own doc
    /// comment describes) — `None` here just means no `TCP_ACCEPTED`
    /// stream can ever be delivered for this generation, not a startup
    /// failure worth surfacing; a `-R` opened through it would simply
    /// have nowhere to register a `forward_id` either.
    #[cfg(unix)]
    fn spawn_tunnel_accept_loop(
        &self,
        conn: Connection,
        name: &str,
        generation: u64,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let hub = self.hubs.get_matching(name, generation)?;
        Some(tokio::spawn(Listen::run_tunnel_accept_loop(conn, hub)))
    }

    #[cfg(not(unix))]
    fn spawn_tunnel_accept_loop(
        &self,
        _conn: Connection,
        _name: &str,
        _generation: u64,
    ) -> Option<tokio::task::JoinHandle<()>> {
        None
    }

    /// Accept every peer-initiated bidi stream on `conn` for as long as
    /// it lives — on a registered reverse connection that is, exactly,
    /// every `TCP_ACCEPTED` stream the target opens for one of this
    /// hub's registered `forward_id`s (`PLAN.md` M4 Step 5 (a),
    /// `docs/design/protocol.md` §11-3's "-R(remote forward)이 역방향 위에서
    /// 도는 경로"). Ends on its own — no cancellation token needed — the
    /// moment `accept_bi` reports the connection is gone; the caller
    /// (`Self::drive_registered_session`) also aborts this task's handle
    /// explicitly the moment its own loop exits, so a connection that
    /// dies by some path other than `accept_bi` noticing (e.g. this
    /// generation replaced by a newer one, `CLOSE_CODE_REPLACED`) does
    /// not leave this loop parked on a connection nothing else is using.
    ///
    /// Each accepted stream is handled on its own spawned task
    /// ([`Self::handle_tcp_accepted_stream`]) so one slow/adversarial
    /// header never blocks the next `accept_bi` — the same reasoning
    /// [`crate::tunnel::remote::dispatch_remote_forwards`]'s doc gives for
    /// the direct-connect leg's mirror-image accept loop.
    #[cfg(unix)]
    async fn run_tunnel_accept_loop(conn: Connection, hub: Arc<ControlHub>) {
        // The queued-arrival sweeper lives exactly as long as this loop
        // does — its own task rather than a `select!` arm here, so
        // nothing can make `accept_bi`'s future be dropped mid-poll, and
        // guarded by [`AbortOnDrop`] rather than joined, because this
        // loop is normally ended by the caller's `.abort()` and an
        // aborted task's locals are dropped at its next poll point (which
        // is what runs the guard). Same lifetime, same connection: a hub
        // whose connection is gone has already had every queue drained by
        // `ControlHub::mark_dead`'s per-conduit sweep, so there is
        // nothing left for a sweeper to do past this point.
        let _sweeper = AbortOnDrop(tokio::spawn(Listen::run_tunnel_arrival_sweeper(
            hub.clone(),
        )));
        loop {
            match conn.accept_bi().await {
                Ok((send, recv)) => {
                    tokio::spawn(Listen::handle_tcp_accepted_stream(send, recv, hub.clone()));
                }
                Err(_) => return,
            }
        }
    }

    /// Enforce [`MAX_QUEUED_TUNNEL_ARRIVAL_AGE`] on this hub's queued
    /// `TCP_ACCEPTED` arrivals every [`TUNNEL_ARRIVAL_SWEEP_INTERVAL`]
    /// ([`ControlHub::sweep_expired_arrivals`]'s own doc on why a queued
    /// arrival needs a bounded life at all). Never ends on its own —
    /// [`Self::run_tunnel_accept_loop`]'s `AbortOnDrop` guard ends it,
    /// whether that loop returned or was aborted.
    ///
    /// `MissedTickBehavior::Delay`: if the runtime is busy enough that a
    /// tick is missed, the next sweep should be one interval *later*, not
    /// a burst of catch-up sweeps that each take this hub's lock for
    /// nothing.
    #[cfg(unix)]
    async fn run_tunnel_arrival_sweeper(hub: Arc<ControlHub>) {
        let mut ticker = tokio::time::interval(TUNNEL_ARRIVAL_SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            hub.sweep_expired_arrivals();
        }
    }

    /// One accepted stream's whole life on this leg: read its
    /// `StreamHeader` (bounded by `crate::server::HEADER_TIMEOUT`, the
    /// same bound the direct-connect requester leg uses for the identical
    /// read), require `TCP_ACCEPTED` and a shape-valid `forward_id`
    /// ticket (`qsh_proto::wire::valid_forward_id` — checked **before**
    /// the registry lookup, `PLAN.md` M4 Step 5 (a)), take a
    /// [`MAX_TUNNEL_STREAMS_PER_HUB`] permit, then hand it to
    /// [`ControlHub::deliver_tcp_accepted`]. Every rejection path resets
    /// the stream and touches nothing else — no permit taken for a
    /// malformed header, no queue entry for an unregistered id, no partial
    /// pipe ever started (`PLAN.md` M4 Step 5 (a)'s explicit requirement).
    ///
    /// Never logs the ticket's bytes on a rejection, only its length — the
    /// same `qsh_proto::wire::sanitize_peer_text` discipline
    /// `crate::tunnel::remote::handle_accepted_stream`'s identical check
    /// documents, and for the identical reason: past `valid_forward_id`
    /// the string is `[A-Za-z0-9_-]{1,64}` by construction and safe to
    /// log as-is, but a string that *failed* the check is arbitrary
    /// peer-controlled text.
    #[cfg(unix)]
    pub(super) async fn handle_tcp_accepted_stream(
        send: SendStream,
        recv: RecvStream,
        hub: Arc<ControlHub>,
    ) {
        let mut stream = qsh_transport::FramedStream::data(send, recv);
        let header: wire::StreamHeader = match tokio::time::timeout(
            crate::server::HEADER_TIMEOUT,
            stream.recv.recv::<wire::StreamHeader>(),
        )
        .await
        {
            Ok(Ok(Some(h))) => h,
            _ => {
                stream.send.reset(crate::server::RESET_CODE_BAD_HEADER);
                stream.recv.stop(crate::server::RESET_CODE_BAD_HEADER);
                return;
            }
        };
        if header.stream_kind() != Some(wire::StreamKind::TcpAccepted) {
            tracing::debug!(
                kind = header.kind,
                "qsh::reverse: unexpected peer-opened stream kind on a registered connection"
            );
            stream.send.reset(crate::server::RESET_CODE_BAD_HEADER);
            stream.recv.stop(crate::server::RESET_CODE_BAD_HEADER);
            return;
        }
        let forward_id = match String::from_utf8(header.ticket.clone()) {
            Ok(id) if wire::valid_forward_id(&id) => id,
            _ => {
                tracing::warn!(
                    ticket_len = header.ticket.len(),
                    "qsh::reverse: TCP_ACCEPTED with a malformed forward_id ticket"
                );
                stream.send.reset(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
                stream.recv.stop(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
                return;
            }
        };
        let Some(permit) = hub.try_acquire_tunnel_permit() else {
            tracing::warn!(
                forward_id,
                "qsh::reverse: this hub's tunnel-stream cap is exhausted; rejecting TCP_ACCEPTED"
            );
            stream.send.reset(RESET_CODE_TUNNEL_HUB_EXHAUSTED);
            stream.recv.stop(RESET_CODE_TUNNEL_HUB_EXHAUSTED);
            return;
        };

        // Past this point the stream is a raw byte pipe — same residue
        // handoff `crate::tunnel::remote::handle_accepted_stream`'s
        // identical `TCP_ACCEPTED` leg documents. `residue` cannot be
        // written anywhere yet: nobody has claimed this `forward_id` —
        // possibly nobody ever will — so it travels inside the queued
        // [`TunnelArrival`] instead of being flushed here.
        let (send_half, recv_half) = stream.split();
        let raw_send = send_half.into_raw();
        let (raw_recv, residue) = recv_half.into_raw();
        if let Err(rejected) =
            hub.deliver_tcp_accepted(&forward_id, raw_send, raw_recv, residue, permit)
        {
            // `deliver_tcp_accepted` never inserted anything and handed
            // the streams straight back, still owning their permit — this
            // is the ordinary, expected race
            // `crate::tunnel::remote::RESET_CODE_UNKNOWN_FORWARD`'s own
            // doc describes for the direct-connect leg's mirror-image
            // case (a `TCP_ACCEPTED` outrunning the control round trip
            // that would have registered it, or simply arriving after the
            // forward was already closed) — not necessarily a hostile
            // one, but rejected identically either way: reset, nothing
            // spliced, permit released.
            tracing::warn!(
                forward_id,
                "qsh::reverse: TCP_ACCEPTED for an unregistered forward_id"
            );
            rejected.reset(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
        }
        // `Ok(())`: queued in `hub`'s `tunnel_queue`, owning its permit,
        // for `ControlHub::claim_tcp_accepted` to hand to a `LOCAL_STREAM`
        // conduit — nothing further to do on this task.
    }
}

/// Classify a [`ClientError`] from [`Listen::drive_registered_session`]'s
/// own `session.next_control_message()` read into [`crate::reverse::ReconnectCause`]'s
/// `peer_closed`/`path_dead`/`local` slice (issue #4 item 6) — the same
/// judgment [`crate::reverse::classify_connection_error`] already applies to a raw
/// `ConnectionError`, reached through whichever of `ClientError`'s two
/// variants actually carries one on this client role's control stream.
/// Everything else (`Remote`, a peer-sent wire `Error` reply;
/// `Unsupported`/`Protocol`, a malformed peer; a stream framing error with
/// no underlying `ConnectionError`; `HelloTimeout`/`OutputTooLarge`,
/// unreachable here — none of it is `Connection`/a `ConnectionLost`
/// stream error) falls to `local`: none of it is a peer-initiated clean
/// close or a PathWatch-class idle judgment, so by elimination it is
/// "something about this side's own read that isn't one of the other
/// two", the same catch-all `crate::reverse::classify_connection_error`'s own doc
/// already claims.
fn classify_client_error(err: &ClientError) -> crate::reverse::ReconnectCause {
    match err {
        ClientError::Connection(e) => crate::reverse::classify_connection_error(e),
        ClientError::Stream(qsh_transport::StreamError::Read(
            qsh_transport::ReadError::ConnectionLost(e),
        ))
        | ClientError::Stream(qsh_transport::StreamError::Write(
            qsh_transport::WriteError::ConnectionLost(e),
        )) => crate::reverse::classify_connection_error(e),
        _ => crate::reverse::ReconnectCause::Local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutation coverage for `classify_client_error`'s own three-way split
    /// (issue #4 item 6): a real `ClientError` of each documented shape
    /// classifies as the one `classify_client_error`'s doc comment claims.
    #[test]
    fn classify_client_error_maps_the_documented_vocabulary() {
        // `Connection(ApplicationClosed)` with an ordinary close code (not
        // `CLOSE_CODE_PATH_DEAD`) — a real, clean peer close.
        let closed = ClientError::Connection(qsh_transport::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(0),
                reason: bytes::Bytes::new(),
            },
        ));
        assert_eq!(
            classify_client_error(&closed),
            crate::reverse::ReconnectCause::PeerClosed
        );

        // `Connection(TimedOut)` — quinn's own idle-timeout judgment on an
        // otherwise-silent path, the same condition `PathWatch` exists to
        // detect sooner.
        let timed_out = ClientError::Connection(qsh_transport::ConnectionError::TimedOut);
        assert_eq!(
            classify_client_error(&timed_out),
            crate::reverse::ReconnectCause::PathDead
        );

        // Everything else — a peer-sent wire `Error` reply, here — is
        // `local`: none of it is a peer-initiated clean close or a
        // PathWatch-class idle judgment.
        let remote = ClientError::Remote {
            code: qsh_proto::ErrorCode::PermissionDenied,
            message: "denied".to_string(),
            retryable: false,
        };
        assert_eq!(
            classify_client_error(&remote),
            crate::reverse::ReconnectCause::Local
        );
    }
}
