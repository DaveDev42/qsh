//! Redial and local (localctl) reattach paths: [`DialReconnect`], [`LocalReconnect`], and [`local_reattach`].

use super::*;

/// The forward route's [`Reconnect`]: re-dial the peer directly.
///
/// Owns exactly what the forward route's reconnect step needs — the
/// [`Link`] to redial on and, through `ctx.target`, the [`PeerTarget`] to
/// dial — plus the one piece of state that has to survive a cancelled
/// attempt: a redemption [`spawn_reattach`] started that a timed-out
/// caller walked away from. That adoption logic used to live inline in
/// [`recover_attach`]'s loop as a bare `&mut Option<ReattachTask>`; it is
/// moved here verbatim, not rewritten, so the behaviour — a second
/// attempt finds and awaits the *same* in-flight task rather than starting
/// a second redemption of the same single-use resume token
/// (`spawn_reattach`'s own doc) — is unchanged.
pub(super) struct DialReconnect {
    ctx: Arc<AttachContext>,
    link: Link,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    /// The in-flight redemption, if a previous attempt's deadline stopped
    /// waiting on it without stopping it. A `tokio::sync::Mutex` because
    /// [`Reconnect::reconnect`] has to hold the guard across the `.await`
    /// on the task handle: that is what lets the *outer* `recover()`
    /// timeout cancel this future while leaving the handle in the slot for
    /// the next attempt to pick back up, exactly as the bare `&mut`
    /// binding it replaces did.
    in_flight: tokio::sync::Mutex<Option<ReattachTask>>,
}

impl DialReconnect {
    pub(super) fn new(
        ctx: Arc<AttachContext>,
        link: Link,
        pending: Arc<std::sync::Mutex<PendingInput>>,
    ) -> Self {
        Self {
            ctx,
            link,
            pending,
            in_flight: tokio::sync::Mutex::new(None),
        }
    }
}

impl Reconnect for DialReconnect {
    fn has_pending(&self) -> bool {
        // Never contended at the point `recover_attach` calls this: it
        // asks at the top of a loop iteration, after any previous
        // `reconnect()` future has either run to completion (which clears
        // the slot below) or been dropped by the outer deadline (which
        // drops this guard along with it). A `try_lock` failure here would
        // itself be the bug, not a legitimate "still pending" answer.
        self.in_flight
            .try_lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    fn reconnect(&self, last_output_seq: u64) -> ReconnectFuture<'_> {
        Box::pin(async move {
            let mut in_flight = self.in_flight.lock().await;
            let handle = in_flight.get_or_insert_with(|| {
                spawn_reattach(
                    self.ctx.clone(),
                    self.link.clone(),
                    self.pending.clone(),
                    last_output_seq,
                )
            });
            let joined = handle.await;
            // Reached only when the redemption finished, so a
            // cancellation above (the recovery deadline firing while this
            // `.await` was pending) leaves the handle in the slot for the
            // next attempt to adopt.
            *in_flight = None;
            match joined {
                Ok(result) => result,
                Err(err) => Err(ResumeError::Local(OpError::new(
                    ErrorCode::Internal,
                    format!("the resume task did not finish: {err}"),
                ))),
            }
        })
    }
}

/// The reverse route's [`Reconnect`] (`PLAN.md` M3 Step 8,
/// `docs/design/protocol.md` §11-4's Reattach mapping): no dial of its own
/// to make — [`RecoveryLink`]'s own doc explains why there is no
/// `Connection` here to redial — instead it waits for *the target's own*
/// re-dial to land as a new registration `generation` on the daemon
/// (`Listen::control_hub_wait`, via [`dial_reverse_wait`]), then performs
/// §10 Reattach steps 2–5 on the fresh `LOCAL_CONTROL`/`LOCAL_STREAM`
/// conduit pair that registration's handshake hands back.
///
/// Mirrors [`DialReconnect`]'s in-flight adoption (`Self::in_flight`) for
/// the same reason: the wait for a new generation can legitimately run
/// well past a single [`REDIAL_DEADLINE`] window (the target's own
/// backoff climbs to `backoff_max_ms`, default 30 s), so a caller whose
/// attempt deadline fires must only stop *waiting* on the underlying
/// task, never cancel it outright — cancelling it mid-redemption would
/// either orphan a resume token this device can no longer reach (the same
/// "credential critical section" `docs/design/protocol.md` §10 names for
/// the forward route) or, worse, let the *next* attempt spawn a second,
/// concurrent wait racing the first for the same single-use token.
pub(super) struct LocalReconnect {
    ctx: Arc<AttachContext>,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    /// Same shape and purpose as [`DialReconnect::in_flight`] — see that
    /// field's doc for why a `tokio::sync::Mutex` held across the
    /// `.await` is what lets the outer deadline stop waiting without
    /// stopping the work.
    in_flight: tokio::sync::Mutex<Option<LocalReattachTask>>,
}

impl LocalReconnect {
    pub(super) fn new(
        ctx: Arc<AttachContext>,
        pending: Arc<std::sync::Mutex<PendingInput>>,
    ) -> Self {
        Self {
            ctx,
            pending,
            in_flight: tokio::sync::Mutex::new(None),
        }
    }
}

impl Reconnect for LocalReconnect {
    fn has_pending(&self) -> bool {
        // Same reasoning as `DialReconnect::has_pending`: never contended
        // at the point `recover_attach` asks.
        self.in_flight
            .try_lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    fn reconnect(&self, last_output_seq: u64) -> ReconnectFuture<'_> {
        Box::pin(async move {
            let mut in_flight = self.in_flight.lock().await;
            let handle = in_flight.get_or_insert_with(|| {
                spawn_local_reattach(self.ctx.clone(), self.pending.clone(), last_output_seq)
            });
            let joined = handle.await;
            *in_flight = None;
            match joined {
                Ok(result) => result,
                Err(err) => Err(ResumeError::Local(OpError::new(
                    ErrorCode::Internal,
                    format!("the reverse resume task did not finish: {err}"),
                ))),
            }
        })
    }

    /// The wait [`local_reattach`] measured and stored on
    /// [`ReverseRoute::registration_wait_ms`] before this call's
    /// `reconnect` future resolved — `local_reattach` records it
    /// unconditionally, on both the success and the error path, so by
    /// the time `reconnect` above has returned either way the value is
    /// already there to read. The `u64::MAX` sentinel (no
    /// [`LocalReconnect`] wait has landed on this route yet — the case
    /// where the outer [`REDIAL_DEADLINE`] fired before this attempt's
    /// `local_reattach` got as far as its own store, which can only
    /// happen on the very first attempt) folds to `0` here rather than
    /// leaking a nonsense millisecond count into the telemetry line.
    fn registration_wait_ms(&self) -> u64 {
        let Some(route) = self.ctx.reverse_route.as_ref() else {
            return 0;
        };
        match route
            .registration_wait_ms
            .load(std::sync::atomic::Ordering::Acquire)
        {
            u64::MAX => 0,
            ms => ms,
        }
    }

    /// `ctx.recovery.registration_wait` (the ceiling `local_reattach` asks
    /// the daemon to block for, `RecoveryConfig::registration_wait`'s own
    /// doc) plus [`REDIAL_DEADLINE`] for the resume steps that follow a
    /// registration — exactly the budget split `RecoveryConfig::registration_wait`
    /// promises ("that 2 s budget covers the resume *after* a registration
    /// is observed … while this covers the wait *for* one"). Without this
    /// override `recover`'s default [`REDIAL_DEADLINE`] would cut the wait
    /// itself off after 2 s regardless of `registration_wait`, silently
    /// breaking that promise (`Reconnect::attempt_deadline`'s own doc).
    fn attempt_deadline(&self) -> Duration {
        self.ctx
            .recovery
            .registration_wait
            .saturating_add(REDIAL_DEADLINE)
    }
}

/// A reverse redemption in flight: the [`local_reattach`] the recovery is
/// waiting on — the reverse-route twin of [`ReattachTask`].
type LocalReattachTask =
    tokio::task::JoinHandle<Result<(Session, crate::client::Attached), ResumeError>>;

/// Run [`local_reattach`] on a task of its own — the reverse-route twin of
/// [`spawn_reattach`], for the identical reason: the recovery deadline may
/// stop *waiting* for it without stopping it, so the redemption inside it
/// always runs to `store.put`.
fn spawn_local_reattach(
    ctx: Arc<AttachContext>,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    last_output_seq: u64,
) -> LocalReattachTask {
    tokio::spawn(async move { local_reattach(&ctx, &pending, last_output_seq).await })
}

/// [`reattach`]'s reverse-route twin: wait for the target's re-registration
/// instead of redialing, then redeem the resume credential, persist its
/// successor, open the data stream and retransmit unacked input — exactly
/// §10 Reattach steps 2–5, unchanged (`PLAN.md` M3 Step 8's "새 resume
/// 로직을 만들지 않는다").
///
/// Only ever invoked through [`spawn_local_reattach`], on a
/// [`RecoveryLink::Reverse`] attach (`recover_attach`'s reverse call site
/// builds a [`LocalReconnect`] only when `ctx.link` already is one) — the
/// `ctx.reverse_route`/`ctx.link` mismatches this function bails out on
/// below are defence in depth against a future call site breaking that
/// pairing, not a path this function's only caller can currently reach.
#[cfg(unix)]
async fn local_reattach(
    ctx: &Arc<AttachContext>,
    pending: &Arc<std::sync::Mutex<PendingInput>>,
    last_output_seq: u64,
) -> Result<(Session, crate::client::Attached), ResumeError> {
    // Same cheapest-first check `reattach` opens with: a detach that raced
    // the recovery must not spend a wait, a redemption, and a durable
    // write on a session the user already left.
    if ctx.finished() {
        return Err(abandoned());
    }
    let Some(route) = ctx.reverse_route.as_ref() else {
        // `AttachContext::reverse_route` and `ctx.link`'s
        // `RecoveryLink::Reverse` variant are seeded together, from the
        // same `session_attach` reverse arm (`ReverseRoute`'s own doc on
        // `AttachContext`) — never one without the other. Fail closed
        // instead of panicking if that invariant is ever broken.
        return Err(ResumeError::Local(OpError::new(
            ErrorCode::Internal,
            "reverse recovery attempted with no reverse route recorded on this attach",
        )));
    };
    let RecoveryLink::Reverse(kill) = &ctx.link else {
        return Err(ResumeError::Local(OpError::new(
            ErrorCode::Internal,
            "reverse recovery attempted on an attach whose link is not the reverse route",
        )));
    };
    // The generation baseline this wait must land strictly past —
    // `Listen::control_hub_wait`'s own doc on why "still sitting at
    // exactly this generation" is the dead registration, not a live one.
    let known_generation = route.generation.load(std::sync::atomic::Ordering::Acquire);
    let local_route = LocalRoute {
        host: route.host.clone(),
        socket: route.socket.clone(),
    };
    let wait_ms = u32::try_from(ctx.recovery.registration_wait.as_millis()).unwrap_or(u32::MAX);
    let wait_started = std::time::Instant::now();
    let dialed = dial_reverse_wait(&local_route, wait_ms, Some(known_generation)).await;
    // Recorded regardless of outcome: a failed wait still spent this long
    // finding that out, and a campaign that only ever sees successes
    // cannot tell a fast target from a slow one it happened to catch
    // failing for an unrelated reason.
    let waited_ms = u64::try_from(wait_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    route
        .registration_wait_ms
        .store(waited_ms, std::sync::atomic::Ordering::Release);
    let (mut session, peer_fingerprint, generation) = dialed?;
    // Never proceed on the old generation. `control_hub_wait`'s own
    // strictly-greater gate already guarantees this on the daemon side;
    // this is defence in depth on the client side against a future daemon
    // regression silently handing back the very connection whose death
    // this recovery exists to repair.
    if generation <= known_generation {
        return Err(ResumeError::Local(OpError::new(
            ErrorCode::Internal,
            "daemon handed back a registration generation that did not advance past the one \
             this attach already rode",
        )));
    }
    let store = ResumeStore::new(&ctx.paths);
    // `dial_reverse_wait` always reports `Some` (`LocalHelloAck.peer_fingerprint`
    // is not optional on the wire) — handled as fail-closed `None` here
    // anyway rather than unwrapped, exactly as the first-attach path
    // (`Ops::session_attach`) already treats an absent fingerprint: no
    // verified peer means nothing to bind a credential to.
    let Some(peer) = peer_fingerprint else {
        return Err(NoToken::PeerMismatch.into_error(&ctx.session_ref).into());
    };
    let token = match store.take_for(&ctx.session_ref, &peer) {
        Ok(token) => token,
        Err(why) => return Err(why.into_error(&ctx.session_ref).into()),
    };
    let attached = session
        .attach_request(wire::SessionAttach {
            session_id: ctx.session_id.clone(),
            resume_token: token.expose().to_vec(),
            last_output_seq,
            mode: wire::AttachMode::Rw as i32,
            no_steal: ctx.no_steal,
        })
        .await
        .inspect_err(|err| {
            // Same non-distinguishing treatment as every other resume
            // path: whether the session is gone or the credential is
            // stale is deliberately indistinguishable to the peer.
            if let ClientError::Remote { code, .. } = err
                && matches!(code, ErrorCode::AuthFailed | ErrorCode::SessionNotFound)
            {
                let _ = store.forget(&ctx.session_ref);
            }
        })?;
    // Durable before the stream is touched (ADR-0007) — identical to
    // `reattach`'s ordering.
    if let Some(successor) = StoredToken::from_slice(&attached.new_resume_token)
        && let Err(err) = store.put(
            &ctx.session_ref,
            &ctx.host,
            &ctx.session_id,
            successor,
            &peer,
            &attached.expires_at,
        )
    {
        let _ = store.forget(&ctx.session_ref);
        return Err(err.into());
    }
    let mut attached = session.open_attach_stream(attached).await?;
    // Re-assert the last geometry the frontend asked for — identical
    // reasoning to `reattach`.
    let window = *lock(&ctx.window);
    if let Some((cols, rows)) = window {
        attached.resize(cols, rows).await?;
    }
    let replay = lock(pending).rebase(attached.input_from)?.to_vec();
    if !replay.is_empty() {
        attached.send_input(&replay).await?;
    }
    // Last gate before this leg becomes *the* leg: a detach that landed
    // while this was being built must not have its freshly built
    // replacement installed behind it. The successor credential is
    // already durable, so the session stays attachable — only this leg is
    // dropped, exactly as `reattach`'s own closing gate does.
    if ctx.finished() {
        return Err(abandoned());
    }
    // Advance the generation baseline before the old kill switch is
    // silenced, so a concurrent read of `route.generation` (there is
    // none today — only this one `LocalReconnect` ever runs at a time,
    // Step 8's own single-flight design — but this ordering costs
    // nothing and keeps the invariant true even if that ever changes)
    // never observes the new leg installed under the old generation.
    route
        .generation
        .store(generation, std::sync::atomic::Ordering::Release);
    // Only now, with the new leg working, is the old conduit let go —
    // `reattach`'s "only now is the old connection let go" ordering,
    // ported to the reverse route's hard-stop primitive.
    let old_kill = kill.replace(attached.kill.clone());
    old_kill.kill();
    Ok((session, attached))
}

/// Windows twin of [`local_reattach`]: unreachable in practice (no
/// `RecoveryLink::Reverse` attach exists off unix — `Ops::connect_reverse`'s
/// non-unix arm always fails first), kept only so `LocalReconnect`'s
/// `Reconnect` impl compiles on every platform.
#[cfg(not(unix))]
async fn local_reattach(
    ctx: &Arc<AttachContext>,
    _pending: &Arc<std::sync::Mutex<PendingInput>>,
    _last_output_seq: u64,
) -> Result<(Session, crate::client::Attached), ResumeError> {
    let _ = ctx;
    Err(ResumeError::Local(OpError::new(
        ErrorCode::Unsupported,
        "reverse routing (localctl) is not available on this platform",
    )))
}
