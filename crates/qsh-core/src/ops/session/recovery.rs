//! Attach recovery: [`Recovery`], [`recover_attach`], the liveness probe, and the resume-error mapping.

use super::*;

/// What one recovery produced.
#[allow(clippy::large_enum_variant, reason = "short-lived, moved once")]
pub(super) enum Recovery {
    /// The connection survived; carry on with the leg that is already
    /// running. Only ever a valid answer to [`LegEnd::PathDead`], because
    /// it hands the caller back the very reader and writer it came in
    /// with.
    SameLeg,
    /// A new connection and a resumed attach.
    NewLeg(Session, crate::client::Attached),
    /// The frontend ended the attach while the recovery was running, so
    /// there is nothing left to recover *to*. Not a failure: nobody is
    /// owed an error for a detach they asked for.
    Abandoned,
    /// Nothing worked inside the budget.
    Failed(OpError),
}

/// Recover one detected path death: migrate if that is enough, otherwise
/// re-dial and resume, retrying up to [`RecoveryConfig::attempts`] times.
///
/// Every attempt is bounded by `reconnect.attempt_deadline()` ([`REDIAL_DEADLINE`]
/// on the forward route, wider on the reverse route — see
/// [`Reconnect::attempt_deadline`]) and recorded on `qsh::recovery` by
/// [`recover`] itself, so a failed attempt is a campaign datapoint rather
/// than a silence.
///
/// `leg_survived` says whether the old leg's streams are still worth
/// keeping ([`LegEnd::leg_survived`]). When they are not, the migration
/// half is skipped outright: probing the connection would answer "alive"
/// and return [`Recovery::SameLeg`], which is a broken reader handed back
/// to a caller that will fail on it again with no backoff.
///
/// `link` is `Some` only on the forward route (`Step 8`: this function is
/// now shared with the reverse route too, unlike before Step 8, when it
/// was forward-only and took a bare `&Link`). `None` disables migration
/// unconditionally, regardless of `leg_survived`/`ctx.recovery.migration`
/// — there is no `Connection` to probe or rebind on the reverse route
/// (`RecoveryLink`'s own doc), so every attempt falls straight through to
/// `reconnect`. In practice `leg_survived` is already always `false` on
/// that route (reverse's [`spawn_watchdog`] never produces
/// [`LegEnd::PathDead`], the only end [`LegEnd::leg_survived`] answers
/// `true` for), so this is defence in depth, not the only thing standing
/// between a reverse leg and a migration attempt.
#[allow(
    clippy::too_many_arguments,
    reason = "one more than before Step 8 (`reconnect`, the `Reconnect` seam the forward call \
              site builds a `DialReconnect` for — bundling it into `ctx` would put a route- \
              specific reconnect step back where `RecoveryLink` already keeps the routes apart)"
)]
pub(super) async fn recover_attach(
    ctx: &Arc<AttachContext>,
    link: Option<&Link>,
    leg_survived: bool,
    watch: &PathWatch,
    probes: &Arc<tokio::sync::Notify>,
    cursor: &Arc<std::sync::Mutex<OutputCursor>>,
    pumps: &mut LegPumps,
    reconnect: &dyn Reconnect,
) -> Recovery {
    let mut last: Option<OpError> = None;
    for attempt in 0..ctx.recovery.attempts.max(1) {
        // Re-checked on every attempt, not once before the loop: a `~d`
        // that lands mid-recovery must end the attach, not be answered
        // with a fresh connection to the session the user just left.
        if ctx.finished() {
            return Recovery::Abandoned;
        }
        let backoff = RecoveryConfig::backoff(attempt);
        if !backoff.is_zero() {
            tokio::time::sleep(backoff).await;
        }
        if ctx.finished() {
            return Recovery::Abandoned;
        }
        // Only the first attempt still has a live leg behind it, so only
        // the first can migrate: after a re-dial has been attempted the
        // old connection and its control stream are gone. And only a leg
        // whose streams outlived the failure can be kept at all. `link`
        // being `None` (the reverse route) forces this `false` too — see
        // this function's own doc.
        let live_leg = link.is_some() && leg_survived && attempt == 0 && !reconnect.has_pending();
        let binder = link.map(Link::endpoint);
        let migration = live_leg && ctx.recovery.migration;
        let path_binder: Option<&dyn PathBinder> = if migration {
            binder.as_ref().map(|b| b as &dyn PathBinder)
        } else {
            None
        };
        let last_output_seq = lock(cursor).last_seq();

        let outcome = recover(
            &ctx.session_ref,
            path_binder,
            reconnect.attempt_deadline(),
            || {
                let watch = watch.clone();
                let probes = probes.clone();
                // `None` only when `link` is `None` (the reverse route),
                // in which case `live_leg` is already forced `false`
                // above — so `rtt.is_none()` short-circuits the `&&`
                // below before `probe_alive` would ever need a value.
                let rtt = link.map(|link| link.connection().quinn().stats().path.rtt);
                async move {
                    match rtt {
                        Some(rtt) => live_leg && probe_alive(&watch, &probes, rtt).await,
                        None => false,
                    }
                }
            },
            || async {
                // Past the point of no return for this leg: stop the pumps
                // (which is what releases the command queue and the
                // `Session`) before building a replacement.
                pumps.stop().await;
                reconnect.reconnect(last_output_seq).await
            },
            // Read only after the attempt above has resolved (`recover`'s
            // own doc) — `0` on the forward route, the reverse route's
            // measured re-registration wait on the other
            // (`Reconnect::registration_wait_ms`'s own doc).
            || reconnect.registration_wait_ms(),
        )
        .await;

        match outcome.outcome {
            Ok(Recovered::Migrated) => return Recovery::SameLeg,
            Ok(Recovered::Resumed(leg)) => return Recovery::NewLeg(leg.0, leg.1),
            Err(err) => {
                if ctx.finished() {
                    return Recovery::Abandoned;
                }
                last = Some(map_resume_error(err));
            }
        }
    }
    Recovery::Failed(last.unwrap_or_else(|| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            "the session's path died and could not be recovered",
        )
    }))
}

/// Ask the host, on the connection we already have, whether it is still
/// there — and take any answer at all as a yes.
///
/// The `Ping` goes out through the control pump, which owns the stream;
/// the answer is whatever the watchdog next sees as inbound traffic, which
/// may be the `Pong`, a session event, or a frame of output.
async fn probe_alive(watch: &PathWatch, probes: &Arc<tokio::sync::Notify>, rtt: Duration) -> bool {
    // Subscribed **before** the question is asked. The answer can land on
    // a runtime worker before this task is polled again, and a
    // notification edge issued in that window is delivered to nobody — a
    // connection that genuinely survived would then be written off as
    // unmigratable and pay for a full resume it did not need.
    let mut answered = watch.inbound_signal();
    probes.notify_one();
    tokio::time::timeout(migration_probe_budget(rtt), answered.changed())
        .await
        .is_ok()
}

/// A redemption in flight: the [`reattach`] the recovery is waiting on.
pub(super) type ReattachTask =
    tokio::task::JoinHandle<Result<(Session, crate::client::Attached), ResumeError>>;

/// Run [`reattach`] on a task of its own, so the recovery deadline can stop
/// *waiting* for it without stopping it.
///
/// This is not an optimization, it is the difference between a recovered
/// session and one nobody can ever reach again. The host kills the
/// presented resume token the instant it mints the successor
/// (protocol.md §10 "Rotation"), so there is a window — from "the request
/// is on the wire" to "the successor is on disk" — in which cancelling the
/// client leaves this device holding a credential the host has already
/// retired, for a session that is alive and, because attach is
/// device-bound (`docs/CLI.md` §6.2), that no other device can rescue.
/// A cancelled `.await` on a `JoinHandle` merely detaches the task, so the
/// redemption always runs to `store.put`.
pub(super) fn spawn_reattach(
    ctx: Arc<AttachContext>,
    link: Link,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    last_output_seq: u64,
) -> ReattachTask {
    tokio::spawn(async move { reattach(&ctx, &link, &pending, last_output_seq).await })
}

/// Rebuild a dead attach on a fresh connection: dial, redeem the resume
/// credential, persist its successor, open the data stream, and retransmit
/// the input the host never acknowledged (`docs/design/protocol.md` §10).
///
/// `link` is the same forward [`Link`] `drive_attach`'s gate already pulled
/// out of `ctx.link` — never re-derived here, and never itself the reverse
/// route's kind, because [`recover_attach`] (this function's only caller,
/// via [`spawn_reattach`]) is never invoked with one (`RecoveryLink`'s own
/// doc).
async fn reattach(
    ctx: &Arc<AttachContext>,
    link: &Link,
    pending: &Arc<std::sync::Mutex<PendingInput>>,
    last_output_seq: u64,
) -> Result<(Session, crate::client::Attached), ResumeError> {
    // Cheapest place to notice a detach that raced the recovery: before a
    // socket, a handshake or a `session.attach` the host would audit and
    // answer by moving the writer lease back to a client that has left.
    if ctx.finished() {
        return Err(abandoned());
    }
    // `ctx.target` is `Some` on every forward-route attach (the only kind
    // that ever reaches `reattach` — this fn's own doc), and `None` only
    // on the reverse route, which never resolves one at all
    // (`session_attach`'s own doc). `AttachContext::target`'s doc names
    // this same invariant.
    let target = ctx
        .target
        .as_ref()
        .expect("reattach only runs on the forward route, which always resolves a PeerTarget");
    let (endpoint, connection, mut session) = dial_peer(target).await?;
    let store = ResumeStore::new(&ctx.paths);
    let Some(peer) = connection.peer_fingerprint().map(|fp| fp.to_string()) else {
        connection.close(0, b"unverified");
        endpoint.wait_idle().await;
        return Err(NoToken::PeerMismatch.into_error(&ctx.session_ref).into());
    };
    let token = match store.take_for(&ctx.session_ref, &peer) {
        Ok(token) => token,
        Err(why) => {
            connection.close(0, b"no credential");
            endpoint.wait_idle().await;
            return Err(why.into_error(&ctx.session_ref).into());
        }
    };
    let attached = session
        .attach_request(wire::SessionAttach {
            session_id: ctx.session_id.clone(),
            resume_token: token.expose().to_vec(),
            // Exactly where the frontend's terminal stopped, so the host
            // replays from there and nothing is redrawn or lost.
            last_output_seq,
            mode: wire::AttachMode::Rw as i32,
            no_steal: ctx.no_steal,
        })
        .await
        .inspect_err(|err| {
            // Same reasoning as a first attach: whether the session is gone
            // or the credential is stale is deliberately indistinguishable,
            // and the answer is the same either way.
            if let ClientError::Remote { code, .. } = err
                && matches!(code, ErrorCode::AuthFailed | ErrorCode::SessionNotFound)
            {
                let _ = store.forget(&ctx.session_ref);
            }
        })?;
    // Durable before the stream is touched (ADR-0007).
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
        connection.close(0, b"credential not durable");
        endpoint.wait_idle().await;
        return Err(err.into());
    }
    let mut attached = session.open_attach_stream(attached).await?;
    // A `SIGWINCH` that landed while the path was dead wrote to a stream
    // nobody was reading, and a resize is not part of the un-acked input
    // axis, so nothing else would ever retransmit it. Re-assert the
    // geometry the frontend last asked for before the input replay, so the
    // shell redraws at the size the terminal is actually at.
    let window = *lock(&ctx.window);
    if let Some((cols, rows)) = window {
        attached.resize(cols, rows).await?;
    }
    // The host's axis for this attach starts at what it actually applied on
    // the stream we lost, so the tail it never saw is retransmitted — and
    // nothing it *did* see is sent twice (protocol.md §10-5).
    let replay = lock(pending).rebase(attached.input_from)?.to_vec();
    if !replay.is_empty() {
        attached.send_input(&replay).await?;
    }
    // Last gate before the new connection becomes *the* connection: a
    // detach that landed while this was being built must not have its
    // freshly dialed replacement installed behind it. The successor
    // credential is already durable, so the session stays attachable — it
    // is only this leg that is dropped.
    if ctx.finished() {
        connection.close(0, b"detached");
        endpoint.wait_idle().await;
        return Err(abandoned());
    }
    // Only now, with the new leg working, is the old connection let go.
    let (old_endpoint, old_connection) = link.replace(endpoint, connection);
    old_connection.close(0, b"superseded");
    drop(old_endpoint);
    Ok((session, attached))
}

/// The attach ended under a recovery that was still running.
pub(super) fn abandoned() -> ResumeError {
    ResumeError::Local(OpError::new(
        ErrorCode::ConnectionFailed,
        "the attach was ended while its path was being recovered",
    ))
}

pub(super) fn map_resume_error(err: ResumeError) -> OpError {
    match err {
        ResumeError::Local(err) => err,
        ResumeError::Client(err) => map_client_error(err),
        ResumeError::Deadline(deadline) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!(
                "the session's path died and was not recovered within {} ms",
                deadline.as_millis()
            ),
        ),
        other @ (ResumeError::UnackedInputOverflow { .. }
        | ResumeError::InputUnrecoverable { .. }) => {
            OpError::new(ErrorCode::ResourceExhausted, other.to_string())
        }
    }
}

/// Lock a mutex, ignoring poisoning: every critical section here is a few
/// field updates, so a poisoned lock means a panic elsewhere and the state
/// is still coherent.
pub(super) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
