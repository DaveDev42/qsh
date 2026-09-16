//! The attach driver loop: watchdog, [`drive_attach`], and [`read_leg`].

use super::*;

/// Start (or, on the reverse route, deliberately not start) the path
/// watchdog for one leg.
///
/// Forward: [`watch_path`] polls the real QUIC `Connection` this attach's
/// [`RecoveryLink::Forward`] holds, exactly as before Step 7. Reverse:
/// there is no connection this attach owns alone to probe (`RecoveryLink`'s
/// own doc) — the returned task simply never completes, so `watch.dead()`
/// never fires and [`read_leg`]'s `select!` is decided purely by the
/// `LOCAL_STREAM` conduit's own reader (a clean end is [`LegEnd::Ended`],
/// an error is [`LegEnd::Broken`] — both already handled with no recovery
/// attempted, since `drive_attach`'s gate only ever calls [`recover_attach`]
/// on a `Forward` link).
fn spawn_watchdog(
    link: &RecoveryLink,
    watch: PathWatch,
    probes: Arc<tokio::sync::Notify>,
) -> AbortOnDrop {
    match link {
        RecoveryLink::Forward(link) => {
            AbortOnDrop(tokio::spawn(watch_path(link.connection(), watch, probes)))
        }
        RecoveryLink::Reverse(_) => AbortOnDrop(tokio::spawn(async move {
            let _ = (watch, probes);
            std::future::pending::<()>().await;
        })),
    }
}

/// Drive one attach for its whole life, across as many connections as it
/// takes (`docs/design/protocol.md` §2, §10; `PLAN.md` M2 Step 7 (a)).
///
/// Each *leg* is one connection's worth of attach: a data stream, a control
/// stream, and a watchdog asking whether the path still carries packets. A
/// leg ends when the session does, when the frontend goes away, or when the
/// watchdog says the path is dead — and only the last of those is
/// recoverable. Recovery either revives the leg (the connection migrated:
/// nothing to rebuild, nothing to replay) or builds a new one and stitches
/// it to the old with [`OutputCursor`] and [`PendingInput`], so the byte
/// stream the frontend sees has no seam in it.
///
/// Three tasks per leg, never one `select!` over all of them, for two
/// reasons that both bit the first cut:
///
/// - a `select!` arm that awaits `AttachWriter::send_input` stops polling
///   the read arm while it is parked on QUIC flow control, and the host
///   parks its own input reader when *its* frame queue fills — a large
///   paste on a chatty session deadlocks both ends until the idle timeout;
/// - `Session::next_event` answers a `Ping` with a `write_all`, which is
///   **not** cancel-safe: losing a `select!` race mid-write leaves half a
///   control frame on the wire and desynchronises the peer's decoder. The
///   control pump uses [`Session::next_control`], which only reads, and
///   does its writing in the branch body where nothing can cancel it.
pub(super) async fn drive_attach(
    ctx: Arc<AttachContext>,
    session: Session,
    attached: crate::client::Attached,
    commands: tokio::sync::mpsc::Receiver<AttachCommand>,
    events: tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
) {
    // Shared across legs: the command queue survives a recovery (input
    // typed while the path was dying is still input), and so do the two
    // cursors that make the stitch invisible.
    let commands = Arc::new(tokio::sync::Mutex::new(commands));
    let pending = Arc::new(std::sync::Mutex::new(PendingInput::new(
        attached.input_from,
    )));
    let cursor = Arc::new(std::sync::Mutex::new(OutputCursor::new(0)));

    let mut session = session;
    let mut attached = attached;

    'leg: loop {
        let watch = PathWatch::new(ctx.recovery.watch);
        let probes = Arc::new(tokio::sync::Notify::new());
        let (writer, mut reader) = attached.split();

        let (input_stop, input_stop_rx) = tokio::sync::oneshot::channel();
        let (ctl_stop, ctl_stop_rx) = tokio::sync::oneshot::channel();
        let mut pumps = LegPumps {
            input: Some(Pump {
                stop: Some(input_stop),
                handle: tokio::spawn(pump_attach_input(
                    writer,
                    commands.clone(),
                    pending.clone(),
                    watch.clone(),
                    ctx.clone(),
                    events.clone(),
                    input_stop_rx,
                )),
            }),
            control: Some(Pump {
                stop: Some(ctl_stop),
                handle: tokio::spawn(pump_attach_control(
                    session,
                    ctx.session_id.clone(),
                    ctx.session_ref.clone(),
                    events.clone(),
                    watch.clone(),
                    probes.clone(),
                    ctl_stop_rx,
                )),
            }),
        };
        let mut watchdog = spawn_watchdog(&ctx.link, watch.clone(), probes.clone());

        loop {
            let end = read_leg(&mut reader, &cursor, &pending, &watch, &ctx, &events).await;
            // Decided here, before `end` is consumed: a recovery may only
            // be answered with "keep reading the same leg" if the leg
            // itself survived. See [`LegEnd::leg_survived`].
            let leg_survived = end.leg_survived();
            let recoverable = match end {
                LegEnd::Ended => {
                    // The data stream ended. `session.closed` has no
                    // `SessionFrame` form, so a close the host queued just
                    // before the FIN is still in flight on the control
                    // stream — give it a bounded moment to arrive rather
                    // than racing it to the exit (CLI.md §6.4 makes it the
                    // last event).
                    if let Some(pump) = pumps.control.as_mut() {
                        let _ = tokio::time::timeout(ATTACH_CONTROL_DRAIN, &mut pump.handle).await;
                    }
                    return;
                }
                LegEnd::Gone => return,
                LegEnd::PathDead => None,
                LegEnd::Broken(err) => Some(err),
            };
            // A connection the frontend closed on purpose (a detach) is not
            // a path that died, and recovering from it would resurrect an
            // attach the user just ended — checked identically on both
            // routes. Which `Reconnect` `recover_attach` gets built with is
            // the one thing that still depends on the route (`RecoveryLink`'s
            // own doc): the forward route redials itself (`DialReconnect`),
            // the reverse route waits for the target's own re-dial to land
            // as a new registration generation (`LocalReconnect`, Step 8).
            let recovery = if let RecoveryLink::Forward(link) = &ctx.link
                && ctx.recovery.enabled
                && !ctx.finished()
            {
                let forward_link = link.clone();
                drop(watchdog);
                let reconnector =
                    DialReconnect::new(ctx.clone(), forward_link.clone(), pending.clone());
                let recovery = recover_attach(
                    &ctx,
                    Some(&forward_link),
                    leg_survived,
                    &watch,
                    &probes,
                    &cursor,
                    &mut pumps,
                    &reconnector,
                )
                .await;
                if matches!(recovery, Recovery::SameLeg) {
                    // Migrated: the connection, both streams and every
                    // cursor are exactly as they were. Re-arm the watchdog
                    // and keep reading the same stream. Only the forward
                    // route can ever produce this (`recover_attach`'s own
                    // doc on its `link: None` branch), so it is handled
                    // here rather than in the route-agnostic match below.
                    watch.revive();
                    watchdog = AbortOnDrop(tokio::spawn(watch_path(
                        forward_link.connection(),
                        watch.clone(),
                        probes.clone(),
                    )));
                    continue;
                }
                recovery
            } else if let RecoveryLink::Reverse(_) = &ctx.link
                && ctx.recovery.enabled
                && !ctx.finished()
            {
                drop(watchdog);
                let reconnector = LocalReconnect::new(ctx.clone(), pending.clone());
                recover_attach(
                    &ctx,
                    None,
                    leg_survived,
                    &watch,
                    &probes,
                    &cursor,
                    &mut pumps,
                    &reconnector,
                )
                .await
            } else {
                if let Some(err) = recoverable {
                    let _ = events.send(Err(map_client_error(err))).await;
                }
                return;
            };

            match recovery {
                Recovery::SameLeg => {
                    // Structurally reachable only from the forward branch
                    // above, which already `continue`d before getting
                    // here — a typed error rather than `unreachable!()` so
                    // a future `Reconnect` implementation that breaks that
                    // invariant fails closed instead of panicking
                    // (`docs/design/testing.md`; `PLAN.md` M3 Step 8's
                    // "recovery == migrated must be impossible on the
                    // reverse leg").
                    let _ = events
                        .send(Err(OpError::new(
                            ErrorCode::Internal,
                            "recovery reported a migrated connection on a route with no \
                             migration",
                        )))
                        .await;
                    return;
                }
                Recovery::NewLeg(new_session, new_attached) => {
                    // Last check before the new leg is installed: a detach
                    // that raced the rebuild must not be answered with a
                    // fresh leg on a session the user has already left.
                    if ctx.finished() {
                        return;
                    }
                    session = new_session;
                    attached = new_attached;
                    continue 'leg;
                }
                // The frontend ended the attach while we were recovering
                // it. Nothing to report: this is the user's own doing.
                Recovery::Abandoned => return,
                Recovery::Failed(err) => {
                    let _ = events.send(Err(err)).await;
                    return;
                }
            }
        }
    }
}

/// Read one leg's data stream until it ends, breaks, or the path dies.
async fn read_leg(
    reader: &mut crate::client::AttachReader,
    cursor: &Arc<std::sync::Mutex<OutputCursor>>,
    pending: &Arc<std::sync::Mutex<PendingInput>>,
    watch: &PathWatch,
    ctx: &AttachContext,
    events: &tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
) -> LegEnd {
    loop {
        let next = tokio::select! {
            biased;
            // Checked first: once the path is dead the frames still
            // arriving are from a connection that cannot answer, and every
            // millisecond spent on them comes out of the recovery budget.
            () = watch.dead() => return LegEnd::PathDead,
            // Cancel-safe: `FramedRecv` keeps its partial frame in the
            // decoder, so losing this race loses nothing.
            next = reader.next() => next,
        };
        let event = match next {
            Ok(Some(event)) => event,
            Ok(None) => return LegEnd::Ended,
            Err(err) => return LegEnd::Broken(err),
        };
        // Anything at all from the host proves the path carries packets —
        // and a session that is producing output is a session in use, so
        // this is traffic rather than bare liveness.
        watch.traffic();
        if let AttachEvent::InputAck { acked_input_seq } = &event {
            lock(pending).ack(*acked_input_seq);
            // Monotonic: a resumed leg re-acks from the offset the host
            // applied, and a stale ack from the leg that just died must not
            // walk the mark backwards under a waiting detach.
            ctx.applied_input.send_if_modified(|applied| {
                let ahead = *acked_input_seq > *applied;
                if ahead {
                    *applied = *acked_input_seq;
                }
                ahead
            });
        }
        // Defence in depth against a doubled terminal (protocol.md §10-3):
        // the host is asked to replay from exactly where we stopped, but a
        // frame still in flight on the connection that just died, or a host
        // replaying from a conservative earlier offset, must not redraw
        // what is already on screen.
        let Some(event) = lock(cursor).accept(event) else {
            continue;
        };
        if let Some(json) = attach_event_json(&ctx.session_ref, event) {
            // A frontend that stopped draining looks exactly like a path
            // that stopped answering; say which it is rather than let the
            // watchdog guess.
            let _stalled = watch.stalled();
            if events.send(Ok(json)).await.is_err() {
                return LegEnd::Gone;
            }
        }
    }
}
