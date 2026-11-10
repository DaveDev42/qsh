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
/// takes (`docs/design/protocol.md` §2, §10; M2 plan Step 7 (a) (2473c88)).
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
        let watch = PathWatch::linked(ctx.recovery.watch, ctx.link_status.clone());
        let probes = Arc::new(tokio::sync::Notify::new());
        // Screen sync (ADR-0052): this leg's screen, and the channel the
        // reader tells the input pump which state to acknowledge on. A new
        // leg starts from nothing (the host sends a full screen first) and
        // from a terminal nobody can vouch for.
        let (ack_tx, ack_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
        let mut leg_screen = match &ctx.screen {
            Some(sink) if !attached.screen_channel.is_empty() => {
                sink.new_leg(attached.writer_lease);
                Some(LegScreen {
                    client: crate::client::screen::ClientScreen::new(),
                    acks: ack_tx,
                })
            }
            _ => None,
        };
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
                    InputSignals {
                        stop: input_stop_rx,
                        acks: ack_rx,
                    },
                )),
            }),
            control: Some(Pump {
                stop: Some(ctl_stop),
                handle: tokio::spawn(pump_attach_control(
                    session,
                    ctx.clone(),
                    events.clone(),
                    watch.clone(),
                    probes.clone(),
                    ctl_stop_rx,
                )),
            }),
        };
        let mut watchdog = spawn_watchdog(&ctx.link, watch.clone(), probes.clone());

        loop {
            let end = read_leg(
                &mut reader,
                &cursor,
                &pending,
                &watch,
                &ctx,
                &events,
                &mut leg_screen,
            )
            .await;
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
                let recovery = with_status_ticks(
                    &ctx,
                    &events,
                    recover_attach(
                        &ctx,
                        Some(&forward_link),
                        leg_survived,
                        &watch,
                        &probes,
                        &cursor,
                        &mut pumps,
                        &reconnector,
                    ),
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
                with_status_ticks(
                    &ctx,
                    &events,
                    recover_attach(
                        &ctx,
                        None,
                        leg_survived,
                        &watch,
                        &probes,
                        &cursor,
                        &mut pumps,
                        &reconnector,
                    ),
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
                    // (`docs/design/testing.md`; M3 plan Step 8 (2473c88)'s
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

/// Run a recovery while keeping the status line alive: no leg is being read
/// then, so nothing else would draw the seconds counting or the attempt
/// number (ADR-0053 decision 9). The line is drawn from the arm's body, which
/// is never cancelled, so a frame is either handed to the frontend or not
/// computed at all. The recovery's attempt marker ends with it.
async fn with_status_ticks<T>(
    ctx: &AttachContext,
    events: &tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
    recovery: impl std::future::Future<Output = T>,
) -> T {
    tokio::pin!(recovery);
    let out = loop {
        tokio::select! {
            biased;
            out = &mut recovery => break out,
            () = screen_tick_due(ctx.screen.as_deref()) => {
                if let Some(sink) = &ctx.screen {
                    // A frontend that went away ends the recovery by
                    // its own `finished` flag; nothing to do here.
                    let now = std::time::Instant::now();
                    let _ = sink
                        .emit(events, &ctx.session_ref, None, |s| s.tick(now))
                        .await;
                }
            }
        }
    };
    ctx.link_status.set_recovering(None);
    out
}

/// One leg's side of screen sync: the screen the host described so far and
/// the way to acknowledge states (ADR-0052 decisions 5 and 6).
pub(super) struct LegScreen {
    client: crate::client::screen::ClientScreen,
    acks: tokio::sync::mpsc::UnboundedSender<u64>,
}

/// [`ScreenSink::tick_due`], or never for an attach without a screen.
async fn screen_tick_due(sink: Option<&ScreenSink>) {
    match sink {
        Some(sink) => sink.tick_due().await,
        None => std::future::pending().await,
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
    screen: &mut Option<LegScreen>,
) -> LegEnd {
    loop {
        let next = tokio::select! {
            biased;
            // Checked first: once the path is dead the frames still
            // arriving are from a connection that cannot answer, and every
            // millisecond spent on them comes out of the recovery budget.
            () = watch.dead() => return LegEnd::PathDead,
            // A prediction turned late, or the policy changed: redraw the
            // overlay (ADR-0053 decision 8). Pends forever without one.
            () = screen_tick_due(ctx.screen.as_deref()) => {
                if let Some(sink) = &ctx.screen {
                    let now = std::time::Instant::now();
                    if !sink
                        .emit(events, &ctx.session_ref, Some(watch), |s| s.tick(now))
                        .await
                    {
                        return LegEnd::Gone;
                    }
                }
                continue;
            }
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
        // Screen sync, reverse route: the spacing between an `Input` and the
        // `InputAck` that covers it is the round-trip sample the prediction
        // policy runs on (ADR-0053 decision 8). A policy change shows up as a
        // different overlay, drawn right here.
        if screen.is_some()
            && let AttachEvent::InputAck { acked_input_seq } = &event
            && let Some(sink) = &ctx.screen
        {
            let now = std::time::Instant::now();
            if !sink
                .emit(events, &ctx.session_ref, Some(watch), |s| {
                    s.input_ack(*acked_input_seq, now)
                })
                .await
            {
                return LegEnd::Gone;
            }
        }
        // The host's input reflection point: judge the predictions it
        // covers. A report for a state not applied yet is held by the
        // predictor (one, the newest) until that state is drawn below.
        if screen.is_some()
            && let AttachEvent::ScreenEcho(echo) = &event
        {
            if let Some(sink) = &ctx.screen {
                let now = std::time::Instant::now();
                if !sink
                    .emit(events, &ctx.session_ref, Some(watch), |s| s.echo(echo, now))
                    .await
                {
                    return LegEnd::Gone;
                }
            }
            continue;
        }
        // A screen-sync leg: parts of a state go to the leg's screen, the
        // state number it now holds goes back to the host, and an applied
        // state is drawn on the frontend's terminal as `Output` bytes.
        if screen.is_some()
            && let AttachEvent::ScreenHistory(h) = &event
        {
            if let Some(sink) = &ctx.screen {
                // Lossy: the lines are untrusted text, and the renderer
                // sanitises what is left.
                let lines: Vec<String> = h
                    .lines
                    .iter()
                    .map(|l| String::from_utf8_lossy(l).into_owned())
                    .collect();
                if !sink
                    .emit(events, &ctx.session_ref, Some(watch), |s| {
                        s.history(&lines, h.skipped)
                    })
                    .await
                {
                    return LegEnd::Gone;
                }
            }
            continue;
        }
        if let Some(leg) = screen.as_mut() {
            let outcome = match &event {
                AttachEvent::Screen(part) => match leg.client.on_part(part) {
                    Ok(outcome) => Some(outcome),
                    Err(err) => return LegEnd::Broken(err),
                },
                AttachEvent::ScreenDatagram(part) => Some(leg.client.on_datagram_part(part)),
                _ => None,
            };
            if let Some(outcome) = outcome {
                if let Some(state_num) = outcome.ack() {
                    // The input pump sends it; it is gone when the leg is.
                    let _ = leg.acks.send(state_num);
                }
                if let crate::client::screen::ScreenOutcome::Applied {
                    effects,
                    output_seq,
                    new_num,
                } = outcome
                    && let (Some(sink), Some(state)) = (&ctx.screen, leg.client.state())
                {
                    let now = std::time::Instant::now();
                    if !sink
                        .emit(events, &ctx.session_ref, Some(watch), |s| {
                            s.draw(state, &effects, output_seq, new_num, now)
                        })
                        .await
                    {
                        return LegEnd::Gone;
                    }
                }
                continue;
            }
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
