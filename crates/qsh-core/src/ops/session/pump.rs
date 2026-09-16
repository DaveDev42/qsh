//! The attach input/control pumps and the event JSON they emit.

use super::*;

/// Sole owner of one leg's send half: queued input and resizes, in order. A
/// write that fails does not end the attach — a stolen writer lease demotes
/// this peer to read-only (protocol.md §10) and it is still owed its
/// output.
///
/// Every accepted command is recorded in `pending` **before** it is
/// written, so a leg that dies mid-write leaves the bytes retransmittable
/// rather than lost.
pub(super) async fn pump_attach_input(
    mut writer: crate::client::AttachWriter,
    commands: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<AttachCommand>>>,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    watch: PathWatch,
    ctx: Arc<AttachContext>,
    events: tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    let finished = &ctx.finished;
    let mut commands = commands.lock().await;
    loop {
        let command = tokio::select! {
            biased;
            _ = &mut stop => return,
            // Cancel-safe, and the only await that can lose the race: the
            // handling below runs to completion once a command is taken.
            command = commands.recv() => match command {
                Some(command) => command,
                None => break,
            },
        };
        // Somebody is waiting for an answer, so the watchdog runs at its
        // fast cadence from here.
        watch.activity();
        let sent = match command {
            AttachCommand::Input(data) => {
                // Recorded first: bytes accepted from the frontend are the
                // client's responsibility from this moment, and a leg that
                // dies before the write lands must retransmit them.
                // Bound the guard to this statement: the refusal below
                // awaits, and a `std` guard held across an await is not
                // `Send`.
                let refused = lock(&pending).push(&data).err();
                if let Some(err) = refused {
                    // protocol.md §10-5 is explicit that overrunning the
                    // 64 KiB cap is an **error**, not silent buffering.
                    // These bytes cannot be replayed across a break, so a
                    // `warn` on stderr would be the user believing they
                    // typed something the shell will never see — under a
                    // raw-mode TUI, invisibly. Say so on the event stream
                    // and stop writing.
                    //
                    // Only this leg's send half stops: the output the user
                    // is owed keeps arriving, and a recovery — which is
                    // what an unacking host usually means — spawns a fresh
                    // pump against a host that is acking again.
                    tracing::warn!(%err, "the un-acked input buffer is full");
                    let _ = events.send(Err(map_resume_error(err))).await;
                    return;
                }
                writer.send_input(&data).await.map(|_| ())
            }
            AttachCommand::Resize { cols, rows } => {
                // Remembered before it is written: a resize is not on the
                // input axis, so a resume has nothing to retransmit it
                // from unless the last size was kept somewhere.
                *lock(&ctx.window) = Some((cols, rows));
                writer.resize(cols, rows).await
            }
            AttachCommand::Detach(ack) => {
                // Everything queued ahead of the detach has been written by
                // the time we get here, so this offset covers every byte
                // the frontend handed us. Mark the attach deliberately over
                // (the supervisor must not recover it), FIN the send half,
                // and wait for the host to say the child ran them.
                finished.store(true, std::sync::atomic::Ordering::Release);
                let target = writer.input_seq();
                writer.finish();
                let _ = ack.send(await_applied(&ctx.applied_input, target).await);
                return;
            }
        };
        if sent.is_err() {
            return;
        }
    }
    // The frontend dropped its handle: finish our send half so the host
    // drains what is left and finishes the stream.
    finished.store(true, std::sync::atomic::Ordering::Release);
    writer.finish();
}

/// Wait until the host has acknowledged applying every byte up to `target`,
/// or [`DETACH_FLUSH`] passes.
///
/// Returns immediately when the mark is already there, which is the usual
/// case for a `~d` typed on its own line: the escape follows a CR the host
/// acked while the user was still reading the prompt.
async fn await_applied(applied: &tokio::sync::watch::Sender<u64>, target: u64) -> DetachFlush {
    let mut mark = applied.subscribe();
    let reached = tokio::time::timeout(DETACH_FLUSH, mark.wait_for(|applied| *applied >= target));
    match reached.await {
        Ok(Ok(_)) => DetachFlush::Applied,
        // The sender lives in the attach context this task holds, so a
        // closed channel is not reachable; a timeout is, and both mean the
        // same thing to the user.
        Ok(Err(_)) | Err(_) => DetachFlush::Unconfirmed,
    }
}

/// Sole owner of one leg's control stream: the asynchronous `SessionEvent`s
/// (`writer_changed`, `closed`) an attached peer is owed, the `Pong` a host
/// `Ping` is owed, and the liveness `Ping`s the watchdog asks for.
///
/// The `select!` races exactly one future that touches the session
/// ([`Session::next_control`], which only reads), so nothing that writes is
/// ever cancelled.
pub(super) async fn pump_attach_control(
    mut session: Session,
    session_id: String,
    session_ref: String,
    events: tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
    watch: PathWatch,
    probes: Arc<tokio::sync::Notify>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return,
            () = probes.notified() => {
                if session.send_ping().await.is_err() {
                    return;
                }
            }
            message = session.next_control() => {
                let message = match message {
                    Ok(Some(message)) => message,
                    Ok(None) | Err(_) => return,
                };
                match message {
                    // The answer to our own liveness probe. Proof the path
                    // carries packets, and nothing more — counting it as
                    // activity would let the watchdog hold itself inside
                    // the active window forever and the idle cadence would
                    // never be reached on a healthy path.
                    ControlIn::Pong => watch.inbound(),
                    ControlIn::Ping { request_id } => {
                        watch.traffic();
                        if session.send_pong(request_id).await.is_err() {
                            return;
                        }
                    }
                    // Unreachable in practice on a forward attach (the
                    // host never sends a request back to its client), but
                    // must still be answered rather than dropped — the
                    // same `UNSUPPORTED`/zero-resource contract
                    // `reverse/listen.rs` relies on for the reverse
                    // direction (`ControlIn::Request`'s docs).
                    ControlIn::Request { request_id } => {
                        watch.traffic();
                        if session.reject_unsupported(request_id).await.is_err() {
                            return;
                        }
                    }
                    // `Exited` also arrives as a data frame, which is the
                    // authoritative copy; emitting both would duplicate a
                    // terminal event in the JSONL stream.
                    ControlIn::Event(event) => {
                        watch.traffic();
                        // Defensive on a forward attach today (one
                        // connection per session, so the peer only ever
                        // has this session's events to send) and load-bearing
                        // the moment this pump runs over a shared
                        // `ControlLink::Local` control stream, where a
                        // `session.writer_changed` is broadcast to every
                        // conduit of the host regardless of which session
                        // it names (`crate::localctl::mux::ControlMux::route_event`).
                        // `docs/design/protocol.md` §11-3's own rule:
                        // "구독자 쪽 클라이언트도 낯선 session_id의 event는
                        // 방어적으로 무시한다" — without this, an event for
                        // a different session would be re-stamped with
                        // *this* session's `session_ref` and emitted as a
                        // fabricated `qsh.event/v1` line (adversarial
                        // review finding).
                        if event.session_id != session_id {
                            continue;
                        }
                        if let Some(json) = control_event_json(&session_ref, event) {
                            let _stalled = watch.stalled();
                            if events.send(Ok(json)).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One attach data frame as a `qsh.event/v1` event. `InputAck` is flow
/// control, not an event, and has no `qsh.event/v1` type.
pub(super) fn attach_event_json(
    session_ref: &str,
    event: crate::client::AttachEvent,
) -> Option<SessionEvent> {
    let schema = EVENT_SCHEMA.to_string();
    let session_ref = session_ref.to_string();
    Some(match event {
        crate::client::AttachEvent::Output { sequence, data } => SessionEvent::Output {
            schema,
            session_ref,
            sequence,
            data_b64: BASE64.encode(&data),
        },
        crate::client::AttachEvent::Gap {
            requested_after,
            available_from,
        } => SessionEvent::Gap {
            schema,
            session_ref,
            requested_after,
            available_from,
        },
        crate::client::AttachEvent::Exit {
            final_seq,
            exit_code,
            signal,
        } => SessionEvent::Exit {
            schema,
            session_ref,
            sequence: final_seq,
            // A signal-terminated child has no exit code (CLI.md §6.4).
            exit_code: if signal.is_some() {
                None
            } else {
                Some(exit_code)
            },
            signal,
        },
        crate::client::AttachEvent::InputAck { .. } => return None,
    })
}

/// One asynchronous control-stream `SessionEvent` as a `qsh.event/v1`
/// event; the exit is dropped because the data stream already carries it.
fn control_event_json(session_ref: &str, event: wire::SessionEvent) -> Option<SessionEvent> {
    let schema = EVENT_SCHEMA.to_string();
    let session_ref = session_ref.to_string();
    Some(match event.body? {
        wire::session_event::Body::WriterChanged(w) => SessionEvent::WriterChanged {
            schema,
            session_ref,
            sequence: w.seq,
            writer: w.new_writer,
        },
        wire::session_event::Body::Closed(c) => SessionEvent::Closed {
            schema,
            session_ref,
            sequence: c.seq,
            reason: c.reason,
        },
        wire::session_event::Body::Exited(_) => return None,
    })
}
