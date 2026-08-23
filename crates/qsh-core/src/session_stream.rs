//! Host side of the `SESSION_DATA` stream — one bidirectional QUIC stream
//! per attach (`docs/design/protocol.md` §7 "Session data" row, §9
//! `SessionFrame`, §12).
//!
//! The stream is opened by the attaching peer, identified by its
//! `StreamHeader{SESSION_DATA, ticket}`, and admitted by the dispatch edge
//! only after the ticket issued by an authorized `session.open` /
//! `session.attach` was redeemed — nothing here re-decides policy.
//!
//! Three concurrent parts, so neither direction can stall the other:
//!
//! - the **output pump**: a cursor pull loop on the broker's replay ring —
//!   the same [`SessionBackend::pull`] primitive `session read --wait` and
//!   `--follow` use — turning [`ReplayEvent`]s into `Output`/`Gap`/`Exit`
//!   frames. The ring is the decoupler (protocol.md §12): a slow consumer
//!   only falls behind its own cursor and is resynchronised with a `Gap`;
//!   it can never block the session's source reader.
//! - the **input loop**: `Input`/`Resize` frames from the peer. `Input`
//!   carries the cumulative input offset *after* its chunk, so the host
//!   discards (or trims) whatever it already applied and answers
//!   `InputAck{acked_input_seq}` — lossless and duplicate-free
//!   (protocol.md §10-5). Losing the writer lease demotes this attach to
//!   read-only rather than ending it: input is dropped on the floor while
//!   another peer drives, still acked so the peer's stream stays
//!   contiguous, and writing resumes by itself on a steal-back.
//! - the **frame writer**: sole owner of the send half, fed by both of the
//!   above through a bounded queue.
//!
//! Everything is torn down when the QUIC connection dies, so a wedged child
//! (a session write parked on a full PTY input buffer) can never keep the
//! stream — or its [`AttachToken`], which suspends the session's resume TTL
//! — alive past the connection.
//!
//! This module lives outside `broker/` on purpose: it is the only part of
//! the session path that names `qsh-transport` types, and `xtask arch`
//! bans those under `crates/qsh-core/src/broker/`.

use std::sync::Arc;
use std::time::Duration;

use qsh_proto::wire::{self, ControlMessage, SessionFrame, control_message, session_frame};
use qsh_transport::{Connection, FramedRecv, FramedSend, FramedStream, StreamError};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::broker::{
    AttachToken, BrokerError, ConnectionId, ControlEvent, Cursor, InputStreamId, ReplayEvent,
    SessionBackend, SessionId,
};

/// Payload budget of one output pull: four wire chunks. Enough to keep the
/// stream busy without building a reply the writer cannot drain.
pub const SESSION_STREAM_PULL_BYTES: usize = 4 * wire::SESSION_CHUNK_MAX;

/// How long one output pull parks waiting for new bytes before looping.
/// Only sets how often the pump re-enters the ring — the pull wakes
/// immediately on an append.
pub const SESSION_STREAM_PULL_WAIT: Duration = Duration::from_secs(30);

/// How long [`output_pump`] waits for `Closed` after `Exit`, once, before
/// giving up. An explicit `session.close`/SIGTERM drain on a still-running
/// session appends both as one actor operation (`begin_close`/
/// `mark_closed`) and they almost always land in the very next `pull()`
/// batch together — this covers the rare case they do not. A **child that
/// exits on its own** is different: no caller closed it, so `Closed` only
/// ever comes from the TTL reaper, which will not run at all while this
/// pump's attach token is held (`Broker::ttl_reap_reason`) — waiting
/// indefinitely there would hold the token, and the reaper, hostage
/// forever. `docs/CLI.md` §6.4 agrees for the sibling `--follow` consumer
/// of the same ring: it ends the moment it sees `session.exit` and does not
/// wait for the reaper's later `session.closed{reason:"exit"}` either.
const EXIT_CLOSED_GRACE: Duration = Duration::from_secs(2);

/// Depth of the queue between the two pumps and the single frame writer.
pub const SESSION_STREAM_QUEUE: usize = 64;

/// Why a `SESSION_DATA` stream ended.
#[derive(Debug, Error)]
pub enum SessionStreamError {
    /// Stream I/O failed (peer reset, connection lost, oversize frame).
    #[error(transparent)]
    Stream(#[from] StreamError),
    /// The peer sent a frame that violates the session-data grammar.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The broker refused an operation the stream depends on.
    #[error(transparent)]
    Backend(#[from] BrokerError),
    /// The connection went away while the stream was running.
    #[error("connection closed")]
    PeerGone,
}

impl SessionStreamError {
    /// Whether this is just the peer going away rather than a host fault —
    /// the dispatch edge logs those at debug, not warn.
    pub fn is_peer_gone(&self) -> bool {
        matches!(
            self,
            SessionStreamError::PeerGone
                | SessionStreamError::Stream(StreamError::Read(_) | StreamError::Write(_))
        )
    }
}

/// Everything one `SESSION_DATA` stream needs, assembled by the dispatch
/// edge (which has already authorized it).
pub struct SessionStream {
    /// The broker seam.
    pub sessions: Arc<dyn SessionBackend>,
    /// The session this stream is attached to.
    pub session_id: SessionId,
    /// Connection identity, for the writer-lease check on inbound `Input`.
    pub conn: ConnectionId,
    /// Where output replay starts (`SessionAttach.last_output_seq`; `0` for
    /// a stream redeemed straight off `session.open`).
    pub cursor: Cursor,
    /// The logical input stream this attach continues (protocol.md §10-5).
    /// A resumed attach carries the id it left, so the session's dedup
    /// cursor still applies to it; anything else carries a fresh id.
    pub input_stream: InputStreamId,
    /// Cumulative input offset the peer was told to resume its own counter
    /// from (`SessionAttached.input_seq`) — the first ack it can expect.
    pub input_from: u64,
    /// Funnel to the connection's control-stream writer for the
    /// asynchronous `SessionEvent`s an attached peer is owed
    /// (protocol.md §9). For an *attached* peer this is the only carrier
    /// of `writer_changed`/`closed` — neither has a `SessionFrame` — so a
    /// full queue parks the pump instead of dropping the event (PRD §8:
    /// never lose silently). The queue is drained by the connection loop,
    /// which never parks on a session.
    pub events: Option<mpsc::Sender<ControlMessage>>,
}

impl SessionStream {
    /// Drive the stream to completion. On return the send half has been
    /// finished (or dropped, on error).
    pub async fn run(
        self,
        stream: FramedStream,
        connection: &Connection,
    ) -> Result<(), SessionStreamError> {
        tokio::select! {
            result = self.run_inner(stream) => result,
            // A parked `sessions.write` (child not draining its PTY input)
            // must never outlive the connection: the attach token below
            // suspends the session's resume TTL, so a stuck pump would keep
            // an orphaned session alive for ever.
            _ = connection.closed() => Err(SessionStreamError::PeerGone),
        }
    }

    async fn run_inner(self, stream: FramedStream) -> Result<(), SessionStreamError> {
        let SessionStream {
            sessions,
            session_id,
            conn,
            cursor,
            input_stream,
            input_from,
            events,
        } = self;

        // While this token lives the session counts as attached and its
        // resume TTL is suspended (architecture.md §3). Taken only after
        // the ticket was redeemed, i.e. after authorization.
        let attached: Box<dyn AttachToken> = sessions.attach(&session_id)?;

        let (mut send, recv) = stream.split();
        // protocol.md §12 band: below the control stream (200), above bulk.
        send.set_priority(wire::PRIORITY_SESSION_DATA);

        let (frames_tx, frames_rx) = mpsc::channel::<SessionFrame>(SESSION_STREAM_QUEUE);
        let mut writer = AbortOnDrop(tokio::spawn(async move {
            let result = write_frames(&mut send, frames_rx).await;
            let _ = send.finish();
            result
        }));

        let mut output = AbortOnDrop(tokio::spawn(output_pump(
            Arc::clone(&sessions),
            session_id.clone(),
            cursor,
            frames_tx.clone(),
            events,
        )));

        // Set once `writer` ends on its own — the peer sent `STOP_SENDING`
        // (`write_frames`'s own `send.stopped()` race) or a write failed —
        // so the trailing cleanup below knows not to poll that already-
        // completed `JoinHandle` a second time (`AbortOnDrop`'s `.0` is a
        // plain `tokio::task::JoinHandle`, and polling one again past
        // completion is not something this code relies on being safe).
        let mut writer_done = false;
        let result = {
            let input = input_pump(
                sessions,
                session_id,
                conn,
                input_stream,
                input_from,
                recv,
                frames_tx,
            );
            tokio::pin!(input);
            tokio::select! {
                r = &mut input => match r {
                    // The peer finished its send half — but it is still
                    // owed its output, so the stream lives until the
                    // output pump is done. (Losing the writer lease does
                    // *not* land here: that only demotes the attach to
                    // read-only, it keeps reading input.) *Or* until the
                    // write side notices nobody is listening any more —
                    // see the `writer` arm below, which is exactly as
                    // valid a reason to stop here as `output` finishing:
                    // an idle session's `output_pump` can sit forever with
                    // nothing new to pull, and would otherwise never learn
                    // that the peer detached with no more output ever
                    // coming (the localctl `LOCAL_STREAM` splice's own
                    // cross-leg cancellation is exactly what triggers
                    // this on the reverse route).
                    Ok(()) => tokio::select! {
                        r = &mut output.0 => r.unwrap_or(Ok(())),
                        r = &mut writer.0 => {
                            writer_done = true;
                            r.unwrap_or(Ok(())).map_err(SessionStreamError::from)
                        }
                    },
                    Err(err) => Err(err),
                },
                // `Exit`/`Closed`: the last frame has been queued.
                r = &mut output.0 => r.unwrap_or(Ok(())),
                // See the comment on the nested arm above — the write
                // side can end first too, most commonly on the reverse
                // route where a detached peer's data conduit is gone
                // long before `input`/`output` would otherwise notice.
                r = &mut writer.0 => {
                    writer_done = true;
                    r.unwrap_or(Ok(())).map_err(SessionStreamError::from)
                }
            }
        };
        // Every sender is dropped by now, so the writer drains the queue,
        // FINs the stream and returns — unless it already ended on its
        // own above, in which case awaiting it again would poll an
        // already-completed `JoinHandle`.
        drop(output);
        if !writer_done {
            let _ = (&mut writer.0).await;
        }
        drop(attached);
        result
    }
}

/// A spawned task that is aborted if its owner is dropped — so the whole
/// stream disappears when [`SessionStream::run`] loses the race against
/// `Connection::closed()`.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The single owner of the send half.
///
/// Races draining `frames` against [`FramedSend::stopped`] — which
/// resolves only when the peer sends `STOP_SENDING` (or the stream/
/// connection is already gone), never merely on an ordinary ack of bytes
/// already written (`quinn`'s own `send_stream_stopped`: `Ok(None)` for an
/// already-closed stream, `Ok(Some(code))` for a real `STOP_SENDING`,
/// otherwise it keeps waiting). A peer that will never read another byte
/// here — most commonly a reverse-route localctl `LOCAL_STREAM` conduit
/// whose CLI end already detached (`localctl::daemon`'s cross-leg
/// cancellation resets the corresponding `RecvStream`, which the QUIC
/// layer turns into `STOP_SENDING` on this end) — is exactly as good a
/// reason to stop as the queue itself ending, and unlike a *forward*
/// attach's own connection loss, nothing else here would ever notice on
/// an idle session otherwise: `output_pump` can sit forever finding no
/// new bytes to pull, and would hold this stream's `AttachToken` (and the
/// TTL suspension it implies) open indefinitely on the peer's behalf.
async fn write_frames(
    send: &mut FramedSend,
    mut frames: mpsc::Receiver<SessionFrame>,
) -> Result<(), StreamError> {
    loop {
        tokio::select! {
            frame = frames.recv() => {
                match frame {
                    Some(frame) => send.send(&frame).await?,
                    None => return Ok(()),
                }
            }
            () = send.stopped() => return Ok(()),
        }
    }
}

/// Cursor pull loop: replay ring → `Output`/`Gap`/`Exit` frames.
async fn output_pump(
    sessions: Arc<dyn SessionBackend>,
    id: SessionId,
    mut cursor: Cursor,
    frames: mpsc::Sender<SessionFrame>,
    events: Option<mpsc::Sender<ControlMessage>>,
) -> Result<(), SessionStreamError> {
    // Set once `Exit` has been seen with no `Closed` in the same batch —
    // gives exactly one more, short-waited pull a chance to catch a
    // `Closed` that landed a moment later, then gives up regardless
    // ([`EXIT_CLOSED_GRACE`]'s docs: the ordinary self-exit case has no
    // `Closed` coming at all while this pump holds the attach token).
    let mut exit_grace_used = false;
    loop {
        let wait = if exit_grace_used {
            EXIT_CLOSED_GRACE
        } else {
            SESSION_STREAM_PULL_WAIT
        };
        let out = match sessions
            .pull(&id, cursor, SESSION_STREAM_PULL_BYTES, wait)
            .await
        {
            Ok(out) => out,
            // The session left the registry (past `CLOSED_RETENTION`):
            // nothing more to stream.
            Err(BrokerError::NotFound) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        cursor = out.next;
        let mut exited_this_batch = false;
        for event in out.events {
            match event {
                ReplayEvent::Output { sequence, data } => {
                    // The ring's chunks are already ≤ SESSION_CHUNK_MAX;
                    // re-splitting is defensive, never lossy, and keeps
                    // every `sequence` the exact cumulative end offset.
                    let mut offset = sequence - data.len() as u64;
                    for chunk in data.chunks(wire::SESSION_CHUNK_MAX) {
                        offset += chunk.len() as u64;
                        send_frame(&frames, SessionFrame::output(offset, chunk.to_vec())).await?;
                    }
                }
                ReplayEvent::Gap {
                    requested_after,
                    available_from,
                } => {
                    send_frame(&frames, SessionFrame::gap(requested_after, available_from)).await?;
                }
                ReplayEvent::Control {
                    sequence, event, ..
                } => {
                    notify(&events, &id, sequence, &event).await?;
                    match event {
                        ControlEvent::Exit { exit_code, signal } => {
                            // The wire `exit_code` is not optional: a
                            // signal-terminated child reports -1 plus its
                            // signal name (CLI.md §6.4).
                            send_frame(
                                &frames,
                                SessionFrame::exit(sequence, exit_code.unwrap_or(-1), signal),
                            )
                            .await?;
                            // Not terminal on its own: an explicit
                            // `session.close` (or the SIGTERM drain) on a
                            // still-*running* session appends `Exit` then
                            // `Closed` as one actor operation
                            // (`broker::session`'s `begin_close`/
                            // `mark_closed`) — almost always landing in this
                            // very `pull()` batch together. Returning here
                            // would silently drop the `Closed` `notify` a
                            // couple of loop iterations away, leaving an
                            // attached consumer never told the session is
                            // gone (an L5 real-process test, not this
                            // module's own unit tests, is what caught it —
                            // see `serve_sigterm_drain.rs`). `EXIT_CLOSED_GRACE`
                            // below covers that, bounded — a child that
                            // exited on its own with nobody having called
                            // `session.close` has no `Closed` coming while
                            // this pump holds the attach token, so waiting
                            // past the grace is a self-deadlock, not a fix.
                            exited_this_batch = true;
                        }
                        // Always the last ring entry; nothing follows it.
                        ControlEvent::Closed { .. } => return Ok(()),
                        // Not representable as a `SessionFrame`; it went out
                        // on the control stream in `notify` above.
                        ControlEvent::WriterChanged { .. } => {}
                    }
                }
            }
        }
        if exited_this_batch {
            exit_grace_used = true;
        } else if exit_grace_used {
            // The grace pull came back with no `Closed` (and no fresh
            // `Exit`, which cannot recur): nobody is going to close this
            // session while we keep waiting. Give up rather than hold the
            // attach token — and the TTL reaper it blocks — forever.
            return Ok(());
        }
    }
}

/// `Input`/`Resize` from the peer, with the input dedup + ack of
/// protocol.md §10-5.
#[allow(clippy::too_many_arguments)]
async fn input_pump(
    sessions: Arc<dyn SessionBackend>,
    id: SessionId,
    conn: ConnectionId,
    stream: InputStreamId,
    input_from: u64,
    mut recv: FramedRecv,
    frames: mpsc::Sender<SessionFrame>,
) -> Result<(), SessionStreamError> {
    // The dedup cursor lives in the **session** (protocol.md §10-5), not
    // here: `SessionBackend::write_at` trims whatever the child already ran
    // under the actor's own serialisation. A reattach that retransmits its
    // un-acked tail therefore cannot make the child see a byte twice, and a
    // stealing peer — told where the axis stands in
    // `SessionAttached.input_seq` — cannot have its input mistaken for a
    // replay. This local value is only the last ack we sent.
    let mut applied: u64 = input_from;
    loop {
        let Some(frame) = recv.recv::<SessionFrame>().await? else {
            return Ok(()); // peer finished its half cleanly
        };
        // A peer not running our encoder is bounded only by the frame cap.
        frame
            .validate()
            .map_err(|e| SessionStreamError::Protocol(e.to_string()))?;
        match frame.body {
            Some(session_frame::Body::Input(input)) => {
                let len = input.data.len() as u64;
                let Some(start) = input.input_seq.checked_sub(len) else {
                    return Err(SessionStreamError::Protocol(format!(
                        "Input.input_seq {} is smaller than its own chunk",
                        input.input_seq
                    )));
                };
                if start > applied {
                    // The peer skipped input bytes we never saw. Accepting
                    // would lose them silently, which PRD §8 forbids. (The
                    // session re-checks this against its own cursor; this
                    // catches it one round trip earlier.)
                    return Err(SessionStreamError::Protocol(format!(
                        "Input starts at {start} but only {applied} bytes were applied"
                    )));
                }
                match sessions
                    .write_at(&id, conn, stream, input.data.clone(), input.input_seq)
                    .await
                {
                    Ok(now) => applied = now,
                    Err(BrokerError::InvalidArgument(why)) => {
                        return Err(SessionStreamError::Protocol(why));
                    }
                    // The lease was stolen (this attach is read-only
                    // now — protocol.md §10 "read-only로 강등된다") or
                    // the child is gone. Neither ends the attach: the
                    // peer is still owed its output and its `Exit`, and
                    // a steal-back must resume writing without a
                    // reattach. Discard the bytes but keep the offset
                    // moving, so the peer's stream stays contiguous and
                    // its ack is never left dangling, and try again on
                    // the next frame.
                    Err(
                        BrokerError::NotRunning | BrokerError::NotWriter | BrokerError::NotFound,
                    ) => applied = applied.max(input.input_seq),
                    Err(err) => return Err(err.into()),
                }
                // Re-ack a duplicate too: the peer is waiting for it.
                send_frame(&frames, SessionFrame::input_ack(applied)).await?;
            }
            Some(session_frame::Body::Resize(resize)) => {
                let (Ok(cols), Ok(rows)) = (u16::try_from(resize.cols), u16::try_from(resize.rows))
                else {
                    return Err(SessionStreamError::Protocol(
                        "Resize cols/rows must fit in 16 bits".into(),
                    ));
                };
                // `resize_at`, not `resize`: this attach may have been
                // demoted to read-only by a steal-back on another
                // connection (protocol.md §10), same as `Input` above —
                // a stale attach must not keep SIGWINCH-ing the live PTY
                // out from under the connection that actually holds it.
                match sessions.resize_at(&id, conn, cols, rows).await {
                    Ok(())
                    | Err(
                        BrokerError::NotRunning | BrokerError::NotFound | BrokerError::NotWriter,
                    ) => {}
                    Err(err) => return Err(err.into()),
                }
            }
            // Host → client frames coming back from a client are a slip,
            // not an attack surface; ignore them like a stray Pong.
            Some(_) | None => {}
        }
    }
}

/// Queue one frame for the writer. A closed queue means the writer is gone.
async fn send_frame(
    frames: &mpsc::Sender<SessionFrame>,
    frame: SessionFrame,
) -> Result<(), SessionStreamError> {
    frames
        .send(frame)
        .await
        .map_err(|_| SessionStreamError::PeerGone)
}

/// Mirror a ring control entry onto the control stream as an asynchronous
/// `SessionEvent` (protocol.md §9). `writer_changed` and `closed` have no
/// `SessionFrame` form, so for an attached peer this is their only door —
/// it waits for room rather than dropping them.
async fn notify(
    events: &Option<mpsc::Sender<ControlMessage>>,
    id: &SessionId,
    sequence: u64,
    event: &ControlEvent,
) -> Result<(), SessionStreamError> {
    let Some(tx) = events else { return Ok(()) };
    let body = match event {
        ControlEvent::Exit { exit_code, signal } => wire::SessionEvent::exited(
            id.as_str(),
            wire::Exit {
                final_seq: sequence,
                exit_code: exit_code.unwrap_or(-1),
                signal: signal.clone(),
            },
        ),
        ControlEvent::WriterChanged { writer } => {
            wire::SessionEvent::writer_changed(id.as_str(), writer.clone(), sequence)
        }
        ControlEvent::Closed { reason } => {
            wire::SessionEvent::closed(id.as_str(), reason.as_str(), sequence)
        }
    };
    tx.send(ControlMessage::new(
        0,
        control_message::Body::SessionEvent(body),
    ))
    .await
    .map_err(|_| SessionStreamError::PeerGone)
}
