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
//!   (protocol.md §10-5).
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
    AttachToken, BrokerError, ConnectionId, ControlEvent, Cursor, ReplayEvent, SessionBackend,
    SessionId,
};

/// Payload budget of one output pull: four wire chunks. Enough to keep the
/// stream busy without building a reply the writer cannot drain.
pub const SESSION_STREAM_PULL_BYTES: usize = 4 * wire::SESSION_CHUNK_MAX;

/// How long one output pull parks waiting for new bytes before looping.
/// Only sets how often the pump re-enters the ring — the pull wakes
/// immediately on an append.
pub const SESSION_STREAM_PULL_WAIT: Duration = Duration::from_secs(30);

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
    /// Funnel to the connection's control-stream writer for the
    /// asynchronous `SessionEvent`s an attached peer is owed
    /// (protocol.md §9). Advisory: a full queue drops the notification
    /// rather than stalling the pump — the pull path carries the same
    /// events authoritatively.
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

        let result = {
            let input = input_pump(sessions, session_id, conn, recv, frames_tx);
            tokio::pin!(input);
            tokio::select! {
                r = &mut input => match r {
                    // The peer's send half is done (clean FIN, or this
                    // attach was demoted to read-only when its lease was
                    // stolen) — but it is still owed its output, so the
                    // stream lives until the output pump is finished.
                    Ok(()) => (&mut output.0).await.unwrap_or(Ok(())),
                    Err(err) => Err(err),
                },
                // `Exit`/`Closed`: the last frame has been queued.
                r = &mut output.0 => r.unwrap_or(Ok(())),
            }
        };
        // Every sender is dropped by now, so the writer drains the queue,
        // FINs the stream and returns.
        drop(output);
        let _ = (&mut writer.0).await;
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
async fn write_frames(
    send: &mut FramedSend,
    mut frames: mpsc::Receiver<SessionFrame>,
) -> Result<(), StreamError> {
    while let Some(frame) = frames.recv().await {
        send.send(&frame).await?;
    }
    Ok(())
}

/// Cursor pull loop: replay ring → `Output`/`Gap`/`Exit` frames.
async fn output_pump(
    sessions: Arc<dyn SessionBackend>,
    id: SessionId,
    mut cursor: Cursor,
    frames: mpsc::Sender<SessionFrame>,
    events: Option<mpsc::Sender<ControlMessage>>,
) -> Result<(), SessionStreamError> {
    loop {
        let out = match sessions
            .pull(
                &id,
                cursor,
                SESSION_STREAM_PULL_BYTES,
                SESSION_STREAM_PULL_WAIT,
            )
            .await
        {
            Ok(out) => out,
            // The session left the registry (past `CLOSED_RETENTION`):
            // nothing more to stream.
            Err(BrokerError::NotFound) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        cursor = out.next;
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
                    notify(&events, &id, sequence, &event);
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
                            return Ok(());
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
    }
}

/// `Input`/`Resize` from the peer, with the input dedup + ack of
/// protocol.md §10-5.
async fn input_pump(
    sessions: Arc<dyn SessionBackend>,
    id: SessionId,
    conn: ConnectionId,
    mut recv: FramedRecv,
    frames: mpsc::Sender<SessionFrame>,
) -> Result<(), SessionStreamError> {
    // Highest cumulative input offset applied on this stream. Per-attach in
    // M2 Step 5: one attach is one input stream starting at 0. PLAN Step 7
    // lifts it into the session, keyed by the resume token, so it survives
    // a reattach (protocol.md §10-5).
    let mut applied: u64 = 0;
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
                    // would lose them silently, which PRD §8 forbids.
                    return Err(SessionStreamError::Protocol(format!(
                        "Input starts at {start} but only {applied} bytes were applied"
                    )));
                }
                if input.input_seq > applied {
                    // Trim the already-applied prefix, then write the rest.
                    let skip = (applied - start) as usize;
                    match sessions.write(&id, conn, input.data[skip..].to_vec()).await {
                        Ok(()) => applied = input.input_seq,
                        // Child gone, or the lease was stolen: this attach
                        // is read-only from here on. The output pump still
                        // owes the peer its `Exit`, so stop reading input
                        // instead of tearing the stream down.
                        Err(BrokerError::NotRunning | BrokerError::NotWriter) => return Ok(()),
                        Err(err) => return Err(err.into()),
                    }
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
                match sessions.resize(&id, cols, rows).await {
                    Ok(()) | Err(BrokerError::NotRunning | BrokerError::NotFound) => {}
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
/// `SessionEvent` (protocol.md §9). Advisory — never blocks the pump.
fn notify(
    events: &Option<mpsc::Sender<ControlMessage>>,
    id: &SessionId,
    sequence: u64,
    event: &ControlEvent,
) {
    let Some(tx) = events else { return };
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
    let _ = tx.try_send(ControlMessage::new(
        0,
        control_message::Body::SessionEvent(body),
    ));
}
