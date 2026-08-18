//! L3 loopback end-to-end for the `SESSION_DATA` attach stream (PLAN M2
//! Step 5): `StreamHeader{SESSION_DATA, ticket}` → framed `SessionFrame`s
//! over a real QUIC connection against a pipe-backed session
//! (`docs/design/testing.md` §3). Zero PTY code.
//!
//! Every wait here is a real round trip under a wall-clock deadline — no
//! sleep-based synchronisation.

use std::time::Duration;

use qsh_core::broker::{PipeHandle, SessionSpec};
use qsh_core::client::{AttachEvent, Session};
use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, StreamHeader, session_frame};
use qsh_testkit::loopback::LoopbackHarness;
use qsh_transport::FramedStream;

/// Wall-clock ceiling for anything that should resolve in milliseconds.
/// A miss is a hang, which is a failure, not flake.
const DEADLINE: Duration = Duration::from_secs(20);

/// The harness' replay ring and pipe buffers (`LoopbackHarness`).
const RING_BYTES: usize = 64 * 1024;

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// Open a session and redeem its `SESSION_DATA` ticket on a fresh bidi
/// stream. Returns the session id, the "child" side of the pipe, and the
/// live attach stream.
async fn open_and_attach(
    h: &LoopbackHarness,
    s: &mut Session,
) -> (String, PipeHandle, FramedStream) {
    let opened = s.session_open(open_req()).await.expect("session.open");
    let pipe = h.pipes.take().expect("pipe handle");
    let (send, recv) = s.connection().open_bi().await.expect("open_bi");
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&StreamHeader::session_data(opened.ticket))
        .await
        .expect("stream header");
    (opened.session_id, pipe, data)
}

/// Read frames until `want` output bytes have arrived, returning the bytes
/// and every `Output.sequence` in arrival order.
async fn read_output(data: &mut FramedStream, want: usize) -> (Vec<u8>, Vec<u64>) {
    let mut bytes = Vec::new();
    let mut sequences = Vec::new();
    tokio::time::timeout(DEADLINE, async {
        while bytes.len() < want {
            let frame = data
                .recv
                .recv::<wire::SessionFrame>()
                .await
                .expect("frame")
                .expect("stream ended early");
            if let Some(session_frame::Body::Output(o)) = frame.body {
                bytes.extend_from_slice(&o.data);
                sequences.push(o.sequence);
            }
        }
    })
    .await
    .expect("output arrives within the deadline");
    (bytes, sequences)
}

/// Output arrives in order, split at the wire chunk cap, with `sequence`
/// the exact cumulative end offset of each chunk.
#[tokio::test(flavor = "multi_thread")]
async fn attach_stream_delivers_output_in_order_with_monotonic_sequences() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let (_id, mut pipe, mut data) = open_and_attach(&h, &mut s).await;

    // More than one wire chunk, so the host has to split — and a
    // recognisable pattern, so a reorder or a duplicate is visible.
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    pipe.write_output(&payload).await.unwrap();

    let (bytes, sequences) = read_output(&mut data, payload.len()).await;
    assert_eq!(
        bytes, payload,
        "bytes arrive in order, none lost or doubled"
    );
    assert!(
        sequences.windows(2).all(|w| w[0] < w[1]),
        "sequences must be strictly increasing: {sequences:?}"
    );
    assert_eq!(
        sequences.last().copied(),
        Some(payload.len() as u64),
        "the last sequence is the cumulative total"
    );
    assert!(
        sequences
            .windows(2)
            .all(|w| w[1] - w[0] <= wire::SESSION_CHUNK_MAX as u64),
        "no chunk exceeds SESSION_CHUNK_MAX: {sequences:?}"
    );

    s.close();
    h.shutdown().await;
}

/// `Input.input_seq` is a cumulative offset, so replaying a frame the host
/// already applied is discarded and re-acked — lossless and duplicate-free
/// (protocol.md §10-5).
#[tokio::test(flavor = "multi_thread")]
async fn replayed_input_is_discarded_and_re_acked_exactly_once() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let (_id, mut pipe, mut data) = open_and_attach(&h, &mut s).await;

    let first = wire::SessionFrame::input(5, b"hello".to_vec());
    data.send.send(&first).await.unwrap();
    assert_eq!(next_ack(&mut data).await, 5);
    assert_eq!(pipe.read_input(64).await.unwrap(), b"hello");

    // The exact same frame again: applied once, acked again.
    data.send.send(&first).await.unwrap();
    assert_eq!(
        next_ack(&mut data).await,
        5,
        "ack is repeated, not advanced"
    );

    // A partially-overlapping retransmit: only the new tail is applied.
    data.send
        .send(&wire::SessionFrame::input(8, b"loBYE".to_vec()))
        .await
        .unwrap();
    assert_eq!(next_ack(&mut data).await, 8);

    // If the duplicate had been applied, the child would see "hello"
    // again (or "loBYE" whole) ahead of this.
    assert_eq!(
        tokio::time::timeout(DEADLINE, pipe.read_input(64))
            .await
            .expect("input arrives within the deadline")
            .unwrap(),
        b"BYE",
        "only the bytes past the applied offset reach the child"
    );

    s.close();
    h.shutdown().await;
}

/// Read frames until the next `InputAck`, returning its offset.
async fn next_ack(data: &mut FramedStream) -> u64 {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let frame = data
                .recv
                .recv::<wire::SessionFrame>()
                .await
                .expect("frame")
                .expect("stream ended early");
            if let Some(session_frame::Body::InputAck(a)) = frame.body {
                return a.acked_input_seq;
            }
        }
    })
    .await
    .expect("an ack arrives within the deadline")
}

/// A consumer whose cursor fell out of the ring is resynchronised with a
/// `Gap` and then keeps receiving output. Separately: the source reader is
/// never blocked by the absence of a consumer — every byte the child wrote
/// was ingested (the ring, not the consumer, is the decoupler,
/// protocol.md §12).
#[tokio::test(flavor = "multi_thread")]
async fn stale_consumer_gets_a_gap_and_the_source_reader_is_never_blocked() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let opened = s.session_open(open_req()).await.unwrap();
    let id = opened.session_id.clone();
    let mut pipe = h.pipes.take().unwrap();

    // Nobody is attached and nobody is reading: push three ring-fulls
    // through the child. Each `write_output` completing at all is the
    // assertion that a slow/absent consumer cannot block the source.
    let total = 3 * RING_BYTES;
    let block = vec![b'x'; 4096];
    let mut written = 0usize;
    while written < total {
        tokio::time::timeout(DEADLINE, pipe.write_output(&block))
            .await
            .expect("the source reader is never blocked by a missing consumer")
            .unwrap();
        written += block.len();
    }
    // Every byte reached the ring even though nothing consumed them.
    let ingested = tokio::time::timeout(DEADLINE, async {
        loop {
            let info = s.session_get(&id).await.unwrap();
            if info.last_sequence >= written as u64 {
                return info.last_sequence;
            }
        }
    })
    .await
    .expect("the ring ingests everything the child wrote");
    assert_eq!(ingested, written as u64);

    // Attach from offset 0 — long since evicted. The stream opens with a
    // Gap and then continues from what the ring still holds.
    let mut attached = s
        .attach(wire::SessionAttach {
            session_id: id.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            ..Default::default()
        })
        .await
        .expect("session.attach");
    let available_from = match tokio::time::timeout(DEADLINE, attached.next())
        .await
        .expect("the gap arrives within the deadline")
        .unwrap()
        .unwrap()
    {
        AttachEvent::Gap {
            requested_after,
            available_from,
        } => {
            assert_eq!(requested_after, 0);
            assert!(
                available_from > 0 && available_from < ingested,
                "gap resumes inside the retained window: {available_from} of {ingested}"
            );
            available_from
        }
        other => panic!("expected a Gap first, got {other:?}"),
    };

    // …and the consumer continues from there rather than being stuck.
    let mut next = available_from;
    tokio::time::timeout(DEADLINE, async {
        while next < ingested {
            match attached.next().await.unwrap().unwrap() {
                AttachEvent::Output { sequence, data } => {
                    assert_eq!(
                        sequence - data.len() as u64,
                        next,
                        "output resumes exactly at the gap's available_from, with no hole"
                    );
                    next = sequence;
                }
                AttachEvent::Gap { .. } => panic!("only one gap is owed"),
                other => panic!("unexpected {other:?}"),
            }
        }
    })
    .await
    .expect("the consumer keeps receiving output after the gap");
    assert_eq!(next, ingested);

    attached.finish();
    s.close();
    h.shutdown().await;
}

/// The live-defect regression (PLAN M2 Step 5): a child that stops draining
/// its PTY/pipe input parks the session's writer task for ever. That must
/// never park the *connection*: other control traffic keeps flowing, and
/// when the connection dies the writer lease is still released.
#[tokio::test(flavor = "multi_thread")]
async fn a_wedged_child_cannot_stall_other_control_traffic_on_the_connection() {
    let h = LoopbackHarness::start().await;
    let dialed = h.dial().await;
    let mut ctl = hello(&dialed).await;

    // Open through the raw control stream so we can pipeline: the point of
    // the test is a request issued while an earlier one is still parked.
    ctl.send
        .send(&wire::ControlMessage::new(
            1,
            wire::control_message::Body::SessionOpen(open_req()),
        ))
        .await
        .unwrap();
    let id = match reply_to(&mut ctl, 1).await {
        wire::response::Body::SessionOpened(o) => o.session_id,
        other => panic!("expected SessionOpened, got {other:?}"),
    };
    // Nobody ever reads this: the child is wedged from here on.
    let _pipe = h.pipes.take().unwrap();

    // Far more input than the child's buffer holds, so the session's writer
    // task is parked with a backlog behind it — and none of these replies
    // is read.
    let chunk = vec![b'k'; wire::SESSION_CHUNK_MAX];
    for request_id in 10..40 {
        ctl.send
            .send(&wire::ControlMessage::new(
                request_id,
                wire::control_message::Body::SessionWrite(wire::SessionWrite {
                    session_id: id.clone(),
                    data: chunk.clone(),
                }),
            ))
            .await
            .unwrap();
    }

    // The connection must still answer. Before the fix this timed out: the
    // connection loop was parked inside the first write that the child
    // would not drain.
    ctl.send
        .send(&wire::ControlMessage::new(
            100,
            wire::control_message::Body::Ping(wire::Ping {}),
        ))
        .await
        .unwrap();
    ctl.send
        .send(&wire::ControlMessage::new(
            101,
            wire::control_message::Body::SessionGet(wire::SessionGet {
                session_id: id.clone(),
            }),
        ))
        .await
        .unwrap();
    match reply_to(&mut ctl, 101).await {
        wire::response::Body::SessionInfo(info) => {
            assert_eq!(info.session_id, id);
            assert_eq!(info.state, "running");
        }
        wire::response::Body::Error(e) => {
            // A saturated per-connection backlog is a *retryable* refusal,
            // never a stall — but it must not be the answer to the read.
            panic!("session.get was refused: {:?}", e.error_code());
        }
        other => panic!("expected SessionInfo, got {other:?}"),
    }

    // The connection dies with the writer still parked; the lease must
    // still come back (architecture.md §3 rule c: the session survives, the
    // lease does not).
    dialed.connection.close(0, b"bye");
    drop(dialed);
    drop(ctl);

    let mut s = h.session().await;
    let info = tokio::time::timeout(DEADLINE, async {
        loop {
            let info = s.session_get(&id).await.unwrap();
            if info.writer.is_none() {
                return info;
            }
        }
    })
    .await
    .expect("the writer lease is released when the connection dies");
    assert_eq!(info.state, "running", "the session itself survives");
    assert_eq!(h.broker.session_count(), 1);
    s.close();
    h.shutdown().await;
}

/// A saturated write backlog is refused with a retryable
/// `RESOURCE_EXHAUSTED`, not by parking the connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_saturated_write_backlog_is_refused_retryably() {
    let h = LoopbackHarness::start().await;
    let dialed = h.dial().await;
    let mut ctl = hello(&dialed).await;
    ctl.send
        .send(&wire::ControlMessage::new(
            1,
            wire::control_message::Body::SessionOpen(open_req()),
        ))
        .await
        .unwrap();
    let id = match reply_to(&mut ctl, 1).await {
        wire::response::Body::SessionOpened(o) => o.session_id,
        other => panic!("expected SessionOpened, got {other:?}"),
    };
    let _pipe = h.pipes.take().unwrap();

    // Enough writes to overrun both the child's buffer and every queue
    // between here and it. Whatever the host cannot take must come back as
    // an error, and that error must be retryable.
    let chunk = vec![b'k'; wire::SESSION_CHUNK_MAX];
    for request_id in 10..400 {
        ctl.send
            .send(&wire::ControlMessage::new(
                request_id,
                wire::control_message::Body::SessionWrite(wire::SessionWrite {
                    session_id: id.clone(),
                    data: chunk.clone(),
                }),
            ))
            .await
            .unwrap();
    }
    let refusal = tokio::time::timeout(DEADLINE, async {
        loop {
            let msg = ctl
                .recv
                .recv::<wire::ControlMessage>()
                .await
                .unwrap()
                .unwrap();
            if let Some(wire::control_message::Body::Response(wire::Response {
                body: Some(wire::response::Body::Error(e)),
            })) = msg.body
            {
                return e;
            }
        }
    })
    .await
    .expect("the host refuses rather than parking");
    assert_eq!(refusal.error_code(), ErrorCode::ResourceExhausted);
    assert!(refusal.retryable, "a full backlog is a retryable condition");

    dialed.connection.close(0, b"bye");
    h.shutdown().await;
}

/// `session.attach` on a session another connection can also reach: the
/// stream carries the same output the cursor-pull path would, and the
/// child's exit closes it with an `Exit` frame.
#[tokio::test(flavor = "multi_thread")]
async fn attach_stream_ends_with_exit_when_the_child_exits() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let id = h
        .broker
        .open(&SessionSpec {
            argv: vec!["sh".into()],
            env: vec![],
            term: None,
            cols: 80,
            rows: 24,
            user: None,
        })
        .unwrap()
        .id()
        .to_string();
    let mut pipe = h.pipes.take().unwrap();

    let mut attached = s
        .attach(wire::SessionAttach {
            session_id: id.clone(),
            mode: wire::AttachMode::Rw as i32,
            ..Default::default()
        })
        .await
        .expect("session.attach");
    assert!(attached.writer_lease, "an RW attach holds the lease");
    assert!(
        attached.new_resume_token.is_empty(),
        "no resume token before Step 7"
    );

    pipe.write_output(b"done\r\n").await.unwrap();
    pipe.exit(qsh_core::broker::SourceExit {
        exit_code: Some(3),
        signal: None,
    });

    let mut output = Vec::new();
    let exit = tokio::time::timeout(DEADLINE, async {
        loop {
            match attached.next().await.unwrap() {
                Some(AttachEvent::Output { data, .. }) => output.extend_from_slice(&data),
                Some(AttachEvent::Exit {
                    final_seq,
                    exit_code,
                    signal,
                }) => return (final_seq, exit_code, signal),
                Some(other) => panic!("unexpected {other:?}"),
                None => panic!("stream ended without an Exit frame"),
            }
        }
    })
    .await
    .expect("the exit arrives within the deadline");
    assert_eq!(output, b"done\r\n");
    assert_eq!(exit, (6, 3, None), "Exit carries the final offset and code");

    attached.finish();
    s.close();
    h.shutdown().await;
}

/// Raw `Hello` handshake on a fresh connection, for the tests that need to
/// pipeline control messages the typed client serialises.
async fn hello(dialed: &qsh_transport::Dialed) -> FramedStream {
    let (send, recv) = dialed.connection.open_bi().await.unwrap();
    let mut ctl = FramedStream::control(send, recv);
    ctl.send
        .send(&wire::ControlMessage::new(
            0,
            wire::control_message::Body::Hello(wire::Hello {
                versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
                device_name: "laptop".into(),
                capabilities: wire::LOCAL_CAPABILITIES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            }),
        ))
        .await
        .unwrap();
    let reply = ctl
        .recv
        .recv::<wire::ControlMessage>()
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        reply.body,
        Some(wire::control_message::Body::Hello(_))
    ));
    ctl
}

/// Read control messages until the one correlated to `request_id`.
async fn reply_to(ctl: &mut FramedStream, request_id: u64) -> wire::response::Body {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let msg = ctl
                .recv
                .recv::<wire::ControlMessage>()
                .await
                .expect("control stream")
                .expect("control stream ended");
            if msg.request_id != request_id {
                continue;
            }
            match msg.body {
                Some(wire::control_message::Body::Response(wire::Response { body: Some(b) })) => {
                    return b;
                }
                Some(wire::control_message::Body::Pong(_)) => continue,
                other => panic!("expected a response, got {other:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no reply to request {request_id} within the deadline"))
}
