//! Prost-generated wire messages for QSH major version 1 (ALPN [`ALPN`]),
//! plus the small amount of glue that binds them to the frame layer
//! ([`crate::frame`]) and to the shared error vocabulary
//! ([`crate::ErrorCode`]).
//!
//! The grammar lives in `proto/qsh/wire/v1.proto` (compiled by `build.rs`
//! with `protox` + `prost-build`; no `protoc` needed). See
//! `docs/design/protocol.md` §5–§9.
//!
//! Everything here is sans-IO: `&[u8] → Result<Message>` and back. Stream
//! plumbing (quinn) lives in `qsh-transport`.

use prost::Message;
use thiserror::Error;

use crate::ErrorCode;
use crate::frame::{CONTROL_FRAME_MAX, DATA_FRAME_MAX, FrameError, encode_frame};

#[allow(
    missing_docs,
    clippy::doc_markdown,
    clippy::derive_partial_eq_without_eq,
    clippy::large_enum_variant
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/qsh.wire.v1.rs"));
}

pub use generated::*;

/// TLS ALPN protocol identifier for wire major version 1
/// (`docs/design/protocol.md` §4). A breaking wire revision becomes `qsh/2`;
/// everything additive is negotiated via [`Hello`] capabilities.
pub const ALPN: &[u8] = b"qsh/1";

/// Minor versions this build speaks within major 1. Peers adopt the
/// intersection of their `Hello.versions`; empty intersection is fatal.
pub const WIRE_MINOR_VERSIONS: &[u32] = &[0];

/// Capability string advertised by peers that implement `exec.run`.
pub const CAP_EXEC: &str = "exec";

/// Capability string advertised by peers that implement the `session.*`
/// control ops and the `SESSION_DATA` stream.
pub const CAP_SESSION: &str = "session";

/// Capability string advertised by peers that implement session resume
/// (`SessionAttach` with `resume_token`/`last_output_seq`, `protocol.md`
/// §10).
pub const CAP_RESUME_V1: &str = "resume.v1";

/// Capabilities this build advertises in [`Hello`].
pub const LOCAL_CAPABILITIES: &[&str] = &[CAP_EXEC, CAP_SESSION, CAP_RESUME_V1];

/// Maximum size of a single exec payload chunk (the `data` field of a
/// [`Stdout`]/[`Stderr`]/[`Stdin`] frame), 16 KiB (`protocol.md` §5).
pub const EXEC_CHUNK_MAX: usize = 16 * 1024;

/// Maximum size of a single session payload chunk — the `data` field of an
/// [`Output`]/[`Input`] frame and of a [`SessionWrite`] request — 16 KiB
/// (`protocol.md` §5, §9). Enforced at encode time by
/// [`encode_session_frame`] / [`encode_control`], not merely by the 64 KiB
/// data-frame cap.
pub const SESSION_CHUNK_MAX: usize = 16 * 1024;

/// Errors from encoding a message into a frame.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireEncodeError {
    /// The encoded message exceeds the frame cap for its stream class.
    #[error("encoded message ({len} bytes) exceeds frame max {max}")]
    TooLarge {
        /// Encoded message length.
        len: usize,
        /// The applicable frame cap.
        max: usize,
    },
    /// A payload chunk inside the message exceeds its per-chunk cap
    /// ([`SESSION_CHUNK_MAX`]), even though the whole frame would fit.
    #[error("payload chunk ({len} bytes) exceeds chunk max {max}")]
    ChunkTooLarge {
        /// Chunk length.
        len: usize,
        /// The applicable chunk cap.
        max: usize,
    },
    /// Frame-layer failure (unreachable in practice: `TooLarge` triggers
    /// first, but kept so callers see one error type).
    #[error(transparent)]
    Frame(#[from] FrameError),
}

fn check_chunk(len: usize) -> Result<(), WireEncodeError> {
    if len > SESSION_CHUNK_MAX {
        return Err(WireEncodeError::ChunkTooLarge {
            len,
            max: SESSION_CHUNK_MAX,
        });
    }
    Ok(())
}

/// Encode `msg` and wrap it in a length-prefixed frame, enforcing `max`
/// (use [`CONTROL_FRAME_MAX`] / [`DATA_FRAME_MAX`]).
pub fn encode_framed<M: Message>(msg: &M, max: usize) -> Result<Vec<u8>, WireEncodeError> {
    let len = msg.encoded_len();
    if len > max {
        return Err(WireEncodeError::TooLarge { len, max });
    }
    let mut body = Vec::with_capacity(len);
    msg.encode(&mut body)
        .expect("Vec<u8> has unbounded capacity; prost encode cannot fail");
    Ok(encode_frame(&body)?)
}

/// Decode one frame payload (already de-framed by [`crate::frame::FrameDecoder`])
/// into a message. Never panics on malformed input.
pub fn decode_msg<M: Message + Default>(payload: &[u8]) -> Result<M, prost::DecodeError> {
    M::decode(payload)
}

/// Encode a [`ControlMessage`] as one control-stream frame. A
/// [`SessionWrite`] whose `data` exceeds [`SESSION_CHUNK_MAX`] is refused
/// with [`WireEncodeError::ChunkTooLarge`].
pub fn encode_control(msg: &ControlMessage) -> Result<Vec<u8>, WireEncodeError> {
    if let Some(control_message::Body::SessionWrite(w)) = &msg.body {
        check_chunk(w.data.len())?;
    }
    encode_framed(msg, CONTROL_FRAME_MAX)
}

/// Encode an [`ExecFrame`] as one data-stream frame.
pub fn encode_exec_frame(msg: &ExecFrame) -> Result<Vec<u8>, WireEncodeError> {
    encode_framed(msg, DATA_FRAME_MAX)
}

/// Encode a [`SessionFrame`] as one data-stream frame. An [`Output`] or
/// [`Input`] chunk larger than [`SESSION_CHUNK_MAX`] is refused with
/// [`WireEncodeError::ChunkTooLarge`] before framing.
pub fn encode_session_frame(msg: &SessionFrame) -> Result<Vec<u8>, WireEncodeError> {
    match &msg.body {
        Some(session_frame::Body::Output(o)) => check_chunk(o.data.len())?,
        Some(session_frame::Body::Input(i)) => check_chunk(i.data.len())?,
        _ => {}
    }
    encode_framed(msg, DATA_FRAME_MAX)
}

/// Encode a [`StreamHeader`] as one data-stream frame.
pub fn encode_stream_header(msg: &StreamHeader) -> Result<Vec<u8>, WireEncodeError> {
    encode_framed(msg, DATA_FRAME_MAX)
}

impl ControlMessage {
    /// Build a request/response/event with the given correlation id and body.
    pub fn new(request_id: u64, body: control_message::Body) -> Self {
        Self {
            request_id,
            body: Some(body),
        }
    }

    /// A [`Response`] carrying a typed success payload, correlated to
    /// `request_id`.
    pub fn response(request_id: u64, body: response::Body) -> Self {
        Self::new(
            request_id,
            control_message::Body::Response(Response { body: Some(body) }),
        )
    }

    /// A [`Response`] carrying an [`Error`], correlated to `request_id`.
    pub fn error(request_id: u64, err: Error) -> Self {
        Self::response(request_id, response::Body::Error(err))
    }
}

impl Error {
    /// Build a wire error from the shared vocabulary.
    pub fn new(code: ErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code: code.as_str().to_string(),
            message: message.into(),
            retryable,
        }
    }

    /// Build a wire error with the code's default retryability.
    pub fn from_code(code: ErrorCode, message: impl Into<String>) -> Self {
        let retryable = code.default_retryable();
        Self::new(code, message, retryable)
    }

    /// The error code, parsed through the shared vocabulary. Unknown strings
    /// pass through as [`ErrorCode::Unknown`] (never fails).
    pub fn error_code(&self) -> ErrorCode {
        match self.code.parse::<ErrorCode>() {
            Ok(code) => code,
            Err(never) => match never {},
        }
    }
}

impl StreamHeader {
    /// Header for an exec data stream carrying `ticket`.
    pub fn exec_data(ticket: Vec<u8>) -> Self {
        Self {
            kind: StreamKind::ExecData as i32,
            ticket,
            host: String::new(),
            port: 0,
        }
    }

    /// Header for a session data stream carrying `ticket` (from
    /// [`SessionOpened`] / [`SessionAttached`]).
    pub fn session_data(ticket: Vec<u8>) -> Self {
        Self {
            kind: StreamKind::SessionData as i32,
            ticket,
            host: String::new(),
            port: 0,
        }
    }

    /// The declared stream kind, or `None` if this build does not know it.
    pub fn stream_kind(&self) -> Option<StreamKind> {
        StreamKind::try_from(self.kind).ok()
    }
}

impl ExecFrame {
    /// Wrap a body variant.
    pub fn from_body(body: exec_frame::Body) -> Self {
        Self { body: Some(body) }
    }

    /// `Stdout` frame.
    pub fn stdout(data: Vec<u8>) -> Self {
        Self::from_body(exec_frame::Body::Stdout(Stdout { data }))
    }

    /// `Stderr` frame.
    pub fn stderr(data: Vec<u8>) -> Self {
        Self::from_body(exec_frame::Body::Stderr(Stderr { data }))
    }

    /// `Stdin` frame.
    pub fn stdin(data: Vec<u8>) -> Self {
        Self::from_body(exec_frame::Body::Stdin(Stdin { data }))
    }

    /// `StdinEof` frame.
    pub fn stdin_eof() -> Self {
        Self::from_body(exec_frame::Body::StdinEof(StdinEof {}))
    }

    /// `ExecExit` frame.
    pub fn exec_exit(exit_code: i32, signal: Option<String>) -> Self {
        Self::from_body(exec_frame::Body::ExecExit(ExecExit {
            exit_code,
            signal,
            timed_out: false,
        }))
    }

    /// `ExecExit` frame for a process the host killed on `timeout_ms`.
    pub fn exec_exit_timed_out(exit_code: i32, signal: Option<String>) -> Self {
        Self::from_body(exec_frame::Body::ExecExit(ExecExit {
            exit_code,
            signal,
            timed_out: true,
        }))
    }
}

impl SessionFrame {
    /// Wrap a body variant.
    pub fn from_body(body: session_frame::Body) -> Self {
        Self { body: Some(body) }
    }

    /// `Output` frame: `data` ending at cumulative offset `sequence`.
    pub fn output(sequence: u64, data: Vec<u8>) -> Self {
        Self::from_body(session_frame::Body::Output(Output { sequence, data }))
    }

    /// `Input` frame: `data` ending at cumulative input offset `input_seq`.
    pub fn input(input_seq: u64, data: Vec<u8>) -> Self {
        Self::from_body(session_frame::Body::Input(Input { input_seq, data }))
    }

    /// `InputAck` frame.
    pub fn input_ack(acked_input_seq: u64) -> Self {
        Self::from_body(session_frame::Body::InputAck(InputAck { acked_input_seq }))
    }

    /// `Gap` frame.
    pub fn gap(requested_after: u64, available_from: u64) -> Self {
        Self::from_body(session_frame::Body::Gap(Gap {
            requested_after,
            available_from,
        }))
    }

    /// `Resize` frame.
    pub fn resize(cols: u32, rows: u32) -> Self {
        Self::from_body(session_frame::Body::Resize(Resize { cols, rows }))
    }

    /// `Exit` frame.
    pub fn exit(final_seq: u64, exit_code: i32, signal: Option<String>) -> Self {
        Self::from_body(session_frame::Body::Exit(Exit {
            final_seq,
            exit_code,
            signal,
        }))
    }
}

impl SessionAttach {
    /// The requested attach mode, or `None` if this build does not know it
    /// (treat as a malformed request, never as RW).
    pub fn attach_mode(&self) -> Option<AttachMode> {
        AttachMode::try_from(self.mode).ok()
    }
}

impl SessionEvent {
    /// Wrap a body variant for `session_id`.
    pub fn from_body(session_id: impl Into<String>, body: session_event::Body) -> Self {
        Self {
            session_id: session_id.into(),
            body: Some(body),
        }
    }

    /// `Exited` event.
    pub fn exited(session_id: impl Into<String>, exit: Exit) -> Self {
        Self::from_body(session_id, session_event::Body::Exited(exit))
    }

    /// `WriterChanged` event; `new_writer = None` means the lease was
    /// released with no holder.
    pub fn writer_changed(
        session_id: impl Into<String>,
        new_writer: Option<String>,
        seq: u64,
    ) -> Self {
        Self::from_body(
            session_id,
            session_event::Body::WriterChanged(WriterChanged { new_writer, seq }),
        )
    }

    /// `Closed` event.
    pub fn closed(session_id: impl Into<String>, reason: impl Into<String>, seq: u64) -> Self {
        Self::from_body(
            session_id,
            session_event::Body::Closed(Closed {
                reason: reason.into(),
                seq,
            }),
        )
    }
}

impl SessionReadEvent {
    /// Wrap a body variant.
    pub fn from_body(body: session_read_event::Body) -> Self {
        Self { body: Some(body) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameDecoder;
    use proptest::prelude::*;
    use std::collections::HashMap;

    // ---- strategies -----------------------------------------------------

    fn arb_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..=max)
    }

    fn arb_hello() -> impl Strategy<Value = Hello> {
        (
            proptest::collection::vec(any::<u32>(), 0..4),
            ".{0,32}",
            proptest::collection::vec("[a-z.0-9]{1,16}", 0..4),
        )
            .prop_map(|(versions, device_name, capabilities)| Hello {
                versions,
                device_name,
                capabilities,
            })
    }

    fn arb_error() -> impl Strategy<Value = Error> {
        (
            proptest::sample::select(ErrorCode::KNOWN.to_vec()),
            ".{0,64}",
            any::<bool>(),
        )
            .prop_map(|(code, message, retryable)| Error::new(code, message, retryable))
    }

    fn arb_exec_start() -> impl Strategy<Value = ExecStart> {
        (
            proptest::collection::vec(".{0,16}", 0..5),
            proptest::collection::hash_map("[A-Z_]{1,8}", ".{0,16}", 0..4),
            any::<u64>(),
        )
            .prop_map(|(argv, env, timeout_ms)| ExecStart {
                argv,
                env,
                timeout_ms,
            })
    }

    fn arb_exec_started() -> impl Strategy<Value = ExecStarted> {
        (".{0,26}", arb_bytes(16)).prop_map(|(exec_id, ticket)| ExecStarted { exec_id, ticket })
    }

    // -- session control (M2) --

    fn arb_session_id() -> impl Strategy<Value = String> {
        "[0-9A-HJKMNP-TV-Z]{26}"
    }

    fn arb_rfc3339() -> impl Strategy<Value = String> {
        "20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z"
    }

    fn arb_principal() -> impl Strategy<Value = String> {
        "(device|user|fp):[a-z0-9]{1,12}"
    }

    fn arb_session_open() -> impl Strategy<Value = SessionOpen> {
        (
            proptest::collection::vec(".{0,16}", 0..5),
            proptest::collection::hash_map("[A-Z_]{1,8}", ".{0,16}", 0..4),
            "[a-z0-9-]{0,16}",
            any::<u32>(),
            any::<u32>(),
            proptest::option::of("[a-z]{1,8}"),
        )
            .prop_map(|(argv, env, term, cols, rows, user)| SessionOpen {
                argv,
                env,
                term,
                cols,
                rows,
                user,
            })
    }

    fn arb_session_opened() -> impl Strategy<Value = SessionOpened> {
        (
            arb_session_id(),
            arb_bytes(32),
            arb_bytes(16),
            any::<u64>(),
            arb_rfc3339(),
        )
            .prop_map(
                |(session_id, resume_token, ticket, initial_seq, expires_at)| SessionOpened {
                    session_id,
                    resume_token,
                    ticket,
                    initial_seq,
                    expires_at,
                },
            )
    }

    fn arb_session_attach() -> impl Strategy<Value = SessionAttach> {
        (
            arb_session_id(),
            arb_bytes(32),
            any::<u64>(),
            0i32..=2,
            any::<bool>(),
        )
            .prop_map(
                |(session_id, resume_token, last_output_seq, mode, no_steal)| SessionAttach {
                    session_id,
                    resume_token,
                    last_output_seq,
                    mode,
                    no_steal,
                },
            )
    }

    fn arb_session_attached() -> impl Strategy<Value = SessionAttached> {
        (
            arb_bytes(16),
            arb_bytes(32),
            any::<u64>(),
            any::<bool>(),
            arb_rfc3339(),
        )
            .prop_map(
                |(ticket, new_resume_token, replay_from, writer_lease, expires_at)| {
                    SessionAttached {
                        ticket,
                        new_resume_token,
                        replay_from,
                        writer_lease,
                        expires_at,
                    }
                },
            )
    }

    fn arb_session_info() -> impl Strategy<Value = SessionInfo> {
        (
            arb_session_id(),
            "(running|exited)",
            proptest::option::of(arb_principal()),
            arb_rfc3339(),
            any::<u64>(),
        )
            .prop_map(|(session_id, state, writer, created_at, last_sequence)| {
                SessionInfo {
                    session_id,
                    state,
                    writer,
                    created_at,
                    last_sequence,
                }
            })
    }

    fn arb_output() -> impl Strategy<Value = Output> {
        (any::<u64>(), arb_bytes(64)).prop_map(|(sequence, data)| Output { sequence, data })
    }

    fn arb_gap() -> impl Strategy<Value = Gap> {
        (any::<u64>(), any::<u64>()).prop_map(|(requested_after, available_from)| Gap {
            requested_after,
            available_from,
        })
    }

    fn arb_exit() -> impl Strategy<Value = Exit> {
        (
            any::<u64>(),
            any::<i32>(),
            proptest::option::of("SIG[A-Z]{3,4}"),
        )
            .prop_map(|(final_seq, exit_code, signal)| Exit {
                final_seq,
                exit_code,
                signal,
            })
    }

    fn arb_writer_changed() -> impl Strategy<Value = WriterChanged> {
        (proptest::option::of(arb_principal()), any::<u64>())
            .prop_map(|(new_writer, seq)| WriterChanged { new_writer, seq })
    }

    fn arb_closed() -> impl Strategy<Value = Closed> {
        ("(closed|exit|ttl_expired|future_reason)", any::<u64>())
            .prop_map(|(reason, seq)| Closed { reason, seq })
    }

    fn arb_session_read_event() -> impl Strategy<Value = SessionReadEvent> {
        use session_read_event::Body;
        prop_oneof![
            arb_output().prop_map(|o| SessionReadEvent::from_body(Body::Output(o))),
            arb_gap().prop_map(|g| SessionReadEvent::from_body(Body::Gap(g))),
            arb_exit().prop_map(|e| SessionReadEvent::from_body(Body::Exit(e))),
            arb_writer_changed().prop_map(|w| SessionReadEvent::from_body(Body::WriterChanged(w))),
            arb_closed().prop_map(|c| SessionReadEvent::from_body(Body::Closed(c))),
            Just(SessionReadEvent { body: None }),
        ]
    }

    fn arb_session_event() -> impl Strategy<Value = SessionEvent> {
        (
            arb_session_id(),
            prop_oneof![
                arb_exit().prop_map(session_event::Body::Exited),
                arb_writer_changed().prop_map(session_event::Body::WriterChanged),
                arb_closed().prop_map(session_event::Body::Closed),
            ],
        )
            .prop_map(|(session_id, body)| SessionEvent::from_body(session_id, body))
    }

    fn arb_response() -> impl Strategy<Value = Response> {
        let body = prop_oneof![
            arb_session_opened().prop_map(response::Body::SessionOpened),
            arb_session_attached().prop_map(response::Body::SessionAttached),
            arb_exec_started().prop_map(response::Body::ExecStarted),
            proptest::collection::vec(arb_session_read_event(), 0..4)
                .prop_map(|events| response::Body::SessionReadResult(SessionReadResult { events })),
            proptest::collection::vec(arb_session_info(), 0..4).prop_map(|sessions| {
                response::Body::SessionListResult(SessionListResult { sessions })
            }),
            arb_session_info().prop_map(response::Body::SessionInfo),
            Just(response::Body::SessionWritten(SessionWritten {})),
            Just(response::Body::SessionResized(SessionResized {})),
            any::<u64>()
                .prop_map(|final_seq| response::Body::SessionClosed(SessionClosed { final_seq })),
            arb_error().prop_map(response::Body::Error),
        ];
        proptest::option::of(body).prop_map(|body| Response { body })
    }

    fn arb_control_body() -> impl Strategy<Value = control_message::Body> {
        use control_message::Body;
        prop_oneof![
            arb_hello().prop_map(Body::Hello),
            arb_response().prop_map(Body::Response),
            arb_session_open().prop_map(Body::SessionOpen),
            arb_session_attach().prop_map(Body::SessionAttach),
            Just(Body::SessionList(SessionList {})),
            arb_session_id().prop_map(|session_id| Body::SessionGet(SessionGet { session_id })),
            (arb_session_id(), any::<u32>(), any::<u32>()).prop_map(|(session_id, cols, rows)| {
                Body::SessionResize(SessionResize {
                    session_id,
                    cols,
                    rows,
                })
            }),
            (
                arb_session_id(),
                proptest::option::of("SIG(HUP|INT|QUIT|TERM|USR1|USR2|KILL)")
            )
                .prop_map(|(session_id, signal)| Body::SessionClose(SessionClose {
                    session_id,
                    signal
                })),
            (arb_session_id(), any::<u64>(), any::<u32>(), any::<u64>()).prop_map(
                |(session_id, after, max_bytes, wait_ms)| {
                    Body::SessionRead(SessionRead {
                        session_id,
                        after,
                        max_bytes,
                        wait_ms,
                    })
                }
            ),
            (arb_session_id(), arb_bytes(64)).prop_map(|(session_id, data)| Body::SessionWrite(
                SessionWrite { session_id, data }
            )),
            arb_exec_start().prop_map(Body::ExecStart),
            Just(Body::Ping(Ping {})),
            Just(Body::Pong(Pong {})),
            arb_session_event().prop_map(Body::SessionEvent),
        ]
    }

    fn arb_control() -> impl Strategy<Value = ControlMessage> {
        (any::<u64>(), proptest::option::of(arb_control_body()))
            .prop_map(|(request_id, body)| ControlMessage { request_id, body })
    }

    fn arb_stream_header() -> impl Strategy<Value = StreamHeader> {
        (0i32..=4, arb_bytes(16), ".{0,32}", any::<u32>()).prop_map(|(kind, ticket, host, port)| {
            StreamHeader {
                kind,
                ticket,
                host,
                port,
            }
        })
    }

    fn arb_session_frame() -> impl Strategy<Value = SessionFrame> {
        prop_oneof![
            (any::<u64>(), arb_bytes(64)).prop_map(|(seq, data)| SessionFrame::output(seq, data)),
            (any::<u64>(), arb_bytes(64)).prop_map(|(seq, data)| SessionFrame::input(seq, data)),
            any::<u64>().prop_map(SessionFrame::input_ack),
            (any::<u64>(), any::<u64>()).prop_map(|(a, b)| SessionFrame::gap(a, b)),
            (any::<u32>(), any::<u32>()).prop_map(|(c, r)| SessionFrame::resize(c, r)),
            (
                any::<u64>(),
                any::<i32>(),
                proptest::option::of("SIG[A-Z]{3,4}")
            )
                .prop_map(|(seq, code, sig)| SessionFrame::exit(seq, code, sig)),
            Just(SessionFrame { body: None }),
        ]
    }

    fn arb_exec_frame() -> impl Strategy<Value = ExecFrame> {
        prop_oneof![
            arb_bytes(64).prop_map(ExecFrame::stdin),
            Just(ExecFrame::stdin_eof()),
            arb_bytes(64).prop_map(ExecFrame::stdout),
            arb_bytes(64).prop_map(ExecFrame::stderr),
            (any::<i32>(), proptest::option::of("[A-Z]{3,7}"))
                .prop_map(|(code, sig)| ExecFrame::exec_exit(code, sig)),
            (any::<i32>(), proptest::option::of("[A-Z]{3,7}"))
                .prop_map(|(code, sig)| ExecFrame::exec_exit_timed_out(code, sig)),
            Just(ExecFrame { body: None }),
        ]
    }

    // ---- roundtrip ------------------------------------------------------

    fn roundtrip_via_frame<M: Message + Default + PartialEq + std::fmt::Debug>(m: &M, max: usize) {
        let wire = encode_framed(m, max).unwrap();
        let mut dec = FrameDecoder::new(max);
        dec.push(&wire);
        let payload = dec.next_frame().unwrap().expect("one complete frame");
        assert_eq!(dec.next_frame().unwrap(), None, "no trailing bytes");
        let back: M = decode_msg(&payload).unwrap();
        assert_eq!(&back, m);
    }

    proptest! {
        #[test]
        fn control_message_roundtrips(m in arb_control()) {
            roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
        }

        #[test]
        fn stream_header_roundtrips(m in arb_stream_header()) {
            roundtrip_via_frame(&m, DATA_FRAME_MAX);
        }

        #[test]
        fn exec_frame_roundtrips(m in arb_exec_frame()) {
            roundtrip_via_frame(&m, DATA_FRAME_MAX);
        }

        #[test]
        fn session_frame_roundtrips(m in arb_session_frame()) {
            roundtrip_via_frame(&m, DATA_FRAME_MAX);
            // The dedicated encoder agrees with the generic one for
            // in-cap chunks.
            let via_helper = encode_session_frame(&m).unwrap();
            prop_assert_eq!(via_helper, encode_framed(&m, DATA_FRAME_MAX).unwrap());
        }

        /// Every session message reachable from the control stream
        /// (session_* requests, every Response body, SessionEvent) is a
        /// `control_message::Body`; `arb_control_body` enumerates them all,
        /// so this pins `decode(encode(m)) == m` for each one.
        #[test]
        fn session_control_bodies_roundtrip(body in arb_control_body(), id in any::<u64>()) {
            let m = ControlMessage::new(id, body);
            roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
        }

        /// Every strict prefix of a framed encoding is "incomplete" at the
        /// frame layer (`Ok(None)`): never a frame, never a panic. The
        /// protobuf body itself is prefix-tolerant by design, so the
        /// truncation guarantee lives in the frame layer.
        #[test]
        fn framed_prefixes_are_incomplete(m in arb_control()) {
            let wire = encode_control(&m).unwrap();
            for cut in 0..wire.len() {
                let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
                dec.push(&wire[..cut]);
                prop_assert_eq!(dec.next_frame().unwrap(), None, "prefix len {}", cut);
            }
        }

        /// Same truncation guarantee for the data-stream frame types.
        #[test]
        fn framed_session_frame_prefixes_are_incomplete(m in arb_session_frame()) {
            let wire = encode_session_frame(&m).unwrap();
            for cut in 0..wire.len() {
                let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
                dec.push(&wire[..cut]);
                prop_assert_eq!(dec.next_frame().unwrap(), None, "prefix len {}", cut);
            }
        }

        #[test]
        fn framed_stream_header_prefixes_are_incomplete(m in arb_stream_header()) {
            let wire = encode_stream_header(&m).unwrap();
            for cut in 0..wire.len() {
                let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
                dec.push(&wire[..cut]);
                prop_assert_eq!(dec.next_frame().unwrap(), None, "prefix len {}", cut);
            }
        }

        /// Arbitrary bytes never panic the decoder.
        #[test]
        fn garbage_never_panics(bytes in arb_bytes(256)) {
            let _ = decode_msg::<ControlMessage>(&bytes);
            let _ = decode_msg::<StreamHeader>(&bytes);
            let _ = decode_msg::<ExecFrame>(&bytes);
            let _ = decode_msg::<SessionFrame>(&bytes);
        }

        /// Bit-flipped valid encodings never panic and, when they decode,
        /// re-encode without panicking.
        #[test]
        fn bit_flips_never_panic(m in arb_control(), idx in any::<prop::sample::Index>(), bit in 0u8..8) {
            let mut body = m.encode_to_vec();
            if body.is_empty() { return Ok(()); }
            let i = idx.index(body.len());
            body[i] ^= 1 << bit;
            if let Ok(decoded) = decode_msg::<ControlMessage>(&body) {
                let _ = decoded.encode_to_vec();
            }
        }
    }

    // ---- allocation bound ----------------------------------------------

    #[test]
    fn oversize_control_frame_rejected_before_allocation() {
        // A peer claiming a 4 GiB frame is rejected from the 4-byte header
        // alone; the frame layer never allocates `attacker_length` bytes.
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&u32::MAX.to_be_bytes());
        assert_eq!(
            dec.next_frame().unwrap_err(),
            FrameError::Oversize {
                len: u32::MAX,
                max: CONTROL_FRAME_MAX
            }
        );
    }

    #[test]
    fn encode_refuses_messages_over_frame_cap() {
        let big = ExecFrame::stdout(vec![0u8; DATA_FRAME_MAX + 1]);
        assert!(matches!(
            encode_exec_frame(&big),
            Err(WireEncodeError::TooLarge { .. })
        ));
    }

    // ---- chunk cap ------------------------------------------------------

    #[test]
    fn session_frame_chunk_over_cap_is_rejected_at_encode() {
        // Exactly the cap is fine …
        assert!(
            encode_session_frame(&SessionFrame::output(0, vec![0u8; SESSION_CHUNK_MAX])).is_ok()
        );
        assert!(
            encode_session_frame(&SessionFrame::input(0, vec![0u8; SESSION_CHUNK_MAX])).is_ok()
        );
        // … one byte more is refused *before* framing, even though it would
        // still fit the 64 KiB data-frame cap.
        const { assert!(SESSION_CHUNK_MAX + 1 < DATA_FRAME_MAX) };
        for frame in [
            SessionFrame::output(0, vec![0u8; SESSION_CHUNK_MAX + 1]),
            SessionFrame::input(0, vec![0u8; SESSION_CHUNK_MAX + 1]),
        ] {
            assert_eq!(
                encode_session_frame(&frame),
                Err(WireEncodeError::ChunkTooLarge {
                    len: SESSION_CHUNK_MAX + 1,
                    max: SESSION_CHUNK_MAX
                })
            );
        }
    }

    #[test]
    fn session_write_chunk_over_cap_is_rejected_at_encode() {
        let m = ControlMessage::new(
            5,
            control_message::Body::SessionWrite(SessionWrite {
                session_id: "01K0SESSION".into(),
                data: vec![0u8; SESSION_CHUNK_MAX + 1],
            }),
        );
        assert!(matches!(
            encode_control(&m),
            Err(WireEncodeError::ChunkTooLarge { .. })
        ));
    }

    #[test]
    fn stream_header_session_data_constructor() {
        let h = StreamHeader::session_data(vec![1, 2, 3]);
        assert_eq!(h.stream_kind(), Some(StreamKind::SessionData));
        assert_eq!(h.ticket, vec![1, 2, 3]);
        assert!(h.host.is_empty());
        assert_eq!(h.port, 0);
    }

    #[test]
    fn attach_mode_unknown_is_none_not_rw() {
        let a = SessionAttach {
            mode: 42,
            ..Default::default()
        };
        assert_eq!(a.attach_mode(), None);
        let a = SessionAttach {
            mode: AttachMode::Rw as i32,
            ..Default::default()
        };
        assert_eq!(a.attach_mode(), Some(AttachMode::Rw));
    }

    #[test]
    fn local_capabilities_advertise_session_and_resume() {
        assert!(LOCAL_CAPABILITIES.contains(&CAP_EXEC));
        assert!(LOCAL_CAPABILITIES.contains(&CAP_SESSION));
        assert!(LOCAL_CAPABILITIES.contains(&CAP_RESUME_V1));
    }

    // ---- error vocabulary ----------------------------------------------

    #[test]
    fn wire_error_code_uses_error_code_vocabulary_verbatim() {
        for code in ErrorCode::KNOWN {
            let err = Error::from_code(code.clone(), "x");
            assert_eq!(err.code, code.as_str());
            assert_eq!(&err.error_code(), code);
        }
        // The session codes M2 starts producing are part of the shared
        // vocabulary (never ad hoc strings anywhere in the session path).
        for (code, s) in [
            (ErrorCode::SessionNotFound, "SESSION_NOT_FOUND"),
            (ErrorCode::SessionConflict, "SESSION_CONFLICT"),
            (ErrorCode::ResumeGap, "RESUME_GAP"),
        ] {
            assert!(ErrorCode::KNOWN.contains(&code));
            assert_eq!(Error::from_code(code.clone(), "x").code, s);
            assert_eq!(s.parse::<ErrorCode>().unwrap(), code);
        }
        let unknown = Error {
            code: "SOME_FUTURE_CODE".into(),
            message: String::new(),
            retryable: false,
        };
        assert_eq!(
            unknown.error_code(),
            ErrorCode::Unknown("SOME_FUTURE_CODE".into())
        );
    }

    // ---- golden vectors -------------------------------------------------

    /// Checked-in hex frames. Breaking these means the wire format changed:
    /// that requires a deliberate `qsh/2` decision, not a test edit.
    #[test]
    fn golden_hello_frame() {
        let msg = ControlMessage::new(
            1,
            control_message::Body::Hello(Hello {
                versions: vec![0],
                device_name: "hermes".into(),
                capabilities: vec!["exec".into()],
            }),
        );
        let wire = encode_control(&msg).unwrap();
        assert_eq!(
            hex(&wire),
            "0000001508015211" // frame len 21 | request_id=1 | field 10 (Hello) len 17
                .to_owned()
                + "0a0100" // versions: packed [0]
                + "12066865726d6573" // device_name "hermes"
                + "1a0465786563" // capabilities ["exec"]
        );
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn golden_exec_exit_frame() {
        let msg = ExecFrame::exec_exit(7, None);
        let wire = encode_exec_frame(&msg).unwrap();
        assert_eq!(hex(&wire), "000000042a020807");
        let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
        dec.push(&wire);
        let back: ExecFrame = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn golden_error_response_frame() {
        let msg = ControlMessage::error(2, Error::new(ErrorCode::PermissionDenied, "no", false));
        let wire = encode_control(&msg).unwrap();
        assert_eq!(
            hex(&wire),
            "0000001d08025a197a17" // frame len 29 | request_id=2 | Response(len 25) | Error(len 23)
                .to_owned()
                + "0a115045524d495353494f4e5f44454e494544" // code
                + "12026e6f" // message "no"
        );
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn golden_session_open_frame() {
        let msg = ControlMessage::new(
            3,
            control_message::Body::SessionOpen(SessionOpen {
                argv: vec!["claude".into()],
                env: Default::default(),
                term: "xterm-256color".into(),
                cols: 120,
                rows: 40,
                user: Some("dave".into()),
            }),
        );
        let wire = encode_control(&msg).unwrap();
        assert_eq!(
            hex(&wire),
            "000000270803a20122" // frame len 39 | request_id=3 | field 20 (SessionOpen) len 34
                .to_owned()
                + "0a06636c61756465" // argv ["claude"]
                + "1a0e787465726d2d323536636f6c6f72" // term "xterm-256color"
                + "2078" // cols 120
                + "2828" // rows 40
                + "320464617665" // user "dave"
        );
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn golden_session_output_frame() {
        // Output{sequence: 49, data: "Hello\r\n"} — the CLI.md §6.4 example
        // (7 bytes after `--after 42` → cumulative offset 49).
        let msg = SessionFrame::output(49, b"Hello\r\n".to_vec());
        let wire = encode_session_frame(&msg).unwrap();
        assert_eq!(
            hex(&wire),
            "0000000d0a0b" // frame len 13 | field 1 (Output) len 11
                .to_owned()
                + "0831" // sequence 49
                + "120748656c6c6f0d0a" // data "Hello\r\n"
        );
        let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
        dec.push(&wire);
        let back: SessionFrame = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn golden_session_closed_event_frame() {
        let msg = ControlMessage::new(
            0,
            control_message::Body::SessionEvent(SessionEvent::closed("01K0SESSION", "closed", 180)),
        );
        let wire = encode_control(&msg).unwrap();
        assert_eq!(
            hex(&wire),
            "0000001de2031a" // frame len 29 | (request_id 0 omitted) | field 60 (SessionEvent) len 26
                .to_owned()
                + "0a0b30314b3053455353494f4e" // session_id "01K0SESSION"
                + "220b" // field 4 (Closed) len 11
                + "0a06636c6f736564" // reason "closed"
                + "10b401" // seq 180
        );
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn exec_start_env_map_roundtrips() {
        let mut env = HashMap::new();
        env.insert("A".to_string(), "1".to_string());
        env.insert("B".to_string(), "2".to_string());
        let msg = ControlMessage::new(
            9,
            control_message::Body::ExecStart(ExecStart {
                argv: vec!["sh".into(), "-c".into(), "true".into()],
                env,
                timeout_ms: 1500,
            }),
        );
        roundtrip_via_frame(&msg, CONTROL_FRAME_MAX);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
