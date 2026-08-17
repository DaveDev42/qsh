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

/// Capabilities this build advertises in [`Hello`].
pub const LOCAL_CAPABILITIES: &[&str] = &[CAP_EXEC];

/// Maximum size of a single PTY/exec payload chunk (the `data` field of a
/// [`Stdout`]/[`Stderr`]/[`Stdin`] frame), 16 KiB (`protocol.md` §5).
pub const EXEC_CHUNK_MAX: usize = 16 * 1024;

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
    /// Frame-layer failure (unreachable in practice: `TooLarge` triggers
    /// first, but kept so callers see one error type).
    #[error(transparent)]
    Frame(#[from] FrameError),
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

/// Encode a [`ControlMessage`] as one control-stream frame.
pub fn encode_control(msg: &ControlMessage) -> Result<Vec<u8>, WireEncodeError> {
    encode_framed(msg, CONTROL_FRAME_MAX)
}

/// Encode an [`ExecFrame`] as one data-stream frame.
pub fn encode_exec_frame(msg: &ExecFrame) -> Result<Vec<u8>, WireEncodeError> {
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

    fn arb_response() -> impl Strategy<Value = Response> {
        prop_oneof![
            arb_exec_started().prop_map(|e| Response {
                body: Some(response::Body::ExecStarted(e))
            }),
            arb_error().prop_map(|e| Response {
                body: Some(response::Body::Error(e))
            }),
            Just(Response { body: None }),
        ]
    }

    fn arb_control_body() -> impl Strategy<Value = control_message::Body> {
        prop_oneof![
            arb_hello().prop_map(control_message::Body::Hello),
            arb_response().prop_map(control_message::Body::Response),
            arb_exec_start().prop_map(control_message::Body::ExecStart),
            Just(control_message::Body::Ping(Ping {})),
            Just(control_message::Body::Pong(Pong {})),
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

        /// Arbitrary bytes never panic the decoder.
        #[test]
        fn garbage_never_panics(bytes in arb_bytes(256)) {
            let _ = decode_msg::<ControlMessage>(&bytes);
            let _ = decode_msg::<StreamHeader>(&bytes);
            let _ = decode_msg::<ExecFrame>(&bytes);
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

    // ---- error vocabulary ----------------------------------------------

    #[test]
    fn wire_error_code_uses_error_code_vocabulary_verbatim() {
        for code in ErrorCode::KNOWN {
            let err = Error::from_code(code.clone(), "x");
            assert_eq!(err.code, code.as_str());
            assert_eq!(&err.error_code(), code);
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
