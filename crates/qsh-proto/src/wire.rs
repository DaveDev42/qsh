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

/// Capabilities this build advertises in [`Hello`]. Advertised and
/// implemented stay in lockstep — a capability string is a promise about
/// behaviour, and a peer that advertises resume and then cannot replay is
/// worse than one that never claimed it. [`CAP_RESUME_V1`] joined the list
/// with the resume implementation (PLAN M2 Step 7): the host redeems a
/// resume credential, replays from the requested offset (or opens with a
/// `Gap`), and deduplicates retransmitted input.
pub const LOCAL_CAPABILITIES: &[&str] = &[CAP_EXEC, CAP_SESSION, CAP_RESUME_V1];

/// quinn send priority of the control stream — the top of the
/// `docs/design/protocol.md` §12 band, so a saturated bulk stream can never
/// delay a control message in the local send queue.
pub const PRIORITY_CONTROL: i32 = 200;

/// quinn send priority of a `SESSION_DATA` stream (interactive PTY), below
/// [`PRIORITY_CONTROL`] and above bulk traffic (`protocol.md` §12).
pub const PRIORITY_SESSION_DATA: i32 = 100;

/// quinn send priority of an `EXEC_DATA` stream (`protocol.md` §12).
pub const PRIORITY_EXEC_DATA: i32 = 50;

/// quinn send priority of tunnel/file streams (`protocol.md` §12; M4).
pub const PRIORITY_TUNNEL: i32 = 0;

/// Maximum size of a single exec payload chunk (the `data` field of a
/// [`Stdout`]/[`Stderr`]/[`Stdin`] frame), 16 KiB (`protocol.md` §5).
pub const EXEC_CHUNK_MAX: usize = 16 * 1024;

/// Maximum size of a single session payload chunk — the `data` field of an
/// [`Output`]/[`Input`] frame and of a [`SessionWrite`] request — 16 KiB
/// (`protocol.md` §5, §9). Enforced at encode time by
/// [`encode_session_frame`] / [`encode_control`], not merely by the 64 KiB
/// data-frame cap.
pub const SESSION_CHUNK_MAX: usize = 16 * 1024;

/// Upper bound the host applies to `SessionRead.max_bytes` (JSON
/// `limit_bytes`): the total `Output.data` payload of one
/// [`SessionReadResult`], 192 KiB = 12 × [`SESSION_CHUNK_MAX`]. Chosen so a
/// full-limit reply plus its per-event and frame overhead always fits one
/// [`CONTROL_FRAME_MAX`] frame (pinned by a test). Larger requests are
/// clamped, never rejected.
pub const SESSION_READ_MAX_BYTES: usize = 12 * SESSION_CHUNK_MAX;

/// A payload chunk exceeds its per-chunk cap ([`SESSION_CHUNK_MAX`]).
/// Returned by the encoders (sender side) and by the `validate()` helpers
/// on decoded messages (receiver side — a peer not running our encoder is
/// bounded only by the frame cap, so hosts must validate before acting).
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
#[error("payload chunk ({len} bytes) exceeds chunk max {max}")]
pub struct ChunkTooLarge {
    /// Chunk length.
    pub len: usize,
    /// The applicable chunk cap.
    pub max: usize,
}

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
    #[error(transparent)]
    ChunkTooLarge(#[from] ChunkTooLarge),
    /// Frame-layer failure (unreachable in practice: `TooLarge` triggers
    /// first, but kept so callers see one error type).
    #[error(transparent)]
    Frame(#[from] FrameError),
}

fn check_chunk(len: usize) -> Result<(), ChunkTooLarge> {
    if len > SESSION_CHUNK_MAX {
        return Err(ChunkTooLarge {
            len,
            max: SESSION_CHUNK_MAX,
        });
    }
    Ok(())
}

impl SessionWrite {
    /// Receiver-side chunk check: `data` must not exceed
    /// [`SESSION_CHUNK_MAX`]. Hosts call this before touching the session
    /// (answer `INVALID_ARGUMENT` on error).
    pub fn validate(&self) -> Result<(), ChunkTooLarge> {
        check_chunk(self.data.len())
    }
}

impl SessionReadResult {
    /// Receiver-side chunk check over every `Output` event.
    pub fn validate(&self) -> Result<(), ChunkTooLarge> {
        self.events.iter().try_for_each(|e| match &e.body {
            Some(session_read_event::Body::Output(o)) => check_chunk(o.data.len()),
            _ => Ok(()),
        })
    }
}

impl SessionFrame {
    /// Receiver-side chunk check: an `Output`/`Input` chunk must not
    /// exceed [`SESSION_CHUNK_MAX`]. The `SESSION_DATA` pump calls this on
    /// every decoded frame before feeding the PTY / replay ring.
    pub fn validate(&self) -> Result<(), ChunkTooLarge> {
        match &self.body {
            Some(session_frame::Body::Output(o)) => check_chunk(o.data.len()),
            Some(session_frame::Body::Input(i)) => check_chunk(i.data.len()),
            _ => Ok(()),
        }
    }
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
/// [`SessionWrite`] whose `data` exceeds [`SESSION_CHUNK_MAX`], or a
/// [`SessionReadResult`] carrying an over-cap `Output`, is refused with
/// [`WireEncodeError::ChunkTooLarge`].
pub fn encode_control(msg: &ControlMessage) -> Result<Vec<u8>, WireEncodeError> {
    match &msg.body {
        Some(control_message::Body::SessionWrite(w)) => w.validate()?,
        Some(control_message::Body::Response(Response {
            body: Some(response::Body::SessionReadResult(r)),
        })) => r.validate()?,
        _ => {}
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
    msg.validate()?;
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

/// Shape of a name a reverse target may offer for itself
/// (`ReverseRegistration.offered_name`) or a controller may register a
/// target under: `1..=64` bytes of `[A-Za-z0-9._-]`.
///
/// Same discipline as `server::valid_session_id`
/// (`crates/qsh-core/src/server/mod.rs`): a peer-supplied string that will
/// become an ACL resource and an audit field gets its shape checked before
/// either of those, so a peer cannot inflate audit records or exploit
/// downstream assumptions with an oversized or oddly-charactered string
/// (`docs/design/protocol.md` §9 — the same "check shape first" rule
/// applied there to `session_id`). Lives in `qsh-proto`, not `qsh-core`,
/// specifically so the M3 `host.reverse` ACL choke point can call it
/// *before* authorization runs (`PLAN.md` M3 Step 1).
pub fn valid_host_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Shape of a `forward_id` (`RemoteForwardOpened.forward_id`,
/// `RemoteForwardClose.forward_id`, and — carried again — `StreamHeader.
/// ticket` on a `TCP_ACCEPTED` stream): `1..=64` bytes of
/// `[A-Za-z0-9_-]` (URL-safe, no `.`  — unlike [`valid_host_name`] this is
/// an opaque host-issued token, not a display name).
///
/// Same "check shape before it becomes an ACL resource or audit field"
/// discipline as [`valid_host_name`] (this fn's own doc, `PLAN.md` M4 §4.1):
/// a `forward_id` a peer sends back is never trusted until it passes this
/// check, so an oversized or oddly-charactered string a confused or hostile
/// peer echoes back can never inflate an audit record.
pub fn valid_forward_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Direction of a `-L`/`-R` port forward (`docs/CLI.md` §6.9, M4).
/// [`parse_forward_spec`] cannot infer this from the spec string alone (the
/// grammar is identical for both) — it comes from which flag the caller
/// parsed, so [`ForwardSpec::direction`] defaults to [`ForwardDirection::Local`]
/// and a `-R` caller must set it explicitly after parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ForwardDirection {
    /// `-L`: the requester (client) binds `bind:listen_port` locally; for
    /// each connection accepted there it dials `host:host_port` on the
    /// peer.
    #[default]
    Local,
    /// `-R`: the peer (host) binds `bind:listen_port`; for each connection
    /// it accepts there, the *requester* dials `host:host_port` — the two
    /// legs are swapped relative to `Local`.
    Remote,
}

/// A parsed `-L`/`-R` forward spec (`docs/CLI.md` §6.9, M4) — the result of
/// [`parse_forward_spec`]. Shape-only: this type and its parser carry no
/// policy (e.g. "remote binds must be loopback"); that is host-side ACL
/// policy enforced later, not here (this struct's fields' own docs, `PLAN.md`
/// M4 §4.1 #5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForwardSpec {
    /// `-L` or `-R`. Defaults to [`ForwardDirection::Local`] from
    /// [`parse_forward_spec`] alone — see that type's doc.
    pub direction: ForwardDirection,
    /// The `[bind:]` prefix, when present. `None` means the caller-side
    /// default (loopback) applies — which side's default (client listener
    /// vs. host listener) and whether a non-default bind is even allowed
    /// is policy this parser does not decide.
    pub bind: Option<String>,
    /// The `listen_port` component: `1..=65535`.
    pub listen_port: u16,
    /// The `host` component: a bracket-stripped IPv6 literal, an IPv4
    /// literal, a DNS-shaped hostname, or `"*"`.
    pub host: String,
    /// The `host_port` component: `1..=65535`.
    pub host_port: u16,
}

/// One colon-delimited token of a forward spec, tagged with whether it was
/// written inside `[...]` brackets (only legal for an IPv6 literal) — the
/// distinction the validators below need but plain string splitting throws
/// away.
#[derive(Debug, Clone, Copy)]
enum ForwardSpecToken<'a> {
    Plain(&'a str),
    Bracketed(&'a str),
}

impl<'a> ForwardSpecToken<'a> {
    /// The token's text with any surrounding brackets already stripped.
    fn inner(self) -> &'a str {
        match self {
            ForwardSpecToken::Plain(s) | ForwardSpecToken::Bracketed(s) => s,
        }
    }
}

/// Split a forward spec into its colon-delimited tokens, treating a
/// `[...]`-bracketed run as one token even though its contents (an IPv6
/// literal) themselves contain colons. Returns `None` on any malformed
/// bracket/colon structure (unmatched `[`/`]`, an empty token, a stray `[`
/// or `]` inside a plain token, or a trailing separator) — never panics.
fn tokenize_forward_spec(spec: &str) -> Option<Vec<ForwardSpecToken<'_>>> {
    if spec.is_empty() {
        return None;
    }
    let mut tokens = Vec::new();
    let bytes = spec.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    loop {
        if i >= len {
            // Reached here only via a trailing ':' with nothing after it —
            // every other path `break`s once the final token is consumed.
            return None;
        }
        if bytes[i] == b'[' {
            let close_rel = spec[i + 1..].find(']')?;
            let close = i + 1 + close_rel;
            let inner = &spec[i + 1..close];
            if inner.is_empty() {
                return None;
            }
            tokens.push(ForwardSpecToken::Bracketed(inner));
            i = close + 1;
            if i == len {
                break;
            }
            if bytes[i] != b':' {
                return None;
            }
            i += 1;
        } else {
            match spec[i..].find(':') {
                Some(rel) => {
                    let tok = &spec[i..i + rel];
                    if tok.is_empty() || tok.contains(['[', ']']) {
                        return None;
                    }
                    tokens.push(ForwardSpecToken::Plain(tok));
                    i += rel + 1;
                }
                None => {
                    let tok = &spec[i..];
                    if tok.is_empty() || tok.contains(['[', ']']) {
                        return None;
                    }
                    tokens.push(ForwardSpecToken::Plain(tok));
                    break;
                }
            }
        }
    }
    Some(tokens)
}

/// Shape of a `bind`/`host` token: a bracketed token must be a valid IPv6
/// literal; a plain token is a `1..=253`-byte run of
/// `[A-Za-z0-9._-]`, or the bare wildcard `"*"`.
fn valid_forward_host_token(tok: ForwardSpecToken<'_>) -> bool {
    match tok {
        ForwardSpecToken::Bracketed(s) => s.parse::<std::net::Ipv6Addr>().is_ok(),
        ForwardSpecToken::Plain(s) => {
            !s.is_empty()
                && s.len() <= 253
                && (s == "*"
                    || s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
        }
    }
}

/// Parse a `1..=65535` port from a plain (never bracketed) token. Rejects
/// `"0"` and anything `> 65535` (including `"65536"`) by construction: both
/// fail to fit a nonzero `u16`.
fn parse_forward_port(raw: &str) -> Option<u16> {
    match raw.parse::<u16>() {
        Ok(0) | Err(_) => None,
        Ok(port) => Some(port),
    }
}

/// Parse a `-L`/`-R` forward spec: `[bind:]listen_port:host:host_port`
/// (`docs/CLI.md` §6.9), e.g. `"8080:localhost:3000"` or
/// `"[::1]:8080:localhost:3000"`. Pure grammar/shape parsing — sans-IO, no
/// policy: a non-loopback `bind` parses `Ok` exactly like a loopback one,
/// because whether a non-loopback `-R` bind is *allowed* is host-side ACL
/// policy decided in a later milestone step, not something this parser can
/// or should know (`PLAN.md` M4 §4.1 #5). The returned [`ForwardSpec`]'s
/// `direction` is always [`ForwardDirection::Local`] — set it explicitly
/// after parsing when the caller is handling `-R` (see that field's doc).
///
/// Returns [`Error`] with [`ErrorCode::InvalidArgument`] for anything that
/// does not fit the grammar: not exactly 3 or 4 colon-separated parts, a
/// port outside `1..=65535`, an empty or malformed host/bind, unmatched
/// `[`/`]`, or a bracketed listen/host port.
pub fn parse_forward_spec(spec: &str) -> Result<ForwardSpec, Error> {
    fn invalid(detail: impl std::fmt::Display) -> Error {
        Error::from_code(ErrorCode::InvalidArgument, detail.to_string())
    }

    let tokens = tokenize_forward_spec(spec)
        .ok_or_else(|| invalid(format!("malformed forward spec {spec:?}")))?;

    let (bind_tok, listen_tok, host_tok, host_port_tok) = match tokens.as_slice() {
        [listen, host, host_port] => (None, *listen, *host, *host_port),
        [bind, listen, host, host_port] => (Some(*bind), *listen, *host, *host_port),
        other => {
            return Err(invalid(format!(
                "expected 3 or 4 colon-separated parts in {spec:?}, found {}",
                other.len()
            )));
        }
    };

    if let Some(tok) = bind_tok
        && !valid_forward_host_token(tok)
    {
        return Err(invalid(format!(
            "invalid bind host {:?} in {spec:?}",
            tok.inner()
        )));
    }
    if !valid_forward_host_token(host_tok) {
        return Err(invalid(format!(
            "invalid host {:?} in {spec:?}",
            host_tok.inner()
        )));
    }
    let ForwardSpecToken::Plain(listen_raw) = listen_tok else {
        return Err(invalid(format!(
            "listen port must not be bracketed in {spec:?}"
        )));
    };
    let ForwardSpecToken::Plain(host_port_raw) = host_port_tok else {
        return Err(invalid(format!(
            "host port must not be bracketed in {spec:?}"
        )));
    };
    let listen_port = parse_forward_port(listen_raw)
        .ok_or_else(|| invalid(format!("invalid listen port {listen_raw:?} in {spec:?}")))?;
    let host_port = parse_forward_port(host_port_raw)
        .ok_or_else(|| invalid(format!("invalid host port {host_port_raw:?} in {spec:?}")))?;

    Ok(ForwardSpec {
        direction: ForwardDirection::default(),
        bind: bind_tok.map(|t| t.inner().to_string()),
        listen_port,
        host: host_tok.inner().to_string(),
        host_port,
    })
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
    /// The requested attach mode. `None` when the field is unset
    /// (`ATTACH_MODE_UNSPECIFIED`, the proto3 default) or unknown to this
    /// build — treat both as `INVALID_ARGUMENT`, never as RW: the writer
    /// lease is only ever requested by an explicit `ATTACH_MODE_RW`.
    pub fn attach_mode(&self) -> Option<AttachMode> {
        match AttachMode::try_from(self.mode) {
            Ok(AttachMode::Unspecified) | Err(_) => None,
            Ok(mode) => Some(mode),
        }
    }

    /// `true` only for an explicit `ATTACH_MODE_RW` — the single value that
    /// asks for the writer lease.
    pub fn wants_write(&self) -> bool {
        self.attach_mode() == Some(AttachMode::Rw)
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

    fn arb_reverse_registration() -> impl Strategy<Value = ReverseRegistration> {
        (
            "[a-zA-Z0-9._-]{0,64}",
            proptest::collection::vec("[a-z.0-9]{1,16}", 0..4),
        )
            .prop_map(|(offered_name, capabilities)| ReverseRegistration {
                offered_name,
                capabilities,
            })
    }

    fn arb_hello() -> impl Strategy<Value = Hello> {
        (
            proptest::collection::vec(any::<u32>(), 0..4),
            ".{0,32}",
            proptest::collection::vec("[a-z.0-9]{1,16}", 0..4),
            proptest::option::of(arb_reverse_registration()),
        )
            .prop_map(|(versions, device_name, capabilities, reverse)| Hello {
                versions,
                device_name,
                capabilities,
                reverse,
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

    // -- tunnel control (M4) --

    fn arb_forward_id() -> impl Strategy<Value = String> {
        "[A-Za-z0-9_-]{1,64}"
    }

    fn arb_remote_forward_open() -> impl Strategy<Value = RemoteForwardOpen> {
        (".{0,64}", any::<u32>(), ".{0,64}", any::<u32>()).prop_map(
            |(bind_host, bind_port, forward_host, forward_port)| RemoteForwardOpen {
                bind_host,
                bind_port,
                forward_host,
                forward_port,
            },
        )
    }

    fn arb_remote_forward_opened() -> impl Strategy<Value = RemoteForwardOpened> {
        (arb_forward_id(), any::<u32>()).prop_map(|(forward_id, actual_port)| RemoteForwardOpened {
            forward_id,
            actual_port,
        })
    }

    fn arb_remote_forward_close() -> impl Strategy<Value = RemoteForwardClose> {
        arb_forward_id().prop_map(|forward_id| RemoteForwardClose { forward_id })
    }

    fn arb_connect_result() -> impl Strategy<Value = ConnectResult> {
        (
            any::<bool>(),
            "(|CONNECTION_FAILED|PERMISSION_DENIED)",
            ".{0,64}",
        )
            .prop_map(|(ok, code, message)| ConnectResult { ok, code, message })
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
            // Any i32: prost keeps unknown enum values in the raw field, so
            // out-of-range modes must round-trip too.
            any::<i32>(),
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
            any::<u64>(),
        )
            .prop_map(
                |(ticket, new_resume_token, replay_from, writer_lease, expires_at, input_seq)| {
                    SessionAttached {
                        ticket,
                        new_resume_token,
                        replay_from,
                        writer_lease,
                        expires_at,
                        input_seq,
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
            (
                proptest::collection::vec(arb_session_read_event(), 0..4),
                any::<u64>(),
                any::<u64>(),
            )
                .prop_map(|(events, next_after, next_ctl_after)| {
                    response::Body::SessionReadResult(SessionReadResult {
                        events,
                        next_after,
                        next_ctl_after,
                    })
                }),
            proptest::collection::vec(arb_session_info(), 0..4).prop_map(|sessions| {
                response::Body::SessionListResult(SessionListResult { sessions })
            }),
            arb_session_info().prop_map(response::Body::SessionInfo),
            any::<u64>().prop_map(|bytes_written| {
                response::Body::SessionWritten(SessionWritten { bytes_written })
            }),
            (any::<u32>(), any::<u32>()).prop_map(|(cols, rows)| response::Body::SessionResized(
                SessionResized { cols, rows }
            )),
            any::<u64>()
                .prop_map(|final_seq| response::Body::SessionClosed(SessionClosed { final_seq })),
            arb_remote_forward_opened().prop_map(response::Body::RfwdOpened),
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
            (
                arb_session_id(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
            )
                .prop_map(|(session_id, after, max_bytes, wait_ms, ctl_after)| {
                    Body::SessionRead(SessionRead {
                        session_id,
                        after,
                        max_bytes,
                        wait_ms,
                        ctl_after,
                    })
                }),
            (arb_session_id(), arb_bytes(64)).prop_map(|(session_id, data)| Body::SessionWrite(
                SessionWrite { session_id, data }
            )),
            arb_exec_start().prop_map(Body::ExecStart),
            arb_remote_forward_open().prop_map(Body::RfwdOpen),
            arb_remote_forward_close().prop_map(Body::RfwdClose),
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

    /// `decode(encode(m)) == m`: the frame round-trips to an equal message.
    ///
    /// This does *not* also assert `encode(decode(b)) == b` (canonical
    /// encoding) the way `local::tests::roundtrip_and_canonical` does — some
    /// `qsh.wire.v1` messages carry a `map<string, string>` field
    /// (`SessionOpen.env`, `ExecStart.env`), and prost's `HashMap` field
    /// encoding order is a function of the map's internal bucket layout, not
    /// wire order, so two maps with identical contents but different
    /// insertion histories can legitimately re-encode to different (but
    /// semantically equal) bytes. Canonical encoding is asserted separately,
    /// scoped to the map-free messages that actually need it — see
    /// `hello_encoding_is_canonical` below.
    fn roundtrip_via_frame<M: Message + Default + PartialEq + std::fmt::Debug>(m: &M, max: usize) {
        let wire = encode_framed(m, max).unwrap();
        let mut dec = FrameDecoder::new(max);
        dec.push(&wire);
        let payload = dec.next_frame().unwrap().expect("one complete frame");
        assert_eq!(dec.next_frame().unwrap(), None, "no trailing bytes");
        let back: M = decode_msg(&payload).unwrap();
        assert_eq!(&back, m, "roundtrip: decode(encode(m)) == m");
    }

    /// `encode(decode(b)) == b` for a valid `b`: re-encoding what we just
    /// decoded reproduces the exact bytes, not merely an equivalent message.
    /// `Hello`/`ReverseRegistration` carry no map field, so this holds
    /// (unlike `ControlMessage` in general — see `roundtrip_via_frame`).
    fn assert_canonical_via_frame<M: Message + Default + PartialEq + std::fmt::Debug>(
        m: &M,
        max: usize,
    ) {
        let wire = encode_framed(m, max).unwrap();
        let mut dec = FrameDecoder::new(max);
        dec.push(&wire);
        let payload = dec.next_frame().unwrap().expect("one complete frame");
        let back: M = decode_msg(&payload).unwrap();
        let re = encode_framed(&back, max).unwrap();
        assert_eq!(re, wire, "canonical: encode(decode(b)) == b");
    }

    proptest! {
        #[test]
        fn control_message_roundtrips(m in arb_control()) {
            roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
        }

        /// `Hello` (including the M3 `reverse` field) is map-free, so unlike
        /// `ControlMessage` in general it owes canonical encoding too
        /// (`docs/design/testing.md` L0).
        #[test]
        fn hello_encoding_is_canonical(m in arb_hello()) {
            let ctl = ControlMessage::new(0, control_message::Body::Hello(m));
            assert_canonical_via_frame(&ctl, CONTROL_FRAME_MAX);
        }

        #[test]
        fn stream_header_roundtrips(m in arb_stream_header()) {
            roundtrip_via_frame(&m, DATA_FRAME_MAX);
        }

        // -- M4 tunnel messages (`docs/design/testing.md` L0): `decode(encode(m))
        // == m` plus canonical encoding for each — none of the four carry a
        // map field, so (unlike `ControlMessage` in general) canonical
        // encoding holds directly, the same reasoning as
        // `hello_encoding_is_canonical` above. --

        #[test]
        fn remote_forward_open_roundtrips_and_is_canonical(m in arb_remote_forward_open()) {
            roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
            assert_canonical_via_frame(&m, CONTROL_FRAME_MAX);
        }

        #[test]
        fn remote_forward_opened_roundtrips_and_is_canonical(m in arb_remote_forward_opened()) {
            roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
            assert_canonical_via_frame(&m, CONTROL_FRAME_MAX);
        }

        #[test]
        fn remote_forward_close_roundtrips_and_is_canonical(m in arb_remote_forward_close()) {
            roundtrip_via_frame(&m, CONTROL_FRAME_MAX);
            assert_canonical_via_frame(&m, CONTROL_FRAME_MAX);
        }

        #[test]
        fn connect_result_roundtrips_and_is_canonical(m in arb_connect_result()) {
            roundtrip_via_frame(&m, DATA_FRAME_MAX);
            assert_canonical_via_frame(&m, DATA_FRAME_MAX);
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
            let _ = decode_msg::<RemoteForwardOpen>(&bytes);
            let _ = decode_msg::<RemoteForwardOpened>(&bytes);
            let _ = decode_msg::<RemoteForwardClose>(&bytes);
            let _ = decode_msg::<ConnectResult>(&bytes);
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

    /// The allocation-bound guarantee extends to the new M3 message: a
    /// `Hello.reverse` carrying an oversize `ReverseRegistration` is
    /// refused by the same `CONTROL_FRAME_MAX` cap `encode_control` already
    /// enforces for every other control message — no new bypass was opened
    /// by adding the field.
    #[test]
    fn hello_with_oversize_reverse_registration_rejected_over_frame_cap() {
        let msg = ControlMessage::new(
            1,
            control_message::Body::Hello(Hello {
                versions: vec![0],
                device_name: "hermes".into(),
                capabilities: vec![],
                reverse: Some(ReverseRegistration {
                    offered_name: "x".into(),
                    capabilities: vec!["x".repeat(CONTROL_FRAME_MAX)],
                }),
            }),
        );
        assert!(matches!(
            encode_control(&msg),
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
            let expected = ChunkTooLarge {
                len: SESSION_CHUNK_MAX + 1,
                max: SESSION_CHUNK_MAX,
            };
            assert_eq!(
                encode_session_frame(&frame),
                Err(WireEncodeError::ChunkTooLarge(expected))
            );
            // The receiver-side check reports the same violation on a
            // frame that arrived without passing through our encoder.
            assert_eq!(frame.validate(), Err(expected));
        }
    }

    #[test]
    fn decoded_over_cap_chunks_are_rejected_by_validate() {
        // A peer that bypasses our encoder can put up to DATA_FRAME_MAX /
        // CONTROL_FRAME_MAX in a chunk; `validate()` is what bounds it.
        let frame = SessionFrame::output(0, vec![0u8; SESSION_CHUNK_MAX + 1]);
        let raw = encode_framed(&frame, DATA_FRAME_MAX).unwrap();
        let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
        dec.push(&raw);
        let payload = dec.next_frame().unwrap().unwrap();
        let back: SessionFrame = decode_msg(&payload).unwrap();
        assert!(back.validate().is_err());

        let write = SessionWrite {
            session_id: "01K0SESSION".into(),
            data: vec![0u8; SESSION_CHUNK_MAX + 1],
        };
        let raw = encode_framed(&write, CONTROL_FRAME_MAX).unwrap();
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&raw);
        let payload = dec.next_frame().unwrap().unwrap();
        let back: SessionWrite = decode_msg(&payload).unwrap();
        assert!(back.validate().is_err());
        assert!(
            SessionWrite {
                data: vec![0u8; SESSION_CHUNK_MAX],
                ..write
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn session_read_result_over_cap_output_is_rejected_at_encode() {
        let m = ControlMessage::response(
            1,
            response::Body::SessionReadResult(SessionReadResult {
                events: vec![SessionReadEvent::from_body(
                    session_read_event::Body::Output(Output {
                        sequence: 0,
                        data: vec![0u8; SESSION_CHUNK_MAX + 1],
                    }),
                )],
                ..Default::default()
            }),
        );
        assert!(matches!(
            encode_control(&m),
            Err(WireEncodeError::ChunkTooLarge(_))
        ));
    }

    #[test]
    fn full_limit_session_read_result_fits_one_control_frame() {
        // SESSION_READ_MAX_BYTES of Output payload, split into max-size
        // chunks, plus interleaved control entries, must encode under
        // CONTROL_FRAME_MAX — otherwise a legal `limit_bytes` could make the
        // host unable to form a reply.
        const { assert!(SESSION_READ_MAX_BYTES.is_multiple_of(SESSION_CHUNK_MAX)) };
        let mut events = Vec::new();
        for i in 0..(SESSION_READ_MAX_BYTES / SESSION_CHUNK_MAX) {
            events.push(SessionReadEvent::from_body(
                session_read_event::Body::Output(Output {
                    sequence: u64::MAX - i as u64,
                    data: vec![0xffu8; SESSION_CHUNK_MAX],
                }),
            ));
            events.push(SessionReadEvent::from_body(
                session_read_event::Body::WriterChanged(WriterChanged {
                    new_writer: Some("device:".to_string() + &"x".repeat(200)),
                    seq: u64::MAX,
                }),
            ));
        }
        events.push(SessionReadEvent::from_body(session_read_event::Body::Exit(
            Exit {
                final_seq: u64::MAX,
                exit_code: i32::MIN,
                signal: Some("SIGKILL".into()),
            },
        )));
        let m = ControlMessage::response(
            u64::MAX,
            response::Body::SessionReadResult(SessionReadResult {
                events,
                ..Default::default()
            }),
        );
        assert!(encode_control(&m).is_ok());
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
    fn attach_mode_unknown_or_unset_is_none_not_rw() {
        // Unknown value.
        let a = SessionAttach {
            mode: 42,
            ..Default::default()
        };
        assert_eq!(a.attach_mode(), None);
        assert!(!a.wants_write());
        // Unset field (proto3 default 0 = ATTACH_MODE_UNSPECIFIED): a client
        // that forgets `mode` must not be granted the writer lease.
        let a = SessionAttach::default();
        assert_eq!(a.mode, 0);
        assert_eq!(a.attach_mode(), None);
        assert!(!a.wants_write());
        // Only an explicit RW asks for the lease.
        let a = SessionAttach {
            mode: AttachMode::Rw as i32,
            ..Default::default()
        };
        assert_eq!(a.attach_mode(), Some(AttachMode::Rw));
        assert!(a.wants_write());
        let a = SessionAttach {
            mode: AttachMode::Ro as i32,
            ..Default::default()
        };
        assert_eq!(a.attach_mode(), Some(AttachMode::Ro));
        assert!(!a.wants_write());
    }

    #[test]
    fn local_capabilities_advertise_exactly_what_is_implemented() {
        assert!(LOCAL_CAPABILITIES.contains(&CAP_EXEC));
        assert!(LOCAL_CAPABILITIES.contains(&CAP_SESSION));
        // Resume is implemented (PLAN M2 Step 7): credential redemption,
        // replay from `last_output_seq` with a `Gap` when the ring has
        // moved past it, and input dedup across the reattach. This
        // assertion is the lockstep — flipping it back means the
        // implementation went away.
        assert!(LOCAL_CAPABILITIES.contains(&CAP_RESUME_V1));
    }

    #[test]
    fn send_priority_band_matches_protocol_md_12() {
        // control 200 > session data 100 > exec 50 > tunnel 0.
        assert_eq!(
            (
                PRIORITY_CONTROL,
                PRIORITY_SESSION_DATA,
                PRIORITY_EXEC_DATA,
                PRIORITY_TUNNEL
            ),
            (200, 100, 50, 0)
        );
        // The ordering itself, not just the values: a later re-tune must
        // keep control above session data above exec above bulk.
        let band = [
            PRIORITY_CONTROL,
            PRIORITY_SESSION_DATA,
            PRIORITY_EXEC_DATA,
            PRIORITY_TUNNEL,
        ];
        assert!(band.windows(2).all(|w| w[0] > w[1]), "band: {band:?}");
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
        // No `reverse` field set: encoding is byte-for-byte identical to
        // the pre-M3 wire format. This is the mechanical proof that adding
        // `Hello.reverse` (M3, filling the tag `Hello` reserved for it) is
        // additive — an old Hello re-encodes to exactly these bytes, field
        // 4 simply never appears when unset. If this assertion ever needs
        // to change, the wire format changed and that requires a
        // deliberate `qsh/2` decision, not a test edit (PLAN.md M3 Step 1).
        let msg = ControlMessage::new(
            1,
            control_message::Body::Hello(Hello {
                versions: vec![0],
                device_name: "hermes".into(),
                capabilities: vec!["exec".into()],
                reverse: None,
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
    fn golden_hello_with_reverse_frame() {
        // New M3 golden: a Hello carrying `reverse` (a target registering
        // itself). Paired with `golden_hello_frame` above — that one pins
        // the additive *absence* of the field, this one pins its
        // *presence*, both as checked-in bytes.
        let msg = ControlMessage::new(
            1,
            control_message::Body::Hello(Hello {
                versions: vec![0],
                device_name: "hermes".into(),
                capabilities: vec!["exec".into()],
                reverse: Some(ReverseRegistration {
                    offered_name: "personal-mac".into(),
                    capabilities: vec![],
                }),
            }),
        );
        let wire = encode_control(&msg).unwrap();
        assert_eq!(
            hex(&wire),
            "0000002508015221" // frame len 37 | request_id=1 | field 10 (Hello) len 33
                .to_owned()
                + "0a0100" // versions: packed [0]
                + "12066865726d6573" // device_name "hermes"
                + "1a0465786563" // capabilities ["exec"]
                + "220e" // field 4 (ReverseRegistration) len 14
                + "0a0c706572736f6e616c2d6d6163" // offered_name "personal-mac" (capabilities empty, omitted)
        );
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    // ---- valid_host_name --------------------------------------------

    #[test]
    fn valid_host_name_boundary_table() {
        // Empty string: too short.
        assert!(!valid_host_name(""));
        // Exactly 64 bytes: allowed; 65 bytes: refused.
        assert!(valid_host_name(&"a".repeat(64)));
        assert!(!valid_host_name(&"a".repeat(65)));
        // Path-traversal-shaped input: `/` is not in the allowed alphabet,
        // so any name containing it is refused regardless of the dots.
        assert!(!valid_host_name("../"));
        assert!(!valid_host_name("/"));
        // Two bare dots *are* in-alphabet on their own (`.` is allowed) —
        // shape validity does not imply the name is semantically sensible,
        // only that its bytes are in the allowed set and length range.
        assert!(valid_host_name(".."));
        // Unicode: multi-byte characters fall outside the ASCII alphabet.
        assert!(!valid_host_name("café"));
        assert!(!valid_host_name("主机"));
        // Other disallowed separators.
        assert!(!valid_host_name("host/name"));
        assert!(!valid_host_name("host name"));
        assert!(!valid_host_name("host@name"));
        // Every allowed byte, exhaustively.
        for b in (b'A'..=b'Z').chain(b'a'..=b'z').chain(b'0'..=b'9') {
            let s = (b as char).to_string();
            assert!(valid_host_name(&s), "byte {b} ({s:?}) should be allowed");
        }
        for c in ['.', '_', '-'] {
            assert!(valid_host_name(&c.to_string()));
        }
    }

    // ---- valid_forward_id ------------------------------------------------

    #[test]
    fn valid_forward_id_boundary_table() {
        // Empty: too short.
        assert!(!valid_forward_id(""));
        // Exactly 64 bytes: allowed; 65 bytes: refused.
        assert!(valid_forward_id(&"a".repeat(64)));
        assert!(!valid_forward_id(&"a".repeat(65)));
        // Unlike `valid_host_name`, `.` is *not* in the alphabet — a
        // `forward_id` is an opaque URL-safe token, not a display name.
        assert!(!valid_forward_id("."));
        assert!(!valid_forward_id("fwd.01"));
        // Path-traversal-shaped / separator input stays refused.
        assert!(!valid_forward_id("../"));
        assert!(!valid_forward_id("/"));
        assert!(!valid_forward_id("fwd/id"));
        assert!(!valid_forward_id("fwd id"));
        // Unicode falls outside the ASCII alphabet.
        assert!(!valid_forward_id("café"));
        // Every allowed byte, exhaustively.
        for b in (b'A'..=b'Z').chain(b'a'..=b'z').chain(b'0'..=b'9') {
            let s = (b as char).to_string();
            assert!(valid_forward_id(&s), "byte {b} ({s:?}) should be allowed");
        }
        for c in ['_', '-'] {
            assert!(valid_forward_id(&c.to_string()));
        }
        // A realistic-shaped id.
        assert!(valid_forward_id("fwd_01K0EXAMPLE-token"));
    }

    // ---- parse_forward_spec -----------------------------------------------

    #[test]
    fn parse_forward_spec_three_part_has_no_bind() {
        let spec = parse_forward_spec("8080:localhost:3000").unwrap();
        assert_eq!(spec.direction, ForwardDirection::Local);
        assert_eq!(spec.bind, None);
        assert_eq!(spec.listen_port, 8080);
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.host_port, 3000);
    }

    #[test]
    fn parse_forward_spec_four_part_has_bind() {
        let spec = parse_forward_spec("0.0.0.0:8080:localhost:3000").unwrap();
        assert_eq!(spec.bind.as_deref(), Some("0.0.0.0"));
        assert_eq!(spec.listen_port, 8080);
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.host_port, 3000);
    }

    #[test]
    fn parse_forward_spec_ipv6_bind_brackets() {
        let spec = parse_forward_spec("[::1]:8080:localhost:3000").unwrap();
        assert_eq!(spec.bind.as_deref(), Some("::1"));
        assert_eq!(spec.listen_port, 8080);
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.host_port, 3000);
    }

    #[test]
    fn parse_forward_spec_ipv6_host_brackets_without_bind() {
        // Three logical parts even though the host segment is bracketed:
        // token *count* (not bracket presence) decides bind-vs-no-bind.
        let spec = parse_forward_spec("8080:[::1]:3000").unwrap();
        assert_eq!(spec.bind, None);
        assert_eq!(spec.listen_port, 8080);
        assert_eq!(spec.host, "::1");
        assert_eq!(spec.host_port, 3000);
    }

    #[test]
    fn parse_forward_spec_ipv6_bind_and_host_brackets() {
        let spec = parse_forward_spec("[::1]:8080:[::2]:3000").unwrap();
        assert_eq!(spec.bind.as_deref(), Some("::1"));
        assert_eq!(spec.host, "::2");
    }

    #[test]
    fn parse_forward_spec_rejects_port_zero_and_65536() {
        for spec in ["0:localhost:3000", "8080:localhost:0"] {
            assert_eq!(
                parse_forward_spec(spec).unwrap_err().error_code(),
                ErrorCode::InvalidArgument,
                "spec {spec:?}"
            );
        }
        for spec in ["65536:localhost:3000", "8080:localhost:65536"] {
            assert_eq!(
                parse_forward_spec(spec).unwrap_err().error_code(),
                ErrorCode::InvalidArgument,
                "spec {spec:?}"
            );
        }
        // The boundary values immediately on either side of the rejected
        // ones are accepted.
        assert!(parse_forward_spec("1:localhost:65535").is_ok());
    }

    #[test]
    fn parse_forward_spec_rejects_empty_host() {
        for spec in ["8080::3000", "8080:[]:3000", ":8080:localhost:3000"] {
            assert_eq!(
                parse_forward_spec(spec).unwrap_err().error_code(),
                ErrorCode::InvalidArgument,
                "spec {spec:?}"
            );
        }
    }

    #[test]
    fn parse_forward_spec_accepts_non_loopback_bind_shape_only() {
        // The parser knows no policy: a non-loopback bind is shape-valid.
        // Loopback-only enforcement is host-side (PLAN.md M4 §4.1 #5,
        // implemented in a later milestone step, not here).
        let spec = parse_forward_spec("0.0.0.0:8080:localhost:3000").unwrap();
        assert_eq!(spec.bind.as_deref(), Some("0.0.0.0"));
        let spec = parse_forward_spec("203.0.113.5:8080:localhost:3000").unwrap();
        assert_eq!(spec.bind.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn parse_forward_spec_rejects_garbage() {
        for spec in [
            "",
            "garbage",
            "8080",
            "8080:localhost",
            "a:b:8080:localhost:3000",
            "8080:localhost:3000:extra",
            "8080:localhost:3000:",
            ":",
            "[::1:8080:localhost:3000",
            "[]:8080:localhost:3000",
            "8080:localhost:abc",
            "abc:localhost:3000",
            "[8080]:localhost:3000",
            "8080:local host:3000",
        ] {
            assert_eq!(
                parse_forward_spec(spec).unwrap_err().error_code(),
                ErrorCode::InvalidArgument,
                "spec {spec:?} should be rejected"
            );
        }
    }

    #[test]
    fn parse_forward_spec_direction_defaults_local_caller_sets_remote() {
        let spec = parse_forward_spec("8080:localhost:3000").unwrap();
        assert_eq!(spec.direction, ForwardDirection::Local);
        let spec = ForwardSpec {
            direction: ForwardDirection::Remote,
            ..spec
        };
        assert_eq!(spec.direction, ForwardDirection::Remote);
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

    // ---- golden vectors: M4 tags 40/41/4 realized (mechanical proof the
    // realization is additive — the golden tests above for Hello, the
    // plain error Response, SessionOpen and the SessionEvent-carrying
    // ControlMessage are unchanged by this file's edits and still pass
    // byte-for-byte, since none of them touch tags 40/41/4; these four are
    // the new tags' own golden vectors) --------------------------------

    #[test]
    fn golden_remote_forward_open_frame() {
        let msg = ControlMessage::new(
            4,
            control_message::Body::RfwdOpen(RemoteForwardOpen {
                bind_host: "0.0.0.0".into(),
                bind_port: 8080,
                forward_host: "localhost".into(),
                forward_port: 3000,
            }),
        );
        let wire = encode_control(&msg).unwrap();
        assert_eq!(
            hex(&wire),
            "0000001f0804c2021a" // frame len 31 | request_id=4 | field 40 (rfwd_open) len 26
                .to_owned()
                + "0a07302e302e302e30" // bind_host "0.0.0.0"
                + "10903f" // bind_port 8080
                + "1a096c6f63616c686f7374" // forward_host "localhost"
                + "20b817" // forward_port 3000
        );
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn golden_remote_forward_close_frame() {
        let msg = ControlMessage::new(
            5,
            control_message::Body::RfwdClose(RemoteForwardClose {
                forward_id: "fwd_01K0EXAMPLE".into(),
            }),
        );
        let wire = encode_control(&msg).unwrap();
        assert_eq!(
            hex(&wire),
            "000000160805ca0211" // frame len 22 | request_id=5 | field 41 (rfwd_close) len 17
                .to_owned()
                + "0a0f6677645f30314b304558414d504c45" // forward_id "fwd_01K0EXAMPLE"
        );
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn golden_remote_forward_opened_response_frame() {
        let msg = ControlMessage::response(
            6,
            response::Body::RfwdOpened(RemoteForwardOpened {
                forward_id: "fwd_01K0EXAMPLE".into(),
                actual_port: 8080,
            }),
        );
        let wire = encode_control(&msg).unwrap();
        assert_eq!(
            hex(&wire),
            "0000001a08065a16" // frame len 26 | request_id=6 | field 11 (Response) len 22
                .to_owned()
                + "2214" // field 4 (rfwd_opened) len 20
                + "0a0f6677645f30314b304558414d504c45" // forward_id "fwd_01K0EXAMPLE"
                + "10903f" // actual_port 8080
        );
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        let back: ControlMessage = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn golden_connect_result_ok_frame() {
        let msg = ConnectResult {
            ok: true,
            code: String::new(),
            message: String::new(),
        };
        let wire = encode_framed(&msg, DATA_FRAME_MAX).unwrap();
        assert_eq!(
            hex(&wire),
            "00000002" // frame len 2
                .to_owned()
                + "0801" // ok = true
        );
        let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
        dec.push(&wire);
        let back: ConnectResult = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn golden_connect_result_err_frame() {
        let msg = ConnectResult {
            ok: false,
            code: "CONNECTION_FAILED".into(),
            message: "dial refused".into(),
        };
        let wire = encode_framed(&msg, DATA_FRAME_MAX).unwrap();
        assert_eq!(
            hex(&wire),
            "00000021" // frame len 33 | `ok` omitted (proto3 default false)
                .to_owned()
                + "1211434f4e4e454354494f4e5f4641494c4544" // code "CONNECTION_FAILED"
                + "1a0c6469616c2072656675736564" // message "dial refused"
        );
        let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
        dec.push(&wire);
        let back: ConnectResult = decode_msg(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
