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

/// Capability string advertised by peers whose `TCP_CONNECT` dialer honors
/// [`StreamHeader::deny_host_local`] (ADR-0019 decision 3): when that field
/// is set, every resolved destination address is checked against the
/// host-local categories before `connect`, and the stream is refused
/// (`ErrorCode::PermissionDenied`) if none survive. A peer that has not
/// advertised this string silently ignores the field (proto3 default
/// `false`), so a sender must confirm the capability before ever setting it
/// — there is no fallback that filters without it.
pub const CAP_DIAL_FILTER_V1: &str = "dial-filter.v1";

/// Capability string for the remote file ops (`file.read`, `file.write`,
/// `file.list`, `file.mkdir`) and the `FILE_DATA` stream (ADR-0029). Every
/// build advertises it ([`LOCAL_CAPABILITIES`]): the host data plane exists
/// on unix and on Windows (ADR-0029 decision 23, ADR-0035 decision 26), and a
/// capability string is a promise about behaviour. A sender never emits a
/// file op to a peer that has not advertised it.
pub const CAP_FILE_V1: &str = "file.v1";

/// Capability string for [`ExecStart::shell_command`], [`ExecStart::login_shell`]
/// and [`SessionOpen::shell_command`] (ADR-0051 decision 6): the host runs a
/// command string through the account's shell. A host that predates it skips
/// the fields as unknown (proto3), so `exec` would see an empty `argv`. A
/// sender confirms the capability before setting any of the three and fails
/// `UNSUPPORTED` locally without it (`docs/design/protocol.md` §7.1).
pub const CAP_SHELL_COMMAND_V1: &str = "shell-command.v1";

/// Capability string for screen state sync (ADR-0052 decisions 2 to 6, 9;
/// `docs/design/protocol.md` §18): the host can run a terminal emulator for a
/// session and send `ScreenUpdate` on the `SESSION_DATA` stream instead of
/// `Output`, and takes `ScreenAck`. A sender sets `SessionOpen.screen` /
/// `SessionAttach.screen` and emits `ScreenAck` only when this is in the
/// negotiated set; a host never sends `ScreenUpdate` to a peer that did not
/// advertise it.
pub const CAP_SCREEN_V1: &str = "screen.v1";

/// Capability string for the QUIC DATAGRAM carrier (ADR-0052 decisions 6 to
/// 9, `docs/design/protocol.md` §18.9): this peer handles `DatagramFrame`s
/// of `ScreenUpdate`, `ScreenAck` and `Input` on the channel id of a screen
/// sync attach. Datagrams are used only when both sides advertise it and the
/// transport reports `max_datagram_size()`; every datagram message has a
/// stream twin.
pub const CAP_DATAGRAM_V1: &str = "datagram.v1";

/// Capability string for the input-reflection signal (ADR-0053 decision 3,
/// `docs/design/protocol.md` §18.12): the host sends [`ScreenEcho`] on a screen
/// sync attach and the client decodes it. A host sends it only when both
/// sides advertise this; a peer without it never sees `SessionFrame` 10 or
/// datagram kind 13.
pub const CAP_SCREEN_ECHO_V1: &str = "screen-echo.v1";

/// Capability string for hole punching (ADR-0054 decision 9,
/// `docs/design/protocol.md` §19): this peer understands `PunchRequest`,
/// `PunchOffer`, `PunchReply`, `PunchAnswer`, `RendezvousQuery` and
/// `RendezvousList` and handles them in its own role. `[punch].mode = "off"`
/// still advertises it and answers a request `UNSUPPORTED`. A peer without it
/// is never sent those messages (`protocol.md` §16.4).
pub const CAP_PUNCH_V1: &str = "punch.v1";

/// Capability string for ssh-agent forwarding (ADR-0055 decision 3,
/// `docs/design/protocol.md` §20): this peer, as host, handles
/// `agent_channel` on `SessionOpen`, `SessionAttach` and `ExecStart` and
/// opens `AGENT` streams; as client, receives them. A peer without it is
/// never sent `agent_channel` (`protocol.md` §16.4).
pub const CAP_AGENT_V1: &str = "agent.v1";

/// Length in bytes of an `agent_channel` (ADR-0055 decision 3): drawn by the
/// client from a CSPRNG and carried again as `StreamHeader.ticket` of the
/// `AGENT` stream it names.
pub const AGENT_CHANNEL_LEN: usize = 16;

/// Capabilities this build advertises in [`Hello`]. Advertised and
/// implemented stay in lockstep — a capability string is a promise about
/// behaviour, and a peer that advertises resume and then cannot replay is
/// worse than one that never claimed it. [`CAP_RESUME_V1`] joined the list
/// with the resume implementation (M2 plan Step 7 (2473c88)): the host redeems a
/// resume credential, replays from the requested offset (or opens with a
/// `Gap`), and deduplicates retransmitted input. [`CAP_DIAL_FILTER_V1`]
/// joined with the host-local dial filter (ADR-0019 decision 3): the
/// advertisement and the filter land in the same commit. [`CAP_FILE_V1`]
/// joined with the `FILE_DATA` data plane (ADR-0029 decisions 1 and 9): the
/// same commit that serves the stream advertises it. [`CAP_SHELL_COMMAND_V1`]
/// joined with the host's shell resolution (ADR-0051 decision 6). [`CAP_SCREEN_V1`]
/// joined with the host emulator's stream carrier (ADR-0052 decision 9),
/// and [`CAP_DATAGRAM_V1`] with the datagram carrier and the input copy.
/// [`CAP_SCREEN_ECHO_V1`] joined with `ScreenEcho` (ADR-0053 decision 3), and
/// [`CAP_PUNCH_V1`] with the hole-punching messages (ADR-0054 decision 9), and
/// [`CAP_AGENT_V1`] with agent forwarding (ADR-0055 decision 3). The set is
/// the same on every platform.
pub const LOCAL_CAPABILITIES: &[&str] = &[
    CAP_EXEC,
    CAP_SESSION,
    CAP_RESUME_V1,
    CAP_DIAL_FILTER_V1,
    CAP_FILE_V1,
    CAP_SHELL_COMMAND_V1,
    CAP_SCREEN_V1,
    CAP_DATAGRAM_V1,
    CAP_SCREEN_ECHO_V1,
    CAP_PUNCH_V1,
    CAP_AGENT_V1,
];

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

/// Maximum size of a single `FILE_DATA` payload chunk (the `data` field of a
/// [`FileFrame`]), 32 KiB (ADR-0029 decision 9). Enforced at encode time by
/// [`encode_file_frame`] and on receipt by [`FileFrame::validate`].
pub const FILE_CHUNK_MAX: usize = 32 * 1024;

/// Most entries one [`FileListed`] response carries (ADR-0029 decision 9).
/// A full page of 255-byte names fits one [`CONTROL_FRAME_MAX`] frame
/// (pinned by a test).
pub const FILE_LIST_PAGE_MAX: usize = 512;

/// Most entries one directory may hold for `file.list` to page through it;
/// a larger directory is `RESOURCE_EXHAUSTED` (ADR-0029 decision 9).
pub const FILE_LIST_DIR_MAX: usize = 65536;

/// Free bytes the destination filesystem must keep beyond a `file.write`'s
/// announced size, 256 MiB (ADR-0029 decision 13). A write that would leave
/// less is refused `RESOURCE_EXHAUSTED` before any temp file exists: the
/// audit writer is fail-closed, so a remote write that fills the disk the
/// audit log lives on would stop the whole host.
pub const FILE_WRITE_FREE_RESERVE: u64 = 256 * 1024 * 1024;

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
    /// A hole-punching message breaks its shape rules (ADR-0054 decision 11).
    #[error(transparent)]
    Punch(#[from] crate::punch::PunchMessageError),
    /// Frame-layer failure (unreachable in practice: `TooLarge` triggers
    /// first, but kept so callers see one error type).
    #[error(transparent)]
    Frame(#[from] FrameError),
}

fn check_chunk(len: usize) -> Result<(), ChunkTooLarge> {
    check_chunk_max(len, SESSION_CHUNK_MAX)
}

fn check_chunk_max(len: usize, max: usize) -> Result<(), ChunkTooLarge> {
    if len > max {
        return Err(ChunkTooLarge { len, max });
    }
    Ok(())
}

/// What an [`ExecStart`] asks the host to run (ADR-0051 decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecTarget<'a> {
    /// `argv`, executed directly with no shell.
    Argv,
    /// This string through the host account's shell (`shell_command`).
    ShellCommand(&'a str),
    /// The account's login shell itself (`login_shell`).
    LoginShell,
}

/// Why a shell-command request is malformed. The text never repeats the
/// command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellCommandError(pub &'static str);

impl std::fmt::Display for ShellCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ShellCommandError {}

const SHELL_COMMAND_NUL: ShellCommandError =
    ShellCommandError("shell_command must not contain NUL");

impl ExecStart {
    /// Receiver-side shape check of the three ways to say what to run:
    /// exactly one of a non-empty `argv`, `shell_command` (the empty string
    /// is a command) and `login_shell` may be given, and a command must not
    /// contain NUL. Hosts call this before the ACL decision (it depends on
    /// nothing about the caller) and answer `INVALID_ARGUMENT` on error. A
    /// request with none of the three is an empty `argv`, which the caller
    /// reports as before. A host that predates `shell-command.v1` never
    /// reaches this: it skips the fields as unknown (§16.4).
    pub fn target(&self) -> Result<Option<ExecTarget<'_>>, ShellCommandError> {
        let given = usize::from(!self.argv.is_empty())
            + usize::from(self.shell_command.is_some())
            + usize::from(self.login_shell);
        if given == 0 {
            return Ok(None);
        }
        if given > 1 {
            return Err(ShellCommandError(
                "exactly one of argv, shell_command and login_shell may be set",
            ));
        }
        Ok(Some(match &self.shell_command {
            Some(command) if command.contains('\0') => return Err(SHELL_COMMAND_NUL),
            Some(command) => ExecTarget::ShellCommand(command),
            None if self.login_shell => ExecTarget::LoginShell,
            None => ExecTarget::Argv,
        }))
    }

    /// Whether the request uses a field only `shell-command.v1` peers know.
    pub fn uses_shell_fields(&self) -> bool {
        self.shell_command.is_some() || self.login_shell
    }
}

impl SessionOpen {
    /// Receiver-side shape check of `shell_command`: it excludes a
    /// non-empty `argv` and must not contain NUL. `Ok(None)` when absent.
    pub fn shell_command_checked(&self) -> Result<Option<&str>, ShellCommandError> {
        match self.shell_command.as_deref() {
            None => Ok(None),
            Some(_) if !self.argv.is_empty() => Err(ShellCommandError(
                "argv and shell_command are mutually exclusive",
            )),
            Some(command) if command.contains('\0') => Err(SHELL_COMMAND_NUL),
            Some(command) => Ok(Some(command)),
        }
    }
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
            Some(session_frame::Body::ScreenUpdate(u)) => u.validate(),
            Some(session_frame::Body::ScreenHistory(h)) => h.validate(),
            _ => Ok(()),
        }
    }
}

/// A `ScreenEcho` named an input offset the receiver never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("screen echo names input offset {input_seq}, but only {sent} bytes were sent")]
pub struct EchoBeyondSent {
    /// The offset in the message.
    pub input_seq: u64,
    /// Input bytes the receiver has sent.
    pub sent: u64,
}

impl ScreenEcho {
    /// The tty state; a value this build does not know reads as
    /// [`TtyEcho::Unknown`] so a later additive variant never fails a decode.
    pub fn tty_echo(&self) -> TtyEcho {
        TtyEcho::try_from(self.tty).unwrap_or(TtyEcho::Unknown)
    }

    /// Receiver-side check (ADR-0053 decision 3): `input_seq` must not exceed
    /// the cumulative input offset the receiver has sent. The caller drops
    /// and counts a signal that fails, and does not close the connection.
    pub fn validate_against_sent(&self, sent: u64) -> Result<(), EchoBeyondSent> {
        if self.input_seq > sent {
            Err(EchoBeyondSent {
                input_seq: self.input_seq,
                sent,
            })
        } else {
            Ok(())
        }
    }

    /// Whether `self` is strictly ahead of `other` in `(state_num,
    /// input_seq)` order, the order a client keeps the newer of two carriers.
    pub fn is_newer_than(&self, other: &Self) -> bool {
        (self.state_num, self.input_seq) > (other.state_num, other.input_seq)
    }
}

impl ScreenHistory {
    /// Receiver-side check: the encoded message is within
    /// [`SESSION_CHUNK_MAX`], the cap [`Self::batches`] cuts to.
    pub fn validate(&self) -> Result<(), ChunkTooLarge> {
        check_chunk(prost::Message::encoded_len(self))
    }

    /// Encoded size of one entry of `lines` (tag, length, bytes).
    fn entry_len(line: &str) -> usize {
        1 + prost::encoding::encoded_len_varint(line.len() as u64) + line.len()
    }

    /// Room a `skipped` field takes at most (tag plus a 10-byte varint).
    const SKIPPED_ROOM: usize = 11;

    /// Cut `lines` (oldest first) and the `skipped` count into messages that
    /// each fit [`SESSION_CHUNK_MAX`]; `skipped` rides on the last one, after
    /// its lines. A line too large for any message is counted into `skipped`
    /// rather than dropped silently; the second value is how many.
    pub fn batches(lines: &[String], skipped: u64) -> (Vec<Self>, u64) {
        let cap = SESSION_CHUNK_MAX - Self::SKIPPED_ROOM;
        let mut out: Vec<Self> = Vec::new();
        let mut cur = Self::default();
        let mut size = 0usize;
        let mut oversize = 0u64;
        for line in lines {
            let n = Self::entry_len(line);
            if n > cap {
                // Everything after this line scrolled off later, so the
                // count it adds would be out of order if it were folded into
                // the earlier `skipped`; it is reported at the end instead.
                oversize += 1;
                continue;
            }
            if size + n > cap {
                out.push(std::mem::take(&mut cur));
                size = 0;
            }
            cur.lines.push(line.clone().into_bytes());
            size += n;
        }
        cur.skipped = skipped.saturating_add(oversize);
        if !cur.lines.is_empty() || cur.skipped > 0 {
            out.push(cur);
        }
        (out, oversize)
    }
}

impl ScreenUpdate {
    /// Receiver-side check: the part is within [`crate::screen::PART_MAX`].
    /// The numbering is checked by [`crate::screen::Reassembler::push`].
    pub fn validate(&self) -> Result<(), ChunkTooLarge> {
        check_chunk_max(self.data.len(), crate::screen::PART_MAX)
    }

    /// The parts of one encoded [`crate::screen::ScreenUpdate`] cut into
    /// slices of at most `max_part` bytes (a datagram carrier part).
    pub fn parts_sized(new_num: u64, encoded: &[u8], max_part: usize) -> Vec<Self> {
        let slices = crate::screen::split_parts_sized(encoded, max_part);
        let parts = slices.len() as u32;
        slices
            .into_iter()
            .enumerate()
            .map(|(i, data)| Self {
                new_num,
                part: i as u32,
                parts,
                data: data.to_vec(),
            })
            .collect()
    }

    /// The parts of one encoded [`crate::screen::ScreenUpdate`], in order.
    pub fn parts_of(new_num: u64, encoded: &[u8]) -> Vec<Self> {
        let slices = crate::screen::split_parts(encoded);
        let parts = slices.len() as u32;
        slices
            .into_iter()
            .enumerate()
            .map(|(i, data)| Self {
                new_num,
                part: i as u32,
                parts,
                data: data.to_vec(),
            })
            .collect()
    }
}

impl FileFrame {
    /// Receiver-side chunk check: a `data` chunk must not exceed
    /// [`FILE_CHUNK_MAX`]. The `FILE_DATA` pump calls this on every decoded
    /// frame; an over-cap chunk is a protocol violation (ADR-0029
    /// decision 9). Whether a frame is legal at its position (nothing after
    /// `end`, no requester-sent `result`) is the pump's state, not a property
    /// of one frame.
    pub fn validate(&self) -> Result<(), ChunkTooLarge> {
        match &self.body {
            Some(file_frame::Body::Data(data)) => check_chunk_max(data.len(), FILE_CHUNK_MAX),
            _ => Ok(()),
        }
    }

    /// Wrap a body variant.
    pub fn from_body(body: file_frame::Body) -> Self {
        Self { body: Some(body) }
    }

    /// `data` frame.
    pub fn data(data: Vec<u8>) -> Self {
        Self::from_body(file_frame::Body::Data(data))
    }

    /// `end` frame closing a byte sequence of `size` bytes whose BLAKE3-256
    /// digest is `blake3`.
    pub fn end(size: u64, blake3: Vec<u8>) -> Self {
        Self::from_body(file_frame::Body::End(FileEnd { size, blake3 }))
    }

    /// `result` frame (host to requester on `file.write` only).
    pub fn result(
        ok: bool,
        code: impl Into<String>,
        message: impl Into<String>,
        overwritten: bool,
    ) -> Self {
        Self::from_body(file_frame::Body::Result(FileWriteResult {
            ok,
            code: code.into(),
            message: message.into(),
            overwritten,
        }))
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
        Some(control_message::Body::PunchRequest(m)) => m.validate()?,
        Some(control_message::Body::PunchOffer(m)) => m.validate()?,
        Some(control_message::Body::Response(Response {
            body: Some(response::Body::PunchReply(m)),
        })) => m.validate()?,
        Some(control_message::Body::Response(Response {
            body: Some(response::Body::PunchAnswer(m)),
        })) => m.validate()?,
        Some(control_message::Body::Response(Response {
            body: Some(response::Body::RendezvousList(m)),
        })) => m.validate()?,
        _ => {}
    }
    encode_framed(msg, CONTROL_FRAME_MAX)
}

/// Encode an [`ExecFrame`] as one data-stream frame.
pub fn encode_exec_frame(msg: &ExecFrame) -> Result<Vec<u8>, WireEncodeError> {
    encode_framed(msg, DATA_FRAME_MAX)
}

/// Encode a [`FileFrame`] as one data-stream frame. A `data` chunk larger
/// than [`FILE_CHUNK_MAX`] is refused with [`WireEncodeError::ChunkTooLarge`]
/// before framing.
pub fn encode_file_frame(msg: &FileFrame) -> Result<Vec<u8>, WireEncodeError> {
    msg.validate()?;
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

    /// A [`Response`] carrying an [`struct@Error`], correlated to `request_id`.
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
/// *before* authorization runs (M3 plan Step 1 (2473c88)).
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
/// discipline as [`valid_host_name`] (this fn's own doc, M4 plan §4.1 (2473c88)):
/// a `forward_id` a peer sends back is never trusted until it passes this
/// check, so an oversized or oddly-charactered string a confused or hostile
/// peer echoes back can never inflate an audit record.
pub fn valid_forward_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Replace every control character except `\t` in peer-supplied prose with
/// `U+FFFD`.
///
/// For the strings the shape checks above cannot constrain: free-form text
/// a peer authored and this side may end up *displaying* — a
/// [`ConnectResult`]'s `code`/`message`, most sharply, because the
/// interactive `-L` form prints tunnel diagnostics onto a terminal it has
/// just put in raw mode. Without this a malicious or compromised host can
/// embed ANSI/OSC escape sequences in a refusal and move the operator's
/// cursor, repaint their screen, retitle their window, or forge extra
/// lines of `qsh` output.
///
/// Same rule as the CLI renderer's own `sanitize` (`crates/qsh-cli/src/
/// render/human.rs`), and deliberately the same *shape* of rule: replace,
/// never drop, so the text's length still tells the operator something was
/// there. Lives in `qsh-proto` because the escaping hazard belongs to the
/// contract string itself — `qsh-core` displays these too and may not
/// depend on `qsh-cli` (`docs/design/architecture.md` §1).
///
/// It sanitizes for *display*; it is not a validator and never widens what
/// a caller chose to print.
pub fn sanitize_peer_text(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\t' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Why [`validate_device_name`] rejected a name — never carries the
/// rejected value itself (`docs/design/protocol.md` §15.5's own "the value
/// never appears in a log line" rule extends to this type's own `Display`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeviceNameError {
    /// Empty, or more than 64 bytes when UTF-8 encoded.
    #[error("must be 1..=64 bytes")]
    Length,
    /// A control character (`char::is_control()`, tab included — a device
    /// name is a label, not formatted text).
    #[error("must not contain a control character")]
    Control,
    /// A bidi-override or bidi-isolate control (U+202A–U+202E,
    /// U+2066–U+2069, U+200E–U+200F) — none of these are `char::is_control()`,
    /// so [`Self::Control`] never catches them, yet a name built from one
    /// can visually reorder its own or its neighbor's rendering (the
    /// classic "evil.txt" RLO trick) wherever a renderer prints it next to
    /// a fingerprint or a path.
    #[error("must not contain a bidi control character")]
    Bidi,
    /// A zero-width character (U+200B–U+200D, U+2060, U+FEFF) — invisible
    /// in a terminal, so two names that render identically can compare
    /// unequal, letting one silently shadow the other under a pin.
    #[error("must not contain a zero-width character")]
    ZeroWidth,
}

/// Shape a peer-reported device name must have before pairing ever pins,
/// persists, or traces it: `1..=64` bytes, no control character
/// (`char::is_control()`, tab included), no bidi-override/isolate control,
/// no zero-width character (`docs/design/protocol.md` §15.5).
///
/// Shared by both pairing directions (`qsh-core`'s `pairing::
/// reject_control_chars`, called for `PairingProof.device_name` on the
/// responder and `PairingAccepted.device_name` on the initiator) so the two
/// call sites can never drift onto different rejection tables. Lives in
/// `qsh-proto`, not `qsh-core`, for the same reason [`valid_host_name`]
/// does: `qsh-core` may depend on `qsh-proto` but not the reverse
/// (`docs/design/architecture.md` §1), and this shape check has to run
/// before the value reaches anything `qsh-core` owns.
///
/// Deliberately does **not** check for homoglyph/confusable characters —
/// a table-driven confusable check needs a curated Unicode confusables
/// table this crate does not carry (no new crate for it, per this
/// function's own design brief), and §15.4's fingerprint pinning is
/// already the defense that matters here: two names that merely *look*
/// alike still pin under different, independently-verified fingerprints,
/// so a homoglyph name can confuse an operator's eye but never substitute
/// for the identity check itself.
pub fn validate_device_name(name: &str) -> Result<(), DeviceNameError> {
    if name.is_empty() || name.len() > 64 {
        return Err(DeviceNameError::Length);
    }
    for c in name.chars() {
        if c.is_control() {
            return Err(DeviceNameError::Control);
        }
        if matches!(c,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}'..='\u{200F}'
        ) {
            return Err(DeviceNameError::Bidi);
        }
        if matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}') {
            return Err(DeviceNameError::ZeroWidth);
        }
    }
    Ok(())
}

/// Render a forward destination as the canonical `host:port` string:
/// `"db.internal:5432"`, `"127.0.0.1:5432"`, and — the case plain
/// concatenation gets wrong — `"[::1]:5432"` for an IPv6 literal.
///
/// [`parse_forward_spec`] strips the brackets off a `[::1]` token
/// ([`ForwardSpec::host`] is "a bracket-stripped IPv6 literal"), so
/// `format!("{host}:{port}")` on an IPv6 destination produces `::1:5432`
/// — a string no reader can split back into a host and a port, and one
/// that collides with a *different* address's rendering.
///
/// This matters beyond cosmetics: the host's inline `forward.local` check
/// uses this string as its ACL **resource** and audit field, and M5's
/// policy engine will pattern-match rules against it. Ambiguity in that
/// string is ambiguity in a policy decision, so the canonical form is
/// pinned here, in the contract crate, next to the parser that produced
/// the halves.
pub fn format_host_port(host: &str, port: u16) -> String {
    // Classification, not string inspection: only something that really
    // parses as an IPv6 address needs brackets, and an already-bracketed
    // host does not re-parse (so it is left exactly as given).
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
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
/// policy enforced later, not here (this struct's fields' own docs, the M4 plan (2473c88)
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
/// or should know (M4 plan §4.1 #5 (2473c88)). The returned [`ForwardSpec`]'s
/// `direction` is always [`ForwardDirection::Local`] — set it explicitly
/// after parsing when the caller is handling `-R` (see that field's doc).
///
/// Returns [`struct@Error`] with [`ErrorCode::InvalidArgument`] for anything that
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

/// A parsed `-D` dynamic-forward spec (ADR-0019 decision 11) — the result
/// of [`parse_dynamic_spec`]. Shape-only, same discipline as
/// [`ForwardSpec`]: whether a non-loopback `bind` is allowed is host-side
/// policy decided later (ADR-0019 decision 9), not here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DynamicSpec {
    /// The `[bind:]` prefix, when present. `None` means the caller-side
    /// loopback default applies — same convention as [`ForwardSpec::bind`].
    pub bind: Option<String>,
    /// The `listen_port` component: `1..=65535`.
    pub listen_port: u16,
}

/// Parse a `-D` dynamic-forward spec: `[bind:]listen_port` (ADR-0019
/// decision 11), e.g. `"1080"` or `"127.0.0.1:1080"`. Reuses the same
/// internal tokenizer [`parse_forward_spec`] uses — a 1-or-2-token variant
/// of that function's 3-or-4-token grammar, since a dynamic forward has no
/// fixed dial target to encode.
///
/// Returns [`struct@Error`] with [`ErrorCode::InvalidArgument`] for anything
/// that does not fit the grammar: not exactly 1 or 2 colon-separated parts,
/// a port outside `1..=65535`, a malformed bind, unmatched `[`/`]`, or a
/// bracketed listen port.
pub fn parse_dynamic_spec(spec: &str) -> Result<DynamicSpec, Error> {
    fn invalid(detail: impl std::fmt::Display) -> Error {
        Error::from_code(ErrorCode::InvalidArgument, detail.to_string())
    }

    let tokens = tokenize_forward_spec(spec)
        .ok_or_else(|| invalid(format!("malformed dynamic forward spec {spec:?}")))?;

    let (bind_tok, port_tok) = match tokens.as_slice() {
        [port] => (None, *port),
        [bind, port] => (Some(*bind), *port),
        other => {
            return Err(invalid(format!(
                "expected 1 or 2 colon-separated parts in {spec:?}, found {}",
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
    let ForwardSpecToken::Plain(port_raw) = port_tok else {
        return Err(invalid(format!(
            "listen port must not be bracketed in {spec:?}"
        )));
    };
    let listen_port = parse_forward_port(port_raw)
        .ok_or_else(|| invalid(format!("invalid listen port {port_raw:?} in {spec:?}")))?;

    Ok(DynamicSpec {
        bind: bind_tok.map(|t| t.inner().to_string()),
        listen_port,
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
            deny_host_local: false,
        }
    }

    /// Header for a file data stream carrying `ticket` (from
    /// [`FileReadOpened`] / [`FileWriteOpened`]).
    pub fn file_data(ticket: Vec<u8>) -> Self {
        Self {
            kind: StreamKind::FileData as i32,
            ticket,
            host: String::new(),
            port: 0,
            deny_host_local: false,
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
            deny_host_local: false,
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

    /// `ScreenUpdate` frame (one part).
    pub fn screen_update(part: ScreenUpdate) -> Self {
        Self::from_body(session_frame::Body::ScreenUpdate(part))
    }

    /// `ScreenHistory` frame.
    pub fn screen_history(history: ScreenHistory) -> Self {
        Self::from_body(session_frame::Body::ScreenHistory(history))
    }

    /// `ScreenEcho` frame (ADR-0053 decision 3).
    pub fn screen_echo(echo: ScreenEcho) -> Self {
        Self::from_body(session_frame::Body::ScreenEcho(echo))
    }

    /// `ScreenAck` frame; `state_num` 0 asks for the full screen.
    pub fn screen_ack(state_num: u64) -> Self {
        Self::from_body(session_frame::Body::ScreenAck(ScreenAck { state_num }))
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
mod tests;
