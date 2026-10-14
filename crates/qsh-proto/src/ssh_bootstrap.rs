//! SSH bootstrap stream: message types, line parser, version negotiation
//! (ADR-0044 decision 11).
//!
//! `qsh pair ssh` runs `qsh pair ssh-respond` on the remote through the
//! system `ssh`, and the two ends talk over that child's stdin/stdout. This
//! is **not** a QUIC wire: nothing here is protobuf, and no `.proto` file
//! describes it. It is still an interoperability contract between two qsh
//! builds of possibly different versions, so `docs/design/protocol.md`
//! documents it in its own section and applies the additive-only rule of
//! §16 (listed in §16.2).
//!
//! The stream is line oriented. Every message is one line made of the
//! fixed prefix [`BOOTSTRAP_LINE_PREFIX`] followed by one JSON object, and
//! no line exceeds [`BOOTSTRAP_LINE_MAX`] bytes. The JSON object carries a
//! `"type"` tag (`hello`, `commit`, `result`); unknown fields are ignored so
//! a newer peer may add some. The three messages, in the order they appear:
//!
//! - responder to client [`Hello`]: supported versions, qsh version, a
//!   [`HelloStatus`], and, when ready, the responder's fingerprint and
//!   serve facts;
//! - client to responder [`Commit`]: the chosen version, the client's
//!   fingerprint, the name and role the responder should pin it under, and
//!   (reverse direction only) the dial address;
//! - responder to client [`BootstrapResult`]: a [`ResultStatus`] and what
//!   was written.
//!
//! Everything the remote shell prints before its `hello` (rc files, `motd`
//! banners) arrives on the same stdout. [`BootstrapReader`] skips such
//! untagged lines up to [`BOOTSTRAP_PREAMBLE_MAX`] bytes in total, keeps
//! only their count, and never retains or exposes their content, so it
//! cannot leak into a log. After the `hello`, an untagged line, an
//! over-long line or a message in the wrong position is a protocol error.
//!
//! This module reads input an attacker who can influence the remote
//! account's output controls, so it is sans-IO, total over arbitrary bytes,
//! allocation-bounded, and a cargo-fuzz target (`parse_ssh_bootstrap_line`,
//! `docs/design/protocol.md` §13). Errors never carry a copy of the
//! offending input. Policy (which name to pin, whether a fingerprint is
//! well formed, how an [`BootstrapLineError`] maps to `REMOTE_ERROR` with
//! `details.reason = "bootstrap_protocol"`) belongs to `qsh-core`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::ErrorCode;

/// Fixed prefix of every bootstrap line, including the trailing space
/// (ADR-0044 decision 11).
pub const BOOTSTRAP_LINE_PREFIX: &str = "qsh-bootstrap ";

/// Longest line in bytes, prefix and JSON included, newline excluded
/// (ADR-0044 decision 11).
pub const BOOTSTRAP_LINE_MAX: usize = 8 * 1024;

/// Total bytes of untagged lines (newlines included) a reader skips before
/// the `hello`; one byte more is a protocol error (ADR-0044 decision 11).
pub const BOOTSTRAP_PREAMBLE_MAX: usize = 64 * 1024;

/// Bootstrap versions this build speaks, ascending (ADR-0044 decision 11
/// lists `[1]`).
pub const BOOTSTRAP_VERSIONS: &[u32] = &[1];

/// Responder status in a [`Hello`].
///
/// The wire form is an open string. Values this build does not know are
/// kept as [`HelloStatus::Unknown`] so the caller can fail with
/// `REMOTE_ERROR` (`bootstrap_protocol`) instead of the parser guessing.
/// The text is peer-authored: sanitize it before showing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloStatus {
    /// The responder has an identity and will accept a `commit`.
    Ready,
    /// The responder has no identity (`qsh setup host` was not run). It
    /// writes nothing and does not create one.
    NotInitialized,
    /// A status this build does not know.
    Unknown(String),
}

impl HelloStatus {
    /// The wire string.
    pub fn as_str(&self) -> &str {
        match self {
            HelloStatus::Ready => "ready",
            HelloStatus::NotInitialized => "not_initialized",
            HelloStatus::Unknown(s) => s,
        }
    }
}

impl Serialize for HelloStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HelloStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "ready" => HelloStatus::Ready,
            "not_initialized" => HelloStatus::NotInitialized,
            _ => HelloStatus::Unknown(s),
        })
    }
}

/// Outcome in a [`BootstrapResult`]. Open string on the wire, like
/// [`HelloStatus`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultStatus {
    /// A new pin was written.
    Pinned,
    /// The client's fingerprint was already pinned; nothing was created and
    /// the existing pin's role is unchanged.
    Exists,
    /// The same name is pinned with a different fingerprint; nothing was
    /// written.
    Conflict,
    /// The responder failed (`code`/`message` say why); nothing was written.
    Error,
    /// A status this build does not know.
    Unknown(String),
}

impl ResultStatus {
    /// The wire string.
    pub fn as_str(&self) -> &str {
        match self {
            ResultStatus::Pinned => "pinned",
            ResultStatus::Exists => "exists",
            ResultStatus::Conflict => "conflict",
            ResultStatus::Error => "error",
            ResultStatus::Unknown(s) => s,
        }
    }
}

impl Serialize for ResultStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ResultStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "pinned" => ResultStatus::Pinned,
            "exists" => ResultStatus::Exists,
            "conflict" => ResultStatus::Conflict,
            "error" => ResultStatus::Error,
            _ => ResultStatus::Unknown(s),
        })
    }
}

/// Responder to client, first message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Bootstrap versions the responder supports.
    pub versions: Vec<u32>,
    /// The responder's qsh version string (informational).
    pub qsh_version: String,
    /// Whether the responder can take a `commit`.
    pub status: HelloStatus,
    /// The responder's identity fingerprint, `sha256:BASE64`. Present when
    /// `status` is `ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The responder's `[serve].bind` as configured. Present when `ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_bind: Option<String>,
    /// Whether a UDP bind on `serve_bind` failed with "address in use"
    /// (ADR-0044 decision 10). Absent or `null` means unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_listening: Option<bool>,
}

/// Client to responder, sent after a version was agreed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    /// The version the client chose ([`negotiate_version`]).
    pub version: u32,
    /// The client's identity fingerprint, `sha256:BASE64`.
    pub fingerprint: String,
    /// The name the responder pins the client under.
    pub name: String,
    /// The role the responder writes on a new pin (ADR-0045 vocabulary,
    /// validated by the responder, not here).
    pub role: String,
    /// Reverse direction only: where the responder dials the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// Responder to client, last message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapResult {
    /// What happened.
    pub status: ResultStatus,
    /// The name the client is (or would have been) pinned under.
    pub name: String,
    /// The role of the pin that exists after the call. `null` when there is
    /// no pin or the existing pin has no role. Always serialized.
    #[serde(default)]
    pub role: Option<String>,
    /// Whether this call created the pin.
    pub created: bool,
    /// On failure, an [`ErrorCode`] from the shared vocabulary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<ErrorCode>,
    /// On failure, a human-readable reason (peer-authored: sanitize it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One parsed bootstrap line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BootstrapLine {
    /// Responder to client.
    Hello(Hello),
    /// Client to responder.
    Commit(Commit),
    /// Responder to client.
    Result(BootstrapResult),
}

/// Why a line or a stream was refused. Every variant maps to
/// `REMOTE_ERROR` with `details.reason = "bootstrap_protocol"`; none of
/// them carries bytes from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BootstrapLineError {
    /// The line does not start with [`BOOTSTRAP_LINE_PREFIX`].
    #[error("bootstrap line lacks the `qsh-bootstrap ` prefix")]
    MissingPrefix,
    /// The line is longer than [`BOOTSTRAP_LINE_MAX`].
    #[error("bootstrap line exceeds {BOOTSTRAP_LINE_MAX} bytes")]
    LineTooLong,
    /// The JSON object is not valid, has no known `type`, or lacks or
    /// mistypes a required field.
    #[error("bootstrap line is not a valid message")]
    Malformed,
    /// More than [`BOOTSTRAP_PREAMBLE_MAX`] bytes of untagged lines came
    /// before the `hello`.
    #[error("untagged output before the hello exceeds {BOOTSTRAP_PREAMBLE_MAX} bytes")]
    PreambleTooLarge,
    /// An untagged line after the `hello`.
    #[error("untagged line after the hello")]
    UntaggedAfterHello,
    /// A message in the wrong position (a `result` before the `hello`, a
    /// second `hello`, a `commit` on the client side, any message after the
    /// `result`).
    #[error("bootstrap message out of order")]
    OutOfOrder,
}

/// Parses one line, **without** its `\n` (one trailing `\r` is tolerated,
/// for a CRLF-translating remote). Total over arbitrary bytes.
pub fn parse_ssh_bootstrap_line(line: &[u8]) -> Result<BootstrapLine, BootstrapLineError> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.len() > BOOTSTRAP_LINE_MAX {
        return Err(BootstrapLineError::LineTooLong);
    }
    let body = line
        .strip_prefix(BOOTSTRAP_LINE_PREFIX.as_bytes())
        .ok_or(BootstrapLineError::MissingPrefix)?;
    serde_json::from_slice(body).map_err(|_| BootstrapLineError::Malformed)
}

impl BootstrapLine {
    /// Serializes to one line, prefix and trailing `\n` included. JSON
    /// string escaping guarantees the object holds no raw newline, so the
    /// result is exactly one line. [`BootstrapLineError::LineTooLong`] if
    /// the message would exceed [`BOOTSTRAP_LINE_MAX`] (a peer would refuse
    /// it).
    pub fn encode_line(&self) -> Result<String, BootstrapLineError> {
        let json = serde_json::to_string(self).map_err(|_| BootstrapLineError::Malformed)?;
        debug_assert!(!json.contains(['\n', '\r']));
        if BOOTSTRAP_LINE_PREFIX.len() + json.len() > BOOTSTRAP_LINE_MAX {
            return Err(BootstrapLineError::LineTooLong);
        }
        Ok(format!("{BOOTSTRAP_LINE_PREFIX}{json}\n"))
    }
}

/// The version to speak: the largest value in both lists, or `None` when
/// they are disjoint (the client then ends with `UNSUPPORTED` and sends no
/// `commit`, ADR-0044 decision 11).
pub fn negotiate_version(ours: &[u32], theirs: &[u32]) -> Option<u32> {
    ours.iter().copied().filter(|v| theirs.contains(v)).max()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitHello,
    AwaitResult,
    Done,
    Failed(BootstrapLineError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineState {
    /// Buffered bytes are still a prefix of [`BOOTSTRAP_LINE_PREFIX`].
    Prefix,
    /// The prefix matched; the rest of the line is being buffered.
    Tagged,
    /// The line cannot be tagged; its bytes are counted and dropped.
    Untagged,
}

/// Incremental receiver for the client side of the stream (the stdout of
/// the ssh child): optional untagged preamble, one `hello`, one `result`.
///
/// Feed it whatever chunks the pipe yields; the outcome does not depend on
/// where the chunks split. Memory is bounded by [`BOOTSTRAP_LINE_MAX`]
/// regardless of input: untagged bytes are counted, never stored. After an
/// error the reader stays failed and returns the same error.
#[derive(Debug, Clone)]
pub struct BootstrapReader {
    phase: Phase,
    line_state: LineState,
    line: Vec<u8>,
    skipped_bytes: usize,
    skipped_lines: u32,
}

impl Default for BootstrapReader {
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapReader {
    /// A reader waiting for the `hello`.
    pub fn new() -> Self {
        Self {
            phase: Phase::AwaitHello,
            line_state: LineState::Prefix,
            line: Vec::new(),
            skipped_bytes: 0,
            skipped_lines: 0,
        }
    }

    /// Consumes `data` and returns the messages completed by it, in order.
    ///
    /// On error the messages completed earlier in the same call are
    /// dropped: a stream with a protocol error is abandoned whole.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<BootstrapLine>, BootstrapLineError> {
        if let Phase::Failed(e) = self.phase {
            return Err(e);
        }
        let mut out = Vec::new();
        for &b in data {
            match self.step(b) {
                Ok(Some(msg)) => out.push(msg),
                Ok(None) => {}
                Err(e) => {
                    self.phase = Phase::Failed(e);
                    self.line = Vec::new();
                    return Err(e);
                }
            }
        }
        Ok(out)
    }

    /// Untagged lines skipped so far (a count only; their content is gone).
    pub fn skipped_lines(&self) -> u32 {
        self.skipped_lines
    }

    /// Bytes of those lines, newlines included.
    pub fn skipped_bytes(&self) -> usize {
        self.skipped_bytes
    }

    /// Whether the `hello` has been received.
    pub fn hello_seen(&self) -> bool {
        matches!(self.phase, Phase::AwaitResult | Phase::Done)
    }

    /// Whether the `result` has been received. Any further byte is a
    /// protocol error, so the driver stops reading here.
    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    fn step(&mut self, b: u8) -> Result<Option<BootstrapLine>, BootstrapLineError> {
        if b == b'\n' {
            return self.end_of_line();
        }
        match self.line_state {
            LineState::Untagged => {
                self.count_skipped(1)?;
            }
            LineState::Prefix => {
                self.line.push(b);
                if !BOOTSTRAP_LINE_PREFIX.as_bytes().starts_with(&self.line) {
                    self.require_preamble()?;
                    let buffered = self.line.len();
                    self.line.clear();
                    self.line_state = LineState::Untagged;
                    self.count_skipped(buffered)?;
                } else if self.line.len() == BOOTSTRAP_LINE_PREFIX.len() {
                    self.line_state = LineState::Tagged;
                }
            }
            LineState::Tagged => {
                self.line.push(b);
                // One byte of slack for a CRLF terminator; the exact cap is
                // checked once the line is complete.
                if self.line.len() > BOOTSTRAP_LINE_MAX + 1 {
                    return Err(BootstrapLineError::LineTooLong);
                }
            }
        }
        Ok(None)
    }

    fn end_of_line(&mut self) -> Result<Option<BootstrapLine>, BootstrapLineError> {
        let state = self.line_state;
        let buffered = self.line.len();
        self.line_state = LineState::Prefix;
        match state {
            LineState::Prefix => {
                // A whole line that never grew into the prefix, possibly
                // empty.
                self.require_preamble()?;
                self.line.clear();
                self.count_skipped(buffered + 1)?;
                self.skipped_lines = self.skipped_lines.saturating_add(1);
                Ok(None)
            }
            LineState::Untagged => {
                self.count_skipped(1)?;
                self.skipped_lines = self.skipped_lines.saturating_add(1);
                Ok(None)
            }
            LineState::Tagged => {
                let parsed = parse_ssh_bootstrap_line(&self.line);
                self.line.clear();
                let msg = parsed?;
                self.phase = match (self.phase, &msg) {
                    (Phase::AwaitHello, BootstrapLine::Hello(_)) => Phase::AwaitResult,
                    (Phase::AwaitResult, BootstrapLine::Result(_)) => Phase::Done,
                    _ => return Err(BootstrapLineError::OutOfOrder),
                };
                Ok(Some(msg))
            }
        }
    }

    fn require_preamble(&self) -> Result<(), BootstrapLineError> {
        if self.phase == Phase::AwaitHello {
            Ok(())
        } else {
            Err(BootstrapLineError::UntaggedAfterHello)
        }
    }

    fn count_skipped(&mut self, n: usize) -> Result<(), BootstrapLineError> {
        self.skipped_bytes = self.skipped_bytes.saturating_add(n);
        if self.skipped_bytes > BOOTSTRAP_PREAMBLE_MAX {
            return Err(BootstrapLineError::PreambleTooLarge);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
