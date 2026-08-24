//! Interactive attach — `qsh [user@]host` and `qsh attach <session-ref>`
//! (`docs/CLI.md` §7).
//!
//! A **thin** consumer of one stream operation. Everything that decides
//! anything — authorization, the writer lease, the replay cursor, the
//! session's lifetime — lives behind [`Ops::session_attach`] in `qsh-core`
//! (`docs/CLI.md` §7.1, §11). What is left here is terminal work:
//!
//! - put the local terminal in raw mode and restore it on *every* exit
//!   path — normal, error, panic, signal ([`term`]);
//! - forward stdin bytes **verbatim**, recognising nothing except the
//!   line-start escape sequences ([`Escape`]);
//! - turn `SIGWINCH` into `session.resize`, and an externally delivered
//!   `SIGINT` into the `^C` byte the remote PTY expects (`docs/CLI.md` §9);
//! - map the remote exit status onto this process's exit code (§4).
//!
//! Nothing on this path writes to stdout except session output itself:
//! diagnostics, the `~?` help and every warning go to stderr
//! (`docs/CLI.md` §2.2). There is no machine mode: `--json`/`--jsonl` on
//! either interactive form is `INVALID_ARGUMENT` (§7), because stdout
//! belongs to the remote terminal.
//!
//! ## Deliberate gaps
//!
//! - `~^Z` and job control: `docs/CLI.md` §7's escape table is exhaustive
//!   and has no suspend, so SIGTSTP/SIGCONT are not handled. A `kill
//!   -TSTP` therefore resumes into a terminal the client last configured;
//!   that is backlog, not M2.
//! - A lone escape character held at EOF is dropped when stdin closes,
//!   which is what ssh does and what §7 leaves unspecified.
//!
//! ## Threads
//!
//! Three, because [`SessionAttachStream::next_event`] blocks the thread
//! that owns the stream and no `Ops` entry point may be called from inside
//! a tokio runtime:
//!
//! | thread | role |
//! |---|---|
//! | main | drains events, writes session output to stdout, owns the raw-mode guard |
//! | input | blocking `read(2)` on stdin → [`Escape`] → `AttachHandle::write` |
//! | signals | `SIGWINCH` → `resize`, `SIGINT` → `^C`, `SIGTERM`/`SIGHUP` → restore and die |
//!
//! The two helpers are detached, never joined: both park in a blocking
//! syscall, and the process exits as soon as the event loop is done.

#[cfg(unix)]
mod term;

use qsh_core::{OpError, Ops};
use qsh_proto::ErrorCode;
// Only the POSIX driver builds requests; on Windows `run` refuses before
// there is anything to ask for.
#[cfg(unix)]
use qsh_proto::{SessionAttachReq, SessionOpenReq};

/// What to attach to.
#[derive(Debug, Clone)]
pub enum Attach {
    /// `qsh [user@]host` — open a fresh session, then attach to it.
    Open {
        /// Host alias from the trust store.
        host: String,
        /// The `user@` hint, checked by the host against its own login
        /// name (`docs/CLI.md` §7).
        user: Option<String>,
        /// `-L` local forward specs, unparsed
        /// (`qsh_core::parse_local_forwards` is what turns them into
        /// specs and decides their error code — `docs/CLI.md` §6.9). Only
        /// this form carries them: `qsh attach` takes no `-L`, and the
        /// standalone tunnel form is `qsh tunnel open`.
        // Read only by the `#[cfg(unix)]` driver below (`tui::unix::run`);
        // the Windows `run` refuses the whole interactive form before it
        // could look at a forward, so the field is constructed but never
        // read there — dead, not absent, on Windows.
        #[cfg_attr(not(unix), allow(dead_code))]
        forwards: Vec<String>,
        /// `-R` remote forward specs, unparsed
        /// (`qsh_core::parse_remote_forwards` turns them into specs;
        /// `PLAN.md` M4 Step 4). Same scope as `forwards` — only this
        /// form carries them, and only the `#[cfg(unix)]` driver reads
        /// them.
        #[cfg_attr(not(unix), allow(dead_code))]
        remote_forwards: Vec<String>,
    },
    /// `qsh attach <session-ref>` — attach to a session already running.
    Existing {
        /// Opaque session handle.
        session_ref: String,
    },
}

impl Attach {
    /// The operation name this form reports in diagnostics and in the
    /// `--json` error envelope.
    pub fn command(&self) -> &'static str {
        use qsh_core::{Operation as _, SessionAttachOp, SessionOpenOp};
        match self {
            // The bare form's first (and only failing-before-attach) step
            // is `session.open`.
            Attach::Open { .. } => SessionOpenOp::COMMAND,
            Attach::Existing { .. } => SessionAttachOp::COMMAND,
        }
    }
}

/// Environment variables an interactive client passes to the remote
/// session: locale only (`docs/CLI.md` §7, `docs/design/architecture.md`
/// §4 — `TERM` travels in `SessionSpec.term`, and
/// `HOME`/`USER`/`LOGNAME`/`SHELL`/`PATH` are pinned by the host and
/// silently ignored here).
///
/// Interactive-only on purpose, and documented as such: `qsh session open`
/// and the MCP adapter send exactly the `--env` their caller asked for, so
/// a machine caller's session is never shaped by whatever locale the
/// process that started it happened to have.
#[cfg(unix)]
const LOCALE_VARS: &[&str] = &["LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_COLLATE"];

/// Run an interactive session to completion and return the process exit
/// code (`docs/CLI.md` §4: the remote shell's code, `255` clamped to
/// `254`; a detach is `0`).
#[cfg(unix)]
pub fn run(ops: &Ops, what: Attach, escape: Option<u8>) -> Result<i32, OpError> {
    unix::run(ops, what, escape)
}

/// Windows client is P1 (`docs/design/architecture.md` §8): the interactive
/// path is refused with `UNSUPPORTED` rather than silently degrading to a
/// cooked-mode pipe.
#[cfg(not(unix))]
pub fn run(_ops: &Ops, what: Attach, _escape: Option<u8>) -> Result<i32, OpError> {
    let target = match &what {
        Attach::Open {
            host,
            user: Some(user),
            ..
        } => format!("{user}@{host}"),
        Attach::Open {
            host, user: None, ..
        } => host.clone(),
        Attach::Existing { session_ref } => session_ref.clone(),
    };
    Err(OpError::new(
        ErrorCode::Unsupported,
        format!(
            "interactive attach to {target} needs a POSIX terminal; use \
             `qsh session open` with `qsh session read --follow` and \
             `qsh session write` on this platform"
        ),
    ))
}

/// Reject `--json`/`--jsonl` on the interactive path: an attach is a
/// terminal, not an envelope, and `docs/CLI.md` §2.2 reserves stdout for
/// the session's own bytes. Machine callers compose `session open` +
/// `session read --follow --jsonl` + `session write` instead.
pub fn json_mode_unsupported() -> OpError {
    OpError::new(
        ErrorCode::InvalidArgument,
        "interactive attach has no JSON output mode; use `qsh session open --json` \
         with `qsh session read --follow --jsonl` and `qsh session write`",
    )
}

/// Locale variables of this process, to be layered over the remote login
/// environment.
#[cfg(unix)]
fn locale_env() -> Vec<qsh_proto::EnvVar> {
    LOCALE_VARS
        .iter()
        .filter_map(|name| {
            std::env::var(name).ok().map(|value| qsh_proto::EnvVar {
                name: (*name).to_string(),
                value,
            })
        })
        .collect()
}

/// Build the `session.open` request for the bare `qsh [user@]host` form.
#[cfg(unix)]
fn open_request(host: String, user: Option<String>, size: Option<(u16, u16)>) -> SessionOpenReq {
    SessionOpenReq {
        host,
        argv: Vec::new(),
        env: locale_env(),
        term: std::env::var("TERM").ok().filter(|t| !t.is_empty()),
        cols: size.map(|(cols, _)| u32::from(cols)),
        rows: size.map(|(_, rows)| u32::from(rows)),
        user,
    }
}

/// The attach request. `no_steal` is deliberately false: taking over the
/// writer lease is what makes re-attaching after a dead client work at all
/// (`docs/design/protocol.md` §10).
#[cfg(unix)]
fn attach_request(session_ref: String) -> SessionAttachReq {
    SessionAttachReq {
        session_ref,
        no_steal: false,
    }
}

/// The line-start escape state machine (`docs/CLI.md` §7).
///
/// ssh's rule, restated for a client with no line discipline: the escape
/// character is only recognised at the start of a line, and "start of a
/// line" means *nothing has been forwarded yet, or the last byte forwarded
/// to the remote was CR or LF*. A recognised escape byte is held locally
/// until the next byte decides what it meant; an unknown second byte sends
/// **both** on, so input is never silently swallowed.
///
/// Deliberately portable and free of terminal I/O so it can be unit-tested
/// on any host — the Windows CI leg compiles and runs these tests too,
/// even though nothing there drives it yet.
#[cfg(any(unix, test))]
#[derive(Debug)]
pub struct Escape {
    /// The escape character, or `None` when escape processing is off
    /// (`--escape-char none`, or stdin is not a TTY).
    escape: Option<u8>,
    /// Whether the next byte sits at the start of a line.
    at_line_start: bool,
    /// Whether an escape character is being held back.
    pending: bool,
}

/// What one chunk of stdin turned into.
#[cfg(any(unix, test))]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Processed {
    /// Bytes to forward to the remote PTY, in order.
    pub forward: Vec<u8>,
    /// The user asked to detach (`~d` / `~.`). Bytes after it are dropped:
    /// this client is leaving.
    pub detach: bool,
    /// The user asked for the escape help (`~?`), which goes to stderr.
    pub help: bool,
}

#[cfg(any(unix, test))]
impl Escape {
    /// A machine for `escape`, which is `None` when escape processing is
    /// disabled (then every byte is forwarded verbatim).
    pub fn new(escape: Option<u8>) -> Self {
        Self {
            escape,
            at_line_start: true,
            pending: false,
        }
    }

    /// Feed one chunk of stdin.
    pub fn feed(&mut self, input: &[u8]) -> Processed {
        let mut out = Processed::default();
        let Some(escape) = self.escape else {
            out.forward.extend_from_slice(input);
            return out;
        };
        for &byte in input {
            if self.pending {
                self.pending = false;
                match byte {
                    b'd' | b'.' => {
                        out.detach = true;
                        return out;
                    }
                    b'?' => out.help = true,
                    b if b == escape => self.push(&mut out, escape),
                    other => {
                        // Unknown sequence: ssh forwards both bytes rather
                        // than eating the input (`docs/CLI.md` §7).
                        self.push(&mut out, escape);
                        self.push(&mut out, other);
                    }
                }
                continue;
            }
            if byte == escape && self.at_line_start {
                self.pending = true;
                continue;
            }
            self.push(&mut out, byte);
        }
        out
    }

    /// Forward one byte and update the line-start state from it.
    fn push(&mut self, out: &mut Processed, byte: u8) {
        out.forward.push(byte);
        self.at_line_start = byte == b'\r' || byte == b'\n';
    }
}

/// The `~?` help text (`docs/CLI.md` §7). CR-LF terminated: the local
/// terminal is in raw mode, so `\n` alone would stair-step.
#[cfg(any(unix, test))]
fn escape_help(escape: u8) -> String {
    let e = escape as char;
    format!(
        "\r\nSupported escape sequences:\r\n \
         {e}d - detach (the session keeps running)\r\n \
         {e}. - detach (the session keeps running)\r\n \
         {e}{e} - send the escape character by typing it twice\r\n \
         {e}? - this message\r\n\
         (Escapes are only recognised immediately after a newline.)\r\n"
    )
}

#[cfg(unix)]
mod unix;

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(escape: Option<u8>, chunks: &[&[u8]]) -> Vec<Processed> {
        let mut machine = Escape::new(escape);
        chunks.iter().map(|c| machine.feed(c)).collect()
    }

    fn forwarded(escape: Option<u8>, chunks: &[&[u8]]) -> Vec<u8> {
        feed(escape, chunks)
            .into_iter()
            .flat_map(|p| p.forward)
            .collect()
    }

    #[test]
    fn plain_input_is_forwarded_verbatim() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        // No line start is entered, so not even a leading `~` is special
        // after the first byte.
        assert_eq!(forwarded(Some(b'~'), &[b"x", &bytes]), {
            let mut want = b"x".to_vec();
            want.extend_from_slice(&bytes);
            want
        });
    }

    #[test]
    fn escape_is_only_recognised_at_the_start_of_a_line() {
        // Mid-line `~` is ordinary input, even followed by `d`.
        assert_eq!(forwarded(Some(b'~'), &[b"echo ~d\r"]), b"echo ~d\r");
        // After CR the next `~d` detaches.
        let out = feed(Some(b'~'), &[b"echo hi\r", b"~d"]);
        assert!(!out[0].detach);
        assert!(out[1].detach);
        // LF counts as a line start too.
        let out = feed(Some(b'~'), &[b"echo hi\n~d"]);
        assert!(out[0].detach);
        assert_eq!(out[0].forward, b"echo hi\n");
    }

    #[test]
    fn the_escape_byte_is_held_until_the_next_byte_arrives() {
        let mut machine = Escape::new(Some(b'~'));
        // Held: nothing is forwarded yet.
        assert_eq!(machine.feed(b"~"), Processed::default());
        // `~~` sends exactly one literal `~`, and that is not a line start.
        let out = machine.feed(b"~");
        assert_eq!(out.forward, b"~");
        assert!(!out.detach && !out.help);
        // So a following `~d` is now ordinary input.
        assert_eq!(machine.feed(b"~d").forward, b"~d");
    }

    #[test]
    fn an_unknown_sequence_forwards_both_bytes() {
        let out = feed(Some(b'~'), &[b"~x"]);
        assert_eq!(out[0].forward, b"~x");
        assert!(!out[0].detach);
        // ...and the second byte decides the new line-start state.
        assert_eq!(forwarded(Some(b'~'), &[b"~\r~d"]), b"~\r");
    }

    #[test]
    fn help_consumes_the_sequence_and_keeps_the_line_start() {
        let out = feed(Some(b'~'), &[b"~?"]);
        assert!(out[0].help);
        assert!(out[0].forward.is_empty());
        // Nothing was forwarded, so we are still at a line start: the very
        // next `~d` detaches.
        let out = feed(Some(b'~'), &[b"~?", b"~d"]);
        assert!(out[1].detach);
    }

    #[test]
    fn detach_drops_the_rest_of_the_chunk() {
        let out = feed(Some(b'~'), &[b"~drm -rf /\r"]);
        assert!(out[0].detach);
        assert!(out[0].forward.is_empty());
    }

    #[test]
    fn a_custom_escape_character_replaces_the_default() {
        // `~` is now ordinary input, and `^d` at a line start detaches.
        let out = feed(Some(b'^'), &[b"~d\r^d"]);
        assert!(out[0].detach);
        assert_eq!(out[0].forward, b"~d\r");
    }

    #[test]
    fn disabled_escape_forwards_every_sequence() {
        let out = feed(None, &[b"~d~.~~~?"]);
        assert_eq!(out[0].forward, b"~d~.~~~?");
        assert!(!out[0].detach && !out[0].help);
    }

    #[test]
    fn help_text_names_every_documented_sequence() {
        let help = escape_help(b'~');
        for seq in ["~d", "~.", "~~", "~?"] {
            assert!(help.contains(seq), "{seq} missing from {help:?}");
        }
        // Raw mode has no output post-processing: every line must carry
        // its own CR. (`str::lines` strips one, so split explicitly.)
        let mut lines = help.split('\n');
        let last = lines.next_back();
        assert!(lines.all(|l| l.ends_with('\r')), "{help:?}");
        assert_eq!(last, Some(""), "the help ends with a newline");
    }
}
