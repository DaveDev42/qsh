//! The POSIX interactive attach driver (`docs/CLI.md` §7).
//!
//! Everything here is terminal plumbing around a single
//! [`Ops::session_attach`] stream — see the module docs in
//! [`super`](super) for the thread layout and why it is three threads.

use std::io::{self, Read as _, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_core::{AttachHandle, OpError, Ops, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{ErrorCode, SessionOpenReq};

use super::term::{self, RawMode};
use super::{Attach, Escape, attach_request, escape_help, open_request};

/// Read size for the stdin pump. One `read(2)` per keystroke is normal;
/// this only bounds a paste.
const INPUT_CHUNK: usize = 8 * 1024;

/// Exit code when the session ends without a remote status of its own —
/// the connection died, or somebody else closed the session out from under
/// us. Same code every other qsh runtime failure uses (`docs/CLI.md` §4).
const EXIT_RUNTIME_FAILURE: i32 = 255;

/// Run an interactive session to completion; see [`super::run`].
pub fn run(ops: &Ops, what: Attach, escape: Option<u8>) -> Result<i32, OpError> {
    let size = term::window_size();

    // Authorization, session creation and the attach all happen here, in
    // `Ops`, before a single byte of terminal state is touched: a refused
    // attach must leave the operator's terminal exactly as it found it.
    let session_ref = match what {
        Attach::Open { host, user } => open_session(ops, open_request(host, user, size))?,
        Attach::Existing { session_ref } => session_ref,
    };
    let mut stream = ops.session_attach(attach_request(session_ref))?;

    // Adopt this terminal's size before the shell draws anything. On the
    // freshly opened path this is what `session.open` already recorded; on
    // `qsh attach` it is a real change.
    if let Some((cols, rows)) = size {
        stream.resize(cols, rows)?;
    }

    let raw = RawMode::enter().map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("cannot put the terminal in raw mode: {err}"),
        )
    })?;
    #[cfg(debug_assertions)]
    test_panic_hook();

    let detached = Arc::new(AtomicBool::new(false));
    // Escape processing is a *terminal* feature: with a pipe or a file on
    // stdin every byte is forwarded verbatim (`docs/CLI.md` §7).
    let escape = escape.filter(|_| raw.is_raw());
    spawn_input_pump(stream.handle(), escape, Arc::clone(&detached));
    spawn_signal_pump(stream.handle());

    let outcome = pump_events(&mut stream, &detached);

    // Restore the terminal *before* any diagnostic is printed, so a
    // message about the exit is not typeset in raw mode.
    drop(raw);
    stream.close();
    finish(outcome)
}

/// `session.open` for the bare `qsh [user@]host` form.
fn open_session(ops: &Ops, req: SessionOpenReq) -> Result<String, OpError> {
    Ok(ops.session_open(req)?.session_ref)
}

/// How the interactive session ended.
enum Outcome {
    /// The user detached (`~d` / `~.`): the session keeps running and this
    /// process exits `0` (`docs/CLI.md` §4).
    Detached,
    /// The remote process exited with this status.
    Exit {
        /// Remote exit code, or `None` when a signal killed it.
        code: Option<i32>,
        /// Signal name, when one killed it.
        signal: Option<String>,
    },
    /// The session was removed while we were attached.
    Closed(String),
    /// The stream ended without telling us why.
    Lost,
    /// The stream failed.
    Failed(OpError),
}

/// Drain the attach's event stream, writing session output to stdout.
/// Returns as soon as the session ends or the user detaches.
fn pump_events(stream: &mut SessionAttachStream, detached: &AtomicBool) -> Outcome {
    let mut stdout = io::stdout().lock();
    while let Some(event) = stream.next_event() {
        if detached.load(Ordering::SeqCst) {
            return Outcome::Detached;
        }
        let event = match event {
            Ok(event) => event,
            Err(err) => return Outcome::Failed(err),
        };
        match event {
            SessionEvent::Output { data_b64, .. } => {
                let Ok(bytes) = BASE64.decode(data_b64.as_bytes()) else {
                    return Outcome::Failed(OpError::new(
                        ErrorCode::Internal,
                        "session output was not valid Base64",
                    ));
                };
                // A write failure here is our own stdout dying (the
                // terminal went away); treat it as a lost session rather
                // than spinning on a broken pipe.
                if stdout
                    .write_all(&bytes)
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    return Outcome::Lost;
                }
            }
            // Structural only — never the payload (`CLAUDE.md` security
            // defaults). A gap means the ring outran us; the bytes are
            // gone and saying so is the honest answer.
            SessionEvent::Gap { available_from, .. } => {
                note(&format!(
                    "output was dropped; the session resumed at offset {available_from}"
                ));
            }
            SessionEvent::WriterChanged { writer, .. } => match writer {
                Some(writer) => note(&format!("the writer lease moved to {writer}")),
                None => note("the writer lease was released"),
            },
            SessionEvent::Exit {
                exit_code, signal, ..
            } => {
                return Outcome::Exit {
                    code: exit_code,
                    signal,
                };
            }
            SessionEvent::Closed { reason, .. } => return Outcome::Closed(reason),
            SessionEvent::Unknown(_) => {}
        }
    }
    if detached.load(Ordering::SeqCst) {
        Outcome::Detached
    } else {
        Outcome::Lost
    }
}

/// Turn the outcome into this process's exit code (`docs/CLI.md` §4).
fn finish(outcome: Outcome) -> Result<i32, OpError> {
    match outcome {
        Outcome::Detached => {
            eprintln!("qsh: detached; the session keeps running");
            Ok(0)
        }
        // Remote `0..=254` verbatim, remote `255` clamped to `254`, exactly
        // like `qsh exec`. A signal-killed child has no exit code of its
        // own; it reports the same `-1`-shaped status the read path does
        // and names the signal on stderr.
        Outcome::Exit { code, signal } => {
            if let Some(signal) = &signal {
                eprintln!("qsh: the remote process was terminated by {signal}");
            }
            Ok(crate::remote_exit_code_to_process_exit(code.unwrap_or(-1)))
        }
        Outcome::Closed(reason) => {
            eprintln!("qsh: the session was closed ({reason})");
            Ok(EXIT_RUNTIME_FAILURE)
        }
        Outcome::Lost => Err(OpError::new(
            ErrorCode::ConnectionFailed,
            "the session ended without a remote exit status",
        )),
        Outcome::Failed(err) => Err(err),
    }
}

/// One diagnostic line on stderr. Raw mode has no output post-processing,
/// so every line carries its own CR (`docs/CLI.md` §2.2 keeps all of this
/// off stdout).
fn note(message: &str) {
    let mut stderr = io::stderr().lock();
    let _ = write!(stderr, "\r\nqsh: {message}\r\n");
    let _ = stderr.flush();
}

/// stdin → escape machine → the session, on its own thread.
///
/// Detached on purpose: it parks in `read(2)` on the terminal, which
/// nothing but the process exiting can interrupt. It owns no terminal
/// state, so leaving it parked is safe.
fn spawn_input_pump(handle: AttachHandle, escape: Option<u8>, detached: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("qsh-tui-input".into())
        .spawn(move || {
            let mut machine = Escape::new(escape);
            let mut stdin = io::stdin().lock();
            let mut buf = vec![0u8; INPUT_CHUNK];
            loop {
                let read = match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                let processed = machine.feed(&buf[..read]);
                if processed.help
                    && let Some(escape) = escape
                {
                    let mut stderr = io::stderr().lock();
                    let _ = stderr.write_all(escape_help(escape).as_bytes());
                    let _ = stderr.flush();
                }
                if !processed.forward.is_empty() && handle.write(processed.forward).is_err() {
                    break;
                }
                if processed.detach {
                    // Announce the detach before ending the attach, so the
                    // event pump reports a detach rather than a lost
                    // connection.
                    detached.store(true, Ordering::SeqCst);
                    handle.detach();
                    break;
                }
            }
        })
        .expect("spawn the stdin pump");
}

/// `SIGWINCH` → `session.resize`, `SIGINT` → the `^C` byte, `SIGTERM` /
/// `SIGHUP` → restore the terminal and die of the signal.
///
/// The tokio runtime lives on this thread only, and every `Ops` call is
/// made *after* `block_on` returns — a blocking send from inside a runtime
/// would panic, and the whole client is deliberately synchronous.
fn spawn_signal_pump(handle: AttachHandle) {
    std::thread::Builder::new()
        .name("qsh-tui-signals".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::warn!(%err, "no signal handling for this session");
                    return;
                }
            };
            let mut signals = match runtime.block_on(async { Signals::install() }) {
                Ok(signals) => signals,
                Err(err) => {
                    tracing::warn!(%err, "no signal handling for this session");
                    return;
                }
            };
            loop {
                // Note the `block_on` boundary: the runtime context ends
                // when this returns, which is what makes the blocking
                // `AttachHandle` calls below legal.
                match runtime.block_on(signals.next()) {
                    Some(Caught::Winch) => {
                        if let Some((cols, rows)) = term::window_size()
                            && handle.resize(cols, rows).is_err()
                        {
                            return;
                        }
                    }
                    // `docs/CLI.md` §9: an interactive attach forwards
                    // SIGINT to the remote PTY. From the keyboard this
                    // never fires (raw mode delivers `^C` as a byte); it is
                    // the `kill -INT` and not-a-TTY cases that land here.
                    Some(Caught::Int) => {
                        if handle.write(vec![0x03]).is_err() {
                            return;
                        }
                    }
                    Some(Caught::Fatal(signal)) => term::restore_and_die(signal),
                    None => return,
                }
            }
        })
        .expect("spawn the signal pump");
}

/// What the signal pump saw.
enum Caught {
    /// The window changed size.
    Winch,
    /// SIGINT, to be forwarded to the remote PTY.
    Int,
    /// A signal whose default action is to end this process.
    Fatal(nix::sys::signal::Signal),
}

/// The signal streams an interactive attach listens on.
struct Signals {
    winch: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
}

impl Signals {
    /// Install the handlers. Must be called from inside the runtime that
    /// will poll them.
    fn install() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            winch: signal(SignalKind::window_change())?,
            int: signal(SignalKind::interrupt())?,
            term: signal(SignalKind::terminate())?,
            hup: signal(SignalKind::hangup())?,
        })
    }

    /// The next signal, or `None` if every stream ended.
    async fn next(&mut self) -> Option<Caught> {
        tokio::select! {
            signal = self.winch.recv() => signal.map(|()| Caught::Winch),
            signal = self.int.recv() => signal.map(|()| Caught::Int),
            signal = self.term.recv() => {
                signal.map(|()| Caught::Fatal(nix::sys::signal::Signal::SIGTERM))
            }
            signal = self.hup.recv() => {
                signal.map(|()| Caught::Fatal(nix::sys::signal::Signal::SIGHUP))
            }
        }
    }
}

/// Test seam for "the terminal is restored even when the client panics"
/// (`docs/design/testing.md` L5). Debug builds only, so a release binary
/// has no way to be talked into panicking by its environment.
#[cfg(debug_assertions)]
fn test_panic_hook() {
    if std::env::var_os("QSH_TUI_TEST_PANIC").is_some() {
        panic!("QSH_TUI_TEST_PANIC");
    }
}
