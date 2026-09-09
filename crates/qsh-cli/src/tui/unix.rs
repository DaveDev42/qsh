//! The POSIX interactive attach driver (`docs/CLI.md` §7).
//!
//! Everything here is terminal plumbing around a single
//! [`Ops::session_attach`] stream — see the module docs in
//! [`super`] for the thread layout and why it is three threads.

use std::io::{self, Read as _, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_core::{AttachHandle, DetachFlush, OpError, Ops, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{ErrorCode, SessionOpenReq};

use crate::render::human;
use crate::stderr_note;

use super::term::{self, RawMode};
use super::{Attach, Escape, attach_request, escape_help, open_request};

/// Read size for the stdin pump. One `read(2)` per keystroke is normal;
/// this only bounds a paste.
const INPUT_CHUNK: usize = 8 * 1024;

/// How long to wait for the signal thread to install its handlers before
/// the terminal goes raw. Bounded: if the pump never comes up the client
/// still runs, it just has no signal handling (which it says on stderr).
const SIGNALS_READY: std::time::Duration = std::time::Duration::from_secs(2);

/// Run an interactive session to completion; see [`super::run`].
pub fn run(ops: &Ops, what: Attach, escape: Option<u8>) -> Result<i32, OpError> {
    let size = term::window_size();

    // Authorization, session creation and the attach all happen here, in
    // `Ops`, before a single byte of terminal state is touched: a refused
    // attach must leave the operator's terminal exactly as it found it.
    //
    // `-L` specs are parsed and policy-checked *first*, before a session
    // exists: a malformed or non-loopback spec must not cost the operator
    // a running remote shell to find out about (`docs/CLI.md` §6.9,
    // `PLAN.md` M4 §4.1 #3). The listeners themselves come up after the
    // attach, because they ride its connection.
    let (session_ref, opened, forward_specs, remote_forward_specs) = match what {
        Attach::Open {
            host,
            user,
            forwards,
            remote_forwards,
        } => {
            let specs = qsh_core::parse_local_forwards(&forwards)?;
            let remote_specs = qsh_core::parse_remote_forwards(&remote_forwards)?;
            (
                open_session(ops, open_request(host, user, size))?,
                true,
                specs,
                remote_specs,
            )
        }
        Attach::Existing { session_ref } => (session_ref, false, Vec::new(), Vec::new()),
    };
    // From here on a failure on the freshly opened path would strand a
    // real remote shell, so every early return names it: sessions outlive
    // their clients by design (`docs/PRD.md` §8), and one nobody was told
    // about is only findable through `qsh sessions`.
    let orphan = |err: OpError| -> OpError {
        if opened {
            stderr_note!(
                "qsh: the session is still running as {session_ref}; \
                 reattach with `qsh attach {session_ref}` or end it with \
                 `qsh session close {session_ref}`"
            );
        }
        err
    };

    // `-R`'s `RemoteForwardOpen` round trips happen **inside**
    // `session_attach` itself, before its attach driver takes the control
    // stream (`Ops::session_attach`'s own doc) — so the specs go in here,
    // not as a later call on `stream`.
    let mut stream = ops
        .session_attach(attach_request(session_ref.clone()), &remote_forward_specs)
        .map_err(orphan)?;

    // The `-L` listeners: bound before the terminal goes raw, so a bind
    // failure is an ordinary error report on a terminal that was never
    // touched. They are owned by `stream`, so they die with this attach
    // and with this process — no daemon, nothing to close (`docs/CLI.md`
    // §6.14).
    for tunnel in stream.open_local_forwards(&forward_specs).map_err(orphan)? {
        // A renderer call, not an `eprintln!`: the announcement goes
        // through the same sanitizing path every other human line does,
        // because `forward_to` is operator-supplied text.
        let _ = human::print_forward_started(&tunnel);
    }
    // `-R` remote forwards: already opened above (all-or-nothing, same as
    // `-L`'s bind above, `PLAN.md` M4 Step 4) — this just collects the
    // DTOs to render.
    for tunnel in stream.take_remote_forward_tunnels() {
        let _ = human::print_forward_started(&tunnel);
    }

    // Adopt this terminal's size before the shell draws anything. On the
    // freshly opened path this is what `session.open` already recorded; on
    // `qsh attach` it is a real change.
    if let Some((cols, rows)) = size {
        stream.resize(cols, rows).map_err(orphan)?;
    }

    // Signals *before* raw mode: between `tcsetattr` and an installed
    // handler a SIGTERM would kill the client with the terminal still raw,
    // which is the one outcome the restore machinery exists to prevent.
    //
    // Nothing to restore yet — the terminal is still cooked — so a spawn
    // failure here is just `orphan`'s usual "session is still running"
    // report (BRIEF-6 §1.4: `spawn` used to `.expect()`, which would panic
    // *after* the session was created but leave the operator with no idea
    // it was still running).
    spawn_signal_pump(stream.handle(), &RealThreadSpawn).map_err(|err| {
        orphan(OpError::new(
            ErrorCode::Internal,
            format!("cannot start the signal-handling thread: {err}"),
        ))
    })?;

    let raw = RawMode::enter().map_err(|err| {
        orphan(OpError::new(
            ErrorCode::Internal,
            format!("cannot put the terminal in raw mode: {err}"),
        ))
    })?;
    #[cfg(debug_assertions)]
    test_panic_hook();

    let detached = Arc::new(AtomicBool::new(false));
    // Escape processing is a *terminal* feature: with a pipe or a file on
    // stdin every byte is forwarded verbatim (`docs/CLI.md` §7).
    let is_raw = raw.is_raw();
    let escape = escape.filter(|_| is_raw);
    // Past this point the terminal *is* raw, so a spawn failure has to walk
    // the same restore path every other exit does: drop the guard (`term::
    // restore`, via `RawMode`'s `Drop`) before reporting anything, the same
    // ordering `drop(raw)` uses lower down for the ordinary exit path
    // (BRIEF-6 §1.4 — this used to `.expect()` here, which panics with the
    // terminal already switched and no guard on the unwinding stack to put
    // it back). The `Err` branch below and this ordering — `drop(raw)`
    // *before* `orphan`'s stderr note, not after — are read-verified but
    // not test-pinned: reaching the branch needs a real spawn failure
    // (`spawn_input_pump`'s own unit tests use a stub `PumpHandle` and
    // never call this closure at all), and a mutation deleting this
    // `drop(raw)` was confirmed to slip past the full `qsh-cli` suite
    // (verify-lens 2, BRIEF-6 §1.4 mutation d2).
    if let Err(err) = spawn_input_pump(
        stream.handle(),
        escape,
        Arc::clone(&detached),
        is_raw,
        &RealThreadSpawn,
    ) {
        drop(raw);
        return Err(orphan(OpError::new(
            ErrorCode::Internal,
            format!("cannot start the input pump thread: {err}"),
        )));
    }

    let outcome = pump_events(&mut stream, &detached, is_raw);

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
fn pump_events(stream: &mut SessionAttachStream, detached: &AtomicBool, raw: bool) -> Outcome {
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
                note(
                    raw,
                    &format!("output was dropped; the session resumed at offset {available_from}"),
                );
            }
            // The principal is the peer's to choose, so it is sanitised
            // before it reaches a terminal (`render::human::sanitize`).
            SessionEvent::WriterChanged { writer, .. } => match writer {
                Some(writer) => note(
                    raw,
                    &format!("the writer lease moved to {}", human::sanitize(&writer)),
                ),
                None => note(raw, "the writer lease was released"),
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
            stderr_note!("qsh: detached; the session keeps running");
            Ok(0)
        }
        // Remote `0..=254` verbatim, remote `255` clamped to `254`, exactly
        // like `qsh exec` (`docs/CLI.md` §4). A signal-killed child has no
        // exit code of its own on this path — `session.exit` carries the
        // *name* and a null `exit_code` (§6.4) — so the name is mapped back
        // to the `128 + signo` `qsh exec` reports for the identical death.
        // `254` is then left meaning what §4 says it means: a status this
        // client never learned.
        Outcome::Exit { code, signal } => {
            if let Some(signal) = &signal {
                stderr_note!(
                    "qsh: the remote process was terminated by {}",
                    human::sanitize(signal)
                );
            }
            let remote = match signal.as_deref().and_then(qsh_core::exec::signal_number) {
                Some(signo) => 128 + signo,
                None => code.unwrap_or(-1),
            };
            Ok(crate::remote_exit_code_to_process_exit(remote))
        }
        Outcome::Closed(reason) => {
            stderr_note!("qsh: the session was closed ({})", human::sanitize(&reason));
            Ok(crate::EXIT_RUNTIME_FAILURE)
        }
        Outcome::Lost => Err(OpError::new(
            ErrorCode::ConnectionFailed,
            "the session ended without a remote exit status",
        )),
        Outcome::Failed(err) => Err(err),
    }
}

/// One diagnostic line on stderr (`docs/CLI.md` §2.2 keeps all of this off
/// stdout).
///
/// `raw` says whether the terminal is in raw mode: it has no output
/// post-processing, so each line has to carry its own CR — while a piped
/// stderr must not be sprinkled with stray CRs.
fn note(raw: bool, message: &str) {
    let end = if raw { "\r\n" } else { "\n" };
    let mut stderr = io::stderr().lock();
    let _ = write!(stderr, "{end}qsh: {message}{end}");
    let _ = stderr.flush();
}

/// stdin → escape machine → the session, on its own thread.
///
/// Detached on purpose: it parks in `read(2)` on the terminal, which
/// nothing but the process exiting can interrupt. It owns no terminal
/// state, so leaving it parked is safe.
///
/// Returns the spawn failure instead of panicking (BRIEF-6 §1.4): by the
/// time the caller can reach here the terminal is already raw, and a
/// `.expect()` here used to leave the operator's terminal stuck raw with a
/// panic backtrace stair-stepped across it — exactly the failure `term::
/// restore_and_die` exists to prevent for signals, just reached from a
/// different door.
fn spawn_input_pump<H: PumpHandle>(
    handle: H,
    escape: Option<u8>,
    detached: Arc<AtomicBool>,
    raw: bool,
    spawner: &dyn ThreadSpawn,
) -> io::Result<()> {
    spawner.spawn(
        "qsh-tui-input",
        Box::new(move || {
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
                if processed.detach {
                    // `~d` must work *especially* when the session is
                    // wedged, so the bytes ahead of it get a non-blocking
                    // attempt rather than the usual backpressure: a full
                    // queue means the host stopped reading and they were
                    // never going to land. The driver still writes what it
                    // accepted before the detach — the queue is ordered —
                    // and a drop is reported, never silent.
                    if !processed.forward.is_empty()
                        && matches!(handle.try_write(processed.forward), Ok(false))
                    {
                        note(raw, "the input typed before the detach was not delivered");
                    }
                    // Announce the detach before ending the attach, so the
                    // event pump reports a detach rather than a lost
                    // connection.
                    detached.store(true, Ordering::SeqCst);
                    if handle.detach() == DetachFlush::Unconfirmed {
                        note(
                            raw,
                            "the host did not confirm the input typed before the detach",
                        );
                    }
                    break;
                }
                if !processed.forward.is_empty() && handle.write(processed.forward).is_err() {
                    break;
                }
            }
        }),
    )
}

/// `SIGWINCH` → `session.resize`, `SIGINT` → the `^C` byte,
/// `SIGTERM`/`SIGHUP`/`SIGQUIT` → restore the terminal and die of the
/// signal.
///
/// Returns once the handlers are installed, so the caller can put the
/// terminal in raw mode knowing a fatal signal will restore it.
///
/// The tokio runtime lives on this thread only, and every `Ops` call is
/// made *after* `block_on` returns — a blocking send from inside a runtime
/// would panic, and the whole client is deliberately synchronous.
///
/// **This loop never blocks on the session.** Once tokio owns the
/// disposition of SIGTERM/SIGHUP/SIGQUIT, a pump parked on a full command
/// queue would make the client undisposable *and* leave the terminal raw —
/// the exact failure [`term::restore_and_die`] exists to prevent. So the
/// session-bound arms use the non-blocking sends and drop what will not
/// fit: a lost resize is re-sent by the next `SIGWINCH`, and a lost `^C`
/// is cheap next to an unkillable process.
///
/// Returns the spawn failure instead of panicking (BRIEF-6 §1.4): this
/// runs before the terminal goes raw, so the caller has nothing to restore
/// yet, but a `.expect()` panic here still used to strand the session the
/// caller already opened with no `orphan` report telling the operator it
/// was still running.
fn spawn_signal_pump<H: PumpHandle>(handle: H, spawner: &dyn ThreadSpawn) -> io::Result<()> {
    let (ready, installed) = std::sync::mpsc::sync_channel(1);
    spawner.spawn(
        "qsh-tui-signals",
        Box::new(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::warn!(%err, "no signal handling for this session");
                    let _ = ready.send(());
                    return;
                }
            };
            let mut signals = match runtime.block_on(async { Signals::install() }) {
                Ok(signals) => signals,
                Err(err) => {
                    tracing::warn!(%err, "no signal handling for this session");
                    // A partial install would leave some of these caught
                    // but never polled — i.e. ignored. Put the defaults
                    // back so the client stays killable.
                    Signals::disarm();
                    let _ = ready.send(());
                    return;
                }
            };
            let _ = ready.send(());
            loop {
                // Note the `block_on` boundary: the runtime context ends
                // when this returns, which is what makes the
                // `AttachHandle` calls below legal.
                match runtime.block_on(signals.next()) {
                    Some(Caught::Winch) => {
                        if let Some((cols, rows)) = term::window_size() {
                            // Only a dead attach ends the pump; the next
                            // event is still a fatal signal we owe the
                            // terminal a restore for.
                            let _ = handle.try_resize(cols, rows);
                        }
                    }
                    // `docs/CLI.md` §9: an interactive attach forwards
                    // SIGINT to the remote PTY. From the keyboard this
                    // never fires (raw mode delivers `^C` as a byte); it is
                    // the `kill -INT` and not-a-TTY cases that land here.
                    Some(Caught::Int) => {
                        let _ = handle.try_write(vec![0x03]);
                    }
                    Some(Caught::Fatal(signal)) => term::restore_and_die(signal),
                    None => return,
                }
            }
        }),
    )?;
    // Bounded: a client with no signal thread is worse off, but hanging
    // here would be worse still.
    let _ = installed.recv_timeout(SIGNALS_READY);
    Ok(())
}

/// The subset of [`AttachHandle`] the two pumps actually call — abstracted
/// so the spawn-failure tests (BRIEF-6 §1.4, verify-lens 2 finding P2) can
/// pass a handle double instead of a live `AttachHandle`, whose fields are
/// private to `qsh-core::ops::session` with no test constructor exposed to
/// `qsh-cli` (building a real one means driving `Ops::session_attach`
/// against a running host or `qsh-testkit`'s harness).
///
/// `write`/`try_write`/`try_resize`/`detach` are exactly the four
/// `AttachHandle` methods `spawn_input_pump` and `spawn_signal_pump` use;
/// grep confirms no other `AttachHandle` method appears in this file.
trait PumpHandle: Send + 'static {
    fn write(&self, data: Vec<u8>) -> Result<(), OpError>;
    fn try_write(&self, data: Vec<u8>) -> Result<bool, OpError>;
    fn try_resize(&self, cols: u16, rows: u16) -> Result<bool, OpError>;
    fn detach(&self) -> DetachFlush;
}

impl PumpHandle for AttachHandle {
    fn write(&self, data: Vec<u8>) -> Result<(), OpError> {
        AttachHandle::write(self, data)
    }

    fn try_write(&self, data: Vec<u8>) -> Result<bool, OpError> {
        AttachHandle::try_write(self, data)
    }

    fn try_resize(&self, cols: u16, rows: u16) -> Result<bool, OpError> {
        AttachHandle::try_resize(self, cols, rows)
    }

    fn detach(&self) -> DetachFlush {
        AttachHandle::detach(self)
    }
}

/// Starts a named background thread — abstracted so the two pumps' spawn
/// failure path (BRIEF-6 §1.4) can be exercised deterministically, the same
/// DI seam `qsh-core`'s `DoctorEnvironment` uses to force `Ops::doctor`'s
/// probes through a stub rather than a real failing OS resource.
trait ThreadSpawn {
    fn spawn(&self, name: &str, body: Box<dyn FnOnce() + Send>) -> io::Result<()>;
}

/// The real spawner: `std::thread::Builder`, detached — the join handle is
/// dropped, matching both pumps' "parks in a blocking syscall for the
/// process's life, never joined" contract (`super`'s module doc).
struct RealThreadSpawn;

impl ThreadSpawn for RealThreadSpawn {
    fn spawn(&self, name: &str, body: Box<dyn FnOnce() + Send>) -> io::Result<()> {
        std::thread::Builder::new()
            .name(name.into())
            .spawn(body)
            .map(|_join| ())
    }
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

/// The signals whose default action ends this process and which therefore
/// have to restore the terminal on the way out.
const FATAL: [nix::sys::signal::Signal; 3] = [
    nix::sys::signal::Signal::SIGTERM,
    nix::sys::signal::Signal::SIGHUP,
    nix::sys::signal::Signal::SIGQUIT,
];

/// The signal streams an interactive attach listens on.
struct Signals {
    winch: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
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
            quit: signal(SignalKind::quit())?,
        })
    }

    /// Put the default disposition back for every fatal signal, for the
    /// case where the install failed halfway: a signal tokio caught but
    /// nobody polls is a signal that has been silently *ignored*.
    fn disarm() {
        for signal in FATAL {
            // SAFETY: restoring a signal's default disposition takes only
            // plain integers and is done from a plain thread.
            unsafe {
                let _ = nix::sys::signal::signal(signal, nix::sys::signal::SigHandler::SigDfl);
            }
        }
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
            signal = self.quit.recv() => {
                signal.map(|()| Caught::Fatal(nix::sys::signal::Signal::SIGQUIT))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A spawner that always fails, standing in for a process that has hit
    /// its thread limit — deterministic in a way the real OS failure never
    /// is (BRIEF-6 §1.4).
    struct FailingThreadSpawn;

    impl ThreadSpawn for FailingThreadSpawn {
        fn spawn(&self, _name: &str, _body: Box<dyn FnOnce() + Send>) -> io::Result<()> {
            Err(io::Error::other("no threads left (test double)"))
        }
    }

    /// [`RealThreadSpawn`]'s `Ok` path: it actually starts a thread, whose
    /// body runs on it rather than inline.
    #[test]
    fn real_thread_spawn_starts_a_thread() {
        let (tx, rx) = std::sync::mpsc::channel();
        RealThreadSpawn
            .spawn(
                "qsh-tui-test",
                Box::new(move || {
                    let _ = tx.send(());
                }),
            )
            .expect("spawn");
        rx.recv_timeout(std::time::Duration::from_secs(1))
            .expect("the spawned thread ran its body");
    }

    /// [`PumpHandle`] double: reports success on every call. Stands in for
    /// a live `qsh_core::AttachHandle` (BRIEF-6 §1.4 verify-lens 2, finding
    /// P2) — its fields are private to `qsh-core::ops::session` with no
    /// test constructor exposed to `qsh-cli`, so building a real one means
    /// driving `Ops::session_attach` against a running host or
    /// `qsh-testkit`'s harness, integration-test weight for a spawn-only
    /// question. `spawn_input_pump`/`spawn_signal_pump` only ever call
    /// `spawner.spawn(...)` before touching the handle at all, so a handle
    /// that is never actually exercised still lets a real
    /// `spawn_input_pump(...)`/`spawn_signal_pump(...)` call run and return.
    #[derive(Clone)]
    struct StubHandle;

    impl PumpHandle for StubHandle {
        fn write(&self, _data: Vec<u8>) -> Result<(), OpError> {
            Ok(())
        }

        fn try_write(&self, _data: Vec<u8>) -> Result<bool, OpError> {
            Ok(true)
        }

        fn try_resize(&self, _cols: u16, _rows: u16) -> Result<bool, OpError> {
            Ok(true)
        }

        fn detach(&self) -> DetachFlush {
            DetachFlush::Applied
        }
    }

    /// Pins the one moving part `spawn_input_pump`/`spawn_signal_pump`
    /// changed for BRIEF-6 §1.4: a spawn failure now reaches the caller as
    /// a plain `io::Result::Err` through [`ThreadSpawn::spawn`], not a
    /// `.expect()` panic.
    ///
    /// This is the seam (`ThreadSpawn`) both pumps call through
    /// unconditionally; `run()`'s two call sites then just
    /// `.map_err`/`if let Err` that same `io::Error` into an `OpError`,
    /// which is ordinary, already-covered control flow.
    #[test]
    fn failing_spawner_reports_err_not_panic() {
        let err = FailingThreadSpawn
            .spawn("qsh-tui-test", Box::new(|| {}))
            .expect_err("a failing spawner must report Err, not panic");
        assert_eq!(err.to_string(), "no threads left (test double)");
    }

    /// The actual `spawn_input_pump`/`spawn_signal_pump` `Err` path
    /// (verify-lens 2 finding P2 / mutation d1: restoring
    /// `.expect("spawn the stdin pump")` must make this test fail).
    /// `StubHandle` is never touched — both functions only reach the
    /// handle from inside the spawned closure, which `FailingThreadSpawn`
    /// never runs.
    #[test]
    fn spawn_failure_is_returned_not_panicked() {
        spawn_input_pump(
            StubHandle,
            None,
            Arc::new(AtomicBool::new(false)),
            false,
            &FailingThreadSpawn,
        )
        .expect_err("spawn_input_pump must surface a failing spawner as Err");

        spawn_signal_pump(StubHandle, &FailingThreadSpawn)
            .expect_err("spawn_signal_pump must surface a failing spawner as Err");
    }

    /// The `Ok` path, through the real spawner — checked with the signal
    /// pump only. The input pump's body blocks in stdin `read(2)` for the
    /// life of the process once spawned (by design: it is detached and
    /// never joined, see the pump's own doc comment), so spawning it for
    /// real here would leave a thread parked on this test binary's stdin
    /// for the rest of the run; that is harmless in a production client
    /// that exits with the process, but in `cargo nextest`'s per-test
    /// process it is one more live thread than the next test in this
    /// process needs. `real_thread_spawn_starts_a_thread` above already
    /// pins `RealThreadSpawn`'s `Ok` path in isolation, so the signal pump
    /// is enough to confirm `spawn_signal_pump` itself returns `Ok` end to
    /// end (handlers installed, `ready` signalled, no `Err` mapped).
    #[test]
    fn spawn_success_returns_ok() {
        spawn_signal_pump(StubHandle, &RealThreadSpawn)
            .expect("spawn_signal_pump must return Ok when the spawner succeeds");
    }
}
