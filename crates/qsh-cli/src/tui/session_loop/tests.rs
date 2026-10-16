//! Tests of the platform-neutral driver, on a fake [`Terminal`].
//!
//! Compiled on every CI leg: nothing here touches a real terminal, signal or
//! console. The pumps are started on [`InlineSpawn`], which runs the thread
//! body to completion on the calling thread, so each test reads its result
//! after the call returns instead of waiting for it.

use std::collections::VecDeque;
use std::sync::Mutex;

use super::*;
use crate::tui::terminal::{EventSource, HangupCause, RawGuard, TermEvent, Terminal};

/// A fresh "detached" flag, as the driver creates one per attach.
fn no_detach() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// Runs the thread body inline, to completion.
struct InlineSpawn;

impl ThreadSpawn for InlineSpawn {
    fn spawn(&self, _name: &str, body: Box<dyn FnOnce() + Send>) -> io::Result<()> {
        body();
        Ok(())
    }
}

/// A terminal that reads a script and records what the driver asked of it.
#[derive(Default)]
struct FakeTerminal {
    size: Mutex<Option<(u16, u16)>>,
    input: Mutex<VecDeque<Vec<u8>>>,
    events: Mutex<VecDeque<TermEvent>>,
    hangups: Mutex<Vec<HangupCause>>,
    /// What [`Terminal::detaches_on_hangup`] answers.
    detaches: bool,
}

impl FakeTerminal {
    fn arc() -> Arc<dyn Terminal> {
        Arc::new(Self::default())
    }

    /// A terminal whose stdin delivers `chunks`, one `read` each, then EOF.
    fn with_input(chunks: &[&[u8]]) -> Arc<Self> {
        let terminal = Self::default();
        *terminal.input.lock().unwrap() = chunks.iter().map(|c| c.to_vec()).collect();
        Arc::new(terminal)
    }

    /// A terminal of the given size that reports `events` in order.
    fn with_events(size: Option<(u16, u16)>, events: &[TermEvent]) -> Arc<Self> {
        let terminal = Self::default();
        *terminal.size.lock().unwrap() = size;
        *terminal.events.lock().unwrap() = events.iter().copied().collect();
        Arc::new(terminal)
    }
}

struct FakeRaw;

impl RawGuard for FakeRaw {
    fn is_raw(&self) -> bool {
        true
    }
}

struct FakeEvents(VecDeque<TermEvent>);

impl EventSource for FakeEvents {
    fn next_event(&mut self) -> Option<TermEvent> {
        self.0.pop_front()
    }
}

impl Terminal for FakeTerminal {
    fn window_size(&self) -> Option<(u16, u16)> {
        *self.size.lock().unwrap()
    }

    fn enter_raw(&self) -> io::Result<Box<dyn RawGuard>> {
        Ok(Box::new(FakeRaw))
    }

    fn read_stdin(&self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(chunk) = self.input.lock().unwrap().pop_front() else {
            return Ok(0);
        };
        assert!(
            chunk.len() <= buf.len(),
            "a scripted chunk exceeds the read size"
        );
        buf[..chunk.len()].copy_from_slice(&chunk);
        Ok(chunk.len())
    }

    fn open_events(&self) -> io::Result<Box<dyn EventSource>> {
        Ok(Box::new(FakeEvents(std::mem::take(
            &mut *self.events.lock().unwrap(),
        ))))
    }

    fn detaches_on_hangup(&self) -> bool {
        self.detaches
    }

    fn leave_on_hangup(&self, cause: HangupCause) {
        self.hangups.lock().unwrap().push(cause);
    }
}

/// What the pumps asked of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Write(Vec<u8>),
    TryWrite(Vec<u8>),
    TryResize(u16, u16),
    Detach,
}

/// A [`PumpHandle`] that records every call.
#[derive(Clone, Default)]
struct RecordingHandle(Arc<Mutex<Vec<Call>>>);

impl RecordingHandle {
    fn calls(&self) -> Vec<Call> {
        self.0.lock().unwrap().clone()
    }

    /// Every byte the session was given, in order, however it was sent.
    fn written(&self) -> Vec<u8> {
        self.calls()
            .into_iter()
            .flat_map(|call| match call {
                Call::Write(bytes) | Call::TryWrite(bytes) => bytes,
                Call::TryResize(..) | Call::Detach => Vec::new(),
            })
            .collect()
    }
}

impl PumpHandle for RecordingHandle {
    fn write(&self, data: Vec<u8>) -> Result<(), OpError> {
        self.0.lock().unwrap().push(Call::Write(data));
        Ok(())
    }

    fn try_write(&self, data: Vec<u8>) -> Result<bool, OpError> {
        self.0.lock().unwrap().push(Call::TryWrite(data));
        Ok(true)
    }

    fn try_resize(&self, cols: u16, rows: u16) -> Result<bool, OpError> {
        self.0.lock().unwrap().push(Call::TryResize(cols, rows));
        Ok(true)
    }

    fn detach(&self) -> DetachFlush {
        self.0.lock().unwrap().push(Call::Detach);
        DetachFlush::Applied
    }
}

/// Run the input pump over `chunks` and return what the session saw and
/// whether the pump announced a detach.
fn run_input(escape: Option<u8>, chunks: &[&[u8]]) -> (RecordingHandle, bool) {
    let handle = RecordingHandle::default();
    let detached = Arc::new(AtomicBool::new(false));
    spawn_input_pump(
        handle.clone(),
        escape,
        Arc::clone(&detached),
        true,
        FakeTerminal::with_input(chunks),
        &InlineSpawn,
    )
    .expect("the inline spawner cannot fail");
    (handle, detached.load(Ordering::SeqCst))
}

/// Run the signal pump over `events` and return the session's calls and the
/// terminal, for what it was asked to do.
fn run_events(
    size: Option<(u16, u16)>,
    events: &[TermEvent],
) -> (RecordingHandle, Arc<FakeTerminal>) {
    let handle = RecordingHandle::default();
    let terminal = FakeTerminal::with_events(size, events);
    spawn_signal_pump(handle.clone(), terminal.clone(), no_detach(), &InlineSpawn)
        .expect("the inline spawner cannot fail");
    (handle, terminal)
}

/// Every byte value reaches the session unchanged and in order, with the
/// escape machine on and with it off, however the input is chunked. The
/// escape character is only special at the start of a line, and the run
/// 0..=255 never leaves a `~` at one.
#[test]
fn session_loop_forwards_stdin_bytes_verbatim() {
    let bytes: Vec<u8> = (0u8..=255).collect();
    for escape in [Some(b'~'), None] {
        let (handle, detached) = run_input(escape, &[&bytes]);
        assert_eq!(handle.written(), bytes, "escape {escape:?}");
        assert!(!detached);
        assert!(!handle.calls().contains(&Call::Detach));

        let (first, second) = bytes.split_at(97);
        let (handle, _) = run_input(escape, &[first, second]);
        assert_eq!(handle.written(), bytes, "split input, escape {escape:?}");
    }
}

/// `~.` right after a newline detaches: what was typed before it is
/// delivered, the detach is announced before it is sent, and nothing after
/// it is read.
#[test]
fn session_loop_tilde_dot_at_line_start_detaches() {
    let (handle, detached) = run_input(Some(b'~'), &[b"ls\r", b"~.", b"never read\r"]);
    assert_eq!(
        handle.calls(),
        vec![Call::Write(b"ls\r".to_vec()), Call::Detach]
    );
    assert!(
        detached,
        "the event pump has to see a detach, not a lost connection"
    );

    // The same at the very start of the input, where nothing has been
    // forwarded yet.
    let (handle, detached) = run_input(Some(b'~'), &[b"~."]);
    assert_eq!(handle.calls(), vec![Call::Detach]);
    assert!(detached);
}

/// `~.` in the middle of a line is ordinary input.
#[test]
fn session_loop_tilde_inside_a_line_is_plain_input() {
    let (handle, detached) = run_input(Some(b'~'), &[b"echo a ~.", b"\r"]);
    assert_eq!(handle.written(), b"echo a ~.\r");
    assert!(!detached);
    assert!(!handle.calls().contains(&Call::Detach));
}

/// One size event becomes exactly one resize, carrying the size the
/// terminal reports when the event is handled.
#[test]
fn session_loop_size_change_sends_one_resize() {
    let (handle, terminal) = run_events(Some((100, 40)), &[TermEvent::Resize]);
    assert_eq!(handle.calls(), vec![Call::TryResize(100, 40)]);
    assert!(terminal.hangups.lock().unwrap().is_empty());

    // A terminal that cannot report a size (stdin is not one) sends nothing.
    let (handle, _) = run_events(None, &[TermEvent::Resize]);
    assert_eq!(handle.calls(), vec![]);
}

/// A hang-up hands the terminal to its `leave_on_hangup` once and ends the
/// pump: nothing is written to the session, no detach or close is sent, and
/// events behind it are not acted on. The host keeps the session
/// (`docs/CLI.md` §7).
#[test]
fn session_loop_hangup_signal_detaches_and_keeps_the_session() {
    let cause = HangupCause(1);
    let (handle, terminal) = run_events(
        Some((80, 24)),
        &[
            TermEvent::Hangup(cause),
            TermEvent::Resize,
            TermEvent::Interrupt,
        ],
    );
    assert_eq!(*terminal.hangups.lock().unwrap(), vec![cause]);
    assert_eq!(handle.calls(), vec![], "the session is left as it is");
}

/// A terminal whose process ends with its hang-up handler asks for a detach
/// instead: the attach is detached as `~d` does, flagged first so the event
/// pump reports a detach, and the terminal is not asked to leave (the client
/// ends through its ordinary exit).
#[test]
fn session_loop_hangup_is_a_detach_when_the_terminal_asks() {
    let handle = RecordingHandle::default();
    let terminal = Arc::new(FakeTerminal {
        detaches: true,
        ..FakeTerminal::default()
    });
    *terminal.events.lock().unwrap() =
        [TermEvent::Hangup(HangupCause(2)), TermEvent::Interrupt].into();
    let detached = no_detach();
    spawn_signal_pump(
        handle.clone(),
        terminal.clone(),
        Arc::clone(&detached),
        &InlineSpawn,
    )
    .expect("the inline spawner cannot fail");
    assert!(detached.load(Ordering::SeqCst));
    assert_eq!(handle.calls(), vec![Call::Detach]);
    assert!(terminal.hangups.lock().unwrap().is_empty());
}

/// An interrupt that did not come from the keyboard is the `^C` byte.
#[test]
fn session_loop_interrupt_is_forwarded_as_ctrl_c() {
    let (handle, _) = run_events(None, &[TermEvent::Interrupt]);
    assert_eq!(handle.calls(), vec![Call::TryWrite(vec![0x03])]);
}

/// A spawner that always fails, standing in for a process that has hit
/// its thread limit — deterministic in a way the real OS failure never
/// is.
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
/// a live `qsh_core::AttachHandle` (verify-lens 2, finding P2) — its
/// fields are private to `qsh-core::ops::session` with no
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
/// changed: a spawn failure now reaches the caller as a plain
/// `io::Result::Err` through [`ThreadSpawn::spawn`], not a
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
        FakeTerminal::arc(),
        &FailingThreadSpawn,
    )
    .expect_err("spawn_input_pump must surface a failing spawner as Err");

    spawn_signal_pump(
        StubHandle,
        FakeTerminal::arc(),
        no_detach(),
        &FailingThreadSpawn,
    )
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
#[cfg(unix)]
#[test]
fn spawn_success_returns_ok() {
    spawn_signal_pump(
        StubHandle,
        Arc::new(super::super::unix::UnixTerminal),
        no_detach(),
        &RealThreadSpawn,
    )
    .expect("spawn_signal_pump must return Ok when the spawner succeeds");
}

/// A console whose conhost cannot interpret VT output, as one older than
/// Windows 10 1809: everything else works.
struct NoVtConsole;

impl crate::tui::windows::ConsoleApi for NoVtConsole {
    fn input_mode(&self) -> Option<u32> {
        Some(0x07)
    }

    fn set_input_mode(&self, _mode: u32) -> io::Result<()> {
        Ok(())
    }

    fn output_mode(&self) -> Option<u32> {
        Some(0x03)
    }

    fn set_output_mode(&self, mode: u32) -> io::Result<()> {
        if mode & crate::tui::console_mode::ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return Err(io::Error::other("VT processing refused"));
        }
        Ok(())
    }

    fn code_pages(&self) -> (u32, u32) {
        (437, 437)
    }

    fn set_code_pages(&self, _input: u32, _output: u32) -> io::Result<()> {
        Ok(())
    }

    fn window_size(&self) -> Option<(u16, u16)> {
        Some((80, 24))
    }

    fn read_stdin(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }

    fn install_ctrl_handler(&self) -> io::Result<()> {
        Ok(())
    }
}

struct NoSleep;

impl crate::tui::windows::Sleep for NoSleep {
    fn sleep(&self, _duration: std::time::Duration) {}
}

/// A console that cannot show VT output ends the interactive form with
/// `UNSUPPORTED` that names Windows 10 1809, and ends it *before*
/// `session.open`: the host is pinned and listening, and it sees no
/// datagram at all, so no session was opened there to be orphaned.
#[test]
fn vt_unavailable_is_unsupported_before_session_open() {
    use qsh_core::Paths;
    use qsh_proto::{IdentityInitReq, KeyStoreMode, TrustAddReq};

    let dir = tempfile::tempdir().expect("tempdir");
    let ops = Ops::new(Paths::new(
        dir.path().join("config"),
        dir.path().join("state"),
    ));
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        import_ssh_key: None,
    })
    .expect("init an identity");

    let host = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind the fake host");
    host.set_nonblocking(true).expect("non-blocking");
    ops.trust_add(TrustAddReq {
        name: "fakehost".into(),
        address: Some(host.local_addr().expect("address").to_string()),
        fingerprint: Some(format!("sha256:{}", "A".repeat(43))),
        cert_pem: None,
        role: None,
    })
    .expect("pin the fake host");

    let terminal = Arc::new(crate::tui::windows::WindowsTerminal::new(
        Arc::new(NoVtConsole),
        Arc::new(NoSleep),
    ));
    let err = run(
        &ops,
        Attach::Open {
            host: "fakehost".into(),
            user: None,
            forwards: Vec::new(),
            remote_forwards: Vec::new(),
            dynamic_forwards: Vec::new(),
        },
        Some(b'~'),
        terminal,
    )
    .expect_err("a console without VT cannot run an interactive session");

    assert_eq!(err.code, ErrorCode::Unsupported);
    assert!(err.message.contains("1809"), "{}", err.message);
    let mut datagram = [0u8; 2048];
    assert!(
        matches!(
            host.recv_from(&mut datagram),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
        ),
        "the host heard from the client although the console was refused"
    );
}

/// The Windows client's signal table agrees with the POSIX one on every
/// name it knows, so a remote death by signal exits with the same code from
/// either client; a name it does not know is `None`, never a wrong number.
#[test]
fn portable_signal_numbers_are_the_shared_posix_ones() {
    for (name, signo) in [
        ("SIGHUP", 1),
        ("SIGINT", 2),
        ("SIGQUIT", 3),
        ("SIGKILL", 9),
        ("SIGSEGV", 11),
        ("SIGPIPE", 13),
        ("SIGTERM", 15),
        ("SIG34", 34),
    ] {
        assert_eq!(portable_signal_number(name), Some(signo), "{name}");
    }
    assert_eq!(portable_signal_number("SIGUSR1"), None);
    assert_eq!(portable_signal_number("TERM"), None);
    #[cfg(unix)]
    for name in [
        "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGFPE", "SIGKILL",
        "SIGSEGV", "SIGPIPE", "SIGALRM", "SIGTERM",
    ] {
        assert_eq!(
            portable_signal_number(name),
            qsh_core::exec::signal_number(name),
            "{name}"
        );
    }
}
