//! Tests of the Windows console terminal over a fake console.
//!
//! Compiled on every CI leg: nothing here calls Win32. What needs the real
//! console (raw input bytes, resize through a pseudo-console, the modes after
//! a panic or a close event in a live process) is `tests/it/console_probe.rs`.

use std::sync::mpsc::{Receiver, Sender, channel};

use super::*;
use crate::tui::console_mode::{
    DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
};

/// A cooked console as Windows hands it out.
const COOKED_IN: u32 = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | 0x40;
const COOKED_OUT: u32 = 0x01 | 0x02;

/// The statics (`ACTIVE`, `EVENTS`, the panic hook) are process-wide, so the
/// tests that arm a terminal take turns even when the harness runs them as
/// threads of one process.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug)]
struct State {
    input: Option<u32>,
    output: Option<u32>,
    code_pages: (u32, u32),
    size: Option<(u16, u16)>,
    /// Refuse VT output processing, as a conhost older than 1809 does.
    refuse_vt_output: bool,
    /// Refuse VT input.
    refuse_vt_input: bool,
    /// Every mutation, in order, for the tests that pin the order or count.
    calls: Vec<String>,
    window_reads: u32,
}

/// A console that records what it is asked.
struct FakeConsole(Mutex<State>);

impl FakeConsole {
    fn cooked() -> Arc<Self> {
        Arc::new(Self(Mutex::new(State {
            input: Some(COOKED_IN),
            output: Some(COOKED_OUT),
            code_pages: (437, 437),
            size: Some((80, 24)),
            refuse_vt_output: false,
            refuse_vt_input: false,
            calls: Vec::new(),
            window_reads: 0,
        })))
    }

    fn with(edit: impl FnOnce(&mut State)) -> Arc<Self> {
        let console = Self::cooked();
        edit(&mut console.0.lock().unwrap());
        console
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn modes(&self) -> (Option<u32>, Option<u32>, (u32, u32)) {
        let s = self.state();
        (s.input, s.output, s.code_pages)
    }

    fn calls(&self) -> Vec<String> {
        self.state().calls.clone()
    }
}

impl ConsoleApi for FakeConsole {
    fn input_mode(&self) -> Option<u32> {
        self.state().input
    }

    fn set_input_mode(&self, mode: u32) -> io::Result<()> {
        let mut s = self.state();
        if s.refuse_vt_input && mode & ENABLE_VIRTUAL_TERMINAL_INPUT != 0 {
            return Err(io::Error::other("VT input refused"));
        }
        s.calls.push(format!("in={mode:#x}"));
        s.input = Some(mode);
        Ok(())
    }

    fn output_mode(&self) -> Option<u32> {
        self.state().output
    }

    fn set_output_mode(&self, mode: u32) -> io::Result<()> {
        let mut s = self.state();
        if s.refuse_vt_output && mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return Err(io::Error::other("VT output refused"));
        }
        s.calls.push(format!("out={mode:#x}"));
        s.output = Some(mode);
        Ok(())
    }

    fn code_pages(&self) -> (u32, u32) {
        self.state().code_pages
    }

    fn set_code_pages(&self, input: u32, output: u32) -> io::Result<()> {
        let mut s = self.state();
        s.calls.push(format!("cp={input},{output}"));
        s.code_pages = (input, output);
        Ok(())
    }

    fn window_size(&self) -> Option<(u16, u16)> {
        let mut s = self.state();
        s.window_reads += 1;
        s.size
    }

    fn read_stdin(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }

    fn install_ctrl_handler(&self) -> io::Result<()> {
        Ok(())
    }
}

/// A pause that does not pass until the test says so.
struct GateSleep(Mutex<Receiver<()>>);

impl Sleep for GateSleep {
    fn sleep(&self, _duration: Duration) {
        // A closed gate ends the poll thread with the test.
        if self.0.lock().unwrap().recv().is_err() {
            loop {
                std::thread::park();
            }
        }
    }
}

/// A pause that never waits.
struct NoSleep;

impl Sleep for NoSleep {
    fn sleep(&self, _duration: Duration) {}
}

fn terminal(console: &Arc<FakeConsole>) -> WindowsTerminal {
    WindowsTerminal::new(console.clone(), Arc::new(NoSleep))
}

fn gate() -> (Sender<()>, Arc<GateSleep>) {
    let (tx, rx) = channel();
    (tx, Arc::new(GateSleep(Mutex::new(rx))))
}

const RAW_IN: u32 = (COOKED_IN & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
    | ENABLE_VIRTUAL_TERMINAL_INPUT;
const RAW_OUT: u32 = COOKED_OUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;

#[test]
fn raw_mode_sets_the_documented_modes_and_utf8_and_dropping_restores_them() {
    let _serial = serial();
    let console = FakeConsole::cooked();
    let term = terminal(&console);
    let guard = term.enter_raw().unwrap();
    assert!(guard.is_raw());
    assert_eq!(
        console.modes(),
        (Some(RAW_IN), Some(RAW_OUT), (CP_UTF8, CP_UTF8))
    );
    drop(guard);
    assert_eq!(
        console.modes(),
        (Some(COOKED_IN), Some(COOKED_OUT), (437, 437)),
        "the original modes and code pages are back"
    );
}

#[test]
fn restoring_runs_once_however_many_paths_ask() {
    let _serial = serial();
    let console = FakeConsole::cooked();
    let term = terminal(&console);
    let guard = term.enter_raw().unwrap();
    // The guard's Drop, the panic hook and the console handler can all race.
    restore_active();
    term.restorer.restore();
    let after_first = console.calls();
    drop(guard);
    restore_active();
    assert_eq!(console.calls(), after_first, "nothing is restored twice");
    assert_eq!(console.modes().0, Some(COOKED_IN));
}

#[test]
fn a_failed_raw_switch_restores_what_it_changed() {
    let _serial = serial();
    let console = FakeConsole::with(|s| s.refuse_vt_output = true);
    let term = terminal(&console);
    assert!(term.enter_raw().is_err());
    assert_eq!(
        console.modes(),
        (Some(COOKED_IN), Some(COOKED_OUT), (437, 437))
    );
}

#[test]
fn a_console_output_with_a_piped_stdin_gets_vt_but_no_raw_input() {
    let _serial = serial();
    let console = FakeConsole::with(|s| s.input = None);
    let term = terminal(&console);
    assert_eq!(term.window_size(), None, "no size without a console stdin");
    let guard = term.enter_raw().unwrap();
    assert!(!guard.is_raw(), "escape processing stays off for a pipe");
    assert_eq!(console.state().input, None);
    assert_eq!(console.state().output, Some(RAW_OUT));
    drop(guard);
    assert_eq!(console.state().output, Some(COOKED_OUT));
}

#[test]
fn a_console_output_with_a_piped_stdin_still_announces_xterm_256color() {
    let console = FakeConsole::with(|s| s.input = None);
    let term = terminal(&console);
    term.preflight().unwrap();
    assert_eq!(term.fallback_term(), Some("xterm-256color"));
}

#[test]
fn a_piped_stdout_announces_no_terminal() {
    let console = FakeConsole::with(|s| s.output = None);
    let term = terminal(&console);
    term.preflight().unwrap();
    assert_eq!(term.fallback_term(), None);
}

#[test]
fn no_console_at_all_changes_nothing() {
    let _serial = serial();
    let console = FakeConsole::with(|s| {
        s.input = None;
        s.output = None;
    });
    let term = terminal(&console);
    term.preflight().unwrap();
    assert_eq!(term.fallback_term(), None);
    let guard = term.enter_raw().unwrap();
    assert!(!guard.is_raw());
    drop(guard);
    assert!(console.calls().is_empty(), "{:?}", console.calls());
}

#[test]
fn preflight_refuses_a_console_without_vt_and_names_the_windows_floor() {
    for (label, console) in [
        ("output", FakeConsole::with(|s| s.refuse_vt_output = true)),
        ("input", FakeConsole::with(|s| s.refuse_vt_input = true)),
    ] {
        let term = terminal(&console);
        let err = term.preflight().expect_err(label);
        assert_eq!(err.code, ErrorCode::Unsupported, "{label}");
        assert!(!err.retryable, "{label}");
        assert!(err.message.contains("1809"), "{label}: {}", err.message);
        assert_eq!(term.fallback_term(), None, "{label}");
        assert_eq!(
            console.modes(),
            (Some(COOKED_IN), Some(COOKED_OUT), (437, 437)),
            "{label}: a refused probe leaves the console as found"
        );
    }
}

#[test]
fn preflight_on_a_vt_console_probes_and_puts_the_modes_back() {
    let console = FakeConsole::cooked();
    let term = terminal(&console);
    assert_eq!(term.fallback_term(), None, "nothing is announced before");
    term.preflight().unwrap();
    assert_eq!(term.fallback_term(), Some("xterm-256color"));
    assert_eq!(
        console.modes(),
        (Some(COOKED_IN), Some(COOKED_OUT), (437, 437))
    );
}

#[test]
fn the_resize_poller_reports_each_change_once() {
    let mut poller = ResizePoller::new(Some((80, 24)));
    assert!(
        !poller.changed(Some((80, 24))),
        "the known size is no change"
    );
    assert!(poller.changed(Some((100, 30))));
    assert!(!poller.changed(Some((100, 30))), "one callback per change");
    assert!(!poller.changed(None), "an unreadable size is no change");
    assert!(poller.changed(Some((80, 24))), "back to the first size");
    // With no size known at the start, the first reading is a change.
    let mut poller = ResizePoller::new(None);
    assert!(poller.changed(Some((80, 24))));
}

/// Wait until `reads` window reads happened, so a poll tick is known to have
/// been processed. A deadline, not a pause: the condition is observable.
fn wait_for_reads(console: &FakeConsole, reads: u32) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while console.state().window_reads < reads {
        assert!(
            std::time::Instant::now() < deadline,
            "the poll thread did not read the size {reads} times"
        );
        std::thread::yield_now();
    }
}

#[test]
fn the_poll_thread_sends_one_resize_per_size_change() {
    let _serial = serial();
    let console = FakeConsole::cooked();
    let (tick, sleeper) = gate();
    let term = WindowsTerminal::new(console.clone(), sleeper);
    let mut events = term.open_events().unwrap();
    // `open_events` read the size once for the poller's starting point.
    let base = console.state().window_reads;

    console.state().size = Some((100, 30));
    tick.send(()).unwrap();
    assert_eq!(events.next_event(), Some(TermEvent::Resize));

    // Same size on the next two ticks: no event.
    tick.send(()).unwrap();
    tick.send(()).unwrap();
    wait_for_reads(&console, base + 3);

    console.state().size = Some((90, 20));
    tick.send(()).unwrap();
    assert_eq!(events.next_event(), Some(TermEvent::Resize));

    // A hang-up queued now arrives next, so no stray resize sits before it.
    assert!(on_console_event(CTRL_BREAK_EVENT));
    assert_eq!(events.next_event(), Some(TermEvent::Hangup(HangupCause(1))));
}

#[test]
fn a_close_event_restores_the_console_and_becomes_a_hangup() {
    let _serial = serial();
    let console = FakeConsole::cooked();
    let term = terminal(&console);
    let mut events = term.open_events().unwrap();
    let guard = term.enter_raw().unwrap();
    assert_eq!(console.modes().0, Some(RAW_IN));

    for (event, number) in [
        (CTRL_CLOSE_EVENT, 2),
        (CTRL_LOGOFF_EVENT, 5),
        (CTRL_SHUTDOWN_EVENT, 6),
        (CTRL_BREAK_EVENT, 1),
    ] {
        assert!(on_console_event(event), "event {event} is handled");
        assert_eq!(
            events.next_event(),
            Some(TermEvent::Hangup(HangupCause(number)))
        );
    }
    assert_eq!(
        console.modes(),
        (Some(COOKED_IN), Some(COOKED_OUT), (437, 437)),
        "the handler restored the console before the guard dropped"
    );
    drop(guard);
}

#[test]
fn a_console_event_with_nobody_attached_restores_and_lets_the_default_run() {
    let _serial = serial();
    let console = FakeConsole::cooked();
    let prompt = EchoSuppressed::enter(console.clone()).unwrap();
    assert_eq!(console.modes().0, Some(COOKED_IN & !ENABLE_ECHO_INPUT));
    // `false` hands the event to the next handler, whose default ends the
    // process, on a console that is already back.
    for event in [CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_BREAK_EVENT] {
        assert!(!on_console_event(event), "event {event}");
    }
    assert_eq!(console.modes().0, Some(COOKED_IN));
    assert!(!on_console_event(3), "an unknown event is not ours");
    drop(prompt);
}

#[test]
fn a_closing_console_notifies_an_armed_process_and_waits_until_it_has_stopped() {
    let _serial = serial();
    let (told, told_rx) = channel();
    arm_shutdown(move || {
        let _ = told.send(());
    });
    // The handler holds the closing window until the process says it is done,
    // so the event runs on its own thread, as the system's would.
    let handler = std::thread::spawn(|| on_console_event(CTRL_CLOSE_EVENT));
    told_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("the armed process is told to stop");
    assert!(
        !handler.is_finished(),
        "the handler keeps the window open while the process is still stopping"
    );
    shutdown_finished();
    assert!(
        handler.join().unwrap(),
        "the event is handled, so the system does not run the next handler"
    );
    // Nothing is armed any more: the default action is left to run.
    assert!(!on_console_event(CTRL_CLOSE_EVENT));
}

#[test]
fn ctrl_c_is_left_to_the_runtime_even_when_a_process_is_armed() {
    let _serial = serial();
    arm_shutdown(|| panic!("Ctrl-C must not reach the close notifier"));
    assert!(!on_console_event(CTRL_C_EVENT));
    shutdown_finished();
}

#[test]
fn an_interrupt_with_a_session_attached_is_forwarded_not_fatal() {
    let _serial = serial();
    let console = FakeConsole::cooked();
    let term = terminal(&console);
    let mut events = term.open_events().unwrap();
    let guard = term.enter_raw().unwrap();
    assert!(on_console_event(CTRL_C_EVENT));
    assert_eq!(events.next_event(), Some(TermEvent::Interrupt));
    assert_eq!(
        console.modes(),
        (Some(RAW_IN), Some(RAW_OUT), (CP_UTF8, CP_UTF8)),
        "the session keeps running, so the console stays raw"
    );
    drop(guard);
}

#[test]
fn a_panic_restores_the_console_before_unwinding() {
    let _serial = serial();
    let console = FakeConsole::cooked();
    let term = terminal(&console);
    let guard = term.enter_raw().unwrap();
    let caught = std::panic::catch_unwind(|| panic!("a panic on some thread"));
    assert!(caught.is_err());
    // The guard is still alive: only the hook can have restored this.
    assert_eq!(
        console.modes(),
        (Some(COOKED_IN), Some(COOKED_OUT), (437, 437))
    );
    drop(guard);
}

#[test]
fn echo_suppression_clears_only_echo_input_and_restores_on_drop() {
    let _serial = serial();
    let console = FakeConsole::cooked();
    let prompt = EchoSuppressed::enter(console.clone()).unwrap();
    let quiet = console.state().input.unwrap();
    assert_eq!(quiet, COOKED_IN & !ENABLE_ECHO_INPUT);
    assert_ne!(quiet & ENABLE_LINE_INPUT, 0, "line editing stays");
    assert_ne!(quiet & ENABLE_PROCESSED_INPUT, 0, "Ctrl-C handling stays");
    assert_eq!(console.state().output, Some(COOKED_OUT), "output untouched");
    assert_eq!(
        console.state().code_pages,
        (437, 437),
        "code pages untouched"
    );
    drop(prompt);
    assert_eq!(console.state().input, Some(COOKED_IN));
}

#[test]
fn echo_suppression_on_a_non_console_stdin_does_nothing() {
    let _serial = serial();
    let console = FakeConsole::with(|s| s.input = None);
    let prompt = EchoSuppressed::enter(console.clone()).unwrap();
    drop(prompt);
    assert!(console.calls().is_empty());
}

#[test]
fn window_size_reads_the_console_window_when_stdin_is_a_console() {
    let console = FakeConsole::with(|s| s.size = Some((132, 43)));
    let term = terminal(&console);
    assert_eq!(term.window_size(), Some((132, 43)));
}
