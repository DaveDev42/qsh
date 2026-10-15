//! A small console program for the Windows console tests. It drives the
//! console layer of `qsh-cli` (`tui/windows.rs`, included by path in
//! `tui.rs`) and reports what the console did.
//!
//! The ConPTY harness (`qsh_testkit::conpty`) runs this inside a
//! pseudo-console and reads the records from the pseudo-console's output.
//! Every record is one `<<QSH-PROBE key fields>>` token followed by CR-LF,
//! so the harness can find it in a VT stream that also carries the
//! pseudo-console's own escape sequences. Modes print as `0x..`, or `-` when
//! that handle is not a console.
//!
//! # `raw` (the default)
//!
//! Enters raw mode through the real terminal and reads stdin until `0x04`
//! (`^D`) or end of input, with, in order:
//!
//! - `console in=BOOL out=BOOL`, `size COLS ROWS` (or `none`),
//!   `mode-initial in=.. out=..`, `cp-initial in=N out=N`.
//! - `preflight-error CODE`: the console cannot run an interactive session;
//!   the probe exits with status 4.
//! - `mode-raw in=.. out=..`, `cp-raw in=N out=N`, `raw BOOL`, `ready`.
//! - `bytes HEX`: one record per read of stdin, the bytes as they arrived.
//! - `resize COLS ROWS N`: the size poller saw a new size; `N` counts the
//!   callbacks so far, one per distinct change.
//! - `hangup N` and `interrupt`: console control events the terminal
//!   reported.
//! - `mode-final in=.. out=..`, `cp-final ..`, `done resizes=N`, after the
//!   guard is dropped.
//!
//! One option makes the probe end the session another way, with the guard
//! still alive when it reports, so what is observed was done by the exit
//! path and not by the guard's `Drop`: `--panic` (a caught panic, restored
//! by the panic hook), `--break` (a real `CTRL_BREAK_EVENT` sent to this
//! console) and `--close` (the control handler called with
//! `CTRL_CLOSE_EVENT`, which a pseudo-console cannot deliver and still
//! be observed afterwards). Each reports `mode-after-NAME` and
//! `cp-after-NAME`.
//!
//! `QSH_PROBE_INITIAL_CP=N` sets both console code pages to `N` before
//! anything is read, so a test can start from a code page that is not
//! UTF-8 and see it come back.
//!
//! # `line`
//!
//! A cooked-mode control: reads one line with the console's own echo and
//! reports `line-done`. A test uses it to show the harness does see typed
//! text echoed when echo is on.
//!
//! # `wrap PROGRAM [ARGS...]`
//!
//! Runs a program on this console and reports the modes around it:
//! `mode-initial`, `cp-initial`, `child-exit CODE`, `mode-final`,
//! `cp-final`. For checking what a real `qsh` leaves behind.
//!
//! On any other platform it builds as a stub that exits with status 2.

#[cfg(windows)]
mod tui;

#[cfg(not(windows))]
fn main() {
    eprintln!("qsh-console-probe needs a Windows console");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    std::process::exit(probe::run());
}

#[cfg(windows)]
mod probe {
    use std::io::Write as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc::{Sender, channel};
    use std::time::Duration;

    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent, SetConsoleCP, SetConsoleOutputCP,
    };

    use super::tui::terminal::{TermEvent, Terminal as _};
    use super::tui::windows::{
        CTRL_CLOSE_EVENT, ConsoleApi, WindowsTerminal, on_console_event, system,
    };

    const WAIT: Duration = Duration::from_secs(60);

    fn record(key: &str, fields: &str) {
        let mut out = std::io::stdout().lock();
        let _ = write!(out, "<<QSH-PROBE {key} {fields}>>\r\n");
        let _ = out.flush();
    }

    fn mode(mode: Option<u32>) -> String {
        mode.map_or_else(|| "-".to_string(), |m| format!("{m:#x}"))
    }

    fn report_modes(key: &str, api: &dyn ConsoleApi) {
        record(
            key,
            &format!(
                "in={} out={}",
                mode(api.input_mode()),
                mode(api.output_mode())
            ),
        );
    }

    fn report_code_pages(key: &str, api: &dyn ConsoleApi) {
        let (input, output) = api.code_pages();
        record(key, &format!("in={input} out={output}"));
    }

    pub fn run() -> i32 {
        let mut args = std::env::args().skip(1);
        match args.next().as_deref() {
            None | Some("raw") => raw(args.collect()),
            Some("line") => line(),
            Some("wrap") => wrap(args.collect()),
            Some(other) => {
                eprintln!("qsh-console-probe: unknown scenario {other:?}");
                2
            }
        }
    }

    /// How the `raw` scenario ends its session.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Ending {
        Read,
        Panic,
        Break,
        Close,
    }

    fn raw(options: Vec<String>) -> i32 {
        let ending = match options.first().map(String::as_str) {
            None => Ending::Read,
            Some("--panic") => Ending::Panic,
            Some("--break") => Ending::Break,
            Some("--close") => Ending::Close,
            Some(other) => {
                eprintln!("qsh-console-probe: unknown option {other:?}");
                return 2;
            }
        };

        if let Some(cp) = std::env::var("QSH_PROBE_INITIAL_CP")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
        {
            // SAFETY: plain calls that take a code page number.
            unsafe {
                SetConsoleCP(cp);
                SetConsoleOutputCP(cp);
            }
        }
        let api = system::console();
        let term = Arc::new(system::terminal());
        record(
            "console",
            &format!(
                "in={} out={}",
                api.input_mode().is_some(),
                api.output_mode().is_some()
            ),
        );
        match term.window_size() {
            Some((cols, rows)) => record("size", &format!("{cols} {rows}")),
            None => record("size", "none"),
        }
        report_modes("mode-initial", &*api);
        report_code_pages("cp-initial", &*api);

        if let Err(err) = term.preflight() {
            record("preflight-error", &format!("{:?}", err.code));
            return 4;
        }

        // Events before raw mode, as the client does: from here on a
        // control event finds the restore armed.
        let resizes = Arc::new(AtomicU32::new(0));
        let (hangups, hangup_seen) = channel();
        start_events(&term, &resizes, hangups);

        let guard = match term.enter_raw() {
            Ok(guard) => guard,
            Err(err) => {
                record("raw-error", &err.to_string().replace(['\r', '\n'], " "));
                return 5;
            }
        };
        report_modes("mode-raw", &*api);
        report_code_pages("cp-raw", &*api);
        record("raw", &guard.is_raw().to_string());
        record("ready", "");

        match ending {
            Ending::Read => {
                let mut buf = [0u8; 256];
                while let Ok(n) = term.read_stdin(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let chunk = &buf[..n];
                    let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    record("bytes", &hex);
                    if chunk.contains(&0x04) {
                        break;
                    }
                }
            }
            Ending::Panic => {
                let caught = std::panic::catch_unwind(|| panic!("probe panic"));
                assert!(caught.is_err());
                report_modes("mode-after-panic", &*api);
                report_code_pages("cp-after-panic", &*api);
            }
            Ending::Break | Ending::Close => {
                if ending == Ending::Break {
                    // SAFETY: sends CTRL_BREAK to every process on this
                    // console, which is this one and nothing else in a
                    // pseudo-console of its own.
                    let sent = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) };
                    assert_ne!(sent, 0, "GenerateConsoleCtrlEvent failed");
                } else {
                    assert!(on_console_event(CTRL_CLOSE_EVENT));
                }
                // The terminal reported the hang-up, so the handler has
                // already run; the guard is still alive.
                hangup_seen.recv_timeout(WAIT).expect("no hang-up event");
                report_modes("mode-after-event", &*api);
                report_code_pages("cp-after-event", &*api);
            }
        }

        drop(guard);
        report_modes("mode-final", &*api);
        report_code_pages("cp-final", &*api);
        record(
            "done",
            &format!("resizes={}", resizes.load(Ordering::SeqCst)),
        );
        0
    }

    /// The event thread: reports what the terminal's event source yields.
    fn start_events(term: &Arc<WindowsTerminal>, resizes: &Arc<AtomicU32>, hangups: Sender<()>) {
        let term = Arc::clone(term);
        let resizes = Arc::clone(resizes);
        let (ready, started) = channel();
        std::thread::spawn(move || {
            let mut events = match term.open_events() {
                Ok(events) => events,
                Err(err) => {
                    record("events-error", &err.to_string().replace(['\r', '\n'], " "));
                    let _ = ready.send(());
                    return;
                }
            };
            let _ = ready.send(());
            while let Some(event) = events.next_event() {
                match event {
                    TermEvent::Resize => {
                        let n = resizes.fetch_add(1, Ordering::SeqCst) + 1;
                        let (cols, rows) = term.window_size().unwrap_or((0, 0));
                        record("resize", &format!("{cols} {rows} {n}"));
                    }
                    TermEvent::Interrupt => record("interrupt", ""),
                    TermEvent::Hangup(cause) => {
                        record("hangup", &cause.0.to_string());
                        let _ = hangups.send(());
                    }
                }
            }
        });
        let _ = started.recv_timeout(WAIT);
    }

    fn line() -> i32 {
        let mut line = String::new();
        let read = std::io::stdin().read_line(&mut line);
        record("line-done", &format!("{}", read.is_ok()));
        0
    }

    fn wrap(argv: Vec<String>) -> i32 {
        let Some((program, args)) = argv.split_first() else {
            eprintln!("qsh-console-probe: wrap needs a program");
            return 2;
        };
        let api = system::console();
        report_modes("mode-initial", &*api);
        report_code_pages("cp-initial", &*api);
        let code = match std::process::Command::new(program).args(args).status() {
            Ok(status) => status
                .code()
                .map_or_else(|| "none".to_string(), |c| c.to_string()),
            Err(err) => {
                record("spawn-error", &err.to_string().replace(['\r', '\n'], " "));
                return 3;
            }
        };
        record("child-exit", &code);
        report_modes("mode-final", &*api);
        report_code_pages("cp-final", &*api);
        0
    }
}
