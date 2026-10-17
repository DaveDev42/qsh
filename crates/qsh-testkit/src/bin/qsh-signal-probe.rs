//! A console program that reports which event a session signal turned into
//! (ADR-0035 decision 22). Tests run it as the command of a Windows session
//! and read what it received from its exit code in `session.exit`.
//!
//! The ConPTY tests of `qsh-core` and the Windows route tests of `qsh-cli`
//! start it with `qsh_testkit::signal_probe::bin()`.
//!
//! ```text
//! qsh-signal-probe [MODE] [--report FILE] [--ready-event NAME]
//! qsh-signal-probe internal console-ctrl <pid> <c|break>
//! ```
//!
//! Every mode first lets Ctrl-C reach this process (a process started under a
//! parent that ignores it inherits the ignore flag), installs a console
//! control handler, and opens the session's `Usr1` and `Usr2` events by the
//! names in `QSH_SIGNAL_EVENT_USR1` and `QSH_SIGNAL_EVENT_USR2` when they are
//! set. Then it prints `<<QSH-SIGNAL ready>>`. A test sends nothing before it
//! has seen that record: a process that a snapshot lists may not yet be
//! attached to the console, or not yet have its handler.
//!
//! Each event it receives is one record, `<<QSH-SIGNAL event NAME>>`, and a
//! line `NAME` appended to the `--report` file (the names and exit codes are
//! in `qsh_testkit::signal_probe`).
//!
//! # Modes
//!
//! - `exit` (the default): ends at the first event with the exit code that
//!   stands for it. A program ended by `CTRL_CLOSE_EVENT` ends inside the
//!   handler, so the code is the event's even though Windows ends the
//!   process once the handler returns.
//! - `hold`: reports every event and keeps running, so the close escalation
//!   has something to end.
//! - `tree`: `exit` plus a child of the same program on the same console
//!   (also in `exit` mode). The parent prints its `ready` record only after
//!   the child has installed its handlers (the child sets the named event
//!   the parent passes with `--ready-event`, and prints no `ready` of its
//!   own). After its own event the parent waits for the child and prints
//!   `<<QSH-SIGNAL child-exit CODE>>`. A test uses it to show that an event
//!   reaches every process on the console.
//! - `env`: prints `<<QSH-SIGNAL env-usr1 NAME>>` and `<<QSH-SIGNAL
//!   env-usr2 NAME>>` (`-` for a variable that is not set), each short
//!   enough for one line of a wide console, and then behaves as `hold`.
//!
//! Without an event for two minutes it exits with
//! `qsh_testkit::signal_probe::NO_EVENT_EXIT_CODE`, so a probe that nothing
//! ever signalled does not outlive its test.
//!
//! On any other platform it builds as a stub that exits with status 2.

#[cfg(not(windows))]
fn main() {
    eprintln!("qsh-signal-probe needs a Windows console");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    std::process::exit(probe::run());
}

#[cfg(windows)]
mod probe {
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};

    use qsh_testkit::signal_probe::{
        CTRL_BREAK, CTRL_C, CTRL_CLOSE, CTRL_LOGOFF, CTRL_SHUTDOWN, NO_EVENT_EXIT_CODE, ProbeEvent,
        READY, USR1, USR2, event_record,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
        SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, EVENT_MODIFY_STATE, ExitProcess, OpenEventW, SetEvent,
        WaitForMultipleObjects, WaitForSingleObject,
    };

    /// How long the probe waits for an event before it gives up.
    const DEADLINE_MS: u32 = 120_000;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Exit,
        Hold,
        Tree,
        Env,
    }

    /// Where `--report` appends event names.
    static REPORT: OnceLock<Option<PathBuf>> = OnceLock::new();
    /// Whether the first event ends the process.
    static ENDS_AT_FIRST: AtomicBool = AtomicBool::new(false);
    /// The auto-reset event the console handler sets for the main thread.
    static WAKE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    /// The exit code of the console event the handler saw last.
    static LAST_CODE: AtomicI32 = AtomicI32::new(0);

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.first().map(String::as_str) == Some("internal") {
            return console_ctrl(&args[1..]);
        }
        let mut mode = Mode::Exit;
        let mut report = None;
        let mut ready_event = None;
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "exit" => mode = Mode::Exit,
                "hold" => mode = Mode::Hold,
                "tree" => mode = Mode::Tree,
                "env" => mode = Mode::Env,
                "--report" => match rest.next() {
                    Some(path) => report = Some(PathBuf::from(path)),
                    None => return usage("--report needs a file"),
                },
                "--ready-event" => match rest.next() {
                    Some(name) => ready_event = Some(name.clone()),
                    None => return usage("--ready-event needs a name"),
                },
                other => return usage(&format!("unknown argument {other:?}")),
            }
        }
        let _ = REPORT.set(report.clone());
        ENDS_AT_FIRST.store(matches!(mode, Mode::Exit | Mode::Tree), Ordering::SeqCst);

        // SAFETY: a null routine with `FALSE` clears this process's ignore
        // flag for Ctrl-C, which it may have inherited; the handler is a
        // plain function that lives for the whole process.
        unsafe {
            SetConsoleCtrlHandler(None, 0);
        }
        // SAFETY: no security attributes, no name: a private event.
        let wake = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        assert!(!wake.is_null(), "CreateEventW failed");
        WAKE.store(wake, Ordering::SeqCst);
        // SAFETY: as above.
        assert_ne!(
            unsafe { SetConsoleCtrlHandler(Some(handler), 1) },
            0,
            "SetConsoleCtrlHandler failed"
        );

        let usr1 = open_event("QSH_SIGNAL_EVENT_USR1", "usr1");
        let usr2 = open_event("QSH_SIGNAL_EVENT_USR2", "usr2");
        if mode == Mode::Env {
            let show = |key: &str| std::env::var(key).unwrap_or_else(|_| "-".to_string());
            record(&format!("env-usr1 {}", show("QSH_SIGNAL_EVENT_USR1")));
            record(&format!("env-usr2 {}", show("QSH_SIGNAL_EVENT_USR2")));
        }
        let child = if mode == Mode::Tree {
            Some(spawn_child())
        } else {
            None
        };
        match &ready_event {
            // A child tells its parent it is set up; the parent speaks for
            // both.
            Some(name) => set_named_event(name),
            None => print_line(READY),
        }

        let code = wait_for_events(wake, usr1, usr2);
        if let Some(mut child) = child {
            let status = child.wait().ok().and_then(|status| status.code());
            record(&format!(
                "child-exit {}",
                status.map_or_else(|| "-".to_string(), |code| code.to_string())
            ));
        }
        code
    }

    fn usage(why: &str) -> i32 {
        eprintln!("qsh-signal-probe: {why}");
        2
    }

    /// `internal console-ctrl <pid> <c|break>`: the same entry `qsh` has, so
    /// a test can start sessions whose host sends Ctrl-C and Ctrl-Break
    /// through this program instead of through `qsh`.
    fn console_ctrl(args: &[String]) -> i32 {
        if args.first().map(String::as_str) != Some("console-ctrl") {
            return usage("expected `internal console-ctrl <pid> <c|break>`");
        }
        let (pid, kind) = match qsh_core::pty::console_ctrl::parse_args(&args[1..]) {
            Ok(parsed) => parsed,
            Err(err) => return usage(&err),
        };
        match qsh_core::pty::console_ctrl::run(pid, kind) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("qsh-signal-probe: console-ctrl: {err}");
                1
            }
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set_named_event(name: &str) {
        let name = wide(name);
        // SAFETY: `name` is NUL-terminated.
        let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
        assert!(!event.is_null(), "open the ready event");
        // SAFETY: a live handle that is closed once.
        unsafe {
            SetEvent(event);
            CloseHandle(event);
        }
    }

    /// The same program in `exit` mode, on this console. Returns once the
    /// child has installed its handlers.
    fn spawn_child() -> std::process::Child {
        let name = format!("Local\\qsh-probe-ready-{}", std::process::id());
        let wname = wide(&name);
        // SAFETY: a named auto-reset event with default security.
        let ready = unsafe { CreateEventW(std::ptr::null(), 0, 0, wname.as_ptr()) };
        assert!(!ready.is_null(), "create the ready event");
        let exe = std::env::current_exe().expect("current_exe");
        let mut command = std::process::Command::new(exe);
        command.arg("exit").arg("--ready-event").arg(&name);
        if let Some(Some(report)) = REPORT.get() {
            command.arg("--report").arg(report);
        }
        let mut child = command.spawn().expect("start the child probe");
        // SAFETY: a live handle. The wait ends early if the child dies.
        let waited = unsafe { WaitForSingleObject(ready, 30_000) };
        // SAFETY: closed once.
        unsafe { CloseHandle(ready) };
        if waited != WAIT_OBJECT_0 {
            let _ = child.kill();
            panic!("the child probe never became ready");
        }
        child
    }

    fn print_line(line: &str) {
        let mut out = std::io::stdout().lock();
        let _ = write!(out, "{line}\r\n");
        let _ = out.flush();
    }

    fn record(fields: &str) {
        print_line(&format!("<<QSH-SIGNAL {fields}>>"));
    }

    /// One record for a received event, and its line in the report file.
    fn report(event: ProbeEvent) {
        print_line(&event_record(event.name));
        if let Some(Some(path)) = REPORT.get()
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            // One write, so two processes reporting at once do not interleave.
            let _ = file.write_all(format!("{}\n", event.name).as_bytes());
        }
    }

    fn open_event(variable: &str, label: &str) -> Option<HANDLE> {
        let name = wide(&std::env::var(variable).ok()?);
        // SAFETY: `name` is a NUL-terminated name.
        let handle = unsafe { OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, 0, name.as_ptr()) };
        if handle.is_null() {
            let err = std::io::Error::last_os_error();
            record(&format!("open-failed {label} {err}"));
            return None;
        }
        Some(handle)
    }

    unsafe extern "system" fn handler(ctrl_type: u32) -> i32 {
        let event = match ctrl_type {
            CTRL_C_EVENT => CTRL_C,
            CTRL_BREAK_EVENT => CTRL_BREAK,
            CTRL_CLOSE_EVENT => CTRL_CLOSE,
            CTRL_LOGOFF_EVENT => CTRL_LOGOFF,
            CTRL_SHUTDOWN_EVENT => CTRL_SHUTDOWN,
            _ => return 0,
        };
        report(event);
        if matches!(ctrl_type, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
            LAST_CODE.store(event.exit_code, Ordering::SeqCst);
            // SAFETY: the wake event outlives the handler (it is never closed).
            unsafe { SetEvent(WAKE.load(Ordering::SeqCst)) };
            return 1;
        }
        // Windows ends the process when the handler for a close, logoff or
        // shutdown event returns, so a probe that is to report this event
        // as its exit code has to end here.
        if ENDS_AT_FIRST.load(Ordering::SeqCst) {
            // SAFETY: ends the process; nothing runs after it.
            unsafe { ExitProcess(event.exit_code as u32) };
        }
        1
    }

    /// Wait for events and return the exit code of the first, or keep
    /// reporting them in `hold` mode.
    fn wait_for_events(wake: HANDLE, usr1: Option<HANDLE>, usr2: Option<HANDLE>) -> i32 {
        let mut handles = vec![wake];
        let mut usr = Vec::new();
        for (handle, event) in [(usr1, USR1), (usr2, USR2)] {
            if let Some(handle) = handle {
                handles.push(handle);
                usr.push(event);
            }
        }
        loop {
            // SAFETY: `handles` holds live event handles.
            let waited = unsafe {
                WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, DEADLINE_MS)
            };
            if waited == WAIT_TIMEOUT {
                return NO_EVENT_EXIT_CODE;
            }
            let Some(index) = waited.checked_sub(WAIT_OBJECT_0) else {
                return NO_EVENT_EXIT_CODE;
            };
            let index = index as usize;
            let code = if index == 0 {
                // The handler already reported the console event.
                LAST_CODE.load(Ordering::SeqCst)
            } else if let Some(event) = usr.get(index - 1) {
                report(*event);
                event.exit_code
            } else {
                return NO_EVENT_EXIT_CODE;
            };
            if ENDS_AT_FIRST.load(Ordering::SeqCst) {
                return code;
            }
        }
    }
}
