//! `CTRL_C_EVENT` and `CTRL_BREAK_EVENT` for a session's console, through a
//! helper process (ADR-0035 decision 22).
//!
//! `GenerateConsoleCtrlEvent` reaches only the console the caller is attached
//! to, and attaching is process-global state: a host that attached itself to
//! a session's console would lose its own console handlers, and two sessions
//! signalled at once would fight over the one attachment. So the host never
//! attaches. It starts the hidden entry `qsh internal console-ctrl <pid>
//! <c|break>` as a **detached** process of the same executable, which
//! attaches to the console of the session's root process, ignores the event
//! itself, sends it to every process on that console, and exits. [`run`] is
//! that entry's whole body, and `send` is the host's side of it.
//!
//! The helper reports delivery itself: right after `GenerateConsoleCtrlEvent`
//! returns nonzero it writes one [`DELIVERED`] byte to its stdout (when that
//! is not a terminal) and writes nothing on any failure. The helper's exit
//! status cannot say the same: a helper that delivered the event to a console
//! that then closed may end by that very close, which looks like a failure.
//! `send` waits, bounded, for the byte, so the caller knows synchronously
//! whether the event went out, as with `kill(2)` on unix. This is
//! the only place in the workspace that attaches to a console on behalf of
//! a session; a test pins that.
//!
//! The session's root is created without `CREATE_NEW_PROCESS_GROUP`, so it
//! (and what it starts) receives `CTRL_C_EVENT`. Writing `0x03` into the
//! pseudo-console's input is not an alternative: a program that turned
//! processed input off reads that byte as a character, while `killpg(SIGINT)`
//! on unix reaches it whatever the terminal mode is.
//!
//! The arguments are a process id and one of two words, nothing else
//! ([`parse_args`]). `0` and `0xFFFFFFFF` are not process ids here:
//! `AttachConsole` reads the second as "the parent's console".

use std::fmt;
use std::io;
use std::str::FromStr;

/// Which console control event the helper sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrlKind {
    /// `CTRL_C_EVENT`, `c` on the command line.
    C,
    /// `CTRL_BREAK_EVENT`, `break` on the command line.
    Break,
}

impl CtrlKind {
    /// The word the helper's command line spells this kind as.
    pub const fn as_arg(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Break => "break",
        }
    }
}

impl fmt::Display for CtrlKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_arg())
    }
}

impl FromStr for CtrlKind {
    type Err = String;

    /// Exactly `c` or `break`: no case folding and no other spelling, because
    /// the only caller that is not a person is the host, which sends these
    /// two words.
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "c" => Ok(Self::C),
            "break" => Ok(Self::Break),
            other => Err(format!("expected `c` or `break`, got {other:?}")),
        }
    }
}

/// The one byte the helper writes to its stdout once the event is generated.
pub const DELIVERED: u8 = b'+';

/// Whether `pid` can name a process to attach to.
fn valid_pid(pid: u32) -> bool {
    // `0` is never a process id, and `ATTACH_PARENT_PROCESS` (`(DWORD)-1`)
    // would attach to the parent's console instead of a process's.
    pid != 0 && pid != u32::MAX
}

/// A process id as the helper takes it: decimal digits only (`u32`'s parser
/// would also take a leading `+`), and not `0` or `0xFFFFFFFF`.
pub fn parse_pid(text: &str) -> Result<u32, String> {
    let not_a_pid = || format!("{text:?} is not a process id");
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(not_a_pid());
    }
    let parsed: u32 = text.parse().map_err(|_| not_a_pid())?;
    if !valid_pid(parsed) {
        return Err(not_a_pid());
    }
    Ok(parsed)
}

/// The helper's arguments after `console-ctrl`: a process id and a kind.
pub fn parse_args<S: AsRef<str>>(args: &[S]) -> Result<(u32, CtrlKind), String> {
    let [pid, kind] = args else {
        return Err(format!(
            "expected <pid> <c|break>, got {} argument(s)",
            args.len()
        ));
    };
    Ok((parse_pid(pid.as_ref())?, kind.as_ref().parse()?))
}

/// What the helper does, on a platform that has no console to attach to.
#[cfg(not(windows))]
pub fn run(_pid: u32, _kind: CtrlKind) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "console control events exist only on Windows",
    ))
}

/// The body of `qsh internal console-ctrl <pid> <c|break>`: attach to the
/// console of process `pid`, send `kind` to every process on it, detach.
///
/// The helper is itself on that console while the event goes out, so it
/// ignores the event first (`CTRL_C_EVENT` through the process-wide ignore
/// flag, either kind through a handler that claims it) and detaches again
/// before it exits.
#[cfg(windows)]
pub fn run(pid: u32, kind: CtrlKind) -> io::Result<()> {
    use std::io::{IsTerminal as _, Write as _};

    use windows_sys::Win32::System::Console::{
        AttachConsole, CTRL_BREAK_EVENT, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent,
        SetConsoleCtrlHandler,
    };

    use crate::winproc::os_error;

    if !valid_pid(pid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{pid} is not a process id"),
        ));
    }

    /// Detaches from the console it attached to, however the helper ends.
    struct Detach;
    impl Drop for Detach {
        fn drop(&mut self) {
            // SAFETY: no arguments; harmless when there is no console.
            unsafe { FreeConsole() };
        }
    }

    /// Claims every console event that reaches the helper, so none of them
    /// ends it before it has finished.
    unsafe extern "system" fn claim(_event: u32) -> i32 {
        1
    }

    // Decided before the console changes: a person running the entry by hand
    // gets no stray byte on the terminal.
    let report = !io::stdout().is_terminal();

    // A detached process has no console, but a caller that is not detached
    // does: leave it, since a process is attached to at most one.
    // SAFETY: no arguments; fails harmlessly when there is no console.
    unsafe { FreeConsole() };
    // SAFETY: a plain call; the result is checked.
    if unsafe { AttachConsole(pid) } == 0 {
        return Err(os_error("AttachConsole"));
    }
    let _detach = Detach;
    // SAFETY: a null routine with `TRUE` makes this process ignore
    // `CTRL_C_EVENT`; the routine registered next is a plain function that
    // lives for the whole process.
    unsafe {
        SetConsoleCtrlHandler(None, 1);
        SetConsoleCtrlHandler(Some(claim), 1);
    }
    let event = match kind {
        CtrlKind::C => CTRL_C_EVENT,
        CtrlKind::Break => CTRL_BREAK_EVENT,
    };
    // Process group 0 is every process on the attached console.
    // SAFETY: a plain call; the result is checked.
    if unsafe { GenerateConsoleCtrlEvent(event, 0) } == 0 {
        return Err(os_error("GenerateConsoleCtrlEvent"));
    }
    // Before anything can tear this process down. If the report cannot be
    // written the host sees no byte and treats the event as not delivered;
    // there is no better channel left to tell it on.
    if report {
        let mut out = io::stdout().lock();
        let _ = out.write_all(&[DELIVERED]).and_then(|()| out.flush());
    }
    Ok(())
}

/// How long the host waits for the helper's report. The helper does three
/// system calls; this only passes when the machine is stuck.
#[cfg(windows)]
const REPORT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

/// The host's side: run the helper for the console of process `pid` and
/// return once it has reported. `Ok` means the helper wrote [`DELIVERED`],
/// so the event was generated; any other outcome (the helper could not start,
/// ended without the byte, or took longer than the deadline) is an error and
/// the event must be taken as not sent. `program` is the executable to run as
/// `<program> internal console-ctrl <pid> <kind>`; `None` is this executable.
///
/// This blocks for the helper's lifetime, normally milliseconds. On a
/// multi-threaded runtime it tells the runtime so (`block_in_place`); on any
/// other it blocks the calling thread, which is the session actor's.
#[cfg(windows)]
pub(crate) fn send(program: Option<&std::path::Path>, pid: u32, kind: CtrlKind) -> io::Result<()> {
    use std::io::Read as _;
    use std::os::windows::process::CommandExt as _;

    use windows_sys::Win32::System::Threading::DETACHED_PROCESS;

    let program = match program {
        Some(program) => program.to_path_buf(),
        None => std::env::current_exe()?,
    };
    let blocking = || -> io::Result<()> {
        let mut child = std::process::Command::new(program)
            .args(["internal", "console-ctrl"])
            .arg(pid.to_string())
            .arg(kind.as_arg())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .creation_flags(DETACHED_PROCESS)
            .spawn()?;
        let mut stdout = child.stdout.take().expect("stdout was piped");
        let (tx, rx) = std::sync::mpsc::channel();
        // The reader ends when the helper writes, ends, or is killed below.
        let reader = std::thread::spawn(move || {
            let mut byte = [0u8; 1];
            let _ = tx.send(matches!(stdout.read(&mut byte), Ok(1) if byte[0] == DELIVERED));
        });
        let delivered = rx.recv_timeout(REPORT_DEADLINE);
        if delivered != Ok(true) {
            // No report: make sure nothing is left running, then say why.
            let _ = child.kill();
        }
        let _ = reader.join();
        match delivered {
            Ok(true) => {
                // Reap off this thread; the helper is about to exit.
                drop(std::thread::spawn(move || {
                    let _ = child.wait();
                }));
                Ok(())
            }
            Ok(false) => {
                let status = child
                    .wait()
                    .map_or_else(|e| e.to_string(), |s| s.to_string());
                tracing::warn!(pid, %kind, %status, "the console control helper delivered nothing");
                Err(io::Error::other(format!(
                    "the console control helper did not deliver {kind} ({status})"
                )))
            }
            Err(_) => {
                let _ = child.wait();
                tracing::warn!(pid, %kind, "the console control helper did not report in time; ended it");
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("the console control helper did not report {kind} in time"),
                ))
            }
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(blocking)
        }
        _ => blocking(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_ctrl_args_accept_only_a_real_pid_and_c_or_break() {
        assert_eq!(parse_args(&["4242", "c"]), Ok((4242, CtrlKind::C)));
        assert_eq!(parse_args(&["1", "break"]), Ok((1, CtrlKind::Break)));
        assert_eq!(
            parse_args(&["4294967294", "c"]),
            Ok((u32::MAX - 1, CtrlKind::C))
        );
        for bad in [
            // Not a pid: zero, ATTACH_PARENT_PROCESS, signs, spaces, words.
            ["0", "c"],
            ["4294967295", "c"],
            ["-1", "c"],
            ["+5", "c"],
            [" 5", "c"],
            ["5 ", "c"],
            ["0x10", "c"],
            ["five", "c"],
            ["", "c"],
            ["4294967296", "c"],
            // Not a kind: any other spelling, case, or event.
            ["5", ""],
            ["5", "C"],
            ["5", "Break"],
            ["5", "BREAK"],
            ["5", "ctrl-c"],
            ["5", "close"],
            ["5", "c "],
        ] {
            assert!(parse_args(&bad).is_err(), "{bad:?} must be rejected");
        }
        // Arity.
        assert!(parse_args::<&str>(&[]).is_err());
        assert!(parse_args(&["5"]).is_err());
        assert!(parse_args(&["5", "c", "extra"]).is_err());
        // The word the host sends is the word the helper parses.
        for kind in [CtrlKind::C, CtrlKind::Break] {
            assert_eq!(kind.as_arg().parse(), Ok(kind));
            assert_eq!(kind.to_string(), kind.as_arg());
        }
    }

    /// Where the sources of this crate and of `qsh-cli` live.
    fn source_dirs() -> [std::path::PathBuf; 2] {
        let core = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        [
            core.join("src"),
            core.join("..").join("qsh-cli").join("src"),
        ]
    }

    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read a source directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// ADR-0035 decision 22: attaching to a console is process-global, so the
    /// host never does it. The one call in `qsh-core` and `qsh-cli` is the
    /// helper's, in this file.
    #[test]
    fn console_ctrl_is_the_only_attach_console_caller() {
        let needle = concat!("Attach", "Console(");
        let own = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("pty")
            .join("console_ctrl.rs");
        let mut files = Vec::new();
        for dir in source_dirs() {
            rust_files(&dir, &mut files);
        }
        assert!(
            files.len() > 50,
            "the walk found only {} files",
            files.len()
        );
        let mut own_calls = 0;
        for file in files {
            let source = std::fs::read_to_string(&file).expect("read a source file");
            let is_own = file == own;
            // This file's tests name the needle; its code is what counts.
            let code = if is_own {
                source.split("#[cfg(test)]").next().unwrap()
            } else {
                source.as_str()
            };
            for line in code.lines() {
                if line.trim_start().starts_with("//") || !line.contains(needle) {
                    continue;
                }
                assert!(
                    is_own,
                    "{} attaches to a console outside the helper: `{line}`",
                    file.display()
                );
                own_calls += 1;
            }
        }
        assert_eq!(own_calls, 1, "the helper attaches in exactly one place");
    }
}
