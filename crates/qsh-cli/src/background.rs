//! `-f` and `-E` of the root ssh form (ADR-0051 decision 7).
//!
//! `-E file` points the process's standard error at a file, so every
//! diagnostic (tracing lines, notices, the ssh child's stderr) lands there.
//!
//! `-f` runs the command twice. The foreground process re-executes itself
//! with [`CHILD_ENV`] set and waits. The child authenticates, opens the
//! forwards, and once they stand writes [`READY`] on its standard output;
//! the foreground process then exits `0`. If the child ends first, the
//! foreground process exits with the child's status, after relaying what the
//! child wrote on standard error. The child leaves the terminal (`setsid`
//! on unix; Windows starts it detached) and, unless `-E` was given, drops
//! its diagnostics. A fork would be shorter, but the process already runs a
//! multi-threaded runtime by then and fork is not safe there.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// Set in the re-executed child.
pub(crate) const CHILD_ENV: &str = "QSH_BACKGROUND_CHILD";

/// The line the child writes on standard output when the forwards stand.
const READY: &str = "qsh-background-ready";

/// Point standard error at `path` (append, created `0600` on unix).
pub(crate) fn redirect_stderr_to_file(path: &str) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    replace_stderr(file)
}

#[cfg(unix)]
fn replace_stderr(file: std::fs::File) -> io::Result<()> {
    use std::os::fd::AsFd as _;
    nix::unistd::dup2_stderr(file.as_fd()).map_err(io::Error::from)
}

#[cfg(windows)]
fn replace_stderr(file: std::fs::File) -> io::Result<()> {
    use std::os::windows::io::IntoRawHandle as _;
    use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, SetStdHandle};
    let handle = file.into_raw_handle();
    // SAFETY: `handle` is a valid, owned file handle; the process keeps it
    // for its remaining life as its standard error.
    if unsafe { SetStdHandle(STD_ERROR_HANDLE, handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether this process is the re-executed child of `-f`.
pub(crate) fn is_child() -> bool {
    std::env::var_os(CHILD_ENV).is_some()
}

/// The foreground half of `-f`: start the child, relay its stderr, wait for
/// the ready line. Returns the exit code of the foreground process.
pub(crate) fn run_foreground() -> i32 {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            crate::stderr_note!("qsh: cannot find my own executable for -f: {err}");
            return crate::EXIT_RUNTIME_FAILURE;
        }
    };
    let mut command = Command::new(exe);
    command
        .args(std::env::args_os().skip(1))
        .env(CHILD_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: no console to prompt
        // on, so ssh must authenticate without a question (key or agent).
        command.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            crate::stderr_note!("qsh: cannot start the background process: {err}");
            return crate::EXIT_RUNTIME_FAILURE;
        }
    };
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let relay = std::thread::spawn(move || {
        let _ = io::copy(&mut stderr, &mut io::stderr());
    });
    let mut ready = false;
    for line in BufReader::new(stdout).lines() {
        match line {
            Ok(line) if line == READY => {
                ready = true;
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    if ready {
        // The child closes its stderr right after the ready line.
        let _ = relay.join();
        return 0;
    }
    let _ = relay.join();
    match child.wait().ok().and_then(|status| status.code()) {
        Some(code) => code,
        None => crate::EXIT_RUNTIME_FAILURE,
    }
}

/// The child's half: the forwards stand. Tell the foreground process, leave
/// the terminal, and drop what would have gone to the terminal.
pub(crate) fn announce_ready(keep_stderr: bool) {
    if !is_child() {
        return;
    }
    {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "{READY}");
        let _ = out.flush();
    }
    #[cfg(unix)]
    {
        let _ = nix::unistd::setsid();
        if let Ok(null) = OpenOptions::new().write(true).open("/dev/null") {
            use std::os::fd::AsFd as _;
            let _ = nix::unistd::dup2_stdout(null.as_fd());
            if !keep_stderr {
                let _ = nix::unistd::dup2_stderr(null.as_fd());
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawHandle as _;
        use windows_sys::Win32::System::Console::{
            STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
        };
        if let Ok(null) = OpenOptions::new().write(true).open("NUL") {
            let handle = null.into_raw_handle();
            // SAFETY: an owned handle kept for the rest of the process.
            unsafe {
                SetStdHandle(STD_OUTPUT_HANDLE, handle);
                if !keep_stderr {
                    SetStdHandle(STD_ERROR_HANDLE, handle);
                }
            }
        }
    }
}
