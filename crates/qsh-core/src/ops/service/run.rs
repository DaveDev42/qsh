//! `qsh service run <mode>` — the entry the Windows Task Scheduler task
//! calls (ADR-0035 decision 27), and the one place the process's standard
//! streams are pointed at the mode logs.
//!
//! A task that starts a console executable gets a console window and has no
//! place to put its stdout and stderr; launchd's `StandardOutPath` and
//! systemd's journal have no task definition field to match. So the task
//! action is this entry: it detaches from the console (`FreeConsole`),
//! points stdout and stderr at `<state_dir>/log/<mode>.out.log` and
//! `<mode>.err.log` (append, owner-only), and the caller then runs the same
//! entry function as the foreground `qsh serve`, `qsh listen` or
//! `qsh serve --to`. On unix the unit files do not call it, and typing it
//! there does the same redirection and runs the same entry.
//!
//! The redirection is the whole of what is added. Nothing here reads the
//! config, so a failure of the run mode itself lands in the err log through
//! the usual stderr path.

use std::fs::File;
use std::path::PathBuf;

use qsh_proto::ErrorCode;

use crate::config::Paths;
use crate::fsutil::{PrivateOpen, open_private_file};
use crate::ops::{OpError, Ops};

/// The closed set of run modes `qsh service run` takes, spelled as the unit
/// file names and `infer_run_mode` spell them.
pub const SERVICE_RUN_MODES: [&str; 3] = ["serve", "listen", "reverse"];

/// `<state_dir>/log/<mode>.out.log` and `<mode>.err.log`.
pub(crate) fn service_log_paths(paths: &Paths, mode: &str) -> (PathBuf, PathBuf) {
    let dir = paths.state_dir.join("log");
    (
        dir.join(format!("{mode}.out.log")),
        dir.join(format!("{mode}.err.log")),
    )
}

/// Creates the log directory as a private directory and opens both logs for
/// append, each created owner-only (mode 0600, or a protected single-ACE DACL
/// on Windows). Nothing is redirected yet.
pub(crate) fn open_service_logs(paths: &Paths, mode: &str) -> Result<(File, File), OpError> {
    let (out_path, err_path) = service_log_paths(paths, mode);
    if let Some(dir) = out_path.parent() {
        crate::config::ensure_private_dir(dir)?;
    }
    let open = |path: &PathBuf| {
        open_private_file(PrivateOpen::Append, path)
            .map_err(|err| crate::config::config_io_error(path, "open", &err))
    };
    Ok((open(&out_path)?, open(&err_path)?))
}

/// Points this process's stdout and stderr at `out` and `err` for the rest of
/// its life. The files are leaked on purpose: the process owns those
/// descriptors until it exits.
#[cfg(unix)]
fn redirect_std_streams(out: File, err: File) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::fd::IntoRawFd as _;

    // Whatever the standard library buffered for the old descriptors goes out
    // before they are replaced.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    for (file, target) in [(out, libc::STDOUT_FILENO), (err, libc::STDERR_FILENO)] {
        let fd = file.into_raw_fd();
        if fd == target {
            // The log already sits on the standard descriptor (the process
            // started with it closed), so there is nothing to duplicate and
            // the descriptor must stay open.
            continue;
        }
        // SAFETY: `dup2` on two valid descriptors, `fd` ours and `target` one
        // of the process's standard descriptors; it touches no memory.
        let duplicated = unsafe { libc::dup2(fd, target) };
        // SAFETY: `fd` came from `into_raw_fd` above and is closed once, here.
        unsafe { libc::close(fd) };
        if duplicated < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// As the unix twin. `FreeConsole` first: the task's console window closes
/// with its last attached process. The standard library looks the handles up
/// on every write, so `SetStdHandle` is enough for `stdout`, `stderr` and
/// anything the tracing layer writes.
#[cfg(windows)]
fn redirect_std_streams(out: File, err: File) -> std::io::Result<()> {
    use std::os::windows::io::IntoRawHandle as _;

    use windows_sys::Win32::System::Console::{
        FreeConsole, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
    };

    let nul = File::open("NUL")?;
    // SAFETY: `FreeConsole` takes no arguments. It fails harmlessly when the
    // process has no console, which is the case this entry also serves.
    unsafe { FreeConsole() };
    for (id, handle) in [
        (STD_INPUT_HANDLE, nul.into_raw_handle()),
        (STD_OUTPUT_HANDLE, out.into_raw_handle()),
        (STD_ERROR_HANDLE, err.into_raw_handle()),
    ] {
        // SAFETY: `handle` is a valid, open file handle whose ownership this
        // call hands to the process's standard handle table, so it is not
        // closed here.
        if unsafe { SetStdHandle(id, handle as _) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

impl Ops {
    /// The redirection step of `qsh service run <mode>`: opens the mode's two
    /// logs and points stdout and stderr at them. Returns an `INTERNAL` or
    /// `CONFIG_ERROR` before anything is redirected when a log cannot be
    /// opened, so the failure still reaches the original stderr.
    pub fn service_run_redirect(&self, mode: &str) -> Result<(), OpError> {
        debug_assert!(SERVICE_RUN_MODES.contains(&mode));
        let (out, err) = open_service_logs(&self.paths, mode)?;
        redirect_std_streams(out, err).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("could not point stdout and stderr at the {mode} logs: {err}"),
            )
            .with_retryable(false)
        })
    }
}

#[cfg(test)]
mod tests;
