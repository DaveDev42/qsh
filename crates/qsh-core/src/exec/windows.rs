//! The Windows half of host-side `exec.run` (ADR-0035 decision 23): the child
//! is created inside a Job Object, so a timeout, a vanished peer or a write
//! failure ends the whole tree (the counterpart of `process_group(0)` +
//! `killpg`), and its environment is composed like unix `exec.run`'s: no
//! locale, time zone or `TERM` from the serve process.
//!
//! The pipes are the ones a session's pseudo-console uses (`winproc::pipe`):
//! the host's end of each is an owner-only overlapped named pipe read and
//! written through tokio, the child's end is an ordinary inherited handle.
//! Exactly those three handles are inherited
//! (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), not every inheritable handle the
//! `qsh serve` process happens to have, and they are inheritable only while
//! `winproc::spawn_in_job` runs, under the process-wide spawn lock, so no
//! other process this one starts at the same moment can inherit them.
//!
//! The child has no console of its own to show: it is created with
//! `CREATE_NO_WINDOW`, so a console program started by a service or from a
//! terminal does not open a window or share the terminal's Ctrl-C.

use std::ffi::OsString;
use std::io;
use std::os::windows::io::{AsRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use super::{ExecSpec, SpawnFailure, Spawned, spawn_failure_code};
use crate::pty::env_policy;
use crate::winproc::launch::{self, command_line, resolve_program};
use crate::winproc::pipe::host_pipe;
use crate::winproc::{self, ExitWatch, JobObject, ProcessSpec, StdioHandles};

/// The exit code a process killed with the tree reports. Windows has no
/// signal to name, so the code is all the client sees besides `timed_out`.
const KILLED_EXIT_CODE: u32 = 1;

/// The spawned child and the job it is in. Dropping it closes the job, which
/// ends the child and whatever it started (`KILL_ON_JOB_CLOSE`).
pub(super) struct ExecChild {
    /// First, so the tree ends before the watch is torn down.
    job: JobObject,
    process: Arc<OwnedHandle>,
    watch: ExitWatch,
    exit: Option<u32>,
}

impl ExecChild {
    /// End every process in the job (`TerminateJobObject`).
    pub(super) fn kill_tree(&mut self) {
        let _ = self.job.terminate(KILLED_EXIT_CODE);
    }

    /// Wait for the child to end and report `(exit_code, signal)`. The code
    /// is the 32-bit exit status read as signed, as `ExitStatus::code()`
    /// does; there is no signal. Safe to cancel and to call again.
    pub(super) async fn wait(&mut self) -> io::Result<(i32, Option<String>)> {
        let code = match self.exit {
            Some(code) => code,
            None => {
                self.watch.wait().await;
                let code = winproc::exit_code(&self.process)?;
                self.exit = Some(code);
                code
            }
        };
        Ok((env_policy::windows_exit_code(code), None))
    }

    #[cfg(test)]
    pub(super) fn job(&self) -> &JobObject {
        &self.job
    }
}

/// Start `program` with `args`; `spec` carries `argv` whole and the caller's
/// `env`.
pub(super) fn spawn_child(
    program: &str,
    _args: &[String],
    spec: &ExecSpec,
) -> Result<Spawned, SpawnFailure> {
    let failure = |err: io::Error| SpawnFailure {
        code: spawn_failure_code(&err),
        message: format!("qsh: cannot execute {program:?}: {err}\n"),
    };
    let account = |err: io::Error| SpawnFailure {
        code: 126,
        message: format!("qsh: cannot resolve host account: {err}\n"),
    };
    let user_env = winproc::user_environment().map_err(account)?;
    let windows_dir = winproc::windows_directory().map_err(account)?;
    let cwd = std::env::current_dir().map_err(failure)?;
    let launch = plan(&spec.argv, &spec.env, &user_env, &windows_dir, &cwd).map_err(failure)?;
    start(&launch).map_err(failure)
}

/// What to start: the program as a full path, its command line, and the
/// child's environment block.
#[derive(Debug)]
pub(super) struct Launch {
    pub(super) application: PathBuf,
    pub(super) command_line: OsString,
    pub(super) environment: Vec<u16>,
}

/// Plan the child of `argv` against this host's inputs: the account's
/// environment block (`user_env`), the Windows directory and the working
/// directory a relative program path is relative to.
///
/// The environment is the account's block, then the caller's `env`, then the
/// pinned keys of the block applied last (`env_policy::windows_overlay_env`),
/// which is what unix `exec.run` does. Nothing of the serve process's own
/// environment reaches the child: no locale or time zone (`LANG`,
/// `LANGUAGE`, `LC_*`, `TZ`), and no `TERM`, since a scripted command has no
/// terminal. A pinned key the account's block does not define is not in the
/// child either.
pub(super) fn plan(
    argv: &[String],
    client_env: &[(String, String)],
    user_env: &[(String, String)],
    windows_dir: &str,
    cwd: &Path,
) -> io::Result<Launch> {
    let Some(program) = argv.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exec argv is empty",
        ));
    };
    // An embedded NUL would end the command line there and drop the
    // arguments after it without a word.
    if argv.iter().any(|arg| arg.contains('\0')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exec argv must not contain NUL",
        ));
    }
    let pinned = env_policy::windows_pinned_values(user_env);
    let env = env_policy::windows_overlay_env(user_env, &[client_env], &pinned);
    let application = resolve_program(
        program,
        env_policy::windows_lookup(&env, "PATH"),
        cwd,
        &launch::system_dirs(windows_dir),
    )?;
    Ok(Launch {
        application,
        command_line: command_line(argv),
        environment: env_policy::windows_environment_block(&env),
    })
}

/// Create the three pipes, the job and the child, in that order. A failure
/// drops the job on the way out, so nothing is left running.
fn start(launch: &Launch) -> io::Result<Spawned> {
    let stdin = host_pipe(false)?;
    let stdout = host_pipe(true)?;
    let stderr = host_pipe(true)?;
    let job = JobObject::new_kill_on_close()?;
    let process = winproc::spawn_in_job(
        &job,
        &ProcessSpec {
            application: Some(launch.application.as_os_str()),
            command_line: &launch.command_line,
            creation_flags: CREATE_NO_WINDOW,
            pseudo_console: None,
            environment: Some(&launch.environment),
            current_dir: None,
            stdio: Some(StdioHandles {
                stdin: stdin.child.as_raw_handle(),
                stdout: stdout.child.as_raw_handle(),
                stderr: stderr.child.as_raw_handle(),
            }),
        },
    )?;
    // The child holds its own copies now (they were inheritable only inside
    // `spawn_in_job`). Ours must go, or an output pipe would not end while
    // this process lives.
    drop((stdin.child, stdout.child, stderr.child));
    let process_handle = Arc::new(process.handle);
    let watch = ExitWatch::new(Arc::clone(&process_handle))?;
    tracing::debug!(pid = process.pid, "exec child started");
    Ok(Spawned {
        child: ExecChild {
            job,
            process: process_handle,
            watch,
            exit: None,
        },
        stdin: Some(Box::new(stdin.host)),
        stdout: Some(Box::new(stdout.host)),
        stderr: Some(Box::new(stderr.host)),
    })
}

#[cfg(test)]
mod tests;
