//! The service-manager seam of `qsh service` (ADR-0032 decisions 3, 8, 10):
//! the argv builders for the documented recipes, the [`ManagerRunner`]
//! trait every manager call goes through, and the one place a process is
//! spawned ([`CommandRunner`]).
//!
//! The builders are plain functions of a uid, a unit path and the closed
//! `<mode>` set (`serve`/`listen`/`reverse`), with no `cfg`: the launchd,
//! systemd and Task Scheduler rows run on every build target, so every CI leg
//! exercises all three. Only `resolve_manager` in the parent module is
//! `cfg`-gated. No user-supplied string reaches an argv (decision 3): the
//! controller literal of a `reverse` unit lives in the unit file, never on a
//! manager command line.
//!
//! The Task Scheduler column of the decision 3 table is the `schtasks_*`
//! builders below plus [`TaskStateQuery`], whose Windows implementation reads
//! the run state through COM, because `schtasks /Query` reports registration
//! in its exit code and the run state only in localized text. This module is
//! also the only place a manager process is spawned: `schtasks` is started by
//! [`CommandRunner`] like `launchctl` and `systemctl`, from an argv these
//! builders made.

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ops::OpError;

/// Deadline of one manager call (ADR-0032 decision 8).
pub const MANAGER_CALL_DEADLINE: Duration = Duration::from_secs(30);

/// Bytes of the manager's stderr kept in an error message (ADR-0032
/// decision 8: the first line, cut at 512 bytes).
pub const MANAGER_STDERR_CAP: usize = 512;

/// How a manager call that ran to the end went: the exit code (`None` when
/// the process was ended by a signal) and the first line of its stderr.
/// Stdout is never read, so there is no external output format to parse
/// (ADR-0032 decision 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerOutput {
    /// Exit code, or `None` if a signal ended the process.
    pub exit_code: Option<i32>,
    /// First line of stderr, lossily decoded. The op cuts it to
    /// [`MANAGER_STDERR_CAP`] bytes.
    pub stderr_first_line: String,
}

impl ManagerOutput {
    /// Whether the call exited 0.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Why a manager call did not run to the end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The executable was not found (spawn `NotFound`). Maps to
    /// `UNSUPPORTED` (ADR-0032 decision 8).
    NotFound,
    /// The call outlived its deadline and the process was killed. Maps to
    /// `TIMEOUT`.
    TimedOut,
    /// Any other spawn or wait failure. Maps to `INTERNAL`.
    Io(String),
}

/// The seam every manager call goes through (ADR-0032 decision 10): argv
/// and a deadline in, exit status and stderr first line out. Tests inject a
/// recording implementation; the public `Ops::service_*` methods build the
/// real [`CommandRunner`].
pub trait ManagerRunner: Send + Sync {
    /// Run `argv` (program first, no shell) and wait at most `deadline`.
    fn run(&self, argv: &[String], deadline: Duration) -> Result<ManagerOutput, RunError>;
}

/// The run-state query of the Task Scheduler backend (ADR-0032 decision 3
/// table, ADR-0035 decision 28): a task name in, whether it is running out.
/// The Windows implementation is the Task Scheduler COM API
/// (`IRegisteredTask::get_State`), because `schtasks /Query` only reports
/// registration in its exit code. A task that is not registered is not
/// running. Tests inject a fake; a production run on any other OS never calls
/// it.
pub trait TaskStateQuery: Send + Sync {
    /// Whether the task named `task_name` (for example `\qsh\qsh-serve`) is
    /// currently running.
    fn is_running(&self, task_name: &str) -> Result<bool, OpError>;
}

/// The clock [`CommandRunner`] measures its deadline with. Injected so the
/// deadline path is tested without waiting 30 seconds.
pub trait ManagerClock: Send + Sync {
    /// Monotonic time since an arbitrary fixed origin.
    fn now(&self) -> Duration;
    /// Wait a short moment between two polls of the child.
    fn pause(&self);
}

/// The real clock: [`Instant`] elapsed since construction, with a 10 ms
/// pause between polls.
pub struct SystemManagerClock {
    origin: Instant,
}

impl SystemManagerClock {
    /// A clock whose origin is now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemManagerClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagerClock for SystemManagerClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn pause(&self) {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// How much of the child's stderr is kept to find its first line. The rest
/// is drained and dropped so a chatty manager cannot block on a full pipe.
const STDERR_KEEP: usize = 8 * 1024;

/// The default [`ManagerRunner`]: `std::process::Command` with the argv as
/// an array (no shell), stdin and stdout null, stderr piped for its first
/// line. This is the only place a manager executable is spawned.
pub struct CommandRunner {
    clock: Arc<dyn ManagerClock>,
}

impl CommandRunner {
    /// The runner `Ops::service_*` uses: real clock.
    pub fn system() -> Self {
        Self {
            clock: Arc::new(SystemManagerClock::new()),
        }
    }

    /// A runner measuring its deadline with `clock`.
    pub fn with_clock(clock: Arc<dyn ManagerClock>) -> Self {
        Self { clock }
    }
}

impl ManagerRunner for CommandRunner {
    fn run(&self, argv: &[String], deadline: Duration) -> Result<ManagerOutput, RunError> {
        let Some((program, args)) = argv.split_first() else {
            return Err(RunError::Io("empty manager argv".to_string()));
        };
        let mut child = {
            // Not while another spawn has handles inheritable (`winproc`).
            #[cfg(windows)]
            let _spawning = crate::winproc::spawn_guard();
            Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|err| match err.kind() {
                    std::io::ErrorKind::NotFound => RunError::NotFound,
                    _ => RunError::Io(err.to_string()),
                })?
        };
        let reader = child.stderr.take().map(|mut stderr| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut kept = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stderr.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let room = STDERR_KEEP.saturating_sub(kept.len());
                            kept.extend_from_slice(&chunk[..n.min(room)]);
                        }
                    }
                }
                let _ = tx.send(kept);
            });
            rx
        });

        let started = self.clock.now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if self.clock.now().saturating_sub(started) >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        // The reader thread is left to finish on its own: a
                        // grandchild that inherited the pipe must not hold
                        // this call open past its deadline.
                        return Err(RunError::TimedOut);
                    }
                    self.clock.pause();
                }
                Err(err) => return Err(RunError::Io(err.to_string())),
            }
        };
        // The manager has exited, but a grandchild that inherited the pipe
        // can keep stderr open; wait for it no longer than the deadline left,
        // then report the exit status with whatever stderr was not read.
        let left = deadline.saturating_sub(self.clock.now().saturating_sub(started));
        let kept = reader
            .and_then(|rx| rx.recv_timeout(left).ok())
            .unwrap_or_default();
        Ok(ManagerOutput {
            exit_code: status.code(),
            stderr_first_line: first_line(&kept),
        })
    }
}

/// The first line of `bytes`, lossily decoded and trimmed.
fn first_line(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// `text` cut to at most `cap` bytes on a character boundary.
pub(crate) fn cap_bytes(text: &str, cap: usize) -> &str {
    if text.len() <= cap {
        return text;
    }
    let mut end = cap;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

// ---------------------------------------------------------------------
// argv builders — ADR-0032 decision 3, launchd and systemd columns.
// ---------------------------------------------------------------------

/// `<mode>` is the closed set `infer_run_mode` returns; nothing a user typed
/// can reach a builder (ADR-0032 decision 3).
fn closed_mode(mode: &str) -> &str {
    debug_assert!(
        matches!(mode, "serve" | "listen" | "reverse"),
        "manager argv takes only the closed mode set, got {mode:?}"
    );
    mode
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

/// The launchd label of `mode`'s unit (`io.qsh.<mode>`).
fn launchd_label(mode: &str) -> String {
    format!("io.qsh.{}", closed_mode(mode))
}

/// The systemd unit name of `mode` (`qsh-<mode>.service`).
fn systemd_unit(mode: &str) -> String {
    format!("qsh-{}.service", closed_mode(mode))
}

/// "Already loaded / registered?" on launchd: exit 0 means loaded in the
/// user's `gui/<uid>` domain.
pub fn launchd_print_argv(uid: &str, mode: &str) -> Vec<String> {
    let target = format!("gui/{uid}/{}", launchd_label(mode));
    argv(&["launchctl", "print", &target])
}

/// Activation on launchd: load the unit file into the `gui/<uid>` domain.
pub fn launchd_bootstrap_argv(uid: &str, unit_path: &str) -> Vec<String> {
    let domain = format!("gui/{uid}");
    argv(&["launchctl", "bootstrap", &domain, unit_path])
}

/// Deactivation on launchd.
pub fn launchd_bootout_argv(uid: &str, mode: &str) -> Vec<String> {
    let target = format!("gui/{uid}/{}", launchd_label(mode));
    argv(&["launchctl", "bootout", &target])
}

/// The query for the human-installed LaunchDaemon form (ADR-0032 decision
/// 18). Never run by qsh: whether `launchctl print system/…` answers
/// without root is unverified, so `status --live` names this command in its
/// error instead of calling it.
pub fn launchd_print_system_argv(mode: &str) -> Vec<String> {
    let target = format!("system/{}", launchd_label(mode));
    argv(&["launchctl", "print", &target])
}

/// "Already running?" on systemd: exit 0 means active.
pub fn systemd_is_active_argv(mode: &str) -> Vec<String> {
    let unit = systemd_unit(mode);
    argv(&["systemctl", "--user", "is-active", &unit])
}

/// First activation step on systemd: make the manager read the unit file.
pub fn systemd_daemon_reload_argv() -> Vec<String> {
    argv(&["systemctl", "--user", "daemon-reload"])
}

/// Second activation step on systemd. `--now` starts an inactive unit and
/// leaves an active one alone; there is no `restart` anywhere (decision 4).
pub fn systemd_enable_now_argv(mode: &str) -> Vec<String> {
    let unit = systemd_unit(mode);
    argv(&["systemctl", "--user", "enable", "--now", &unit])
}

/// Deactivation on systemd.
pub fn systemd_disable_now_argv(mode: &str) -> Vec<String> {
    let unit = systemd_unit(mode);
    argv(&["systemctl", "--user", "disable", "--now", &unit])
}

// ---------------------------------------------------------------------
// argv builders — ADR-0032 decision 3, Task Scheduler column.
// ---------------------------------------------------------------------

/// `\qsh\qsh-<mode>`, the one task name every `schtasks` argv and the COM
/// reads share (`crate::doctor::probe::windows_task_name`).
fn task_name(mode: &str) -> String {
    crate::doctor::probe::windows_task_name(closed_mode(mode))
}

/// "Registered?" on the Task Scheduler: exit 0 means a task of that name
/// exists. Only the exit code is read.
pub fn schtasks_query_argv(mode: &str) -> Vec<String> {
    argv(&["schtasks", "/Query", "/TN", &task_name(mode)])
}

/// Activation on the Task Scheduler, first step: register the task from the
/// definition file, replacing a task of that name. `/F` does not stop a
/// running instance (`docs/deploy/service.md`, Windows, measured).
pub fn schtasks_create_argv(mode: &str, task_path: &str) -> Vec<String> {
    argv(&[
        "schtasks",
        "/Create",
        "/F",
        "/TN",
        &task_name(mode),
        "/XML",
        task_path,
    ])
}

/// Activation on the Task Scheduler, second step, only for a task that is not
/// running: start it now instead of at the next logon.
pub fn schtasks_run_argv(mode: &str) -> Vec<String> {
    argv(&["schtasks", "/Run", "/TN", &task_name(mode)])
}

/// Deactivation on the Task Scheduler, first step, only for a running task.
pub fn schtasks_end_argv(mode: &str) -> Vec<String> {
    argv(&["schtasks", "/End", "/TN", &task_name(mode)])
}

/// Deactivation on the Task Scheduler, last step: unregister the task.
pub fn schtasks_delete_argv(mode: &str) -> Vec<String> {
    argv(&["schtasks", "/Delete", "/F", "/TN", &task_name(mode)])
}
