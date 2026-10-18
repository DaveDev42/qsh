//! The local half of the bootstrap: the `ssh` child and everything around it
//! that does not talk to the remote qsh (ADR-0044 decisions 4, 6, 9, 14, 16,
//! 19, 20, 25).
//!
//! qsh runs the system `ssh` twice. `ssh -G -- <dest>` evaluates the user's
//! ssh configuration locally (no network) and qsh reads four keys of it.
//! Then `ssh ... <dest> <remote_qsh> pair ssh-respond` carries the bootstrap
//! stream over the child's stdin and stdout. Authentication, host key
//! checks and every prompt stay inside ssh: its stderr and controlling
//! terminal are inherited, and qsh never reads a key, a passphrase or an
//! agent socket.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::ssh_bootstrap::{BootstrapLine, BootstrapLineError, BootstrapReader};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use super::dest::Dest;
use crate::config::SshConfig;
use crate::ops::{CancelToken, OpError};

/// Largest `ssh -G` output qsh reads, in bytes (ADR-0044 decision 4). The
/// same figure bounds a single line: a longer line is a longer output.
pub const SSH_G_OUTPUT_MAX: usize = 64 * 1024;

/// How long a `BatchMode` run waits for the responder's `hello`
/// (ADR-0044 decision 16). Without `BatchMode` the wait has no bound: a
/// person may be answering a password prompt.
pub const BATCH_HELLO_TIMEOUT: Duration = Duration::from_secs(60);

/// How long each message after the `hello` may take (ADR-0044 decision 16).
pub const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an ssh child that already closed its stdout may take to exit
/// before it is terminated, and how long a terminated one gets before it is
/// killed.
const EXIT_GRACE: Duration = Duration::from_secs(5);

/// Windows exit status of a process ended by Ctrl-C (`STATUS_CONTROL_C_EXIT`).
const STATUS_CONTROL_C_EXIT: u32 = 0xC000_013A;

/// The ssh options of the responder call, in the order ADR-0044 decision 9
/// fixes them, before the optional `BatchMode` and the `--`.
const RESPONDER_OPTIONS: &[&str] = &[
    "-T",
    "-a",
    "-x",
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    "RemoteCommand=none",
    "-o",
    "RequestTTY=no",
    "-o",
    "PermitLocalCommand=no",
];

/// Whether the responder call must run with `BatchMode=yes`: only for
/// machine output modes and for a stdin that is not a terminal. On a
/// terminal ssh keeps its prompts (ADR-0044 decision 16).
pub fn batch_mode(machine_mode: bool, stdin_is_terminal: bool) -> bool {
    machine_mode || !stdin_is_terminal
}

/// The arguments of `ssh -G` (ADR-0044 decision 4).
pub fn ssh_g_args(dest: &Dest) -> Vec<String> {
    vec!["-G".into(), "--".into(), dest.as_ssh_arg().into()]
}

/// The arguments of the responder call (ADR-0044 decision 9):
///
/// `-T -a -x -o ClearAllForwardings=yes -o RemoteCommand=none -o
/// RequestTTY=no -o PermitLocalCommand=no [-o BatchMode=yes] -- <dest>
/// <remote_qsh> pair ssh-respond`
///
/// Nothing else is set. In particular `StrictHostKeyChecking` and
/// `UserKnownHostsFile` stay as the user configured them (decision 20), and
/// no user-chosen string besides `<dest>` and `<remote_qsh>` is on the
/// command line.
pub fn responder_args(
    dest: &Dest,
    remote_qsh: &str,
    batch_mode: bool,
) -> Result<Vec<String>, OpError> {
    let remote = quote_remote_program(remote_qsh)?;
    let mut args: Vec<String> = RESPONDER_OPTIONS.iter().map(|s| (*s).to_string()).collect();
    if batch_mode {
        args.push("-o".into());
        args.push("BatchMode=yes".into());
    }
    args.push("--".into());
    args.push(dest.as_ssh_arg().into());
    args.push(remote);
    args.push("pair".into());
    args.push("ssh-respond".into());
    Ok(args)
}

/// Longest `<remote_qsh>` accepted, in bytes.
const REMOTE_QSH_MAX: usize = 4096;

/// The `<remote_qsh>` word as the remote shell must receive it (ADR-0044
/// decision 9).
///
/// ssh joins the remaining arguments with spaces and hands the result to
/// the remote account's shell, which may be POSIX `sh`, `cmd.exe` or
/// PowerShell. A word made only of `[A-Za-z0-9_./~+:\\-]` (the default
/// `qsh`, the usual paths, a Windows drive path) is the same token in all
/// three, so it is passed as is. Any other character (a space, for one)
/// gets POSIX single quotes, with an embedded `'` written as `'\''`. A
/// remote Windows shell that does not understand POSIX quoting then fails,
/// and the `remote_command_failed` message tells the user to put the
/// executable on `PATH` or use a path made of the safe characters.
///
/// Empty words and control characters (newline, NUL, ...) are
/// `INVALID_ARGUMENT`: they would split or truncate the remote command.
pub fn quote_remote_program(word: &str) -> Result<String, OpError> {
    if word.is_empty() || word.len() > REMOTE_QSH_MAX || word.chars().any(char::is_control) {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            "the remote qsh must be a non-empty command of at most 4096 bytes without \
                 control characters",
        )
        .with_retryable(false));
    }
    let bare = word.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '~' | '+' | ':' | '\\' | '-')
    });
    if bare {
        return Ok(word.to_string());
    }
    Ok(format!("'{}'", word.replace('\'', "'\\''")))
}

/// What qsh keeps from `ssh -G` (ADR-0044 decisions 4, 6, 26).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshResolved {
    /// ssh's `hostname`: the host the QUIC dial goes to. IPv6 literals
    /// arrive unbracketed.
    pub hostname: String,
    /// ssh's resolved login. In memory only; it is written to no qsh file
    /// (decision 26).
    pub user: Option<String>,
    /// `proxyjump` or `proxycommand` is set: ssh reaches the host through a
    /// relay the QUIC dial will not use (decision 6). The relay's text is
    /// not kept.
    pub proxied: bool,
}

/// Read the four keys qsh uses from `ssh -G` output: `hostname`, `user`,
/// `proxyjump`, `proxycommand`. Every other line is skipped unread. The
/// first occurrence of a key wins.
///
/// More than [`SSH_G_OUTPUT_MAX`] bytes, a missing or unusable `hostname`
/// are a `CONFIG_ERROR`; the message never repeats the output.
pub fn parse_ssh_g(output: &[u8]) -> Result<SshResolved, OpError> {
    if output.len() > SSH_G_OUTPUT_MAX {
        return Err(ssh_g_error(
            "ssh_g_too_large",
            "the ssh -G output is too large",
        ));
    }
    let mut hostname: Option<&[u8]> = None;
    let mut user: Option<&[u8]> = None;
    let mut proxy_jump: Option<&[u8]> = None;
    let mut proxy_command: Option<&[u8]> = None;
    for line in output.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let split = line
            .iter()
            .position(|b| *b == b' ' || *b == b'\t')
            .unwrap_or(line.len());
        let (key, rest) = line.split_at(split);
        let slot = if key.eq_ignore_ascii_case(b"hostname") {
            &mut hostname
        } else if key.eq_ignore_ascii_case(b"user") {
            &mut user
        } else if key.eq_ignore_ascii_case(b"proxyjump") {
            &mut proxy_jump
        } else if key.eq_ignore_ascii_case(b"proxycommand") {
            &mut proxy_command
        } else {
            continue;
        };
        if slot.is_none() {
            *slot = Some(rest.trim_ascii());
        }
    }
    let hostname = hostname
        .and_then(|raw| std::str::from_utf8(raw).ok())
        .filter(|h| !h.is_empty() && !h.chars().any(|c| c.is_whitespace() || c.is_control()))
        .ok_or_else(|| {
            ssh_g_error(
                "ssh_g_unreadable",
                "ssh -G did not report a usable hostname for the destination",
            )
        })?
        .to_string();
    let is_set = |value: Option<&[u8]>| {
        value.is_some_and(|v| !v.is_empty() && !v.eq_ignore_ascii_case(b"none"))
    };
    Ok(SshResolved {
        hostname,
        user: user
            .and_then(|raw| std::str::from_utf8(raw).ok())
            .filter(|u| !u.is_empty())
            .map(str::to_string),
        proxied: is_set(proxy_jump) || is_set(proxy_command),
    })
}

fn ssh_g_error(reason: &str, message: &str) -> OpError {
    OpError::new(ErrorCode::ConfigError, message)
        .with_retryable(false)
        .with_details(json!({ "reason": reason }))
}

/// How an ssh child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshExit {
    /// Exit status. Windows statuses can exceed 255 (`cmd.exe` reports a
    /// missing command as 9009).
    Code(i32),
    /// Ended by the user's interrupt: SIGINT on Unix, a console Ctrl-C on
    /// Windows. ssh sits in the foreground process group, so the key that
    /// interrupts qsh ends it too.
    Interrupted,
    /// Ended by another signal.
    Signal(i32),
}

impl SshExit {
    /// Classify a raw exit status. The Ctrl-C status of Windows is
    /// recognized on every platform: no Unix exit code can equal it.
    pub fn from_code(code: i32) -> Self {
        if code as u32 == STATUS_CONTROL_C_EXIT {
            SshExit::Interrupted
        } else {
            SshExit::Code(code)
        }
    }

    fn from_status(status: ExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                return if signal == libc::SIGINT {
                    SshExit::Interrupted
                } else {
                    SshExit::Signal(signal)
                };
            }
        }
        match status.code() {
            Some(code) => Self::from_code(code),
            None => SshExit::Signal(0),
        }
    }
}

/// The error for an ssh child that ended without delivering the result
/// (ADR-0044 decision 14). `hello_seen` tells whether the responder had
/// already spoken.
///
/// Before the `hello` the exit status says what the remote shell did:
/// 127 (and 9009 from `cmd.exe`) means no `qsh` on the remote `PATH`, 2 an
/// older `qsh` that does not know `pair ssh-respond`, 1 a failure that
/// PowerShell also uses for a missing command, 255 ssh itself failing. The
/// stderr text ssh wrote was already shown to the user and is not read
/// again. After the `hello`, 255 is still ssh failing; any other early end
/// is a protocol error. An interrupt is `CANCELED` at every point. All
/// `details.reason` values are additive.
pub fn map_ssh_exit(exit: SshExit, hello_seen: bool) -> OpError {
    let reason = |code: ErrorCode, reason: &str, message: &str, extra: serde_json::Value| {
        let mut details = json!({ "reason": reason });
        if let (Some(map), Some(extra)) = (details.as_object_mut(), extra.as_object()) {
            map.extend(extra.clone());
        }
        OpError::new(code, message)
            .with_retryable(false)
            .with_details(details)
    };
    let none = serde_json::Value::Null;
    match exit {
        SshExit::Interrupted => {
            OpError::new(ErrorCode::Canceled, "interrupted while running ssh").with_retryable(false)
        }
        SshExit::Code(255) => OpError::new(
            ErrorCode::ConnectionFailed,
            "ssh failed (exit 255); its own error message is above",
        )
        .with_details(json!({ "reason": "ssh_failed", "ssh_exit": 255 })),
        SshExit::Signal(signal) => OpError::new(
            ErrorCode::ConnectionFailed,
            "ssh was ended by a signal; its own error message may be above",
        )
        .with_details(json!({ "reason": "ssh_failed", "ssh_signal": signal })),
        _ if hello_seen => reason(
            ErrorCode::RemoteError,
            "bootstrap_protocol",
            "the remote command ended before it delivered a result",
            none,
        ),
        SshExit::Code(code @ (127 | 9009)) => reason(
            ErrorCode::RemoteError,
            "remote_qsh_missing",
            "the remote shell did not find `qsh`, so nothing was written on either side; pass \
             --remote-qsh <path> or set [ssh].remote_qsh in config.toml (a non-interactive ssh \
             shell often lacks ~/.cargo/bin or /usr/local/bin in its PATH) and run this again",
            json!({ "remote_exit": code }),
        ),
        SshExit::Code(2) => reason(
            ErrorCode::Unsupported,
            "remote_qsh_too_old",
            "the remote qsh does not know `pair ssh-respond`, so nothing was written on either \
             side; upgrade qsh on the remote host and run this again",
            json!({ "remote_exit": 2 }),
        ),
        SshExit::Code(0) => reason(
            ErrorCode::RemoteError,
            "bootstrap_protocol",
            "the remote command ended without answering",
            none,
        ),
        SshExit::Code(code) => reason(
            ErrorCode::RemoteError,
            "remote_command_failed",
            "the remote command failed before answering, so nothing was written on either side; \
             if the remote default shell is PowerShell, a missing qsh looks like this (exit 1): \
             put qsh.exe on the remote PATH or pass its full path with --remote-qsh / \
             [ssh].remote_qsh, then run this again",
            json!({ "remote_exit": code }),
        ),
    }
}

/// The `ssh_not_found` error (ADR-0044 decisions 14 and 25). `windows`
/// selects the wording; the caller passes `cfg!(windows)`.
pub fn ssh_not_found(program: &str, windows: bool) -> OpError {
    let hint = if windows {
        "enable the Windows optional feature \"OpenSSH Client\" (Settings > Apps > Optional \
         features), or set [ssh].program in config.toml"
    } else {
        "install OpenSSH, or set [ssh].program in config.toml"
    };
    OpError::new(
        ErrorCode::ConfigError,
        format!("the ssh program {program:?} was not found; {hint}"),
    )
    .with_retryable(false)
    .with_details(json!({ "reason": "ssh_not_found" }))
}

fn spawn_error(program: &str, err: &io::Error) -> OpError {
    if err.kind() == io::ErrorKind::NotFound {
        return ssh_not_found(program, cfg!(windows));
    }
    OpError::new(
        ErrorCode::ConfigError,
        format!("could not run the ssh program {program:?}: {}", err.kind()),
    )
    .with_retryable(false)
    .with_details(json!({ "reason": "ssh_spawn_failed" }))
}

fn protocol_error(err: BootstrapLineError) -> OpError {
    OpError::new(
        ErrorCode::RemoteError,
        format!("bootstrap protocol violation: {err}"),
    )
    .with_retryable(false)
    .with_details(json!({ "reason": "bootstrap_protocol" }))
}

fn timeout_error(stage: &str) -> OpError {
    OpError::new(
        ErrorCode::Timeout,
        format!("the remote did not answer the bootstrap in time (waiting for the {stage})"),
    )
    .with_details(json!({ "reason": "bootstrap_timeout", "stage": stage }))
}

fn canceled_error() -> OpError {
    OpError::new(ErrorCode::Canceled, "canceled while running ssh").with_retryable(false)
}

/// Waits for the bootstrap deadlines of one ssh child (ADR-0044 decision 16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapTimeouts {
    /// Wait for the `hello`. `None` is unbounded.
    pub hello: Option<Duration>,
    /// Wait for each message after the `hello`.
    pub message: Duration,
}

impl BootstrapTimeouts {
    /// The ADR defaults: unbounded for the `hello` unless `BatchMode` is on
    /// (then 60 s), 30 s per later message.
    pub fn for_batch_mode(batch_mode: bool) -> Self {
        Self {
            hello: batch_mode.then_some(BATCH_HELLO_TIMEOUT),
            message: MESSAGE_TIMEOUT,
        }
    }
}

/// Everything [`SshRunner::spawn_responder`] needs besides the destination.
#[derive(Clone)]
pub struct ResponderOptions {
    /// `-o BatchMode=yes` (see [`batch_mode`]).
    pub batch_mode: bool,
    /// Deadlines; [`BootstrapTimeouts::for_batch_mode`] by default.
    pub timeouts: BootstrapTimeouts,
    /// Fires when the user interrupts qsh. The ssh child is then ended and
    /// reaped and the call fails with `CANCELED`.
    pub cancel: CancelToken,
}

impl ResponderOptions {
    /// Options with the ADR default deadlines.
    pub fn new(batch_mode: bool, cancel: CancelToken) -> Self {
        Self {
            batch_mode,
            timeouts: BootstrapTimeouts::for_batch_mode(batch_mode),
            cancel,
        }
    }
}

/// Runs the system `ssh`.
#[derive(Debug, Clone)]
pub struct SshRunner {
    program: OsString,
}

impl SshRunner {
    /// A runner for `program`, a path or a name looked up on `PATH`.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
        }
    }

    /// The runner `[ssh].program` (default `ssh`, `ssh.exe` on Windows)
    /// describes.
    pub fn from_config(config: &SshConfig) -> Result<Self, OpError> {
        Ok(Self::new(config.program()?))
    }

    fn program_text(&self) -> String {
        self.program.to_string_lossy().into_owned()
    }

    /// `ssh -G -- <dest>`: evaluate the ssh configuration locally and read
    /// the four keys qsh uses (ADR-0044 decision 4). No network is touched.
    /// `cancel` ends the child and fails with `CANCELED`.
    pub async fn resolve(&self, dest: &Dest, cancel: &CancelToken) -> Result<SshResolved, OpError> {
        let program = self.program_text();
        let mut child = {
            // Not while another spawn has handles inheritable (`winproc`).
            #[cfg(windows)]
            let _spawning = crate::winproc::spawn_guard();
            Command::new(&self.program)
                .args(ssh_g_args(dest))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .map_err(|err| spawn_error(&program, &err))?
        };
        let stdout = child.stdout.take().expect("stdout is piped");
        let read = async {
            let mut out = Vec::new();
            stdout
                .take(SSH_G_OUTPUT_MAX as u64 + 1)
                .read_to_end(&mut out)
                .await
                .map(|_| out)
        };
        let output = tokio::select! {
            biased;
            () = cancel.canceled() => {
                end_child(&mut child).await;
                return Err(canceled_error());
            }
            out = read => out,
        };
        let output = match output {
            Ok(output) => output,
            Err(_) => {
                end_child(&mut child).await;
                return Err(ssh_g_error(
                    "ssh_g_unreadable",
                    "could not read the ssh -G output",
                ));
            }
        };
        if output.len() > SSH_G_OUTPUT_MAX {
            end_child(&mut child).await;
            return Err(ssh_g_error(
                "ssh_g_too_large",
                "the ssh -G output is too large",
            ));
        }
        let status = child
            .wait()
            .await
            .map_err(|_| ssh_g_error("ssh_g_failed", "could not wait for ssh -G"))?;
        tracing::debug!(target: "qsh::ssh_bootstrap", stage = "ssh_g", ok = status.success());
        if !status.success() {
            let exit = SshExit::from_status(status);
            if exit == SshExit::Interrupted {
                return Err(canceled_error());
            }
            let ssh_exit = match exit {
                SshExit::Code(code) => json!(code),
                _ => serde_json::Value::Null,
            };
            return Err(OpError::new(
                ErrorCode::ConfigError,
                "ssh -G failed; its own error message is above",
            )
            .with_retryable(false)
            .with_details(json!({ "reason": "ssh_g_failed", "ssh_exit": ssh_exit })));
        }
        parse_ssh_g(&output)
    }

    /// Start the responder call (ADR-0044 decisions 9 and 16). stdin and
    /// stdout are pipes for the bootstrap stream; stderr and the controlling
    /// terminal are inherited, so ssh asks its own questions (passwords,
    /// passphrases, host key confirmation) directly on the terminal.
    pub fn spawn_responder(
        &self,
        dest: &Dest,
        remote_qsh: &str,
        options: ResponderOptions,
    ) -> Result<SshChild, OpError> {
        let args = responder_args(dest, remote_qsh, options.batch_mode)?;
        let program = self.program_text();
        let mut child = {
            // Not while another spawn has handles inheritable (`winproc`).
            #[cfg(windows)]
            let _spawning = crate::winproc::spawn_guard();
            Command::new(&self.program)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .map_err(|err| spawn_error(&program, &err))?
        };
        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = child.stdout.take().expect("stdout is piped");
        tracing::debug!(target: "qsh::ssh_bootstrap", stage = "spawned", batch_mode = options.batch_mode);
        Ok(SshChild {
            child,
            stdin: Some(stdin),
            stream: MessageStream::new(stdout),
            timeouts: options.timeouts,
            cancel: options.cancel,
        })
    }
}

/// End a child that must not outlive the call and reap it. On Unix it is
/// asked to terminate first (SIGTERM), so ssh restores the terminal state a
/// password prompt changed, and killed only if it does not go within
/// [`EXIT_GRACE`]. On Windows it is terminated.
async fn end_child(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
        // SAFETY: plain kill(2) on a process this call spawned and has not
        // yet reaped, so the pid cannot have been reused.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        if tokio::time::timeout(EXIT_GRACE, child.wait()).await.is_ok() {
            return;
        }
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Reads bootstrap messages off a byte stream. Generic over the source so
/// the logging rules can be tested without a process.
pub(crate) struct MessageStream<R> {
    src: R,
    reader: BootstrapReader,
    pending: VecDeque<BootstrapLine>,
    buf: Box<[u8; 4096]>,
    eof: bool,
    hello_logged: bool,
}

impl<R: AsyncRead + Unpin> MessageStream<R> {
    pub(crate) fn new(src: R) -> Self {
        Self {
            src,
            reader: BootstrapReader::new(),
            pending: VecDeque::new(),
            buf: Box::new([0; 4096]),
            eof: false,
            hello_logged: false,
        }
    }

    pub(crate) fn hello_seen(&self) -> bool {
        self.reader.hello_seen()
    }

    pub(crate) fn skipped_lines(&self) -> u32 {
        self.reader.skipped_lines()
    }

    pub(crate) fn skipped_bytes(&self) -> usize {
        self.reader.skipped_bytes()
    }

    /// The next message, or `None` at end of stream (or after the `result`,
    /// where the driver stops reading).
    ///
    /// Untagged lines (the remote shell's rc output) are counted by the
    /// reader and never stored; only the counts reach the log (ADR-0044
    /// decision 19).
    pub(crate) async fn next(&mut self) -> Result<Option<BootstrapLine>, OpError> {
        loop {
            if let Some(line) = self.pending.pop_front() {
                return Ok(Some(line));
            }
            if self.eof || self.reader.is_done() {
                return Ok(None);
            }
            let n = self.src.read(&mut self.buf[..]).await.map_err(|err| {
                OpError::new(
                    ErrorCode::Internal,
                    format!("could not read the ssh child's output: {}", err.kind()),
                )
            })?;
            if n == 0 {
                self.eof = true;
                continue;
            }
            match self.reader.push(&self.buf[..n]) {
                Ok(lines) => {
                    if !self.hello_logged && self.reader.hello_seen() {
                        self.hello_logged = true;
                        self.log_counts("hello");
                    }
                    self.pending.extend(lines);
                }
                Err(err) => {
                    self.log_counts("protocol_error");
                    return Err(protocol_error(err));
                }
            }
        }
    }

    fn log_counts(&self, stage: &str) {
        tracing::debug!(
            target: "qsh::ssh_bootstrap",
            stage,
            skipped_lines = self.reader.skipped_lines(),
            skipped_bytes = self.reader.skipped_bytes(),
        );
    }
}

/// A running responder call: the ssh child plus the bootstrap stream over
/// its pipes.
pub struct SshChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stream: MessageStream<ChildStdout>,
    timeouts: BootstrapTimeouts,
    cancel: CancelToken,
}

impl SshChild {
    /// Whether the responder's `hello` has arrived.
    pub fn hello_seen(&self) -> bool {
        self.stream.hello_seen()
    }

    /// Untagged lines skipped before the `hello`. Only a count exists.
    pub fn skipped_lines(&self) -> u32 {
        self.stream.skipped_lines()
    }

    /// Bytes of those lines.
    pub fn skipped_bytes(&self) -> usize {
        self.stream.skipped_bytes()
    }

    /// The next message from the responder.
    ///
    /// Waits as long as [`BootstrapTimeouts`] allow. If the child ends first,
    /// the error is [`map_ssh_exit`]'s; an interrupt, or the cancel token,
    /// is `CANCELED`; a deadline is `TIMEOUT` (`bootstrap_timeout`). The
    /// child is ended and reaped on every error.
    pub async fn recv(&mut self) -> Result<BootstrapLine, OpError> {
        let limit = if self.stream.hello_seen() {
            Some(self.timeouts.message)
        } else {
            self.timeouts.hello
        };
        let stage = if self.stream.hello_seen() {
            "message"
        } else {
            "hello"
        };
        let wait = async {
            match limit {
                Some(limit) => tokio::time::timeout(limit, self.stream.next())
                    .await
                    .map_err(|_| timeout_error(stage))?,
                None => self.stream.next().await,
            }
        };
        let outcome = tokio::select! {
            biased;
            () = self.cancel.canceled() => Err(canceled_error()),
            outcome = wait => outcome,
        };
        match outcome {
            Ok(Some(line)) => Ok(line),
            Ok(None) => Err(self.reap_after_close().await),
            Err(err) => {
                end_child(&mut self.child).await;
                tracing::debug!(target: "qsh::ssh_bootstrap", stage = "recv_failed", code = err.code.as_str());
                Err(err)
            }
        }
    }

    /// Send one message to the responder.
    ///
    /// A broken pipe means the child is gone; its exit status then gives
    /// the error, as in [`Self::recv`].
    pub async fn send(&mut self, line: &BootstrapLine) -> Result<(), OpError> {
        enum Sent {
            Done,
            Broken,
            TimedOut,
            Canceled,
        }
        let text = line.encode_line().map_err(protocol_error)?;
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(self.reap_after_close().await);
        };
        let write = async {
            stdin.write_all(text.as_bytes()).await?;
            stdin.flush().await
        };
        let sent = tokio::select! {
            biased;
            () = self.cancel.canceled() => Sent::Canceled,
            outcome = tokio::time::timeout(self.timeouts.message, write) => match outcome {
                Ok(Ok(())) => Sent::Done,
                Ok(Err(_)) => Sent::Broken,
                Err(_) => Sent::TimedOut,
            },
        };
        match sent {
            Sent::Done => Ok(()),
            Sent::Broken => Err(self.reap_after_close().await),
            Sent::TimedOut => {
                end_child(&mut self.child).await;
                Err(timeout_error("message"))
            }
            Sent::Canceled => {
                end_child(&mut self.child).await;
                Err(canceled_error())
            }
        }
    }

    /// Close the child's stdin and wait for it to exit. The responder ends
    /// when it sees the end of its input; one that does not within the grace
    /// period is terminated. Returns how it ended.
    pub async fn finish(mut self) -> SshExit {
        drop(self.stdin.take());
        self.reap_after_close_exit().await
    }

    /// The error for a child that ended on its own. An interrupt is
    /// `CANCELED` whatever the exit status says: a real OpenSSH can outlive
    /// the connection's SIGINT and report 255 ("Killed by signal 2") instead
    /// of dying of the signal, and the cancel token is what knows the user
    /// pressed Ctrl-C.
    async fn reap_after_close(&mut self) -> OpError {
        let exit = self.reap_after_close_exit().await;
        let canceled = self.cancel.is_canceled();
        tracing::debug!(target: "qsh::ssh_bootstrap", stage = "ssh_exit", interrupted = exit == SshExit::Interrupted, canceled);
        if canceled {
            return canceled_error();
        }
        map_ssh_exit(exit, self.stream.hello_seen())
    }

    async fn reap_after_close_exit(&mut self) -> SshExit {
        if tokio::time::timeout(EXIT_GRACE, self.child.wait())
            .await
            .is_err()
        {
            end_child(&mut self.child).await;
        }
        match self.child.wait().await {
            Ok(status) => SshExit::from_status(status),
            Err(_) => SshExit::Signal(0),
        }
    }
}
