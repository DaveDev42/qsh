//! Host-side `exec.run`: spawn a non-PTY child with piped stdio and pump it
//! over an `EXEC_DATA` stream as framed [`ExecFrame`]s
//! (`docs/design/protocol.md` §7 "Exec data" row, §9 `ExecFrame`).
//!
//! Ordering guarantees: every `Stdout`/`Stderr` chunk is sent before
//! `ExecExit`; `ExecExit` is the last frame; the stream is then finished.
//! The child is only spawned by [`run_exec`], which the server calls **after**
//! the ACL check passed and the ticket was redeemed — never earlier.

use std::process::Stdio;
use std::time::Duration;

use qsh_proto::wire::{EXEC_CHUNK_MAX, ExecFrame, exec_frame};
use qsh_transport::{FramedRecv, FramedSend, StreamError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecSpec {
    /// Program + arguments, executed directly (no shell).
    pub argv: Vec<String>,
    /// Extra environment layered over the host process environment.
    pub env: Vec<(String, String)>,
    /// Kill the child after this long. `None` = no limit.
    pub timeout: Option<Duration>,
}

/// How an exec ended, as reported to the client in `ExecExit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    /// Exit code (`128 + signo` if signaled).
    pub exit_code: i32,
    /// Terminating signal name, if any.
    pub signal: Option<String>,
    /// Whether the host killed the child because `timeout` elapsed.
    pub timed_out: bool,
}

/// Errors from running an exec. Spawn failures are *not* errors here: they
/// are reported to the client in-band (stderr message + exit 126/127, like
/// a shell would), because the control response was already sent.
#[derive(Debug, Error)]
pub enum ExecError {
    /// The data stream failed while pumping.
    #[error("exec stream: {0}")]
    Stream(#[from] StreamError),
    /// Waiting on the child failed.
    #[error("wait: {0}")]
    Wait(std::io::Error),
    /// The peer stopped reading the data stream and did not drain it within
    /// [`DRAIN_GRACE`] after the child ended; the stream was reset.
    #[error("peer stopped reading exec output; stream reset")]
    PeerNotReading,
    /// The stream writer task died (panic/cancellation).
    #[error("exec writer task failed: {0}")]
    Writer(String),
}

impl ExecError {
    /// Whether this failure just means the peer stopped participating
    /// (connection lost / stream reset / not reading) rather than anything
    /// going wrong on the host.
    pub fn is_peer_gone(&self) -> bool {
        match self {
            ExecError::Stream(StreamError::Read(_) | StreamError::Write(_)) => true,
            ExecError::PeerNotReading => true,
            ExecError::Stream(_) | ExecError::Wait(_) | ExecError::Writer(_) => false,
        }
    }
}

/// Bounded queue depth between the pipe readers and the stream writer.
const OUTPUT_QUEUE_FRAMES: usize = 64;

/// How the stream-writer task ended.
enum WriterEnd {
    /// Every output frame was delivered; the send half is handed back for
    /// `ExecExit`.
    Done(FramedSend),
    /// A send failed (peer gone); the rest was drained and discarded.
    Failed(FramedSend, StreamError),
    /// Cancelled while wedged on a non-reading peer; the stream was reset.
    Cancelled,
}

/// How long the host keeps trying to deliver buffered output / `ExecExit`
/// to a peer that has stopped reading (flow-control wedge) after the child
/// is gone, before resetting the stream and giving up.
pub const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Exit code reported when the program could not be executed
/// (`ENOENT` → 127, anything else → 126 — shell convention).
fn spawn_failure_code(err: &std::io::Error) -> i32 {
    match err.kind() {
        std::io::ErrorKind::NotFound => 127,
        _ => 126,
    }
}

/// Run `spec`, streaming its stdio over `(send, recv)`. Consumes the stream:
/// on return the send side has been finished (or reset on error).
pub async fn run_exec(
    spec: ExecSpec,
    mut send: FramedSend,
    mut recv: FramedRecv,
) -> Result<ExecOutcome, ExecError> {
    let Some((program, args)) = spec.argv.split_first() else {
        send.send(&ExecFrame::stderr(b"qsh: empty argv\n".to_vec()))
            .await?;
        send.send(&ExecFrame::exec_exit(126, None)).await?;
        let _ = send.finish();
        return Ok(ExecOutcome {
            exit_code: 126,
            signal: None,
            timed_out: false,
        });
    };

    let mut cmd = Command::new(program);
    cmd.args(args)
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        // Own process group so a timeout kill reaches the whole tree.
        cmd.process_group(0);
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            let code = spawn_failure_code(&err);
            let msg = format!("qsh: cannot execute {program:?}: {err}\n");
            send.send(&ExecFrame::stderr(msg.into_bytes())).await?;
            send.send(&ExecFrame::exec_exit(code, None)).await?;
            let _ = send.finish();
            return Ok(ExecOutcome {
                exit_code: code,
                signal: None,
                timed_out: false,
            });
        }
    };

    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    // Pipe readers → single writer, so frames never interleave mid-frame.
    let (tx, mut rx) = mpsc::channel::<ExecFrame>(OUTPUT_QUEUE_FRAMES);
    let stdout_task = child_stdout.map(|out| tokio::spawn(pump_output(out, tx.clone(), true)));
    let stderr_task = child_stderr.map(|err| tokio::spawn(pump_output(err, tx.clone(), false)));
    drop(tx);

    // Client stdin → child stdin. Ends on StdinEof, stream end, or error.
    // A read *error* (as opposed to a clean end) means the peer is gone —
    // the stream was reset or the connection dropped — and nobody is
    // listening for output anymore, so the writer is told to kill the
    // child instead of letting it run to completion as an orphan.
    let (peer_gone_tx, mut peer_gone_rx) = tokio::sync::oneshot::channel::<()>();
    let stdin_task = tokio::spawn(async move {
        let mut child_stdin = child_stdin;
        let mut peer_gone_tx = Some(peer_gone_tx);
        loop {
            match recv.recv::<ExecFrame>().await {
                Ok(Some(ExecFrame {
                    body: Some(exec_frame::Body::Stdin(chunk)),
                })) => {
                    if let Some(stdin) = child_stdin.as_mut()
                        && stdin.write_all(&chunk.data).await.is_err()
                    {
                        // Child closed its stdin; keep draining the peer so
                        // it never blocks on flow control.
                        child_stdin = None;
                    }
                }
                Ok(Some(ExecFrame {
                    body: Some(exec_frame::Body::StdinEof(_)),
                })) => {
                    child_stdin = None; // drop → EOF to child
                }
                Ok(Some(_)) => {
                    // Client-side frames other than stdin are a protocol
                    // slip; ignore rather than kill a running command.
                }
                Ok(None) => break,
                Err(_) => {
                    if let Some(tx) = peer_gone_tx.take() {
                        let _ = tx.send(());
                    }
                    break;
                }
            }
        }
        drop(child_stdin);
        recv
    });

    // Writer: owns the send half and forwards output frames until both
    // readers are done. It runs as its own task so that a send blocked on
    // QUIC flow control (a peer that stopped reading) can never delay the
    // deadline / peer-gone handling below — those select over the writer's
    // *completion*, not over individual sends.
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::oneshot::channel::<()>();
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let mut writer = tokio::spawn(async move {
        let mut write_failed_tx = Some(write_failed_tx);
        let mut write_err: Option<StreamError> = None;
        while let Some(frame) = rx.recv().await {
            if write_err.is_some() {
                // Keep draining so the readers finish and the child can be
                // reaped; nothing more can be delivered.
                continue;
            }
            tokio::select! {
                sent = send.send(&frame) => {
                    if let Err(err) = sent {
                        write_err = Some(err);
                        if let Some(tx) = write_failed_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
                _ = &mut cancel_rx => {
                    // Told to give up on a peer that is not reading: reset
                    // rather than leave a half-written frame behind.
                    send.reset(1);
                    return WriterEnd::Cancelled;
                }
            }
        }
        match write_err {
            None => WriterEnd::Done(send),
            Some(err) => WriterEnd::Failed(send, err),
        }
    });

    let deadline = spec.timeout.map(|t| tokio::time::Instant::now() + t);
    let mut timed_out = false;
    let mut killed = false;
    fn kill(child: &mut tokio::process::Child, killed: &mut bool) {
        if !*killed {
            *killed = true;
            kill_group(child);
            let _ = child.start_kill();
        }
    }
    let mut peer_gone_polled = false;
    let mut write_failed_polled = false;
    let ended = loop {
        tokio::select! {
            joined = &mut writer => break joined,
            _ = sleep_until_opt(deadline), if deadline.is_some() && !timed_out => {
                timed_out = true;
                kill(&mut child, &mut killed);
                // Reap right away (SIGKILL is prompt) so the child never
                // lingers as a zombie while the tail drains; tokio caches
                // the status for the final `wait` below.
                let _ = child.wait().await;
                // Readers hit EOF once the group is dead; the writer then
                // ends — unless the peer stopped reading and a send is
                // wedged on flow control. Bound that: after `DRAIN_GRACE`
                // tell the writer to reset and give up on the tail.
                match tokio::time::timeout(DRAIN_GRACE, &mut writer).await {
                    Ok(joined) => break joined,
                    Err(_elapsed) => {
                        let _ = cancel_tx.send(());
                        break (&mut writer).await;
                    }
                }
            }
            res = &mut peer_gone_rx, if !killed && !peer_gone_polled => {
                // A oneshot receiver must not be polled again once it has
                // resolved. `Ok` = the peer vanished mid-exec; `Err` = the
                // stdin task ended normally without signalling.
                peer_gone_polled = true;
                if res.is_ok() {
                    kill(&mut child, &mut killed);
                }
            }
            res = &mut write_failed_rx, if !killed && !write_failed_polled => {
                // The peer stopped listening (stream reset / connection
                // gone): kill the child rather than let it run as an
                // orphan whose output nobody reads.
                write_failed_polled = true;
                if res.is_ok() {
                    kill(&mut child, &mut killed);
                }
            }
        }
    };
    let (mut send, write_err) = match ended {
        Ok(WriterEnd::Done(send)) => (send, None),
        Ok(WriterEnd::Failed(send, err)) => (send, Some(err)),
        Ok(WriterEnd::Cancelled) => {
            // The stream is already reset; nothing more can be delivered.
            // Make sure the child does not outlive the exec and reap it.
            kill(&mut child, &mut killed);
            stdin_task.abort();
            let _ = child.wait().await;
            return Err(ExecError::PeerNotReading);
        }
        Err(join_err) => {
            kill(&mut child, &mut killed);
            stdin_task.abort();
            let _ = child.wait().await;
            return Err(ExecError::Writer(join_err.to_string()));
        }
    };
    if let Some(t) = stdout_task {
        let _ = t.await;
    }
    if let Some(t) = stderr_task {
        let _ = t.await;
    }

    // Reap. Pipes are at EOF, so a well-behaved child has exited or is
    // about to; still honor the deadline in case it lingers.
    let status = match deadline {
        Some(d) if !timed_out => match tokio::time::timeout_at(d, child.wait()).await {
            Ok(status) => status,
            Err(_) => {
                timed_out = true;
                kill(&mut child, &mut killed);
                child.wait().await
            }
        },
        _ => child.wait().await,
    };
    // The stdin pump must not outlive the exec on any path.
    stdin_task.abort();
    let status = status.map_err(ExecError::Wait)?;

    let (exit_code, signal) = exit_status_parts(&status);
    if let Some(err) = write_err {
        send.reset(1);
        return Err(ExecError::Stream(err));
    }
    let exit = if timed_out {
        ExecFrame::exec_exit_timed_out(exit_code, signal.clone())
    } else {
        ExecFrame::exec_exit(exit_code, signal.clone())
    };
    // The final frame gets the same bounded patience as the tail drain.
    match tokio::time::timeout(DRAIN_GRACE, send.send(&exit)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            send.reset(1);
            return Err(ExecError::Stream(err));
        }
        Err(_elapsed) => {
            send.reset(1);
            return Err(ExecError::PeerNotReading);
        }
    }
    let _ = send.finish();
    Ok(ExecOutcome {
        exit_code,
        signal,
        timed_out,
    })
}

async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Read `pipe` to EOF, forwarding ≤ [`EXEC_CHUNK_MAX`] chunks as frames.
async fn pump_output<R: AsyncRead + Unpin>(
    mut pipe: R,
    tx: mpsc::Sender<ExecFrame>,
    is_stdout: bool,
) {
    let mut buf = vec![0u8; EXEC_CHUNK_MAX];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let data = buf[..n].to_vec();
                let frame = if is_stdout {
                    ExecFrame::stdout(data)
                } else {
                    ExecFrame::stderr(data)
                };
                if tx.send(frame).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(unix)]
fn kill_group(child: &tokio::process::Child) {
    if let Some(pid) = child.id() {
        // SAFETY: killpg is async-signal-safe and only takes plain integers;
        // the pgid equals the child's pid because we spawned it with
        // `process_group(0)`.
        unsafe {
            libc::killpg(pid as libc::pid_t, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_group(_child: &tokio::process::Child) {}

/// Split an [`std::process::ExitStatus`] into (exit_code, signal_name).
pub fn exit_status_parts(status: &std::process::ExitStatus) -> (i32, Option<String>) {
    if let Some(code) = status.code() {
        return (code, None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signo) = status.signal() {
            return (128 + signo, Some(signal_name(signo)));
        }
    }
    (1, None)
}

/// Portable-enough signal naming for the common POSIX signals.
#[cfg(unix)]
pub fn signal_name(signo: i32) -> String {
    let name = match signo {
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGILL => "SIGILL",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGKILL => "SIGKILL",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGALRM => "SIGALRM",
        libc::SIGTERM => "SIGTERM",
        libc::SIGCHLD => "SIGCHLD",
        libc::SIGCONT => "SIGCONT",
        libc::SIGSTOP => "SIGSTOP",
        libc::SIGTSTP => "SIGTSTP",
        libc::SIGTTIN => "SIGTTIN",
        libc::SIGTTOU => "SIGTTOU",
        libc::SIGXCPU => "SIGXCPU",
        libc::SIGXFSZ => "SIGXFSZ",
        libc::SIGWINCH => "SIGWINCH",
        _ => return format!("SIG{signo}"),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_failure_codes_follow_shell_convention() {
        assert_eq!(
            spawn_failure_code(&std::io::Error::from(std::io::ErrorKind::NotFound)),
            127
        );
        assert_eq!(
            spawn_failure_code(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            126
        );
    }

    #[cfg(unix)]
    #[test]
    fn signal_names() {
        assert_eq!(signal_name(libc::SIGKILL), "SIGKILL");
        assert_eq!(signal_name(libc::SIGTERM), "SIGTERM");
        assert_eq!(signal_name(200), "SIG200");
    }

    #[cfg(unix)]
    #[test]
    fn exit_status_parts_reports_signal() {
        use std::os::unix::process::ExitStatusExt;
        let st = std::process::ExitStatus::from_raw(libc::SIGKILL); // killed by 9
        assert_eq!(exit_status_parts(&st), (137, Some("SIGKILL".into())));
        let st = std::process::ExitStatus::from_raw(7 << 8); // exit(7)
        assert_eq!(exit_status_parts(&st), (7, None));
    }
}
