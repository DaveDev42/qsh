//! ConPTY backend for the session broker (`docs/design/architecture.md` §4,
//! ADR-0035 decision 20): the Windows counterpart of `posix.rs`.
//!
//! [`ConPtySource`] is a [`crate::broker::SessionSource`]. One session is:
//!
//! - a **pseudo-console** (`CreatePseudoConsole`) with two pipes: input
//!   (the host writes keystrokes, conhost reads) and output (conhost writes
//!   the VT stream, the host reads);
//! - a **Job Object** with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and a child
//!   created inside it by one `CreateProcessW` call whose attribute list
//!   carries both the pseudo-console and the job
//!   ([`crate::winproc::spawn_in_job`]). The child and everything it starts
//!   are in the job from the first instruction, so the tree can be ended as
//!   one unit (the counterpart of `setsid` + `killpg`) and ends with the host
//!   if the host dies;
//! - the **host ends of the pipes** as overlapped named pipes with an owner
//!   only DACL and an unguessable name, read and written through tokio. The
//!   conhost ends must be synchronous handles, which is why the host ends are
//!   named pipes (an anonymous pipe has no overlapped mode) and no thread is
//!   parked on a read per session.
//!
//! **Exit and output.** The child's exit is a process-handle wait on the
//! system thread pool. ConPTY keeps the output pipe open after the child
//! exits: it flushes what is left of the screen and closes the pipe only when
//! the pseudo-console is closed. Earlier Windows builds make
//! `ClosePseudoConsole` itself wait until that output has been read; Windows
//! 11 24H2 returns at once. So the close runs on a blocking thread while the
//! pump keeps reading, and the end of the stream (not the exit) is what tells
//! the session actor that every byte is in the replay buffer. The actor
//! appends `session.exit` only after both, which keeps the output before exit
//! invariant of `docs/design/testing.md` L5. Closing early would cut the
//! output short, so the close is tied to the child's exit and nothing else.
//! Whatever else still runs on the console at that point ends with it.
//!
//! This module does not build the child's environment or pick a shell yet:
//! the child inherits the host's environment and `argv` must name the
//! program.

use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::future::Future as _;
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::OwnedHandle;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};

use crate::broker::{SessionSource, SessionSpec, Signal, SourceControl, SourceExit, SpawnedSource};
use crate::fsutil::dacl::{CurrentUser, DaclSource as _, ObjectKind};
use crate::winproc::{self, ExitWatch, JobObject, ProcessSpec};

#[cfg(test)]
mod tests;

/// The window size used when the client sends `0` in either dimension (the
/// same fallback as the POSIX backend).
const FALLBACK_SIZE: (u16, u16) = (80, 24);

/// Pipe buffer size for both host pipes.
const PIPE_BUFFER: u32 = 64 * 1024;

fn normalize_size(cols: u16, rows: u16) -> (u16, u16) {
    if cols == 0 || rows == 0 {
        FALLBACK_SIZE
    } else {
        (cols, rows)
    }
}

/// The production-shaped [`SessionSource`] for Windows: runs `argv` in a
/// pseudo-console inside its own Job Object.
#[derive(Debug, Default)]
pub struct ConPtySource;

impl ConPtySource {
    /// A source that spawns the session's `argv`.
    pub fn new() -> Self {
        Self
    }
}

impl SessionSource for ConPtySource {
    fn spawn(self: Box<Self>, spec: &SessionSpec) -> io::Result<SpawnedSource> {
        // The host pipes are registered with the reactor here.
        let _rt = tokio::runtime::Handle::try_current().map_err(|_| {
            io::Error::other("ConPtySource::spawn must be called from within a tokio runtime")
        })?;
        if spec.argv.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ConPtySource needs a program in argv",
            ));
        }
        // An embedded NUL would end the command line there and drop the
        // arguments after it without a word.
        if spec.argv.iter().any(|arg| arg.contains('\0')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ConPtySource argv must not contain NUL",
            ));
        }
        let (cols, rows) = normalize_size(spec.cols, spec.rows);
        let command_line = command_line(&spec.argv);
        ConPtySession::start(&command_line, cols, rows)?.into_spawned()
    }
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

/// `argv` as one `CreateProcessW` command line, quoted the way Rust's
/// `std::process::Command` quotes a Windows command line (the rules every
/// MSVCRT-style `argv` parser undoes).
fn command_line(argv: &[String]) -> OsString {
    let mut wide: Vec<u16> = Vec::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            wide.push(u16::from(b' '));
        }
        push_arg(&mut wide, OsStr::new(arg));
    }
    OsString::from_wide(&wide)
}

fn push_arg(out: &mut Vec<u16>, arg: &OsStr) {
    let units: Vec<u16> = arg.encode_wide().collect();
    let quote = units.is_empty() || units.iter().any(|&c| c == 0x20 || c == 0x09);
    if quote {
        out.push(u16::from(b'"'));
    }
    let mut backslashes = 0usize;
    for &unit in &units {
        if unit == u16::from(b'\\') {
            backslashes += 1;
        } else {
            if unit == u16::from(b'"') {
                // n backslashes before a quote become 2n + 1.
                out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes + 1));
            }
            backslashes = 0;
        }
        out.push(unit);
    }
    if quote {
        // n backslashes before the closing quote become 2n.
        out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        out.push(u16::from(b'"'));
    }
}

// ---------------------------------------------------------------------------
// Pseudo-console
// ---------------------------------------------------------------------------

/// An open pseudo-console. Closing is idempotent and may block (see the
/// module doc), so it never runs on an async task: [`Self::close`] is called
/// from a blocking task, and dropping an open console closes it on a detached
/// thread.
#[derive(Debug)]
struct PseudoConsole {
    handle: Mutex<Option<HPCON>>,
}

impl PseudoConsole {
    fn create(
        cols: u16,
        rows: u16,
        input_read: &OwnedHandle,
        output_write: &OwnedHandle,
    ) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle as _;
        let mut hpc: HPCON = 0;
        // SAFETY: both handles are live, synchronous pipe ends; conhost
        // duplicates them, so the caller may close its copies afterwards.
        let hr = unsafe {
            CreatePseudoConsole(
                coord(cols, rows),
                input_read.as_raw_handle(),
                output_write.as_raw_handle(),
                0,
                &mut hpc,
            )
        };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "CreatePseudoConsole failed: HRESULT {hr:#010x}"
            )));
        }
        Ok(Self {
            handle: Mutex::new(Some(hpc)),
        })
    }

    /// The handle for the process attribute list, while the console is open.
    fn raw(&self) -> Option<HPCON> {
        *self.handle.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn resize(&self, cols: u16, rows: u16) -> io::Result<()> {
        let guard = self.handle.lock().unwrap_or_else(|e| e.into_inner());
        let Some(hpc) = *guard else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the pseudo-console is closed",
            ));
        };
        // SAFETY: `hpc` is an open pseudo-console (the lock is held).
        let hr = unsafe { ResizePseudoConsole(hpc, coord(cols, rows)) };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "ResizePseudoConsole failed: HRESULT {hr:#010x}"
            )));
        }
        Ok(())
    }

    /// Close the console. Blocks until conhost has flushed its last output
    /// into the output pipe and the reader has taken it (or the reader is
    /// gone).
    fn close(&self) {
        let hpc = self.handle.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(hpc) = hpc {
            // SAFETY: `hpc` was open and is closed exactly once: it was
            // taken out of the cell above.
            unsafe { ClosePseudoConsole(hpc) };
        }
    }
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        let hpc = self
            .handle
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(hpc) = hpc {
            // A blocking close must not stall whichever task drops us.
            let _ = std::thread::Builder::new()
                .name("qsh-conpty-close".into())
                // SAFETY: as in `close`.
                .spawn(move || unsafe { ClosePseudoConsole(hpc) });
        }
    }
}

fn coord(cols: u16, rows: u16) -> COORD {
    COORD {
        X: cols.min(i16::MAX as u16) as i16,
        Y: rows.min(i16::MAX as u16) as i16,
    }
}

// ---------------------------------------------------------------------------
// Host pipes
// ---------------------------------------------------------------------------

/// A pipe between the host and conhost: the host's overlapped end, and the
/// synchronous end handed to `CreatePseudoConsole`.
struct HostPipe {
    host: NamedPipeServer,
    conhost: OwnedHandle,
}

/// Create an owner-only pipe under an unguessable name. `host_reads` is the
/// direction: output (conhost writes, host reads) or input (host writes).
fn host_pipe(host_reads: bool) -> io::Result<HostPipe> {
    let name = format!(r"\\.\pipe\qsh-conpty-{:032x}", rand::random::<u128>());
    let descriptor = CurrentUser.owner_only(ObjectKind::Pipe)?;
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte)
        .max_instances(1)
        .access_inbound(host_reads)
        .access_outbound(!host_reads)
        .in_buffer_size(PIPE_BUFFER)
        .out_buffer_size(PIPE_BUFFER);
    // SAFETY: the attributes point at a descriptor owned by `descriptor`,
    // which outlives the call; the kernel copies it.
    let host =
        unsafe { options.create_with_security_attributes_raw(&name, descriptor.attributes_ptr()) }?;
    // Synchronous open (no overlapped flag): conhost does blocking I/O on it.
    let conhost = OpenOptions::new()
        .read(!host_reads)
        .write(host_reads)
        .open(&name)?;
    mark_connected(&host)?;
    Ok(HostPipe {
        host,
        conhost: OwnedHandle::from(conhost),
    })
}

/// Tell the reactor the host end is connected, so it starts servicing reads
/// and writes. The client is already attached (we opened it above), so
/// `ConnectNamedPipe` completes at once with `ERROR_PIPE_CONNECTED` and
/// `connect()` is ready on its first poll; polling it once here keeps
/// [`SessionSource::spawn`] synchronous.
fn mark_connected(host: &NamedPipeServer) -> io::Result<()> {
    let mut cx = Context::from_waker(Waker::noop());
    match std::pin::pin!(host.connect()).poll(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => Err(io::Error::other(
            "the host pipe did not report its client as connected",
        )),
    }
}

/// The output side as an `AsyncRead` that reports a closed pipe as a clean
/// end of stream, like a pty master at hang-up.
struct HostOutput(NamedPipeServer);

impl AsyncRead for HostOutput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.0).poll_read(cx, buf) {
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => Poll::Ready(Ok(())),
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A started pseudo-console session before it is split into the broker's
/// I/O trio. Field order is drop order: the job goes first, so the tree ends
/// before the console and the pipes are torn down.
pub(crate) struct ConPtySession {
    job: Arc<JobObject>,
    console: Arc<PseudoConsole>,
    process: Arc<OwnedHandle>,
    #[cfg_attr(not(test), allow(dead_code))]
    pid: u32,
    output: NamedPipeServer,
    input: NamedPipeServer,
}

impl ConPtySession {
    /// Start `command_line` in a new pseudo-console of `cols` x `rows`.
    pub(crate) fn start(command_line: &OsStr, cols: u16, rows: u16) -> io::Result<Self> {
        let output = host_pipe(true)?;
        let input = host_pipe(false)?;
        let console = PseudoConsole::create(cols, rows, &input.conhost, &output.conhost)?;
        // conhost holds its own duplicates now. Ours must go, or the output
        // pipe would not end while this process lives.
        drop((input.conhost, output.conhost));
        let console = Arc::new(console);
        let job = Arc::new(JobObject::new_kill_on_close()?);
        let process = winproc::spawn_in_job(
            &job,
            &ProcessSpec {
                command_line,
                pseudo_console: console.raw(),
            },
        )?;
        tracing::debug!(pid = process.pid, "ConPTY session started");
        Ok(Self {
            job,
            console,
            pid: process.pid,
            process: Arc::new(process.handle),
            output: output.host,
            input: input.host,
        })
    }

    #[cfg(test)]
    fn pid(&self) -> u32 {
        self.pid
    }

    /// Split into what the broker drives.
    pub(crate) fn into_spawned(self) -> io::Result<SpawnedSource> {
        let Self {
            job,
            console,
            process,
            output,
            input,
            ..
        } = self;
        let watch = ExitWatch::new(Arc::clone(&process))?;
        let closer = Arc::clone(&console);
        let wait = Box::pin(async move {
            watch.exited().await;
            let exit_code = winproc::exit_code(&process).ok().map(|c| c as i32);
            // Closing flushes conhost's last frame into the output pipe and
            // returns once the reader has taken it; the pump is reading on
            // its own task meanwhile, so this only has to leave the async
            // threads. The end of the output stream, not this call, is what
            // the actor waits for.
            drop(tokio::task::spawn_blocking(move || closer.close()));
            SourceExit {
                exit_code,
                signal: None,
            }
        });
        Ok(SpawnedSource {
            output: Box::new(HostOutput(output)),
            input: Box::new(input),
            control: Box::new(ConPtyControl { job, console }),
            wait,
        })
    }

    #[cfg(test)]
    fn job(&self) -> &Arc<JobObject> {
        &self.job
    }

    #[cfg(test)]
    fn host_pipe_handles(&self) -> [std::os::windows::io::RawHandle; 2] {
        use std::os::windows::io::AsRawHandle as _;
        [self.output.as_raw_handle(), self.input.as_raw_handle()]
    }
}

/// Resize and signal control over a running session. Dropping it drops the
/// job, which ends whatever is still running in the session.
struct ConPtyControl {
    job: Arc<JobObject>,
    console: Arc<PseudoConsole>,
}

impl SourceControl for ConPtyControl {
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        let (cols, rows) = normalize_size(cols, rows);
        self.console.resize(cols, rows)
    }

    fn signal(&mut self, signal: Signal) -> io::Result<()> {
        match signal {
            Signal::Kill => self.job.terminate(1),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this signal has no mapping in the ConPTY backend yet",
            )),
        }
    }
}
