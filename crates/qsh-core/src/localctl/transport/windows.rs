//! The Windows transport: a named pipe per daemon, `\\.\pipe\qsh-<scope>-<pid>`
//! (ADR-0035 decision 14). It carries the unix trust model over unchanged:
//! only the same OS user reaches a daemon, and both ends check that before
//! a frame is exchanged.
//!
//! - **Name.** `<scope>` is the first 16 hex digits of the SHA-256 of the
//!   process token's user SID string and the normalised runtime directory,
//!   joined by a NUL ([`pipe_scope`]). Another user, or another state
//!   directory (`QSH_STATE_DIR`), lives in another name space and neither
//!   sees nor touches the other's daemon. A daemon uses one `<pid>` at a time.
//! - **Creation.** The first instance is created with
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a name somebody else already holds
//!   makes [`PipeListener::bind`] fail instead of silently sharing it. Remote
//!   clients are always rejected and the pipe is a byte stream
//!   ([`CreateOptions`]); `frame.rs` does the framing.
//! - **Access.** Every instance gets a protected DACL with one ACE for the
//!   owner (`crate::fsutil::dacl`, [`ObjectKind::Pipe`]): read, write and
//!   `FILE_CREATE_PIPE_INSTANCE`. The default pipe DACL would give Everyone
//!   and the anonymous user read access, so it is never left to default.
//!   The instance for the next client is created before the current
//!   connection is handed off, so the name is never without a listener.
//! - **Credentials, server side.** [`PipeListener::accept`] looks up the
//!   connecting process (`GetNamedPipeClientProcessId`), reads the user SID
//!   of its token and compares it with its own *before the caller can read a
//!   byte*. A different SID, or any failure on the way, drops the
//!   connection without a word.
//! - **Credentials, client side.** [`connect`] opens the pipe with
//!   `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so a fake server
//!   cannot impersonate the caller's token, and before it returns the stream
//!   it compares the server process's user SID with its own. A different SID
//!   is an error and nothing was written.
//!
//! - **Half-close.** The one thing a byte-mode pipe cannot do that a socket
//!   can is end one direction while the other stays open. The raw byte phase
//!   of a conduit (after the framed `qsh.local.v1` messages) therefore
//!   carries its bytes in chunks, a 4-byte big-endian length and that many
//!   bytes, and a zero length ends the writer's direction
//!   (`crate::localctl::chunked`; [`raw_reader`], [`raw_writer`],
//!   [`raw_bytes`], [`shutdown_write`]). The framed phase is not chunked.
//!   [`shutdown_both`] is the hard stop: it cancels the pending I/O and makes
//!   every later read end and every later write fail.
//!
//! The lookups that need the OS ([`ProcessSids`]) and the DACL source
//! ([`DaclSource`]) are traits so a test can make the peer a different user
//! or the DACL fail; production code uses [`Os`] and the process token.

use std::ffi::OsString;
use std::io;
use std::os::windows::io::{AsRawHandle as _, RawHandle};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use qsh_proto::ErrorCode;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};
use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};

use crate::config::Paths;
use crate::fsutil::dacl::{
    CurrentUser, DaclSource, ObjectKind, equal_sid, process_user_sid, sid_to_string, token_user_sid,
};
use crate::localctl::chunked::{self, ChunkedReader, ChunkedWriter};
use crate::ops::OpError;

/// Where every pipe name starts.
pub(crate) const PIPE_NAMESPACE: &str = r"\\.\pipe\";

/// How long [`connect`] keeps retrying while every instance of the pipe is
/// busy (`ERROR_PIPE_BUSY`): the daemon creates the next instance right
/// after it accepts one, so the window is normally microseconds.
const BUSY_RETRY_BUDGET: Duration = Duration::from_secs(5);
const BUSY_RETRY_STEP: Duration = Duration::from_millis(10);

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// The scope part of a pipe name for the user `sid_text` and the runtime
/// directory `runtime_dir`: 16 lower-case hex digits of
/// `SHA-256(sid ‖ NUL ‖ normalised runtime dir)`.
///
/// The directory is normalised lexically — made absolute, `/` turned into
/// `\`, a `\\?\` prefix and trailing separators dropped, lower-cased — and
/// never looked up on disk, because the runtime directory is not created on
/// Windows and a name must not depend on whether it exists.
pub(crate) fn pipe_scope(sid_text: &str, runtime_dir: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sid_text.as_bytes());
    hasher.update([0u8]);
    hasher.update(normalise_dir(runtime_dir).as_bytes());
    let digest = hasher.finalize();
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn normalise_dir(dir: &Path) -> String {
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let text = absolute.to_string_lossy().replace('/', "\\");
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    text.trim_end_matches('\\').to_lowercase()
}

/// `qsh-<scope>-`, the prefix every pipe of this scope starts with.
pub(crate) fn pipe_prefix(scope: &str) -> String {
    format!("qsh-{scope}-")
}

/// The full pipe name for a daemon with this pid.
pub(crate) fn pipe_name(scope: &str, pid: u32) -> PathBuf {
    PathBuf::from(format!("{PIPE_NAMESPACE}{}{pid}", pipe_prefix(scope)))
}

/// The pipe name for a daemon with pid `pid` serving `runtime_dir`, for this
/// process's own user.
pub(crate) fn scoped_pipe_name(runtime_dir: &Path, pid: u32) -> io::Result<PathBuf> {
    Ok(pipe_name(&current_scope(&Os, runtime_dir)?, pid))
}

/// The scope of this process: its token's user SID with `runtime_dir`.
fn current_scope(sids: &dyn ProcessSids, runtime_dir: &Path) -> io::Result<String> {
    Ok(pipe_scope(&sid_to_string(&sids.own()?)?, runtime_dir))
}

/// From the names found in `\\.\pipe\`, the ones that belong to `scope`:
/// `qsh-<scope>-<digits>`, as `(pid, name)` pid-ascending. Anything else —
/// another scope, another program's pipe, a non-numeric tail — is not ours.
pub(crate) fn pick_scoped_pipes(
    names: impl IntoIterator<Item = OsString>,
    scope: &str,
) -> Vec<(u32, PathBuf)> {
    let prefix = pipe_prefix(scope);
    let mut out: Vec<(u32, PathBuf)> = names
        .into_iter()
        .filter_map(|name| {
            let name = name.to_str()?;
            let tail = name.strip_prefix(&prefix)?;
            if tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let pid = tail.parse().ok()?;
            Some((pid, pipe_name(scope, pid)))
        })
        .collect();
    out.sort_by_key(|(pid, _)| *pid);
    out
}

/// This machine's localctl pipes for this user and `runtime_dir`, pid-ascending
/// (the counterpart of the unix `<pid>.sock` listing). A pipe disappears with
/// its process, so there is nothing stale to clean up.
pub(crate) fn candidate_endpoints(runtime_dir: &Path) -> io::Result<Vec<(u32, PathBuf)>> {
    candidate_endpoints_with(&Os, runtime_dir)
}

fn candidate_endpoints_with(
    sids: &dyn ProcessSids,
    runtime_dir: &Path,
) -> io::Result<Vec<(u32, PathBuf)>> {
    let scope = current_scope(sids, runtime_dir)?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(PIPE_NAMESPACE)? {
        names.push(entry?.file_name());
    }
    Ok(pick_scoped_pipes(names, &scope))
}

/// A pipe vanishes with its process, so a refused connection leaves nothing
/// to clean up.
pub(crate) fn forget_refused_endpoint(_pid: u32, _endpoint: &Path) {}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// The two lookups behind the credential check, so a test can make the
/// other end of a pipe another user.
pub(crate) trait ProcessSids: Send + Sync {
    /// The user SID this process runs as.
    fn own(&self) -> io::Result<Vec<u32>>;
    /// The user SID of the process `pid`.
    fn of_process(&self, pid: u32) -> io::Result<Vec<u32>>;
}

/// The real lookups: the process token, and `OpenProcess` +
/// `OpenProcessToken` for the peer.
pub(crate) struct Os;

impl ProcessSids for Os {
    fn own(&self) -> io::Result<Vec<u32>> {
        token_user_sid()
    }
    fn of_process(&self, pid: u32) -> io::Result<Vec<u32>> {
        process_user_sid(pid)
    }
}

/// Whether process `pid` runs as the same user as this process. A failed
/// lookup is an error, which every caller treats as "no".
fn same_user(sids: &dyn ProcessSids, pid: u32) -> io::Result<bool> {
    Ok(equal_sid(&sids.own()?, &sids.of_process(pid)?))
}

fn raw(handle: RawHandle) -> HANDLE {
    handle.cast()
}

/// The pid of the process at the other end of a server-side pipe handle.
fn client_pid(pipe: &NamedPipeServer) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` owns a live pipe handle; the out-pointer is a local.
    if unsafe { GetNamedPipeClientProcessId(raw(pipe.as_raw_handle()), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// The pid of the process at the other end of a client-side pipe handle.
fn server_pid(pipe: &NamedPipeClient) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` owns a live pipe handle; the out-pointer is a local.
    if unsafe { GetNamedPipeServerProcessId(raw(pipe.as_raw_handle()), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

// ---------------------------------------------------------------------------
// Create options
// ---------------------------------------------------------------------------

/// The creation parameters of a pipe instance that decide who can reach it,
/// as a plain value: tokio's `ServerOptions` cannot be read back, so this is
/// what a test pins and what [`Self::server_options`] builds from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CreateOptions {
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE`: fail if the name already exists.
    pub(crate) first_instance: bool,
    /// `PIPE_REJECT_REMOTE_CLIENTS`: nobody over SMB.
    pub(crate) reject_remote_clients: bool,
    /// `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE`.
    pub(crate) byte_stream: bool,
}

impl CreateOptions {
    /// The options for the first instance of a name, or for a later one.
    pub(crate) fn for_instance(first: bool) -> Self {
        Self {
            first_instance: first,
            reject_remote_clients: true,
            byte_stream: true,
        }
    }

    fn server_options(self) -> ServerOptions {
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(self.first_instance)
            .reject_remote_clients(self.reject_remote_clients)
            .pipe_mode(if self.byte_stream {
                PipeMode::Byte
            } else {
                PipeMode::Message
            });
        options
    }
}

/// The `dwFlagsAndAttributes` security bits a client opens the pipe with:
/// a quality-of-service block is present and the impersonation level is
/// identification, so the server can learn who the client is but cannot act
/// as it.
pub(crate) const fn client_qos_flags() -> u32 {
    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
}

// ---------------------------------------------------------------------------
// The server end
// ---------------------------------------------------------------------------

/// A bound pipe name: the instance waiting for the next client, and what is
/// needed to create the one after it.
pub(crate) struct PipeListener {
    name: PathBuf,
    sids: Arc<dyn ProcessSids>,
    dacl: Arc<dyn DaclSource>,
    waiting: NamedPipeServer,
}

impl PipeListener {
    /// Bind the pipe a daemon with pid `pid` serves for `runtime_dir`.
    pub(crate) fn bind(runtime_dir: &Path, pid: u32) -> io::Result<Self> {
        Self::bind_at(&scoped_pipe_name(runtime_dir, pid)?)
    }

    /// Bind exactly `name`, with the real lookups.
    pub(crate) fn bind_at(name: &Path) -> io::Result<Self> {
        Self::bind_named(name.to_path_buf(), Arc::new(Os), Arc::new(CurrentUser))
    }

    /// Bind `name` with explicit lookups. Fails when the name is already
    /// taken by any pipe, whoever created it.
    pub(crate) fn bind_named(
        name: PathBuf,
        sids: Arc<dyn ProcessSids>,
        dacl: Arc<dyn DaclSource>,
    ) -> io::Result<Self> {
        let waiting = create_instance(&name, true, dacl.as_ref())?;
        Ok(Self {
            name,
            sids,
            dacl,
            waiting,
        })
    }

    /// The pipe name this listener serves.
    pub(crate) fn name(&self) -> &Path {
        &self.name
    }

    /// Wait for the next client whose process runs as this user.
    ///
    /// The instance for the client after this one exists before this
    /// returns. A client that fails the credential check is dropped without
    /// a byte read or written, and the wait goes on.
    pub(crate) async fn accept(&mut self) -> io::Result<LocalStream> {
        loop {
            self.waiting.connect().await?;
            let next = create_instance(&self.name, false, self.dacl.as_ref())?;
            let connected = std::mem::replace(&mut self.waiting, next);
            match client_pid(&connected).and_then(|pid| same_user(self.sids.as_ref(), pid)) {
                Ok(true) => return Ok(LocalStream::new(Inner::Server(connected))),
                Ok(false) => {
                    tracing::warn!(
                        "localctl: rejected a connecting process that runs as another user"
                    );
                }
                Err(err) => {
                    tracing::warn!(%err, "localctl: peer credential check failed; rejecting");
                }
            }
        }
    }

    /// The raw handle of the instance that is waiting for a client, for the
    /// tests that read its security descriptor.
    #[cfg(test)]
    pub(crate) fn waiting_handle(&self) -> RawHandle {
        self.waiting.as_raw_handle()
    }
}

fn create_instance(name: &Path, first: bool, dacl: &dyn DaclSource) -> io::Result<NamedPipeServer> {
    let descriptor = dacl.owner_only(ObjectKind::Pipe)?;
    // SAFETY: the attributes point at a descriptor owned by `descriptor`,
    // which outlives the call; the kernel copies it.
    unsafe {
        CreateOptions::for_instance(first)
            .server_options()
            .create_with_security_attributes_raw(name, descriptor.attributes_ptr())
    }
}

// ---------------------------------------------------------------------------
// The client end
// ---------------------------------------------------------------------------

/// Open the pipe `endpoint`, then check that its server runs as this user.
pub(crate) async fn connect(endpoint: &Path) -> io::Result<LocalStream> {
    connect_with(endpoint, &Os).await
}

/// [`connect`] with an explicit credential lookup. A server that runs as
/// another user (or whose user cannot be determined) is an error, and by
/// then nothing has been written to it.
pub(crate) async fn connect_with(
    endpoint: &Path,
    sids: &dyn ProcessSids,
) -> io::Result<LocalStream> {
    let client = open_client(endpoint).await?;
    match server_pid(&client).and_then(|pid| same_user(sids, pid)) {
        Ok(true) => Ok(LocalStream::new(Inner::Client(client))),
        Ok(false) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the pipe {} is served by a process of another user",
                endpoint.display()
            ),
        )),
        Err(err) => Err(io::Error::new(
            err.kind(),
            format!(
                "cannot verify who serves the pipe {}: {err}",
                endpoint.display()
            ),
        )),
    }
}

async fn open_client(endpoint: &Path) -> io::Result<NamedPipeClient> {
    let started = tokio::time::Instant::now();
    loop {
        match ClientOptions::new()
            .security_qos_flags(client_qos_flags())
            .open(endpoint)
        {
            Ok(client) => return Ok(client),
            Err(err)
                if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && started.elapsed() < BUSY_RETRY_BUDGET =>
            {
                tokio::time::sleep(BUSY_RETRY_STEP).await;
            }
            Err(err) => return Err(err),
        }
    }
}

// ---------------------------------------------------------------------------
// The stream
// ---------------------------------------------------------------------------

enum Inner {
    Client(NamedPipeClient),
    Server(NamedPipeServer),
}

/// A connected localctl pipe, from either end.
///
/// It offers the same readiness-based methods as `UnixStream` (`readable`,
/// `try_read`, `poll_read_ready`, …) through `&self`, because the data half
/// of a `LOCAL_STREAM` conduit is shared by several owners, plus
/// `AsyncRead`/`AsyncWrite` for the framed phase.
pub struct LocalStream {
    inner: Inner,
    /// Set by [`shutdown_both`]: the stream reads as ended and refuses writes.
    stopped: AtomicBool,
    /// Set by [`shutdown_write`]: the end chunk was written (or is on its way).
    write_ended: AtomicBool,
}

impl std::fmt::Debug for LocalStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStream")
            .field("stopped", &self.stopped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

macro_rules! pipe {
    ($stream:expr, $p:ident => $body:expr) => {
        match &$stream.inner {
            Inner::Client($p) => $body,
            Inner::Server($p) => $body,
        }
    };
}

impl LocalStream {
    fn new(inner: Inner) -> Self {
        Self {
            inner,
            stopped: AtomicBool::new(false),
            write_ended: AtomicBool::new(false),
        }
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Wait until a read is likely to make progress.
    pub async fn readable(&self) -> io::Result<()> {
        if self.is_stopped() {
            return Ok(());
        }
        pipe!(self, p => p.readable().await)
    }

    /// Wait until a write is likely to make progress.
    pub async fn writable(&self) -> io::Result<()> {
        if self.is_stopped() {
            return Ok(());
        }
        pipe!(self, p => p.writable().await)
    }

    /// Poll for read readiness.
    pub fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.is_stopped() {
            return Poll::Ready(Ok(()));
        }
        pipe!(self, p => p.poll_read_ready(cx))
    }

    /// Poll for write readiness.
    pub fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.is_stopped() {
            return Poll::Ready(Ok(()));
        }
        pipe!(self, p => p.poll_write_ready(cx))
    }

    /// Read without waiting. `Ok(0)` is the end of the stream.
    pub fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.is_stopped() {
            return Ok(0);
        }
        pipe!(self, p => p.try_read(buf))
    }

    /// Write without waiting.
    pub fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        if self.is_stopped() {
            return Err(stopped_error());
        }
        pipe!(self, p => p.try_write(buf))
    }

    fn handle(&self) -> RawHandle {
        pipe!(self, p => p.as_raw_handle())
    }
}

fn stopped_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "the localctl pipe was stopped locally",
    )
}

impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.is_stopped() {
            return Poll::Ready(Ok(()));
        }
        match &mut this.inner {
            Inner::Client(p) => Pin::new(p).poll_read(cx, buf),
            Inner::Server(p) => Pin::new(p).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.is_stopped() {
            return Poll::Ready(Err(stopped_error()));
        }
        match &mut this.inner {
            Inner::Client(p) => Pin::new(p).poll_write(cx, buf),
            Inner::Server(p) => Pin::new(p).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            Inner::Client(p) => Pin::new(p).poll_flush(cx),
            Inner::Server(p) => Pin::new(p).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            Inner::Client(p) => Pin::new(p).poll_shutdown(cx),
            Inner::Server(p) => Pin::new(p).poll_shutdown(cx),
        }
    }
}

/// The read side of a conduit's raw byte phase: the half, decoded from the
/// chunk framing (`crate::localctl::chunked`).
pub(crate) type RawReader<R> = ChunkedReader<R>;
/// The write side of a conduit's raw byte phase: the half, encoded as chunks;
/// shutting it down writes the end chunk.
pub(crate) type RawWriter<W> = ChunkedWriter<W>;

/// Start the raw phase on the read side. `prefetched` is what the framed
/// phase already read past its last message, still chunk-encoded; the reader
/// decodes it first, so no bytes come back to deliver separately.
pub(crate) fn raw_reader<R>(read: R, prefetched: Vec<u8>) -> (RawReader<R>, Vec<u8>) {
    (ChunkedReader::new(read, prefetched), Vec::new())
}

/// Start the raw phase on the write side.
pub(crate) fn raw_writer<W>(write: W) -> RawWriter<W> {
    ChunkedWriter::new(write)
}

/// `data` as the raw phase carries it on the wire.
pub(crate) fn raw_bytes(data: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    std::borrow::Cow::Owned(chunked::encode(data))
}

/// End the write direction of the raw phase by writing the end chunk, for a
/// stream that several owners share and a caller that cannot await. It is
/// written once per stream; if the pipe has no room right now the rest goes
/// out from a spawned task, which holds its own reference to the stream. The
/// peer's read reports the end while it can still answer.
pub(crate) fn shutdown_write(stream: &Arc<LocalStream>) {
    if stream.write_ended.swap(true, Ordering::AcqRel) || stream.is_stopped() {
        return;
    }
    let sent = stream.try_write(&chunked::END_CHUNK).unwrap_or(0);
    if sent == chunked::END_CHUNK.len() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let stream = stream.clone();
    runtime.spawn(async move {
        let mut rest = &chunked::END_CHUNK[sent..];
        while !rest.is_empty() {
            if stream.writable().await.is_err() {
                return;
            }
            match stream.try_write(rest) {
                Ok(n) => rest = &rest[n..],
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
    });
}

/// Hard stop from any thread: every pending operation is cancelled, later
/// reads report the end of the stream and later writes fail.
pub(crate) fn shutdown_both(stream: &LocalStream) {
    stream.stopped.store(true, Ordering::Release);
    // SAFETY: the handle belongs to `stream`, which is borrowed for the call;
    // a null `OVERLAPPED` cancels every request of this handle. A failure
    // means there was nothing pending.
    unsafe {
        CancelIoEx(raw(stream.handle()), std::ptr::null());
    }
}

// ---------------------------------------------------------------------------
// Split halves, the daemon's listener
// ---------------------------------------------------------------------------

/// The read half of a split [`LocalStream`].
pub(crate) struct OwnedReadHalf(Arc<LocalStream>);

/// The write half of a split [`LocalStream`]. Shutting it down does nothing
/// by itself; a conduit's raw phase wraps it in [`RawWriter`], whose shutdown
/// writes the end chunk.
pub(crate) struct OwnedWriteHalf(Arc<LocalStream>);

/// Split a conduit into independently owned halves.
pub(crate) fn split(stream: LocalStream) -> (OwnedReadHalf, OwnedWriteHalf) {
    let shared = Arc::new(stream);
    (OwnedReadHalf(shared.clone()), OwnedWriteHalf(shared))
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            std::task::ready!(self.0.poll_read_ready(cx))?;
            match self.0.try_read(buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }
}

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.0.poll_write_ready(cx))?;
            match self.0.try_write(buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Resolves once the peer has closed its end of the conduit entirely, as
/// opposed to having ended only its write direction with the end chunk. After
/// the end chunk the peer sends nothing, so the next thing the pipe reports
/// is the peer closing it (or, against the protocol, more bytes; either way
/// there is nothing left to wait for). The read half is watched directly,
/// below the chunk decoder.
pub(crate) async fn wait_for_hangup(read: &RawReader<OwnedReadHalf>) {
    let stream = &read.get_ref().0;
    let mut scratch = [0u8; 64];
    loop {
        if stream.readable().await.is_err() {
            return;
        }
        match stream.try_read(&mut scratch) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            _ => return,
        }
    }
}

/// The daemon's bound pipe name.
pub(crate) struct Listener(PipeListener);

impl Listener {
    /// The next connection whose process runs as this user. Another user's
    /// connection never gets this far ([`PipeListener::accept`] drops it
    /// before a byte is read), so the verdict is always `Ok(true)`.
    pub(crate) async fn accept(&mut self) -> io::Result<(LocalStream, io::Result<bool>)> {
        Ok((self.0.accept().await?, Ok(true)))
    }
}

/// Bind this daemon's pipe `\\.\pipe\qsh-<scope>-<pid>`. The runtime
/// directory only feeds the name, so it is not created. The name already
/// existing, whoever holds it, is an error.
pub(crate) fn bind(paths: &Paths, pid: u32) -> Result<(Listener, PathBuf), OpError> {
    let listener = PipeListener::bind(&paths.runtime_dir(), pid).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!(
                "localctl: cannot bind the named pipe for pid {pid} under {}: {err}",
                paths.runtime_dir().display()
            ),
        )
    })?;
    let name = listener.name().to_path_buf();
    Ok((Listener(listener), name))
}

/// A pipe vanishes with its process, so a stopped daemon leaves nothing to
/// remove.
pub(crate) fn remove_endpoint(_endpoint: &Path) {}

#[cfg(test)]
mod tests;
