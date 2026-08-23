//! CLI-process side of localctl: connect to a resident `qsh listen`
//! daemon's UDS socket, speak the `LOCAL_ADMIN` conduit, and (for a later
//! step's host-specific routing) discover *which* daemon on this machine
//! knows a given host by trying each of this machine's sockets in turn
//! (`docs/design/protocol.md` §11-3, `docs/design/architecture.md` §7
//! "런타임 소켓 discovery", `PLAN.md` M3 Step 5).
//!
//! Deliberately transport-free (`crate::localctl` module docs): this file
//! must never name `qsh_transport`, `quinn` or `rustls` —
//! `xtask/src/arch.rs`'s `ModuleBan` enforces exactly that trio for this
//! file mechanically. It also never names `crate::client`/
//! `crate::Principal`/`crate::Fingerprint`, but that is true by
//! construction (this file never touches a live connection or a
//! principal), not a fourth-through-sixth token arch-lint separately
//! checks here — see `crate::localctl` module docs for which files get the
//! full six-token set and why. Holding any of the six is the daemon side's
//! business (`daemon.rs`, a later step), which bridges a `LOCAL_CONTROL`
//! conduit onto a live reverse QUIC connection.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use qsh_proto::ErrorCode;
use qsh_proto::frame::{DATA_FRAME_MAX, FrameDecoder};
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LocalError, LocalHello, LocalHost, LocalHostList, LocalHostListResult,
    LocalResponse, LocalStreamKind, local_response,
};
use qsh_proto::wire::{self, ControlMessage};
use tokio::net::UnixStream;
use tokio::task::JoinSet;

use crate::localctl::frame::LocalConduit;
use crate::ops::OpError;

/// Open a `LOCAL_ADMIN` conduit to the daemon listening on `socket_path`
/// and return its current reverse-host registrations
/// (`docs/design/protocol.md` §11-3's `LocalHostList`/`LocalHostListResult`
/// round trip).
///
/// This talks to exactly the one socket named — it does not retry and does
/// not consult [`discover`]. "Try every socket on this machine and merge
/// the results" is `Ops::host_list`'s job (PR 5b), built on top of this and
/// [`candidate_sockets`].
pub async fn admin_host_list(socket_path: &Path) -> Result<Vec<LocalHost>, OpError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| io_error("connect", socket_path, &err))?;
    admin_host_list_over(stream).await
}

/// Same exchange as [`admin_host_list`], over an already-connected
/// conduit. Split out so tests — and, later, [`discover`] probes for
/// PR 5b/Step 6's host-specific routing — can drive the `LOCAL_ADMIN`
/// exchange without going through a real `connect(2)` first.
pub async fn admin_host_list_over(stream: UnixStream) -> Result<Vec<LocalHost>, OpError> {
    match tokio::time::timeout(PROBE_TIMEOUT, admin_host_list_over_inner(stream)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(OpError::new(
            ErrorCode::ConnectionFailed,
            format!(
                "localctl: daemon accepted the conduit but never answered LocalHostList within \
                 {PROBE_TIMEOUT:?}"
            ),
        )),
    }
}

async fn admin_host_list_over_inner(stream: UnixStream) -> Result<Vec<LocalHost>, OpError> {
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalAdmin as i32,
            host: String::new(), // ignored for LOCAL_ADMIN (qsh/local/v1.proto)
            wait_ms: 0,          // a local admin query never needs to wait
            known_generation: None, // no host, so no generation to gate on
        })
        .await?;
    conduit.send(&LocalHostList {}).await?;

    let response: LocalResponse = conduit.recv().await?.ok_or_else(|| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            "localctl: daemon closed the conduit without answering LocalHostList",
        )
    })?;
    match response.body {
        Some(local_response::Body::HostListResult(LocalHostListResult { hosts })) => Ok(hosts),
        Some(local_response::Body::Error(err)) => Err(remote_error(err)),
        _ => Err(OpError::new(
            ErrorCode::ConnectionFailed,
            "localctl: daemon answered LocalHostList with an unexpected response",
        )),
    }
}

/// Open a `LOCAL_CONTROL` conduit to the daemon listening on `socket_path`
/// for `host`, and consume its `LocalHelloAck` — the CLI-process-side half
/// of `docs/design/protocol.md` §11-3's relay: after this returns, the
/// [`ControlConduit`] it hands back carries the exact same
/// `qsh.wire.v1::ControlMessage`/`Response` pair a QUIC control stream to
/// `host` would (`crate::client::link::ControlLink::Local` is the seam
/// that plugs this into a `client::Session`, `PLAN.md` M3 Step 6).
///
/// `wait_ms` is passed straight through to `LocalHello` (clamped by the
/// daemon to `LOCAL_WAIT_MAX`, `qsh/local/v1.proto`); Step 6's own callers
/// pass `0` (`Ops::resolve_host_route`/`resolve_host_route_async` already
/// resolved a *live* registration before this is ever called — there is
/// nothing to wait for yet). `known_generation` is `LocalHello.known_generation`
/// verbatim (`qsh/local/v1.proto`'s own doc on that field) — `None` for
/// every such caller (no baseline: anything live satisfies them), `Some(g)`
/// for `LocalReconnect` (`crate::ops::session`, M3 Step 8), which is by
/// definition retrying after generation `g`'s connection just died and must
/// never be handed that same generation back.
pub(crate) async fn open_control(
    socket_path: &Path,
    host: &str,
    wait_ms: u32,
    known_generation: Option<u64>,
) -> Result<ControlHandshake, OpError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| io_error("connect", socket_path, &err))?;
    open_control_over(stream, host, wait_ms, known_generation).await
}

/// Same exchange as [`open_control`], over an already-connected conduit —
/// split out for the same reason [`admin_host_list_over`] is: tests drive
/// the handshake without a real `connect(2)`.
pub(crate) async fn open_control_over(
    stream: UnixStream,
    host: &str,
    wait_ms: u32,
    known_generation: Option<u64>,
) -> Result<ControlHandshake, OpError> {
    match tokio::time::timeout(
        PROBE_TIMEOUT,
        open_control_over_inner(stream, host, wait_ms, known_generation),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(OpError::new(
            ErrorCode::ConnectionFailed,
            format!(
                "localctl: daemon accepted the LOCAL_CONTROL conduit but never answered within \
                 {PROBE_TIMEOUT:?}"
            ),
        )),
    }
}

async fn open_control_over_inner(
    stream: UnixStream,
    host: &str,
    wait_ms: u32,
    known_generation: Option<u64>,
) -> Result<ControlHandshake, OpError> {
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalControl as i32,
            host: host.to_string(),
            wait_ms,
            known_generation,
        })
        .await?;

    let response: LocalResponse = conduit.recv().await?.ok_or_else(|| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            "localctl: daemon closed the conduit without answering the LOCAL_CONTROL LocalHello",
        )
    })?;
    match response.body {
        Some(local_response::Body::HelloAck(ack)) => Ok(ControlHandshake {
            conduit: ControlConduit { conduit },
            host: ack.host,
            peer_fingerprint: ack.peer_fingerprint,
            generation: ack.generation,
            capabilities: ack.capabilities,
        }),
        Some(local_response::Body::Error(err)) => Err(remote_error(err)),
        _ => Err(OpError::new(
            ErrorCode::ConnectionFailed,
            "localctl: daemon answered the LOCAL_CONTROL LocalHello with an unexpected response",
        )),
    }
}

/// What a successful [`open_control`]/[`open_control_over`] handshake
/// produced: the live [`ControlConduit`] plus the registration facts its
/// `LocalHelloAck` carried (`qsh/local/v1.proto`'s `LocalHelloAck` doc
/// comment) — `peer_fingerprint` in particular is the ADR-0007
/// presentation-condition input on the reverse leg
/// (`crate::ops::session::Connected::peer_fingerprint`), since the CLI
/// process is not itself a TLS endpoint on the underlying connection and
/// has no other way to learn it.
pub(crate) struct ControlHandshake {
    pub conduit: ControlConduit,
    pub host: String,
    pub peer_fingerprint: String,
    /// Registration generation at the moment of this ack — Step 8's
    /// `LocalReconnect` input (`crate::ops::session::dial_reverse_wait`),
    /// detecting a re-registration across a dropped reverse connection.
    pub generation: u64,
    pub capabilities: Vec<String>,
}

/// A live `LOCAL_CONTROL` conduit, past its `LocalHelloAck` — carries
/// `qsh.wire.v1::ControlMessage` frames verbatim in both directions
/// (`qsh/local/v1.proto`'s file-level doc: "이 connection 은 그 정확히 같은
/// qsh.wire.v1 ControlMessage/Response pair 를 나른다"). Deliberately a
/// thin wrapper — everything about *when* to send what and how to
/// correlate a reply belongs to `crate::client::Session`
/// (`crate::client::link::ControlLink::Local` holds one of these), not
/// here; this file stays "connect and hand back a channel," matching
/// [`admin_host_list_over`]'s own shape.
pub(crate) struct ControlConduit {
    conduit: LocalConduit<UnixStream>,
}

impl ControlConduit {
    /// Send one `ControlMessage` verbatim.
    pub(crate) async fn send(&mut self, msg: &ControlMessage) -> Result<(), OpError> {
        self.conduit.send(msg).await
    }

    /// Read the next `ControlMessage`. `Ok(None)` on a clean end of the
    /// conduit (the daemon closed it — a dead conduit, or `serve_control`
    /// ending it because `host`'s reverse connection died,
    /// `docs/design/protocol.md` §11-3).
    pub(crate) async fn recv(&mut self) -> Result<Option<ControlMessage>, OpError> {
        self.conduit.recv().await
    }
}

/// Open a `LOCAL_STREAM` conduit to the daemon listening on `socket_path`
/// for `host`, send `header` as the conduit's one framed message, then hand
/// back a raw byte-level split — the CLI-process-side half of
/// `crate::localctl::daemon::LocalctlDaemon::serve_stream`'s splice
/// (`docs/design/protocol.md` §11-3, `PLAN.md` M3 Step 7).
///
/// `header` is sent **by this function**, not the caller: exactly like
/// [`open_control`] consuming its own `LocalHelloAck`, the shape of the
/// very next frame on a fresh `LOCAL_STREAM` conduit is dictated entirely
/// by the daemon-side protocol (`serve_stream`'s own doc — "the next frame
/// from the CLI is the wire `StreamHeader`"), so there is nothing a caller
/// could usefully vary about *how* it is sent, only *what* it says. The
/// daemon answers a well-formed `SESSION_DATA` header with silence (it
/// moves straight to the raw splice, `serve_stream`'s own doc), so this
/// function does not wait for anything after sending it — matching
/// `client::Session::open_attach_stream`'s forward-route sibling, which
/// likewise never waits for a target-side ack of the header it writes.
pub(crate) async fn open_stream(
    socket_path: &Path,
    host: &str,
    header: &wire::StreamHeader,
) -> Result<DataHandshake, OpError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| io_error("connect", socket_path, &err))?;
    open_stream_over(stream, host, header).await
}

/// Same exchange as [`open_stream`], over an already-connected conduit —
/// split out for the same reason [`open_control_over`] is: tests drive the
/// handshake without a real `connect(2)`.
pub(crate) async fn open_stream_over(
    stream: UnixStream,
    host: &str,
    header: &wire::StreamHeader,
) -> Result<DataHandshake, OpError> {
    match tokio::time::timeout(PROBE_TIMEOUT, open_stream_over_inner(stream, host, header)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(OpError::new(
            ErrorCode::ConnectionFailed,
            format!(
                "localctl: daemon accepted the LOCAL_STREAM conduit but never answered within \
                 {PROBE_TIMEOUT:?}"
            ),
        )),
    }
}

async fn open_stream_over_inner(
    stream: UnixStream,
    host: &str,
    header: &wire::StreamHeader,
) -> Result<DataHandshake, OpError> {
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalStream as i32,
            host: host.to_string(),
            wait_ms: 0,
            // The data conduit never waits on its own — by the time
            // `LocalReconnect` opens this, its `LOCAL_CONTROL` conduit has
            // already landed on a live, newer-than-`known_generation`
            // registration (`open_control`'s own doc), so there is nothing
            // left to gate this second conduit on.
            known_generation: None,
        })
        .await?;
    let response: LocalResponse = conduit.recv().await?.ok_or_else(|| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            "localctl: daemon closed the conduit without answering the LOCAL_STREAM LocalHello",
        )
    })?;
    let ack = match response.body {
        Some(local_response::Body::HelloAck(ack)) => ack,
        Some(local_response::Body::Error(err)) => return Err(remote_error(err)),
        _ => {
            return Err(OpError::new(
                ErrorCode::ConnectionFailed,
                "localctl: daemon answered the LOCAL_STREAM LocalHello with an unexpected \
                 response",
            ));
        }
    };
    conduit.send(header).await?;
    // From here on this conduit never speaks framed `qsh.local.v1` again —
    // `into_raw` hands back the still-open stream plus whatever bytes of
    // the peer's first `SessionFrame` the last `read()` already swallowed
    // alongside the header (`LocalConduit::into_raw`'s own doc; the daemon
    // sends nothing back on success, so any such bytes can only be the
    // CLI's *own* next write racing this same read, not a reply).
    let (stream, prefetched) = conduit.into_raw();
    // One `Arc` shared by both halves plus [`DataHandshake::socket`] (a
    // third clone a caller can keep for a synchronous, any-thread
    // hard-stop — `crate::client::link::DataKillSwitch`'s own doc explains
    // why that needs its own held reference rather than a bare fd):
    // `shutdown(2)` on any one of the three ends the whole socket, and the
    // fd stays allocated for as long as *any* clone is alive, so a
    // hard-stop can never race a `Drop` elsewhere into hitting a reused
    // descriptor.
    let socket = Arc::new(stream);
    let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
    dec.push(&prefetched);
    Ok(DataHandshake {
        send: DataSendHalf {
            socket: socket.clone(),
        },
        recv: DataRecvHalf {
            socket: socket.clone(),
            dec,
            buf: vec![0u8; 16 * 1024],
        },
        socket,
        peer_fingerprint: ack.peer_fingerprint,
        generation: ack.generation,
    })
}

/// What a successful [`open_stream`]/[`open_stream_over`] handshake
/// produced.
pub(crate) struct DataHandshake {
    pub send: DataSendHalf,
    pub recv: DataRecvHalf,
    /// A third, independent clone of the same socket [`send`](Self::send)
    /// and [`recv`](Self::recv) share — for
    /// `crate::client::link::DataKillSwitch`, built one layer up
    /// (`crate::client::mod`'s `Session::open_local_data_link`) so this
    /// transport-free file never has to name that cross-platform type
    /// (`crate::localctl` module docs' dependency direction: this module
    /// is depended on, never the reverse).
    pub socket: Arc<UnixStream>,
    /// This `LOCAL_STREAM` conduit's own `LocalHelloAck.peer_fingerprint`
    /// — compared by [`crate::client::mod`]'s `open_local_data_link`
    /// against the fingerprint the session's own `LOCAL_CONTROL` leg
    /// recorded, so a registration that died and came back between the
    /// two handshakes (or was superseded by a new one) is caught here as
    /// a stale route, fail-closed, rather than reaching `redeem_ticket` on
    /// a target whose per-connection ticket table never saw this ticket
    /// (adversarial review finding: "fail closed on any ambiguous auth/ACL
    /// state", `CLAUDE.md`).
    pub peer_fingerprint: String,
    /// This conduit's own `LocalHelloAck.generation` — same comparison as
    /// [`Self::peer_fingerprint`], for the case where the peer reconnected
    /// with the *same* fingerprint but a new registration generation.
    pub generation: u64,
}

/// Client → daemon half of a `LOCAL_STREAM` conduit, once its header has
/// been sent — raw `qsh.wire.v1` frames (in practice, `SessionFrame`s)
/// written straight to the socket, capped at [`DATA_FRAME_MAX`]: the same
/// cap `qsh_transport::control::FramedSend::data` enforces on the far side
/// of the daemon's splice, so a frame this process is willing to send is
/// exactly a frame the target's own decoder is willing to accept
/// (`docs/design/protocol.md` §7, §11-3).
///
/// Reads and writes through `&self` — [`UnixStream::writable`]/
/// [`UnixStream::try_write`] rather than an owned, exclusive
/// `AsyncWrite` — precisely so this half, [`DataRecvHalf`] and
/// `DataKillSwitch` can all hold independent clones of the *same* `Arc`
/// and run concurrently without a mutable-borrow conflict between them
/// (see [`open_stream_over_inner`]'s own doc on why that matters).
pub(crate) struct DataSendHalf {
    socket: Arc<UnixStream>,
}

impl DataSendHalf {
    /// Encode + frame + write one message.
    pub(crate) async fn send<M: Message>(&mut self, msg: &M) -> Result<(), OpError> {
        let wire =
            wire::encode_framed(msg, DATA_FRAME_MAX).map_err(|err| conduit_error("encode", err))?;
        write_all(&self.socket, &wire)
            .await
            .map_err(|err| conduit_error("write", err))
    }

    /// Half-close: shut the write direction of the underlying socket down.
    /// Synchronous, no runtime needed — the same nature
    /// [`qsh_transport::control::FramedSend::finish`] has (queues the FIN,
    /// does not wait for it): the daemon's own read on its end of this
    /// same UDS pair sees a clean EOF and relays it onward as a QUIC
    /// `finish` on the target's data stream (`crate::localctl::daemon`'s
    /// `pump_uds_to_quic`, "UDS EOF -> QUIC finish").
    pub(crate) fn finish(&self) {
        unsafe {
            libc::shutdown(as_raw_fd(&self.socket), libc::SHUT_WR);
        }
    }
}

/// Daemon → client half of a `LOCAL_STREAM` conduit, once its header has
/// been sent. See [`DataSendHalf`]'s own doc for why this reads through
/// `&self` rather than an owned, exclusive half.
pub(crate) struct DataRecvHalf {
    socket: Arc<UnixStream>,
    dec: FrameDecoder,
    buf: Vec<u8>,
}

impl DataRecvHalf {
    /// Read the next message. `Ok(None)` on a clean end-of-conduit (the
    /// daemon closed its end at a frame boundary — a `QUIC FIN` relayed
    /// onward, `pump_quic_to_uds`'s "QUIC FIN/reset -> UDS shutdown" —
    /// with nothing pending); a truncated final frame is
    /// [`ErrorCode::ConnectionFailed`], the same framing-lost treatment
    /// [`LocalConduit::recv`] gives it.
    pub(crate) async fn recv<M: Message + Default>(&mut self) -> Result<Option<M>, OpError> {
        loop {
            if let Some(payload) = self
                .dec
                .next_frame()
                .map_err(|err| conduit_error("frame", err))?
            {
                let msg =
                    M::decode(payload.as_slice()).map_err(|err| conduit_error("decode", err))?;
                return Ok(Some(msg));
            }
            let n = read_some(&self.socket, &mut self.buf)
                .await
                .map_err(|err| conduit_error("read", err))?;
            if n == 0 {
                let buffered = self.dec.buffered();
                return if buffered == 0 {
                    Ok(None)
                } else {
                    Err(conduit_error(
                        "read",
                        format!("conduit ended mid-frame ({buffered} bytes buffered)"),
                    ))
                };
            }
            // Without this the bytes just read sit in `self.buf` and are
            // never seen by `self.dec` — `next_frame()` above would find
            // nothing, forever, on every subsequent loop no matter how
            // much data actually arrives.
            self.dec.push(&self.buf[..n]);
        }
    }
}

/// Write all of `buf` to `socket`'s send direction, via the readiness-based
/// `writable`/`try_write` pair rather than [`tokio::io::AsyncWriteExt`] —
/// the latter needs a `&mut UnixStream`, which an `Arc`-shared socket
/// cannot hand out to more than one owner at a time.
async fn write_all(socket: &UnixStream, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        socket.writable().await?;
        match socket.try_write(buf) {
            Ok(n) => buf = &buf[n..],
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Read at least one byte (or report a clean EOF as `Ok(0)`) from
/// `socket`'s receive direction. See [`write_all`]'s own doc for why this
/// is readiness-based rather than [`tokio::io::AsyncReadExt`].
async fn read_some(socket: &UnixStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        socket.readable().await?;
        match socket.try_read(buf) {
            Ok(n) => return Ok(n),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }
}

/// The raw fd a `shutdown(2)` targets — `AsRawFd` needs `std::os::fd`,
/// unix-only, which this whole module already is (`crate::localctl`'s own
/// `#[cfg(unix)]` gate in `lib.rs`), so no further cfg is needed here.
fn as_raw_fd(socket: &UnixStream) -> std::os::fd::RawFd {
    use std::os::fd::AsRawFd as _;
    socket.as_raw_fd()
}

/// Wrap a `LOCAL_STREAM` data-conduit I/O failure as
/// [`ErrorCode::ConnectionFailed`] — the same code
/// [`crate::localctl::frame`]'s own `conduit_error` uses for the identical
/// reason (a broken local IPC conduit to this machine's own daemon plays
/// the same role an unreachable controller plays on the forward route).
fn conduit_error(step: &str, err: impl std::fmt::Display) -> OpError {
    OpError::new(
        ErrorCode::ConnectionFailed,
        format!("localctl data conduit {step} failed: {err}"),
    )
}

/// Convert a `LocalError` the daemon sent us into an [`OpError`], preserving
/// its code and message verbatim — `code` is already drawn from the shared
/// `docs/CLI.md` §3.3 vocabulary (`qsh.local/v1.proto`'s `LocalError` doc
/// comment), so there is nothing to translate.
fn remote_error(err: LocalError) -> OpError {
    OpError::new(err.error_code(), err.message)
}

fn io_error(step: &str, path: &Path, err: &io::Error) -> OpError {
    OpError::new(
        ErrorCode::ConnectionFailed,
        format!("localctl: {step} {}: {err}", path.display()),
    )
}

/// This machine's localctl sockets, named `<pid>.sock`
/// (`docs/design/architecture.md` §7), in pid-ascending order. A missing
/// runtime directory (no daemon has ever bound a socket here) yields an
/// empty list, not an error — that is the normal "no `qsh listen` running"
/// state. Entries that are not `<digits>.sock` are silently skipped: the
/// runtime directory is not exclusively ours to police.
pub fn candidate_sockets(runtime_dir: &Path) -> io::Result<Vec<(u32, PathBuf)>> {
    let entries = match std::fs::read_dir(runtime_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if let Some(pid) = socket_pid(&path) {
            out.push((pid, path));
        }
    }
    out.sort_by_key(|(pid, _)| *pid);
    Ok(out)
}

fn socket_pid(path: &Path) -> Option<u32> {
    if path.extension().and_then(|ext| ext.to_str()) != Some("sock") {
        return None;
    }
    path.file_stem()?.to_str()?.parse().ok()
}

/// What one candidate daemon said in answer to a [`discover`] probe.
pub enum DiscoverOutcome<T> {
    /// This daemon answered with what the caller was looking for — stop
    /// searching and return this value.
    Found(T),
    /// This daemon doesn't have it (e.g. its own `HOST_NOT_FOUND` answer)
    /// — move on to the next socket.
    NotFound,
}

/// Try this machine's localctl sockets in pid-ascending order until one
/// answers [`DiscoverOutcome::Found`] — the discovery mechanism
/// `docs/design/protocol.md` §11-3 and `docs/design/architecture.md` §7
/// describe, built generic over *what* is being asked for so it is ready
/// for PR 5b/Step 6's host-specific routing (the concrete probe that opens
/// a `LOCAL_CONTROL` conduit for one host name and reads back
/// `LocalHelloAck` vs a `HOST_NOT_FOUND` `LocalError`) without this loop
/// changing shape when that lands. `probe` receives one already-connected
/// stream per candidate and decides continue-or-stop; this function owns
/// everything about *which* socket to try and in what order.
///
/// - A candidate whose connection is refused (`ECONNREFUSED` — the daemon
///   that bound it has already exited) is unlinked and skipped, exactly
///   like a crashed daemon's stale pid file.
/// - Any other failure to connect, or any error `probe` itself returns,
///   also moves on to the next candidate rather than aborting the whole
///   search — one unreachable or misbehaving daemon must not hide the
///   others (`docs/CLI.md` §6.2's "부분 실패를 감추지 않는다" discipline
///   applied to discovery: a bad daemon doesn't get to hide the good
///   ones).
/// - Every candidate exhausted (or none exist) ⇒ [`ErrorCode::HostNotFound`]
///   (`docs/design/architecture.md` §7: "전부 실패하면 `HOST_NOT_FOUND`다").
pub async fn discover<T>(
    runtime_dir: &Path,
    mut probe: impl AsyncFnMut(UnixStream) -> Result<DiscoverOutcome<T>, OpError>,
) -> Result<T, OpError> {
    let candidates =
        candidate_sockets(runtime_dir).map_err(|err| io_error("list", runtime_dir, &err))?;
    for (pid, sock) in candidates {
        let Some(stream) = connect_candidate(pid, &sock).await else {
            continue;
        };
        match tokio::time::timeout(PROBE_TIMEOUT, probe(stream)).await {
            Ok(Ok(DiscoverOutcome::Found(value))) => return Ok(value),
            Ok(Ok(DiscoverOutcome::NotFound)) => {
                tracing::debug!(pid, "localctl discover: candidate said not-found");
            }
            Ok(Err(err)) => {
                tracing::debug!(pid, %err, "localctl discover: candidate probe failed");
            }
            Err(_elapsed) => {
                // A daemon that accepted but never answered would
                // otherwise wedge every remaining candidate behind it
                // forever — one misbehaving daemon must not hide the
                // others (this function's own doc, and `docs/CLI.md`
                // §6.2). Its socket is left alone: an
                // unresponsive-but-connectable daemon is not provably
                // dead, so nothing here unlinks it.
                tracing::warn!(
                    pid,
                    "localctl discover: candidate accepted but never answered within {:?}; skipping",
                    PROBE_TIMEOUT
                );
            }
        }
    }
    Err(OpError::new(
        ErrorCode::HostNotFound,
        "no daemon on this machine has that host registered",
    ))
}

/// One candidate daemon's answer when [`admin_host_list_all`] asks *every*
/// socket on this machine for its current reverse registrations.
///
/// Unlike [`discover`] (stop at the first match — a routing probe only
/// ever needs one answer), `Ops::host_list`'s reverse source needs the
/// union across every live daemon, so this tries all of them and reports
/// what each one said (`PLAN.md` M3 Step 5 (a): "reverse — 이 머신의
/// localctl 데몬들에 등록된 엔트리의 합집합").
#[derive(Debug, PartialEq, Eq)]
pub struct DaemonHostList {
    /// The daemon's pid — from its own `<pid>.sock` filename
    /// (`docs/design/architecture.md` §7).
    pub pid: u32,
    /// The daemon's localctl socket path, kept for a routing caller that
    /// needs to speak to this exact daemon again (Step 6).
    pub socket: PathBuf,
    /// Hosts this daemon currently has registered, live or stale — never
    /// filtered here (`docs/CLI.md` §6.2's "부분 실패를 감추지 않는다"
    /// discipline applies to the merge, not this probe).
    pub hosts: Vec<LocalHost>,
}

/// Ask every localctl socket on this machine for its `LocalHostList`,
/// skipping any that is unreachable, refused, or silent — a dead or
/// misbehaving daemon is dropped from the result, never turned into an
/// error (`docs/CLI.md` §6.1: "`host.list`는 dial하지 않는다... 잠든
/// 노트북 한 대가 목록을 느리게 만들지 않는다"). No candidates at all (or
/// an unreadable runtime directory) is an empty list, the normal "no `qsh
/// listen` running" state — never an error a caller has to special-case.
///
/// Every candidate is probed **concurrently**, each under
/// [`ADMIN_LIST_CANDIDATE_TIMEOUT`], so the total wall-clock cost of a
/// listing is bounded by that one deadline regardless of how many sockets
/// exist — a serial loop would let a wedged daemon early in pid-ascending
/// order add its own timeout on top of every candidate behind it
/// (adversarial review finding: measured 60.015 s for one wedged socket,
/// serially, before this existed; N wedged sockets would have been N×60 s).
/// Results are re-sorted by pid afterward so the returned order matches the
/// pid-ascending order candidates were discovered in, independent of which
/// connect happened to finish first.
///
/// Reuses [`connect_candidate`]'s stale-socket-unlink discipline (the same
/// one [`discover`] applies), so a crashed daemon's leftover socket gets
/// cleaned up here too, not only on the routing path.
pub async fn admin_host_list_all(runtime_dir: &Path) -> Vec<DaemonHostList> {
    let candidates = match candidate_sockets(runtime_dir) {
        Ok(candidates) => candidates,
        Err(err) => {
            // `warn!` (not `debug!`, the CLI's default level): a caller
            // must be able to see *why* the reverse source came back empty
            // without raising verbosity, mirroring `session.list`'s
            // fan-out `unreachable` reporting discipline (`docs/CLI.md`
            // §6.2's "부분 실패를 감추지 않는다") — the runtime dir being
            // unreadable is a partial-result cause, not routine noise
            // (adversarial review finding: this was invisible at any
            // normal verbosity).
            tracing::warn!(
                %err,
                "localctl admin_host_list_all: could not list the runtime dir; \
                 treating as no daemons (host.list never fails closed on this)"
            );
            return Vec::new();
        }
    };

    let mut set = JoinSet::new();
    for (pid, socket) in candidates {
        set.spawn(async move {
            match tokio::time::timeout(
                ADMIN_LIST_CANDIDATE_TIMEOUT,
                admin_host_list_one(pid, socket),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(_elapsed) => {
                    // A daemon that accepted but never answered would
                    // otherwise hold up this whole listing until
                    // `PROBE_TIMEOUT` (60 s, a *routing*-probe budget) —
                    // `host.list` is a pure local read (`docs/CLI.md`
                    // §6.1) and must not stall anywhere near that long on
                    // one silent socket.
                    tracing::warn!(
                        pid,
                        "localctl admin_host_list_all: candidate did not answer within {:?}; \
                         skipping it (host.list never fails closed)",
                        ADMIN_LIST_CANDIDATE_TIMEOUT
                    );
                    None
                }
            }
        });
    }

    let mut out = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Some(daemon) = joined.expect("admin_host_list_all: a candidate probe task panicked")
        {
            out.push(daemon);
        }
    }
    out.sort_by_key(|daemon| daemon.pid);
    out
}

/// One candidate's connect-then-ask, for [`admin_host_list_all`]'s
/// per-candidate task. Split out so the timeout wrapped around it in the
/// caller has a single, clearly-bounded unit of work to apply to.
async fn admin_host_list_one(pid: u32, socket: PathBuf) -> Option<DaemonHostList> {
    let stream = connect_candidate(pid, &socket).await?;
    match admin_host_list_over(stream).await {
        Ok(hosts) => Some(DaemonHostList { pid, socket, hosts }),
        Err(err) => {
            // `warn!`, not `debug!` — same reasoning as the runtime-dir
            // branch above: a daemon answering with an error (e.g. a
            // rejected admin query) is a dropped partial result, and
            // dropping it silently at the CLI's default log level would
            // make a live-but-erroring daemon indistinguishable from one
            // that was never registered (adversarial review finding).
            tracing::warn!(
                pid,
                %err,
                "localctl admin_host_list_all: candidate answered with an error; \
                 skipping it (host.list never fails closed)"
            );
            None
        }
    }
}

/// Connect to one discovery candidate, applying the same bounded-wait and
/// stale-socket-unlink discipline both [`discover`] and
/// [`admin_host_list_all`] need: an `ECONNREFUSED` candidate is unlinked
/// only when its own pid is verifiably dead (never a live-but-busy
/// daemon — see the inline comment below), and a `connect(2)` that hangs
/// (defensive; UDS connects don't block on the network) or never completes
/// within [`PROBE_TIMEOUT`] is treated as unreachable rather than allowed
/// to wedge the caller. `None` means "skip this candidate".
async fn connect_candidate(pid: u32, sock: &Path) -> Option<UnixStream> {
    match tokio::time::timeout(PROBE_TIMEOUT, UnixStream::connect(sock)).await {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => {
            // ECONNREFUSED is *not* proof the daemon is dead: on
            // macOS/BSD a live listener whose accept backlog is full
            // reports it exactly this way, and even on Linux a
            // just-`bind`-not-yet-`listen`ing socket can produce it for
            // an instant. Only unlink when the pid the socket's own
            // filename names (`<pid>.sock`, `docs/design/architecture.md`
            // §7) is actually gone — `kill(pid, 0)` returning `ESRCH` is
            // the one thing that proves that (adversarial review finding:
            // unconditional unlink here could delete a live, merely-busy
            // daemon's socket, permanently orphaning it from `qsh hosts`
            // and Step 6 routing until a manual restart).
            if process_is_verifiably_dead(pid) {
                let _ = std::fs::remove_file(sock);
            } else {
                tracing::debug!(
                    pid,
                    "localctl: connection refused but pid {pid} is still alive; leaving its \
                     socket in place"
                );
            }
            None
        }
        Ok(Err(err)) => {
            tracing::debug!(pid, %err, "localctl: could not connect to candidate");
            None
        }
        Err(_elapsed) => {
            // `connect(2)` on a UDS does not block on the network, so this
            // branch is defensive rather than expected — but a stuck
            // connect must not be able to wedge a caller any more than a
            // stuck probe can.
            tracing::warn!(pid, "localctl: connect to candidate timed out");
            None
        }
    }
}

/// Bound on how long [`discover`] waits for any single candidate's
/// `connect`/probe round trip before moving on — the ceiling
/// `qsh_proto::local::LOCAL_WAIT_MAX` already defines for "a caller must
/// not be able to pin a daemon slot open indefinitely" (`qsh/local/v1.proto`),
/// reused here for the symmetric client-side guarantee: no single candidate
/// may pin *discovery itself* open indefinitely.
const PROBE_TIMEOUT: Duration = qsh_proto::local::LOCAL_WAIT_MAX;

/// Per-candidate deadline for [`admin_host_list_all`]'s connect-then-ask
/// round trip — deliberately **not** [`PROBE_TIMEOUT`]. `PROBE_TIMEOUT` is
/// `qsh_proto::local::LOCAL_WAIT_MAX`, the ceiling for a caller who is
/// *deliberately* willing to wait for a reverse registration to appear
/// (`LocalHello.wait_ms`'s clamp); reusing it here was a category error
/// (adversarial review finding) — the `LOCAL_ADMIN` exchange this path
/// drives sends `wait_ms: 0` ("a local admin query never needs to wait",
/// `admin_host_list_over_inner`), and `admin_host_list_all` backs
/// `host.list`/`host.get`, a "pure local read" that `docs/CLI.md` §6.1
/// promises never dials and never stalls on a sleeping peer. A same-machine
/// UDS round trip normally completes in well under a millisecond; this
/// bound only exists to cap a silent or wedged daemon's cost, so it can
/// afford to be generous against CI scheduling jitter while staying nowhere
/// near long enough to read as "hung" (measured regression before this
/// existed: 60.015 s per wedged socket, serially).
const ADMIN_LIST_CANDIDATE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Whether the process named by `pid` — the pid `<pid>.sock`'s own
/// filename already carries — is provably gone, via `kill(pid, 0)`
/// (`man 2 kill`: signal `0` performs no signal delivery, only the
/// existence/permission check). Only `ESRCH` ("no such process") counts as
/// proof of death; a permission error (`EPERM`, a different uid holding
/// that pid — impossible for a genuine same-user daemon, but not this
/// function's job to assume) or success (the process exists) both leave
/// the socket alone, because unlinking a live daemon's socket is
/// unrecoverable for that process's lifetime while leaving a truly stale
/// one costs nothing but a retry on the next discovery pass.
fn process_is_verifiably_dead(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        // A pid that doesn't fit `pid_t` can't name a live process on this
        // machine either way; treat it as dead so a garbage filename
        // doesn't linger forever.
        return true;
    };
    // SAFETY: `kill` with signal `0` sends no signal; it only performs the
    // existence/permission check documented above, and touches no memory
    // this function does not own.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return false; // the signal would have been delivered: pid exists.
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use qsh_proto::local::LocalHelloAck;
    use tokio::net::UnixListener;

    use super::*;

    fn sample_host(name: &str) -> LocalHost {
        LocalHost {
            name: name.to_string(),
            address: "203.0.113.5:51820".to_string(),
            state: "reachable".to_string(),
            fingerprint: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            capabilities: vec!["pty".to_string()],
            generation: 1,
            registered_at: "2026-08-22T00:00:00Z".to_string(),
        }
    }

    /// Spawn a one-shot fake daemon on `path`: reads a `LocalHello` +
    /// `LocalHostList` request off `LOCAL_ADMIN`, and answers with
    /// whatever `LocalResponse` body the caller supplies. No real `qsh
    /// listen` process anywhere in these tests — this is `docs/design/
    /// testing.md` L2 "no real daemon needed" for the discovery/framing
    /// contract, not an L3 harness.
    fn spawn_fake_admin_daemon(
        listener: UnixListener,
        body: local_response::Body,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = LocalConduit::new(stream);
            let hello: LocalHello = conduit.recv().await.unwrap().unwrap();
            assert_eq!(hello.kind, LocalStreamKind::LocalAdmin as i32);
            let _req: LocalHostList = conduit.recv().await.unwrap().unwrap();
            conduit
                .send(&LocalResponse { body: Some(body) })
                .await
                .unwrap();
        })
    }

    #[tokio::test]
    async fn admin_host_list_round_trips_through_a_fake_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("100.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let expected = vec![sample_host("personal-mac")];
        let daemon = spawn_fake_admin_daemon(
            listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        let hosts = admin_host_list(&sock).await.unwrap();
        assert_eq!(hosts, expected);
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn admin_host_list_surfaces_a_remote_error_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("101.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = spawn_fake_admin_daemon(
            listener,
            local_response::Body::Error(LocalError::from_code(
                ErrorCode::HostNotFound,
                "no such registration",
            )),
        );

        let err = admin_host_list(&sock).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert_eq!(err.message, "no such registration");
        daemon.await.unwrap();
    }

    // ---- `open_control` / `ControlConduit` (M3 Step 6) ----

    /// Spawn a one-shot fake daemon: reads one `LOCAL_CONTROL` `LocalHello`
    /// off `listener`, asserts it against `expect_host`, and answers with
    /// whatever `LocalResponse` body the caller supplies — the
    /// `LOCAL_CONTROL` sibling of [`spawn_fake_admin_daemon`].
    fn spawn_fake_control_daemon(
        listener: UnixListener,
        expect_host: &'static str,
        body: local_response::Body,
    ) -> tokio::task::JoinHandle<LocalConduit<UnixStream>> {
        tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = LocalConduit::new(stream);
            let hello: LocalHello = conduit.recv().await.unwrap().unwrap();
            assert_eq!(hello.kind, LocalStreamKind::LocalControl as i32);
            assert_eq!(hello.host, expect_host);
            conduit
                .send(&LocalResponse { body: Some(body) })
                .await
                .unwrap();
            conduit
        })
    }

    #[tokio::test]
    async fn open_control_ack_happy_path_carries_the_ack_fields_and_the_conduit_relays_after() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("200.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = spawn_fake_control_daemon(
            listener,
            "personal-mac",
            local_response::Body::HelloAck(LocalHelloAck {
                host: "personal-mac".to_string(),
                peer_fingerprint: "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                generation: 3,
                capabilities: vec!["pty".to_string()],
            }),
        );

        let handshake = open_control(&sock, "personal-mac", 0, None).await.unwrap();
        assert_eq!(handshake.host, "personal-mac");
        assert_eq!(
            handshake.peer_fingerprint,
            "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        );
        assert_eq!(handshake.capabilities, vec!["pty".to_string()]);
        let mut daemon_conduit = daemon.await.unwrap();

        // Past the ack, the conduit carries `wire::ControlMessage` verbatim
        // in both directions (`qsh/local/v1.proto`'s file doc) — prove it
        // round-trips one, the way a real `session.get` request/response
        // pair would.
        let mut conduit = handshake.conduit;
        let ping = qsh_proto::wire::ControlMessage::new(
            7,
            qsh_proto::wire::control_message::Body::Ping(qsh_proto::wire::Ping {}),
        );
        conduit.send(&ping).await.unwrap();
        let received: qsh_proto::wire::ControlMessage =
            daemon_conduit.recv().await.unwrap().unwrap();
        assert_eq!(received, ping);
    }

    #[tokio::test]
    async fn open_control_maps_a_local_error_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("201.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = spawn_fake_control_daemon(
            listener,
            "phone",
            local_response::Body::Error(LocalError::from_code(
                ErrorCode::HostNotFound,
                "phone is not a currently reachable registered host",
            )),
        );

        let err = open_control(&sock, "phone", 0, None).await.err().unwrap();
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert_eq!(
            err.message,
            "phone is not a currently reachable registered host"
        );
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn open_control_maps_a_version_or_kind_rejection_the_same_way_as_any_local_error() {
        // The daemon rejects a `LocalHello` it cannot serve (bad version,
        // or a `kind` it does not support) with the same `LocalError`
        // envelope as any other refusal — `open_control` has no special
        // case for these, they are just another remote error to map
        // verbatim (`crate::localctl::client::remote_error`).
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("202.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = spawn_fake_control_daemon(
            listener,
            "phone",
            local_response::Body::Error(LocalError::from_code(
                ErrorCode::Unsupported,
                "unsupported LocalHello version",
            )),
        );

        let err = open_control(&sock, "phone", 0, None).await.err().unwrap();
        assert_eq!(err.code, ErrorCode::Unsupported);
        assert_eq!(err.message, "unsupported LocalHello version");
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn open_control_treats_an_unexpected_response_body_as_connection_failed() {
        // A `LOCAL_ADMIN`-shaped reply (`HostListResult`) on a
        // `LOCAL_CONTROL` conduit is not a `LocalError` — it's a
        // protocol-shape violation, not a "the daemon refused" answer, so
        // it maps to `ConnectionFailed` rather than being misread as
        // success.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("203.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = spawn_fake_control_daemon(
            listener,
            "phone",
            local_response::Body::HostListResult(LocalHostListResult { hosts: Vec::new() }),
        );

        let err = open_control(&sock, "phone", 0, None).await.err().unwrap();
        assert_eq!(err.code, ErrorCode::ConnectionFailed);
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn admin_host_list_over_a_socket_nothing_is_listening_on_fails_connection() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("102.sock");
        // Never bound at all — plain ENOENT, not ECONNREFUSED, but either
        // way `admin_host_list` (unlike `discover`) surfaces the failure
        // rather than silently treating it as "not found".
        let err = admin_host_list(&sock).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::ConnectionFailed);
    }

    #[test]
    fn candidate_sockets_are_sorted_ascending_by_pid_and_skip_non_matching_names() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "20.sock",
            "3.sock",
            "100.sock",
            "notasocket.txt",
            "abc.sock",
        ] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }

        let found = candidate_sockets(dir.path()).unwrap();
        let pids: Vec<u32> = found.iter().map(|(pid, _)| *pid).collect();
        assert_eq!(pids, vec![3, 20, 100]);
        assert_eq!(found[0].1, dir.path().join("3.sock"));
    }

    // ---- liveness check backing the `ECONNREFUSED` unlink decision ----

    #[test]
    fn process_is_verifiably_dead_distinguishes_a_live_pid_from_a_reaped_one() {
        assert!(
            !process_is_verifiably_dead(std::process::id()),
            "this test's own process must never be reported dead"
        );
        assert!(
            process_is_verifiably_dead(a_definitely_dead_pid()),
            "a spawned-and-reaped child's pid must be reported dead"
        );
    }

    // ---- bounded waits (`discover`/`admin_host_list_over` must never hang
    // forever on one misbehaving daemon) ----

    #[tokio::test(start_paused = true)]
    async fn admin_host_list_over_a_daemon_that_never_answers_times_out_instead_of_hanging() {
        let (client_end, _daemon_end) = UnixStream::pair().unwrap();
        // `_daemon_end` is held open (accepted the conduit) but never read
        // or written to — the "daemon wedged after accept" shape a
        // deadline must catch, since it is neither a connect failure nor a
        // clean close. `start_paused` auto-advances virtual time past the
        // timeout the instant nothing else is runnable, so this proves the
        // deadline fires without an real wall-clock wait.
        let err = admin_host_list_over(client_end).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::ConnectionFailed);
    }

    #[tokio::test(start_paused = true)]
    async fn discover_moves_past_a_silent_daemon_instead_of_hanging_on_it_forever() {
        let dir = tempfile::tempdir().unwrap();
        let silent = dir.path().join("7.sock");
        let healthy = dir.path().join("8.sock");

        let silent_listener = UnixListener::bind(&silent).unwrap();
        let silent_daemon = tokio::spawn(async move {
            let (_stream, _addr) = silent_listener.accept().await.unwrap();
            // Accept the conduit, then never read or write anything —
            // exactly the daemon-wedged-after-accept scenario `discover`'s
            // own doc promises "one misbehaving daemon must not hide the
            // others" against.
            std::future::pending::<()>().await
        });

        let healthy_listener = UnixListener::bind(&healthy).unwrap();
        let expected = vec![sample_host("found-on-healthy")];
        let healthy_daemon = spawn_fake_admin_daemon(
            healthy_listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        // pid-ascending order visits the silent "7.sock" before the
        // healthy "8.sock"; without a deadline this call never returns.
        let hosts = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap();
        assert_eq!(hosts, expected);

        silent_daemon.abort();
        healthy_daemon.await.unwrap();
    }

    // ---- `discover` must never unlink a live daemon's socket ----

    #[tokio::test]
    async fn discover_does_not_unlink_a_refused_socket_whose_pid_is_still_alive() {
        let dir = tempfile::tempdir().unwrap();
        // Named after *this test process's own pid* — by construction
        // alive for the whole test — to prove `discover` consults
        // liveness rather than treating every `ECONNREFUSED` as proof of
        // death (adversarial review finding: a live daemon whose accept
        // backlog is full, or that is caught between `bind` and `listen`,
        // answers `ECONNREFUSED` too).
        let live_pid = std::process::id();
        let refused = dir.path().join(format!("{live_pid}.sock"));
        {
            // Bind then immediately drop the listener: the socket file
            // stays on disk, but nothing is listening any more, so a
            // connect to it now fails `ECONNREFUSED` — the same wire
            // symptom a full accept backlog on a genuinely live daemon
            // would produce, deliberately reused here for a
            // process-inspection-only assertion (this test cannot
            // actually fill an OS accept backlog deterministically).
            let _listener = UnixListener::bind(&refused).unwrap();
        }
        assert!(refused.exists());

        let err = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert!(
            refused.exists(),
            "a socket named after a still-alive pid must never be unlinked on ECONNREFUSED alone"
        );
    }

    #[test]
    fn candidate_sockets_on_a_missing_runtime_dir_is_an_empty_list_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert_eq!(candidate_sockets(&missing).unwrap(), Vec::new());
    }

    /// Turn `admin_host_list_over`'s result into a [`DiscoverOutcome`] the
    /// way a real host-routing probe eventually will: a clean answer is
    /// `Found`, the daemon's own `HOST_NOT_FOUND` is `NotFound`, anything
    /// else propagates as an error `discover` will skip past.
    async fn probe_via_admin_host_list(
        stream: UnixStream,
    ) -> Result<DiscoverOutcome<Vec<LocalHost>>, OpError> {
        match admin_host_list_over(stream).await {
            Ok(hosts) => Ok(DiscoverOutcome::Found(hosts)),
            Err(err) if err.code == ErrorCode::HostNotFound => Ok(DiscoverOutcome::NotFound),
            Err(err) => Err(err),
        }
    }

    /// A pid this test can prove is dead right now (spawn a trivial child,
    /// wait for it to exit) — the one thing `discover`'s liveness check
    /// actually trusts before unlinking an `ECONNREFUSED` candidate. A
    /// hardcoded low pid like `1` (`init`/`launchd`, always alive) is not
    /// safe to use for a "stale" candidate any more now that `discover`
    /// verifies liveness rather than unlinking on `ECONNREFUSED` alone
    /// (adversarial review finding).
    fn a_definitely_dead_pid() -> u32 {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn a short-lived helper process");
        let status = child.wait().expect("wait for the helper process to exit");
        assert!(status.success(), "helper process must exit cleanly");
        child.id()
    }

    #[tokio::test]
    async fn discover_unlinks_a_refused_stale_socket_and_finds_the_next_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let dead_pid = a_definitely_dead_pid();
        let stale = dir.path().join(format!("{dead_pid}.sock"));
        // `dead_pid + 1` sorts immediately after it by construction, so
        // pid-ascending discovery is guaranteed to visit the stale
        // candidate first regardless of what `dead_pid` actually is.
        let live = dir.path().join(format!("{}.sock", dead_pid + 1));

        // A socket file with no listener behind it: bind, then drop the
        // listener immediately. The special file stays on disk; connecting
        // to it now fails ECONNREFUSED — exactly a crashed daemon's leftover.
        {
            let _listener = UnixListener::bind(&stale).unwrap();
        }
        assert!(stale.exists(), "the stale socket file must still exist");

        let listener = UnixListener::bind(&live).unwrap();
        let expected = vec![sample_host("phone")];
        let daemon = spawn_fake_admin_daemon(
            listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        let hosts = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap();
        assert_eq!(hosts, expected);
        assert!(
            !stale.exists(),
            "the refused stale socket must be unlinked during discovery"
        );
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn discover_tries_candidates_in_pid_ascending_order() {
        let dir = tempfile::tempdir().unwrap();
        let lower = dir.path().join("5.sock");
        let higher = dir.path().join("50.sock");

        let lower_hosts = vec![sample_host("lower-answered")];
        let higher_hosts = vec![sample_host("higher-answered")];

        let lower_listener = UnixListener::bind(&lower).unwrap();
        let higher_listener = UnixListener::bind(&higher).unwrap();
        let lower_daemon = spawn_fake_admin_daemon(
            lower_listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: lower_hosts.clone(),
            }),
        );
        let higher_daemon = spawn_fake_admin_daemon(
            higher_listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: higher_hosts,
            }),
        );

        // Both candidates would answer `Found` — if discovery visited
        // pid-descending (or arbitrary directory order) it could just as
        // easily return the higher-pid daemon's answer. Getting the
        // lower-pid one back is the only outcome consistent with
        // pid-ascending order and "stop at the first `Found`".
        let hosts = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap();
        assert_eq!(hosts, lower_hosts);

        lower_daemon.await.unwrap();
        // The higher-pid daemon is never dialed once the lower one answers
        // `Found` — nothing to await there but its accept() never completes,
        // which is exactly the point; drop it without joining.
        higher_daemon.abort();
    }

    #[tokio::test]
    async fn discover_moves_past_daemons_that_say_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("10.sock");
        let second = dir.path().join("11.sock");

        let first_listener = UnixListener::bind(&first).unwrap();
        let second_listener = UnixListener::bind(&second).unwrap();
        let first_daemon = spawn_fake_admin_daemon(
            first_listener,
            local_response::Body::Error(LocalError::from_code(
                ErrorCode::HostNotFound,
                "unknown host",
            )),
        );
        let expected = vec![sample_host("found-on-second")];
        let second_daemon = spawn_fake_admin_daemon(
            second_listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        let hosts = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap();
        assert_eq!(hosts, expected);
        first_daemon.await.unwrap();
        second_daemon.await.unwrap();
    }

    #[tokio::test]
    async fn discover_exhausted_is_host_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let only = dir.path().join("42.sock");
        let listener = UnixListener::bind(&only).unwrap();
        let daemon = spawn_fake_admin_daemon(
            listener,
            local_response::Body::Error(LocalError::from_code(
                ErrorCode::HostNotFound,
                "unknown host",
            )),
        );

        let err = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn discover_with_no_candidates_at_all_is_host_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
    }

    // ---- `admin_host_list_all` — union across every daemon, bounded ----
    // (adversarial review: this had zero direct coverage, and its own
    // timeout stalled 60 s per wedged socket, serially)

    #[tokio::test]
    async fn admin_host_list_all_unions_across_two_live_daemons() {
        let dir = tempfile::tempdir().unwrap();
        let low = dir.path().join("10.sock");
        let high = dir.path().join("20.sock");

        let low_hosts = vec![sample_host("from-low-pid")];
        let high_hosts = vec![sample_host("from-high-pid")];
        let low_daemon = spawn_fake_admin_daemon(
            UnixListener::bind(&low).unwrap(),
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: low_hosts.clone(),
            }),
        );
        let high_daemon = spawn_fake_admin_daemon(
            UnixListener::bind(&high).unwrap(),
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: high_hosts.clone(),
            }),
        );

        let mut result = admin_host_list_all(dir.path()).await;
        result.sort_by_key(|d| d.pid);
        assert_eq!(result.len(), 2, "both live daemons must contribute");
        assert_eq!(result[0].pid, 10);
        assert_eq!(result[0].hosts, low_hosts);
        assert_eq!(result[1].pid, 20);
        assert_eq!(result[1].hosts, high_hosts);

        low_daemon.await.unwrap();
        high_daemon.await.unwrap();
    }

    #[tokio::test]
    async fn admin_host_list_all_skips_a_daemon_that_answers_with_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("30.sock");
        let good = dir.path().join("40.sock");

        let bad_daemon = spawn_fake_admin_daemon(
            UnixListener::bind(&bad).unwrap(),
            local_response::Body::Error(LocalError::from_code(
                ErrorCode::PermissionDenied,
                "not allowed",
            )),
        );
        let expected = vec![sample_host("still-listed")];
        let good_daemon = spawn_fake_admin_daemon(
            UnixListener::bind(&good).unwrap(),
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        let result = admin_host_list_all(dir.path()).await;
        assert_eq!(
            result.len(),
            1,
            "a daemon answering with an error must be dropped, not turned into a failure"
        );
        assert_eq!(result[0].pid, 40);
        assert_eq!(result[0].hosts, expected);

        bad_daemon.await.unwrap();
        good_daemon.await.unwrap();
    }

    #[tokio::test]
    async fn admin_host_list_all_with_no_candidates_is_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(admin_host_list_all(dir.path()).await, Vec::new());
    }

    /// The regression this whole group of tests exists for: a socket that
    /// accepts the conduit and then never answers must not be able to
    /// stall the listing anywhere near [`PROBE_TIMEOUT`] (60 s) — measured
    /// wall-clock, not virtual time, because the defect under test was a
    /// real per-candidate wall-clock cost (adversarial review: 60.015 s
    /// with one wedged socket before `ADMIN_LIST_CANDIDATE_TIMEOUT`
    /// existed).
    #[tokio::test]
    async fn admin_host_list_all_does_not_stall_on_a_silent_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let silent = dir.path().join("50.sock");
        let silent_listener = UnixListener::bind(&silent).unwrap();
        let silent_daemon = tokio::spawn(async move {
            let (_stream, _addr) = silent_listener.accept().await.unwrap();
            // Accept the conduit, then never read or write — exactly the
            // "daemon wedged after accept" shape the adversarial review
            // reproduced against a real `qsh hosts` invocation.
            std::future::pending::<()>().await
        });

        let start = Instant::now();
        let result = admin_host_list_all(dir.path()).await;
        let elapsed = start.elapsed();

        assert_eq!(result, Vec::new(), "a silent daemon contributes nothing");
        assert!(
            elapsed < ADMIN_LIST_CANDIDATE_TIMEOUT * 2,
            "admin_host_list_all took {elapsed:?} against one silent daemon — \
             ADMIN_LIST_CANDIDATE_TIMEOUT is {ADMIN_LIST_CANDIDATE_TIMEOUT:?}"
        );

        silent_daemon.abort();
    }

    /// Two silent daemons must cost roughly the same as one — proving the
    /// candidates are probed concurrently rather than serially (a serial
    /// loop would cost ~2×[`ADMIN_LIST_CANDIDATE_TIMEOUT`] here, and the
    /// pre-fix code cost ~2×`PROBE_TIMEOUT`, i.e. two full minutes).
    #[tokio::test]
    async fn admin_host_list_all_probes_multiple_silent_daemons_concurrently() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemons = Vec::new();
        for pid in [60, 61] {
            let sock = dir.path().join(format!("{pid}.sock"));
            let listener = UnixListener::bind(&sock).unwrap();
            daemons.push(tokio::spawn(async move {
                let (_stream, _addr) = listener.accept().await.unwrap();
                std::future::pending::<()>().await
            }));
        }

        let start = Instant::now();
        let result = admin_host_list_all(dir.path()).await;
        let elapsed = start.elapsed();

        assert_eq!(result, Vec::new());
        assert!(
            elapsed < ADMIN_LIST_CANDIDATE_TIMEOUT * 2,
            "two silent daemons took {elapsed:?} — candidates are not being probed \
             concurrently (serial cost would be ~2×{ADMIN_LIST_CANDIDATE_TIMEOUT:?})"
        );

        for daemon in daemons {
            daemon.abort();
        }
    }

    /// The same silent-daemon-does-not-hide-others discipline `discover`
    /// already proves, on `admin_host_list_all`'s union path instead of
    /// `discover`'s stop-at-first-match path.
    #[tokio::test]
    async fn admin_host_list_all_returns_the_healthy_daemon_despite_a_silent_one() {
        let dir = tempfile::tempdir().unwrap();
        let silent = dir.path().join("70.sock");
        let healthy = dir.path().join("71.sock");

        let silent_listener = UnixListener::bind(&silent).unwrap();
        let silent_daemon = tokio::spawn(async move {
            let (_stream, _addr) = silent_listener.accept().await.unwrap();
            std::future::pending::<()>().await
        });

        let expected = vec![sample_host("healthy-answered")];
        let healthy_daemon = spawn_fake_admin_daemon(
            UnixListener::bind(&healthy).unwrap(),
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        let start = Instant::now();
        let result = admin_host_list_all(dir.path()).await;
        let elapsed = start.elapsed();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 71);
        assert_eq!(result[0].hosts, expected);
        assert!(
            elapsed < ADMIN_LIST_CANDIDATE_TIMEOUT * 2,
            "took {elapsed:?} with one silent daemon present"
        );

        silent_daemon.abort();
        healthy_daemon.await.unwrap();
    }
}
