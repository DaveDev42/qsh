//! Raw byte splice for tunnel streams (`PLAN.md` M4 Step 3;
//! `docs/design/protocol.md` §5, §7).
//!
//! A tunnel stream is framed only for its handshake — `StreamHeader`, then
//! the host's `ConnectResult`. Past `ConnectResult{ok:true}` §7's stream
//! table says the stream is a **raw byte pipe**: no length prefixes, no
//! messages, nothing to parse. This module is that pipe, and it is
//! deliberately the dumbest code in the crate:
//!
//! - **It never parses a byte.** There is no protocol past the handshake to
//!   parse; anything that looked at the payload would be inventing one.
//! - **It never logs a byte.** `CLAUDE.md`'s "never log PTY/command
//!   contents" has a tunnel edition (`PLAN.md` M4 §4 "터널 payload 로그
//!   금지"): tunnel diagnostics carry `host:port` and byte *counts*, and
//!   have no field a payload byte could be put in even by accident —
//!   [`SpliceStats`] is two `u64`s.
//! - **It never buffers without bound.** Each direction owns one
//!   [`SPLICE_BUF_LEN`] buffer and does read → `write_all` → read, so a
//!   slow reader stalls its own direction (QUIC flow control on one side,
//!   TCP zero-window on the other) instead of growing memory here.
//!
//! **Half-close is the interesting part.** A forwarded protocol may legally
//! shut down one direction and keep draining the other (`nc -N`, HTTP
//! request bodies, `git` over a tunnel). So an EOF on one direction only
//! shuts down *that* direction's writer ([`pump`]'s final `shutdown()`,
//! which is a QUIC `finish()` on the tunnel side and a `shutdown(SHUT_WR)`
//! on the TCP side) and lets the other keep running to its own EOF. Only an
//! *error* tears both sides down — and then loudly: see
//! [`splice_tcp_quic`]'s teardown, which resets rather than closes, because
//! a truncated transfer that looks like a clean EOF is data loss the
//! application cannot detect.

use std::io;

use quinn::{RecvStream, SendStream};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// Per-direction copy buffer. One of these exists per direction per live
/// tunnel connection (so 128 KiB per forwarded TCP connection), which is
/// the whole memory footprint of a splice — there is no queue behind it.
///
/// Sized at 64 KiB to match [`qsh_proto::frame::DATA_FRAME_MAX`]: not a
/// framing constraint (nothing here is framed) but the same order as the
/// QUIC stream receive window, so a single `read` can drain a full window's
/// worth without a syscall per chunk. `PLAN.md` M4 §4.2 lists tunnel window
/// tuning as measure-then-fix in Step 7 — this constant is a starting
/// point, not a contract.
const SPLICE_BUF_LEN: usize = 64 * 1024;

/// Bound on bytes [`pump`] copies in one direction before it explicitly
/// hands control back to the async runtime (`docs/design/protocol.md`
/// §12's bufferbloat defense — the send-side depth cap the priority band
/// alone was not enough for; see M4 Step 7's measured evidence below).
///
/// Quinn's own per-stream flow control lets a single direction write far
/// more than this before *quinn* ever blocks it — up to the connection's
/// `stream_receive_window`
/// ([`qsh_transport::endpoint::TUNNEL_STREAM_RECEIVE_WINDOW`], 2 MiB as
/// of M4 Step 7) — because `write_all` only blocks once the peer's
/// granted window is exhausted, not once "enough" has been queued for
/// send. Left unbounded, [`pump`]'s tight `read` → `write_all` loop can
/// hand quinn many iterations' worth of one stream's bytes back-to-back
/// with no intervening yield point, which crowds out *newly*-ready,
/// higher-priority streams even though `set_priority` correctly ranks
/// them: priority only decides which *already-pending* stream quinn's
/// packet builder picks next, not how often the packet builder — and
/// therefore quinn's own connection-driver task — gets scheduled to ask.
///
/// **Measured evidence (M4 Step 7 DoD 4).** The saturated-tunnel-vs-PTY-
/// echo gate (`crates/qsh-testkit/tests/tunnel_echo_under_load.rs`),
/// fixed to saturate host→client (the direction that actually contends
/// with PTY output on the host's own send scheduler) and to measure a
/// genuine client-originated round trip, first measured p95=30.579ms
/// (min=0.132ms, max=74.883ms) at the 2 MiB window with no send-side
/// cap — a clear DoD 4 miss despite the priority band and the 2 MiB
/// window (both already in place). Three cap sizes were tried against
/// both DoD 3 (throughput ratio) and DoD 4 (echo p95) together, since
/// they pull in opposite directions (a smaller cap yields more often,
/// which helps p95 but adds per-chunk scheduling overhead that eats into
/// raw throughput):
///
/// - 256 KiB (four [`SPLICE_BUF_LEN`] chunks): p95=10.085ms — still a
///   DoD 4 miss, just barely.
/// - 64 KiB (one chunk, yield after every `pump` iteration): p95 as low
///   as 5.480ms, comfortably under DoD 4's bar, but repeated runs pushed
///   DoD 3's throughput ratio down to 0.799 — under its 0.80 floor — on
///   one of three trials. Too aggressive: the extra yields cede the
///   runtime often enough to cost measurable tunnel throughput.
/// - **128 KiB (two chunks) — the value kept.** Five combined DoD 3 +
///   DoD 4 runs all passed both gates with margin: DoD 3 ratio
///   {0.899, 0.927, 0.942, 0.945, 0.909} (floor 0.80, and stable well
///   above the 0.85 "no threshold change needed" bar); DoD 4 p95
///   {7.919, 7.621, 7.672, 7.766, 7.146} ms (bar <10ms).
///
/// 128 KiB applies uniformly to every [`pump`] direction, including the
/// two that never touch quinn (`splice_tcp_uds`'s UDS halves) — an extra
/// yield point on a plain TCP/UDS copy is harmless (fairness with
/// whatever else is on that runtime), so a single constant is simpler to
/// reason about than threading a "this direction matters" flag through
/// every call site.
const SEND_DEPTH_CAP_BYTES: u64 = 128 * 1024;

/// QUIC application error code used to reset a tunnel stream whose splice
/// died mid-transfer. Internal (like `crate::server`'s `RESET_CODE_*` and
/// `crate::localctl::daemon`'s `0x2005`/`0x2006`), not a documented wire
/// contract: the peer only needs to learn "this was **not** a clean end of
/// stream", which the reset itself conveys.
pub(crate) const RESET_CODE_TUNNEL_ABORT: u32 = 0x2007;

/// How many bytes each direction carried. Byte *counts* only — the one
/// thing about a tunnel's payload that is safe to log (this module's own
/// doc).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpliceStats {
    /// Bytes copied from the local TCP socket to the tunnel stream.
    pub(crate) local_to_remote: u64,
    /// Bytes copied from the tunnel stream to the local TCP socket,
    /// including any handshake residue delivered first.
    pub(crate) remote_to_local: u64,
}

/// Why a splice ended early. Both variants mean the tunnel was truncated:
/// neither side saw a clean end of stream, so both carriers get reset
/// rather than closed ([`splice_tcp_quic`]).
#[derive(Debug, Error)]
pub(crate) enum SpliceError {
    /// Reading the local socket, or writing the tunnel stream, failed.
    #[error("tunnel splice failed local->remote: {0}")]
    LocalToRemote(#[source] io::Error),
    /// Reading the tunnel stream, or writing the local socket, failed.
    #[error("tunnel splice failed remote->local: {0}")]
    RemoteToLocal(#[source] io::Error),
}

/// Copy one direction to EOF, then half-close the writer.
///
/// `prefix` is written before anything is read from `from` — it exists for
/// the handshake residue [`qsh_transport::FramedRecv::into_raw`] hands
/// back, which is payload that has already arrived and must lead the
/// stream (that method's own doc explains why dropping or reordering it
/// silently corrupts the tunnel).
///
/// The trailing `shutdown()` is what makes half-open peers work: it is a
/// QUIC `finish()` on a [`SendStream`] and a `shutdown(SHUT_WR)` on a TCP
/// write half, so the far side of *this* direction sees EOF while the
/// opposite direction keeps flowing. Its error is deliberately swallowed —
/// a peer that already reset or stopped this stream makes the FIN
/// unsendable, and that is a fact about the peer, not a failure to copy
/// the bytes this call was asked to copy.
///
/// Generic over the halves rather than written against quinn/TCP directly
/// so the half-close behavior above is unit-testable over
/// [`tokio::io::duplex`] pipes, with no QUIC connection involved — and,
/// `pub(crate)` (`PLAN.md` M4 Step 5 (a)), so
/// `crate::localctl::daemon`'s `LOCAL_STREAM` tunnel legs (`TCP_CONNECT`/
/// `TCP_ACCEPTED`) can reuse this exact half-close discipline for their
/// UDS<->QUIC hop instead of re-deriving it: tunnel payload is unframed
/// past the handshake on *both* legs of that relay, not just the direct-
/// connect one this module was first written for.
pub(crate) async fn pump<R, W>(from: &mut R, to: &mut W, prefix: &[u8]) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut copied = 0u64;
    if !prefix.is_empty() {
        to.write_all(prefix).await?;
        copied += prefix.len() as u64;
    }
    let mut buf = vec![0u8; SPLICE_BUF_LEN];
    let mut since_yield = 0u64;
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        to.write_all(&buf[..n]).await?;
        copied += n as u64;
        // Send-side depth cap (`SEND_DEPTH_CAP_BYTES`'s own doc) — an
        // explicit yield every so often, not just whatever yield points
        // `read`/`write_all` happen to hit on their own, so a fast source
        // (already-buffered TCP/UDS data, nothing to wait for) cannot run
        // many iterations back-to-back with no scheduling opportunity for
        // anything else on this runtime.
        since_yield += n as u64;
        if since_yield >= SEND_DEPTH_CAP_BYTES {
            since_yield = 0;
            tokio::task::yield_now().await;
        }
    }
    let _ = to.shutdown().await;
    Ok(copied)
}

/// The four live handles a splice needs, owned so that reset-on-truncation
/// teardown is [`Drop`]-driven rather than return-path-driven.
///
/// [`splice_tcp_quic`] itself is not spawned: both directions are polled
/// by whichever task awaits it. That task can end three ways — the
/// function returns clean, the function returns an error, or the *task
/// itself* is aborted out from under the future while a splice is still
/// mid-transfer (`RemoteForwardClose`, a purged connection, a `-L`
/// handle's `Drop` — every one of them a plain `JoinHandle::abort()` on
/// an ancestor task, not a signal this future ever sees). A hand-written
/// error-path teardown only ever covers the second case:
/// `tokio::task::JoinHandle::abort` drops the task's future at whatever
/// await point it is suspended on, so none of that code runs on the
/// third — a bare quinn [`SendStream`]/[`RecvStream`] drop finishes
/// cleanly and a bare [`TcpStream`] half drop sends a FIN. Exactly the
/// silent "looks like a clean end" this module's own module doc says a
/// truncated transfer must never produce.
///
/// This type owns all four handles from the moment they exist, and its
/// `Drop` runs the reset teardown unless [`SpliceGuard::disarm`] already
/// ran. `disarm` is called only on the clean-finish return path, so
/// every other way the owning future's scope can end — an error return,
/// or the future being dropped mid-poll by an aborted ancestor task —
/// reaches `Drop` still armed and gets the same reset a hand-written
/// error-path teardown would have given it.
struct SpliceGuard {
    remote_send: Option<SendStream>,
    remote_recv: Option<RecvStream>,
    local_read: Option<OwnedReadHalf>,
    local_write: Option<OwnedWriteHalf>,
}

impl SpliceGuard {
    fn new(
        remote_send: SendStream,
        remote_recv: RecvStream,
        local_read: OwnedReadHalf,
        local_write: OwnedWriteHalf,
    ) -> Self {
        Self {
            remote_send: Some(remote_send),
            remote_recv: Some(remote_recv),
            local_read: Some(local_read),
            local_write: Some(local_write),
        }
    }

    /// The clean-finish path: both directions already told their peers
    /// the truth via [`pump`]'s own half-closes, so the four handles have
    /// nothing left to signal. Consuming `self` here — rather than
    /// merely flipping a flag — takes the fields out to `None` first, so
    /// even a future edit that made `Drop` unconditional could not turn
    /// this into a double-teardown.
    fn disarm(mut self) {
        self.remote_send.take();
        self.remote_recv.take();
        self.local_read.take();
        self.local_write.take();
    }
}

impl Drop for SpliceGuard {
    fn drop(&mut self) {
        // Reached only when `disarm` did not run: a genuine transfer
        // error, or this whole future dropped mid-poll by an aborted
        // ancestor task. Both are a truncated transfer, so both carriers
        // get the same reset [`splice_tcp_quic`]'s doc describes — moved
        // here, unchanged, from what used to be that function's own error
        // arm.
        if let (Some(mut send), Some(mut recv), Some(read)) = (
            self.remote_send.take(),
            self.remote_recv.take(),
            self.local_read.take(),
        ) {
            let _ = send.reset(quinn::VarInt::from_u32(RESET_CODE_TUNNEL_ABORT));
            let _ = recv.stop(quinn::VarInt::from_u32(RESET_CODE_TUNNEL_ABORT));
            let _ = read.as_ref().set_zero_linger();
        }
        if let Some(write) = self.local_write.take() {
            // `OwnedWriteHalf`'s own drop would otherwise emit a graceful
            // `shutdown(SHUT_WR)` first, muddying the abort with a FIN
            // the application could read as a normal end of stream.
            write.forget();
        }
    }
}

/// Splice a local TCP connection against a tunnel QUIC stream until both
/// directions end.
///
/// `residue` is the handshake leftover from
/// [`qsh_transport::FramedRecv::into_raw`] — bytes the peer pipelined
/// behind its last handshake frame, which this function writes to the
/// local socket ahead of everything subsequently read from `remote_recv`.
/// Callers that pass `Vec::new()` here when their framed reader *did* hold
/// residue silently truncate the tunnel.
///
/// Returns once both directions have hit EOF (the normal end of a
/// forwarded connection, each direction having been half-closed as it
/// finished), or the first error on either — with two different teardowns,
/// both driven by [`SpliceGuard`] rather than written out here:
///
/// - **Clean end:** each direction's writer was already `shutdown()` by
///   [`pump`], so the QUIC stream is `finish()`ed and the TCP socket got
///   its FIN. [`SpliceGuard::disarm`] is called, so dropping the halves
///   afterward adds nothing.
/// - **Error, including this task being aborted mid-transfer:** both
///   carriers are **reset**, not closed. Dropping a bare quinn
///   [`SendStream`] finishes it cleanly (quinn's `Drop`), and dropping a
///   bare [`TcpStream`] half sends a FIN — either would tell the far end
///   "the stream ended normally" about a transfer that in fact lost
///   bytes. So [`SpliceGuard`] stays armed on this path: its `Drop`
///   explicitly resets/stops the QUIC stream with
///   [`RESET_CODE_TUNNEL_ABORT`] and gives the TCP socket `SO_LINGER 0`
///   ([`TcpStream::set_zero_linger`]), which makes its close an RST. The
///   forwarded application then sees a connection error, which is the
///   truth. (Zero is the one `SO_LINGER` value that does not block on
///   close, which is why tokio exposes it separately from the deprecated
///   `set_linger`.)
pub(crate) async fn splice_tcp_quic(
    local: TcpStream,
    remote_send: SendStream,
    remote_recv: RecvStream,
    residue: Vec<u8>,
) -> Result<SpliceStats, SpliceError> {
    let (local_read, local_write) = local.into_split();
    let mut guard = SpliceGuard::new(remote_send, remote_recv, local_read, local_write);

    // Scoped so both futures — and the borrows of the guard's four
    // handles they hold — are dropped before `guard` is touched again
    // below, either to disarm it or to let it fall out of scope armed.
    let (up, down) = {
        let up = pump(
            guard.local_read.as_mut().expect("armed"),
            guard.remote_send.as_mut().expect("armed"),
            &[],
        );
        let down = pump(
            guard.remote_recv.as_mut().expect("armed"),
            guard.local_write.as_mut().expect("armed"),
            &residue,
        );
        tokio::pin!(up, down);

        let mut up_res: Option<io::Result<u64>> = None;
        let mut down_res: Option<io::Result<u64>> = None;
        while up_res.is_none() || down_res.is_none() {
            // The `if` guards keep an already-completed future from being
            // polled again; both branches' futures are cancel-safe to
            // leave pending across iterations because `select!` only drops
            // the *poll*, never the pinned future itself.
            tokio::select! {
                r = &mut up, if up_res.is_none() => {
                    let failed = r.is_err();
                    up_res = Some(r);
                    if failed {
                        break;
                    }
                }
                r = &mut down, if down_res.is_none() => {
                    let failed = r.is_err();
                    down_res = Some(r);
                    if failed {
                        break;
                    }
                }
            }
        }
        (up_res, down_res)
    };

    match (up, down) {
        (Some(Ok(local_to_remote)), Some(Ok(remote_to_local))) => {
            // Clean end on both directions: nothing left to reset.
            guard.disarm();
            Ok(SpliceStats {
                local_to_remote,
                remote_to_local,
            })
        }
        (up, down) => {
            // Truncated: leave `guard` armed. It is about to fall out of
            // scope (this function returning `Err`), and `SpliceGuard`'s
            // `Drop` is what now makes both peers see an abort, never a
            // clean EOF — the same teardown a task-abort mid-transfer
            // gets, for the same reason.
            match (up, down) {
                (Some(Err(err)), _) => Err(SpliceError::LocalToRemote(err)),
                (_, Some(Err(err))) => Err(SpliceError::RemoteToLocal(err)),
                // Unreachable: the loop only exits with both directions
                // resolved or with one of them holding an `Err`. Treated
                // as a truncation rather than an `unreachable!()` so a
                // future edit to the loop cannot turn a logic slip into a
                // panic on a live tunnel.
                _ => Err(SpliceError::RemoteToLocal(io::Error::other(
                    "tunnel splice ended with neither direction resolved",
                ))),
            }
        }
    }
}

/// [`SpliceGuard`]'s counterpart for [`splice_tcp_uds`]: only the local TCP
/// half needs drop-driven reset teardown here. The remote half is the
/// reverse `LOCAL_STREAM` conduit to this same machine's resident daemon
/// (raw [`crate::localctl::client::RawUdsRead`]/`RawUdsWrite`), which has
/// no equivalent abrupt-close signal available through tokio — exactly the
/// asymmetry `crate::localctl::daemon::TunnelQuicGuard`'s own doc already
/// establishes for the daemon's own UDS↔QUIC relay hop ("losing the
/// clean/abrupt distinction there does not create data loss or
/// misdelivery, only a coarser signal to a process on this same machine").
/// So this guard, unlike [`SpliceGuard`], only ever holds the TCP halves —
/// the UDS halves are plain local variables in [`splice_tcp_uds`] and drop
/// however they drop.
#[cfg(unix)]
struct LocalTcpGuard {
    local_read: Option<OwnedReadHalf>,
    local_write: Option<OwnedWriteHalf>,
}

#[cfg(unix)]
impl LocalTcpGuard {
    fn new(local_read: OwnedReadHalf, local_write: OwnedWriteHalf) -> Self {
        Self {
            local_read: Some(local_read),
            local_write: Some(local_write),
        }
    }

    /// The clean-finish path — see [`SpliceGuard::disarm`]'s own doc.
    fn disarm(mut self) {
        self.local_read.take();
        self.local_write.take();
    }
}

#[cfg(unix)]
impl Drop for LocalTcpGuard {
    fn drop(&mut self) {
        // Reached only on a truncated transfer or this future being
        // dropped mid-poll — see [`SpliceGuard`]'s own doc for why a bare
        // drop here would be the wrong signal to the forwarded
        // application.
        if let Some(read) = self.local_read.take() {
            let _ = read.as_ref().set_zero_linger();
        }
        if let Some(write) = self.local_write.take() {
            write.forget();
        }
    }
}

/// Splice a local TCP connection against a reverse `LOCAL_STREAM` conduit
/// (`crate::localctl::client::RawUdsRead`/`RawUdsWrite`) until both
/// directions end — the `-L over reverse` counterpart of
/// [`splice_tcp_quic`] (`PLAN.md` M4 Step 5 (a)), reusing the exact same
/// [`pump`] primitive and half-close discipline so a forwarded protocol
/// that shuts down one direction and keeps draining the other behaves
/// identically on either carrier.
///
/// `residue` is the handshake leftover
/// [`crate::localctl::client::DataRecvHalf::into_raw`] hands back — see
/// [`splice_tcp_quic`]'s own doc on why it must lead the stream.
///
/// Teardown is asymmetric by design — see [`LocalTcpGuard`]'s own doc: the
/// local TCP side gets the same `SO_LINGER 0` RST-on-truncation treatment
/// [`splice_tcp_quic`] gives it, while the UDS side (a process-local hop to
/// this machine's own daemon) is simply dropped, clean or not.
#[cfg(unix)]
pub(crate) async fn splice_tcp_uds(
    local: TcpStream,
    mut uds_write: crate::localctl::client::RawUdsWrite,
    mut uds_read: crate::localctl::client::RawUdsRead,
    residue: Vec<u8>,
) -> Result<SpliceStats, SpliceError> {
    let (local_read, local_write) = local.into_split();
    let mut guard = LocalTcpGuard::new(local_read, local_write);

    let (up, down) = {
        let up = pump(
            guard.local_read.as_mut().expect("armed"),
            &mut uds_write,
            &[],
        );
        let down = pump(
            &mut uds_read,
            guard.local_write.as_mut().expect("armed"),
            &residue,
        );
        tokio::pin!(up, down);

        let mut up_res: Option<io::Result<u64>> = None;
        let mut down_res: Option<io::Result<u64>> = None;
        while up_res.is_none() || down_res.is_none() {
            tokio::select! {
                r = &mut up, if up_res.is_none() => {
                    let failed = r.is_err();
                    up_res = Some(r);
                    if failed {
                        break;
                    }
                }
                r = &mut down, if down_res.is_none() => {
                    let failed = r.is_err();
                    down_res = Some(r);
                    if failed {
                        break;
                    }
                }
            }
        }
        (up_res, down_res)
    };

    match (up, down) {
        (Some(Ok(local_to_remote)), Some(Ok(remote_to_local))) => {
            guard.disarm();
            Ok(SpliceStats {
                local_to_remote,
                remote_to_local,
            })
        }
        (up, down) => match (up, down) {
            (Some(Err(err)), _) => Err(SpliceError::LocalToRemote(err)),
            (_, Some(Err(err))) => Err(SpliceError::RemoteToLocal(err)),
            _ => Err(SpliceError::RemoteToLocal(io::Error::other(
                "tunnel splice ended with neither direction resolved",
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Half-close, the property the whole module exists for: EOF on one
    /// direction shuts down only that direction's writer, and the opposite
    /// direction keeps carrying bytes afterwards. Written against
    /// [`tokio::io::duplex`] pipes so it tests `pump`'s own logic with no
    /// QUIC connection in the way.
    #[tokio::test]
    async fn pump_half_closes_only_its_own_direction_at_eof() {
        let (mut source, source_peer) = tokio::io::duplex(64);
        let (mut sink, mut sink_peer) = tokio::io::duplex(64);

        // The source ends after "early"; the pump must copy it and then
        // shut its writer down.
        let mut source_peer = source_peer;
        tokio::spawn(async move {
            source_peer.write_all(b"early").await.unwrap();
            source_peer.shutdown().await.unwrap();
        });

        let copied = pump(&mut source, &mut sink, &[]).await.unwrap();
        assert_eq!(copied, 5);

        let mut got = Vec::new();
        sink_peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"early", "sink saw the bytes then a clean EOF");
    }

    /// The handshake residue leads the stream: bytes handed to `pump` as a
    /// prefix are written before anything read from the source, and are
    /// counted. This is the transition
    /// [`qsh_transport::FramedRecv::into_raw`] exists to make safe — a
    /// splice that dropped or appended the residue would silently truncate
    /// or reorder every tunnel whose peer pipelined its first payload
    /// bytes behind the handshake frame.
    #[tokio::test]
    async fn pump_writes_handshake_residue_before_anything_it_reads() {
        let (mut source, mut source_peer) = tokio::io::duplex(64);
        let (mut sink, mut sink_peer) = tokio::io::duplex(64);

        tokio::spawn(async move {
            source_peer.write_all(b"-then-the-stream").await.unwrap();
            source_peer.shutdown().await.unwrap();
        });

        let copied = pump(&mut source, &mut sink, b"residue").await.unwrap();
        assert_eq!(copied, b"residue-then-the-stream".len() as u64);

        let mut got = Vec::new();
        sink_peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"residue-then-the-stream");
    }

    /// A pump whose writer dies reports the error rather than spinning or
    /// swallowing it — the input to `splice_tcp_quic`'s reset-don't-close
    /// teardown.
    #[tokio::test]
    async fn pump_reports_a_write_failure() {
        let (mut source, mut source_peer) = tokio::io::duplex(64);
        let (mut sink, sink_peer) = tokio::io::duplex(64);
        drop(sink_peer);

        tokio::spawn(async move {
            let _ = source_peer.write_all(b"into the void").await;
        });

        let err = pump(&mut source, &mut sink, &[]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// The regression this stage exists for: `task.abort()` on whatever
    /// task owns a call to [`splice_tcp_quic`] — exactly what
    /// `RemoteForwardClose`, a purged connection, and `LocalForwardHandle`
    /// drop all do to the task that (transitively, via a `JoinSet`) is
    /// running a live splice — must never let either peer see a clean
    /// end. Real TCP and real QUIC on both sides, so the assertions are
    /// about what actually crosses the wire, not about which internal
    /// function got called.
    #[tokio::test]
    async fn aborting_the_owning_task_mid_transfer_resets_both_peers_not_a_clean_eof() {
        use tokio::net::{TcpListener, TcpStream};

        // A live TCP pair: one half feeds `splice_tcp_quic` as `local`,
        // the other stays here as an observer of what the peer sees.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_task = tokio::spawn(TcpStream::connect(addr));
        let (accepted, _) = listener.accept().await.unwrap();
        let mut tcp_observer = connect_task.await.unwrap().unwrap();

        // A live QUIC bidi stream pair, same shape: one half feeds
        // `splice_tcp_quic`, the other is this test's observer. The
        // observer side writes first — proving the peer's `accept_bi`
        // resolves and, once the splice starts, that "hello" is what
        // actually proves real bytes crossed before the abort.
        let (conn_a, conn_b) = crate::tunnel::testutil::loopback_pair().await;
        let accept_fut = conn_b.accept_bi();
        let open_fut = async {
            let (mut send, recv) = conn_a.open_bi().await.unwrap();
            send.write_all(b"hello").await.unwrap();
            (send, recv)
        };
        let (accepted_pair, (quic_observer_send, mut quic_observer_recv)) =
            tokio::join!(accept_fut, open_fut);
        let (remote_send, remote_recv) = accepted_pair.unwrap();
        // Keep the sender alive until the end of the test — dropping it
        // early would itself end the QUIC stream and confound what the
        // final assertion is checking.
        let _quic_observer_send = quic_observer_send;

        let task = tokio::spawn(splice_tcp_quic(
            accepted,
            remote_send,
            remote_recv,
            Vec::new(),
        ));

        // Down direction: the "hello" queued above must actually arrive
        // at the TCP observer once the splice starts pumping — proof
        // this is a real mid-transfer abort, not "abort before anything
        // ever ran".
        let mut down = [0u8; 5];
        tcp_observer.read_exact(&mut down).await.unwrap();
        assert_eq!(&down, b"hello");

        // Up direction, same proof the other way.
        tcp_observer.write_all(b"world").await.unwrap();
        let mut up = [0u8; 5];
        match quic_observer_recv.read(&mut up).await.unwrap() {
            Some(5) => assert_eq!(&up, b"world"),
            other => panic!("expected the up-direction payload, got {other:?}"),
        }

        // Now abort the task out from under the splice, exactly as
        // `RemoteForwardClose`/`purge_connection`/`LocalForwardHandle`'s
        // `Drop` do to their owning task.
        task.abort();
        let joined = task.await;
        assert!(
            joined.unwrap_err().is_cancelled(),
            "the task must actually have been aborted, not merely finished"
        );

        // The TCP peer must see an abort, never `Ok(0)` — a clean EOF it
        // cannot tell apart from "nothing more, but fine".
        let mut buf = [0u8; 8];
        match tcp_observer.read(&mut buf).await {
            Ok(0) => {
                panic!("TCP side saw a clean EOF from an aborted splice — truncation looks orderly")
            }
            Ok(n) => panic!("unexpected data after abort: {:?}", &buf[..n]),
            Err(_) => {} // reset — the correct outcome; exact kind is platform-dependent
        }

        // The QUIC peer must see the stream reset, never a clean finish
        // (`Ok(None)`).
        match quic_observer_recv.read(&mut buf).await {
            Ok(None) => panic!(
                "QUIC side saw a clean finish from an aborted splice — truncation looks orderly"
            ),
            Ok(Some(n)) => panic!("unexpected data after abort: {:?}", &buf[..n]),
            Err(_) => {} // reset — the correct outcome
        }
    }
}
