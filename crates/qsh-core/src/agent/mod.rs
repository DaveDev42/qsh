//! The host side of agent forwarding (ADR-0055 decisions 6 to 10): the
//! per-session (or per-exec) socket, or named pipe on Windows, that a
//! program on the host reaches through `SSH_AUTH_SOCK`.
//!
//! This module only owns the local endpoint. It creates it with owner-only
//! access, accepts connections from the same user, enforces the concurrent
//! connection caps and removes the endpoint when it goes away. It knows
//! nothing about QUIC, sessions or authorization: the session layer takes
//! each [`AgentConn`] this module hands out and bridges it to an `AGENT`
//! stream of whichever connection currently backs the socket.
//!
//! | platform | endpoint | who may connect |
//! |---|---|---|
//! | unix | `<runtime_dir>/agent/<32 hex>.sock`, or `/tmp/qsh-agent-XXXXXXXXXX/<32 hex>.sock` when that path would not fit `sun_path` | the directory is 0700, the socket 0600, and every accepted peer's uid is compared with this process's euid |
//! | Windows | `\\.\pipe\qsh-agent-<32 hex>` | a protected owner-only DACL, `FILE_FLAG_FIRST_PIPE_INSTANCE`, remote clients rejected, and the peer process's user SID compared with this process's |
//!
//! # Caps
//!
//! Three caps bound the concurrent local connections (ADR-0055 decision 10).
//! The per-socket cap ([`MAX_AGENT_STREAMS_PER_SOCKET`]) is enforced here: a
//! connection over it is closed inside [`AgentListener::accept`] and never
//! returned. The per-connection ([`MAX_AGENT_STREAMS_PER_CONN`]) and
//! per-reverse-hub ([`MAX_AGENT_STREAMS_PER_HUB`]) caps depend on which QUIC
//! connection backs the socket at that moment, which only the session layer
//! knows. It owns a [`StreamBudget`] for each and calls
//! [`AgentConn::hold`] with it; a `false` answer means "close this
//! connection". Slots are released when the [`AgentConn`] is dropped.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{AgentListener, sweep_stale, sweep_stale_older_than};
#[cfg(windows)]
pub use windows::{AgentListener, sweep_stale, sweep_stale_older_than};

#[cfg(test)]
mod tests;

/// Concurrent `AGENT` streams on one socket (one session or one exec).
pub const MAX_AGENT_STREAMS_PER_SOCKET: usize = 16;
/// Concurrent `AGENT` streams on one QUIC connection.
pub const MAX_AGENT_STREAMS_PER_CONN: usize = 64;
/// Concurrent `AGENT` streams through one reverse hub.
pub const MAX_AGENT_STREAMS_PER_HUB: usize = 32;

/// The local stream type of an accepted connection.
#[cfg(unix)]
pub type AgentStream = tokio::net::UnixStream;
/// The local stream type of an accepted connection.
#[cfg(windows)]
pub type AgentStream = crate::localctl::transport::LocalStream;

/// A counting limit on concurrent connections. Cloning shares the count.
#[derive(Debug, Clone)]
pub struct StreamBudget {
    inner: Arc<BudgetInner>,
}

#[derive(Debug)]
struct BudgetInner {
    cap: usize,
    in_use: AtomicUsize,
}

impl StreamBudget {
    /// A budget that allows `cap` concurrent [`Permit`]s.
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new(BudgetInner {
                cap,
                in_use: AtomicUsize::new(0),
            }),
        }
    }

    /// Take a slot, or `None` when `cap` are already out.
    pub fn try_acquire(&self) -> Option<Permit> {
        self.inner
            .in_use
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.inner.cap).then_some(n + 1)
            })
            .ok()?;
        Some(Permit {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Slots currently taken.
    pub fn in_use(&self) -> usize {
        self.inner.in_use.load(Ordering::Acquire)
    }

    /// The most slots that can be out at once.
    pub fn cap(&self) -> usize {
        self.inner.cap
    }
}

/// One slot of a [`StreamBudget`], released on drop.
#[derive(Debug)]
pub struct Permit {
    inner: Arc<BudgetInner>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.inner.in_use.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Why a local connection was closed without being handed out. These are
/// the `accept_closed` reasons of the `qsh::agent` log (ADR-0055 decision
/// 17) that this module can know; `no_backing` belongs to the session layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The socket already had [`MAX_AGENT_STREAMS_PER_SOCKET`] connections.
    Cap,
    /// The peer is another user, or its identity could not be read.
    PeerUid,
}

impl RefusalReason {
    /// The closed-vocabulary word the log line carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cap => "cap",
            Self::PeerUid => "peer_uid",
        }
    }
}

/// How many connections an [`AgentListener`] has handled so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentStats {
    /// Connections handed out by `accept`.
    pub accepted: usize,
    /// Connections closed because the socket was at its cap.
    pub refused_cap: usize,
    /// Connections closed because the peer was another user.
    pub refused_peer_uid: usize,
}

/// Shared counters behind [`AgentStats`].
#[derive(Debug, Default)]
pub(crate) struct Counters {
    accepted: AtomicUsize,
    refused_cap: AtomicUsize,
    refused_peer_uid: AtomicUsize,
}

impl Counters {
    pub(crate) fn accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a refusal and write the `qsh::agent` line. Only a count and a
    /// closed-vocabulary reason are logged.
    pub(crate) fn refused(&self, reason: RefusalReason) {
        let counter = match reason {
            RefusalReason::Cap => &self.refused_cap,
            RefusalReason::PeerUid => &self.refused_peer_uid,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            target: "qsh::agent",
            event = "accept_closed",
            reason = reason.as_str(),
        );
    }

    pub(crate) fn snapshot(&self) -> AgentStats {
        AgentStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            refused_cap: self.refused_cap.load(Ordering::Relaxed),
            refused_peer_uid: self.refused_peer_uid.load(Ordering::Relaxed),
        }
    }
}

/// An accepted local connection: a byte stream to the program on the host,
/// plus the slots it holds. Dropping it closes the stream and frees the slots.
#[derive(Debug)]
pub struct AgentConn {
    stream: AgentStream,
    permits: Vec<Permit>,
}

impl AgentConn {
    pub(crate) fn new(stream: AgentStream, socket_slot: Permit) -> Self {
        Self {
            stream,
            permits: vec![socket_slot],
        }
    }

    /// Take a slot of `budget` for as long as this connection lives (the
    /// per-connection and per-hub caps). `false` means the budget is full and
    /// the caller should drop this connection.
    #[must_use]
    pub fn hold(&mut self, budget: &StreamBudget) -> bool {
        match budget.try_acquire() {
            Some(permit) => {
                self.permits.push(permit);
                true
            }
            None => false,
        }
    }

    /// Split off the stream, keeping the slots held until the returned
    /// [`SlotGuard`] is dropped.
    pub fn into_parts(self) -> (AgentStream, SlotGuard) {
        (
            self.stream,
            SlotGuard {
                _permits: self.permits,
            },
        )
    }
}

/// The slots of a split [`AgentConn`], released on drop.
#[derive(Debug)]
pub struct SlotGuard {
    _permits: Vec<Permit>,
}

impl AsyncRead for AgentConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for AgentConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// 128 random bits as 32 lower-case hex digits: the endpoint's name, which
/// has nothing to do with the session id (ADR-0055 decision 6).
pub(crate) fn random_hex_name() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
