//! The requester side of a local forward, `-L [bind:]lport:host:hport`
//! (`PLAN.md` M4 Step 3, `docs/CLI.md` §6.9, `docs/design/protocol.md` §7).
//!
//! One [`LocalForward`] owns one local TCP listener. Every connection
//! accepted on it becomes one tunnel stream to the peer:
//!
//! ```text
//! local TCP conn ──▶ StreamHeader{TCP_CONNECT, host, port} ──▶ peer
//!                 ◀── ConnectResult{ok}                     ──
//!                 ◀────────── raw bytes, both ways ─────────▶
//! ```
//!
//! Everything security-relevant happens on the *other* side: the peer
//! authorizes `forward.local` for `host:port` and only then dials
//! (`crate::server::Server::authorize_and_dial_tunnel`). This side creates
//! no remote resource and makes no decision — it asks, and either gets a
//! byte pipe or a refusal it must clean up after. It is written to be
//! boring for exactly that reason.
//!
//! **Loopback bind (`PLAN.md` M4 §4.1 #3).** The listener binds loopback,
//! full stop: with no `bind:` prefix it defaults to `127.0.0.1`, and an
//! explicit non-loopback `bind:` is refused rather than honored. A local
//! forward's port speaks to the peer with *this* machine's credentials, so
//! exposing it on a LAN interface would hand every host on that network an
//! unauthenticated ride through this process's authorization — and whether
//! to ever allow that is deliberately out of M4's scope (§4.1 #3:
//! "loopback 고정, 필요 시 P1").
//!
//! **Windows.** Nothing here is platform-specific — a TCP listener, a QUIC
//! stream and a byte copy exist on every target — so unlike M4's host-side
//! listener/relay legs this module is not `cfg(unix)`-gated and its tests
//! run on the Windows leg too (`PLAN.md` "전 step 공통 계약 규율" ties the
//! client-side `-L` bind's platform reach to §4.1 #1's holder decision,
//! which came out foreground-only, i.e. no daemon and so no unix-only
//! dependency). Only the reverse `LOCAL_STREAM` carrier below is unix-only,
//! and it is refused here in any case until Step 5.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::wire::{
    ConnectResult, ForwardSpec, StreamHeader, StreamKind, format_host_port, sanitize_peer_text,
};
use qsh_proto::{ErrorCode, Tunnel};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use crate::client::ClientError;
use crate::client::link::DataLink;
use crate::tunnel::splice::{SpliceError, SpliceStats, splice_tcp_quic};

/// An owned carrier a [`LocalForward`] can keep opening tunnel streams on,
/// for as long as it runs.
///
/// [`DataLink`] is a *borrowing* view (it is what
/// [`crate::tunnel::open_stream`] takes), which a spawned per-connection
/// task cannot hold. This is the owned counterpart, on exactly the same
/// forward/reverse axis, so the accept loop can hand each connection task
/// an [`Arc`] of it and let the task make its own short-lived [`DataLink`].
pub(crate) enum ForwardCarrier {
    /// A live QUIC connection dialed straight to the peer (forward route).
    /// `qsh_transport::Connection` is itself a cheap handle, so this holds
    /// one rather than borrowing.
    ///
    /// A **snapshot**, deliberately: it is the connection the forward was
    /// started on, not a view of whichever connection the owning attach
    /// currently holds. A forward-route recovery replaces the attach's
    /// connection (`crate::ops::session`'s `Link::replace`), and streams
    /// opened here after that point fail on the old one — a forward has to
    /// be restarted across a recovery. Tunnel behavior under resume/chaos
    /// is `PLAN.md` M4 Step 8's subject; nothing before it promises a
    /// forward survives a reconnect.
    Quic(qsh_transport::Connection),
    /// This machine's resident `qsh listen` daemon socket plus the host
    /// name to relay to (reverse route) — see [`DataLink::Local`].
    /// Constructing this is legal, but splicing over it is refused with
    /// [`ForwardConnError::CarrierNotRaw`] until `PLAN.md` M4 Step 5
    /// teaches the daemon to relay tunnel streams.
    #[cfg(unix)]
    #[allow(dead_code)] // consumed by Step 5 (`-L over reverse`)
    Local {
        /// The daemon's UDS socket path.
        socket: std::path::PathBuf,
        /// The registered host name to relay to.
        host: String,
    },
}

impl ForwardCarrier {
    /// Borrow this carrier as the link [`crate::tunnel::open_stream`]
    /// wants.
    fn link(&self) -> DataLink<'_> {
        match self {
            ForwardCarrier::Quic(conn) => DataLink::Quic(conn),
            #[cfg(unix)]
            ForwardCarrier::Local { socket, host } => DataLink::Local {
                socket: socket.as_path(),
                host: host.as_str(),
            },
        }
    }
}

/// Why a local forward could not be set up. Both variants are pre-listener:
/// a `-L` that fails here never binds anything.
#[derive(Debug, Error)]
pub enum LocalForwardError {
    /// The spec's `bind:` is not a loopback address (this module's own doc
    /// on §4.1 #3). [`ErrorCode::InvalidArgument`], not `UNSUPPORTED`: the
    /// request violates a standing constraint on its shape, the same way a
    /// non-loopback `-R` bind does (`PLAN.md` M4 §4.1 #5).
    #[error("{0}")]
    Bind(String),
    /// The loopback bind itself failed (port already in use, privileged
    /// port, …). [`ErrorCode::ConnectionFailed`] — the local endpoint the
    /// forward needs could not be established.
    #[error("bind {addr}: {source}")]
    Listen {
        /// The address that could not be bound.
        addr: SocketAddr,
        /// The OS error.
        #[source]
        source: io::Error,
    },
}

impl LocalForwardError {
    /// The `docs/CLI.md` §3.3 code this maps to. M4 introduces no new
    /// [`ErrorCode`] (`PLAN.md` M4 §4.1 #9).
    pub fn code(&self) -> ErrorCode {
        match self {
            LocalForwardError::Bind(_) => ErrorCode::InvalidArgument,
            LocalForwardError::Listen { .. } => ErrorCode::ConnectionFailed,
        }
    }
}

/// Why one forwarded connection failed. Never fatal to the forward itself
/// — [`LocalForward::run`] logs and keeps accepting ([`LocalForward::run`]'s
/// own doc).
#[derive(Debug, Error)]
pub(crate) enum ForwardConnError {
    /// The tunnel stream could not be opened, or its handshake could not be
    /// read.
    #[error(transparent)]
    Link(#[from] ClientError),
    /// The peer answered `ConnectResult{ok:false}` — an inline
    /// `forward.local` denial (`PERMISSION_DENIED`), a dial that failed
    /// (`CONNECTION_FAILED`/`HOST_NOT_FOUND`), or a malformed destination
    /// (`INVALID_ARGUMENT`).
    ///
    /// The peer's verdict is reported, never re-decided here — but it is
    /// **not** passed through raw. Both strings are peer-authored prose
    /// that ends up in this side's diagnostics, and on the interactive
    /// `-L` form those diagnostics land on a terminal this process has
    /// just put in raw mode, so a hostile or compromised host could
    /// otherwise repaint the operator's screen or forge `qsh` output with
    /// an escape sequence. They are passed through
    /// [`sanitize_peer_text`] at construction, which is the only place
    /// either string is built.
    #[error("peer refused the forward: {code}: {message}")]
    Refused {
        /// The peer's `docs/CLI.md` §3.3 code, sanitized for display.
        code: String,
        /// The peer's message, sanitized for display.
        message: String,
    },
    /// The peer ended the tunnel stream without answering the
    /// `TCP_CONNECT` at all — protocol.md §7 requires a `ConnectResult`
    /// either way.
    #[error("peer closed the tunnel stream without a ConnectResult")]
    NoConnectResult,
    /// The carrier cannot surrender a raw byte pipe: a local forward over
    /// the reverse `LOCAL_STREAM` conduit, which is `PLAN.md` M4 Step 5.
    #[error("local forwards over a reverse connection land in M4 Step 5")]
    CarrierNotRaw,
    /// The byte pipe itself broke mid-transfer.
    #[error(transparent)]
    Splice(#[from] SpliceError),
}

/// A bound local forward: one loopback TCP listener plus the peer-side
/// destination every connection accepted on it should reach.
///
/// Split from [`LocalForward::run`] so the caller learns the real bound
/// port *before* the accept loop starts — `-L 0:host:port` is how tests
/// (and `docs/design/testing.md`'s "port 0 bind" CI rule) avoid fixed
/// ports, and `PLAN.md` M4 Step 3 (c) requires the L5 harness to
/// parameterize DoD 1's `8080` that way.
#[derive(Debug)]
pub(crate) struct LocalForward {
    listener: TcpListener,
    local_addr: SocketAddr,
    host: String,
    host_port: u16,
}

impl LocalForward {
    /// Bind the local listener for `spec` (which must be
    /// [`qsh_proto::wire::ForwardDirection::Local`]; the caller sets that
    /// from which flag it parsed).
    ///
    /// This is the only resource a local forward creates on this side, and
    /// it is deliberately created *before* any tunnel stream exists: it
    /// grants nothing — every stream it later opens is authorized by the
    /// peer, per connection, before the peer creates anything
    /// (`docs/PRD.md` §9, `docs/design/protocol.md` §7).
    pub(crate) async fn bind(spec: &ForwardSpec) -> Result<Self, LocalForwardError> {
        let addr = loopback_bind_addr(spec.bind.as_deref(), spec.listen_port)?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| LocalForwardError::Listen { addr, source })?;
        let local_addr = listener
            .local_addr()
            .map_err(|source| LocalForwardError::Listen { addr, source })?;
        Ok(Self {
            listener,
            local_addr,
            host: spec.host.clone(),
            host_port: spec.host_port,
        })
    }

    /// The address actually bound — with `listen_port` 0, the port the OS
    /// picked.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The peer-side destination each connection is forwarded to.
    pub(crate) fn destination(&self) -> (&str, u16) {
        (&self.host, self.host_port)
    }

    /// Accept forever, forwarding each connection over its own tunnel
    /// stream.
    ///
    /// Returns only on a **fatal** listener error; otherwise it runs until
    /// the future is dropped, which is how the foreground `-L` holder ends
    /// it (`PLAN.md` M4 §4.1 #1: the listener lives as long as the
    /// interactive session and dies with the process — no daemon, no
    /// `close` RPC). Dropping this future also aborts every in-flight
    /// connection task, because they live in a [`JoinSet`] this future
    /// owns: nothing is spawned that outlives the forward.
    ///
    /// One connection can never take the forward down. A refused, broken
    /// or malformed connection is logged (structurally — destination and
    /// byte counts, never payload) and the loop goes straight back to
    /// accepting, which is also what keeps a peer that denies
    /// `forward.local` from turning into a self-inflicted outage of every
    /// other forward on the same listener.
    ///
    /// Cancel-safe at every await: [`TcpListener::accept`] and
    /// [`JoinSet::join_next`] both are, so dropping this future mid-poll
    /// loses at most one not-yet-accepted connection.
    pub(crate) async fn run(self, carrier: Arc<ForwardCarrier>) -> io::Error {
        let mut tasks: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (tcp, peer) = match accepted {
                        Ok(pair) => pair,
                        // One failed `accept()` must never end the forward
                        // (this method's own doc): only a listener that is
                        // itself gone does. See `accept_disposition`.
                        Err(err) => match accept_disposition(&err) {
                            AcceptDisposition::Retry => {
                                tracing::debug!(%err, "qsh::tunnel: transient accept error");
                                continue;
                            }
                            AcceptDisposition::Backoff => {
                                // Structural: an errno and the forward's
                                // destination, never a payload byte.
                                tracing::warn!(
                                    host = self.host,
                                    port = self.host_port,
                                    %err,
                                    backoff_ms = ACCEPT_BACKOFF.as_millis() as u64,
                                    "qsh::tunnel: accept deferred, out of resources"
                                );
                                tokio::time::sleep(ACCEPT_BACKOFF).await;
                                continue;
                            }
                            AcceptDisposition::Fatal => return err,
                        },
                    };
                    let carrier = Arc::clone(&carrier);
                    let host = self.host.clone();
                    let host_port = self.host_port;
                    tasks.spawn(async move {
                        match forward_connection(tcp, &carrier, &host, host_port).await {
                            Ok(stats) => tracing::debug!(
                                host,
                                port = host_port,
                                sent = stats.local_to_remote,
                                received = stats.remote_to_local,
                                "qsh::tunnel: forwarded connection closed"
                            ),
                            Err(err) => tracing::warn!(
                                host,
                                port = host_port,
                                %peer,
                                %err,
                                "qsh::tunnel: forwarded connection failed"
                            ),
                        }
                    });

                }
                // Reap finished connection tasks so a long-lived forward
                // does not accumulate their handles. Guarded because
                // `join_next` on an empty set resolves to `None`
                // immediately, which would spin this loop.
                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(err) = joined
                        && err.is_panic()
                    {
                        tracing::warn!(%err, "qsh::tunnel: forwarded connection task panicked");
                    }
                }
            }
        }
    }
}

/// A bound, running local forward — the public face of `-L`.
///
/// This is the whole tunnel lifecycle model M4 settled on (`PLAN.md` M4
/// §4.1 #1, `docs/CLI.md` §6.14): a **foreground holder**, not a daemon
/// and not a registry entry. There is no `close` RPC and nothing on the
/// peer to release, because a local forward creates nothing on the peer
/// until a TCP connection arrives (and even then only after the peer's own
/// inline `forward.local` check). Dropping this handle aborts the accept
/// loop, which closes the listener and aborts every in-flight connection
/// task with it — so process exit, session end, or simply letting the
/// handle go is a complete teardown.
///
/// Held by [`crate::ops::TunnelHold`] (`qsh tunnel open`) and by
/// [`crate::ops::SessionAttachStream`] (the interactive `qsh [user@]host
/// -L spec` form). Frontends never build one directly — they receive the
/// [`Tunnel`] DTO and nothing else, which is what keeps tunnel lifecycle
/// out of the renderers (`docs/CLI.md` §11).
#[derive(Debug)]
pub struct LocalForwardHandle {
    tunnel_id: String,
    bind: SocketAddr,
    forward_to: (String, u16),
    task: tokio::task::JoinHandle<io::Error>,
}

impl LocalForwardHandle {
    /// Bind `spec`'s loopback listener and start serving it over
    /// `connection`.
    ///
    /// Must be called from inside a tokio runtime: the accept loop is
    /// spawned onto the current one, and the handle's [`Drop`] aborts it
    /// there. `connection` is a snapshot — see `ForwardCarrier::Quic`.
    ///
    /// The listener exists only after this returns `Ok`: a refused bind
    /// (non-loopback, port in use) creates nothing.
    pub async fn start(
        spec: &ForwardSpec,
        connection: qsh_transport::Connection,
    ) -> Result<Self, LocalForwardError> {
        let forward = LocalForward::bind(spec).await?;
        let bind = forward.local_addr();
        let (host, host_port) = forward.destination();
        let forward_to = (host.to_string(), host_port);
        let carrier = Arc::new(ForwardCarrier::Quic(connection));
        Ok(Self {
            tunnel_id: ulid::Ulid::new().to_string(),
            bind,
            forward_to,
            task: tokio::spawn(forward.run(carrier)),
        })
    }

    /// The address actually bound — with a `0` listen port, the one the
    /// kernel picked.
    pub fn local_addr(&self) -> SocketAddr {
        self.bind
    }

    /// This forward as the `qsh.cli/v1` [`Tunnel`] DTO (`docs/CLI.md`
    /// §6.9). `host` is the peer alias, which only the `Ops` layer knows —
    /// the same `Ops`-filled-alias rule [`qsh_proto::Session::host`]
    /// follows (ADR-0007).
    pub fn tunnel(&self, host: &str) -> Tunnel {
        Tunnel {
            tunnel_id: self.tunnel_id.clone(),
            mode: "local".to_string(),
            // Result shape, not request shape: `bind` carries the bound
            // `host:port` so a fixed-port forward still reports where it
            // actually listens (`docs/CLI.md` §6.9).
            bind: self.bind.to_string(),
            // Canonical `host:port`, so an IPv6 destination is
            // `[::1]:5432` rather than the unsplittable `::1:5432` — the
            // same form the peer's `forward.local` ACL resource takes
            // (`qsh_proto::wire::format_host_port`).
            forward_to: format_host_port(&self.forward_to.0, self.forward_to.1),
            // Always the real bound port, whether or not the spec named
            // one. `docs/CLI.md` §6.9's own `Tunnel` example carries
            // `actual_port` for a fixed-port forward, and a reader that
            // has to fall back to splitting `bind` whenever the field is
            // absent is exactly the parsing this field exists to spare it
            // (and `bind` is the harder split, being a socket address).
            // Additive: the field's type and `Option`-ness are unchanged
            // — this side simply always fills it.
            actual_port: Some(u32::from(self.bind.port())),
            host: host.to_string(),
        }
    }

    /// Wait for the forward's listener to fail fatally.
    ///
    /// Only a *listener* error resolves this — one broken forwarded
    /// connection never does (`LocalForward::run`'s own doc) — so in
    /// practice a holder parks here until the process ends or the handle
    /// is dropped.
    pub async fn wait(&mut self) -> io::Error {
        match (&mut self.task).await {
            Ok(err) => err,
            Err(err) => io::Error::other(format!("local forward task ended: {err}")),
        }
    }
}

impl Drop for LocalForwardHandle {
    fn drop(&mut self) {
        // The listener and every in-flight connection task live inside the
        // aborted future (`LocalForward::run`'s `JoinSet`), so this is the
        // whole teardown — there is nothing else to release.
        self.task.abort();
    }
}

/// One accepted TCP connection's whole life: open the tunnel stream, read
/// the peer's verdict, then either splice or clean up.
///
/// The handshake is exactly `docs/design/protocol.md` §7's: a
/// `StreamHeader{TCP_CONNECT}` (written by [`crate::tunnel::open_stream`],
/// which also applies `PRIORITY_TUNNEL`), one `ConnectResult` back, and
/// from there raw bytes with no framing at all.
async fn forward_connection(
    tcp: TcpStream,
    carrier: &ForwardCarrier,
    host: &str,
    port: u16,
) -> Result<SpliceStats, ForwardConnError> {
    let header = StreamHeader {
        kind: StreamKind::TcpConnect as i32,
        // §7: `TCP_CONNECT` is the sole stream kind that carries no
        // ticket — the peer authorizes it inline instead.
        ticket: Vec::new(),
        host: host.to_string(),
        port: u32::from(port),
    };
    let link = carrier.link();
    let (send, mut recv, kill) = match crate::tunnel::open_stream(&link, &header).await {
        Ok(opened) => opened,
        Err(err) => return Err(abort_local(tcp, err.into())),
    };

    let result: ConnectResult = match recv.recv().await {
        Ok(Some(result)) => result,
        Ok(None) => {
            kill.kill();
            return Err(abort_local(tcp, ForwardConnError::NoConnectResult));
        }
        Err(err) => {
            kill.kill();
            return Err(abort_local(tcp, err.into()));
        }
    };
    if !result.ok {
        kill.kill();
        return Err(abort_local(
            tcp,
            ForwardConnError::Refused {
                // Sanitized at construction — the peer authored these and
                // they end up in this side's diagnostics, possibly on a
                // raw-mode terminal (`ForwardConnError::Refused`'s doc).
                code: sanitize_peer_text(&result.code),
                message: sanitize_peer_text(&result.message),
            },
        ));
    }

    // Past `ConnectResult{ok:true}` the stream is a raw byte pipe (§5, §7):
    // hand both halves to the splice, along with any payload the peer
    // already pipelined behind the `ConnectResult` frame — which
    // `into_raw_quic` returns and the splice must write first.
    let (Ok(raw_send), Ok((raw_recv, residue))) = (send.into_raw_quic(), recv.into_raw_quic())
    else {
        kill.kill();
        return Err(abort_local(tcp, ForwardConnError::CarrierNotRaw));
    };
    Ok(splice_tcp_quic(tcp, raw_send, raw_recv, residue).await?)
}

/// End an accepted local connection the way a *failed* tunnel must end it,
/// and hand `err` straight back so callers stay one-liners.
///
/// One discipline for **every** handshake failure — a tunnel stream that
/// would not open, a `ConnectResult` that never arrived, a refusal, a
/// carrier that cannot surrender a raw pipe: close with `SO_LINGER 0`, so
/// the close is an RST rather than a FIN. A plain FIN tells the local
/// application "connected fine, no data", which it cannot tell apart from
/// a successful empty response — and on every path through here the
/// destination was never reached at all, or the transfer was truncated.
/// An RST surfaces as a connection error, which is the truth. Same reason
/// [`crate::tunnel::splice`] resets rather than closes a truncated splice.
fn abort_local(tcp: TcpStream, err: ForwardConnError) -> ForwardConnError {
    let _ = tcp.set_zero_linger();
    drop(tcp);
    err
}

/// Whether `spec`'s `[bind:]` is one this module would bind, decided
/// without creating anything.
///
/// The frontend pre-flight ([`crate::ops::parse_local_forwards`]) calls
/// this so `-L 0.0.0.0:8080:host:port` fails before a session exists,
/// rather than after one is already running. It is the *same* function
/// [`LocalForward::bind`] uses, not a copy of its rule.
pub(crate) fn check_bind(spec: &ForwardSpec) -> Result<(), LocalForwardError> {
    loopback_bind_addr(spec.bind.as_deref(), spec.listen_port).map(|_| ())
}

/// Resolve a `-L` spec's `[bind:]` to the loopback socket address to bind,
/// refusing anything that is not loopback (this module's own doc, `PLAN.md`
/// M4 §4.1 #3).
///
/// Loopback-ness is decided by *address classification*
/// ([`IpAddr::is_loopback`]), never by string comparison, so neither
/// `127.0.0.7` nor `[::1]` nor a decimal-mangled `2130706433` can be
/// mistaken for a non-loopback address or vice versa. `localhost` is the
/// one name accepted, and it is mapped to `127.0.0.1` here rather than
/// resolved — a resolver that returned something else for it (a doctored
/// `/etc/hosts`) would otherwise decide where this port listens.
fn loopback_bind_addr(bind: Option<&str>, port: u16) -> Result<SocketAddr, LocalForwardError> {
    let Some(bind) = bind else {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    };
    if bind.eq_ignore_ascii_case("localhost") {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    match bind.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => Ok(SocketAddr::new(ip, port)),
        Ok(_) => Err(LocalForwardError::Bind(format!(
            "local forward bind {bind:?} is not a loopback address; \
             -L listeners are loopback-only"
        ))),
        Err(_) => Err(LocalForwardError::Bind(format!(
            "local forward bind {bind:?} is not an IP address or \"localhost\"; \
             -L listeners are loopback-only"
        ))),
    }
}

/// How long [`LocalForward::run`] pauses after a resource-exhaustion
/// `accept()` failure before trying again.
///
/// Not a retry policy — the smallest pause that keeps a *persistent*
/// `EMFILE`/`ENOBUFS` from turning the accept loop into a busy spin that
/// burns a core and floods the log. Short enough that a momentary
/// exhaustion (another task closing an fd) costs one stall nobody notices,
/// long enough that a sustained one costs ~20 attempts a second instead of
/// millions.
pub(crate) const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Errnos that mean "this `accept()` ran out of a resource", for the ones
/// with no stable [`io::ErrorKind`] to match on yet (`EMFILE`, `ENFILE`,
/// `ENOBUFS` all land in `ErrorKind::Uncategorized`). The listener is
/// unharmed by every one of them — the *process* or the kernel is
/// momentarily out of descriptors or buffers — so they are retried behind
/// [`ACCEPT_BACKOFF`], never fatal.
#[cfg(unix)]
const ACCEPT_EXHAUSTION_ERRNOS: &[i32] = &[libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
/// Winsock's twins of the above (`WSAEMFILE`, `WSAENOBUFS`): `accept()`
/// reports these as `10024`/`10055`, not as C errnos, so the `libc`
/// constants above would never match on this platform.
#[cfg(windows)]
const ACCEPT_EXHAUSTION_ERRNOS: &[i32] = &[10024, 10055];
#[cfg(not(any(unix, windows)))]
const ACCEPT_EXHAUSTION_ERRNOS: &[i32] = &[];

/// Errnos that describe the *pending connection*, not the listener.
///
/// Linux hands already-pending network errors on the incoming socket back
/// out of `accept()` itself, which `accept(2)` calls out as differing from
/// other BSD implementations: "For reliable operation the application
/// should detect the network errors defined for the protocol after
/// `accept()` and treat them like `EAGAIN` by retrying." Without this set
/// they fall through to [`AcceptDisposition::Fatal`], so one unreachable
/// client could take the operator's whole `-L` forward down — exactly the
/// failure mode the accept loop exists to prevent (`PLAN.md` M4 Step 3:
/// one failed connection must not abort the accept loop).
///
/// Classified as [`AcceptDisposition::Backoff`] rather than `Retry`: the
/// man page's advice is to retry, but a *persistent* `ENETDOWN` retried
/// flat out would spin a core, and paying [`ACCEPT_BACKOFF`] before the
/// next connection is not a cost anyone can measure.
#[cfg(target_os = "linux")]
const ACCEPT_PER_CONNECTION_ERRNOS: &[i32] = &[
    libc::ENETDOWN,
    libc::EPROTO,
    libc::ENOPROTOOPT,
    libc::EHOSTDOWN,
    libc::ENONET,
    libc::EHOSTUNREACH,
    libc::EOPNOTSUPP,
    libc::ENETUNREACH,
];
/// Empty off Linux: this pass-the-pending-error-through behavior is the
/// Linux-specific deviation `accept(2)` documents, and `ENONET` does not
/// exist elsewhere. Other platforms report these on the connection itself,
/// where the splice already handles them.
#[cfg(not(target_os = "linux"))]
const ACCEPT_PER_CONNECTION_ERRNOS: &[i32] = &[];

/// What one failed `accept()` means for the forward as a whole.
///
/// The distinction the `-L` contract rests on (`PLAN.md` M4 Step 3: one
/// failed connection must not abort the accept loop): almost every
/// `accept()` error is about a single pending connection or a momentary
/// shortage, and treating those as fatal would let any local client take
/// the operator's whole forward down.
///
/// `pub(crate)`: [`crate::tunnel::remote`]'s host-side accept loop
/// (`PLAN.md` M4 Step 4) reuses this table verbatim rather than
/// duplicating it — a `-R` listener owes the exact same liveness
/// discipline as a `-L` listener, and there is only one place that logic
/// should be able to drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptDisposition {
    /// One pending connection died on the way in, or a signal interrupted
    /// the syscall. The listener never noticed — retry immediately.
    Retry,
    /// This `accept()` ran out of descriptors or buffers. The listener is
    /// still fine and the next attempt may well succeed, but retrying flat
    /// out would spin, so pause for [`ACCEPT_BACKOFF`] first.
    Backoff,
    /// The listener itself is unusable. This, and only this, ends the
    /// forward.
    Fatal,
}

/// Classify an `accept()` failure — see [`AcceptDisposition`].
pub(crate) fn accept_disposition(err: &io::Error) -> AcceptDisposition {
    match err.kind() {
        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted => {
            return AcceptDisposition::Retry;
        }
        // `ENOMEM` is the one exhaustion errno with a stable `ErrorKind`.
        io::ErrorKind::OutOfMemory => return AcceptDisposition::Backoff,
        _ => {}
    }
    match err.raw_os_error() {
        Some(code) if ACCEPT_EXHAUSTION_ERRNOS.contains(&code) => AcceptDisposition::Backoff,
        Some(code) if ACCEPT_PER_CONNECTION_ERRNOS.contains(&code) => AcceptDisposition::Backoff,
        _ => AcceptDisposition::Fatal,
    }
}

#[cfg(test)]
mod tests {
    use qsh_proto::wire::{ForwardDirection, parse_forward_spec};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::tunnel::testutil::loopback_pair;

    /// Build a `-L` spec directly rather than through
    /// [`parse_forward_spec`], because the parser's grammar rejects listen
    /// port 0 (`1..=65535`, settled in M4 Step 1) while
    /// `docs/design/testing.md`'s CI rule requires tests to bind port 0.
    /// [`LocalForward`] takes a [`ForwardSpec`], not a spec string, so a
    /// test can express what the CLI grammar cannot.
    fn local_spec(bind: Option<&str>, listen_port: u16, host: &str, host_port: u16) -> ForwardSpec {
        ForwardSpec {
            direction: ForwardDirection::Local,
            bind: bind.map(str::to_string),
            listen_port,
            host: host.to_string(),
            host_port,
        }
    }

    /// The port-0 loopback spec every splice test below binds.
    fn ephemeral_spec() -> ForwardSpec {
        local_spec(None, 0, "db.internal", 5432)
    }

    /// The parser and this module agree on where a real `-L` string binds:
    /// a parsed spec's `bind` flows into [`loopback_bind_addr`] unchanged.
    #[test]
    fn a_parsed_spec_binds_the_address_it_names() {
        let spec = parse_forward_spec("127.0.0.1:8080:db.internal:5432").unwrap();
        assert_eq!(spec.direction, ForwardDirection::Local);
        let addr = loopback_bind_addr(spec.bind.as_deref(), spec.listen_port).unwrap();
        assert_eq!(addr, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
    }

    // ---- bind policy (§4.1 #3) ------------------------------------------

    #[test]
    fn bind_defaults_to_ipv4_loopback_when_the_spec_has_no_bind() {
        let addr = loopback_bind_addr(None, 8080).unwrap();
        assert_eq!(addr, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn bind_accepts_every_loopback_spelling() {
        for (bind, expected) in [
            ("localhost", "127.0.0.1:1:"),
            ("LocalHost", "127.0.0.1:1:"),
            ("127.0.0.1", "127.0.0.1:1:"),
            // Not `127.0.0.1`: loopback is the whole 127/8 block, which a
            // string comparison against "127.0.0.1" would get wrong.
            ("127.0.0.7", "127.0.0.7:1:"),
            ("::1", "[::1]:1:"),
        ] {
            let addr = loopback_bind_addr(Some(bind), 1).unwrap();
            assert!(addr.ip().is_loopback(), "{bind} must classify as loopback");
            assert_eq!(
                format!("{addr}:"),
                expected,
                "{bind} must bind the address it names"
            );
        }
    }

    /// The security property of §4.1 #3: a `-L` listener is never exposed
    /// off this machine, and the refusal happens *before* any listener
    /// exists (`bind` returns `Err` without touching the network).
    #[tokio::test]
    async fn non_loopback_bind_is_refused_and_binds_nothing() {
        for bind in [
            "0.0.0.0",
            "::",
            "192.168.1.10",
            "8.8.8.8",
            // A name, not an address — never resolved, since a resolver
            // answer would otherwise pick the interface.
            "example.com",
            "*",
        ] {
            let err =
                loopback_bind_addr(Some(bind), 0).expect_err("non-loopback bind must be refused");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{bind}");

            let refused = LocalForward::bind(&local_spec(Some(bind), 0, "example.test", 80))
                .await
                .expect_err("bind must refuse before listening");
            assert_eq!(refused.code(), ErrorCode::InvalidArgument, "{bind}");
        }
    }

    #[tokio::test]
    async fn bind_reports_the_real_port_for_a_port_zero_spec() {
        let forward = LocalForward::bind(&ephemeral_spec()).await.unwrap();
        assert!(forward.local_addr().ip().is_loopback());
        assert_ne!(forward.local_addr().port(), 0, "port 0 must resolve");
        assert_eq!(forward.destination(), ("db.internal", 5432));
    }

    // ---- the `Tunnel` DTO (`docs/CLI.md` §6.9) ---------------------------

    /// `actual_port` reports the port actually bound, **including** when
    /// the spec named it — which is what §6.9's own `Tunnel` example
    /// shows. Reporting it only for a `0` request would leave every
    /// fixed-port reader re-splitting `bind` (a socket address, so the
    /// harder split of the two) to learn the same number.
    #[tokio::test]
    async fn the_tunnel_dto_reports_the_bound_port_for_a_fixed_port_spec() {
        // A port the kernel just handed out and released: fixed from the
        // spec's point of view, never a literal (`docs/design/testing.md`'s
        // CI rule).
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let (client_conn, host_conn) = loopback_pair().await;
        let handle =
            LocalForwardHandle::start(&local_spec(None, port, "db.internal", 5432), client_conn)
                .await
                .unwrap();

        assert_eq!(
            handle.local_addr().port(),
            port,
            "the spec's fixed port was granted as asked"
        );
        let dto = handle.tunnel("box");
        assert_eq!(
            dto.actual_port,
            Some(u32::from(port)),
            "a fixed-port forward still reports the port it bound"
        );
        assert_eq!(dto.bind, format!("127.0.0.1:{port}"));
        assert_eq!(dto.forward_to, "db.internal:5432");
        assert_eq!(dto.mode, "local");
        assert_eq!(dto.host, "box");

        drop(handle);
        drop(host_conn);
    }

    /// `forward_to` is the canonical `host:port`, so an IPv6 destination
    /// is bracketed — `parse_forward_spec` strips the brackets off
    /// `[::1]`, and plain concatenation would emit the unsplittable
    /// `::1:5432` (the same form the peer's `forward.local` ACL resource
    /// takes).
    #[tokio::test]
    async fn the_tunnel_dto_brackets_an_ipv6_destination() {
        let (client_conn, host_conn) = loopback_pair().await;
        let handle = LocalForwardHandle::start(&local_spec(None, 0, "::1", 5432), client_conn)
            .await
            .unwrap();

        assert_eq!(handle.tunnel("box").forward_to, "[::1]:5432");

        drop(handle);
        drop(host_conn);
    }

    // ---- accept-error classification (Step 3: one bad accept must not
    //      end the forward) --------------------------------------------

    /// The `-L` contract's liveness half: only a dead *listener* ends a
    /// forward. A connection that died on the way in is retried at once;
    /// running out of descriptors or buffers is retried behind
    /// [`ACCEPT_BACKOFF`] so a persistent `EMFILE` cannot spin the loop;
    /// and everything else — the listener itself being unusable — is the
    /// one thing that stops accepting.
    #[test]
    fn accept_errors_are_classified_so_one_bad_accept_never_ends_the_forward() {
        use io::ErrorKind;

        for kind in [ErrorKind::ConnectionAborted, ErrorKind::Interrupted] {
            assert_eq!(
                accept_disposition(&io::Error::from(kind)),
                AcceptDisposition::Retry,
                "{kind:?} is about one pending connection, not the listener"
            );
        }

        assert!(
            !ACCEPT_EXHAUSTION_ERRNOS.is_empty(),
            "this platform must name its exhaustion errnos, or the loop \
             treats a recoverable EMFILE as a dead listener"
        );
        for code in ACCEPT_EXHAUSTION_ERRNOS {
            assert_eq!(
                accept_disposition(&io::Error::from_raw_os_error(*code)),
                AcceptDisposition::Backoff,
                "errno {code} exhausts a resource; the listener survives it"
            );
        }
        assert_eq!(
            accept_disposition(&io::Error::from(ErrorKind::OutOfMemory)),
            AcceptDisposition::Backoff
        );

        // Linux passes a pending connection's own network error back out
        // of `accept()`; `accept(2)` says to treat those like `EAGAIN`.
        // Left unclassified they land in the `Fatal` catch-all below, so
        // one unreachable client would end the whole forward.
        for code in ACCEPT_PER_CONNECTION_ERRNOS {
            assert_eq!(
                accept_disposition(&io::Error::from_raw_os_error(*code)),
                AcceptDisposition::Backoff,
                "errno {code} describes the pending connection, not the listener"
            );
        }

        for kind in [
            ErrorKind::InvalidInput,
            ErrorKind::PermissionDenied,
            ErrorKind::NotConnected,
            ErrorKind::Other,
        ] {
            assert_eq!(
                accept_disposition(&io::Error::from(kind)),
                AcceptDisposition::Fatal,
                "{kind:?} says the listener is unusable"
            );
        }
    }

    // ---- the requester leg end to end ------------------------------------

    /// Stand in for the host side of `docs/design/protocol.md` §7 over a
    /// real QUIC connection: accept one tunnel stream, assert the header
    /// is a ticket-less `TCP_CONNECT` for the expected destination, answer
    /// `ConnectResult`, and — when allowed — echo raw bytes back with
    /// `pipelined` prepended *in the same write as the `ConnectResult`*,
    /// which is what forces the client's framed reader to buffer payload
    /// past the handshake frame.
    ///
    /// Takes a **clone** of the connection: `qsh_transport::Connection` is
    /// a handle whose last drop closes the whole QUIC connection with
    /// application code 0, which would tear down stream data still in
    /// flight the moment this helper returned.
    async fn fake_host(
        conn: qsh_transport::Connection,
        allow: bool,
        pipelined: &'static [u8],
    ) -> StreamHeader {
        let (send, recv) = conn.accept_bi().await.unwrap();
        let mut framed = qsh_transport::FramedStream::data(send, recv);
        let header: StreamHeader = framed.recv.recv().await.unwrap().expect("header");
        assert_eq!(header.stream_kind(), Some(StreamKind::TcpConnect));
        assert!(
            header.ticket.is_empty(),
            "§7: TCP_CONNECT carries no ticket"
        );

        if !allow {
            framed
                .send
                .send(&ConnectResult {
                    ok: false,
                    code: ErrorCode::PermissionDenied.as_str().to_string(),
                    message: "denied".into(),
                })
                .await
                .unwrap();
            let _ = framed.send.finish();
            return header;
        }

        framed
            .send
            .send(&ConnectResult {
                ok: true,
                code: String::new(),
                message: String::new(),
            })
            .await
            .unwrap();
        let (send, recv) = framed.split();
        let mut raw_send = send.into_raw();
        let (mut raw_recv, residue) = recv.into_raw();
        assert!(
            residue.is_empty(),
            "client sends nothing before the verdict"
        );
        if !pipelined.is_empty() {
            raw_send.write_all(pipelined).await.unwrap();
        }
        // Echo until the client half-closes, then half-close back.
        let mut buf = [0u8; 256];
        loop {
            // `quinn::RecvStream` has its own inherent `read` returning
            // `Option<usize>` (`None` == FIN), which shadows
            // `AsyncReadExt::read` here.
            match raw_recv.read(&mut buf).await.unwrap() {
                None => break,
                Some(n) => raw_send.write_all(&buf[..n]).await.unwrap(),
            }
        }
        raw_send.finish().unwrap();
        header
    }

    /// The whole requester leg: a connection to the bound loopback port
    /// becomes a `TCP_CONNECT` for the spec's destination, and after
    /// `ConnectResult{ok:true}` the socket is a transparent byte pipe —
    /// including the bytes the peer pipelined behind the handshake frame,
    /// which arrive **first and exactly once** (the residue transition
    /// `FramedRecv::into_raw` exists for; without it this test loses
    /// `"ahead-"`).
    #[tokio::test]
    async fn allowed_connection_splices_raw_bytes_and_delivers_handshake_residue_first() {
        let (client_conn, host_conn) = loopback_pair().await;
        let host = tokio::spawn(fake_host(host_conn.clone(), true, b"ahead-"));

        let forward = LocalForward::bind(&ephemeral_spec()).await.unwrap();
        let addr = forward.local_addr();
        let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"ping").await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut got = Vec::new();
        tcp.read_to_end(&mut got).await.unwrap();
        assert_eq!(
            got, b"ahead-ping",
            "residue must lead the stream, then the echoed payload"
        );

        let header = host.await.unwrap();
        assert_eq!(header.host, "db.internal");
        assert_eq!(header.port, 5432);
        runner.abort();
        drop(host_conn);
    }

    /// A refused connection (the peer's inline `forward.local` denial) must
    /// not leak the accepted socket and must not take the forward down:
    /// the local client sees the connection fail, and the *next*
    /// connection is still served.
    #[tokio::test]
    async fn refused_connection_closes_the_local_socket_and_the_forward_keeps_serving() {
        let (client_conn, host_conn) = loopback_pair().await;
        let deny = tokio::spawn(fake_host(host_conn.clone(), false, b""));

        let forward = LocalForward::bind(&ephemeral_spec()).await.unwrap();
        let addr = forward.local_addr();
        let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let mut got = Vec::new();
        // Either an RST (`ConnectionReset`) or a bare EOF is a closed
        // socket; what must never happen is data arriving from a
        // destination that was never dialed.
        match tcp.read_to_end(&mut got).await {
            Ok(_) => assert!(got.is_empty(), "a refused forward must carry no payload"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::ConnectionReset),
        }
        deny.await.unwrap();

        // Same forward, second connection — now allowed, and it works.
        let allow = tokio::spawn(fake_host(host_conn.clone(), true, b""));
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"second").await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut got = Vec::new();
        tcp.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"second", "one refusal must not end the forward");
        allow.await.unwrap();
        runner.abort();
        drop(host_conn);
    }
}
