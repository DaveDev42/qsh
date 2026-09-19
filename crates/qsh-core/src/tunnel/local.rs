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
use quinn::{RecvStream, SendStream};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use crate::client::ClientError;
use crate::client::link::DataLink;
use crate::tunnel::dial::DialPolicy;
#[cfg(unix)]
use crate::tunnel::splice::splice_tcp_uds;
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
    /// `-L over reverse`, `PLAN.md` M4 Step 5 (a): each forwarded
    /// connection opens its own `TCP_CONNECT` over a fresh `LOCAL_STREAM`
    /// conduit, and past `ConnectResult{ok:true}` splices raw bytes with
    /// [`crate::tunnel::splice::splice_tcp_uds`] — the reverse carrier's
    /// counterpart to [`ForwardCarrier::Quic`]'s `splice_tcp_quic`.
    ///
    /// Constructing and splicing over this variant is complete as of this
    /// stage (`PLAN.md` M4 Step 5 (a)) — only its *call site* is not: the
    /// interactive `-L`/standalone `tunnel_open` entry points still always
    /// pick [`ForwardCarrier::Quic`], deciding the route is `ops`'s job
    /// (`PLAN.md` M4 Step 5 PR 5b), not this module's.
    #[cfg(unix)]
    #[allow(dead_code)] // wired up by PR 5b's route-aware `Ops` entry points
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
    /// The carrier cannot surrender the raw byte pipe [`forward_connection`]
    /// expected for it. Not reachable in practice — `carrier`'s variant and
    /// `carrier.link()`'s variant always agree, so the matching
    /// `into_raw_quic`/`into_raw_local` call always succeeds — but kept as
    /// a real, reported variant rather than `unreachable!()` so a future
    /// carrier this splice does not yet know how to pump fails loudly
    /// instead of panicking a live connection's task.
    #[error("this tunnel carrier cannot surrender a raw byte pipe")]
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
        let addr = loopback_bind_addr(spec.bind.as_deref(), spec.listen_port, "-L")?;
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
        Self::start_with_carrier(spec, ForwardCarrier::Quic(connection)).await
    }

    /// [`Self::start`]'s reverse-route sibling, `-L over reverse`
    /// (`PLAN.md` M4 Step 5 (a)): each connection accepted on this
    /// forward's listener relays through `socket_path` (this machine's
    /// resident `qsh listen` daemon's UDS socket) to `host`'s live reverse
    /// registration, instead of dialing a QUIC connection directly. See
    /// `ForwardCarrier::Local`'s own doc for the wire shape this opens
    /// per connection.
    ///
    /// `pub`, not `pub(crate)` — the same Stage D widening
    /// `crate::tunnel::RemoteForwardAcceptor::spawn_reverse` already
    /// got: `crates/qsh-testkit/tests/reverse_tunnel.rs` (L3, Step 5 (a))
    /// drives the real `-L over reverse` requester leg end to end rather
    /// than re-implementing it, which needs this callable from outside
    /// `qsh-core`. `Ops`'s route-aware entry point (PR 5b) is still the
    /// only *production* caller.
    #[cfg(unix)]
    pub async fn start_reverse(
        spec: &ForwardSpec,
        socket_path: std::path::PathBuf,
        host: String,
    ) -> Result<Self, LocalForwardError> {
        Self::start_with_carrier(
            spec,
            ForwardCarrier::Local {
                socket: socket_path,
                host,
            },
        )
        .await
    }

    async fn start_with_carrier(
        spec: &ForwardSpec,
        carrier: ForwardCarrier,
    ) -> Result<Self, LocalForwardError> {
        let forward = LocalForward::bind(spec).await?;
        let bind = forward.local_addr();
        let (host, host_port) = forward.destination();
        let forward_to = (host.to_string(), host_port);
        let carrier = Arc::new(carrier);
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

/// A tunnel stream past its `ConnectResult{ok:true}` handshake: a raw byte
/// pipe on whichever carrier [`open_tunnel`] actually opened it on, plus any
/// payload the peer already pipelined behind the handshake frame (the
/// `residue` [`splice_opened`] must write first — same requirement
/// `splice_tcp_quic`'s own doc states).
///
/// Split out of the old single-shot `forward_connection` (ADR-0019 decision
/// 9) so a `-D` SOCKS driver can hold the local TCP connection open across
/// its own handshake (reading the SOCKS request, writing the `REP`) between
/// [`open_tunnel`] returning and [`splice_opened`] being called — `-L` still
/// calls the two back to back with nothing in between, so its behavior is
/// unchanged.
pub(crate) enum OpenedTunnel {
    /// Opened on [`ForwardCarrier::Quic`].
    Quic {
        send: SendStream,
        recv: RecvStream,
        residue: Vec<u8>,
    },
    /// Opened on [`ForwardCarrier::Local`].
    #[cfg(unix)]
    Local {
        send: crate::localctl::client::RawUdsWrite,
        recv: crate::localctl::client::RawUdsRead,
        residue: Vec<u8>,
    },
}

/// Open one tunnel stream on `carrier` for `host:port` and wait for the
/// peer's verdict — everything up to, but not including, the raw byte
/// splice.
///
/// The handshake is exactly `docs/design/protocol.md` §7's:
/// `StreamHeader{TCP_CONNECT}` (written by [`crate::tunnel::open_stream`],
/// which also applies `PRIORITY_TUNNEL`) out, one `ConnectResult` back. On
/// `ConnectResult{ok:true}` this converts the framed stream to the raw halves
/// [`splice_opened`] needs; on anything else it reports [`ForwardConnError`]
/// and leaves the caller's `tcp` connection untouched — callers that need
/// `-L`'s always-RST cleanup do that themselves (`abort_local`), and callers
/// that owe the local peer a SOCKS `REP` first (`-D`) get the chance to send
/// one before closing anything.
///
/// `policy.deny_host_local` becomes `StreamHeader.deny_host_local` verbatim
/// (ADR-0019 decision 3) — `-L` always passes
/// [`DialPolicy::default`]-equivalent `false` (operator-chosen destination,
/// not attacker-steered content behind a proxy), `-D` always passes `true`.
pub(crate) async fn open_tunnel(
    carrier: &ForwardCarrier,
    host: &str,
    port: u16,
    policy: DialPolicy,
) -> Result<OpenedTunnel, ForwardConnError> {
    let header = StreamHeader {
        kind: StreamKind::TcpConnect as i32,
        // §7: `TCP_CONNECT` is the sole stream kind that carries no
        // ticket — the peer authorizes it inline instead.
        ticket: Vec::new(),
        host: host.to_string(),
        port: u32::from(port),
        deny_host_local: policy.deny_host_local,
    };
    let link = carrier.link();
    let (send, mut recv, kill) = crate::tunnel::open_stream(&link, &header).await?;

    let result: ConnectResult = match recv.recv().await {
        Ok(Some(result)) => result,
        Ok(None) => {
            kill.kill();
            return Err(ForwardConnError::NoConnectResult);
        }
        Err(err) => {
            kill.kill();
            return Err(err.into());
        }
    };
    if !result.ok {
        kill.kill();
        return Err(ForwardConnError::Refused {
            // Sanitized at construction — the peer authored these and
            // they end up in this side's diagnostics, possibly on a
            // raw-mode terminal (`ForwardConnError::Refused`'s doc).
            code: sanitize_peer_text(&result.code),
            message: sanitize_peer_text(&result.message),
        });
    }

    // Past `ConnectResult{ok:true}` the stream is a raw byte pipe (§5, §7):
    // convert both halves to whichever raw carrier this connection actually
    // opened its stream on — `carrier`'s own variant decides which raw
    // conversion must succeed, so the two always agree; the `CarrierNotRaw`
    // arm exists only as a defensive fallback (`ForwardConnError::
    // CarrierNotRaw`'s own doc), never a reachable outcome.
    match carrier {
        ForwardCarrier::Quic(_) => {
            let (Ok(send), Ok((recv, residue))) = (send.into_raw_quic(), recv.into_raw_quic())
            else {
                kill.kill();
                return Err(ForwardConnError::CarrierNotRaw);
            };
            Ok(OpenedTunnel::Quic {
                send,
                recv,
                residue,
            })
        }
        #[cfg(unix)]
        ForwardCarrier::Local { .. } => {
            let (Ok(send), Ok((recv, residue))) = (send.into_raw_local(), recv.into_raw_local())
            else {
                kill.kill();
                return Err(ForwardConnError::CarrierNotRaw);
            };
            Ok(OpenedTunnel::Local {
                send,
                recv,
                residue,
            })
        }
    }
}

/// Splice `tcp` against `opened`'s raw carrier until both directions end —
/// [`open_tunnel`]'s other half. Any payload the peer pipelined behind the
/// `ConnectResult` (`opened`'s `residue`) is written to `tcp` first (module
/// docs).
pub(crate) async fn splice_opened(
    tcp: TcpStream,
    opened: OpenedTunnel,
) -> Result<SpliceStats, ForwardConnError> {
    match opened {
        OpenedTunnel::Quic {
            send,
            recv,
            residue,
        } => Ok(splice_tcp_quic(tcp, send, recv, residue).await?),
        #[cfg(unix)]
        OpenedTunnel::Local {
            send,
            recv,
            residue,
        } => Ok(splice_tcp_uds(tcp, send, recv, residue).await?),
    }
}

/// One accepted TCP connection's whole life for `-L`: open the tunnel
/// stream, read the peer's verdict, then either splice or clean up.
///
/// The two-step split ([`open_tunnel`] then [`splice_opened`]) exists for
/// `-D` (ADR-0019 decision 9); `-L` has no handshake of its own to interleave
/// between them, so this just calls both in sequence with its existing
/// [`abort_local`] discipline — behavior identical to before the split.
async fn forward_connection(
    tcp: TcpStream,
    carrier: &ForwardCarrier,
    host: &str,
    port: u16,
) -> Result<SpliceStats, ForwardConnError> {
    // `-L`'s destination is operator-chosen, not attacker-steered content
    // behind a proxy (ADR-0019's threat model) — unfiltered, today's
    // behavior, same as every host predating this field.
    let policy = DialPolicy {
        deny_host_local: false,
    };
    let opened = match open_tunnel(carrier, host, port, policy).await {
        Ok(opened) => opened,
        Err(err) => return Err(abort_local(tcp, err)),
    };
    splice_opened(tcp, opened).await
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
    loopback_bind_addr(spec.bind.as_deref(), spec.listen_port, "-L").map(|_| ())
}

/// Resolve a `[bind:]` to the loopback socket address to bind, refusing
/// anything that is not loopback (this module's own doc, `PLAN.md` M4 §4.1
/// #3; ADR-0019 decision 9 reuses this verbatim for `-D`).
///
/// Loopback-ness is decided by *address classification*
/// ([`IpAddr::is_loopback`]), never by string comparison, so neither
/// `127.0.0.7` nor `[::1]` nor a decimal-mangled `2130706433` can be
/// mistaken for a non-loopback address or vice versa. `localhost` is the
/// one name accepted, and it is mapped to `127.0.0.1` here rather than
/// resolved — a resolver that returned something else for it (a doctored
/// `/etc/hosts`) would otherwise decide where this port listens.
///
/// `flag` names the actual caller (`"-L"` or `"-D"`) in the refusal text —
/// ADR-0019 decision 9: "오류 문면은 '-L listeners'가 아니라 실제 flag
/// 이름을 댄다", so a `-D` caller's listener is never described as a `-L`
/// listener. The noun phrase leading the message stays `-L`'s original,
/// byte-identical text (`"local forward bind ..."`, predating `-D`); only
/// the trailing `"{flag} listeners are loopback-only"` — and, for `-D`, the
/// noun itself — actually varies by caller.
pub(crate) fn loopback_bind_addr(
    bind: Option<&str>,
    port: u16,
    flag: &str,
) -> Result<SocketAddr, LocalForwardError> {
    let noun = match flag {
        "-D" => "dynamic forward",
        _ => "local forward",
    };
    let Some(bind) = bind else {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    };
    if bind.eq_ignore_ascii_case("localhost") {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    match bind.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => Ok(SocketAddr::new(ip, port)),
        Ok(_) => Err(LocalForwardError::Bind(format!(
            "{noun} bind {bind:?} is not a loopback address; \
             {flag} listeners are loopback-only"
        ))),
        Err(_) => Err(LocalForwardError::Bind(format!(
            "{noun} bind {bind:?} is not an IP address or \"localhost\"; \
             {flag} listeners are loopback-only"
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
mod tests;
