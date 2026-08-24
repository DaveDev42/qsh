//! The host side of a remote forward, `-R [bind:]rport:host:hport`
//! (`PLAN.md` M4 Step 4, `docs/design/protocol.md` §7, §9).
//!
//! **Stage A** landed the contract surface only:
//! [`resolve_loopback_bind_addr`], the classification a
//! `RemoteForwardOpen`'s `bind_host` is put through **after** the
//! `forward.remote` ACL check and **before** any listener is bound
//! (`PLAN.md` §155 "loopback-only bind") — one resolution, whose validated
//! address is the one bound. **Stage B** (this addition) lands the rest:
//! [`RemoteForwardBinder`] (the bind seam a unit test instruments to prove
//! "bind 0" — the same seam shape as
//! [`crate::tunnel::dial::TunnelDialer`]), and
//! [`serve_remote_forward`] (the accept loop that turns each inbound TCP
//! connection into a `TCP_ACCEPTED` stream back to the requester). The
//! choke point itself — `Authorizer::check` + audit, then this module's
//! loopback check, then the bind — lives on
//! [`crate::server::Server::authorize_and_bind_remote_forward`], mirroring
//! [`crate::server::Server::authorize_and_dial_tunnel`]'s shape exactly;
//! this module supplies the seams that function calls, not the ACL
//! decision itself (`docs/design/architecture.md` §6: the choke point is
//! `server::dispatch`'s territory).
//!
//! **Why loopback-only is not an ACL decision.** A principal can hold
//! `forward.remote` outright and still not get a non-loopback bind — that
//! is a request constraint the host enforces on *every* principal, not a
//! per-principal permission (`crate::acl::Action::ForwardRemote`'s own
//! doc). Concretely: the ACL check answers "may this principal open a
//! remote forward at all", the check in this module answers "is the
//! address it asked to bind one this host will ever bind for anyone" —
//! the second question has the same answer regardless of who is asking.
//! That is why a failure here reports [`qsh_proto::ErrorCode::InvalidArgument`]
//! (a bad request), never `PERMISSION_DENIED` (a bad principal).
//!
//! **`TCP_ACCEPTED` carries no handshake reply.** Unlike `TCP_CONNECT`
//! (`crate::tunnel::local`), the wire contract says a `TCP_ACCEPTED`
//! stream "carries no `ConnectResult`: it *is* the accepted leg, opened
//! only after the peer already knows the accept succeeded"
//! (`v1.proto`'s own comment on the message). So [`serve_remote_forward`]
//! never reads a reply off the stream it opens — it writes the
//! `StreamHeader` and immediately splices, which is simpler than
//! `crate::tunnel::local`'s requester leg, not an oversight.
//!
//! **Stage C** (this addition) lands the requester side of the same
//! step: [`RemoteForwardAcceptor`], the dispatcher that accepts the peer's
//! `TCP_ACCEPTED` streams and turns each into a dial to *this* side's own
//! local `forward_host:forward_port` — the mirror image of the host-side
//! accept loop above, one connection away. Driven from
//! [`crate::ops::Ops::session_attach`]'s `remote_forward_specs` handling,
//! the interactive `-R`'s entry point (and, on the standalone-op side, by
//! [`crate::ops::Ops::tunnel_open`]'s `"remote"` mode).
//!
//! **Unix-only.** Like `crate::tunnel::local`'s reverse carrier, this
//! module's listener/accept-loop leg is host-only infrastructure gated the
//! same way the rest of M4's host-side tunnel code is — see
//! `crates/qsh-core/Cargo.toml`'s platform split and `PLAN.md`'s own
//! Windows-leg notes for M4 Step 3/4 (compiles, does not run the
//! integration leg on Windows). [`RemoteForwardAcceptor`] is the
//! requester leg, not the host leg, and is **not** `cfg(unix)`-gated —
//! same reasoning as `crate::tunnel::local`'s own requester-side listener.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_proto::wire::{StreamHeader, StreamKind, sanitize_peer_text, valid_forward_id};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use crate::client::ClientError;
use crate::client::link::DataLink;
use crate::tunnel::dial::{SystemDialer, TunnelDialer};
use crate::tunnel::splice::{SpliceError, splice_tcp_quic};

// ---------------------------------------------------------------------
// Bind-host resolution: resolve once, validate that answer, bind it.
// ---------------------------------------------------------------------

/// Future returned by [`BindHostResolver::lookup`]. Boxed for the same
/// reason [`BindFuture`] is: the choke point holds the resolver as
/// `&dyn BindHostResolver` so a test can substitute a double whose
/// answers it chooses.
pub(crate) type LookupFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// "What addresses does this name have?" Nothing else — the resolver seam
/// [`resolve_loopback_bind_addr`] goes through, so a test can prove that a
/// `bind_host` is resolved **exactly once** per `RemoteForwardOpen` and
/// that the address bound is the address that was validated.
///
/// This seam exists for a security property, not for convenience. When
/// validation and binding each resolved the name on their own, a peer that
/// controls a DNS zone could answer loopback to the validating lookup and
/// a routable address to the binding one — round-robin or a one-second TTL
/// is enough, no host compromise required — and `bind_host` arrives
/// verbatim in the peer's `RemoteForwardOpen`. One lookup, one answer set,
/// one validated address closes that gap by construction.
pub(crate) trait BindHostResolver: Send + Sync {
    /// Resolve `host` to every address it names, each carrying `port`.
    fn lookup<'a>(&'a self, host: &'a str, port: u16) -> LookupFuture<'a>;
}

/// The one implementation that ships: the system resolver.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemResolver;

impl BindHostResolver for SystemResolver {
    fn lookup<'a>(&'a self, host: &'a str, port: u16) -> LookupFuture<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// A `bind_host` this host will not bind for anyone: it is not loopback,
/// or it named nothing at all.
///
/// One rejection for both cases on purpose. There is nothing to bind
/// either way, and the peer learns the same thing from each — folding them
/// together keeps the host's resolver behaviour (does this name exist? did
/// lookup time out?) out of a reply the peer can probe. The caller maps
/// this to [`qsh_proto::ErrorCode::InvalidArgument`], never
/// `PermissionDenied` (this module's own doc on why loopback-only is a
/// request constraint and not an ACL decision).
#[derive(Debug, Error)]
#[error("remote forward binds loopback only")]
pub(crate) struct NotLoopback;

/// Bound on how long resolving a peer-supplied `bind_host` may take
/// before [`resolve_loopback_bind_addr`] gives up and reports it as not
/// loopback, never `PermissionDenied` (this module's own doc on why).
///
/// This resolve runs inline on `RemoteForwardOpen`'s handling, which is
/// itself intercepted and awaited directly on the connection's single
/// serialized control-message loop
/// (`crate::server::Server::handle_rfwd_open`'s own doc explains why it
/// cannot be dispatched normally) — so every other control message on
/// that connection, unrelated tunnels and the session's own PTY I/O
/// included, waits behind this one resolve. Unbounded is not an option
/// here for the same structural reason
/// [`crate::tunnel::dial::TUNNEL_DIAL_TIMEOUT`]'s own doc gives for the
/// destination dial: a resolver that never answers — attacker-influenced
/// (a `bind_host` naming a zone the peer controls) or merely broken —
/// must not be able to park a connection's entire control plane on a
/// name it chose. Same value as `TUNNEL_DIAL_TIMEOUT`, kept as its own
/// constant because tuning one bound must not silently retune the other.
const BIND_HOST_RESOLVE_TIMEOUT: Duration = crate::tunnel::dial::TUNNEL_DIAL_TIMEOUT;

/// Resolve a peer-supplied `bind_host` and return the loopback
/// [`SocketAddr`] to bind — **the address bound is the address validated**.
///
/// Runs **after** the `forward.remote` ACL check and **before** any
/// listener exists (`crate::server::Server::authorize_and_bind_remote_forward`
/// is the one caller, and its own doc pins that order). `PLAN.md` M4
/// Step 4's "loopback-only bind", `docs/PRD.md` §9, M4 DoD 2.
///
/// # One resolution, by construction
///
/// The name is resolved once. That single answer set is what gets
/// validated, and the address returned comes out of it — there is no
/// second lookup between the check and the bind, so there is no window in
/// which the answer can change. This is not a hardening detail: `bind_host`
/// is peer-supplied, so a peer that controls a DNS zone would only need
/// short TTLs or round-robin to serve loopback to a validating lookup and
/// a routable address to a binding one. An authenticated-but-restricted
/// peer escalating to a non-loopback bind is exactly what DoD 2 exists to
/// prevent, so that is inside the threat model, not outside it.
///
/// # Every address, not just one
///
/// A name that resolves to more than one address — a multi-A/AAAA record,
/// a split-horizon resolver, `/etc/hosts` plus a real DNS answer — must be
/// loopback in **every** answer ([`all_loopback`]), not merely one. "Some
/// resolved address is loopback" is not a safety property: a name that
/// answers with both `127.0.0.1` and a public address would otherwise read
/// as loopback-safe while a bind could land on the public one. Requiring
/// the whole answer set is the only classification an attacker cannot
/// steer around by picking which address wins.
///
/// Two inputs never reach the resolver at all. The empty string is the
/// wire default for "no `bind:` prefix" (`RemoteForwardOpen.bind_host`,
/// `docs/design/protocol.md` §7) and binds `127.0.0.1` — the same default
/// `crate::tunnel::local::loopback_bind_addr` applies on the requester
/// side. An IP literal is classified by **address**, never by string
/// comparison, so the whole `127.0.0.0/8` block and `::1` pass while
/// `0.0.0.0`, `::` and every routable literal do not.
pub(crate) async fn resolve_loopback_bind_addr(
    resolver: &dyn BindHostResolver,
    bind_host: &str,
    port: u16,
) -> Result<SocketAddr, NotLoopback> {
    resolve_loopback_bind_addr_bounded(resolver, bind_host, port, BIND_HOST_RESOLVE_TIMEOUT).await
}

/// [`resolve_loopback_bind_addr`]'s real body, with the resolve bound
/// taken as a parameter rather than the [`BIND_HOST_RESOLVE_TIMEOUT`]
/// constant, so a test can prove the bound actually applies without
/// waiting out the production value — the same reason
/// [`crate::tunnel::dial::SystemDialer::with_timeout`] exists next to its
/// own default-timeout constructor.
async fn resolve_loopback_bind_addr_bounded(
    resolver: &dyn BindHostResolver,
    bind_host: &str,
    port: u16,
    resolve_timeout: Duration,
) -> Result<SocketAddr, NotLoopback> {
    if bind_host.is_empty() {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }

    if let Ok(ip) = bind_host.parse::<IpAddr>() {
        return if ip.is_loopback() {
            Ok(SocketAddr::new(ip, port))
        } else {
            Err(NotLoopback)
        };
    }

    // A name: one lookup, and nothing else ever resolves it again. Bound
    // so a resolver that never answers cannot park this connection's
    // control loop forever (`BIND_HOST_RESOLVE_TIMEOUT`'s own doc) — an
    // expiry is folded into the same `NotLoopback` a genuine resolve
    // failure gets, for the same "don't let a reply teach the peer about
    // host resolver behaviour" reason the error-fold below already
    // documents.
    let addrs = match tokio::time::timeout(resolve_timeout, resolver.lookup(bind_host, port)).await
    {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(err)) => {
            // The host name is peer-supplied text on its way to a log
            // line, so it is sanitized first — a raw `bind_host` could
            // carry escape sequences into an operator's terminal
            // (`qsh_proto::wire::sanitize_peer_text`'s own doc).
            tracing::debug!(
                bind_host = %sanitize_peer_text(bind_host),
                %err,
                "qsh::tunnel: remote-forward bind host did not resolve"
            );
            return Err(NotLoopback);
        }
        Err(_elapsed) => {
            tracing::debug!(
                bind_host = %sanitize_peer_text(bind_host),
                timeout_ms = resolve_timeout.as_millis() as u64,
                "qsh::tunnel: remote-forward bind host resolve timed out"
            );
            return Err(NotLoopback);
        }
    };

    if !all_loopback(addrs.iter().map(|addr| addr.ip())) {
        return Err(NotLoopback);
    }

    // One of the addresses that just satisfied `all_loopback` — not a
    // fresh answer, and (by that predicate) necessarily loopback.
    addrs.into_iter().next().ok_or(NotLoopback)
}

/// The fold at the center of [`resolve_loopback_bind_addr`]'s bypass
/// defense, pulled out on its own so the "every address, not just one"
/// rule is exercised as pure, synchronous logic — no resolver, no
/// network, no flakiness — leaving the resolving wrapper above with
/// nothing left to get wrong but plumbing. An empty set resolves to
/// `false`: no addresses means nothing was actually certified loopback,
/// so it must not default to permissive.
fn all_loopback(addrs: impl IntoIterator<Item = IpAddr>) -> bool {
    let mut saw_any = false;
    for addr in addrs {
        saw_any = true;
        if !addr.is_loopback() {
            return false;
        }
    }
    saw_any
}

// ---------------------------------------------------------------------
// Stage B: the bind seam, address resolution, and the accept loop.
// ---------------------------------------------------------------------

/// Future returned by [`RemoteForwardBinder::bind`]. Boxed for the same
/// reason [`crate::tunnel::dial::DialFuture`] is: the host holds the
/// binder as `&dyn RemoteForwardBinder` so a test can substitute a
/// counting double.
pub(crate) type BindFuture<'a> = Pin<Box<dyn Future<Output = io::Result<TcpListener>> + Send + 'a>>;

/// "Bind a TCP listener at `addr`." Nothing else — the same tiny,
/// ACL-blind seam [`crate::tunnel::dial::TunnelDialer`] is for the local
/// forward's dial, mirrored for the remote forward's bind: it exists so a
/// unit test can prove **zero binds** on a denied or non-loopback
/// `RemoteForwardOpen` without a real socket ever touching the network
/// (`docs/design/testing.md` L2, `PLAN.md` M4 Step 4 (c)). This trait must
/// never learn about ACL or loopback policy — both decisions are made by
/// [`crate::server::Server::authorize_and_bind_remote_forward`] strictly
/// before the first call to [`bind`](Self::bind).
pub(crate) trait RemoteForwardBinder: Send + Sync {
    /// Bind `addr`. `addr.port() == 0` asks for a kernel-assigned port —
    /// the caller reads it back with `TcpListener::local_addr`.
    fn bind<'a>(&'a self, addr: SocketAddr) -> BindFuture<'a>;
}

/// The one implementation that ships: `TcpListener::bind` itself.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemBinder;

impl RemoteForwardBinder for SystemBinder {
    fn bind<'a>(&'a self, addr: SocketAddr) -> BindFuture<'a> {
        Box::pin(async move { TcpListener::bind(addr).await })
    }
}

/// Why one accepted remote-forward connection failed to become a spliced
/// pipe. Never fatal to the forward itself — [`serve_remote_forward`]
/// logs and keeps accepting, the same discipline
/// [`crate::tunnel::local::ForwardConnError`] documents for the `-L` leg.
#[derive(Debug, Error)]
enum RemoteForwardConnError {
    /// The `TCP_ACCEPTED` stream could not be opened.
    #[error(transparent)]
    Link(#[from] ClientError),
    /// The carrier cannot surrender a raw byte pipe: a remote forward over
    /// the reverse `LOCAL_STREAM` conduit, which is `PLAN.md` M4 Step 5.
    /// Never reached in Step 4 — the only carrier this stage ever builds
    /// is [`DataLink::Quic`] — kept as a real variant rather than
    /// `unreachable!()` so a future carrier that is not yet raw-capable
    /// fails loudly instead of panicking a spliced connection's task.
    #[error("remote forwards over a reverse connection land in M4 Step 5")]
    CarrierNotRaw,
    /// The byte pipe itself broke mid-transfer.
    #[error(transparent)]
    Splice(#[from] SpliceError),
}

/// End an accepted TCP connection the way a failed `TCP_ACCEPTED` handoff
/// must end it: `SO_LINGER 0` so the close is an RST, never a FIN — the
/// same reasoning as [`crate::tunnel::local::abort_local`]'s own doc (a
/// plain FIN reads as "connected fine, no data", which is not what
/// happened on any path that calls this).
fn reset_tcp(tcp: TcpStream) {
    let _ = tcp.set_zero_linger();
    drop(tcp);
}

/// One accepted TCP connection's whole life on the remote-forward leg:
/// open the `TCP_ACCEPTED` stream (ticket = `forward_id`) and splice it
/// against `tcp` — no handshake reply to wait for (this module's own doc
/// on why `TCP_ACCEPTED` differs from `TCP_CONNECT` here).
async fn accept_one(
    tcp: TcpStream,
    conn: &qsh_transport::Connection,
    forward_id: &[u8],
) -> Result<crate::tunnel::splice::SpliceStats, RemoteForwardConnError> {
    let header = StreamHeader {
        kind: StreamKind::TcpAccepted as i32,
        ticket: forward_id.to_vec(),
        host: String::new(),
        port: 0,
    };
    let link = DataLink::Quic(conn);
    let (send, recv, kill) = match crate::tunnel::open_stream(&link, &header).await {
        Ok(opened) => opened,
        Err(err) => {
            reset_tcp(tcp);
            return Err(err.into());
        }
    };
    let (Ok(raw_send), Ok((raw_recv, residue))) = (send.into_raw_quic(), recv.into_raw_quic())
    else {
        kill.kill();
        reset_tcp(tcp);
        return Err(RemoteForwardConnError::CarrierNotRaw);
    };
    Ok(splice_tcp_quic(tcp, raw_send, raw_recv, residue).await?)
}

/// Accept forever on `listener`, turning each connection into a
/// `TCP_ACCEPTED` stream on `conn` and splicing it — the host side of
/// `PLAN.md` M4 Step 4's `-R`, symmetric to
/// [`crate::tunnel::local::LocalForward::run`] in every way that matters:
/// same accept-error classification
/// ([`crate::tunnel::local::accept_disposition`], reused rather than
/// duplicated — this function's own module doc), same "one bad connection
/// never takes the listener down" discipline, same per-connection
/// [`JoinSet`] so dropping this future (this forward's owning task being
/// aborted, by [`crate::server::Server::purge_connection`] or a
/// `RemoteForwardClose`) tears down every in-flight splice with it.
///
/// Returns only when the listener itself dies fatally, or is dropped from
/// outside (this future being aborted) — there is no other exit, matching
/// `LocalForward::run`'s own contract. `conn` is a snapshot, the same
/// `ForwardCarrier::Quic` caveat `crate::tunnel::local` documents: this
/// forward does not survive a forward-route connection recovery
/// (`PLAN.md` M4 Step 8's subject).
pub(crate) async fn serve_remote_forward(
    listener: TcpListener,
    conn: qsh_transport::Connection,
    forward_id: Vec<u8>,
) {
    use crate::tunnel::local::{ACCEPT_BACKOFF, AcceptDisposition, accept_disposition};

    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => match accept_disposition(&err) {
                        AcceptDisposition::Retry => {
                            tracing::debug!(%err, "qsh::tunnel: remote-forward transient accept error");
                            continue;
                        }
                        AcceptDisposition::Backoff => {
                            tracing::warn!(
                                %err,
                                backoff_ms = ACCEPT_BACKOFF.as_millis() as u64,
                                "qsh::tunnel: remote-forward accept deferred, out of resources"
                            );
                            tokio::time::sleep(ACCEPT_BACKOFF).await;
                            continue;
                        }
                        AcceptDisposition::Fatal => return,
                    },
                };
                let conn = conn.clone();
                let forward_id = forward_id.clone();
                tasks.spawn(async move {
                    match accept_one(tcp, &conn, &forward_id).await {
                        Ok(stats) => tracing::debug!(
                            %peer,
                            sent = stats.local_to_remote,
                            received = stats.remote_to_local,
                            "qsh::tunnel: remote-forward connection closed"
                        ),
                        Err(err) => tracing::warn!(
                            %peer,
                            %err,
                            "qsh::tunnel: remote-forward connection failed"
                        ),
                    }
                });
            }
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(err) = joined
                    && err.is_panic()
                {
                    tracing::warn!(%err, "qsh::tunnel: remote-forward connection task panicked");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Stage C: the requester leg — dispatching the peer's TCP_ACCEPTED
// streams back to whichever `-R` destination each `forward_id` names.
// ---------------------------------------------------------------------

/// Reset code for a `TCP_ACCEPTED` stream whose `ticket` names a
/// `forward_id` this requester never registered (already closed, never
/// opened, or opened by a different attach) — rejected without dialing
/// anything, per `PLAN.md` M4 Step 4's requester-leg requirement.
const RESET_CODE_UNKNOWN_FORWARD: u32 = 0x2008;

/// Reset code for a `TCP_ACCEPTED` stream whose `forward_id` *was* found,
/// but this side's own local dial (`host:port`) failed. Distinct from
/// [`RESET_CODE_UNKNOWN_FORWARD`] so a peer inspecting the QUIC error code
/// can tell "you asked for something I never opened" from "I tried and
/// your local destination refused" — the same code either way, since
/// `TCP_ACCEPTED` carries no `ConnectResult`-equivalent this side could
/// otherwise report the distinction through (`serve_remote_forward`'s own
/// doc on why).
const RESET_CODE_LOCAL_DIAL_FAILED: u32 = 0x2009;

/// One `-R` spec's local dial target, keyed by the `forward_id` the
/// peer's `RemoteForwardOpened` minted for it.
type RemoteForwardTable = Arc<Mutex<HashMap<String, (String, u16)>>>;

/// The requester side of `-R`: a single dispatcher, shared by every `-R`
/// spec opened on one connection, that accepts the peer's `TCP_ACCEPTED`
/// streams and turns each into a dial to this side's own local
/// `forward_host:forward_port` (`PLAN.md` M4 Step 4's requester leg,
/// `docs/design/protocol.md` §7).
///
/// One dispatcher per connection, not one per spec:
/// [`qsh_transport::Connection::accept_bi`] hands back *every*
/// peer-initiated stream on the connection, with no way to ask for only
/// the ones belonging to one `forward_id` — so two independent accept
/// loops racing the same `accept_bi()` would nondeterministically steal
/// each other's streams. A table shared across every `-R` on this
/// connection, keyed by `forward_id`, is the only correct shape once more
/// than one `-R` spec shares a connection.
///
/// [`Self::register`]/[`Self::unregister`] are safe to call while the
/// dispatcher is running, and they have to be: the host's listener is in
/// the kernel's `LISTEN` state — and `serve_remote_forward`'s accept loop
/// is spawned and already polling it — from the moment
/// `authorize_and_bind_remote_forward` binds it, which is *before*
/// `handle_rfwd_open` even constructs the `RemoteForwardOpened` reply, let
/// alone before this connection's control loop sends it, before this side
/// receives it, and before this side's own `register` call runs. Nothing
/// in `protocol.md` §7 promises the host withholds accepting until that
/// whole round trip finishes, and nothing here makes it — a `bind_port`
/// naming a well-known or already-being-probed port can hit this window
/// for entirely ordinary reasons, not just an adversarial race. So a
/// `TCP_ACCEPTED` that arrives before the matching `register` call is a
/// real, expected case, not a theoretical one, and it is rejected exactly
/// like any other unregistered `forward_id` — this dispatcher has no way,
/// and no need, to tell "genuinely unknown" apart from "not registered
/// yet". A caller that loses this race sees the connection reset and
/// simply retries at the application layer, the same as any other
/// `-R` connection that arrived before the forward was ready.
///
/// **Stage D:** `pub`, not `pub(crate)` — the same widening
/// [`crate::tunnel::LocalForwardHandle`] already got in Step 3, and for
/// the same reason: `crates/qsh-testkit/tests/tunnel_remote_loopback.rs`
/// (L3, `docs/design/testing.md`) drives the real requester leg end to
/// end rather than re-implementing it, which needs this type nameable
/// from outside `qsh-core`. `mod remote` itself stays `pub(crate)`
/// (`crate::tunnel`'s own `pub use`) — only this type and its three
/// methods left the crate boundary, nothing about `RemoteForwardOpen`'s
/// host-side handling did.
pub struct RemoteForwardAcceptor {
    table: RemoteForwardTable,
    task: tokio::task::JoinHandle<()>,
}

impl RemoteForwardAcceptor {
    /// Start dispatching `conn`'s incoming `TCP_ACCEPTED` streams. Starts
    /// with an empty table, so spawning this before the first
    /// `RemoteForwardOpen` round trip completes is safe — nothing is
    /// dispatched until [`Self::register`] names a `forward_id`.
    ///
    /// `async fn` with no `.await` of its own, matching
    /// [`crate::tunnel::LocalForwardHandle::start`]'s own shape on
    /// purpose: both call [`tokio::spawn`], which needs an ambient runtime
    /// — every caller is a synchronous `Ops`/`SessionAttachStream` method,
    /// so both are driven through `Connected::runtime().block_on(...)`
    /// rather than called bare (`tunnel_open`'s own call site is where
    /// this bit — spawning bare, off-runtime — was first caught, by the
    /// `qsh-cli` `tunnel_e2e` L5 suite panicking with "no reactor
    /// running").
    pub async fn spawn(conn: qsh_transport::Connection) -> Self {
        let table: RemoteForwardTable = Arc::new(Mutex::new(HashMap::new()));
        let task = tokio::spawn(dispatch_remote_forwards(conn, Arc::clone(&table)));
        Self { table, task }
    }

    /// Route future `TCP_ACCEPTED{ticket: forward_id}` streams to
    /// `host:port` — this side's own local dial target for the `-R` spec
    /// `forward_id` was minted for.
    pub fn register(&self, forward_id: String, host: String, port: u16) {
        self.table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(forward_id, (host, port));
    }

    /// Stop routing `forward_id` — a later `TCP_ACCEPTED` naming it is
    /// rejected as unknown rather than dialed. Called on `-R` teardown
    /// (`RemoteForwardClose`) and, best-effort, when a sibling `-R` in the
    /// same [`crate::ops::Ops::session_attach`] call fails after this one
    /// already opened.
    pub fn unregister(&self, forward_id: &str) {
        self.table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(forward_id);
    }
}

impl Drop for RemoteForwardAcceptor {
    fn drop(&mut self) {
        // Aborts the dispatcher task; every in-flight splice it spawned
        // lives inside that aborted future's own `JoinSet` and goes with
        // it — the same one-drop teardown
        // `crate::tunnel::local::LocalForwardHandle`'s `Drop` documents.
        self.task.abort();
    }
}

/// The dispatcher body: accept forever, look each stream's header up in
/// `table`, and either dial-and-splice or reject without dialing.
///
/// Structured like [`serve_remote_forward`]: each accepted stream is
/// handled on its own spawned task in a [`JoinSet`] so one bad stream can
/// never block the next. Unlike a TCP `accept()`, `accept_bi()`'s only
/// failure mode is the connection itself being gone — there is no
/// transient-vs-fatal table to consult here the way
/// [`crate::tunnel::local::accept_disposition`] gives the TCP accept
/// loops; any error ends the dispatcher.
async fn dispatch_remote_forwards(conn: qsh_transport::Connection, table: RemoteForwardTable) {
    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            accepted = conn.accept_bi() => {
                let (send, recv) = match accepted {
                    Ok(pair) => pair,
                    // The connection itself is gone — nothing left to
                    // dispatch. In-flight splices already spawned live in
                    // `tasks` and are dropped with this future.
                    Err(_) => return,
                };
                let table = Arc::clone(&table);
                tasks.spawn(async move {
                    handle_accepted_stream(send, recv, &table).await;
                });
            }
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(err) = joined
                    && err.is_panic()
                {
                    tracing::warn!(%err, "qsh::tunnel: remote-forward dispatch task panicked");
                }
            }
        }
    }
}

/// One accepted `TCP_ACCEPTED` stream's whole life on the requester side:
/// read the header, look `ticket` (the `forward_id`) up in `table`, and
/// either dial this side's local destination and splice, or reject
/// without dialing anything — an unregistered `forward_id`, or a stream
/// that is not `TCP_ACCEPTED` at all, never causes a socket to open.
///
/// No `ConnectResult`-equivalent is ever written back
/// ([`serve_remote_forward`]'s own doc on why `TCP_ACCEPTED` carries no
/// reply): the peer already committed its accepted TCP connection to this
/// stream before opening it, so a dial failure here is reported by
/// resetting the stream, not by a frame the peer would have to read to
/// learn about it.
async fn handle_accepted_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    table: &Mutex<HashMap<String, (String, u16)>>,
) {
    let mut stream = qsh_transport::FramedStream::data(send, recv);
    let header: StreamHeader = match tokio::time::timeout(
        crate::server::HEADER_TIMEOUT,
        stream.recv.recv::<StreamHeader>(),
    )
    .await
    {
        Ok(Ok(Some(h))) => h,
        _ => {
            stream.send.reset(crate::server::RESET_CODE_BAD_HEADER);
            stream.recv.stop(crate::server::RESET_CODE_BAD_HEADER);
            return;
        }
    };
    if header.stream_kind() != Some(StreamKind::TcpAccepted) {
        tracing::debug!(
            kind = header.kind,
            "qsh::tunnel: unexpected peer-opened stream kind"
        );
        stream.send.reset(crate::server::RESET_CODE_BAD_HEADER);
        stream.recv.stop(crate::server::RESET_CODE_BAD_HEADER);
        return;
    }
    // The ticket on a `TCP_ACCEPTED` stream is a `forward_id` **the peer
    // is handing back to us**, so it is shape-checked before it is used
    // for anything at all: not looked up, not dispatched, not logged
    // (`qsh_proto::wire::valid_forward_id`, `v1.proto`'s own comment on
    // `RemoteForwardOpened.forward_id`). A malformed one is rejected
    // exactly like an unknown one — reset, nothing dialed, no socket
    // opened on its behalf.
    //
    // The rejection log deliberately carries the ticket's **length**, not
    // its bytes: an id that failed this check is arbitrary peer-controlled
    // text, and the one thing it must never do is reach an operator's
    // terminal (`qsh_proto::wire::sanitize_peer_text`'s own doc on why
    // peer text and terminals do not mix). Past the check the id is
    // `[A-Za-z0-9_-]{1,64}` by construction, which is strictly stronger
    // than sanitizing, so the paths below log it as it is.
    let forward_id = match String::from_utf8(header.ticket.clone()) {
        Ok(id) if valid_forward_id(&id) => id,
        _ => {
            tracing::warn!(
                ticket_len = header.ticket.len(),
                "qsh::tunnel: TCP_ACCEPTED with a malformed forward_id ticket"
            );
            stream.send.reset(RESET_CODE_UNKNOWN_FORWARD);
            stream.recv.stop(RESET_CODE_UNKNOWN_FORWARD);
            return;
        }
    };
    let destination = table
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&forward_id)
        .cloned();
    let Some((host, port)) = destination else {
        // Rejected without dialing anything (requester-leg item 2's own
        // requirement) — an unknown `forward_id` never gets a socket
        // opened on its behalf.
        tracing::warn!(
            forward_id,
            "qsh::tunnel: TCP_ACCEPTED for an unregistered forward_id"
        );
        stream.send.reset(RESET_CODE_UNKNOWN_FORWARD);
        stream.recv.stop(RESET_CODE_UNKNOWN_FORWARD);
        return;
    };

    // `SystemDialer::default()` carries the production
    // `crate::tunnel::dial::TUNNEL_DIAL_TIMEOUT` — same bound and same
    // dialer the host side's `authorize_and_dial_tunnel` uses for `-L`.
    let dialer = SystemDialer::default();
    let tcp = match dialer.dial(&host, port).await {
        Ok(tcp) => tcp,
        Err(err) => {
            tracing::warn!(
                host,
                port,
                %err,
                "qsh::tunnel: remote-forward local dial failed"
            );
            stream.send.reset(RESET_CODE_LOCAL_DIAL_FAILED);
            stream.recv.stop(RESET_CODE_LOCAL_DIAL_FAILED);
            return;
        }
    };

    // Past this point the stream is a raw byte pipe — same residue
    // handoff `crate::server::Server::handle_tcp_connect` documents on
    // the mirror-image `-L` leg.
    let (send, recv) = stream.split();
    let (raw_recv, residue) = recv.into_raw();
    match splice_tcp_quic(tcp, send.into_raw(), raw_recv, residue).await {
        Ok(stats) => tracing::debug!(
            host,
            port,
            sent = stats.local_to_remote,
            received = stats.remote_to_local,
            "qsh::tunnel: remote-forward local connection closed"
        ),
        Err(err) => tracing::warn!(
            host,
            port,
            %err,
            "qsh::tunnel: remote-forward local connection failed"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::tunnel::testutil::{ScriptedResolver, addr, loopback_pair};

    // ---- all_loopback: the pure fold, network-free -------------------

    #[test]
    fn all_loopback_requires_every_address_not_just_one() {
        // The bypass vector this module's doc names: one loopback answer
        // among several must not be enough.
        assert!(!all_loopback([
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), // TEST-NET-3, public-shaped
        ]));
        // ...but the mirror image is loopback-safe: several addresses,
        // all of them loopback (mixed v4/v6, and 127/8 beyond .1).
        assert!(all_loopback([
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]));
    }

    #[test]
    fn all_loopback_of_nothing_is_not_loopback() {
        // No addresses means nothing was certified loopback — must not
        // default to permissive.
        assert!(!all_loopback(std::iter::empty()));
    }

    #[test]
    fn all_loopback_single_address_cases() {
        assert!(all_loopback([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]));
        assert!(all_loopback([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))]));
        assert!(all_loopback([IpAddr::V6(Ipv6Addr::LOCALHOST)]));
        assert!(!all_loopback([IpAddr::V4(Ipv4Addr::UNSPECIFIED)])); // 0.0.0.0
        assert!(!all_loopback([IpAddr::V6(Ipv6Addr::UNSPECIFIED)])); // ::
        assert!(!all_loopback([IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]));
    }

    // ---- resolve_loopback_bind_addr: the table this stage owes --------
    // (`PLAN.md` M4 Step 4 (c) "loopback 강제 표")

    #[tokio::test]
    async fn loopback_bind_host_table() {
        let loopback_cases = [
            "127.0.0.1",
            "127.0.0.53", // whole 127.0.0.0/8, not just .1
            "::1",
        ];
        for host in loopback_cases {
            let bound = resolve_loopback_bind_addr(&SystemResolver, host, 4321)
                .await
                .unwrap_or_else(|err| panic!("{host} must classify as loopback: {err}"));
            assert!(bound.ip().is_loopback(), "{host}");
            assert_eq!(bound.port(), 4321, "{host}");
        }

        let non_loopback_cases = [
            "0.0.0.0",
            "::",
            "203.0.113.9", // TEST-NET-3: public-shaped literal
        ];
        for host in non_loopback_cases {
            assert!(
                resolve_loopback_bind_addr(&SystemResolver, host, 4321)
                    .await
                    .is_err(),
                "{host} must NOT classify as loopback"
            );
        }
    }

    #[tokio::test]
    async fn empty_bind_host_is_the_loopback_default() {
        // The wire default for "no `bind:` prefix" — must not resolve, and
        // must not be mistaken for "unspecified".
        let resolver = ScriptedResolver::new(vec![vec![addr("203.0.113.9:4321")]]);
        assert_eq!(
            resolve_loopback_bind_addr(&resolver, "", 4321)
                .await
                .unwrap(),
            addr("127.0.0.1:4321")
        );
        assert_eq!(resolver.calls(), 0, "the wire default never resolves");
    }

    #[tokio::test]
    async fn an_ip_literal_never_reaches_the_resolver() {
        // Classification by address, not by string — and no lookup at
        // all, so a resolver cannot influence a literal either way.
        let resolver = ScriptedResolver::new(vec![vec![addr("203.0.113.9:4321")]]);
        assert_eq!(
            resolve_loopback_bind_addr(&resolver, "127.0.0.53", 4321)
                .await
                .unwrap(),
            addr("127.0.0.53:4321")
        );
        assert!(
            resolve_loopback_bind_addr(&resolver, "0.0.0.0", 4321)
                .await
                .is_err()
        );
        assert_eq!(resolver.calls(), 0, "an IP literal never resolves");
    }

    /// **The check-then-use regression guard.** A resolver that answers
    /// loopback to the first lookup and a routable address to the second
    /// — a peer-controlled zone with a one-second TTL, no host compromise
    /// needed — must never yield a routable bind address. The whole
    /// defense is that there *is* no second lookup: exactly one call, and
    /// the address returned is one of the addresses that call produced.
    ///
    /// Mutation-checked: reintroducing a second `resolver.lookup` after
    /// the `all_loopback` check makes this fail on both assertions.
    #[tokio::test]
    async fn the_address_returned_is_the_address_validated_never_a_second_answer() {
        let resolver = ScriptedResolver::new(vec![
            vec![addr("127.0.0.1:4321")],
            vec![addr("203.0.113.9:4321")],
        ]);

        let bound = resolve_loopback_bind_addr(&resolver, "evil.example", 4321)
            .await
            .expect("the validated answer was loopback");

        assert_eq!(
            resolver.calls(),
            1,
            "a bind_host is resolved exactly once — a second lookup is the bug"
        );
        assert_eq!(
            bound,
            addr("127.0.0.1:4321"),
            "the address bound must come out of the answer set that was validated"
        );
        assert!(bound.ip().is_loopback());
    }

    #[tokio::test]
    async fn a_mixed_answer_set_is_rejected_whole() {
        // "Some resolved address is loopback" is not a safety property.
        let resolver =
            ScriptedResolver::new(vec![vec![addr("127.0.0.1:4321"), addr("203.0.113.9:4321")]]);
        assert!(
            resolve_loopback_bind_addr(&resolver, "split.example", 4321)
                .await
                .is_err(),
            "a name that also answers with a routable address must be refused"
        );
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_nothing_is_refused() {
        let resolver = ScriptedResolver::new(vec![vec![]]);
        assert!(
            resolve_loopback_bind_addr(&resolver, "nothing.example", 4321)
                .await
                .is_err(),
            "an empty answer set certifies nothing as loopback"
        );
    }

    #[tokio::test]
    async fn a_resolver_failure_is_refused_as_not_loopback() {
        struct FailingResolver;
        impl BindHostResolver for FailingResolver {
            fn lookup<'a>(&'a self, _host: &'a str, _port: u16) -> LookupFuture<'a> {
                Box::pin(async { Err(io::Error::other("resolver is down")) })
            }
        }
        // Including a `bind_host` carrying terminal escapes: the debug log
        // line this path emits sanitizes it, and nothing is bound either
        // way.
        assert!(
            resolve_loopback_bind_addr(&FailingResolver, "a\u{1b}[31mb.example", 4321)
                .await
                .is_err()
        );
    }

    /// A resolver that never answers must not park the caller forever —
    /// `RemoteForwardOpen` is handled inline on the connection's single
    /// serialized control loop, so an unbounded resolve here stalls every
    /// other message on that connection, on a name the peer chose
    /// (`BIND_HOST_RESOLVE_TIMEOUT`'s own doc). The bound is injected so
    /// this test does not wait out the production ten seconds.
    #[tokio::test]
    async fn a_resolver_that_never_answers_is_bounded_not_parked_forever() {
        struct HangingResolver;
        impl BindHostResolver for HangingResolver {
            fn lookup<'a>(&'a self, _host: &'a str, _port: u16) -> LookupFuture<'a> {
                Box::pin(std::future::pending())
            }
        }
        let started = std::time::Instant::now();
        let err = resolve_loopback_bind_addr_bounded(
            &HangingResolver,
            "evil.example",
            4321,
            Duration::from_millis(50),
        )
        .await
        .expect_err("a resolver that never answers must not classify as loopback");
        let _ = err; // `NotLoopback` carries nothing to inspect beyond its `Display`
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the injected bound must have applied, not some much longer default: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn localhost_resolves_to_loopback() {
        // Goes through the real resolver (not hardcoded — this module's
        // own doc explains why), so this asserts the *classification*
        // holds for whatever the system resolver answers `localhost`
        // with, which is loopback on every CI/dev environment this crate
        // targets.
        let bound = resolve_loopback_bind_addr(&SystemResolver, "localhost", 4321)
            .await
            .expect("localhost must resolve to loopback");
        assert!(bound.ip().is_loopback());
    }

    #[tokio::test]
    async fn a_real_non_loopback_interface_address_is_not_loopback() {
        // A real, routable interface address on this host — obtained by
        // opening a UDP socket "connected" to a public address, which
        // populates the local address with whatever interface the kernel
        // would actually route through, no traffic sent
        // (`crate::tunnel` has no simpler way to name "an address that is
        // genuinely this host's LAN/interface address" than asking the
        // kernel). Skips rather than fails on a sandboxed runner with no
        // route to the outside — the point is proving the classifier
        // rejects a real interface address, not proving one exists here.
        let Ok(probe) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
            return;
        };
        if probe.connect("203.0.113.9:9").await.is_err() {
            return;
        }
        let Ok(local_addr) = probe.local_addr() else {
            return;
        };
        let ip = local_addr.ip();
        if ip.is_loopback() || ip.is_unspecified() {
            // No real outbound route on this runner; nothing to assert.
            return;
        }
        assert!(
            resolve_loopback_bind_addr(&SystemResolver, &ip.to_string(), 4321)
                .await
                .is_err(),
            "a real interface address ({ip}) must not classify as loopback"
        );
    }

    // ---- RemoteForwardAcceptor: the requester leg (Stage C) -----------

    /// Send a `TCP_ACCEPTED{ticket}` header on a fresh bidi stream opened
    /// from `conn` — the same handshake `serve_remote_forward`'s
    /// `accept_one` writes for real, played back by hand so a test can be
    /// the "host" side without standing up a whole listener.
    async fn open_fake_tcp_accepted(
        conn: &qsh_transport::Connection,
        forward_id: &[u8],
    ) -> (quinn::SendStream, (quinn::RecvStream, Vec<u8>)) {
        let (send, recv) = conn.open_bi().await.unwrap();
        let mut framed = qsh_transport::FramedStream::data(send, recv);
        framed
            .send
            .send(&StreamHeader {
                kind: StreamKind::TcpAccepted as i32,
                ticket: forward_id.to_vec(),
                host: String::new(),
                port: 0,
            })
            .await
            .unwrap();
        let (send, recv) = framed.split();
        let residue = recv.into_raw();
        (send.into_raw(), residue)
    }

    /// A `TCP_ACCEPTED` naming a `forward_id` this side registered is
    /// dialed at the registered `host:port` and spliced — both directions,
    /// proving the dispatcher does not merely accept the stream but
    /// actually forwards the bytes.
    #[tokio::test]
    async fn registered_forward_id_is_dialed_at_its_destination_and_spliced() {
        let (requester_conn, peer_conn) = loopback_pair().await;

        // Stand in for the `-R` spec's local destination: an echo server
        // on loopback, port 0 (`docs/design/testing.md`'s CI rule).
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut sock, _peer) = echo.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;
        acceptor.register(
            "fwd-1".to_string(),
            "127.0.0.1".to_string(),
            echo_addr.port(),
        );

        let (mut raw_send, (mut raw_recv, residue)) =
            open_fake_tcp_accepted(&peer_conn, b"fwd-1").await;
        assert!(
            residue.is_empty(),
            "nothing was pipelined behind the header in this test"
        );
        raw_send.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 16];
        let n = match raw_recv.read(&mut buf).await.unwrap() {
            Some(n) => n,
            None => panic!("registered forward_id must be spliced, not reset"),
        };
        assert_eq!(&buf[..n], b"ping", "the destination must echo what it got");

        echo_task.await.unwrap();
        drop(acceptor);
        drop(peer_conn);
    }

    /// A `TCP_ACCEPTED` naming a `forward_id` that was never registered —
    /// never opened, or already closed — is rejected without dialing
    /// anything: the peer sees the stream reset, not an echo
    /// (`PLAN.md` M4 Step 4's requester-leg requirement).
    #[tokio::test]
    async fn unregistered_forward_id_is_rejected_without_dialing() {
        let (requester_conn, peer_conn) = loopback_pair().await;
        // Spawned, but nothing is ever registered on it.
        let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;

        let (mut raw_send, (mut raw_recv, _residue)) =
            open_fake_tcp_accepted(&peer_conn, b"never-registered").await;

        // The dispatcher must reset the stream immediately, before ever
        // reaching a dial — so reading back gets a reset error, not a
        // hang and not an echo of anything this test never sent.
        let read_err = raw_recv.read(&mut [0u8; 8]).await;
        assert!(
            read_err.is_err(),
            "an unregistered forward_id must reset the stream, not stay open: {read_err:?}"
        );

        drop(acceptor);
        drop(peer_conn);
        let _ = raw_send.finish();
    }

    /// [`RemoteForwardAcceptor::unregister`] takes a `forward_id` back out
    /// of dispatch: a `TCP_ACCEPTED` for it arriving *after* unregister is
    /// treated exactly like one that was never registered at all — the
    /// `-R` teardown path ([`crate::ops::TunnelHold::close`]) depends on
    /// this to stop dispatching before it sends `RemoteForwardClose`.
    /// A `forward_id` ticket that does not satisfy
    /// [`qsh_proto::wire::valid_forward_id`] never reaches the dispatch
    /// table, never causes a dial, and never reaches a log line verbatim.
    /// The escape-sequence case is the sharp one: the requester leg logs
    /// its rejections, and a raw ticket there would let the peer drive the
    /// operator's terminal.
    ///
    /// Registering the malformed id first is deliberate — it proves the
    /// shape check runs *before* the lookup, so a peer cannot smuggle a
    /// malformed id into service even if one somehow got registered.
    #[tokio::test]
    async fn malformed_forward_id_ticket_is_rejected_without_dialing() {
        let malformed: [&[u8]; 6] = [
            b"",                      // empty
            b"a\x1b[31mb",            // ANSI escape run
            b"fwd\nqsh: forged line", // forged log/terminal line
            b"fwd\x00-1",             // NUL
            b"fwd.1",                 // `.` is not in the alphabet
            &[b'x'; 65],              // one byte over the 64-byte cap
        ];

        for ticket in malformed {
            let (requester_conn, peer_conn) = loopback_pair().await;
            let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;
            // A destination that would be dialed if the check were missing.
            if let Ok(id) = std::str::from_utf8(ticket) {
                acceptor.register(id.to_string(), "127.0.0.1".to_string(), 9);
            }

            let (mut raw_send, (mut raw_recv, _residue)) =
                open_fake_tcp_accepted(&peer_conn, ticket).await;

            let read_err = raw_recv.read(&mut [0u8; 8]).await;
            assert!(
                read_err.is_err(),
                "a malformed forward_id ({ticket:?}) must reset the stream: {read_err:?}"
            );

            drop(acceptor);
            drop(peer_conn);
            let _ = raw_send.finish();
        }
    }

    /// Invalid UTF-8 is the same rejection, one layer earlier.
    #[tokio::test]
    async fn non_utf8_forward_id_ticket_is_rejected_without_dialing() {
        let (requester_conn, peer_conn) = loopback_pair().await;
        let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;

        let (mut raw_send, (mut raw_recv, _residue)) =
            open_fake_tcp_accepted(&peer_conn, &[0xff, 0xfe]).await;

        let read_err = raw_recv.read(&mut [0u8; 8]).await;
        assert!(read_err.is_err(), "{read_err:?}");

        drop(acceptor);
        drop(peer_conn);
        let _ = raw_send.finish();
    }

    /// **Not just "the stream got reset for some reason."** The earlier
    /// version of this test pointed `fwd-2` at port 1 — a port nothing
    /// listens on — so it passed even with `unregister` gutted into a
    /// no-op: a still-registered `fwd-2` would have been dialed, the dial
    /// to port 1 would have failed on its own, and the stream would have
    /// been reset for *that* unrelated reason, indistinguishable from a
    /// correct rejection. This version points `fwd-2` at a real,
    /// listening echo server, so the only way the stream can come back
    /// reset instead of carrying an echo is that `unregister` actually
    /// took the id out of dispatch.
    ///
    /// Mutation-checked: gutting `unregister`'s body (so it no longer
    /// removes anything) makes this test fail — `read_err` comes back
    /// `Ok(Some(4))` carrying the echoed `"ping"` instead of an error,
    /// because the dispatcher happily dials the still-registered
    /// destination and splices it — while
    /// `unregistered_forward_id_is_rejected_without_dialing` alone would
    /// still have passed, which is exactly the blind spot this version
    /// closes.
    #[tokio::test]
    async fn unregister_stops_dispatching_a_previously_registered_forward_id() {
        let (requester_conn, peer_conn) = loopback_pair().await;

        // A real destination that would happily answer if dialed — so a
        // gutted `unregister` shows up as an echo, not a coincidental
        // reset.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            // Never actually reached on a correct `unregister` — this
            // task is dropped, unjoined, when the test ends.
            let (mut sock, _peer) = echo.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let acceptor = RemoteForwardAcceptor::spawn(requester_conn).await;
        acceptor.register(
            "fwd-2".to_string(),
            "127.0.0.1".to_string(),
            echo_addr.port(),
        );
        acceptor.unregister("fwd-2");

        let (mut raw_send, (mut raw_recv, _residue)) =
            open_fake_tcp_accepted(&peer_conn, b"fwd-2").await;
        raw_send.write_all(b"ping").await.unwrap();
        let read_err = raw_recv.read(&mut [0u8; 8]).await;
        assert!(
            read_err.is_err(),
            "an unregistered forward_id must reset the stream, not dial and splice \
             the destination it used to name: {read_err:?}"
        );

        drop(acceptor);
        drop(peer_conn);
        let _ = raw_send.finish();
        echo_task.abort();
    }
}
