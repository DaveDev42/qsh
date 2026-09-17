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
// The reverse claim loop's backoff decision is the only consumer, and it
// is `cfg(unix)` with the rest of the reverse leg.
#[cfg(unix)]
use std::time::Instant;

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

/// The exact `docs/CLI.md` §6.9 / `README.md` wording for a non-loopback
/// `-R` bind's `INVALID_ARGUMENT` refusal (`PLAN.md` M4 Step 8's L6
/// doc-consistency gate, the same discipline M3 Step 9 applied to
/// `qsh_core::doctor::CONTROLLER_UNREACHABLE`). `NotLoopback`'s
/// `Display` is defined in terms of this constant rather than its own
/// literal so the two cannot drift apart — `crates/qsh-core/tests/
/// tunnel_docs.rs` pins docs to this single source, not to a second copy
/// of the string.
///
/// Three parts: the observation is deliberately **not** "is
/// not a loopback address" — `resolve_loopback_bind_addr_bounded`
/// returns this same `NotLoopback` from five distinct branches (a
/// non-loopback IP literal, a name that resolves to a non-loopback
/// answer, an empty answer set, a resolver failure, and a resolve
/// timeout), and this module's own anti-oracle rationale for folding them
/// together (this const's neighboring doc on `NotLoopback`, and the
/// resolve-failure/timeout arms below) means the host does not actually
/// know, in the last three cases, that the bind is not loopback — only
/// that it could not confirm it is. "could not be confirmed" is true in
/// all five; "is not" would have been a false assertion in three of them.
/// The leading clause stays byte-identical to the pre-M9 wording on
/// purpose: `docs/CLI.md` and `README.md` already quote it inside prose
/// ("정확히 ... 다"), so extending the quoted span is all either doc needs
/// to do to stay verbatim-consistent.
pub const REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE: &str = "remote forward binds loopback only: this bind could not be confirmed as a loopback address, so nothing was opened on the host. Re-run `-R` with a loopback bind (omit the bind, or use `127.0.0.1` / `[::1]`).";

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
#[derive(Debug)]
pub(crate) struct NotLoopback;

impl std::fmt::Display for NotLoopback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE)
    }
}

impl std::error::Error for NotLoopback {}

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

/// The forward-axis quota key for one `-R` listener: `rfwd:` plus the
/// registration's `forward_id`.
///
/// The prefix makes a namespace guarantee structural rather than
/// incidental. `-L`'s own forward-axis key is a `host:port` string
/// (`Server::authorize_and_dial_tunnel`, via `wire::format_host_port`),
/// while `forward_id` is a host-minted ULID (`server/mod.rs`'s
/// `forward.remote.open` handler — Crockford base32, no colon), so the
/// two could not collide even unprefixed; `rfwd:` makes that a property
/// of the key shape instead of a property of ULID's alphabet. The key is
/// a map key only — it never reaches an audit record or the CLI.
///
/// `from_utf8_lossy` is lossless in practice: the only production caller
/// mints `forward_id` with `String::into_bytes()`. The parameter stays
/// `&[u8]` because `accept_one` carries the same id as ticket bytes.
fn remote_forward_quota_key(forward_id: &[u8]) -> String {
    format!("rfwd:{}", String::from_utf8_lossy(forward_id))
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
    quotas: Arc<crate::quota::Quotas>,
    audit: Arc<dyn crate::audit::AuditSink>,
) {
    use crate::tunnel::local::{ACCEPT_BACKOFF, AcceptDisposition, accept_disposition};

    // Tunnel-stream concurrency permit (M8 Step 4b, J13): the same choke
    // point `Server::authorize_and_dial_tunnel`'s own `-L` leg applies
    // after its ACL decision and before its dial, applied here after the
    // TCP accept and before `open_bi` — nothing QUIC-shaped may exist
    // before a reservation succeeds. `-R`'s listener port is reachable
    // with no authentication at all (this module's own doc), so this is
    // the *only* gate between an anonymous TCP client and a spawned task
    // + an open QUIC stream on `conn`; ADR-0010's "decide after
    // authorization, before creation; count what's alive" applies with
    // the earlier `RemoteForwardOpen` authorization standing in for the
    // per-connection ACL check `-L` makes per dial. `owner`/`forward_key`
    // are fixed for this listener's whole life — same principal, same
    // `forward_id` — so both are computed once, outside the accept loop.
    let owner = crate::acl::opener_key(conn.principal(), conn.auth_path());
    let forward_key = remote_forward_quota_key(&forward_id);

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
                let permit = match quotas.reserve_tunnel_stream(&owner, &forward_key) {
                    Ok(permit) => permit,
                    Err(kind) => {
                        // No QUIC stream was ever opened for this TCP
                        // connection, so there is no QUIC `RESET_STREAM`
                        // to send. The TCP side is an ordinary close; a
                        // client that already wrote bytes leaves them
                        // unread in the receive buffer, so the kernel
                        // turns that close into an RST (the reason both
                        // this axis's tests accept `Ok(0)` *and*
                        // `ConnectionReset`/`ConnectionAborted`).
                        let records = quotas.record_rejection(
                            kind,
                            &owner,
                            peer,
                            quotas.now(),
                            None,
                            conn.auth_path(),
                        );
                        crate::audit::write_quota_audit(audit.as_ref(), &records);
                        drop(tcp);
                        continue;
                    }
                };
                let conn = conn.clone();
                let forward_id = forward_id.clone();
                tasks.spawn(async move {
                    // Held across the whole splice — the same "permit
                    // lives inside the spawned future" shape
                    // `Server::handle_tcp_connect` uses for `-L`'s own
                    // `TunnelStreamPermit`; dropped (both axes released)
                    // only when `accept_one` returns.
                    let _permit = permit;
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
    dispatch: AcceptDispatch,
}

/// How [`RemoteForwardAcceptor`] actually receives `TCP_ACCEPTED` streams
/// — the requester leg's own carrier axis, `PLAN.md` M4 Step 5 (a)'s
/// counterpart to [`crate::tunnel::local::ForwardCarrier`]. The two
/// variants are not merely two ways to reach the same primitive: on the
/// forward route this process holds the live QUIC connection and
/// `accept_bi()` hands back *every* peer-opened stream on it, so one
/// shared dispatcher loop and [`RemoteForwardTable`] lookup is exactly
/// [`crate::tunnel::local::ForwardCarrier`]'s own reasoning for a shared
/// table. On the reverse route this process holds no connection at all —
/// the resident daemon does — and the only primitive it offers is a
/// *named* claim (`crate::localctl::client::open_stream_with_wait` with a
/// `TCP_ACCEPTED{ticket: forward_id}` header): there is no "accept
/// anything" operation to share a loop over, so each registered
/// `forward_id` gets its own persistent claim loop instead.
enum AcceptDispatch {
    /// Forward route: [`dispatch_remote_forwards`] already running against
    /// a live [`qsh_transport::Connection`], shared by every `-R` on it.
    Quic { task: tokio::task::JoinHandle<()> },
    /// Reverse route: this machine's resident daemon socket, plus one
    /// claim-loop task per currently-registered `forward_id`
    /// (`claim_remote_forward_reverse`).
    #[cfg(unix)]
    Local {
        socket: std::path::PathBuf,
        host: String,
        claims: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
        /// This instance's own claim token
        /// (`crate::reverse::listen::ControlHub::claim_tcp_accepted`'s own
        /// doc on why one is required at all — adversarial-review
        /// finding: knowing a `forward_id` must not be enough to claim
        /// it). Minted once, here, and reused verbatim by every claim
        /// attempt this instance ever makes, for every `forward_id` it
        /// registers — the daemon's ownership check is keyed on exactly
        /// this stability: the *first* claim for a given `forward_id`
        /// seats whatever token it presented, and every later claim,
        /// including this instance's own retries after a claimed splice
        /// ends, must keep presenting the same bytes.
        claim_token: Vec<u8>,
    },
}

impl RemoteForwardAcceptor {
    /// Start dispatching `conn`'s incoming `TCP_ACCEPTED` streams (forward
    /// route). Starts with an empty table, so spawning this before the
    /// first `RemoteForwardOpen` round trip completes is safe — nothing is
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
        Self {
            table,
            dispatch: AcceptDispatch::Quic { task },
        }
    }

    /// [`Self::spawn`]'s reverse-route sibling, `-R over reverse`
    /// (`PLAN.md` M4 Step 5 (a)): `socket_path` is this machine's resident
    /// `qsh listen` daemon's UDS socket, `host` the reverse registration
    /// it should relay each claim to. Unlike [`Self::spawn`] this starts
    /// no task at all — there is nothing to dispatch until
    /// [`Self::register`] names the first `forward_id`, at which point a
    /// dedicated claim loop starts for exactly that id
    /// (`AcceptDispatch::Local`'s own doc on why one loop per id, not
    /// one shared loop).
    #[cfg(unix)]
    pub async fn spawn_reverse(socket_path: std::path::PathBuf, host: String) -> Self {
        Self {
            table: Arc::new(Mutex::new(HashMap::new())),
            dispatch: AcceptDispatch::Local {
                socket: socket_path,
                host,
                claims: Mutex::new(HashMap::new()),
                // A `Ulid` is convenient, unguessable (128 bits, 80 of
                // them random) entropy already a direct dependency of
                // this crate (`Server::handle_rfwd_open` mints
                // `forward_id` the same way) — its meaning here is
                // unrelated to `forward_id`'s (a *claim token*, never
                // compared against or substituted for a `forward_id`
                // anywhere), it is simply a convenient source of a fresh
                // random byte string.
                claim_token: ulid::Ulid::new().to_string().into_bytes(),
            },
        }
    }

    /// This instance's own claim token, reverse route only — the exact
    /// bytes `Self::spawn_reverse` minted, unchanged. `None` on the
    /// forward route (`AcceptDispatch::Quic` has no claim token; a
    /// live QUIC connection makes the token's whole purpose moot, since
    /// nothing else can claim from it). A caller that opens a `-R over
    /// reverse` forward must call this **before** it sends
    /// `RemoteForwardOpen`, so the request carries this exact value in
    /// `claim_token` — `crate::reverse::listen::ControlHub`'s
    /// `claim_tokens` doc: the hub seats whatever token that request
    /// carried the instant it registers the `forward_id`, and every
    /// claim [`Self::register`]'s claim loop makes afterward must
    /// present those identical bytes back or be refused. This is the
    /// only way the two ever agree — there is no wire round trip that
    /// echoes the token back for this side to read.
    pub fn claim_token(&self) -> Option<&[u8]> {
        match &self.dispatch {
            AcceptDispatch::Quic { .. } => None,
            #[cfg(unix)]
            AcceptDispatch::Local { claim_token, .. } => Some(claim_token.as_slice()),
        }
    }

    /// Route future `TCP_ACCEPTED{ticket: forward_id}` streams to
    /// `host:port` — this side's own local dial target for the `-R` spec
    /// `forward_id` was minted for. On the reverse route this is also
    /// what starts `forward_id`'s claim loop — there is nothing to
    /// register *into* the way the forward route's shared table is; the
    /// registration and the dispatch start together.
    pub fn register(&self, forward_id: String, host: String, port: u16) {
        self.table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(forward_id.clone(), (host.clone(), port));
        #[cfg(unix)]
        if let AcceptDispatch::Local {
            socket,
            host: daemon_host,
            claims,
            claim_token,
        } = &self.dispatch
        {
            let mut claims = claims.lock().unwrap_or_else(|e| e.into_inner());
            claims.entry(forward_id.clone()).or_insert_with(|| {
                tokio::spawn(claim_remote_forward_reverse(
                    socket.clone(),
                    daemon_host.clone(),
                    forward_id,
                    claim_token.clone(),
                    host,
                    port,
                ))
            });
        }
    }

    /// Stop routing `forward_id` — a later `TCP_ACCEPTED` naming it is
    /// rejected as unknown rather than dialed. Called on `-R` teardown
    /// (`RemoteForwardClose`) and, best-effort, when a sibling `-R` in the
    /// same [`crate::ops::Ops::session_attach`] call fails after this one
    /// already opened. On the reverse route this also aborts
    /// `forward_id`'s claim loop — the same one-drop teardown
    /// [`Self::drop`] gives every remaining claim loop, just scoped to
    /// this one id — which stops *new* claims immediately but, same as
    /// the forward route's own `dispatch_remote_forwards`, never
    /// disturbs a splice already in flight for this id: it drains to its
    /// own natural end (`DrainSplicesOnDrop`'s own doc on how the
    /// abort above achieves that rather than tearing those splices down
    /// with it).
    pub fn unregister(&self, forward_id: &str) {
        self.table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(forward_id);
        #[cfg(unix)]
        if let AcceptDispatch::Local { claims, .. } = &self.dispatch
            && let Some(task) = claims
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(forward_id)
        {
            task.abort();
        }
    }
}

impl Drop for RemoteForwardAcceptor {
    fn drop(&mut self) {
        // Aborts every still-running dispatch/claim-loop task —
        // `dispatch_remote_forwards` (forward route) or every currently-
        // registered `forward_id`'s `claim_remote_forward_reverse`
        // (reverse route) — which stops *new* work immediately on both
        // routes. What that abort does to work already in flight is
        // deliberately identical on both routes too (adversarial-review
        // finding, this type's headline claim that the role axis is
        // independent of connection direction): every already-accepted
        // or already-claimed splice *drains* to its own natural end
        // rather than being force-aborted, because on both routes the
        // aborted task's own `JoinSet` of splices is wrapped in
        // `DrainSplicesOnDrop`, and the reverse route additionally wraps
        // its one outstanding claim attempt in `DrainClaimAttemptOnDrop`
        // so a claim granted the instant after teardown still completes
        // instead of vanishing. This is *not*
        // `crate::tunnel::local::LocalForwardHandle`'s `Drop` — that type
        // owns the TCP listener itself and correctly tears everything
        // down with it (its own doc); this type owns only the dispatch
        // side, where the peer's connection (forward route) or the
        // resident daemon (reverse route) is what actually accepted the
        // TCP connection, so refusing to finish relaying it would abandon
        // a connection someone else already committed to.
        match &self.dispatch {
            AcceptDispatch::Quic { task } => task.abort(),
            #[cfg(unix)]
            AcceptDispatch::Local { claims, .. } => {
                for (_, task) in claims.lock().unwrap_or_else(|e| e.into_inner()).drain() {
                    task.abort();
                }
            }
        }
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
    let mut tasks = DrainSplicesOnDrop(JoinSet::new());
    loop {
        tokio::select! {
            accepted = conn.accept_bi() => {
                let (send, recv) = match accepted {
                    Ok(pair) => pair,
                    // The connection itself is gone — nothing left to
                    // dispatch. In-flight splices already spawned live in
                    // `tasks`; wrapped in `DrainSplicesOnDrop`, so this
                    // return hands them to a detached reaper that drains
                    // them to their own end rather than aborting them —
                    // matching `RemoteForwardAcceptor::drop`'s reverse-
                    // route behavior (`DrainSplicesOnDrop`'s own doc). In
                    // practice each already-accepted stream rides this
                    // same now-dead `conn`, so it fails on its own almost
                    // immediately either way; this path exists so that
                    // fact is never load-bearing.
                    Err(_) => return,
                };
                let table = Arc::clone(&table);
                tasks.0.spawn(async move {
                    handle_accepted_stream(send, recv, &table).await;
                });
            }
            Some(joined) = tasks.0.join_next(), if !tasks.0.is_empty() => {
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

// ---------------------------------------------------------------------
// Stage E: the reverse-route requester leg — `-R over reverse`
// (`PLAN.md` M4 Step 5 (a)).
// ---------------------------------------------------------------------

/// How long each claim attempt long-polls the daemon for the next
/// `TCP_ACCEPTED` arrival before trying again — the same ceiling the
/// daemon itself clamps every `LOCAL_STREAM` wait to
/// (`crate::localctl::daemon`'s `clamp_wait`/`LOCAL_WAIT_MAX`), so this
/// asks for the largest budget the daemon will actually honor.
#[cfg(unix)]
const REVERSE_CLAIM_WAIT_MS: u32 = qsh_proto::local::LOCAL_WAIT_MAX.as_millis() as u32;

/// How long to pause before retrying a claim that failed for a reason
/// other than "nothing arrived yet" (`ErrorCode::Timeout`) — a daemon
/// that is transiently unreachable (restarting, momentarily overloaded)
/// should not be hammered with a fresh UDS connect in a tight loop. Same
/// order of magnitude as [`crate::tunnel::local::ACCEPT_BACKOFF`], for the
/// same reason.
#[cfg(unix)]
const REVERSE_CLAIM_RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// Build a `TCP_ACCEPTED` claim's `ticket`: `forward_id`, a NUL byte,
/// then `claim_token` — the one place this exact shape is produced, and
/// `crate::localctl::daemon::LocalctlDaemon::serve_tcp_accepted`'s own
/// doc names this function as the shape it parses back apart. A NUL is a
/// safe, unambiguous separator because `forward_id` can never contain one
/// (`wire::valid_forward_id`'s charset is `[A-Za-z0-9_-]`) while
/// `claim_token` is opaque bytes with no charset restriction of its own.
#[cfg(unix)]
fn claim_ticket(forward_id: &str, claim_token: &[u8]) -> Vec<u8> {
    let mut ticket = Vec::with_capacity(forward_id.len() + 1 + claim_token.len());
    ticket.extend_from_slice(forward_id.as_bytes());
    ticket.push(0);
    ticket.extend_from_slice(claim_token);
    ticket
}

/// Owns an accept/dispatch loop's in-flight splice tasks so that when the
/// loop's own task ends — including via `.abort()`
/// ([`RemoteForwardAcceptor::unregister`] on the reverse route,
/// [`RemoteForwardAcceptor::drop`] on both routes) — those splices
/// *drain* to completion instead of being force-aborted with it. Shared,
/// not per-route, on purpose: this is exactly the adversarial-review
/// finding that this type exists to close — reverse-route teardown used
/// to abort every in-flight splice for a forward while the forward-route
/// dispatcher never did, an observable behavioral difference across the
/// role axis this whole PR's headline claim says is independent of
/// connection direction. Both [`dispatch_remote_forwards`] (forward
/// route) and [`claim_remote_forward_reverse`] (reverse route) wrap their
/// splice `JoinSet` in this same type now, so `Drop` drains on both sides
/// identically — the one place this still differs is [`serve_remote_forward`],
/// the *target*-side TCP listener, which is not part of the role axis
/// this type closes (its own doc explains why it tears down with its
/// splices instead).
///
/// Rust drops every live local when a task ends, `.abort()` included —
/// tokio's documented cancellation mechanism is to drop the task's future
/// at its next poll point, which runs ordinary destructors for everything
/// still alive in its stack — so a bare `JoinSet<()>` field here would
/// have its own `Drop` abort every splice still inside it, exactly the
/// bug this type exists to fix. This type's own [`Drop`] intercepts that:
/// it hands the set off to a small *detached* reaper task whose only job
/// is to `join_next()` it to empty, so every splice this loop ever
/// claimed keeps running to its own natural end no matter why or how this
/// loop itself stopped.
struct DrainSplicesOnDrop(JoinSet<()>);

impl Drop for DrainSplicesOnDrop {
    fn drop(&mut self) {
        if self.0.is_empty() {
            return;
        }
        let mut set = std::mem::take(&mut self.0);
        tokio::spawn(async move { while set.join_next().await.is_some() {} });
    }
}

/// Spawn one claim attempt as its own detached task and return its
/// [`tokio::task::JoinHandle`] — the cancel-safety seam
/// [`claim_remote_forward_reverse`]'s own doc explains: a `JoinHandle`
/// dropped mid-poll does **not** abort the task it names (unlike the
/// `JoinSet` [`DrainSplicesOnDrop`] guards), it merely stops *this*
/// caller from observing the result — the underlying `open_stream_with_wait`
/// call keeps running to completion on the runtime regardless of whether
/// or how many times the returned handle is polled. Owned copies of
/// `socket`/`daemon_host`/`header` move into the spawned future so it is
/// fully self-contained (`'static`), independent of the loop's own stack
/// frame.
#[cfg(unix)]
type ClaimAttemptHandle = tokio::task::JoinHandle<
    Result<
        (
            crate::client::link::DataSend,
            crate::client::link::DataRecv,
            crate::client::link::DataKillSwitch,
        ),
        ClientError,
    >,
>;

#[cfg(unix)]
fn spawn_claim_attempt(
    socket: std::path::PathBuf,
    daemon_host: String,
    header: StreamHeader,
) -> ClaimAttemptHandle {
    tokio::spawn(async move {
        let link = DataLink::Local {
            socket: &socket,
            host: &daemon_host,
        };
        crate::tunnel::open_stream_with_wait(&link, &header, REVERSE_CLAIM_WAIT_MS).await
    })
}

/// Guards [`claim_remote_forward_reverse`]'s single currently-outstanding
/// [`spawn_claim_attempt`] handle against the same silent-loss failure
/// mode [`DrainSplicesOnDrop`] fixes for already-spawned splices, one
/// level earlier (adversarial-review finding: `unregister`/[`Drop`] abort
/// only the claim *loop*'s task, never the detached attempt it was
/// polling — that attempt keeps running regardless, per
/// [`spawn_claim_attempt`]'s own doc, and can still be granted a real
/// [`crate::reverse::listen::hub::TunnelArrival`] by the daemon after nothing
/// is left to hand it to [`handle_reverse_claim`]. Left alone, the
/// runtime just drops that `(send, recv, kill)` return value the instant
/// the orphaned task finishes — no reset, no log, the arrival simply
/// stops existing).
///
/// Dropping this type hands the outstanding handle to its own detached
/// reaper, exactly [`DrainSplicesOnDrop`]'s technique: await it, and if
/// it *was* granted, run it to completion through the same
/// [`handle_reverse_claim`] the loop itself would have called — which
/// dials and splices on success, or calls
/// [`crate::client::link::DataKillSwitch::kill`] and logs on a dial
/// failure or a non-`Local` carrier. So a win after teardown is either
/// completed or explicitly, visibly reset — never silently dropped.
/// `Timeout` or any other non-granted outcome needs nothing further;
/// there is no arrival to lose. A `None` handle (the loop always holds
/// `Some` between iterations, see [`claim_remote_forward_reverse`]) is
/// simply a no-op, same as `DrainSplicesOnDrop` on an empty set.
#[cfg(unix)]
struct DrainClaimAttemptOnDrop {
    handle: Option<ClaimAttemptHandle>,
    host: String,
    port: u16,
}

#[cfg(unix)]
impl DrainClaimAttemptOnDrop {
    fn new(handle: ClaimAttemptHandle, host: String, port: u16) -> Self {
        Self {
            handle: Some(handle),
            host,
            port,
        }
    }

    /// Replace the outstanding attempt with a fresh one, same as
    /// reassigning a bare `claim_handle` local did before this type
    /// existed. The handle being replaced has already resolved (it is
    /// only ever called with the just-`joined` arm's own next attempt),
    /// so dropping it here is an ordinary no-op, not a loss.
    fn replace(&mut self, handle: ClaimAttemptHandle) {
        self.handle = Some(handle);
    }

    /// The live handle to poll in `select!` — always `Some` between loop
    /// iterations ([`Self::new`] seeds it, every arm that consumes it
    /// calls [`Self::replace`] before the next poll).
    fn poll_handle(&mut self) -> &mut ClaimAttemptHandle {
        self.handle
            .as_mut()
            .expect("claim_remote_forward_reverse always holds an outstanding attempt")
    }
}

#[cfg(unix)]
impl Drop for DrainClaimAttemptOnDrop {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        let host = std::mem::take(&mut self.host);
        let port = self.port;
        tokio::spawn(async move {
            if let Ok(Ok((send, recv, kill))) = handle.await {
                tracing::debug!(
                    host,
                    port,
                    "qsh::tunnel: reverse TCP_ACCEPTED claim granted after its loop was torn \
                     down, completing the splice instead of discarding it"
                );
                handle_reverse_claim(send, recv, kill, host, port).await;
            }
        });
    }
}

/// One registered `forward_id`'s persistent claim loop on the reverse
/// route (`AcceptDispatch::Local`'s own doc on why one loop per id): long-
/// poll [`crate::tunnel::open_stream_with_wait`] over a
/// [`DataLink::Local`] for the next queued `TCP_ACCEPTED` arrival, spawn a
/// dial-and-splice task for it, and claim again immediately — never
/// waiting for that task to finish, so more than one accepted connection
/// for the same `forward_id` can be in flight at once, exactly like
/// [`serve_remote_forward`]'s own per-connection [`JoinSet`].
///
/// **Cancel-safety** (adversarial review finding, three lenses): the
/// obvious shape — race the claim future directly inside the same
/// `select!` that also races `tasks.join_next()` — is *not* cancel-safe.
/// When an unrelated splice task happens to finish at the same moment a
/// claim is in flight, `select!` polls every branch and, if the splice
/// branch wins, drops the *other* branches' futures — including a claim
/// future that may already have been granted by the daemon (it dequeued
/// a real `TunnelArrival` and is mid-`send` of the `ClaimGranted` frame,
/// or has already sent it): dropping that future there destroys the
/// claimed connection with no trace, silently, for a reason (a *different*
/// forward's splice finishing) that has nothing to do with this claim at
/// all. The fix is [`spawn_claim_attempt`]: each claim attempt is spawned
/// as its own detached task, and only its *`JoinHandle`* is raced in
/// `select!` below. Losing that race — a splice's `tasks.join_next()`
/// branch winning instead — drops only the losing `select!` arm's
/// reference to the handle for *this poll*, not the task the handle
/// names; the claim keeps running to completion on the runtime regardless,
/// and the next loop iteration reaches this same `select!` again and polls
/// the identical, still-live `claim_handle`.
///
/// Runs until [`RemoteForwardAcceptor::unregister`] or
/// [`RemoteForwardAcceptor::drop`] aborts this task — there is no other
/// exit, matching every other tunnel accept loop's contract in this
/// crate ([`DrainSplicesOnDrop`]'s own doc on what happens to any splices
/// still running at that point, [`DrainClaimAttemptOnDrop`]'s own doc on
/// the one attempt still outstanding when that happens). `ErrorCode::Timeout` is the loop's
/// *ordinary* outcome (nothing arrived within this attempt's budget,
/// `crate::localctl::daemon`'s `serve_tcp_accepted`'s own doc on why an
/// unregistered and a merely-idle `forward_id` answer the same way) and
/// is not logged or backed off *when the attempt actually spent its
/// budget waiting* — claiming again is the wait. Any other error gets a
/// short backoff so a genuinely unreachable daemon is retried, not
/// hammered. A claim task ending via `JoinError` (panic) is treated the
/// same as any other failed attempt — logged, backed off, and retried —
/// rather than silently stalling the loop.
///
/// **Fast-timeout guard (adversarial-review finding, `PLAN.md` M4 Step 5
/// PR 5b: a third party — `qsh tunnel close`, via
/// `crate::reverse::listen::ControlHub::admin_close_forward` — can remove
/// this loop's `forward_id` registration without ending this loop's own
/// conduit).** Once that happens, `admits_claim` is `false` for every
/// future attempt and `crate::reverse::listen::ControlHub::claim_tcp_accepted`
/// returns `None` on its very first poll, before any `.await` — so the
/// attempt resolves to `Timeout` in microseconds instead of after the
/// real ~60s (`qsh_proto::local::LOCAL_WAIT_MAX`) budget. Treating that
/// the same as an ordinary exhausted-budget timeout turns this loop into
/// an unbounded hot spin of UDS connect + `LocalHello` + `StreamHeader`
/// for as long as the process lives. Distinguishing the two without a
/// wire change: a `Timeout` whose attempt took under
/// [`FAST_TIMEOUT_THRESHOLD`] cannot have genuinely waited out the
/// budget, so it gets the same [`REVERSE_CLAIM_RETRY_BACKOFF`] every
/// other failure mode gets; only a `Timeout` that actually spent close to
/// the full budget is the ordinary long-poll outcome and is retried at
/// once.
#[cfg(unix)]
const FAST_TIMEOUT_THRESHOLD: Duration = Duration::from_secs(1);

/// The decision [`FAST_TIMEOUT_THRESHOLD`]'s doc describes, pulled out as
/// a pure function so it is unit-testable without driving the real
/// `select!` loop: `true` means the just-finished attempt could not have
/// genuinely waited out [`REVERSE_CLAIM_WAIT_MS`]'s ~60s budget, so it
/// must be a registration that vanished out from under this loop (the
/// only way `claim_tcp_accepted` returns before its first `.await`) — get
/// backed off like every other failure, not retried instantly.
#[cfg(unix)]
fn timeout_needs_backoff(elapsed: Duration) -> bool {
    elapsed < FAST_TIMEOUT_THRESHOLD
}

#[cfg(unix)]
async fn claim_remote_forward_reverse(
    socket: std::path::PathBuf,
    daemon_host: String,
    forward_id: String,
    claim_token: Vec<u8>,
    host: String,
    port: u16,
) {
    let header = StreamHeader {
        kind: StreamKind::TcpAccepted as i32,
        ticket: claim_ticket(&forward_id, &claim_token),
        host: String::new(),
        port: 0,
    };
    let mut tasks = DrainSplicesOnDrop(JoinSet::new());
    let mut attempt_started = Instant::now();
    let mut claim_handle = DrainClaimAttemptOnDrop::new(
        spawn_claim_attempt(socket.clone(), daemon_host.clone(), header.clone()),
        host.clone(),
        port,
    );
    loop {
        tokio::select! {
            joined = claim_handle.poll_handle() => {
                let next = match joined {
                    Ok(Ok((send, recv, kill))) => {
                        tasks
                            .0
                            .spawn(handle_reverse_claim(send, recv, kill, host.clone(), port));
                        attempt_started = Instant::now();
                        spawn_claim_attempt(socket.clone(), daemon_host.clone(), header.clone())
                    }
                    Ok(Err(ClientError::Remote { code: qsh_proto::ErrorCode::Timeout, .. }))
                        if !timeout_needs_backoff(attempt_started.elapsed()) =>
                    {
                        // Nothing arrived within this attempt's budget —
                        // the ordinary long-poll outcome. Claim again
                        // right away.
                        attempt_started = Instant::now();
                        spawn_claim_attempt(socket.clone(), daemon_host.clone(), header.clone())
                    }
                    Ok(Err(err)) => {
                        tracing::warn!(
                            forward_id,
                            %err,
                            "qsh::tunnel: reverse TCP_ACCEPTED claim failed, retrying"
                        );
                        tokio::time::sleep(REVERSE_CLAIM_RETRY_BACKOFF).await;
                        attempt_started = Instant::now();
                        spawn_claim_attempt(socket.clone(), daemon_host.clone(), header.clone())
                    }
                    Err(join_err) => {
                        if join_err.is_panic() {
                            tracing::warn!(
                                forward_id,
                                %join_err,
                                "qsh::tunnel: reverse TCP_ACCEPTED claim task panicked, retrying"
                            );
                        }
                        tokio::time::sleep(REVERSE_CLAIM_RETRY_BACKOFF).await;
                        attempt_started = Instant::now();
                        spawn_claim_attempt(socket.clone(), daemon_host.clone(), header.clone())
                    }
                };
                claim_handle.replace(next);
            }
            Some(joined) = tasks.0.join_next(), if !tasks.0.is_empty() => {
                if let Err(err) = joined
                    && err.is_panic()
                {
                    tracing::warn!(
                        %err,
                        "qsh::tunnel: reverse remote-forward connection task panicked"
                    );
                }
            }
        }
    }
}

/// One claimed `TCP_ACCEPTED` arrival's whole life on the reverse-route
/// requester side: dial this side's own local `host:port` and splice —
/// the reverse-route sibling of [`accept_one`] with the direction of
/// "who dials" unchanged (this side always dials its own local
/// destination; only *how the claim itself was obtained* differs from the
/// forward route's `accept_bi()`/[`handle_accepted_stream`]).
///
/// No `forward_id` lookup here, unlike [`handle_accepted_stream`]: the
/// claim that produced `send`/`recv` already named `forward_id` explicitly
/// (`claim_remote_forward_reverse`'s own header), so there is nothing left
/// to look up — `host`/`port` arrive already resolved, captured by
/// [`RemoteForwardAcceptor::register`] at the moment this loop was
/// spawned.
#[cfg(unix)]
async fn handle_reverse_claim(
    send: crate::client::link::DataSend,
    recv: crate::client::link::DataRecv,
    kill: crate::client::link::DataKillSwitch,
    host: String,
    port: u16,
) {
    let (Ok(raw_send), Ok((raw_recv, residue))) = (send.into_raw_local(), recv.into_raw_local())
    else {
        kill.kill();
        tracing::warn!(
            "qsh::tunnel: reverse TCP_ACCEPTED claim produced a non-Local carrier, dropping"
        );
        return;
    };

    // Same dialer, same timeout, as `handle_accepted_stream`'s own dial.
    let dialer = SystemDialer::default();
    let tcp = match dialer.dial(&host, port).await {
        Ok(tcp) => tcp,
        Err(err) => {
            kill.kill();
            tracing::warn!(
                host,
                port,
                %err,
                "qsh::tunnel: remote-forward local dial failed (reverse route)"
            );
            return;
        }
    };

    match crate::tunnel::splice::splice_tcp_uds(tcp, raw_send, raw_recv, residue).await {
        Ok(stats) => tracing::debug!(
            host,
            port,
            sent = stats.local_to_remote,
            received = stats.remote_to_local,
            "qsh::tunnel: remote-forward local connection closed (reverse route)"
        ),
        Err(err) => tracing::warn!(
            host,
            port,
            %err,
            "qsh::tunnel: remote-forward local connection failed (reverse route)"
        ),
    }
}

#[cfg(test)]
mod tests;
