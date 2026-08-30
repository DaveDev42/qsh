//! `tunnel.*` operations (`docs/CLI.md` §6.9, §6.14; `PLAN.md` M4 Step 3,
//! Step 4).
//!
//! M4 Step 3 landed `tunnel.open` in `"local"` mode — the standalone twin
//! of the interactive `qsh [user@]host -L spec` form (whose entry point is
//! [`crate::ops::SessionAttachStream::open_local_forwards`], because that
//! form's forwards ride the attach's own connection). M4 Step 4 (this
//! addition) lands `"remote"` mode the same way, with
//! [`Ops::session_attach`]'s `remote_forward_specs` parameter as its
//! interactive twin. M4 Step 5 PR 5b lands `tunnel.list`/`tunnel.close`
//! ([`Ops::tunnel_list`]/[`Ops::tunnel_close`]) and route-awareness for
//! `tunnel.open` (forward *and* reverse connections, via
//! [`Ops::tunnel_open_reverse`]).
//!
//! **Holder model** (`PLAN.md` M4 §4.1 #1, `docs/CLI.md` §6.14).
//! `tunnel.open` is a *value* operation that returns one envelope
//! immediately — and then the process that called it has to stay alive,
//! because it *is* the tunnel. [`TunnelHold`] is that obligation made
//! into a type: it owns the connection and the forward (a local listener,
//! or — Step 4 — a remote forward's peer-side registration plus this
//! side's `TCP_ACCEPTED` acceptor), hands the frontend the [`Tunnel`] DTO
//! to render, and then blocks in [`TunnelHold::hold`] until the forward or
//! the connection dies. Dropping it instead is a complete teardown. There
//! is no resident client daemon and no tunnel registry anywhere in this
//! design.
//!
//! **Where the authorization is.** Nowhere here, on *either* mode. A local
//! forward's ACL check (`forward.local`) happens on the peer, inline at
//! every `TCP_CONNECT` stream open, before the peer dials anything
//! (`docs/design/protocol.md` §7's sole ticket exception;
//! `crate::server::Server::authorize_and_dial_tunnel`) — this side binds a
//! loopback listener, which grants nothing and creates nothing remote. A
//! remote forward's ACL check (`forward.remote`) and its loopback-only
//! bind enforcement both happen on the peer too, at `RemoteForwardOpen`
//! (`crate::server::Server::authorize_and_bind_remote_forward`) — this
//! side sends the request and, only on success, starts dialing whatever
//! `TCP_ACCEPTED` streams come back.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use qsh_proto::wire::{self, ForwardDirection, ForwardSpec, parse_forward_spec};
use qsh_proto::{
    ErrorCode, Tunnel, TunnelCloseData, TunnelCloseReq, TunnelListData, TunnelListReq,
    TunnelOpenReq,
};

use crate::ops::session::Connected;
use crate::ops::{OpError, Operation, Ops};
use crate::tunnel::remote::RemoteForwardAcceptor;
use crate::tunnel::{LocalForwardError, LocalForwardHandle};

/// One [`Ops::tunnel_open_and_hold`] registration's close signal
/// (`PLAN.md` M6 Step 2+3 검증 라운드 판정 ②/F2). The payload is a reply
/// channel, not `()`: [`Ops::tunnel_close`]'s same-process path
/// (`close_registered_tunnel_hold`, below) blocks on it, so a caller that
/// gets `closed: true` back can trust the forward is already torn down —
/// listener released, peer notified — not merely that a signal was sent
/// (the E2E requirement task item ②'s "immediate same-port reopen must
/// succeed" depends on this ordering, not just on the signal existing).
type TunnelCloseSignal = tokio::sync::oneshot::Sender<std::sync::mpsc::Sender<()>>;

/// [`Ops`]'s shared, [`Ops::clone`]-visible table of every tunnel this
/// process is holding via [`Ops::tunnel_open_and_hold`], keyed by
/// `tunnel_id`. `Arc`-backed so every clone of one `Ops` sees the same
/// registrations — `crate::mcp::QshMcpServer`'s `call_tool` (`qsh-cli`)
/// clones a fresh `Ops` per tool call, and an `open_tunnel` call's
/// registration must still be visible to a *later* `close_tunnel` call's
/// own clone.
pub(crate) type TunnelHoldRegistry = Arc<Mutex<HashMap<String, TunnelCloseSignal>>>;

/// A fresh, empty [`TunnelHoldRegistry`] — [`Ops::new`]'s own construction
/// site, kept here so the registry's type and its one legal way to start
/// empty live next to each other.
pub(crate) fn new_tunnel_hold_registry() -> TunnelHoldRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

/// The `tunnel.open` operation (`docs/CLI.md` §6.9).
pub struct TunnelOpenOp;
impl Operation for TunnelOpenOp {
    const COMMAND: &'static str = "tunnel.open";
}

/// The `tunnel.list` operation (`qsh tunnels`, `docs/CLI.md` §6.9, `PLAN.md`
/// M4 Step 5 PR 5b).
pub struct TunnelListOp;
impl Operation for TunnelListOp {
    const COMMAND: &'static str = "tunnel.list";
}

/// The `tunnel.close` operation (`qsh tunnel close <id>`, `docs/CLI.md`
/// §6.9, `PLAN.md` M4 Step 5 PR 5b).
pub struct TunnelCloseOp;
impl Operation for TunnelCloseOp {
    const COMMAND: &'static str = "tunnel.close";
}

/// The exact `docs/CLI.md` §6.9 disclosure text for `-D`'s P0 refusal
/// (`PLAN.md` M4 Step 6, DoD 5). This is the single place the wording
/// lives — `qsh-cli`'s two call sites (`InteractiveArgs`'s bare
/// `qsh host -D …` and `TunnelOpenArgs`'s `qsh tunnel open … --dynamic`)
/// both go through [`dynamic_forward_unsupported`] rather than each
/// formatting their own string, so the exit-code matrix and the golden
/// `error.UNSUPPORTED.json` fixture check one wording, not two that could
/// drift apart.
pub const DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE: &str =
    "SOCKS dynamic forwarding (-D) is a P1 feature";

/// `-D`/SOCKS dynamic forwarding's P0 stub (`docs/CLI.md` §6.9,
/// `docs/ROADMAP.md` M4 "명시적 out", `PLAN.md` M4 Step 6, DoD 5).
///
/// Always `UNSUPPORTED`, unconditionally — there is no spec to parse, no
/// bind to attempt, and no ACL check: `forward.socks` is not an M4
/// `Action` (M5 promotes it to "defined, always deny",
/// `docs/ROADMAP.md` M5 scope), so this sits *before* the ACL/connect
/// layer entirely, at what `PLAN.md` calls the "CLI/negotiation layer" —
/// both `qsh-cli` call sites invoke this before calling
/// [`Ops::tunnel_open`]/[`Ops::session_attach`] at all, so no connection,
/// session, or listener exists on this path (`docs/PRD.md` §9, "no
/// resource before authorization" — trivially true here because nothing
/// downstream of this call ever runs).
pub fn dynamic_forward_unsupported() -> OpError {
    OpError::new(ErrorCode::Unsupported, DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE)
}

/// Parse `-L` spec strings into [`ForwardSpec`]s, refusing anything that
/// could not be bound, **before** any resource — local or remote —
/// exists.
///
/// This is the frontend's pre-flight: `docs/CLI.md` §6.9's grammar is
/// checked by [`parse_forward_spec`] (sans-IO, shape only), and this then
/// applies the one policy that is not shape — a `-L` listener binds
/// loopback (`PLAN.md` M4 §4.1 #3) — so `qsh host -L 0.0.0.0:8080:…`
/// fails with `INVALID_ARGUMENT` before a session is opened rather than
/// after. Both failure modes carry a `docs/CLI.md` §3.3 code; M4 adds no
/// new one (§4.1 #9).
///
/// Kept in `qsh-core` rather than in the CLI on purpose: the mapping from
/// a spec string to a typed error code is contract behavior, and a
/// frontend that re-derived it would be the second place it could drift
/// (`docs/CLI.md` §11).
pub fn parse_local_forwards(specs: &[String]) -> Result<Vec<ForwardSpec>, OpError> {
    let mut parsed = Vec::with_capacity(specs.len());
    for spec in specs {
        let mut forward = parse_forward_spec(spec)
            .map_err(|err| OpError::new(err.error_code(), format!("-L {spec}: {}", err.message)))?;
        // `parse_forward_spec` cannot know which flag it came from
        // (`ForwardDirection`'s own doc) — this one did.
        forward.direction = ForwardDirection::Local;
        // Refuse a bind this side would reject anyway, here, where nothing
        // has been created yet.
        crate::tunnel::local::check_bind(&forward)
            .map_err(|err| OpError::new(err.code(), format!("-L {spec}: {err}")))?;
        parsed.push(forward);
    }
    Ok(parsed)
}

/// Parse `-R` spec strings into [`ForwardSpec`]s (`PLAN.md` M4 Step 4).
///
/// Shape only, like [`parse_local_forwards`] — but unlike that function,
/// this one applies **no** loopback pre-check: a `-R` bind is validated on
/// the *peer*, after its `forward.remote` ACL gate
/// (`crate::server::Server::authorize_and_bind_remote_forward`), because
/// loopback-only is a constraint the peer enforces on every principal
/// alike, not something this side can decide in advance
/// (`crate::acl::Action::ForwardRemote`'s own doc). A non-loopback `-R`
/// therefore parses `Ok` here and fails later, on the peer's
/// `RemoteForwardOpened`/`Error` reply, with the same
/// [`ErrorCode::InvalidArgument`] it would have gotten from a client-side
/// check — just one control round trip later.
pub fn parse_remote_forwards(specs: &[String]) -> Result<Vec<ForwardSpec>, OpError> {
    let mut parsed = Vec::with_capacity(specs.len());
    for spec in specs {
        let mut forward = parse_forward_spec(spec)
            .map_err(|err| OpError::new(err.error_code(), format!("-R {spec}: {}", err.message)))?;
        forward.direction = ForwardDirection::Remote;
        parsed.push(forward);
    }
    Ok(parsed)
}

/// Build the wire request a `-R` spec becomes (`docs/design/protocol.md`
/// §7): the `[bind:]` half is what the *peer* should bind, the `host:port`
/// half is where *this* side dials each `TCP_ACCEPTED` it gets back — the
/// same [`ForwardSpec`] field mapping [`spec_from_request`] already uses
/// for `"remote"` mode, exposed here so [`Ops::session_attach`]'s `-R`
/// handling (a different `ops` submodule) does not have to re-derive it.
pub(crate) fn remote_forward_open_from_spec(spec: &ForwardSpec) -> wire::RemoteForwardOpen {
    wire::RemoteForwardOpen {
        bind_host: spec.bind.clone().unwrap_or_default(),
        bind_port: u32::from(spec.listen_port),
        forward_host: spec.host.clone(),
        forward_port: u32::from(spec.host_port),
        // Forward (direct-connect) route never touches `ControlHub`, so
        // this builder leaves the field empty — there is no claimant
        // other than this process's own live QUIC connection.
        //
        // **A reverse-route caller MUST overwrite this field before
        // sending.** An empty `claim_token` is not a "no capability
        // needed" marker there: `crate::reverse::listen::ControlHub`
        // registers such a forward as *permanently unclaimable*
        // (`ClaimSeat`'s own doc — an absent capability is a refusal,
        // never a pass), so its `TCP_ACCEPTED` streams are reset rather
        // than delivered to anyone. `Ops::tunnel_open_reverse` (`PLAN.md`
        // M4 Step 5 PR 5b) does exactly that: it builds the request with
        // this function and then overwrites `claim_token` with
        // `RemoteForwardAcceptor::claim_token`'s bytes before sending.
        claim_token: Vec::new(),
    }
}

/// The `qsh.cli/v1` [`Tunnel`] DTO for a `"remote"`-mode forward
/// (`docs/CLI.md` §6.9). Mirrors [`LocalForwardHandle::tunnel`]'s shape
/// with the two sides swapped: `bind` is where the *peer* bound (this side
/// never learns more than the port the peer's `RemoteForwardOpened`
/// reports, so an unspecified `bind_host` is displayed as the same
/// `127.0.0.1` default `crate::tunnel::remote::resolve_loopback_bind_addr`
/// actually yields), and `forward_to` is this side's own local dial target.
///
/// `tunnel_id` is the peer's `forward_id` verbatim, not a second ID minted
/// here — the same "no parallel ID space" choice `Session.host`/
/// `session_ref` makes (ADR-0007), and the one that lets a future
/// `tunnel.close <id>` (`PLAN.md` M4 Step 5) turn straight into
/// `RemoteForwardClose{forward_id: id}` with no lookup table in between.
pub(crate) fn remote_tunnel_dto(
    spec: &ForwardSpec,
    opened: &wire::RemoteForwardOpened,
    host: &str,
) -> Tunnel {
    let bind_host = spec.bind.as_deref().unwrap_or("127.0.0.1");
    // `opened.actual_port` is peer-supplied (`RemoteForwardOpened`, sent
    // by the target we just asked to bind a port) and not validated to
    // fit a real port range before this point. Clamp once, to the same
    // `u16`, and reuse that single value for *both* `bind`'s port and
    // `actual_port` below — never clamp one and leave the other raw,
    // which would make the two fields disagree about which port is
    // actually bound (adversarial-review finding: `docs/CLI.md` §6.9's
    // own stated invariant is that they always agree, precisely so a
    // reader never has to re-derive one from the other).
    let actual_port = u16::try_from(opened.actual_port).unwrap_or(u16::MAX);
    Tunnel {
        tunnel_id: opened.forward_id.clone(),
        mode: "remote".to_string(),
        bind: wire::format_host_port(bind_host, actual_port),
        forward_to: wire::format_host_port(&spec.host, spec.host_port),
        actual_port: Some(u32::from(actual_port)),
        host: host.to_string(),
    }
}

/// Map a [`LocalForwardError`] onto the shared error vocabulary. The
/// code comes from the error itself (`LocalForwardError::code`), never
/// from a string invented here.
pub(crate) fn map_local_forward_error(err: LocalForwardError) -> OpError {
    OpError::new(err.code(), err.to_string())
}

/// The resource one held tunnel owns on *this* side — a `"local"` mode's
/// listener, or a `"remote"` mode's `TCP_ACCEPTED` dispatcher plus the
/// `forward_id` it dispatches for.
///
/// Both variants are symmetric in the one way that matters for teardown:
/// dropping either aborts the task backing it (`LocalForwardHandle`'s own
/// `Drop`; `RemoteForwardAcceptor`'s own `Drop`), so [`TunnelHold`] does
/// not need to know which variant it holds to tear down correctly — only
/// [`TunnelHold::close`]'s peer-side `RemoteForwardClose` notification
/// needs to match on it.
enum ForwardResource {
    Local(LocalForwardHandle),
    Remote {
        acceptor: RemoteForwardAcceptor,
        forward_id: String,
    },
}

/// A tunnel this process is holding open (`docs/CLI.md` §6.14).
///
/// Owns the peer connection and the forward resource. See this module's
/// doc for why a value operation hands back something that has to be
/// held.
pub struct TunnelHold {
    /// Declared before `conn`: dropping the handle aborts its accept/
    /// dispatch task on `conn`'s runtime, so it must go while that runtime
    /// still exists (same ordering rule as
    /// `SessionAttachStream::forwards`/`remote_acceptor`). Rust drops
    /// struct fields in declaration order, so this ordering *is* the
    /// mechanism, not a comment about one — moving `forward` below `conn`
    /// would abort the task on a runtime that has already gone (this is
    /// the exact bug M4 §4.1 flags as a hazard `TunnelHold` must not
    /// reintroduce).
    forward: ForwardResource,
    conn: Connected,
    tunnel: Tunnel,
}

/// The natural-end wait both [`TunnelHold::hold`] and
/// [`TunnelHold::hold_until_closed`] race against their own close signal
/// (the latter only) — factored out so the two methods cannot drift on
/// what "the tunnel ended on its own" means.
async fn wait_for_end(forward: &mut ForwardResource, conn: &mut Connected) -> OpError {
    match forward {
        ForwardResource::Local(local) => {
            tokio::select! {
                err = local.wait() => OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("the local forward's listener failed: {err}"),
                ),
                err = conn.wait_dead() => err,
            }
        }
        ForwardResource::Remote { .. } => conn.wait_dead().await,
    }
}

impl TunnelHold {
    /// The envelope payload for this tunnel — what the frontend renders
    /// and then stops caring about.
    pub fn tunnel(&self) -> &Tunnel {
        &self.tunnel
    }

    /// Block until this tunnel is over, and say why.
    ///
    /// Two things end it (`docs/CLI.md` §6.14: "그 프로세스가 끝나거나 …
    /// 밑에 깔린 QUIC connection이 죽으면, 그 프로세스가 쥔 모든 터널이
    /// 함께 끝난다"): a `"local"` mode's listener failing fatally, or the
    /// connection carrying the tunnel closing (the only signal a
    /// `"remote"` mode has on this side — the listener lives on the peer,
    /// which has no fatal-error channel back to this side other than the
    /// connection itself). Neither is a normal end — a deliberate end is
    /// the process exiting or this value being dropped, which never
    /// reaches here — so this always returns an error.
    ///
    /// Individual forwarded connections failing (a refusal, a dead
    /// destination, a broken pipe) do **not** end the tunnel; they are
    /// logged structurally and accepting continues.
    ///
    /// "The connection carrying the tunnel closing" is [`Connected::
    /// wait_dead`] on *either* route (`PLAN.md` M4 Step 5 PR 5b) —
    /// forward route: the QUIC connection's own close future, exactly as
    /// before; reverse route: the `LOCAL_CONTROL` conduit's own clean-end/
    /// error, which is this side's only way to learn the reverse
    /// registration died. The runtime handle is taken up front (rather
    /// than borrowing `self.conn.runtime()` for the duration) because the
    /// async block below also needs `&mut self.conn` for `wait_dead`, and
    /// the two borrows cannot coexist.
    pub fn hold(mut self) -> OpError {
        let handle = self.conn.runtime().handle().clone();
        let err = {
            let forward = &mut self.forward;
            let conn = &mut self.conn;
            handle.block_on(wait_for_end(forward, conn))
        };
        self.close();
        err
    }

    /// Like [`Self::hold`], but also returns early — a deliberate close,
    /// never treated as a failure — the instant `close_rx` delivers a
    /// reply channel (`PLAN.md` M6 Step 2+3 검증 라운드 판정 ②/F2).
    ///
    /// [`Self::hold`]'s only close mechanism is process death (`docs/CLI.md`
    /// §6.9's "forward route에서는 tunnel이 그것을 연 CLI 프로세스에 수명이
    /// 결합된다") — exactly right for `qsh tunnel open`, one process per
    /// tunnel, but wrong for a long-running host that opens many tunnels
    /// across many tool calls in one process (`qsh mcp`): killing that
    /// process to close one tunnel would close all of them. This method is
    /// [`Ops::tunnel_open_and_hold`]'s only caller — it is what lets a
    /// *later*, same-process `close_tunnel` reach back into an *earlier*
    /// `open_tunnel`'s still-live hold.
    ///
    /// Either branch tears the tunnel down before returning (`self.close()`,
    /// same as `hold`). `Some` means the tunnel ended on its own — same
    /// meaning `hold`'s always-`Err` return carries. `None` means
    /// `close_rx` delivered a reply channel: this sends `()` back on it
    /// only *after* `self.close()` has finished, so the caller blocked on
    /// that reply can trust the forward — listener released, peer notified
    /// — is really gone, not just that a signal was sent.
    fn hold_until_closed(
        mut self,
        close_rx: tokio::sync::oneshot::Receiver<std::sync::mpsc::Sender<()>>,
    ) -> Option<OpError> {
        enum Outcome {
            Died(OpError),
            Closed(std::sync::mpsc::Sender<()>),
        }
        let handle = self.conn.runtime().handle().clone();
        let outcome = {
            let forward = &mut self.forward;
            let conn = &mut self.conn;
            handle.block_on(async move {
                tokio::select! {
                    err = wait_for_end(forward, conn) => Outcome::Died(err),
                    Ok(ack_tx) = close_rx => Outcome::Closed(ack_tx),
                }
            })
        };
        self.close();
        match outcome {
            Outcome::Died(err) => Some(err),
            Outcome::Closed(ack_tx) => {
                let _ = ack_tx.send(());
                None
            }
        }
    }

    /// Tear the tunnel down: for `"remote"` mode, best-effort ask the peer
    /// to close its listener first (its accept loop, not just this side's
    /// dispatcher registration, must stop — dropping `forward` alone would
    /// leave the peer's listener bound with nobody left to dial its
    /// `TCP_ACCEPTED` streams, the same reasoning [`Ops::session_attach`]'s
    /// own `-R` handling gives); then drop the forward resource, then
    /// close the connection.
    pub fn close(mut self) {
        if let ForwardResource::Remote {
            acceptor,
            forward_id,
        } = &self.forward
        {
            acceptor.unregister(forward_id);
            let close_req = wire::RemoteForwardClose {
                forward_id: forward_id.clone(),
            };
            let _ = self.conn.run(move |s| Box::pin(s.rfwd_close(close_req)));
        }
        // Field order does this already; spelled out so the sequence is
        // not an accident of declaration order in a later edit.
        drop(self.forward);
        self.conn.close();
    }
}

impl Ops {
    /// `tunnel.open` (`docs/CLI.md` §6.9, `-L`/`-R`).
    ///
    /// Sends no `SessionOpen`: this form opens a tunnel and no shell
    /// (`docs/CLI.md` §7, §4.1 #10). `"local"` mode sends no control
    /// message at all — a local forward's only wire traffic is one
    /// `TCP_CONNECT` stream per forwarded TCP connection, each authorized
    /// by the peer at open (protocol.md §7). `"remote"` mode sends exactly
    /// one `RemoteForwardOpen` control round trip before anything exists
    /// (this module's own doc, "where the authorization is").
    ///
    /// The returned [`TunnelHold`] is the tunnel: the caller renders
    /// [`TunnelHold::tunnel`] once and then [`TunnelHold::hold`]s it.
    pub fn tunnel_open(&self, req: TunnelOpenReq) -> Result<TunnelHold, OpError> {
        let spec = spec_from_request(&req)?;
        let conn = self.connect(&req.host)?;
        match conn.connection() {
            Some(connection) => Self::tunnel_open_forward(conn, connection, &spec, &req.host),
            None => Self::tunnel_open_reverse(conn, &spec, &req.host),
        }
    }

    /// Forward route: dial the peer's QUIC connection directly — exactly
    /// [`Self::tunnel_open`]'s original (pre-Step-5) body, unchanged.
    fn tunnel_open_forward(
        mut conn: Connected,
        connection: qsh_transport::Connection,
        spec: &ForwardSpec,
        host: &str,
    ) -> Result<TunnelHold, OpError> {
        match spec.direction {
            ForwardDirection::Local => {
                let forward = match conn
                    .runtime()
                    .block_on(LocalForwardHandle::start(spec, connection))
                {
                    Ok(forward) => forward,
                    Err(err) => {
                        conn.close();
                        return Err(map_local_forward_error(err));
                    }
                };
                let tunnel = forward.tunnel(host);
                Ok(TunnelHold {
                    conn,
                    forward: ForwardResource::Local(forward),
                    tunnel,
                })
            }
            ForwardDirection::Remote => {
                let acceptor = conn
                    .runtime()
                    .block_on(RemoteForwardAcceptor::spawn(connection));
                let open_req = remote_forward_open_from_spec(spec);
                let opened = match conn.run(move |s| Box::pin(s.rfwd_open(open_req))) {
                    Ok(opened) => opened,
                    Err(err) => {
                        conn.close();
                        return Err(err);
                    }
                };
                acceptor.register(opened.forward_id.clone(), spec.host.clone(), spec.host_port);
                let tunnel = remote_tunnel_dto(spec, &opened, host);
                Ok(TunnelHold {
                    conn,
                    forward: ForwardResource::Remote {
                        acceptor,
                        forward_id: opened.forward_id,
                    },
                    tunnel,
                })
            }
        }
    }

    /// Reverse route (`PLAN.md` M4 Step 5 PR 5b): relay through this
    /// machine's resident `qsh listen` daemon over the `LOCAL_STREAM`
    /// conduit instead of a QUIC connection this process does not hold.
    /// `"local"` mode: [`LocalForwardHandle::start_reverse`] — each
    /// forwarded TCP connection opens its own `TCP_CONNECT`-carrying
    /// `LOCAL_STREAM` conduit, same as the forward route's per-connection
    /// stream, just relayed. `"remote"` mode:
    /// [`RemoteForwardAcceptor::spawn_reverse`] mints this holder's own
    /// claim token *before* `RemoteForwardOpen` is sent — the daemon seats
    /// whatever `claim_token` that request carries as the only credential
    /// that may ever claim the resulting `forward_id`'s `TCP_ACCEPTED`
    /// arrivals (`crate::reverse::listen::ForwardRegistration`'s own doc;
    /// [`remote_forward_open_from_spec`]'s forward-route build leaves this
    /// field empty on purpose, so it is overwritten here, never reused).
    ///
    /// Windows has no localctl (UDS) and `Ops::resolve_route` never
    /// produces a reverse route there (`Ops::connect_reverse`'s own
    /// Windows twin), so `conn.connection()` returning `None` — this
    /// function's only caller — is unreachable in practice on that
    /// platform; the `#[cfg(not(unix))]` twin below exists only so the
    /// match in [`Self::tunnel_open`] compiles there.
    #[cfg(unix)]
    fn tunnel_open_reverse(
        mut conn: Connected,
        spec: &ForwardSpec,
        host: &str,
    ) -> Result<TunnelHold, OpError> {
        let Some((socket, route_host)) = conn.reverse_route() else {
            conn.close();
            return Err(OpError::new(
                ErrorCode::Internal,
                "reverse connection is missing its localctl route",
            ));
        };
        let socket = socket.to_path_buf();
        let route_host = route_host.to_string();
        match spec.direction {
            ForwardDirection::Local => {
                let forward = match conn
                    .runtime()
                    .block_on(LocalForwardHandle::start_reverse(spec, socket, route_host))
                {
                    Ok(forward) => forward,
                    Err(err) => {
                        conn.close();
                        return Err(map_local_forward_error(err));
                    }
                };
                let tunnel = forward.tunnel(host);
                Ok(TunnelHold {
                    conn,
                    forward: ForwardResource::Local(forward),
                    tunnel,
                })
            }
            ForwardDirection::Remote => {
                let acceptor = conn
                    .runtime()
                    .block_on(RemoteForwardAcceptor::spawn_reverse(socket, route_host));
                let claim_token = acceptor.claim_token().unwrap_or_default().to_vec();
                let mut open_req = remote_forward_open_from_spec(spec);
                open_req.claim_token = claim_token;
                let opened = match conn.run(move |s| Box::pin(s.rfwd_open(open_req))) {
                    Ok(opened) => opened,
                    Err(err) => {
                        conn.close();
                        return Err(err);
                    }
                };
                // Reverse-route `register()` starts this `forward_id`'s
                // claim loop via a bare `tokio::spawn`
                // ([`RemoteForwardAcceptor::register`]'s own doc), which
                // panics ("no reactor running") unless called from inside
                // an entered Tokio runtime. `qsh-cli`'s `fn main()` is
                // plain synchronous -- there is no ambient runtime on this
                // thread outside a `block_on` call -- so this must be
                // driven through `conn.runtime()` exactly like
                // `spawn_reverse` a few lines above
                // ([`RemoteForwardAcceptor::spawn`]'s own doc names the
                // exact failure mode this call site reproduced until this
                // fix: "the `qsh-cli` `tunnel_e2e` L5 suite panicking with
                // 'no reactor running'").
                conn.runtime().block_on(async {
                    acceptor.register(opened.forward_id.clone(), spec.host.clone(), spec.host_port);
                });
                let tunnel = remote_tunnel_dto(spec, &opened, host);
                Ok(TunnelHold {
                    conn,
                    forward: ForwardResource::Remote {
                        acceptor,
                        forward_id: opened.forward_id,
                    },
                    tunnel,
                })
            }
        }
    }

    /// Windows twin — see [`Self::tunnel_open_reverse`]'s own doc on why
    /// this is unreachable in practice rather than dead code.
    #[cfg(not(unix))]
    fn tunnel_open_reverse(
        conn: Connected,
        _spec: &ForwardSpec,
        _host: &str,
    ) -> Result<TunnelHold, OpError> {
        conn.close();
        Err(OpError::new(
            ErrorCode::Unsupported,
            "reverse routing (localctl) is not available on this platform",
        ))
    }

    /// `tunnel.open` for a long-running, multi-call host process (`qsh mcp`,
    /// `PLAN.md` M6 Step 2+3 검증 라운드 판정 ②/F2) rather than a one-shot
    /// CLI invocation.
    ///
    /// [`Self::tunnel_open`] hands back a [`TunnelHold`] and leaves holding
    /// it entirely to the caller (`docs/CLI.md` §6.14): `qsh tunnel open`
    /// blocks its own single-purpose process in [`TunnelHold::hold`] and
    /// relies on process death (Ctrl-C; for a daemon-held reverse `-R`,
    /// the peer's own `RemoteForwardClose`) as its only close mechanism —
    /// correct there, because that process holds exactly one tunnel. It
    /// breaks down for a server that opens many tunnels across many tool
    /// calls in one long-lived process: killing the process to close one
    /// tunnel would close all of them, and — for a **forward-route**
    /// tunnel, `docs/CLI.md` §6.9's own documented holder-model gap
    /// ("forward route에서 standalone `qsh tunnel open`이 연 터널은 …
    /// 다른 프로세스의 `qsh tunnels`에는 절대 나타나지 않는다") — there is
    /// no daemon involved at all for a *different* process to ask through,
    /// so nothing outside the holding process could ever close it.
    ///
    /// This method keeps the tunnel alive on a background thread — for as
    /// long as this process runs, the same promise §6.14 makes for any
    /// holder — and registers a close signal for it, keyed by `tunnel_id`,
    /// in `self`'s own (shared, `Ops::clone()`-visible)
    /// [`tunnel_holds`](Ops::tunnel_holds) table. [`Self::tunnel_close`]
    /// checks that table before ever touching the cross-process daemon
    /// fan-out ([`Self::admin_close_tunnel`]) — so a `close_tunnel` call in
    /// this *same* process, for a tunnel this *same* process opened this
    /// way, is truthful (`closed: true` really tears the forward down)
    /// regardless of route, not only for a daemon-held reverse `-R`. A
    /// *different* process still cannot see or close a forward-route
    /// tunnel this way — that part of the documented gap is unchanged,
    /// because it is a real consequence of "no resident client daemon and
    /// no tunnel registry" (this module's own top doc), not something an
    /// in-process table can fix across a process boundary.
    pub fn tunnel_open_and_hold(&self, req: TunnelOpenReq) -> Result<Tunnel, OpError> {
        let hold = self.tunnel_open(req)?;
        let tunnel = hold.tunnel().clone();
        let (close_tx, close_rx) = tokio::sync::oneshot::channel();
        self.tunnel_holds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(tunnel.tunnel_id.clone(), close_tx);
        let holds = Arc::clone(&self.tunnel_holds);
        let tunnel_id = tunnel.tunnel_id.clone();
        std::thread::spawn(move || {
            let outcome = hold.hold_until_closed(close_rx);
            if let Some(err) = outcome {
                // Natural death: nobody is ever going to call
                // `close_tunnel` for this id and get a signal through, so
                // remove our own registration — a no-op if
                // `close_registered_tunnel_hold` already raced us to it
                // (whichever side observes the entry first wins; removing
                // an absent key is always safe).
                holds
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&tunnel_id);
                tracing::warn!(%err, "qsh: a held tunnel ended on its own");
            }
        });
        Ok(tunnel)
    }

    /// Same-process half of `tunnel.close` (`PLAN.md` M6 Step 2+3 검증
    /// 라운드 판정 ②/F2): `true`, with the tunnel already torn down by the
    /// time this returns, when `tunnel_id` names a hold
    /// [`Self::tunnel_open_and_hold`] registered in this same `Ops` (any
    /// clone of it — the registry is shared) and has not already ended on
    /// its own; `false` otherwise, leaving [`Self::tunnel_close`] to fall
    /// back to [`Self::admin_close_tunnel`]'s cross-process daemon fan-out.
    fn close_registered_tunnel_hold(&self, tunnel_id: &str) -> bool {
        let close_tx = self
            .tunnel_holds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(tunnel_id);
        let Some(close_tx) = close_tx else {
            return false;
        };
        let (ack_tx, ack_rx) = std::sync::mpsc::channel::<()>();
        if close_tx.send(ack_tx).is_ok() {
            // Block until the holder thread has actually finished tearing
            // the tunnel down (`TunnelHold::close`, inside
            // `hold_until_closed`) — a caller that gets `closed: true`
            // back must be able to trust the listener is already
            // released (e.g. reopen the same port immediately), not
            // merely that a signal was sent.
            let _ = ack_rx.recv();
        }
        // Found and removed either way: the tunnel is gone by the time
        // this returns, whether this call's signal reached the holder in
        // time or it had already ended on its own in the same instant
        // (the send above failing is exactly that race, harmlessly lost).
        true
    }

    /// `tunnel.list` (`qsh tunnels`, `docs/CLI.md` §6.9, `PLAN.md` M4 Step
    /// 5 PR 5b): every tunnel visible to this caller.
    ///
    /// Only ever the daemon-held reverse source — the direct structural
    /// twin of [`crate::ops::host::Ops::host_list`]'s reverse source
    /// ([`crate::localctl::client::admin_tunnel_list_all`], the twin of
    /// `admin_host_list_all`). A forward-route `-L`/`-R` opened by a
    /// standalone `qsh tunnel open` has **no** entry here: that tunnel's
    /// only holder is the CLI process that opened it (`docs/CLI.md` §6.14's
    /// ordinary rule — no resident client daemon), and there is no IPC
    /// surface by which a second, later `qsh tunnels` process could reach
    /// into a first, unrelated process's memory to ask it anything
    /// (`PLAN.md` M4 §3 non-goals: "client-측 상주 터널 데몬(미확정)").
    /// This is a real, deliberate visibility gap, not an oversight — the
    /// only tunnels a resident `qsh listen` daemon can report on are the
    /// ones *it* holds, and only `-R over reverse` ever registers a
    /// `forward_id` with a daemon at all
    /// ([`qsh_proto::local::LocalTunnel::mode`]'s own doc:
    /// [`crate::reverse::listen::ForwardMeta::mode`] is always
    /// `"remote"`).
    ///
    /// Never dials anything and never fails closed on an unreachable or
    /// absent daemon — an empty list is the ordinary "no reverse
    /// connections right now" state, not an error (`docs/CLI.md` §6.9:
    /// same "부분 실패를 감추지 않는다" discipline `host.list` already
    /// documents, applied here to tunnels instead of hosts).
    pub fn tunnel_list(&self, _req: TunnelListReq) -> Result<TunnelListData, OpError> {
        Ok(TunnelListData {
            tunnels: self.reverse_tunnel_entries(),
        })
    }

    /// `tunnel.close <id>` (`docs/CLI.md` §6.9, `PLAN.md` M4 Step 5 PR
    /// 5b): ask every localctl daemon on this machine to close `tunnel_id`
    /// and report whether any of them held it.
    ///
    /// **Ownership decision** (`docs/CLI.md` §2.5: "해당 tunnel의 소유
    /// peer이면 허용"). The wire-level owning-peer check already exists
    /// and is unchanged by this op: `Server::handle_rfwd_close`
    /// (`crates/qsh-core/src/server/mod.rs`) scopes `RemoteForwardClose` to
    /// the **principal** that opened it (`RemoteForwardEntry::owner`, its
    /// own doc — an `opener_key`, not a `conn_id`; F6, M5 Step 5
    /// adversarial review corrected this doc's earlier "scoped to the
    /// connection" premise), so every `RfwdClose` this op eventually causes
    /// the daemon to send still passes that check regardless of which live
    /// connection instance actually carries it — the resident daemon
    /// authenticates to this host as the same device identity on the
    /// reverse connection or on any replacement resume opens for it, so
    /// this does not even need "the daemon is the sole holder of one
    /// connection" to hold. What this op decides is
    /// a *different*, purely local question the wire-level check has
    /// nothing to say about: which local CLI process — this one, running
    /// as a brand-new `qsh tunnel close <id>` invocation, distinct from
    /// whichever process ran the original `tunnel.open` — is allowed to
    /// ask the daemon to do that at all. `ControlHub::admin_close_forward`
    /// (`crate::reverse::listen`) answers it: `localctl`'s same-uid accept
    /// check (`crate::localctl` module docs, `docs/design/architecture.md`
    /// §7) is already the trust boundary every local process crosses to
    /// talk to this daemon in the first place, so a second same-uid
    /// process asking to close a forward the first one opened is still
    /// the owning peer asking — anything stricter (e.g. requiring the same
    /// live conduit) would make `qsh tunnel close <id>` unable to ever
    /// work for a daemon-held forward, since `docs/CLI.md` §6.9's own
    /// usage example has no `--host`/process-affinity argument for it to
    /// reconnect through. This does not weaken the *data*-plane
    /// misdelivery invariant PR 5a built (`docs/design/protocol.md`
    /// §11-3's owner-conduit gate on `RfwdClose` *relay*) — that gate
    /// still applies unchanged to `Self::close` (forward route,
    /// `TunnelHold::close`) and to any other conduit's own `RfwdClose`;
    /// this op instead acts with the *daemon's own authority*, tearing the
    /// registration down locally first (so nothing can be misdelivered to
    /// it from the instant this call is made) before best-effort notifying
    /// the target — see `admin_close_forward`'s own doc for the full
    /// argument.
    ///
    /// No resource is created by this op ever, on any path — closing is
    /// pure teardown, so there is no "authorize before creating" ordering
    /// concern here the way there is for `tunnel.open`.
    ///
    /// Idempotent: `closed: false` (never an error) when `tunnel_id` names
    /// nothing any reachable daemon currently holds — never registered,
    /// already closed, a `"local"` mode id (never registered daemon-side
    /// at all), or a forward-route id (no daemon involved,
    /// [`Self::tunnel_list`]'s own doc) — same shape
    /// [`qsh_proto::TunnelCloseData::closed`]'s own doc requires.
    pub fn tunnel_close(&self, req: TunnelCloseReq) -> Result<TunnelCloseData, OpError> {
        // Same-process registrations (`Self::tunnel_open_and_hold`, F2)
        // take priority: if this `Ops` (or a clone of it) is itself
        // holding `tunnel_id`, that is authoritative and requires no
        // daemon round trip at all. Only when nothing local matches does
        // this fall back to the pre-existing cross-process daemon fan-out
        // — unchanged, still the only path for a reverse-route `-R`
        // opened by a *different* process (`Self::admin_close_tunnel`'s
        // own doc).
        let closed = self.close_registered_tunnel_hold(&req.tunnel_id)
            || self.admin_close_tunnel(&req.tunnel_id);
        Ok(TunnelCloseData {
            tunnel_id: req.tunnel_id,
            closed,
        })
    }

    #[cfg(unix)]
    fn reverse_tunnel_entries(&self) -> Vec<Tunnel> {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                // Never fail `tunnel.list` over this — same "one daemon
                // this machine cannot even start a runtime for must not
                // hide every other tunnel" discipline `host.list` already
                // applies (`crate::ops::host::Ops::reverse_host_entries`).
                tracing::warn!(
                    %err,
                    "tunnel.list: failed to start an async runtime for the reverse source; \
                     reporting no tunnels"
                );
                return Vec::new();
            }
        };
        runtime.block_on(self.reverse_tunnel_entries_async())
    }

    #[cfg(unix)]
    async fn reverse_tunnel_entries_async(&self) -> Vec<Tunnel> {
        let runtime_dir = self.paths().runtime_dir();
        crate::localctl::client::admin_tunnel_list_all(&runtime_dir)
            .await
            .into_iter()
            .flat_map(|daemon| daemon.tunnels.into_iter().map(to_tunnel_dto))
            .collect()
    }

    /// Windows twin: localctl (UDS) has no meaning there, so the reverse
    /// source — the only source `tunnel.list` has — is always empty
    /// (`docs/CLI.md` §6.13).
    #[cfg(not(unix))]
    fn reverse_tunnel_entries(&self) -> Vec<Tunnel> {
        Vec::new()
    }

    #[cfg(unix)]
    fn admin_close_tunnel(&self, tunnel_id: &str) -> bool {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                tracing::warn!(
                    %err,
                    "tunnel.close: failed to start an async runtime for the localctl fan-out; \
                     reporting not closed"
                );
                return false;
            }
        };
        let runtime_dir = self.paths().runtime_dir();
        runtime.block_on(crate::localctl::client::admin_tunnel_close_all(
            &runtime_dir,
            tunnel_id,
        ))
    }

    /// Windows twin: localctl (UDS) has no meaning there, so there is no
    /// daemon to ask and nothing is ever closed by this op
    /// (`docs/CLI.md` §6.13). This is not a gap on Windows specifically:
    /// `tunnel_open_reverse`'s own Windows twin already means no `"remote"`
    /// forward is ever daemon-held there in the first place.
    #[cfg(not(unix))]
    fn admin_close_tunnel(&self, _tunnel_id: &str) -> bool {
        false
    }
}

/// Map a daemon-reported [`qsh_proto::local::LocalTunnel`] to the JSON
/// [`Tunnel`] DTO `tunnel.list` returns — a plain field-for-field copy;
/// `host` is already filled in by the daemon
/// (`LocalctlDaemon::serve_admin_tunnel_list`'s own doc), unlike
/// `host.list`'s reverse source, which fills it from the client-side
/// registration name instead (there is no per-entry ambiguity to resolve
/// here: one `LocalTunnel` is always exactly one forward on exactly one
/// host).
#[cfg(unix)]
fn to_tunnel_dto(local: qsh_proto::local::LocalTunnel) -> Tunnel {
    Tunnel {
        tunnel_id: local.tunnel_id,
        mode: local.mode,
        bind: local.bind,
        forward_to: local.forward_to,
        actual_port: Some(local.actual_port),
        host: local.host,
    }
}

/// Rebuild the [`ForwardSpec`] a [`TunnelOpenReq`] carries in pieces
/// (`docs/CLI.md` §6.9: the request holds the already-parsed halves, never
/// the raw string), for either mode.
///
/// The field mapping is the same [`remote_forward_open_from_spec`] and
/// [`parse_local_forwards`]/[`parse_remote_forwards`] use: `listen_port` is
/// the port bound (locally for `"local"`, on the peer for `"remote"`), and
/// `forward_host`/`forward_port` is where connections end up dialed
/// (on the peer for `"local"`, locally for `"remote"`).
fn spec_from_request(req: &TunnelOpenReq) -> Result<ForwardSpec, OpError> {
    // `mode` is an open string (`docs/CLI.md` §6.9) — an unknown value is
    // `INVALID_ARGUMENT`, the distinction §3.3 draws from a
    // known-but-unimplemented one (M4 has none left here as of Step 4).
    let direction = match req.mode.as_str() {
        "local" => ForwardDirection::Local,
        "remote" => ForwardDirection::Remote,
        other => {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                format!("tunnel mode {other:?} is not one of \"local\", \"remote\""),
            ));
        }
    };
    let listen_port = port(req.listen_port, "listen_port")?;
    let forward_port = port(req.forward_port, "forward_port")?;
    let spec = ForwardSpec {
        direction,
        bind: req.bind.clone(),
        listen_port,
        host: req.forward_host.clone(),
        host_port: forward_port,
    };
    if spec.host.is_empty() {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            "tunnel forward_host is empty",
        ));
    }
    // The loopback pre-check applies to `"local"` only — a `"remote"`
    // bind is validated on the peer, never here
    // ([`parse_remote_forwards`]'s own doc on why).
    if direction == ForwardDirection::Local {
        crate::tunnel::local::check_bind(&spec).map_err(map_local_forward_error)?;
    }
    Ok(spec)
}

/// A JSON `uint32` port narrowed to the `1..=65535` the grammar allows
/// (`docs/CLI.md` §6.9). The wire/JSON types are `u32`, so this is where a
/// request that skipped the CLI parser is caught.
fn port(value: u32, field: &str) -> Result<u16, OpError> {
    match u16::try_from(value) {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(OpError::new(
            ErrorCode::InvalidArgument,
            format!("tunnel {field} {value} is outside 1..=65535"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(mode: &str, bind: Option<&str>, listen_port: u32) -> TunnelOpenReq {
        TunnelOpenReq {
            host: "box".to_string(),
            mode: mode.to_string(),
            bind: bind.map(str::to_string),
            listen_port,
            forward_host: "db.internal".to_string(),
            forward_port: 5432,
        }
    }

    /// A `-R` request is refused as unimplemented, not as malformed, and
    /// an unknown mode the other way round (`docs/CLI.md` §3.3).
    #[test]
    fn both_modes_parse_and_an_unknown_mode_is_invalid_argument() {
        assert_eq!(
            spec_from_request(&req("socks", None, 9000))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        let spec = spec_from_request(&req("local", None, 8080)).unwrap();
        assert_eq!(spec.direction, ForwardDirection::Local);
        assert_eq!(spec.listen_port, 8080);
        assert_eq!((spec.host.as_str(), spec.host_port), ("db.internal", 5432));

        let spec = spec_from_request(&req("remote", None, 9000)).unwrap();
        assert_eq!(spec.direction, ForwardDirection::Remote);
        assert_eq!(spec.listen_port, 9000);
        assert_eq!((spec.host.as_str(), spec.host_port), ("db.internal", 5432));
    }

    /// A request that never went through the CLI parser still cannot
    /// smuggle a port outside the grammar, or (in `"local"` mode) a
    /// non-loopback bind past §4.1 #3. `"remote"` mode applies no such
    /// pre-check (`spec_from_request`'s own doc) — a non-loopback `-R`
    /// bind parses here and is caught on the peer instead.
    #[test]
    fn a_hand_built_request_is_still_held_to_the_grammar_and_the_local_loopback_rule() {
        for mode in ["local", "remote"] {
            for bad in [0, 65_536, u32::MAX] {
                assert_eq!(
                    spec_from_request(&req(mode, None, bad)).unwrap_err().code,
                    ErrorCode::InvalidArgument,
                    "{mode} listen_port {bad}"
                );
            }
        }
        assert_eq!(
            spec_from_request(&req("local", Some("0.0.0.0"), 8080))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(spec_from_request(&req("local", Some("127.0.0.9"), 8080)).is_ok());
        assert!(spec_from_request(&req("local", Some("::1"), 8080)).is_ok());
        // `"remote"` mode: a non-loopback bind is not rejected here — the
        // peer decides (`crate::server::Server::authorize_and_bind_remote_forward`).
        assert!(spec_from_request(&req("remote", Some("0.0.0.0"), 8080)).is_ok());
    }

    /// The frontend pre-flight: the grammar's code and the loopback
    /// rule's code both come back as `INVALID_ARGUMENT`, with the
    /// offending spec named, and nothing is created.
    #[test]
    fn the_preflight_reports_bad_specs_before_anything_binds() {
        let ok = parse_local_forwards(&["8080:localhost:3000".to_string()]).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].direction, ForwardDirection::Local);
        assert_eq!(ok[0].listen_port, 8080);

        for bad in [
            "not-a-spec",
            "0:localhost:3000",
            "70000:localhost:3000",
            "8080::3000",
            "203.0.113.5:8080:localhost:3000",
        ] {
            let err = parse_local_forwards(&[bad.to_string()]).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad}");
            assert!(err.message.contains(bad), "{bad}: {}", err.message);
        }
    }

    /// An empty `-L` list is not an error — it is the ordinary
    /// `qsh [user@]host` form with no forwards.
    #[test]
    fn no_specs_parse_to_no_forwards() {
        assert!(parse_local_forwards(&[]).unwrap().is_empty());
    }

    /// **Regression (adversarial-review finding).** `RemoteForwardOpened
    /// .actual_port` is peer-supplied and not range-checked before this
    /// point — a buggy or hostile target can send any `u32`. Before this
    /// fix, `bind`'s port was clamped to `u16::MAX` on overflow while
    /// `Tunnel.actual_port` kept the raw, un-clamped value, so the two
    /// fields could name two different "actual" ports for the same
    /// tunnel (`docs/CLI.md` §6.9's own stated invariant is that they
    /// always agree). This asserts they still agree once clamped.
    #[test]
    fn remote_tunnel_dto_clamps_bind_and_actual_port_to_the_same_value() {
        let spec = ForwardSpec {
            direction: ForwardDirection::Remote,
            bind: None,
            listen_port: 9000,
            host: "db.internal".to_string(),
            host_port: 5432,
        };
        for out_of_range in [65_536u32, u32::MAX] {
            let opened = wire::RemoteForwardOpened {
                forward_id: "fwd-test".to_string(),
                actual_port: out_of_range,
            };
            let tunnel = remote_tunnel_dto(&spec, &opened, "box");
            assert_eq!(
                tunnel.actual_port,
                Some(u32::from(u16::MAX)),
                "actual_port must be clamped, not left raw, for {out_of_range}"
            );
            assert_eq!(
                tunnel.bind,
                wire::format_host_port("127.0.0.1", u16::MAX),
                "bind's port for {out_of_range}"
            );
        }

        // The ordinary in-range case is untouched: no spurious clamping.
        let opened = wire::RemoteForwardOpened {
            forward_id: "fwd-test".to_string(),
            actual_port: 9000,
        };
        let tunnel = remote_tunnel_dto(&spec, &opened, "box");
        assert_eq!(tunnel.actual_port, Some(9000));
        assert_eq!(tunnel.bind, wire::format_host_port("127.0.0.1", 9000));
    }
}
