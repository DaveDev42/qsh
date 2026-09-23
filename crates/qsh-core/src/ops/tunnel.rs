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
//! `Ops::tunnel_open_reverse`).
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
use std::time::{Duration, Instant};

use qsh_proto::wire::{
    self, ForwardDirection, ForwardSpec, parse_dynamic_spec, parse_forward_spec,
};
use qsh_proto::{
    DynamicTunnel, ErrorCode, Tunnel, TunnelCloseData, TunnelCloseReq, TunnelDynamicReq,
    TunnelListData, TunnelListReq, TunnelOpenReq,
};

use crate::ops::host;
use crate::ops::session::Connected;
use crate::ops::{OpError, Operation, Ops};
use crate::tunnel::remote::RemoteForwardAcceptor;
use crate::tunnel::{DynamicForwardHandle, LocalForwardError, LocalForwardHandle};

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
/// registrations — a long-running external process's (e.g. an agent tool)
/// per-call adapter clones a fresh `Ops` per call, and an `open_tunnel`
/// call's registration must still be visible to a *later* `close_tunnel`
/// call's own clone.
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

/// The `tunnel.dynamic` operation (`-D`, ADR-0019 decision 11).
pub struct TunnelDynamicOp;
impl Operation for TunnelDynamicOp {
    const COMMAND: &'static str = "tunnel.dynamic";
}

/// The security fact `-D` needs to disclose everywhere its ACL story is
/// explained (ADR-0019 decision 14): `-D` is not a new grant, it is
/// `forward.local` reused, and `forward.socks` — despite sitting right
/// next to it in the action vocabulary — plays no part in authorizing it.
/// `README.md` and `docs/CLI.md` §6.9 quote this verbatim
/// (`crates/qsh-core/tests/tunnel_docs.rs` pins both), the same anti-drift
/// discipline that used to guard the P0 stub's own refusal wording before
/// `-D` was implemented.
pub const DYNAMIC_FORWARD_ACL_NOTE: &str = "`-D` runs SOCKS5 on this machine and authorizes every CONNECT on the peer as `forward.local`; `forward.socks` is never consulted.";

/// [`Ops::tunnel_dynamic`]'s missing-capability refusal on the forward
/// route (ADR-0019 decision 3: "peer가 `dial-filter.v1`을 advertise하지
/// 않으면 fallback 없이 UNSUPPORTED로 거부한다"). Names the fix (upgrade the
/// peer), not just the symptom, matching this module's other refusal
/// messages.
pub const DYNAMIC_FORWARD_CAPABILITY_UNSUPPORTED_MESSAGE: &str = "SOCKS dynamic forwarding (-D) needs the peer's dial-filter.v1 capability to enforce \
     host-local address filtering safely, and this peer does not advertise it; nothing was \
     bound. Upgrade qsh on the peer.";

/// `-D` refused after connecting but before binding anything, because the
/// negotiated session capabilities do not include
/// [`wire::CAP_DIAL_FILTER_V1`] (ADR-0019 decision 3's "no fallback" rule
/// — this is not a degrade-gracefully case). The connection this refusal
/// is raised on is always closed by the caller before this returns to the
/// caller of `tunnel_dynamic`/`tunnel_dynamic_with_connected`.
///
/// `pub(crate)`: [`crate::ops::session::SessionAttachStream::open_dynamic_forwards`]
/// reuses this exact wording too, and so does [`Ops::session_open_gated`]
/// for the interactive `-D` ordering (ADR-0020 decisions 2–3).
pub(crate) fn dynamic_forward_capability_unsupported() -> OpError {
    OpError::new(
        ErrorCode::Unsupported,
        DYNAMIC_FORWARD_CAPABILITY_UNSUPPORTED_MESSAGE,
    )
}

/// [`Ops::tunnel_dynamic`]'s missing-capability refusal on the reverse
/// route (ADR-0020 decision 2). Unlike the forward-route message, a
/// missing `dial-filter.v1` here has two distinct possible causes this
/// side cannot tell apart — the target's `qsh` may predate the
/// capability, or this machine's own resident `qsh listen` daemon may
/// have started before *this* machine's `qsh` was upgraded and so is
/// still relaying the older, pre-upgrade capability set it negotiated at
/// registration time — so the refusal names both, plus the next command
/// that clears either one.
pub const DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE: &str = "SOCKS dynamic forwarding (-D) needs dial-filter.v1 to enforce host-local address \
     filtering safely, and this reverse route does not have it: either the target's qsh \
     predates dial-filter.v1, or this machine's `qsh listen` daemon started before this \
     machine's own qsh was last upgraded and is still relaying its old capability set; nothing \
     was bound. Upgrade qsh on the target, then restart `qsh listen` on this machine and retry.";

/// [`DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE`]'s
/// constructor — see [`dynamic_forward_capability_unsupported`]'s own doc
/// for the sharing rationale, which applies identically here.
pub(crate) fn dynamic_forward_reverse_capability_unsupported() -> OpError {
    OpError::new(
        ErrorCode::Unsupported,
        DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE,
    )
}

/// The gate itself (ADR-0019 decision 3, "no fallback"; ADR-0020 decision
/// 2's dual-cause reverse wording), factored out so
/// [`Ops::tunnel_dynamic_with_connected`],
/// [`crate::ops::session::SessionAttachStream::open_dynamic_forwards`] and
/// [`Ops::session_open_gated`] share one predicate, not just the error
/// constructors above — a duplicated `if !caps.iter().any(...)` at each
/// call site meant a test deleting one copy would not have caught the
/// other rotting (found in review; each call site used to re-derive this
/// check independently). `is_reverse` picks which of the two refusal
/// messages a missing capability gets — the connected route already knows
/// which one it is (`Connected::connection().is_none()`), so every call
/// site can pass that straight through rather than re-deriving it.
pub(crate) fn require_dial_filter_capability(
    capabilities: &[String],
    is_reverse: bool,
) -> Result<(), OpError> {
    if capabilities
        .iter()
        .any(|cap| cap == wire::CAP_DIAL_FILTER_V1)
    {
        Ok(())
    } else if is_reverse {
        Err(dynamic_forward_reverse_capability_unsupported())
    } else {
        Err(dynamic_forward_capability_unsupported())
    }
}

#[cfg(test)]
mod require_dial_filter_capability_tests {
    use super::*;

    #[test]
    fn present_capability_is_ok_on_either_route() {
        let caps = vec![wire::CAP_DIAL_FILTER_V1.to_string(), "other.v1".to_string()];
        assert!(require_dial_filter_capability(&caps, false).is_ok());
        assert!(require_dial_filter_capability(&caps, true).is_ok());
    }

    #[test]
    fn missing_capability_on_forward_route_is_the_forward_message() {
        let caps = vec!["other.v1".to_string()];
        let err = require_dial_filter_capability(&caps, false).expect_err("must refuse");
        assert_eq!(err.code, ErrorCode::Unsupported);
        assert_eq!(err.message, DYNAMIC_FORWARD_CAPABILITY_UNSUPPORTED_MESSAGE);
    }

    #[test]
    fn missing_capability_on_reverse_route_names_both_causes() {
        let err = require_dial_filter_capability(&[], true).expect_err("must refuse");
        assert_eq!(err.code, ErrorCode::Unsupported);
        assert_eq!(
            err.message,
            DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE
        );
        assert!(err.message.contains("target's qsh predates"));
        assert!(err.message.contains("qsh listen` daemon started before"));
    }

    #[test]
    fn empty_capability_list_is_unsupported() {
        let err = require_dial_filter_capability(&[], false).expect_err("must refuse");
        assert_eq!(err.code, ErrorCode::Unsupported);
    }
}

/// Parse `-D` spec strings into [`wire::DynamicSpec`]s, refusing anything
/// that could not be bound, **before** any resource — connection or
/// listener — exists. Mirrors [`parse_local_forwards`]'s shape:
/// [`parse_dynamic_spec`] checks the grammar (sans-IO), and this then
/// applies the one policy that is not shape — a `-D` listener binds
/// loopback (ADR-0019 decision 9, same rule `-L` follows) — so `qsh host
/// -D 0.0.0.0:1080` fails with `INVALID_ARGUMENT` before a connection is
/// even dialed, let alone a session opened.
pub fn parse_dynamic_forwards(specs: &[String]) -> Result<Vec<wire::DynamicSpec>, OpError> {
    let mut parsed = Vec::with_capacity(specs.len());
    for spec in specs {
        let dynamic = parse_dynamic_spec(spec)
            .map_err(|err| OpError::new(err.error_code(), format!("-D {spec}: {}", err.message)))?;
        crate::tunnel::local::loopback_bind_addr(
            dynamic.bind.as_deref(),
            dynamic.listen_port,
            "-D",
        )
        .map_err(|err| OpError::new(err.code(), format!("-D {spec}: {err}")))?;
        parsed.push(dynamic);
    }
    Ok(parsed)
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
    /// `-D`'s own SOCKS5 listener (ADR-0019 decision 11). Symmetric with
    /// `Local` for teardown purposes (dropping it aborts its accept task —
    /// [`DynamicForwardHandle`]'s own `Drop`) — the only reason it is not
    /// simply folded into `Local` is that the two hold structurally
    /// different DTOs (`TunnelDto`'s own doc).
    Dynamic(DynamicForwardHandle),
}

/// The envelope payload [`TunnelHold`] hands back — [`Tunnel`] for
/// `tunnel.open`'s `"local"`/`"remote"` modes, [`DynamicTunnel`] for
/// `tunnel.dynamic` (ADR-0019 decision 11: a dedicated DTO, not a widened
/// [`Tunnel`] — that type's own doc). One [`TunnelHold`] only ever holds
/// one or the other, never both, so [`TunnelHold::tunnel`] and
/// [`TunnelHold::dynamic_tunnel`] each panic on the variant they are not —
/// the same "structurally impossible, so panic rather than thread an
/// `Option` through every caller" precedent
/// [`crate::ops::session::Connected::runtime`] already sets.
enum TunnelDto {
    Forward(Tunnel),
    Dynamic(DynamicTunnel),
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
    tunnel: TunnelDto,
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
        ForwardResource::Dynamic(dynamic) => {
            tokio::select! {
                err = dynamic.wait() => OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("the dynamic forward's listener failed: {err}"),
                ),
                err = conn.wait_dead() => err,
            }
        }
    }
}

impl TunnelHold {
    /// The envelope payload for a `"local"`/`"remote"`-mode tunnel — what
    /// the frontend renders and then stops caring about.
    ///
    /// Panics if this hold is actually a `tunnel.dynamic` hold — see
    /// `TunnelDto`'s own doc on why that is structurally impossible from
    /// any real caller (`Ops::tunnel_open`/`tunnel_open_and_hold` are the
    /// only producers of this variant).
    pub fn tunnel(&self) -> &Tunnel {
        match &self.tunnel {
            TunnelDto::Forward(tunnel) => tunnel,
            TunnelDto::Dynamic(_) => {
                unreachable!("TunnelHold::tunnel called on a tunnel.dynamic hold")
            }
        }
    }

    /// [`Self::tunnel`]'s `tunnel.dynamic` twin. Panics if this hold is
    /// actually a `"local"`/`"remote"`-mode hold — see `TunnelDto`'s own
    /// doc.
    pub fn dynamic_tunnel(&self) -> &DynamicTunnel {
        match &self.tunnel {
            TunnelDto::Dynamic(tunnel) => tunnel,
            TunnelDto::Forward(_) => {
                unreachable!("TunnelHold::dynamic_tunnel called on a tunnel.open hold")
            }
        }
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
    /// across many calls in one process (a long-running external process,
    /// e.g. an agent tool): killing that process to close one tunnel would
    /// close all of them. This method is
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
    ///
    /// `req.wait_ms` (`docs/CLI.md` §6.9's `--wait`, issue #4 item 5a)
    /// wraps the connect in a retry over the connect step (private
    /// `connect_with_wait`): absent or `0` takes exactly one attempt,
    /// identical to every call before this field existed.
    pub fn tunnel_open(&self, req: TunnelOpenReq) -> Result<TunnelHold, OpError> {
        let spec = spec_from_request(&req)?;
        let wait_budget_ms = wait_budget_ms(req.wait_ms)?;
        let wait_budget_ms = self.cap_wait_budget_to_stale_retention(wait_budget_ms);
        let conn = self.connect_with_wait(&req.host, wait_budget_ms)?;
        match conn.connection() {
            Some(connection) => Self::tunnel_open_forward(conn, connection, &spec, &req.host),
            None => Self::tunnel_open_reverse(conn, &spec, &req.host),
        }
    }

    /// [`Self::connect`], retried while — and only while — it keeps
    /// failing with the PR-C stale-registration branch (issue #4 items
    /// 3a/5a): `HOST_NOT_FOUND`, `retryable: true`,
    /// `details.reason == host::STALE_REGISTRATION_REASON`
    /// ([`is_stale_registration`]). Any other error, including a
    /// `HOST_NOT_FOUND` for a name with no registration at all, returns
    /// on the very first attempt — this never widens what `--wait`
    /// retries beyond the one documented branch. `wait_budget_ms == 0`
    /// (absent `--wait`, or `--wait 0`) also takes exactly one attempt,
    /// so this is a no-op wrapper in every call site that existed before
    /// the flag did.
    ///
    /// The retry decision itself is [`retry_while_stale`], factored out
    /// generic over the attempt's return type so it is unit-testable
    /// against a fake attempt closure without a real daemon or peer
    /// (`docs/design/testing.md` L2) — the real-daemon case (registration
    /// actually coming back mid-wait) is
    /// `crates/qsh-testkit/tests/reverse_tunnel.rs`'s job.
    fn connect_with_wait(&self, host: &str, wait_budget_ms: u64) -> Result<Connected, OpError> {
        retry_while_stale(wait_budget_ms, WAIT_POLL_INTERVAL, || self.connect(host))
    }

    /// Cap a wait budget at this machine's own effective
    /// `[listen].stale_retention` (`docs/design/protocol.md` §11-4, issue
    /// #4 item 5a) — [`WAIT_MS_MAX`]'s own `0..=600_000` bound is a wire-
    /// level sanity check, not a promise that the whole range stays
    /// retryable: once `stale_retention` elapses,
    /// `Registry::sweep_expired` (`crates/qsh-core/src/reverse/registry.rs`)
    /// removes the registry entry outright, and the next resolution falls
    /// through to a non-retryable "not configured" `HOST_NOT_FOUND`
    /// (`ops::host::unconfigured_host_not_found`) that
    /// [`is_stale_registration`] no longer recognizes. Left uncapped, a
    /// `--wait` past that window would silently stop being retryable
    /// partway through — contradicting `docs/CLI.md` §6.9's "예산이 다
    /// 떨어지면 마지막 시도가 낸 것과 같은 retryable `HOST_NOT_FOUND`를
    /// 그대로 돌려준다" promise. Capping here keeps `retry_while_stale`
    /// from ever running past the point where a stale error could still
    /// occur, so its own expiry branch always returns one.
    ///
    /// Same best-effort/infallible-on-config-error shape as
    /// [`host::Ops::stale_retry_after_ms`](super::host)'s own doc: a
    /// malformed local `config.toml` must not turn this bound into a hard
    /// routing failure, so any load/validation error falls back to the
    /// compiled-in default ([`crate::config::ListenConfig::
    /// DEFAULT_STALE_RETENTION_SECS`], 120 s) instead of propagating.
    fn cap_wait_budget_to_stale_retention(&self, wait_budget_ms: u64) -> u64 {
        let retention_ms = self
            .config()
            .ok()
            .and_then(|config| config.stale_retention().ok())
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(crate::config::ListenConfig::DEFAULT_STALE_RETENTION_SECS * 1_000);
        wait_budget_ms.min(retention_ms)
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
                    tunnel: TunnelDto::Forward(tunnel),
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
                    tunnel: TunnelDto::Forward(tunnel),
                })
            }
        }
    }

    /// Reverse route (`PLAN.md` M4 Step 5 PR 5b): relay through this
    /// machine's resident `qsh listen` daemon over the `LOCAL_STREAM`
    /// conduit instead of a QUIC connection this process does not hold.
    /// `"local"` mode: `LocalForwardHandle::start_reverse` — each
    /// forwarded TCP connection opens its own `TCP_CONNECT`-carrying
    /// `LOCAL_STREAM` conduit, same as the forward route's per-connection
    /// stream, just relayed. `"remote"` mode:
    /// `RemoteForwardAcceptor::spawn_reverse` mints this holder's own
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
                    tunnel: TunnelDto::Forward(tunnel),
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
                    tunnel: TunnelDto::Forward(tunnel),
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

    /// `tunnel.open` for a long-running, multi-call host process (e.g. an
    /// agent tool, `PLAN.md` M6 Step 2+3 검증 라운드 판정 ②/F2) rather than a one-shot
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
    /// `tunnel_holds` table. [`Self::tunnel_close`]
    /// checks that table before ever touching the cross-process daemon
    /// fan-out (`Self::admin_close_tunnel`) — so a `close_tunnel` call in
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
        self.register_hold(hold, tunnel.tunnel_id.clone());
        Ok(tunnel)
    }

    /// The registration half of [`Self::tunnel_open_and_hold`]/
    /// [`Self::tunnel_dynamic_and_hold`], factored out so both `_and_hold`
    /// twins share one place that inserts into `self.tunnel_holds` and
    /// spawns the background thread that keeps `hold` alive until a
    /// same-process `tunnel.close` (or the tunnel's own natural death)
    /// ends it — rather than two copies of this bookkeeping that could
    /// drift apart.
    fn register_hold(&self, hold: TunnelHold, tunnel_id: String) {
        let (close_tx, close_rx) = tokio::sync::oneshot::channel();
        self.tunnel_holds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(tunnel_id.clone(), close_tx);
        let holds = Arc::clone(&self.tunnel_holds);
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
    }

    /// `tunnel.dynamic` (`-D`, ADR-0019 decision 11, ADR-0020 decisions 1–3).
    ///
    /// Order, each step failing closed before the next resource exists
    /// (`docs/PRD.md` §9's "never create a resource before authorization
    /// succeeds", applied here one step earlier still — before even a
    /// connection exists):
    ///
    /// 1. shape + loopback bind check ([`parse_dynamic_forwards`]'s own
    ///    policy, applied inline here since this is one spec, not a list) —
    ///    a non-loopback `bind` is `INVALID_ARGUMENT` before anything
    ///    connects, with zero connect attempts made;
    /// 2. connect — forward *or* reverse (ADR-0020 decision 1 lifts the
    ///    forward-only restriction ADR-0019 decision 10 originally set;
    ///    `Self::connect` resolves the route the same way every other
    ///    value op does);
    /// 3. require `dial-filter.v1` on whichever route connected
    ///    (`Self::tunnel_dynamic_with_connected`, ADR-0019 decision 3,
    ///    ADR-0020 decision 2's dual-cause reverse wording) — the
    ///    connection is closed and the call refused, with nothing bound,
    ///    if absent, no fallback;
    /// 4. only then bind the SOCKS5 listener, opening each `CONNECT`
    ///    through the connected route's own carrier
    ///    (`ForwardCarrier::Quic`/`Local`).
    pub fn tunnel_dynamic(&self, req: TunnelDynamicReq) -> Result<TunnelHold, OpError> {
        let listen_port = port(req.listen_port, "listen_port")?;
        crate::tunnel::local::loopback_bind_addr(req.bind.as_deref(), listen_port, "-D")
            .map_err(map_local_forward_error)?;
        let conn = self.connect(&req.host)?;
        Self::tunnel_dynamic_with_connected(conn, req.bind.as_deref(), listen_port, &req.host)
    }

    /// The post-connect half of [`Self::tunnel_dynamic`], split out as a
    /// test seam: a test can hand this a [`Connected`] built directly
    /// ([`Connected::for_test_forward`]/[`Connected::for_test_reverse`])
    /// carrying a fabricated negotiated capability set, to exercise the
    /// capability gate without a real peer `Hello`/`LocalHelloAck`
    /// answering a dial.
    fn tunnel_dynamic_with_connected(
        conn: Connected,
        bind: Option<&str>,
        listen_port: u16,
        host: &str,
    ) -> Result<TunnelHold, OpError> {
        let is_reverse = conn.connection().is_none();
        if let Err(err) = require_dial_filter_capability(conn.capabilities(), is_reverse) {
            conn.close();
            return Err(err);
        }
        match conn.connection() {
            Some(connection) => {
                Self::tunnel_dynamic_forward(conn, connection, bind, listen_port, host)
            }
            None => Self::tunnel_dynamic_reverse(conn, bind, listen_port, host),
        }
    }

    /// Forward route: dial the peer's QUIC connection directly — exactly
    /// [`Self::tunnel_dynamic_with_connected`]'s original (pre-ADR-0020)
    /// body once the capability gate has already passed.
    fn tunnel_dynamic_forward(
        conn: Connected,
        connection: qsh_transport::Connection,
        bind: Option<&str>,
        listen_port: u16,
        host: &str,
    ) -> Result<TunnelHold, OpError> {
        let forward = match conn.runtime().block_on(DynamicForwardHandle::start(
            bind,
            listen_port,
            connection,
        )) {
            Ok(forward) => forward,
            Err(err) => {
                conn.close();
                return Err(map_local_forward_error(err));
            }
        };
        let tunnel = forward.dynamic_tunnel(host);
        Ok(TunnelHold {
            conn,
            forward: ForwardResource::Dynamic(forward),
            tunnel: TunnelDto::Dynamic(tunnel),
        })
    }

    /// Reverse route (ADR-0020 decision 1): relay through this machine's
    /// resident `qsh listen` daemon over the `LOCAL_STREAM` conduit
    /// instead of a QUIC connection this process does not hold — same
    /// shape as [`Self::tunnel_open_reverse`]'s `"local"` mode, just with
    /// [`DynamicForwardHandle::start_reverse`] in place of
    /// `LocalForwardHandle::start_reverse`.
    ///
    /// Windows has no localctl (UDS) and `Ops::resolve_route` never
    /// produces a reverse route there, so `conn.connection()` returning
    /// `None` — this function's only caller — is unreachable in practice
    /// on that platform; the `#[cfg(not(unix))]` twin below exists only so
    /// the match in [`Self::tunnel_dynamic_with_connected`] compiles there.
    #[cfg(unix)]
    fn tunnel_dynamic_reverse(
        conn: Connected,
        bind: Option<&str>,
        listen_port: u16,
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
        let forward = match conn.runtime().block_on(DynamicForwardHandle::start_reverse(
            bind,
            listen_port,
            socket,
            route_host,
        )) {
            Ok(forward) => forward,
            Err(err) => {
                conn.close();
                return Err(map_local_forward_error(err));
            }
        };
        let tunnel = forward.dynamic_tunnel(host);
        Ok(TunnelHold {
            conn,
            forward: ForwardResource::Dynamic(forward),
            tunnel: TunnelDto::Dynamic(tunnel),
        })
    }

    /// Windows twin — see [`Self::tunnel_dynamic_reverse`]'s own doc on why
    /// this is unreachable in practice rather than dead code.
    #[cfg(not(unix))]
    fn tunnel_dynamic_reverse(
        conn: Connected,
        _bind: Option<&str>,
        _listen_port: u16,
        _host: &str,
    ) -> Result<TunnelHold, OpError> {
        conn.close();
        Err(OpError::new(
            ErrorCode::Unsupported,
            "reverse routing (localctl) is not available on this platform",
        ))
    }

    /// [`Self::tunnel_open_and_hold`]'s `tunnel.dynamic` twin (ADR-0019
    /// decision 11) — same long-running-host holder-table registration
    /// (this module's own top doc), so a same-process `tunnel.close` can
    /// tear a `-D` listener down too, not only a `-L`/`-R` one.
    pub fn tunnel_dynamic_and_hold(&self, req: TunnelDynamicReq) -> Result<DynamicTunnel, OpError> {
        let hold = self.tunnel_dynamic(req)?;
        let tunnel = hold.dynamic_tunnel().clone();
        self.register_hold(hold, tunnel.tunnel_id.clone());
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
    /// twin of [`crate::ops::Ops::host_list`]'s reverse source
    /// (`crate::localctl::client::admin_tunnel_list_all`, the twin of
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
    /// `ForwardMeta::mode` is always
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

/// Upper bound on `TunnelOpenReq.wait_ms` (`docs/CLI.md` §6.9's `--wait`,
/// issue #4 item 5a) — ten minutes, an effectively-unbounded-hang refusal
/// at the wire/parse layer, checked by [`wait_budget_ms`] before a
/// connection is ever attempted. It is not, by itself, a promise that the
/// whole `0..=600_000` range stays retryable: the value that actually
/// governs how long a stale registration stays retryable is
/// `[listen].stale_retention` (`crate::config::ListenConfig`, default
/// 120 s — well under this constant), because
/// [`Ops::cap_wait_budget_to_stale_retention`] additionally caps the
/// budget at that value before retrying.
const WAIT_MS_MAX: u32 = 600_000;

/// Poll interval for [`retry_while_stale`]'s client-side retry loop —
/// short enough that a registration coming back mid-wait is picked up
/// promptly, long enough not to hammer the local daemon list
/// (`Ops::reverse_host_entries`, one `admin_host_list_all` round trip per
/// attempt) while waiting.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Validate and narrow `TunnelOpenReq.wait_ms` to the millisecond budget
/// [`retry_while_stale`] takes — same "a request that skipped the CLI
/// parser is still caught here" discipline as [`port`] just above.
/// Absent maps to `0` (one attempt, unchanged from before `--wait`
/// existed).
fn wait_budget_ms(wait_ms: Option<u32>) -> Result<u64, OpError> {
    match wait_ms {
        None => Ok(0),
        Some(ms) if ms <= WAIT_MS_MAX => Ok(u64::from(ms)),
        Some(ms) => Err(OpError::new(
            ErrorCode::InvalidArgument,
            format!("tunnel wait_ms {ms} is outside 0..={WAIT_MS_MAX}"),
        )),
    }
}

/// Whether `err` is exactly the PR-C stale-registration branch
/// (`crate::ops::host::stale_host_not_found`'s own doc; issue #4 items
/// 3a/5a) — `--wait` retries this branch alone, never a `HOST_NOT_FOUND`
/// for a name with no registration at all (that one is `retryable:
/// false`) and never any other error code.
fn is_stale_registration(err: &OpError) -> bool {
    err.code == ErrorCode::HostNotFound
        && err.retryable
        && err
            .details
            .get("reason")
            .and_then(serde_json::Value::as_str)
            == Some(host::STALE_REGISTRATION_REASON)
}

/// The retry driver [`Ops::connect_with_wait`] wires to a real
/// [`Ops::connect`] — kept generic and free of `Connected`/`resolve_route`
/// so it is unit-testable against a fake `attempt` closure
/// (this module's `tests::retry_while_stale_tests`).
///
/// Attempts `attempt` once unconditionally; on
/// [`is_stale_registration`] error and remaining budget, sleeps up to
/// `poll_interval` (capped by what is left) and attempts again. Any other
/// error, or an exhausted budget, returns that attempt's own `Err`
/// unchanged — in particular, on expiry this is the *same* retryable
/// stale error the last attempt produced, not a generic timeout (issue
/// #4 item 5a's own "returns the SAME retryable error" requirement).
/// `wait_budget_ms == 0` never retries at all, regardless of what
/// `attempt` returns.
fn retry_while_stale<T>(
    wait_budget_ms: u64,
    poll_interval: Duration,
    mut attempt: impl FnMut() -> Result<T, OpError>,
) -> Result<T, OpError> {
    let deadline = Instant::now() + Duration::from_millis(wait_budget_ms);
    loop {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(err) if wait_budget_ms > 0 && is_stale_registration(&err) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(err);
                }
                std::thread::sleep(poll_interval.min(deadline - now));
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    fn req(mode: &str, bind: Option<&str>, listen_port: u32) -> TunnelOpenReq {
        TunnelOpenReq {
            host: "box".to_string(),
            mode: mode.to_string(),
            bind: bind.map(str::to_string),
            listen_port,
            forward_host: "db.internal".to_string(),
            forward_port: 5432,
            wait_ms: None,
        }
    }

    /// `--wait`'s bound (`docs/CLI.md` §6.9, issue #4 item 5a): `0..=600_000`
    /// is accepted (mapped straight through as a millisecond budget),
    /// anything above is `INVALID_ARGUMENT` before a connection is ever
    /// attempted — same shape as [`port`]'s own `1..=65535` check just
    /// above it in this file.
    #[test]
    fn wait_ms_is_bounded_0_to_600_000() {
        assert_eq!(wait_budget_ms(None).unwrap(), 0);
        assert_eq!(wait_budget_ms(Some(0)).unwrap(), 0);
        assert_eq!(
            wait_budget_ms(Some(WAIT_MS_MAX)).unwrap(),
            u64::from(WAIT_MS_MAX)
        );
        let err = wait_budget_ms(Some(WAIT_MS_MAX + 1)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(err.message.contains("wait_ms"), "{}", err.message);
        assert_eq!(
            wait_budget_ms(Some(u32::MAX)).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    /// [`wait_budget_ms`]'s bound wired all the way through
    /// [`Ops::tunnel_open`], not just the private helper the test above
    /// pins in isolation (issue #4 item 5a review finding: nothing
    /// previously called `tunnel_open` with an out-of-range `wait_ms`, so
    /// a mutation that let it silently become `0` passed the whole
    /// suite). `wait_budget_ms(req.wait_ms)?` runs before
    /// `connect_with_wait` ever dials anything, so this needs no daemon
    /// or peer — a valid `listen_port` (`req`'s own default shape) keeps
    /// `spec_from_request`'s own port check from firing first and masking
    /// which check actually rejected the request.
    #[test]
    fn tunnel_open_rejects_an_out_of_range_wait_ms_before_ever_connecting() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
        let ops = Ops::new(paths);
        let over_budget = TunnelOpenReq {
            wait_ms: Some(WAIT_MS_MAX + 1),
            ..req("local", None, 8080)
        };
        let err = match ops.tunnel_open(over_budget) {
            Ok(_) => panic!("wait_ms above WAIT_MS_MAX must be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(err.message.contains("wait_ms"), "{}", err.message);
    }

    /// A retryable `HOST_NOT_FOUND` shaped exactly like
    /// `crate::ops::host::stale_host_not_found`'s output (that function is
    /// private to `ops::host`, so this rebuilds the same shape from its
    /// public `STALE_REGISTRATION_REASON` rather than reaching into it) —
    /// the one branch [`retry_while_stale`] is allowed to retry.
    fn stale_err() -> OpError {
        OpError::new(ErrorCode::HostNotFound, "reverse registration is stale")
            .with_retryable(true)
            .with_details(serde_json::json!({
                "reason": host::STALE_REGISTRATION_REASON,
                "lost_ago_ms": 1234,
                "retry_after_ms": 30_000,
            }))
    }

    /// A `HOST_NOT_FOUND` for a name with **no** registration at all
    /// (`crate::ops::host::unconfigured_host_not_found`'s shape) —
    /// same code as [`stale_err`], `retryable: false`, no `reason` in
    /// `details`. [`is_stale_registration`]/[`retry_while_stale`] must
    /// tell the two apart on more than `code` alone.
    fn unretryable_not_found_err() -> OpError {
        OpError::new(ErrorCode::HostNotFound, "no such host").with_retryable(false)
    }

    #[test]
    fn is_stale_registration_matches_only_the_pr_c_shape() {
        assert!(is_stale_registration(&stale_err()));
        assert!(!is_stale_registration(&unretryable_not_found_err()));
        // Same code, retryable, but a different `details.reason` — must
        // not be mistaken for the stale branch.
        let other_reason = OpError::new(ErrorCode::HostNotFound, "x")
            .with_retryable(true)
            .with_details(serde_json::json!({ "reason": "something_else" }));
        assert!(!is_stale_registration(&other_reason));
        assert!(!is_stale_registration(&OpError::new(
            ErrorCode::ConnectionFailed,
            "x"
        )));
    }

    /// Mutation check (issue #4 item 5a's own "Tests" ask): comment the
    /// retry loop out of [`retry_while_stale`] — i.e. make it return on
    /// the very first `Err` regardless of budget — and this test reds,
    /// because it would then see `stale_err()` instead of the eventual
    /// `Ok`.
    #[test]
    fn retry_while_stale_retries_the_stale_branch_until_it_succeeds() {
        let mut calls = 0u32;
        let result = retry_while_stale(5_000, Duration::from_millis(5), || {
            calls += 1;
            if calls < 3 {
                Err(stale_err())
            } else {
                Ok("connected")
            }
        });
        assert_eq!(result, Ok("connected"));
        assert_eq!(
            calls, 3,
            "must have retried exactly twice before succeeding"
        );
    }

    /// Mutation check (issue #4 item 5a's own "Tests" ask): replace the
    /// expiry return with a generic/synthesized error instead of the
    /// last attempt's own `Err`, and this test reds — the returned error
    /// must equal `stale_err()` field-for-field (code, `retryable`, and
    /// `details` all included, via `OpError`'s derived `PartialEq`), not
    /// merely share its `ErrorCode`.
    #[test]
    fn retry_while_stale_returns_the_last_attempts_own_stale_error_on_expiry() {
        let mut calls = 0u32;
        let result: Result<(), OpError> = retry_while_stale(30, Duration::from_millis(10), || {
            calls += 1;
            Err(stale_err())
        });
        assert_eq!(result, Err(stale_err()));
        assert!(
            calls >= 2,
            "a 30ms budget over a 10ms poll must retry at least once: {calls}"
        );
    }

    /// A non-stale error — even one that shares `HOST_NOT_FOUND` — returns
    /// on the very first attempt regardless of budget: `--wait` never
    /// widens retrying beyond the one documented branch.
    #[test]
    fn retry_while_stale_never_retries_a_non_stale_error() {
        let mut calls = 0u32;
        let result: Result<(), OpError> =
            retry_while_stale(5_000, Duration::from_millis(5), || {
                calls += 1;
                Err(unretryable_not_found_err())
            });
        assert_eq!(result, Err(unretryable_not_found_err()));
        assert_eq!(calls, 1);
    }

    /// `wait_budget_ms == 0` (absent `--wait`, or `--wait 0`) is a single
    /// attempt even when that attempt is the stale branch — the
    /// byte-identical-to-before-this-flag guarantee (`docs/CLI.md` §6.9).
    #[test]
    fn retry_while_stale_with_a_zero_budget_never_retries_even_the_stale_branch() {
        let mut calls = 0u32;
        let result: Result<(), OpError> = retry_while_stale(0, Duration::from_millis(5), || {
            calls += 1;
            Err(stale_err())
        });
        assert_eq!(result, Err(stale_err()));
        assert_eq!(calls, 1);
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

    /// ADR-0019 decision 3, no-fallback half: a peer that does not
    /// advertise `dial-filter.v1` gets `UNSUPPORTED` and **nothing is
    /// bound** — pinned by asking the OS for an ephemeral port
    /// (`listen_port: 0`) and confirming `Ok` was never reached at all
    /// (there is no handle to ask for its bound port; the only way to
    /// observe "nothing bound" here is that this call never got that far).
    ///
    /// Builds a real (but handshake-free) forward-route [`Connected`] via
    /// [`Connected::for_test_forward`]: `Session::from_control` performs
    /// no I/O, so a hand-built [`wire::Hello`] whose `capabilities` omits
    /// [`wire::CAP_DIAL_FILTER_V1`] is enough to exercise the gate without
    /// a real peer answering one.
    #[test]
    fn tunnel_dynamic_without_dial_filter_capability_is_unsupported_and_binds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
        let ops = Ops::new(paths);
        let runtime = ops.connect_runtime().unwrap();

        // `_server` is never touched again but must stay alive for the
        // test's whole duration: dropping the peer's own accepted
        // connection would tear down `client`'s side of the loopback pair
        // out from under it.
        let (endpoint, client, _server) =
            runtime.block_on(crate::tunnel::testutil::loopback_pair_with_client_endpoint());
        // The control stream `Session::from_control` stores — never read
        // in this test, since the capability check runs before any
        // request would ever go out on it.
        let ctl = runtime.block_on(async {
            let (send, recv) = client.open_bi().await.unwrap();
            qsh_transport::FramedStream::control(send, recv)
        });
        let hello = wire::Hello {
            versions: vec![1],
            device_name: "peer".to_string(),
            // Every other capability present, `dial-filter.v1` deliberately
            // missing — an old peer that predates ADR-0019.
            capabilities: vec![
                qsh_proto::wire::CAP_EXEC.to_string(),
                qsh_proto::wire::CAP_SESSION.to_string(),
            ],
            reverse: None,
        };
        let session = crate::client::Session::from_control(client.clone(), ctl, hello);
        let conn = Connected::for_test_forward(runtime, endpoint, client, session);

        let err = match Ops::tunnel_dynamic_with_connected(conn, None, 0, "box") {
            Err(err) => err,
            Ok(_) => panic!("-D must never bind without the peer's dial-filter.v1 capability"),
        };
        assert_eq!(err.code, ErrorCode::Unsupported);
        assert_eq!(err.message, DYNAMIC_FORWARD_CAPABILITY_UNSUPPORTED_MESSAGE);
    }

    /// ADR-0020 decision 2's reverse-route twin of the test just above:
    /// a reverse route whose `LOCAL_CONTROL` registration never negotiated
    /// `dial-filter.v1` gets `UNSUPPORTED` naming both possible causes, and
    /// **nothing is bound** — same "no handle to ask for a bound port, so
    /// the only way to observe it is that this call never got that far"
    /// pin as the forward-route test.
    ///
    /// Builds a real (but registration-free) reverse-route [`Connected`]
    /// via [`Connected::for_test_reverse`]: a fake localctl daemon,
    /// speaking exactly the `qsh.local.v1` `LOCAL_CONTROL` handshake
    /// [`crate::localctl::client::open_control_over`] drives, answers with
    /// a `LocalHelloAck` whose `capabilities` omits
    /// [`wire::CAP_DIAL_FILTER_V1`] — the same "target predates the
    /// capability, or this machine's own `qsh listen` daemon has not been
    /// restarted since its own upgrade" state ADR-0020 decision 2 names.
    #[cfg(unix)]
    #[test]
    fn tunnel_dynamic_over_reverse_without_dial_filter_capability_is_unsupported_and_binds_nothing()
    {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
        let ops = Ops::new(paths);
        let runtime = ops.connect_runtime().unwrap();

        let handshake = runtime.block_on(async {
            let (client_end, daemon_end) = tokio::net::UnixStream::pair().expect("socketpair");
            tokio::spawn(async move {
                let mut daemon = crate::localctl::frame::LocalConduit::new(daemon_end);
                let _hello: qsh_proto::local::LocalHello = daemon
                    .recv()
                    .await
                    .expect("recv LocalHello")
                    .expect("conduit open");
                let ack = qsh_proto::local::LocalResponse {
                    body: Some(qsh_proto::local::local_response::Body::HelloAck(
                        qsh_proto::local::LocalHelloAck {
                            host: "target".to_string(),
                            peer_fingerprint: "sha256:deadbeef".to_string(),
                            generation: 1,
                            // `dial-filter.v1` deliberately missing — an
                            // old target, or a daemon still relaying its
                            // pre-upgrade registration.
                            capabilities: vec![qsh_proto::wire::CAP_EXEC.to_string()],
                        },
                    )),
                };
                daemon.send(&ack).await.expect("send LocalHelloAck");
                // Keep the daemon end alive for the test's whole duration —
                // dropping it here would race the client's own read of the
                // ack above with an early EOF.
                std::future::pending::<()>().await
            });
            crate::localctl::client::open_control_over(client_end, "target", 0, None)
                .await
                .expect("fake LOCAL_CONTROL handshake")
        });

        let session = crate::client::Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            dir.path().join("fake.sock"),
            handshake.peer_fingerprint,
            handshake.generation,
        );
        let conn = Connected::for_test_reverse(
            runtime,
            session,
            dir.path().join("fake.sock"),
            "target".to_string(),
        );

        let err = match Ops::tunnel_dynamic_with_connected(conn, None, 0, "target") {
            Err(err) => err,
            Ok(_) => panic!("-D over reverse must never bind without dial-filter.v1"),
        };
        assert_eq!(err.code, ErrorCode::Unsupported);
        assert_eq!(
            err.message,
            DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE
        );
    }

    /// ADR-0019 decision 11 promises that a same-process `tunnel.close`
    /// really tears a `-D` hold down — this
    /// proves it through the same `register_hold` mechanism
    /// `tunnel_dynamic_and_hold` itself calls (extracted as this test's
    /// own doc explains), rather than through `tunnel_dynamic_and_hold`
    /// end to end: that entry point additionally needs a real
    /// `resolve_route`/`connect_target` dial, which — same reasoning as
    /// `tunnel_dynamic_without_dial_filter_capability_is_unsupported_and_binds_nothing`
    /// just above — is exactly what `Connected::for_test_forward` exists
    /// to route around for this crate's own unit tests
    /// (`crate::tunnel::testutil`'s own module doc: `qsh-testkit`, which
    /// has the live-host harness, cannot be a dev-dependency here).
    #[test]
    fn tunnel_dynamic_and_hold_close_frees_the_socks_listener_port() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
        let ops = Ops::new(paths);
        let runtime = ops.connect_runtime().unwrap();

        let (endpoint, client, _server) =
            runtime.block_on(crate::tunnel::testutil::loopback_pair_with_client_endpoint());
        let ctl = runtime.block_on(async {
            let (send, recv) = client.open_bi().await.unwrap();
            qsh_transport::FramedStream::control(send, recv)
        });
        let hello = wire::Hello {
            versions: vec![1],
            device_name: "peer".to_string(),
            capabilities: vec![
                qsh_proto::wire::CAP_EXEC.to_string(),
                wire::CAP_DIAL_FILTER_V1.to_string(),
            ],
            reverse: None,
        };
        let session = crate::client::Session::from_control(client.clone(), ctl, hello);
        let conn = Connected::for_test_forward(runtime, endpoint, client, session);

        // Ephemeral port (`listen_port: 0`): the OS picks one, so a
        // successful re-bind after close is real proof the listener is
        // gone, not just that the request named a fixed, always-free port.
        let hold = Ops::tunnel_dynamic_with_connected(conn, None, 0, "box")
            .expect("a peer advertising dial-filter.v1 must be allowed to bind");
        let tunnel = hold.dynamic_tunnel().clone();
        let bound_port = u16::try_from(
            tunnel
                .actual_port
                .expect("a bound -D listener always reports actual_port"),
        )
        .expect("actual_port must fit a real TCP port");
        TcpListener::bind(("127.0.0.1", bound_port))
            .expect_err("the -D listener should still hold this port before close");

        ops.register_hold(hold, tunnel.tunnel_id.clone());

        let closed = ops
            .tunnel_close(TunnelCloseReq {
                tunnel_id: tunnel.tunnel_id.clone(),
            })
            .expect("tunnel.close never errors");
        assert!(
            closed.closed,
            "a same-process -D hold must report closed: true"
        );

        TcpListener::bind(("127.0.0.1", bound_port)).unwrap_or_else(|e| {
            panic!("port {bound_port} was not re-bindable after tunnel.close: {e}")
        });
    }
}
