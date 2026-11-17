//! `tunnel.*` operations (`docs/CLI.md` §6.9, §6.14; M4 plan Step 3 (8237375),
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
//! **Holder model** (M4 plan §4.1 #1 (8237375), `docs/CLI.md` §6.14).
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
use std::time::Duration;

use qsh_proto::wire::{
    self, ForwardDirection, ForwardSpec, parse_dynamic_spec, parse_forward_spec,
};
use qsh_proto::{
    DynamicTunnel, ErrorCode, Tunnel, TunnelCloseData, TunnelCloseReq, TunnelDynamicReq,
    TunnelListData, TunnelListReq, TunnelOpenReq,
};

use crate::ops::session::{Connected, RecoveryConfig, RouteSeed};
use crate::ops::{OpError, Operation, Ops};
use crate::tunnel::local::ForwardCarrier;
use crate::tunnel::remote::RemoteForwardAcceptor;
use crate::tunnel::{DynamicForwardHandle, LocalForwardError, LocalForwardHandle};

mod supervise;
use supervise::{SuperviseEnd, SuperviseTask};

/// One [`Ops::tunnel_open_and_hold`] registration's close signal
/// (M6 plan Step 2 (8237375)+3 검증 라운드 판정 ②/F2). The payload is a reply
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

/// The `tunnel.list` operation (`qsh tunnels`, `docs/CLI.md` §6.9, the M4 plan (8237375)
/// M4 Step 5 PR 5b).
pub struct TunnelListOp;
impl Operation for TunnelListOp {
    const COMMAND: &'static str = "tunnel.list";
}

/// The `tunnel.close` operation (`qsh tunnel close <id>`, `docs/CLI.md`
/// §6.9, M4 plan Step 5 (8237375) PR 5b).
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
/// (`crates/qsh-core/tests/it/tunnel_docs.rs` pins both), the same anti-drift
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

/// The missing-capability refusal [`Ops::tunnel_dynamic`] gave on the
/// reverse route (ADR-0020 decision 2); ADR-0068 retired that route, so
/// nothing emits it any more and the text stays only as recorded
/// vocabulary. Unlike the forward-route message, a
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

/// The gate itself (ADR-0019 decision 3, "no fallback"), factored out so
/// [`Ops::tunnel_dynamic_with_connected`],
/// [`crate::ops::session::SessionAttachStream::open_dynamic_forwards`] and
/// [`Ops::session_open_gated`] share one predicate, not just the error
/// constructors above — a duplicated `if !caps.iter().any(...)` at each
/// call site meant a test deleting one copy would not have caught the
/// other rotting (found in review; each call site used to re-derive this
/// check independently).
pub(crate) fn require_dial_filter_capability(capabilities: &[String]) -> Result<(), OpError> {
    if capabilities
        .iter()
        .any(|cap| cap == wire::CAP_DIAL_FILTER_V1)
    {
        Ok(())
    } else {
        Err(dynamic_forward_capability_unsupported())
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
/// loopback (M4 plan §4.1 #3 (8237375)) — so `qsh host -L 0.0.0.0:8080:…`
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

/// Parse `-R` spec strings into [`ForwardSpec`]s (M4 plan Step 4 (8237375)).
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
        // than delivered to anyone. `Ops::tunnel_open_reverse` (the M4 plan (8237375)
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
/// `tunnel.close <id>` (M4 plan Step 5 (8237375)) turn straight into
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
    /// A supervised `-R` tunnel. The registration and the acceptor that
    /// serves it belong to the supervisor, which replaces both each time it
    /// re-opens the forward; the holder keeps only enough to say goodbye.
    SupervisedRemote(supervise::RemoteHandle),
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
    /// The supervisor of a `--supervise` tunnel (ADR-0023). Before `conn`
    /// for the same reason as `forward`: it holds tasks on `conn`'s
    /// runtime and must go while that runtime still exists.
    supervisor: Option<SuperviseTask>,
    conn: Connected,
    tunnel: TunnelDto,
}

/// Owned copy of what a `qsh::lifecycle` tunnel record carries, so the
/// hold methods can keep it while they borrow the tunnel's fields.
struct LifecycleIds {
    tunnel_id: String,
    mode: String,
    supervise: bool,
}

impl LifecycleIds {
    fn facts(&self) -> crate::lifecycle::TunnelFacts<'_> {
        crate::lifecycle::TunnelFacts {
            tunnel_id: &self.tunnel_id,
            mode: &self.mode,
            supervise: self.supervise,
        }
    }

    fn opened(&self) {
        crate::lifecycle::tunnel_opened(self.facts());
    }

    fn ended(&self, err: &OpError, cause: Option<&str>) {
        crate::lifecycle::tunnel_ended(self.facts(), err.code.as_str(), cause);
    }
}

/// The natural-end wait both [`TunnelHold::hold`] and
/// [`TunnelHold::hold_until_closed`] race against their own close signal
/// (the latter only) — factored out so the two methods cannot drift on
/// what "the tunnel ended on its own" means.
async fn wait_for_end(
    forward: &mut ForwardResource,
    supervisor: &mut Option<SuperviseTask>,
    conn: &mut Connected,
) -> Ending {
    // What ends the tunnel besides its own listener failing: the connection
    // dying for an unsupervised tunnel, and only the supervisor giving up
    // for a supervised one (a lost connection is the supervisor's to mend).
    let carrier_end = async {
        match supervisor {
            Some(supervisor) => match supervisor.finished().await {
                SuperviseEnd::Failed(err) => Ending::Failed(err, None),
            },
            None => {
                let (err, cause) = conn.wait_dead_with_cause().await;
                Ending::Failed(err, cause)
            }
        }
    };
    match forward {
        ForwardResource::Local(local) => {
            tokio::select! {
                err = local.wait() => Ending::Failed(OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("the local forward's listener failed: {err}"),
                ), None),
                ended = carrier_end => ended,
            }
        }
        ForwardResource::Remote { .. } | ForwardResource::SupervisedRemote(_) => carrier_end.await,
        ForwardResource::Dynamic(dynamic) => {
            tokio::select! {
                err = dynamic.wait() => Ending::Failed(OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("the dynamic forward's listener failed: {err}"),
                ), None),
                ended = carrier_end => ended,
            }
        }
    }
}

/// How a held tunnel ended.
enum Ending {
    /// On its own, with this error and the diagnostic cause when known.
    Failed(OpError, Option<&'static str>),
}

impl Ending {
    /// The error form, for callers whose contract has no deliberate end.
    fn into_error(self) -> OpError {
        match self {
            Ending::Failed(err, _) => err,
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

    /// The facts a `qsh::lifecycle` record about this tunnel carries.
    fn lifecycle_ids(&self) -> LifecycleIds {
        let (tunnel_id, mode) = match &self.tunnel {
            TunnelDto::Forward(t) => (t.tunnel_id.clone(), t.mode.clone()),
            TunnelDto::Dynamic(t) => (t.tunnel_id.clone(), t.mode.clone()),
        };
        LifecycleIds {
            tunnel_id,
            mode,
            supervise: self.supervisor.is_some(),
        }
    }

    /// Emit the `tunnel_opened` lifecycle record (ADR-0023 decision 21).
    /// The frontend calls this once the envelope is out and flushed, right
    /// where it writes its own "holding" line.
    pub fn announce_opened(&self) {
        self.lifecycle_ids().opened();
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
    /// wait_dead_with_cause`] on *either* route (M4 plan Step 5 (8237375) PR 5b) —
    /// forward route: the QUIC connection's own close future, exactly as
    /// before; reverse route: the `LOCAL_CONTROL` conduit's own clean-end/
    /// error, which is this side's only way to learn the reverse
    /// registration died. The runtime handle is taken up front (rather
    /// than borrowing `self.conn.runtime()` for the duration) because the
    /// async block below also needs `&mut self.conn` for `wait_dead_with_cause`, and
    /// the two borrows cannot coexist.
    pub fn hold(mut self) -> OpError {
        let handle = self.conn.runtime().handle().clone();
        let ids = self.lifecycle_ids();
        let ending = {
            let forward = &mut self.forward;
            let supervisor = &mut self.supervisor;
            let conn = &mut self.conn;
            handle.block_on(wait_for_end(forward, supervisor, conn))
        };
        let Ending::Failed(err, cause) = ending;
        ids.ended(&err, cause);
        self.close();
        err
    }

    /// The runtime this tunnel runs on. A frontend that must be ready for a
    /// signal before it prints anything registers its handlers under
    /// `handle.enter()`, then hands the wait to [`Self::hold_until`].
    pub fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.conn.runtime().handle().clone()
    }

    /// [`Self::hold`] that also returns when `shutdown` resolves: `None`
    /// then, a deliberate end that is not a failure (ADR-0023 decision 11:
    /// a supervised tunnel ends with exit `0` on SIGINT/SIGTERM); `Some`
    /// is the error that ended the tunnel on its own. The tunnel is torn
    /// down either way.
    pub fn hold_until(
        mut self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Option<OpError> {
        let handle = self.conn.runtime().handle().clone();
        let ids = self.lifecycle_ids();
        let outcome = {
            let forward = &mut self.forward;
            let supervisor = &mut self.supervisor;
            let conn = &mut self.conn;
            handle.block_on(async move {
                tokio::select! {
                    ended = wait_for_end(forward, supervisor, conn) => Some(ended),
                    () = shutdown => None,
                }
            })
        };
        if let Some(Ending::Failed(err, cause)) = &outcome {
            ids.ended(err, *cause);
        }
        self.close();
        outcome.map(|Ending::Failed(err, _)| err)
    }

    /// Like [`Self::hold`], but also returns early — a deliberate close,
    /// never treated as a failure — the instant `close_rx` delivers a
    /// reply channel (M6 plan Step 2 (8237375)+3 검증 라운드 판정 ②/F2).
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
            let supervisor = &mut self.supervisor;
            let conn = &mut self.conn;
            handle.block_on(async move {
                tokio::select! {
                    ended = wait_for_end(forward, supervisor, conn) => Outcome::Died(ended.into_error()),
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
            ..
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
        if let ForwardResource::SupervisedRemote(handle) = &self.forward {
            // Only a live carrier can be told anything, and the supervisor
            // knows whether there is one (ADR-0023 decision 11).
            let handle = handle.clone();
            self.conn.runtime().block_on(handle.close_best_effort());
        }
        drop(self.forward);
        drop(self.supervisor.take());
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
        check_supervise(
            req.supervise_ms,
            req.accept_hold_ms,
            match spec.direction {
                ForwardDirection::Local => SuperviseMode::Local,
                ForwardDirection::Remote => SuperviseMode::Remote,
            },
        )?;
        // `--wait` waited for a reverse registration to come back
        // (ADR-0023); ADR-0068 retired that, so the value is validated and
        // otherwise ignored.
        wait_budget_ms(req.wait_ms)?;
        let liveness = self.liveness()?;
        let (conn, seed) = self.connect_keeping_target(&req.host, liveness.tuning())?;
        let supervision =
            self.supervision(req.supervise_ms, req.accept_hold_ms, seed, &conn, &liveness)?;
        if let Some(supervision) = supervision {
            return match spec.direction {
                ForwardDirection::Local => {
                    Self::supervised_local(conn, &spec, &req.host, supervision)
                }
                ForwardDirection::Remote => {
                    Self::supervised_remote(conn, &spec, &req.host, supervision)
                }
            };
        }
        let connection = conn.connection();
        Self::tunnel_open_forward(conn, connection, &spec, &req.host)
    }

    /// The supervision inputs of a `--supervise` open, once the route is
    /// known. `Ok(None)` for an unsupervised tunnel.
    fn supervision(
        &self,
        supervise_ms: Option<u32>,
        accept_hold_ms: Option<u32>,
        seed: RouteSeed,
        conn: &Connected,
        liveness: &crate::config::Liveness,
    ) -> Result<Option<Supervision>, OpError> {
        let ms = supervise_ms.unwrap_or(0);
        if ms == 0 {
            return Ok(None);
        }
        let Some(fingerprint) = conn.peer_fingerprint() else {
            return Err(OpError::new(
                ErrorCode::AuthFailed,
                "the peer's identity is unknown, so the tunnel cannot be supervised",
            ));
        };
        Ok(Some(Supervision {
            seed,
            fingerprint,
            total: Duration::from_millis(u64::from(ms)),
            accept_hold: accept_hold_ms
                .filter(|hold| *hold != 0)
                .map(|hold| Duration::from_millis(u64::from(hold))),
            recovery: self.effective_recovery(liveness),
            tuning: liveness.tuning(),
        }))
    }

    /// Open the forward on `connection`, the QUIC connection `conn` holds.
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
                    supervisor: None,
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
                    supervisor: None,
                    forward: ForwardResource::Remote {
                        acceptor,
                        forward_id: opened.forward_id,
                    },
                    tunnel: TunnelDto::Forward(tunnel),
                })
            }
        }
    }

    /// `tunnel.open` for a long-running, multi-call host process (e.g. an
    /// agent tool, M6 plan Step 2 (8237375)+3 검증 라운드 판정 ②/F2) rather than a one-shot
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
        reject_supervise_for_and_hold(req.supervise_ms)?;
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
    ///    (`ForwardCarrier::Direct`/`Local`).
    pub fn tunnel_dynamic(&self, req: TunnelDynamicReq) -> Result<TunnelHold, OpError> {
        let listen_port = port(req.listen_port, "listen_port")?;
        crate::tunnel::local::loopback_bind_addr(req.bind.as_deref(), listen_port, "-D")
            .map_err(map_local_forward_error)?;
        check_supervise(req.supervise_ms, req.accept_hold_ms, SuperviseMode::Dynamic)?;
        let liveness = self.liveness()?;
        let (conn, seed) = self.connect_keeping_target(&req.host, liveness.tuning())?;
        let supervision =
            match self.supervision(req.supervise_ms, req.accept_hold_ms, seed, &conn, &liveness) {
                Ok(supervision) => supervision,
                Err(err) => {
                    conn.close();
                    return Err(err);
                }
            };
        Self::tunnel_dynamic_with_connected(
            conn,
            req.bind.as_deref(),
            listen_port,
            &req.host,
            supervision,
        )
    }

    /// The post-connect half of [`Self::tunnel_dynamic`], split out as a
    /// test seam: a test can hand this a [`Connected`] built directly
    /// ([`Connected::for_test_forward`]) carrying a fabricated negotiated
    /// capability set, to exercise the capability gate without a real peer
    /// `Hello` answering a dial.
    fn tunnel_dynamic_with_connected(
        conn: Connected,
        bind: Option<&str>,
        listen_port: u16,
        host: &str,
        supervision: Option<Supervision>,
    ) -> Result<TunnelHold, OpError> {
        if let Err(err) = require_dial_filter_capability(conn.capabilities()) {
            conn.close();
            return Err(err);
        }
        if let Some(supervision) = supervision {
            return Self::supervised_dynamic(conn, bind, listen_port, host, supervision);
        }
        let connection = conn.connection();
        Self::tunnel_dynamic_forward(conn, connection, bind, listen_port, host)
    }

    /// Open the `-D` forward on `connection` once the capability gate has
    /// already passed.
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
            supervisor: None,
            forward: ForwardResource::Dynamic(forward),
            tunnel: TunnelDto::Dynamic(tunnel),
        })
    }

    /// [`Self::tunnel_open_and_hold`]'s `tunnel.dynamic` twin (ADR-0019
    /// decision 11) — same long-running-host holder-table registration
    /// (this module's own top doc), so a same-process `tunnel.close` can
    /// tear a `-D` listener down too, not only a `-L`/`-R` one.
    pub fn tunnel_dynamic_and_hold(&self, req: TunnelDynamicReq) -> Result<DynamicTunnel, OpError> {
        reject_supervise_for_and_hold(req.supervise_ms)?;
        let hold = self.tunnel_dynamic(req)?;
        let tunnel = hold.dynamic_tunnel().clone();
        self.register_hold(hold, tunnel.tunnel_id.clone());
        Ok(tunnel)
    }

    /// Same-process half of `tunnel.close` (M6 plan Step 2 (8237375)+3 검증
    /// 라운드 판정 ②/F2): `true`, with the tunnel already torn down by the
    /// time this returns, when `tunnel_id` names a hold
    /// [`Self::tunnel_open_and_hold`] registered in this same `Ops` (any
    /// clone of it — the registry is shared) and has not already ended on
    /// its own; `false` otherwise, leaving [`Self::tunnel_close`] to fall
    /// answer `closed: false`.
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

    /// `tunnel.list` (`qsh tunnels`, `docs/CLI.md` §6.9): the empty list.
    ///
    /// The only tunnels this command could ever report were the ones a
    /// resident `qsh listen` daemon held (`-R` over a reverse route).
    /// ADR-0068 retired the daemon, and a forward-route tunnel's only
    /// holder is the CLI process that opened it (`docs/CLI.md` §6.14: no
    /// resident client daemon), so a second process has nothing to ask.
    /// The command and its JSON shape stay (ADR-0068 decision 8).
    pub fn tunnel_list(&self, _req: TunnelListReq) -> Result<TunnelListData, OpError> {
        Ok(TunnelListData {
            tunnels: Vec::new(),
        })
    }

    /// `tunnel.close <id>` (`docs/CLI.md` §6.9): `closed: true` only for a
    /// tunnel [`Self::tunnel_open_and_hold`] registered in this same `Ops`
    /// (any clone of it — the registry is shared); `closed: false`, never
    /// an error, for anything else (never registered, already closed, or
    /// held by another process), the shape
    /// [`qsh_proto::TunnelCloseData::closed`]'s own doc requires.
    ///
    /// No resource is created by this op ever — closing is pure teardown,
    /// so there is no "authorize before creating" ordering concern.
    pub fn tunnel_close(&self, req: TunnelCloseReq) -> Result<TunnelCloseData, OpError> {
        let closed = self.close_registered_tunnel_hold(&req.tunnel_id);
        Ok(TunnelCloseData {
            tunnel_id: req.tunnel_id,
            closed,
        })
    }
}

/// What a supervised open carries over from the first connection
/// (ADR-0023 decisions 4 and 7).
struct Supervision {
    /// What the first open learned about how to find the carrier again.
    seed: RouteSeed,
    /// The fingerprint the first open verified.
    fingerprint: String,
    /// The disconnection budget.
    total: Duration,
    /// `--accept-hold`: how long a connection that arrives while
    /// disconnected may be kept (decision 19). `None` refuses at once.
    accept_hold: Option<Duration>,
    recovery: RecoveryConfig,
    /// `[transport]` as read before the first dial; a redial reuses it.
    tuning: qsh_transport::TransportTuning,
}

/// The pieces a supervisor is started from, taken from a `Connected`.
struct SupervisionParts {
    session: crate::client::Session,
    route: supervise::Route,
    initial: ForwardCarrier,
}

impl Ops {
    /// `-L` with `--supervise`: the listener reads its carrier from a
    /// channel the supervisor writes (decision 3).
    fn supervised_local(
        mut conn: Connected,
        spec: &ForwardSpec,
        host: &str,
        supervision: Supervision,
    ) -> Result<TunnelHold, OpError> {
        let Supervision {
            seed,
            fingerprint,
            total,
            accept_hold,
            recovery,
            tuning,
        } = supervision;
        let parts = match Self::supervision_parts(&mut conn, seed) {
            Ok(parts) => parts,
            Err(err) => {
                conn.close();
                return Err(err);
            }
        };
        let started = conn.runtime().block_on(async {
            let wiring = supervise::Wiring::new(parts.initial, &recovery, accept_hold);
            let forward = LocalForwardHandle::start_supervised(spec, wiring.view()).await?;
            let task = supervise::spawn(
                wiring,
                supervise::Params {
                    route: parts.route,
                    fingerprint,
                    require_dial_filter: false,
                    total,
                    tunnel_id: forward.tunnel_id().to_string(),
                    mode: "local",
                    recovery,
                    tuning,
                },
                parts.session,
                None,
            );
            Ok::<_, LocalForwardError>((forward, task))
        });
        match started {
            Ok((forward, task)) => {
                let tunnel = forward.tunnel(host);
                Ok(TunnelHold {
                    conn,
                    supervisor: Some(task),
                    forward: ForwardResource::Local(forward),
                    tunnel: TunnelDto::Forward(tunnel),
                })
            }
            Err(err) => {
                conn.close();
                Err(map_local_forward_error(err))
            }
        }
    }

    /// `-R` with `--supervise`: the registration on the peer is what the
    /// supervisor keeps, so it, not the holder, owns the acceptor
    /// (ADR-0023 decisions 7-4 and 13).
    fn supervised_remote(
        mut conn: Connected,
        spec: &ForwardSpec,
        host: &str,
        supervision: Supervision,
    ) -> Result<TunnelHold, OpError> {
        let Supervision {
            seed,
            fingerprint,
            total,
            accept_hold: _,
            recovery,
            tuning,
        } = supervision;
        // The first open is the unsupervised one, step for step.
        let (acceptor, open, opened) = match Self::open_remote(&mut conn, spec) {
            Ok(opened) => opened,
            Err(err) => {
                conn.close();
                return Err(err);
            }
        };
        let parts = match Self::supervision_parts(&mut conn, seed) {
            Ok(parts) => parts,
            Err(err) => {
                conn.close();
                return Err(err);
            }
        };
        let tunnel = remote_tunnel_dto(spec, &opened, host);
        let (remote, handle) = supervise::RemoteTunnel::new(acceptor, open, &opened);
        let task = conn.runtime().block_on(async {
            let wiring = supervise::Wiring::new(parts.initial, &recovery, None);
            supervise::spawn(
                wiring,
                supervise::Params {
                    route: parts.route,
                    fingerprint,
                    require_dial_filter: false,
                    total,
                    tunnel_id: opened.forward_id.clone(),
                    mode: "remote",
                    recovery,
                    tuning,
                },
                parts.session,
                Some(remote),
            )
        });
        Ok(TunnelHold {
            conn,
            supervisor: Some(task),
            forward: ForwardResource::SupervisedRemote(handle),
            tunnel: TunnelDto::Forward(tunnel),
        })
    }

    /// The first `RemoteForwardOpen` of a supervised `-R` tunnel. Returns
    /// the acceptor serving the new registration, the request as sent and
    /// the peer's answer.
    fn open_remote(
        conn: &mut Connected,
        spec: &ForwardSpec,
    ) -> Result<
        (
            RemoteForwardAcceptor,
            wire::RemoteForwardOpen,
            wire::RemoteForwardOpened,
        ),
        OpError,
    > {
        let open_req = remote_forward_open_from_spec(spec);
        let connection = conn.connection();
        let acceptor = conn
            .runtime()
            .block_on(RemoteForwardAcceptor::spawn(connection));
        let sent = open_req.clone();
        let opened = conn.run(move |s| Box::pin(s.rfwd_open(open_req)))?;
        acceptor.register(opened.forward_id.clone(), spec.host.clone(), spec.host_port);
        Ok((acceptor, sent, opened))
    }

    /// `-D` with `--supervise`; see [`Self::supervised_local`].
    fn supervised_dynamic(
        mut conn: Connected,
        bind: Option<&str>,
        listen_port: u16,
        host: &str,
        supervision: Supervision,
    ) -> Result<TunnelHold, OpError> {
        let Supervision {
            seed,
            fingerprint,
            total,
            accept_hold,
            recovery,
            tuning,
        } = supervision;
        let parts = match Self::supervision_parts(&mut conn, seed) {
            Ok(parts) => parts,
            Err(err) => {
                conn.close();
                return Err(err);
            }
        };
        let started = conn.runtime().block_on(async {
            let wiring = supervise::Wiring::new(parts.initial, &recovery, accept_hold);
            let forward =
                DynamicForwardHandle::start_supervised(bind, listen_port, wiring.view()).await?;
            let task = supervise::spawn(
                wiring,
                supervise::Params {
                    route: parts.route,
                    fingerprint,
                    require_dial_filter: true,
                    total,
                    tunnel_id: forward.tunnel_id().to_string(),
                    mode: "dynamic",
                    recovery,
                    tuning,
                },
                parts.session,
                None,
            );
            Ok::<_, LocalForwardError>((forward, task))
        });
        match started {
            Ok((forward, task)) => {
                let tunnel = forward.dynamic_tunnel(host);
                Ok(TunnelHold {
                    conn,
                    supervisor: Some(task),
                    forward: ForwardResource::Dynamic(forward),
                    tunnel: TunnelDto::Dynamic(tunnel),
                })
            }
            Err(err) => {
                conn.close();
                Err(map_local_forward_error(err))
            }
        }
    }

    /// The control stream, the first carrier and the route a supervisor
    /// takes over from a `Connected`. `alias` is the host the user typed.
    fn supervision_parts(
        conn: &mut Connected,
        seed: RouteSeed,
    ) -> Result<SupervisionParts, OpError> {
        let internal = || OpError::new(ErrorCode::Internal, "the connection is not supervisable");
        let RouteSeed::Forward(target) = seed;
        let link = conn.forward_link();
        let session = conn.take_session().ok_or_else(internal)?;
        let initial = ForwardCarrier::Direct(link.connection());
        Ok(SupervisionParts {
            session,
            route: supervise::Route { target, link },
            initial,
        })
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
/// connection is ever attempted. ADR-0068 retired the wait itself, so the
/// bound only keeps an out-of-range request an `INVALID_ARGUMENT`.
const WAIT_MS_MAX: u32 = 600_000;

/// Validate and narrow `TunnelOpenReq.wait_ms` to a millisecond budget —
/// same "a request that skipped the CLI
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

/// Upper bound on `supervise_ms` (`docs/CLI.md` §6.9's `--supervise`,
/// ADR-0023 decision 1): one day of total disconnected time.
const SUPERVISE_MS_MAX: u32 = 86_400_000;

/// Upper bound on `accept_hold_ms` (`docs/CLI.md` §6.9's `--accept-hold`,
/// ADR-0023 decision 13).
const ACCEPT_HOLD_MS_MAX: u32 = 2_000;

/// Which forward shape a supervise request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuperviseMode {
    Local,
    Remote,
    Dynamic,
}

/// Validate `supervise_ms` and `accept_hold_ms` before any connection or
/// bind exists (ADR-0023 decisions 1 and 13). Order: ranges, then the
/// combinations that make no sense (`INVALID_ARGUMENT`). Every mode on
/// every route is supervisable, so nothing is `UNSUPPORTED` any more
/// (decision 24).
fn check_supervise(
    supervise_ms: Option<u32>,
    accept_hold_ms: Option<u32>,
    mode: SuperviseMode,
) -> Result<(), OpError> {
    let supervise = supervise_ms.unwrap_or(0);
    let hold = accept_hold_ms.unwrap_or(0);
    if supervise > SUPERVISE_MS_MAX {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            format!("tunnel supervise_ms {supervise} is outside 0..={SUPERVISE_MS_MAX}"),
        ));
    }
    if hold > ACCEPT_HOLD_MS_MAX {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            format!("tunnel accept_hold_ms {hold} is outside 0..={ACCEPT_HOLD_MS_MAX}"),
        ));
    }
    if hold != 0 && supervise == 0 {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            "tunnel accept_hold_ms needs a nonzero supervise_ms",
        ));
    }
    if hold != 0 && mode == SuperviseMode::Remote {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            "tunnel accept_hold_ms does not apply to a remote forward",
        ));
    }
    Ok(())
}

/// `tunnel_open_and_hold`/`tunnel_dynamic_and_hold` serve long-running
/// hosts that own their own lifecycle; a supervised tunnel is a CLI
/// foreground behavior, so a nonzero `supervise_ms` is refused before
/// anything connects (ADR-0023 decision 1).
fn reject_supervise_for_and_hold(supervise_ms: Option<u32>) -> Result<(), OpError> {
    if supervise_ms.unwrap_or(0) != 0 {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            "supervise_ms is not accepted by the hold-in-process tunnel calls",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
