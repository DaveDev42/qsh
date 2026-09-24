//! `qsh serve` — the long-running host mode (`docs/CLI.md` §6.12). Not an
//! operation: no envelope, foreground only, prints the bound address to
//! stderr via the `on_bound` callback — fired immediately before the
//! accept loop starts, so the line cannot be read while the loop is not
//! yet armed — and runs until `shutdown` resolves.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use qsh_proto::ErrorCode;
use qsh_transport::{Listener, SetupError, TrustEvaluator};

use crate::acl::{Role, StartupDiagnostic, load_or_deny_with_index};
use crate::audit::RotatingAuditSink;
use crate::broker::{Broker, BrokerConfig, SystemClock};
use crate::config::{Config, Paths};
use crate::identity::LoadedIdentity;
use crate::ops::OpError;
use crate::server::Server;
use crate::trust::{SharedInviteStore, SharedTrustStore};

/// Default listen address when neither `--bind` nor `[serve].bind` is set.
pub const DEFAULT_BIND: &str = "[::]:4433";

/// The one port qsh uses when a peer address does not name one
/// (ADR-0014 결정 1). Not a second default: it is parsed out of
/// [`DEFAULT_BIND`] at compile time, so the bind default and the peer
/// default can never drift apart. Peer addresses only — a *bind* spec with
/// no port is still refused (ADR-0014 결정 8, [`resolve_bind`]).
pub const DEFAULT_PORT: u16 = trailing_port(DEFAULT_BIND);

/// The decimal port at the end of `text`, parsed in a `const` context:
/// scans backwards over ASCII digits and stops at the first byte that is
/// not one. Panics at compile time when `text` ends in no digits, or in a
/// number too large for a `u16`.
pub(crate) const fn trailing_port(text: &str) -> u16 {
    let bytes = text.as_bytes();
    let mut i = bytes.len();
    let mut port: u32 = 0;
    let mut scale: u32 = 1;
    let mut digits = 0usize;
    while i > 0 {
        i -= 1;
        let byte = bytes[i];
        if !byte.is_ascii_digit() {
            break;
        }
        port += (byte - b'0') as u32 * scale;
        scale *= 10;
        digits += 1;
    }
    assert!(digits > 0, "DEFAULT_BIND must end in a decimal port");
    assert!(port <= u16::MAX as u32, "the port must fit in a u16");
    port as u16
}

/// Whether every independent run of decimal digits in `text` equals `port`,
/// and at least one such run exists — checked in a `const` context so a
/// wording constant that names a port can be pinned to
/// [`DEFAULT_PORT`] without a second literal becoming a second source of
/// truth (ADR-0014 결정 1).
///
/// Unlike [`trailing_port`], this does not fix the port's position — a
/// three-part failure notice (ADR-0014 결정 5's "one line")
/// puts the port in the middle of a sentence, so what the assertion must
/// hold is "this wording names `serve::DEFAULT_PORT`, and only that
/// number", not "the port is the last byte". Seeing "and only that
/// number" through is what keeps this a single source of truth the same
/// way [`trailing_port`]'s own doc requires — it is a whole-string scan,
/// not an existence check, on purpose.
pub(crate) const fn names_only_port(text: &str, port: u16) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut found = false;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_digit()) {
            // A run of two or more digits starting with `0` is a
            // different spelling of the same number (`04433` vs `4433`)
            // — reject it rather than let it numerically match `port`.
            if bytes[i] == b'0' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                return false;
            }
            let mut value: u32 = 0;
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                value = value * 10 + (bytes[j] - b'0') as u32;
                // Bail out the moment the run can no longer equal `port`
                // instead of continuing to multiply: a digit run longer
                // than five bytes overflows `u32` on the next
                // multiplication, which is a hard `E0080` const-eval
                // error, not the `false` this function must return for
                // "this wording names a number other than `port`".
                if value > u16::MAX as u32 {
                    return false;
                }
                j += 1;
            }
            if value != port as u32 {
                return false;
            }
            found = true;
            i = j;
        } else {
            i += 1;
        }
    }
    found
}

/// Stderr remedy appended to a bind-failure report (ADR-0014 결정 9,
/// `:57`) — `qsh serve` ([`run_serve`]) and `qsh listen`
/// (`crate::reverse::listen`) both default to [`DEFAULT_PORT`], so one
/// machine running both needs an explicit `--bind` for at least one of
/// them. Observation (`cannot listen on {bind}: {err}`) is composed by
/// [`bind_unavailable`]'s caller; this constant is only the impact and
/// next-command parts, shared by both call sites so a fix to one can never
/// leave the other holding a remedy-less copy of the same format string.
pub const BIND_UNAVAILABLE_REMEDY: &str = "Nothing is being served. `qsh serve` and `qsh listen` both default to port 4433, so one machine running both needs an explicit bind for at least one of them. Re-run with `--bind <ip:port>` on a free port.";

/// This remedy also names the one default port by number, so it gets the
/// same single-source-of-truth assertion [`ADDRESS_PORT_ASSUMED_NOTICE`]
/// does.
const _: () = assert!(
    names_only_port(BIND_UNAVAILABLE_REMEDY, DEFAULT_PORT),
    "BIND_UNAVAILABLE_REMEDY must name DEFAULT_PORT and no other number"
);

/// The single place a bind failure becomes a `CONFIG_ERROR`, for both
/// `qsh serve` ([`run_serve`], below) and `qsh listen`
/// (`crate::reverse::listen::run_listen_unix`) — `ADR-0014` 결정 9 warns
/// that two independent copies of this format string is exactly how one
/// gets a remedy and the other does not. The observation clause
/// (`cannot listen on {bind}: {err}`) stays byte-identical to the
/// pre-M9 wording: `qsh-cli/tests/exit_code_matrix.rs` asserts
/// `starts_with("qsh: cannot listen on")` on the rendered line.
pub fn bind_unavailable(bind: &SocketAddr, err: &dyn std::fmt::Display) -> OpError {
    OpError::new(
        ErrorCode::ConfigError,
        format!("cannot listen on {bind}: {err}. {BIND_UNAVAILABLE_REMEDY}"),
    )
}

/// [`Listener::bind`]'s actual failure type is [`SetupError`], which is
/// not only a port conflict: `SetupError::Tls`/`SetupError::Quic` fire
/// before a socket is ever touched (a rejected identity cert, a rustls
/// config quinn refuses), and re-running with a different `--bind` cannot
/// fix either. [`BIND_UNAVAILABLE_REMEDY`]'s shared-default-port sentence
/// is only true of `SetupError::Bind` (an OS-level bind failure — port in
/// use, no such interface, a privileged port without the privilege); the
/// other variants get the bare observation instead, with no remedy that
/// would misdirect the operator toward a `--bind` that was never the
/// problem.
pub fn bind_setup_error(bind: &SocketAddr, err: SetupError) -> OpError {
    if matches!(err, SetupError::Bind { .. }) {
        bind_unavailable(bind, &err)
    } else {
        OpError::new(
            ErrorCode::ConfigError,
            format!("cannot listen on {bind}: {err}"),
        )
    }
}

/// Resolve the bind address: CLI flag > `config.toml` `[serve].bind` >
/// [`DEFAULT_BIND`]. Accepts `ip:port` or `host:port` (first resolution).
pub fn resolve_bind(flag: Option<&str>, config: &Config) -> Result<SocketAddr, OpError> {
    let spec = flag
        .map(str::to_owned)
        .or_else(|| config.serve.bind.clone())
        .unwrap_or_else(|| DEFAULT_BIND.to_string());
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Ok(addr);
    }
    spec.to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .ok_or_else(|| {
            OpError::new(
                ErrorCode::InvalidArgument,
                format!("invalid bind address {spec:?} (expected ip:port or host:port)"),
            )
        })
}

/// What `qsh serve` resolves to once every CLI flag and config key has been
/// weighed (`docs/CLI.md` §6.12/§6.13, ADR-0012 결정 2/4/5, ADR-0014 결정
/// 7): listen inbound, or dial out and register as a reverse target — the
/// same role the hidden `qsh reverse <controller>` alias plays. [`Outbound`]
/// carries the *literal* the operator or config named, not yet resolved
/// through the trust store/`hosts.toml` — [`crate::ops::Ops::resolve_serve_target`]
/// is the next step for a caller that needs the actual controller key,
/// mirroring [`crate::reverse::target`]'s own "keep the literal, resolve it
/// per dial attempt" discipline so both spellings share one resolution
/// path.
///
/// [`Outbound`]: ServeMode::Outbound
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeMode {
    /// Listen inbound at this resolved address (already CLI flag >
    /// `[serve].bind` > [`DEFAULT_BIND`], via [`resolve_bind`]).
    Inbound(SocketAddr),
    /// Dial `target` and register as a reverse target, offering `name` if
    /// given.
    Outbound {
        target: String,
        offered_name: Option<String>,
    },
}

/// Both `[serve].to` and the legacy `[reverse].controller` set, and
/// disagreeing — the one condition [`resolve_serve_mode`]'s config branch
/// (step 5) must fail closed on rather than silently pick a winner for
/// (ADR-0012 결정 5). Returns `(serve_to, reverse_controller)` so a caller
/// can name both values in its own message. `None` whenever at most one
/// key is set, or both are set and equal — `ServeConfig::to` wins in
/// that last case, silently, because there is nothing to disagree about.
///
/// The single source of truth both [`config_outbound_target`] (which turns
/// `Some` into a `CONFIG_ERROR` for `qsh serve`/`qsh service install`) and
/// `Ops::doctor`'s `config_serve_to_conflict` finding (which turns the same
/// `Some` into a `warn`-free `error` finding instead, never a hard failure
/// — `doctor.run` always exits `0`) read, so the two surfaces can never
/// drift on what counts as a conflict.
pub fn config_serve_to_conflict(config: &Config) -> Option<(&str, &str)> {
    match (
        config.serve.to.as_deref(),
        config.reverse.controller.as_deref(),
    ) {
        (Some(serve_to), Some(controller)) if serve_to != controller => {
            Some((serve_to, controller))
        }
        _ => None,
    }
}

/// The last branch of [`resolve_serve_mode`]: neither `--to` nor `--bind` was given
/// on the command line, so the outbound target (if any) comes from
/// `config.toml` alone. `[serve].to` wins over the legacy
/// `[reverse].controller` key when both are set and equal;
/// [`config_serve_to_conflict`] is consulted first so a disagreement is a
/// `CONFIG_ERROR` here rather than a silently resolved precedence pick
/// (ADR-0012 결정 5). `Ok(None)` means no outbound target configured at
/// all — the caller falls back to [`resolve_bind`].
pub fn config_outbound_target(config: &Config) -> Result<Option<String>, OpError> {
    if let Some((serve_to, controller)) = config_serve_to_conflict(config) {
        return Err(OpError::new(
            ErrorCode::ConfigError,
            format!(
                "[serve].to ({serve_to:?}) and [reverse].controller ({controller:?}) are both \
                 set and disagree. Delete one of the two keys, keep [serve].to, then restart \
                 `qsh serve` — config.toml is only read once at start."
            ),
        ));
    }
    Ok(config
        .serve
        .to
        .clone()
        .or_else(|| config.reverse.controller.clone()))
}

/// Resolve what `qsh serve` does this run: listen inbound, or dial out as a
/// reverse target (`docs/CLI.md` §6.12/§6.13, ADR-0012 결정 2/4/5, ADR-0014
/// 결정 7). All decision logic lives here, in `qsh-core` — `qsh-cli` only
/// parses `--to`/`--name`/`--bind` and dispatches on the result
/// (`CLAUDE.md`'s crate boundary).
///
/// Strict order, each step short-circuiting the rest:
/// 1. `to` and `bind` both given → [`ErrorCode::InvalidArgument`] (never a
///    clap `conflicts_with` — this must exit `255`, not clap's `2`, the
///    same precedent `cli.rs`'s `-L` doc sets for a spec clap itself could
///    reject but deliberately does not).
/// 2. `name` given without `to` → `InvalidArgument` — a name is only
///    meaningful outbound; failing closed here is cheaper than silently
///    ignoring an operator's flag.
/// 3. `to` given → [`ServeMode::Outbound`] with that literal. The config
///    keys are not read *at all* on this path — the short-circuit happens
///    before either lookup, so "no conflict verdict when `--to` wins" is
///    unreachable by construction, not a suppressed check.
/// 4. `bind` given (no `to`) → [`ServeMode::Inbound`] via [`resolve_bind`].
///    The config's outbound keys are not read either: a CLI flag is tier
///    one, and the operator typed an inbound address.
/// 5. Neither given → [`config_outbound_target`] decides: `Some` is
///    outbound, `None` falls back to [`resolve_bind`] with no CLI flag.
pub fn resolve_serve_mode(
    to: Option<&str>,
    name: Option<&str>,
    bind: Option<&str>,
    config: &Config,
) -> Result<ServeMode, OpError> {
    if to.is_some() && bind.is_some() {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            "--to and --bind are mutually exclusive: --to dials out as a reverse target, \
             --bind listens inbound. Pick one.",
        ));
    }
    if to.is_none() && name.is_some() {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            "--name only takes effect together with --to; it names nothing when this process \
             listens inbound.",
        ));
    }
    if let Some(target) = to {
        return Ok(ServeMode::Outbound {
            target: target.to_string(),
            offered_name: name.map(str::to_owned),
        });
    }
    if bind.is_some() {
        return Ok(ServeMode::Inbound(resolve_bind(bind, config)?));
    }
    match config_outbound_target(config)? {
        Some(target) => Ok(ServeMode::Outbound {
            target,
            offered_name: None,
        }),
        None => Ok(ServeMode::Inbound(resolve_bind(None, config)?)),
    }
}

/// Run the host until `shutdown` resolves.
///
/// `bind` is the already-resolved address — the caller runs
/// [`resolve_serve_mode`]/[`resolve_bind`] itself and passes
/// `ServeMode::Inbound`'s payload straight through, so this function
/// never re-reads `config.toml` or re-resolves the bind flag (the mode
/// decision and the accept-loop startup used to resolve
/// the bind address independently, which could disagree on a
/// multi-address `--bind` name and always cost a second config read).
///
/// `identity` must already be loaded (synchronously, before entering the
/// runtime — see `identity::load`). `on_bound` receives the actual bound
/// address, and fires immediately before the accept loop starts rather
/// than as soon as the listener is up — callers announce readiness with
/// it, so it must not be observable while the loop is not yet armed. Any
/// startup diagnostic this function emits through another channel
/// therefore lands *before* the `on_bound` announcement.
///
/// `on_notice` is wired onto the returned [`HostRuntime`]'s
/// `server` before the accept loop ever starts, so every pairing-pin
/// notice (ADR-0017 결정 3) and invite-replay notice (결정 4's exempted
/// axes plus a third, host-local line) a connection can produce reaches it.
/// `qsh-core` never performs this I/O itself (`docs/design/
/// architecture.md` §1) — `qsh-cli`'s `run_serve` wrapper passes a closure
/// that prints `qsh serve: {notice}` to stderr.
#[allow(clippy::too_many_arguments)]
pub async fn run_serve(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    bind: SocketAddr,
    on_bound: impl FnOnce(SocketAddr),
    on_runtime: impl FnOnce(&HostRuntime),
    on_notice: impl Fn(&str) + Send + Sync + 'static,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    let trust = SharedTrustStore::open(paths.trust_file())?;
    // ADR-0002 / M7 Step 4 (report §B12: forward-host, `qsh serve`, only —
    // deliberately wired here in `run_serve`, not in the `host_runtime`
    // `qsh reverse` also shares, since a reverse target never runs
    // `Server::run`'s own accept loop at all and so could never reach
    // `serve_pairing_connection` regardless; keeping the attach here keeps
    // that out-of-scope role's trust store untouched instead of relying on
    // that reachability argument alone). `trust.attach_pairing` must run
    // *before* `Listener::bind` below — every accepted connection's TLS
    // verification reads `pairing_open()` off this same evaluator.
    let invites = SharedInviteStore::open(paths.invites_file())?;
    trust.attach_pairing(Arc::clone(&invites));
    // A bind that cannot be satisfied (port in use, privileged port, no
    // such interface) is a configuration problem on this host, not an
    // internal fault: report it as such so `--bind`/`[serve].bind` is the
    // obvious thing to look at. `bind_setup_error` only attaches that
    // remedy to an actual `SetupError::Bind` — a rejected TLS/QUIC config
    // gets the bare observation instead.
    let listener = Listener::bind(
        bind,
        identity.local,
        Arc::clone(&trust) as Arc<dyn TrustEvaluator>,
    )
    .map_err(|err| bind_setup_error(&bind, err))?;
    let actual = listener.local_addr().map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("cannot read bound address: {err}"),
        )
    })?;
    let runtime = host_runtime(paths, config, identity.identity.device_id.clone());
    // Wired before `on_runtime`/`on_bound` so it is live for every
    // connection the accept loop below could ever admit.
    runtime.server.set_notice_sink(on_notice);
    // Same `trust`/`invites` pair the listener's own evaluator was built
    // from (report §B9/§B14) — `Server::serve_pairing_connection` pins
    // through `trust`'s path and redeems through `invites`.
    runtime.server.set_pairing(trust, invites);
    on_runtime(&runtime);
    tracing::info!(
        device_id = %identity.identity.device_id,
        fingerprint = %identity.identity.fingerprint,
        %actual,
        "qsh serve listening"
    );
    // Announced here, not right after `local_addr()` above, so that the
    // line an external script synchronizes on (`docs/CLI.md` §6.12 makes
    // the stderr line the operator-facing "the address is up" contract)
    // cannot be read before the accept loop is armed. There is no `.await`
    // between this call and `Server::run`'s first `select!` poll, so under
    // tokio's cooperative scheduling nothing can observe the announcement
    // while this task is still short of the loop. Announcing earlier left
    // the config-dependent work below — `host_runtime`'s audit-sink spawn
    // and its `acl::load_or_deny` read — inside the window instead.
    on_bound(actual);
    // `Server::run` takes `self: Arc<Self>` by value — this call already
    // consumes and (once the accept loop exits) drops `runtime.server`
    // internally, so nothing of this function's own is keeping `Server`
    // alive once `.await` resolves; only `runtime.audit` survives.
    runtime.server.run(listener, shutdown).await;
    // F2 (`PLAN.md` M5 Step 3): `Server::run`'s accept loop detaches each
    // connection's task (`tokio::spawn`, no `JoinSet`) and `drain()` only
    // waits for the broker's own sessions, not those tasks themselves — so
    // a straggler can still hold its own `Arc<Server>` clone (and thus,
    // through it, the one shared `Server::audit` field) for a moment after
    // `run` returns. Give it a bounded grace period to drop it before this
    // function's own `runtime.audit` goes out of scope, so
    // `RotatingAuditSink::drop`'s final bounded flush is more likely to run
    // promptly once every remaining clone is gone. Best effort, not a
    // guarantee — see `wait_for_sole_owner`'s docs.
    crate::audit::wait_for_sole_owner(&runtime.audit, crate::audit::AUDIT_SHUTDOWN_GRACE).await;
    Ok(())
}

/// An authorized, broker-backed host, ready to `dispatch` requests over any
/// control stream (`docs/design/architecture.md` §3, §6).
///
/// [`host_runtime`] is the one place that assembles this — shared by `qsh
/// serve` here and, from `PLAN.md` Step 3 PR 3b, `qsh reverse`: a reverse
/// target *is* a host, just one that dialed out instead of accepting a
/// connection, so it reuses the exact same broker/audit/authorizer
/// construction rather than a second copy of it (`docs/CLI.md` §6.13: the
/// sessions a reverse target serves follow the same broker/writer-lease
/// discipline as `qsh serve`'s).
#[derive(Clone)]
pub struct HostRuntime {
    /// The host, ready for `server.run(..)` (forward) or
    /// `server.serve_control(..)` (reverse, on an already-dialed
    /// connection).
    pub server: Arc<Server>,
    /// The audit sink `server` writes to — exposed so a caller that needs
    /// to record connection-level decisions of its own (e.g. Step 3's
    /// `host.reverse` registration choke point) writes to the same log.
    pub audit: Arc<RotatingAuditSink>,
    /// `Some` when `acl.toml` could not be turned into a usable policy
    /// (missing or invalid) — `server`'s authorizer is [`crate::acl::DenyAll`]
    /// in that case, and the caller (`qsh-cli`'s `run_serve`/`run_reverse`
    /// wrappers) must print [`StartupDiagnostic::render`]'s output to
    /// stderr exactly once (`PLAN.md` M5 Step 6). `None` when a real
    /// [`crate::acl::Policy`] loaded.
    pub policy_diagnostic: Option<StartupDiagnostic>,
}

/// Build a [`HostRuntime`]: session broker (with its TTL reaper spawned),
/// the `acl.toml`-backed policy this process resolved at startup
/// ([`load_or_deny_with_index`] — falls back to `DenyAll` plus a
/// [`HostRuntime::policy_diagnostic`] on anything short of a clean load,
/// `PLAN.md` M5 Step 6; replaces the M1–M4 `AllowAllPinned` interim
/// posture), the rotating, bounded-queue audit sink at `[audit]`'s
/// configured path (`crate::audit::RotatingAuditSink`, `PLAN.md` M5 Step
/// 3), and the `Server` that ties them together under `device_id`.
///
/// The broker outlives every connection (`docs/design/architecture.md`
/// §3); its TTL reaper stops on its own once the returned `Server` (and the
/// broker `Arc` inside it) is dropped. Sessions are PTY-backed on unix;
/// elsewhere the factory answers `UNSUPPORTED` without spawning anything
/// (Windows host is P2 — README limitations).
///
/// Policy loads exactly once, here, at process start — never hot-reloaded
/// (`docs/CLI.md` §6.12/§6.13, `PLAN.md` M5 §4.1 #6): a reverse target
/// calls this once per process too (`crate::reverse::target::run_reverse_unix`),
/// not once per reconnect, for the same reason.
pub fn host_runtime(paths: &Paths, config: &Config, device_id: impl Into<String>) -> HostRuntime {
    let audit = Arc::new(RotatingAuditSink::spawn(
        config.audit.path(paths),
        config.audit.max_bytes(),
        config.audit.retain(),
        config.audit.queue_depth(),
    ));
    let broker = Broker::new(
        Arc::new(SystemClock),
        BrokerConfig::from_serve(&config.serve),
        crate::pty::factory(),
    );
    tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
    // `_with_index` over plain `load_or_deny`: the pairing-pin
    // notice (ADR-0017 결정 3) needs to ask "does a pin-path row already
    // name this principal", which only the concrete `Policy` this call
    // just loaded can answer (`crate::acl::PinnedPrincipalIndex`'s own
    // doc) — by the time `authorizer` below is an `Arc<dyn Authorizer>`
    // that type is erased. `crate::reverse::listen::run_listen_unix` keeps
    // calling plain `load_or_deny`: a reverse target never reaches
    // `Server::serve_pairing_connection` at all.
    let (authorizer, policy_diagnostic, pinned_principals) =
        load_or_deny_with_index(paths, Role::Serve);
    // `PLAN.md` M8 Step 2: the same operator-configured admission bounds
    // for every host role this constructs (`qsh serve` and a reverse
    // target's own accept loop, `crate::reverse::target::run_reverse_unix`
    // — both are internet-exposed accept loops per the design's own audit
    // finding).
    let admission = crate::admission::Gate::new(
        Arc::new(SystemClock),
        config.serve.max_concurrent_handshakes(),
        config.serve.handshake_rate_per_source(),
        config.serve.validated_rate_per_source(),
    );
    // `PLAN.md` M8 Step 3: the same operator-configured `[serve]` quota
    // limits the broker above already resolved via `BrokerConfig::
    // from_serve` (session-count axes), so the `Server`'s own quota
    // tracker (`exec.run` concurrency + every axis's audit-aggregation
    // window, `crate::quota` module doc) sees the identical values instead
    // of `QuotaLimits::default`.
    let quotas = crate::quota::Quotas::new(
        crate::quota::QuotaLimits::from_serve(&config.serve),
        Arc::new(SystemClock),
    );
    let server = Server::with_admission_and_quotas(
        authorizer,
        audit.clone(),
        broker,
        device_id,
        admission,
        quotas,
    );
    server.set_pinned_principals(pinned_principals);
    HostRuntime {
        server,
        audit,
        policy_diagnostic,
    }
}

#[cfg(test)]
mod tests;
