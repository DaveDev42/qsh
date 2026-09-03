//! `qsh serve` — the long-running host mode (`docs/CLI.md` §6.12). Not an
//! operation: no envelope, foreground only, prints the bound address to
//! stderr via the `on_bound` callback and runs until `shutdown` resolves.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use qsh_proto::ErrorCode;
use qsh_transport::{Listener, TrustEvaluator};

use crate::acl::{StartupDiagnostic, load_or_deny};
use crate::audit::RotatingAuditSink;
use crate::broker::{Broker, BrokerConfig, SystemClock};
use crate::config::{Config, Paths};
use crate::identity::LoadedIdentity;
use crate::ops::OpError;
use crate::server::Server;
use crate::trust::{SharedInviteStore, SharedTrustStore};

/// Default listen address when neither `--bind` nor `[serve].bind` is set.
pub const DEFAULT_BIND: &str = "[::]:4433";

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

/// Run the host until `shutdown` resolves.
///
/// `identity` must already be loaded (synchronously, before entering the
/// runtime — see `identity::load`). `on_bound` receives the actual bound
/// address once the listener is up.
pub async fn run_serve(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    bind_flag: Option<&str>,
    on_bound: impl FnOnce(SocketAddr),
    on_runtime: impl FnOnce(&HostRuntime),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    let bind = resolve_bind(bind_flag, config)?;
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
    // obvious thing to look at.
    let listener = Listener::bind(
        bind,
        identity.local,
        Arc::clone(&trust) as Arc<dyn TrustEvaluator>,
    )
    .map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("cannot listen on {bind}: {err}"),
        )
    })?;
    let actual = listener.local_addr().map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("cannot read bound address: {err}"),
        )
    })?;
    on_bound(actual);

    let runtime = host_runtime(paths, config, identity.identity.device_id.clone());
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
/// ([`load_or_deny`] — falls back to `DenyAll` plus a
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
    let (authorizer, policy_diagnostic) = load_or_deny(paths);
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
    HostRuntime {
        server,
        audit,
        policy_diagnostic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_precedence_flag_then_config_then_default() {
        let mut config = Config::default();
        assert_eq!(
            resolve_bind(None, &config).unwrap(),
            DEFAULT_BIND.parse::<SocketAddr>().unwrap()
        );
        config.serve.bind = Some("127.0.0.1:5000".into());
        assert_eq!(
            resolve_bind(None, &config).unwrap(),
            "127.0.0.1:5000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_bind(Some("127.0.0.1:6000"), &config).unwrap(),
            "127.0.0.1:6000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_bind(Some("localhost:7000"), &config)
                .unwrap()
                .port(),
            7000
        );
        let err = resolve_bind(Some("not an address"), &config).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn host_runtime_wires_device_id_and_a_shared_audit_sink() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path(), dir.path());
        let runtime = host_runtime(&paths, &Config::default(), "hermes");
        assert_eq!(runtime.server.local_hello(None).device_name, "hermes");
        assert_eq!(runtime.audit.path(), paths.audit_log());
        assert_eq!(runtime.server.pending_tickets(), 0);
    }
}
