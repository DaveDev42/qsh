//! The relay endpoint of a host (ADR-0061 decisions 2, 3, 4, 10 to 12): the
//! second way into `qsh serve` and `qsh listen`, beside the UDP socket.
//!
//! [`IrohServe`] is what a host needs to bring one up; `None` means the host
//! is as it was before the iroh route existed: no endpoint, no extra socket
//! and no contact with any relay. A host given `Some` binds an
//! [`IrohEndpoint`] on its own identity and attaches it to its accept loop
//! ([`crate::server::Server::set_iroh`], [`crate::reverse::listen::Listen::set_iroh`]).
//! Connections that arrive through it join the pipeline QUIC connections
//! use, unchanged from the handshake on: the pin check, role, ACL, audit,
//! quotas, session broker, exec, tunnels and files do not know which
//! transport carried the peer.
//!
//! What differs is admission, because iroh offers no Retry round trip and
//! no peer address that means anything behind a relay (decision 4):
//!
//! 1. before the handshake, [`admit_attempt`]: a direct attempt is rate
//!    limited by its source address, every attempt takes a permit from the
//!    same concurrent-handshake pool QUIC attempts use, and an attempt over
//!    the cap is refused without running a handshake;
//! 2. after the handshake, [`judge_keyed`]: the proven key is counted
//!    against its own bucket ([`crate::admission::Gate::decide_keyed`]), so
//!    a peer is limited as a key, not as the address of a relay or of
//!    whichever path it happens to be on.

use std::net::SocketAddr;
use std::sync::Arc;

use qsh_proto::ErrorCode;
use qsh_transport::{
    CertificateDer, Connection, DEFAULT_RELAY_URL, IrohConfig, IrohEndpoint, IrohIncoming,
    IrohRelay, IrohRelayTrust, LocalIdentity, TrustEvaluator,
};
use tokio::sync::OwnedSemaphorePermit;

use crate::admission::{Decision, Gate};
use crate::audit::AuditSink;
use crate::config::Config;
use crate::ops::OpError;
use crate::server::CLOSE_CODE_RESOURCE_EXHAUSTED;

/// What a host needs to run an iroh endpoint. Passed as `Option<IrohServe>`
/// to the serve and listen startup paths: `None` disables the endpoint.
///
/// The `[iroh]` configuration section feeds this ([`iroh_serve_from_config`]);
/// everything else about how the host serves is already fixed by the rest of
/// its configuration.
#[derive(Debug, Clone)]
pub struct IrohServe {
    /// The one relay the endpoint homes on (`[iroh].relay_url`). Must be an
    /// `https` URL.
    pub relay_url: String,
    /// The UDP port for the endpoint's direct path (`[iroh].bind_port`);
    /// `0` lets the OS pick, which is what a host behind a firewall that
    /// only needs the relay wants.
    pub bind_port: u16,
    /// Whether the relay connection follows `HTTPS_PROXY`-style environment
    /// variables (`[iroh].proxy = "env"`, the default).
    pub proxy_from_env: bool,
    /// Test seam: when non-empty, the relay's TLS certificate is checked
    /// against exactly these roots instead of the OS trust store (an
    /// in-process test relay has a self-signed certificate). Production
    /// leaves it empty, which is the OS store (ADR-0061 decision 12).
    #[doc(hidden)]
    pub relay_roots: Vec<CertificateDer>,
}

impl Default for IrohServe {
    fn default() -> Self {
        Self {
            relay_url: DEFAULT_RELAY_URL.to_owned(),
            bind_port: 0,
            proxy_from_env: true,
            relay_roots: Vec::new(),
        }
    }
}

impl IrohServe {
    /// An endpoint on `relay_url` with its direct path on `bind_port`.
    pub fn new(relay_url: impl Into<String>, bind_port: u16) -> Self {
        Self {
            relay_url: relay_url.into(),
            bind_port,
            proxy_from_env: true,
            relay_roots: Vec::new(),
        }
    }
}

/// The [`IrohServe`] `config` asks for: `None` when the endpoint is off.
///
/// `[iroh]` is validated when the config loads, so an invalid section never
/// reaches a daemon; a value that still fails here keeps the endpoint off
/// (fail closed: no relay contact).
pub fn iroh_serve_from_config(config: &Config) -> Option<IrohServe> {
    let settings = config.iroh.settings().ok()?;
    if !settings.enable {
        return None;
    }
    let mut serve = IrohServe::new(settings.relay_url, settings.bind_port);
    serve.proxy_from_env = matches!(settings.proxy, crate::iroh_settings::IrohProxy::Env);
    Some(serve)
}

/// What `serve.json` records about a running endpoint (`docs/CLI.md` §6.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohBound {
    /// The endpoint's id as a qsh fingerprint (what a peer's pin names).
    pub endpoint_id: String,
    /// The relay it homes on.
    pub relay: String,
}

/// Bind the endpoint `serve` describes for `identity`, judging every peer by
/// `trust`. Configuration problems (a relay URL that is not `https`) are a
/// `CONFIG_ERROR` before any socket exists; a port that cannot be had is a
/// `CONFIG_ERROR` that names it.
pub async fn bind(
    serve: &IrohServe,
    identity: &LocalIdentity,
    trust: Arc<dyn TrustEvaluator>,
) -> Result<IrohEndpoint, OpError> {
    if !serve.relay_url.starts_with("https://") {
        return Err(OpError::new(
            ErrorCode::ConfigError,
            format!(
                "the iroh relay URL {:?} must be an https URL. Fix [iroh].relay_url and restart.",
                serve.relay_url
            ),
        ));
    }
    let trust_roots = if serve.relay_roots.is_empty() {
        IrohRelayTrust::System
    } else {
        IrohRelayTrust::OnlyRoots(serve.relay_roots.clone())
    };
    let config = |bind: Vec<SocketAddr>| IrohConfig {
        relay: IrohRelay::Url(serve.relay_url.clone()),
        relay_trust: trust_roots.clone(),
        bind,
        proxy_from_env: serve.proxy_from_env,
    };
    if serve.bind_port == 0 {
        return IrohEndpoint::bind(identity, trust, config(Vec::new()))
            .await
            .map_err(|err| bind_error(serve, &err));
    }
    // A fixed port: both families on it, and IPv4 alone on a host that has
    // no IPv6 to bind.
    let v4 = SocketAddr::from(([0, 0, 0, 0], serve.bind_port));
    let v6 = SocketAddr::from(([0u16; 8], serve.bind_port));
    match IrohEndpoint::bind(identity, Arc::clone(&trust), config(vec![v4, v6])).await {
        Ok(endpoint) => Ok(endpoint),
        Err(_) => IrohEndpoint::bind(identity, trust, config(vec![v4]))
            .await
            .map_err(|err| bind_error(serve, &err)),
    }
}

fn bind_error(serve: &IrohServe, err: &dyn std::fmt::Display) -> OpError {
    OpError::new(
        ErrorCode::ConfigError,
        format!(
            "cannot start the iroh endpoint (relay {}, port {}): {err}. Nothing is being served. \
             Free the port or set [iroh].bind_port to a free one (0 lets the OS choose), or set \
             [iroh].enable = false.",
            serve.relay_url, serve.bind_port
        ),
    )
}

/// What `serve.json` records for a bound endpoint.
pub fn describe(endpoint: &IrohEndpoint) -> IrohBound {
    IrohBound {
        endpoint_id: endpoint.fingerprint().to_string(),
        relay: endpoint.relay_url().unwrap_or_default(),
    }
}

/// The next inbound attempt on `endpoint`; never resolves when the host has
/// none, so a `select!` arm for it simply stays quiet.
pub(crate) async fn next_incoming(endpoint: Option<&IrohEndpoint>) -> Option<IrohIncoming> {
    match endpoint {
        Some(endpoint) => endpoint.accept().await,
        None => std::future::pending().await,
    }
}

/// Judge one inbound attempt before its handshake. `Some` is the attempt and
/// the handshake permit it holds (drop the permit when the handshake
/// resolves, as for a QUIC attempt); `None` means the attempt was ignored or
/// refused and any audit rows are already written.
pub(crate) fn admit_attempt(
    gate: &Gate,
    audit: &dyn AuditSink,
    incoming: IrohIncoming,
) -> Option<(IrohIncoming, OwnedSemaphorePermit)> {
    let peer = incoming.remote_address();
    match gate.decide_iroh_attempt(&peer, gate.now()) {
        Decision::Admit(permit) => Some((incoming, permit)),
        Decision::Ignore(_, records) => {
            crate::audit::write_admission_audit(audit, &records);
            incoming.ignore();
            None
        }
        Decision::Refuse(_, records) => {
            crate::audit::write_admission_audit(audit, &records);
            incoming.refuse();
            None
        }
        // `decide_iroh_attempt` never asks for a Retry round trip; if a
        // later change ever does, the safe answer is not to proceed.
        Decision::Retry => {
            incoming.ignore();
            None
        }
    }
}

/// Judge a handshaken connection by its proven key. `true` admits it. `false`
/// means the key is over its budget: the rejection is audited (a `connect`
/// `deny` row with the peer's `iroh:<fingerprint>`, aggregated into windowed
/// summaries like every admission rejection) and the connection closed
/// before anything is served on it.
pub(crate) fn judge_keyed(gate: &Gate, audit: &dyn AuditSink, conn: &Connection) -> bool {
    match gate.decide_keyed(&conn.remote_address(), gate.now()) {
        Ok(()) => true,
        Err(records) => {
            crate::audit::write_admission_audit(audit, &records);
            conn.close(CLOSE_CODE_RESOURCE_EXHAUSTED, b"at capacity");
            false
        }
    }
}
