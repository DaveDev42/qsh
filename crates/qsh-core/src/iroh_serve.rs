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
//! 1. before the handshake, `admit_attempt`: a direct attempt is rate
//!    limited by its source address, every attempt takes a permit from the
//!    same concurrent-handshake pool QUIC attempts use, and an attempt over
//!    the cap is refused without running a handshake;
//! 2. after the handshake, `judge_keyed`: the proven key is counted
//!    against its own bucket ([`crate::admission::Gate::decide_keyed`]), so
//!    a peer is limited as a key, not as the address of a relay or of
//!    whichever path it happens to be on.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write as _;
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
use crate::config::{Config, Paths};
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
    /// Test seam: when non-empty and `bind_port` is `0`, the endpoint binds
    /// exactly these sockets instead of ephemeral ports on every interface.
    /// A test that must prove the relay carried a connection binds the host
    /// to IPv4 loopback and its peer to IPv6 loopback, so no direct path can
    /// form. Production leaves it empty.
    #[doc(hidden)]
    pub bind_addrs: Vec<SocketAddr>,
}

impl Default for IrohServe {
    fn default() -> Self {
        Self {
            relay_url: DEFAULT_RELAY_URL.to_owned(),
            bind_port: 0,
            proxy_from_env: true,
            relay_roots: Vec::new(),
            bind_addrs: Vec::new(),
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
            bind_addrs: Vec::new(),
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
        relay_quic_port: None,
    };
    if serve.bind_port == 0 {
        return IrohEndpoint::bind(identity, trust, config(serve.bind_addrs.clone()))
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

/// The file in the state directory whose lock says which process of this
/// machine homes on the relay with the device key.
const CLAIM_FILE: &str = "iroh-endpoint.lock";

/// The right to home on the relay with this device's key, held for as long
/// as the value lives (an advisory lock the OS drops when the process dies).
///
/// A relay keeps one home connection per `EndpointId`, and a daemon endpoint
/// has the device key as its id, so two daemons of one machine (`qsh serve`
/// beside a separate `qsh listen`, both with `[iroh].enable`) would take the
/// relay from each other: the later connection wins, the other process goes
/// deaf without an error ("Another endpoint connected with the same endpoint
/// id"), and a peer's dial lands on whichever happens to hold the relay. A
/// dial that reaches the controller instead of the host is not served. Only
/// one process at a time opens the endpoint; the others say so and run
/// without it (protocol §22.9).
#[derive(Debug)]
pub struct IrohClaim {
    _file: Option<File>,
}

/// What [`claim`] found.
#[derive(Debug)]
pub enum IrohSlot {
    /// This process may open the endpoint; keep the claim for as long as the
    /// endpoint lives.
    Claimed(IrohClaim),
    /// Another live process of this machine holds it; the string names it
    /// ("`qsh serve` (pid 123)").
    Taken(String),
}

/// Try to take the right to home on the relay with this device's key for
/// `role` (`"serve"` or `"listen"`, for the message the other side prints).
/// A state directory that cannot hold the lock file leaves the process as it
/// was before the claim existed: it gets the slot, with a warning.
pub fn claim(paths: &Paths, role: &str) -> IrohSlot {
    let path = paths.state_dir.join(CLAIM_FILE);
    let opened = crate::config::ensure_private_dir(&paths.state_dir)
        .map_err(|err| std::io::Error::other(err.message))
        .and_then(|()| {
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&path)
        });
    let mut file = match opened {
        Ok(file) => file,
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "cannot open the iroh claim file; not checking for another endpoint of this device");
            return IrohSlot::Claimed(IrohClaim { _file: None });
        }
    };
    match file.try_lock() {
        Ok(()) => {
            // Informational: the next claimant names this process from it.
            let _ = file.set_len(0);
            let _ = write!(file, "{} {}", role, std::process::id());
            let _ = file.flush();
            IrohSlot::Claimed(IrohClaim { _file: Some(file) })
        }
        Err(TryLockError::WouldBlock) => {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let mut parts = text.split_whitespace();
            let holder = match (parts.next(), parts.next()) {
                (Some(role), Some(pid)) => format!("`qsh {role}` (pid {pid})"),
                _ => "another qsh process".to_string(),
            };
            IrohSlot::Taken(holder)
        }
        Err(TryLockError::Error(err)) => {
            tracing::warn!(path = %path.display(), %err, "cannot lock the iroh claim file; not checking for another endpoint of this device");
            IrohSlot::Claimed(IrohClaim { _file: Some(file) })
        }
    }
}

/// The endpoint of a daemon plus the claim that lets it exist.
#[derive(Debug)]
pub struct OwnedEndpoint {
    /// The endpoint, homed on the relay with the device key.
    pub endpoint: IrohEndpoint,
    _claim: IrohClaim,
}

/// [`bind`], once this process holds the machine's claim on the device key
/// ([`claim`]). Returns `Ok(None)` and says why through `notice` when another
/// process holds it: the host still starts, without the relay endpoint.
pub async fn bind_exclusive(
    serve: &IrohServe,
    identity: &LocalIdentity,
    trust: Arc<dyn TrustEvaluator>,
    paths: &Paths,
    role: &str,
    notice: impl FnOnce(&str),
) -> Result<Option<OwnedEndpoint>, OpError> {
    let claim = match claim(paths, role) {
        IrohSlot::Claimed(claim) => claim,
        IrohSlot::Taken(holder) => {
            let line = format!(
                "the iroh relay endpoint is not started: {holder} of this device already homes \
                 on the relay with the device key, and a relay keeps one connection per key, so \
                 two processes would take it from each other. Serve and listen from one \
                 `qsh listen --serve`, or set [iroh].enable = false for one of them."
            );
            tracing::warn!("{line}");
            notice(&line);
            return Ok(None);
        }
    };
    let endpoint = bind(serve, identity, trust).await?;
    Ok(Some(OwnedEndpoint {
        endpoint,
        _claim: claim,
    }))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &tempfile::TempDir) -> Paths {
        Paths::new(dir.path().join("c"), dir.path().join("s"))
    }

    /// Two daemons of one machine cannot both home on the relay with the
    /// device key: the second one is told who has it, and gets the slot back
    /// once the first lets go (or dies; the lock is the OS's).
    #[test]
    fn one_process_per_state_dir_holds_the_device_key_at_the_relay() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(&dir);
        let first = match claim(&paths, "serve") {
            IrohSlot::Claimed(claim) => claim,
            IrohSlot::Taken(who) => panic!("a fresh state dir is free, got {who}"),
        };
        match claim(&paths, "listen") {
            IrohSlot::Taken(who) => {
                assert_eq!(who, format!("`qsh serve` (pid {})", std::process::id()));
            }
            IrohSlot::Claimed(_) => panic!("a second claim in the same state dir must wait"),
        }
        drop(first);
        assert!(matches!(claim(&paths, "listen"), IrohSlot::Claimed(_)));
    }

    /// Another state dir is another device identity as far as the lock goes.
    #[test]
    fn another_state_dir_has_its_own_slot() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let _held = claim(&paths(&a), "serve");
        assert!(matches!(claim(&paths(&b), "serve"), IrohSlot::Claimed(_)));
    }
}
