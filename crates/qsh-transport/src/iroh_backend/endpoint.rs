//! The iroh endpoint: build one from a qsh identity, dial a peer by key,
//! accept peers, and judge every peer by the qsh trust store right after the
//! handshake (ADR-0061 decisions 3, 4, 10 to 13).
//!
//! What is fixed here, and why:
//!
//! - **No discovery** (decision 11). The endpoint is built from
//!   `presets::Empty`, which has no address lookup service, so nothing is
//!   published to or resolved from pkarr or DNS. A peer is reached by the
//!   addresses the caller supplies: an optional relay URL (the default relay
//!   when the caller names none) and optional direct socket addresses.
//! - **A configured set of relays** (decision 11, amended by ADR-0062). The
//!   relay map holds exactly the candidate URLs the caller names, and nothing
//!   else is ever added to it. iroh measures them (QUIC address discovery and
//!   an HTTPS probe per relay), homes on the one with the best recent
//!   latency, and moves home to another candidate when the home one stops
//!   answering: the next net report leaves a dead relay out of the latency
//!   table, so it cannot be preferred. A daemon endpoint also asks for a
//!   report as soon as its home relay has been down for a few seconds
//!   ([`keep_home_relay`]) instead of waiting out iroh's 20 to 26 second
//!   period. A dial puts every candidate in the target's address, so the
//!   first packet reaches whichever relay the target is homed on. None of
//!   this needs discovery: the candidates come from configuration.
//! - **OS trust store for relay TLS** (decision 12): [`IrohRelayTrust::System`]
//!   is the default. The relay hop is not what authenticates the peer; the
//!   QUIC connection inside it is, by pin.
//! - **Pin check after the handshake** (decisions 3, 4). iroh cannot consult
//!   a trust store inside its TLS handshake the way the QUIC backend's
//!   verifier does, so the check runs as soon as the handshake is done and
//!   before the connection is handed to anyone. A peer that is not pinned is
//!   closed with `CLOSE_CODE_UNVERIFIED_PEER`, the code the QUIC backend
//!   uses for the same refusal.
//! - **Daemons use the device key, clients a fresh one** (protocol §22.8).
//!   A relay keeps one home connection per `EndpointId`, so two client
//!   processes of one machine on the device key would evict each other. A
//!   client endpoint ([`IrohEndpoint::bind_client`]) therefore binds with a
//!   random key and proves its qsh identity in-band right after the
//!   handshake; the server judges the proven key, not the endpoint id. A
//!   daemon endpoint ([`IrohEndpoint::bind`]) keeps the device key, so its
//!   `EndpointId` is the key peers pin and dial.
//! - **Graceful close** ([`EndpointHandle`]). iroh logs an error when the
//!   last handle of an endpoint drops before `Endpoint::close` ran, so the
//!   handle closes the endpoint itself when it is dropped inside a runtime.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{self as ie, QuicTransportConfig, VarInt, presets};
use iroh::tls::CaTlsConfig;
use iroh::{EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, Watcher as _};
use rustls::pki_types::CertificateDer as TlsCertificateDer;

use super::conn::IrohConn;
use super::errors::{chain, conn_err};
use super::identity_proof::{self, PROOF_TIMEOUT, ProofError};
use super::key::{fingerprint_of_endpoint, fingerprint_of_key};
use super::portmap;
use super::reflexive::{Action, Keeper};
use crate::endpoint::{
    AcceptError, CLOSE_CODE_UNVERIFIED_PEER, CONNECTION_RECEIVE_WINDOW,
    DATAGRAM_RECEIVE_BUFFER_SIZE, DATAGRAM_SEND_BUFFER_SIZE, DialError, LocalIdentity,
    MAX_CONCURRENT_BIDI_STREAMS, MAX_IDLE_TIMEOUT, SetupError, TUNNEL_STREAM_RECEIVE_WINDOW,
    default_dial_timeout,
};
use crate::error::ConnectionError;
use crate::identity::{CertificateDer, Fingerprint};
use crate::peer_addr::{PeerAddr, PeerKey, PeerPath};
use crate::tls::{AuthPath, PeerRole, RejectReason, TrustEvaluator, VerifiedPeer};
use crate::{Connection, Principal};

/// The ALPN iroh connections negotiate; the QUIC backend's is the same
/// string (`qsh/1`).
pub const IROH_ALPN: &[u8] = b"qsh/1";

/// One of n0's public relays (ADR-0061 decisions 10 and 11), the first of
/// [`DEFAULT_RELAY_URLS`]. The public relays are rate limited and their terms
/// can change; a self-hosted `iroh-relay` is the alternative.
pub const DEFAULT_RELAY_URL: &str = "https://aps1-1.relay.n0.iroh.link.";

/// The relays used when none is configured: n0's four public relays
/// (ADR-0062). The endpoint homes on whichever answers fastest and moves to
/// another when it stops answering, so one relay being down does not take
/// every link with it.
pub const DEFAULT_RELAY_URLS: [&str; 4] = [
    "https://aps1-1.relay.n0.iroh.link.",
    "https://usw1-1.relay.n0.iroh.link.",
    "https://use1-1.relay.n0.iroh.link.",
    "https://euc1-1.relay.n0.iroh.link.",
];

/// The most relay candidates one endpoint takes. A dial opens a connection
/// to every candidate, so the set stays small.
pub const MAX_RELAY_CANDIDATES: usize = 8;

/// How an iroh endpoint uses relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrohRelay {
    /// No relay: only direct addresses work. The endpoint never contacts a
    /// relay.
    Disabled,
    /// Home on this one relay URL and dial peers through it unless the peer
    /// names another. No failover: the relay is the only candidate.
    Url(String),
    /// Home on the best of these candidate relays and move to another when it
    /// fails; dial peers through all of them unless the peer names one. At
    /// most [`MAX_RELAY_CANDIDATES`], none empty.
    Urls(Vec<String>),
}

impl IrohRelay {
    /// The candidate URLs, in the order given; empty when the relay is
    /// disabled.
    pub fn candidates(&self) -> Vec<&str> {
        match self {
            Self::Disabled => Vec::new(),
            Self::Url(url) => vec![url.as_str()],
            Self::Urls(urls) => urls.iter().map(String::as_str).collect(),
        }
    }
}

impl Default for IrohRelay {
    fn default() -> Self {
        Self::Urls(DEFAULT_RELAY_URLS.iter().map(|u| (*u).to_owned()).collect())
    }
}

/// Which certificates the relay's TLS certificate is checked against
/// (ADR-0061 decision 12).
#[derive(Clone, Debug, Default)]
pub enum IrohRelayTrust {
    /// The operating system's trust store, through iroh's
    /// `platform-verifier`. A TLS-intercepting network whose root the OS
    /// trusts is accepted.
    #[default]
    System,
    /// The OS trust store plus these roots (a self-hosted relay with a
    /// private CA).
    SystemWithRoots(Vec<CertificateDer>),
    /// Only these roots, ignoring the OS store.
    OnlyRoots(Vec<CertificateDer>),
}

/// How to build an [`IrohEndpoint`].
#[derive(Clone, Debug, Default)]
pub struct IrohConfig {
    /// Relay use. Defaults to n0's public relays ([`DEFAULT_RELAY_URLS`]).
    pub relay: IrohRelay,
    /// How the relay's certificate is verified. Defaults to the OS store.
    pub relay_trust: IrohRelayTrust,
    /// UDP sockets to bind. Empty means one IPv4 and one IPv6 socket on
    /// ephemeral ports. A server that wants a fixed port names it here
    /// (`0.0.0.0:PORT`, and `[::]:PORT` for IPv6).
    pub bind: Vec<SocketAddr>,
    /// Send the relay connection through the HTTP(S) proxy the environment
    /// names (`HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`).
    /// Off by default, so an endpoint built without saying so never reads
    /// the environment (`[iroh].proxy`, `docs/CLI.md` §6.23).
    pub proxy_from_env: bool,
    /// Ask the router for a port mapping (UPnP, NAT-PMP, PCP) so a peer
    /// behind a symmetric NAT can send first to the mapped address
    /// (ADR-0064, `[iroh].portmap`). Honored by a daemon endpoint
    /// ([`IrohEndpoint::bind`]) only: a client endpoint never maps. Off by
    /// default, so an endpoint built without saying so never probes the LAN
    /// gateway; iroh only maps while a relay is configured.
    pub portmap: bool,
    /// Test seam: the UDP port of the relay's QUIC address discovery
    /// service, when it is not the standard one (7842). A test relay that
    /// binds an ephemeral port names it here; production leaves it `None`.
    #[doc(hidden)]
    pub relay_quic_port: Option<u16>,
}

/// Whom to dial: the peer's Ed25519 public key plus however to reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrohPeer {
    /// The peer's Ed25519 public key (its iroh endpoint id).
    pub key: [u8; 32],
    /// The one relay the peer homes on; `None` means every candidate relay of
    /// this endpoint (the peer fails over among its own candidates, so the
    /// dial offers them all).
    pub relay: Option<String>,
    /// Direct socket addresses to try alongside the relay.
    pub direct_addrs: Vec<SocketAddr>,
}

impl IrohPeer {
    /// A peer reached through this endpoint's relay.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            relay: None,
            direct_addrs: Vec::new(),
        }
    }

    /// The qsh fingerprint of the peer's key.
    pub fn fingerprint(&self) -> Fingerprint {
        super::key::fingerprint_of_key(&self.key)
    }
}

/// Endpoints whose graceful close is running in the background.
///
/// A static on purpose. iroh's `Endpoint::close` takes about a second even
/// on loopback, because the endpoint's QUIC address discovery connection to
/// its relay is closed too and the relay never answers that close, so the
/// endpoint waits out the connection's closing period (three PTOs) before it
/// reports the close done. A short command cannot afford that wait, so it
/// starts the close and exits. A process that exits while the close task
/// runs drops the task and the clone it holds; if that were the last clone,
/// iroh would log "Endpoint dropped without calling `Endpoint::close`". The
/// clone kept here is never dropped by a process exit (statics are not
/// dropped), so the endpoint dies with the process, silently. The close task
/// removes its entry when it finishes, so a long-lived process holds an
/// entry only for the seconds a close takes.
static CLOSING: Mutex<Vec<(u64, iroh::Endpoint)>> = Mutex::new(Vec::new());

/// Start `ep`'s graceful close on the current runtime and return at once.
/// Outside a runtime there is nothing to run it on and the endpoint is left
/// to iroh's own drop.
fn close_in_background(ep: &iroh::Endpoint) {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    if ep.is_closed() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let token = NEXT.fetch_add(1, Ordering::Relaxed);
    CLOSING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((token, ep.clone()));
    let ep = ep.clone();
    runtime.spawn(async move {
        ep.close().await;
        CLOSING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(t, _)| *t != token);
    });
}

/// Owns an iroh endpoint and closes it when the last holder lets go.
///
/// iroh logs an error ("Endpoint dropped without calling `Endpoint::close`")
/// when its endpoint is dropped before `close` finished, and a command that
/// ends early, a dial that loses a route race or fails, or an endpoint whose
/// graceful wait was cut short all reach that drop. This handle, shared by
/// [`IrohEndpoint`] and every [`IrohConn`] made from it, starts the close
/// itself when it is the last to go ([`close_in_background`]).
pub(crate) struct EndpointHandle {
    ep: iroh::Endpoint,
    /// The qsh identity key: signs the in-band proof, and is what peers pin.
    /// Equal to the endpoint's own key for a daemon endpoint. Kept here, not
    /// in [`IrohEndpoint`], so the handle every `Endpoint` carries stays
    /// small.
    identity: SecretKey,
    /// Connections a holder closed, kept so the end of a command can wait
    /// for the peer's answer to their `CONNECTION_CLOSE` ([`Self::flush`]).
    /// A closed connection needs no auto-close on drop, so holding a clone
    /// changes nothing about its lifetime.
    closing: Mutex<Vec<ie::Connection>>,
    /// The tasks that keep a daemon endpoint healthy: its public address
    /// advertised ([`keep_reflexive_address`]) and its home relay replaced
    /// when it dies ([`keep_home_relay`]); empty for a client endpoint. They
    /// hold clones of the iroh endpoint, so [`Drop`] ends them before the
    /// close.
    keepers: Vec<tokio::task::JoinHandle<()>>,
}

impl EndpointHandle {
    fn new(
        ep: iroh::Endpoint,
        identity: SecretKey,
        daemon: bool,
        nudge: Option<RelayNudge>,
    ) -> Self {
        let mut keepers = Vec::new();
        if daemon {
            keepers.push(tokio::spawn(keep_reflexive_address(ep.clone())));
            if let Some(nudge) = nudge {
                keepers.push(tokio::spawn(keep_home_relay(ep.clone(), nudge)));
            }
        }
        Self {
            ep,
            identity,
            closing: Mutex::new(Vec::new()),
            keepers,
        }
    }

    /// Remember a connection a holder just closed.
    pub(crate) fn note_closed(&self, conn: &ie::Connection) {
        let mut closing = self.closing.lock().unwrap_or_else(|e| e.into_inner());
        if !closing.iter().any(|c| c.stable_id() == conn.stable_id()) {
            closing.push(conn.clone());
            // A client closes a handful (a punch race, a reconnect); a daemon
            // closes one per peer for as long as it runs and never flushes.
            if closing.len() > MAX_NOTED_CLOSES {
                closing.remove(0);
            }
        }
    }

    /// Wait, for at most `cap`, until the peer has answered the close of
    /// every connection a holder closed. The peer answers a
    /// `CONNECTION_CLOSE` with its own, and that arriving proves ours got
    /// through; a connection the peer closed first has it already. One
    /// round trip in practice, so a path that does not answer costs `cap`.
    async fn flush(&self, cap: Duration) {
        let conns: Vec<ie::Connection> = self
            .closing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let deadline = tokio::time::Instant::now() + cap;
        while !conns
            .iter()
            .all(|c| c.stats().frame_rx.connection_close > 0)
        {
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(FLUSH_POLL).await;
        }
    }
}

/// How many closed connections an endpoint handle remembers.
const MAX_NOTED_CLOSES: usize = 16;

/// How often [`EndpointHandle::flush`] looks for the peer's answer.
const FLUSH_POLL: Duration = Duration::from_millis(2);

impl fmt::Debug for EndpointHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the identity key.
        f.debug_struct("EndpointHandle")
            .field("id", &self.ep.id().fmt_short().to_string())
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for EndpointHandle {
    type Target = iroh::Endpoint;

    fn deref(&self) -> &iroh::Endpoint {
        &self.ep
    }
}

impl Drop for EndpointHandle {
    fn drop(&mut self) {
        for keeper in self.keepers.drain(..) {
            keeper.abort();
        }
        close_in_background(&self.ep);
    }
}

/// Keep the daemon endpoint `ep` advertising the public address its net
/// reports find, through the gaps in which iroh's own set loses it
/// (`reflexive.rs` has the why). Runs until the task is aborted, which
/// [`EndpointHandle`] does when the last holder lets go, or until iroh's
/// report watcher disconnects.
async fn keep_reflexive_address(ep: iroh::Endpoint) {
    let mut keeper = Keeper::default();
    let mut reports = ep.net_report();
    let mut pending = Some(reports.get());
    loop {
        let report = match pending.take() {
            Some(report) => report,
            None => {
                let wake = keeper.next_expiry();
                tokio::select! {
                    next = reports.updated() => match next {
                        Ok(report) => report,
                        Err(_) => return,
                    },
                    () = async {
                        match wake {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending().await,
                        }
                    } => {
                        apply(&ep, keeper.on_tick(tokio::time::Instant::now())).await;
                        continue;
                    }
                }
            }
        };
        let Some(report) = report else {
            continue;
        };
        let actions = keeper.on_report(
            tokio::time::Instant::now(),
            report.global_v4.map(SocketAddr::V4),
            report.global_v6.map(SocketAddr::V6),
        );
        apply(&ep, actions).await;
    }
}

/// Carry out the keeper's decisions on `ep`.
async fn apply(ep: &iroh::Endpoint, actions: Vec<Action>) {
    for action in actions {
        match action {
            Action::Add(addr) => {
                tracing::info!(%addr, "iroh: advertising the public address a net report found");
                ep.add_external_addr(addr).await;
            }
            Action::Remove(addr) => {
                tracing::info!(%addr, "iroh: no longer advertising a public address no report has confirmed");
                ep.remove_external_addr(&addr).await;
            }
        }
    }
}

/// What it takes to make iroh run a net report at once: the relay set, whose
/// re-insertion is the one public way to start a full report.
#[derive(Clone)]
struct RelayNudge {
    relays: Vec<(RelayUrl, Arc<iroh::RelayConfig>)>,
}

impl RelayNudge {
    fn new(urls: &[RelayUrl], quic_port: Option<u16>) -> Self {
        Self {
            relays: urls
                .iter()
                .map(|url| (url.clone(), Arc::new(relay_config(url, quic_port))))
                .collect(),
        }
    }

    /// Re-insert the first candidate: iroh treats it as a relay map change
    /// and starts a full report, which measures every candidate again and
    /// re-picks the home relay among those that answered.
    async fn run(&self, ep: &iroh::Endpoint) {
        if let Some((url, config)) = self.relays.first() {
            ep.insert_relay(url.clone(), Arc::clone(config)).await;
        }
    }
}

/// How long a daemon endpoint's home relay may be down before the endpoint
/// asks for a net report to re-pick it.
const HOME_RELAY_GRACE: Duration = Duration::from_secs(3);

/// How often a daemon endpoint asks again while no home relay is connected.
const HOME_RELAY_NUDGE_EVERY: Duration = Duration::from_secs(10);

/// Re-home a daemon endpoint quickly when its home relay goes away.
///
/// iroh re-picks its home relay from each net report and runs one every 20
/// to 26 seconds. A dead relay is left out of a report's latency table, so
/// the report names another candidate, but a link would wait up to that long
/// for it. This task watches the home relay's connection state and, once no
/// home relay has been connected for [`HOME_RELAY_GRACE`], asks for a report
/// ([`RelayNudge::run`]), again every [`HOME_RELAY_NUDGE_EVERY`] until one is
/// connected. It only asks; the choice stays iroh's. Runs until the task is
/// aborted ([`EndpointHandle`]'s drop) or the status watcher disconnects.
async fn keep_home_relay(ep: iroh::Endpoint, nudge: RelayNudge) {
    let mut status = ep.home_relay_status();
    let mut down: Option<tokio::time::Instant> = None;
    let mut next = tokio::time::Instant::now();
    loop {
        if status
            .get()
            .iter()
            .any(iroh::endpoint::RelayStatus::is_connected)
        {
            down = None;
            if status.updated().await.is_err() {
                return;
            }
            continue;
        }
        let now = tokio::time::Instant::now();
        if down.is_none() {
            down = Some(now);
            next = now + HOME_RELAY_GRACE;
        }
        tokio::select! {
            changed = status.updated() => {
                if changed.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep_until(next) => {
                tracing::info!("iroh: no home relay is connected; asking for a net report to re-home");
                nudge.run(&ep).await;
                next = tokio::time::Instant::now() + HOME_RELAY_NUDGE_EVERY;
            }
        }
    }
}

/// An iroh endpoint bound to a qsh identity. A cheap `Clone` handle.
#[derive(Clone)]
pub struct IrohEndpoint {
    ep: Arc<EndpointHandle>,
    evaluator: Arc<dyn TrustEvaluator>,
    /// The candidate relays, in the order configured; empty when the relay
    /// is disabled.
    ///
    /// Behind an `Arc` so the handle stays as small as it was with a single
    /// relay (an enum in `qsh-core` holds these by value).
    relays: Arc<Vec<RelayUrl>>,
    /// [`IrohConfig::relay_quic_port`], kept for [`Self::refresh_net_report`].
    relay_quic_port: Option<u16>,
    /// Whether this endpoint asked iroh to map a router port.
    mapping: bool,
    timeout: Duration,
    /// How long an accepted connection may take to send its identity proof.
    proof_timeout: Duration,
}

impl fmt::Debug for IrohEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohEndpoint")
            .field("id", &self.ep.id().fmt_short().to_string())
            .field("relays", &self.relays)
            .finish_non_exhaustive()
    }
}

fn setup_err(what: &str, err: &dyn std::error::Error) -> SetupError {
    SetupError::Iroh(format!("{what}: {}", chain(err)))
}

/// The connection-level transport settings qsh sets on its QUIC connections,
/// applied to the iroh connection too: stream table, flow-control windows,
/// send fairness and the datagram buffers (`docs/design/protocol.md` §12),
/// and the 45 s idle timeout the QUIC backend uses. The keep-alive interval
/// stays iroh's 5 s: it is shorter than the QUIC backend's 15 s, so it keeps
/// a relay path and a NAT binding at least as alive, and iroh warns against
/// raising it (its multipath keeps a per-path heartbeat of its own). The
/// congestion controller stays iroh's, which tunes it for holepunching.
fn transport_config() -> QuicTransportConfig {
    let idle = ie::IdleTimeout::try_from(MAX_IDLE_TIMEOUT)
        .expect("45s fits in a QUIC idle timeout VarInt");
    QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle))
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_CONCURRENT_BIDI_STREAMS))
        .send_fairness(true)
        .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER_SIZE))
        .datagram_send_buffer_size(DATAGRAM_SEND_BUFFER_SIZE)
        .stream_receive_window(VarInt::from_u32(TUNNEL_STREAM_RECEIVE_WINDOW))
        .receive_window(
            VarInt::try_from(CONNECTION_RECEIVE_WINDOW).unwrap_or(VarInt::from_u32(u32::MAX)),
        )
        .build()
}

/// The relay's configuration: its URL with the standard QUIC address
/// discovery port, or `quic_port` when a test relay binds another.
fn relay_config(url: &RelayUrl, quic_port: Option<u16>) -> iroh::RelayConfig {
    let mut config = iroh::RelayConfig::from(url.clone());
    if let (Some(port), Some(quic)) = (quic_port, config.quic.as_mut()) {
        quic.port = port;
    }
    config
}

/// The neutral certificates in the TLS stack's type, at the backend boundary.
fn tls_roots(roots: &[CertificateDer]) -> impl Iterator<Item = TlsCertificateDer<'static>> + '_ {
    roots
        .iter()
        .map(|c| TlsCertificateDer::from(c.as_der().to_vec()))
}

fn ca_tls_config(trust: &IrohRelayTrust) -> CaTlsConfig {
    match trust {
        IrohRelayTrust::System => CaTlsConfig::system(),
        IrohRelayTrust::SystemWithRoots(roots) => {
            CaTlsConfig::system().with_extra_roots(tls_roots(roots))
        }
        IrohRelayTrust::OnlyRoots(roots) => CaTlsConfig::custom_roots(tls_roots(roots)),
    }
}

impl IrohEndpoint {
    /// Bind a daemon endpoint for `identity`: the iroh key is the qsh
    /// identity key, so [`Self::public_key`] is the key peers pin and dial.
    /// `evaluator` is the trust store every connecting and accepted peer is
    /// judged by.
    pub async fn bind(
        identity: &LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        config: IrohConfig,
    ) -> Result<Self, SetupError> {
        Self::bind_with(identity, evaluator, config, false).await
    }

    /// Bind a client endpoint for `identity`: the iroh key is a fresh random
    /// one, so concurrent client endpoints of one identity have distinct
    /// `EndpointId`s and a relay keeps all of them. Every dial proves the qsh
    /// identity in-band (protocol §22.8). Use one per command or per dial.
    pub async fn bind_client(
        identity: &LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        config: IrohConfig,
    ) -> Result<Self, SetupError> {
        Self::bind_with(identity, evaluator, config, true).await
    }

    async fn bind_with(
        identity: &LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        config: IrohConfig,
        ephemeral: bool,
    ) -> Result<Self, SetupError> {
        let identity_key = identity.iroh_secret_key()?;
        let mapping = portmap::mapping_wanted(!ephemeral, config.portmap);
        let secret = if ephemeral {
            SecretKey::generate()
        } else {
            identity_key.clone()
        };
        let candidates = config.relay.candidates();
        if candidates.len() > MAX_RELAY_CANDIDATES {
            return Err(SetupError::Iroh(format!(
                "relay url: {} candidates given, at most {MAX_RELAY_CANDIDATES} are taken",
                candidates.len()
            )));
        }
        let mut relays: Vec<RelayUrl> = Vec::with_capacity(candidates.len());
        for url in candidates {
            let parsed = url
                .parse::<RelayUrl>()
                .map_err(|e| setup_err("relay url", &e))?;
            if !relays.contains(&parsed) {
                relays.push(parsed);
            }
        }

        // `presets::Empty`: no address lookup (no pkarr, no DNS), relays
        // disabled until set below. The crypto provider is named explicitly
        // so a build where another provider is also compiled in (a test
        // relay pulls in ring) cannot change which one endpoints use.
        let mut builder = iroh::Endpoint::builder(presets::Empty)
            .secret_key(secret)
            .alpns(vec![IROH_ALPN.to_vec()])
            .crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .clear_address_lookup()
            .ca_tls_config(ca_tls_config(&config.relay_trust))
            .transport_config(transport_config())
            // Always set, never left to iroh's default (`Enabled` once the
            // `portmapper` feature is compiled in): a client must say no.
            .portmapper_config(portmap::portmapper_config(mapping));
        if !relays.is_empty() {
            builder = builder.relay_mode(RelayMode::Custom(
                relays
                    .iter()
                    .map(|url| relay_config(url, config.relay_quic_port))
                    .collect::<iroh::RelayMap>(),
            ));
        }
        if config.proxy_from_env {
            builder = builder.proxy_from_env();
        }
        if !config.bind.is_empty() {
            builder = builder.clear_ip_transports();
            for addr in &config.bind {
                // The IPv6 wildcard may fail to bind on a host without IPv6
                // (iroh's own default socket is optional the same way);
                // every other address is required.
                let optional = addr.ip().is_unspecified() && addr.is_ipv6();
                builder = builder
                    .bind_addr_with_opts(*addr, ie::BindOpts::default().set_is_required(!optional))
                    .map_err(|e| setup_err("bind address", &e))?;
            }
        }
        let ep = builder
            .bind()
            .await
            .map_err(|e| setup_err("bind iroh endpoint", &e))?;
        let nudge = (!relays.is_empty()).then(|| RelayNudge::new(&relays, config.relay_quic_port));
        Ok(Self {
            ep: Arc::new(EndpointHandle::new(ep, identity_key, !ephemeral, nudge)),
            evaluator,
            relays: Arc::new(relays),
            relay_quic_port: config.relay_quic_port,
            mapping,
            timeout: default_dial_timeout(),
            proof_timeout: PROOF_TIMEOUT,
        })
    }

    /// Override the dial timeout (default: [`default_dial_timeout`]).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override how long an accepted connection may take to send its
    /// identity proof (default: [`PROOF_TIMEOUT`], the header timeout). A
    /// test hook: nothing outside tests has a reason to move it.
    #[doc(hidden)]
    #[must_use]
    pub fn with_proof_timeout(mut self, timeout: Duration) -> Self {
        self.proof_timeout = timeout;
        self
    }

    /// This endpoint's iroh key: its `EndpointId`, what a peer dials. For a
    /// daemon endpoint ([`Self::bind`]) this is the qsh identity key; a
    /// client endpoint ([`Self::bind_client`]) has a random one.
    pub fn public_key(&self) -> [u8; 32] {
        *self.ep.id().as_bytes()
    }

    /// The qsh identity key this endpoint speaks for: what a server pins.
    pub fn identity_key(&self) -> [u8; 32] {
        *self.ep.identity.public().as_bytes()
    }

    /// The qsh fingerprint of [`Self::identity_key`].
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint_of_endpoint(&self.ep.identity.public())
    }

    /// Whether this endpoint asks the router for a port mapping: a daemon
    /// endpoint built with [`IrohConfig::portmap`]. A client endpoint is
    /// always `false`.
    pub fn portmap_enabled(&self) -> bool {
        self.mapping
    }

    /// The local UDP sockets the endpoint is bound on.
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.ep.bound_sockets()
    }

    /// The direct addresses the endpoint advertises to peers right now: its
    /// own interface addresses plus the public address a net report found
    /// (a daemon endpoint keeps that one through a failed probe). For logs and tests.
    pub fn advertised_addrs(&self) -> Vec<SocketAddr> {
        self.ep.addr().ip_addrs().copied().collect()
    }

    /// Run a net report now (a test hook: the periodic one runs every 20 to
    /// 26 seconds). Re-inserting the relay is what makes iroh start a full
    /// report at once.
    #[doc(hidden)]
    pub async fn refresh_net_report(&self) {
        if self.relays.is_empty() {
            return;
        }
        RelayNudge::new(self.relays.as_slice(), self.relay_quic_port)
            .run(&self.ep)
            .await;
    }

    /// Resolves with the next net report that found no public IPv4 address,
    /// or `false` when none finishes within `within` (a test hook).
    #[doc(hidden)]
    pub async fn next_report_without_public_v4(&self, within: Duration) -> bool {
        let mut reports = self.ep.net_report();
        let wait = async {
            while let Ok(report) = reports.updated().await {
                if report.is_some_and(|r| r.global_v4.is_none()) {
                    return true;
                }
            }
            false
        };
        tokio::time::timeout(within, wait).await.unwrap_or(false)
    }

    /// The candidate relays, as the URLs they were configured with, in the
    /// order given; empty when the relay is disabled.
    pub fn relay_urls(&self) -> Vec<String> {
        self.relays.iter().map(ToString::to_string).collect()
    }

    /// The relay this endpoint is homed on right now, when it has picked one
    /// (a connected home relay is preferred over one still connecting);
    /// `None` before the first pick, while no candidate answers, and when the
    /// relay is disabled.
    pub fn home_relay(&self) -> Option<String> {
        let mut status = self.ep.home_relay_status();
        let homes = status.get();
        homes
            .iter()
            .find(|s| s.is_connected())
            .or_else(|| homes.first())
            .map(|s| s.url().to_string())
    }

    /// The relay to name in a log or report: the home relay when there is
    /// one, else the first candidate; `None` when the relay is disabled.
    pub fn relay_url(&self) -> Option<String> {
        self.home_relay()
            .or_else(|| self.relays.first().map(ToString::to_string))
    }

    /// Resolves once the endpoint is connected to its relay (never, when the
    /// relay is disabled). Callers wanting a bound should wrap it in a
    /// timeout.
    pub async fn online(&self) {
        self.ep.online().await;
    }

    /// Run a TLS handshake against `addr` with the trust anchors this
    /// endpoint verifies relay certificates with, and report why it failed.
    /// A test hook: the relay connection itself reports nothing a caller can
    /// match on, so the relay-trust tests check the certificate verdict here.
    #[doc(hidden)]
    pub async fn probe_relay_tls(&self, addr: SocketAddr) -> Result<(), String> {
        let config = Arc::new(self.ep.tls_config().clone());
        tokio::task::spawn_blocking(move || {
            let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
            let mut conn =
                rustls::ClientConnection::new(config, name).map_err(|e| e.to_string())?;
            let limit = Duration::from_secs(5);
            let mut tcp =
                std::net::TcpStream::connect_timeout(&addr, limit).map_err(|e| e.to_string())?;
            tcp.set_read_timeout(Some(limit))
                .map_err(|e| e.to_string())?;
            tcp.set_write_timeout(Some(limit))
                .map_err(|e| e.to_string())?;
            while conn.is_handshaking() {
                conn.complete_io(&mut tcp).map_err(|e| chain(&e))?;
            }
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// Close the endpoint and every connection on it, waiting for the close
    /// frames to be acknowledged (iroh bounds that at about three seconds).
    ///
    /// The close runs in its own task, so a caller that stops waiting (a
    /// timeout around this future) does not cancel it half way: iroh treats
    /// an endpoint dropped before its close finished as an error.
    pub async fn close(&self) {
        let ep = Arc::clone(&self.ep);
        let close = tokio::spawn(async move { ep.close().await });
        let _ = close.await;
    }

    /// End a client command's use of the endpoint: wait up to `cap` for the
    /// peer to answer the close of every connection a holder closed, then
    /// start the endpoint's own close in the background and return.
    ///
    /// [`Self::close`] is for a daemon that shuts down and can spend the
    /// seconds iroh needs; waiting for it here added a second to every short
    /// command (see `close_in_background`). The peer learns of the close
    /// from the `CONNECTION_CLOSE` the connection sent, which has left by the
    /// time the answer is back; the endpoint's close adds nothing the
    /// command's exit needs.
    pub async fn finish(&self, cap: Duration) {
        self.ep.flush(cap).await;
        close_in_background(&self.ep);
    }

    /// Start the endpoint's close without waiting for it.
    pub fn close_in_background(&self) {
        close_in_background(&self.ep);
    }

    /// Dial `peer` and judge it by the trust store.
    ///
    /// The dialed key is authenticated by the handshake itself (iroh refuses
    /// a server that does not hold the key), so a name bound to a pin
    /// (ADR-0060) reaches only that pin's key. The pin check that follows
    /// is for the trust store: a key that is not pinned is
    /// [`DialError::LocalRejected`], the same result the QUIC backend gives.
    pub async fn dial(&self, peer: &IrohPeer) -> Result<Connection, DialError> {
        let id = EndpointId::from_bytes(&peer.key).map_err(|_| {
            DialError::Failed(ConnectionError::Other("invalid peer public key".into()))
        })?;
        // The dialed key must be pinned (or a pairing window open) before
        // any packet leaves: an unpinned key causes no handshake and no
        // relay traffic. The check after the handshake still runs, on the
        // key the handshake proved.
        let dialed_fp = fingerprint_of_endpoint(&id);
        if let Err(reason) = verify_iroh_peer(&*self.evaluator, &dialed_fp) {
            return Err(DialError::LocalRejected {
                reason,
                observed: Some(dialed_fp),
            });
        }
        let mut addr = EndpointAddr::new(id);
        // The peer fails over among its own candidates, so it may be homed on
        // any of them. Every candidate goes in the address: iroh sends the
        // first packet to all of them at once, a dead one costs nothing but
        // its own queue, and the handshake completes through the one the peer
        // is on.
        let relays = match &peer.relay {
            Some(url) => vec![url.parse::<RelayUrl>().map_err(|e| {
                DialError::Failed(ConnectionError::Other(
                    format!("peer relay url: {e}").into(),
                ))
            })?],
            None => self.relays.to_vec(),
        };
        for url in relays {
            addr = addr.with_relay_url(url);
        }
        for direct in &peer.direct_addrs {
            addr = addr.with_ip_addr(*direct);
        }
        if addr.is_empty() {
            return Err(DialError::Failed(ConnectionError::NoRoute));
        }

        let conn = match tokio::time::timeout(self.timeout, self.ep.connect(addr, IROH_ALPN)).await
        {
            Err(_) => return Err(DialError::Timeout(self.timeout)),
            Ok(Ok(conn)) => conn,
            Ok(Err(err)) => return Err(classify_connect(err)),
        };

        let peer_id = conn.remote_id();
        let fp = fingerprint_of_endpoint(&peer_id);
        let verified = if peer_id == id {
            verify_iroh_peer(&*self.evaluator, &fp)
        } else {
            // iroh authenticates the dialed key; a different one here would
            // be a bug, and it is not a peer we meant to reach.
            Err(RejectReason::Untrusted)
        };
        match verified {
            Ok(verified) => {
                // The server is the pinned key; now prove who we are, before
                // any other stream (protocol §22.8).
                if let Err(err) =
                    identity_proof::send(&conn, &self.ep.identity, &self.ep.id()).await
                {
                    return Err(match err {
                        ProofError::Lost(lost) => DialError::Failed(conn_err(lost)),
                        ProofError::Invalid(why) => {
                            conn.close(VarInt::from_u32(0), b"identity proof failed");
                            DialError::Failed(ConnectionError::Other(why.into()))
                        }
                    });
                }
                Ok(self.wrap(conn, peer_id.as_bytes(), PeerRole::Server, verified))
            }
            Err(reason) => {
                conn.close(
                    VarInt::from_u32(CLOSE_CODE_UNVERIFIED_PEER),
                    b"unverified peer",
                );
                Err(DialError::LocalRejected {
                    reason,
                    observed: Some(fp),
                })
            }
        }
    }

    /// The next inbound connection attempt, or `None` once the endpoint is
    /// closed. The handshake runs in [`IrohIncoming::accept`], so a caller
    /// can drive many handshakes at once.
    pub async fn accept(&self) -> Option<IrohIncoming> {
        let incoming = self.ep.accept().await?;
        Some(IrohIncoming {
            incoming,
            endpoint: self.clone(),
        })
    }

    /// Wrap a verified connection. `peer_key` is the qsh identity key of the
    /// other end: the dialed server's key, or the key a client proved.
    fn wrap(
        &self,
        conn: ie::Connection,
        peer_key: &[u8; 32],
        role: PeerRole,
        verified: VerifiedPeer,
    ) -> Connection {
        Connection::from_iroh(
            IrohConn::new(conn, Arc::clone(&self.ep), *peer_key),
            role,
            verified,
        )
    }
}

/// An inbound iroh connection attempt that has not been handshaken yet.
pub struct IrohIncoming {
    incoming: ie::Incoming,
    endpoint: IrohEndpoint,
}

impl fmt::Debug for IrohIncoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohIncoming").finish_non_exhaustive()
    }
}

impl IrohIncoming {
    /// Where the attempt comes from, for logs only (unauthenticated). An
    /// attempt through a relay names its claimed key and the relay URL
    /// ([`PeerAddr::Keyed`] on a relay path). A direct attempt carries no
    /// key before the handshake, so it is the plain socket address.
    pub fn remote_address(&self) -> PeerAddr {
        match self.incoming.remote_addr() {
            ie::IncomingAddr::Ip(addr) => PeerAddr::Socket(addr),
            ie::IncomingAddr::Relay { url, endpoint_id } => PeerAddr::Keyed {
                key: PeerKey(*endpoint_id.as_bytes()),
                path: PeerPath::Relay(url.to_string()),
            },
            // A transport iroh adds later: neither a socket address nor a
            // claimed key is known before the handshake, and a made-up key
            // would read as a real peer in logs. The unspecified socket
            // address is the explicit "unknown" (this value is for logs only
            // and is never matched against the trust store).
            _ => PeerAddr::Socket(SocketAddr::from(([0, 0, 0, 0], 0))),
        }
    }

    /// Refuse the attempt: the peer is told the endpoint is at capacity and
    /// no handshake runs.
    pub fn refuse(self) {
        self.incoming.refuse();
    }

    /// Drop the attempt without answering: no handshake runs and nothing is
    /// sent back.
    pub fn ignore(self) {
        self.incoming.ignore();
    }

    /// Whether the attempt arrives through a relay.
    pub fn via_relay(&self) -> bool {
        matches!(self.incoming.remote_addr(), ie::IncomingAddr::Relay { .. })
    }

    /// Run the handshake and judge the peer by the trust store. A peer that
    /// is not pinned (and for which no pairing window is open) is closed
    /// with `CLOSE_CODE_UNVERIFIED_PEER` and never surfaces as a
    /// [`Connection`].
    pub async fn accept(self) -> Result<Connection, AcceptError> {
        self.accept_with_peer().await.0
    }

    /// [`Self::accept`], plus the address to name the peer by in a log or
    /// audit record of the outcome. When the client's identity proof
    /// verified, that is its qsh identity key (on the path the attempt came
    /// by), even if the key turned out not to be pinned: the operator needs
    /// the key that was refused, not the random endpoint id the client
    /// dialed from. When no proof verified (none, or a bad one) it is the
    /// attempt's claimed address ([`Self::remote_address`]), which is all
    /// there is.
    pub async fn accept_with_peer(self) -> (Result<Connection, AcceptError>, PeerAddr) {
        let claimed = self.remote_address();
        let mut proven = None;
        let result = self.accept_inner(&mut proven).await;
        let peer = match (proven, claimed) {
            (Some(key), PeerAddr::Keyed { path, .. }) => PeerAddr::Keyed {
                key: PeerKey(key),
                path,
            },
            (Some(key), PeerAddr::Socket(addr)) => PeerAddr::Keyed {
                key: PeerKey(key),
                path: PeerPath::Direct(addr),
            },
            (None, claimed) => claimed,
        };
        (result, peer)
    }

    async fn accept_inner(
        self,
        proven_out: &mut Option<[u8; 32]>,
    ) -> Result<Connection, AcceptError> {
        let Self { incoming, endpoint } = self;
        let accepting = incoming
            .accept()
            .map_err(|e| AcceptError::Handshake(conn_err(e)))?;
        let conn = accepting.await.map_err(|e| match e {
            ie::ConnectingError::ConnectionError { source, .. } => {
                AcceptError::Handshake(conn_err(source))
            }
            other => AcceptError::Handshake(ConnectionError::Other(chain(&other).into())),
        })?;
        // The handshake proved the endpoint id, which for a client is a
        // random key. The qsh identity is the key it proves in-band; until
        // that arrives (and within the header timeout) nothing else on the
        // connection is read.
        let proven = match tokio::time::timeout(
            endpoint.proof_timeout,
            identity_proof::receive(&conn, &endpoint.ep.id()),
        )
        .await
        {
            Ok(Ok(key)) => key,
            Ok(Err(ProofError::Lost(lost))) => {
                return Err(AcceptError::Handshake(conn_err(lost)));
            }
            Ok(Err(ProofError::Invalid(why))) => {
                tracing::debug!(why, "iroh identity proof refused");
                return Err(unverified(&conn));
            }
            Err(_) => {
                tracing::debug!("iroh identity proof did not arrive in time");
                return Err(unverified(&conn));
            }
        };
        *proven_out = Some(proven);
        let fp = fingerprint_of_key(&proven);
        match verify_iroh_peer(&*endpoint.evaluator, &fp) {
            Ok(verified) => Ok(endpoint.wrap(conn, &proven, PeerRole::Client, verified)),
            Err(_) => Err(unverified(&conn)),
        }
    }
}

/// Refuse a client the way every refusal of an unverified peer goes: the
/// same close code and the same reason for a missing proof, a bad proof and
/// an unpinned key, so the peer learns nothing about which it was.
fn unverified(conn: &ie::Connection) -> AcceptError {
    conn.close(
        VarInt::from_u32(CLOSE_CODE_UNVERIFIED_PEER),
        b"unverified peer",
    );
    AcceptError::Unverified(RejectReason::Untrusted)
}

/// The trust decision for an iroh peer: the same pin lookup and pairing
/// fallback the certificate verifier applies (`tls::verify_core`), minus the
/// private-CA path, which iroh connections do not have (ADR-0061 decision 4).
/// One function for the handshake-time check and
/// [`Connection::reverify`], so they cannot drift.
pub(crate) fn verify_iroh_peer(
    evaluator: &dyn TrustEvaluator,
    fingerprint: &Fingerprint,
) -> Result<VerifiedPeer, RejectReason> {
    if let Some(principal) = evaluator.lookup_pin(fingerprint) {
        return Ok(VerifiedPeer {
            principal,
            auth_path: AuthPath::Pin,
        });
    }
    if evaluator.pairing_open() {
        return Ok(VerifiedPeer {
            principal: Principal::Pairing,
            auth_path: AuthPath::Pairing,
        });
    }
    Err(RejectReason::Untrusted)
}

/// Whether `err` is a TLS alert about the peer's certificate or key proof
/// (RFC 8446 6.2): `bad_certificate` 42 through `certificate_unknown` 46,
/// `unknown_ca` 48, `access_denied` 49, `decrypt_error` 51 and
/// `certificate_required` 116. Other alerts (`handshake_failure`,
/// `no_application_protocol` 120 for an ALPN mismatch, ...) say nothing about
/// whether the dialed key matched.
fn is_certificate_alert(err: &ConnectionError) -> bool {
    matches!(
        err,
        ConnectionError::Crypto {
            alert: 42..=46 | 48 | 49 | 51 | 116,
            ..
        }
    )
}

/// Map a failed iroh connect to the dial error the ops layer classifies.
fn classify_connect(err: ie::ConnectError) -> DialError {
    // The QUIC-level cause, wherever iroh nested it.
    let quic = match &err {
        ie::ConnectError::Connection { source, .. } => Some(conn_err(source.clone())),
        ie::ConnectError::Connecting {
            source: ie::ConnectingError::ConnectionError { source, .. },
            ..
        } => Some(conn_err(source.clone())),
        _ => None,
    };
    match quic {
        // The handshake is the one place the dialed key is proven, and the
        // server only closes an unpinned client after it (as an application
        // close). A TLS failure while connecting therefore means the server
        // did not hold the key we dialed: a local rejection of the target,
        // never a server-side rejection of us.
        Some(q) if is_certificate_alert(&q) => DialError::LocalRejected {
            reason: RejectReason::Untrusted,
            observed: None,
        },
        Some(q) if q.is_refused() => DialError::Refused,
        Some(q) => DialError::Failed(q),
        None => DialError::Failed(ConnectionError::Other(chain(&err).into())),
    }
}

#[cfg(test)]
mod classify_tests {
    use super::*;

    #[test]
    fn only_certificate_class_alerts_count_as_an_untrusted_target() {
        for alert in [42, 43, 44, 45, 46, 48, 49, 51, 116] {
            assert!(
                is_certificate_alert(&ConnectionError::crypto(alert)),
                "alert {alert}"
            );
        }
        // handshake_failure, protocol_version, no_application_protocol (ALPN).
        for alert in [40, 70, 120] {
            assert!(
                !is_certificate_alert(&ConnectionError::crypto(alert)),
                "alert {alert}"
            );
        }
        assert!(!is_certificate_alert(&ConnectionError::TimedOut));
    }
}
