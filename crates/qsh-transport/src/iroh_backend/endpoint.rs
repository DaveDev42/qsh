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
//! - **One fixed relay** (decision 11). The relay map holds one URL, so the
//!   endpoint always picks it as its home relay; there is no latency-based
//!   choice among n0's servers.
//! - **OS trust store for relay TLS** (decision 12): [`IrohRelayTrust::System`]
//!   is the default. The relay hop is not what authenticates the peer; the
//!   QUIC connection inside it is, by pin.
//! - **Pin check after the handshake** (decisions 3, 4). iroh cannot consult
//!   a trust store inside its TLS handshake the way the QUIC backend's
//!   verifier does, so the check runs as soon as the handshake is done and
//!   before the connection is handed to anyone. A peer that is not pinned is
//!   closed with `CLOSE_CODE_UNVERIFIED_PEER`, the code the QUIC backend
//!   uses for the same refusal.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{self as ie, QuicTransportConfig, VarInt, presets};
use iroh::tls::CaTlsConfig;
use iroh::{EndpointAddr, EndpointId, RelayMode, RelayUrl};
use rustls::pki_types::CertificateDer as TlsCertificateDer;

use super::conn::IrohConn;
use super::errors::{chain, conn_err};
use super::key::fingerprint_of_endpoint;
use crate::endpoint::{
    AcceptError, CLOSE_CODE_UNVERIFIED_PEER, CONNECTION_RECEIVE_WINDOW,
    DATAGRAM_RECEIVE_BUFFER_SIZE, DATAGRAM_SEND_BUFFER_SIZE, DialError, LocalIdentity,
    MAX_CONCURRENT_BIDI_STREAMS, SetupError, TUNNEL_STREAM_RECEIVE_WINDOW, default_dial_timeout,
};
use crate::error::ConnectionError;
use crate::identity::{CertificateDer, Fingerprint};
use crate::peer_addr::{PeerAddr, PeerKey, PeerPath};
use crate::tls::{AuthPath, PeerRole, RejectReason, TrustEvaluator, VerifiedPeer};
use crate::{Connection, Principal};

/// The ALPN iroh connections negotiate; the QUIC backend's is the same
/// string (`qsh/1`).
pub const IROH_ALPN: &[u8] = b"qsh/1";

/// The relay used when none is configured: one of n0's public relays, fixed
/// (ADR-0061 decisions 10 and 11). The public relays are rate limited and
/// their terms can change; a self-hosted `iroh-relay` is the alternative.
pub const DEFAULT_RELAY_URL: &str = "https://aps1-1.relay.n0.iroh.link.";

/// How an iroh endpoint uses relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrohRelay {
    /// No relay: only direct addresses work. The endpoint never contacts a
    /// relay.
    Disabled,
    /// Home on this one relay URL and dial peers through it unless the peer
    /// names another.
    Url(String),
}

impl Default for IrohRelay {
    fn default() -> Self {
        Self::Url(DEFAULT_RELAY_URL.to_owned())
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
    /// Relay use. Defaults to the fixed public relay.
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
}

/// Whom to dial: the peer's Ed25519 public key plus however to reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrohPeer {
    /// The peer's Ed25519 public key (its iroh endpoint id).
    pub key: [u8; 32],
    /// The relay the peer homes on; `None` means this endpoint's own relay.
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

/// An iroh endpoint bound to a qsh identity. A cheap `Clone` handle.
#[derive(Clone)]
pub struct IrohEndpoint {
    ep: iroh::Endpoint,
    evaluator: Arc<dyn TrustEvaluator>,
    relay: Option<RelayUrl>,
    timeout: Duration,
}

impl fmt::Debug for IrohEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohEndpoint")
            .field("id", &self.ep.id().fmt_short().to_string())
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

fn setup_err(what: &str, err: &dyn std::error::Error) -> SetupError {
    SetupError::Iroh(format!("{what}: {}", chain(err)))
}

/// The connection-level transport settings qsh sets on its QUIC connections,
/// applied to the iroh connection too: stream table, flow-control windows,
/// send fairness and the datagram buffers (`docs/design/protocol.md` §12).
/// Keep-alive, idle timeout and congestion control stay iroh's, which tunes
/// them for its multipath holepunching.
fn transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
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
    /// Bind an endpoint for `identity`. `evaluator` is the trust store every
    /// connecting and accepted peer is judged by.
    pub async fn bind(
        identity: &LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        config: IrohConfig,
    ) -> Result<Self, SetupError> {
        let secret = identity.iroh_secret_key()?;
        let relay = match &config.relay {
            IrohRelay::Disabled => None,
            IrohRelay::Url(url) => Some(
                url.parse::<RelayUrl>()
                    .map_err(|e| setup_err("relay url", &e))?,
            ),
        };

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
            .transport_config(transport_config());
        if let Some(url) = &relay {
            builder = builder.relay_mode(RelayMode::custom([url.clone()]));
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
        Ok(Self {
            ep,
            evaluator,
            relay,
            timeout: default_dial_timeout(),
        })
    }

    /// Override the dial timeout (default: [`default_dial_timeout`]).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// This endpoint's Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        *self.ep.id().as_bytes()
    }

    /// This endpoint's qsh fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint_of_endpoint(&self.ep.id())
    }

    /// The local UDP sockets the endpoint is bound on.
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.ep.bound_sockets()
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

    /// Close the endpoint and every connection on it, waiting briefly for
    /// the close frames to be acknowledged.
    pub async fn close(&self) {
        self.ep.close().await;
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
        let relay = match &peer.relay {
            Some(url) => Some(url.parse::<RelayUrl>().map_err(|e| {
                DialError::Failed(ConnectionError::Other(
                    format!("peer relay url: {e}").into(),
                ))
            })?),
            None => self.relay.clone(),
        };
        if let Some(url) = relay {
            addr = addr.with_relay_url(url);
        }
        for direct in &peer.direct_addrs {
            addr = addr.with_ip_addr(*direct);
        }
        if addr.is_empty() {
            return Err(DialError::Failed(ConnectionError::Other(
                "no route to the peer: relay disabled and no direct address".into(),
            )));
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
            Ok(verified) => Ok(self.wrap(conn, fp, PeerRole::Server, verified)),
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

    fn wrap(
        &self,
        conn: ie::Connection,
        peer: Fingerprint,
        role: PeerRole,
        verified: VerifiedPeer,
    ) -> Connection {
        Connection::from_iroh(IrohConn::new(conn, self.ep.clone(), peer), role, verified)
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

    /// Whether the attempt arrives through a relay.
    pub fn via_relay(&self) -> bool {
        matches!(self.incoming.remote_addr(), ie::IncomingAddr::Relay { .. })
    }

    /// Run the handshake and judge the peer by the trust store. A peer that
    /// is not pinned (and for which no pairing window is open) is closed
    /// with `CLOSE_CODE_UNVERIFIED_PEER` and never surfaces as a
    /// [`Connection`].
    pub async fn accept(self) -> Result<Connection, AcceptError> {
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
        let fp = fingerprint_of_endpoint(&conn.remote_id());
        match verify_iroh_peer(&*endpoint.evaluator, &fp) {
            Ok(verified) => Ok(endpoint.wrap(conn, fp, PeerRole::Client, verified)),
            Err(reason) => {
                conn.close(
                    VarInt::from_u32(CLOSE_CODE_UNVERIFIED_PEER),
                    b"unverified peer",
                );
                Err(AcceptError::Unverified(reason))
            }
        }
    }
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
