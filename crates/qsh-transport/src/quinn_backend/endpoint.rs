//! The QUIC backend's endpoints: everything `endpoint` hands to quinn.
//!
//! `endpoint` holds the neutral surface ([`Dialer`], [`Listener`],
//! [`Incoming`], [`Endpoint`]: their fields, options and docs) and
//! dispatches here for the work that names quinn:
//!
//! - [`QuicEndpoint`], [`QuicIncoming`]: newtypes over quinn's endpoint and
//!   pending connection, with the few operations callers use.
//! - [`TransportProfile`]: qsh's tuned `TransportConfig` or quinn's stock one.
//! - `impl Dialer`: building the client config, binding the socket, running
//!   the handshake under the dial timeout and classifying a failure.
//! - `impl Listener`: building the server config and binding the socket.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;

use super::config::{client_tls_config, server_config, server_endpoint_config, transport_config};
use super::conn::{QuicConn, classify_dial_failure};
use super::pipe::{
    JUMP_PACKET_MAX, JUMP_PACKET_MIN, PIPE_LOCAL_ADDR, PIPE_REMOTE_ADDR, PacketPipe,
};
use super::socket::{bind_listener_socket, bind_tuned_udp_socket};
use crate::endpoint::{
    DialError, Dialed, Dialer, Endpoint, Incoming, Listener, LocalIdentity, RESET_KEY_LEN,
    SetupError, TransportTuning, finish_dial,
};
use crate::error::{ConnectError, ConnectionError};
use crate::tls::{QshPeerVerifier, TrustEvaluator};

/// A UDP socket a caller supplies instead of a real one (the virtual network
/// of `qsh_testkit::netsim`, the hole-punching socket).
pub type VirtualSocket = dyn quinn::AsyncUdpSocket;

/// Which `TransportConfig` a QUIC endpoint is built with.
#[derive(Clone, Copy, Debug)]
pub(crate) enum TransportProfile {
    /// qsh's tuning (`docs/design/protocol.md` §12) with the given liveness
    /// knobs.
    Tuned(TransportTuning),
    /// quinn's own stock configuration, for the untuned baseline of the
    /// throughput gate.
    Stock,
}

impl TransportProfile {
    fn build(self) -> quinn::TransportConfig {
        match self {
            Self::Tuned(tuning) => transport_config(tuning),
            Self::Stock => quinn::TransportConfig::default(),
        }
    }
}

/// A quinn endpoint.
#[derive(Clone, Debug)]
pub(crate) struct QuicEndpoint(pub(crate) quinn::Endpoint);

impl QuicEndpoint {
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    pub(crate) async fn wait_idle(&self) {
        self.0.wait_idle().await;
    }

    pub(crate) fn close(&self, code: u32, reason: &[u8]) {
        self.0.close(quinn::VarInt::from_u32(code), reason);
    }

    /// The next inbound attempt; `None` once the endpoint is closed.
    pub(crate) async fn accept(&self) -> Option<QuicIncoming> {
        self.0.accept().await.map(QuicIncoming)
    }

    /// Move to a fresh socket of the same address family (unspecified
    /// address, ephemeral port) tuned like the dial's own; returns the new
    /// local address.
    pub(crate) fn rebind_ephemeral(&self) -> io::Result<SocketAddr> {
        let bind: SocketAddr = match self.0.local_addr()? {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = bind_tuned_udp_socket(bind, true)?;
        self.0.rebind(socket)?;
        self.0.local_addr()
    }
}

/// An inbound quinn attempt whose handshake has not completed.
pub(crate) struct QuicIncoming(pub(crate) quinn::Incoming);

impl QuicIncoming {
    pub(crate) fn remote_address(&self) -> SocketAddr {
        self.0.remote_address()
    }

    pub(crate) fn remote_address_validated(&self) -> bool {
        self.0.remote_address_validated()
    }

    pub(crate) fn may_retry(&self) -> bool {
        self.0.may_retry()
    }

    /// Respond with a Retry; on `Err` the attempt comes back unchanged.
    #[allow(clippy::result_large_err)]
    pub(crate) fn retry(self) -> Result<(), Self> {
        self.0.retry().map_err(|err| Self(err.into_incoming()))
    }

    pub(crate) fn refuse(self) {
        self.0.refuse();
    }

    pub(crate) fn ignore(self) {
        self.0.ignore();
    }

    /// Run the handshake.
    pub(crate) async fn handshake(self) -> Result<QuicConn, ConnectionError> {
        Ok(QuicConn(self.0.await?))
    }
}

impl Dialer {
    /// [`Dialer::dial`] over a UDP socket in `addr`'s address family.
    pub(crate) async fn dial_quic(
        &self,
        addr: SocketAddr,
        server_name: &str,
        profile: TransportProfile,
    ) -> Result<Dialed, DialError> {
        let (client_config, verifier) = self.client_config(profile.build())?;

        // Bind in the remote's address family so we never rely on
        // dual-stack sockets.
        let bind: SocketAddr = match addr.ip() {
            IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = bind_tuned_udp_socket(bind, true)
            .map_err(|source| SetupError::Bind { addr: bind, source })?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|source| SetupError::Bind { addr: bind, source })?;
        endpoint.set_default_client_config(client_config);
        self.connect_on(endpoint, addr, server_name, verifier).await
    }

    /// [`Dialer::dial_over_pipe`]: a client-only endpoint on `pipe`.
    pub(crate) async fn dial_quic_over_pipe(
        &self,
        pipe: PacketPipe,
        server_name: &str,
    ) -> Result<Dialed, DialError> {
        let mut transport = transport_config(self.tuning);
        transport.initial_mtu(JUMP_PACKET_MIN);
        transport.min_mtu(JUMP_PACKET_MIN);
        let mut mtud = quinn::MtuDiscoveryConfig::default();
        mtud.upper_bound(JUMP_PACKET_MAX);
        transport.mtu_discovery_config(Some(mtud));
        let (client_config, verifier) = self.client_config(transport)?;
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            pipe.into_socket(),
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|source| SetupError::Bind {
            addr: PIPE_LOCAL_ADDR,
            source,
        })?;
        endpoint.set_default_client_config(client_config);
        let dialed = self
            .connect_on(endpoint, PIPE_REMOTE_ADDR, server_name, verifier)
            .await?;
        // Binding a real socket under a pipe would cut the inner connection
        // off its channel; a chain says whose socket to move instead
        // ([`Endpoint::rebinding_via`]).
        Ok(Dialed {
            endpoint: dialed.endpoint.without_rebind(),
            ..dialed
        })
    }

    fn client_config(
        &self,
        transport: quinn::TransportConfig,
    ) -> Result<(quinn::ClientConfig, Arc<QshPeerVerifier>), DialError> {
        let verifier = Arc::new(QshPeerVerifier::new(self.evaluator.clone()));
        let tls = client_tls_config(&self.identity, verifier.clone())?;
        let quic = QuicClientConfig::try_from(tls).map_err(|e| SetupError::Quic(e.to_string()))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic));
        client_config.transport_config(Arc::new(transport));
        Ok((client_config, verifier))
    }

    async fn connect_on(
        &self,
        endpoint: quinn::Endpoint,
        addr: SocketAddr,
        server_name: &str,
        verifier: Arc<QshPeerVerifier>,
    ) -> Result<Dialed, DialError> {
        let connecting = endpoint
            .connect(addr, server_name)
            .map_err(ConnectError::from)?;
        let result = tokio::time::timeout(self.timeout, connecting).await;
        let conn = match result {
            Err(_) => return Err(DialError::Timeout(self.timeout)),
            Ok(Ok(conn)) => conn,
            Ok(Err(err)) => return Err(classify_dial_failure(err, verifier.last_observation())),
        };

        let connection = finish_dial(QuicConn(conn), &verifier)?;
        Ok(Dialed {
            connection,
            endpoint: Endpoint::from_quic(QuicEndpoint(endpoint)),
            verifier,
        })
    }
}

impl Listener {
    /// [`Listener::bind`] and its variants: a server endpoint on `bind`.
    pub(crate) fn bind_quic(
        bind: SocketAddr,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        profile: TransportProfile,
        reset_key: Option<&[u8; RESET_KEY_LEN]>,
    ) -> Result<Self, SetupError> {
        let verifier = Arc::new(QshPeerVerifier::new(evaluator));
        let server_config = server_config(&identity, verifier.clone(), profile.build())?;
        let socket =
            bind_listener_socket(bind).map_err(|source| SetupError::Bind { addr: bind, source })?;
        let endpoint = quinn::Endpoint::new(
            server_endpoint_config(reset_key),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|source| SetupError::Bind { addr: bind, source })?;
        Ok(Self {
            endpoint: QuicEndpoint(endpoint),
            verifier,
        })
    }

    /// [`Listener::bind_virtual`]: a server endpoint on a caller-supplied
    /// socket.
    pub(crate) fn bind_quic_virtual(
        socket: Arc<VirtualSocket>,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        tuning: TransportTuning,
    ) -> Result<Self, SetupError> {
        let verifier = Arc::new(QshPeerVerifier::new(evaluator));
        let server_config = server_config(&identity, verifier.clone(), transport_config(tuning))?;
        let addr = socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)));
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            server_endpoint_config(None),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|source| SetupError::Bind { addr, source })?;
        Ok(Self {
            endpoint: QuicEndpoint(endpoint),
            verifier,
        })
    }
}

impl Incoming {
    /// Wrap a QUIC attempt with the verifier of the endpoint that received
    /// it.
    pub(crate) fn from_quic(incoming: QuicIncoming, verifier: Arc<QshPeerVerifier>) -> Self {
        Self { incoming, verifier }
    }
}
