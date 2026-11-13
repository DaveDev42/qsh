//! The iroh client identity proof (`docs/design/protocol.md` §22.8).
//!
//! A client endpoint binds a fresh random iroh key and proves its qsh
//! identity in-band; the server judges the proven key. These tests pin both
//! halves: concurrent client endpoints of one identity coexist on a relay,
//! and the server refuses a forged, replayed, unpinned, missing or malformed
//! proof without producing a connection.
//!
//! The refusal tests speak the wire frame by hand through iroh's own API, so
//! the frame layout in the document is checked independently of the code that
//! writes it. Everything runs on loopback or against the in-process relay.

use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use iroh::endpoint::{self as ie, presets};
use iroh::{EndpointAddr, EndpointId, RelayMode, SecretKey};
use qsh_transport::endpoint::CLOSE_CODE_UNVERIFIED_PEER;
use qsh_transport::{
    AcceptError, CLOSE_DRAIN_CAP, CertificateDer, Connection, Endpoint, Fingerprint, IROH_ALPN,
    IrohEndpoint, IrohPeer, LocalIdentity, PeerAddr, Principal, RejectReason, StaticTrust,
    fingerprint_of_ed25519_key,
};

use crate::iroh_support::{TestRelay, direct_config};

const DEADLINE: Duration = Duration::from_secs(15);

/// The signed-message domain and exporter label of §22.8, written out here
/// on purpose: a change to either in the code must fail these tests.
const DOMAIN: &[u8] = b"qsh iroh client identity v1";
const EXPORTER_LABEL: &[u8] = b"qsh iroh client identity exporter v1";

/// A qsh identity built from a known seed, so a test can also sign with it.
struct Identity {
    local: LocalIdentity,
    secret: SecretKey,
    fp: Fingerprint,
}

fn identity() -> Identity {
    let secret = SecretKey::generate();
    // PKCS#8 v1 PrivateKeyInfo for an Ed25519 seed (RFC 8410).
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&secret.to_bytes());
    Identity {
        local: LocalIdentity {
            cert_chain: Vec::<CertificateDer>::new(),
            key_pkcs8_der: zeroize::Zeroizing::new(der),
        },
        fp: fingerprint_of_ed25519_key(secret.public().as_bytes()),
        secret,
    }
}

fn client_trust(server: &Identity) -> Arc<StaticTrust> {
    Arc::new(StaticTrust::empty().with_pin(server.fp, Principal::Device("server".into())))
}

fn server_trust(client: &Identity) -> StaticTrust {
    StaticTrust::empty().with_pin(client.fp, Principal::Device("laptop".into()))
}

/// Echo every stream of `conn` until it ends.
fn serve_echo(conn: Connection) {
    tokio::spawn(async move {
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let Ok(data) = recv.read_to_end(1 << 16).await else {
                break;
            };
            if send.write_all(&data).await.is_err() {
                break;
            }
            let _ = send.finish();
        }
    });
}

async fn echo(conn: &Connection, payload: &[u8]) {
    let round = async {
        let (mut send, mut recv) = conn.open_bi().await.expect("open a stream");
        send.write_all(payload).await.expect("write");
        send.finish().expect("finish");
        recv.read_to_end(1 << 16).await.expect("read the echo")
    };
    let back = tokio::time::timeout(DEADLINE, round)
        .await
        .expect("an echo within the deadline");
    assert_eq!(back, payload);
}

/// Accept `n` connections on `ep` and hand each to the echo server; return
/// them for the test to inspect.
fn accept_n(ep: &IrohEndpoint, n: usize) -> tokio::task::JoinHandle<Vec<Connection>> {
    let ep = ep.clone();
    tokio::spawn(async move {
        let mut out = Vec::new();
        for _ in 0..n {
            let incoming = ep.accept().await.expect("an attempt");
            let conn = incoming.accept().await.expect("server handshake");
            serve_echo(conn.clone());
            out.push(conn);
        }
        out
    })
}

/// Two client endpoints of one identity, on one relay, to one server: the
/// failure this pins is a relay keeping only the newest of two endpoints
/// with the same `EndpointId`. Both connections work, before and after the
/// other has been active, and the server sees the same proven identity on
/// each.
#[tokio::test]
async fn two_client_endpoints_of_one_identity_both_stay_connected() {
    let relay = TestRelay::spawn().await;
    let server = identity();
    let client = identity();
    let server_ep = IrohEndpoint::bind(
        &server.local,
        Arc::new(server_trust(&client)),
        relay.config(),
    )
    .await
    .expect("bind the server");
    tokio::time::timeout(DEADLINE, server_ep.online())
        .await
        .expect("the server reaches the relay");

    // The clients have only an IPv6 loopback socket and the server only an
    // IPv4 one, so no direct path can form and everything stays on the
    // relay, where an `EndpointId` shared by two endpoints is fatal to one
    // (binding both with `IrohEndpoint::bind` fails this test).
    let mut config = relay.config();
    config.bind = vec![(std::net::Ipv6Addr::LOCALHOST, 0).into()];
    let a = IrohEndpoint::bind_client(&client.local, client_trust(&server), config.clone())
        .await
        .expect("bind client a");
    let b = IrohEndpoint::bind_client(&client.local, client_trust(&server), config)
        .await
        .expect("bind client b");
    assert_ne!(
        a.public_key(),
        b.public_key(),
        "client endpoints must not share an EndpointId"
    );
    assert_ne!(a.public_key(), *client.secret.public().as_bytes());
    assert_eq!(a.identity_key(), *client.secret.public().as_bytes());
    assert_eq!(a.fingerprint(), client.fp);
    assert_eq!(b.fingerprint(), client.fp);

    let accepted = accept_n(&server_ep, 2);
    let peer = IrohPeer::new(server_ep.public_key());
    let ca = tokio::time::timeout(DEADLINE, a.dial(&peer))
        .await
        .unwrap()
        .expect("dial a");
    let cb = tokio::time::timeout(DEADLINE, b.dial(&peer))
        .await
        .unwrap()
        .expect("dial b");
    let server_side = tokio::time::timeout(DEADLINE, accepted)
        .await
        .unwrap()
        .unwrap();

    for conn in &server_side {
        assert_eq!(conn.peer_fingerprint(), Some(client.fp));
        assert_eq!(conn.principal(), &Principal::Device("laptop".into()));
        match conn.remote_address() {
            PeerAddr::Keyed { key, .. } => {
                assert_eq!(key.0, *client.secret.public().as_bytes(), "the proven key");
            }
            other => panic!("expected a keyed peer, got {other}"),
        }
    }

    echo(&ca, b"a first").await;
    echo(&cb, b"b first").await;
    // Long enough for a relay that evicted the older endpoint to have done
    // so and for the older connection to notice.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    echo(&ca, b"a again").await;
    echo(&cb, b"b again").await;
    assert!(ca.close_reason().is_none() && cb.close_reason().is_none());
}

/// A device-key endpoint (a daemon dialing out) proves its identity too, and
/// its proven key is its own endpoint id.
#[tokio::test]
async fn a_daemon_endpoint_proves_the_key_it_is_bound_to() {
    let server = identity();
    let client = identity();
    let server_ep = IrohEndpoint::bind(
        &server.local,
        Arc::new(server_trust(&client)),
        direct_config(),
    )
    .await
    .unwrap();
    let daemon = IrohEndpoint::bind(&client.local, client_trust(&server), direct_config())
        .await
        .unwrap();
    assert_eq!(daemon.public_key(), daemon.identity_key());
    let accepted = accept_n(&server_ep, 1);
    let mut peer = IrohPeer::new(server_ep.public_key());
    peer.direct_addrs = server_ep.bound_sockets();
    let conn = tokio::time::timeout(DEADLINE, daemon.dial(&peer))
        .await
        .unwrap()
        .expect("dial");
    let server_side = accepted.await.unwrap();
    assert_eq!(server_side[0].peer_fingerprint(), Some(client.fp));
    echo(&conn, b"hello").await;
}

// ---- hand-made proofs -------------------------------------------------

async fn raw_endpoint(secret: SecretKey) -> iroh::Endpoint {
    iroh::Endpoint::builder(presets::Empty)
        .secret_key(secret)
        .alpns(vec![IROH_ALPN.to_vec()])
        .crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clear_address_lookup()
        .relay_mode(RelayMode::Disabled)
        // iroh's own default is an enabled portmapper (the `portmapper`
        // feature, ADR-0064): a test endpoint must not search the LAN.
        .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
        .bind()
        .await
        .expect("bind the raw client")
}

async fn raw_connect(ep: &iroh::Endpoint, server: &IrohEndpoint) -> ie::Connection {
    let id = EndpointId::from_bytes(&server.public_key()).unwrap();
    let mut addr = EndpointAddr::new(id);
    for sock in server.bound_sockets() {
        addr = addr.with_ip_addr(sock);
    }
    tokio::time::timeout(DEADLINE, ep.connect(addr, IROH_ALPN))
        .await
        .expect("connect in time")
        .expect("connect")
}

fn exporter(conn: &ie::Connection) -> [u8; 32] {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, &[])
        .expect("export");
    out
}

/// The frame of §22.8: version 1, the identity key, and its signature over
/// `DOMAIN || exporter || server id || client id`.
fn frame(
    claimed: &SecretKey,
    signer: &SecretKey,
    exporter: &[u8; 32],
    server: &EndpointId,
    client: &EndpointId,
) -> Vec<u8> {
    let mut msg = DOMAIN.to_vec();
    msg.extend_from_slice(exporter);
    msg.extend_from_slice(server.as_bytes());
    msg.extend_from_slice(client.as_bytes());
    let mut out = vec![1u8];
    out.extend_from_slice(claimed.public().as_bytes());
    out.extend_from_slice(&signer.sign(&msg).to_bytes());
    out
}

async fn send_frame(conn: &ie::Connection, bytes: &[u8]) {
    let mut stream = conn.open_uni().await.expect("open the proof stream");
    stream.write_all(bytes).await.expect("write the proof");
    stream.finish().expect("finish the proof");
}

fn closed_unverified(err: &ie::ConnectionError) -> bool {
    matches!(
        err,
        ie::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == u64::from(CLOSE_CODE_UNVERIFIED_PEER)
    )
}

/// One refused attempt: what the server's accept returned, and whether the
/// raw client then saw the unverified-peer close.
struct Refusal {
    accepted: Result<Connection, AcceptError>,
    client_saw_unverified_close: bool,
    waited: Duration,
}

/// A server that pins `client`, and one raw connection to it whose first
/// stream is `proof(&conn, server_id, client_id)` (`None` sends nothing).
async fn attempt(
    client: &Identity,
    proof_timeout: Duration,
    proof: impl FnOnce(&ie::Connection, &EndpointId, &EndpointId) -> Option<Vec<u8>>,
) -> Refusal {
    let server = identity();
    let server_ep = IrohEndpoint::bind(
        &server.local,
        Arc::new(server_trust(client)),
        direct_config(),
    )
    .await
    .unwrap()
    .with_proof_timeout(proof_timeout);
    let accept = {
        let ep = server_ep.clone();
        tokio::spawn(async move {
            let incoming = ep.accept().await.expect("an attempt");
            incoming.accept().await
        })
    };
    let ephemeral = SecretKey::generate();
    let raw = raw_endpoint(ephemeral.clone()).await;
    let conn = raw_connect(&raw, &server_ep).await;
    let started = Instant::now();
    let server_id = EndpointId::from_bytes(&server_ep.public_key()).unwrap();
    if let Some(bytes) = proof(&conn, &server_id, &ephemeral.public()) {
        send_frame(&conn, &bytes).await;
    }
    let accepted = tokio::time::timeout(DEADLINE, accept)
        .await
        .expect("accept finishes")
        .unwrap();
    let waited = started.elapsed();
    let closed = tokio::time::timeout(DEADLINE, conn.closed())
        .await
        .expect("the refused connection is closed");
    Refusal {
        accepted,
        client_saw_unverified_close: closed_unverified(&closed),
        waited,
    }
}

fn assert_refused(r: &Refusal, what: &str) {
    assert!(
        matches!(
            r.accepted,
            Err(AcceptError::Unverified(RejectReason::Untrusted))
        ),
        "{what}: expected Unverified(Untrusted), got {:?}",
        r.accepted
    );
    assert!(
        r.client_saw_unverified_close,
        "{what}: the client must see the unverified-peer close"
    );
}

/// The frame as the document defines it is accepted: this is what makes the
/// refusals below about the proof and not about the harness.
#[tokio::test]
async fn a_hand_made_proof_is_accepted() {
    let client = identity();
    let server = identity();
    let server_ep = IrohEndpoint::bind(
        &server.local,
        Arc::new(server_trust(&client)),
        direct_config(),
    )
    .await
    .unwrap();
    let accept = {
        let ep = server_ep.clone();
        tokio::spawn(async move { ep.accept().await.unwrap().accept().await })
    };
    let ephemeral = SecretKey::generate();
    let raw = raw_endpoint(ephemeral.clone()).await;
    let conn = raw_connect(&raw, &server_ep).await;
    let server_id = EndpointId::from_bytes(&server_ep.public_key()).unwrap();
    let bytes = frame(
        &client.secret,
        &client.secret,
        &exporter(&conn),
        &server_id,
        &ephemeral.public(),
    );
    assert_eq!(bytes.len(), 97);
    send_frame(&conn, &bytes).await;
    let accepted = tokio::time::timeout(DEADLINE, accept)
        .await
        .unwrap()
        .unwrap()
        .expect("a correct proof is accepted");
    assert_eq!(accepted.peer_fingerprint(), Some(client.fp));
    assert_eq!(accepted.principal(), &Principal::Device("laptop".into()));
}

#[tokio::test]
async fn a_forged_signature_is_refused() {
    let client = identity();
    let forger = SecretKey::generate();
    let r = attempt(&client, DEADLINE, |conn, server, local| {
        // Claims the pinned key, signs with another.
        Some(frame(
            &client.secret,
            &forger,
            &exporter(conn),
            server,
            local,
        ))
    })
    .await;
    assert_refused(&r, "forged signature");
}

#[tokio::test]
async fn a_proof_made_for_another_endpoint_pair_is_refused() {
    let client = identity();
    let r = attempt(&client, DEADLINE, |conn, server, _local| {
        let someone_else = SecretKey::generate().public();
        Some(frame(
            &client.secret,
            &client.secret,
            &exporter(conn),
            server,
            &someone_else,
        ))
    })
    .await;
    assert_refused(&r, "proof for another client endpoint id");
}

#[tokio::test]
async fn a_proof_for_a_key_the_server_does_not_pin_is_refused() {
    let pinned = identity();
    let stranger = identity();
    // The proof is correct; the key it proves is not pinned and no pairing
    // window is open.
    let r = attempt(&pinned, DEADLINE, |conn, server, local| {
        Some(frame(
            &stranger.secret,
            &stranger.secret,
            &exporter(conn),
            server,
            local,
        ))
    })
    .await;
    assert_refused(&r, "unpinned proven key");
}

#[tokio::test]
async fn a_missing_proof_times_out() {
    let client = identity();
    let r = attempt(&client, Duration::from_millis(600), |_, _, _| None).await;
    assert_refused(&r, "missing proof");
    assert!(
        r.waited >= Duration::from_millis(500),
        "the server waited for the proof ({:?})",
        r.waited
    );
    assert!(r.waited < Duration::from_secs(5), "{:?}", r.waited);
}

#[tokio::test]
async fn malformed_frames_are_refused() {
    let client = identity();
    let good = |conn: &ie::Connection, server: &EndpointId, local: &EndpointId| {
        frame(
            &client.secret,
            &client.secret,
            &exporter(conn),
            server,
            local,
        )
    };
    // One byte short.
    let r = attempt(&client, DEADLINE, |c, s, l| {
        let mut f = good(c, s, l);
        f.pop();
        Some(f)
    })
    .await;
    assert_refused(&r, "short frame");
    // One byte over: the frame is bounded, so the extra byte is refused.
    let r = attempt(&client, DEADLINE, |c, s, l| {
        let mut f = good(c, s, l);
        f.push(0);
        Some(f)
    })
    .await;
    assert_refused(&r, "long frame");
    // An unknown version.
    let r = attempt(&client, DEADLINE, |c, s, l| {
        let mut f = good(c, s, l);
        f[0] = 2;
        Some(f)
    })
    .await;
    assert_refused(&r, "unknown version");
    // Far over the bound: refused without buffering it all.
    let r = attempt(&client, DEADLINE, |_, _, _| Some(vec![1u8; 64 * 1024])).await;
    assert_refused(&r, "oversize frame");
}

/// A proof is bound to the connection it was made on. The same raw endpoint
/// (so the same client endpoint id) opens two connections to one server; the
/// first carries a correct proof, the second carries a copy of the first's.
#[tokio::test]
async fn a_proof_replayed_onto_another_connection_is_refused() {
    let client = identity();
    let server = identity();
    let server_ep = IrohEndpoint::bind(
        &server.local,
        Arc::new(server_trust(&client)),
        direct_config(),
    )
    .await
    .unwrap();
    let accept = {
        let ep = server_ep.clone();
        tokio::spawn(async move {
            let first = ep.accept().await.unwrap().accept().await;
            let second = ep.accept().await.unwrap().accept().await;
            (first, second)
        })
    };
    let ephemeral = SecretKey::generate();
    let raw = raw_endpoint(ephemeral.clone()).await;
    let server_id = EndpointId::from_bytes(&server_ep.public_key()).unwrap();

    let first = raw_connect(&raw, &server_ep).await;
    let copied = frame(
        &client.secret,
        &client.secret,
        &exporter(&first),
        &server_id,
        &ephemeral.public(),
    );
    send_frame(&first, &copied).await;
    // Let the first connection finish before the second starts, so the
    // server's accept order is the order here.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let second = raw_connect(&raw, &server_ep).await;
    assert_ne!(
        exporter(&first),
        exporter(&second),
        "two connections must have two exporters"
    );
    send_frame(&second, &copied).await;

    let (first_result, second_result) = tokio::time::timeout(DEADLINE, accept)
        .await
        .unwrap()
        .unwrap();
    assert!(first_result.is_ok(), "the original proof is accepted");
    assert!(
        matches!(
            second_result,
            Err(AcceptError::Unverified(RejectReason::Untrusted))
        ),
        "the replayed proof must be refused, got {second_result:?}"
    );
    let closed = tokio::time::timeout(DEADLINE, second.closed())
        .await
        .unwrap();
    assert!(closed_unverified(&closed), "{closed:?}");
}

/// Through the real client API: a client endpoint whose identity the server
/// does not pin gets no connection and sees the refusal as a crypto-class
/// close, the way the QUIC backend reports an unpinned client.
#[tokio::test]
async fn an_unpinned_client_endpoint_gets_no_connection() {
    let server = identity();
    let client = identity();
    let other = identity();
    let server_ep = IrohEndpoint::bind(
        &server.local,
        Arc::new(server_trust(&other)),
        direct_config(),
    )
    .await
    .unwrap();
    let accept = {
        let ep = server_ep.clone();
        tokio::spawn(async move { ep.accept().await.unwrap().accept().await })
    };
    let ep = IrohEndpoint::bind_client(&client.local, client_trust(&server), direct_config())
        .await
        .unwrap();
    let mut peer = IrohPeer::new(server_ep.public_key());
    peer.direct_addrs = server_ep.bound_sockets();
    let conn = tokio::time::timeout(DEADLINE, ep.dial(&peer))
        .await
        .unwrap()
        .expect("the client's own checks pass");
    let accepted = tokio::time::timeout(DEADLINE, accept)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            accepted,
            Err(AcceptError::Unverified(RejectReason::Untrusted))
        ),
        "{accepted:?}"
    );
    let closed = tokio::time::timeout(DEADLINE, conn.closed()).await.unwrap();
    assert!(
        qsh_transport::endpoint::is_crypto_failure(&closed),
        "{closed:?}"
    );
}

// ---- graceful close ---------------------------------------------------

/// Events at error level, recorded by a process-wide subscriber. Nextest runs
/// each test in its own process, so the global default is this test's alone.
static ERRORS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct ErrorCollector;

impl tracing::Subscriber for ErrorCollector {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::ERROR
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        ERRORS
            .lock()
            .unwrap()
            .push(format!("{}: {}", event.metadata().target(), message.0));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn collect_errors() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        tracing::subscriber::set_global_default(ErrorCollector)
            .expect("no other global subscriber in this test process");
    });
}

fn recorded_errors() -> Vec<String> {
    ERRORS.lock().unwrap().clone()
}

/// A short client command: dial, one round trip, close the connection, wait
/// for the endpoint as `exec` does (`CLOSE_DRAIN_CAP`), and exit. iroh logs
/// an error when an endpoint is dropped before its close finished; a normal
/// command exit must log none.
///
/// The server runs in a runtime of its own and the client in another that is
/// dropped the moment the command ends, the way a process exit drops its
/// runtime and every task still in it. Nothing the command spawned gets time
/// to finish after the last statement.
#[test]
fn a_short_client_command_ends_without_an_error_log() {
    collect_errors();
    let server_rt = tokio::runtime::Runtime::new().unwrap();
    let server = identity();
    let client = identity();
    let (relay, server_ep, accepted) = server_rt.block_on(async {
        let relay = TestRelay::spawn().await;
        let server_ep = IrohEndpoint::bind(
            &server.local,
            Arc::new(server_trust(&client)),
            relay.config(),
        )
        .await
        .unwrap();
        tokio::time::timeout(DEADLINE, server_ep.online())
            .await
            .expect("the server reaches the relay");
        let accepted = accept_n(&server_ep, 1);
        (relay, server_ep, accepted)
    });

    let command = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server_key = server_ep.public_key();
    command.block_on(async {
        let ep = IrohEndpoint::bind_client(&client.local, client_trust(&server), relay.config())
            .await
            .unwrap();
        let conn = ep.dial(&IrohPeer::new(server_key)).await.expect("dial");
        let endpoint = Endpoint::from_iroh(ep);
        echo(&conn, b"one round trip").await;

        // What `exec` does at the end of a command.
        conn.close(0, b"done");
        drop(conn);
        let started = Instant::now();
        endpoint.wait_idle_for(CLOSE_DRAIN_CAP).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the graceful close ends with the peer's acknowledgement, not the cap"
        );
        drop(endpoint);
    });
    drop(command);
    // Whatever iroh logs from the dropped runtime has been logged by now.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(recorded_errors(), Vec::<String>::new());

    let _server_side = server_rt.block_on(accepted).unwrap();
    server_rt.block_on(server_ep.close());
    drop(server_ep);
    drop(relay);
    drop(server_rt);
}

/// Ending a command by dropping the handles, with no explicit close (an
/// error path, a lost route race, a cancelled future), closes the endpoint
/// gracefully too.
#[tokio::test]
async fn dropping_a_client_endpoint_closes_it_gracefully() {
    collect_errors();
    let client = identity();
    let server = identity();
    let server_ep = IrohEndpoint::bind(
        &server.local,
        Arc::new(server_trust(&client)),
        direct_config(),
    )
    .await
    .unwrap();
    let accepted = accept_n(&server_ep, 1);
    let ep = IrohEndpoint::bind_client(&client.local, client_trust(&server), direct_config())
        .await
        .unwrap();
    let mut peer = IrohPeer::new(server_ep.public_key());
    peer.direct_addrs = server_ep.bound_sockets();
    let conn = ep.dial(&peer).await.expect("dial");
    let _server_side = accepted.await.unwrap();
    echo(&conn, b"x").await;
    drop(conn);
    drop(ep);

    // An endpoint that only ever failed to dial.
    let unused = IrohEndpoint::bind_client(&client.local, client_trust(&server), direct_config())
        .await
        .unwrap();
    drop(unused);

    server_ep.close().await;
    drop(server_ep);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(recorded_errors(), Vec::<String>::new());
}

/// What the end of a short iroh command costs, and whether the server hears
/// the close. The client closes its connection, drops it, and waits for its
/// endpoint as `exec` does; the server's view of that connection must end
/// with the client's application close, promptly, not with the 45 s idle
/// timeout. A command that took a second here (iroh's own `Endpoint::close`
/// waits out its relay address-discovery connection) is the regression.
///
/// Server and client run in runtimes of their own, and the client's is
/// dropped the moment the command ends, the way a process exit drops every
/// task still in it: the close the server sees was sent before that, not
/// by a background task that never got to run.
fn short_command_close(relay: bool) {
    collect_errors();
    let server_rt = tokio::runtime::Runtime::new().unwrap();
    let server = identity();
    let client = identity();
    let (test_relay, server_ep, accepted) = server_rt.block_on(async {
        let test_relay = if relay {
            Some(TestRelay::spawn().await)
        } else {
            None
        };
        let config = match &test_relay {
            Some(r) => r.config(),
            None => direct_config(),
        };
        let server_ep = IrohEndpoint::bind(&server.local, Arc::new(server_trust(&client)), config)
            .await
            .unwrap();
        if relay {
            tokio::time::timeout(DEADLINE, server_ep.online())
                .await
                .expect("the server reaches the relay");
        }
        let accepted = accept_n(&server_ep, 1);
        (test_relay, server_ep, accepted)
    });

    let command = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut peer = IrohPeer::new(server_ep.public_key());
    if !relay {
        peer.direct_addrs = server_ep.bound_sockets();
    }
    let config = match &test_relay {
        Some(r) => r.config(),
        None => direct_config(),
    };
    let (close_took, closed_at) = command.block_on(async {
        let ep = IrohEndpoint::bind_client(&client.local, client_trust(&server), config)
            .await
            .unwrap();
        let conn = ep.dial(&peer).await.expect("dial");
        let server_side = accepted.await.unwrap().remove(0);
        let endpoint = Endpoint::from_iroh(ep);
        echo(&conn, b"one round trip").await;

        // The server's wait for the connection to end, timed on its own
        // runtime from the moment the command starts closing.
        let started = Instant::now();
        let seen = server_rt.spawn(async move {
            let err = server_side.closed().await;
            (err, Instant::now())
        });

        // What `exec` does at the end of a command.
        conn.close(0, b"done");
        drop(conn);
        endpoint.wait_idle().await;
        let close_took = started.elapsed();
        drop(endpoint);
        (close_took, (started, seen))
    });
    drop(command);

    let (started, seen) = closed_at;
    let (err, at) = server_rt.block_on(seen).unwrap();
    assert!(
        matches!(err, qsh_transport::ConnectionError::ApplicationClosed(_)),
        "the server must hear the client's close, got {err:?}"
    );
    let heard_after = at.duration_since(started);
    eprintln!(
        "relay={relay}: the command's close took {close_took:?}, the server heard it after {heard_after:?}"
    );
    assert!(
        close_took < Duration::from_millis(400),
        "a short iroh command's close took {close_took:?}; the budget is one round trip, \
         capped at {:?}",
        qsh_transport::IROH_CLOSE_FLUSH_CAP
    );
    assert!(
        heard_after < Duration::from_secs(2),
        "the server heard the close after {heard_after:?}, which is a timeout, not the close"
    );
    // Whatever iroh logs from the dropped runtime has been logged by now.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(recorded_errors(), Vec::<String>::new());

    server_rt.block_on(server_ep.close());
    drop(server_ep);
    drop(test_relay);
    drop(server_rt);
}

#[test]
fn a_short_command_over_a_relay_closes_fast_and_the_server_hears_it() {
    short_command_close(true);
}

#[test]
fn a_short_command_over_a_direct_path_closes_fast_and_the_server_hears_it() {
    short_command_close(false);
}
