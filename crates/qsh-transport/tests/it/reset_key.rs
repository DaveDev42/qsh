//! L3: the server endpoint's stateless reset key is the injected one
//! (`docs/adr/0036-stateless-reset-key.md`, RFC 9000 §10.3).
//!
//! A process that dies without a goodbye is emulated by dropping the whole
//! tokio runtime the server lives in: every task is dropped unpolled, so
//! no `CONNECTION_CLOSE` leaves the socket, exactly like `SIGKILL`. A
//! second listener then takes the same UDP port. Whether the client's next
//! packet is answered with a stateless reset the client accepts depends on
//! one thing only: the second listener derived its tokens from the same
//! HMAC key.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use qsh_transport::{
    CertificateDer, Dialer, Fingerprint, Listener, LocalIdentity, Principal, RESET_KEY_LEN,
    StaticTrust,
};

fn make_identity() -> (LocalIdentity, Fingerprint) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let fp = Fingerprint::of_cert_der(&der).unwrap();
    (
        LocalIdentity {
            cert_chain: vec![der],
            key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
        },
        fp,
    )
}

/// A server on its own runtime and thread. `crash()` drops the runtime.
struct Server {
    addr: SocketAddr,
    crash: mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl Server {
    fn start(
        bind: SocketAddr,
        identity: LocalIdentity,
        trust: StaticTrust,
        key: [u8; RESET_KEY_LEN],
    ) -> Self {
        let (addr_tx, addr_rx) = mpsc::channel();
        let (crash, crash_rx) = mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let listener = {
                let _guard = rt.enter();
                Listener::bind_with_reset_key(
                    bind,
                    identity,
                    Arc::new(trust),
                    &key,
                    qsh_transport::TransportTuning::default(),
                )
                .unwrap()
            };
            addr_tx.send(listener.local_addr().unwrap()).unwrap();
            rt.spawn(async move {
                let mut held = Vec::new();
                while let Some(incoming) = listener.accept().await {
                    if let Ok(conn) = incoming.accept().await {
                        held.push(conn);
                    }
                }
            });
            let _ = crash_rx.recv();
            drop(rt);
        });
        let addr = addr_rx.recv().unwrap();
        Self {
            addr,
            crash,
            thread,
        }
    }

    fn crash(self) -> SocketAddr {
        self.crash.send(()).unwrap();
        self.thread.join().unwrap();
        self.addr
    }
}

/// Connect a client to a server, crash the server, start a replacement on
/// the same port with `second_key`, make the client send, and report
/// whether the client's connection died within `window`.
async fn client_sees_reset_after_restart(
    first_key: [u8; RESET_KEY_LEN],
    second_key: [u8; RESET_KEY_LEN],
    window: Duration,
) -> Option<qsh_transport::ConnectionError> {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let server_trust = || StaticTrust::empty().with_pin(client_fp, Principal::Device("c".into()));
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("s".into()));

    let first = Server::start(
        "127.0.0.1:0".parse().unwrap(),
        server_id.clone(),
        server_trust(),
        first_key,
    );
    let dialer = Dialer::new(client_id, Arc::new(client_trust));
    let dialed = dialer
        .dial(first.addr, "127.0.0.1")
        .await
        .expect("dial the first server");

    let addr = first.crash();
    let second = Server::start(addr, server_id, server_trust(), second_key);

    // The first packet after the restart: the client writes on a new stream.
    let (mut send, _recv) = dialed.connection.quinn().open_bi().await.expect("open_bi");
    let _ = send.write_all(b"ping").await;

    let outcome = tokio::time::timeout(window, dialed.connection.closed())
        .await
        .ok();
    second.crash();
    outcome
}

#[tokio::test]
async fn server_endpoint_uses_the_injected_reset_key() {
    let key = [0x42u8; RESET_KEY_LEN];
    let err = client_sees_reset_after_restart(key, key, Duration::from_secs(2))
        .await
        .expect("a restarted server holding the same key resets the client within 2 s");
    assert!(
        matches!(err, qsh_transport::ConnectionError::Reset),
        "expected a stateless reset, got {err:?}"
    );
}

#[tokio::test]
async fn a_different_reset_key_leaves_the_client_waiting() {
    let outcome = client_sees_reset_after_restart(
        [0x42u8; RESET_KEY_LEN],
        [0x43u8; RESET_KEY_LEN],
        Duration::from_millis(1500),
    )
    .await;
    assert!(
        outcome.is_none(),
        "a reset derived from another key must not be accepted, got {outcome:?}"
    );
}
