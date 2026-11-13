//! The iroh route on a network where only the relay is reachable (ADR-0061,
//! M28 acceptance items 4 and 5): exec, an interactive session and its resume
//! after a break, a `-L` tunnel and `qsh cp` up and down all run through the
//! relay, and nothing else carries them.
//!
//! "Only the relay is reachable" is made literal. The host's iroh endpoint is
//! bound to IPv4 loopback and the client's to IPv6 loopback
//! (`Ops::with_iroh_client_bind`), so the two have no address family in
//! common and iroh cannot hole-punch a direct path however long it tries. The
//! tests do not rely on that alone: every host-side audit record of an
//! allowed request must say `peer_path = "relay"` with the in-process relay's
//! URL, and so must the live connection the host accepted. A direct path that
//! slipped in would fail those checks.
//!
//! The relay is the in-process test relay on `127.0.0.1` with a self-signed
//! certificate only the client under test is told to trust. Nothing here
//! reaches a public relay, binds UDP 4433, 4434 or 443, or reads
//! `~/.config/qsh`.

#![cfg(unix)]

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use qsh_core::{AttachHandle, CancelToken, Ops, SilentObserver};
use qsh_proto::event::SessionEvent;
use qsh_proto::{
    FileCopyReq, SessionAttachReq, SessionCloseReq, SessionOpenReq, TrustSetIrohReq, TunnelOpenReq,
};
use qsh_testkit::net_probe::free_port;
use qsh_testkit::tunnel::EchoServer;
use qsh_transport::test_relay::TestRelay;
use qsh_transport::{Connection, IrohEndpoint, PeerAddr, PeerPath, Principal, StaticTrust};
use tokio::sync::mpsc;

use super::jump_chain::{
    Net, blocking, blocking_named, echo_argv, echo_through, every_feature_with, exec,
    loopback_options, stdout_of,
};

const TIMEOUT: Duration = Duration::from_secs(40);

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A host `far` reachable only through the relay, and the client `Ops` that
/// dials it: an address-less pin with the iroh route on, a client endpoint
/// bound to IPv6 loopback, a host endpoint bound to IPv4 loopback.
struct RelayOnly {
    net: Net,
    relay: TestRelay,
    ops: Ops,
    /// Every connection the host's iroh endpoint accepted, so a test can
    /// break them and check which path they ran on.
    accepted: Arc<Mutex<Vec<Connection>>>,
    _endpoint: IrohEndpoint,
}

impl RelayOnly {
    async fn start() -> Self {
        let net = Net::start_unpinned(&["far"], |_| "*", loopback_options()).await;
        let relay = TestRelay::spawn().await;
        let host = net.host("far");
        let endpoint = IrohEndpoint::bind(
            &host.h.server_identity.local,
            Arc::new(StaticTrust::empty().with_pin(net.fp, Principal::Device("laptop".into()))),
            relay.config(),
        )
        .await
        .expect("bind the host's iroh endpoint");
        assert_eq!(
            endpoint.bound_sockets().len(),
            1,
            "the host listens on IPv4 loopback alone: {:?}",
            endpoint.bound_sockets()
        );
        tokio::time::timeout(Duration::from_secs(10), endpoint.online())
            .await
            .expect("the host reaches the test relay");

        let accepted = Arc::new(Mutex::new(Vec::new()));
        let (accepting, server, keep) = (
            endpoint.clone(),
            host.h.server.clone(),
            Arc::clone(&accepted),
        );
        tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                let (server, keep) = (server.clone(), Arc::clone(&keep));
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.accept().await {
                        keep.lock().unwrap().push(conn.clone());
                        server.serve_connection(conn).await;
                    }
                });
            }
        });

        let ops = net
            .ops
            .clone()
            .with_iroh_relay_roots(vec![relay.cert.clone()])
            .with_iroh_client_bind(vec![SocketAddr::from((Ipv6Addr::LOCALHOST, 0))]);
        let fingerprint = host.h.server_identity.fingerprint;
        net.pin("far", None, fingerprint).await;
        let key = hex(&endpoint.public_key());
        let (pin_ops, url) = (ops.clone(), relay.url.clone());
        blocking(move || {
            pin_ops.trust_set_iroh(TrustSetIrohReq {
                name: "far".into(),
                relay: Some(url),
                key: Some(key),
                off: false,
            })
        })
        .await
        .expect("trust.set_iroh");
        Self {
            net,
            relay,
            ops,
            accepted,
            _endpoint: endpoint,
        }
    }

    fn pipes(&self) -> &qsh_core::broker::PipeFactory {
        &self.net.host("far").h.pipes
    }

    /// Close every connection the host has accepted so far, as a path that
    /// died under them would. Returns how many were still open.
    fn break_connections(&self) -> usize {
        let taken = std::mem::take(&mut *self.accepted.lock().unwrap());
        let open = taken
            .iter()
            .filter(|conn| conn.close_reason().is_none())
            .count();
        for conn in &taken {
            conn.close(0, b"test: the path broke");
        }
        open
    }

    /// The host's own record of how the client reached it: at least
    /// `at_least` allowed requests, every one of them over the relay, and
    /// every connection it accepted on the relay path too. Returns the number
    /// of allowed requests.
    fn assert_only_the_relay_carried_it(&self, at_least: usize) -> usize {
        let records = self.net.host("far").h.audit.records();
        let allowed: Vec<_> = records.iter().filter(|r| r.decision == "allow").collect();
        assert!(
            allowed.len() >= at_least,
            "expected at least {at_least} allowed requests, saw {}: {allowed:?}",
            allowed.len()
        );
        for record in &allowed {
            assert_eq!(
                record.peer_path.as_deref(),
                Some("relay"),
                "a request did not arrive over the relay: {record:?}"
            );
            assert_eq!(
                record.relay.as_deref(),
                Some(self.relay.url.as_str()),
                "the relay named in the audit record is not the test relay: {record:?}"
            );
        }
        let conns = self.accepted.lock().unwrap();
        for conn in conns.iter() {
            match conn.remote_address() {
                PeerAddr::Keyed {
                    path: PeerPath::Relay(url),
                    ..
                } => assert!(url.starts_with("https://127.0.0.1:"), "{url}"),
                other => panic!("an accepted connection is not on the relay path: {other:?}"),
            }
        }
        allowed.len()
    }

    async fn shutdown(self) {
        self.net.shutdown().await;
    }
}

/// An attach stream read on its own thread, so the test can drive the host's
/// side and break connections while the (blocking) client side waits.
struct Attached {
    handle: AttachHandle,
    events: mpsc::UnboundedReceiver<SessionEvent>,
}

impl Attached {
    async fn start(ops: &Ops, session_ref: &str) -> Self {
        let (ops, session_ref) = (ops.clone(), session_ref.to_string());
        let mut stream = blocking_named("session.attach", move || {
            ops.session_attach(
                SessionAttachReq {
                    session_ref,
                    no_steal: false,
                },
                &[],
            )
        })
        .await
        .expect("session.attach over the relay");
        let handle = stream.handle();
        let (tx, events) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            while let Some(event) = stream.next_event() {
                match event {
                    Ok(event) => {
                        if tx.send(event).is_err() {
                            break;
                        }
                    }
                    Err(err) => panic!("the attach stream failed: {err}"),
                }
            }
            stream.close();
        });
        Self { handle, events }
    }

    async fn write(&self, data: &[u8]) {
        let (handle, data) = (self.handle.clone(), data.to_vec());
        blocking(move || handle.write(data))
            .await
            .expect("session input");
    }
}

/// What an attach delivered: the output text and the cumulative offsets it
/// claimed, so a seam in the stream shows as a gap or a repeat.
#[derive(Default)]
struct Delivered {
    text: Vec<u8>,
    /// `(sequence_after, len)` of every output frame, in delivery order.
    frames: Vec<(u64, usize)>,
}

impl Delivered {
    /// Read events until `want` output bytes have arrived in all.
    async fn read_to(&mut self, attached: &mut Attached, want: usize) {
        tokio::time::timeout(TIMEOUT, async {
            while self.text.len() < want {
                match attached.events.recv().await.expect("the stream ended") {
                    SessionEvent::Output {
                        sequence, data_b64, ..
                    } => {
                        let data = base64::engine::general_purpose::STANDARD
                            .decode(data_b64.as_bytes())
                            .expect("session output is Base64");
                        self.frames.push((sequence, data.len()));
                        self.text.extend_from_slice(&data);
                    }
                    SessionEvent::Gap { .. } => panic!("a replay gap across the break"),
                    SessionEvent::Exit { .. } | SessionEvent::Closed { .. } => {
                        panic!(
                            "the session ended; saw {:?}",
                            String::from_utf8_lossy(&self.text)
                        )
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{want} bytes did not arrive; saw {:?}",
                String::from_utf8_lossy(&self.text)
            )
        });
    }

    /// Every frame starts where the one before it ended: nothing lost and
    /// nothing repeated across the seam.
    fn assert_tiles(&self) {
        let mut expected = self
            .frames
            .first()
            .map_or(0, |(sequence, len)| sequence - *len as u64);
        for (index, (sequence, len)) in self.frames.iter().enumerate() {
            let start = sequence - *len as u64;
            assert_eq!(start, expected, "frame {index} does not follow the last");
            expected = *sequence;
        }
    }
}

fn shell_open(host: &str) -> SessionOpenReq {
    SessionOpenReq {
        host: host.into(),
        argv: vec!["sh".into()],
        env: vec![],
        term: Some("xterm-256color".into()),
        cols: Some(80),
        rows: Some(24),
        user: None,
        shell_command: None,
    }
}

/// Exec, a PTY session, a `-L` tunnel and a copy, one after the other, over a
/// route with no direct path at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_session_tunnel_and_cp_all_run_over_the_relay_alone() {
    let rig = RelayOnly::start().await;
    every_feature_with(&rig.ops, "far", rig.pipes(), "relay").await;
    // exec, session.open, session.read, session.write, tunnel, file ops.
    rig.assert_only_the_relay_carried_it(5);
    rig.shutdown().await;
}

/// A session opened over the relay survives the loss of its connection: the
/// client re-dials through the relay, resumes with the credential, and the
/// output it holds before and after the break is the host's stream, byte for
/// byte, with the input typed into the dead connection applied once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_over_the_relay_resumes_after_a_break_with_identical_output() {
    let rig = RelayOnly::start().await;
    let opened = {
        let ops = rig.ops.clone();
        blocking_named("session.open", move || ops.session_open(shell_open("far")))
            .await
            .expect("session.open over the relay")
    };
    let mut pipe = rig.pipes().take().expect("the host's side of the session");
    let mut attached = Attached::start(&rig.ops, &opened.session_ref).await;

    let before: &[u8] = b"first half of the story\r\n";
    let after: &[u8] = b"second half, after the break\r\n";
    let mut seen = Delivered::default();

    pipe.write_output(before).await.expect("host output");
    seen.read_to(&mut attached, before.len()).await;
    assert_eq!(seen.text, before);

    attached.write(b"typed before the break\n").await;
    assert_eq!(
        pipe.read_input(64).await.expect("input"),
        b"typed before the break\n"
    );

    // The path dies. Nothing tells the client: it finds out from its own
    // connection, and re-dials the host through the relay.
    let broken = rig.break_connections();
    assert!(broken >= 1, "the attach connection was not open to break");
    pipe.write_output(after).await.expect("host output");
    attached.write(b"typed into the dead path\n").await;

    seen.read_to(&mut attached, before.len() + after.len())
        .await;
    let mut reference = before.to_vec();
    reference.extend_from_slice(after);
    assert_eq!(
        String::from_utf8_lossy(&seen.text),
        String::from_utf8_lossy(&reference),
        "the stitched output differs from the host's stream"
    );
    seen.assert_tiles();

    // The input written into the dead connection reaches the shell once.
    let typed = b"typed into the dead path\n";
    let mut got = Vec::new();
    tokio::time::timeout(TIMEOUT, async {
        while got.len() < typed.len() {
            got.extend(pipe.read_input(64).await.expect("input"));
        }
    })
    .await
    .expect("the input written during the break arrives");
    assert_eq!(got, typed, "the input was lost or applied twice");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), pipe.read_input(64))
            .await
            .is_err(),
        "more input arrived than was typed"
    );

    // The host saw two authorized attaches of one session the client never
    // re-opened: the first, and the resume on a new relay connection.
    let attaches = rig
        .net
        .host("far")
        .h
        .audit
        .records()
        .iter()
        .filter(|r| r.action == "session.attach" && r.decision == "allow")
        .count();
    assert_eq!(
        attaches, 2,
        "the host did not see the attach and its resume"
    );
    rig.assert_only_the_relay_carried_it(3);

    let ops = rig.ops.clone();
    let session_ref = opened.session_ref.clone();
    blocking(move || {
        ops.session_close(SessionCloseReq {
            session_ref,
            signal: None,
        })
    })
    .await
    .expect("session.close");
    rig.shutdown().await;
}

/// A `-L` listener whose every connection goes over the relay carries a
/// payload to the far side's echo server and the same bytes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_forward_over_the_relay_carries_bytes_both_ways() {
    let rig = RelayOnly::start().await;
    let echo = EchoServer::start().await.expect("echo server");
    let (echo_port, listen_port) = (echo.port(), free_port());
    // Distinct in each direction of the round trip, and larger than one
    // QUIC flow-control window's worth of small writes.
    let payload: Vec<u8> = (0..512 * 1024).map(|i| (i * 7 % 251) as u8).collect();
    let expected = payload.clone();
    let got = {
        let (ops, host) = (rig.ops.clone(), "far".to_string());
        blocking_named("-L over the relay", move || {
            let hold = ops
                .tunnel_open(TunnelOpenReq {
                    host,
                    mode: "local".into(),
                    bind: None,
                    listen_port: u32::from(listen_port),
                    forward_host: "127.0.0.1".into(),
                    forward_port: u32::from(echo_port),
                    wait_ms: None,
                    supervise_ms: None,
                    accept_hold_ms: None,
                })
                .expect("open the -L tunnel over the relay");
            // Two connections through the one tunnel, one after the other.
            let first = echo_through(listen_port, &payload).expect("first round trip");
            let second = echo_through(listen_port, b"short").expect("second round trip");
            hold.close();
            (first, second)
        })
        .await
    };
    assert_eq!(got.0.len(), expected.len(), "truncated or padded");
    assert!(got.0 == expected, "the echo came back different");
    assert_eq!(got.1, b"short");
    rig.assert_only_the_relay_carried_it(1);
    rig.shutdown().await;
}

/// `qsh cp` up and down over the relay: both copies finish and the bytes on
/// the far side of each are the bytes that were sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cp_up_and_down_over_the_relay_keeps_the_bytes() {
    let rig = RelayOnly::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("up-source.bin");
    let remote = dir.path().join("on-the-host.bin");
    let back = dir.path().join("down-copy.bin");
    let bytes: Vec<u8> = (0..700 * 1024).map(|i| (i * 11 % 253) as u8).collect();
    std::fs::write(&source, &bytes).expect("write the source");

    let copy = |req: FileCopyReq| {
        let ops = rig.ops.clone();
        async move {
            blocking_named("cp", move || {
                ops.file_copy(req, Arc::new(SilentObserver), &CancelToken::new())
            })
            .await
        }
    };
    let up = copy(FileCopyReq {
        sources: vec![source.to_string_lossy().into_owned()],
        destination: format!("[far]:{}", remote.display()),
        recursive: false,
        preserve: false,
        no_clobber: false,
    })
    .await
    .unwrap_or_else(|err| panic!("cp up over the relay: {err:?}"));
    assert_eq!(up.files, 1, "{up:?}");
    assert!(
        std::fs::read(&remote).expect("the uploaded file") == bytes,
        "the uploaded copy differs from the source"
    );

    let down = copy(FileCopyReq {
        sources: vec![format!("[far]:{}", remote.display())],
        destination: back.to_string_lossy().into_owned(),
        recursive: false,
        preserve: false,
        no_clobber: false,
    })
    .await
    .unwrap_or_else(|err| panic!("cp down over the relay: {err:?}"));
    assert_eq!(down.files, 1, "{down:?}");
    assert!(
        std::fs::read(&back).expect("the downloaded file") == bytes,
        "the downloaded copy differs from the original"
    );
    rig.assert_only_the_relay_carried_it(2);
    rig.shutdown().await;
}

/// A single command, for the cheapest proof that the rig itself is relay-only:
/// the host's endpoint has one IPv4 socket, the client's one IPv6 socket, and
/// the audit says relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_rig_has_no_direct_path_to_win() {
    let rig = RelayOnly::start().await;
    let out = exec(&rig.ops, "far", echo_argv("only-the-relay"))
        .await
        .expect("exec over the relay");
    assert_eq!(stdout_of(&out).trim(), "only-the-relay");
    assert_eq!(rig.assert_only_the_relay_carried_it(1), 1);
    // Give iroh time to try a direct path were one possible; the connection
    // is still on the relay afterwards.
    tokio::time::sleep(Duration::from_secs(2)).await;
    rig.assert_only_the_relay_carried_it(1);
    rig.shutdown().await;
}
