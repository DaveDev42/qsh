//! `crates/qsh-core/src/tunnel/local.rs`'s own tests (moved to a sibling
//! file per the `crates/qsh-core/src/pty/` pattern, CLAUDE.md's own-file
//! rule, once `local.rs` itself passed ~800 lines).

use qsh_proto::wire::{ForwardDirection, parse_forward_spec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::tunnel::testutil::loopback_pair;

/// Build a `-L` spec directly rather than through
/// [`parse_forward_spec`], because the parser's grammar rejects listen
/// port 0 (`1..=65535`, settled in M4 Step 1) while
/// `docs/design/testing.md`'s CI rule requires tests to bind port 0.
/// [`LocalForward`] takes a [`ForwardSpec`], not a spec string, so a
/// test can express what the CLI grammar cannot.
fn local_spec(bind: Option<&str>, listen_port: u16, host: &str, host_port: u16) -> ForwardSpec {
    ForwardSpec {
        direction: ForwardDirection::Local,
        bind: bind.map(str::to_string),
        listen_port,
        host: host.to_string(),
        host_port,
    }
}

/// The port-0 loopback spec every splice test below binds.
fn ephemeral_spec() -> ForwardSpec {
    local_spec(None, 0, "db.internal", 5432)
}

/// The parser and this module agree on where a real `-L` string binds:
/// a parsed spec's `bind` flows into [`loopback_bind_addr`] unchanged.
#[test]
fn a_parsed_spec_binds_the_address_it_names() {
    let spec = parse_forward_spec("127.0.0.1:8080:db.internal:5432").unwrap();
    assert_eq!(spec.direction, ForwardDirection::Local);
    let addr = loopback_bind_addr(spec.bind.as_deref(), spec.listen_port, "-L").unwrap();
    assert_eq!(addr, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
}

// ---- bind policy (§4.1 #3) ------------------------------------------

#[test]
fn bind_defaults_to_ipv4_loopback_when_the_spec_has_no_bind() {
    let addr = loopback_bind_addr(None, 8080, "-L").unwrap();
    assert_eq!(addr, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
    assert!(addr.ip().is_loopback());
}

#[test]
fn bind_accepts_every_loopback_spelling() {
    for (bind, expected) in [
        ("localhost", "127.0.0.1:1:"),
        ("LocalHost", "127.0.0.1:1:"),
        ("127.0.0.1", "127.0.0.1:1:"),
        // Not `127.0.0.1`: loopback is the whole 127/8 block, which a
        // string comparison against "127.0.0.1" would get wrong.
        ("127.0.0.7", "127.0.0.7:1:"),
        ("::1", "[::1]:1:"),
    ] {
        let addr = loopback_bind_addr(Some(bind), 1, "-L").unwrap();
        assert!(addr.ip().is_loopback(), "{bind} must classify as loopback");
        assert_eq!(
            format!("{addr}:"),
            expected,
            "{bind} must bind the address it names"
        );
    }
}

/// The security property of §4.1 #3: a `-L` listener is never exposed
/// off this machine, and the refusal happens *before* any listener
/// exists (`bind` returns `Err` without touching the network).
#[tokio::test]
async fn non_loopback_bind_is_refused_and_binds_nothing() {
    for bind in [
        "0.0.0.0",
        "::",
        "192.168.1.10",
        "8.8.8.8",
        // A name, not an address — never resolved, since a resolver
        // answer would otherwise pick the interface.
        "example.com",
        "*",
    ] {
        let err =
            loopback_bind_addr(Some(bind), 0, "-L").expect_err("non-loopback bind must be refused");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{bind}");

        let refused = LocalForward::bind(&local_spec(Some(bind), 0, "example.test", 80))
            .await
            .expect_err("bind must refuse before listening");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument, "{bind}");
    }
}

/// `-L`'s refusal text is the original wording, byte for byte, predating
/// `-D`'s own flag/noun (ADR-0019 decision 9 amendment: `-D` gets its own
/// wording, but a `-L` caller's text does not change). `-D`'s text is
/// pinned separately, naming `-D` and never `-L`. Collapsing both callers
/// onto one shared noun (e.g. always `"{flag} bind ..."`) turns the first
/// two assertions red.
#[test]
fn loopback_bind_refusal_text_is_pinned_per_flag() {
    let not_loopback = loopback_bind_addr(Some("0.0.0.0"), 8080, "-L").unwrap_err();
    assert_eq!(
        not_loopback.to_string(),
        "local forward bind \"0.0.0.0\" is not a loopback address; \
         -L listeners are loopback-only"
    );

    let not_an_ip = loopback_bind_addr(Some("example.com"), 8080, "-L").unwrap_err();
    assert_eq!(
        not_an_ip.to_string(),
        "local forward bind \"example.com\" is not an IP address or \"localhost\"; \
         -L listeners are loopback-only"
    );

    let dynamic_not_loopback = loopback_bind_addr(Some("0.0.0.0"), 1080, "-D").unwrap_err();
    let text = dynamic_not_loopback.to_string();
    assert!(text.contains("-D"), "{text}");
    assert!(!text.contains("-L"), "{text}");
}

#[tokio::test]
async fn bind_reports_the_real_port_for_a_port_zero_spec() {
    let forward = LocalForward::bind(&ephemeral_spec()).await.unwrap();
    assert!(forward.local_addr().ip().is_loopback());
    assert_ne!(forward.local_addr().port(), 0, "port 0 must resolve");
    assert_eq!(forward.destination(), ("db.internal", 5432));
}

// ---- the `Tunnel` DTO (`docs/CLI.md` §6.9) ---------------------------

/// `actual_port` reports the port actually bound, **including** when
/// the spec named it — which is what §6.9's own `Tunnel` example
/// shows. Reporting it only for a `0` request would leave every
/// fixed-port reader re-splitting `bind` (a socket address, so the
/// harder split of the two) to learn the same number.
#[tokio::test]
async fn the_tunnel_dto_reports_the_bound_port_for_a_fixed_port_spec() {
    // A port the kernel just handed out and released: fixed from the
    // spec's point of view, never a literal (`docs/design/testing.md`'s
    // CI rule).
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let (client_conn, host_conn) = loopback_pair().await;
    let handle =
        LocalForwardHandle::start(&local_spec(None, port, "db.internal", 5432), client_conn)
            .await
            .unwrap();

    assert_eq!(
        handle.local_addr().port(),
        port,
        "the spec's fixed port was granted as asked"
    );
    let dto = handle.tunnel("box");
    assert_eq!(
        dto.actual_port,
        Some(u32::from(port)),
        "a fixed-port forward still reports the port it bound"
    );
    assert_eq!(dto.bind, format!("127.0.0.1:{port}"));
    assert_eq!(dto.forward_to, "db.internal:5432");
    assert_eq!(dto.mode, "local");
    assert_eq!(dto.host, "box");

    drop(handle);
    drop(host_conn);
}

/// `forward_to` is the canonical `host:port`, so an IPv6 destination
/// is bracketed — `parse_forward_spec` strips the brackets off
/// `[::1]`, and plain concatenation would emit the unsplittable
/// `::1:5432` (the same form the peer's `forward.local` ACL resource
/// takes).
#[tokio::test]
async fn the_tunnel_dto_brackets_an_ipv6_destination() {
    let (client_conn, host_conn) = loopback_pair().await;
    let handle = LocalForwardHandle::start(&local_spec(None, 0, "::1", 5432), client_conn)
        .await
        .unwrap();

    assert_eq!(handle.tunnel("box").forward_to, "[::1]:5432");

    drop(handle);
    drop(host_conn);
}

// ---- accept-error classification (Step 3: one bad accept must not
//      end the forward) --------------------------------------------

/// The `-L` contract's liveness half: only a dead *listener* ends a
/// forward. A connection that died on the way in is retried at once;
/// running out of descriptors or buffers is retried behind
/// [`ACCEPT_BACKOFF`] so a persistent `EMFILE` cannot spin the loop;
/// and everything else — the listener itself being unusable — is the
/// one thing that stops accepting.
#[test]
fn accept_errors_are_classified_so_one_bad_accept_never_ends_the_forward() {
    use io::ErrorKind;

    for kind in [ErrorKind::ConnectionAborted, ErrorKind::Interrupted] {
        assert_eq!(
            accept_disposition(&io::Error::from(kind)),
            AcceptDisposition::Retry,
            "{kind:?} is about one pending connection, not the listener"
        );
    }

    assert!(
        !ACCEPT_EXHAUSTION_ERRNOS.is_empty(),
        "this platform must name its exhaustion errnos, or the loop \
         treats a recoverable EMFILE as a dead listener"
    );
    for code in ACCEPT_EXHAUSTION_ERRNOS {
        assert_eq!(
            accept_disposition(&io::Error::from_raw_os_error(*code)),
            AcceptDisposition::Backoff,
            "errno {code} exhausts a resource; the listener survives it"
        );
    }
    assert_eq!(
        accept_disposition(&io::Error::from(ErrorKind::OutOfMemory)),
        AcceptDisposition::Backoff
    );

    // Linux passes a pending connection's own network error back out
    // of `accept()`; `accept(2)` says to treat those like `EAGAIN`.
    // Left unclassified they land in the `Fatal` catch-all below, so
    // one unreachable client would end the whole forward.
    for code in ACCEPT_PER_CONNECTION_ERRNOS {
        assert_eq!(
            accept_disposition(&io::Error::from_raw_os_error(*code)),
            AcceptDisposition::Backoff,
            "errno {code} describes the pending connection, not the listener"
        );
    }

    for kind in [
        ErrorKind::InvalidInput,
        ErrorKind::PermissionDenied,
        ErrorKind::NotConnected,
        ErrorKind::Other,
    ] {
        assert_eq!(
            accept_disposition(&io::Error::from(kind)),
            AcceptDisposition::Fatal,
            "{kind:?} says the listener is unusable"
        );
    }
}

/// The test above only exercises `err.raw_os_error() == None` (every
/// `io::Error::from(ErrorKind)` it builds carries no raw errno) —
/// leaving `accept_disposition`'s `_ => Fatal` catch-all for a *real*,
/// unlisted errno unpinned (M8 Step 3b, R10). `EBADF` is exactly the
/// errno the remote-forward accept loop's own fatal path produces (a
/// listener whose fd is no longer valid) and belongs to neither
/// `ACCEPT_EXHAUSTION_ERRNOS` nor `ACCEPT_PER_CONNECTION_ERRNOS` on any
/// platform this crate targets.
#[test]
fn an_unclassified_accept_errno_is_fatal() {
    assert_eq!(
        accept_disposition(&io::Error::from_raw_os_error(libc::EBADF)),
        AcceptDisposition::Fatal,
        "EBADF names a dead listener, not a retryable/backoff-able condition"
    );
}

// ---- the requester leg end to end ------------------------------------

/// Stand in for the host side of `docs/design/protocol.md` §7 over a
/// real QUIC connection: accept one tunnel stream, assert the header
/// is a ticket-less `TCP_CONNECT` for the expected destination, answer
/// `ConnectResult`, and — when allowed — echo raw bytes back with
/// `pipelined` prepended *in the same write as the `ConnectResult`*,
/// which is what forces the client's framed reader to buffer payload
/// past the handshake frame.
///
/// Takes a **clone** of the connection: `qsh_transport::Connection` is
/// a handle whose last drop closes the whole QUIC connection with
/// application code 0, which would tear down stream data still in
/// flight the moment this helper returned.
async fn fake_host(
    conn: qsh_transport::Connection,
    allow: bool,
    pipelined: &'static [u8],
) -> StreamHeader {
    let (send, recv) = conn.accept_bi().await.unwrap();
    let mut framed = qsh_transport::FramedStream::data(send, recv);
    let header: StreamHeader = framed.recv.recv().await.unwrap().expect("header");
    assert_eq!(header.stream_kind(), Some(StreamKind::TcpConnect));
    assert!(
        header.ticket.is_empty(),
        "§7: TCP_CONNECT carries no ticket"
    );

    if !allow {
        framed
            .send
            .send(&ConnectResult {
                ok: false,
                code: ErrorCode::PermissionDenied.as_str().to_string(),
                message: "denied".into(),
            })
            .await
            .unwrap();
        let _ = framed.send.finish();
        return header;
    }

    framed
        .send
        .send(&ConnectResult {
            ok: true,
            code: String::new(),
            message: String::new(),
        })
        .await
        .unwrap();
    let (send, recv) = framed.split();
    let mut raw_send = send.into_raw();
    let (mut raw_recv, residue) = recv.into_raw();
    assert!(
        residue.is_empty(),
        "client sends nothing before the verdict"
    );
    if !pipelined.is_empty() {
        raw_send.write_all(pipelined).await.unwrap();
    }
    // Echo until the client half-closes, then half-close back.
    let mut buf = [0u8; 256];
    loop {
        // `quinn::RecvStream` has its own inherent `read` returning
        // `Option<usize>` (`None` == FIN), which shadows
        // `AsyncReadExt::read` here.
        match raw_recv.read(&mut buf).await.unwrap() {
            None => break,
            Some(n) => raw_send.write_all(&buf[..n]).await.unwrap(),
        }
    }
    raw_send.finish().unwrap();
    header
}

/// The whole requester leg: a connection to the bound loopback port
/// becomes a `TCP_CONNECT` for the spec's destination, and after
/// `ConnectResult{ok:true}` the socket is a transparent byte pipe —
/// including the bytes the peer pipelined behind the handshake frame,
/// which arrive **first and exactly once** (the residue transition
/// `FramedRecv::into_raw` exists for; without it this test loses
/// `"ahead-"`).
#[tokio::test]
async fn allowed_connection_splices_raw_bytes_and_delivers_handshake_residue_first() {
    let (client_conn, host_conn) = loopback_pair().await;
    let host = tokio::spawn(fake_host(host_conn.clone(), true, b"ahead-"));

    let forward = LocalForward::bind(&ephemeral_spec()).await.unwrap();
    let addr = forward.local_addr();
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"ping").await.unwrap();
    tcp.shutdown().await.unwrap();
    let mut got = Vec::new();
    tcp.read_to_end(&mut got).await.unwrap();
    assert_eq!(
        got, b"ahead-ping",
        "residue must lead the stream, then the echoed payload"
    );

    let header = host.await.unwrap();
    assert_eq!(header.host, "db.internal");
    assert_eq!(header.port, 5432);
    runner.abort();
    drop(host_conn);
}

/// A refused connection (the peer's inline `forward.local` denial) must
/// not leak the accepted socket and must not take the forward down:
/// the local client sees the connection fail, and the *next*
/// connection is still served.
#[tokio::test]
async fn refused_connection_closes_the_local_socket_and_the_forward_keeps_serving() {
    let (client_conn, host_conn) = loopback_pair().await;
    let deny = tokio::spawn(fake_host(host_conn.clone(), false, b""));

    let forward = LocalForward::bind(&ephemeral_spec()).await.unwrap();
    let addr = forward.local_addr();
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    // The refusal's RST can arrive before `connect` itself returns —
    // `abort_local`'s `set_zero_linger` above means the requester leg
    // sends RST, not FIN, and a `connect()` that observes
    // `SO_ERROR = ECONNRESET` before the socket is writable surfaces
    // that as `Err` here instead of a connected socket that then
    // reads a reset (observed on macOS CI). Either shape is
    // "refused, no payload"; neither should stop the test short of
    // the "forward keeps serving" assertion below.
    match TcpStream::connect(addr).await {
        Ok(mut tcp) => {
            let mut got = Vec::new();
            // Either an RST (`ConnectionReset`) or a bare EOF is a
            // closed socket; what must never happen is data arriving
            // from a destination that was never dialed.
            match tcp.read_to_end(&mut got).await {
                Ok(_) => assert!(got.is_empty(), "a refused forward must carry no payload"),
                Err(err) => assert_eq!(err.kind(), io::ErrorKind::ConnectionReset),
            }
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) => {}
        Err(e) => panic!("connect to the local forward: {e}"),
    }
    deny.await.unwrap();

    // Same forward, second connection — now allowed, and it works.
    let allow = tokio::spawn(fake_host(host_conn.clone(), true, b""));
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"second").await.unwrap();
    tcp.shutdown().await.unwrap();
    let mut got = Vec::new();
    tcp.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"second", "one refusal must not end the forward");
    allow.await.unwrap();
    runner.abort();
    drop(host_conn);
}
