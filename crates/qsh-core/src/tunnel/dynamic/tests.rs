//! `crates/qsh-core/src/tunnel/dynamic.rs`'s own tests (moved to a sibling
//! file per the `crates/qsh-core/src/pty/` pattern, CLAUDE.md's own-file
//! rule). Each test is written to go red if the property it names is
//! removed — see each test's own doc for what mutation it catches.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_proto::wire::{ConnectResult, StreamHeader, StreamKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::*;
use crate::tunnel::testutil::loopback_pair;

// ---------------------------------------------------------------
// Test scaffolding: a fake peer that plays the host side of
// `docs/design/protocol.md` §7 over a real (loopback) QUIC connection.
// ---------------------------------------------------------------

/// What [`run_fake_host`] observed: every stream's `deny_host_local` flag,
/// in acceptance order, and — for each stream it answered `ok: true` —
/// every byte read off it before it closed.
#[derive(Default)]
struct FakeHostRecord {
    deny_host_local: Vec<bool>,
    received: Vec<Vec<u8>>,
}

/// A stand-in for the peer side of one forward-route QUIC connection:
/// accepts every tunnel stream opened on `conn`, records
/// `StreamHeader.deny_host_local`, answers each with `script(i)` (`i` the
/// 0-based stream index), and — only when the script says `ok: true` —
/// drains the raw pipe until it closes, recording what arrived (the vehicle
/// for `request_bytes_after_connect_are_forwarded_not_dropped`).
///
/// Mirrors `crate::tunnel::local::tests::fake_host`'s shape exactly, mainly
/// because [`open_tunnel`] is the same function `-L`'s tests already drive
/// this way — a "fake carrier" for `-D` is a fake *peer*, not a fake
/// [`ForwardCarrier`], since [`ForwardCarrier::Quic`] always wraps a real
/// (loopback, in tests) QUIC connection.
async fn run_fake_host(
    conn: qsh_transport::Connection,
    record: Arc<Mutex<FakeHostRecord>>,
    opened: Arc<AtomicUsize>,
    script: impl Fn(usize) -> ConnectResult + Send + Sync + 'static,
) {
    let script = Arc::new(script);
    let next_index = Arc::new(AtomicUsize::new(0));
    while let Ok((send, recv)) = conn.accept_bi().await {
        // One task per accepted stream, not a sequential loop body: a test
        // driving two live `CONNECT`s at once (e.g. one held open while a
        // second is still mid-handshake) would otherwise deadlock here —
        // this task would never call `accept_bi` again for the second
        // stream until the first one's drain loop below returns.
        let record = Arc::clone(&record);
        let opened = Arc::clone(&opened);
        let script = Arc::clone(&script);
        let index = next_index.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            opened.fetch_add(1, Ordering::SeqCst);
            let mut framed = qsh_transport::FramedStream::data(send, recv);
            let header: StreamHeader = framed.recv.recv().await.unwrap().expect("header frame");
            assert_eq!(header.stream_kind(), Some(StreamKind::TcpConnect));
            record
                .lock()
                .unwrap()
                .deny_host_local
                .push(header.deny_host_local);

            let result = script(index);
            let ok = result.ok;
            framed.send.send(&result).await.unwrap();
            if !ok {
                let _ = framed.send.finish();
                return;
            }

            let (send, recv) = framed.split();
            let mut raw_send = send.into_raw();
            let (mut raw_recv, residue) = recv.into_raw();
            let mut buf = residue;
            let mut tmp = [0u8; 4096];
            loop {
                // `quinn::RecvStream`'s own inherent `read` (`Option<usize>`,
                // `None` == FIN) shadows `AsyncReadExt::read` here — same
                // shadowing note as `crate::tunnel::local::tests::fake_host`.
                match raw_recv.read(&mut tmp).await {
                    Ok(None) | Err(_) => break,
                    Ok(Some(n)) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            record.lock().unwrap().received.push(buf);
            let _ = raw_send.finish();
        });
    }
}

fn ok_result() -> ConnectResult {
    ConnectResult {
        ok: true,
        code: String::new(),
        message: String::new(),
    }
}

fn err_result(code: &str) -> ConnectResult {
    ConnectResult {
        ok: false,
        code: code.to_string(),
        message: "synthetic test failure".to_string(),
    }
}

/// A `-D` listener with limits generous enough that none of the handshake-
/// slot/connection-cap/rate-limit gates can fire — for tests whose subject
/// is something else entirely.
async fn generous_forward() -> DynamicForward {
    DynamicForward::bind_for_test(None, 0, 1000, 1000, 10_000.0, 10_000.0)
        .await
        .unwrap()
}

// ---------------------------------------------------------------
// SOCKS5 client-side helpers (this side of the listener, playing the
// application `-D` proxies for).
// ---------------------------------------------------------------

/// Send a one-method (no-auth) greeting and assert it is accepted.
async fn greet_no_auth(tcp: &mut TcpStream) {
    tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method_select = [0u8; 2];
    tcp.read_exact(&mut method_select).await.unwrap();
    assert_eq!(method_select, [0x05, 0x00], "no-auth must be selected");
}

/// A `CONNECT` request naming a domain destination (ADR-0019's own ATYP
/// choice for a hostname, `qsh_proto::socks5::parse_request`'s own doc).
fn connect_request_bytes(host: &str, port: u16) -> Vec<u8> {
    let mut v = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    v.extend_from_slice(host.as_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v
}

async fn read_rep(tcp: &mut TcpStream) -> [u8; 10] {
    let mut rep = [0u8; 10];
    tcp.read_exact(&mut rep).await.unwrap();
    rep
}

// ---------------------------------------------------------------
// every_opened_stream_sets_deny_host_local
// ---------------------------------------------------------------

/// Every `-D` `CONNECT` opens its tunnel stream with `deny_host_local:
/// true`, unconditionally — ADR-0019 decision 9's whole reason to exist.
/// Removing the `deny_host_local: true` in [`DialPolicy`]'s construction (or
/// hardcoding `false`) turns this red.
#[tokio::test]
async fn every_opened_stream_sets_deny_host_local() {
    let forward = generous_forward().await;
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut tcp).await;
    tcp.write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = read_rep(&mut tcp).await;
    assert_eq!(rep[1], Rep::Succeeded.code());

    assert_eq!(opened.load(Ordering::SeqCst), 1);
    assert_eq!(record.lock().unwrap().deny_host_local, vec![true]);

    runner.abort();
    drop(tcp);
    drop(host_conn);
}

// ---------------------------------------------------------------
// failure_rep_is_delivered_before_close
// ---------------------------------------------------------------

/// A failed `CONNECT` still gets its `REP` byte, and the socket closes
/// *normally* (FIN), never with an RST that would race the `REP` off the
/// wire — ADR-0019 decision 8's "실패 REP 뒤에는 `shutdown(Write)` 후 보통
/// close". Using `abort_local`'s always-RST discipline here (as `-L` does)
/// would turn this red on some platforms/timings, since an RST can arrive
/// ahead of already-queued bytes.
#[tokio::test]
async fn failure_rep_is_delivered_before_close() {
    let forward = generous_forward().await;
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| err_result("CONNECTION_FAILED"),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut tcp).await;
    tcp.write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = read_rep(&mut tcp).await;
    assert_eq!(
        rep[1],
        Rep::ConnectionRefused.code(),
        "CONNECTION_FAILED must map to REP 0x05"
    );

    // The REP must have survived: a clean FIN (`Ok(0)`), never a reset.
    let mut trailing = [0u8; 1];
    match tcp.read(&mut trailing).await {
        Ok(0) => {}
        Ok(n) => panic!("unexpected trailing byte(s): {n}"),
        Err(err) => panic!("connection must close cleanly, not reset: {err}"),
    }

    runner.abort();
    drop(host_conn);
}

// ---------------------------------------------------------------
// request_bytes_after_connect_are_forwarded_not_dropped
// ---------------------------------------------------------------

/// Bytes the SOCKS client pipelines immediately behind its `CONNECT`
/// request (its own first payload segment, before it has even seen a
/// `REP`) must reach the peer — never be silently dropped. The driver's
/// exact-length reads (ADR-0019 decision 7) never pull this payload into a
/// driver buffer at all: it stays in the socket's own receive buffer for
/// `splice_opened` to read in its ordinary course once the tunnel is
/// spliced. A driver that over-read past the request (pulling the payload
/// into a buffer) and then dropped that tail instead of forwarding it would
/// turn this red.
#[tokio::test]
async fn request_bytes_after_connect_are_forwarded_not_dropped() {
    let forward = generous_forward().await;
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut tcp).await;

    // The request and the client's first payload segment arrive in one
    // write — the exact shape a pipelining SOCKS client (or just a fast
    // loopback stack coalescing two back-to-back writes) produces.
    let mut request_and_payload = connect_request_bytes("example.test", 80);
    request_and_payload.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
    tcp.write_all(&request_and_payload).await.unwrap();

    let rep = read_rep(&mut tcp).await;
    assert_eq!(rep[1], Rep::Succeeded.code());

    // Nothing more from this side — let the peer observe a clean end so
    // `run_fake_host` stops draining and records what it got.
    tcp.shutdown().await.unwrap();
    drop(tcp);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        record.lock().unwrap().received,
        vec![b"GET / HTTP/1.1\r\n\r\n".to_vec()],
        "the pipelined payload must reach the peer, byte for byte"
    );

    runner.abort();
    drop(host_conn);
}

// ---------------------------------------------------------------
// handshake_and_payload_pipelined_in_one_write_are_forwarded_correctly
// ---------------------------------------------------------------

/// A client that writes its greeting, `CONNECT` request, and first payload
/// segment all in a single `write_all` (a pipelining client, or just a fast
/// loopback stack coalescing three back-to-back writes into one segment)
/// still gets a correct method-select, a correct `REP`, and has its payload
/// reach the peer byte for byte — proving the driver's exact-length reads
/// (ADR-0019 decision 7) never pull request or payload bytes into the
/// greeting read, and never pull payload bytes into the request read.
/// Swallowing the request during the greeting read (e.g. discarding
/// anything read beyond the greeting's own exact length, or using a
/// leftover carry-forward buffer that was accidentally reset) would leave
/// `read_request` waiting on the socket until the handshake deadline, so
/// this test would then time out waiting for a `REP` that never arrives.
#[tokio::test]
async fn handshake_and_payload_pipelined_in_one_write_are_forwarded_correctly() {
    let forward = generous_forward().await;
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut tcp = TcpStream::connect(addr).await.unwrap();

    let mut one_write = vec![0x05, 0x01, 0x00]; // greeting: no-auth
    one_write.extend_from_slice(&connect_request_bytes("example.test", 80));
    one_write.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
    tcp.write_all(&one_write).await.unwrap();

    let mut method_select = [0u8; 2];
    tcp.read_exact(&mut method_select).await.unwrap();
    assert_eq!(method_select, [0x05, 0x00], "no-auth must be selected");

    let rep = tokio::time::timeout(Duration::from_secs(5), read_rep(&mut tcp))
        .await
        .expect("the REP must arrive promptly, not after the handshake deadline");
    assert_eq!(rep[1], Rep::Succeeded.code());

    tcp.shutdown().await.unwrap();
    drop(tcp);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        record.lock().unwrap().received,
        vec![b"GET / HTTP/1.1\r\n\r\n".to_vec()],
        "the pipelined payload must reach the peer, byte for byte"
    );

    runner.abort();
    drop(host_conn);
}

// ---------------------------------------------------------------
// rep_is_sent_only_after_connect_result
// ---------------------------------------------------------------

/// No `REP` is ever written before the peer's `ConnectResult` arrives —
/// writing a provisional/optimistic `REP` right after the request parses
/// (skipping the wait) turns this red.
#[tokio::test]
async fn rep_is_sent_only_after_connect_result() {
    let forward = generous_forward().await;
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    // A hand-rolled fake host that answers only once told to, so the test
    // can observe "no REP yet" before releasing it.
    let release = Arc::new(tokio::sync::Notify::new());
    let release_host = Arc::clone(&release);
    let host_task = tokio::spawn(async move {
        let (send, recv) = host_conn.accept_bi().await.unwrap();
        let mut framed = qsh_transport::FramedStream::data(send, recv);
        let _header: StreamHeader = framed.recv.recv().await.unwrap().expect("header");
        release_host.notified().await;
        framed.send.send(&ok_result()).await.unwrap();
        // A bare `drop` here would implicitly reset the stream, which can
        // race the just-written `ConnectResult` frame off the wire before
        // it is delivered — `finish` + `stopped` gives it a real chance to
        // arrive first (`qsh_transport::control::FramedSend::stopped`'s own
        // doc).
        framed.send.finish().unwrap();
        framed.send.stopped().await;
    });
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut tcp).await;
    tcp.write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();

    // No REP yet: a short read must time out, not return bytes.
    let mut probe = [0u8; 1];
    let premature = tokio::time::timeout(Duration::from_millis(150), tcp.read(&mut probe)).await;
    assert!(
        premature.is_err(),
        "a REP must not be sent before ConnectResult arrives"
    );

    release.notify_one();
    let rep = read_rep(&mut tcp).await;
    assert_eq!(rep[1], Rep::Succeeded.code());

    runner.abort();
    let _ = host_task.await;
}

// ---------------------------------------------------------------
// silent_client_is_dropped_at_handshake_deadline_with_no_stream /
// byte_at_a_time_greeting_still_hits_the_deadline
// ---------------------------------------------------------------

/// Non-blocking peek at whether `tcp` is still open: `true` if a `try_read`
/// says "no data yet, but still connected" ([`io::ErrorKind::WouldBlock`]),
/// `false` if it reports a clean EOF. Anything else panics — the two tests
/// below only ever expect one of these outcomes at each checkpoint.
///
/// Deliberately non-blocking (never `.await`s an I/O read): under
/// `start_paused`, an awaited read that finds nothing ready lets the
/// runtime's own "advance to the earliest pending timer" kick in, and with
/// a live `quinn` connection in the same runtime (its internal
/// retransmission/pacing timers are on the same paused clock) that can
/// overshoot well past the instant this test actually wants to inspect —
/// the same reason the rate-limit tests below run on real time instead.
/// `try_read` never waits, so it can only ever report the state the clock
/// is *actually* at once every already-fired timer has had a few scheduler
/// turns (the `yield_now` loop each call site does first) to run.
fn still_open(tcp: &TcpStream) -> bool {
    let mut probe = [0u8; 1];
    match tcp.try_read(&mut probe) {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => true,
        Ok(0) => false,
        other => panic!("unexpected try_read result: {other:?}"),
    }
}

async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// A client that never sends a byte is dropped once the absolute handshake
/// deadline passes, and no tunnel stream is ever opened for it. Removing
/// the deadline bound on the greeting read (waiting forever instead) turns
/// this red — the test would simply hang.
///
/// Checks *around* [`HANDSHAKE_DEADLINE`] with a 1 s margin on each side,
/// using only explicit `tokio::time::advance` (never a blocking read — see
/// [`still_open`]'s own doc for why): a deadline that is finite but wrong
/// (e.g. a stray `10×` multiplier, or a deadline computed in the wrong
/// unit) fails one of the two checks, where a bare "it closes eventually"
/// assertion would not.
#[tokio::test(start_paused = true)]
async fn silent_client_is_dropped_at_handshake_deadline_with_no_stream() {
    let forward = generous_forward().await;
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let tcp = TcpStream::connect(addr).await.unwrap();
    // Let the server actually accept and arm its deadline at ~t=0, before
    // any virtual time moves — otherwise the first `advance` below could
    // race ahead of `handle_connection` even being spawned yet, arming the
    // deadline late and making both checkpoints below meaningless.
    settle().await;

    tokio::time::advance(HANDSHAKE_DEADLINE - Duration::from_secs(1)).await;
    settle().await;
    assert!(
        still_open(&tcp),
        "the connection must still be open a second before the deadline"
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert!(
        !still_open(&tcp),
        "the connection must be closed a second past the deadline"
    );
    assert_eq!(opened.load(Ordering::SeqCst), 0);

    runner.abort();
    drop(host_conn);
}

/// The absolute handshake deadline is not extended by a client that keeps
/// the connection alive by trickling bytes in — it covers the greeting
/// *and* request together, from acceptance, however slowly they arrive
/// (ADR-0019 decision 9: "읽을 때마다 기한이 늘어나지 않는다").
///
/// The client sends `VER` right away, then — after a 2 s wait, comfortably
/// inside the deadline — sends `NMETHODS` and stops; the final `METHODS`
/// byte the greeting still needs never arrives. A deadline that is absolute
/// from acceptance closes the connection by `HANDSHAKE_DEADLINE` (checked
/// with a 1 s margin, same as the sibling test above). A deadline re-armed
/// from the most recently read byte (t≈2 s) would instead stay open past
/// that point, all the way to roughly `t=12s`, and fail the "must be
/// closed" checkpoint below — the property a bare `n == 0` check (as a
/// prior version of this test used) could not distinguish, since either
/// deadline eventually closes the connection.
#[tokio::test(start_paused = true)]
async fn byte_at_a_time_greeting_still_hits_the_deadline() {
    let forward = generous_forward().await;
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut tcp = TcpStream::connect(addr).await.unwrap();

    tcp.write_all(&[0x05]).await.unwrap();
    settle().await;

    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert!(
        still_open(&tcp),
        "a client that is still within the deadline, mid-greeting, must not be dropped early"
    );

    tcp.write_all(&[0x01]).await.unwrap();
    settle().await;

    // The final METHODS byte is never sent. Advance to just before, then
    // just past, the deadline measured from *acceptance* (t=0) — not from
    // the most recent byte (t≈2s, which a sliding deadline would instead
    // measure from).
    tokio::time::advance(HANDSHAKE_DEADLINE - Duration::from_secs(2) - Duration::from_secs(1))
        .await;
    settle().await;
    assert!(
        still_open(&tcp),
        "the connection must still be open a second before the absolute deadline"
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert!(
        !still_open(&tcp),
        "the connection must be closed a second past the absolute deadline — a deadline re-armed \
         from the most recently read byte (t≈2s) would still have it open here"
    );
    assert_eq!(opened.load(Ordering::SeqCst), 0);

    runner.abort();
    drop(host_conn);
}

// ---------------------------------------------------------------
// handshake_slots_are_bounded_and_excess_is_closed_immediately
// ---------------------------------------------------------------

/// Only [`HANDSHAKE_SLOTS`]-worth of connections may be mid-handshake at
/// once; one past the bound is closed immediately — no read, no write, no
/// stream — rather than queued. Removing the `try_acquire_owned` gate (or
/// falling back to an unbounded queue) turns this red, either by letting
/// the excess connection's read block past the test's own short timeout, or
/// by it eventually completing a handshake.
#[tokio::test]
async fn handshake_slots_are_bounded_and_excess_is_closed_immediately() {
    let forward = DynamicForward::bind_for_test(None, 0, 2, 1000, 10_000.0, 10_000.0)
        .await
        .unwrap();
    let addr = forward.local_addr();
    let limits = forward.limits_handle();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    // Two connections that never send a byte: each holds a handshake slot
    // for as long as this test needs it to.
    let _stalled_a = TcpStream::connect(addr).await.unwrap();
    let _stalled_b = TcpStream::connect(addr).await.unwrap();
    wait_for(
        || limits.handshake_slots.available_permits() == 0,
        Duration::from_secs(5),
    )
    .await;

    let mut third = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_millis(500), third.read(&mut buf))
        .await
        .expect("a connection past the handshake-slot bound must be closed immediately, not held")
        .unwrap();
    assert_eq!(
        n, 0,
        "no bytes are ever written to a slot-refused connection"
    );
    assert_eq!(opened.load(Ordering::SeqCst), 0);

    runner.abort();
    drop(host_conn);
}

/// Poll `done` until it is true or `budget` elapses (real time — this test
/// uses a real, unpaused runtime).
async fn wait_for(mut done: impl FnMut() -> bool, budget: Duration) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(start.elapsed() < budget, "condition never became true");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------
// connection_cap_answers_rep_01_and_opens_no_stream
// ---------------------------------------------------------------

/// Once [`MAX_ESTABLISHED_CONNECTIONS`] `CONNECT`s are live, the next one
/// gets `REP 0x01` and opens no tunnel stream at all — the cap is checked
/// *before* [`open_tunnel`], not after. Removing the
/// `reserve_connection_slot` gate turns this red: the second connection
/// would also open a stream and succeed.
#[tokio::test]
async fn connection_cap_answers_rep_01_and_opens_no_stream() {
    let forward = DynamicForward::bind_for_test(None, 0, 1000, 1, 10_000.0, 10_000.0)
        .await
        .unwrap();
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    // First CONNECT succeeds and is kept open, holding the one available
    // connection slot for the rest of the test.
    let mut first = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut first).await;
    first
        .write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = read_rep(&mut first).await;
    assert_eq!(rep[1], Rep::Succeeded.code());

    // Second CONNECT, while the cap is exhausted.
    let mut second = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut second).await;
    second
        .write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = read_rep(&mut second).await;
    assert_eq!(
        rep[1],
        Rep::GeneralFailure.code(),
        "over the established-connection cap must be REP 0x01"
    );
    assert_eq!(
        opened.load(Ordering::SeqCst),
        1,
        "the refused CONNECT must never open a tunnel stream"
    );

    runner.abort();
    drop(first);
    drop(host_conn);
}

// ---------------------------------------------------------------
// connect_over_rate_waits_for_a_token_within_the_handshake_deadline /
// connect_over_rate_past_the_deadline_gets_rep_01_and_opens_no_stream
// (ADR-0019 decision 9's amendment, replacing the plan's flat
// "reject over rate" test.)
// ---------------------------------------------------------------

/// An over-rate `CONNECT` does not get an immediate `REP 0x01` — it waits
/// for a token, and succeeds once one refills, as long as that happens
/// within its own connection's handshake deadline. An implementation that
/// refuses outright the moment the bucket is empty turns this red (the
/// second connection would get `REP 0x01` and no stream, never
/// `Succeeded`).
///
/// Runs on real (unpaused) time with a short, test-only handshake deadline
/// (rather than `tokio::time::pause`): quinn drives this connection's own
/// retransmission/idle timers through the very same Tokio time driver a
/// paused clock would freeze, so advancing virtual time out from under a
/// live QUIC connection is not safe to rely on here — a plain, fast,
/// millisecond-scale real wait is both simpler and correct.
#[tokio::test]
async fn connect_over_rate_waits_for_a_token_within_the_handshake_deadline() {
    // Burst of exactly one, refilling every ~40 ms — well inside the 500 ms
    // test-only handshake deadline.
    let forward = DynamicForward::bind_for_test_with_deadline(
        None,
        0,
        10,
        10,
        25.0,
        1.0,
        Duration::from_millis(500),
    )
    .await
    .unwrap();
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    // First CONNECT consumes the sole token immediately.
    let mut first = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut first).await;
    first
        .write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = read_rep(&mut first).await;
    assert_eq!(rep[1], Rep::Succeeded.code());

    // Second CONNECT arrives with the bucket empty — it must wait, then
    // still succeed once the bucket refills (~40 ms later, well under the
    // 500 ms deadline). The read below is bounded generously (well past the
    // refill wait but short of nextest's own per-test timeout), so a real
    // hang here fails this test with a clear message instead of the test
    // binary's own timeout.
    let mut second = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut second).await;
    second
        .write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = tokio::time::timeout(Duration::from_secs(5), read_rep(&mut second))
        .await
        .expect("an over-rate CONNECT must wait for, then get, a token within its deadline");
    assert_eq!(
        rep[1],
        Rep::Succeeded.code(),
        "an over-rate CONNECT must still succeed once a token refills within the deadline"
    );
    assert_eq!(opened.load(Ordering::SeqCst), 2);

    runner.abort();
    drop(first);
    drop(second);
    drop(host_conn);
}

/// An over-rate `CONNECT` whose token would not refill until *after* its
/// own handshake deadline gets `REP 0x01` and opens no tunnel stream —
/// ADR-0019 decision 9's amendment. A rate limiter with no deadline bound
/// (waiting forever for a token) turns this red as a hang; one that never
/// waits at all turns the *other* rate test above red instead — this test
/// specifically exercises "waited, then gave up".
///
/// Real (unpaused) time, same rationale as
/// [`connect_over_rate_waits_for_a_token_within_the_handshake_deadline`]'s
/// own doc.
#[tokio::test]
async fn connect_over_rate_past_the_deadline_gets_rep_01_and_opens_no_stream() {
    // Burst of one, refilling roughly every 10 real seconds — far past this
    // test's own 150 ms handshake deadline, so the wait is always bounded by
    // the deadline, not the refill.
    let forward = DynamicForward::bind_for_test_with_deadline(
        None,
        0,
        10,
        10,
        0.1,
        1.0,
        Duration::from_millis(150),
    )
    .await
    .unwrap();
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut first = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut first).await;
    first
        .write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = read_rep(&mut first).await;
    assert_eq!(rep[1], Rep::Succeeded.code());

    let mut second = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut second).await;
    second
        .write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = tokio::time::timeout(Duration::from_secs(5), read_rep(&mut second))
        .await
        .expect("a deadline-bounded wait must still end with a REP, not a hang");
    assert_eq!(
        rep[1],
        Rep::GeneralFailure.code(),
        "a token that would only refill past the handshake deadline must give REP 0x01"
    );
    assert_eq!(
        opened.load(Ordering::SeqCst),
        1,
        "the deadline-refused CONNECT must never open a tunnel stream"
    );

    runner.abort();
    drop(first);
    drop(second);
    drop(host_conn);
}

/// The rate-limit wait is bounded by *this connection's own remaining*
/// absolute handshake deadline, not a fresh window starting when the wait
/// begins (ADR-0019 decision 9's amendment).
///
/// Chosen so the two readings actually disagree: the refill (~1200 ms)
/// is *longer* than the deadline (800 ms), so even a connection that hit
/// the limiter the instant it was accepted would time out — but the second
/// connection here waits ~500 ms after its own greeting before sending its
/// request, so by the time it reaches the limiter only ~300 ms of its own
/// deadline is left, while the token (drained at essentially the same
/// moment as this connection's own deadline was armed) is still ~700 ms
/// from refilling. The correct, remaining-deadline-bounded wait times out
/// (300 ms left < ~700 ms to go) and answers `REP 0x01`. An implementation
/// that instead computes a *fresh* `now + limits.handshake_deadline`
/// (800 ms) at the point it starts waiting would see the ~700 ms refill
/// land comfortably inside that fresh window and answer `REP 0x00`
/// instead — turning this red.
///
/// Real (unpaused) time, same rationale as the sibling rate tests' own doc.
#[tokio::test]
async fn connect_over_rate_is_bounded_by_the_remaining_deadline_not_a_fresh_window() {
    // Deadline 800 ms; token refills in ~1200 ms (longer than the
    // deadline itself).
    let forward = DynamicForward::bind_for_test_with_deadline(
        None,
        0,
        10,
        10,
        1.0 / 1.2,
        1.0,
        Duration::from_millis(800),
    )
    .await
    .unwrap();
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    // First CONNECT drains the sole token immediately.
    let mut first = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut first).await;
    first
        .write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = read_rep(&mut first).await;
    assert_eq!(rep[1], Rep::Succeeded.code());

    // Second connection spends ~500 ms of its own 800 ms deadline between
    // greeting and request.
    let mut second = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut second).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    second
        .write_all(&connect_request_bytes("example.test", 80))
        .await
        .unwrap();
    let rep = tokio::time::timeout(Duration::from_secs(5), read_rep(&mut second))
        .await
        .expect("a deadline-bounded wait must still end with a REP, not a hang");
    assert_eq!(
        rep[1],
        Rep::GeneralFailure.code(),
        "the wait must be bounded by this connection's own remaining deadline, \
         not a fresh window starting when the wait began"
    );
    assert_eq!(
        opened.load(Ordering::SeqCst),
        1,
        "the deadline-refused CONNECT must never open a tunnel stream"
    );

    runner.abort();
    drop(first);
    drop(second);
    drop(host_conn);
}

// ---------------------------------------------------------------
// bind_and_udp_associate_get_rep_07_and_open_no_stream
// ---------------------------------------------------------------

/// `BIND` and `UDP ASSOCIATE` are unsupported commands (ADR-0019 decision
/// 7): both get `REP 0x07` and never open a tunnel stream.
#[tokio::test]
async fn bind_and_udp_associate_get_rep_07_and_open_no_stream() {
    for cmd in [0x02u8, 0x03u8] {
        let forward = generous_forward().await;
        let addr = forward.local_addr();
        let (client_conn, host_conn) = loopback_pair().await;

        let opened = Arc::new(AtomicUsize::new(0));
        let record = Arc::new(Mutex::new(FakeHostRecord::default()));
        tokio::spawn(run_fake_host(
            host_conn.clone(),
            Arc::clone(&record),
            Arc::clone(&opened),
            |_| ok_result(),
        ));
        let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        greet_no_auth(&mut tcp).await;
        let mut req = connect_request_bytes("example.test", 80);
        req[1] = cmd;
        tcp.write_all(&req).await.unwrap();
        let rep = read_rep(&mut tcp).await;
        assert_eq!(rep[1], Rep::CommandNotSupported.code(), "cmd {cmd:#04x}");
        assert_eq!(opened.load(Ordering::SeqCst), 0, "cmd {cmd:#04x}");

        runner.abort();
        drop(host_conn);
    }
}

// ---------------------------------------------------------------
// non_socks_first_byte_closes_with_zero_bytes_written_and_zero_streams
// ---------------------------------------------------------------

/// A connection that does not speak SOCKS5 at all (its first byte is not
/// `0x05`) is closed with nothing ever written back to it, and no tunnel
/// stream is opened — writing any reply here (even a generic error) would
/// itself be an information leak to something that never spoke SOCKS5
/// (`qsh_proto::socks5`'s own module doc).
#[tokio::test]
async fn non_socks_first_byte_closes_with_zero_bytes_written_and_zero_streams() {
    let forward = generous_forward().await;
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();

    let mut buf = [0u8; 16];
    let n = tcp.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "nothing is ever written back to a non-SOCKS5 client");
    assert_eq!(opened.load(Ordering::SeqCst), 0);

    runner.abort();
    drop(host_conn);
}

// ---------------------------------------------------------------
// non_loopback_bind_is_refused_before_listen
// ---------------------------------------------------------------

/// `-D`'s bind is loopback-only, refused before any listener is created —
/// the same property, and the same shape of test,
/// `crate::tunnel::local::tests::non_loopback_bind_is_refused_and_binds_nothing`
/// pins for `-L`. The refusal also names the actual flag (ADR-0019 decision
/// 9): a `-D` bind must never be told it is a `-L` listener. Passing `"-L"`
/// instead of `"-D"` to `loopback_bind_addr` at this call site would still
/// satisfy the error-code assertion alone, so the text is pinned too.
#[tokio::test]
async fn non_loopback_bind_is_refused_before_listen() {
    for bind in [
        "0.0.0.0",
        "::",
        "192.168.1.10",
        "8.8.8.8",
        "example.com",
        "*",
    ] {
        let err = match DynamicForward::bind(Some(bind), 0).await {
            Ok(_) => panic!("non-loopback bind must be refused: {bind}"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{bind}");
        let text = err.to_string();
        assert!(text.contains("-D"), "{bind}: {text}");
        assert!(!text.contains("-L"), "{bind}: {text}");
    }
}

// ---------------------------------------------------------------
// socks_loop_logs_no_destination_above_debug
// ---------------------------------------------------------------

mod capture {
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};

    #[derive(Default)]
    pub(super) struct Sink {
        pub(super) events: Mutex<Vec<(String, String, String)>>, // (level, target, rendered fields)
    }

    struct Rec(String);
    impl Visit for Rec {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{}={:?} ", field.name(), value));
        }
    }

    pub(super) struct Sub(pub(super) Arc<Sink>);
    impl tracing::Subscriber for Sub {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::Id, _: &tracing::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut rec = Rec(String::new());
            event.record(&mut rec);
            self.0.events.lock().unwrap().push((
                event.metadata().level().to_string(),
                event.metadata().target().to_string(),
                rec.0,
            ));
        }
        fn enter(&self, _: &tracing::Id) {}
        fn exit(&self, _: &tracing::Id) {}
    }
}

/// The `-D` accept/connection loop never logs a destination above debug
/// (ADR-0019 decision 12): the destination *is* logged, but only at debug,
/// and no event at `INFO`/`WARN`/`ERROR` mentions it. Moving the `CONNECT`
/// `tracing::debug!` up to `tracing::warn!` (or any higher level) turns
/// this red; deleting the log line entirely also turns it red (the "logged
/// somewhere at debug" half of the assertion fails).
#[tokio::test]
async fn socks_loop_logs_no_destination_above_debug() {
    let sink = Arc::new(capture::Sink::default());
    let sub = capture::Sub(Arc::clone(&sink));
    let _guard = tracing::subscriber::set_default(sub);

    const MARKER: &str = "destination-marker.example.test";

    let forward = generous_forward().await;
    let addr = forward.local_addr();
    let (client_conn, host_conn) = loopback_pair().await;

    let opened = Arc::new(AtomicUsize::new(0));
    let record = Arc::new(Mutex::new(FakeHostRecord::default()));
    tokio::spawn(run_fake_host(
        host_conn.clone(),
        Arc::clone(&record),
        Arc::clone(&opened),
        |_| ok_result(),
    ));
    let runner = tokio::spawn(forward.run(Arc::new(ForwardCarrier::Quic(client_conn))));

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    greet_no_auth(&mut tcp).await;
    tcp.write_all(&connect_request_bytes(MARKER, 80))
        .await
        .unwrap();
    let rep = read_rep(&mut tcp).await;
    assert_eq!(rep[1], Rep::Succeeded.code());

    runner.abort();
    drop(tcp);
    drop(host_conn);

    let events = sink.events.lock().unwrap();
    let dynamic_events: Vec<_> = events
        .iter()
        .filter(|(_, target, _)| {
            target.starts_with("qsh::tunnel::dynamic") || target == "qsh_core::tunnel::dynamic"
        })
        .collect();

    assert!(
        dynamic_events
            .iter()
            .any(|(level, _, fields)| level == "DEBUG" && fields.contains(MARKER)),
        "the destination must be logged at debug: {dynamic_events:?}"
    );
    assert!(
        dynamic_events.iter().all(|(level, _, fields)| !(matches!(
            level.as_str(),
            "ERROR" | "WARN" | "INFO"
        ) && fields.contains(MARKER))),
        "the destination must never appear above debug: {dynamic_events:?}"
    );
}
