use super::*;

/// Half-close, the property the whole module exists for: EOF on one
/// direction shuts down only that direction's writer, and the opposite
/// direction keeps carrying bytes afterwards. Written against
/// [`tokio::io::duplex`] pipes so it tests `pump`'s own logic with no
/// QUIC connection in the way.
#[tokio::test]
async fn pump_half_closes_only_its_own_direction_at_eof() {
    let (mut source, source_peer) = tokio::io::duplex(64);
    let (mut sink, mut sink_peer) = tokio::io::duplex(64);

    // The source ends after "early"; the pump must copy it and then
    // shut its writer down.
    let mut source_peer = source_peer;
    tokio::spawn(async move {
        source_peer.write_all(b"early").await.unwrap();
        source_peer.shutdown().await.unwrap();
    });

    let copied = pump(&mut source, &mut sink, &[]).await.unwrap();
    assert_eq!(copied, 5);

    let mut got = Vec::new();
    sink_peer.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"early", "sink saw the bytes then a clean EOF");
}

/// The handshake residue leads the stream: bytes handed to `pump` as a
/// prefix are written before anything read from the source, and are
/// counted. This is the transition
/// [`qsh_transport::FramedRecv::into_raw`] exists to make safe — a
/// splice that dropped or appended the residue would silently truncate
/// or reorder every tunnel whose peer pipelined its first payload
/// bytes behind the handshake frame.
#[tokio::test]
async fn pump_writes_handshake_residue_before_anything_it_reads() {
    let (mut source, mut source_peer) = tokio::io::duplex(64);
    let (mut sink, mut sink_peer) = tokio::io::duplex(64);

    tokio::spawn(async move {
        source_peer.write_all(b"-then-the-stream").await.unwrap();
        source_peer.shutdown().await.unwrap();
    });

    let copied = pump(&mut source, &mut sink, b"residue").await.unwrap();
    assert_eq!(copied, b"residue-then-the-stream".len() as u64);

    let mut got = Vec::new();
    sink_peer.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"residue-then-the-stream");
}

/// A pump whose writer dies reports the error rather than spinning or
/// swallowing it — the input to `splice_tcp_quic`'s reset-don't-close
/// teardown.
#[tokio::test]
async fn pump_reports_a_write_failure() {
    let (mut source, mut source_peer) = tokio::io::duplex(64);
    let (mut sink, sink_peer) = tokio::io::duplex(64);
    drop(sink_peer);

    tokio::spawn(async move {
        let _ = source_peer.write_all(b"into the void").await;
    });

    let err = pump(&mut source, &mut sink, &[]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
}

/// The regression this stage exists for: `task.abort()` on whatever
/// task owns a call to [`splice_tcp_quic`] — exactly what
/// `RemoteForwardClose`, a purged connection, and `LocalForwardHandle`
/// drop all do to the task that (transitively, via a `JoinSet`) is
/// running a live splice — must never let either peer see a clean
/// end. Real TCP and real QUIC on both sides, so the assertions are
/// about what actually crosses the wire, not about which internal
/// function got called.
#[tokio::test]
async fn aborting_the_owning_task_mid_transfer_resets_both_peers_not_a_clean_eof() {
    use tokio::net::{TcpListener, TcpStream};

    // A live TCP pair: one half feeds `splice_tcp_quic` as `local`,
    // the other stays here as an observer of what the peer sees.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect_task = tokio::spawn(TcpStream::connect(addr));
    let (accepted, _) = listener.accept().await.unwrap();
    let mut tcp_observer = connect_task.await.unwrap().unwrap();

    // A live QUIC bidi stream pair, same shape: one half feeds
    // `splice_tcp_quic`, the other is this test's observer. The
    // observer side writes first — proving the peer's `accept_bi`
    // resolves and, once the splice starts, that "hello" is what
    // actually proves real bytes crossed before the abort.
    let (conn_a, conn_b) = crate::tunnel::testutil::loopback_pair().await;
    let accept_fut = conn_b.accept_bi();
    let open_fut = async {
        let (mut send, recv) = conn_a.open_bi().await.unwrap();
        send.write_all(b"hello").await.unwrap();
        (send, recv)
    };
    let (accepted_pair, (quic_observer_send, mut quic_observer_recv)) =
        tokio::join!(accept_fut, open_fut);
    let (remote_send, remote_recv) = accepted_pair.unwrap();
    // Keep the sender alive until the end of the test — dropping it
    // early would itself end the QUIC stream and confound what the
    // final assertion is checking.
    let _quic_observer_send = quic_observer_send;

    let task = tokio::spawn(splice_tcp_quic(
        accepted,
        remote_send,
        remote_recv,
        Vec::new(),
        StallWatch::on(conn_b.quinn(), "test"),
    ));

    // Down direction: the "hello" queued above must actually arrive
    // at the TCP observer once the splice starts pumping — proof
    // this is a real mid-transfer abort, not "abort before anything
    // ever ran".
    let mut down = [0u8; 5];
    tcp_observer.read_exact(&mut down).await.unwrap();
    assert_eq!(&down, b"hello");

    // Up direction, same proof the other way.
    tcp_observer.write_all(b"world").await.unwrap();
    let mut up = [0u8; 5];
    match quic_observer_recv.read(&mut up).await.unwrap() {
        Some(5) => assert_eq!(&up, b"world"),
        other => panic!("expected the up-direction payload, got {other:?}"),
    }

    // Now abort the task out from under the splice, exactly as
    // `RemoteForwardClose`/`purge_connection`/`LocalForwardHandle`'s
    // `Drop` do to their owning task.
    task.abort();
    let joined = task.await;
    assert!(
        joined.unwrap_err().is_cancelled(),
        "the task must actually have been aborted, not merely finished"
    );

    // The TCP peer must see an abort, never `Ok(0)` — a clean EOF it
    // cannot tell apart from "nothing more, but fine".
    let mut buf = [0u8; 8];
    match tcp_observer.read(&mut buf).await {
        Ok(0) => {
            panic!("TCP side saw a clean EOF from an aborted splice — truncation looks orderly")
        }
        Ok(n) => panic!("unexpected data after abort: {:?}", &buf[..n]),
        Err(_) => {} // reset — the correct outcome; exact kind is platform-dependent
    }

    // The QUIC peer must see the stream reset, never a clean finish
    // (`Ok(None)`).
    match quic_observer_recv.read(&mut buf).await {
        Ok(None) => {
            panic!("QUIC side saw a clean finish from an aborted splice — truncation looks orderly")
        }
        Ok(Some(n)) => panic!("unexpected data after abort: {:?}", &buf[..n]),
        Err(_) => {} // reset — the correct outcome
    }
}

// ---- ADR-0037: the stall ledger seen from real TCP and QUIC ----

mod stalled {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use tokio::net::{TcpSocket, TcpStream};
    use tokio::task::JoinHandle;

    use super::super::*;
    use crate::tunnel::stall::{RESET_CODE_TUNNEL_STALLED, StallLedger, StallParams};

    /// Short knobs so these tests wait fractions of a second, not
    /// `STALL_AGE`s. `max_stalled` is set per test.
    fn fast(max_stalled: usize) -> StallParams {
        StallParams {
            stall_age: Duration::from_millis(300),
            max_stalled,
            data_blocked_memory: Duration::from_millis(600),
            evaluate_interval: Duration::from_millis(25),
        }
    }

    /// Hang guard on observable conditions; never a pacing interval.
    const GUARD: Duration = Duration::from_secs(20);

    const CHUNK: [u8; 16 * 1024] = [0x5a; 16 * 1024];

    /// One spliced tunnel stream: the local application's socket, the
    /// splice task, and the peer's flood task (which ends with the error
    /// its writes finally hit).
    struct Leg {
        id: u64,
        app: TcpStream,
        splice: JoinHandle<Result<SpliceStats, SpliceError>>,
        flood: JoinHandle<qsh_transport::WriteError>,
        peer_recv: qsh_transport::RecvStream,
    }

    async fn open_leg(
        peer: &qsh_transport::Connection,
        splicer: &qsh_transport::Connection,
        ledger: &Arc<StallLedger>,
        app_rcvbuf: Option<u32>,
    ) -> Leg {
        // A capped consumer also gets a capped send buffer on the splice's
        // side (accepted sockets inherit it from the listener), so the
        // kernel holds only a few KiB before the splice's local write
        // blocks for good. Left to autotune, a loopback send buffer can
        // take megabytes, and filling them is a long window in which the
        // stream is not stalled yet.
        let listen_socket = TcpSocket::new_v4().unwrap();
        if let Some(size) = app_rcvbuf {
            listen_socket.set_send_buffer_size(size).unwrap();
        }
        listen_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = listen_socket.listen(1).unwrap();
        let addr = listener.local_addr().unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        if let Some(size) = app_rcvbuf {
            socket.set_recv_buffer_size(size).unwrap();
        }
        let (app, accepted) = tokio::join!(socket.connect(addr), listener.accept());
        let (app, (accepted, _)) = (app.unwrap(), accepted.unwrap());

        let (accepted_pair, (mut peer_send, peer_recv)) =
            tokio::join!(splicer.accept_bi(), async {
                let (mut send, recv) = peer.open_bi().await.unwrap();
                send.write_all(&CHUNK).await.unwrap();
                (send, recv)
            });
        let (remote_send, remote_recv) = accepted_pair.unwrap();

        let watch = ledger.watch(addr.to_string());
        let id = watch.id();
        let splice = tokio::spawn(splice_tcp_quic(
            accepted,
            remote_send,
            remote_recv,
            Vec::new(),
            watch,
        ));
        let flood = tokio::spawn(async move {
            loop {
                if let Err(err) = peer_send.write_all(&CHUNK).await {
                    return err;
                }
            }
        });
        Leg {
            id,
            app,
            splice,
            flood,
            peer_recv,
        }
    }

    async fn until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + GUARD;
        while !cond() {
            assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn stopped(leg: &mut Leg) -> Result<SpliceStats, SpliceError> {
        tokio::time::timeout(GUARD, &mut leg.splice)
            .await
            .expect("the splice ended")
            .expect("the splice task did not panic")
    }

    /// Decision 6: the stopped stream's local application sees an RST,
    /// never a clean end, and the peer sees both halves reset and stopped
    /// with `RESET_CODE_TUNNEL_STALLED`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stopped_stalled_stream_reaches_the_local_app_as_a_reset_not_a_clean_end() {
        let (peer, splicer) = crate::tunnel::testutil::loopback_pair().await;
        // A limit of zero: the first stall is already one too many.
        let ledger = StallLedger::start(splicer.quinn().clone(), fast(0));
        let mut leg = open_leg(&peer, &splicer, &ledger, Some(4 * 1024)).await;

        assert!(matches!(stopped(&mut leg).await, Err(SpliceError::Stalled)));

        let code = qsh_transport::StreamCode::from_u32(RESET_CODE_TUNNEL_STALLED);
        let flood_err = tokio::time::timeout(GUARD, &mut leg.flood)
            .await
            .expect("the peer's writes ended")
            .unwrap();
        assert_eq!(flood_err, qsh_transport::WriteError::Stopped(code));
        let mut buf = [0u8; 64];
        match tokio::time::timeout(GUARD, leg.peer_recv.read(&mut buf))
            .await
            .expect("the peer's read ended")
        {
            Err(qsh_transport::ReadError::Reset(got)) => assert_eq!(got, code),
            other => panic!("peer expected a reset with {code}, got {other:?}"),
        }

        // The application drains whatever the kernel still holds and then
        // must hit an error, never `Ok(0)`.
        let mut buf = vec![0u8; 64 * 1024];
        let outcome = tokio::time::timeout(GUARD, async {
            loop {
                match leg.app.read(&mut buf).await {
                    Ok(0) => return Ok(()),
                    Ok(_) => continue,
                    Err(err) => return Err(err),
                }
            }
        })
        .await
        .expect("the application's reads ended");
        assert!(
            outcome.is_err(),
            "a stopped stall reached the local application as a clean EOF"
        );
        assert_eq!(ledger.len(), 0, "the stopped splice left the ledger");
    }

    /// Decision 3 and the ADR's second unit property: with two stalled
    /// streams against a limit of one, only the older is stopped; the
    /// younger stalled stream, a reading tunnel stream and a non-tunnel
    /// stream on the same connection (the PTY's stand-in) carry on.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_stream_stop_leaves_other_tunnel_streams_and_the_pty_untouched() {
        let (peer, splicer) = crate::tunnel::testutil::loopback_pair().await;
        let ledger = StallLedger::start(splicer.quinn().clone(), fast(1));

        // The PTY stand-in: a plain bidi stream, never in any ledger.
        let (pty_accepted, (mut pty_send, _pty_peer_recv)) =
            tokio::join!(splicer.accept_bi(), async {
                let (mut send, recv) = peer.open_bi().await.unwrap();
                send.write_all(b"hello").await.unwrap();
                (send, recv)
            });
        let (_pty_splicer_send, mut pty_recv) = pty_accepted.unwrap();
        let mut hello = [0u8; 5];
        pty_recv.read_exact(&mut hello).await.unwrap();

        // "Older" means the older stall, which is what the ledger orders
        // by: the time the stream's current local write began. Being inside
        // a write is not enough to open the younger stream on, because a
        // stream still filling its kernel buffers is inside one write after
        // another; if the younger stream's last write began first, the
        // ledger rightly stops the younger one and this test waits on the
        // wrong splice. So wait until each stream has sat in one write for
        // a whole stall age, the ledger's own definition of stalled. With
        // the consumer never reading and both buffers capped, that write
        // never returns.
        let stall_age = fast(1).stall_age;
        let mut older = open_leg(&peer, &splicer, &ledger, Some(4 * 1024)).await;
        until("the older stream is stalled", || {
            ledger
                .writing_since(older.id)
                .is_some_and(|since| since.elapsed() >= stall_age)
        })
        .await;
        let younger = open_leg(&peer, &splicer, &ledger, Some(4 * 1024)).await;
        until("the younger stream is stalled", || {
            ledger
                .writing_since(younger.id)
                .is_some_and(|since| since.elapsed() >= stall_age)
        })
        .await;

        // A third tunnel stream whose application reads everything.
        let reading = open_leg(&peer, &splicer, &ledger, None).await;
        let read_bytes = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&read_bytes);
        let mut reading_app = reading.app;
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = reading_app.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
        });

        assert!(matches!(
            stopped(&mut older).await,
            Err(SpliceError::Stalled)
        ));

        // Everything else is still going, for several more stall ages.
        let after = read_bytes.load(Ordering::Relaxed);
        until("the reading tunnel stream keeps moving bytes", || {
            read_bytes.load(Ordering::Relaxed) >= after + 4 * 1024 * 1024
        })
        .await;
        for round in 0u32..50 {
            pty_send.write_all(&round.to_be_bytes()).await.unwrap();
            let mut got = [0u8; 4];
            tokio::time::timeout(GUARD, pty_recv.read_exact(&mut got))
                .await
                .expect("the PTY stand-in kept flowing")
                .unwrap();
            assert_eq!(got, round.to_be_bytes());
        }
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(
            !younger.splice.is_finished(),
            "the younger stall is within the limit and must be left alone"
        );
        assert!(!reading.splice.is_finished());
        assert!(ledger.writing_since(younger.id).is_some());

        younger.splice.abort();
        younger.flood.abort();
        reading.splice.abort();
        reading.flood.abort();
        reader.abort();
    }

    /// The ADR's fourth unit property: a consumer that reads slower than
    /// the sender but keeps reading makes write progress, so at the
    /// production `STALL_AGE` it is never stalled, even against a limit of
    /// zero. Progress is what the kernel reports: a blocked local write
    /// returns only once the socket's autotuned send buffer has drained by
    /// about half, so the reader here is slow next to the flood (which runs
    /// at loopback speed) but not so slow that half a buffer takes a whole
    /// `STALL_AGE` to drain. On Linux under full CPU load, a reader pacing
    /// 64 KiB per 10 ms (about 5 MB/s) was counted stalled once in fifteen
    /// rounds; that floor is a residual in `docs/design/threat-model.md` C14.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_but_reading_consumer_is_never_counted_as_stalled() {
        let (peer, splicer) = crate::tunnel::testutil::loopback_pair().await;
        let params = StallParams {
            stall_age: crate::tunnel::stall::STALL_AGE,
            ..fast(0)
        };
        let ledger = StallLedger::start(splicer.quinn().clone(), params);
        let leg = open_leg(&peer, &splicer, &ledger, None).await;

        // 64 KiB every 2 ms, a few tens of MB/s at most: under
        // backpressure the whole time, never stopped.
        let mut app = leg.app;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        let started = tokio::time::Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            let n = tokio::time::timeout(GUARD, app.read(&mut buf))
                .await
                .expect("the slow reader kept receiving")
                .unwrap_or_else(|e| {
                    panic!(
                        "the slow reader's socket was reset after {total} bytes in {:?}: {e}",
                        started.elapsed()
                    )
                });
            assert_ne!(n, 0, "the slow reader saw its stream end");
            total += n as u64;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(total > 0);
        eprintln!("slow reader: {total} bytes in {:?}", started.elapsed());
        assert!(
            !leg.splice.is_finished(),
            "a reading consumer was stopped as stalled"
        );
        leg.splice.abort();
        leg.flood.abort();
    }
}
