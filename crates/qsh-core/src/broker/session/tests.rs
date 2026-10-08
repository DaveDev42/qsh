use super::*;
use crate::broker::clock::TestClock;
use crate::broker::ring::ReplayEvent;

const A: ConnectionId = ConnectionId(1);
const B: ConnectionId = ConnectionId(2);

/// Fail instead of hanging when the actor is broken. Real time only
/// elapses on failure.
async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .expect("timed out: actor stalled")
}

fn spawn_with(source: PipeSource, clock: &TestClock, config: SessionConfig) -> SessionHandle {
    let (handle, actor) = SessionActor::create(
        "01TESTSESSION".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
        "device:test-opener".to_string(),
        Arc::new(clock.clone()),
        &SessionSpec::default(),
        Box::new(source),
        config,
    )
    .unwrap();
    tokio::spawn(actor.run());
    handle
}

fn spawn_session() -> (SessionHandle, PipeHandle, TestClock) {
    let clock = TestClock::new();
    let (source, pipe) = PipeSource::new(64 * 1024);
    let handle = spawn_with(source, &clock, SessionConfig::default());
    (handle, pipe, clock)
}

fn collect_output(out: &ReadOut) -> Vec<u8> {
    let mut v = Vec::new();
    for e in &out.events {
        if let ReplayEvent::Output { data, .. } = e {
            v.extend_from_slice(data);
        }
    }
    v
}

fn controls(out: &ReadOut) -> Vec<ControlEvent> {
    out.events
        .iter()
        .filter_map(|e| match e {
            ReplayEvent::Control { event, .. } => Some(event.clone()),
            _ => None,
        })
        .collect()
}

/// Pull until the predicate holds on the accumulated events (bounded by
/// the injected clock, never by real sleep).
async fn drain_until(
    handle: &SessionHandle,
    clock: &TestClock,
    mut done: impl FnMut(&[ReplayEvent]) -> bool,
) -> Vec<ReplayEvent> {
    let mut cursor = Cursor::from_offset(0);
    let mut all = Vec::new();
    loop {
        let out = within(handle.pull(cursor, 1024, Duration::from_secs(30), clock))
            .await
            .unwrap();
        cursor = out.next;
        all.extend(out.events);
        if done(&all) {
            return all;
        }
    }
}

#[tokio::test]
async fn output_flows_into_the_ring_and_pull_returns_it() {
    let (handle, mut pipe, clock) = spawn_session();
    pipe.write_output(b"hello\r\n").await.unwrap();
    let out = within(handle.pull(
        Cursor::from_offset(0),
        1024,
        Duration::from_secs(30),
        &clock,
    ))
    .await
    .unwrap();
    assert_eq!(collect_output(&out), b"hello\r\n");
    assert_eq!(out.next.after, 7);
}

#[tokio::test]
async fn write_requires_the_lease_and_reaches_the_source() {
    let (handle, mut pipe, _clock) = spawn_session();
    // No lease yet.
    assert_eq!(
        handle.write(A, b"x".to_vec()).await,
        Err(WriteError::NotWriter)
    );
    // Take it, then write.
    assert!(matches!(
        handle.take_lease("device:a", A, false).await.unwrap(),
        TakeOutcome::Acquired { changed: true, .. }
    ));
    within(handle.write(A, b"ls\n".to_vec())).await.unwrap();
    let got = within(pipe.read_input(16)).await.unwrap();
    assert_eq!(got, b"ls\n");
    // A different connection cannot write.
    assert_eq!(
        handle.write(B, b"y".to_vec()).await,
        Err(WriteError::NotWriter)
    );
}

/// protocol.md §10-5 / PRD §8: input must be neither lost nor
/// duplicated across a resume. The failure this guards is silent — the
/// user's keystrokes are dropped *and* acked — and it happens whenever
/// two attaches of the same session are alive at once, which is the
/// dominant sleep/wake shape: the old attach has not noticed the path
/// is dead and its TUI keeps sending.
#[tokio::test]
async fn a_demoted_attach_cannot_move_the_live_writer_s_input_cursor() {
    let (handle, mut pipe, _clock) = spawn_session();

    // A1 attaches off the open's ticket — which carries the session's
    // first axis, counting from zero — and types 8 bytes.
    let a1 = FIRST_INPUT_STREAM;
    assert_eq!(handle.applied_input(a1), Some(0));
    handle.take_lease("device:a", A, false).await.unwrap();
    within(handle.write_at(A, b"12345678".to_vec(), Some((a1, 8))))
        .await
        .unwrap();
    assert_eq!(within(pipe.read_input(8)).await.unwrap(), b"12345678");

    // The path dies. A2 resumes on a new connection: a fresh axis,
    // forked from A1's, so it continues A1's numbering.
    let (a2, resume_from) = handle.fork_input_stream(Some(a1));
    assert_ne!(a2, a1, "each attach gets its own axis");
    assert_eq!(resume_from, 8, "…seeded with what A1 had applied");
    handle.take_lease("device:a", B, false).await.unwrap();

    // A1 is still connected and still typing. Its writes are refused —
    // it holds no lease — and must have no effect on A2's axis.
    assert_eq!(
        handle.write_at(A, b"XXXX".to_vec(), Some((a1, 12))).await,
        Err(WriteError::NotWriter)
    );
    assert_eq!(
        handle
            .write_at(A, vec![b'Z'; 4096], Some((a1, u64::MAX)))
            .await,
        Err(WriteError::NotWriter),
        "a peer with no lease must not be able to set a cursor at all"
    );

    // A2 types. Every byte reaches the child.
    let applied = within(handle.write_at(B, b"ls\n".to_vec(), Some((a2, 11))))
        .await
        .unwrap();
    assert_eq!(applied, 11);
    assert_eq!(within(pipe.read_input(3)).await.unwrap(), b"ls\n");

    // A1's own axis did move, so a steal-back does not replay the
    // bytes it was refused — but it moved on its axis alone.
    assert_eq!(handle.applied_input(a1), Some(u64::MAX));
    assert_eq!(handle.applied_input(a2), Some(11));
}

/// The exactly-once half: a resumed attach retransmits its un-acked
/// tail and the child sees each byte once.
#[tokio::test]
async fn a_resumed_axis_deduplicates_the_retransmitted_tail() {
    let (handle, mut pipe, _clock) = spawn_session();
    let first = FIRST_INPUT_STREAM;
    handle.take_lease("device:a", A, false).await.unwrap();
    within(handle.write_at(A, b"abc".to_vec(), Some((first, 3))))
        .await
        .unwrap();
    assert_eq!(within(pipe.read_input(3)).await.unwrap(), b"abc");

    let (second, from) = handle.fork_input_stream(Some(first));
    assert_eq!(from, 3);
    handle.take_lease("device:a", B, false).await.unwrap();
    // The client never saw the ack, so it resends from its own 0.
    assert_eq!(
        within(handle.write_at(B, b"abc".to_vec(), Some((second, 3))))
            .await
            .unwrap(),
        3,
        "a pure retransmission is acked and applied nowhere"
    );
    within(handle.write_at(B, b"def".to_vec(), Some((second, 6))))
        .await
        .unwrap();
    assert_eq!(within(pipe.read_input(3)).await.unwrap(), b"def");

    // A hole is refused rather than silently skipped (PRD §8).
    assert_eq!(
        handle.write_at(B, b"gh".to_vec(), Some((second, 20))).await,
        Err(WriteError::InputGap {
            start: 18,
            applied: 6
        })
    );
}

/// The axis map is bounded: a session that reconnects all day must not
/// grow one entry per recovery.
#[tokio::test]
async fn forking_prunes_the_oldest_axes() {
    let clock = TestClock::new();
    let (source, _pipe) = PipeSource::new(64);
    let handle = spawn_with(source, &clock, SessionConfig::default());
    let mut last = FIRST_INPUT_STREAM;
    for _ in 0..(MAX_INPUT_AXES * 2) {
        let (next, _) = handle.fork_input_stream(Some(last));
        last = next;
    }
    assert_eq!(handle.shared.meta().applied_input.len(), MAX_INPUT_AXES);
    assert!(handle.applied_input(last).is_some(), "the newest survives");
    assert!(
        handle.applied_input(FIRST_INPUT_STREAM).is_none(),
        "the oldest is pruned"
    );
}

#[tokio::test]
async fn blocked_input_write_never_stalls_the_pump_or_close() {
    // 8-byte pipes; the "child" never reads its input. A 4 KiB write
    // parks the input writer only: output still flows into the ring,
    // and close still completes.
    let clock = TestClock::new();
    let (source, mut pipe) = PipeSource::new(8);
    let handle = spawn_with(source, &clock, SessionConfig::default());
    handle.take_lease("device:a", A, false).await.unwrap();
    let blocked = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.write(A, vec![b'x'; 4096]).await })
    };
    tokio::task::yield_now().await;
    assert!(!blocked.is_finished(), "the write is parked on the child");

    // The pump is alive: 5 bytes of output land in the ring.
    // (8-byte pipe: write in one go so the test itself does not block.)
    pipe.write_output(b"hello").await.unwrap();
    let events = drain_until(&handle, &clock, |all| {
        all.iter().any(|e| matches!(e, ReplayEvent::Output { .. }))
    })
    .await;
    let bytes: Vec<u8> = events
        .iter()
        .filter_map(|e| match e {
            ReplayEvent::Output { data, .. } => Some(data.to_vec()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(bytes, b"hello");

    // The inbox is alive: a resize round-trips.
    within(handle.resize(80, 24)).await.unwrap();

    // Close completes (cooperative pipe dies on SIGHUP) even though the
    // input writer is still parked.
    within(handle.close(CloseReason::Closed, None)).await;
    assert!(handle.closed_at().is_some());
    // The parked write is torn down with the session.
    let r = within(blocked).await.unwrap();
    assert!(
        matches!(r, Err(WriteError::Gone) | Err(WriteError::Io(_))),
        "{r:?}"
    );
}

#[tokio::test]
async fn full_input_queue_fails_fast_with_backpressure() {
    let clock = TestClock::new();
    let (source, _pipe) = PipeSource::new(8);
    let handle = spawn_with(
        source,
        &clock,
        SessionConfig {
            input_queue: 1,
            ..SessionConfig::default()
        },
    );
    handle.take_lease("device:a", A, false).await.unwrap();
    // First write parks in the writer task; second sits in the
    // (depth-1) queue; third is refused immediately.
    let mut parked = Vec::new();
    for _ in 0..2 {
        let h = handle.clone();
        parked.push(tokio::spawn(
            async move { h.write(A, vec![b'x'; 64]).await },
        ));
        tokio::task::yield_now().await;
    }
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        within(handle.write(A, vec![b'y'; 8])).await,
        Err(WriteError::Backpressure)
    );
    // Nothing else was affected: a resize still round-trips.
    within(handle.resize(1, 1)).await.unwrap();
    for p in parked {
        p.abort();
    }
}

#[tokio::test]
async fn steal_emits_writer_changed_control_in_order() {
    let (handle, mut pipe, clock) = spawn_session();
    pipe.write_output(b"aa").await.unwrap();
    handle.take_lease("device:a", A, false).await.unwrap();
    // Steal from B.
    handle.take_lease("device:b", B, false).await.unwrap();
    // no_steal against a live holder of another principal conflicts.
    assert!(matches!(
        handle.take_lease("device:a", A, true).await.unwrap(),
        TakeOutcome::Conflict { .. }
    ));
    let events = drain_until(&handle, &clock, |all| {
        all.iter()
            .filter(|e| matches!(e, ReplayEvent::Control { .. }))
            .count()
            >= 2
    })
    .await;
    let writers: Vec<Option<String>> = events
        .iter()
        .filter_map(|e| match e {
            ReplayEvent::Control {
                event: ControlEvent::WriterChanged { writer },
                ..
            } => Some(writer.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        writers,
        vec![Some("device:a".to_string()), Some("device:b".to_string())]
    );
    assert_eq!(handle.info().writer.as_deref(), Some("device:b"));
}

#[tokio::test]
async fn lease_auto_releases_on_connection_death() {
    let (handle, _pipe, _clock) = spawn_session();
    handle.take_lease("device:a", A, false).await.unwrap();
    assert_eq!(handle.info().writer.as_deref(), Some("device:a"));
    within(handle.release_connection(A)).await;
    assert_eq!(handle.info().writer, None);
    // Now writes fail again.
    assert_eq!(
        handle.write(A, b"x".to_vec()).await,
        Err(WriteError::NotWriter)
    );
}

#[tokio::test]
async fn exit_control_is_appended_after_all_output() {
    let (handle, mut pipe, clock) = spawn_session();
    pipe.write_output(b"line1\r\n").await.unwrap();
    pipe.write_output(b"line2\r\n").await.unwrap();
    pipe.exit(SourceExit {
        exit_code: Some(0),
        signal: None,
    });
    // Pull (on the injected clock, no sleep) until the exit control
    // arrives; everything before it must be the whole output.
    let events = drain_until(&handle, &clock, |all| {
        all.iter().any(|e| {
            matches!(
                e,
                ReplayEvent::Control {
                    event: ControlEvent::Exit { .. },
                    ..
                }
            )
        })
    })
    .await;
    let mut bytes = Vec::new();
    let mut saw_exit_after = None;
    for e in &events {
        match e {
            ReplayEvent::Output { data, .. } => bytes.extend_from_slice(data),
            ReplayEvent::Control {
                sequence,
                event: ControlEvent::Exit { exit_code, .. },
                ..
            } => {
                assert_eq!(*exit_code, Some(0));
                saw_exit_after = Some(*sequence);
            }
            _ => {}
        }
    }
    assert_eq!(bytes, b"line1\r\nline2\r\n");
    assert_eq!(saw_exit_after, Some(bytes.len() as u64));
    assert_eq!(handle.info().state, SessionState::Exited);
}

#[tokio::test]
async fn resize_and_signal_reach_the_source() {
    let (handle, pipe, _clock) = spawn_session();
    within(handle.resize(120, 40)).await.unwrap();
    within(handle.signal(Signal::Usr1)).await.unwrap();
    assert_eq!(pipe.resizes(), vec![(120, 40)]);
    assert_eq!(pipe.signals(), vec![Signal::Usr1]);
    assert_eq!(handle.state(), SessionState::Running);
}

#[tokio::test]
async fn close_signals_hup_appends_exit_then_closed_and_stops_the_actor() {
    let (handle, pipe, clock) = spawn_session();
    within(handle.close(CloseReason::Closed, None)).await;
    assert_eq!(pipe.signals(), vec![Signal::Hup]);
    let out = handle
        .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
        .await
        .unwrap();
    // The cooperative child died on HUP: exit(signal) then closed, in
    // that order, closed last.
    let ctls = controls(&out);
    assert_eq!(ctls.len(), 2, "{ctls:?}");
    assert!(matches!(
        &ctls[0],
        ControlEvent::Exit { exit_code: None, signal: Some(s) } if s == "SIGHUP"
    ));
    assert_eq!(
        ctls[1],
        ControlEvent::Closed {
            reason: CloseReason::Closed
        }
    );
    assert!(handle.closed_at().is_some());
    // Actor stopped: further writes report it is gone.
    assert_eq!(handle.write(A, b"x".to_vec()).await, Err(WriteError::Gone));
    // A closed session is still readable (late followers drain it).
    let again = handle
        .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
        .await
        .unwrap();
    assert_eq!(controls(&again).len(), 2);
}

#[tokio::test]
async fn close_of_an_exited_session_sends_no_signal() {
    let (handle, mut pipe, clock) = spawn_session();
    pipe.exit(SourceExit {
        exit_code: Some(3),
        signal: None,
    });
    drain_until(&handle, &clock, |all| {
        all.iter().any(|e| {
            matches!(
                e,
                ReplayEvent::Control {
                    event: ControlEvent::Exit { .. },
                    ..
                }
            )
        })
    })
    .await;
    assert_eq!(handle.state(), SessionState::Exited);
    within(handle.close(CloseReason::Closed, Some(Signal::Term))).await;
    assert!(
        pipe.signals().is_empty(),
        "an exited session must never be signalled (CLI.md §6.7): {:?}",
        pipe.signals()
    );
    let out = handle
        .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
        .await
        .unwrap();
    assert_eq!(
        controls(&out).last(),
        Some(&ControlEvent::Closed {
            reason: CloseReason::Closed
        })
    );
}

#[tokio::test]
async fn close_escalates_hup_term_kill_on_the_injected_clock() {
    let clock = TestClock::new();
    let grace = Duration::from_secs(5);
    let (source, pipe) = PipeSource::with_ignored_signals(64 * 1024, &[Signal::Hup, Signal::Term]);
    let handle = spawn_with(
        source,
        &clock,
        SessionConfig {
            close_grace: grace,
            ..SessionConfig::default()
        },
    );
    let closer = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.close(CloseReason::TtlExpired, None).await })
    };
    // Step 1: HUP immediately.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(pipe.signals(), vec![Signal::Hup]);
    assert!(!closer.is_finished());
    // Not yet: one tick short of the grace.
    clock.advance(grace - Duration::from_millis(1));
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(pipe.signals(), vec![Signal::Hup]);
    // Step 2: TERM after the grace.
    clock.advance(Duration::from_millis(1));
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(pipe.signals(), vec![Signal::Hup, Signal::Term]);
    assert!(!closer.is_finished());
    // Step 3: KILL after another grace; the child dies, close completes.
    clock.advance(grace);
    within(closer).await.unwrap();
    assert_eq!(
        pipe.signals(),
        vec![Signal::Hup, Signal::Term, Signal::Kill]
    );
    let out = handle
        .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
        .await
        .unwrap();
    let ctls = controls(&out);
    assert!(matches!(
        &ctls[0],
        ControlEvent::Exit { signal: Some(s), .. } if s == "SIGKILL"
    ));
    assert_eq!(
        ctls[1],
        ControlEvent::Closed {
            reason: CloseReason::TtlExpired
        }
    );
}

#[tokio::test]
async fn close_with_kill_skips_escalation() {
    let (handle, pipe, _clock) = spawn_session();
    within(handle.close(CloseReason::Closed, Some(Signal::Kill))).await;
    assert_eq!(pipe.signals(), vec![Signal::Kill]);
}

#[tokio::test]
async fn close_of_an_unkillable_child_finishes_after_kill_plus_grace() {
    // Nothing kills it (D-state analogue): HUP, TERM, KILL, then a last
    // grace, then forced cleanup — the close never hangs forever and no
    // synthetic exit is invented.
    let clock = TestClock::new();
    let grace = Duration::from_secs(1);
    let (source, pipe) = PipeSource::with_ignored_signals(64 * 1024, &Signal::ALL);
    let handle = spawn_with(
        source,
        &clock,
        SessionConfig {
            close_grace: grace,
            ..SessionConfig::default()
        },
    );
    let closer = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.close(CloseReason::Closed, None).await })
    };
    for step in 0..3 {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!closer.is_finished(), "finished early at step {step}");
        clock.advance(grace);
    }
    within(closer).await.unwrap();
    assert_eq!(
        pipe.signals(),
        vec![Signal::Hup, Signal::Term, Signal::Kill]
    );
    let out = handle
        .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
        .await
        .unwrap();
    assert_eq!(
        controls(&out),
        vec![ControlEvent::Closed {
            reason: CloseReason::Closed
        }]
    );
}

#[tokio::test]
async fn concurrent_closes_all_resolve_on_the_same_close() {
    let (handle, pipe, _clock) = spawn_session();
    let a = {
        let h = handle.clone();
        tokio::spawn(async move { h.close(CloseReason::Closed, None).await })
    };
    let b = {
        let h = handle.clone();
        tokio::spawn(async move { h.close(CloseReason::TtlExpired, Some(Signal::Kill)).await })
    };
    within(a).await.unwrap();
    within(b).await.unwrap();
    // Only the first close's signal was sent; one Closed entry.
    assert_eq!(pipe.signals(), vec![Signal::Hup]);
    let out = handle
        .pull(
            Cursor::from_offset(0),
            1024,
            Duration::ZERO,
            &TestClock::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        controls(&out)
            .iter()
            .filter(|c| matches!(c, ControlEvent::Closed { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn pull_wait_blocks_until_output_then_returns() {
    let (handle, mut pipe, clock) = spawn_session();
    let reader = {
        let handle = handle.clone();
        let clock = clock.clone();
        tokio::spawn(async move {
            handle
                .pull(
                    Cursor::from_offset(0),
                    1024,
                    Duration::from_secs(60),
                    &clock,
                )
                .await
                .map(|o| collect_output(&o))
        })
    };
    // Nothing yet: the reader is parked.
    tokio::task::yield_now().await;
    assert!(!reader.is_finished());
    pipe.write_output(b"late\r\n").await.unwrap();
    assert_eq!(within(reader).await.unwrap().unwrap(), b"late\r\n");
}

#[tokio::test(start_paused = true)]
async fn pull_wait_times_out_via_the_clock_without_sleeping() {
    let (handle, _pipe, clock) = spawn_session();
    let reader = {
        let handle = handle.clone();
        let clock = clock.clone();
        tokio::spawn(async move {
            handle
                .pull(
                    Cursor::from_offset(0),
                    1024,
                    Duration::from_secs(30),
                    &clock,
                )
                .await
        })
    };
    tokio::task::yield_now().await;
    assert!(!reader.is_finished());
    // Advance the injected clock past the deadline; no real time passes.
    clock.advance(Duration::from_secs(30));
    let out = within(reader).await.unwrap().unwrap();
    assert!(out.events.is_empty());
}

#[tokio::test]
async fn pull_with_a_huge_wait_does_not_panic() {
    let (handle, mut pipe, clock) = spawn_session();
    // A caller-supplied `--wait` far beyond what an Instant can hold
    // must clamp, not overflow.
    let reader = {
        let handle = handle.clone();
        let clock = clock.clone();
        tokio::spawn(async move {
            handle
                .pull(Cursor::from_offset(0), 16, Duration::MAX, &clock)
                .await
        })
    };
    tokio::task::yield_now().await;
    assert!(!reader.is_finished());
    pipe.write_output(b"ok").await.unwrap();
    let out = within(reader).await.unwrap().unwrap();
    assert_eq!(collect_output(&out), b"ok");
}

#[tokio::test]
async fn per_session_memory_is_bounded_by_the_ring_budget() {
    // The worst producer for a ring: one byte per read, far past the
    // budget. Bytes retained stay within the budget and — because small
    // pushes coalesce — the entry count (the per-entry overhead) stays
    // within budget / chunk as well, so the session's memory is
    // ring budget + O(1), not O(bytes ever produced). Consumers are
    // just cursors: N of them add no per-byte cost.
    let clock = TestClock::new();
    let budget = 4096;
    let (source, mut pipe) = PipeSource::new(1);
    let handle = spawn_with(
        source,
        &clock,
        SessionConfig {
            replay_bytes: budget,
            ..SessionConfig::default()
        },
    );
    let total = 8 * budget;
    for i in 0..total {
        pipe.write_output(&[(i % 251) as u8]).await.unwrap();
    }
    // Wait (injected clock, no sleep) until the pump has ingested
    // everything: pull at the current end until the end reaches total.
    while handle.end_offset() < total as u64 {
        let cursor = Cursor::from_offset(handle.end_offset());
        within(handle.pull(cursor, 1, Duration::from_secs(30), &clock))
            .await
            .unwrap();
    }
    let (retained, entries, ring_budget, piece) = {
        let ring = handle.shared.ring();
        (
            ring.retained(),
            ring.entry_count(),
            ring.budget(),
            ring.chunk_max(),
        )
    };
    assert_eq!(ring_budget, budget);
    assert!(retained <= budget, "retained {retained} > budget {budget}");
    assert!(
        entries <= budget / piece + 1,
        "entries {entries} exceed budget/chunk ({})",
        budget / piece
    );
    // A rough per-entry overhead proxy: even charging 64 B per entry the
    // whole ring is within 2× the budget.
    assert!(retained + entries * 64 <= 2 * budget);
    // Multiple consumers are cursors only: reading from many offsets
    // returns bounded data and allocates nothing in the session.
    for after in [0u64, 100, 4000, handle.end_offset() - 1] {
        let out = handle
            .pull(
                Cursor::from_offset(after),
                usize::MAX,
                Duration::ZERO,
                &clock,
            )
            .await
            .unwrap();
        assert!(collect_output(&out).len() <= budget);
    }
}

// `TtlWindow` is a pure function of four fields, detached from the actor
// precisely so it can be tested (and fuzzed, `broker_ops_harness.rs`)
// without spawning one — these three cover the same three branches
// `ttl_reap_reason`'s doc describes, directly on the type.

#[test]
fn ttl_window_never_reaps_while_attached() {
    let epoch = Instant::now();
    let ttl = Duration::from_secs(10);
    let window = TtlWindow {
        attached: 1,
        closing: false,
        state: SessionState::Exited,
        ttl_base: epoch,
    };
    // Miles past the TTL on the clock, but still attached: no reason,
    // and the deadline is pinned to `now + ttl` (architecture.md §3 —
    // the TTL does not run at all while attached).
    let now = epoch + ttl * 100;
    assert_eq!(window.reap_reason(now, ttl), None);
    assert_eq!(window.deadline(now, ttl), now + ttl);
}

#[test]
fn ttl_window_reason_depends_on_state_once_the_ttl_elapses() {
    let epoch = Instant::now();
    let ttl = Duration::from_secs(10);
    for state in [SessionState::Running, SessionState::Exited] {
        let window = TtlWindow {
            attached: 0,
            closing: false,
            state,
            ttl_base: epoch,
        };
        // Not yet due: unattached alone is not enough.
        assert_eq!(
            window.reap_reason(epoch + ttl - Duration::from_millis(1), ttl),
            None
        );
        // Exactly due, split by state (session.rs's own `ttl_reap_reason`
        // doc: `Exit` for an already-exited child, `TtlExpired` for one
        // still running).
        let expected = match state {
            SessionState::Exited => CloseReason::Exit,
            SessionState::Running => CloseReason::TtlExpired,
        };
        assert_eq!(window.reap_reason(epoch + ttl, ttl), Some(expected));
    }
}

#[test]
fn ttl_window_closing_suppresses_reap_and_deadline_anchors_to_ttl_base() {
    let epoch = Instant::now();
    let ttl = Duration::from_secs(10);
    let window = TtlWindow {
        attached: 0,
        closing: true,
        state: SessionState::Running,
        ttl_base: epoch,
    };
    let now = epoch + ttl * 100;
    // `closing` suppresses reaping even long past the TTL...
    assert_eq!(window.reap_reason(now, ttl), None);
    // ...but unlike the attached case, the deadline is unaffected by
    // `closing` — it is anchored to `ttl_base`, same as any other
    // unattached session.
    assert_eq!(window.deadline(now, ttl), epoch + ttl);
}
