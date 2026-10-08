use super::*;

/// Fail instead of hanging when something is broken. Real time only
/// elapses on failure.
async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .expect("timed out")
}

fn test_broker(ttl: Duration) -> (Arc<Broker>, TestClock) {
    let clock = TestClock::new();
    let broker = Broker::new(
        Arc::new(clock.clone()),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: ttl,
            close_grace: Duration::from_millis(5000),
            quota_limits: crate::quota::QuotaLimits::default(),
        },
        Arc::new(PipeFactory::new(64 * 1024)),
    );
    (broker, clock)
}

fn open_pipe(broker: &Broker) -> (SessionHandle, PipeHandle) {
    let (source, pipe) = PipeSource::new(64 * 1024);
    let handle = broker
        .open_with(&SessionSpec::default(), Box::new(source))
        .unwrap();
    (handle, pipe)
}

fn sid(h: &SessionHandle) -> SessionId {
    SessionId(h.id().to_string())
}

async fn wait_exited(handle: &SessionHandle, clock: &TestClock) {
    let mut cursor = Cursor::from_offset(0);
    loop {
        let out = within(handle.pull(cursor, 1024, Duration::from_secs(30), clock))
            .await
            .unwrap();
        cursor = out.next;
        if handle.state() == SessionState::Exited {
            return;
        }
    }
}

#[tokio::test]
async fn open_get_list_close_roundtrip() {
    let (broker, clock) = test_broker(Duration::from_secs(3600));
    let (h1, _p1) = open_pipe(&broker);
    let (h2, _p2) = open_pipe(&broker);
    assert_eq!(broker.session_count(), 2);

    let id1 = sid(&h1);
    let info = broker.get(&id1).unwrap().info();
    assert_eq!(info.session_id, h1.id());
    assert_eq!(info.state, SessionState::Running);

    let list = broker.list();
    assert_eq!(list.len(), 2);

    within(broker.close(&id1, CloseReason::Closed, None))
        .await
        .unwrap();
    assert_eq!(broker.session_count(), 1);
    assert!(matches!(broker.get(&id1), Err(BrokerError::NotFound)));
    assert_eq!(broker.list().len(), 1);
    // A second close is NotFound (CLI.md §6.4), not a hang or a panic.
    assert_eq!(
        broker.close(&id1, CloseReason::Closed, None).await,
        Err(BrokerError::NotFound)
    );
    // But the closed session is still readable: `session.closed` is the
    // last event a follower sees.
    let out = within(SessionBackend::pull(
        broker.as_ref(),
        &id1,
        Cursor::from_offset(0),
        1024,
        Duration::ZERO,
    ))
    .await
    .unwrap();
    assert!(matches!(
        out.events.last(),
        Some(ReplayEvent::Control {
            event: ControlEvent::Closed {
                reason: CloseReason::Closed
            },
            ..
        })
    ));
    // …until the retention window passes and the reaper drops it.
    clock.advance(CLOSED_RETENTION);
    broker.reap_once().await;
    assert!(matches!(
        SessionBackend::pull(
            broker.as_ref(),
            &id1,
            Cursor::from_offset(0),
            1024,
            Duration::ZERO
        )
        .await,
        Err(BrokerError::NotFound)
    ));
    // h2 still there.
    assert!(broker.get(&sid(&h2)).is_ok());
}

#[tokio::test]
async fn backend_open_uses_the_source_factory_and_is_object_safe() {
    let (broker, _clock) = test_broker(Duration::from_secs(3600));
    let backend: Arc<dyn SessionBackend> = broker.clone();
    let id = backend
        .open(&SessionSpec::default(), "device:test-opener")
        .unwrap();
    assert_eq!(backend.get(&id).unwrap().state, SessionState::Running);
    assert_eq!(backend.list().len(), 1);
    within(backend.close(&id, CloseReason::Closed, None))
        .await
        .unwrap();
    assert!(matches!(backend.get(&id), Err(BrokerError::NotFound)));
}

#[tokio::test]
async fn reaper_leaves_attached_sessions_and_reaps_unattached_running_ones() {
    let ttl = Duration::from_secs(60);
    let (broker, clock) = test_broker(ttl);
    let (attached, _pa) = open_pipe(&broker);
    let (_idle, pi) = open_pipe(&broker);
    let _guard = attached.attach_guard();

    // Not yet past TTL.
    clock.advance(ttl - Duration::from_secs(1));
    assert!(broker.reap_once().await.is_empty());

    // Past TTL: the idle one is reaped as TtlExpired (still running, so
    // it is signalled), the attached one survives.
    clock.advance(Duration::from_secs(2));
    let reaped = within(broker.reap_once()).await;
    assert_eq!(reaped.len(), 1);
    assert_eq!(pi.signals(), vec![Signal::Hup]);
    assert_eq!(broker.session_count(), 1);
    assert!(broker.get(&sid(&attached)).is_ok());
}

#[tokio::test]
async fn reaper_reason_is_exit_for_an_already_exited_child_and_sends_no_signal() {
    let ttl = Duration::from_secs(60);
    let (broker, clock) = test_broker(ttl);
    let (handle, mut pipe) = open_pipe(&broker);
    pipe.exit(SourceExit {
        exit_code: Some(0),
        signal: None,
    });
    wait_exited(&handle, &clock).await;

    // The exited session's TTL runs from the exit instant.
    clock.advance(ttl + Duration::from_secs(1));
    let now = clock.now();
    assert_eq!(
        handle.ttl_reap_reason(now, ttl),
        Some(CloseReason::Exit),
        "an exited child reaps as Exit, not TtlExpired"
    );
    let reaped = within(broker.reap_once()).await;
    assert_eq!(reaped.len(), 1);
    assert!(
        pipe.signals().is_empty(),
        "an exited session is never signalled (CLI.md §6.7)"
    );
    let out = handle
        .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
        .await
        .unwrap();
    assert!(matches!(
        out.events.last(),
        Some(ReplayEvent::Control {
            event: ControlEvent::Closed {
                reason: CloseReason::Exit
            },
            ..
        })
    ));
}

#[tokio::test]
async fn detach_restarts_the_ttl_clock() {
    let ttl = Duration::from_secs(60);
    let (broker, clock) = test_broker(ttl);
    let (handle, _pipe) = open_pipe(&broker);
    {
        let _guard = handle.attach_guard();
        clock.advance(Duration::from_secs(120)); // long attach
        assert!(broker.reap_once().await.is_empty());
    } // detach here; TTL restarts from now
    assert!(broker.reap_once().await.is_empty());
    clock.advance(ttl + Duration::from_secs(1));
    assert_eq!(within(broker.reap_once()).await.len(), 1);
}

/// A credential must live exactly as long as the session it resumes.
///
/// The session's own TTL does not run while it is attached — that is
/// the product's premise, a shell worked in all day — so anchoring the
/// credential to its issue instant instead would leave a healthy
/// session with an expired credential and orphan it on the next
/// disconnect (PRD §13). The reaper re-anchors on every pass.
#[tokio::test]
async fn an_attached_session_keeps_its_credential_past_the_ttl() {
    let ttl = Duration::from_secs(60);
    let (broker, clock) = test_broker(ttl);
    let (handle, _pipe) = open_pipe(&broker);
    let id = sid(&handle);
    let peer = PeerFingerprint::new([3u8; PEER_FINGERPRINT_LEN]);
    let token = SessionBackend::issue_resume(&*broker, &id, peer);

    {
        let _guard = handle.attach_guard();
        // Ten times the credential's nominal life, worked in the whole
        // time. Nothing reaps, and the credential still verifies.
        for _ in 0..10 {
            clock.advance(ttl);
            assert!(within(broker.reap_once()).await.is_empty());
        }
        assert!(
            SessionBackend::verify_resume(&*broker, &id, token.expose(), peer).is_ok(),
            "a session alive past its TTL must still be resumable"
        );
    }

    // Detached, the credential lapses with the session, not before it.
    clock.advance(ttl / 2);
    assert!(within(broker.reap_once()).await.is_empty());
    assert!(SessionBackend::verify_resume(&*broker, &id, token.expose(), peer).is_ok());
    clock.advance(ttl);
    assert_eq!(within(broker.reap_once()).await.len(), 1);
    assert_eq!(
        SessionBackend::verify_resume(&*broker, &id, token.expose(), peer),
        Err(ResumeDenied),
        "a reaped session's credential is forgotten with it"
    );
}

#[tokio::test]
async fn release_connection_drops_leases_everywhere_but_keeps_sessions() {
    let (broker, _clock) = test_broker(Duration::from_secs(3600));
    let (h1, _p1) = open_pipe(&broker);
    let (h2, _p2) = open_pipe(&broker);
    let conn = ConnectionId(7);
    h1.take_lease("device:a", conn, false).await.unwrap();
    h2.take_lease("device:a", conn, false).await.unwrap();
    assert_eq!(h1.info().writer.as_deref(), Some("device:a"));

    within(broker.release_connection(conn)).await;
    assert_eq!(h1.info().writer, None);
    assert_eq!(h2.info().writer, None);
    assert_eq!(broker.session_count(), 2, "sessions survive lease loss");
}

/// `close_all` is `close`, applied to every live session at once: same
/// `session.closed` emission, same resume-credential forgetting,
/// nothing left running afterwards.
#[tokio::test]
async fn close_all_closes_every_live_session_and_forgets_its_credential() {
    let (broker, _clock) = test_broker(Duration::from_secs(3600));
    let (h1, _p1) = open_pipe(&broker);
    let (h2, _p2) = open_pipe(&broker);
    let id1 = sid(&h1);
    let id2 = sid(&h2);
    let peer = PeerFingerprint::new([9u8; PEER_FINGERPRINT_LEN]);
    let token1 = SessionBackend::issue_resume(&*broker, &id1, peer);
    assert_eq!(broker.session_count(), 2);

    within(broker.close_all(CloseReason::Closed)).await;

    assert_eq!(broker.session_count(), 0);
    assert!(matches!(broker.get(&id1), Err(BrokerError::NotFound)));
    assert!(matches!(broker.get(&id2), Err(BrokerError::NotFound)));
    assert_eq!(
        SessionBackend::verify_resume(&*broker, &id1, token1.expose(), peer),
        Err(ResumeDenied),
        "a session closed by drain forgets its credential exactly like an explicit close"
    );
    let out = within(SessionBackend::pull(
        broker.as_ref(),
        &id1,
        Cursor::from_offset(0),
        1024,
        Duration::ZERO,
    ))
    .await
    .unwrap();
    assert!(matches!(
        out.events.last(),
        Some(ReplayEvent::Control {
            event: ControlEvent::Closed {
                reason: CloseReason::Closed
            },
            ..
        })
    ));
    // Idempotent: a second pass finds nothing left to close.
    within(broker.close_all(CloseReason::Closed)).await;
}

/// The [`SessionBackend`] seam a future out-of-process supervisor would
/// implement, exercised the same way `Server::drain` calls it.
#[tokio::test]
async fn backend_drain_closes_every_session_via_the_trait_object() {
    let (broker, _clock) = test_broker(Duration::from_secs(3600));
    let backend: Arc<dyn SessionBackend> = broker.clone();
    let id = backend
        .open(&SessionSpec::default(), "device:test-opener")
        .unwrap();
    assert_eq!(backend.list().len(), 1);

    within(backend.drain(CloseReason::Closed)).await;

    assert!(backend.list().is_empty());
    assert!(matches!(backend.get(&id), Err(BrokerError::NotFound)));
}

#[tokio::test]
async fn backend_write_maps_lease_errors() {
    let (broker, _clock) = test_broker(Duration::from_secs(3600));
    let (handle, _pipe) = open_pipe(&broker);
    let id = sid(&handle);
    // No lease.
    assert_eq!(
        SessionBackend::write(broker.as_ref(), &id, ConnectionId(1), b"x".to_vec()).await,
        Err(BrokerError::NotWriter)
    );
    // Take + write via the backend trait.
    SessionBackend::take_lease(
        broker.as_ref(),
        &id,
        "device:a".into(),
        ConnectionId(1),
        false,
    )
    .await
    .unwrap();
    within(SessionBackend::write(
        broker.as_ref(),
        &id,
        ConnectionId(1),
        b"ok".to_vec(),
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn no_steal_conflict_surfaces_through_the_backend() {
    let (broker, _clock) = test_broker(Duration::from_secs(3600));
    let (handle, _pipe) = open_pipe(&broker);
    let id = sid(&handle);
    handle
        .take_lease("device:a", ConnectionId(1), false)
        .await
        .unwrap();
    let outcome = SessionBackend::take_lease(
        broker.as_ref(),
        &id,
        "device:b".into(),
        ConnectionId(2),
        true,
    )
    .await
    .unwrap();
    assert!(matches!(outcome, TakeOutcome::Conflict { .. }));
}

#[tokio::test]
async fn pull_beyond_end_is_invalid_argument_not_not_found() {
    let (broker, _clock) = test_broker(Duration::from_secs(3600));
    let (handle, _pipe) = open_pipe(&broker);
    let id = sid(&handle);
    let err = SessionBackend::pull(
        broker.as_ref(),
        &id,
        Cursor::from_offset(999),
        16,
        Duration::ZERO,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, BrokerError::InvalidArgument(_)), "{err:?}");
    // The session is, of course, still there.
    assert!(broker.get(&id).is_ok());
}

#[tokio::test(start_paused = true)]
async fn run_reaper_uses_the_injected_clock_and_stops_with_the_broker() {
    // A SystemClock reaper under tokio pause: advancing tokio time
    // fires the tick without any real sleep.
    let clock = SystemClock;
    let broker = Broker::new(
        Arc::new(clock),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(10),
            close_grace: Duration::from_millis(5000),
            quota_limits: crate::quota::QuotaLimits::default(),
        },
        Arc::new(PipeFactory::new(64 * 1024)),
    );
    let (source, _pipe) = PipeSource::new(64 * 1024);
    broker
        .open_with(&SessionSpec::default(), Box::new(source))
        .unwrap();
    let reaper = tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));

    // Past TTL + a reaper tick.
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::advance(REAPER_TICK).await;
    // Give the reaper task a turn.
    for _ in 0..20 {
        tokio::task::yield_now().await;
        if broker.session_count() == 0 {
            break;
        }
    }
    assert_eq!(broker.session_count(), 0);
    // Dropping the broker ends the reaper on its next wake (Weak).
    drop(broker);
    tokio::time::advance(REAPER_TICK).await;
    within(reaper).await.unwrap();
}

// --- Session quotas (`PLAN.md` M8 Step 3, `docs/adr/0010-resource-
// quotas.md`, design §4.1). ---

use crate::quota::{QuotaKind, QuotaLimits};

fn broker_with_limits(quota_limits: QuotaLimits) -> (Arc<Broker>, TestClock) {
    let clock = TestClock::new();
    let broker = Broker::new(
        Arc::new(clock.clone()),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(5000),
            quota_limits,
        },
        Arc::new(PipeFactory::new(64 * 1024)),
    );
    (broker, clock)
}

/// A [`SourceFactory`] wrapping a [`PipeFactory`], counting how many
/// times `create` actually ran.
struct CountingFactory {
    inner: PipeFactory,
    calls: std::sync::atomic::AtomicUsize,
}

impl CountingFactory {
    fn new(buffer: usize) -> Self {
        Self {
            inner: PipeFactory::new(buffer),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SourceFactory for CountingFactory {
    fn create(&self, spec: &SessionSpec) -> io::Result<Box<dyn SessionSource>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.create(spec)
    }
}

#[tokio::test]
async fn open_refuses_past_the_host_session_cap() {
    let (broker, _clock) = broker_with_limits(QuotaLimits {
        max_sessions: 3,
        ..QuotaLimits::default()
    });
    for _ in 0..3 {
        open_pipe(&broker);
    }
    assert_eq!(broker.session_count(), 3);
    assert_eq!(
        broker
            .open_as(&SessionSpec::default(), "device:extra")
            .unwrap_err(),
        BrokerError::QuotaExceeded(QuotaKind::Sessions)
    );
    assert_eq!(broker.session_count(), 3);
}

/// Verdict arbitration item 11's twin to U3/U14: `Broker::open` and
/// `Broker::open_with` are test-only entry points, but both are
/// `pub`, and both funnel through the same `open_with_opener` — this
/// pins that neither one is a quiet quota bypass a future production
/// caller could reach for.
#[tokio::test]
async fn open_and_open_with_are_refused_by_the_same_cap_as_open_as() {
    let (broker, _clock) = broker_with_limits(QuotaLimits {
        max_sessions: 1,
        ..QuotaLimits::default()
    });
    broker.open_as(&SessionSpec::default(), "device:a").unwrap();
    assert_eq!(
        broker.open(&SessionSpec::default()).unwrap_err(),
        BrokerError::QuotaExceeded(QuotaKind::Sessions)
    );
    let (source, _pipe) = PipeSource::new(64 * 1024);
    assert_eq!(
        broker
            .open_with(&SessionSpec::default(), Box::new(source))
            .unwrap_err(),
        BrokerError::QuotaExceeded(QuotaKind::Sessions)
    );
    assert_eq!(broker.session_count(), 1);
}

#[tokio::test]
async fn per_principal_cap_refuses_one_opener_and_still_admits_another() {
    let (broker, _clock) = broker_with_limits(QuotaLimits {
        max_sessions_per_principal: 2,
        ..QuotaLimits::default()
    });
    broker.open_as(&SessionSpec::default(), "device:a").unwrap();
    broker.open_as(&SessionSpec::default(), "device:a").unwrap();
    assert_eq!(
        broker
            .open_as(&SessionSpec::default(), "device:a")
            .unwrap_err(),
        BrokerError::QuotaExceeded(QuotaKind::SessionsPerPrincipal)
    );
    // A different opener has its own, untouched budget.
    assert!(broker.open_as(&SessionSpec::default(), "device:b").is_ok());
}

/// ADR-0010 §2.1: the global session cap is checked before the
/// per-principal cap in `reserve_slot`. With both caps saturated by
/// the very same opener, the error must still name `Sessions`
/// (global), never `SessionsPerPrincipal` — the two are equally true
/// here, so this only distinguishes them by which one `reserve_slot`
/// actually returns first.
#[tokio::test]
async fn global_cap_is_checked_before_the_per_principal_cap() {
    let (broker, _clock) = broker_with_limits(QuotaLimits {
        max_sessions: 1,
        max_sessions_per_principal: 1,
        ..QuotaLimits::default()
    });
    broker.open_as(&SessionSpec::default(), "device:a").unwrap();
    assert_eq!(
        broker
            .open_as(&SessionSpec::default(), "device:a")
            .unwrap_err(),
        BrokerError::QuotaExceeded(QuotaKind::Sessions)
    );
}

#[tokio::test]
async fn refused_open_never_calls_the_source_factory() {
    let clock = TestClock::new();
    let factory = Arc::new(CountingFactory::new(64 * 1024));
    let broker = Broker::new(
        Arc::new(clock),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(5000),
            quota_limits: QuotaLimits {
                max_sessions: 1,
                ..QuotaLimits::default()
            },
        },
        factory.clone(),
    );
    broker.open(&SessionSpec::default()).unwrap();
    assert_eq!(factory.calls(), 1);
    assert_eq!(
        broker.open(&SessionSpec::default()).unwrap_err(),
        BrokerError::QuotaExceeded(QuotaKind::Sessions)
    );
    // The refusal must not have spawned a second source.
    assert_eq!(factory.calls(), 1);
}

#[tokio::test]
async fn closed_sessions_do_not_hold_quota() {
    let (broker, _clock) = broker_with_limits(QuotaLimits {
        max_sessions: 1,
        ..QuotaLimits::default()
    });
    let (h, _pipe) = open_pipe(&broker);
    assert_eq!(
        broker.open(&SessionSpec::default()).unwrap_err(),
        BrokerError::QuotaExceeded(QuotaKind::Sessions)
    );
    within(broker.close(&sid(&h), CloseReason::Closed, None))
        .await
        .unwrap();
    // Closed-but-lingering (within CLOSED_RETENTION) does not hold
    // the slot — a fresh open succeeds immediately.
    assert!(broker.open(&SessionSpec::default()).is_ok());
}

#[tokio::test]
async fn reaped_sessions_release_quota() {
    let ttl = Duration::from_secs(10);
    let clock = TestClock::new();
    let broker = Broker::new(
        Arc::new(clock.clone()),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: ttl,
            close_grace: Duration::from_millis(5000),
            quota_limits: QuotaLimits {
                max_sessions: 1,
                ..QuotaLimits::default()
            },
        },
        Arc::new(PipeFactory::new(64 * 1024)),
    );
    open_pipe(&broker);
    assert_eq!(
        broker.open(&SessionSpec::default()).unwrap_err(),
        BrokerError::QuotaExceeded(QuotaKind::Sessions)
    );
    clock.advance(ttl + Duration::from_secs(1));
    let reaped = broker.reap_once().await;
    assert_eq!(reaped.len(), 1);
    assert_eq!(broker.session_count(), 0);
    assert!(broker.open(&SessionSpec::default()).is_ok());
}

#[tokio::test]
async fn concurrent_opens_never_exceed_the_cap() {
    const CAP: usize = 8;
    const ATTEMPTS: usize = 32;
    let (broker, _clock) = broker_with_limits(QuotaLimits {
        max_sessions: CAP,
        ..QuotaLimits::default()
    });
    let barrier = Arc::new(tokio::sync::Barrier::new(ATTEMPTS));
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..ATTEMPTS {
        let broker = Arc::clone(&broker);
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            broker
                .open_as(&SessionSpec::default(), format!("device:{i}"))
                .is_ok()
        });
    }
    let mut successes = 0usize;
    while let Some(res) = tasks.join_next().await {
        if res.unwrap() {
            successes += 1;
        }
        assert!(broker.session_count() <= CAP);
    }
    assert_eq!(successes, CAP);
    assert_eq!(broker.session_count(), CAP);
}

/// Main-session arbitration item 1's own test: the in-flight
/// `SessionSlot` reservation must close the residual race F5 of the
/// M8 Step 3a conformance sweep accepted for the old, non-reserving
/// `precheck_quota` — twin of `refused_open_never_calls_the_source_
/// factory` (U3), run under `concurrent_opens_never_exceed_the_cap`'s
/// (U6) own barrier shape. `2N` concurrent openers racing for `N`
/// slots must have `factory.create` called exactly `N` times, never
/// `2N`: a refused attempt must never have created (and then
/// discarded) a source at all, not merely never have kept one.
///
/// This runs on a current-thread runtime, and `Broker::open_as` has no
/// `.await` in it, so its "concurrent" openers actually serialize —
/// the race the reservation exists to close is genuinely exercised by
/// `concurrent_opens_racing_inside_factory_create_still_call_it_once`
/// below, not by this test.
#[tokio::test]
async fn concurrent_opens_call_the_factory_exactly_cap_times() {
    const CAP: usize = 8;
    const ATTEMPTS: usize = CAP * 2;
    let clock = TestClock::new();
    let factory = Arc::new(CountingFactory::new(64 * 1024));
    let broker = Broker::new(
        Arc::new(clock),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(5000),
            quota_limits: QuotaLimits {
                max_sessions: CAP,
                ..QuotaLimits::default()
            },
        },
        factory.clone(),
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(ATTEMPTS));
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..ATTEMPTS {
        let broker = Arc::clone(&broker);
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            broker
                .open_as(&SessionSpec::default(), format!("device:{i}"))
                .map(|h| sid(&h))
        });
    }
    let mut opened = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(id) = res.unwrap() {
            opened.push(id);
        }
    }
    assert_eq!(opened.len(), CAP, "the cap, not more, must actually open");
    assert_eq!(
        factory.calls(),
        CAP,
        "a refused open must never have called the source factory at \
         all — the old non-reserving `precheck_quota` this stage \
         replaces could let a loser's `factory.create` run and then \
         discard the result; the in-flight reservation must close \
         that race outright, not just bound it"
    );
    assert_eq!(broker.session_count(), CAP);
    assert_eq!(broker.in_flight_total(), 0);

    for id in opened {
        within(broker.close(&id, CloseReason::Closed, None))
            .await
            .unwrap();
    }
    assert_eq!(broker.in_flight_total(), 0);
    assert!(
        broker
            .open_as(&SessionSpec::default(), "device:after")
            .is_ok()
    );
}

/// The in-flight `SessionSlot` reservation must be observable by a
/// *genuinely concurrent* opener, not just by openers a current-thread
/// runtime happens to serialize (see the note on
/// `concurrent_opens_call_the_factory_exactly_cap_times` above). This
/// one blocks *inside* `factory.create` until both racers are in it,
/// on a real multi-thread runtime, so the reserve → insert window the
/// reservation exists to close is actually open while both are
/// racing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_opens_racing_inside_factory_create_still_call_it_once() {
    struct SlowFactory {
        inner: PipeFactory,
        calls: std::sync::atomic::AtomicUsize,
        entered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl SourceFactory for SlowFactory {
        fn create(&self, spec: &SessionSpec) -> io::Result<Box<dyn SessionSource>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Widen the reserve->insert window: park here long enough
            // that a second opener is guaranteed to have run
            // `reserve_slot` while this one is still inside create().
            self.entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
            self.inner.create(spec)
        }
    }
    let entered = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let factory = Arc::new(SlowFactory {
        inner: PipeFactory::new(64 * 1024),
        calls: std::sync::atomic::AtomicUsize::new(0),
        entered: entered.clone(),
    });
    let clock = TestClock::new();
    let broker = Broker::new(
        Arc::new(clock),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(5000),
            quota_limits: QuotaLimits {
                max_sessions: 1,
                ..QuotaLimits::default()
            },
        },
        factory.clone(),
    );
    let b1 = Arc::clone(&broker);
    let t1 = tokio::task::spawn_blocking(move || {
        b1.open_as(&SessionSpec::default(), "device:a").is_ok()
    });
    // Let t1 get inside `factory.create` before t2 even starts.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        entered.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the first opener must actually be parked inside factory.create"
    );
    let b2 = Arc::clone(&broker);
    let t2 = tokio::task::spawn_blocking(move || {
        b2.open_as(&SessionSpec::default(), "device:b").is_ok()
    });
    let r1 = t1.await.unwrap();
    let r2 = t2.await.unwrap();
    assert_eq!(
        [r1, r2].iter().filter(|ok| **ok).count(),
        1,
        "exactly one of the two racers may open under max_sessions = 1"
    );
    assert_eq!(
        factory.calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the loser must never have reached factory.create at all — the \
         in-flight reservation taken before create() is what makes the \
         winner visible to the loser's count"
    );
    assert_eq!(broker.session_count(), 1);
    assert_eq!(broker.in_flight_total(), 0);
}

#[tokio::test]
async fn slot_is_released_when_the_factory_fails() {
    let clock = TestClock::new();
    let attempt = std::sync::atomic::AtomicUsize::new(0);
    let factory = move |spec: &SessionSpec| -> io::Result<Box<dyn SessionSource>> {
        if attempt.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            Err(io::Error::other("boom"))
        } else {
            let (source, _pipe) = PipeSource::new(64 * 1024);
            let _ = spec;
            Ok(Box::new(source) as Box<dyn SessionSource>)
        }
    };
    let broker = Broker::new(
        Arc::new(clock),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(5000),
            quota_limits: QuotaLimits {
                max_sessions: 1,
                ..QuotaLimits::default()
            },
        },
        Arc::new(factory),
    );
    // First attempt: factory fails. Nothing was reserved/inserted, so
    // the cap-1 slot is still free for the next attempt.
    assert!(matches!(
        broker.open(&SessionSpec::default()),
        Err(BrokerError::Spawn(_))
    ));
    assert_eq!(broker.session_count(), 0);
    assert!(broker.open(&SessionSpec::default()).is_ok());
    assert_eq!(broker.session_count(), 1);
}

#[tokio::test]
async fn detached_session_still_holds_quota_until_closed() {
    let (broker, _clock) = broker_with_limits(QuotaLimits {
        max_sessions_per_principal: 1,
        ..QuotaLimits::default()
    });
    let h = broker.open_as(&SessionSpec::default(), "device:a").unwrap();
    let id = sid(&h);
    // "Detach": the caller's handle goes away with no explicit
    // session.close — nothing broker-side increments on an attach
    // call here, so this session is exactly the "unattached, still
    // running" shape the design's occupancy predicate must still
    // count (verdict arbitration §2.1: detached sessions occupy
    // their slot; only `closed_at().is_none()` gates the count, never
    // attach state).
    drop(h);
    assert_eq!(
        broker
            .open_as(&SessionSpec::default(), "device:a")
            .unwrap_err(),
        BrokerError::QuotaExceeded(QuotaKind::SessionsPerPrincipal)
    );
    within(broker.close(&id, CloseReason::Closed, None))
        .await
        .unwrap();
    assert!(broker.open_as(&SessionSpec::default(), "device:a").is_ok());
}
