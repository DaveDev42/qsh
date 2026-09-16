use super::*;

#[test]
fn bind_precedence_flag_then_config_then_default() {
    let mut config = Config::default();
    assert_eq!(
        resolve_bind(None, &config).unwrap(),
        crate::serve::DEFAULT_BIND.parse::<SocketAddr>().unwrap()
    );
    config.listen.bind = Some("127.0.0.1:5001".into());
    assert_eq!(
        resolve_bind(None, &config).unwrap(),
        "127.0.0.1:5001".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        resolve_bind(Some("127.0.0.1:6001"), &config).unwrap(),
        "127.0.0.1:6001".parse::<SocketAddr>().unwrap()
    );
    let err = resolve_bind(Some("not an address"), &config).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn diag_host_bounds_an_oversized_offered_name() {
    assert_eq!(diag_host(""), "-");
    assert_eq!(diag_host("widget"), "widget");
    let huge = "a".repeat(10_000);
    let bounded = diag_host(&huge);
    assert_eq!(bounded.chars().count(), OFFERED_NAME_DIAG_MAX_CHARS);
}

#[test]
fn registration_event_json_line_has_the_documented_field_set() {
    let with_generation = serde_json::to_string(&RegistrationEvent {
        event: "registered",
        host: "personal-mac",
        fingerprint: "sha256:abc",
        generation: Some(0),
    })
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&with_generation).unwrap();
    assert_eq!(parsed["event"], "registered");
    assert_eq!(parsed["host"], "personal-mac");
    assert_eq!(parsed["fingerprint"], "sha256:abc");
    assert_eq!(parsed["generation"], 0);

    let without_generation = serde_json::to_string(&RegistrationEvent {
        event: "denied",
        host: "-",
        fingerprint: "sha256:abc",
        generation: None,
    })
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&without_generation).unwrap();
    assert_eq!(parsed["event"], "denied");
    assert!(parsed.get("generation").is_none());
}

#[test]
fn registration_event_json_line_covers_the_expired_event() {
    // Step 4 addition: `Listen::run_stale_sweeper` emits this on the
    // same tracing target/shape as every other `RegistrationEvent`.
    let line = serde_json::to_string(&RegistrationEvent {
        event: "expired",
        host: "personal-mac",
        fingerprint: "sha256:abc",
        generation: Some(3),
    })
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed["event"], "expired");
    assert_eq!(parsed["generation"], 3);
}

fn test_listen() -> Arc<Listen> {
    let registry = Registry::new(Arc::new(SystemClock), false);
    Listen::new(
        registry,
        Arc::new(AllowAllPinned),
        Arc::new(crate::audit::NullAuditSink),
        "hermes",
        Arc::new(SystemClock),
        Duration::from_secs(120),
    )
}

/// [`test_listen`], but with caller-chosen [`crate::quota::
/// QuotaLimits`] — the M8 Step 3b S4 twin of `crate::server::tests::
/// rig_with_quota_limits` for this controller's own, independent
/// accept-arm quota tracker (ruling R6).
fn test_listen_with_quotas(quota_limits: crate::quota::QuotaLimits) -> Arc<Listen> {
    let clock = Arc::new(SystemClock);
    let registry = Registry::new(clock.clone(), false);
    let admission = crate::admission::Gate::new(
        clock.clone(),
        crate::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
        crate::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
        crate::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
    );
    let quotas = crate::quota::Quotas::new(quota_limits, clock.clone());
    Listen::with_admission_and_quotas(
        registry,
        Arc::new(AllowAllPinned),
        Arc::new(crate::audit::NullAuditSink),
        "hermes",
        clock,
        Duration::from_secs(120),
        STALE_SWEEP_TICK,
        admission,
        quotas,
    )
}

/// M8 Step 3b ruling R6: this controller's `quotas` is its own,
/// independent accept-arm tracker — constructed once, from the
/// caller's own `QuotaLimits`, not shared with any
/// `crate::server::Server` that might run in the same process.
#[test]
fn listen_is_wired_with_its_own_independent_quota_limits() {
    let listen = test_listen_with_quotas(crate::quota::QuotaLimits {
        max_connections: 1,
        ..crate::quota::QuotaLimits::default()
    });
    let _first = listen.quotas.reserve_connection("device:a").unwrap();
    assert_eq!(
        listen.quotas.reserve_connection("device:b").unwrap_err(),
        crate::quota::QuotaKind::Connections
    );
}

/// M8 Step 3b arbitration A2/B5 (overturns R3 for this arm — see
/// [`Listen::decide_registration`]'s own doc comment for why): the
/// connection-quota refusal is consulted only *after* [`admit`] — the
/// `host.reverse` ACL choke point — has already allowed the
/// registration, never before it. An allow that is then discarded for
/// quota reasons must roll back the entry `admit` just inserted, so
/// this also asserts the registry shows nothing live under the
/// offered name once the `RESOURCE_EXHAUSTED` reply has gone out —
/// not just that `RegisterOutcome` stayed out of `outcome_cell`
/// (`decide_registration_refuses_on_a_quota_kind_before_inspecting_
/// hello_reverse`'s original assertion, kept, since the "never
/// populate a RegisterOutcome" guarantee this test's predecessor
/// establishes still holds under the new order).
#[tokio::test]
async fn decide_registration_refuses_on_a_quota_kind_after_the_acl_choke_point_without_registering()
{
    let clock = Arc::new(SystemClock);
    let registry = Registry::new(clock.clone(), true);
    let admission = crate::admission::Gate::new(
        clock.clone(),
        crate::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
        crate::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
        crate::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
    );
    let quotas = crate::quota::Quotas::new(crate::quota::QuotaLimits::default(), clock.clone());
    let listen = Listen::with_admission_and_quotas(
        registry,
        Arc::new(AllowAllPinned),
        Arc::new(crate::audit::NullAuditSink),
        "hermes",
        clock,
        Duration::from_secs(120),
        STALE_SWEEP_TICK,
        admission,
        quotas,
    );
    let outcome_cell: Mutex<Option<RegisterOutcome>> = Mutex::new(None);
    // Unlike the predecessor test, `Hello.reverse` must be a genuine,
    // admissible registration — the quota refusal now only matters
    // once `admit` has actually said yes.
    let hello = Hello {
        versions: Vec::new(),
        device_name: String::new(),
        capabilities: Vec::new(),
        reverse: Some(wire::ReverseRegistration {
            offered_name: "adv-fixer".to_string(),
            capabilities: Vec::new(),
        }),
    };
    let (_client, conn) = crate::tunnel::testutil::loopback_pair().await;
    let err = listen
        .decide_registration(
            &conn,
            &hello,
            &outcome_cell,
            Some(crate::quota::QuotaKind::Connections),
        )
        .expect_err("a refused connection quota must never register");
    assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
    assert_eq!(err.message, "connection quota exceeded");
    assert!(err.retryable);
    assert!(
        outcome_cell.into_inner().unwrap().is_none(),
        "a quota refusal must never populate a RegisterOutcome"
    );
    // The registry is keyed by the name `admit()` resolves (the pinned
    // device name, not `offered_name`), so the pin looks at the whole
    // table rather than guessing the key: main-session spot-check found
    // a `get("adv-fixer")` assertion here passing with the rollback
    // deleted, because the leftover row was `("laptop", 0)`.
    assert!(
        listen.registry().snapshot().is_empty(),
        "the ACL-allowed registration admit() inserted must be rolled back, not left \
         live behind a RESOURCE_EXHAUSTED reply: {:?}",
        listen.registry().snapshot()
    );

    // Same pin for the `replaced` half of `Registry::rollback`: a live
    // registration that a refused re-registration would have replaced
    // must come back exactly as it was (same generation), not vanish.
    let live_cell: Mutex<Option<RegisterOutcome>> = Mutex::new(None);
    listen
        .decide_registration(&conn, &hello, &live_cell, None)
        .expect("an unrefused registration on an empty controller must succeed");
    let before: Vec<(String, u64)> = listen
        .registry()
        .snapshot()
        .iter()
        .map(|e| (e.name.clone(), e.generation))
        .collect();
    assert_eq!(
        before.len(),
        1,
        "exactly one live registration expected: {before:?}"
    );
    // `register_connection` is what publishes the live occupant into
    // `conns` in production; `rollback_target` only trusts the
    // replaced snapshot while that occupant is still there, so mirror
    // it here — otherwise the restore path is (correctly) skipped and
    // this half of the test would be measuring the phantom-host guard
    // instead of the rollback.
    listen
        .conns
        .publish(before[0].0.clone(), before[0].1, conn.clone());
    let refused_cell: Mutex<Option<RegisterOutcome>> = Mutex::new(None);
    let err = listen
        .decide_registration(
            &conn,
            &hello,
            &refused_cell,
            Some(crate::quota::QuotaKind::Connections),
        )
        .expect_err("a refused re-registration must not replace the live entry");
    assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
    assert!(refused_cell.into_inner().unwrap().is_none());
    let after: Vec<(String, u64)> = listen
        .registry()
        .snapshot()
        .iter()
        .map(|e| (e.name.clone(), e.generation))
        .collect();
    assert_eq!(
        after, before,
        "the entry the refused registration replaced must be restored unchanged"
    );
}

/// M8 Step 3b arbitration A2/B5 — the oracle regression: a peer
/// `DenyEverything` would refuse anyway must get the identical answer
/// whether the controller is idle or at its connection cap. Ported
/// from adversary A's reproduction
/// (`adv_a_a_denied_registration_learns_whether_the_controller_is_full`,
/// `adv-A/repo/crates/qsh-core/src/reverse/listen.rs` ~4691),
/// unmodified apart from the name: `idle == full == PermissionDenied`
/// is the assertion the arbitration ruling picked (option 1, "code
/// follows the doc"), not the inverted "these must differ" shape the
/// original defect made pass.
#[tokio::test]
async fn a_denied_registration_cannot_learn_whether_the_controller_is_full() {
    struct DenyEverything;
    impl crate::acl::Authorizer for DenyEverything {
        fn check(
            &self,
            _: &qsh_transport::Principal,
            _: qsh_transport::AuthPath,
            _: crate::acl::Action,
            _: crate::acl::ResourceRef<'_>,
        ) -> crate::acl::Verdict {
            crate::acl::Verdict {
                decision: crate::acl::Decision::Deny,
                rule: None,
            }
        }
    }
    let clock = Arc::new(SystemClock);
    let listen = Listen::new(
        Registry::new(clock.clone(), true),
        Arc::new(DenyEverything),
        Arc::new(crate::audit::NullAuditSink),
        "hermes",
        clock,
        Duration::from_secs(120),
    );
    let (_client, conn) = crate::tunnel::testutil::loopback_pair().await;
    let hello = Hello {
        versions: Vec::new(),
        device_name: String::new(),
        capabilities: Vec::new(),
        reverse: Some(wire::ReverseRegistration {
            offered_name: "adv-a".to_string(),
            capabilities: Vec::new(),
        }),
    };
    let idle_cell: Mutex<Option<RegisterOutcome>> = Mutex::new(None);
    let idle = listen
        .decide_registration(&conn, &hello, &idle_cell, None)
        .expect_err("a denied registration must be refused");
    let full_cell: Mutex<Option<RegisterOutcome>> = Mutex::new(None);
    let full = listen
        .decide_registration(
            &conn,
            &hello,
            &full_cell,
            Some(crate::quota::QuotaKind::Connections),
        )
        .expect_err("a denied registration must be refused");
    assert_eq!(idle.error_code(), ErrorCode::PermissionDenied);
    assert_eq!(
        full.error_code(),
        idle.error_code(),
        "the same ACL-denied registration must not answer differently once the \
         controller is at capacity (that answer is a saturation oracle): idle={:?} full={:?}",
        idle.error_code(),
        full.error_code()
    );
}

/// M8 Step 3b arbitration A1(3)/A5: a `qsh listen` registration
/// driven through the real accept path (`Listen::register_connection`,
/// same call [`Listen::accept_and_register_permitted`] makes) must
/// hold exactly one per-principal connection slot while it is live
/// and give it back once the connection ends — the Listen-arm twin of
/// `crate::server::tests::a_served_connection_holds_and_returns_its_
/// connection_slot`, closing the gap A5 named ("this controller's own
/// permit lifetime is unwatched inside qsh-core, only from a
/// testkit e2e").
#[tokio::test]
async fn a_registered_controller_connection_holds_and_returns_its_connection_slot() {
    let listen = test_listen_with_quotas(crate::quota::QuotaLimits {
        max_connections_per_principal: 1,
        ..crate::quota::QuotaLimits::default()
    });
    let (client, conn) = crate::tunnel::testutil::loopback_pair().await;
    let opener = crate::acl::opener_key(conn.principal(), conn.auth_path());
    let quota_permit = listen
        .quotas
        .reserve_connection(&opener)
        .expect("the cap is empty at the start of the test");
    let listen_task = listen.clone();
    let server_side = tokio::spawn(async move {
        listen_task
            .register_connection(conn, Some(quota_permit), None)
            .await
    });

    let local_hello = Hello {
        versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
        device_name: "fixer".to_string(),
        capabilities: Vec::new(),
        reverse: Some(wire::ReverseRegistration {
            offered_name: "adv-fixer-slot".to_string(),
            capabilities: Vec::new(),
        }),
    };
    let (ctl, _peer_hello) = crate::handshake::initiate(&client, local_hello)
        .await
        .expect("the registration must succeed under an empty quota");
    assert_eq!(
        listen.quotas.connections_per_principal_in_use(&opener),
        1,
        "a live registered connection must hold exactly one connection slot"
    );

    drop(ctl);
    drop(client);
    server_side
        .await
        .expect("register_connection must not panic");
    assert_eq!(
        listen.quotas.connections_per_principal_in_use(&opener),
        0,
        "the connection slot must be released once the connection is over"
    );
}

/// M8 Step 3b arbitration B4: `Listen::run`'s periodic tick must flush
/// its own `quotas` audit window the same bounded-latency way the
/// shutdown tail already does — S5 fixed exactly this gap, and this
/// pins it. A quota rejection opens a window on the first call and
/// only *suppresses* further rejections inside the same
/// [`crate::admission::AUDIT_AGGREGATION_WINDOW`]; nothing closes that
/// window into a summary record until either another rejection lands
/// after the window has gone stale, or a periodic tick does it first
/// — this test forces the second path with `tokio::time::advance`
/// under `#[tokio::test(start_paused = true)]`, never a real 10 s
/// sleep (`docs/design/testing.md` L2).
#[tokio::test(start_paused = true)]
async fn listen_run_flushes_its_quota_audit_window_on_the_periodic_tick() {
    let clock = Arc::new(SystemClock);
    let registry = Registry::new(clock.clone(), false);
    let admission = crate::admission::Gate::new(
        clock.clone(),
        crate::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
        crate::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
        crate::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
    );
    let quotas = crate::quota::Quotas::new(crate::quota::QuotaLimits::default(), clock.clone());
    let audit = Arc::new(crate::audit::MemoryAuditSink::new());
    let listen = Listen::with_admission_and_quotas(
        registry,
        Arc::new(AllowAllPinned),
        audit.clone(),
        "hermes",
        clock,
        Duration::from_secs(120),
        STALE_SWEEP_TICK,
        admission,
        quotas,
    );

    let (server_id, _fp) = crate::tunnel::testutil::self_signed();
    let listener = qsh_transport::Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_id,
        Arc::new(qsh_transport::StaticTrust::empty()),
    )
    .expect("bind a loopback listener");
    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let listen_task = listen.clone();
    let _run = tokio::spawn(async move {
        listen_task
            .run(listener, async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    // One immediate rejection (opens the window, its own first-line
    // record written the same way `accept_and_register_permitted`
    // does at its real call site) plus two more within the same
    // window (each only increments `suppressed`, per
    // `Quotas::record_rejection`'s own doc) — the shape that makes
    // the tick's flush produce an observable summary record, not just
    // silently closing an empty window.
    let now = listen.quotas.now();
    let peer_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let first = listen.quotas.record_rejection(
        crate::quota::QuotaKind::Connections,
        "device:flush-probe",
        peer_addr,
        now,
        None,
        qsh_transport::AuthPath::Pin,
    );
    assert_eq!(
        first.len(),
        1,
        "the first rejection of a fresh window audits its own line"
    );
    assert_eq!(
        first[0].peer_addr,
        peer_addr.to_string(),
        "R4 — the connection axis's quota deny record must carry the live peer"
    );
    assert_eq!(
        first[0].request_id, "-",
        "R9 — the connection axis has no control request id"
    );
    crate::audit::write_quota_audit(audit.as_ref(), &first);
    for _ in 0..2 {
        let suppressed = listen.quotas.record_rejection(
            crate::quota::QuotaKind::Connections,
            "device:flush-probe",
            peer_addr,
            listen.quotas.now(),
            None,
            qsh_transport::AuthPath::Pin,
        );
        assert!(
            suppressed.is_empty(),
            "a rejection inside the same aggregation window must only be suppressed"
        );
    }
    assert!(
        audit
            .records()
            .iter()
            .any(|r| r.resource == "quota_connections_host" && r.count.is_none()),
        "the first rejection's own line must already be in the sink"
    );

    // Past the aggregation window, and past at least one of `Listen::
    // run`'s own audit-flush ticks (same period).
    tokio::time::advance(crate::admission::AUDIT_AGGREGATION_WINDOW + Duration::from_secs(2)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
        if audit
            .records()
            .iter()
            .any(|r| r.resource == "quota_connections_host" && r.count == Some(2))
        {
            break;
        }
    }
    assert!(
        audit
            .records()
            .iter()
            .any(|r| r.resource == "quota_connections_host" && r.count == Some(2)),
        "the periodic tick must flush the stale window into a summary record, not only \
         the shutdown tail — got {:?}",
        audit.records()
    );
}

/// [`test_listen`], but on an injectable [`crate::broker::TestClock`]
/// shared between the registry and `Listen` itself — the same sharing
/// [`Listen::new`]'s own doc requires of every caller — so
/// [`Listen::control_hub_wait`]'s poll loop advances only when a test
/// calls [`crate::broker::TestClock::advance`], never on real wall
/// time (`docs/design/testing.md` L2, `PLAN.md` M3 Step 8 (c)).
#[cfg(unix)]
fn test_listen_with_clock(clock: Arc<crate::broker::TestClock>) -> Arc<Listen> {
    let registry = Registry::new(clock.clone(), false);
    Listen::new(
        registry,
        Arc::new(AllowAllPinned),
        Arc::new(crate::audit::NullAuditSink),
        "hermes",
        clock,
        Duration::from_secs(120),
    )
}

/// Registers `name` in `listen`'s registry (so
/// [`Listen::control_hub_wait`] does not take its "name unknown, stop
/// waiting" exit early) and returns the `generation` the registry
/// assigned — the first admission under a fresh name, always `0`
/// ([`ConnTable`]'s own doc: "starting from a pre-existing occupant at
/// generation `0`").
#[cfg(unix)]
fn admit(listen: &Listen, name: &str) -> u64 {
    listen
        .registry()
        .admit(
            name.to_string(),
            registry::AdmittedEntry {
                fingerprint: "sha256:test",
                principal: "device:test",
                address: "127.0.0.1:4433".parse().unwrap(),
                capabilities: vec![],
            },
        )
        .expect("registers")
        .entry
        .generation
}

/// Publishes a bare [`ControlHub`] at `generation` under `name` —
/// exactly what [`Listen::finish_registration`] does after a real
/// `LOCAL_CONTROL` registration handshake, minus the handshake itself
/// (`PLAN.md` M3 Step 8 (c)'s unit tests exercise
/// [`Listen::control_hub_wait`] directly, not the daemon frame loop
/// around it — that path is covered at L3 by
/// `crates/qsh-testkit/tests/local_control_reverse.rs`).
#[cfg(unix)]
fn publish_hub(listen: &Listen, name: &str, generation: u64) -> Arc<ControlHub> {
    let hub = ControlHub::new(
        name.to_string(),
        "sha256:test".to_string(),
        generation,
        vec![],
    );
    listen
        .hubs
        .publish(name.to_string(), generation, hub.clone());
    hub
}

/// **L2 — old generation never satisfies the wait.**
///
/// `PLAN.md` M3 Step 8 (c): "옛 `generation`의 등록으로는 진행하지 않음".
/// A hub is live under `name`, but still sitting at exactly the
/// generation [`LocalReconnect`] already rode to death — the dead
/// registration the recovery exists to wait *past*, not settle for.
/// [`Listen::control_hub_wait`] must not resolve on it: it stays
/// pending across several of its own poll ticks, and once the
/// deadline elapses with nothing newer ever registering, it gives up
/// with `None` — the same outcome
/// `crate::localctl::daemon`'s `LOCAL_CONTROL` serve path turns into
/// `ErrorCode::HostNotFound` (daemon.rs's own doc on this call site).
#[cfg(unix)]
#[tokio::test]
async fn control_hub_wait_does_not_resolve_on_a_registration_still_at_the_known_generation() {
    let clock = Arc::new(crate::broker::TestClock::new());
    let listen = test_listen_with_clock(clock.clone());
    let known_generation = admit(&listen, "widget");
    publish_hub(&listen, "widget", known_generation);

    let deadline = Duration::from_millis(500);
    let waiter = {
        let listen = listen.clone();
        tokio::spawn(async move {
            listen
                .control_hub_wait("widget", Some(known_generation), deadline)
                .await
        })
    };

    // Several poll ticks' worth of clock movement, still short of the
    // deadline: the still-at-`known_generation` hub must not have
    // resolved the wait.
    for _ in 0..3 {
        clock.advance(HUB_WAIT_POLL);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }
    assert!(
        !waiter.is_finished(),
        "a hub still at the known generation must not satisfy the wait"
    );

    // Past the deadline, with nothing newer ever having registered.
    clock.advance(deadline);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    let outcome = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("control_hub_wait must give up once its deadline elapses")
        .expect("the wait task did not panic");
    assert!(
        outcome.is_none(),
        "an old-generation-only registration must time out to None, not resolve"
    );
}

/// **L2 — a within-window newer generation resolves the wait.**
///
/// `PLAN.md` M3 Step 8 (c): "새 generation 등록을 기다렸다가... 대기하고".
/// The same scenario as the previous test, except a strictly newer
/// generation registers before the deadline — [`LocalReconnect`]'s own
/// production path, driven here without a real target re-dial or a
/// real daemon frame loop (`docs/design/protocol.md` §11-4's mapping
/// paragraph: "controller의 attach driver는 새 세대 등록을 기다린다").
#[cfg(unix)]
#[tokio::test]
async fn control_hub_wait_resolves_once_a_strictly_newer_generation_registers() {
    let clock = Arc::new(crate::broker::TestClock::new());
    let listen = test_listen_with_clock(clock.clone());
    let known_generation = admit(&listen, "widget");
    publish_hub(&listen, "widget", known_generation);

    let deadline = Duration::from_secs(5);
    let waiter = {
        let listen = listen.clone();
        tokio::spawn(async move {
            listen
                .control_hub_wait("widget", Some(known_generation), deadline)
                .await
        })
    };

    // Let the wait take its first poll and go to sleep on the
    // still-stale hub, well short of the deadline.
    clock.advance(HUB_WAIT_POLL);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!waiter.is_finished(), "must still be waiting");

    // The target's own re-dial lands as a new registration generation.
    let new_generation = known_generation + 1;
    let published = publish_hub(&listen, "widget", new_generation);

    // One more poll tick wakes the loop onto the fresh hub.
    clock.advance(HUB_WAIT_POLL);
    let hub = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("control_hub_wait must resolve once a newer generation is live")
        .expect("the wait task did not panic")
        .expect("a strictly newer generation must satisfy the wait");
    assert_eq!(
        hub.generation, new_generation,
        "the resolved hub must be the newer generation, not the old one"
    );
    assert!(
        Arc::ptr_eq(&hub, &published),
        "must be the same hub instance published"
    );
}

/// **L2 — window-exceeded with no registration at all times out.**
///
/// `PLAN.md` M3 Step 8 (b): "창이 지나면 `HOST_NOT_FOUND`". No hub is
/// ever published under `name` (the target never re-dials within the
/// window) — [`Listen::control_hub_wait`] keeps polling, because the
/// registry still knows the name (it went stale, not gone), and gives
/// up at exactly its deadline rather than early or late.
#[cfg(unix)]
#[tokio::test]
async fn control_hub_wait_times_out_when_nothing_ever_registers() {
    let clock = Arc::new(crate::broker::TestClock::new());
    let listen = test_listen_with_clock(clock.clone());
    // Registered (so the registry-gone early exit does not fire), but
    // no `ControlHub` is ever published — the registration went stale
    // and nothing re-dialed.
    admit(&listen, "widget");

    let deadline = Duration::from_millis(300);
    let waiter = {
        let listen = listen.clone();
        tokio::spawn(async move { listen.control_hub_wait("widget", None, deadline).await })
    };

    for _ in 0..2 {
        clock.advance(HUB_WAIT_POLL);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }
    assert!(!waiter.is_finished(), "must still be within the deadline");

    clock.advance(deadline);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    let outcome = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("control_hub_wait must give up once its deadline elapses")
        .expect("the wait task did not panic");
    assert!(
        outcome.is_none(),
        "no registration within the window must time out to None (daemon maps this to \
         HostNotFound, `crate::localctl::daemon`'s LOCAL_CONTROL serve path)"
    );
}

#[tokio::test]
async fn listen_wires_device_name_and_starts_with_no_live_connections() {
    let listen = test_listen();
    assert_eq!(listen.local_hello().device_name, "hermes");
    assert!(listen.local_hello().reverse.is_none());
    assert_eq!(listen.live_connections(), 0);
    assert!(listen.registry().snapshot().is_empty());
}

/// `Listen::run_stale_sweeper` — `docs/design/testing.md` L2, no real
/// `sleep()` — removes a stale, retention-expired entry and stops on
/// its own once the last `Arc<Listen>` drops. Both the registry's
/// retention clock and the sweeper's own tick pacing are
/// [`SystemClock`], which is `tokio::time::pause()`-steerable
/// (`broker::clock`'s module docs) — the exact shape
/// `broker::run_reaper_uses_the_injected_clock_and_stops_with_the_broker`
/// already establishes for the sibling reaper.
#[tokio::test(start_paused = true)]
async fn run_stale_sweeper_removes_a_retention_expired_entry() {
    let listen = test_listen();
    let outcome = listen
        .registry()
        .admit(
            "widget".to_string(),
            registry::AdmittedEntry {
                fingerprint: "sha256:a",
                principal: "device:widget",
                address: "127.0.0.1:4433".parse().unwrap(),
                capabilities: vec![],
            },
        )
        .expect("registers");
    listen
        .registry()
        .mark_stale("widget", outcome.entry.generation)
        .expect("goes stale");

    let sweeper = tokio::spawn(Listen::run_stale_sweeper(Arc::downgrade(&listen)));

    // Retention (120s) hasn't elapsed yet — still present, across
    // several of the sweeper's own ticks.
    tokio::time::advance(Duration::from_secs(60)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(listen.registry().get("widget").is_some(), "not due yet");

    // Past retention, and past at least one more of the sweeper's own
    // ticks.
    tokio::time::advance(Duration::from_secs(61) + STALE_SWEEP_TICK).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
        if listen.registry().get("widget").is_none() {
            break;
        }
    }
    assert!(listen.registry().get("widget").is_none(), "swept away");

    drop(listen);
    tokio::time::advance(STALE_SWEEP_TICK).await;
    tokio::time::timeout(Duration::from_secs(5), sweeper)
        .await
        .expect("sweeper must stop once the last Arc<Listen> drops")
        .unwrap();
}

/// `PLAN.md` M3 Step 5 (a): the localctl socket this process bound must
/// not outlive it. Drives the real `run_listen`/`run_listen_unix` end
/// to end — a genuine on-disk identity via `identity::init`/
/// `identity::load` (`File` key-store mode, so nothing touches an OS
/// credential store) — rather than constructing `Listen` directly the
/// way `qsh_testkit::reverse::ReverseHarness` does, because this test
/// is specifically about `run_listen_unix`'s own composition of the
/// localctl accept loop with the QUIC one's drain, which `ReverseHarness`
/// does not build at all (it calls `Listen::new`/`Listen::run` straight,
/// never `run_listen`/`LocalctlListener`).
#[cfg(unix)]
#[tokio::test]
async fn run_listen_unix_unlinks_its_localctl_socket_on_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    // `.with_runtime_dir` pins the localctl socket inside this test's
    // own tempdir, independent of `$XDG_RUNTIME_DIR` — otherwise this
    // and the sibling test below both bind at
    // `$XDG_RUNTIME_DIR/qsh/<this-process's-pid>.sock` (both tests
    // share one process pid under plain `cargo test`), racing each
    // other's bind/unlink and leaking into the real runtime directory
    // (adversarial review finding).
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    crate::identity::init(&paths, qsh_proto::KeyStoreMode::File).expect("identity::init");
    let identity = crate::identity::load(&paths)
        .expect("identity::load")
        .expect("identity was just created");

    let socket_path = paths.localctl_socket(std::process::id());

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel::<()>();
    let run_paths = paths.clone();
    let task = tokio::spawn(async move {
        run_listen(
            &run_paths,
            &Config::default(),
            identity,
            Some("127.0.0.1:0"),
            move |_addr| {
                let _ = bound_tx.send(());
            },
            // No acl.toml in this test's tempdir: the missing-policy
            // diagnostic fires, but this test is about the localctl
            // socket's lifecycle, not authorization, so the rendered
            // text is discarded.
            |_diag| {},
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });

    bound_rx.await.expect("qsh listen bound");
    assert!(
        socket_path.exists(),
        "localctl socket must exist once the daemon is up"
    );

    let _ = shutdown_tx.send(());
    task.await
        .expect("run_listen task did not panic")
        .expect("run_listen exits cleanly on shutdown");

    assert!(
        !socket_path.exists(),
        "localctl socket must be unlinked once shutdown has drained"
    );
}

/// `PLAN.md` M3 Step 5 (a): "unlinks the socket on every exit path", not
/// only the clean-shutdown one the previous test covers. Corrupts
/// `trust.toml` so `SharedTrustStore::open` — the first fallible step
/// *after* `LocalctlListener::bind` already created the socket file —
/// fails startup outright; the socket must still not be left behind.
#[cfg(unix)]
#[tokio::test]
async fn run_listen_unix_unlinks_its_localctl_socket_when_startup_fails_after_binding_it() {
    let dir = tempfile::tempdir().unwrap();
    // See the sibling test above for why `.with_runtime_dir` is
    // required here rather than optional.
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    crate::identity::init(&paths, qsh_proto::KeyStoreMode::File).expect("identity::init");
    let identity = crate::identity::load(&paths)
        .expect("identity::load")
        .expect("identity was just created");

    // Written after `identity::init` (which creates `config_dir`) so
    // this lands exactly where `Paths::trust_file` looks — malformed
    // TOML, not a missing file, since a missing trust file is a normal
    // empty store (`TrustStore::load`), not a startup failure.
    std::fs::write(paths.trust_file(), b"this is not valid toml [[[").unwrap();

    let socket_path = paths.localctl_socket(std::process::id());
    assert!(
        !socket_path.exists(),
        "nothing has bound this pid's socket yet"
    );

    let err = run_listen(
        &paths,
        &Config::default(),
        identity,
        Some("127.0.0.1:0"),
        |_addr| panic!("must fail before the QUIC listener ever reports bound"),
        |_diag| panic!("must fail before the policy diagnostic is ever composed"),
        std::future::pending::<()>(),
    )
    .await
    .expect_err("a corrupt trust store must fail startup");
    assert_eq!(err.code, ErrorCode::ConfigError);

    assert!(
        !socket_path.exists(),
        "the localctl socket bound before the failing step must not survive it"
    );
}

/// `docs/CLI.md` §6.13's Windows gate, mechanically: `run_listen`
/// refuses on every non-unix target before it ever touches its
/// arguments (module docs on [`windows_unsupported`]), so the
/// identity/paths/config below are throwaway. This is the positive
/// Windows-leg assertion `PLAN.md` Step 3 (d) owes ("Windows leg의
/// nextest green … 나머지가 컴파일·통과") — a real `#[tokio::test]` that
/// runs and passes on the Windows CI leg, not just an absence of a
/// compile error there.
#[cfg(not(unix))]
#[tokio::test]
async fn run_listen_is_unsupported_on_non_unix() {
    let identity = LoadedIdentity {
        identity: crate::identity::Identity {
            device_id: "device".into(),
            fingerprint: qsh_transport::Fingerprint::of_spki_der(&[]),
            key_store: qsh_proto::KeyStoreKind::File,
            created_at: "2026-01-01T00:00:00Z".into(),
            cert_der: Vec::new(),
            issued_by_ca: None,
        },
        local: qsh_transport::LocalIdentity {
            cert_chain: Vec::new(),
            key_pkcs8_der: zeroize::Zeroizing::new(Vec::new()),
        },
    };
    let paths = Paths::new("unused-config", "unused-state");
    let err = run_listen(
        &paths,
        &Config::default(),
        identity,
        None,
        |_addr| {},
        |_diag| {},
        std::future::pending::<()>(),
    )
    .await
    .expect_err("non-unix must refuse to run");
    assert_eq!(err.code, ErrorCode::Unsupported);
}

// ------------------------------------------------------------------
// Tunnel relay registry (`PLAN.md` M4 Step 5, PR 5a). `PLAN.md`'s own
// framing: "the central risk of this PR is silent misdelivery" — a
// `forward_id` resolving to the wrong conduit's splice is a security
// incident, not a bug. These tests exercise
// [`ControlHub::deliver_tcp_accepted`]/[`ControlHub::claim_tcp_accepted`]/
// [`ControlHub::unregister_conduit`] and [`Listen::handle_tcp_accepted_stream`]
// directly — the full wire-level round trip through a real reverse
// connection and daemon `LOCAL_STREAM` conduit is
// `crates/qsh-testkit/tests/reverse_tunnel.rs`'s job (L3), not this
// crate's unit tests (the same split `local_stream_at_the_stream_pools_cap_...`
// above already draws for `LOCAL_STREAM`'s own cap).
// ------------------------------------------------------------------

#[cfg(unix)]
fn test_hub() -> Arc<ControlHub> {
    ControlHub::new("widget".into(), "sha256:test".into(), 1, Vec::new())
}

/// A `TCP_ACCEPTED` naming a `forward_id` this hub never registered —
/// never opened, already closed, or its owner already dead — must be
/// refused by [`ControlHub::deliver_tcp_accepted`] itself, before
/// anything is queued: `PLAN.md`'s "an unknown ... forward_id causes
/// a stream reset and nothing else". The rejected [`TunnelArrival`]
/// comes straight back to the caller (never silently dropped —
/// [`ControlHub::deliver_tcp_accepted`]'s own doc on why a bare drop
/// here would be wrong), and the registry gained no trace of the
/// unknown id.
#[cfg(unix)]
#[tokio::test]
async fn deliver_tcp_accepted_refuses_an_unregistered_forward_id_and_queues_nothing() {
    let hub = test_hub();
    let (client, _server) = crate::tunnel::testutil::loopback_pair().await;
    let (send, recv) = client.open_bi().await.unwrap();
    let permit = hub
        .try_acquire_tunnel_permit()
        .expect("a fresh hub is under its cap");

    let rejected = hub
        .deliver_tcp_accepted("never-registered", send, recv, Vec::new(), permit)
        .expect_err("an unregistered forward_id must never be queued");
    assert!(hub.forward_owner("never-registered").is_none());

    // The caller (here, standing in for `handle_tcp_accepted_stream`'s
    // own rejection path) is responsible for resetting it — prove the
    // handles really did come back usable, not consumed.
    rejected.reset(0x9999);
}

/// **The central proof this whole registry exists for**
/// (`PLAN.md` M4 Step 5 (a)): a `forward_id` registered by one conduit
/// never resolves to a different conduit's claim, even when a real
/// arrival is sitting in the hub's queue for the *other* id at the
/// exact moment of the claim. Two conduits, two distinct
/// `forward_id`s, one arrival delivered only for the first — the
/// second conduit's claim on its own id must see nothing, and the
/// first conduit's claim on its own id must see exactly the arrival
/// it registered.
#[cfg(unix)]
#[tokio::test]
async fn a_forward_id_never_resolves_to_a_different_conduits_registration() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-a", conduit_a);
    let token_b = hub.register_forward_for_test("fid-b", conduit_b);

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut target_send, target_recv) = client.open_bi().await.unwrap();
    // A QUIC peer only learns a stream exists once a frame referencing
    // it actually arrives — `accept_bi` below would otherwise block
    // forever waiting on a stream the client never told it about.
    target_send.write_all(b"x").await.unwrap();
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
    drop(target_send);
    drop(target_recv);
    let permit = hub.try_acquire_tunnel_permit().unwrap();
    assert!(
        hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
            .is_ok(),
        "fid-a is registered to conduit_a, so this must be accepted"
    );

    // conduit_b's own id must not see conduit_a's arrival, however
    // briefly it waits.
    let claimed_by_b = hub
        .claim_tcp_accepted("fid-b", &token_b, Duration::from_millis(50))
        .await;
    assert!(
        claimed_by_b.is_none(),
        "fid-b must never resolve to fid-a's queued arrival"
    );

    // fid-a's own claim still succeeds — proving the arrival really
    // was queued, just never reachable under the wrong id.
    let claimed_by_a = hub
        .claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(50))
        .await;
    assert!(
        claimed_by_a.is_some(),
        "fid-a's own claim must still see the arrival it registered"
    );
}

// ------------------------------------------------------------------
// `LocalTunnelList`/`LocalTunnelClose` (`PLAN.md` M4 Step 5 PR 5b) —
// `list_forwards`/`admin_close_forward`'s own registry-level behavior.
// The full wire-level round trip through a real localctl daemon and
// `Ops::tunnel_list`/`Ops::tunnel_close` is
// `crates/qsh-testkit/tests/reverse_tunnel.rs`'s
// `tunnel_list_and_close_manage_a_daemon_held_remote_forward` (L3), not
// this crate's unit tests.
// ------------------------------------------------------------------

/// [`ControlHub::list_forwards`] answers with exactly the structural
/// fields [`ForwardSummary`] declares — `forward_id`/`mode`/`bind`/
/// `actual_port`/`forward_to` — and nothing else: the type itself has
/// no field a claim token (or any other capability/payload byte)
/// could ever ride in, so `crate::localctl::daemon`'s `LocalTunnelList`
/// handling built on top of it structurally cannot leak one either
/// (`docs/design/testing.md` L2's "never leaks tokens/payload").
/// [`ControlHub::register_forward_for_test`]'s own token — a fresh
/// random ULID, distinct from every hardcoded field below — is
/// asserted absent from every string field as a belt-and-suspenders
/// runtime check on top of that type-level guarantee.
#[cfg(unix)]
#[tokio::test]
async fn list_forwards_reports_only_structural_fields_never_the_claim_token() {
    let hub = test_hub();
    let (conduit, _rx) = hub.register_conduit();
    let token = hub.register_forward_for_test("fid-list", conduit);
    let token_text = String::from_utf8(token).expect("test token is ASCII");

    let forwards = hub.list_forwards();
    assert_eq!(forwards.len(), 1);
    let summary = &forwards[0];
    assert_eq!(summary.forward_id, "fid-list");
    assert_eq!(summary.mode, "remote");
    for field in [
        summary.forward_id.as_str(),
        summary.mode,
        summary.bind.as_str(),
        summary.forward_to.as_str(),
    ] {
        assert!(
            !field.contains(&token_text),
            "a LocalTunnelList-bound field must never carry the claim token, got {field:?}"
        );
    }
}

/// [`ControlHub::admin_close_forward`] (`PLAN.md` M4 Step 5 PR 5b): the
/// daemon's own-authority close path — the one `Ops::tunnel_close`
/// drives over a `LOCAL_ADMIN` conduit, deliberately never the owning
/// `LOCAL_CONTROL` conduit's own `RfwdClose` relay
/// (`docs/design/protocol.md` §11-3's owner-conduit gate on
/// [`ControlHub::send_request`], unchanged and untested here).
/// Registered by one conduit, closed by asking the hub directly —
/// exactly the shape a brand-new `qsh tunnel close <id>` process
/// always has (`Ops::tunnel_close`'s own doc on why this is not the
/// owning conduit). Proves: the registration is gone the instant this
/// returns; the target is notified with exactly one `RfwdClose`
/// naming the right `forward_id`, never a second one; and closing is
/// idempotent — an unknown id, or the same id again, is `false`, not
/// an error, and sends nothing further.
#[cfg(unix)]
#[tokio::test]
async fn admin_close_forward_removes_the_registration_and_notifies_the_target_exactly_once() {
    let hub = test_hub();
    let mut outbound_rx = hub
        .take_outbound_receiver()
        .expect("a fresh hub owns its own outbound receiver");
    let (conduit, _rx) = hub.register_conduit();
    let _token = hub.register_forward_for_test("fid-close", conduit);
    assert_eq!(hub.forward_registry_len(), 1);

    // An id nothing registered: no-op, touches nothing.
    assert!(!hub.admin_close_forward("never-registered"));
    assert_eq!(hub.forward_registry_len(), 1);

    assert!(hub.admin_close_forward("fid-close"));
    assert_eq!(
        hub.forward_registry_len(),
        0,
        "the registration must be gone the instant admin_close_forward returns"
    );
    assert!(hub.forward_owner("fid-close").is_none());

    let (_daemon_request_id, body) = outbound_rx
        .recv()
        .await
        .expect("the target must be notified with an outbound RfwdClose");
    match body {
        wire::control_message::Body::RfwdClose(close) => {
            assert_eq!(close.forward_id, "fid-close");
        }
        other => panic!("expected RfwdClose, got {other:?}"),
    }
    assert!(
        outbound_rx.try_recv().is_err(),
        "exactly one notification must be sent, never a second"
    );

    // Idempotent: closing the same id again is `false`, not an error,
    // and sends nothing further.
    assert!(!hub.admin_close_forward("fid-close"));
    assert!(outbound_rx.try_recv().is_err());
}

/// **The adversarial byte-level edition of the proof above**
/// (`PLAN.md` M4 Step 5 (a)'s own framing: misdelivery here is "a
/// security incident, not a bug"). Two conduits, two `forward_id`s,
/// two independent target connections, both queued and both claimed
/// *concurrently* — and then every leg carries a payload that names
/// its own `forward_id` in the clear, in both directions at once. If
/// a single byte of fid-a's traffic ever reached fid-b's claimed
/// stream (or vice versa), the marker comparisons below catch it
/// directly — a leak here is detectable, not merely improbable.
#[cfg(unix)]
#[tokio::test]
async fn distinguishable_payloads_never_cross_between_two_conduits_claimed_forwards() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-a", conduit_a);
    let token_b = hub.register_forward_for_test("fid-b", conduit_b);

    // Two independent loopback QUIC pairs — separate connections, so
    // there is no shared transport-level state between "target a" and
    // "target b" beyond the hub itself.
    let (client_a, server_a) = crate::tunnel::testutil::loopback_pair().await;
    let (client_b, server_b) = crate::tunnel::testutil::loopback_pair().await;

    async fn open_target(client: &Connection) -> (SendStream, RecvStream) {
        let (mut send, recv) = client.open_bi().await.unwrap();
        // A QUIC peer only learns a stream exists once a frame
        // referencing it actually arrives.
        send.write_all(b"x").await.unwrap();
        (send, recv)
    }

    let (mut target_send_a, mut target_recv_a) = open_target(&client_a).await;
    let (mut target_send_b, mut target_recv_b) = open_target(&client_b).await;
    let (daemon_send_a, daemon_recv_a) = server_a.accept_bi().await.unwrap();
    let (daemon_send_b, daemon_recv_b) = server_b.accept_bi().await.unwrap();

    let permit_a = hub.try_acquire_tunnel_permit().unwrap();
    let permit_b = hub.try_acquire_tunnel_permit().unwrap();
    hub.deliver_tcp_accepted("fid-a", daemon_send_a, daemon_recv_a, Vec::new(), permit_a)
        .unwrap_or_else(|_| panic!("fid-a is registered"));
    hub.deliver_tcp_accepted("fid-b", daemon_send_b, daemon_recv_b, Vec::new(), permit_b)
        .unwrap_or_else(|_| panic!("fid-b is registered"));

    // Claim both concurrently — interleaved, not sequential — so a
    // bug that only shows up under a race (a shared cursor, a
    // single-slot cache instead of a genuine per-id queue) has a
    // chance to fire.
    let (claimed_a, claimed_b) = tokio::join!(
        hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_secs(5)),
        hub.claim_tcp_accepted("fid-b", &token_b, Duration::from_secs(5)),
    );
    let (mut daemon_send_a, mut daemon_recv_a, _, _permit_a) =
        claimed_a.expect("fid-a's own arrival must be claimable");
    let (mut daemon_send_b, mut daemon_recv_b, _, _permit_b) =
        claimed_b.expect("fid-b's own arrival must be claimable");

    // Drain `open_target`'s single sentinel byte off each claimed
    // stream before the real payload exchange below — it exists only
    // to make `accept_bi` observe the stream, and is not part of
    // either marker.
    let mut sentinel = [0u8; 1];
    daemon_recv_a.read_exact(&mut sentinel).await.unwrap();
    daemon_recv_b.read_exact(&mut sentinel).await.unwrap();

    const MARKER_A: &[u8] = b"PAYLOAD-BELONGS-TO-FID-A-ONLY";
    const MARKER_B: &[u8] = b"PAYLOAD-BELONGS-TO-FID-B-ONLY";

    // Both directions, both ids, fully interleaved.
    let (w1, w2, w3, w4) = tokio::join!(
        target_send_a.write_all(MARKER_A),
        target_send_b.write_all(MARKER_B),
        daemon_send_a.write_all(MARKER_A),
        daemon_send_b.write_all(MARKER_B),
    );
    w1.unwrap();
    w2.unwrap();
    w3.unwrap();
    w4.unwrap();

    let mut buf_daemon_a = vec![0u8; MARKER_A.len()];
    let mut buf_daemon_b = vec![0u8; MARKER_B.len()];
    let mut buf_target_a = vec![0u8; MARKER_A.len()];
    let mut buf_target_b = vec![0u8; MARKER_B.len()];
    let (r1, r2, r3, r4) = tokio::join!(
        daemon_recv_a.read_exact(&mut buf_daemon_a),
        daemon_recv_b.read_exact(&mut buf_daemon_b),
        target_recv_a.read_exact(&mut buf_target_a),
        target_recv_b.read_exact(&mut buf_target_b),
    );
    r1.unwrap();
    r2.unwrap();
    r3.unwrap();
    r4.unwrap();

    assert_eq!(
        buf_daemon_a, MARKER_A,
        "fid-a's claimed stream must see exactly fid-a's payload, never fid-b's"
    );
    assert_eq!(
        buf_daemon_b, MARKER_B,
        "fid-b's claimed stream must see exactly fid-b's payload, never fid-a's"
    );
    assert_eq!(
        buf_target_a, MARKER_A,
        "fid-a's target must see exactly its own daemon-side reply"
    );
    assert_eq!(
        buf_target_b, MARKER_B,
        "fid-b's target must see exactly its own daemon-side reply"
    );
}

/// **The other half of "one conduit registers, the other tries to
/// claim"**: even the *legitimate* claimant's own two racing attempts
/// for the same `forward_id` (the same [`crate::tunnel::remote::
/// RemoteForwardAcceptor`] instance, hence the same claim token —
/// ownership alone, `Self::claim_tcp_accepted`'s own doc, does not
/// serialize concurrent attempts by the id's rightful owner) must
/// never both win: a single queued arrival is handed to exactly one
/// claimant, never duplicated to two racing callers — duplicating it
/// would itself be a byte leak, the same payload spliced into two
/// different processes.
#[cfg(unix)]
#[tokio::test]
async fn a_single_queued_arrival_is_won_by_exactly_one_of_two_racing_claimants() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-a", conduit_a);

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut target_send, _target_recv) = client.open_bi().await.unwrap();
    target_send.write_all(b"x").await.unwrap();
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
    let permit = hub.try_acquire_tunnel_permit().unwrap();
    hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
        .unwrap_or_else(|_| panic!("fid-a is registered"));

    // Two concurrent claimants for the *same* id, presenting the
    // *same* (real, registered) claim token — modeling the legitimate
    // owner's own two racing attempts, not an adversarial conduit
    // (that case has its own dedicated test below).
    let (first, second) = tokio::join!(
        hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(200)),
        hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(200)),
    );
    let winners = [first.is_some(), second.is_some()];
    assert_eq!(
        winners.iter().filter(|w| **w).count(),
        1,
        "exactly one of two racing claimants must win the single queued arrival, got {winners:?}"
    );
}

/// **The BLOCKER this ownership check exists to close** (adversarial
/// review finding, rated the most important of the batch: "claiming
/// does not check ownership"). The registry already gated
/// *delivery* — `deliver_tcp_accepted` refuses an id it never
/// registered — but before this test's own fix, nothing gated
/// *claiming*: `claim_tcp_accepted` only checked that `forward_id`
/// resolved to *some* registration, not that the caller was the one
/// who held it. Conduit B here knows conduit A's `forward_id` — the
/// adversarial premise the finding names verbatim — and presents its
/// own, different claim token. It must be refused outright, without
/// ever seeing the queue, and conduit A's own subsequent claim (its
/// *first*, seating its token as this id's owner) must still succeed
/// untouched by B's attempt.
#[cfg(unix)]
#[tokio::test]
async fn a_conduit_that_only_knows_another_conduits_forward_id_cannot_claim_it() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (_conduit_b, _rx_b) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-a", conduit_a);

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut target_send, _target_recv) = client.open_bi().await.unwrap();
    target_send.write_all(b"x").await.unwrap();
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
    let permit = hub.try_acquire_tunnel_permit().unwrap();
    hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
        .unwrap_or_else(|_| panic!("fid-a is registered to conduit_a"));

    // Conduit B never registered "fid-a" and holds no token for it —
    // it merely *knows the string* (leaked, guessed, or otherwise
    // obtained out of band) and tries to claim it with a token of its
    // own choosing (necessarily different from the real, hub-minted
    // `token_a`, which B never learned).
    let stolen = hub
        .claim_tcp_accepted("fid-a", b"conduit-b-token", Duration::from_millis(100))
        .await;
    assert!(
        stolen.is_none(),
        "a conduit that never registered fid-a must never claim its arrival, no matter what \
         token it presents"
    );

    // The real owner's own claim, presenting the token registration
    // actually seated, must be entirely unaffected by B's attempt
    // above.
    let claimed_by_owner = hub
        .claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(100))
        .await;
    assert!(
        claimed_by_owner.is_some(),
        "fid-a's real registrant must still be able to claim its own arrival after an \
         adversarial attempt"
    );
}

/// [`ControlHub::claim_tcp_accepted`]'s ownership check, mutation-checked:
/// with the `Some(existing) if existing.as_slice() == claim_token`
/// guard weakened to accept any token once one is merely present, the
/// adversarial test above must fail. This test pins the *shape* of
/// the check a second, independent way: the claim token that matters
/// is the one [`ControlHub::register_forward_for_test`] (standing in
/// for [`ControlHub::deliver_response`]'s own registration arm) seats
/// *atomically at registration* — never one a claimant supplies and
/// has accepted merely for being first, which is exactly the race
/// finding A closed. A mismatched token is refused immediately,
/// before any wait, and the id itself stays registered.
#[cfg(unix)]
#[tokio::test]
async fn a_token_not_seated_at_registration_is_refused_and_the_real_one_still_works() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-a", conduit_a);

    // A token nobody ever registered — not even a first, unclaimed
    // attempt at seating one, since registration (not claiming) is
    // now the only place a token is ever seated. Given a generous
    // budget, it must still be refused *fast*, proving the denial
    // happens at the ownership check itself, before any wait, rather
    // than as a timeout that would also (for the wrong reason)
    // satisfy a bare `is_none` assertion.
    let started = std::time::Instant::now();
    let mismatched = hub
        .claim_tcp_accepted("fid-a", b"wrong-token", Duration::from_secs(5))
        .await;
    assert!(
        mismatched.is_none(),
        "a token that does not match the one seated at registration must be refused"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "a token mismatch must be rejected immediately, not after waiting out the full \
         5s budget"
    );
    assert!(
        hub.forward_owner("fid-a").is_some(),
        "a claim-token mismatch must not deregister the forward_id itself"
    );

    // No arrival was ever queued, so even the *real* token times out
    // rather than errors — proving the mismatch above was rejected
    // for being the wrong token, not because fid-a itself had become
    // unclaimable for some other reason.
    let real_token_result = hub
        .claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(20))
        .await;
    assert!(
        real_token_result.is_none(),
        "no arrival was ever queued, so even the real token's claim must time out, not error"
    );
}

/// [`ControlHub::unregister_conduit`]'s tunnel-registry sweep
/// (`PLAN.md` M4 Step 5 (a)): every `forward_id` the dying conduit
/// owned is removed and every `TCP_ACCEPTED` stream still queued for
/// one of them is reset — but a *different* conduit's own
/// registration is untouched by that same call.
#[cfg(unix)]
#[tokio::test]
async fn unregister_conduit_sweeps_its_own_forwards_and_resets_queued_streams_but_spares_others() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    hub.register_forward_for_test("fid-a", conduit_a);
    hub.register_forward_for_test("fid-b", conduit_b);

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut target_send, mut target_recv) = client.open_bi().await.unwrap();
    // See the sibling test above for why `accept_bi` needs this first.
    target_send.write_all(b"x").await.unwrap();
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
    let permit = hub.try_acquire_tunnel_permit().unwrap();
    assert!(
        hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
            .is_ok(),
        "fid-a is registered"
    );

    hub.unregister_conduit(conduit_a);

    assert!(
        hub.forward_owner("fid-a").is_none(),
        "conduit_a's forward_id must be swept the instant it dies"
    );
    assert_eq!(
        hub.forward_owner("fid-b"),
        Some(conduit_b),
        "a sibling conduit's own registration must survive conduit_a's teardown"
    );

    // The queued stream for fid-a must have been reset, not silently
    // dropped clean — a bare drop finishes/stops a QUIC stream
    // cleanly (`TunnelArrival::reset`'s own doc), which would tell
    // whoever opened it "this ended normally" about a forward that in
    // fact was torn down out from under it.
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
        .await
        .expect("the reset must be observed promptly, not hang");
    match read {
        Err(quinn::ReadError::Reset(code)) => {
            assert_eq!(
                code,
                quinn::VarInt::from_u32(RESET_CODE_TUNNEL_UNKNOWN_FORWARD),
                "a swept forward's queued stream must reset with the documented code"
            );
        }
        other => panic!("expected a stream reset, got {other:?}"),
    }
}

/// The stronger form of the sweep proof above: a conduit that owns
/// *several* `forward_id`s (not just one) loses every one of them the
/// instant it dies, and the registry is verifiably left with zero
/// trace of it — not merely "the two ids this test happened to check
/// are gone" (`PLAN.md` M4 Step 5 (a): "conduit death removes every
/// forward_id it owned"). [`ControlHub::forward_registry_len`] is
/// the precise, exhaustive assertion; per-id [`ControlHub::forward_owner`]
/// checks alone could pass even if the sweep leaked some other id
/// nobody thought to check.
#[cfg(unix)]
#[tokio::test]
async fn unregister_conduit_leaves_zero_trace_of_a_conduit_that_owned_several_forwards() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    hub.register_forward_for_test("fid-a1", conduit_a);
    hub.register_forward_for_test("fid-a2", conduit_a);
    hub.register_forward_for_test("fid-a3", conduit_a);
    hub.register_forward_for_test("fid-b", conduit_b);
    assert_eq!(hub.forward_registry_len(), 4);

    // Queue a real arrival for two of conduit_a's three ids, so the
    // sweep's reset behavior is proven for more than a single
    // straggler.
    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let mut queued_targets = Vec::new();
    for fid in ["fid-a1", "fid-a2"] {
        let (mut target_send, target_recv) = client.open_bi().await.unwrap();
        target_send.write_all(b"x").await.unwrap();
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
        let permit = hub.try_acquire_tunnel_permit().unwrap();
        hub.deliver_tcp_accepted(fid, daemon_send, daemon_recv, Vec::new(), permit)
            .unwrap_or_else(|_| panic!("{fid} is registered"));
        queued_targets.push(target_recv);
    }

    hub.unregister_conduit(conduit_a);

    // Precise, not spot-checked: the registry holds exactly
    // conduit_b's one surviving id, nothing else.
    assert_eq!(
        hub.forward_registry_len(),
        1,
        "every one of conduit_a's forward_ids must be gone, leaving only conduit_b's"
    );
    for fid in ["fid-a1", "fid-a2", "fid-a3"] {
        assert!(hub.forward_owner(fid).is_none(), "{fid} must be swept");
    }
    assert_eq!(
        hub.forward_owner("fid-b"),
        Some(conduit_b),
        "a sibling conduit's own registration must survive conduit_a's teardown"
    );

    // Both queued arrivals — not just the first — were reset, never
    // left to drop clean.
    for mut target_recv in queued_targets {
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
            .await
            .expect("the reset must be observed promptly, not hang");
        match read {
            Err(quinn::ReadError::Reset(code)) => {
                assert_eq!(
                    code,
                    quinn::VarInt::from_u32(RESET_CODE_TUNNEL_UNKNOWN_FORWARD),
                    "every swept forward's queued stream must reset with the documented code"
                );
            }
            other => panic!("expected a stream reset, got {other:?}"),
        }
    }
}

/// [`MAX_TUNNEL_STREAMS_PER_HUB`] is exact, not advisory
/// (`PLAN.md` M4 Step 5 (a)'s hub cap): the `(cap+1)`th
/// [`ControlHub::try_acquire_tunnel_permit`] call is refused while
/// every permit up to the cap is still held, and releasing one frees
/// exactly one slot back.
#[cfg(unix)]
#[tokio::test]
async fn tunnel_permit_cap_is_exact_not_advisory() {
    let hub = test_hub();
    let mut held = Vec::new();
    for _ in 0..MAX_TUNNEL_STREAMS_PER_HUB {
        held.push(
            hub.try_acquire_tunnel_permit()
                .expect("every permit up to the cap must be grantable"),
        );
    }
    assert!(
        hub.try_acquire_tunnel_permit().is_none(),
        "the (cap+1)th tunnel stream must be refused, not silently admitted"
    );

    held.pop();
    assert!(
        hub.try_acquire_tunnel_permit().is_some(),
        "releasing one held permit must free exactly one slot"
    );
}

/// The cap must refuse only the stream that overflows it — it must
/// never corrupt or block delivery for streams already admitted, and
/// once a slot frees, a *different* conduit's registered forward must
/// be able to use it immediately (`PLAN.md` M4 Step 5 (a): exceeding
/// the cap "does not wedge the hub for other conduits").
#[cfg(unix)]
#[tokio::test]
async fn exceeding_the_hub_cap_refuses_the_new_stream_without_wedging_the_hub_for_others() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-a", conduit_a);
    let token_b = hub.register_forward_for_test("fid-b", conduit_b);

    // Fill the cap to one below the limit with permits standing in
    // for other conduits' already-admitted tunnel streams.
    let mut held: Vec<_> = (0..MAX_TUNNEL_STREAMS_PER_HUB - 1)
        .map(|_| hub.try_acquire_tunnel_permit().unwrap())
        .collect();

    // fid-a takes the one remaining slot and is delivered normally —
    // proving a near-full cap does not itself disturb an admission
    // that still fits.
    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut target_send_a, _target_recv_a) = client.open_bi().await.unwrap();
    target_send_a.write_all(b"x").await.unwrap();
    let (daemon_send_a, daemon_recv_a) = server.accept_bi().await.unwrap();
    let permit_a = hub
        .try_acquire_tunnel_permit()
        .expect("the last free slot must still be grantable");
    hub.deliver_tcp_accepted("fid-a", daemon_send_a, daemon_recv_a, Vec::new(), permit_a)
        .unwrap_or_else(|_| panic!("fid-a fits exactly at the cap"));

    // The hub is now saturated. A new stream must be refused —
    // observably, deterministically — rather than hang or wedge the
    // whole hub.
    assert!(
        hub.try_acquire_tunnel_permit().is_none(),
        "the hub is saturated; a new permit must be refused, not granted"
    );

    // fid-a's already-admitted arrival is unaffected by the refusal
    // above — still claimable, proving the cap rejection is scoped to
    // the one overflowing attempt, not a hub-wide stall.
    let claimed_a = hub
        .claim_tcp_accepted("fid-a", &token_a, Duration::from_secs(5))
        .await;
    assert!(
        claimed_a.is_some(),
        "an already-admitted stream must not be disturbed by a sibling's cap refusal"
    );

    // Free exactly one of the "other conduits'" held permits — fid-b
    // must now succeed, proving the hub recovers rather than staying
    // wedged once any capacity returns.
    held.pop();
    let (mut target_send_b, target_recv_b) = client.open_bi().await.unwrap();
    target_send_b.write_all(b"x").await.unwrap();
    let (daemon_send_b, daemon_recv_b) = server.accept_bi().await.unwrap();
    let permit_b = hub
        .try_acquire_tunnel_permit()
        .expect("freeing one held permit must free exactly one slot back");
    hub.deliver_tcp_accepted("fid-b", daemon_send_b, daemon_recv_b, Vec::new(), permit_b)
        .unwrap_or_else(|_| panic!("fid-b must be admitted once capacity returns"));
    let claimed_b = hub
        .claim_tcp_accepted("fid-b", &token_b, Duration::from_secs(5))
        .await;
    assert!(
        claimed_b.is_some(),
        "fid-b must be claimable once the hub has recovered capacity"
    );
    drop(held);
    drop(target_recv_b);
}

/// [`MAX_PARKED_CLAIMS_PER_HUB`] is exact, not advisory — the
/// distinct resource `crate::localctl::daemon::LocalctlDaemon::serve_tcp_accepted`
/// acquires *before* ever calling [`ControlHub::claim_tcp_accepted`]
/// (finding E: a parked claim holds a `MAX_CONCURRENT_LOCAL_STREAM_CONDUITS`
/// permit for its whole wait budget with nothing bounding how many of
/// *this hub's* claims can be parked at once — a `(cap+1)`th
/// parked claim must be refused, not queued behind the ones already
/// parked).
///
/// Driven through as many owning conduits as the hub's pool divides
/// into, because one conduit can no longer reach the ceiling by
/// itself ([`MAX_PARKED_CLAIMS_PER_CONDUIT`]) — the ceiling is what
/// this test is about, and it must still be exact once the shares
/// that fill it are spread across their owners.
#[cfg(unix)]
#[tokio::test]
async fn claim_permit_hub_ceiling_is_exact_not_advisory() {
    let hub = test_hub();
    let shares = MAX_PARKED_CLAIMS_PER_HUB / MAX_PARKED_CLAIMS_PER_CONDUIT;
    let mut held = Vec::new();
    let mut forward_ids = Vec::new();
    // Inboxes kept alive for the whole test: a dropped receiver is not
    // what unregisters a conduit, but keeping them mirrors the live
    // CLIs these conduits stand in for.
    let mut inboxes = Vec::new();
    for n in 0..shares {
        let (conduit, rx) = hub.register_conduit();
        inboxes.push(rx);
        let forward_id = format!("fid-{n}");
        hub.register_forward_for_test(&forward_id, conduit);
        for _ in 0..MAX_PARKED_CLAIMS_PER_CONDUIT {
            held.push(
                hub.try_acquire_claim_permit(&forward_id)
                    .expect("every permit up to each owner's own share must be grantable"),
            );
        }
        forward_ids.push(forward_id);
    }
    assert_eq!(
        hub.parked_claims_held(),
        MAX_PARKED_CLAIMS_PER_HUB,
        "the shares must add up to exactly the hub ceiling, with nothing double-counted"
    );

    // A fresh owner, well inside its own untouched share, is refused:
    // the ceiling binds independently of the shares.
    let (late, _rx_late) = hub.register_conduit();
    hub.register_forward_for_test("fid-late", late);
    assert!(
        hub.try_acquire_claim_permit("fid-late").is_none(),
        "the (cap+1)th parked claim must be refused, not silently admitted, even for an \
         owner holding none of its own share"
    );

    held.pop();
    assert!(
        hub.try_acquire_claim_permit("fid-late").is_some(),
        "releasing one held parked-claim permit must free exactly one slot"
    );
    drop(inboxes);
    drop(forward_ids);
}

/// **The fairness finding this share exists to close.** The steady
/// state of a healthy `-R` is to *sit* holding a parked-claim permit
/// (`crate::tunnel::remote::claim_remote_forward_reverse`: one
/// long-poll per registered `forward_id`, re-armed the instant it
/// returns), so a hub-wide pool with no per-owner share is exhausted
/// by ordinary use: one CLI running [`MAX_PARKED_CLAIMS_PER_HUB`]
/// reverse forwards would hold every permit on this host essentially
/// forever and every other CLI's `-R` would be refused for as long as
/// it kept them — normal operation starving normal operation.
///
/// Conduit A here parks as many claims as it can across *many* of its
/// own forwards — the shape of the real starvation, not a single
/// forward's loop — and conduit B, which has done nothing wrong, must
/// still be able to park and claim its own forward *without A giving
/// anything back*. The ceiling still holds at the same time: A is
/// capped at its share, far below the pool.
#[cfg(unix)]
#[tokio::test]
async fn one_conduit_cannot_take_more_than_its_share_or_block_another_conduits_claim() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    let token_b = hub.register_forward_for_test("fid-b", conduit_b);

    // Conduit A runs many reverse forwards and parks a claim on each,
    // the way a real claim loop does — and keeps going past its share.
    let a_forwards: Vec<String> = (0..MAX_PARKED_CLAIMS_PER_HUB)
        .map(|n| {
            let forward_id = format!("fid-a{n}");
            hub.register_forward_for_test(&forward_id, conduit_a);
            forward_id
        })
        .collect();
    let held: Vec<_> = a_forwards
        .iter()
        .filter_map(|forward_id| hub.try_acquire_claim_permit(forward_id))
        .collect();

    assert_eq!(
        held.len(),
        MAX_PARKED_CLAIMS_PER_CONDUIT,
        "one conduit must be held to its own share no matter how many distinct forwards it \
         spreads its claims across"
    );
    // ("a share equal to the pool would be no share at all" is
    // asserted at the constants themselves, in a `const _` next to
    // `MAX_PARKED_CLAIMS_PER_CONDUIT` — a compile error there, not a
    // test failure here.)

    // Conduit B, entirely uninvolved, parks its own claim — with A
    // still holding every permit it was allowed. Nothing was freed.
    let claim_permit_b = hub
        .try_acquire_claim_permit("fid-b")
        .expect("a conduit sitting at its own share must not deny another conduit a claim");

    // ...and the claim actually completes, end to end, against a real
    // queued arrival: the share bounds *waiting*, never delivery.
    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut target_send_b, _target_recv_b) = client.open_bi().await.unwrap();
    target_send_b.write_all(b"x").await.unwrap();
    let (daemon_send_b, daemon_recv_b) = server.accept_bi().await.unwrap();
    let tunnel_permit_b = hub.try_acquire_tunnel_permit().unwrap();
    hub.deliver_tcp_accepted(
        "fid-b",
        daemon_send_b,
        daemon_recv_b,
        Vec::new(),
        tunnel_permit_b,
    )
    .unwrap_or_else(|_| panic!("fid-b is registered to conduit_b"));
    let claimed_b = hub
        .claim_tcp_accepted("fid-b", &token_b, Duration::from_secs(5))
        .await;
    assert!(
        claimed_b.is_some(),
        "conduit B must be able to claim its own forward while conduit A sits at its share"
    );

    // The hub ceiling is still the outer bound: A's share plus B's one
    // claim is all that is outstanding, and the pool is nowhere near
    // spent — the share divided it, it did not inflate it.
    assert_eq!(
        hub.parked_claims_held(),
        MAX_PARKED_CLAIMS_PER_CONDUIT + 1,
        "no permit may be conjured by spreading claims across forwards or conduits"
    );

    drop(claim_permit_b);
    drop(held);
}

/// A queued `TCP_ACCEPTED` nobody ever claims must not pin this hub's
/// capacity forever (adversarial review finding): each queued arrival
/// holds one [`MAX_TUNNEL_STREAMS_PER_HUB`] permit and one live QUIC
/// stream, and before [`ControlHub::sweep_expired_arrivals`] existed a
/// queue drained only on a successful claim, a conduit death, or an
/// owner-checked close — so one starved or slow claimant's backlog
/// was charged against *every other* CLI's tunnels on this host with
/// no bound on how long.
///
/// Proves all three halves of the fix: the arrival is expired only
/// once it is actually old, its permit comes back to the pool, and
/// the stream is **reset with a real code** rather than dropped clean
/// (a bare drop would tell the target this connection ended normally —
/// [`TunnelArrival::reset`]'s own doc). The registration itself must
/// survive: an idle `-R` whose backlog aged out is still a live
/// forward.
#[cfg(unix)]
#[tokio::test]
async fn a_queued_arrival_nobody_claims_expires_resetting_its_stream_and_freeing_its_permit() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-a", conduit_a);

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut target_send, mut target_recv) = client.open_bi().await.unwrap();
    // See the sibling tests above for why `accept_bi` needs this first.
    target_send.write_all(b"x").await.unwrap();
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
    let permit = hub.try_acquire_tunnel_permit().unwrap();
    hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
        .unwrap_or_else(|_| panic!("fid-a is registered"));
    assert_eq!(
        hub.tunnel_permits_available(),
        MAX_TUNNEL_STREAMS_PER_HUB - 1,
        "a queued arrival holds a real hub tunnel permit for its whole queued life"
    );

    // A fresh arrival is not expired — the sweep must bound the wait,
    // not shorten it to nothing.
    assert_eq!(
        hub.sweep_expired_arrivals(),
        0,
        "an arrival that has just been queued must not be swept"
    );
    assert_eq!(hub.queued_arrival_count("fid-a"), 1);

    hub.backdate_queued_arrivals_for_test(MAX_QUEUED_TUNNEL_ARRIVAL_AGE + Duration::from_secs(1));
    assert_eq!(
        hub.sweep_expired_arrivals(),
        1,
        "an arrival past its budget must be expired"
    );

    // Both resources are back: the permit and the stream.
    assert_eq!(
        hub.tunnel_permits_available(),
        MAX_TUNNEL_STREAMS_PER_HUB,
        "expiring an arrival must return its hub tunnel permit to the pool every other CLI \
         on this host draws from"
    );
    assert_eq!(
        hub.queued_arrival_count("fid-a"),
        0,
        "the expired arrival must leave the queue, not merely be marked"
    );
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
        .await
        .expect("the reset must be observed promptly, not hang");
    match read {
        Err(quinn::ReadError::Reset(code)) => {
            assert_eq!(
                code,
                quinn::VarInt::from_u32(RESET_CODE_TUNNEL_CLAIM_EXPIRED),
                "an expired arrival must reset visibly, with its own documented code — never \
                 drop clean, which would report a normal end for a connection nobody spliced"
            );
        }
        other => panic!("expected a stream reset, got {other:?}"),
    }

    // The forward itself is untouched: still owned, still claimable,
    // just with nothing queued for it now.
    assert_eq!(
        hub.forward_owner("fid-a"),
        Some(conduit_a),
        "expiring a backlog must not close the forward it belonged to"
    );
    assert!(
        hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(50))
            .await
            .is_none(),
        "the expired arrival must be gone from the queue, so a later claim waits for a new \
         one rather than being handed a stream that was already reset"
    );
}

/// Send `header` on a fresh bidi stream `conn` opens, mirroring
/// exactly what a real target's `TCP_ACCEPTED` leg writes
/// (`crate::tunnel::remote`'s own `open_fake_tcp_accepted` test
/// helper plays back the identical handshake for the direct-connect
/// leg). Returns the target-side halves so a test can observe how
/// [`Listen::handle_tcp_accepted_stream`] answered.
#[cfg(unix)]
async fn open_fake_target_tcp_accepted(
    conn: &Connection,
    ticket: &[u8],
) -> (quinn::SendStream, quinn::RecvStream) {
    let (send, recv) = conn.open_bi().await.unwrap();
    let mut framed = qsh_transport::FramedStream::data(send, recv);
    framed
        .send
        .send(&wire::StreamHeader {
            kind: wire::StreamKind::TcpAccepted as i32,
            ticket: ticket.to_vec(),
            host: String::new(),
            port: 0,
        })
        .await
        .unwrap();
    let (send, recv) = framed.split();
    (send.into_raw(), recv.into_raw().0)
}

/// `PLAN.md` M4 Step 5 (a): "shape-check with `wire::valid_forward_id`
/// before the lookup". A `TCP_ACCEPTED` whose ticket fails that shape
/// check must never reach [`ControlHub::deliver_tcp_accepted`] at
/// all — proven here by registering `"not valid!"` (space and `!` are
/// outside `[A-Za-z0-9_-]`) to a real conduit first: if the shape
/// check were skipped, this delivery would succeed.
#[cfg(unix)]
#[tokio::test]
async fn handle_tcp_accepted_stream_rejects_a_malformed_ticket_before_any_registry_lookup() {
    assert!(!wire::valid_forward_id("not valid!"));
    let hub = test_hub();
    let (conduit, _rx) = hub.register_conduit();
    hub.register_forward_for_test("not valid!", conduit);

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (_target_send, mut target_recv) =
        open_fake_target_tcp_accepted(&client, b"not valid!").await;
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();

    Listen::handle_tcp_accepted_stream(daemon_send, daemon_recv, hub.clone()).await;

    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
        .await
        .expect("a malformed ticket must be rejected promptly, not hang");
    match read {
        Err(quinn::ReadError::Reset(code)) => {
            assert_eq!(
                code,
                quinn::VarInt::from_u32(RESET_CODE_TUNNEL_UNKNOWN_FORWARD)
            );
        }
        other => panic!("expected a stream reset, got {other:?}"),
    }
    // No permit was ever spent and no queue entry was ever created for
    // the malformed ticket's literal bytes — the cap is fully intact.
    assert_eq!(
        hub.tunnel_permits.available_permits(),
        MAX_TUNNEL_STREAMS_PER_HUB
    );
}

/// A `TCP_ACCEPTED` naming a real, currently-registered `forward_id`
/// is queued by [`Listen::handle_tcp_accepted_stream`] and reachable
/// by [`ControlHub::claim_tcp_accepted`] for exactly that id —
/// the ordinary, successful path this whole relay exists to serve.
#[cfg(unix)]
#[tokio::test]
async fn handle_tcp_accepted_stream_queues_a_registered_forward_id_for_its_conduit_to_claim() {
    let hub = test_hub();
    let (conduit, _rx) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-a", conduit);

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (_target_send, _target_recv) = open_fake_target_tcp_accepted(&client, b"fid-a").await;
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();

    Listen::handle_tcp_accepted_stream(daemon_send, daemon_recv, hub.clone()).await;

    let claimed = hub
        .claim_tcp_accepted("fid-a", &token_a, Duration::from_secs(5))
        .await;
    assert!(
        claimed.is_some(),
        "a registered forward_id's TCP_ACCEPTED must be claimable"
    );
}

/// `PLAN.md` M4 Step 5 (a)'s hub cap applies to the `TCP_ACCEPTED`
/// ingress path too, not just `TCP_CONNECT`: a `TCP_ACCEPTED` naming
/// a real registered `forward_id` that arrives while this hub is
/// already at [`MAX_TUNNEL_STREAMS_PER_HUB`] is reset with
/// [`RESET_CODE_TUNNEL_HUB_EXHAUSTED`] before it is ever queued — the
/// cap is exact even for a legitimately-registered id.
#[cfg(unix)]
#[tokio::test]
async fn handle_tcp_accepted_stream_at_the_hub_cap_resets_rather_than_queues() {
    let hub = test_hub();
    let (conduit, _rx) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-a", conduit);
    let _held: Vec<_> = (0..MAX_TUNNEL_STREAMS_PER_HUB)
        .map(|_| hub.try_acquire_tunnel_permit().unwrap())
        .collect();

    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (_target_send, mut target_recv) = open_fake_target_tcp_accepted(&client, b"fid-a").await;
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();

    Listen::handle_tcp_accepted_stream(daemon_send, daemon_recv, hub.clone()).await;

    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
        .await
        .expect("a hub-exhausted rejection must be prompt, not hang");
    match read {
        Err(quinn::ReadError::Reset(code)) => {
            assert_eq!(
                code,
                quinn::VarInt::from_u32(RESET_CODE_TUNNEL_HUB_EXHAUSTED)
            );
        }
        other => panic!("expected a stream reset, got {other:?}"),
    }
    assert!(
        hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(50))
            .await
            .is_none(),
        "the rejected arrival must never have been queued"
    );
}

// ------------------------------------------------------------------
// **Ownership: who may claim, who may close** (adversarial-review
// round 2 — the three holes that made `isolation_holds` false). Every
// test below is written from conduit B's side: B knows conduit A's
// `forward_id` (leaked, guessed, or simply observed) and tries to be
// delivered to, or to tear down, something that is not its own.
// `PLAN.md` M4 Step 5 (a)'s framing applies verbatim — misdelivery
// here is a security incident, not a bug.
// ------------------------------------------------------------------

/// A `RemoteForwardOpen` carrying `token`, so a test can drive a real
/// registration through [`ControlHub::send_request`]/
/// [`ControlHub::deliver_response`] — the only path that ever seats
/// one in production — instead of the `register_forward_for_test`
/// shortcut.
#[cfg(unix)]
fn rfwd_open_body_with_token(token: &[u8]) -> wire::control_message::Body {
    wire::control_message::Body::RfwdOpen(wire::RemoteForwardOpen {
        claim_token: token.to_vec(),
        ..Default::default()
    })
}

/// The `RemoteForwardOpened` a target answers with — this module's
/// own copy of `control_hub_tests`' identical helper (a sibling test
/// module's private items are not in scope here).
#[cfg(unix)]
fn rfwd_opened_response(forward_id: &str) -> wire::Response {
    wire::Response {
        body: Some(wire::response::Body::RfwdOpened(
            wire::RemoteForwardOpened {
                forward_id: forward_id.to_string(),
                actual_port: 0,
            },
        )),
    }
}

#[cfg(unix)]
fn rfwd_close_body(forward_id: &str) -> wire::control_message::Body {
    wire::control_message::Body::RfwdClose(wire::RemoteForwardClose {
        forward_id: forward_id.to_string(),
    })
}

/// Queue one real `TCP_ACCEPTED` arrival for `forward_id` off a fresh
/// loopback pair. The returned tuple keeps both connections and the
/// target-side halves alive, so a test can observe whether that
/// stream was ever reset (`TunnelArrival::reset`) — dropping the
/// connection instead would make every read fail for the wrong
/// reason.
#[cfg(unix)]
async fn queue_one_arrival(
    hub: &Arc<ControlHub>,
    forward_id: &str,
) -> (Connection, Connection, SendStream, RecvStream) {
    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut target_send, target_recv) = client.open_bi().await.unwrap();
    // A QUIC peer only learns a stream exists once a frame
    // referencing it actually arrives.
    target_send.write_all(b"x").await.unwrap();
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
    let permit = hub
        .try_acquire_tunnel_permit()
        .expect("a fresh hub is under its cap");
    hub.deliver_tcp_accepted(forward_id, daemon_send, daemon_recv, Vec::new(), permit)
        .unwrap_or_else(|_| panic!("{forward_id} must be registered and claimable here"));
    (client, server, target_send, target_recv)
}

/// **Hole 1 — the check-then-use one.** Before this fix
/// [`ControlHub::claim_tcp_accepted`] validated the presented token
/// exactly once, at entry, and then — inside the wait — *popped* the
/// arrival and re-checked only that the id was still registered to
/// *someone*. So a claimant that parked while it legitimately owned
/// `fid-x`, and stayed parked while `fid-x` was closed and re-opened
/// by a different conduit, woke up and was handed the **new owner's**
/// stream. This is the interleaving verbatim: A parks, the id is
/// re-seated to B mid-wait, the arrival lands, and A wakes.
///
/// A must leave with nothing, and B — the conduit that actually owns
/// the id at the moment the arrival exists — must be able to claim
/// it afterwards, proving the arrival was never consumed by A's wake.
#[cfg(unix)]
#[tokio::test]
async fn a_forward_id_re_seated_mid_wait_never_delivers_to_the_conduit_that_parked_first() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    let token_a = hub.register_forward_for_test("fid-x", conduit_a);

    // A parks: nothing is queued for fid-x yet, and A's token is (for
    // now) the seated one, so this reaches the wait rather than being
    // refused at once.
    let parked = tokio::spawn({
        let hub = Arc::clone(&hub);
        let token_a = token_a.clone();
        async move {
            hub.claim_tcp_accepted("fid-x", &token_a, Duration::from_secs(5))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // fid-x is closed and re-opened while A sleeps: the id is
    // re-seated to conduit B, with B's own, different token.
    let token_b = hub.register_forward_for_test("fid-x", conduit_b);
    assert_ne!(token_a, token_b, "the re-seat must mint a different token");

    // The target opens a TCP_ACCEPTED for the *new* registration.
    // This is what wakes A.
    let _arrival = queue_one_arrival(&hub, "fid-x").await;

    let woken = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .expect("the parked claimant must wake, not hang")
        .expect("the parked claim task must not panic");
    assert!(
        woken.is_none(),
        "a claimant parked under the *previous* seat must be refused when it wakes — \
         the token has to be re-validated against the current seat at the moment the \
         arrival changes hands, never once at entry"
    );

    let claimed_by_b = hub
        .claim_tcp_accepted("fid-x", &token_b, Duration::from_secs(5))
        .await;
    assert!(
        claimed_by_b.is_some(),
        "the arrival belongs to the current seat and must still be there for it — if A's \
         wake had consumed it, this is the assertion that catches the misdelivery"
    );
}

/// The same interleaving with the **owner unchanged** — hole 1's
/// nastier half, and the reason the re-validation is against the
/// *seat* and not against `ForwardRegistration::owner`. Conduit A
/// closes `fid-x` and re-opens it (a new
/// [`crate::tunnel::remote::RemoteForwardAcceptor`] instance, hence a
/// new claim token) while an older claim of its own is still parked.
/// A check that compared only the owning conduit would happily hand
/// the new instance's stream to the stale one; only comparing the
/// token catches it.
#[cfg(unix)]
#[tokio::test]
async fn a_stale_claim_is_refused_even_when_the_re_seat_keeps_the_same_owner() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let stale_token = hub.register_forward_for_test("fid-x", conduit_a);

    let parked = tokio::spawn({
        let hub = Arc::clone(&hub);
        let stale_token = stale_token.clone();
        async move {
            hub.claim_tcp_accepted("fid-x", &stale_token, Duration::from_secs(5))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Same conduit, same id, brand-new instance and therefore a
    // brand-new token.
    let fresh_token = hub.register_forward_for_test("fid-x", conduit_a);
    assert_ne!(stale_token, fresh_token);
    assert_eq!(
        hub.forward_owner("fid-x"),
        Some(conduit_a),
        "the owner is deliberately unchanged — only the seat moved"
    );

    let _arrival = queue_one_arrival(&hub, "fid-x").await;

    let woken = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .expect("the parked claimant must wake, not hang")
        .expect("the parked claim task must not panic");
    assert!(
        woken.is_none(),
        "a stale token must be refused on wake even when the owning conduit never changed"
    );
    assert!(
        hub.claim_tcp_accepted("fid-x", &fresh_token, Duration::from_secs(5))
            .await
            .is_some(),
        "the current seat's own claim must still find the arrival"
    );
}

/// **Hole 2 — the capability that defaulted to "anyone".** A
/// `RemoteForwardOpen` that carried no `claim_token` used to seat an
/// *empty* token, and an empty seat matched any same-uid conduit
/// presenting an empty token — worse than no capability at all,
/// because the surrounding code read as though it were protected.
/// Driven through the real `send_request`/`deliver_response` path,
/// with `wire::RemoteForwardOpen::default()`'s empty token — exactly
/// what `ops::tunnel::remote_forward_open_from_spec` produces today.
///
/// The registration is kept (so the id stays attributed to its
/// conduit, is swept when that conduit dies, and cannot be adopted by
/// a duplicate `RemoteForwardOpened`) but is **permanently
/// unclaimable**: no token claims it, an empty one least of all, and
/// no arrival is ever queued for it — so it holds no hub permit and
/// no live QUIC stream on the strength of a capability nobody holds.
#[cfg(unix)]
#[tokio::test]
async fn an_open_that_carried_no_claim_token_is_registered_permanently_unclaimable() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let mut outbound = hub
        .take_outbound_receiver()
        .expect("hub has an outbound receiver");

    hub.send_request(conduit_a, 0, rfwd_open_body_with_token(b""))
        .unwrap();
    let (open_id, _) = outbound.recv().await.expect("queued send");
    hub.deliver_response(open_id, rfwd_opened_response("fid-empty"));

    assert_eq!(
        hub.forward_owner("fid-empty"),
        Some(conduit_a),
        "the id is still registered and still attributable to the conduit that opened it"
    );
    assert!(
        !hub.forward_is_claimable("fid-empty"),
        "an open that carried no claim token must never end up with a token that passes"
    );

    // The exact adversarial move: present the same nothing the
    // registration carried.
    let started = std::time::Instant::now();
    assert!(
        hub.claim_tcp_accepted("fid-empty", b"", Duration::from_secs(5))
            .await
            .is_none(),
        "an empty presented token must be refused, never matched against an empty seat"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the refusal must come from the seat check, not from waiting out the whole budget"
    );
    assert!(
        hub.claim_tcp_accepted("fid-empty", b"guessed", Duration::from_millis(50))
            .await
            .is_none(),
        "and no other token claims it either — unclaimable is terminal"
    );

    // Nothing is ever queued for it, so it cannot pin a hub tunnel
    // permit or a live QUIC stream waiting for a claimant that can
    // never come.
    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    let (mut target_send, _target_recv) = client.open_bi().await.unwrap();
    target_send.write_all(b"x").await.unwrap();
    let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
    let permit = hub.try_acquire_tunnel_permit().unwrap();
    let rejected = hub
        .deliver_tcp_accepted("fid-empty", daemon_send, daemon_recv, Vec::new(), permit)
        .expect_err("an unclaimable registration must be refused exactly like an unknown id");
    rejected.reset(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
    assert_eq!(
        hub.tunnel_permits.available_permits(),
        MAX_TUNNEL_STREAMS_PER_HUB,
        "the refused arrival must give its permit straight back"
    );
}

/// **Finding 5 — `claim_token` never reaches the outbound channel,**
/// i.e. never reaches the bytes [`Listen::drive_registered_session`]'s
/// `recv_outbound` arm actually serializes onto the live QUIC
/// connection to the peer. Driven through the same real
/// `send_request`/`deliver_response` path the two tests above use,
/// with a real, distinguishable token — so this cannot pass by
/// accident the way an empty-token test could.
///
/// Both halves of the claim matter: the *outbound* copy must have lost
/// it (this is the actual fix — mutation check: revert `send_request`'s
/// `mem::take` back to `.clone()` and `open_body.claim_token` below
/// reads back `b"peer-must-never-see-this"`, failing the first
/// assertion) and the *local* seat must still have it, unchanged
/// (mutation check: change the `mem::take` to simply drop the value
/// instead of feeding it to `pending_rfwd_opens`, and the
/// real-token claim at the end gets refused, failing the last
/// assertion) — proving this is a relocation, not a loss.
#[cfg(unix)]
#[tokio::test]
async fn a_claim_token_is_taken_off_the_body_actually_sent_to_the_peer() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let mut outbound = hub
        .take_outbound_receiver()
        .expect("hub has an outbound receiver");

    const TOKEN: &[u8] = b"peer-must-never-see-this";
    hub.send_request(conduit_a, 0, rfwd_open_body_with_token(TOKEN))
        .unwrap();
    let (open_id, sent_body) = outbound.recv().await.expect("queued send");
    let open_body = match sent_body {
        wire::control_message::Body::RfwdOpen(open) => open,
        other => panic!("expected RfwdOpen, got {other:?}"),
    };
    assert!(
        open_body.claim_token.is_empty(),
        "the body actually handed to the outbound channel — what a real reverse driver \
         loop would serialize onto the wire to the target — must never carry claim_token, \
         got {:?}",
        open_body.claim_token
    );

    // Not lost — relocated: `deliver_response` still seats the real
    // token, and only the real token claims the resulting
    // registration.
    hub.deliver_response(open_id, rfwd_opened_response("fid-taken"));
    assert!(
        hub.claim_tcp_accepted("fid-taken", b"wrong-token", Duration::from_millis(50))
            .await
            .is_none(),
        "a wrong token must still be refused — taking claim_token off the outbound body \
         must not have widened the seat"
    );
    let _arrival = queue_one_arrival(&hub, "fid-taken").await;
    assert!(
        hub.claim_tcp_accepted("fid-taken", TOKEN, Duration::from_secs(5))
            .await
            .is_some(),
        "the real token, captured locally before it was taken off the outbound body, must \
         still claim the arrival"
    );
}

/// Hole 2's exhaustive half: **no registration this hub can produce,
/// by any path, ever ends up with a token an empty claim matches** —
/// and an empty presented token is refused against every seat, not
/// just against the unclaimable one. All three producers are covered:
/// a real token over the wire path, no token over the wire path, and
/// the `register_forward_for_test` shortcut the other unit tests use.
#[cfg(unix)]
#[tokio::test]
async fn an_empty_claim_token_is_refused_against_every_seat_this_hub_can_hold() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let mut outbound = hub
        .take_outbound_receiver()
        .expect("hub has an outbound receiver");

    hub.send_request(conduit_a, 0, rfwd_open_body_with_token(b"real-token"))
        .unwrap();
    let (with_token_id, _) = outbound.recv().await.expect("queued send");
    hub.deliver_response(with_token_id, rfwd_opened_response("fid-token"));

    hub.send_request(conduit_a, 1, rfwd_open_body_with_token(b""))
        .unwrap();
    let (no_token_id, _) = outbound.recv().await.expect("queued send");
    hub.deliver_response(no_token_id, rfwd_opened_response("fid-none"));

    hub.register_forward_for_test("fid-shortcut", conduit_a);

    assert_eq!(
        hub.forward_registry_len(),
        3,
        "all three registrations exist — this test is about their seats, not their presence"
    );
    for forward_id in ["fid-token", "fid-none", "fid-shortcut"] {
        // Timed on purpose. A bare `is_none()` here would pass even
        // if the empty token were *admitted*, because no arrival is
        // queued and an admitted claim simply parks until its budget
        // runs out — the assertion would prove nothing. Given five
        // seconds and asserting the answer comes back inside one,
        // only an actual refusal at the seat check can satisfy it.
        let started = std::time::Instant::now();
        let claimed = hub
            .claim_tcp_accepted(forward_id, b"", Duration::from_secs(5))
            .await;
        assert!(
            claimed.is_none(),
            "{forward_id}: an empty claim token must never pass, whatever the seat holds"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{forward_id}: an empty claim token must be refused at the seat check, not merely time out"
        );
    }
    assert!(
        hub.forward_is_claimable("fid-token") && hub.forward_is_claimable("fid-shortcut"),
        "a registration whose open carried a real token stays claimable by that token"
    );
    assert!(
        !hub.forward_is_claimable("fid-none"),
        "and only the one that carried nothing is unclaimable"
    );
}

/// **Hole 3 — any conduit could tear down any forward.** The
/// `RemoteForwardClose` arm removed the registration and reset every
/// queued arrival without ever comparing against the conduit
/// `ControlMux::map_inbound` had just resolved, so conduit B could
/// delete conduit A's forward and kill A's in-flight streams. Both
/// halves are proven here:
///
/// 1. **inbound** — B's close is answered `success` by the target at
///    a moment when the id is registered to A (B sent it before the
///    id existed, which is the one shape the relay must still
///    forward): nothing may change, and A's queued arrival must
///    survive un-reset and still be claimable.
/// 2. **outbound** — once the id *is* registered to A, B's next close
///    is refused before a `daemon_request_id` is even minted and
///    without a byte reaching the target, which cannot tell the two
///    conduits apart itself.
///
/// And the guard refuses non-owners rather than everyone: A's own
/// close of its own forward still tears it down.
#[cfg(unix)]
#[tokio::test]
async fn a_conduit_can_neither_relay_nor_land_a_close_for_another_conduits_forward() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    let mut outbound = hub
        .take_outbound_receiver()
        .expect("hub has an outbound receiver");

    // B asks to close "fid-a" before it exists — an id this hub does
    // not know is relayed (it may be a close racing its own open, and
    // the target is the right place to answer for it), so B really
    // does hold a live `daemon_request_id` for a close of that id.
    hub.send_request(conduit_b, 0, rfwd_close_body("fid-a"))
        .expect("a close for an unknown id is relayed, not refused");
    let (close_id_b, _) = outbound.recv().await.expect("queued send");

    // A opens fid-a for real.
    hub.send_request(conduit_a, 1, rfwd_open_body_with_token(b"token-a"))
        .unwrap();
    let (open_id_a, _) = outbound.recv().await.expect("queued send");
    hub.deliver_response(open_id_a, rfwd_opened_response("fid-a"));
    assert_eq!(hub.forward_owner("fid-a"), Some(conduit_a));

    // ... and an arrival is queued for A, waiting to be claimed.
    let (_client, _server, _target_send, mut target_recv) = queue_one_arrival(&hub, "fid-a").await;

    // (1) B's close lands, answered success, while A owns the id.
    hub.deliver_response(close_id_b, wire::Response { body: None });

    assert_eq!(
        hub.forward_owner("fid-a"),
        Some(conduit_a),
        "a close from a conduit that does not own the id must change nothing"
    );
    assert!(
        hub.forward_is_claimable("fid-a"),
        "and must not disturb its seat either"
    );
    let mut buf = [0u8; 8];
    let quiet = tokio::time::timeout(Duration::from_millis(200), target_recv.read(&mut buf)).await;
    assert!(
        quiet.is_err(),
        "the owner's queued stream must not be reset by a stranger's close, got {quiet:?}"
    );
    assert!(
        hub.claim_tcp_accepted("fid-a", b"token-a", Duration::from_secs(5))
            .await
            .is_some(),
        "and the owner must still be able to claim the arrival that was waiting for it"
    );

    // (2) B tries again now that the id is registered to A: refused
    // before anything is allocated, and nothing reaches the target.
    assert!(
        matches!(
            hub.send_request(conduit_b, 2, rfwd_close_body("fid-a")),
            Err(HubSendError::NotOwner)
        ),
        "a close for another conduit's forward must be refused, not relayed"
    );
    let leaked = tokio::time::timeout(Duration::from_millis(100), outbound.recv()).await;
    assert!(
        leaked.is_err(),
        "nothing may reach the target — it cannot tell the two conduits apart, got {leaked:?}"
    );

    // The owner's own close still works: this is a non-owner guard,
    // not a blanket refusal.
    hub.send_request(conduit_a, 3, rfwd_close_body("fid-a"))
        .expect("the owner's own close must still be relayed");
    let (close_id_a, _) = outbound.recv().await.expect("queued send");
    hub.deliver_response(close_id_a, wire::Response { body: None });
    assert!(
        hub.forward_owner("fid-a").is_none(),
        "the owner's own close must tear its own registration down"
    );
}

/// **Finding F5 — a target cannot squat a `forward_id` by answering
/// the wrong request.** The `RfwdOpened` arm of
/// [`ControlHub::deliver_response`] used to fire on any
/// `daemon_request_id` whatsoever, so a misbehaving target could
/// answer an ordinary, unrelated request (a `SessionRead` here —
/// long-poll, correlated, entirely routine) with
/// `RemoteForwardOpened { forward_id: Z }` and have Z registered
/// under whichever conduit made that request. With no pending open
/// there was no token to seat, so Z landed permanently unclaimable —
/// and the conduit that later legitimately opened Z hit the
/// duplicate-rejection arm, kept no registration of its own, and was
/// left with a forward that silently never worked.
///
/// Both halves are asserted: the unsolicited answer registers
/// *nothing at all* (registry length, not just "this id is absent"),
/// and the same `forward_id` is then opened and claimed end to end by
/// its rightful conduit.
///
/// Mutation check: drop the `pending_rfwd_open.is_none()` arm from
/// `deliver_response` and the first assertion fails —
/// `forward_registry_len()` is 1, the squatted registration owned by
/// conduit A.
#[cfg(unix)]
#[tokio::test]
async fn an_rfwd_opened_answering_a_request_that_was_never_an_open_registers_nothing() {
    let hub = test_hub();
    let (conduit_a, _rx_a) = hub.register_conduit();
    let (conduit_b, _rx_b) = hub.register_conduit();
    let mut outbound = hub
        .take_outbound_receiver()
        .expect("hub has an outbound receiver");

    // Conduit A issues something that is not a forward open at all.
    hub.send_request(
        conduit_a,
        0,
        wire::control_message::Body::SessionRead(wire::SessionRead {
            session_id: "sess-1".into(),
            ..Default::default()
        }),
    )
    .expect("an ordinary session read is relayed");
    let (read_id, _) = outbound.recv().await.expect("queued send");

    // The target answers that read with a forward-open reply.
    hub.deliver_response(read_id, rfwd_opened_response("fid-squat"));

    assert_eq!(
        hub.forward_registry_len(),
        0,
        "a RemoteForwardOpened answering a request that was never a RemoteForwardOpen must \
         register nothing — under the answering conduit or anyone else"
    );
    assert!(
        hub.forward_owner("fid-squat").is_none(),
        "and the squatted id must be owned by nobody"
    );

    // The id is therefore still free, and its rightful opener gets a
    // real, claimable registration rather than the duplicate-rejection
    // path and a forward that never works.
    hub.send_request(conduit_b, 0, rfwd_open_body_with_token(b"token-b"))
        .unwrap();
    let (open_id, _) = outbound.recv().await.expect("queued send");
    hub.deliver_response(open_id, rfwd_opened_response("fid-squat"));
    assert_eq!(
        hub.forward_owner("fid-squat"),
        Some(conduit_b),
        "the conduit that legitimately opened the id must own it"
    );
    assert!(
        hub.forward_is_claimable("fid-squat"),
        "and its seat must hold the token its own open carried, not be dead on arrival"
    );
    let _arrival = queue_one_arrival(&hub, "fid-squat").await;
    assert!(
        hub.claim_tcp_accepted("fid-squat", b"token-b", Duration::from_secs(5))
            .await
            .is_some(),
        "the rightful owner must be able to claim its arrivals end to end"
    );

    // The gate is "was there a pending open", never "was the token
    // non-empty": an open that carried no token still registers, still
    // permanently unclaimable (`ClaimSeat::seat`), exactly as before.
    hub.send_request(conduit_b, 1, rfwd_open_body_with_token(b""))
        .unwrap();
    let (empty_open_id, _) = outbound.recv().await.expect("queued send");
    hub.deliver_response(empty_open_id, rfwd_opened_response("fid-empty-open"));
    assert_eq!(
        hub.forward_owner("fid-empty-open"),
        Some(conduit_b),
        "an open carrying an empty claim token is still a pending open and must still \
         register — the F5 gate must not have swallowed the empty-token path"
    );
    assert!(
        !hub.forward_is_claimable("fid-empty-open"),
        "and it must stay permanently unclaimable, exactly as it was before the gate"
    );
}

/// **Finding F2 — an orphaned parked claim must not hold its permit
/// for its whole budget.** [`ControlHub::unregister_conduit`] removes
/// a dead conduit's registrations and resets its queued arrivals, but
/// nothing woke the claimants parked in
/// [`ControlHub::claim_tcp_accepted`] on those very forwards. Each
/// such claimant sat out the rest of its wait budget (up to
/// `qsh_proto::local::LOCAL_WAIT_MAX`) still holding its
/// [`ClaimPool`] permit, in a bucket keyed by a [`ConduitId`] that is
/// never reissued — so the hub-wide pool shrank with no live conduit
/// holding anything, and repeating it emptied the pool outright.
///
/// Driven at the hub ceiling, across as many conduits as the pool
/// divides into, because that is the shape of the exhaustion: every
/// permit on this hub held by conduits that are all dead. The window
/// asserted is one second of a sixty-second budget — a claimant that
/// merely times out cannot satisfy it.
///
/// Mutation check: remove `unregister_conduit`'s
/// `tunnel_notify.notify_waiters()` and the parked claimants never
/// wake — the bounded `timeout` around the join handle fails with
/// "must wake when its forward is swept".
#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn unregister_conduit_wakes_the_claims_parked_on_the_forwards_it_sweeps() {
    let hub = test_hub();
    let shares = MAX_PARKED_CLAIMS_PER_HUB / MAX_PARKED_CLAIMS_PER_CONDUIT;
    let mut conduits = Vec::new();
    let mut inboxes = Vec::new();
    let mut parked = Vec::new();

    // Fill the hub pool exactly, the way real claim loops do: one
    // parked claim per registered forward, each holding the permit
    // `LocalctlDaemon::serve_tcp_accepted` acquires before it calls
    // `claim_tcp_accepted` and drops the instant that call returns.
    for c in 0..shares {
        let (conduit, rx) = hub.register_conduit();
        inboxes.push(rx);
        conduits.push(conduit);
        for n in 0..MAX_PARKED_CLAIMS_PER_CONDUIT {
            let forward_id = format!("fid-{c}-{n}");
            let token = hub.register_forward_for_test(&forward_id, conduit);
            let permit = hub
                .try_acquire_claim_permit(&forward_id)
                .expect("every permit up to each owner's own share must be grantable");
            let hub_for_task = Arc::clone(&hub);
            parked.push(tokio::spawn(async move {
                let claimed = hub_for_task
                    .claim_tcp_accepted(&forward_id, &token, Duration::from_secs(60))
                    .await;
                drop(permit);
                claimed
            }));
        }
    }
    // Let every spawned claim actually reach its wait.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        hub.parked_claims_held(),
        MAX_PARKED_CLAIMS_PER_HUB,
        "the pool must start out exactly spent — this test is about giving it back"
    );

    // Every one of those conduits dies.
    for conduit in conduits {
        hub.unregister_conduit(conduit);
    }

    for handle in parked {
        let woken = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect(
                "a claim parked on a forward whose conduit just died must wake when its \
                 forward is swept, not sit out its whole wait budget holding a permit",
            )
            .expect("the parked claim task must not panic");
        assert!(
            woken.is_none(),
            "a swept forward admits nobody — the woken claimant must leave with nothing"
        );
    }
    assert_eq!(
        hub.parked_claims_held(),
        0,
        "every permit must be back in the hub pool, not stranded in the bucket of a \
         ConduitId that will never be reissued"
    );

    // ...and the restored capacity is real: a different, live conduit
    // can take a full share and park on its own forward.
    let (late, _rx_late) = hub.register_conduit();
    let late_token = hub.register_forward_for_test("fid-late", late);
    let late_permits: Vec<_> = (0..MAX_PARKED_CLAIMS_PER_CONDUIT)
        .map(|_| {
            hub.try_acquire_claim_permit("fid-late")
                .expect("a live conduit must be able to park once the dead ones let go")
        })
        .collect();
    let late_claim = tokio::spawn({
        let hub = Arc::clone(&hub);
        async move {
            hub.claim_tcp_accepted("fid-late", &late_token, Duration::from_secs(60))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !late_claim.is_finished(),
        "the late conduit's claim must reach the wait — parked on its own live forward, \
         not refused"
    );

    late_claim.abort();
    drop(late_permits);
    drop(inboxes);
}
