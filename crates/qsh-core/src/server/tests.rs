use super::*;
use crate::acl::{AllowAllPinned, DenyAll};
use crate::audit::{FailingAuditSink, MemoryAuditSink};
use crate::broker::{
    Broker, BrokerConfig, PipeFactory, PipeHandle, RESUME_TOKEN_LEN, SessionState, SourceExit,
    TestClock,
};

const ALL_CAPS: &[&str] = &["exec", "session"];

fn ctx(principal: Principal, caps: &[&str]) -> ConnCtx {
    ConnCtx {
        principal,
        auth_path: AuthPath::Pin,
        peer_fingerprint: Some(PeerFingerprint::new([7u8; 32])),
        peer_addr: "127.0.0.1:5000".parse().unwrap(),
        conn_id: 42,
        capabilities: caps.iter().map(|s| s.to_string()).collect(),
        is_reverse_registration: false,
    }
}

/// A server over a fresh test broker (pipe sources, injected clock).
struct Rig {
    server: Arc<Server>,
    audit: Arc<MemoryAuditSink>,
    broker: Arc<Broker>,
    pipes: Arc<PipeFactory>,
    clock: TestClock,
    /// Same object as `server`'s own (private) `quotas` field — kept
    /// here too so a test can call `flush_expired`/`exec_in_use`
    /// without reaching through `server` (still fine either way: this
    /// module is `crate::server`'s own `tests` submodule, so `Server`'s
    /// private fields are visible from here regardless).
    quotas: Arc<crate::quota::Quotas>,
}

fn rig(authorizer: Arc<dyn Authorizer>) -> Rig {
    rig_with(
        authorizer,
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
    )
}

/// A rig over a caller-built source factory / close grace, so a test can
/// give the "child" its own behaviour (e.g. ignoring SIGHUP).
fn rig_with(
    authorizer: Arc<dyn Authorizer>,
    pipes: Arc<PipeFactory>,
    close_grace: Duration,
) -> Rig {
    rig_with_quota_limits(
        authorizer,
        pipes,
        close_grace,
        crate::quota::QuotaLimits::default(),
    )
}

/// [`rig_with`] plus caller-chosen [`crate::quota::QuotaLimits`], so a
/// quota-cap test does not have to open/reserve hundreds of times to
/// reach the default limits. The broker and the `Server`'s own
/// [`crate::quota::Quotas`] share the same [`TestClock`], so advancing
/// `rig.clock` moves both the session-count and the `exec.run`/audit
/// window axes together, the same way the real `SystemClock` is one
/// clock in production.
fn rig_with_quota_limits(
    authorizer: Arc<dyn Authorizer>,
    pipes: Arc<PipeFactory>,
    close_grace: Duration,
    quota_limits: crate::quota::QuotaLimits,
) -> Rig {
    let clock = TestClock::new();
    let broker = Broker::new(
        Arc::new(clock.clone()),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace,
            quota_limits,
        },
        pipes.clone(),
    );
    let audit = Arc::new(MemoryAuditSink::new());
    let quotas = crate::quota::Quotas::new(quota_limits, Arc::new(clock.clone()));
    let admission = crate::admission::Gate::new(
        Arc::new(clock.clone()),
        crate::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
        crate::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
        crate::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
    );
    let server = Server::with_admission_and_quotas(
        authorizer,
        audit.clone(),
        broker.clone(),
        "host",
        admission,
        quotas.clone(),
    );
    Rig {
        server,
        audit,
        broker,
        pipes,
        clock,
        quotas,
    }
}

fn allow_rig() -> Rig {
    rig(Arc::new(AllowAllPinned))
}

fn exec_start(request_id: u64, argv: &[&str]) -> ControlMessage {
    ControlMessage::new(
        request_id,
        control_message::Body::ExecStart(ExecStart {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: Default::default(),
            timeout_ms: 0,
        }),
    )
}

fn session_open(request_id: u64) -> ControlMessage {
    ControlMessage::new(
        request_id,
        control_message::Body::SessionOpen(wire::SessionOpen {
            argv: vec!["sh".into()],
            cols: 80,
            rows: 24,
            ..Default::default()
        }),
    )
}

fn error_code(msg: &ControlMessage) -> Option<ErrorCode> {
    match &msg.body {
        Some(control_message::Body::Response(wire::Response {
            body: Some(response::Body::Error(e)),
        })) => Some(e.error_code()),
        _ => None,
    }
}

fn response_body(msg: &ControlMessage) -> &response::Body {
    match &msg.body {
        Some(control_message::Body::Response(wire::Response { body: Some(body) })) => body,
        other => panic!("expected a response, got {other:?}"),
    }
}

async fn open_session(rig: &Rig, ctx: &ConnCtx) -> (String, Vec<u8>, PipeHandle) {
    let (opened, pipe) = open_session_full(rig, ctx).await;
    (opened.session_id, opened.ticket, pipe)
}

/// The whole `SessionOpened`, for the tests that need the session's
/// resume credential (every `session.attach` presents one).
async fn open_session_full(rig: &Rig, ctx: &ConnCtx) -> (wire::SessionOpened, PipeHandle) {
    let reply = rig.server.dispatch(ctx, &session_open(1)).await.unwrap();
    let opened = match response_body(&reply) {
        response::Body::SessionOpened(o) => o.clone(),
        other => panic!("expected SessionOpened, got {other:?}"),
    };
    let pipe = rig.pipes.take().expect("pipe handle for the new session");
    (opened, pipe)
}

/// Every session op with a fixed id, as (op name, body) — the set the
/// choke-point tests iterate over.
fn session_bodies(id: &str) -> Vec<(&'static str, control_message::Body)> {
    use control_message::Body;
    vec![
        (
            "open",
            Body::SessionOpen(wire::SessionOpen {
                argv: vec!["sh".into()],
                ..Default::default()
            }),
        ),
        ("list", Body::SessionList(wire::SessionList {})),
        (
            "get",
            Body::SessionGet(wire::SessionGet {
                session_id: id.into(),
            }),
        ),
        (
            "read",
            Body::SessionRead(wire::SessionRead {
                session_id: id.into(),
                ..Default::default()
            }),
        ),
        (
            "write",
            Body::SessionWrite(wire::SessionWrite {
                session_id: id.into(),
                data: b"ls\n".to_vec(),
            }),
        ),
        (
            "resize",
            Body::SessionResize(wire::SessionResize {
                session_id: id.into(),
                cols: 80,
                rows: 24,
            }),
        ),
        (
            "close",
            Body::SessionClose(wire::SessionClose {
                session_id: id.into(),
                signal: None,
            }),
        ),
    ]
}

// ---- exec (M1) — unchanged behaviour ------------------------------

#[tokio::test]
async fn allowed_exec_issues_ticket_and_audits_allow() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let reply = rig
        .server
        .dispatch(&ctx, &exec_start(5, &["true"]))
        .await
        .unwrap();
    assert_eq!(reply.request_id, 5);
    let ticket = match response_body(&reply) {
        response::Body::ExecStarted(started) => started.ticket.clone(),
        other => panic!("expected ExecStarted, got {other:?}"),
    };
    assert_eq!(ticket.len(), TICKET_LEN);
    assert_eq!(rig.server.pending_tickets(), 1);
    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, "allow");
    assert_eq!(recs[0].principal, "device:laptop");
    assert_eq!(recs[0].action, "exec.run");
    assert_eq!(recs[0].request_id, "5");
    // Redeem: bound to the connection and the stream kind, single use.
    assert!(
        rig.server
            .redeem_ticket(41, StreamKind::ExecData, &ticket)
            .is_none(),
        "foreign conn"
    );
    assert!(
        rig.server
            .redeem_ticket(42, StreamKind::SessionData, &ticket)
            .is_none(),
        "wrong stream kind"
    );
    let pending = rig
        .server
        .redeem_ticket(42, StreamKind::ExecData, &ticket)
        .expect("redeem once");
    match pending.purpose {
        TicketPurpose::Exec(exec) => assert_eq!(exec.spec.argv, vec!["true"]),
        other => panic!("expected an exec ticket, got {other:?}"),
    }
    assert!(
        rig.server
            .redeem_ticket(42, StreamKind::ExecData, &ticket)
            .is_none(),
        "single use"
    );
    assert_eq!(rig.server.pending_tickets(), 0);
}

#[tokio::test]
async fn denied_exec_issues_no_ticket_and_audits_deny() {
    let rig = rig(Arc::new(DenyAll));
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let reply = rig
        .server
        .dispatch(&ctx, &exec_start(6, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
    assert_eq!(rig.server.pending_tickets(), 0, "no ticket before ACL pass");
    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, "deny");
}

#[tokio::test]
async fn unpinned_principal_is_denied_under_interim_policy() {
    let rig = allow_rig();
    // A CA-authenticated peer — user or device — is not pinned.
    for principal in [
        Principal::User("dave".into()),
        Principal::Device("laptop".into()),
    ] {
        let mut ctx = ctx(principal, &["exec"]);
        ctx.auth_path = AuthPath::Ca;
        let reply = rig
            .server
            .dispatch(&ctx, &exec_start(1, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
    }
    assert_eq!(rig.server.pending_tickets(), 0);
    let records = rig.audit.records();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.decision == "deny"));
}

/// The subject here is the *per-connection ticket budget*, which
/// `PLAN.md` M8 Step 3 left untouched. It needs an exec quota well
/// clear of that budget to stay observable, because the two now share
/// a numeric boundary: `MAX_PENDING_TICKETS_PER_CONN` and the default
/// `[serve].max_exec_per_principal` are both 32, and an unredeemed
/// exec ticket holds its `ExecPermit` — so under the defaults a single
/// principal's 33rd concurrent exec is refused by the (cross-
/// connection) exec quota before this (per-connection) budget's own
/// "another connection is unaffected" arm can be reached. Raising only
/// this rig's quota keeps the budget's contract asserted exactly as it
/// was; the quota's own boundary is asserted by
/// `exec_cap_rejects_past_the_limit_and_audits_quota_exec_principal`.
#[tokio::test]
async fn outstanding_tickets_per_connection_are_bounded() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_exec_per_principal: MAX_PENDING_TICKETS_PER_CONN * 4,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    for i in 0..MAX_PENDING_TICKETS_PER_CONN {
        let reply = rig
            .server
            .dispatch(&ctx, &exec_start(i as u64, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), None, "ticket {i} must be issued");
    }
    assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
    let reply = rig
        .server
        .dispatch(&ctx, &exec_start(999, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::ResourceExhausted));
    assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
    // `check_ticket_budget` now runs *after* the ACL choke point
    // (main-session arbitration item 3, `handle_exec_start`'s own
    // comment) — so the refused, over-budget request still reaches
    // (and is audited by) ACL first, one more `allow` line than the
    // `MAX_PENDING_TICKETS_PER_CONN` successful opens' own lines.
    assert_eq!(rig.audit.records().len(), MAX_PENDING_TICKETS_PER_CONN + 1);
    // Another connection is unaffected by this one's backlog.
    let mut other = ctx.clone();
    other.conn_id += 1;
    let reply = rig
        .server
        .dispatch(&other, &exec_start(1, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&reply), None);
    assert_eq!(
        rig.server.pending_tickets(),
        MAX_PENDING_TICKETS_PER_CONN + 1
    );
}

#[tokio::test]
async fn exec_without_capability_is_unsupported_and_not_audited() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), &[]);
    let reply = rig
        .server
        .dispatch(&ctx, &exec_start(1, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported));
    assert!(rig.audit.records().is_empty());
    assert_eq!(rig.server.pending_tickets(), 0);
}

// ---- exec.run concurrency quota (`PLAN.md` M8 Step 3, `docs/adr/
// 0010-resource-quotas.md`, verdict arbitration item 5) --------------

#[tokio::test]
async fn exec_cap_rejects_past_the_limit_and_audits_quota_exec_principal() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_exec_per_principal: 1,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let opener = opener_key(&ctx.principal, ctx.auth_path);

    // First exec.run reserves the sole permit.
    let ok = rig
        .server
        .dispatch(&ctx, &exec_start(1, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&ok), None);
    assert_eq!(rig.quotas.exec_in_use(&opener), 1);

    // Second, while the first ticket is still unredeemed, is refused by
    // the per-principal exec cap — not the (much larger) ticket budget.
    let refused = rig
        .server
        .dispatch(&ctx, &exec_start(2, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&refused), Some(ErrorCode::ResourceExhausted));
    match response_body(&refused) {
        response::Body::Error(e) => {
            assert!(e.retryable, "a quota rejection is retryable");
            // The exec axis gets its own wire message, distinct from
            // the session axis's ("session quota exceeded") — see
            // `QuotaKind::wire_message` (docs/CLI.md §6.12).
            assert_eq!(e.message, "exec quota exceeded");
        }
        other => panic!("expected an error response, got {other:?}"),
    }
    // Still only the one ticket the first call issued.
    assert_eq!(rig.server.pending_tickets(), 1);

    let recs = rig.audit.records();
    assert_eq!(
        recs.len(),
        3,
        "first open's ACL allow, second's ACL allow, second's quota deny"
    );
    assert_eq!(recs[0].decision, "allow");
    assert_eq!(recs[1].decision, "allow");
    assert_eq!(recs[2].decision, "deny");
    assert_eq!(recs[2].resource, "quota_exec_principal");
    assert_eq!(recs[2].principal, opener);
    assert_eq!(
        recs[2].request_id, "2",
        "R9 — the exec axis has a real control request id to carry"
    );
    assert_eq!(
        recs[2].peer_addr,
        ctx.peer_addr.to_string(),
        "R4 — the quota deny record must carry the live peer, not \"-\""
    );
}

/// [`crate::exec::run_exec`] reports even a spawn failure ("argv that
/// cannot exec", `ENOENT`) as an `Ok` outcome carrying a
/// shell-convention exit code (its own doc) — there is no early `Err`
/// return that would skip past dropping the exec's `PendingExec`. So
/// the one release point after redemption — [`Server::
/// serve_data_stream`]'s match arm drops `pending` (the permit with
/// it) once `run_exec(pending.spec, ..)` returns — covers "released on
/// child exit" and "released on spawn failure" identically: both are
/// this same drop, at the same point in the same function, differing
/// only in `spec.argv`. Exercising that literal drop through an actual
/// spawned child needs a real QUIC data stream (`FramedSend`/
/// `FramedRecv` wrap `quinn::{Send,Recv}Stream` directly, `qsh-
/// transport`'s `control.rs`) that this in-process `Rig` has no way to
/// create — that level of exercise belongs to `qsh-testkit`'s loopback
/// harness, not this file. What *is* unit-testable here, and is the
/// actual mechanism both scenarios rely on, is that redeeming an exec
/// ticket really does hand the permit to the caller (not leave a
/// second claim on it behind in the ticket map) and that dropping the
/// redeemed value releases it — exactly what `serve_data_stream` does,
/// unconditionally, right after `run_exec` returns.
#[tokio::test]
async fn exec_permit_moves_with_the_redeemed_ticket_and_releases_when_it_is_dropped() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_exec_per_principal: 1,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let opener = opener_key(&ctx.principal, ctx.auth_path);

    let reply = rig
        .server
        .dispatch(&ctx, &exec_start(1, &["true"]))
        .await
        .unwrap();
    let ticket = match response_body(&reply) {
        response::Body::ExecStarted(started) => started.ticket.clone(),
        other => panic!("expected ExecStarted, got {other:?}"),
    };
    assert_eq!(rig.quotas.exec_in_use(&opener), 1);

    // Redeem — the real production method (`Server::serve_data_stream`'s
    // own call). Redemption moves the permit out of the ticket map; it
    // does not itself release it.
    let redeemed = rig
        .server
        .redeem_ticket(ctx.conn_id, StreamKind::ExecData, &ticket)
        .expect("redeem once");
    assert_eq!(
        rig.quotas.exec_in_use(&opener),
        1,
        "redeeming a ticket must not itself free the slot"
    );

    // What `serve_data_stream` does next — `run_exec(pending.spec,
    // ..).await` — needs a real stream and is unreachable here; what it
    // does *after* that call, on every outcome (child exit or spawn
    // failure alike), is drop `pending`. That is what this reproduces.
    drop(redeemed);
    assert_eq!(
        rig.quotas.exec_in_use(&opener),
        0,
        "the permit is released once the redeemed ticket is dropped"
    );

    // And the slot really is usable again, not just reported as such.
    let second = rig
        .server
        .dispatch(&ctx, &exec_start(2, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&second), None);
}

/// M8 Step 5a: [`Server::log_accept_heartbeat`]'s snapshot carries the
/// actual admission/quota counters and `pending_tickets`/`live_conns`
/// state, and its 5-tick idle suppression only kicks in once the
/// snapshot has stopped moving. No `tracing-subscriber` dev-dep exists
/// in this crate yet, so this pins the counter-snapshot/logging
/// *decision* directly (brief §3.4's documented fallback) rather than
/// capturing the emitted line's fields through a subscriber layer.
#[tokio::test]
async fn accept_heartbeat_snapshot_reflects_counters_and_suppresses_when_idle() {
    let rig = rig(Arc::new(AllowAllPinned));
    let opener = "device:laptop".to_string();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

    let mut last_logged = None;
    let mut ticks_since_log: u32 = 0;

    // Tick 1: everything at zero. First tick always "logs" (nothing to
    // suppress against yet) and resets the idle counter.
    rig.server
        .log_accept_heartbeat(&mut last_logged, &mut ticks_since_log);
    assert_eq!(
        last_logged,
        Some(AcceptHeartbeat {
            admitted: 0,
            retry: 0,
            ignore: 0,
            refuse: 0,
            connection_quota_refused: 0,
            live_conns: 0,
            pending_tickets: 0,
            quota_rejections: 0,
        })
    );
    assert_eq!(ticks_since_log, 0);

    // Reserve a connection slot directly (the real reservation happens
    // in the accept path, `Server::serve_connection` — out of reach
    // from a bare `dispatch` call here) and open a session (mints a
    // ticket), so the next snapshot must show both moving.
    let _connection_permit = rig.quotas.reserve_connection(&opener).unwrap();
    let opened = rig.server.dispatch(&ctx, &session_open(1)).await.unwrap();
    assert_eq!(error_code(&opened), None);
    assert_eq!(rig.quotas.connections_per_principal_in_use(&opener), 1);
    assert_eq!(rig.server.pending_tickets(), 1);

    rig.server
        .log_accept_heartbeat(&mut last_logged, &mut ticks_since_log);
    let after_open = last_logged.expect("logged");
    assert_eq!(after_open.live_conns, 1);
    assert_eq!(after_open.pending_tickets, 1);
    assert_eq!(ticks_since_log, 0, "a moved snapshot always logs");

    // Nothing changes for the next 4 ticks: suppressed (idle-tick
    // counter climbs but stays under 5).
    for expected_idle_ticks in 1..5 {
        rig.server
            .log_accept_heartbeat(&mut last_logged, &mut ticks_since_log);
        assert_eq!(last_logged, Some(after_open));
        assert_eq!(ticks_since_log, expected_idle_ticks);
    }

    // The 5th idle tick in a row forces a log even though nothing
    // moved, and resets the idle counter (§3.2: "5틱에 한 번만 낸다").
    rig.server
        .log_accept_heartbeat(&mut last_logged, &mut ticks_since_log);
    assert_eq!(last_logged, Some(after_open));
    assert_eq!(ticks_since_log, 0, "the forced 5th tick resets the counter");
}

/// [`Server::pending_tickets`] does not purge expired
/// entries (its own doc comment — a handful of existing tests are
/// pinned to that non-purging count), so a quiet-period backlog of
/// expired-but-unswept tickets would otherwise make the heartbeat's
/// old read look identical to a genuine leak.
/// [`Server::pending_unexpired_tickets`] is the purging read the
/// heartbeat uses instead. Forces a live ticket to look expired the
/// same way `exec_permit_is_released_when_its_ticket_expires` does
/// below, then checks the purging read reports it gone — and that its
/// own sweep actually removed the entry, not merely filtered it, by
/// checking the non-purging count afterward too.
#[tokio::test]
async fn pending_unexpired_tickets_purges_an_expired_ticket() {
    let rig = rig(Arc::new(AllowAllPinned));
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

    let opened = rig.server.dispatch(&ctx, &session_open(1)).await.unwrap();
    assert_eq!(error_code(&opened), None);
    assert_eq!(rig.server.pending_tickets(), 1);

    // Force the outstanding ticket to look expired (same technique as
    // `exec_permit_is_released_when_its_ticket_expires` below).
    {
        let mut tickets = rig.server.tickets.lock().unwrap_or_else(|e| e.into_inner());
        for ticket in tickets.values_mut() {
            ticket.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }

    assert_eq!(
        rig.server.pending_unexpired_tickets(),
        0,
        "the purging read must not count an expired ticket"
    );
    assert_eq!(
        rig.server.pending_tickets(),
        0,
        "the purging read's own sweep must have removed the entry, not just filtered it"
    );
}

/// The path the verdict flags: an unredeemed exec ticket's permit must
/// not survive the ticket itself. Production reaches an expired ticket
/// after `TICKET_TTL` (30 s) of real wall-clock time — `expires_at`
/// uses `std::time::Instant::now()` directly, not the injected
/// `TestClock`, so this test forces the same state by hand and
/// exercises the sweep itself (`Server::pending_tickets_for`, reached
/// through `check_ticket_budget` on the next request), not the wait.
#[tokio::test]
async fn exec_permit_is_released_when_its_ticket_expires() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_exec_per_principal: 1,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let opener = opener_key(&ctx.principal, ctx.auth_path);

    let first = rig
        .server
        .dispatch(&ctx, &exec_start(1, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&first), None);
    assert_eq!(rig.quotas.exec_in_use(&opener), 1);

    // Confirms the slot really is still held while the ticket lives.
    let refused = rig
        .server
        .dispatch(&ctx, &exec_start(2, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&refused), Some(ErrorCode::ResourceExhausted));

    // Force the outstanding ticket to look expired.
    {
        let mut tickets = rig.server.tickets.lock().unwrap_or_else(|e| e.into_inner());
        for ticket in tickets.values_mut() {
            ticket.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }

    // Any call that reaches `pending_tickets_for` (via
    // `check_ticket_budget`) sweeps expired entries first — dropping
    // the expired `PendingExec` and, with it, its `ExecPermit`.
    let after_sweep = rig
        .server
        .dispatch(&ctx, &exec_start(3, &["true"]))
        .await
        .unwrap();
    assert_eq!(
        error_code(&after_sweep),
        None,
        "the freed slot admits a new exec"
    );
    assert_eq!(
        rig.quotas.exec_in_use(&opener),
        1,
        "exactly one live permit, not two"
    );
}

/// `Server::quota_housekeeping`'s new first step (A9 of the M8 Step
/// 3a fix-3 sweep): sweeping expired tickets is no longer something
/// only a *request* reaches through `check_ticket_budget`/
/// `pending_tickets_for` — the housekeeping call itself must do it,
/// so `Server::run`'s tick, its post-loop shutdown call,
/// `purge_connection`, and `reverse::target`'s per-connection tick
/// all bound an expired unredeemed exec ticket's `ExecPermit` to
/// `TICKET_TTL` plus one tick, with no request required to free it.
#[tokio::test]
async fn quota_housekeeping_sweeps_expired_tickets_before_flushing_audit() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_exec_per_principal: 1,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let opener = opener_key(&ctx.principal, ctx.auth_path);

    let first = rig
        .server
        .dispatch(&ctx, &exec_start(1, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&first), None);
    assert_eq!(rig.quotas.exec_in_use(&opener), 1);

    // Force the outstanding ticket to look expired, same as
    // `exec_permit_is_released_when_its_ticket_expires` above.
    {
        let mut tickets = rig.server.tickets.lock().unwrap_or_else(|e| e.into_inner());
        for ticket in tickets.values_mut() {
            ticket.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }

    // No request in between — `quota_housekeeping` alone sweeps it.
    rig.server.quota_housekeeping();

    assert_eq!(
        rig.quotas.exec_in_use(&opener),
        0,
        "quota_housekeeping released the expired ticket's permit on its own"
    );
}

/// Mechanical form of `docs/adr/0010-resource-quotas.md` §9's
/// "collect under the guard, drop outside" rule (B4 of the M8 Step 3a
/// fix-3 sweep, extended by M8 Step 3b ruling A4 to the
/// `remote_forwards` lock as well): exercises all four sites that
/// sweep expired tickets — `pending_tickets_for`, `issue_ticket`,
/// `purge_connection`, `quota_housekeeping` — each against an expired
/// ticket whose `ExecPermit` is about to drop, plus (at the
/// `purge_connection` site) a live `RemoteForwardEntry` whose own
/// `RemoteForwardPermit` is about to drop from the same call, and
/// asserts `crate::quota::lock_order::violations() == 0` once all
/// four have run. `VIOLATIONS` is process-global, not per-test
/// (`lock_order`'s own doc) — `cargo nextest` runs one test per
/// process, so a nonzero count read back here is never cross-test
/// noise.
#[tokio::test]
async fn ticket_sweep_sites_never_drop_an_exec_permit_while_the_tickets_lock_is_held() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            // Generous — this test is about lock order, not about
            // exhausting the exec cap, and each site below leaves one
            // extra permit outstanding for the next site to sweep.
            max_exec_per_principal: 8,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let opener = opener_key(&ctx.principal, ctx.auth_path);
    let conn_id = ctx.conn_id;

    // Reserve a real `ExecPermit` and wrap it in an already-expired
    // `Ticket`, the same shape `Server::handle_exec_start` builds
    // before `issue_ticket` — but built directly so each site below
    // can be called on its own, not only reachable through
    // `dispatch`'s own call chain (which would sweep at
    // `pending_tickets_for` before any later site got a turn).
    let expired_exec_ticket = |exec_id: &str| -> Ticket {
        let permit = rig.quotas.reserve_exec(&opener).unwrap();
        Ticket {
            purpose: TicketPurpose::Exec(PendingExec {
                exec_id: exec_id.to_string(),
                spec: crate::exec::ExecSpec {
                    argv: vec!["true".to_string()],
                    env: Vec::new(),
                    timeout: None,
                },
                permit,
            }),
            conn_id,
            expires_at: Instant::now() - Duration::from_secs(1),
        }
    };
    let insert = |key: u8, ticket: Ticket| {
        let mut tickets = rig.server.tickets.lock().unwrap_or_else(|e| e.into_inner());
        tickets.insert([key; TICKET_LEN], ticket);
    };

    // Site 1: `pending_tickets_for`.
    insert(1, expired_exec_ticket("a"));
    let _ = rig.server.pending_tickets_for(conn_id);

    // Site 2: `issue_ticket`'s own sweep (distinct from
    // `pending_tickets_for`'s — see `check_ticket_budget`'s call
    // order, which always runs the latter first inside `dispatch`).
    insert(2, expired_exec_ticket("b"));
    let fresh_permit = rig.quotas.reserve_exec(&opener).unwrap();
    let _ = rig.server.issue_ticket(
        conn_id,
        TicketPurpose::Exec(PendingExec {
            exec_id: "c".to_string(),
            spec: crate::exec::ExecSpec {
                argv: vec!["true".to_string()],
                env: Vec::new(),
                timeout: None,
            },
            permit: fresh_permit,
        }),
    );

    // Site 3: `purge_connection` — removes every ticket for `conn_id`
    // regardless of expiry, including the still-live one `issue_ticket`
    // just inserted above; also (A4) removes every `RemoteForwardEntry`
    // this `conn_id` opened, whose own `RemoteForwardPermit` must drop
    // only after `remote_forwards`'s lock is released, exactly like
    // `ExecPermit` above and the tickets lock.
    {
        let remote_forward_permit = rig.quotas.reserve_remote_forward(&opener).unwrap();
        let task = tokio::spawn(std::future::pending::<()>());
        rig.server.lock_remote_forwards().insert(
            "adv-a4-forward".to_string(),
            RemoteForwardEntry {
                conn_id,
                owner: opener.clone(),
                task,
                _quota: remote_forward_permit,
            },
        );
    }
    rig.server.purge_connection(conn_id, ()).await;

    // Site 4: `quota_housekeeping`.
    insert(4, expired_exec_ticket("e"));
    rig.server.quota_housekeeping();

    assert_eq!(
        crate::quota::lock_order::violations(),
        0,
        "a quota permit (ExecPermit or RemoteForwardPermit) dropped while a non-leaf lock \
         (tickets or remote_forwards) was still held"
    );
}

#[tokio::test]
async fn exec_quota_rejections_aggregate_into_one_first_line_and_one_summary() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_exec_per_principal: 1,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);

    let first = rig
        .server
        .dispatch(&ctx, &exec_start(1, &["true"]))
        .await
        .unwrap();
    assert_eq!(error_code(&first), None);
    let before = rig.audit.records().len();

    // A burst of 3 rejections, all inside the same aggregation window.
    for i in 0..3u64 {
        let reply = rig
            .server
            .dispatch(&ctx, &exec_start(100 + i, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::ResourceExhausted));
    }
    // Each of the 3 rejected calls still writes its own ACL *allow*
    // line (`check_ticket_budget`/ACL run before the quota check, same
    // as `exec_cap_rejects_past_the_limit_and_audits_quota_exec_
    // principal`) — what this test pins is that only one of those
    // three calls also produced a *quota* line, not that the audit log
    // grew by exactly one record overall.
    let quota_lines: Vec<_> = rig
        .audit
        .records()
        .into_iter()
        .skip(before)
        .filter(|r| r.resource == "quota_exec_principal")
        .collect();
    assert_eq!(
        quota_lines.len(),
        1,
        "only the burst's first rejection gets its own quota line"
    );
    assert_eq!(quota_lines[0].count, None);

    // The tick `Server::run`'s accept loop drives, exercised directly:
    // the burst has already stopped, so only the periodic flush (not
    // the lazy `record_rejection` path) can close this window.
    rig.clock
        .advance(crate::admission::AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));
    let flushed = rig.quotas.flush_expired(rig.quotas.now());
    for record in &flushed {
        rig.audit.record(record).unwrap();
    }
    assert_eq!(flushed.len(), 1);
    assert_eq!(
        flushed[0].count,
        Some(2),
        "the two suppressed rejections after the burst's first line"
    );
    assert_eq!(flushed[0].resource, "quota_exec_principal");

    // A second flush at the same instant finds nothing left to close.
    assert!(rig.quotas.flush_expired(rig.quotas.now()).is_empty());
}

// ---- session-count quota (`Broker::open_with_opener`'s own
// `reserve_session`) + ACL-vs-quota ordering (verdict arbitration item
// 11) --------------------------------------------------------------

/// An unauthorized principal must never learn "the host is at
/// capacity" as a substitute for "you are not allowed here" — that
/// would be an oracle on occupancy to a peer who should learn nothing.
#[tokio::test]
async fn saturated_quota_still_answers_permission_denied_to_an_unauthorized_principal() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_sessions: 1,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let allowed_ctx = ctx(Principal::Device("laptop".into()), &["session"]);
    let _opened = open_session(&rig, &allowed_ctx).await;
    assert_eq!(rig.broker.session_count(), 1);

    // A CA-asserted principal is not pinned, so `AllowAllPinned` denies
    // it outright (same setup as
    // `unpinned_principal_is_denied_under_interim_policy`) — and the
    // host's single session slot is already saturated by the open
    // above.
    let mut denied_ctx = allowed_ctx.clone();
    denied_ctx.principal = Principal::User("mallory".into());
    denied_ctx.auth_path = AuthPath::Ca;
    denied_ctx.conn_id += 1;

    let reply = rig
        .server
        .dispatch(&denied_ctx, &session_open(9))
        .await
        .unwrap();
    assert_eq!(
        error_code(&reply),
        Some(ErrorCode::PermissionDenied),
        "ACL must run before the quota check"
    );
    // Nothing was created for the refused attempt.
    assert_eq!(rig.broker.session_count(), 1);
    assert_eq!(
        rig.server.pending_tickets(),
        1,
        "only the first, allowed open's ticket"
    );
}

/// Main-session arbitration round, item 3: `handle_exec_start` now
/// runs `check_ticket_budget` *after* the ACL choke point (F4 of the
/// M8 Step 3a conformance sweep had instead documented — and pinned —
/// the pre-existing order where the ticket-budget check ran first;
/// this reverses that call). `check_ticket_budget` creates nothing, so
/// there was never a resource-creation reason to run it early, and
/// leaving it first made `RESOURCE_EXHAUSTED` vs. `PERMISSION_DENIED`
/// tell an unauthorized caller something about its own connection's
/// state before ACL ever got a say. This pins the order directly, on
/// one connection whose ticket budget is genuinely exhausted: a
/// principal ACL denies still sees `PERMISSION_DENIED` (proving ACL
/// runs first), and a principal ACL allows still sees
/// `RESOURCE_EXHAUSTED` (proving the ticket-budget check still runs,
/// second).
#[tokio::test]
async fn exec_ticket_budget_follows_the_acl_choke_point_on_the_same_connection() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_exec_per_principal: MAX_PENDING_TICKETS_PER_CONN * 4,
            ..crate::quota::QuotaLimits::default()
        },
    );
    // A pinned device fills its own connection's ticket budget under
    // an ACL that allows it — ordinary, authorized traffic.
    let allowed_ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    for i in 0..MAX_PENDING_TICKETS_PER_CONN {
        let reply = rig
            .server
            .dispatch(&allowed_ctx, &exec_start(i as u64, &["true"]))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), None, "ticket {i} must be issued");
    }
    assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);

    // The SAME connection (`conn_id` unchanged), but the principal on
    // this next request is one `AllowAllPinned` denies outright — not
    // a realistic mid-connection identity change, just the sharpest
    // way to isolate which check answers first.
    let mut denied_same_conn = allowed_ctx.clone();
    denied_same_conn.principal = Principal::User("mallory".into());
    denied_same_conn.auth_path = AuthPath::Ca;

    let reply = rig
        .server
        .dispatch(&denied_same_conn, &exec_start(999, &["true"]))
        .await
        .unwrap();
    assert_eq!(
        error_code(&reply),
        Some(ErrorCode::PermissionDenied),
        "ACL now runs before check_ticket_budget — an unauthorized \
         principal must never see RESOURCE_EXHAUSTED as a substitute \
         for PERMISSION_DENIED, even on a connection whose ticket \
         budget happens to be exhausted"
    );
    assert_eq!(
        rig.server.pending_tickets(),
        MAX_PENDING_TICKETS_PER_CONN,
        "the denied attempt must not have issued a ticket"
    );

    // The SAME connection, still at its ticket budget, but a principal
    // ACL allows: PERMISSION_DENIED is off the table, so the ticket
    // budget check underneath must still fire.
    let reply = rig
        .server
        .dispatch(&allowed_ctx, &exec_start(1000, &["true"]))
        .await
        .unwrap();
    assert_eq!(
        error_code(&reply),
        Some(ErrorCode::ResourceExhausted),
        "an ACL-allowed principal must still be bounded by its \
         connection's own ticket budget"
    );
    assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
}

/// `handle_session_open`'s twin of the pin above: the M8 Step 3a
/// conformance sweep's F4 had also left `session.open` checking its
/// ticket budget ahead of the ACL choke point (adversary finding A1) —
/// this pins the corrected order the same way, on one connection whose
/// ticket budget is genuinely exhausted: a principal ACL denies still
/// sees `PERMISSION_DENIED` (proving ACL runs first) *and* still gets
/// its own ACL-deny audit row (proving the denied attempt reached the
/// choke point rather than being short-circuited by the ticket-budget
/// check before ACL ever ran), while a principal ACL allows still sees
/// `RESOURCE_EXHAUSTED` (proving the ticket-budget check still runs,
/// second).
#[tokio::test]
async fn session_open_ticket_budget_follows_the_acl_choke_point_on_the_same_connection() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_sessions: MAX_PENDING_TICKETS_PER_CONN * 4,
            max_sessions_per_principal: MAX_PENDING_TICKETS_PER_CONN * 4,
            ..crate::quota::QuotaLimits::default()
        },
    );
    // A pinned device fills its own connection's ticket budget under
    // an ACL that allows it — ordinary, authorized traffic.
    let allowed_ctx = ctx(Principal::Device("laptop".into()), &["session"]);
    for i in 0..MAX_PENDING_TICKETS_PER_CONN {
        let reply = rig
            .server
            .dispatch(&allowed_ctx, &session_open(i as u64))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), None, "ticket {i} must be issued");
    }
    assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
    let records_before_deny = rig.audit.records().len();

    // The SAME connection (`conn_id` unchanged), but the principal on
    // this next request is one `AllowAllPinned` denies outright — not
    // a realistic mid-connection identity change, just the sharpest
    // way to isolate which check answers first.
    let mut denied_same_conn = allowed_ctx.clone();
    denied_same_conn.principal = Principal::User("mallory".into());
    denied_same_conn.auth_path = AuthPath::Ca;

    let reply = rig
        .server
        .dispatch(&denied_same_conn, &session_open(999))
        .await
        .unwrap();
    assert_eq!(
        error_code(&reply),
        Some(ErrorCode::PermissionDenied),
        "ACL now runs before check_ticket_budget on session.open too — \
         an unauthorized principal must never see RESOURCE_EXHAUSTED as \
         a substitute for PERMISSION_DENIED, even on a connection whose \
         ticket budget happens to be exhausted"
    );
    assert_eq!(
        rig.server.pending_tickets(),
        MAX_PENDING_TICKETS_PER_CONN,
        "the denied attempt must not have issued a ticket"
    );
    let recs = rig.audit.records();
    assert_eq!(
        recs.len(),
        records_before_deny + 1,
        "the ACL choke point still writes an audit row for the denied \
         attempt — it was reached and it decided, it did not get \
         short-circuited by a ticket-budget check running first"
    );
    assert_eq!(
        recs.last().unwrap().decision,
        "deny",
        "the denied attempt's own audit row records the ACL deny"
    );

    // The SAME connection, still at its ticket budget, but a principal
    // ACL allows: PERMISSION_DENIED is off the table, so the ticket
    // budget check underneath must still fire.
    let reply = rig
        .server
        .dispatch(&allowed_ctx, &session_open(1000))
        .await
        .unwrap();
    assert_eq!(
        error_code(&reply),
        Some(ErrorCode::ResourceExhausted),
        "an ACL-allowed principal must still be bounded by its \
         connection's own ticket budget"
    );
    assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
}

/// `session.close` must release its own session's unredeemed ticket
/// (main-session arbitration, "병행 정리 묶음 판정" (c)) — the closed
/// session's slot in the connection's `MAX_PENDING_TICKETS_PER_CONN`
/// budget frees up immediately rather than sitting dead until
/// `TICKET_TTL` or the connection itself closes.
#[tokio::test]
async fn session_close_releases_that_sessions_unredeemed_ticket() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_sessions: MAX_PENDING_TICKETS_PER_CONN * 4,
            max_sessions_per_principal: MAX_PENDING_TICKETS_PER_CONN * 4,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), &["session"]);
    let mut session_ids = Vec::with_capacity(MAX_PENDING_TICKETS_PER_CONN);
    for i in 0..MAX_PENDING_TICKETS_PER_CONN {
        let reply = rig
            .server
            .dispatch(&ctx, &session_open(i as u64))
            .await
            .unwrap();
        match response_body(&reply) {
            response::Body::SessionOpened(opened) => {
                session_ids.push(opened.session_id.clone());
            }
            other => panic!("expected SessionOpened, got {other:?}"),
        }
    }
    assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);

    // Close one of the sessions — its own ticket must go with it, and
    // only its own: the other `MAX_PENDING_TICKETS_PER_CONN - 1`
    // sessions' tickets are untouched.
    let closing = session_ids[0].clone();
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                9000,
                control_message::Body::SessionClose(wire::SessionClose {
                    session_id: closing.clone(),
                    signal: None,
                }),
            ),
        )
        .await
        .unwrap();
    assert!(
        matches!(response_body(&reply), response::Body::SessionClosed(_)),
        "expected SessionClosed, got {reply:?}"
    );
    assert_eq!(
        rig.server.pending_tickets(),
        MAX_PENDING_TICKETS_PER_CONN - 1,
        "closing one session must free exactly its own ticket"
    );

    // The freed slot admits a new open without ResourceExhausted — the
    // budget check sees the drop, not just this test's own count.
    let reply = rig
        .server
        .dispatch(&ctx, &session_open(9001))
        .await
        .unwrap();
    assert_eq!(
        error_code(&reply),
        None,
        "a session.open right after the close must not see \
         ResourceExhausted — the closed session's own ticket must \
         already be gone"
    );
    assert_eq!(rig.server.pending_tickets(), MAX_PENDING_TICKETS_PER_CONN);
}

/// `session.close` must release its own session's unredeemed ticket
/// even when the closing connection is not the one that opened it
/// (라운드 1 판정 (c) 항목 4, the two-connection cross-check for
/// dropping `t.conn_id == ctx.conn_id` from the purge predicate
/// above). `close` is the unowned path (`handle_session_close`'s own
/// doc comment): a different device sharing the same ACL scope may
/// reap a session it never opened, and the opener's ticket must not
/// be stranded when that happens — the session is gone either way, so
/// no connection can ever redeem it.
#[tokio::test]
async fn session_close_from_a_different_connection_still_releases_the_opener_s_ticket() {
    let rig = allow_rig();
    let opener = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let closer = ConnCtx {
        conn_id: opener.conn_id + 1,
        ..ctx(Principal::Device("desktop".into()), ALL_CAPS)
    };
    let (id, _t, _pipe) = open_session(&rig, &opener).await;
    assert_eq!(rig.server.pending_tickets(), 1);

    let reply = rig
        .server
        .dispatch(
            &closer,
            &ControlMessage::new(
                1,
                control_message::Body::SessionClose(wire::SessionClose {
                    session_id: id.clone(),
                    signal: None,
                }),
            ),
        )
        .await
        .unwrap();
    assert!(
        matches!(response_body(&reply), response::Body::SessionClosed(_)),
        "expected SessionClosed, got {reply:?}"
    );
    assert_eq!(
        rig.server.pending_tickets(),
        0,
        "the opener's connection did not do the closing, but its \
         ticket must still be gone: the session it targeted no longer \
         exists on either connection"
    );
}

/// The ACL choke point's own audit line for an *allowed* principal must
/// still be written even though that same open then fails on a
/// saturated quota — a quota rejection is a distinct, later decision,
/// not a reason to suppress the (already true) ACL verdict that
/// preceded it.
#[tokio::test]
async fn quota_rejection_still_leaves_the_acl_allow_audit_line() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_sessions: 1,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), &["session"]);
    let _opened = open_session(&rig, &ctx).await;
    assert_eq!(
        rig.audit.records().len(),
        1,
        "first open's own ACL allow line"
    );

    // Same, allowed principal, second connection — ACL allows again
    // (unowned resource, still pinned), but the global session cap is
    // already saturated by the first open.
    let mut second_conn = ctx.clone();
    second_conn.conn_id += 1;
    let reply = rig
        .server
        .dispatch(&second_conn, &session_open(2))
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::ResourceExhausted));

    let recs = rig.audit.records();
    assert_eq!(
        recs.len(),
        3,
        "first open's allow, second open's allow, second's quota deny"
    );
    assert_eq!(
        recs[1].decision, "allow",
        "the ACL allow line is written even though the open then fails on quota"
    );
    assert_eq!(recs[2].decision, "deny");
    assert_eq!(recs[2].resource, "quota_sessions_host");
    assert_eq!(recs[2].action, "session.open");
    assert_eq!(
        recs[1].request_id, recs[2].request_id,
        "the ACL allow line and the quota deny line for the SAME request \
         must share a request_id, or the two cannot be correlated \
         (verdict ruling 11①)"
    );
    assert_ne!(
        recs[2].request_id, "-",
        "the quota deny record must carry the real request_id, not the \
         placeholder used before F2 threaded it through"
    );
    assert_eq!(
        recs[2].request_id, "2",
        "R9 — the session axis has a real control request id to carry"
    );
    assert_eq!(
        recs[2].peer_addr,
        ctx.peer_addr.to_string(),
        "R4 — the quota deny record must carry the live peer, not \"-\""
    );
}

/// `PLAN.md` M5 Step 3(c) "disk-full fail-closed": an
/// `AllowAllPinned`-eligible peer's `session.open` is denied — and no
/// session is created — while the audit sink cannot durably record the
/// allow, then succeeds once the sink recovers. Exercises
/// `Server::authorize`, the first of the four fail-closed choke points
/// (`PLAN.md` §1's "four authorization points").
#[tokio::test]
async fn session_open_fails_closed_when_the_audit_sink_cannot_record_an_allow() {
    let clock = TestClock::new();
    let pipes = Arc::new(PipeFactory::new(64 * 1024));
    let broker = Broker::new(
        Arc::new(clock.clone()),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(100),
            quota_limits: crate::quota::QuotaLimits::default(),
        },
        pipes.clone(),
    );
    let audit = Arc::new(FailingAuditSink::new());
    let server = Server::new(
        Arc::new(AllowAllPinned),
        audit.clone(),
        broker.clone(),
        "host",
    );
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

    // Policy would allow this peer — but the audit sink cannot durably
    // record the decision, so the choke point denies it rather than
    // create a session with no durable record of having authorized it.
    audit.fail();
    let reply = server.dispatch(&ctx, &session_open(1)).await.unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
    assert_eq!(
        broker.session_count(),
        0,
        "no session created while the audit sink is degraded"
    );
    // F8 (M5 Step 4 adversarial review): the degraded-deny reply must
    // carry the exact same wire message as an ordinary policy deny —
    // a peer must not be able to tell "the audit sink is degraded"
    // from "policy said no" by reading `message` (`PERMISSION_DENIED_
    // MESSAGE`'s own doc, `Server::permission_denied`'s doc).
    match &reply.body {
        Some(control_message::Body::Response(wire::Response {
            body: Some(response::Body::Error(e)),
        })) => assert_eq!(
            e.message,
            crate::acl::PERMISSION_DENIED_MESSAGE,
            "fail-closed audit-degraded deny must use the uniform message, byte for byte"
        ),
        other => panic!("expected an error response, got {other:?}"),
    }

    // The writer recovers: the same policy-allowed request now
    // succeeds, and only now does a session exist.
    audit.clear();
    let reply = server.dispatch(&ctx, &session_open(2)).await.unwrap();
    assert!(matches!(
        response_body(&reply),
        response::Body::SessionOpened(_)
    ));
    assert_eq!(broker.session_count(), 1);
    assert_eq!(
        audit.records().len(),
        1,
        "the denied attempt was never durably recorded, only the recovered allow"
    );
}

/// Fail-closed extended to the attach choke point — [`Server::authorize`]
/// is the same choke point `session.open` goes through
/// (`session_open_fails_closed_when_the_audit_sink_cannot_record_
/// an_allow` pins that axis), so a `session.attach` whose credential
/// verifies but whose allow cannot be durably recorded is denied with
/// the exact same [`crate::acl::PERMISSION_DENIED_MESSAGE`],
/// byte-for-byte — a peer must not be able to tell "audit degraded"
/// from "policy said no." The still-valid resume token is untouched
/// by the denial (`Broker::rotate_resume` only runs once the ACL
/// choke point has already passed), so the same token attaches
/// successfully once the sink recovers.
#[tokio::test]
async fn session_attach_fails_closed_when_the_audit_sink_cannot_record_an_allow() {
    let clock = TestClock::new();
    let pipes = Arc::new(PipeFactory::new(64 * 1024));
    let broker = Broker::new(
        Arc::new(clock.clone()),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(100),
            quota_limits: crate::quota::QuotaLimits::default(),
        },
        pipes.clone(),
    );
    let audit = Arc::new(FailingAuditSink::new());
    let server = Server::new(
        Arc::new(AllowAllPinned),
        audit.clone(),
        broker.clone(),
        "host",
    );
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

    // Open the session while the sink is healthy — the axis under
    // test is `session.attach`, not `session.open`.
    let reply = server.dispatch(&ctx, &session_open(1)).await.unwrap();
    let opened = match response_body(&reply) {
        response::Body::SessionOpened(o) => o.clone(),
        other => panic!("expected SessionOpened, got {other:?}"),
    };
    let _pipe = pipes.take().expect("pipe handle for the new session");

    let attach = |token: Vec<u8>| wire::SessionAttach {
        session_id: opened.session_id.clone(),
        resume_token: token,
        mode: wire::AttachMode::Rw as i32,
        ..Default::default()
    };

    audit.fail();
    let reply = server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                2,
                control_message::Body::SessionAttach(attach(opened.resume_token.clone())),
            ),
        )
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
    match &reply.body {
        Some(control_message::Body::Response(wire::Response {
            body: Some(response::Body::Error(e)),
        })) => assert_eq!(
            e.message,
            crate::acl::PERMISSION_DENIED_MESSAGE,
            "fail-closed audit-degraded deny must use the uniform message, byte for byte"
        ),
        other => panic!("expected an error response, got {other:?}"),
    }

    // Recovery: the same still-valid resume token now succeeds — a
    // degraded audit sink must never burn the credential it denied
    // under.
    audit.clear();
    let reply = server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                3,
                control_message::Body::SessionAttach(attach(opened.resume_token.clone())),
            ),
        )
        .await
        .unwrap();
    assert!(
        matches!(response_body(&reply), response::Body::SessionAttached(_)),
        "expected SessionAttached once the audit sink recovers, got {reply:?}"
    );
}

/// Fail-closed extended to the ownership-aware choke point — [`Server::
/// authorize_owned`] is a *different* fail-closed branch than
/// [`Server::authorize`] (`session_open_fails_closed_when_the_audit_
/// sink_cannot_record_an_allow` and `session_attach_fails_closed_
/// when_the_audit_sink_cannot_record_an_allow` both only exercise the
/// latter, via [`Server::authorize`]'s own `!verdict.is_allow() ||
/// recorded.is_err()`). `session.write` reaches `authorize_owned`
/// through `authorize_session_control` → `require_opener`
/// (`Server::prepare_session_write`'s doc), and only the session's own
/// opener gets an `is_allow()` verdict under the default `scope =
/// "owned"` policy — a foreign principal's write is already denied by
/// ownership before `authorize_owned`'s own fail-closed branch is
/// ever reached, which is exactly why this test must write as the
/// opener, the same way `write_by_another_principal_is_denied_by_
/// ownership_not_the_lease` pins the foreign-principal side of the
/// same choke point. Same byte-identical `PERMISSION_DENIED_MESSAGE`
/// contract, same recovery-without-burning-anything shape.
#[tokio::test]
async fn session_write_fails_closed_when_the_audit_sink_cannot_record_an_allow() {
    let clock = TestClock::new();
    let pipes = Arc::new(PipeFactory::new(64 * 1024));
    let broker = Broker::new(
        Arc::new(clock.clone()),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(100),
            quota_limits: crate::quota::QuotaLimits::default(),
        },
        pipes.clone(),
    );
    let audit = Arc::new(FailingAuditSink::new());
    let server = Server::new(
        Arc::new(AllowAllPinned),
        audit.clone(),
        broker.clone(),
        "host",
    );
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

    // Open the session while the sink is healthy — the axis under
    // test is `session.write`, not `session.open`.
    let reply = server.dispatch(&ctx, &session_open(1)).await.unwrap();
    let opened = match response_body(&reply) {
        response::Body::SessionOpened(o) => o.clone(),
        other => panic!("expected SessionOpened, got {other:?}"),
    };
    let _pipe = pipes.take().expect("pipe handle for the new session");

    let write = |request_id: u64| {
        ControlMessage::new(
            request_id,
            control_message::Body::SessionWrite(wire::SessionWrite {
                session_id: opened.session_id.clone(),
                data: b"x".to_vec(),
            }),
        )
    };

    audit.fail();
    let reply = server.dispatch(&ctx, &write(2)).await.unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
    match &reply.body {
        Some(control_message::Body::Response(wire::Response {
            body: Some(response::Body::Error(e)),
        })) => assert_eq!(
            e.message,
            crate::acl::PERMISSION_DENIED_MESSAGE,
            "fail-closed audit-degraded deny must use the uniform message, byte for byte"
        ),
        other => panic!("expected an error response, got {other:?}"),
    }

    // Recovery: the same opener's write now succeeds once the sink
    // recovers.
    audit.clear();
    let reply = server.dispatch(&ctx, &write(3)).await.unwrap();
    assert_eq!(
        error_code(&reply),
        None,
        "expected session.write to succeed once the audit sink recovers, got {reply:?}"
    );
}

/// An unsolicited SessionEvent (host → client only) is dropped.
#[tokio::test]
async fn inbound_session_event_is_ignored() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let msg = ControlMessage::new(
        0,
        control_message::Body::SessionEvent(wire::SessionEvent::closed("01K0SESSION", "closed", 1)),
    );
    assert!(rig.server.dispatch(&ctx, &msg).await.is_none());
}

/// Reserved control number 25 (`SessionSignal`, CLI.md §2.4) and any
/// still-unknown number decode to `body: None` and are answered
/// UNSUPPORTED without creating anything. Tags 40/41 are NO LONGER in
/// that set — M4 Step 1 realized them as `RemoteForwardOpen`/`Close`, so
/// prost decodes them to a real (empty) body and they take a dedicated
/// UNSUPPORTED arm until the host handler lands (M4 Step 4/5); that path
/// is covered separately below.
#[tokio::test]
async fn reserved_and_unknown_control_numbers_are_unsupported() {
    // request_id = 7 (field 1 varint), then field N (LEN) with an empty
    // body: tag = (N << 3) | 2 as a varint.
    fn raw_with_field(field: u32) -> Vec<u8> {
        let mut b = vec![0x08, 0x07];
        let tag = (field << 3) | 2;
        let mut v = tag;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                b.push(byte);
                break;
            }
            b.push(byte | 0x80);
        }
        b.push(0x00);
        b
    }
    for field in [25u32, 200] {
        let msg: ControlMessage = wire::decode_msg(&raw_with_field(field)).unwrap();
        assert_eq!(msg.request_id, 7);
        assert!(
            msg.body.is_none(),
            "field {field} should be dropped by prost"
        );
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();
        assert_eq!(reply.request_id, 7);
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::Unsupported),
            "field {field}"
        );
        assert!(rig.audit.records().is_empty());
        assert_eq!(rig.server.pending_tickets(), 0);
        assert_eq!(rig.broker.session_count(), 0);
    }
    // Tunnel control (40/41) is realized (M4 Step 1) and now has real
    // host handlers (M4 Step 4). `RfwdOpen` still draws `UNSUPPORTED`
    // from a *bare* `dispatch` call specifically — not because the op
    // is unimplemented, but because opening a remote forward needs a
    // live `Connection` this call has none of
    // (`Server::handle_rfwd_open`'s own doc; the real path is
    // `serve_control`'s early interception, covered by
    // `rfwd_open_end_to_end_streams_tcp_accepted_then_close_tears_down`).
    // `RfwdClose` needs no connection, so `dispatch` runs it for real —
    // an unregistered `forward_id` (the zero value `default()` gives)
    // is `INVALID_ARGUMENT`, not `UNSUPPORTED`.
    for (body, want) in [
        (
            control_message::Body::RfwdOpen(wire::RemoteForwardOpen::default()),
            ErrorCode::Unsupported,
        ),
        (
            control_message::Body::RfwdClose(wire::RemoteForwardClose::default()),
            ErrorCode::InvalidArgument,
        ),
    ] {
        assert!(
            ControlMessage::new(7, body.clone()).body.is_some(),
            "40/41 are realized, not dropped to None"
        );
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let reply = rig
            .server
            .dispatch(&ctx, &ControlMessage::new(7, body))
            .await
            .unwrap();
        assert_eq!(reply.request_id, 7);
        assert_eq!(error_code(&reply), Some(want));
        assert!(rig.audit.records().is_empty());
        assert_eq!(rig.server.pending_tickets(), 0);
        assert_eq!(rig.broker.session_count(), 0);
    }
    // A genuinely empty message gets the same answer.
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage {
                request_id: 9,
                body: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported));
}

#[tokio::test]
async fn empty_argv_is_invalid_argument() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let reply = rig
        .server
        .dispatch(&ctx, &exec_start(1, &[]))
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::InvalidArgument));
}

#[tokio::test]
async fn ping_gets_pong_with_same_request_id() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(77, control_message::Body::Ping(wire::Ping {})),
        )
        .await
        .unwrap();
    assert_eq!(reply.request_id, 77);
    assert!(matches!(reply.body, Some(control_message::Body::Pong(_))));
    assert!(
        rig.server
            .dispatch(
                &ctx,
                &ControlMessage::new(78, control_message::Body::Pong(wire::Pong {}))
            )
            .await
            .is_none()
    );
}

#[tokio::test]
async fn purge_connection_drops_its_tickets_and_leases_but_keeps_sessions() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    rig.server.dispatch(&ctx, &exec_start(1, &["true"])).await;
    let (id, _ticket, _pipe) = open_session(&rig, &ctx).await;
    assert_eq!(rig.server.pending_tickets(), 2);
    // A write takes the writer lease for this connection.
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                3,
                control_message::Body::SessionWrite(wire::SessionWrite {
                    session_id: id.clone(),
                    data: b"x".to_vec(),
                }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(error_code(&reply), None, "{reply:?}");
    let sid = SessionId(id.clone());
    assert_eq!(
        rig.broker.get(&sid).unwrap().info().writer.as_deref(),
        Some("device:laptop")
    );

    rig.server.purge_connection(42, ()).await;
    assert_eq!(rig.server.pending_tickets(), 0);
    assert_eq!(rig.broker.get(&sid).unwrap().info().writer, None);
    assert_eq!(rig.broker.session_count(), 1, "the session survives");
}

// ---- session ops: choke point --------------------------------------

/// Under `DenyAll` every session op is PERMISSION_DENIED, audited as a
/// deny, and creates nothing — no session, no ticket. This includes
/// ops on a session that does exist: an unauthorized peer gets the
/// same answer whether or not the id is real (non-distinguishing).
#[tokio::test]
async fn denied_session_ops_create_nothing_and_do_not_disclose_existence() {
    // A real session, created by an allowed rig sharing the broker…
    let allowed = allow_rig();
    let ctx_ok = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (real_id, _t, _pipe) = open_session(&allowed, &ctx_ok).await;
    // …seen through a deny-all server on the same broker.
    let denying = Server::new(
        Arc::new(DenyAll),
        allowed.audit.clone(),
        allowed.broker.clone(),
        "host",
    );
    allowed.audit.clear();
    let ctx_deny = ctx(Principal::Device("intruder".into()), ALL_CAPS);
    let mut replies = Vec::new();
    for id in [real_id.as_str(), "01K0NOSUCHSESSION"] {
        for (i, (name, body)) in session_bodies(id).into_iter().enumerate() {
            let request_id = 100 + i as u64;
            let reply = denying
                .dispatch(&ctx_deny, &ControlMessage::new(request_id, body))
                .await
                .expect("session requests get a reply");
            assert_eq!(reply.request_id, request_id);
            assert_eq!(
                error_code(&reply),
                Some(ErrorCode::PermissionDenied),
                "{name} on {id}"
            );
            replies.push((name, error_code(&reply)));
        }
    }
    // Identical answers for the real and the fabricated id.
    let (real, fake) = replies.split_at(replies.len() / 2);
    assert_eq!(real, fake, "existence must not be distinguishable");
    // Nothing created.
    assert_eq!(denying.pending_tickets(), 0);
    assert_eq!(
        allowed.broker.session_count(),
        1,
        "only the pre-existing one"
    );
    assert_eq!(allowed.pipes.pending(), 0);
    // One structural audit line per op, all denies, all through Action.
    let recs = allowed.audit.records();
    assert_eq!(recs.len(), 14);
    assert!(recs.iter().all(|r| r.decision == "deny"));
    assert!(recs.iter().all(|r| r.principal == "device:intruder"));
    let actions: std::collections::BTreeSet<&str> =
        recs.iter().map(|r| r.action.as_str()).collect();
    // The distinct actions among the 7 session ops, sourced from
    // `OP_REGISTRY` (`PLAN.md` M5 Step 8) rather than named a second
    // time as `Action` literals — a dedup set, since `session.write`/
    // `resize`/`close` all resolve to `Action::SessionControl`.
    let expected_actions: std::collections::BTreeSet<&str> = [
        crate::acl::Op::SessionOpen,
        crate::acl::Op::SessionList,
        crate::acl::Op::SessionGet,
        crate::acl::Op::SessionRead,
        crate::acl::Op::SessionWrite,
        crate::acl::Op::SessionResize,
        crate::acl::Op::SessionClose,
    ]
    .iter()
    .map(|op| op.action().as_str())
    .collect();
    assert_eq!(actions, expected_actions);
}

/// Each session op is audited under exactly the action CLI.md §2.5
/// maps it to, with the session id (or "session") as resource.
#[tokio::test]
async fn every_session_op_passes_the_choke_point_with_the_mapped_action() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (id, _t, _pipe) = open_session(&rig, &ctx).await;
    rig.audit.clear();
    let mut expected: Vec<(&str, Action, String)> = Vec::new();
    for (name, body) in session_bodies(&id) {
        let reply = rig
            .server
            .dispatch(&ctx, &ControlMessage::new(7, body))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), None, "{name}: {reply:?}");
        // `Action`s sourced from `OP_REGISTRY` by dotted op name
        // (`PLAN.md` M5 Step 8), not named a second time as literals —
        // `resource` still depends on which sentinel/id shape each op
        // uses (`OpSpec::resource_kind` documents the shape; the
        // literal string is still the request's own, same as before).
        let (action, resource) = match name {
            "open" => (
                crate::acl::Op::SessionOpen.action(),
                SESSION_RESOURCE.to_string(),
            ),
            "list" => (
                crate::acl::Op::SessionList.action(),
                SESSION_RESOURCE.to_string(),
            ),
            "get" => (crate::acl::Op::SessionGet.action(), id.clone()),
            "read" => (crate::acl::Op::SessionRead.action(), id.clone()),
            "write" => (crate::acl::Op::SessionWrite.action(), id.clone()),
            "resize" => (crate::acl::Op::SessionResize.action(), id.clone()),
            "close" => (crate::acl::Op::SessionClose.action(), id.clone()),
            other => panic!("unexpected op {other}"),
        };
        expected.push((name, action, resource));
    }
    let recs = rig.audit.records();
    assert_eq!(recs.len(), expected.len());
    for (rec, (name, action, resource)) in recs.iter().zip(&expected) {
        assert_eq!(rec.action, action.as_str(), "{name}");
        assert_eq!(&rec.resource, resource, "{name}");
        assert_eq!(rec.decision, "allow", "{name}");
        assert_eq!(rec.request_id, "7", "{name}");
    }
    // The extra `open` in the loop created a second session + ticket,
    // but the loop's own `close` (of the *first* session, opened
    // before the loop) then freed that first ticket along with the
    // session it belonged to (라운드 1 판정 (c): `session.close` frees
    // its own session's unredeemed ticket) — so only the second
    // session's ticket is left outstanding.
    assert_eq!(rig.broker.session_count(), 1, "the loop closed the first");
    assert_eq!(rig.server.pending_tickets(), 1);
}

#[tokio::test]
async fn session_ops_without_capability_are_unsupported_and_not_audited() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), &["exec"]);
    for (name, body) in session_bodies("01K0SESSION") {
        let reply = rig
            .server
            .dispatch(&ctx, &ControlMessage::new(1, body))
            .await
            .unwrap();
        assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported), "{name}");
    }
    assert!(rig.audit.records().is_empty());
    assert_eq!(rig.server.pending_tickets(), 0);
    assert_eq!(rig.broker.session_count(), 0);
}

// ---- session ops: behaviour ---------------------------------------

#[tokio::test]
async fn open_creates_a_session_and_a_session_data_ticket() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let reply = rig.server.dispatch(&ctx, &session_open(1)).await.unwrap();
    let opened = match response_body(&reply) {
        response::Body::SessionOpened(o) => o.clone(),
        other => panic!("expected SessionOpened, got {other:?}"),
    };
    assert_eq!(opened.initial_seq, 0);
    // A resume credential is issued with the session and bound to the
    // connection's verified peer (protocol.md §10). It is the one
    // thing in this reply that never reaches a log or an envelope.
    assert_eq!(
        opened.resume_token.len(),
        RESUME_TOKEN_LEN,
        "session.open must issue a resume credential"
    );
    assert!(!opened.expires_at.is_empty());
    assert_eq!(opened.ticket.len(), TICKET_LEN);
    assert_eq!(rig.broker.session_count(), 1);
    assert_eq!(rig.pipes.pending(), 1);
    // The ticket redeems for SESSION_DATA only, once, on this connection.
    assert!(
        rig.server
            .redeem_ticket(42, StreamKind::ExecData, &opened.ticket)
            .is_none()
    );
    let ticket = rig
        .server
        .redeem_ticket(42, StreamKind::SessionData, &opened.ticket)
        .expect("session ticket");
    assert!(matches!(
        ticket.purpose,
        TicketPurpose::Session { session_id, .. } if session_id.0 == opened.session_id
    ));
    assert!(
        rig.server
            .redeem_ticket(42, StreamKind::SessionData, &opened.ticket)
            .is_none()
    );
    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].action, "session.open");
    assert_eq!(recs[0].resource, SESSION_RESOURCE);
}

#[tokio::test]
async fn open_with_a_foreign_user_hint_is_unsupported_after_acl_and_creates_nothing() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let msg = ControlMessage::new(
        1,
        control_message::Body::SessionOpen(wire::SessionOpen {
            user: Some("definitely-not-the-serve-account-\u{1f512}".into()),
            ..Default::default()
        }),
    );
    let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported));
    assert_eq!(rig.broker.session_count(), 0);
    assert_eq!(rig.server.pending_tickets(), 0);
    // The ACL decision was made (and audited as allow) before the hint
    // check — hint validation is post-authorization only.
    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, "allow");

    // An unauthorized peer with the same hint is PERMISSION_DENIED,
    // never UNSUPPORTED (no login-name oracle).
    let denying = Server::new(
        Arc::new(DenyAll),
        rig.audit.clone(),
        rig.broker.clone(),
        "host",
    );
    let reply = denying.dispatch(&ctx, &msg).await.unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
}

#[cfg(unix)]
#[tokio::test]
async fn open_with_the_serve_accounts_login_name_as_hint_succeeds() {
    let Some(me) = serve_login_name() else {
        eprintln!("no passwd entry for this uid; skipping");
        return;
    };
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let msg = ControlMessage::new(
        1,
        control_message::Body::SessionOpen(wire::SessionOpen {
            user: Some(me),
            ..Default::default()
        }),
    );
    let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();
    assert_eq!(error_code(&reply), None, "{reply:?}");
    assert_eq!(rig.broker.session_count(), 1);
}

#[tokio::test]
async fn write_read_resize_get_list_close_roundtrip() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (id, _t, mut pipe) = open_session(&rig, &ctx).await;
    let sid = SessionId(id.clone());

    // output arrives → read after 0 returns it with the right sequence.
    pipe.write_output(b"hi\r\n").await.unwrap();
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                3,
                control_message::Body::SessionRead(wire::SessionRead {
                    session_id: id.clone(),
                    after: 0,
                    max_bytes: 0,
                    wait_ms: 30_000,
                    ctl_after: 0,
                }),
            ),
        )
        .await
        .unwrap();
    let events = match response_body(&reply) {
        response::Body::SessionReadResult(r) => r.events.clone(),
        other => panic!("expected SessionReadResult, got {other:?}"),
    };
    let mut bytes = Vec::new();
    let mut last_seq = 0;
    for event in &events {
        if let Some(session_read_event::Body::Output(o)) = &event.body {
            bytes.extend_from_slice(&o.data);
            last_seq = o.sequence;
        }
    }
    assert_eq!(bytes, b"hi\r\n");
    assert_eq!(last_seq, 4);

    // write → the pipe sees the input, bytes_written reported.
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                2,
                control_message::Body::SessionWrite(wire::SessionWrite {
                    session_id: id.clone(),
                    data: b"echo hi\n".to_vec(),
                }),
            ),
        )
        .await
        .unwrap();
    match response_body(&reply) {
        response::Body::SessionWritten(w) => assert_eq!(w.bytes_written, 8),
        other => panic!("expected SessionWritten, got {other:?}"),
    }
    assert_eq!(pipe.read_input(64).await.unwrap(), b"echo hi\n");

    // Non-blocking read past everything: no output (only the
    // writer_changed control positioned at 4), not an error.
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                4,
                control_message::Body::SessionRead(wire::SessionRead {
                    session_id: id.clone(),
                    after: 4,
                    max_bytes: 0,
                    wait_ms: 0,
                    ctl_after: 0,
                }),
            ),
        )
        .await
        .unwrap();
    match response_body(&reply) {
        response::Body::SessionReadResult(r) => assert!(
            r.events
                .iter()
                .all(|e| { !matches!(e.body, Some(session_read_event::Body::Output(_))) })
        ),
        other => panic!("expected SessionReadResult, got {other:?}"),
    }
    // Beyond the end is INVALID_ARGUMENT, not NOT_FOUND.
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                5,
                control_message::Body::SessionRead(wire::SessionRead {
                    session_id: id.clone(),
                    after: 999,
                    ..Default::default()
                }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::InvalidArgument));

    // resize reaches the source; get/list reflect the state.
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                6,
                control_message::Body::SessionResize(wire::SessionResize {
                    session_id: id.clone(),
                    cols: 120,
                    rows: 40,
                }),
            ),
        )
        .await
        .unwrap();
    match response_body(&reply) {
        response::Body::SessionResized(r) => assert_eq!((r.cols, r.rows), (120, 40)),
        other => panic!("expected SessionResized, got {other:?}"),
    }
    assert_eq!(pipe.resizes(), vec![(120, 40)]);
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                7,
                control_message::Body::SessionGet(wire::SessionGet {
                    session_id: id.clone(),
                }),
            ),
        )
        .await
        .unwrap();
    match response_body(&reply) {
        response::Body::SessionInfo(info) => {
            assert_eq!(info.session_id, id);
            assert_eq!(info.state, "running");
            assert_eq!(info.writer.as_deref(), Some("device:laptop"));
            assert_eq!(info.last_sequence, 4);
        }
        other => panic!("expected SessionInfo, got {other:?}"),
    }
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(8, control_message::Body::SessionList(wire::SessionList {})),
        )
        .await
        .unwrap();
    match response_body(&reply) {
        response::Body::SessionListResult(list) => {
            assert_eq!(list.sessions.len(), 1);
            assert_eq!(list.sessions[0].session_id, id);
        }
        other => panic!("expected SessionListResult, got {other:?}"),
    }

    // close: the pipe gets HUP and exits; final_seq is the offset.
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                9,
                control_message::Body::SessionClose(wire::SessionClose {
                    session_id: id.clone(),
                    signal: None,
                }),
            ),
        )
        .await
        .unwrap();
    match response_body(&reply) {
        response::Body::SessionClosed(c) => assert_eq!(c.final_seq, 4),
        other => panic!("expected SessionClosed, got {other:?}"),
    }
    assert_eq!(pipe.signals(), vec![Signal::Hup]);
    assert!(matches!(rig.broker.get(&sid), Err(BrokerError::NotFound)));

    // Afterwards get/write/resize/close are SESSION_NOT_FOUND, but a
    // read still drains the trailing `closed` control event.
    for (name, body) in session_bodies(&id) {
        if matches!(name, "open" | "list" | "read") {
            continue;
        }
        let reply = rig
            .server
            .dispatch(&ctx, &ControlMessage::new(10, body))
            .await
            .unwrap();
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::SessionNotFound),
            "{name}"
        );
    }
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                11,
                control_message::Body::SessionRead(wire::SessionRead {
                    session_id: id.clone(),
                    after: 4,
                    ..Default::default()
                }),
            ),
        )
        .await
        .unwrap();
    let events = match response_body(&reply) {
        response::Body::SessionReadResult(r) => r.events.clone(),
        other => panic!("expected SessionReadResult, got {other:?}"),
    };
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| match &e.body {
            Some(session_read_event::Body::WriterChanged(_)) => "writer_changed",
            Some(session_read_event::Body::Exit(_)) => "exit",
            Some(session_read_event::Body::Closed(_)) => "closed",
            other => panic!("unexpected event {other:?}"),
        })
        .collect();
    assert_eq!(kinds.last(), Some(&"closed"));
    assert!(kinds.contains(&"exit"));
    match &events.iter().find_map(|e| match &e.body {
        Some(session_read_event::Body::Exit(x)) => Some(x.clone()),
        _ => None,
    }) {
        Some(exit) => {
            assert_eq!(exit.final_seq, 4);
            assert_eq!(exit.exit_code, -1, "signal exit carries -1");
            assert_eq!(exit.signal.as_deref(), Some("SIGHUP"));
        }
        None => panic!("no exit event"),
    }
}

/// `PLAN.md` Step 3.5 PR②: `session.write` binds to the session's
/// opener, so a foreign principal is refused by ownership before the
/// lease is ever consulted — `SESSION_CONFLICT` from a genuinely
/// foreign principal is no longer reachable through `session.write` at
/// all (`broker::lease`'s own unit tests still cover the underlying
/// `no_steal` mechanics directly). The same principal on a second
/// connection is unaffected: ownership binds to the principal, not the
/// connection.
#[tokio::test]
async fn write_by_another_principal_is_denied_by_ownership_not_the_lease() {
    let rig = allow_rig();
    let a = ctx(Principal::Device("a".into()), ALL_CAPS);
    let mut b = ctx(Principal::Device("b".into()), ALL_CAPS);
    b.conn_id = 43;
    let (id, _t, _pipe) = open_session(&rig, &a).await;
    let write = |cid: u64| {
        ControlMessage::new(
            cid,
            control_message::Body::SessionWrite(wire::SessionWrite {
                session_id: id.clone(),
                data: b"x".to_vec(),
            }),
        )
    };
    assert_eq!(
        error_code(&rig.server.dispatch(&a, &write(1)).await.unwrap()),
        None
    );
    let reply = rig.server.dispatch(&b, &write(2)).await.unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::PermissionDenied));
    assert_eq!(
        rig.broker
            .get(&SessionId(id.clone()))
            .unwrap()
            .info()
            .writer
            .as_deref(),
        Some("device:a"),
        "a denied write must not move the lease"
    );
    // Same principal on another connection still takes over.
    let mut a2 = a.clone();
    a2.conn_id = 44;
    assert_eq!(
        error_code(&rig.server.dispatch(&a2, &write(3)).await.unwrap()),
        None
    );
}

#[tokio::test]
async fn invalid_session_arguments_are_rejected_before_the_broker() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (id, _t, _pipe) = open_session(&rig, &ctx).await;
    rig.audit.clear();
    let cases = vec![
        control_message::Body::SessionWrite(wire::SessionWrite {
            session_id: id.clone(),
            data: vec![0u8; wire::SESSION_CHUNK_MAX + 1],
        }),
        control_message::Body::SessionResize(wire::SessionResize {
            session_id: id.clone(),
            cols: 70_000,
            rows: 24,
        }),
        control_message::Body::SessionResize(wire::SessionResize {
            session_id: id.clone(),
            cols: 0,
            rows: 24,
        }),
        control_message::Body::SessionClose(wire::SessionClose {
            session_id: id.clone(),
            signal: Some("STOP".into()),
        }),
        control_message::Body::SessionOpen(wire::SessionOpen {
            cols: 1 << 20,
            ..Default::default()
        }),
        control_message::Body::SessionAttach(wire::SessionAttach {
            session_id: id.clone(),
            mode: 0,
            ..Default::default()
        }),
        control_message::Body::SessionAttach(wire::SessionAttach {
            session_id: id.clone(),
            mode: wire::AttachMode::Ro as i32,
            ..Default::default()
        }),
    ];
    for body in cases {
        let reply = rig
            .server
            .dispatch(&ctx, &ControlMessage::new(1, body.clone()))
            .await
            .unwrap();
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::InvalidArgument),
            "{body:?}"
        );
    }
    // Argument validation is not a decision: nothing audited.
    assert!(rig.audit.records().is_empty());
    assert_eq!(rig.broker.session_count(), 1);
    assert_eq!(rig.pipes.pending(), 0);
}

#[tokio::test]
async fn attach_redeems_a_credential_and_anything_else_is_refused() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (opened, _pipe) = open_session_full(&rig, &ctx).await;
    let id = opened.session_id.clone();
    rig.audit.clear();

    let attach = |sid: String, token: Vec<u8>| wire::SessionAttach {
        session_id: sid,
        resume_token: token,
        mode: wire::AttachMode::Rw as i32,
        ..Default::default()
    };
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                1,
                control_message::Body::SessionAttach(attach(
                    id.clone(),
                    opened.resume_token.clone(),
                )),
            ),
        )
        .await
        .unwrap();
    let response::Body::SessionAttached(a) = response_body(&reply) else {
        panic!("expected SessionAttached, got {reply:?}");
    };
    assert_eq!(a.ticket.len(), TICKET_LEN);
    assert_eq!(a.replay_from, 0);
    assert!(a.writer_lease);
    // A redemption always mints the next generation, and it is never
    // the one that was spent (protocol.md §10 "Rotation").
    assert_eq!(a.new_resume_token.len(), RESUME_TOKEN_LEN);
    assert_ne!(a.new_resume_token, opened.resume_token);
    assert_eq!(
        a.input_seq, 0,
        "the axis is forked from the open's, which has applied nothing"
    );
    assert_eq!(
        rig.server.pending_tickets(),
        2,
        "the open's ticket plus this one"
    );

    // Every other shape gets the same non-distinguishing answer: no
    // credential at all, a credential that does not verify, a real id,
    // a fabricated one. `SESSION_NOT_FOUND` is not reachable from here,
    // so an unauthorized peer cannot use attach as an existence oracle
    // (protocol.md §10-2).
    let refusals = [
        (2u64, id.clone(), Vec::new()),
        (3, "01K0NOSUCHSESSION".into(), Vec::new()),
        (4, id.clone(), vec![7u8; RESUME_TOKEN_LEN]),
        (5, "01K0NOSUCHSESSION".into(), vec![7u8; RESUME_TOKEN_LEN]),
        // …including the credential that was just spent.
        (6, id.clone(), opened.resume_token.clone()),
    ];
    for (request_id, sid, token) in refusals {
        let reply = rig
            .server
            .dispatch(
                &ctx,
                &ControlMessage::new(
                    request_id,
                    control_message::Body::SessionAttach(attach(sid.clone(), token.clone())),
                ),
            )
            .await
            .unwrap();
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::AuthFailed),
            "request {request_id} on {sid}"
        );
    }
    assert_eq!(
        rig.server.pending_tickets(),
        2,
        "a refused attach mints nothing"
    );

    // Every attempt was audited. A refused credential is a denial, not
    // a silent drop — and the record is structural: op, principal,
    // resource, decision, never the credential.
    let recs = rig.audit.records();
    assert_eq!(recs.len(), 6, "{recs:?}");
    assert!(recs.iter().all(|r| r.action == "session.attach"));
    assert_eq!(recs[0].resource, id);
    assert_eq!(recs[0].decision, "allow");
    assert!(recs[1..].iter().all(|r| r.decision == "deny"), "{recs:?}");

    // Denied peers are audited too. They never reach the ACL, because
    // they hold no credential — and the answer is the same either way.
    let denied = self::rig(Arc::new(DenyAll));
    let dctx = self::ctx(Principal::Device("stranger".into()), ALL_CAPS);
    let reply = denied
        .server
        .dispatch(
            &dctx,
            &ControlMessage::new(
                2,
                control_message::Body::SessionAttach(wire::SessionAttach {
                    session_id: "01K0NOSUCHSESSION".into(),
                    mode: wire::AttachMode::Rw as i32,
                    ..Default::default()
                }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::AuthFailed));
    let recs = denied.audit.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, "deny");
    assert_eq!(recs[0].action, "session.attach");
}

// ---- SIGTERM graceful drain (CLI.md §6.12, ADR-0003) --------------

/// [`Server::drain`] closes every live session through the broker's
/// ordinary close procedure — `session.closed{reason:"closed"}` lands
/// in the ring exactly like an explicit `session.close` would.
#[tokio::test]
async fn drain_closes_every_live_session_with_reason_closed() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (id1, _ticket1, _pipe1) = open_session(&rig, &ctx).await;
    let (id2, _ticket2, _pipe2) = open_session(&rig, &ctx).await;
    assert_eq!(rig.broker.session_count(), 2);

    rig.server.drain().await;

    assert_eq!(rig.broker.session_count(), 0);
    for id in [id1, id2] {
        let out = SessionBackend::pull(
            rig.broker.as_ref(),
            &SessionId(id),
            Cursor::from_offset(0),
            1024,
            Duration::ZERO,
        )
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
    }
}

/// Once draining, `session.open` is refused — `RESOURCE_EXHAUSTED`,
/// never a session created.
#[tokio::test]
async fn draining_refuses_a_new_open_before_creating_a_session() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

    rig.server.drain().await;

    let reply = rig.server.dispatch(&ctx, &session_open(10)).await.unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::ResourceExhausted));
    assert_eq!(
        rig.broker.session_count(),
        0,
        "a refused open must not create a session, draining or not"
    );
}

/// The gate an in-flight `session.open`/`session.attach` races against:
/// `require_not_draining` has to refuse a session that is *still live*,
/// not only one `drain` already finished closing — otherwise the only
/// window it would ever cover is the instant after every session is
/// already gone, where `session.attach`'s credential check fails first
/// on its own (`AuthFailed`, protocol.md §10-2) and never reaches it.
///
/// The session's source ignores `SIGHUP`, so [`Broker::close_all`]'s
/// per-session `close` parks on the injected clock instead of finishing
/// immediately — the real-world equivalent of a child slow to react to
/// the first escalation step, held open here on purpose to observe
/// `draining = true` with the victim session still in the registry and
/// its credential still valid.
#[tokio::test]
async fn draining_refuses_a_still_live_attach_mid_drain() {
    let grace = Duration::from_secs(5);
    let rig = rig_with(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::with_ignored_signals(64 * 1024, &[Signal::Hup])),
        grace,
    );
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (opened, _pipe) = open_session_full(&rig, &ctx).await;
    let pending_before = rig.server.pending_tickets();

    let server = rig.server.clone();
    let draining = tokio::spawn(async move { server.drain().await });
    // Let `drain` set the flag and `close_all` send its HUP; the ignored
    // signal leaves `close` parked on `clock.sleep(grace)`, not finished.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!draining.is_finished(), "drain must still be in flight");
    assert_eq!(
        rig.broker.session_count(),
        1,
        "the victim session must still be live for this test to mean anything"
    );

    let attach_reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                11,
                control_message::Body::SessionAttach(wire::SessionAttach {
                    session_id: opened.session_id.clone(),
                    resume_token: opened.resume_token.clone(),
                    mode: wire::AttachMode::Rw as i32,
                    ..Default::default()
                }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        error_code(&attach_reply),
        Some(ErrorCode::ResourceExhausted),
        "a live session must still be refused while draining, not silently attachable"
    );
    assert_eq!(
        rig.server.pending_tickets(),
        pending_before,
        "a refused attach mints no ticket"
    );

    // Escalate past the ignored HUP: the pipe does not ignore TERM, so
    // one more grace period is all `close` needs to finish, and the
    // spawned `drain` task — and the test — can end cleanly.
    rig.clock.advance(grace);
    draining.await.expect("drain task did not panic");
    assert_eq!(rig.broker.session_count(), 0);
}

/// `no_steal` (protocol.md §10, for "신중한 자동화") has to survive the
/// round trip: it decides the attach *and* rides on the ticket, so
/// redeeming the ticket — which is where the data stream actually takes
/// the lease — cannot quietly upgrade a careful attach into a stealing
/// one. And a ticket minted by `session.open` carries no attach
/// decision at all, because `session.open` only decided `session.open`.
///
/// The control message *probes* the lease rather than taking it: a
/// redemption is not final until its successor credential is minted, and
/// a steal that happened before a failure would leave the real writer
/// demoted in favour of a connection that never attached.
#[tokio::test]
async fn no_steal_is_honoured_at_attach_and_rides_on_the_ticket() {
    let rig = allow_rig();
    let owner = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (opened, _pipe) = open_session_full(&rig, &owner).await;
    let id = opened.session_id.clone();
    let sid = SessionId(id.clone());

    // What `session.open` minted: no steal, and no attach decision.
    let purpose = rig
        .server
        .redeem_ticket(owner.conn_id, StreamKind::SessionData, &opened.ticket)
        .expect("the open's ticket is redeemable")
        .purpose;
    let TicketPurpose::Session {
        no_steal,
        attach_authorized,
        ..
    } = purpose
    else {
        panic!("expected a Session ticket, got {purpose:?}");
    };
    assert!(!no_steal);
    assert!(
        !attach_authorized,
        "session.open never decided session.attach"
    );

    // The owner takes the writer lease.
    let reply = rig
        .server
        .dispatch(
            &owner,
            &ControlMessage::new(
                2,
                control_message::Body::SessionWrite(wire::SessionWrite {
                    session_id: id.clone(),
                    data: b"x".to_vec(),
                }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(error_code(&reply), None, "{reply:?}");

    let attach = |token: Vec<u8>, no_steal: bool| wire::SessionAttach {
        session_id: id.clone(),
        resume_token: token,
        mode: wire::AttachMode::Rw as i32,
        no_steal,
        ..Default::default()
    };
    let careful = ConnCtx {
        principal: Principal::Device("phone".into()),
        conn_id: 43,
        ..owner.clone()
    };

    // A different principal, refusing to steal: SESSION_CONFLICT, and
    // the lease does not move.
    let reply = rig
        .server
        .dispatch(
            &careful,
            &ControlMessage::new(
                3,
                control_message::Body::SessionAttach(attach(opened.resume_token.clone(), true)),
            ),
        )
        .await
        .unwrap();
    assert_eq!(error_code(&reply), Some(ErrorCode::SessionConflict));
    assert_eq!(
        rig.broker.get(&sid).unwrap().info().writer.as_deref(),
        Some("device:laptop"),
        "a refused attach must not move the lease"
    );

    // Steal-by-default wins, and the ticket records that it may. The
    // conflict above was decided before the rotation, so the credential
    // it refused is still the one that works here.
    let reply = rig
        .server
        .dispatch(
            &careful,
            &ControlMessage::new(
                4,
                control_message::Body::SessionAttach(attach(opened.resume_token.clone(), false)),
            ),
        )
        .await
        .unwrap();
    let response::Body::SessionAttached(a) = response_body(&reply) else {
        panic!("expected SessionAttached, got {reply:?}");
    };
    assert_eq!(
        rig.broker.get(&sid).unwrap().info().writer.as_deref(),
        Some("device:laptop"),
        "the steal lands when the data stream opens, not before"
    );
    let next_token = a.new_resume_token.clone();
    let purpose = rig
        .server
        .redeem_ticket(careful.conn_id, StreamKind::SessionData, &a.ticket)
        .expect("the attach ticket is redeemable")
        .purpose;
    let TicketPurpose::Session {
        no_steal,
        attach_authorized,
        ..
    } = purpose
    else {
        panic!("expected a Session ticket, got {purpose:?}");
    };
    assert!(!no_steal);
    assert!(attach_authorized, "session.attach already decided it");

    // A careful attach that *does* win — the lease is the requester's
    // own principal — still stamps `no_steal` on its ticket, so the
    // data stream inherits the promise.
    let reply = rig
        .server
        .dispatch(
            &owner,
            &ControlMessage::new(
                5,
                control_message::Body::SessionAttach(attach(next_token, true)),
            ),
        )
        .await
        .unwrap();
    let response::Body::SessionAttached(a) = response_body(&reply) else {
        panic!("expected SessionAttached, got {reply:?}");
    };
    let purpose = rig
        .server
        .redeem_ticket(owner.conn_id, StreamKind::SessionData, &a.ticket)
        .expect("the attach ticket is redeemable")
        .purpose;
    let TicketPurpose::Session { no_steal, .. } = purpose else {
        panic!("expected a Session ticket, got {purpose:?}");
    };
    assert!(no_steal, "the ticket carries the flag the attach asked for");
}

#[tokio::test]
async fn close_with_kill_and_exit_events_survive_for_late_readers() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (id, _t, mut pipe) = open_session(&rig, &ctx).await;
    pipe.write_output(b"bye").await.unwrap();
    // Blocking read from 0 lands once the output is in the ring.
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                1,
                control_message::Body::SessionRead(wire::SessionRead {
                    session_id: id.clone(),
                    after: 0,
                    max_bytes: 0,
                    wait_ms: 30_000,
                    ctl_after: 0,
                }),
            ),
        )
        .await
        .unwrap();
    assert!(matches!(
        response_body(&reply),
        response::Body::SessionReadResult(r) if !r.events.is_empty()
    ));
    pipe.exit(SourceExit {
        exit_code: Some(3),
        signal: None,
    });
    // Wait for the exit to be recorded via a blocking read.
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                2,
                control_message::Body::SessionRead(wire::SessionRead {
                    session_id: id.clone(),
                    after: 3,
                    max_bytes: 0,
                    wait_ms: 30_000,
                    ctl_after: 0,
                }),
            ),
        )
        .await
        .unwrap();
    let events = match response_body(&reply) {
        response::Body::SessionReadResult(r) => r.events.clone(),
        other => panic!("expected SessionReadResult, got {other:?}"),
    };
    let exit = events
        .iter()
        .find_map(|e| match &e.body {
            Some(session_read_event::Body::Exit(x)) => Some(x.clone()),
            _ => None,
        })
        .expect("exit event");
    assert_eq!(exit.exit_code, 3);
    assert_eq!(exit.signal, None);
    assert_eq!(exit.final_seq, 3);
    assert_eq!(
        rig.broker.get(&SessionId(id.clone())).unwrap().state(),
        SessionState::Exited
    );
    // Closing an exited session sends no signal (CLI.md §6.7).
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                3,
                control_message::Body::SessionClose(wire::SessionClose {
                    session_id: id.clone(),
                    signal: Some("kill".into()),
                }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(error_code(&reply), None, "{reply:?}");
    assert!(pipe.signals().is_empty());
    let _ = &rig.clock;
}

/// A malformed / oversize `session_id` is `INVALID_ARGUMENT` before
/// the choke point (nothing audited) — a pinned peer cannot pump 256 KiB
/// per request into the audit log, and the check discloses nothing.
#[tokio::test]
async fn malformed_session_ids_are_rejected_before_the_choke_point() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let too_long = "A".repeat(SESSION_ID_MAX_LEN + 1);
    for bad in ["", "has space", "slash/inside", "../etc", too_long.as_str()] {
        for (name, body) in session_bodies(bad) {
            if matches!(name, "open" | "list") {
                continue; // no id in those
            }
            let reply = rig
                .server
                .dispatch(&ctx, &ControlMessage::new(1, body))
                .await
                .unwrap();
            assert_eq!(
                error_code(&reply),
                Some(ErrorCode::InvalidArgument),
                "{name} with {bad:?}"
            );
        }
    }
    assert!(rig.audit.records().is_empty(), "rejected before audit");
    assert_eq!(rig.broker.session_count(), 0);
    // The exact-length boundary is fine, and ULIDs (the real shape) pass.
    assert!(valid_session_id(&"a".repeat(SESSION_ID_MAX_LEN)));
    assert!(valid_session_id("01K0SESSIONULID0000000000_"));
    assert!(!valid_session_id(""));
}

/// Control entries are zero-length: they sit *at* an output offset
/// without advancing it, so `after` alone cannot say whether one was
/// already delivered. A caller that echoes `next_ctl_after` back sees
/// each control exactly once and its long-poll parks; one that does not
/// gets the documented at-least-once re-delivery (protocol.md §9).
/// Without the cursor a `--wait` loop would spin for ever.
#[tokio::test]
async fn echoed_control_cursor_makes_a_long_poll_park() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (id, _t, _pipe) = open_session(&rig, &ctx).await;
    // Taking the writer lease appends a control entry at offset 0.
    rig.server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                2,
                control_message::Body::SessionWrite(wire::SessionWrite {
                    session_id: id.clone(),
                    data: b"x".to_vec(),
                }),
            ),
        )
        .await
        .unwrap();

    let read = |request_id, after, ctl_after, wait_ms| {
        let server = rig.server.clone();
        let ctx = ctx.clone();
        let id = id.clone();
        async move {
            let reply = server
                .dispatch(
                    &ctx,
                    &ControlMessage::new(
                        request_id,
                        control_message::Body::SessionRead(wire::SessionRead {
                            session_id: id,
                            after,
                            max_bytes: 0,
                            wait_ms,
                            ctl_after,
                        }),
                    ),
                )
                .await
                .unwrap();
            match response_body(&reply) {
                response::Body::SessionReadResult(r) => r.clone(),
                other => panic!("expected SessionReadResult, got {other:?}"),
            }
        }
    };

    let first = read(3, 0, 0, 0).await;
    assert_eq!(first.events.len(), 1, "writer_changed at offset 0");
    assert_eq!(first.next_after, 0);
    assert!(first.next_ctl_after > 0);

    // Stateless repeat: same event again (at-least-once), returns at
    // once even with a long wait — this is the loop the cursor fixes.
    let repeat = read(4, first.next_after, 0, 30_000).await;
    assert_eq!(repeat.events.len(), 1);

    // Echoing the cursor back: nothing new, so the read parks until the
    // wait elapses on the injected clock.
    let parked = tokio::spawn(read(5, first.next_after, first.next_ctl_after, 30_000));
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(!parked.is_finished(), "parked instead of spinning");
    rig.clock.advance(Duration::from_millis(30_000));
    let out = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .expect("returned once the wait elapsed")
        .unwrap();
    assert!(out.events.is_empty(), "{:?}", out.events);
    assert_eq!(out.next_ctl_after, first.next_ctl_after);
}

/// `wait_ms` is clamped to `SESSION_READ_MAX_WAIT` (like `max_bytes`,
/// never rejected): a read asking to park "forever" returns once the
/// injected clock passes the cap, with no data.
#[tokio::test]
async fn session_read_wait_is_clamped_to_the_cap() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (id, _t, _pipe) = open_session(&rig, &ctx).await;
    let reader = {
        let server = rig.server.clone();
        let ctx = ctx.clone();
        let id = id.clone();
        tokio::spawn(async move {
            server
                .dispatch(
                    &ctx,
                    &ControlMessage::new(
                        2,
                        control_message::Body::SessionRead(wire::SessionRead {
                            session_id: id,
                            after: 0,
                            max_bytes: 0,
                            wait_ms: u64::MAX,
                            ctl_after: 0,
                        }),
                    ),
                )
                .await
                .unwrap()
        })
    };
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(!reader.is_finished(), "still parked before the cap");
    // Just short of the cap: still parked. Past it: returns.
    rig.clock
        .advance(SESSION_READ_MAX_WAIT - Duration::from_millis(1));
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(!reader.is_finished(), "still parked just short of the cap");
    rig.clock.advance(Duration::from_millis(1));
    let reply = tokio::time::timeout(Duration::from_secs(5), reader)
        .await
        .expect("read returned once the clamped wait elapsed")
        .unwrap();
    match response_body(&reply) {
        response::Body::SessionReadResult(r) => assert!(r.events.is_empty()),
        other => panic!("expected SessionReadResult, got {other:?}"),
    }
}

/// `SessionClosed.final_seq` is the offset at removal time (CLI.md
/// §6.7): output the child emits while dying — after HUP, before TERM
/// lands — is included, and it equals the offset on the trailing
/// `session.closed` entry.
#[tokio::test]
async fn close_final_seq_includes_output_emitted_while_dying() {
    let grace = Duration::from_millis(100);
    let rig = rig_with(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::with_ignored_signals(64 * 1024, &[Signal::Hup])),
        grace,
    );
    let clock = rig.clock.clone();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (id, _t, mut pipe) = open_session(&rig, &ctx).await;
    pipe.write_output(b"$ ").await.unwrap();

    let closer = {
        let server = rig.server.clone();
        let ctx = ctx.clone();
        let id = id.clone();
        tokio::spawn(async move {
            server
                .dispatch(
                    &ctx,
                    &ControlMessage::new(
                        2,
                        control_message::Body::SessionClose(wire::SessionClose {
                            session_id: id,
                            signal: None,
                        }),
                    ),
                )
                .await
                .unwrap()
        })
    };
    // HUP is ignored by this child; it keeps talking while dying.
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(!closer.is_finished());
    assert_eq!(pipe.signals(), vec![Signal::Hup]);
    pipe.write_output(b"bye").await.unwrap();
    // Let the dying output reach the ring before TERM ends the child.
    let backend: &dyn SessionBackend = rig.broker.as_ref();
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        backend.pull(
            &SessionId(id.clone()),
            Cursor::from_offset(2),
            1024,
            Duration::from_secs(30),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        out.events
            .iter()
            .any(|e| matches!(e, ReplayEvent::Output { .. }))
    );
    clock.advance(grace);
    let reply = tokio::time::timeout(Duration::from_secs(5), closer)
        .await
        .expect("close finished after TERM")
        .unwrap();
    let final_seq = match response_body(&reply) {
        response::Body::SessionClosed(c) => c.final_seq,
        other => panic!("expected SessionClosed, got {other:?}"),
    };
    assert_eq!(final_seq, 5, "'$ ' + 'bye'");
    assert_eq!(pipe.signals(), vec![Signal::Hup, Signal::Term]);
    // The trailing closed entry carries the same offset.
    let out = backend
        .pull(&SessionId(id), Cursor::from_offset(5), 1024, Duration::ZERO)
        .await
        .unwrap();
    assert!(
        matches!(
            out.events.last(),
            Some(ReplayEvent::Control { sequence: 5, .. })
        ),
        "{:?}",
        out.events
    );
}

/// An empty `SessionWrite` passes ACL + existence but takes no lease,
/// so it can neither displace nor flap the current writer.
#[tokio::test]
async fn empty_write_takes_no_lease() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let (id, _t, _pipe) = open_session(&rig, &ctx).await;
    let reply = rig
        .server
        .dispatch(
            &ctx,
            &ControlMessage::new(
                2,
                control_message::Body::SessionWrite(wire::SessionWrite {
                    session_id: id.clone(),
                    data: Vec::new(),
                }),
            ),
        )
        .await
        .unwrap();
    match response_body(&reply) {
        response::Body::SessionWritten(w) => assert_eq!(w.bytes_written, 0),
        other => panic!("expected SessionWritten, got {other:?}"),
    }
    assert_eq!(rig.broker.get(&SessionId(id)).unwrap().info().writer, None);
    assert_eq!(rig.audit.records().len(), 2, "open + write both audited");
}

#[test]
fn replay_events_map_to_wire_and_oversize_output_is_split() {
    let big = bytes::Bytes::from(vec![7u8; wire::SESSION_CHUNK_MAX * 2 + 5]);
    let events = replay_event_to_wire(ReplayEvent::Output {
        sequence: 100 + big.len() as u64,
        data: big.clone(),
    });
    assert_eq!(events.len(), 3);
    let seqs: Vec<u64> = events
        .iter()
        .map(|e| match &e.body {
            Some(session_read_event::Body::Output(o)) => o.sequence,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        seqs,
        vec![
            100 + wire::SESSION_CHUNK_MAX as u64,
            100 + 2 * wire::SESSION_CHUNK_MAX as u64,
            100 + big.len() as u64
        ]
    );
    let closed = replay_event_to_wire(ReplayEvent::Control {
        sequence: 9,
        ctl_id: 1,
        event: ControlEvent::Closed {
            reason: CloseReason::TtlExpired,
        },
    });
    assert!(matches!(
        &closed[0].body,
        Some(session_read_event::Body::Closed(c)) if c.reason == "ttl_expired" && c.seq == 9
    ));
    assert!(rfc3339_after(Duration::from_secs(60)).ends_with('Z'));
}

// ------------------------------------------------------------------
// ControlPinger (M3 Step 4 Stage A) — `PLAN.md` "L2 유닛 테스트" list:
// request_id monotonic per connection, timeout judgment on a paused
// clock, unsolicited Pong dropped, correlation across interleaved
// inbound traffic. No `sleep()` anywhere below.
// ------------------------------------------------------------------

use crate::client::pathwatch::{PathWatch, PathWatchConfig, ProbeSource, watch_path};

fn pinger() -> (ControlPinger, tokio::sync::mpsc::Receiver<ControlMessage>) {
    let (tx, rx) = tokio::sync::mpsc::channel(MAX_INFLIGHT_REQUESTS_PER_CONN);
    (
        ControlPinger::new(PathWatch::new(PathWatchConfig::default()), tx),
        rx,
    )
}

#[tokio::test]
async fn request_ids_are_monotonic_per_connection() {
    let (pinger, _out) = pinger();
    let mut ids = Vec::new();
    for _ in 0..5 {
        ids.push(pinger.send_probe().await.unwrap());
    }
    assert_eq!(
        ids,
        vec![1, 2, 3, 4, 5],
        "each probe on one connection must get a fresh, increasing id"
    );
}

#[tokio::test(start_paused = true)]
async fn send_probe_backpressures_on_a_full_queue_instead_of_dropping_silently() {
    // The regression finding `4` (M3 Step 4 review): `PathState::verdict`
    // counts a probe as a strike the moment it decides to send one, so
    // a `send_probe` that silently drops on a momentarily-full queue
    // spends that strike on a `Ping` that never reached the wire.
    // `send_probe` must instead wait for room, exactly like every other
    // seam onto this queue (`serve_control`'s "All replies funnel back
    // through `reply_rx`" doc).
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let filler = tx.clone();
    let pinger = ControlPinger::new(PathWatch::new(PathWatchConfig::default()), tx);
    filler
        .try_send(ControlMessage::new(
            0,
            control_message::Body::SessionList(wire::SessionList {}),
        ))
        .expect("capacity-1 queue must accept the first message");

    let mut pending = Box::pin(pinger.send_probe());
    // A bounded deadline backstop under a paused clock, not a sleep
    // standing in for ordering (`docs/design/testing.md` L2): nothing
    // else is runnable, so this resolves the instant tokio proves the
    // future is still pending — it never advances any real wall time.
    assert!(
        tokio::time::timeout(Duration::from_secs(3600), &mut pending)
            .await
            .is_err(),
        "send_probe must not resolve while the outbound queue is full — a full queue is \
         backpressure, not a license to drop the probe"
    );

    // Drain the queue: room exists now, so the pending probe can land.
    let filler_msg = rx
        .recv()
        .await
        .expect("the filler message must still be queued");
    assert_eq!(filler_msg.request_id, 0);
    let id = pending
        .await
        .expect("send_probe must complete once the queue has room, not be dropped");
    let queued = rx
        .recv()
        .await
        .expect("the probe itself must have been queued, not silently discarded");
    assert_eq!(queued.request_id, id);
    assert!(matches!(queued.body, Some(control_message::Body::Ping(_))));
}

#[tokio::test]
async fn send_probe_queues_a_ping_carrying_its_own_id() {
    let (pinger, mut out) = pinger();
    let id = pinger.send_probe().await.unwrap();
    let queued = out.try_recv().expect("send_probe must queue something");
    assert_eq!(queued.request_id, id);
    assert!(matches!(queued.body, Some(control_message::Body::Ping(_))));
}

#[tokio::test]
async fn a_pong_for_an_unknown_request_id_is_dropped() {
    let (pinger, _out) = pinger();
    let _ours = pinger.send_probe().await.unwrap();
    // Never one of ours: nowhere near the counter's range.
    let stray = ControlMessage::new(999_999, control_message::Body::Pong(wire::Pong {}));
    assert!(
        !pinger.observe(&stray),
        "an unsolicited Pong must not be reported as a correlated answer"
    );
    assert!(
        !pinger.watch().is_dead(),
        "observing a stray Pong must not perturb this pinger's watch at all"
    );
}

#[tokio::test]
async fn a_non_pong_message_is_never_treated_as_an_answer() {
    let (pinger, _out) = pinger();
    let id = pinger.send_probe().await.unwrap();
    // Same request_id, but not a `Pong` — must not be mistaken for the
    // answer to our own probe.
    let echo = ControlMessage::new(id, control_message::Body::SessionList(wire::SessionList {}));
    assert!(!pinger.observe(&echo));
}

#[tokio::test]
async fn correlation_survives_interleaved_traffic_and_reordering() {
    let (pinger, _out) = pinger();
    let first = pinger.send_probe().await.unwrap();
    let second = pinger.send_probe().await.unwrap();

    // Unrelated inbound traffic between the probes going out and
    // either being answered.
    let unrelated_request = ControlMessage::new(
        900,
        control_message::Body::SessionList(wire::SessionList {}),
    );
    assert!(!pinger.observe(&unrelated_request));
    let foreign_pong = ControlMessage::new(4_242, control_message::Body::Pong(wire::Pong {}));
    assert!(!pinger.observe(&foreign_pong));

    // The second probe's answer arrives first (realistic under
    // reordering) — it must correlate to its own id, not the first's.
    assert!(pinger.observe(&ControlMessage::new(
        second,
        control_message::Body::Pong(wire::Pong {})
    )));
    // The first, answered later, still correlates.
    assert!(pinger.observe(&ControlMessage::new(
        first,
        control_message::Body::Pong(wire::Pong {})
    )));
    // Both already consumed: a duplicate delivery of either answers
    // nothing a second time.
    assert!(!pinger.observe(&ControlMessage::new(
        first,
        control_message::Body::Pong(wire::Pong {})
    )));
    assert!(!pinger.observe(&ControlMessage::new(
        second,
        control_message::Body::Pong(wire::Pong {})
    )));
}

#[tokio::test]
async fn note_inbound_clears_every_outstanding_id_even_ones_never_answered() {
    let (pinger, _out) = pinger();
    let leaked = pinger.send_probe().await.unwrap();
    let _also_outstanding = pinger.send_probe().await.unwrap();

    // Some other inbound message proves the path without answering
    // either probe by id (e.g. ordinary session traffic, or an
    // uncorrelated `Ping` from the peer's own probe loop).
    pinger.note_inbound();

    // Both ids are gone — a late `Pong` for either no longer
    // correlates, because the connection has already proven itself
    // alive by other means and holding them further would only leak.
    assert!(
        !pinger.observe(&ControlMessage::new(
            leaked,
            control_message::Body::Pong(wire::Pong {})
        )),
        "note_inbound must clear ids that were never individually answered"
    );
}

#[tokio::test(start_paused = true)]
async fn cadence_survives_a_reply_storm_of_uncorrelated_pings() {
    // The regression `finding 1` (M3 Step 4 review) named: symmetric
    // probing must not pin a registered connection to the fast
    // cadence forever. Simulates the peer's own probe loop hammering
    // this side with `Ping`s (never this pinger's own — `record`
    // never sees a `Pong`) while nothing else happens, and asserts the
    // idle cadence is still reached — exactly
    // `pathwatch.rs`'s own `a_healthy_idle_path_falls_to_the_slow_cadence`
    // guard, but through `ControlPinger::record` rather than
    // `PathState` directly.
    let (pinger, _out) = pinger();
    let watch = pinger.watch().clone();
    let cfg = *watch.config();

    let mut request_id = 0u64;
    let mut elapsed = Duration::ZERO;
    while elapsed < cfg.active_window + Duration::from_secs(1) {
        tokio::time::advance(Duration::from_millis(100)).await;
        elapsed += Duration::from_millis(100);
        request_id += 1;
        let ping = ControlMessage::new(request_id, control_message::Body::Ping(wire::Ping {}));
        assert!(!pinger.record(&ping));
    }

    assert_eq!(
        watch.cadence(),
        cfg.idle_probe_interval,
        "a stream of inbound Pings alone must not hold this side's watch on the fast cadence"
    );
}

#[tokio::test(start_paused = true)]
async fn cadence_survives_a_reply_storm_of_uncorrelated_pongs() {
    // The Pong half of the same regression: `note_inbound` clears
    // `outstanding` on *every* non-correlated inbound message, so a
    // peer `Ping` landing between our own `Ping` and its answering
    // `Pong` makes that `Pong` arrive with nothing left to match —
    // `record` must still treat it as bare liveness
    // (`PathState::observe_inbound`), never as `traffic`, or the
    // watch never reaches the idle cadence on a perfectly quiet
    // connection.
    let (pinger, _out) = pinger();
    let watch = pinger.watch().clone();
    let cfg = *watch.config();

    let mut request_id = 0u64;
    let mut elapsed = Duration::ZERO;
    while elapsed < cfg.active_window + Duration::from_secs(1) {
        tokio::time::advance(Duration::from_millis(100)).await;
        elapsed += Duration::from_millis(100);
        request_id += 1;
        // Never correlated: this pinger never allocated `request_id`
        // through `send_probe`, so `observe` always misses and this
        // falls through to `record`'s fallback match.
        let pong = ControlMessage::new(request_id, control_message::Body::Pong(wire::Pong {}));
        assert!(!pinger.record(&pong));
    }

    assert_eq!(
        watch.cadence(),
        cfg.idle_probe_interval,
        "a stream of uncorrelated inbound Pongs alone must not hold this side's watch on \
         the fast cadence"
    );
}

#[tokio::test(start_paused = true)]
async fn a_correlated_pong_clears_strikes_the_same_way_answered_traffic_always_has() {
    use crate::client::pathwatch::Verdict;

    let (pinger, mut out) = pinger();
    let watch = pinger.watch().clone();

    // Silence past the fast cadence earns a strike (mirrors
    // `pathwatch.rs`'s own `silence_earns_probes_and_then_a_verdict`).
    tokio::time::advance(watch.config().probe_interval + Duration::from_millis(1)).await;
    assert_eq!(watch.verdict(Duration::from_millis(1)), Verdict::Probe);

    // Answer it through the pinger's correlation path rather than
    // `PathWatch::inbound` directly — the point of this test is that
    // `ControlPinger::observe` is what reaches `inbound`, not that
    // `inbound` itself clears strikes (already covered in
    // `pathwatch.rs`).
    let id = pinger.send_probe().await.unwrap();
    let queued = out.try_recv().expect("send_probe must have queued a Ping");
    assert_eq!(queued.request_id, id);
    assert!(pinger.observe(&ControlMessage::new(
        id,
        control_message::Body::Pong(wire::Pong {})
    )));

    // Immediately after, the path is not silent — the pending strike
    // must not compound and the connection must not be declared dead
    // even after another `probe_interval` of quiet.
    tokio::time::advance(watch.config().probe_interval).await;
    assert_ne!(watch.verdict(Duration::from_millis(1)), Verdict::Dead);
}

/// A stub `ProbeSource` that never closes on its own — the death in
/// this test must come purely from unanswered probes going silent,
/// exactly like a real connection whose packets stop arriving without
/// QUIC itself noticing anything (`pathwatch.rs`'s module doc).
#[derive(Clone)]
struct NeverCloses;

impl ProbeSource for NeverCloses {
    async fn closed(&self) {
        std::future::pending::<()>().await
    }

    fn rtt(&self) -> Duration {
        Duration::from_millis(1)
    }
}

#[tokio::test(start_paused = true)]
async fn unanswered_probes_are_judged_dead_on_a_paused_clock() {
    let watch = PathWatch::new(PathWatchConfig::default());
    let (tx, mut out) = tokio::sync::mpsc::channel(MAX_INFLIGHT_REQUESTS_PER_CONN);
    let pinger = Arc::new(ControlPinger::new(watch.clone(), tx));
    let probes = Arc::new(tokio::sync::Notify::new());

    // Nobody ever answers a queued Ping — the outbound queue is
    // drained (as `serve_control`'s writer would) but no reply comes
    // back, which is exactly "the path stopped carrying packets".
    let drain = tokio::spawn(async move { while out.recv().await.is_some() {} });
    let watchdog = tokio::spawn(watch_path(NeverCloses, watch.clone(), probes.clone()));
    let driver = tokio::spawn(drive_probes(pinger.clone(), probes));

    tokio::time::timeout(Duration::from_secs(5), watch.dead())
        .await
        .expect("a connection whose probes are never answered must be judged dead");

    watchdog.await.unwrap();
    driver.abort();
    drain.abort();
}

// ---------------------------------------------------------------
// `forward.local` — the inline ACL on a peer-opened `TCP_CONNECT`
// stream (`PLAN.md` M4 Step 3, `docs/design/protocol.md` §7,
// `docs/design/testing.md` L2).
// ---------------------------------------------------------------

fn tcp_connect_header(host: &str, port: u32) -> StreamHeader {
    tcp_connect_header_with_policy(host, port, false)
}

/// Same as [`tcp_connect_header`] but with the caller choosing
/// `deny_host_local` explicitly — for the ADR-0019 host-local dial filter
/// tests, which need a header that asks for filtering.
fn tcp_connect_header_with_policy(host: &str, port: u32, deny_host_local: bool) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::TcpConnect as i32,
        // §7's ticket exception: a `TCP_CONNECT` stream carries none.
        ticket: Vec::new(),
        host: host.to_string(),
        port,
        deny_host_local,
    }
}

/// A [`TunnelDialer`] that counts every call before doing anything
/// else, so "the host dialed nothing" is an assertion and not a hope.
/// With `target: Some(addr)` it makes a real loopback connection (so
/// the allow path is proved end-to-end, not stubbed); with `None`
/// every dial fails, standing in for a refused destination.
///
/// Also records the [`crate::tunnel::dial::DialPolicy`] each call was
/// handed: this dialer never honors `deny_host_local` itself (it is not
/// [`crate::tunnel::dial::SystemDialer`]), so the only way a test using it
/// can pin "`authorize_and_dial_tunnel` threads `header.deny_host_local`
/// through" is to read back what it was actually given.
struct CountingDialer {
    calls: std::sync::atomic::AtomicUsize,
    target: Option<SocketAddr>,
    policies: std::sync::Mutex<Vec<crate::tunnel::dial::DialPolicy>>,
}

impl CountingDialer {
    fn refusing() -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            target: None,
            policies: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn to(target: SocketAddr) -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            target: Some(target),
            policies: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The [`crate::tunnel::dial::DialPolicy`] the most recent `dial` call
    /// was handed. Panics if `dial` was never called — every test that
    /// calls this also asserts `calls() >= 1`.
    fn last_policy(&self) -> crate::tunnel::dial::DialPolicy {
        *self
            .policies
            .lock()
            .unwrap()
            .last()
            .expect("dial was never called")
    }
}

impl TunnelDialer for CountingDialer {
    fn dial<'a>(
        &'a self,
        _host: &'a str,
        _port: u16,
        policy: &'a crate::tunnel::dial::DialPolicy,
    ) -> crate::tunnel::dial::DialFuture<'a> {
        // Count first: an implementation that dialed before checking
        // the ACL would be recorded here even if the dial then failed.
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.policies.lock().unwrap().push(*policy);
        let target = self.target;
        Box::pin(async move {
            match target {
                Some(addr) => tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(crate::tunnel::dial::DialError::Connect),
                None => Err(crate::tunnel::dial::DialError::Connect(
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "mock dialer refuses everything",
                    ),
                )),
            }
        })
    }
}

/// The security core of M4 Step 3: under a denying policy a
/// `TCP_CONNECT` stream must reach **zero** dials (`docs/PRD.md` §9,
/// `docs/design/protocol.md` §13's "socket creation is 0 on the
/// un-authorized path"), and be refused with `PERMISSION_DENIED`.
///
/// Discriminating by construction: the dial counter is incremented as
/// the very first statement of `CountingDialer::dial`, before the
/// returned future can even fail, so an implementation that dialed
/// first and consulted the ACL afterwards — the exact ordering bug
/// this test exists for — would land `calls == 1` here and fail, and
/// would fail identically whether that speculative dial succeeded or
/// not. `..._allowed_dials_exactly_once...` below proves the counter
/// is wired at all (it reaches 1 there), so `0` here is a real
/// observation and not a counter that never moves.
#[tokio::test]
async fn tcp_connect_denied_dials_nothing_and_reports_permission_denied() {
    let rig = rig(Arc::new(DenyAll));
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = CountingDialer::refusing();

    let header = tcp_connect_header("db.internal", 5432);
    let rejection = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect_err("a denied forward.local must not yield a socket");

    assert_eq!(
        dialer.calls(),
        0,
        "the host must not dial before (or after) a forward.local deny"
    );
    assert!(!rejection.ok);
    assert_eq!(rejection.code, ErrorCode::PermissionDenied.as_str());

    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1, "exactly one audit line per decision");
    assert_eq!(recs[0].action, "forward.local");
    assert_eq!(recs[0].decision, "deny");
    assert_eq!(
        recs[0].resource, "db.internal:5432",
        "the audited resource is the requested destination"
    );
}

/// The host's whole `TCP_CONNECT` leg over a real QUIC stream (M4
/// Step 3): header → gate → dial → `ConnectResult{ok:true}` → **raw
/// byte splice**, with a real loopback destination on the far end. The
/// three earlier tests stop at the gate; this one is the only place the
/// bytes actually move, and it asserts the two things the splice can
/// silently get wrong:
///
/// 1. **Residue.** The requester writes payload immediately behind its
///    `StreamHeader` frame, so the host's framed reader has very likely
///    already swallowed those bytes by the time the header decodes
///    (`qsh_transport::FramedRecv::into_raw`). They must reach the
///    destination *first* — a splice that ignored the decoder's
///    leftovers would drop `"pipelined-"` here and echo only `"tail"`.
/// 2. **Half-close.** The requester finishes its send half while still
///    reading. The host must translate that into a `shutdown(SHUT_WR)`
///    on the destination socket — not a teardown — and keep the other
///    direction running: the destination answers the EOF with a
///    farewell (`"bye"`), which can only reach the requester if the
///    half-closed tunnel is still alive in that direction.
#[tokio::test]
async fn tcp_connect_allowed_splices_raw_bytes_both_ways() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A destination that echoes until EOF, then half-closes back.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _peer) = echo.accept().await.unwrap();
        let mut buf = [0u8; 512];
        loop {
            match sock.read(&mut buf).await.unwrap() {
                0 => break,
                n => sock.write_all(&buf[..n]).await.unwrap(),
            }
        }
        // Answer the half-close: a destination that speaks after its
        // peer stopped speaking is exactly what a teardown-on-first-EOF
        // splice would silence.
        sock.write_all(b"bye").await.unwrap();
        sock.shutdown().await.unwrap();
    });

    let (client, host_conn) = crate::tunnel::testutil::loopback_pair().await;
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let header = tcp_connect_header("127.0.0.1", u32::from(echo_addr.port()));

    // Requester: open the stream, send the header, and pipeline
    // payload straight behind it without waiting for the verdict.
    let (send, recv) = client.open_bi().await.unwrap();
    let mut framed = FramedStream::data(send, recv);
    framed.send.send(&header).await.unwrap();
    let (send, mut recv) = framed.split();
    let mut raw_send = send.into_raw();
    raw_send.write_all(b"pipelined-").await.unwrap();

    // Host: exactly what `handle_data_stream` does — read the header
    // off the stream, then hand both to `handle_tcp_connect`.
    let server = rig.server.clone();
    // A clone: the last `Connection` handle's drop closes the whole
    // QUIC connection with application code 0, discarding stream data
    // the peer has not read yet — so the test keeps its own handle
    // alive until it has drained everything.
    let host_handle = host_conn.clone();
    let host_side = tokio::spawn(async move {
        let (send, recv) = host_handle.accept_bi().await.unwrap();
        let mut framed = FramedStream::data(send, recv);
        let header: StreamHeader = framed.recv.recv().await.unwrap().expect("header frame");
        server.handle_tcp_connect(&ctx, framed, &header).await;
    });

    let result: wire::ConnectResult = recv.recv().await.unwrap().expect("ConnectResult");
    assert!(
        result.ok,
        "an allowed forward.local must connect: {result:?}"
    );

    raw_send.write_all(b"tail").await.unwrap();
    raw_send.finish().unwrap();
    let (mut raw_recv, residue) = recv.into_raw();
    assert!(
        residue.is_empty(),
        "the host sends nothing behind ConnectResult"
    );
    // `quinn::RecvStream` has its own inherent `read_to_end(limit)`,
    // which shadows `AsyncReadExt::read_to_end`.
    let got = raw_recv.read_to_end(4096).await.unwrap();
    assert_eq!(
        got, b"pipelined-tailbye",
        "every byte, in order, exactly once: the payload pipelined \
         behind the header frame, the payload after it, and the \
         destination's answer to the half-close"
    );

    host_side.await.unwrap();
    drop(host_conn);

    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].action, "forward.local");
    assert_eq!(recs[0].decision, "allow");
}

/// The `forward.local` resource an IPv6 destination earns is
/// bracketed — `[::1]:5432`, not the unsplittable `::1:5432` that
/// plain concatenation produces. This string is what M5's policy
/// engine will pattern-match rules against and what the audit record
/// carries, so its canonical form is asserted here rather than
/// discovered later (`qsh_proto::wire::format_host_port`).
#[tokio::test]
async fn tcp_connect_audits_an_ipv6_destination_in_bracketed_form() {
    let rig = rig(Arc::new(DenyAll));
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = CountingDialer::refusing();

    // What `parse_forward_spec` actually delivers: an IPv6 literal
    // with its brackets already stripped off the `[::1]` token.
    let header = tcp_connect_header("::1", 5432);
    let rejection = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect_err("a denied forward.local must not yield a socket");

    assert_eq!(dialer.calls(), 0);
    assert_eq!(rejection.code, ErrorCode::PermissionDenied.as_str());

    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].action, "forward.local");
    assert_eq!(recs[0].decision, "deny");
    assert_eq!(
        recs[0].resource, "[::1]:5432",
        "an IPv6 ACL resource must be splittable back into host and port"
    );
}

/// The allow leg of the same gate: one dial, after the decision, and
/// an `allow` audit line carrying `forward.local`. The dial is a real
/// loopback connection, so `Ok` here means an actual socket exists.
#[tokio::test]
async fn tcp_connect_allowed_dials_exactly_once_and_audits_forward_local() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = CountingDialer::to(addr);

    let header = tcp_connect_header("127.0.0.1", u32::from(addr.port()));
    let upstream = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect("an allowed forward.local dials the destination");

    assert_eq!(dialer.calls(), 1, "exactly one dial per TCP_CONNECT");
    let (accepted, _peer) = listener.accept().await.unwrap();
    drop(accepted);
    drop(upstream);

    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].action, "forward.local");
    assert_eq!(recs[0].decision, "allow");
    assert_eq!(recs[0].resource, format!("127.0.0.1:{}", addr.port()));
}

/// An authorized destination that will not accept: the requester gets
/// `CONNECTION_FAILED` (`docs/CLI.md` §3.3), and the `allow` decision
/// is still audited — a failed dial is not a policy event.
#[tokio::test]
async fn tcp_connect_dial_failure_reports_connection_failed() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = CountingDialer::refusing();

    let header = tcp_connect_header("127.0.0.1", 9);
    let rejection = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect_err("a refused destination is not a socket");

    assert_eq!(dialer.calls(), 1);
    assert!(!rejection.ok);
    assert_eq!(rejection.code, ErrorCode::ConnectionFailed.as_str());

    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].action, "forward.local");
    assert_eq!(recs[0].decision, "allow");
}

/// A malformed destination is refused on shape, before the ACL is
/// consulted: nothing to decide about, so no audit line is invented
/// and — as on every other refusal — nothing is dialed
/// (`docs/design/protocol.md` §9's "check the shape first" pattern).
#[tokio::test]
async fn tcp_connect_malformed_destination_is_invalid_argument_and_dials_nothing() {
    for header in [
        tcp_connect_header("", 80),
        tcp_connect_header("localhost", 0),
        tcp_connect_header("localhost", 70_000),
    ] {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let dialer = CountingDialer::refusing();

        let rejection = rig
            .server
            .authorize_and_dial_tunnel(&ctx, &header, &dialer)
            .await
            .expect_err("a malformed destination is never dialed");

        assert_eq!(dialer.calls(), 0, "{header:?}");
        assert_eq!(rejection.code, ErrorCode::InvalidArgument.as_str());
        assert!(
            rig.audit.records().is_empty(),
            "no ACL decision was made, so no audit line: {header:?}"
        );
    }
}

/// A destination host past the 255-octet DNS-name limit is refused on
/// shape, same discipline as the empty-host/zero-port/out-of-range-port
/// cases above: nothing to decide about, so no ACL call, no audit
/// line, and no dial (M8 Step 3b).
#[tokio::test]
async fn an_over_long_destination_host_is_refused_as_invalid_argument() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = CountingDialer::refusing();

    let long_host = "a".repeat(256);
    let header = tcp_connect_header(&long_host, 5432);
    let rejection = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect_err("a 256-octet host is never a real destination");

    assert_eq!(dialer.calls(), 0);
    assert_eq!(rejection.code, ErrorCode::InvalidArgument.as_str());
    assert!(
        rig.audit.records().is_empty(),
        "no ACL decision was made, so no audit line"
    );
}

// ---------------------------------------------------------------
// ADR-0019 decision 5 — byte-category shape check — and decision 3 —
// the host-local dial filter.
// ---------------------------------------------------------------

/// A destination host carrying an ASCII control byte is refused on shape,
/// before the ACL is consulted at all: same "nothing to decide about"
/// discipline as the length check right next to it (ADR-0019 decision 5).
/// No audit line, no dial — a malicious client that skips its own
/// encoder's checks must still be caught here, since the host cannot rely
/// on the peer having validated anything.
#[tokio::test]
async fn tcp_connect_host_with_control_bytes_is_invalid_argument_before_acl() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    for bad_host in ["evil\r\nHost", "tab\there", "de\x7fl", "spa ce"] {
        let dialer = CountingDialer::refusing();
        let header = tcp_connect_header(bad_host, 80);
        let rejection = rig
            .server
            .authorize_and_dial_tunnel(&ctx, &header, &dialer)
            .await
            .expect_err("a control-byte host is never a real destination");

        assert_eq!(dialer.calls(), 0, "{bad_host:?}");
        assert_eq!(rejection.code, ErrorCode::InvalidArgument.as_str());
        assert!(
            rig.audit.records().is_empty(),
            "no ACL decision was made, so no audit line: {bad_host:?}"
        );
    }
}

/// Same shape rule, non-ASCII byte instead of a control byte (ADR-0019
/// decision 5's "or any non-ASCII byte").
#[tokio::test]
async fn tcp_connect_host_with_non_ascii_is_invalid_argument_before_acl() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = CountingDialer::refusing();

    let header = tcp_connect_header("café.example", 80);
    let rejection = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect_err("a non-ASCII host is never a real destination");

    assert_eq!(dialer.calls(), 0);
    assert_eq!(rejection.code, ErrorCode::InvalidArgument.as_str());
    assert!(
        rig.audit.records().is_empty(),
        "no ACL decision was made, so no audit line"
    );
}

/// The security core of ADR-0019 decision 3: a `TCP_CONNECT` that asks for
/// the host-local dial filter (`deny_host_local: true`) and resolves only
/// to a host-local address is refused with `PERMISSION_DENIED`, on top of
/// (not instead of) the `forward.local` ACL `allow` — the filter is a dial
/// policy, not an ACL rule — with exactly one additional connection-level
/// deny audit line, `rule: None`. Uses the real `SystemDialer` (not
/// `CountingDialer`) with an injected resolver, since the filter itself
/// lives in `SystemDialer`, not in the ACL gate above it.
#[tokio::test]
async fn filtered_dial_is_permission_denied_with_one_deny_audit_line() {
    /// A [`crate::tunnel::dial::Resolver`] that always answers with a
    /// fixed, host-local address — this test's way of forcing the real
    /// [`crate::tunnel::dial::SystemDialer`] filter to see a resolution it
    /// must refuse, with no DNS involved.
    struct AlwaysLoopback;
    impl crate::tunnel::dial::Resolver for AlwaysLoopback {
        fn resolve<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> crate::tunnel::dial::ResolveFuture<'a> {
            Box::pin(async move { Ok(vec!["127.0.0.1:80".parse().unwrap()]) })
        }
    }

    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = crate::tunnel::dial::SystemDialer::with_resolver(AlwaysLoopback);

    let header = tcp_connect_header_with_policy("attacker-controlled.example", 80, true);
    let rejection = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect_err("a fully host-local resolution must be refused");

    assert!(!rejection.ok);
    assert_eq!(rejection.code, ErrorCode::PermissionDenied.as_str());

    // Two lines, not one: the ACL `allow` for `forward.local` (the filter
    // is a dial policy, not an ACL rule — `authorize_and_dial_tunnel`'s own
    // doc — so it never replaces that decision) and, on top of it, exactly
    // one filter-deny line in the same connection-level shape.
    let recs = rig.audit.records();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(recs[0].action, "forward.local");
    assert_eq!(recs[0].decision, "allow");
    assert_eq!(recs[1].action, "forward.local");
    assert_eq!(recs[1].decision, "deny");
    assert_eq!(recs[1].rule, None);
    assert_eq!(recs[1].resource, "attacker-controlled.example:80");
}

/// The regression this whole shape/filter addition must not cause: a
/// plain `-L`-shaped `TCP_CONNECT` (`deny_host_local: false`, today's
/// default) to `localhost` still dials — the filter never applies unless
/// the field asks for it. Also pins that `false` is what actually reaches
/// the dialer, not just that a dial happened: `CountingDialer` never
/// filters on its own, so a server that hard-coded `DialPolicy {
/// deny_host_local: true }` at the call site would still dial here and
/// only `last_policy()` catches it.
#[tokio::test]
async fn dynamic_hint_does_not_change_plain_tcp_connect_to_localhost() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = CountingDialer::to(addr);

    let header = tcp_connect_header_with_policy("127.0.0.1", u32::from(addr.port()), false);
    let upstream = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect("an unfiltered TCP_CONNECT to localhost dials exactly as before ADR-0019");

    assert_eq!(dialer.calls(), 1);
    assert!(
        !dialer.last_policy().deny_host_local,
        "header.deny_host_local: false must reach the dialer as false"
    );
    let (accepted, _peer) = listener.accept().await.unwrap();
    drop(accepted);
    drop(upstream);
}

/// The other direction of the same threading: `deny_host_local: true` on
/// the header must reach the dialer as `true`. `CountingDialer` does not
/// filter, so this dials regardless — the assertion that matters is
/// `last_policy()`, which is what would catch a server that hard-coded
/// either constant at the `DialPolicy` construction site in
/// `authorize_and_dial_tunnel`.
#[tokio::test]
async fn tcp_connect_threads_header_deny_host_local_true_to_the_dialer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = CountingDialer::to(addr);

    let header = tcp_connect_header_with_policy("127.0.0.1", u32::from(addr.port()), true);
    let upstream = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect("CountingDialer does not itself filter anything");

    assert_eq!(dialer.calls(), 1);
    assert!(
        dialer.last_policy().deny_host_local,
        "header.deny_host_local: true must reach the dialer as true"
    );
    let (accepted, _peer) = listener.accept().await.unwrap();
    drop(accepted);
    drop(upstream);
}

/// The security core of the tunnel-stream quota (M8 Step 3b, mirrors
/// `tcp_connect_denied_dials_nothing_and_reports_permission_denied`'s
/// own reasoning for the ACL axis): a principal already at its
/// `max_tunnel_streams_per_forward` cap must see **zero** dials and a
/// `RESOURCE_EXHAUSTED` `ConnectResult`, with the deny audited under
/// the quota category rather than `forward.local`'s allow/deny pair.
#[tokio::test]
async fn a_tunnel_dial_past_the_quota_never_reaches_the_dialer() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_tunnel_streams_per_forward: 0,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let dialer = CountingDialer::refusing();

    let header = tcp_connect_header("db.internal", 5432);
    let rejection = rig
        .server
        .authorize_and_dial_tunnel(&ctx, &header, &dialer)
        .await
        .expect_err("a principal already at its forward cap must not dial");

    assert_eq!(
        dialer.calls(),
        0,
        "the quota gate sits before the dial, same as the ACL gate"
    );
    assert!(!rejection.ok);
    assert_eq!(rejection.code, ErrorCode::ResourceExhausted.as_str());
    assert_eq!(rejection.message, "tunnel quota exceeded");

    // The ACL `allow` line for `forward.local` is still audited
    // (`authorize_stream` ran and passed) — the quota rejection is a
    // *second*, distinct line under its own category, not a
    // replacement for the ACL decision.
    let recs = rig.audit.records();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(recs[0].action, "forward.local");
    assert_eq!(recs[0].decision, "allow");
    assert_eq!(recs[1].resource, "quota_tunnels_forward");
    assert_eq!(recs[1].decision, "deny");
    assert_eq!(
        recs[1].request_id, "-",
        "R9 — the tunnel axis has no control request id (a data stream dial)"
    );
    assert_eq!(
        recs[1].peer_addr,
        ctx.peer_addr.to_string(),
        "R4 — the quota deny record must carry the live peer, not \"-\""
    );
}

/// The wire-level shape of a quota refusal on a real QUIC stream: the
/// requester's receive half is stopped with
/// [`RESET_CODE_RESOURCE_EXHAUSTED`], not the generic `0` a plain
/// "destination would not accept" refusal uses — a client reading
/// only the QUIC stop code (no `ConnectResult` frame reachable, e.g.
/// racing a connection teardown) still learns "retry" rather than
/// misreading a capacity refusal as "we are just done reading".
#[tokio::test]
async fn a_quota_refusal_stops_the_receive_half_with_resource_exhausted() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_tunnel_streams_per_forward: 0,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let header = tcp_connect_header("db.internal", 5432);

    let (client, host_conn) = crate::tunnel::testutil::loopback_pair().await;

    let (send, recv) = client.open_bi().await.unwrap();
    let mut framed = FramedStream::data(send, recv);
    framed.send.send(&header).await.unwrap();
    let (send, mut recv) = framed.split();
    // Nothing more is ever written on this half — into_raw is safe to
    // call immediately, and is the only way to read back the peer's
    // `STOP_SENDING` error code (`FramedSend::stopped` discards it).
    let raw_send = send.into_raw();

    let server = rig.server.clone();
    let host_handle = host_conn.clone();
    let host_side = tokio::spawn(async move {
        let (send, recv) = host_handle.accept_bi().await.unwrap();
        let mut framed = FramedStream::data(send, recv);
        let header: StreamHeader = framed.recv.recv().await.unwrap().expect("header frame");
        server.handle_tcp_connect(&ctx, framed, &header).await;
    });

    let result: wire::ConnectResult = recv.recv().await.unwrap().expect("ConnectResult");
    assert!(!result.ok);
    assert_eq!(result.code, ErrorCode::ResourceExhausted.as_str());

    let stop = tokio::time::timeout(Duration::from_secs(5), raw_send.stopped())
        .await
        .expect("the host must stop the receive half promptly")
        .expect("stopped() must observe the STOP_SENDING, not a connection error");
    assert_eq!(
        stop.map(|code| code.into_inner()),
        Some(u64::from(RESET_CODE_RESOURCE_EXHAUSTED)),
        "a quota refusal must stop with RESET_CODE_RESOURCE_EXHAUSTED, not the generic 0"
    );

    host_side.await.unwrap();
    drop(host_conn);
}

// ------------------------------------------------------------------
// connection caps, M8 Step 3b S4 — host/principal/pairing
// ------------------------------------------------------------------

/// M8 Step 3b ruling R3: a peer past the host connection cap must
/// never receive the ordinary local `Hello` — the refusal is decided
/// entirely in `Server::serve_connection`, *before*
/// `serve_connection_inner` (and the `local_hello` it builds) ever
/// runs, and reaches the peer as a normal `RESOURCE_EXHAUSTED` reply
/// to its own `Hello` (not a raw connection close — that shape is
/// pairing-only, ruling R2). The occupant below holds a *different*
/// principal's slot, proving this is the host axis
/// ([`QuotaKind::Connections`]), not the (nowhere-near-exhausted)
/// per-principal one.
#[tokio::test]
async fn a_connection_past_the_host_cap_is_refused_with_resource_exhausted_before_the_local_hello()
{
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_connections: 1,
            max_connections_per_principal: 100,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let occupant = opener_key(&Principal::Device("occupant".into()), AuthPath::Pin);
    let _occupant_permit = rig.quotas.reserve_connection(&occupant).unwrap();
    assert_eq!(rig.quotas.connections_per_principal_in_use(&occupant), 1);

    let (client, host_conn) = crate::tunnel::testutil::loopback_pair().await;
    let server = rig.server.clone();
    let host_side = tokio::spawn(async move { server.serve_connection(host_conn).await });

    let local_hello = rig.server.local_hello(None);
    let err = match crate::handshake::initiate(&client, local_hello).await {
        Ok(_) => panic!("a connection past the host cap must never get a Hello reply"),
        Err(err) => err,
    };
    match err {
        crate::handshake::HelloError::Remote {
            code,
            message,
            retryable,
        } => {
            assert_eq!(code, ErrorCode::ResourceExhausted);
            assert_eq!(message, "connection quota exceeded");
            assert!(retryable, "a quota refusal must be retryable");
        }
        other => panic!("expected a Remote RESOURCE_EXHAUSTED rejection, got {other:?}"),
    }

    host_side.await.unwrap();
    // The refused connection was never counted — only the
    // manually-seeded occupant still holds a slot.
    assert_eq!(rig.quotas.connections_per_principal_in_use(&occupant), 1);
    drop(client);
}

/// M8 Step 3b ruling R2: a pre-identity (`Principal::Pairing`)
/// connection past the fixed pairing cap is refused *without ever
/// naming the reason* — no control stream accepted, no proof read,
/// no error frame written, just an immediate close carrying
/// [`CLOSE_CODE_RESOURCE_EXHAUSTED`] — the same non-distinguishing
/// discipline `docs/design/protocol.md` §10-2/§15.5 already apply to
/// every other pairing refusal (a missing invite looks identical on
/// the wire).
#[tokio::test]
async fn a_pairing_connection_past_its_fixed_cap_is_refused_without_naming_the_reason() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits::default(),
    );
    let mut occupants = Vec::new();
    for _ in 0..crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS {
        occupants.push(rig.quotas.reserve_pairing_connection().unwrap());
    }

    let (client, host_conn) = crate::tunnel::testutil::pairing_loopback_pair().await;
    assert_eq!(*host_conn.principal(), Principal::Pairing);
    let server = rig.server.clone();
    let host_side = tokio::spawn(async move { server.serve_connection(host_conn).await });

    // No stream accepted, no proof read, no frame written (R2): the
    // client's own `open_bi` must never even be answered — the
    // connection is simply closed out from under it.
    let close_err = client.closed().await;
    match close_err {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                u64::from(close.error_code),
                u64::from(CLOSE_CODE_RESOURCE_EXHAUSTED)
            );
            assert_eq!(&close.reason[..], b"at capacity");
        }
        other => panic!("expected ApplicationClosed, got {other:?}"),
    }

    host_side.await.unwrap();
    // Every occupant slot is still held — the refusal created and
    // consumed no ninth permit.
    assert_eq!(
        rig.quotas.pairing_connections_in_use(),
        crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS
    );
    drop(occupants);
}

/// M8 Step 3b ruling B3 (adversary A1/B3): behavioral twin of the
/// former source-text tripwire — a connection served by the real
/// accept path must take exactly one slot on its own principal and
/// give it back once the connection is over. `purge_connection` now
/// takes the permit by value and drops it as its own last statement
/// (see that function's doc), so "released only after purge" is a
/// compile-time property of `serve_connection`'s two call sites, not
/// something a test has to watch for by re-reading source text; this
/// test instead pins the *externally observable* half of that
/// contract — the slot is really held while the connection is live
/// and really given back once it ends.
#[tokio::test]
async fn a_served_connection_holds_and_returns_its_connection_slot() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits::default(),
    );
    let (client, host_conn) = crate::tunnel::testutil::loopback_pair().await;
    let opener = opener_key(host_conn.principal(), host_conn.auth_path());
    let server = rig.server.clone();
    let host_side = tokio::spawn(async move { server.serve_connection(host_conn).await });
    let local_hello = rig.server.local_hello(None);
    let ctl = match crate::handshake::initiate(&client, local_hello).await {
        Ok(ctl) => ctl,
        Err(err) => panic!("the handshake must succeed under an empty quota: {err:?}"),
    };
    assert_eq!(
        rig.quotas.connections_per_principal_in_use(&opener),
        1,
        "a live served connection must hold exactly one connection slot"
    );
    drop(ctl);
    drop(client);
    host_side.await.unwrap();
    assert_eq!(
        rig.quotas.connections_per_principal_in_use(&opener),
        0,
        "the connection slot must be released once the connection is over"
    );
}

/// Pairing sibling of the above: the fixed pairing axis
/// ([`crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS`] == 8) behaves
/// the same way for a connection that actually clears the cap and gets
/// served, not just for one manually seeded and never served. Seven
/// occupants are hand-seeded (leaving exactly one slot), then the
/// eighth is driven through the real pairing protocol
/// (`crate::pairing::accept`/`respond`) so `serve_connection`'s
/// pairing arm — real `reserve_pairing_connection`, real
/// `serve_connection_inner`, real `purge_connection` — is what holds
/// and releases the slot, not the test.
#[tokio::test]
async fn a_served_pairing_connection_holds_and_returns_its_pairing_slot() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits::default(),
    );

    let mut occupants = Vec::new();
    for _ in 0..crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS - 1 {
        occupants.push(rig.quotas.reserve_pairing_connection().unwrap());
    }
    assert_eq!(
        rig.quotas.pairing_connections_in_use(),
        crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS - 1
    );

    // Wire up a real, minimal invite + trust store so the eighth
    // connection clears `serve_pairing_connection`'s "not configured"
    // guard and runs the actual wire exchange.
    let dir = tempfile::tempdir().unwrap();
    let invite_path = dir.path().join("invites.toml");
    let secret = crate::trust::pairing::generate_secret();
    {
        let _lock = crate::trust::pairing::InviteStore::lock(&invite_path).unwrap();
        let mut store = crate::trust::pairing::InviteStore::load(&invite_path).unwrap();
        store.add(secret.as_slice(), std::time::SystemTime::now());
        store.save(&invite_path).unwrap();
    }
    let invites = crate::trust::pairing::SharedInviteStore::open(&invite_path).unwrap();
    let trust = crate::trust::SharedTrustStore::open(dir.path().join("trust.toml")).unwrap();
    rig.server.set_pairing(trust, invites);

    let (client, host_conn) = crate::tunnel::testutil::pairing_loopback_pair().await;
    assert_eq!(*host_conn.principal(), Principal::Pairing);
    let server = rig.server.clone();
    let host_side = tokio::spawn(async move { server.serve_connection(host_conn).await });

    // The eighth slot is observable only *while* `serve_pairing_connection`
    // is still in flight: the server releases it the moment its own reply's
    // `stopped()` drain resolves in `pairing::respond`, independently of
    // whether the client's `accept()` (below) has finished reading that
    // reply on its own task/thread. A single read taken after `accept()`
    // returns races the server's teardown and reads seven under parallel
    // load (the flake this replaces). Watch the count concurrently with the
    // handshake instead, so the check lands inside the window where the slot
    // is genuinely held (bounded by the invite-store file I/O plus a QUIC
    // round trip), and fold the ninth-reservation-must-fail check into that
    // same instant rather than a second, separately racy read.
    let quotas_for_peak = rig.quotas.clone();
    let peak_watcher = tokio::spawn(async move {
        loop {
            if quotas_for_peak.pairing_connections_in_use()
                == crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS
            {
                break quotas_for_peak.reserve_pairing_connection();
            }
            tokio::task::yield_now().await;
        }
    });

    let accepted = crate::pairing::accept(&client, "adv-a1-b-client", secret.as_slice())
        .await
        .expect("the eighth pairing connection must clear the cap and pair successfully");
    assert_eq!(accepted.peer_device_name, rig.server.device_name);

    // `accept()` returning only means the client saw the reply, not that the
    // watcher has caught the peak yet. Bound the wait so a real regression
    // (the slot never reaching eight at all) fails fast instead of hanging.
    let ninth_reservation = tokio::time::timeout(Duration::from_secs(5), peak_watcher)
        .await
        .expect(
            "the eighth, served pairing connection must hold the last slot \
             at some point during its handshake",
        )
        .unwrap();
    assert!(
        matches!(
            ninth_reservation,
            Err(crate::quota::QuotaKind::PairingConnections)
        ),
        "a ninth reservation must fail while all eight are held"
    );

    drop(client);
    host_side.await.unwrap();
    assert_eq!(
        rig.quotas.pairing_connections_in_use(),
        crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS - 1,
        "the pairing slot must be released once the connection is over"
    );

    drop(occupants);
}

// ------------------------------------------------------------------
// remote forward (`-R`), M4 Step 4 — choke point + accept loop
// ------------------------------------------------------------------

fn rfwd_open(
    bind_host: &str,
    bind_port: u32,
    forward_host: &str,
    forward_port: u32,
) -> wire::RemoteForwardOpen {
    wire::RemoteForwardOpen {
        bind_host: bind_host.to_string(),
        bind_port,
        forward_host: forward_host.to_string(),
        forward_port,
        claim_token: Vec::new(),
    }
}

/// A [`RemoteForwardBinder`] that counts every call before doing
/// anything else, so "the host bound nothing" is an assertion and not
/// a hope — the remote-forward twin of `CountingDialer` above. With
/// `real: true` it makes a real loopback bind (so the allow path is
/// proved end-to-end); otherwise every bind fails, standing in for a
/// destination that must never be touched.
struct CountingBinder {
    calls: std::sync::atomic::AtomicUsize,
    /// Every address `bind` was asked for, in order — so a test can
    /// assert not just *how many* binds happened but *which address*
    /// each one was for. That distinction is the whole content of
    /// "the address bound is the address validated".
    attempted: std::sync::Mutex<Vec<SocketAddr>>,
    real: bool,
}

impl CountingBinder {
    fn refusing() -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            attempted: std::sync::Mutex::new(Vec::new()),
            real: false,
        }
    }

    fn real() -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            attempted: std::sync::Mutex::new(Vec::new()),
            real: true,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn attempted(&self) -> Vec<SocketAddr> {
        self.attempted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl RemoteForwardBinder for CountingBinder {
    fn bind<'a>(&'a self, addr: SocketAddr) -> crate::tunnel::remote::BindFuture<'a> {
        // Count first: a caller that bound before checking the ACL
        // (or the loopback gate) would be recorded here even if the
        // bind then failed — the same discriminating shape
        // `CountingDialer::dial`'s own doc explains.
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.attempted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(addr);
        let real = self.real;
        Box::pin(async move {
            if real {
                tokio::net::TcpListener::bind(addr).await
            } else {
                Err(std::io::Error::other("mock binder refuses everything"))
            }
        })
    }
}

/// The security core of M4 Step 4, the remote-forward twin of
/// `tcp_connect_denied_dials_nothing_and_reports_permission_denied`:
/// under a denying policy, `RemoteForwardOpen` must bind **zero**
/// listeners (`docs/PRD.md` §9, `docs/design/protocol.md` §13) and be
/// refused with `PERMISSION_DENIED`, with one audit line naming
/// `forward.remote`.
#[tokio::test]
async fn rfwd_open_denied_binds_nothing_and_reports_permission_denied() {
    let rig = rig(Arc::new(DenyAll));
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let binder = CountingBinder::refusing();

    let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 5432);
    let rejection = rig
        .server
        .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
        .await
        .expect_err("a denied forward.remote must not bind");

    assert_eq!(
        binder.calls(),
        0,
        "the host must not bind before (or after) a forward.remote deny"
    );
    assert_eq!(error_code(&rejection), Some(ErrorCode::PermissionDenied));

    let recs = rig.audit.records();
    assert_eq!(recs.len(), 1, "exactly one audit line per decision");
    assert_eq!(recs[0].action, "forward.remote");
    assert_eq!(recs[0].decision, "deny");
    assert_eq!(
        recs[0].resource, "127.0.0.1:0",
        "the audited resource is bind_host:bind_port, never the requester's own destination"
    );
}

/// **DoD 2's closing assertion.** A non-loopback `bind_host` is
/// refused even under an allow-everything policy: loopback-only is a
/// request constraint, not a principal permission
/// (`Server::authorize_and_bind_remote_forward`'s own doc,
/// `crate::acl::Action::ForwardRemote`'s). Every non-loopback case
/// binds **zero** listeners and reports `INVALID_ARGUMENT` over an
/// `allow` audit decision (the ACL gate itself passed; only the
/// separate loopback gate refused); every loopback case — including
/// the empty-string wire default and `localhost` — binds **exactly
/// once**, to a genuinely loopback address.
#[tokio::test]
async fn rfwd_open_loopback_table_binds_only_the_loopback_cases() {
    let non_loopback = ["0.0.0.0", "::", "203.0.113.9", "192.168.1.10"];
    // Not `127.0.0.53`: it *classifies* as loopback (the whole
    // `127.0.0.0/8` block does — `resolve_loopback_bind_addr`'s own
    // `loopback_bind_host_table` test already proves that in
    // isolation), but actually binding it depends on the runner
    // having that address assigned to an interface, which only Linux
    // does by default — macOS refuses it with `EADDRNOTAVAIL`. This
    // table only needs one genuinely-bindable loopback case per
    // platform to prove the choke point calls `bind` at all.
    let loopback = ["127.0.0.1", "::1", "localhost", ""];

    for bind_host in non_loopback {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let binder = CountingBinder::refusing();
        let req = rfwd_open(bind_host, 0, "127.0.0.1", 5432);

        let rejection = rig
            .server
            .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
            .await
            .expect_err("a non-loopback bind must be refused");

        assert_eq!(binder.calls(), 0, "{bind_host:?} must bind nothing");
        assert_eq!(
            error_code(&rejection),
            Some(ErrorCode::InvalidArgument),
            "{bind_host:?} must be INVALID_ARGUMENT, not PERMISSION_DENIED — \
             this principal DOES hold forward.remote"
        );
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1, "{bind_host:?}");
        assert_eq!(recs[0].action, "forward.remote", "{bind_host:?}");
        assert_eq!(
            recs[0].decision, "allow",
            "{bind_host:?}: the ACL decision itself was an allow — only \
             the non-ACL loopback gate refused this request"
        );
    }

    for bind_host in loopback {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let binder = CountingBinder::real();
        let req = rfwd_open(bind_host, 0, "127.0.0.1", 5432);

        let (listener, _quota) = rig
            .server
            .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
            .await
            .unwrap_or_else(|err| panic!("{bind_host:?} must bind: {err:?}"));

        assert_eq!(binder.calls(), 1, "{bind_host:?} must bind exactly once");
        assert!(
            listener.local_addr().unwrap().ip().is_loopback(),
            "{bind_host:?} must bind a loopback address"
        );
        let recs = rig.audit.records();
        assert_eq!(recs.len(), 1, "{bind_host:?}");
        assert_eq!(recs[0].action, "forward.remote", "{bind_host:?}");
        assert_eq!(recs[0].decision, "allow", "{bind_host:?}");
    }
}

/// **The check-then-use regression guard, at the choke point.** The
/// loopback gate and the bind must agree on one address, because
/// `bind_host` arrives verbatim in the peer's `RemoteForwardOpen`: a
/// peer that controls a DNS zone can answer loopback to one lookup and
/// a routable address to the next with nothing but a short TTL or
/// round-robin — no host compromise required — and an
/// authenticated-but-restricted peer escalating to a non-loopback bind
/// is precisely what DoD 2 exists to prevent.
///
/// So: a resolver whose first answer is loopback and whose second is
/// routable must produce **zero** non-loopback binds. It is resolved
/// exactly once, and the only address `bind` is ever asked for is the
/// one that answer certified.
///
/// Mutation-checked: reintroducing a second resolution between the
/// check and the bind makes this test fail (the bind is attempted on
/// `203.0.113.9`, which is both non-loopback and unbindable here).
#[tokio::test]
async fn rfwd_open_binds_the_address_it_validated_never_a_second_resolution() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let binder = CountingBinder::real();
    let resolver = crate::tunnel::testutil::ScriptedResolver::new(vec![
        vec![crate::tunnel::testutil::addr("127.0.0.1:0")],
        vec![crate::tunnel::testutil::addr("203.0.113.9:0")],
    ]);
    let req = rfwd_open("rebinder.example", 0, "127.0.0.1", 5432);

    let (listener, _quota) = rig
        .server
        .authorize_and_bind_remote_forward(&ctx, 1, &req, &resolver, &binder)
        .await
        .expect("the validated answer was loopback, so the bind must succeed");

    assert_eq!(
        resolver.calls(),
        1,
        "bind_host must be resolved exactly once per RemoteForwardOpen"
    );
    assert_eq!(
        binder.attempted(),
        vec![crate::tunnel::testutil::addr("127.0.0.1:0")],
        "the only address bound must be the one the loopback gate validated"
    );
    assert!(
        binder.attempted().iter().all(|a| a.ip().is_loopback()),
        "zero non-loopback binds"
    );
    assert!(listener.local_addr().unwrap().ip().is_loopback());
}

/// The other half of the same seam: a resolver whose (single) answer
/// set mixes loopback with a routable address is refused whole, and
/// binds nothing at all — "some resolved address is loopback" is not a
/// safety property (`crate::tunnel::remote::all_loopback`'s own doc).
#[tokio::test]
async fn rfwd_open_mixed_answer_set_binds_nothing() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let binder = CountingBinder::refusing();
    let resolver = crate::tunnel::testutil::ScriptedResolver::new(vec![vec![
        crate::tunnel::testutil::addr("127.0.0.1:0"),
        crate::tunnel::testutil::addr("203.0.113.9:0"),
    ]]);
    let req = rfwd_open("split.example", 0, "127.0.0.1", 5432);

    let rejection = rig
        .server
        .authorize_and_bind_remote_forward(&ctx, 1, &req, &resolver, &binder)
        .await
        .expect_err("a split-horizon answer must be refused");

    assert_eq!(binder.calls(), 0, "nothing may be bound");
    assert_eq!(error_code(&rejection), Some(ErrorCode::InvalidArgument));
}

/// A malformed request (empty/zero-port destination, out-of-range
/// ports) is refused on shape, before the ACL is consulted: nothing
/// to decide about, so no audit line is invented and nothing is bound
/// — the remote-forward twin of
/// `tcp_connect_malformed_destination_is_invalid_argument_and_dials_nothing`.
#[tokio::test]
async fn rfwd_open_malformed_request_is_invalid_argument_and_binds_nothing() {
    for req in [
        rfwd_open("127.0.0.1", 0, "", 80),
        rfwd_open("127.0.0.1", 0, "127.0.0.1", 0),
        rfwd_open("127.0.0.1", 0, "127.0.0.1", 70_000),
        rfwd_open("127.0.0.1", 70_000, "127.0.0.1", 80),
    ] {
        let rig = allow_rig();
        let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
        let binder = CountingBinder::refusing();

        let rejection = rig
            .server
            .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
            .await
            .expect_err("a malformed request is never bound");

        assert_eq!(binder.calls(), 0, "{req:?}");
        assert_eq!(error_code(&rejection), Some(ErrorCode::InvalidArgument));
        assert!(
            rig.audit.records().is_empty(),
            "no ACL decision was made, so no audit line: {req:?}"
        );
    }
}

/// The security core of M8 Step 3b's listener quota, the
/// remote-forward twin of `a_tunnel_dial_past_the_quota_never_reaches_
/// the_dialer`: a principal already at `max_remote_forwards_per_
/// principal` must be refused **before** `binder.bind` ever runs — a
/// spy binder observes zero calls, not one bind-then-unwind.
#[tokio::test]
async fn a_remote_forward_past_the_quota_is_refused_before_the_binder_runs() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_remote_forwards_per_principal: 0,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let binder = CountingBinder::real();
    let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 5432);

    let rejection = rig
        .server
        .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &binder)
        .await
        .expect_err("a principal already at its listener cap must not bind");

    assert_eq!(
        binder.calls(),
        0,
        "the quota gate sits before the bind, same as the ACL and loopback gates"
    );
    assert_eq!(error_code(&rejection), Some(ErrorCode::ResourceExhausted));

    // The ACL `allow` line for `forward.remote` is still audited — the
    // quota rejection is a *second*, distinct line under its own
    // category, not a replacement for the ACL decision.
    let recs = rig.audit.records();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(recs[0].action, "forward.remote");
    assert_eq!(recs[0].decision, "allow");
    assert_eq!(recs[1].resource, "quota_remote_forwards_principal");
    assert_eq!(recs[1].decision, "deny");
    // R9 (per `Quotas::record_rejection`'s own doc: "a control request
    // (session, exec, `RemoteForwardOpen`) has a real one to pass as
    // `Some`") — remote-forward is a control request, so this axis's
    // first row carries the real request_id, same as session/exec.
    // REBUTTAL B2 (see F3 handoff): the arbitration table's summary
    // grouped remote-forward with the tunnel/connection/pairing "-"
    // axes, but `authorize_and_bind_remote_forward` passes
    // `Some(request_id)`, not `None` — implemented against the actual
    // call site instead.
    assert_eq!(
        recs[1].request_id, "1",
        "R9 — the remote-forward axis has a real control request id (RemoteForwardOpen)"
    );
    assert_eq!(
        recs[1].peer_addr,
        ctx.peer_addr.to_string(),
        "R4 — the quota deny record must carry the live peer, not \"-\""
    );
}

/// Both places a live [`RemoteForwardEntry`] is ever removed —
/// [`Server::handle_rfwd_close`] and [`Server::purge_connection`] —
/// must release its [`crate::quota::RemoteForwardPermit`], not just
/// one of them. Proved indirectly, the same way the tunnel-stream twin
/// tests reopening past a cap: with `max_remote_forwards_per_
/// principal: 1`, a second open by the same principal only ever
/// succeeds again after whichever removal path just ran actually
/// dropped the permit.
#[tokio::test]
async fn the_listener_permit_is_released_by_both_removal_sites() {
    let rig = rig_with_quota_limits(
        Arc::new(AllowAllPinned),
        Arc::new(PipeFactory::new(64 * 1024)),
        Duration::from_millis(100),
        crate::quota::QuotaLimits {
            max_remote_forwards_per_principal: 1,
            ..crate::quota::QuotaLimits::default()
        },
    );
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);

    // --- purge_connection path ---
    let (client1, host1) = crate::tunnel::testutil::loopback_pair().await;
    let reply1 = rig.server.handle_rfwd_open(&ctx, &host1, 1, &req).await;
    let response::Body::RfwdOpened(_opened1) = response_body(&reply1) else {
        panic!("expected RfwdOpened, got {reply1:?}");
    };

    rig.server.purge_connection(ctx.conn_id, ()).await;

    let (client2, host2) = crate::tunnel::testutil::loopback_pair().await;
    let ctx2 = ConnCtx {
        conn_id: 99,
        ..ctx.clone()
    };
    let reply2 = rig.server.handle_rfwd_open(&ctx2, &host2, 2, &req).await;
    let response::Body::RfwdOpened(opened2) = response_body(&reply2) else {
        panic!("purge_connection did not release the listener permit: {reply2:?}");
    };
    let opened2 = opened2.clone();

    // At the cap again (opened2 is still live) — a third open must be
    // refused, so the test below actually proves a release rather than
    // an accident of the cap being loose.
    let reply3 = rig.server.handle_rfwd_open(&ctx2, &host2, 3, &req).await;
    assert_eq!(error_code(&reply3), Some(ErrorCode::ResourceExhausted));

    // --- handle_rfwd_close path ---
    let close = wire::RemoteForwardClose {
        forward_id: opened2.forward_id.clone(),
    };
    let closed = rig.server.handle_rfwd_close(&ctx2, 4, &close);
    assert_eq!(error_code(&closed), None, "{closed:?}");

    let reply4 = rig.server.handle_rfwd_open(&ctx2, &host2, 5, &req).await;
    let response::Body::RfwdOpened(_opened4) = response_body(&reply4) else {
        panic!("handle_rfwd_close did not release the listener permit: {reply4:?}");
    };

    drop(client1);
    drop(client2);
}

/// U11a (R10): when its `serve` future returns on its own — in
/// production, only a `Fatal` accept disposition ends `serve_remote_
/// forward`, `crate::tunnel::remote`'s own doc — the accept loop must
/// remove its own `forward_id` from [`Server::remote_forwards`] and
/// release the listener permit, freeing the id for `RemoteForwardOpen`
/// to reuse. Registers the entry exactly the way `handle_rfwd_open`'s
/// own production path does (same `authorize_and_bind_remote_forward`
/// choke point), then drives `run_remote_forward_accept_loop` (the
/// exact free fn `handle_rfwd_open`'s own spawn calls) with `async {}`
/// standing in for `serve_remote_forward` — an immediately-ready
/// future exercises the exact same self-removal tail a real `Fatal`
/// return does, without needing a real listener broken from outside
/// tokio's reactor to produce one (R10 rejects that: unsound double
/// `close`, Windows-hostile `AsRawFd`).
#[tokio::test]
async fn the_accept_loop_removes_its_own_forward_and_releases_the_permit_when_it_returns() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let opener = crate::acl::opener_key(&ctx.principal, ctx.auth_path);

    let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
    let (_listener, quota) = rig
        .server
        .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &SystemBinder)
        .await
        .expect("loopback bind must succeed");
    assert_eq!(
        rig.quotas.remote_forwards_per_principal_in_use(&opener),
        1,
        "the permit is reserved once the bind succeeds"
    );

    // Register it the way `handle_rfwd_open` would — a harmless
    // already-finished task stands in for the real spawn, since this
    // test drives the accept loop itself rather than through
    // `tokio::spawn`.
    let forward_id = "self-removal-test-forward".to_string();
    let task = tokio::spawn(async {});
    rig.server
        .remote_forwards
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            forward_id.clone(),
            RemoteForwardEntry {
                conn_id: ctx.conn_id,
                owner: opener.clone(),
                task,
                _quota: quota,
            },
        );

    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        run_remote_forward_accept_loop(Arc::downgrade(&rig.server), async {}, forward_id.clone()),
    )
    .await
    .expect("an immediately-ready serve future must not hang the accept loop");

    assert!(
        rig.server
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&forward_id)
            .is_none(),
        "the accept loop must remove its own forward_id once its serve future returns"
    );
    assert_eq!(
        rig.quotas.remote_forwards_per_principal_in_use(&opener),
        0,
        "the listener permit must release along with the registry entry"
    );
}

/// U11b (R10): the other half of the self-removal tail's safety —
/// when this forward is torn down by its closer (`handle_rfwd_close`/
/// `purge_connection`: remove the entry, then `abort()` the task) the
/// accept loop's own `.await` on `serve` is dropped mid-flight and its
/// removal tail below that `.await` never runs, so the forward is
/// removed exactly once — never by both the closer and the aborted
/// task. Drives the same production fn with `std::future::pending()`
/// standing in for a `serve_remote_forward` that would otherwise run
/// forever, then reproduces `handle_rfwd_close`'s own remove-then-abort
/// sequence on it directly.
#[tokio::test]
async fn an_aborted_accept_loop_is_removed_once_by_its_closer_and_never_again() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let opener = crate::acl::opener_key(&ctx.principal, ctx.auth_path);

    let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
    let (_listener, quota) = rig
        .server
        .authorize_and_bind_remote_forward(&ctx, 1, &req, &SystemResolver, &SystemBinder)
        .await
        .expect("loopback bind must succeed");
    assert_eq!(
        rig.quotas.remote_forwards_per_principal_in_use(&opener),
        1,
        "the permit is reserved once the bind succeeds"
    );

    let forward_id = "abort-test-forward".to_string();
    let task = tokio::spawn(run_remote_forward_accept_loop(
        Arc::downgrade(&rig.server),
        std::future::pending(),
        forward_id.clone(),
    ));
    rig.server
        .remote_forwards
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            forward_id.clone(),
            RemoteForwardEntry {
                conn_id: ctx.conn_id,
                owner: opener.clone(),
                task,
                _quota: quota,
            },
        );

    // Mirror `handle_rfwd_close`'s closer sequence exactly: remove the
    // entry from the registry first (this alone drops `_quota` and
    // releases the permit), then abort the task.
    let entry = rig
        .server
        .remote_forwards
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&forward_id)
        .expect("the entry must be present before its closer runs");
    let RemoteForwardEntry { task, _quota, .. } = entry;
    task.abort();
    // `handle_rfwd_close`'s own order: `entry.task.abort()` runs while
    // the entry (and its permit) is still alive, and the entry drops
    // — releasing the permit — immediately after, at the end of that
    // match arm. `drop(_quota)` here stands in for that implicit drop.
    drop(_quota);
    assert_eq!(
        rig.quotas.remote_forwards_per_principal_in_use(&opener),
        0,
        "the closer's remove-then-drop must release the permit right away, before the \
         aborted task is even polled again"
    );
    let join_result = tokio::time::timeout(std::time::Duration::from_secs(3), task)
        .await
        .expect("an aborted task must resolve promptly, not hang");
    assert!(
        join_result.is_err_and(|e| e.is_cancelled()),
        "an aborted accept loop's handle must report cancellation, not a panic"
    );

    // The loop's own `.await` on `pending()` was dropped mid-flight —
    // its self-removal tail never ran, so the permit was released
    // exactly once (by the closer above), never twice.
    assert_eq!(
        rig.quotas.remote_forwards_per_principal_in_use(&opener),
        0,
        "an aborted accept loop must not release its permit a second time"
    );
    assert!(
        rig.server
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&forward_id)
            .is_none(),
        "the closer's own removal must stand; the aborted loop must not re-insert or re-touch it"
    );
}

/// The full production path — the part
/// `authorize_and_bind_remote_forward`'s own unit tests above cannot
/// exercise, because it takes no `Connection` by construction
/// (`Server::handle_rfwd_open`'s own doc): a bound listener's accepted
/// connection becomes a `TCP_ACCEPTED` stream on the peer, carrying
/// the minted `forward_id` as its ticket, opened with no handshake
/// reply to wait for (`crate::tunnel::remote`'s module doc). Then
/// `RemoteForwardClose` tears the listener down, and closing it again
/// finds nothing.
#[tokio::test]
async fn rfwd_open_end_to_end_streams_tcp_accepted_then_close_tears_down() {
    let (client_conn, host_conn) = crate::tunnel::testutil::loopback_pair().await;
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

    // `forward_host`/`forward_port` are the *requester's* destination
    // (Step 4's client leg, out of this stage's scope) — the host
    // never dials them, so any shape-valid value is fine here.
    let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
    let reply = rig.server.handle_rfwd_open(&ctx, &host_conn, 7, &req).await;
    let response::Body::RfwdOpened(opened) = response_body(&reply) else {
        panic!("expected RfwdOpened, got {reply:?}");
    };
    assert!(!opened.forward_id.is_empty());
    assert_ne!(
        opened.actual_port, 0,
        "a port-0 request resolves to a real port"
    );

    let bound: SocketAddr = format!("127.0.0.1:{}", opened.actual_port).parse().unwrap();
    let _tcp = tokio::net::TcpStream::connect(bound).await.unwrap();

    let (send, recv) = client_conn.accept_bi().await.unwrap();
    let mut framed = FramedStream::data(send, recv);
    let header: StreamHeader = framed
        .recv
        .recv()
        .await
        .unwrap()
        .expect("TCP_ACCEPTED header");
    assert_eq!(header.stream_kind(), Some(StreamKind::TcpAccepted));
    assert_eq!(
        header.ticket,
        opened.forward_id.as_bytes(),
        "the ticket is the forward_id, verbatim"
    );

    let close = wire::RemoteForwardClose {
        forward_id: opened.forward_id.clone(),
    };
    let closed = rig.server.handle_rfwd_close(&ctx, 8, &close);
    assert!(
        matches!(
            &closed.body,
            Some(control_message::Body::Response(wire::Response {
                body: None
            }))
        ),
        "RemoteForwardClose succeeds with a bare Response, no dedicated payload: {closed:?}"
    );

    let again = rig.server.handle_rfwd_close(&ctx, 9, &close);
    assert_eq!(
        error_code(&again),
        Some(ErrorCode::InvalidArgument),
        "closing an already-closed forward_id finds nothing"
    );

    drop(host_conn);
    drop(client_conn);
}

/// A `forward_id` on `RemoteForwardClose` arrives **from the peer**,
/// so it is shape-checked (`qsh_proto::wire::valid_forward_id`) before
/// it is used to look anything up, tear anything down, or reach a log
/// line. A malformed one is `INVALID_ARGUMENT` and leaves the live
/// forward it was aimed at untouched — including the escape-sequence
/// and control-character shapes, which must never reach an operator's
/// terminal through the host's own logs.
#[tokio::test]
async fn rfwd_close_malformed_forward_id_is_invalid_argument_and_closes_nothing() {
    let (client_conn, host_conn) = crate::tunnel::testutil::loopback_pair().await;
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

    let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
    let reply = rig.server.handle_rfwd_open(&ctx, &host_conn, 7, &req).await;
    let response::Body::RfwdOpened(opened) = response_body(&reply) else {
        panic!("expected RfwdOpened, got {reply:?}");
    };

    for id in [
        "",
        "a\u{1b}[31mb",
        "fwd\nqsh: forged line",
        "fwd\u{0}-1",
        "fwd.1",
        &"x".repeat(65),
    ] {
        let close = wire::RemoteForwardClose {
            forward_id: id.to_string(),
        };
        let reply = rig.server.handle_rfwd_close(&ctx, 8, &close);
        assert_eq!(
            error_code(&reply),
            Some(ErrorCode::InvalidArgument),
            "{id:?} must be refused on shape"
        );
    }

    // Untouched: the real forward still closes cleanly afterwards.
    let close = wire::RemoteForwardClose {
        forward_id: opened.forward_id.clone(),
    };
    let closed = rig.server.handle_rfwd_close(&ctx, 9, &close);
    assert!(
        matches!(
            &closed.body,
            Some(control_message::Body::Response(wire::Response {
                body: None
            }))
        ),
        "the live forward must survive every malformed close: {closed:?}"
    );

    drop(host_conn);
    drop(client_conn);
}

/// The host-minted side of the same predicate: the `forward_id` this
/// host issues is a ULID, which satisfies
/// `qsh_proto::wire::valid_forward_id` by construction — so the peer's
/// own `RemoteForwardClose` and its `TCP_ACCEPTED` tickets can be held
/// to that shape without ever refusing an id this host itself minted.
#[test]
fn minted_forward_ids_satisfy_the_wire_shape() {
    for _ in 0..64 {
        let id = ulid::Ulid::new().to_string();
        assert!(
            wire::valid_forward_id(&id),
            "a minted forward_id must satisfy the wire shape: {id:?}"
        );
    }
}

/// `RemoteForwardOpen` genuinely cannot be answered by a bare
/// `dispatch` call — there is no `Connection` to open this forward's
/// future `TCP_ACCEPTED` streams on — so it draws `UNSUPPORTED`
/// there, documented at the match arm itself. The real path is
/// `Server::serve_control`'s early interception calling
/// `Server::handle_rfwd_open` directly, exercised above.
#[tokio::test]
async fn dispatch_rfwd_open_with_no_connection_is_unsupported() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 5432);
    let msg = ControlMessage::new(3, control_message::Body::RfwdOpen(req));

    let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();

    assert_eq!(error_code(&reply), Some(ErrorCode::Unsupported));
}

/// `RemoteForwardClose`, unlike `RemoteForwardOpen`, needs no
/// connection — it is an ACL choke point over a `Server::
/// remote_forwards` lookup plus an abort — so it is handled by
/// `dispatch` itself, end to end. An unknown `forward_id` has
/// `owner: None`, so under `AllowAllPinned` (this test's `allow_rig`)
/// the choke point admits it unconditionally and the refusal below is
/// step 4's ordinary "nothing to remove", not a `PermissionDenied`.
#[tokio::test]
async fn dispatch_rfwd_close_unknown_forward_is_invalid_argument() {
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);
    let msg = ControlMessage::new(
        4,
        control_message::Body::RfwdClose(wire::RemoteForwardClose {
            forward_id: "nope".to_string(),
        }),
    );

    let reply = rig.server.dispatch(&ctx, &msg).await.unwrap();

    assert_eq!(error_code(&reply), Some(ErrorCode::InvalidArgument));
}

/// The connection-bound lifetime half of `PLAN.md` M4 Step 4 (b): a
/// dead connection's remote forwards are aborted and forgotten by
/// `purge_connection`, the same way its tickets and writer leases are
/// — nothing keyed to a `conn_id` outlives that connection.
#[tokio::test]
async fn purge_connection_removes_and_aborts_this_connections_remote_forwards() {
    let (client_conn, host_conn) = crate::tunnel::testutil::loopback_pair().await;
    let rig = allow_rig();
    let ctx = ctx(Principal::Device("laptop".into()), ALL_CAPS);

    let req = rfwd_open("127.0.0.1", 0, "127.0.0.1", 9);
    let reply = rig.server.handle_rfwd_open(&ctx, &host_conn, 1, &req).await;
    let response::Body::RfwdOpened(opened) = response_body(&reply) else {
        panic!("expected RfwdOpened, got {reply:?}");
    };

    assert!(
        rig.server
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&opened.forward_id),
        "the forward must be registered before purge"
    );

    rig.server.purge_connection(ctx.conn_id, ()).await;

    assert!(
        !rig.server
            .remote_forwards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&opened.forward_id),
        "purge_connection must remove every remote forward this connection opened"
    );

    drop(host_conn);
    drop(client_conn);
}
