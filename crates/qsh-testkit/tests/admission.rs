//! Admission control integration tests (`PLAN.md` M8 Step 2,
//! `docs/adr/0009-admission-defenses.md`): `qsh_core::admission::Gate`
//! wired into a *real*, running `Server::run`/`Listen::run` accept loop
//! over real loopback QUIC — `qsh-core::admission`'s own unit tests pin
//! `Gate::decide`'s pure logic (permits, sketch, keying, aggregation)
//! without a network; these pin the same invariants end to end, against
//! the real accept loop, the real audit sink, and (for two of them) a
//! real already-open session.
//!
//! `crates/qsh-testkit/src/loopback.rs`'s `LoopbackHarness::
//! start_with_admission` and `crates/qsh-testkit/src/reverse.rs`'s
//! `ReverseHarness::start_with_admission` build the `Server`/`Listen` host
//! with a caller-chosen `(max_concurrent_handshakes,
//! handshake_rate_per_source)` instead of `ServeConfig`'s defaults, so
//! these tests reach the cap/rate limit without hundreds of real
//! connections. Both accept loops share the same `qsh_core::admission::
//! Gate` type and the same `Decision` mapping (`Listen::admit` mirrors
//! `Server::admit` exactly) — the `listen_*` tests below exist because
//! that mirroring was, until the M8 Step 2 verification round, entirely
//! unpinned: `Listen::admit`'s gate check could be deleted outright with
//! every other test in the workspace still green.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use qsh_core::audit::AuditRecord;
use qsh_core::broker::PipeHandle;
use qsh_core::client::Session;
use qsh_proto::wire;
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_testkit::reverse::ReverseHarness;
use qsh_transport::{DialError, Dialer, FramedStream, Principal, StaticTrust};
use tokio::net::UdpSocket;

/// A fresh [`Dialer`] for `h`'s client identity/trust, with a
/// caller-chosen timeout. `h.dialer` (the harness's own) always uses
/// `qsh_transport::endpoint::DEFAULT_DIAL_TIMEOUT` (10 s) — too slow for
/// a test that deliberately wants an `ignore()`d (silently dropped)
/// attempt to fail fast rather than eat a real 10 s wait.
fn dialer_with_timeout(h: &LoopbackHarness, timeout: Duration) -> Dialer {
    let trust = StaticTrust::empty().with_pin(
        h.server_identity.fingerprint,
        Principal::Device("box".into()),
    );
    Dialer::new(h.client.local.clone(), Arc::new(trust)).with_timeout(timeout)
}

/// `resource == "at_capacity"` audit records, in order.
fn at_capacity(records: &[AuditRecord]) -> Vec<&AuditRecord> {
    records
        .iter()
        .filter(|r| r.resource == "at_capacity")
        .collect()
}

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// Redeem a `session.open` ticket on a fresh bidi stream, mirroring
/// `attach_loopback.rs`'s `open_and_attach` (duplicated rather than
/// shared — the two test crates' helpers have no common home, and this
/// one is small).
async fn attach(session: &mut Session, ticket: Vec<u8>) -> FramedStream {
    let (send, recv) = session.connection().open_bi().await.expect("open_bi");
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&wire::StreamHeader::session_data(ticket))
        .await
        .expect("stream header");
    data
}

/// Write `payload` on the host-side pipe and assert it arrives on `data`
/// as a single `Output` frame carrying exactly `payload`.
async fn echo_round_trip(pipe: &mut PipeHandle, data: &mut FramedStream, payload: &[u8]) {
    pipe.write_output(payload).await.expect("write_output");
    let frame = tokio::time::timeout(
        Duration::from_secs(5),
        data.recv.recv::<wire::SessionFrame>(),
    )
    .await
    .expect("frame arrives within the deadline")
    .expect("frame")
    .expect("stream ended early");
    match frame.body {
        Some(wire::session_frame::Body::Output(o)) => assert_eq!(o.data, payload),
        other => panic!("expected an Output frame, got {other:?}"),
    }
}

/// Pins `PLAN.md` M8 Step 2's "reject before resource" invariant at the
/// handshake concurrency cap: once `max_concurrent_handshakes` permits
/// are exhausted, a losing attempt is refused — fast, distinguishable,
/// `DialError::Refused` (`qsh_transport::endpoint::DialError::Refused`'s
/// own doc), never a hang — and the host's audit trail stays bounded by
/// §5's "first + summary" aggregation instead of one line per rejection.
#[tokio::test(flavor = "multi_thread")]
async fn admission_cap_refuses_and_creates_nothing() {
    const CONCURRENT_DIALS: usize = 24;
    // Rate limiting is not this test's subject: a source rate high enough
    // that no attempt is ever mistaken for a flood, so every rejection
    // observed here is unambiguously `AtCapacity`, never `RateLimited`.
    let h = LoopbackHarness::start_with_admission(1, u32::MAX / 4).await;

    let mut tasks = Vec::with_capacity(CONCURRENT_DIALS);
    for _ in 0..CONCURRENT_DIALS {
        let dialer = dialer_with_timeout(&h, Duration::from_secs(5));
        let addr = h.addr;
        tasks.push(tokio::spawn(
            async move { dialer.dial(addr, "127.0.0.1").await },
        ));
    }
    let mut oks = 0usize;
    let mut refused = 0usize;
    for task in tasks {
        match task.await.expect("dial task") {
            Ok(_dialed) => oks += 1,
            Err(DialError::Refused) => refused += 1,
            Err(other) => panic!("expected Ok or Refused at cap=1, got {other:?}"),
        }
    }
    assert!(
        oks >= 1,
        "at least one of {CONCURRENT_DIALS} concurrent dials should be admitted at cap=1"
    );
    assert!(
        refused >= 1,
        "cap=1 with {CONCURRENT_DIALS} concurrent dials should refuse at least one — \
         this can only spuriously fail if the runtime happened to fully serialize \
         every dial, which {CONCURRENT_DIALS}-way concurrency makes vanishingly unlikely"
    );

    let records = h.audit.records();
    let rejected = at_capacity(&records);
    // §5's aggregation is a *lazy* flush: a window's summary is only
    // turned into a record the next time a rejection in the same
    // category arrives *after* the window has run past
    // `AUDIT_AGGREGATION_WINDOW` (10 s) — never on a background timer.
    // Every refusal in this test lands inside one such window (well
    // under 10 s of wall-clock time for `CONCURRENT_DIALS` loopback
    // dials), so the audit trail here is always exactly the window's
    // first-occurrence record, however many refusals actually happened —
    // the same bound `admission_rejection_audit_is_aggregated` pins with
    // a much larger, deterministic rejection count.
    assert_eq!(
        rejected.len(),
        1,
        "{refused} refusals inside one aggregation window must collapse to exactly \
         one audit record: {records:?}"
    );
    assert!(
        rejected[0].count.is_none(),
        "the sole record is the un-summarized first-in-window one"
    );
    for r in &rejected {
        assert_eq!(r.action, "connect");
        assert_eq!(r.decision, "deny");
        assert_eq!(
            r.principal, "-",
            "structural only — never a principal for a pre-auth reject"
        );
        assert_eq!(r.auth_path, "-");
        assert!(r.rule.is_none());
    }

    // No refused dial ever produced a `Connection` on the client side —
    // and, correspondingly, no session was ever opened on the host side.
    // `gate_releases_permit_on_handshake_completion` (core unit test)
    // separately pins that an *admitted* handshake's permit is released
    // before serving, so this cap could never deadlock the remaining
    // concurrent dials into starvation instead of a clean refusal.
    assert_eq!(
        h.broker.session_count(),
        0,
        "no dial in this test ever proceeded to session.open"
    );

    h.shutdown().await;
}

/// Pins that the per-source rate limit is not sticky: once the flood
/// that triggered it stops, a legitimate client recovers and PTY echo
/// works, exactly like any other loopback session — `crate::admission::
/// Gate`'s throttle is a sliding window, not a ban.
#[tokio::test(flavor = "multi_thread")]
async fn legitimate_client_connects_after_flood_subsides() {
    // burst_limit = rate * EPOCH.as_secs() = 1 * 2 = 2 (`crate::admission`'s
    // `EPOCH`, `PLAN.md` M8 Step 2 verification round F2) — a handful of
    // concurrent *fresh* dial attempts reliably exceeds it. Concurrency
    // cap is generous; it is not this test's subject.
    let h = LoopbackHarness::start_with_admission(64, 1).await;

    // The flood: each is its own fresh QUIC Initial (a fresh
    // `Dialer::dial` call — `qsh_transport::endpoint::Dialer::dial_inner`
    // builds a fresh `Endpoint` per dial), so each independently costs
    // one sketch record. A short timeout turns an `ignore()`d attempt
    // into a fast failure instead of the real 10 s dial timeout.
    const FLOOD_ATTEMPTS: usize = 8;
    let mut flood = Vec::with_capacity(FLOOD_ATTEMPTS);
    for _ in 0..FLOOD_ATTEMPTS {
        let dialer = dialer_with_timeout(&h, Duration::from_millis(700));
        let addr = h.addr;
        flood.push(tokio::spawn(
            async move { dialer.dial(addr, "127.0.0.1").await },
        ));
    }
    let mut timed_out = 0usize;
    for task in flood {
        if let Err(DialError::Timeout(_)) = task.await.expect("flood dial task") {
            timed_out += 1;
        }
    }
    assert!(
        timed_out >= 1,
        "expected the per-source rate limit to silently ignore at least one of \
         {FLOOD_ATTEMPTS} concurrent fresh dials at burst=2 — none timed out, so the \
         throttle never actually fired and the rest of this test proves nothing"
    );

    // Recovery: first a bounded wait, then a bounded retry-poll — not a
    // bare sleep-then-hope. The sliding window needs real wall-clock
    // epochs to elapse, since the harness wires `crate::admission::Gate`
    // to a real `SystemClock` (`LoopbackHarness::start_inner`), not a
    // steerable `TestClock`. `EPOCH` is 2 s (`crate::admission`'s own
    // const, `PLAN.md` M8 Step 2 verification round F2) — the blended
    // sliding-window estimate at the very start of a fresh epoch still
    // weights *all* of the previous epoch's count (weight = `1 -
    // fraction_into_epoch`, and `fraction_into_epoch = 0` right at the
    // boundary), so waiting only one epoch after the flood risks probing
    // right as that weight is still ~1. Waiting `2 * EPOCH` plus a margin
    // guarantees the flood's own epoch has fully rolled out of both the
    // current *and* blended-previous window before the first probe fires.
    // Each *probe* thereafter is itself a fresh unvalidated Initial and so
    // itself costs one sketch record — spaced more than one full `EPOCH`
    // apart, a probe never perpetuates the flood it is trying to outlast;
    // probed every few hundred ms instead, this loop would never converge
    // (self-inflicted flood), which is exactly what an earlier,
    // tighter-interval version of this test measured.
    // `crate::admission::EPOCH` (2 s) is a private const, not exported —
    // mirrored here as a literal rather than referenced.
    const EPOCH: Duration = Duration::from_secs(2);
    tokio::time::sleep(2 * EPOCH + Duration::from_secs(1)).await;
    const MAX_ATTEMPTS: u32 = 6;
    let mut dialed = None;
    for attempt in 0..MAX_ATTEMPTS {
        let dialer = dialer_with_timeout(&h, Duration::from_millis(700));
        match dialer.dial(h.addr, "127.0.0.1").await {
            Ok(d) => {
                dialed = Some(d);
                break;
            }
            Err(err) if attempt + 1 < MAX_ATTEMPTS => {
                tokio::time::sleep(EPOCH + Duration::from_secs(1)).await;
                let _ = err;
            }
            Err(err) => panic!(
                "client never recovered after the flood subsided ({MAX_ATTEMPTS} attempts): {err:?}"
            ),
        }
    }
    let dialed = dialed.expect("recovered within MAX_ATTEMPTS");

    let mut session = Session::negotiate(dialed.connection, "laptop")
        .await
        .expect("negotiate after recovery");
    let opened = session
        .session_open(open_req())
        .await
        .expect("session.open after recovery");
    let mut pipe = h.pipes.take().expect("pipe handle");
    let mut data = attach(&mut session, opened.ticket).await;

    echo_round_trip(&mut pipe, &mut data, b"admission-recovery-echo").await;

    session.close();
    h.shutdown().await;
}

/// Pins §5's audit-flood-break bound: a flood of rejections landing
/// inside one 10 s aggregation window produces a single audit record —
/// not one per rejection. This only exercises the *first*-rejection half
/// of "first + summary" (the summary is a lazy flush that only fires the
/// next time a rejection in the same category arrives after the window
/// has closed, `crate::admission::Gate::record_rejection`'s own doc —
/// forcing that open here would mean a real >10 s wait); the stronger
/// bound observed here — REJECTIONS rejections, one record — is the
/// sharper version of the same claim.
#[tokio::test(flavor = "multi_thread")]
async fn admission_rejection_audit_is_aggregated() {
    const REJECTIONS: usize = 50;
    // cap = 0: every address-validated attempt is refused,
    // deterministically — no concurrency race needed to reach "at
    // capacity". This is a raw `Gate::new` value, not a documented
    // config one (`ServeConfig::max_concurrent_handshakes`'s `0 ⇒
    // default` degradation is pinned separately, in
    // `qsh-core::config::tests::
    // admission_keys_use_the_documented_names_and_defaults`).
    let h = LoopbackHarness::start_with_admission(0, u32::MAX / 4).await;

    for _ in 0..REJECTIONS {
        let dialer = dialer_with_timeout(&h, Duration::from_secs(3));
        match dialer.dial(h.addr, "127.0.0.1").await {
            Err(DialError::Refused) => {}
            other => panic!("expected Refused at cap=0, got {other:?}"),
        }
    }

    let records = h.audit.records();
    let rejected = at_capacity(&records);
    assert_eq!(
        rejected.len(),
        1,
        "{REJECTIONS} rejections inside one aggregation window must collapse to exactly \
         one audit record: {records:?}"
    );
    assert!(
        rejected[0].count.is_none(),
        "the sole record is the un-summarized first-in-window one"
    );
    assert!(
        rejected[0].peer_addr.parse::<SocketAddr>().is_ok(),
        "the first record keeps the real observed peer_addr: {:?}",
        rejected[0]
    );
    for r in &records {
        // Structural only — never a payload, never anything beyond the
        // category (`CLAUDE.md`: audit records are structural, not
        // content).
        assert_eq!(r.action, "connect");
        assert_eq!(r.principal, "-");
        assert_eq!(r.auth_path, "-");
        assert!(r.rule.is_none());
    }

    h.shutdown().await;
}

/// A host-stability test, **not `admission::Gate` coverage**
/// (`PLAN.md` M8 Step 2 verification round, P3-7 — renamed from
/// `spoofed_initial_flood_creates_no_state`, which read as a `Gate`
/// invariant it does not exercise). Pins that a flood of Initial-shaped
/// UDP garbage never costs a session, a task, or the stability of an
/// already-open legitimate session sharing the same host — but none of
/// this flood ever produces a valid QUIC handshake (no real Initial keys
/// back it), so it never even reaches `crate::admission::Gate`; what
/// actually absorbs it is quinn's own pre-application AEAD-tag drop
/// (`PLAN.md` M8 Step 2 design §0: a datagram whose header parses as an
/// Initial but whose AEAD tag does not validate is dropped before any
/// `Incoming` is ever produced, so `Gate::decide` is never called at
/// all). Confirmed empirically during the verification round: this test
/// passed unchanged under both a mutation that fully neutered `Retry`
/// (M1) and one that let an unvalidated peer acquire a handshake permit
/// (M4) — proof it cannot detect a broken `Gate`. What it *does* prove is
/// that this absorption doesn't cost the rest of the host anything, which
/// is a real and separate invariant worth keeping in this file.
///
/// **Honest limitation** (design §8's own note, carried forward here):
/// on loopback the source *port* varies across these sockets but the
/// source *IP* cannot — every one of them is `127.0.0.1`. So this
/// exercises the single-source accept path, never the per-source
/// /32-/64 keying; that invariant is pinned instead by
/// `gate_keys_ipv6_by_64_prefix` and
/// `gate_table_is_constant_size_under_forged_cardinality`
/// (`crates/qsh-core/src/admission.rs`'s own unit tests).
#[tokio::test(flavor = "multi_thread")]
async fn host_survives_garbage_initial_flood() {
    let h = LoopbackHarness::start().await;

    let mut session = h.session().await;
    let opened = session
        .session_open(open_req())
        .await
        .expect("session.open");
    let mut pipe = h.pipes.take().expect("pipe handle");
    let mut data = attach(&mut session, opened.ticket).await;

    echo_round_trip(&mut pipe, &mut data, b"before-flood").await;

    // The flood: many ephemeral-port sources, each firing several
    // >=1200-byte (>= quinn's own `MIN_INITIAL_SIZE`) datagrams shaped
    // like a QUIC long-header Initial's first byte, at the host's real
    // bound address. None of it is a real QUIC handshake.
    const SOCKETS: usize = 24;
    const PACKETS_PER_SOCKET: usize = 12;
    let mut senders = Vec::with_capacity(SOCKETS);
    for i in 0..SOCKETS {
        let host_addr = h.host_addr;
        senders.push(tokio::spawn(async move {
            let sock = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind flood socket");
            let mut datagram = vec![0xAAu8; 1200];
            datagram[0] = 0xC3; // long header, fixed bit set, Initial packet type
            for j in 0..PACKETS_PER_SOCKET {
                datagram[1] = i as u8;
                datagram[2] = j as u8;
                let _ = sock.send_to(&datagram, host_addr).await;
            }
        }));
    }

    // Interleaved with the flood, not just before/after it.
    for _ in 0..5 {
        echo_round_trip(&mut pipe, &mut data, b"during-flood").await;
    }

    for s in senders {
        s.await.expect("flood sender task");
    }

    echo_round_trip(&mut pipe, &mut data, b"after-flood").await;

    assert_eq!(
        h.broker.session_count(),
        1,
        "the flood must never open a session of its own — only the one this test opened"
    );

    session.close();
    h.shutdown().await;
}

/// `AUDIT_AGGREGATION_WINDOW` mirrored as a literal — `crate::admission`'s
/// own const is `pub(crate)`, not visible from this external test crate.
const AUDIT_AGGREGATION_WINDOW: Duration = Duration::from_secs(10);

/// How long the on-exit-flush tests (`admission_on_exit_flush_reports_
/// suppressed_rejections_at_shutdown`, its `Listen`-arm twin) wait after
/// harness start before dialing at all, so the rejection window they open
/// starts with a wide margin from the accept loop's own periodic-tick
/// schedule instead of a millisecond-scale race against it — see those
/// tests' own doc for why that race is otherwise decided by ordinary
/// scheduling jitter, not by which flush path is actually under test.
const WINDOW_OPEN_DELAY_FROM_LOOP_START: Duration = Duration::from_secs(4);

/// Poll `records_fn` for up to `AUDIT_AGGREGATION_WINDOW + 10s` slack for a
/// `resource`-category record carrying a `count` (the summary half of §5's
/// "first + summary" aggregation) — used by both
/// `admission_rejection_summary_flushes_without_further_dials` (Server
/// arm) and `listen_admission_rejection_summary_flushes_without_further_dials`
/// (Listen arm) so the two integration tests share one polling shape.
async fn poll_for_summary(
    records_fn: impl Fn() -> Vec<AuditRecord>,
    resource: &str,
) -> AuditRecord {
    let poll_timeout = AUDIT_AGGREGATION_WINDOW + Duration::from_secs(10);
    let poll_interval = Duration::from_millis(500);
    let deadline = tokio::time::Instant::now() + poll_timeout;
    loop {
        let records = records_fn();
        if let Some(r) = records
            .iter()
            .find(|r| r.resource == resource && r.count.is_some())
        {
            return r.clone();
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "no {resource} summary record appeared within {poll_timeout:?} of the flood \
                 stopping (audit trail so far: {records:?})"
            );
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// `PLAN.md` M8 Step 2 verification round, P1-3/F1: pins the *bounded*
/// half of the audit aggregation contract on the `Server` arm — a flood
/// that stops still produces its aggregation window's summary record
/// within one more accept-loop tick, with **no further dial** to trigger
/// the lazy-flush path (`crate::admission::Gate::record_rejection`'s own
/// doc, which only flushes lazily on the *next* rejection). Before
/// `Gate::flush_expired` and the accept loop's `tokio::time::interval`
/// tick existed, this scenario — the one an operator watching a flood
/// subside actually cares about — could never happen: the summary would
/// simply never arrive.
///
/// Wall-clock cost: up to `AUDIT_AGGREGATION_WINDOW` (10 s) plus the
/// polling slack above, dominated by waiting for the real `SystemClock`-
/// driven aggregation window to actually close — there is no faster path
/// available here (`LoopbackHarness::start_with_admission` wires a real
/// clock, not a `TestClock`, matching every other wall-clock-bound test
/// in this file).
#[tokio::test(flavor = "multi_thread")]
async fn admission_rejection_summary_flushes_without_further_dials() {
    const REJECTIONS: usize = 5;
    let h = LoopbackHarness::start_with_admission(0, u32::MAX / 4).await;

    for _ in 0..REJECTIONS {
        let dialer = dialer_with_timeout(&h, Duration::from_secs(3));
        match dialer.dial(h.addr, "127.0.0.1").await {
            Err(DialError::Refused) => {}
            other => panic!("expected Refused at cap=0, got {other:?}"),
        }
    }

    // No further dial from here on — the summary must appear from the
    // accept loop's own periodic flush alone.
    let summary = poll_for_summary(|| h.audit.records(), "at_capacity").await;
    assert_eq!(
        summary.count,
        Some((REJECTIONS - 1) as u32),
        "the first rejection was reported immediately (not suppressed); the summary covers \
         only the remaining {} suppressed ones",
        REJECTIONS - 1
    );
    assert_eq!(
        summary.peer_addr, "-",
        "the summary row never carries an observed address"
    );

    h.shutdown().await;
}

/// `PLAN.md` M8 Step 2 verification round, P1-1 + P1-3/F1: the `Listen`
/// arm's own coverage of `Listen::admit`'s admission cap — before this,
/// the whole `Listen::run` accept loop had zero admission integration
/// coverage (a mutation deleting the gate check outright passed
/// 1151/1151). `k` deterministic `AtCapacity` refusals against a real,
/// running `Listen::run` accept loop, no session/registration/task ever
/// created, and the summary record for the suppressed refusals appears
/// via `Listen::run`'s own periodic flush tick — the `Listen`-arm
/// counterpart to `admission_rejection_summary_flushes_without_further_dials`.
#[tokio::test(flavor = "multi_thread")]
async fn listen_admission_cap_refuses_creates_nothing_and_summary_flushes() {
    const REJECTIONS: usize = 5;
    let h = ReverseHarness::start_with_admission(0, u32::MAX / 4).await;
    let target = make_identity();

    for _ in 0..REJECTIONS {
        match h.dial(&target).await {
            Err(DialError::Refused) => {}
            other => panic!("expected Refused at cap=0, got {other:?}"),
        }
    }

    assert_eq!(
        h.listen.live_connections(),
        0,
        "no dial at cap=0 must ever produce a live Listen connection"
    );
    assert_eq!(
        h.listen.registry().snapshot().len(),
        0,
        "no dial at cap=0 must ever reach the registry — the QUIC handshake itself was refused"
    );

    let records = h.audit.records();
    let first: Vec<_> = records
        .iter()
        .filter(|r| r.resource == "at_capacity" && r.count.is_none())
        .collect();
    assert_eq!(
        first.len(),
        1,
        "{REJECTIONS} refusals inside one aggregation window must collapse to exactly one \
         un-summarized first-in-window record: {records:?}"
    );
    assert!(
        first[0].peer_addr.parse::<SocketAddr>().is_ok(),
        "the first record keeps the real observed peer_addr: {:?}",
        first[0]
    );
    for r in &records {
        assert_eq!(r.action, "connect");
        assert_eq!(r.decision, "deny");
        assert_eq!(r.principal, "-");
        assert_eq!(r.auth_path, "-");
        assert!(r.rule.is_none());
    }

    // No further dial from here on.
    let summary = poll_for_summary(|| h.audit.records(), "at_capacity").await;
    assert_eq!(summary.count, Some((REJECTIONS - 1) as u32));
    assert_eq!(summary.peer_addr, "-");
}

/// Mutation-testing round 4, X3: pins that a handshake permit is released
/// the instant the handshake itself resolves
/// (`crate::admission::Decision::Admit`'s own doc;
/// `Server::accept_and_serve_permitted`'s `drop(permit)` sits right after
/// `incoming.accept()` resolves, strictly before `serve_connection` ever
/// runs — never held across it). At `max_concurrent_handshakes = 1`:
/// connection A dials, negotiates, and opens a session, then is kept
/// alive — never dropped, never closed — for the rest of this test. A
/// second connection B, dialed and negotiated only *after* A is fully up
/// and still live, must still succeed. Under the mutation "move
/// `drop(permit)` to after `serve_connection(conn).await` returns", A's
/// permit would still be held for as long as A's connection is being
/// served — i.e. indefinitely here, since A is deliberately never
/// dropped — so B's validated attempt would find the cap already
/// exhausted and be refused instead.
#[tokio::test(flavor = "multi_thread")]
async fn admission_permit_is_released_at_handshake_end_not_connection_end() {
    let h = LoopbackHarness::start_with_admission(1, u32::MAX / 4).await;

    // Connection A: dial, negotiate, open a session — then hold it open
    // for the rest of the test.
    let dialed_a = h.dial().await;
    let mut session_a = Session::negotiate(dialed_a.connection, "laptop")
        .await
        .expect("negotiate A");
    let _opened_a = session_a
        .session_open(open_req())
        .await
        .expect("session.open A");

    // Connection B: dialed while A is still fully alive and being served.
    // Under correct code A's permit was released the moment its handshake
    // finished (well before this point), so B's own handshake has a free
    // slot despite A never having disconnected.
    let dialer_b = dialer_with_timeout(&h, Duration::from_secs(5));
    let dialed_b = dialer_b.dial(h.addr, "127.0.0.1").await.expect(
        "B must be admitted while A is still alive — a permit held until connection end \
         (the mutation) would refuse this dial",
    );
    let mut session_b = Session::negotiate(dialed_b.connection, "laptop")
        .await
        .expect("negotiate B");
    session_b
        .session_open(open_req())
        .await
        .expect("session.open B — proves B's handshake actually completed, not just dialed");

    // `ReverseHarness::start_with_admission` hardcodes an empty controller
    // trust store (no target identity can be pinned through its current
    // signature), so no target can pass mTLS peer verification on that
    // arm — a live/negotiated Listen-arm connection isn't reachable
    // without threading a trust store through a new harness parameter.
    // Skipped rather than forced through a signature change on a shared
    // harness function other suites also call.

    session_a.close();
    session_b.close();
    h.shutdown().await;
}

/// Mutation-testing round 4, N6: pins the on-exit flush in `Server::run`
/// — "one more flush on the way out" after the accept loop's `select!`
/// breaks (`Server::run`'s own comment) — in isolation from both the lazy
/// flush inside `record_rejection` and the periodic `audit_flush.tick()`
/// branch.
///
/// **Timing, empirically pinned down** (an earlier version of this test
/// dialed immediately after harness start and got it wrong — see below):
/// `tokio::time::interval` fires its *first* tick immediately on
/// creation, then every `AUDIT_AGGREGATION_WINDOW` (10s) after that — so
/// the accept loop's `audit_flush` ticks land at loop-start `t0`, `t0+10`,
/// `t0+20`, ... `Gate::flush_expired` only closes a window that is
/// already at least 10s old, so a tick landing before that bound is a
/// no-op.
///
/// A window that opens *immediately* after loop start (`t0+ε` for tiny
/// `ε`) becomes stale at `t0+ε+10` — a razor's-edge few milliseconds
/// after the second tick's own nominal `t0+10` firing. In practice that
/// race is decided by ordinary task-scheduling jitter, not by `ε`'s sign:
/// measured directly (temporary `eprintln!` timestamps against this
/// exact scenario), the second tick actually fired ~3ms *after* the
/// window's staleness point and closed it — the on-exit flush never got
/// a chance to prove anything, and a version of this test built that way
/// passed unchanged even with the on-exit flush lines deleted.
///
/// This version instead delays the first dial by
/// `WINDOW_OPEN_DELAY_FROM_LOOP_START` (4s) after harness start, so the
/// window opens at `t0+4` with a wide, non-marginal margin either side:
/// the second tick (`t0+10`) sees the window at only 6s old (4s short of
/// stale, not milliseconds) and skips it; the window itself goes stale at
/// `t0+14`; this test's own shutdown lands at `t0+~15.5` — 1.5s after
/// staleness, 4.5s clear of the third tick at `t0+20`. Only the on-exit
/// flush has had a chance to observe the stale window by the time
/// `h.shutdown()` returns.
#[tokio::test(flavor = "multi_thread")]
async fn admission_on_exit_flush_reports_suppressed_rejections_at_shutdown() {
    const REJECTIONS: usize = 3;
    let h = LoopbackHarness::start_with_admission(0, u32::MAX / 4).await;

    // See this fn's doc: a wide, non-marginal gap from loop start before
    // the window even opens, so the second periodic tick (~t0+10) is
    // nowhere near this window's own staleness point (~t0+14).
    tokio::time::sleep(WINDOW_OPEN_DELAY_FROM_LOOP_START).await;

    for _ in 0..REJECTIONS {
        let dialer = dialer_with_timeout(&h, Duration::from_secs(3));
        match dialer.dial(h.addr, "127.0.0.1").await {
            Err(DialError::Refused) => {}
            other => panic!("expected Refused at cap=0, got {other:?}"),
        }
    }

    // Past AUDIT_AGGREGATION_WINDOW (10s) so the window is stale, but
    // nowhere near the accept loop's third periodic tick (~t0+20, per
    // this fn's doc) — see the doc above for why only the on-exit flush
    // can be responsible for what this test asserts.
    tokio::time::sleep(AUDIT_AGGREGATION_WINDOW + Duration::from_millis(1500)).await;

    let audit = h.audit.clone();
    h.shutdown().await;

    let records = audit.records();
    let summary = records
        .iter()
        .find(|r| r.resource == "at_capacity" && r.count.is_some())
        .unwrap_or_else(|| {
            panic!("expected an at_capacity summary record from the on-exit flush, got {records:?}")
        });
    assert_eq!(
        summary.count,
        Some((REJECTIONS - 1) as u32),
        "the first rejection was reported immediately; the on-exit summary covers only \
         the remaining {} suppressed ones",
        REJECTIONS - 1
    );
    assert_eq!(summary.peer_addr, "-");
}

/// `Listen`-arm twin of
/// `admission_on_exit_flush_reports_suppressed_rejections_at_shutdown` —
/// cheap here (unlike X3's twin above): this scenario never needs a live,
/// mTLS-verified connection, only address-validated rejections at cap=0,
/// which `crate::admission::Gate::decide` resolves before any peer
/// certificate is ever checked. `Listen::run`'s on-exit flush is a
/// separate two-line block from `Server::run`'s (mirrored, not shared
/// code), so a mutation deleting only the `Listen::run` copy needs its
/// own pin. Same real-time-wait rationale as the Server-arm version's own
/// doc — including the same `WINDOW_OPEN_DELAY_FROM_LOOP_START` delay
/// before the first dial, for the same reason (empirically, dialing
/// immediately after harness start puts the window's staleness point
/// within milliseconds of the periodic tick's own nominal firing, which
/// is decided by scheduling jitter rather than proving anything about the
/// on-exit flush specifically).
#[tokio::test(flavor = "multi_thread")]
async fn listen_admission_on_exit_flush_reports_suppressed_rejections_at_shutdown() {
    const REJECTIONS: usize = 3;
    let h = ReverseHarness::start_with_admission(0, u32::MAX / 4).await;
    let target = make_identity();

    tokio::time::sleep(WINDOW_OPEN_DELAY_FROM_LOOP_START).await;

    for _ in 0..REJECTIONS {
        match h.dial(&target).await {
            Err(DialError::Refused) => {}
            other => panic!("expected Refused at cap=0, got {other:?}"),
        }
    }

    tokio::time::sleep(AUDIT_AGGREGATION_WINDOW + Duration::from_millis(1500)).await;

    let audit = h.audit.clone();
    h.shutdown().await;

    let records = audit.records();
    let summary = records
        .iter()
        .find(|r| r.resource == "at_capacity" && r.count.is_some())
        .unwrap_or_else(|| {
            panic!("expected an at_capacity summary record from the on-exit flush, got {records:?}")
        });
    assert_eq!(
        summary.count,
        Some((REJECTIONS - 1) as u32),
        "the first rejection was reported immediately; the on-exit summary covers only \
         the remaining {} suppressed ones",
        REJECTIONS - 1
    );
    assert_eq!(summary.peer_addr, "-");
}
