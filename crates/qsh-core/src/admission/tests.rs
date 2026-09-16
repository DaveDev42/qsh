use super::*;
use crate::broker::TestClock;
use std::net::Ipv4Addr;

fn addr(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip, port)
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// `Decision` has no `Debug` impl (`Decision::Admit` holds an
/// `OwnedSemaphorePermit`, which doesn't implement it either) — this
/// is the panic-message-only stand-in the newer tests below use
/// instead of `{other:?}`.
fn decision_kind(d: &Decision) -> &'static str {
    match d {
        Decision::Retry => "Retry",
        Decision::Ignore(..) => "Ignore",
        Decision::Refuse(..) => "Refuse",
        Decision::Admit(_) => "Admit",
    }
}

/// `PLAN.md` M8 Step 2 design §8 — the concurrency cap: the first
/// `max_concurrent_handshakes` validated attempts are all `Admit`ted,
/// and the next one is `Refuse`d with an `AtCapacity` audit record
/// while every earlier permit is still held.
#[tokio::test]
async fn gate_admits_then_refuses_at_cap() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 2, 10, 10);
    let peer = addr(v4(203, 0, 113, 1), 1);

    let permit1 = match gate.decide(peer, true, gate.now()) {
        Decision::Admit(p) => p,
        _ => panic!("expected Admit"),
    };
    let permit2 = match gate.decide(peer, true, gate.now()) {
        Decision::Admit(p) => p,
        _ => panic!("expected Admit"),
    };
    match gate.decide(peer, true, gate.now()) {
        Decision::Refuse(RejectReason::AtCapacity, records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].resource, "at_capacity");
            assert_eq!(records[0].peer_addr, peer.to_string());
            assert!(
                records[0].count.is_none(),
                "first rejection carries no count"
            );
        }
        _ => panic!("expected Refuse(AtCapacity)"),
    }
    drop((permit1, permit2));
}

/// M8 Step 5a: every one of [`Decision`]'s four branches increments
/// its own [`AdmissionCounters`] field, and only that field.
#[tokio::test]
async fn gate_counters_tally_every_decision_branch() {
    let clock = Arc::new(TestClock::new());
    // Cap 1 so the second validated attempt is `Refuse(AtCapacity)`
    // without needing to first exhaust a rate-limit budget.
    let gate = Gate::new(clock.clone(), 1, 1000, 1000);
    assert_eq!(gate.counters(), AdmissionCounters::default());

    // Retry: unvalidated, under its rate limit.
    match gate.decide(addr(v4(203, 0, 113, 1), 1), false, gate.now()) {
        Decision::Retry => {}
        other => panic!("expected Retry, got {}", decision_kind(&other)),
    }
    assert_eq!(
        gate.counters(),
        AdmissionCounters {
            retry: 1,
            ..Default::default()
        }
    );

    // Admit: validated, under the cap.
    let permit = match gate.decide(addr(v4(203, 0, 113, 2), 1), true, gate.now()) {
        Decision::Admit(p) => p,
        other => panic!("expected Admit, got {}", decision_kind(&other)),
    };
    assert_eq!(
        gate.counters(),
        AdmissionCounters {
            retry: 1,
            admit: 1,
            ..Default::default()
        }
    );

    // Refuse: validated, but the cap (now 1/1) is already held.
    match gate.decide(addr(v4(203, 0, 113, 3), 1), true, gate.now()) {
        Decision::Refuse(RejectReason::AtCapacity, _) => {}
        other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
    }
    assert_eq!(
        gate.counters(),
        AdmissionCounters {
            retry: 1,
            admit: 1,
            refuse: 1,
            ..Default::default()
        }
    );
    drop(permit);

    // Ignore: same unvalidated source hammered past its rate limit.
    let flood_peer = addr(v4(203, 0, 113, 9), 1);
    let mut saw_ignore = false;
    for _ in 0..10_000 {
        if let Decision::Ignore(RejectReason::RateLimited, _) =
            gate.decide(flood_peer, false, gate.now())
        {
            saw_ignore = true;
            break;
        }
    }
    assert!(saw_ignore, "expected the flood to eventually be Ignore'd");
    let counters = gate.counters();
    assert_eq!(counters.ignore, 1, "exactly one Ignore so far");
    assert_eq!(counters.admit, 1);
    assert_eq!(counters.refuse, 1);
}

/// `PLAN.md` M8 Step 2 design §8 — dropping the permit returned by
/// `Admit` (standing in for the handshake resolving, `Decision::Admit`'s
/// own doc) frees the slot for a later attempt.
#[tokio::test]
async fn gate_releases_permit_on_handshake_completion() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 1, 10, 10);
    let peer = addr(v4(203, 0, 113, 2), 1);

    let permit = match gate.decide(peer, true, gate.now()) {
        Decision::Admit(p) => p,
        _ => panic!("expected Admit"),
    };
    assert_eq!(gate.available_permits(), 0);
    match gate.decide(peer, true, gate.now()) {
        Decision::Refuse(..) => {}
        _ => panic!("expected Refuse while the permit is held"),
    }
    drop(permit); // the handshake "resolved"
    assert_eq!(gate.available_permits(), 1);
    match gate.decide(peer, true, gate.now()) {
        Decision::Admit(_) => {}
        _ => panic!("expected Admit once the permit was released"),
    }
}

/// `PLAN.md` M8 Step 2 design §8 — an unvalidated source under the
/// rate limit is always `Retry`d (never audited); once it exceeds
/// `rate_per_source * 2` (burst) within one epoch it is `Ignore`d
/// with a `RateLimited` record, and advancing the clock past the next
/// epoch boundary lets it through again.
#[tokio::test]
async fn gate_throttles_per_source_and_recovers_next_window() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 5, 10); // burst = 10
    let peer = addr(v4(198, 51, 100, 7), 4242);

    let mut retried = 0;
    let mut ignored = 0;
    for _ in 0..10 {
        match gate.decide(peer, false, gate.now()) {
            Decision::Retry => retried += 1,
            Decision::Ignore(RejectReason::RateLimited, _) => ignored += 1,
            _ => panic!("unvalidated attempt must be Retry or Ignore"),
        }
    }
    assert_eq!(retried, 10, "all 10 attempts are within burst=10");
    assert_eq!(ignored, 0);

    match gate.decide(peer, false, gate.now()) {
        Decision::Ignore(RejectReason::RateLimited, records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].resource, "rate_limited");
        }
        _ => panic!("the 11th attempt in one epoch must be throttled"),
    }

    // Cross two full epoch boundaries so both generations are clear
    // of this source's history (the sliding-window blend still
    // weights the immediately-prior epoch otherwise).
    clock.advance(EPOCH * 2);
    match gate.decide(peer, false, gate.now()) {
        Decision::Retry => {}
        _ => panic!("expected recovery after the window passed"),
    }
}

/// `PLAN.md` M8 Step 2 design §8 — two IPv6 addresses sharing a /64
/// share a rate-limit bucket; a different /64 does not.
#[tokio::test]
async fn gate_keys_ipv6_by_64_prefix() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 2, 10); // burst = 4

    let same_prefix_a = addr(IpAddr::V6("2001:db8:1234:5678::1".parse().unwrap()), 1);
    let same_prefix_b = addr(
        IpAddr::V6("2001:db8:1234:5678:ffff:ffff:ffff:ffff".parse().unwrap()),
        2,
    );
    let different_prefix = addr(IpAddr::V6("2001:db8:1234:9999::1".parse().unwrap()), 3);

    // Exhaust the shared /64's burst using both addresses.
    for _ in 0..4 {
        assert!(matches!(
            gate.decide(same_prefix_a, false, gate.now()),
            Decision::Retry
        ));
    }
    // The *second* address in the same /64 is already over budget —
    // proof the two share one bucket, not two.
    assert!(matches!(
        gate.decide(same_prefix_b, false, gate.now()),
        Decision::Ignore(RejectReason::RateLimited, _)
    ));
    // A genuinely different /64 has its own, untouched budget.
    assert!(matches!(
        gate.decide(different_prefix, false, gate.now()),
        Decision::Retry
    ));
}

/// `PLAN.md` M8 Step 2 design §8 — the sketch's backing storage
/// cannot grow no matter how many distinct (forged) source addresses
/// pass through `decide`. Proxy: pointer identity of the sketch's
/// backing `Vec`s (see `Gate::sketch_storage_pointers`'s doc for why
/// that is a valid, measurable stand-in for "no allocation growth")
/// stays bit-for-bit identical before and after 10⁵ distinct
/// synthetic sources — the forged cardinality this test drives.
#[tokio::test]
async fn gate_table_is_constant_size_under_forged_cardinality() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 10, 10);
    let before = gate.sketch_storage_pointers();

    const FORGED_SOURCES: u32 = 100_000;
    for i in 0..FORGED_SOURCES {
        let ip = v4((i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8);
        let peer = addr(ip, 1);
        // Ignore the outcome — the point is that `decide` never
        // panics and never needs to allocate to accommodate a source
        // it has never seen before.
        let _ = gate.decide(peer, false, gate.now());
    }

    let after = gate.sketch_storage_pointers();
    assert_eq!(
        before, after,
        "the sketch's backing storage must never reallocate, regardless of source cardinality"
    );
}

/// `PLAN.md` M8 Step 2 design §8 — false-positive rate under a flood
/// of forged sources. **Forged cardinality tested at: 5,000** distinct
/// spoofed sources, each firing once within the same epoch (expected
/// load ≈ 5000/1024 ≈ 4.9 events per column per row) — chosen as a
/// flood dense enough to load the sketch meaningfully while the
/// legitimate traffic below stays well under `burst_limit`; asserts
/// under 1% of 1,000 independent legitimate low-rate sources are
/// incorrectly throttled by hash collisions with the forged flood.
#[tokio::test]
async fn gate_false_positive_rate_under_flood() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 10, 10); // burst = 20
    let now = gate.now();

    const FORGED_SOURCES: u32 = 5_000;
    for i in 0..FORGED_SOURCES {
        // Offset well clear of the legitimate range below.
        let ip = v4(10, (i >> 16) as u8, (i >> 8) as u8, i as u8);
        let _ = gate.decide(addr(ip, 1), false, now);
    }

    const LEGITIMATE_SOURCES: u32 = 1_000;
    const LEGITIMATE_REQUESTS_PER_SOURCE: u32 = 5; // well under burst=20
    let mut throttled = 0u32;
    for i in 0..LEGITIMATE_SOURCES {
        // 203.0.0.0/8 range, distinct from the 10.0.0.0/8 forged range
        // above — plenty of distinct /32s for 1,000 legitimate
        // sources.
        let ip = v4(203, (i >> 16) as u8, (i >> 8) as u8, i as u8);
        let peer = addr(ip, 1);
        let mut this_source_throttled = false;
        for _ in 0..LEGITIMATE_REQUESTS_PER_SOURCE {
            if matches!(
                gate.decide(peer, false, now),
                Decision::Ignore(RejectReason::RateLimited, _)
            ) {
                this_source_throttled = true;
            }
        }
        if this_source_throttled {
            throttled += 1;
        }
    }

    let fp_rate = throttled as f64 / LEGITIMATE_SOURCES as f64;
    assert!(
        fp_rate < 0.01,
        "false-positive rate {fp_rate:.4} ({throttled}/{LEGITIMATE_SOURCES}) must stay \
         under 1% at {FORGED_SOURCES} forged sources"
    );
}

/// `M8 Step 4`: the time axis `gate_table_is_constant_size_under_forged_cardinality`
/// doesn't cover — a sustained unvalidated (spoofable) flood that keeps firing across
/// many [`EPOCH`] generation rollovers must still never grow the sketch's backing
/// storage and must never touch the handshake permit pool, no matter how many
/// generations have rotated through the sliding-window blend
/// ([`Gate::rate_exceeded`]'s epoch/fraction math).
#[tokio::test]
async fn gate_state_and_permits_survive_generation_rollovers_under_sustained_forged_flood() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 8, 10, 10);
    let before_pointers = gate.sketch_storage_pointers();
    let before_permits = gate.available_permits();

    const GENERATIONS: u32 = 50;
    const SOURCES_PER_GENERATION: u32 = 200;
    for generation in 0..GENERATIONS {
        for i in 0..SOURCES_PER_GENERATION {
            // A fresh forged /32 every attempt, reused across
            // generations by (generation, i) so the flood is both
            // wide (cardinality) and sustained (keeps firing across
            // rollovers) rather than a one-shot burst.
            let ip = v4(10, (generation % 256) as u8, (i >> 8) as u8, i as u8);
            let peer = addr(ip, 1);
            // Unvalidated: outcome doesn't matter here — the
            // invariant is what it never does (grow storage, touch
            // the permit pool), which
            // `unvalidated_peer_never_touches_the_permit_pool_even_at_cap_zero`
            // already pins per-call; this test pins it across time.
            let _ = gate.decide(peer, false, gate.now());
        }
        clock.advance(EPOCH);
    }

    let after_pointers = gate.sketch_storage_pointers();
    assert_eq!(
        before_pointers, after_pointers,
        "the sketch's backing storage must never reallocate across EPOCH generation \
         rollovers, regardless of sustained forged-source cardinality"
    );
    assert_eq!(
        gate.available_permits(),
        before_permits,
        "a sustained unvalidated flood must never consume a handshake permit, across any \
         number of EPOCH generation rollovers"
    );

    // M8 Step 4 adversarial review, P2-2: the two asserts above are both time-invariant
    // regardless of whether `Sketch::advance_to` ever actually rolls a generation
    // over — storage never reallocates and an unvalidated decide never touches the
    // permit pool either way (P2-2's mutation experiment: gutting `advance_to` to a
    // no-op `return;` still passes both).
    // What's missing is a load-bearing check *of the rollover itself*
    // — that generations are really rotating, not just that nothing
    // visibly breaks if they don't. Two more, on the still-forged
    // `gate`/`clock` above:
    //
    // (a) a single legitimate source amid the flood is never a false
    // positive — sketch saturation from 50 generations × 200 forged
    // sources/generation must not spill onto an honest source's own
    // estimate.
    let honest = addr(v4(192, 168, 0, 7), 1);
    assert!(
        matches!(gate.decide(honest, false, gate.now()), Decision::Retry),
        "a legitimate source amid a sustained forged flood spanning many EPOCH rollovers \
         must not be falsely throttled"
    );

    // (b) a single *sustained* source, pushed past `burst_limit` (=
    // `rate_per_source * EPOCH.as_secs()` = 10 * 2 = 20, this gate's
    // own `rate_exceeded` doc) within one generation, is throttled —
    // and two EPOCH rollovers later the same source is admitted
    // again, which only happens if `advance_to` actually resets its
    // counters rather than merely leaving old ones in place forever.
    let noisy = addr(v4(203, 0, 113, 9), 1);
    for i in 1..=20 {
        match gate.decide(noisy, false, gate.now()) {
            Decision::Retry => {}
            other => panic!(
                "burst attempt {i}/20 within one epoch must be Retry, got {}",
                decision_kind(&other)
            ),
        }
    }
    assert!(
        matches!(
            gate.decide(noisy, false, gate.now()),
            Decision::Ignore(RejectReason::RateLimited, _)
        ),
        "the 21st attempt within one epoch must be throttled once burst_limit=20 is exceeded"
    );
    clock.advance(EPOCH);
    clock.advance(EPOCH);
    assert!(
        matches!(gate.decide(noisy, false, gate.now()), Decision::Retry),
        "two EPOCH rollovers after being throttled, the same source must be admitted again \
         — proof the rollover actually resets its counters, not just that nothing crashes \
         if it doesn't"
    );
}

/// `PLAN.md` M8 Step 2 verification round, P1-2: pins the L2-before-L3
/// ordering `Gate::decide`'s own doc claims — an *unvalidated* peer is
/// never charged against the handshake-concurrency semaphore, even
/// with the cap already exhausted (`max_concurrent_handshakes = 0`
/// here, the extreme case). Under mutation M4 (acquire the permit
/// before the validated check), this becomes `Refuse`, not `Retry`,
/// and reflects a `CONNECTION_REFUSED` at a spoofable address instead
/// of silently retrying it — the adversarial report's own finding.
#[tokio::test]
async fn unvalidated_peer_never_touches_the_permit_pool_even_at_cap_zero() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 0, 10, 10);
    let peer = addr(v4(198, 51, 100, 20), 1);

    let before = gate.available_permits();
    assert_eq!(before, 0, "cap=0 starts with zero permits, not unlimited");

    match gate.decide(peer, false, gate.now()) {
        Decision::Retry => {}
        other => panic!(
            "an unvalidated peer at cap=0 must still be Retry (never Refuse) — the \
             rate limit, not the semaphore, is what an unvalidated attempt can ever \
             fail against; got {}",
            decision_kind(&other)
        ),
    }
    assert_eq!(
        gate.available_permits(),
        before,
        "an unvalidated Retry must never touch the permit pool"
    );

    // A validated peer at the same cap=0 is the contrasting case:
    // Refuse, from the semaphore, not the rate limiter.
    match gate.decide(peer, true, gate.now()) {
        Decision::Refuse(RejectReason::AtCapacity, _) => {}
        other => panic!(
            "a validated peer at cap=0 must be Refuse(AtCapacity), got {}",
            decision_kind(&other)
        ),
    }
    assert_eq!(gate.available_permits(), 0);
}

/// `PLAN.md` M8 Step 2 verification round, P1-3/F1: pins
/// [`Gate::flush_expired`] without any real wall-clock wait —
/// `Gate` is clock-injected precisely so this doesn't need one.
/// Reject `n` times (all suppressed after the first), advance the
/// clock past [`AUDIT_AGGREGATION_WINDOW`], flush: exactly one
/// summary record with `count == Some(n - 1)` and `peer_addr == "-"`.
/// A second flush with nothing new to report yields nothing — the
/// window was already closed by the first flush, not left open to
/// double-report.
#[tokio::test]
async fn gate_flush_expired_emits_exactly_one_summary_after_the_window_closes() {
    let clock = Arc::new(TestClock::new());
    // cap=0: every attempt is a deterministic AtCapacity rejection —
    // no rate-limit interaction to account for.
    let gate = Gate::new(clock.clone(), 0, 10, 10);
    let peer = addr(v4(198, 51, 100, 21), 1);

    const REJECTIONS: usize = 7;
    for _ in 0..REJECTIONS {
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::AtCapacity, _) => {}
            other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
        }
    }

    // Nothing to flush yet — the window is still open.
    assert!(
        gate.flush_expired(gate.now()).is_empty(),
        "flush_expired must not fire before the window has run past \
         AUDIT_AGGREGATION_WINDOW"
    );

    clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));
    let flushed = gate.flush_expired(gate.now());
    assert_eq!(
        flushed.len(),
        1,
        "expected exactly one summary record, got {flushed:?}"
    );
    assert_eq!(flushed[0].resource, "at_capacity");
    assert_eq!(
        flushed[0].count,
        Some((REJECTIONS - 1) as u32),
        "the first rejection was reported immediately (not suppressed); the summary \
         covers only the remaining {} suppressed ones",
        REJECTIONS - 1
    );
    assert_eq!(
        flushed[0].peer_addr, "-",
        "the summary row never carries an observed address"
    );

    // The window is now closed — a second flush at the same instant
    // (or later, with no new rejection in between) reports nothing.
    assert!(
        gate.flush_expired(gate.now()).is_empty(),
        "a closed window with nothing new since must not re-emit a summary"
    );
}

/// `PLAN.md` M8 Step 2 verification round, F2/item 4: pins the
/// corrected rate semantics with a `TestClock` and wide margins —
/// `rate_per_source = 10` ⇒ `burst_limit = 10 * EPOCH.as_secs() = 20`.
///
/// - Sustained 5/s (well under the 10/s budget) for 6 s: never
///   throttled.
/// - A burst of 20 fired back-to-back within one epoch (a fresh
///   source, so the blended-previous-epoch term is 0): every one of
///   the 20 is `Retry`; the 21st is `Ignore`.
/// - Sustained 15/s (over the 10/s budget): throttled before the
///   first epoch (2 s) even completes.
#[tokio::test]
async fn gate_rate_limit_bounds_sustained_rate_not_just_instantaneous_burst() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 10, 10); // burst_limit = 20
    let five_per_sec = addr(v4(198, 51, 100, 22), 1);
    let burst_peer = addr(v4(198, 51, 100, 23), 1);
    let fifteen_per_sec = addr(v4(198, 51, 100, 24), 1);

    // Sustained 5/s (200 ms apart) for 6 s = 30 attempts, all Retry.
    for tick in 0..30 {
        match gate.decide(five_per_sec, false, gate.now()) {
            Decision::Retry => {}
            other => panic!(
                "sustained 5/s (well under the 10/s budget) must never be throttled — \
                 tick {tick} got {}",
                decision_kind(&other)
            ),
        }
        clock.advance(Duration::from_millis(200));
    }

    // 20 back-to-back attempts from a fresh source, same instant: all
    // Retry (estimate climbs 1..=20, burst_limit is 20, `>` not `>=`).
    for i in 1..=20 {
        match gate.decide(burst_peer, false, gate.now()) {
            Decision::Retry => {}
            other => panic!(
                "burst attempt {i}/20 within one epoch must be Retry, got {}",
                decision_kind(&other)
            ),
        }
    }
    match gate.decide(burst_peer, false, gate.now()) {
        Decision::Ignore(RejectReason::RateLimited, _) => {}
        other => panic!(
            "the 21st attempt within one epoch must be Ignore, got {}",
            decision_kind(&other)
        ),
    }

    // Sustained 15/s (≈66.7 ms apart): must be ignored before the
    // first 2 s epoch completes.
    let mut ignored_before_2s = false;
    let mut elapsed = Duration::ZERO;
    while elapsed < Duration::from_secs(2) {
        if matches!(
            gate.decide(fifteen_per_sec, false, gate.now()),
            Decision::Ignore(RejectReason::RateLimited, _)
        ) {
            ignored_before_2s = true;
            break;
        }
        clock.advance(Duration::from_millis(67));
        elapsed += Duration::from_millis(67);
    }
    assert!(
        ignored_before_2s,
        "sustained 15/s (over the 10/s budget) must be throttled before t = 2s"
    );
}

/// Mutation-testing round 4, N10 + X2: pins that both flush paths —
/// `record_rejection`'s lazy flush *and* `flush_expired`'s scheduled
/// flush — reset `guard.suppressed = 0` when they close a window, not
/// just report its count. A mutant that drops either reset leaks the
/// closed window's count into the *next* window's tally, so that
/// window's own (correctly small) suppressed count gets over-reported
/// later. This also pins X2 — `record_rejection`'s own lazy-flush
/// summary push (distinct from `flush_expired`'s) — since the first
/// assertion block only passes if that push still runs.
///
/// Sequence: window 1 gets 3 rejections (1 first row + 2 suppressed);
/// advancing past the window and rejecting again closes window 1
/// lazily, returning exactly `[summary(count=Some(2)), first_row]`.
/// Window 2 then gets 2 more rejections (both suppressed, no records).
/// Advancing past the window and calling `flush_expired` must report
/// `count == Some(2)` — a leaked counter from window 1 would report
/// `4`. Finally, a fresh window's first rejection carries no summary
/// at all — nothing was suppressed in it yet.
#[tokio::test]
async fn gate_record_rejection_and_flush_expired_both_reset_suppressed_not_just_report_it() {
    let clock = Arc::new(TestClock::new());
    // cap=0: every validated attempt is a deterministic AtCapacity
    // rejection.
    let gate = Gate::new(clock.clone(), 0, 10, 10);
    let peer = addr(v4(198, 51, 100, 30), 1);

    // Window 1: 3 rejections — 1 first-occurrence row + 2 suppressed.
    for _ in 0..3 {
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::AtCapacity, _) => {}
            other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
        }
    }

    clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));

    // This rejection opens window 2 and, in the same call, lazily
    // closes window 1 (`record_rejection`'s doc) — exactly
    // [summary(count=Some(2)), first_row_of_window_2].
    match gate.decide(peer, true, gate.now()) {
        Decision::Refuse(RejectReason::AtCapacity, records) => {
            assert_eq!(
                records.len(),
                2,
                "expected [summary, first_row] closing window 1, got {records:?}"
            );
            assert_eq!(records[0].resource, "at_capacity");
            assert_eq!(
                records[0].count,
                Some(2),
                "window 1 suppressed exactly 2 of its 3 rejections"
            );
            assert_eq!(
                records[0].peer_addr, "-",
                "the summary row never carries an observed address"
            );
            assert!(
                records[1].count.is_none(),
                "window 2's own first row carries no count"
            );
            assert_eq!(records[1].peer_addr, peer.to_string());
        }
        other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
    }

    // Window 2: 2 more rejections, both suppressed — no records
    // returned for either (same-window suppression never reports
    // synchronously).
    for _ in 0..2 {
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::AtCapacity, records) => {
                assert!(
                    records.is_empty(),
                    "a suppressed rejection inside an open window must carry no \
                     records, got {records:?}"
                );
            }
            other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
        }
    }

    clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));

    // `flush_expired` closes window 2. If either flush path failed to
    // reset `suppressed`, this would report 4 (2 leaked from window 1
    // plus window 2's own 2), not window 2's real count of 2.
    let flushed = gate.flush_expired(gate.now());
    assert_eq!(
        flushed.len(),
        1,
        "expected exactly one summary closing window 2, got {flushed:?}"
    );
    assert_eq!(flushed[0].resource, "at_capacity");
    assert_eq!(
        flushed[0].count,
        Some(2),
        "window 2 suppressed exactly 2 — a leaked counter from window 1 would \
         report 4 instead"
    );
    assert_eq!(
        flushed[0].peer_addr, "-",
        "the summary row never carries an observed address"
    );

    // A fresh window (3) opens on the next rejection with nothing
    // carried over from window 2, which `flush_expired` already
    // closed above — its first row must come alone, no summary.
    clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));
    match gate.decide(peer, true, gate.now()) {
        Decision::Refuse(RejectReason::AtCapacity, records) => {
            assert_eq!(
                records.len(),
                1,
                "a fresh window's first rejection must carry only its own first-row \
                 record, no leftover summary from window 2: {records:?}"
            );
            assert!(
                records[0].count.is_none(),
                "the fresh window's first row carries no count"
            );
            assert_eq!(records[0].peer_addr, peer.to_string());
        }
        other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
    }
}

/// `PLAN.md` M8 Step 3 P2-3 (design §4.3, U15) — the validated-axis
/// rate limiter sits *ahead* of the handshake semaphore, exactly the
/// `AtCapacity` axis's own ordering: an attempt that loses only to
/// its own rate budget must never dent `available_permits()`.
#[tokio::test]
async fn validated_rate_limit_rejects_without_taking_a_permit() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 10, 5); // validated burst = 10
    let peer = addr(v4(203, 0, 113, 40), 1);

    let mut held_permits = Vec::new();
    for i in 1..=10 {
        match gate.decide(peer, true, gate.now()) {
            Decision::Admit(p) => held_permits.push(p),
            other => panic!(
                "attempt {i}/10 within the validated burst must be Admit, got {}",
                decision_kind(&other)
            ),
        }
    }
    let permits_before = gate.available_permits();

    match gate.decide(peer, true, gate.now()) {
        Decision::Refuse(RejectReason::ValidatedRateLimited, records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].resource, "validated_rate_limited");
            assert_eq!(records[0].peer_addr, peer.to_string());
            assert!(
                records[0].count.is_none(),
                "first rejection carries no count"
            );
        }
        other => panic!(
            "the 11th validated attempt within one epoch must be \
             Refuse(ValidatedRateLimited), got {}",
            decision_kind(&other)
        ),
    }
    assert_eq!(
        gate.available_permits(),
        permits_before,
        "a validated-rate rejection must never touch the handshake permit pool"
    );
    drop(held_permits);
}

/// `validated_rate_limit_rejects_without_taking_a_permit` only compares
/// `available_permits()` *before* and *after* the call, which cannot
/// tell "never acquired" apart from "acquired, then released on the
/// way out" — this one watches the pool *during* a validated-rate
/// flood: with `validated_rate_per_source = 0` every validated attempt
/// is a rate-axis rejection, so the single handshake permit must read
/// `1` at every instant a concurrent reader samples it. Capped at a
/// fixed iteration count (well under the adversarial source's
/// 2,000,000) so it runs in well under a second.
#[test]
fn validated_rate_rejection_never_dips_the_permit_pool_even_transiently() {
    const SAMPLES: usize = 200_000;

    let clock = Arc::new(TestClock::new());
    let gate = Arc::new(Gate::new(clock.clone(), 1, 10, 0));
    let peer = addr(v4(198, 51, 100, 77), 1);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let flood_gate = Arc::clone(&gate);
    let flood_stop = Arc::clone(&stop);
    let flooder = std::thread::spawn(move || {
        while !flood_stop.load(Ordering::Relaxed) {
            let now = flood_gate.now();
            match flood_gate.decide(peer, true, now) {
                Decision::Refuse(RejectReason::ValidatedRateLimited, _) => {}
                other => panic!(
                    "every validated attempt at rate 0 must be \
                     ValidatedRateLimited, got {}",
                    decision_kind(&other)
                ),
            }
        }
    });

    let mut dips = 0usize;
    for _ in 0..SAMPLES {
        if gate.available_permits() != 1 {
            dips += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    flooder.join().unwrap();
    assert_eq!(
        dips, 0,
        "a validated-rate rejection must never take a handshake permit, \
         not even transiently"
    );
}

/// `PLAN.md` M8 Step 3 P2-3 (design §4.3, U16), both directions: the
/// two axes are tracked in genuinely independent `Sketch`es, so a
/// flood on one axis from a given address never spends the other
/// axis's budget for that same address.
#[tokio::test]
async fn unvalidated_flood_does_not_consume_a_validated_sources_budget() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 5, 5); // both bursts = 10
    let peer = addr(v4(203, 0, 113, 41), 1);

    // Flood the unvalidated axis well past its own burst from this
    // address — the validated axis must not notice.
    for _ in 0..15 {
        let _ = gate.decide(peer, false, gate.now());
    }
    match gate.decide(peer, true, gate.now()) {
        Decision::Admit(_) => {}
        other => panic!(
            "a validated attempt from an address that only flooded the unvalidated \
             axis must still be Admit, got {}",
            decision_kind(&other)
        ),
    }

    // And the reverse: flood a fresh address's validated axis past
    // its own burst — the unvalidated axis for that same address
    // must still see a clean slate.
    let other_peer = addr(v4(203, 0, 113, 43), 1);
    for _ in 0..15 {
        let _ = gate.decide(other_peer, true, gate.now());
    }
    match gate.decide(other_peer, false, gate.now()) {
        Decision::Retry => {}
        other => panic!(
            "an unvalidated attempt from an address that only flooded the validated \
             axis must still be Retry, got {}",
            decision_kind(&other)
        ),
    }
}

/// `PLAN.md` M8 Step 3 P2-3 (design §4.3, U17) — the validated-axis
/// sketch's twin of `gate_table_is_constant_size_under_forged_cardinality`:
/// its backing storage must never reallocate regardless of how many
/// distinct validated addresses an attacker forges.
#[tokio::test]
async fn validated_rate_state_is_constant_size_under_forged_cardinality() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 10, 10);
    let before = gate.validated_sketch_storage_pointers();

    const FORGED_SOURCES: u32 = 100_000;
    for i in 0..FORGED_SOURCES {
        let ip = v4((i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8);
        let peer = addr(ip, 1);
        let _ = gate.decide(peer, true, gate.now());
    }

    let after = gate.validated_sketch_storage_pointers();
    assert_eq!(
        before, after,
        "the validated-axis sketch's backing storage must never reallocate, \
         regardless of source cardinality"
    );
}

/// `PLAN.md` M8 Step 3 P2-3 (design §4.3, U18) — pins the documented
/// default (`[serve].validated_rate_per_source = 10`, `docs/CLI.md`
/// §6.12): a sustained validated source at exactly the burst ceiling
/// (20 within one epoch, same `rate × EPOCH.as_secs()` formula as the
/// unvalidated axis) always passes, and the 21st trips
/// `ValidatedRateLimited`.
#[tokio::test]
async fn validated_rate_threshold_matches_the_documented_sustained_rate() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(
        clock.clone(),
        64,
        10,
        crate::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
    );
    let peer = addr(v4(203, 0, 113, 42), 1);
    let mut held_permits = Vec::new();

    for i in 1..=20 {
        match gate.decide(peer, true, gate.now()) {
            Decision::Admit(p) => held_permits.push(p),
            other => panic!(
                "attempt {i}/20 at the documented default validated rate must be \
                 Admit, got {}",
                decision_kind(&other)
            ),
        }
    }
    match gate.decide(peer, true, gate.now()) {
        Decision::Refuse(RejectReason::ValidatedRateLimited, _) => {}
        other => panic!(
            "the 21st validated attempt at the documented default (10/s, burst 20) \
             must be ValidatedRateLimited, got {}",
            decision_kind(&other)
        ),
    }
    drop(held_permits);
}

/// `PLAN.md` M8 Step 3, verdict ruling 10's U18 twin (F3 of the M8
/// Step 3a conformance sweep — `validated_rate_threshold_matches_
/// the_documented_sustained_rate` above proves only the validated
/// axis, at a single instant; the ADR-0010 draft cited it as the
/// two-axis cadence pin, which it is not). One source dials at a
/// truly *sustained* 10/s — one dial every `EPOCH / RATE` (100 ms),
/// not `RATE * EPOCH.as_secs()` (20) dials bursted at each epoch
/// boundary — across several epochs, each dial driving *both* axes
/// the way a real client does: `decide(peer, false, …)` (Initial,
/// always `Retry` below the unvalidated ceiling) followed by
/// `decide(peer, true, …)` (post-Retry-roundtrip, `Admit` below the
/// validated ceiling, permit dropped immediately — a completed
/// handshake, not a held one).
///
/// The even spacing matters, not just the total: [`Sketch::
/// record_and_estimate`]'s two-generation estimator weights the
/// *previous* epoch's count by `1 - fraction_into_epoch`, so 20
/// events bursted at one epoch's very start followed by 20 more
/// bursted at the very next epoch's start would double-count (the new
/// epoch's first event already sees the full, undecayed previous
/// count) — correctly rejecting a burst that only *looks* like two
/// separate epochs' worth of budget, but not what "sustained 10/s"
/// means. Spreading the same total count evenly is what a genuinely
/// paced dialer looks like, and neither axis may ever reject it — a
/// coupling regression between the two independently-sketched axes,
/// or an off-by-one in the sliding-window math, would show up here
/// even though it passes U18 (which never calls `TestClock::advance`
/// at all).
#[tokio::test]
async fn one_source_dialing_at_a_sustained_rate_passes_both_axes_across_epochs() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 10, 10);
    let peer = addr(v4(203, 0, 113, 44), 1);

    const RATE_PER_SEC: u32 = 10;
    const EPOCHS: u32 = 4;
    let dial_interval = EPOCH / RATE_PER_SEC;
    let total_dials = RATE_PER_SEC * EPOCHS * (EPOCH.as_secs() as u32);

    for dial in 1..=total_dials {
        match gate.decide(peer, false, gate.now()) {
            Decision::Retry => {}
            other => panic!(
                "dial {dial}/{total_dials}: the unvalidated axis of a sustained \
                 10/s dialer must stay Retry, got {}",
                decision_kind(&other)
            ),
        }
        match gate.decide(peer, true, gate.now()) {
            Decision::Admit(permit) => drop(permit),
            other => panic!(
                "dial {dial}/{total_dials}: the validated axis of a sustained \
                 10/s dialer must stay Admit, got {}",
                decision_kind(&other)
            ),
        }
        clock.advance(dial_interval);
    }
}

/// `PLAN.md` M8 Step 3 P2-3 — the `ValidatedRateLimited` category's
/// audit shares the exact first-row-then-summary aggregation contract
/// every other `RejectReason` already has
/// (`gate_flush_expired_emits_exactly_one_summary_after_the_window_closes`'s
/// twin), pinned independently for the new category and window slot.
#[tokio::test]
async fn validated_rate_limited_rejections_aggregate_into_first_row_then_summary() {
    let clock = Arc::new(TestClock::new());
    // validated_rate_per_source = 0: burst = 0, so every validated
    // attempt is a deterministic ValidatedRateLimited rejection —
    // same pattern the existing cap=0 AtCapacity tests use, just on
    // the rate axis instead of the semaphore.
    let gate = Gate::new(clock.clone(), 64, 10, 0);
    let peer = addr(v4(198, 51, 100, 50), 1);

    const REJECTIONS: usize = 5;
    for i in 0..REJECTIONS {
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::ValidatedRateLimited, records) => {
                if i == 0 {
                    assert_eq!(records.len(), 1, "the first rejection carries its own row");
                    assert_eq!(records[0].resource, "validated_rate_limited");
                    assert_eq!(records[0].peer_addr, peer.to_string());
                    assert!(records[0].count.is_none());
                } else {
                    assert!(
                        records.is_empty(),
                        "further rejections in the same window are suppressed, not \
                         re-reported: {records:?}"
                    );
                }
            }
            other => panic!(
                "expected Refuse(ValidatedRateLimited), got {}",
                decision_kind(&other)
            ),
        }
    }

    assert!(
        gate.flush_expired(gate.now()).is_empty(),
        "flush_expired must not fire before the window has run past \
         AUDIT_AGGREGATION_WINDOW"
    );

    clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));
    let flushed = gate.flush_expired(gate.now());
    assert_eq!(
        flushed.len(),
        1,
        "expected exactly one summary record, got {flushed:?}"
    );
    assert_eq!(flushed[0].resource, "validated_rate_limited");
    assert_eq!(flushed[0].count, Some((REJECTIONS - 1) as u32));
    assert_eq!(
        flushed[0].peer_addr, "-",
        "the summary row never carries an observed address"
    );
}
