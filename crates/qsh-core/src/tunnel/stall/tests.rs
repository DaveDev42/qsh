//! The ledger's decision rule (ADR-0037 decisions 2-4) against synthetic
//! timestamps. The splice-level behavior over real TCP and QUIC lives in
//! `crate::tunnel::splice`'s tests.

use super::*;

async fn ledger(
    params: StallParams,
) -> (
    Arc<StallLedger>,
    (qsh_transport::Connection, qsh_transport::Connection),
) {
    let (client, server) = crate::tunnel::testutil::loopback_pair().await;
    (
        StallLedger::unstarted_for_test(client.quinn().clone(), params),
        (client, server),
    )
}

const SECOND: Duration = Duration::from_secs(1);

/// Decision 3's relation, pinned in numbers as well as in the const
/// assertions: one stream window short of the connection window.
#[test]
fn stalled_stream_limit_is_one_stream_window_short_of_the_connection_window() {
    assert_eq!(
        MAX_STALLED_STREAMS_PER_CONNECTION as u64,
        CONNECTION_RECEIVE_WINDOW / u64::from(TUNNEL_STREAM_RECEIVE_WINDOW) - 1
    );
    assert_eq!(MAX_STALLED_STREAMS_PER_CONNECTION, 3, "8 MiB / 2 MiB - 1");
    let held = MAX_STALLED_STREAMS_PER_CONNECTION as u64 * u64::from(TUNNEL_STREAM_RECEIVE_WINDOW);
    assert!(
        CONNECTION_RECEIVE_WINDOW - held >= u64::from(TUNNEL_STREAM_RECEIVE_WINDOW),
        "stalled streams at the limit leave at least one stream window of credit"
    );
    assert_eq!(RESET_CODE_TUNNEL_STALLED, 0x200E);
    assert_ne!(
        RESET_CODE_TUNNEL_STALLED,
        crate::tunnel::splice::RESET_CODE_TUNNEL_ABORT,
        "decision 6: distinct from the generic abort code"
    );
}

/// Decision 3: past the limit, only the oldest stalls are stopped, exactly
/// enough of them to get back to the limit; a stream that is not inside a
/// write is never counted.
#[tokio::test]
async fn only_the_oldest_stalled_streams_past_the_limit_are_stopped() {
    let (ledger, _conn) = ledger(StallParams::PRODUCTION).await;
    let watches: Vec<StallWatch> = (0..6).map(|i| ledger.watch(format!("s{i}"))).collect();
    let now = Instant::now() + 10 * SECOND;
    // Five streams stalled, oldest first; the sixth is idle (not writing).
    for (age, watch) in watches.iter().take(5).enumerate() {
        ledger.force_writing_since(watch.id(), now - SECOND * (10 - age as u32));
    }

    let evictions = ledger.decide(now, 0);
    assert_eq!(
        evictions.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![watches[0].id(), watches[1].id()],
        "5 stalled against a limit of 3: the two oldest, nothing else"
    );
    assert!(
        evictions
            .iter()
            .all(|e| e.reason == StallReason::StalledLimit)
    );
    // Timestamps are kept to the microsecond.
    let off = evictions[0].stalled_for.abs_diff(10 * SECOND);
    assert!(off < Duration::from_millis(1), "stalled_for off by {off:?}");
}

/// Decisions 2 and 3: at or under the limit nothing is stopped, and a write
/// younger than the stall age is not a stall at all.
#[tokio::test]
async fn streams_at_the_limit_or_writing_for_less_than_the_stall_age_are_left_alone() {
    let (ledger, _conn) = ledger(StallParams::PRODUCTION).await;
    let watches: Vec<StallWatch> = (0..5).map(|i| ledger.watch(format!("s{i}"))).collect();
    let now = Instant::now() + 10 * SECOND;
    for watch in watches.iter().take(3) {
        ledger.force_writing_since(watch.id(), now - 5 * SECOND);
    }
    // Two more inside a write, but for less than `STALL_AGE`.
    for watch in watches.iter().skip(3) {
        ledger.force_writing_since(watch.id(), now - STALL_AGE / 2);
    }
    assert!(ledger.decide(now, 0).is_empty());
}

/// Decision 4: a `DATA_BLOCKED` rise with a stall under the limit stops
/// the single oldest stalled stream, once.
#[tokio::test]
async fn a_data_blocked_rise_stops_the_single_oldest_stalled_stream_under_the_limit() {
    let (ledger, _conn) = ledger(StallParams::PRODUCTION).await;
    let a = ledger.watch("a");
    let b = ledger.watch("b");
    let now = Instant::now() + 10 * SECOND;
    ledger.force_writing_since(a.id(), now - 3 * SECOND);
    ledger.force_writing_since(b.id(), now - 2 * SECOND);

    let evictions = ledger.decide(now, 1);
    assert_eq!(evictions.len(), 1);
    assert_eq!(evictions[0].id, a.id());
    assert_eq!(evictions[0].reason, StallReason::DataBlocked);

    // The rise has been answered: the same count does not stop `b` too.
    assert!(ledger.decide(now + EVALUATE_INTERVAL, 1).is_empty());
}

/// Decision 4's guard: `DATA_BLOCKED` with no stalled stream is saturation
/// with a reading consumer, and stops nothing.
#[tokio::test]
async fn data_blocked_without_a_stalled_stream_stops_nothing() {
    let (ledger, _conn) = ledger(StallParams::PRODUCTION).await;
    let a = ledger.watch("a");
    let now = Instant::now() + 10 * SECOND;
    // Writing, but only just.
    ledger.force_writing_since(a.id(), now - STALL_AGE / 4);
    assert!(ledger.decide(now, 5).is_empty());
}

/// A rise is remembered for `DATA_BLOCKED_MEMORY` so a stream that only
/// qualifies as stalled a tick later is still answered, and is forgotten
/// after that.
#[tokio::test]
async fn a_data_blocked_rise_is_remembered_for_its_window_and_then_forgotten() {
    let (ledger, _conn) = ledger(StallParams::PRODUCTION).await;
    let a = ledger.watch("a");
    let t0 = Instant::now() + 10 * SECOND;
    ledger.force_writing_since(a.id(), t0 - STALL_AGE / 2);
    assert!(ledger.decide(t0, 1).is_empty(), "not yet stalled");
    let later = t0 + STALL_AGE;
    assert_eq!(
        ledger.decide(later, 1).len(),
        1,
        "stalled now, rise still fresh"
    );

    // A later rise while nothing is stalled stops nothing, and is not
    // held over to a stall that only appears after the memory window.
    // (`decide` alone does not mark `a` stopped; its splice would be gone.)
    drop(a);
    let b = ledger.watch("b");
    let t1 = later + SECOND;
    assert!(ledger.decide(t1, 2).is_empty(), "no stalled stream");
    let stale = t1 + DATA_BLOCKED_MEMORY + SECOND;
    ledger.force_writing_since(b.id(), stale - 2 * STALL_AGE);
    assert!(
        ledger.decide(stale, 2).is_empty(),
        "a rise older than DATA_BLOCKED_MEMORY stops nothing"
    );
}

/// An already-stopped stream is not counted again while its splice is
/// tearing down, and a dropped watch leaves the ledger.
#[tokio::test]
async fn a_stopped_or_dropped_stream_is_no_longer_counted() {
    let params = StallParams {
        max_stalled: 1,
        ..StallParams::PRODUCTION
    };
    let (ledger, _conn) = ledger(params).await;
    let a = ledger.watch("a");
    let b = ledger.watch("b");
    let now = Instant::now() + 10 * SECOND;
    ledger.force_writing_since(a.id(), now - 4 * SECOND);
    ledger.force_writing_since(b.id(), now - 3 * SECOND);

    ledger.tick_for_test(now);
    // `a` was signalled: its `evicted()` resolves at once.
    tokio::time::timeout(Duration::from_secs(5), a.evicted())
        .await
        .expect("the oldest stream was signalled");
    assert!(
        ledger.decide(now, 0).is_empty(),
        "with `a` stopped, `b` alone is within the limit"
    );

    drop(a);
    drop(b);
    assert_eq!(ledger.len(), 0);
}

/// One ledger per connection: two watches on the same connection share it,
/// another connection gets its own.
#[tokio::test]
async fn ledgers_are_shared_within_a_connection_and_separate_across_connections() {
    let (c1, _s1) = crate::tunnel::testutil::loopback_pair().await;
    let (c2, _s2) = crate::tunnel::testutil::loopback_pair().await;
    let l1 = StallLedger::for_connection(c1.quinn());
    let l1_again = StallLedger::for_connection(c1.quinn());
    let l2 = StallLedger::for_connection(c2.quinn());
    assert!(Arc::ptr_eq(&l1, &l1_again));
    assert!(!Arc::ptr_eq(&l1, &l2));
}

/// A counter hook, and the streams of a ledger started for the test.
fn counting_hook() -> (TrafficHook, Arc<std::sync::atomic::AtomicUsize>) {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    (
        Arc::new(move || {
            seen.fetch_add(1, Ordering::Relaxed);
        }),
        calls,
    )
}

/// A connection's traffic hook hears both directions of every stream that
/// starts after it is registered, a zero-byte report is not traffic, and a
/// stream on another connection is not heard at all.
#[tokio::test]
async fn a_traffic_hook_hears_bytes_moving_in_either_direction_on_its_connection_only() {
    let (hooked, _hooked_peer) = crate::tunnel::testutil::loopback_pair().await;
    let (other, _other_peer) = crate::tunnel::testutil::loopback_pair().await;
    let (hook, calls) = counting_hook();
    let _guard = report_traffic(hooked.quinn(), hook);

    let on_hooked = StallWatch::on(hooked.quinn(), "hooked");
    let on_other = StallWatch::on(other.quinn(), "other");

    on_hooked.track().count_sent(0);
    on_hooked.track().leave_write(0);
    assert_eq!(calls.load(Ordering::Relaxed), 0, "no bytes, no traffic");

    on_hooked.track().count_sent(10);
    assert_eq!(calls.load(Ordering::Relaxed), 1, "send direction");
    on_hooked.track().enter_write();
    on_hooked.track().leave_write(10);
    assert_eq!(calls.load(Ordering::Relaxed), 2, "receive direction");

    on_other.track().count_sent(10);
    assert_eq!(calls.load(Ordering::Relaxed), 2, "another connection");
}

/// Dropping the guard stops the reporting for streams that start later. A
/// second registration on the same connection replaces the first, and the
/// first guard's drop leaves the replacement alone.
#[tokio::test]
async fn a_traffic_guard_removes_only_its_own_hook() {
    let (conn, _peer) = crate::tunnel::testutil::loopback_pair().await;

    let (first, first_calls) = counting_hook();
    let first_guard = report_traffic(conn.quinn(), first);
    let (second, second_calls) = counting_hook();
    let second_guard = report_traffic(conn.quinn(), second);

    drop(first_guard);
    StallWatch::on(conn.quinn(), "after the first guard")
        .track()
        .count_sent(1);
    assert_eq!(first_calls.load(Ordering::Relaxed), 0, "replaced");
    assert_eq!(second_calls.load(Ordering::Relaxed), 1, "still installed");

    drop(second_guard);
    StallWatch::on(conn.quinn(), "after the second guard")
        .track()
        .count_sent(1);
    assert_eq!(second_calls.load(Ordering::Relaxed), 1, "removed");
    assert!(
        lock(traffic_hooks())
            .get(&conn.quinn().stable_id())
            .is_none(),
        "no entry is left behind for a connection id"
    );
}

/// The reverse registration's wiring: tunnel bytes on the registration's
/// connection count as activity for its path watch, and nothing else does.
#[tokio::test(start_paused = true)]
async fn tunnel_bytes_hold_a_path_watch_on_the_fast_cadence() {
    use crate::client::pathwatch::{PathWatch, PathWatchConfig};

    let (conn, _peer) = crate::tunnel::testutil::loopback_pair().await;
    let cfg = PathWatchConfig::default();
    let watch = PathWatch::new(cfg);
    let _guard = crate::reverse::report_tunnel_traffic(&watch, &conn);
    let tunnel = StallWatch::on(conn.quinn(), "tunnel");

    // Well past the active window with nothing counted: idle.
    tokio::time::advance(cfg.active_window + SECOND).await;
    assert_eq!(watch.cadence(), cfg.idle_probe_interval);

    // A chunk of tunnel bytes: in use again, at once.
    tunnel.track().count_sent(512);
    assert_eq!(watch.cadence(), cfg.probe_interval);
    tokio::time::advance(cfg.active_window - SECOND).await;
    tunnel.track().enter_write();
    tunnel.track().leave_write(512);
    tokio::time::advance(SECOND * 2).await;
    assert_eq!(
        watch.cadence(),
        cfg.probe_interval,
        "the receive direction renewed the window"
    );

    // And back to idle once the bytes stop.
    tokio::time::advance(cfg.active_window).await;
    assert_eq!(watch.cadence(), cfg.idle_probe_interval);
}
