use super::*;
use crate::broker::TestClock;

fn quotas_with(max_exec_per_principal: usize) -> Arc<Quotas> {
    Quotas::new(
        QuotaLimits {
            max_exec_per_principal,
            ..QuotaLimits::default()
        },
        Arc::new(TestClock::new()),
    )
}

#[test]
fn reserve_exec_refuses_past_the_cap_and_release_frees_the_slot() {
    let quotas = quotas_with(2);
    let p1 = quotas.reserve_exec("device:a").unwrap();
    let p2 = quotas.reserve_exec("device:a").unwrap();
    assert_eq!(quotas.exec_in_use("device:a"), 2);
    assert_eq!(
        quotas.reserve_exec("device:a").unwrap_err(),
        QuotaKind::ExecPerPrincipal
    );

    drop(p1);
    assert_eq!(quotas.exec_in_use("device:a"), 1);
    let p3 = quotas.reserve_exec("device:a").unwrap();
    assert_eq!(quotas.exec_in_use("device:a"), 2);

    drop(p2);
    drop(p3);
    assert_eq!(quotas.exec_in_use("device:a"), 0);
}

/// Adversary finding A8: `exec_in_use`'s comparison against
/// `max_exec_per_principal` used to cast the limit down to `u32`,
/// truncating any limit above `u32::MAX` back into a small (even
/// zero) effective cap. `exec_in_use` is `usize` now, so a limit this
/// large must still admit the very first reservation.
#[test]
fn reserve_exec_is_not_truncated_by_a_limit_above_u32_max() {
    let quotas = quotas_with(1usize << 32);
    assert!(quotas.reserve_exec("device:a").is_ok());
}

fn quotas_with_tunnel(
    max_tunnel_streams_per_principal: usize,
    max_tunnel_streams_per_forward: usize,
) -> Arc<Quotas> {
    Quotas::new(
        QuotaLimits {
            max_tunnel_streams_per_principal,
            max_tunnel_streams_per_forward,
            ..QuotaLimits::default()
        },
        Arc::new(TestClock::new()),
    )
}

/// [`TunnelStreamPermit::drop`] must decrement both axes it
/// incremented and, once either count reaches zero, remove that map
/// entry entirely — the same "no entry without a live resource"
/// invariant `reserve_exec_refuses_past_the_cap_and_release_frees_
/// the_slot` pins for `ExecPermit`. Distinct from that test in
/// checking cardinality (`_entry_count`) as well as the count itself:
/// `_in_use`'s `unwrap_or(0)` alone cannot tell "no entry" apart from
/// "entry present holding `0`".
#[test]
fn tunnel_permit_release_frees_the_slot_and_drops_the_map_entry() {
    let quotas = quotas_with_tunnel(64, 2);
    let p1 = quotas
        .reserve_tunnel_stream("device:a", "db.internal:5432")
        .unwrap();
    let p2 = quotas
        .reserve_tunnel_stream("device:a", "db.internal:5432")
        .unwrap();
    assert_eq!(
        quotas.tunnel_streams_per_forward_in_use("device:a", "db.internal:5432"),
        2
    );
    assert_eq!(quotas.tunnel_streams_per_principal_in_use("device:a"), 2);
    assert_eq!(
        quotas
            .reserve_tunnel_stream("device:a", "db.internal:5432")
            .unwrap_err(),
        QuotaKind::TunnelStreamsPerForward
    );

    drop(p1);
    assert_eq!(
        quotas.tunnel_streams_per_forward_in_use("device:a", "db.internal:5432"),
        1
    );
    assert_eq!(quotas.tunnel_streams_per_principal_entry_count(), 1);

    drop(p2);
    assert_eq!(
        quotas.tunnel_streams_per_forward_in_use("device:a", "db.internal:5432"),
        0
    );
    assert_eq!(
        quotas.tunnel_streams_per_forward_entry_count(),
        0,
        "the last release must remove the map entry, not just zero it"
    );
    assert_eq!(quotas.tunnel_streams_per_principal_entry_count(), 0);
}

/// The forward axis is keyed by `(principal, destination)`, not by
/// either alone: the same principal dialing two destinations gets two
/// independent forward budgets, and two principals dialing the same
/// destination get two independent budgets too — only the
/// per-principal axis (checked first) is shared across destinations
/// for one principal.
#[test]
fn the_tunnel_quota_is_keyed_by_principal_and_destination() {
    let quotas = quotas_with_tunnel(64, 1);
    let _a_db = quotas
        .reserve_tunnel_stream("device:a", "db.internal:5432")
        .unwrap();
    // Same principal, different destination: forward axis is
    // independent, so this must not see "device:a"/"db" 's count.
    let _a_web = quotas
        .reserve_tunnel_stream("device:a", "web.internal:443")
        .unwrap();
    assert_eq!(quotas.tunnel_streams_per_principal_in_use("device:a"), 2);

    // Different principal, same destination: also independent.
    let _b_db = quotas
        .reserve_tunnel_stream("device:b", "db.internal:5432")
        .unwrap();
    assert_eq!(
        quotas.tunnel_streams_per_forward_in_use("device:b", "db.internal:5432"),
        1
    );

    // But "device:a" against "db.internal:5432" is still at its own
    // forward cap of 1.
    assert_eq!(
        quotas
            .reserve_tunnel_stream("device:a", "db.internal:5432")
            .unwrap_err(),
        QuotaKind::TunnelStreamsPerForward
    );
}

fn quotas_with_remote_forward(max_remote_forwards_per_principal: usize) -> Arc<Quotas> {
    Quotas::new(
        QuotaLimits {
            max_remote_forwards_per_principal,
            ..QuotaLimits::default()
        },
        Arc::new(TestClock::new()),
    )
}

/// [`RemoteForwardPermit::drop`] must decrement the principal's
/// in-use count and, once it reaches zero, remove the map entry
/// entirely — the M8 Step 3b twin of `reserve_exec_refuses_past_the_
/// cap_and_release_frees_the_slot`/`tunnel_permit_release_frees_the_
/// slot_and_drops_the_map_entry` for the listener axis.
#[test]
fn remote_forward_permit_release_frees_the_slot_and_drops_the_map_entry() {
    let quotas = quotas_with_remote_forward(2);
    let p1 = quotas.reserve_remote_forward("device:a").unwrap();
    let p2 = quotas.reserve_remote_forward("device:a").unwrap();
    assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 2);
    assert_eq!(
        quotas.reserve_remote_forward("device:a").unwrap_err(),
        QuotaKind::RemoteForwardsPerPrincipal
    );

    drop(p1);
    assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 1);
    assert_eq!(quotas.remote_forwards_per_principal_entry_count(), 1);
    let p3 = quotas.reserve_remote_forward("device:a").unwrap();
    assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 2);

    drop(p2);
    drop(p3);
    assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 0);
    assert_eq!(
        quotas.remote_forwards_per_principal_entry_count(),
        0,
        "the last release must remove the map entry, not just zero it"
    );
}

/// Isolated per principal, same as `exec_quota_is_isolated_per_
/// principal`/`the_tunnel_quota_is_keyed_by_principal_and_
/// destination`'s own principal axis: one principal at its cap never
/// blocks another.
#[test]
fn remote_forward_quota_is_isolated_per_principal() {
    let quotas = quotas_with_remote_forward(1);
    let _a = quotas.reserve_remote_forward("device:a").unwrap();
    let _b = quotas.reserve_remote_forward("device:b").unwrap();
    assert_eq!(quotas.remote_forwards_per_principal_in_use("device:a"), 1);
    assert_eq!(quotas.remote_forwards_per_principal_in_use("device:b"), 1);
    assert_eq!(
        quotas.reserve_remote_forward("device:a").unwrap_err(),
        QuotaKind::RemoteForwardsPerPrincipal
    );
}

fn quotas_with_connections(
    max_connections: usize,
    max_connections_per_principal: usize,
) -> Arc<Quotas> {
    Quotas::new(
        QuotaLimits {
            max_connections,
            max_connections_per_principal,
            ..QuotaLimits::default()
        },
        Arc::new(TestClock::new()),
    )
}

/// [`ConnectionPermit::drop`] must decrement the principal's in-use
/// count and, once it reaches zero, remove the map entry entirely —
/// the M8 Step 3b twin of `remote_forward_permit_release_frees_the_
/// slot_and_drops_the_map_entry` for the connection axis.
#[test]
fn connection_permit_release_frees_the_slot_and_drops_the_map_entry() {
    let quotas = quotas_with_connections(100, 2);
    let p1 = quotas.reserve_connection("device:a").unwrap();
    let p2 = quotas.reserve_connection("device:a").unwrap();
    assert_eq!(quotas.connections_per_principal_in_use("device:a"), 2);
    assert_eq!(
        quotas.reserve_connection("device:a").unwrap_err(),
        QuotaKind::ConnectionsPerPrincipal
    );

    drop(p1);
    assert_eq!(quotas.connections_per_principal_in_use("device:a"), 1);
    assert_eq!(quotas.connections_per_principal_entry_count(), 1);
    let p3 = quotas.reserve_connection("device:a").unwrap();
    assert_eq!(quotas.connections_per_principal_in_use("device:a"), 2);

    drop(p2);
    drop(p3);
    assert_eq!(quotas.connections_per_principal_in_use("device:a"), 0);
    assert_eq!(
        quotas.connections_per_principal_entry_count(),
        0,
        "the last release must remove the map entry, not just zero it"
    );
}

/// Host axis first, then per-principal — same order
/// `exec_reservation_refuses_on_the_host_cap_before_the_principal_cap`
/// pins for `reserve_exec`, restated here for `reserve_connection`
/// (M8 Step 3b ruling R3: "host → principal, matching `reserve_exec`'s
/// own order").
#[test]
fn connection_reservation_refuses_on_the_host_cap_before_the_principal_cap() {
    let quotas = quotas_with_connections(1, 100);
    let _first = quotas.reserve_connection("device:a").unwrap();

    // A second, entirely distinct principal — nowhere near its own
    // per-principal budget — is still refused, and refused for the
    // host reason, not the (irrelevant, unreached) per-principal one.
    assert_eq!(
        quotas.reserve_connection("device:b").unwrap_err(),
        QuotaKind::Connections
    );
    assert_eq!(quotas.connections_per_principal_in_use("device:b"), 0);

    // The principal that filled the host cap is bound by it too.
    assert_eq!(
        quotas.reserve_connection("device:a").unwrap_err(),
        QuotaKind::Connections
    );
}

/// Isolated per principal, same as every other per-principal axis in
/// this module.
#[test]
fn connection_quota_is_isolated_per_principal() {
    let quotas = quotas_with_connections(100, 1);
    let _a = quotas.reserve_connection("device:a").unwrap();
    let _b = quotas.reserve_connection("device:b").unwrap();
    assert_eq!(quotas.connections_per_principal_in_use("device:a"), 1);
    assert_eq!(quotas.connections_per_principal_in_use("device:b"), 1);
    assert_eq!(
        quotas.reserve_connection("device:a").unwrap_err(),
        QuotaKind::ConnectionsPerPrincipal
    );
}

/// M8 Step 5a: `reserve_connection`'s success and both its refusal
/// branches (host cap, per-principal cap) each land in their own
/// [`QuotaCounters`] field.
#[test]
fn quota_counters_tally_reserve_connection_outcomes() {
    let quotas = quotas_with_connections(1, 100);
    assert_eq!(quotas.counters(), QuotaCounters::default());

    let _held = quotas.reserve_connection("device:a").unwrap();
    assert_eq!(
        quotas.counters(),
        QuotaCounters {
            connection_reserved: 1,
            ..Default::default()
        }
    );

    // Host cap (1) already spent by `_held` — refused for the host
    // reason regardless of principal.
    assert_eq!(
        quotas.reserve_connection("device:b").unwrap_err(),
        QuotaKind::Connections
    );
    assert_eq!(
        quotas.counters(),
        QuotaCounters {
            connection_reserved: 1,
            connection_refused: 1,
            ..Default::default()
        }
    );
}

/// The test above only ever trips the host-cap branch
/// (`max_connections`) — with `max_connections == 1`, the
/// per-principal cap (`quotas_with_connections`'s second argument) is
/// never reached, so its doc comment's claim ("both its refusal
/// branches ... each land in their own field") was untrue of the test
/// that made it. This drives the per-principal branch instead
/// (`quotas_with_connections(100, 1)`), pinning that
/// `connection_refused` really does tally *that* branch too, not only
/// the host one.
#[test]
fn quota_counters_tally_the_per_principal_reserve_connection_refusal_too() {
    let quotas = quotas_with_connections(100, 1);
    let _held = quotas.reserve_connection("device:a").unwrap();
    assert_eq!(
        quotas.reserve_connection("device:a").unwrap_err(),
        QuotaKind::ConnectionsPerPrincipal
    );
    assert_eq!(
        quotas.counters(),
        QuotaCounters {
            connection_reserved: 1,
            connection_refused: 1,
            ..Default::default()
        }
    );
}

/// M8 Step 5a twin of the above, for `reserve_pairing_connection`'s
/// own (fixed-cap) success/refusal pair — independent counter fields,
/// untouched by `reserve_connection` traffic.
#[test]
fn quota_counters_tally_reserve_pairing_connection_outcomes() {
    let quotas = Quotas::new(QuotaLimits::default(), Arc::new(TestClock::new()));
    let mut permits = Vec::new();
    for _ in 0..MAX_CONCURRENT_PAIRING_CONNECTIONS {
        permits.push(quotas.reserve_pairing_connection().unwrap());
    }
    assert_eq!(
        quotas.counters(),
        QuotaCounters {
            pairing_reserved: MAX_CONCURRENT_PAIRING_CONNECTIONS as u64,
            ..Default::default()
        }
    );

    assert_eq!(
        quotas.reserve_pairing_connection().unwrap_err(),
        QuotaKind::PairingConnections
    );
    assert_eq!(
        quotas.counters(),
        QuotaCounters {
            pairing_reserved: MAX_CONCURRENT_PAIRING_CONNECTIONS as u64,
            pairing_refused: 1,
            ..Default::default()
        }
    );
}

/// [`PairingConnectionPermit::drop`] must decrement the fixed counter
/// — no map, no principal key, same discipline as every other
/// permit's `Drop` in this module. Also pins the fixed cap itself
/// (`MAX_CONCURRENT_PAIRING_CONNECTIONS = 8`, M8 Step 3b ruling R2):
/// not configurable, so this test (unlike every other `reserve_*`
/// test here) needs no `QuotaLimits` override to reach it.
#[test]
fn pairing_connection_permit_release_frees_the_fixed_slot() {
    let quotas = Quotas::new(QuotaLimits::default(), Arc::new(TestClock::new()));
    let mut permits = Vec::new();
    for _ in 0..MAX_CONCURRENT_PAIRING_CONNECTIONS {
        permits.push(quotas.reserve_pairing_connection().unwrap());
    }
    assert_eq!(
        quotas.pairing_connections_in_use(),
        MAX_CONCURRENT_PAIRING_CONNECTIONS
    );
    assert_eq!(
        quotas.reserve_pairing_connection().unwrap_err(),
        QuotaKind::PairingConnections
    );

    drop(permits.pop().unwrap());
    assert_eq!(
        quotas.pairing_connections_in_use(),
        MAX_CONCURRENT_PAIRING_CONNECTIONS - 1
    );
    let _fresh = quotas.reserve_pairing_connection().unwrap();
    assert_eq!(
        quotas.pairing_connections_in_use(),
        MAX_CONCURRENT_PAIRING_CONNECTIONS
    );

    permits.clear();
    drop(_fresh);
    assert_eq!(quotas.pairing_connections_in_use(), 0);
}

#[test]
fn exec_quota_is_isolated_per_principal() {
    let quotas = quotas_with(1);
    let _a = quotas.reserve_exec("device:a").unwrap();
    // A's cap is full, but B is a distinct key and still admits.
    let _b = quotas.reserve_exec("device:b").unwrap();
    assert_eq!(quotas.exec_in_use("device:a"), 1);
    assert_eq!(quotas.exec_in_use("device:b"), 1);
    assert_eq!(
        quotas.reserve_exec("device:a").unwrap_err(),
        QuotaKind::ExecPerPrincipal
    );
    assert_eq!(
        quotas.reserve_exec("device:b").unwrap_err(),
        QuotaKind::ExecPerPrincipal
    );
}

/// F9 of the M8 Step 3a conformance sweep: `reserve_exec` must test
/// the cap *before* touching `exec_in_use`'s map, not
/// `entry(..).or_insert(0)` ahead of the check. With
/// `max_exec_per_principal == 0` (unreachable through parsed config,
/// where `0` degrades to the default — `QuotaLimits::from_serve` — but
/// directly reachable through a hand-built `QuotaLimits` the way this
/// test, and 3b's tunnel/connection quotas, construct one) every
/// refused reservation must leave the map exactly as it found it: no
/// zero-valued entry surviving under the refused principal's key.
#[test]
fn reserve_exec_leaves_no_entry_behind_when_the_cap_is_zero() {
    let quotas = quotas_with(0);
    assert_eq!(
        quotas.reserve_exec("device:a").unwrap_err(),
        QuotaKind::ExecPerPrincipal
    );
    assert_eq!(quotas.exec_in_use("device:a"), 0);
    assert_eq!(
        quotas.exec_in_use_principal_count(),
        0,
        "a refused reservation against a zero cap must not plant a \
         zero-valued map entry — the module's own \"no entry without \
         a live resource\" invariant"
    );

    // A second, distinct principal against the same zero cap: same
    // refusal, same empty map afterward.
    assert_eq!(
        quotas.reserve_exec("device:b").unwrap_err(),
        QuotaKind::ExecPerPrincipal
    );
    assert_eq!(quotas.exec_in_use_principal_count(), 0);
}

/// `Quotas::record_rejection`'s per-kind tally
/// (`QuotaCounters::rejections_by_kind`) increments independently for
/// two different axes rejected once each — the heartbeat's
/// `quota_rejections` field (`rejections_total`) must reflect every
/// axis a soak can bind on, not just the two `reserve_connection`/
/// `reserve_pairing_connection` counters the old `quota_refused` field
/// summed.
#[test]
fn rejections_by_kind_tallies_each_kind_independently() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    quotas.record_rejection(
        QuotaKind::ExecPerPrincipal,
        "device:a",
        peer,
        t0,
        None,
        qsh_transport::AuthPath::Ca,
    );
    quotas.record_rejection(
        QuotaKind::Connections,
        "device:a",
        peer,
        t0,
        None,
        qsh_transport::AuthPath::Ca,
    );

    let counters = quotas.counters();
    assert_eq!(
        counters.rejections_by_kind[QuotaKind::ExecPerPrincipal as usize],
        1
    );
    assert_eq!(
        counters.rejections_by_kind[QuotaKind::Connections as usize],
        1
    );
    assert_eq!(counters.rejections_total(), 2);
}

/// A second rejection of the *same* kind inside the
/// same aggregation window is audit-suppressed (no new
/// `AuditRecord` — `quota_audit_reports_first_then_summary` below
/// pins that half), but the raw tally still counts it — counting and
/// audit emission are different concerns, and a soak reading
/// `quota_rejections` must see the true rejection volume even during
/// a suppressed flood.
#[test]
fn rejections_by_kind_counts_a_window_suppressed_rejection_too() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    let first = quotas.record_rejection(
        QuotaKind::ExecPerPrincipal,
        "device:a",
        peer,
        t0,
        None,
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(
        first.len(),
        1,
        "first rejection in a fresh window gets its own audit line"
    );

    let second = quotas.record_rejection(
        QuotaKind::ExecPerPrincipal,
        "device:a",
        peer,
        t0 + std::time::Duration::from_secs(1),
        None,
        qsh_transport::AuthPath::Ca,
    );
    assert!(
        second.is_empty(),
        "same window — this one is audit-suppressed"
    );

    assert_eq!(
        quotas.counters().rejections_by_kind[QuotaKind::ExecPerPrincipal as usize],
        2,
        "both calls must count even though the second produced no audit line"
    );
}

#[test]
fn quota_audit_reports_first_then_summary() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    // First rejection in a fresh window: an immediate, real record.
    let first_batch = quotas.record_rejection(
        QuotaKind::ExecPerPrincipal,
        "device:a",
        peer,
        t0,
        Some(1),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(
        first_batch.len(),
        1,
        "just the fresh window's own first line"
    );
    let first = &first_batch[0];
    assert_eq!(first.principal, "device:a");
    assert_eq!(first.resource, QuotaKind::ExecPerPrincipal.category());
    assert_eq!(first.count, None);

    // Two more within the same window: suppressed, no record yet.
    assert!(
        quotas
            .record_rejection(
                QuotaKind::ExecPerPrincipal,
                "device:a",
                peer,
                t0 + std::time::Duration::from_secs(1),
                Some(1),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty()
    );
    assert!(
        quotas
            .record_rejection(
                QuotaKind::ExecPerPrincipal,
                "device:a",
                peer,
                t0 + std::time::Duration::from_secs(2),
                Some(1),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty()
    );

    // Flushing before the window has aged out reports nothing.
    assert!(
        quotas
            .flush_expired(t0 + std::time::Duration::from_secs(3))
            .is_empty()
    );

    // Once the window has aged past AUDIT_AGGREGATION_WINDOW, flush
    // closes it with a summary counting the two suppressed rejections.
    let flushed =
        quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
    assert_eq!(flushed.len(), 1);
    // R2: the window is keyed on (category, principal), so its
    // summary carries that principal's own name, not the old shared
    // "-" — every rejection above was against "device:a".
    assert_eq!(flushed[0].principal, "device:a");
    assert_eq!(flushed[0].count, Some(2));
    assert_eq!(flushed[0].resource, QuotaKind::ExecPerPrincipal.category());
}

/// M8 Step 3b S5: twin of `quota_audit_reports_first_then_summary`,
/// but for a tunnel-stream category and interleaved with rejections
/// on an unrelated category (`ExecPerPrincipal`) in the same window —
/// `windows` is one slot per `QuotaKind`, so the tunnel category's
/// first-line/summary count must reflect only *its own* rejections,
/// never the other category's, even though both windows are open and
/// aging over the exact same wall-clock span.
#[test]
fn a_tunnel_quota_rejection_reports_first_then_summary_in_its_own_window() {
    let quotas = quotas_with_tunnel(1, 64);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let sec = std::time::Duration::from_secs(1);

    // First tunnel rejection in a fresh window: real record.
    let first = quotas.record_rejection(
        QuotaKind::TunnelStreamsPerPrincipal,
        "device:a",
        peer,
        t0,
        None,
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(first.len(), 1);
    assert_eq!(
        first[0].resource,
        QuotaKind::TunnelStreamsPerPrincipal.category()
    );

    // An unrelated category's own first rejection, same instant: its
    // own window opens independently and must not be folded into the
    // tunnel window's count.
    let unrelated_first = quotas.record_rejection(
        QuotaKind::ExecPerPrincipal,
        "device:a",
        peer,
        t0,
        Some(9),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(unrelated_first.len(), 1);

    // Three more tunnel rejections within the window: suppressed.
    for i in 1..=3u64 {
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::TunnelStreamsPerPrincipal,
                    "device:a",
                    peer,
                    t0 + sec * i as u32,
                    None,
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );
    }
    // One more on the unrelated category too, so both windows close
    // at the same flush with different suppressed counts.
    assert!(
        quotas
            .record_rejection(
                QuotaKind::ExecPerPrincipal,
                "device:a",
                peer,
                t0 + sec,
                Some(9),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty()
    );

    let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
    assert_eq!(flushed.len(), 2, "both windows close at this flush");
    let tunnel_summary = flushed
        .iter()
        .find(|r| r.resource == QuotaKind::TunnelStreamsPerPrincipal.category())
        .expect("tunnel summary present");
    assert_eq!(
        tunnel_summary.count,
        Some(3),
        "tunnel window must count exactly its own 3 suppressed \
         rejections, not the unrelated category's"
    );
    let exec_summary = flushed
        .iter()
        .find(|r| r.resource == QuotaKind::ExecPerPrincipal.category())
        .expect("exec summary present");
    assert_eq!(exec_summary.count, Some(1));
}

/// M8 Step 3b S5: `Quotas::windows` grew from 3 slots to
/// `QuotaKind::ALL.len()` (10) across S1-S4. This pins that every one
/// of the 7 categories S1 added closes its own window with a real
/// summary — not just that `flush_expired_summary_names_the_correct_
/// kind_for_every_category` above sees *a* record (which a stray
/// hardcoded `windows: [AuditWindow; 3]` would already fail loudly
/// on, via an out-of-bounds index panic long before this test could
/// even run) but that the suppressed-count arithmetic for each new
/// slot is independent and correct.
#[test]
fn flush_expired_closes_every_new_category_window() {
    let new_kinds = [
        QuotaKind::ExecHost,
        QuotaKind::TunnelStreamsPerPrincipal,
        QuotaKind::TunnelStreamsPerForward,
        QuotaKind::RemoteForwardsPerPrincipal,
        QuotaKind::ConnectionsPerPrincipal,
        QuotaKind::Connections,
        QuotaKind::PairingConnections,
    ];
    assert_eq!(
        new_kinds.len() + 3,
        QuotaKind::ALL.len(),
        "this test's own table must cover every category S1 added \
         on top of the pre-existing 3"
    );
    for kind in new_kinds {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let sec = std::time::Duration::from_secs(1);

        let first = quotas.record_rejection(
            kind,
            "device:a",
            peer,
            t0,
            None,
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(first.len(), 1, "kind {kind:?}: first line");
        for i in 1..=2u64 {
            assert!(
                quotas
                    .record_rejection(
                        kind,
                        "device:a",
                        peer,
                        t0 + sec * i as u32,
                        None,
                        qsh_transport::AuthPath::Ca,
                    )
                    .is_empty(),
                "kind {kind:?}: suppressed rejection #{i}"
            );
        }
        let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
        assert_eq!(flushed.len(), 1, "kind {kind:?}: summary on flush");
        assert_eq!(
            flushed[0].count,
            Some(2),
            "kind {kind:?}: must count exactly its own 2 suppressed \
             rejections"
        );
        assert_eq!(flushed[0].resource, kind.category());
        assert!(
            !quotas.audit_window_is_open(kind, "device:a"),
            "kind {kind:?}: flush must actually close its window"
        );
    }
}

/// `record_rejection` indexes `Quotas`'s internal `windows` array by
/// `kind as usize` (this module's `windows: [AuditWindow;
/// QuotaKind::ALL.len()]` field), while `flush_expired` walks
/// `windows` zipped in lockstep with `QuotaKind::ALL`'s own iteration
/// order — the two only agree with each other if `ALL`'s declared
/// order exactly matches each variant's discriminant.
#[test]
fn quota_kind_all_is_declared_in_discriminant_order() {
    for (i, k) in QuotaKind::ALL.iter().enumerate() {
        assert_eq!(*k as usize, i);
    }
}

/// Twin of the discriminant-order pin above, exercised through the
/// actual read/write path rather than the raw enum values: a window
/// `record_rejection` opens for `kind` (via `kind as usize`) must be
/// the exact same slot `flush_expired`'s `windows.iter().zip(ALL)`
/// later reports back out *as* `kind` — reordering `QuotaKind::ALL`
/// relative to declaration order would make `flush_expired` attribute
/// one category's suppressed rejections to a different one.
#[test]
fn flush_expired_summary_names_the_correct_kind_for_every_category() {
    for &kind in QuotaKind::ALL {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let sec = std::time::Duration::from_secs(1);

        let first = quotas.record_rejection(
            kind,
            "device:a",
            peer,
            t0,
            Some(1),
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(first.len(), 1, "kind {kind:?}: first line");
        assert_eq!(
            first[0].peer_addr,
            peer.to_string(),
            "kind {kind:?}: R4 — first line must carry the live peer, not \"-\""
        );
        assert_eq!(
            first[0].request_id, "1",
            "kind {kind:?}: R9 — a Some(1) request_id must audit as \"1\", not the \"-\" sentinel"
        );
        assert!(
            quotas
                .record_rejection(
                    kind,
                    "device:a",
                    peer,
                    t0 + sec,
                    Some(1),
                    qsh_transport::AuthPath::Ca
                )
                .is_empty(),
            "kind {kind:?}: second rejection suppressed"
        );

        let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
        assert_eq!(flushed.len(), 1, "kind {kind:?}: summary");
        assert_eq!(
            flushed[0].resource,
            kind.category(),
            "kind {kind:?}: summary named the wrong category"
        );
        assert_eq!(
            flushed[0].peer_addr, "-",
            "kind {kind:?}: R4 — a summary record spans many peers and stays \"-\""
        );
        assert_eq!(
            flushed[0].request_id, "-",
            "kind {kind:?}: R9 — a summary record spans many requests and stays \"-\""
        );
    }
}

#[test]
fn quota_flush_expired_closes_a_window_with_no_further_rejections() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    let first = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:a",
        peer,
        t0,
        Some(1),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(first.len(), 1, "first rejection reported");
    // Nothing else ever calls record_rejection again for this
    // category — the flood already stopped. The periodic tick must
    // still close the window on its own.
    let flushed =
        quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
    // No further rejections were suppressed, so there is nothing to
    // summarize — but the window itself must be closed (a second
    // flush at the same instant reports nothing new either).
    assert!(flushed.is_empty());
    // Directly on the window's own state, not merely inferred from
    // "nothing was reported": an empty `flushed` is also what a bug
    // that re-stamped `guard.start = Some(start)` instead of clearing
    // it to `None` would produce, since that bug leaves nothing new
    // to summarize either. `audit_window_is_open` reads exactly the
    // (deleted-or-not) entry, so it fails the way that bug should.
    assert!(
        !quotas.audit_window_is_open(QuotaKind::Sessions, "device:a"),
        "flush_expired must actually close the window (entry deleted), \
         not just decline to report anything"
    );
    assert_eq!(
        quotas.audit_window_principal_count(QuotaKind::Sessions),
        0,
        "the closed entry must be removed from the map, not merely reset"
    );
    assert!(
        quotas
            .flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1))
            .is_empty()
    );

    // A rejection after the close starts a brand new window and is
    // reported immediately, proving the old one did not linger open.
    // Reusing "device:a" (not a different principal) matters here: in
    // the R2 (category, principal)-keyed design a *different*
    // principal always gets its own fresh first line regardless of
    // whether "device:a"'s window is still open — so only reusing the
    // same principal actually exercises "the old window did not
    // linger open" rather than "a different principal has its own
    // window", which `a_second_principals_first_rejection_opens_its_
    // own_window` covers separately.
    let reopened = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:a",
        peer,
        t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(2),
        Some(2),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(
        reopened.len(),
        1,
        "closed window reopens on the next rejection"
    );
    assert_eq!(reopened[0].principal, "device:a");
    assert_eq!(reopened[0].count, None);
}

/// The quota module's twin of
/// `crate::admission::tests::gate_record_rejection_and_flush_expired_
/// both_reset_suppressed_not_just_report_it`, which `Quotas` never got
/// when it copied `Gate::flush_expired`'s shape. `flush_expired` must
/// *consume* the suppressed count it reports, not merely read it —
/// otherwise the next rejection to reopen that category's window
/// re-emits a phantom summary for suppressions that were already
/// summarized one window ago.
#[test]
fn quota_flush_expired_resets_suppressed_not_just_reports_it() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let sec = std::time::Duration::from_secs(1);

    assert_eq!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:a",
                peer,
                t0,
                Some(1),
                qsh_transport::AuthPath::Ca
            )
            .len(),
        1
    );
    for n in 1..=2u64 {
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    "device:a",
                    peer,
                    t0 + sec * (n as u32),
                    Some(1),
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );
    }

    let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].count, Some(2));

    // A later, isolated rejection opens a brand new window: it owes
    // exactly one fresh first line and nothing else. A second summary
    // here would be re-reporting the two suppressions the flush above
    // already accounted for.
    let later = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:b",
        peer,
        t0 + AUDIT_AGGREGATION_WINDOW + sec * 2,
        Some(7),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(
        later.len(),
        1,
        "flush_expired must consume the suppressed count it reported — \
         got a phantom second summary: {later:?}"
    );
    assert_eq!(later[0].principal, "device:b");
    assert!(later[0].count.is_none());
}

/// Main-session arbitration round, item 4 (S1 deviation 2 overturned):
/// the stale-reopen branch must return *both* the closing window's
/// summary and the triggering rejection's own first line, mirroring
/// `crate::admission::Gate::record_rejection` exactly — not the single
/// `Option` the M8 Step 3a S1 stage had shipped, which could only ever
/// return one of the two. If a different principal came instead, the
/// return would be 1 row, not 2 — `a_second_principals_first_
/// rejection_opens_its_own_window` covers that branch.
#[test]
fn quota_rejection_reopens_a_stale_window_with_both_its_summary_and_a_fresh_first_line() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    // Three rejections in one window: one immediate first line, two
    // suppressed.
    let first = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:a",
        peer,
        t0,
        Some(1),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(first.len(), 1);
    assert!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:a",
                peer,
                t0 + std::time::Duration::from_secs(1),
                Some(1),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty()
    );
    assert!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:a",
                peer,
                t0 + std::time::Duration::from_secs(2),
                Some(1),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty()
    );

    // Advance past the window with nothing to close it (no
    // `flush_expired` tick), then one more rejection: this call alone
    // must close the stale window (summary, 2 suppressed) *and* report
    // its own fresh first line — never one at the other's expense.
    //
    // R2: this must reuse "device:a" (not a different principal like
    // the old "device:b"). With windows keyed on (category,
    // principal), a *different* principal always opens its own fresh
    // window regardless of "device:a"'s state and this call would
    // return only 1 record, not 2 — the len()==2 assertion below only
    // means what it says when both records are attributed to the same
    // principal's own window: the closing summary of its stale window
    // plus its own reopening first line.
    let stale_reopen = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:a",
        peer,
        t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1),
        Some(9),
        qsh_transport::AuthPath::Pin,
    );
    assert_eq!(
        stale_reopen.len(),
        2,
        "the closing summary and the reopening rejection's own line, \
         both — got {stale_reopen:?}"
    );
    assert_eq!(stale_reopen[0].principal, "device:a");
    assert_eq!(stale_reopen[0].count, Some(2));
    assert_eq!(stale_reopen[0].resource, QuotaKind::Sessions.category());
    assert_eq!(stale_reopen[1].principal, "device:a");
    assert_eq!(stale_reopen[1].count, None);
    assert_eq!(stale_reopen[1].request_id, "9");
    assert_eq!(stale_reopen[1].auth_path, "pin");

    // The window this rejection just opened is fresh — a flush at the
    // same instant reports nothing new for it.
    assert!(
        quotas
            .flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1))
            .is_empty()
    );
}

/// M8 Step 3b S1: `Quotas::windows` is sized `[AuditWindow;
/// QuotaKind::ALL.len()]` and every `record_rejection`/`flush_expired`
/// index into it is `kind as usize` — so `ALL`'s length (and, via the
/// discriminant-order test above, its declaration order) is exactly
/// what keeps the two in lockstep. This test pins the length half of
/// that invariant directly, independent of the discriminant-order
/// test, so a mutation that drops a variant from `ALL` without
/// touching declaration order still gets caught.
#[test]
fn quota_kind_all_stays_in_lockstep_with_the_window_array() {
    let quotas = quotas_with(1);
    // `Quotas::windows` is declared `[AuditWindow; QuotaKind::ALL.len()]`
    // — its length can never mechanically diverge from `ALL.len()`, so
    // the invariant this test exists to pin is that *count* against a
    // literal (10, the full 3b vocabulary), not against `ALL.len()`
    // itself: comparing a derived quantity to the very expression it
    // was derived from can never fail no matter how many variants a
    // mutation drops from `ALL`.
    assert_eq!(
        quotas.windows.len(),
        10,
        "Quotas::windows must have exactly one slot per QuotaKind::ALL entry \
         (10 variants after M8 Step 3b S1)"
    );
    assert_eq!(
        QuotaKind::ALL.len(),
        10,
        "QuotaKind::ALL must list all 10 variants"
    );
    // Every kind must be reachable as a valid index — a variant added
    // to the enum but left out of ALL would panic here instead of
    // silently aliasing another kind's window.
    for &kind in QuotaKind::ALL {
        let _ = &quotas.windows[kind as usize];
    }
}

/// M8 Step 3b ruling R5: pins the full, exact vocabulary for every one
/// of the 10 `QuotaKind` variants — `category()`, `action()`, and
/// `wire_message()` — against the ruling's own table, so a variant
/// added to the enum without a matching arm in one of these three
/// functions (or a typo in the string a match arm returns) fails here
/// instead of only being caught by a doc-contract test much later.
#[test]
fn every_quota_kind_maps_to_its_documented_category_action_and_wire_message() {
    let expected: &[(QuotaKind, &str, &str, &str)] = &[
        (
            QuotaKind::Sessions,
            "quota_sessions_host",
            "session.open",
            "session quota exceeded",
        ),
        (
            QuotaKind::SessionsPerPrincipal,
            "quota_sessions_principal",
            "session.open",
            "session quota exceeded",
        ),
        (
            QuotaKind::ExecPerPrincipal,
            "quota_exec_principal",
            "exec.run",
            "exec quota exceeded",
        ),
        (
            QuotaKind::ExecHost,
            "quota_exec_host",
            "exec.run",
            "exec quota exceeded",
        ),
        (
            QuotaKind::TunnelStreamsPerPrincipal,
            "quota_tunnels_principal",
            "forward.local",
            "tunnel quota exceeded",
        ),
        (
            QuotaKind::TunnelStreamsPerForward,
            "quota_tunnels_forward",
            "forward.local",
            "tunnel quota exceeded",
        ),
        (
            QuotaKind::RemoteForwardsPerPrincipal,
            "quota_remote_forwards_principal",
            "forward.remote",
            "remote forward quota exceeded",
        ),
        (
            QuotaKind::ConnectionsPerPrincipal,
            "quota_connections_principal",
            "connect",
            "connection quota exceeded",
        ),
        (
            QuotaKind::Connections,
            "quota_connections_host",
            "connect",
            "connection quota exceeded",
        ),
        (
            QuotaKind::PairingConnections,
            "quota_connections_pairing",
            "connect",
            "connection quota exceeded",
        ),
    ];
    assert_eq!(
        expected.len(),
        QuotaKind::ALL.len(),
        "this test's own table must cover every QuotaKind::ALL entry"
    );
    for &(kind, category, action, wire_message) in expected {
        assert_eq!(kind.category(), category, "kind {kind:?}: category");
        assert_eq!(kind.action(), action, "kind {kind:?}: action");
        assert_eq!(
            kind.wire_message(),
            wire_message,
            "kind {kind:?}: wire_message"
        );
    }
}

/// M8 Step 3b S1: `reserve_exec` checks the host-wide axis
/// (`QuotaLimits::max_exec`, derived as `Σ exec_in_use.values()`)
/// before the per-principal axis — a host at its host cap must refuse
/// with `QuotaKind::ExecHost` even for a principal nowhere near its own
/// per-principal cap, and must never touch that principal's map entry
/// while refusing.
#[test]
fn exec_reservation_refuses_on_the_host_cap_before_the_principal_cap() {
    let quotas = Quotas::new(
        QuotaLimits {
            max_exec: 1,
            max_exec_per_principal: 100,
            ..QuotaLimits::default()
        },
        Arc::new(TestClock::new()),
    );
    // One reservation for device:a fills the host cap (1) while
    // leaving device:a's own per-principal cap (100) nowhere near
    // exhausted.
    let _first = quotas.reserve_exec("device:a").unwrap();

    // A second principal, entirely within its own per-principal
    // budget, must still be refused — and refused for the host reason,
    // not the (irrelevant, unreached) per-principal one.
    assert_eq!(
        quotas.reserve_exec("device:b").unwrap_err(),
        QuotaKind::ExecHost
    );
    // The refused principal must get no map entry at all (F9
    // discipline, extended to the host axis).
    assert_eq!(quotas.exec_in_use("device:b"), 0);

    // The same principal already holding the one live reservation is
    // refused too — the host cap binds everyone once it is full,
    // including the principal that filled it.
    assert_eq!(
        quotas.reserve_exec("device:a").unwrap_err(),
        QuotaKind::ExecHost
    );
}

/// M8 Step 3b S1: every new `[serve]` key degrades `0`/unset to its
/// documented default, the same discipline every existing quota key
/// already follows (`ServeConfig::max_exec_per_principal`, etc.) —
/// exercised through `QuotaLimits::from_serve` end to end rather than
/// each individual getter in isolation, so a mismatch between
/// `QuotaLimits::from_serve`'s field wiring and the getters it calls
/// is caught here too.
#[test]
fn an_unset_or_zero_quota_key_degrades_to_its_documented_default() {
    let unset = crate::config::ServeConfig::default();
    let limits = QuotaLimits::from_serve(&unset);
    assert_eq!(
        limits.max_exec,
        crate::config::ServeConfig::DEFAULT_MAX_EXEC
    );
    assert_eq!(
        limits.max_tunnel_streams_per_principal,
        crate::config::ServeConfig::DEFAULT_MAX_TUNNEL_STREAMS_PER_PRINCIPAL
    );
    assert_eq!(
        limits.max_tunnel_streams_per_forward,
        crate::config::ServeConfig::DEFAULT_MAX_TUNNEL_STREAMS_PER_FORWARD
    );
    assert_eq!(
        limits.max_remote_forwards_per_principal,
        crate::config::ServeConfig::DEFAULT_MAX_REMOTE_FORWARDS_PER_PRINCIPAL
    );
    assert_eq!(
        limits.max_connections_per_principal,
        crate::config::ServeConfig::DEFAULT_MAX_CONNECTIONS_PER_PRINCIPAL
    );
    assert_eq!(
        limits.max_connections,
        crate::config::ServeConfig::DEFAULT_MAX_CONNECTIONS
    );

    // Explicit `0` degrades exactly the same way as unset.
    let zeroed = crate::config::ServeConfig {
        max_exec: Some(0),
        max_tunnel_streams_per_principal: Some(0),
        max_tunnel_streams_per_forward: Some(0),
        max_remote_forwards_per_principal: Some(0),
        max_connections_per_principal: Some(0),
        max_connections: Some(0),
        ..crate::config::ServeConfig::default()
    };
    let zeroed_limits = QuotaLimits::from_serve(&zeroed);
    assert_eq!(zeroed_limits.max_exec, limits.max_exec);
    assert_eq!(
        zeroed_limits.max_tunnel_streams_per_principal,
        limits.max_tunnel_streams_per_principal
    );
    assert_eq!(
        zeroed_limits.max_tunnel_streams_per_forward,
        limits.max_tunnel_streams_per_forward
    );
    assert_eq!(
        zeroed_limits.max_remote_forwards_per_principal,
        limits.max_remote_forwards_per_principal
    );
    assert_eq!(
        zeroed_limits.max_connections_per_principal,
        limits.max_connections_per_principal
    );
    assert_eq!(zeroed_limits.max_connections, limits.max_connections);
}

/// R2 설계 검토 (b-5) #1: with windows keyed on `(category,
/// principal)`, principal A opening (and then re-suppressing into) its
/// own window must never absorb principal B's *first* rejection in the
/// same category and the same wall-clock window — B still gets its own
/// fresh first line.
///
/// Mutation this catches: reverting the window key to `kind` alone
/// (the pre-Step-5 shape) makes B's rejection land in A's already-open
/// window and return an empty `Vec` (suppressed) instead of a 1-row
/// first line. This test pins that most narrowly, but it is not the
/// only one that mutation breaks (R2 review B, B4) — every other
/// multi-principal test added alongside it in this module
/// (`two_principals_audit_windows_expire_independently`,
/// `flush_expired_removes_every_closed_window_entry`,
/// `the_sixty_fifth_principal_falls_into_the_category_overflow_
/// window`) also rely on distinct principals getting distinct windows,
/// and would each independently fail (or, for the ones asserting on
/// `CategoryWindows::per_principal`'s own shape via
/// `audit_window_principal_count`/`audit_window_is_open`, fail to
/// build) under a mutation that collapses the window key back to
/// `kind` alone.
#[test]
fn a_second_principals_first_rejection_opens_its_own_window() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    let a_first = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:a",
        peer,
        t0,
        Some(1),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(a_first.len(), 1);
    assert_eq!(a_first[0].principal, "device:a");

    // A's second rejection in the same window is suppressed into A's
    // own window, as always.
    assert!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:a",
                peer,
                t0 + std::time::Duration::from_secs(1),
                Some(1),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty()
    );

    // B's first rejection, same category, same window instant: must
    // be its own fresh first line, not folded into A's open window.
    let b_first = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:b",
        peer,
        t0 + std::time::Duration::from_secs(1),
        Some(2),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(
        b_first.len(),
        1,
        "principal B's own first rejection must not be absorbed into \
         principal A's window: {b_first:?}"
    );
    assert_eq!(b_first[0].principal, "device:b");
    assert!(b_first[0].count.is_none());
}

/// R2 설계 검토 (b-5) #2: two principals' audit windows in the same
/// category expire independently — closing one does not close, or
/// otherwise disturb, the other's suppressed count or start time.
///
/// R2 review B (B3): the mutation this test is meant to catch is
/// `flush_expired` closing every window in a category the instant any
/// one of them goes stale (equivalent to sharing one `WindowState`
/// across principals, the pre-Step-5 shape). The assertion that
/// actually catches it is the `audit_window_is_open(Sessions,
/// "device:b")` check right after the first flush — B's window must
/// still read as open there. The *previous* version of this doc
/// claimed the second flush's "reports nothing" assertion was what
/// caught it, but that assertion passes either way: under the
/// mutation B's window was already closed (and its zero suppressions
/// already reported, i.e. not reported) by the *first* flush, so the
/// second flush finding nothing left to report is not evidence of
/// anything. B now suppresses one rejection of its own precisely so
/// the second flush has something to report — under the mutation, B's
/// closing summary and its `count` would have already been consumed
/// (or never opened) by the first flush and this second flush would
/// come back empty instead of `len() == 1`, giving that assertion real
/// bite as a second, independent witness to the same mutation.
#[test]
fn two_principals_audit_windows_expire_independently() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    // A opens its window at t0 and suppresses one more rejection.
    assert_eq!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:a",
                peer,
                t0,
                Some(1),
                qsh_transport::AuthPath::Ca,
            )
            .len(),
        1
    );
    assert!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:a",
                peer,
                t0 + std::time::Duration::from_secs(1),
                Some(1),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty()
    );

    // B opens its own window 6s later (still well within A's window)
    // and suppresses one further rejection of its own — giving the
    // second flush below something concrete to report.
    let t_b = t0 + std::time::Duration::from_secs(6);
    assert_eq!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:b",
                peer,
                t_b,
                Some(2),
                qsh_transport::AuthPath::Ca,
            )
            .len(),
        1
    );
    assert!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:b",
                peer,
                t_b + std::time::Duration::from_secs(1),
                Some(2),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty()
    );

    // Flushing once A's window (but not yet B's) has aged out reports
    // only A's summary.
    let flushed_a =
        quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
    assert_eq!(
        flushed_a.len(),
        1,
        "only A's window should have closed: {flushed_a:?}"
    );
    assert_eq!(flushed_a[0].principal, "device:a");
    assert_eq!(flushed_a[0].count, Some(1));
    assert!(
        quotas.audit_window_is_open(QuotaKind::Sessions, "device:b"),
        "B's still-fresh window must not have been touched by A's flush"
    );

    // Flushing again once B's window has also aged out reports only
    // B's summary, with B's own suppressed count — untouched by A's
    // earlier, separate flush.
    let flushed_b =
        quotas.flush_expired(t_b + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
    assert_eq!(
        flushed_b.len(),
        1,
        "B's window must still carry its own suppressed rejection at \
         this point, untouched by A's earlier flush: {flushed_b:?}"
    );
    assert_eq!(flushed_b[0].principal, "device:b");
    assert_eq!(flushed_b[0].count, Some(1));
    assert!(!quotas.audit_window_is_open(QuotaKind::Sessions, "device:b"));
}

/// R2 설계 검토 (b-5) #3: `flush_expired` must actually *remove* every
/// closed principal-window entry from the category's map, not merely
/// re-stamp `start = None` in place — otherwise the map grows by one
/// entry for every distinct principal ever rejected over the
/// process's lifetime instead of staying bounded by
/// [`MAX_AUDIT_WINDOW_PRINCIPALS`].
///
/// Mutation this catches: changing `flush_expired`'s `retain` closure
/// to reset the entry in place (`state.start = None; state.suppressed
/// = 0; true`) instead of returning `false` to drop it. Most tests in
/// this module only inspect the `Vec<AuditRecord>` a flush returns,
/// which is identical either way (both shapes report zero summaries
/// when nothing was suppressed) — checking the map's own cardinality
/// after the flush is what distinguishes them, which is exactly what
/// `audit_window_principal_count` does here. (R2 review A confirmed by
/// mutation: this is not the *only* test that catches it —
/// `quota_flush_expired_closes_a_window_with_no_further_rejections`
/// makes the same cardinality check on its own single principal — but
/// this test is the one that pins it across *many* distinct
/// principals in one category, closer to the actual flood shape the
/// cap exists for.)
#[test]
fn flush_expired_removes_every_closed_window_entry() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    for n in 0..8u32 {
        let principal = format!("device:{n}");
        assert_eq!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    &principal,
                    peer,
                    t0,
                    Some(1),
                    qsh_transport::AuthPath::Ca,
                )
                .len(),
            1,
            "principal {principal}: own first line"
        );
    }
    assert_eq!(
        quotas.audit_window_principal_count(QuotaKind::Sessions),
        8,
        "all 8 distinct principals must have their own live window"
    );

    let flushed =
        quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
    assert!(
        flushed.is_empty(),
        "none of the 8 principals suppressed a second rejection, so \
         there is nothing to summarize: {flushed:?}"
    );
    assert_eq!(
        quotas.audit_window_principal_count(QuotaKind::Sessions),
        0,
        "every closed entry must be deleted from the map, not merely \
         reset in place"
    );
}

/// R2 설계 검토 (b-5) #4: the 65th distinct principal rejected within
/// one category's window falls into that category's single overflow
/// window instead of growing the per-principal map past
/// [`MAX_AUDIT_WINDOW_PRINCIPALS`] — and, since the overflow window
/// starts out fresh, that 65th principal's own first rejection still
/// carries its real name; only the *summary* line for the (possibly
/// multi-principal) shared overflow window is audited under `"-"`.
///
/// Mutation this catches: dropping the `per_principal.len() >=
/// MAX_AUDIT_WINDOW_PRINCIPALS` guard makes the 66th principal also
/// get its own fresh window (map size 66, not 64, and no overflow
/// window ever opens) — the count/`is_open` assertions below fail.
/// Attributing the overflow window's *first* line to `"-"` instead of
/// the rejected principal's own name (rather than only the summary)
/// is a separate mutation this test also catches via the `first_65th`
/// assertion.
#[test]
fn the_sixty_fifth_principal_falls_into_the_category_overflow_window() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    for n in 0..MAX_AUDIT_WINDOW_PRINCIPALS {
        let principal = format!("device:{n}");
        assert_eq!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    &principal,
                    peer,
                    t0,
                    Some(1),
                    qsh_transport::AuthPath::Ca,
                )
                .len(),
            1,
            "principal {principal}: own first line"
        );
    }
    assert_eq!(
        quotas.audit_window_principal_count(QuotaKind::Sessions),
        MAX_AUDIT_WINDOW_PRINCIPALS
    );
    assert!(!quotas.audit_overflow_window_is_open(QuotaKind::Sessions));

    // The 65th distinct principal: falls into overflow, but its own
    // first line still names it (the overflow window is itself fresh).
    let first_65th = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:overflow-1",
        peer,
        t0,
        Some(1),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(first_65th.len(), 1);
    assert_eq!(first_65th[0].principal, "device:overflow-1");
    assert_eq!(
        quotas.audit_window_principal_count(QuotaKind::Sessions),
        MAX_AUDIT_WINDOW_PRINCIPALS,
        "the map itself must not grow past the cap"
    );
    assert!(quotas.audit_overflow_window_is_open(QuotaKind::Sessions));

    // The 66th distinct principal: the overflow window is now open
    // and fresh, so this one is suppressed into it.
    assert!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:overflow-2",
                peer,
                t0,
                Some(1),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty(),
        "a second overflow principal in the same window is suppressed, \
         not given its own line"
    );

    let flushed =
        quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
    let overflow_summary: Vec<_> = flushed.iter().filter(|r| r.principal == "-").collect();
    assert_eq!(
        overflow_summary.len(),
        1,
        "exactly one overflow summary line, attributed to \"-\": {flushed:?}"
    );
    assert_eq!(overflow_summary[0].count, Some(1));
    assert!(!quotas.audit_overflow_window_is_open(QuotaKind::Sessions));
}

/// R2 review A, F2: none of the existing tests drive
/// `record_rejection`'s own `if is_overflow { "-" } else { principal
/// }` branch (quota.rs, the summary line built inside
/// `record_rejection` itself, not `flush_expired`'s separate summary
/// path) with `is_overflow == true` — `the_sixty_fifth_principal_...`
/// only ever closes the overflow window via `flush_expired`, and
/// mutating this call's `"-"` to `principal` unconditionally
/// (confirmed by mutation: A's M5) left every existing test green.
/// This test fills the category to the overflow cap, suppresses one
/// rejection inside the (already fresh) overflow window, then lets it
/// go stale and reopens it — driving the same "stale window closes
/// with a summary, plus a fresh first line" shape
/// `quota_rejection_reopens_a_stale_window_with_both_its_summary_and_
/// a_fresh_first_line` already covers for a normal window, but for the
/// overflow window specifically.
#[test]
fn overflow_window_reopening_emits_a_dash_summary_line_from_record_rejection() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    for n in 0..MAX_AUDIT_WINDOW_PRINCIPALS {
        let principal = format!("device:{n}");
        assert_eq!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    &principal,
                    peer,
                    t0,
                    Some(1),
                    qsh_transport::AuthPath::Ca,
                )
                .len(),
            1
        );
    }

    // The overflow window's own first line: fresh, names the real
    // principal, not "-".
    let overflow_first = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:overflow-a",
        peer,
        t0,
        Some(1),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(overflow_first.len(), 1);
    assert_eq!(overflow_first[0].principal, "device:overflow-a");

    // A second, different principal lands in the same still-fresh
    // overflow window and is suppressed.
    assert!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "device:overflow-b",
                peer,
                t0 + std::time::Duration::from_secs(1),
                Some(1),
                qsh_transport::AuthPath::Ca,
            )
            .is_empty()
    );

    // Let the overflow window go stale, then reopen it with a third
    // principal's rejection: `record_rejection` itself (not
    // `flush_expired`) must emit the closing summary under "-", plus
    // its own fresh first line under the real name — both from this
    // one call.
    let stale_reopen = quotas.record_rejection(
        QuotaKind::Sessions,
        "device:overflow-c",
        peer,
        t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1),
        Some(1),
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(
        stale_reopen.len(),
        2,
        "the overflow window's closing summary and the reopening \
         rejection's own line, both — got {stale_reopen:?}"
    );
    assert_eq!(
        stale_reopen[0].principal, "-",
        "the overflow window's *summary* line must be attributed to \
         the reserved sentinel, not whichever principal happened to \
         reopen it: {stale_reopen:?}"
    );
    assert_eq!(stale_reopen[0].count, Some(1));
    assert_eq!(stale_reopen[1].principal, "device:overflow-c");
    assert!(stale_reopen[1].count.is_none());
}

/// R2 review B, B1: `"-"` is a reserved sentinel for the overflow
/// summary, never a legitimate `per_principal` key — a caller that
/// audits a pre-identity axis under `"-"` (matching the admission
/// convention `docs/CLI.md` §6.12 already uses for `rate_limited`/
/// `at_capacity`) must land in the shared overflow window, not open an
/// ordinary window under that literal string. Confirmed by mutation
/// (B's M4 against `server/mod.rs`'s pairing-rejection call site):
/// before the `principal == "-"` guard in `record_rejection`, passing
/// `"-"` through opened a normal `per_principal["-"]` entry
/// indistinguishable from an actual overflow summary, and zero tests
/// caught it.
#[test]
fn a_rejection_audited_under_the_reserved_dash_principal_lands_in_overflow() {
    let quotas = quotas_with(1);
    let clock = TestClock::new();
    let t0 = clock.now();
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    let first = quotas.record_rejection(
        QuotaKind::Sessions,
        "-",
        peer,
        t0,
        None,
        qsh_transport::AuthPath::Ca,
    );
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].principal, "-");
    assert_eq!(
        quotas.audit_window_principal_count(QuotaKind::Sessions),
        0,
        "\"-\" must never become a per_principal map entry"
    );
    assert!(quotas.audit_overflow_window_is_open(QuotaKind::Sessions));

    assert!(
        quotas
            .record_rejection(
                QuotaKind::Sessions,
                "-",
                peer,
                t0 + std::time::Duration::from_secs(1),
                None,
                qsh_transport::AuthPath::Ca,
            )
            .is_empty(),
        "a second \"-\" rejection in the same window is suppressed into \
         the overflow window, same as any other overflow rejection"
    );

    let flushed =
        quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].principal, "-");
    assert_eq!(flushed[0].count, Some(1));
}

/// R2 review A, F1: `flush_expired`'s doc names 650 (`QuotaKind::
/// ALL.len() × (MAX_AUDIT_WINDOW_PRINCIPALS + 1)`) as the worst-case
/// per-tick record burst and claims it stays under
/// `AuditConfig::DEFAULT_QUEUE_DEPTH`'s headroom. Pin the arithmetic
/// itself so a future `QuotaKind::ALL` growth, a
/// `MAX_AUDIT_WINDOW_PRINCIPALS` increase, or a `DEFAULT_QUEUE_DEPTH`
/// decrease that closes this gap fails here instead of only showing
/// up as an occasional `QueueFull` under load.
#[test]
fn flush_expired_worst_case_burst_fits_under_the_default_audit_queue_depth() {
    let worst_case_burst = QuotaKind::ALL.len() * (MAX_AUDIT_WINDOW_PRINCIPALS + 1);
    assert_eq!(worst_case_burst, 650, "documented worst-case burst drifted");
    assert!(
        (worst_case_burst as u32) < crate::config::AuditConfig::DEFAULT_QUEUE_DEPTH,
        "flush_expired's worst-case per-tick burst ({worst_case_burst}) \
         must stay under the default [audit].queue_depth \
         ({}) — otherwise a routine quota-audit flush can itself \
         saturate the queue at defaults, with no operator \
         misconfiguration involved",
        crate::config::AuditConfig::DEFAULT_QUEUE_DEPTH
    );
}
