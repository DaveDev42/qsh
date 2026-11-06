//! Policy table (ADR-0052 decision 18 item 5). One row per threshold side,
//! hysteresis band and override. No clock, no sleeping.

use std::time::Duration;

use super::*;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn obs(f: impl FnOnce(&mut Observed)) -> Observed {
    let mut o = Observed {
        datagram: true,
        ..Observed::default()
    };
    f(&mut o);
    o
}

fn with_prediction(p: Prediction) -> Knobs {
    Knobs {
        prediction: p,
        ..Knobs::default()
    }
}

// (a) bulk yielding ------------------------------------------------------

#[test]
fn yield_table() {
    // (interactive, bulk, adaptive, expect yield)
    let rows = [
        (true, true, true, true),
        (true, false, true, false),
        (false, true, true, false),
        (false, false, true, false),
        (true, true, false, false), // adaptive = "off"
    ];
    for (interactive, bulk, adaptive, expect) in rows {
        let o = obs(|o| {
            o.interactive = interactive;
            o.bulk = bulk;
            o.user.adaptive = adaptive;
        });
        let k = decide(&o, &Knobs::default());
        let want = if expect {
            BulkYield::Yield {
                target: ms(25),
                floor_bytes_per_sec: 64 * 1024,
            }
        } else {
            BulkYield::Off
        };
        assert_eq!(k.bulk_yield, want, "{interactive} {bulk} {adaptive}");
    }
}

#[test]
fn yield_floor_is_the_larger_of_64_kib_and_5_percent_of_bandwidth() {
    for (bw, floor) in [
        (None, 64 * 1024),
        (Some(1_000_000), 64 * 1024), // 5% = 50 kB/s
        (Some(1_310_720), 64 * 1024),
        (Some(2_500_000), 125_000), // 5% = 125 kB/s
        (Some(100_000_000), 5_000_000),
    ] {
        let o = obs(|o| {
            o.interactive = true;
            o.bulk = true;
            o.est_bandwidth = bw;
        });
        let BulkYield::Yield {
            floor_bytes_per_sec,
            ..
        } = decide(&o, &Knobs::default()).bulk_yield
        else {
            panic!("not yielding");
        };
        assert_eq!(floor_bytes_per_sec, floor.max(64 * 1024), "{bw:?}");
    }
}

#[test]
fn queue_delay_reason_straddles_the_target() {
    for (srtt, min, listed) in [(125, 100, false), (126, 100, true), (90, 100, false)] {
        let o = obs(|o| {
            o.srtt = ms(srtt);
            o.min_rtt = ms(min);
        });
        let k = decide(&o, &Knobs::default());
        assert_eq!(k.reasons.contains(&Reason::QueueDelayHigh), listed);
    }
}

// (b) screen interval ----------------------------------------------------

#[test]
fn frame_interval_and_collect_table() {
    // (srtt ms, interval us, collect us)
    let rows = [
        (0, 20_000, 1_000),
        (10, 20_000, 1_250), // srtt/8 above its 1 ms floor
        (39, 20_000, 4_875), // srtt/2 = 19.5 ms: clamped up to 20
        (40, 20_000, 5_000),
        (41, 20_500, 5_125), // srtt/2 just above the 20 ms floor
        (60, 30_000, 7_500),
        (64, 32_000, 8_000),
        (200, 100_000, 8_000),
        (500, 250_000, 8_000),
        (900, 250_000, 8_000),
    ];
    for (srtt, interval, collect) in rows {
        let k = decide(&obs(|o| o.srtt = ms(srtt)), &Knobs::default());
        assert_eq!(
            k.frame_interval,
            Duration::from_micros(interval),
            "interval at {srtt}"
        );
        assert_eq!(
            k.collect,
            Duration::from_micros(collect),
            "collect at {srtt}"
        );
    }
}

#[test]
fn frame_interval_is_fixed_to_the_mosh_defaults_when_adaptive_is_off() {
    let k = decide(
        &obs(|o| {
            o.srtt = ms(400);
            o.user.adaptive = false;
        }),
        &Knobs::default(),
    );
    assert_eq!((k.frame_interval, k.collect), (ms(20), ms(8)));
}

// (c) carrier ------------------------------------------------------------

#[test]
fn carrier_without_datagram_is_stream() {
    let o = obs(|o| o.datagram = false);
    let k = decide(&o, &Knobs::default());
    assert_eq!(k.carrier, Carrier::Stream(StreamWhy::DatagramUnavailable));
    assert!(k.reasons.contains(&Reason::DatagramUnavailable));
}

#[test]
fn carrier_with_datagram_is_datagram() {
    let k = decide(&obs(|_| {}), &Knobs::default());
    assert_eq!(k.carrier, Carrier::Datagram);
}

#[test]
fn unacked_datagram_switches_to_stream_only_past_four_srtt_and_with_stream_acks() {
    // (unacked ms, stream acks flowing, expect stream)
    let rows = [
        (400, true, false), // exactly 4 x srtt is not past it
        (401, true, true),
        (401, false, false), // the whole connection is silent, not a datagram problem
        (10_000, true, true),
    ];
    for (age, flowing, expect) in rows {
        let o = obs(|o| {
            o.srtt = ms(100);
            o.datagram_unacked_for = Some(ms(age));
            o.stream_acks_flowing = flowing;
        });
        let k = decide(&o, &Knobs::default());
        let want = if expect {
            Carrier::Stream(StreamWhy::DatagramUnacked)
        } else {
            Carrier::Datagram
        };
        assert_eq!(k.carrier, want, "{age} {flowing}");
    }
    let none = decide(&obs(|o| o.srtt = ms(100)), &Knobs::default());
    assert_eq!(none.carrier, Carrier::Datagram);
}

#[test]
fn unacked_stream_choice_holds_until_the_retest_is_due() {
    let held = Knobs {
        carrier: Carrier::Stream(StreamWhy::DatagramUnacked),
        ..Knobs::default()
    };
    // Hysteresis band: nothing outstanding any more, but no retest yet.
    let k = decide(&obs(|_| {}), &held);
    assert_eq!(k.carrier, Carrier::Stream(StreamWhy::DatagramUnacked));
    // Retest due and the probe was acked: back to datagram.
    let k = decide(&obs(|o| o.datagram_probe_due = true), &held);
    assert_eq!(k.carrier, Carrier::Datagram);
    // Retest due but the probe is unacked past 4 x srtt: stays on stream.
    let k = decide(
        &obs(|o| {
            o.datagram_probe_due = true;
            o.srtt = ms(50);
            o.datagram_unacked_for = Some(ms(300));
        }),
        &held,
    );
    assert_eq!(k.carrier, Carrier::Stream(StreamWhy::DatagramUnacked));
}

#[test]
fn per_update_fragment_rule_straddles_half_delivery() {
    // loss 5%: 0.95^13 = 0.513 (datagram), 0.95^14 = 0.488 (stream)
    let k = decide(&obs(|o| o.loss = 0.05), &Knobs::default());
    assert_eq!(k.carrier_for_update(1), Carrier::Datagram);
    assert_eq!(k.carrier_for_update(13), Carrier::Datagram);
    assert_eq!(
        k.carrier_for_update(14),
        Carrier::Stream(StreamWhy::FragmentsLossy)
    );
    // No loss: any part count stays on datagram.
    let k = decide(&obs(|_| {}), &Knobs::default());
    assert_eq!(k.carrier_for_update(1000), Carrier::Datagram);
    // A stream base carrier is never promoted by the per-update rule.
    let k = decide(&obs(|o| o.datagram = false), &Knobs::default());
    assert_eq!(
        k.carrier_for_update(1),
        Carrier::Stream(StreamWhy::DatagramUnavailable)
    );
}

#[test]
fn adaptive_off_uses_datagram_when_present_even_with_unacked_updates() {
    let o = obs(|o| {
        o.user.adaptive = false;
        o.srtt = ms(100);
        o.datagram_unacked_for = Some(ms(5_000));
    });
    assert_eq!(decide(&o, &Knobs::default()).carrier, Carrier::Datagram);
}

// (d) prediction ---------------------------------------------------------

#[test]
fn prediction_table() {
    use Prediction::*;
    // (srtt ms, previous, expect)
    let rows = [
        // display threshold, both sides, from Off
        (19, Off, Off),
        (20, Off, Off),
        (25, Off, Off), // hysteresis band keeps Off
        (30, Off, Off), // 30 itself is not "above"
        (31, Off, Display),
        // leaving Display
        (31, Display, Display),
        (25, Display, Display), // band keeps Display
        (20, Display, Display),
        (19, Display, Off),
        // underline threshold, both sides
        (80, Display, Display),
        (81, Display, Underline),
        (81, Off, Underline),
        // underline hysteresis band 50..=80
        (79, Underline, Underline),
        (50, Underline, Underline),
        (49, Underline, Display),
        (60, Display, Display), // band keeps Display too
        // falling straight through the bands
        (25, Underline, Display),
        (10, Underline, Off),
    ];
    for (srtt, prev, expect) in rows {
        let k = decide(&obs(|o| o.srtt = ms(srtt)), &with_prediction(prev));
        assert_eq!(k.prediction, expect, "srtt {srtt} from {prev:?}");
    }
}

#[test]
fn prediction_is_off_when_adaptive_is_off() {
    let o = obs(|o| {
        o.srtt = ms(200);
        o.user.adaptive = false;
    });
    let k = decide(&o, &with_prediction(Prediction::Underline));
    assert_eq!(k.prediction, Prediction::Off);
}

// (e) keep-alive ---------------------------------------------------------

#[test]
fn keep_alive_table() {
    let user = |ka: Option<u64>, adaptive: bool| User {
        adaptive,
        keep_alive: ka.map(ms),
    };
    let prev = |ka: u64| Knobs {
        keep_alive: ms(ka),
        ..Knobs::default()
    };
    // (user, nat rebind g ms, previous ms, expect ms)
    let rows = [
        (user(None, true), None, 15_000, 15_000),
        // g/2 inside 1 s..=15 s
        (user(None, true), Some(20_000), 15_000, 10_000),
        (user(None, true), Some(30_000), 15_000, 15_000), // 15 s: not shorter
        (user(None, true), Some(40_000), 15_000, 15_000), // clamp to 15 s, never longer
        (user(None, true), Some(1_000), 15_000, 1_000),   // clamp at the 1 s floor
        (user(None, true), Some(29_998), 15_000, 14_999), // just under the ceiling
        (user(None, true), Some(2_000), 15_000, 1_000),   // g/2 lands on the floor
        (user(None, true), Some(2_002), 15_000, 1_001),
        (user(None, true), Some(0), 15_000, 1_000),
        // only shorter: a later, larger observation does not lengthen
        (user(None, true), Some(30_000), 10_000, 10_000),
        (user(None, true), None, 10_000, 10_000),
        (user(None, true), Some(8_000), 10_000, 4_000),
        // user value wins over everything, adaptive or not
        (user(Some(5_000), true), Some(2_000), 15_000, 5_000),
        (user(Some(5_000), false), None, 15_000, 5_000),
        (user(Some(20_000), true), None, 15_000, 20_000),
        // adaptive off: today's 15 s, even if previously shortened
        (user(None, false), Some(2_000), 3_000, 15_000),
    ];
    for (u, g, previous, expect) in rows {
        let o = obs(|o| {
            o.user = u;
            o.nat_rebind_after_idle = g.map(ms);
        });
        let k = decide(&o, &prev(previous));
        assert_eq!(
            k.keep_alive,
            ms(expect),
            "user {u:?} g {g:?} previous {previous}"
        );
        assert!(k.keep_alive >= KEEP_ALIVE_MIN && k.keep_alive <= KEEP_ALIVE_MAX);
    }
}

#[test]
fn nat_rebind_reason_only_when_it_actually_shortened() {
    let shortened = decide(
        &obs(|o| o.nat_rebind_after_idle = Some(ms(10_000))),
        &Knobs::default(),
    );
    assert!(shortened.reasons.contains(&Reason::NatRebind));
    let same = decide(
        &obs(|o| o.nat_rebind_after_idle = Some(ms(10_000))),
        &shortened,
    );
    assert!(!same.reasons.contains(&Reason::NatRebind));
}

// (f) outer carrier ------------------------------------------------------

#[test]
fn outer_carrier_table() {
    // (nested, outer datagram, expect)
    let rows = [
        (false, true, None),
        (false, false, None),
        (true, true, Some(Carrier::Datagram)),
        (
            true,
            false,
            Some(Carrier::Stream(StreamWhy::DatagramUnavailable)),
        ),
    ];
    for (nested, outer, expect) in rows {
        let o = obs(|o| {
            o.nested = nested;
            o.outer_datagram = outer;
        });
        let k = decide(&o, &Knobs::default());
        assert_eq!(k.outer_carrier, expect, "{nested} {outer}");
        assert_eq!(k.reasons.contains(&Reason::Nested), nested);
    }
}

// overrides --------------------------------------------------------------

#[test]
fn adaptive_off_pins_every_knob() {
    let o = obs(|o| {
        o.user.adaptive = false;
        o.srtt = ms(300);
        o.min_rtt = ms(50);
        o.loss = 0.1;
        o.interactive = true;
        o.bulk = true;
        o.nat_rebind_after_idle = Some(ms(2_000));
    });
    let k = decide(&o, &with_prediction(Prediction::Underline));
    assert_eq!(k.bulk_yield, BulkYield::Off);
    assert_eq!((k.frame_interval, k.collect), (ms(20), ms(8)));
    assert_eq!(k.carrier, Carrier::Datagram);
    assert_eq!(k.prediction, Prediction::Off);
    assert_eq!(k.keep_alive, ms(15_000));
    assert_eq!(k.reasons, vec![Reason::UserOverride]);
}

#[test]
fn user_keep_alive_pin_is_listed_as_override() {
    let o = obs(|o| o.user.keep_alive = Some(ms(7_000)));
    let k = decide(&o, &Knobs::default());
    assert_eq!(k.keep_alive, ms(7_000));
    assert!(k.reasons.contains(&Reason::UserOverride));
    // The rest stays adaptive.
    let o = obs(|o| {
        o.user.keep_alive = Some(ms(7_000));
        o.srtt = ms(100);
    });
    assert_eq!(
        decide(&o, &Knobs::default()).prediction,
        Prediction::Underline
    );
}

#[test]
fn decide_is_deterministic() {
    let o = obs(|o| {
        o.srtt = ms(70);
        o.loss = 0.03;
    });
    let p = Knobs::default();
    assert_eq!(decide(&o, &p), decide(&o, &p));
}

#[test]
fn reason_strings_match_the_decision_14_vocabulary() {
    let all = [
        (Reason::RttHigh, "rtt_high"),
        (Reason::RttLow, "rtt_low"),
        (Reason::LossHigh, "loss_high"),
        (Reason::QueueDelayHigh, "queue_delay_high"),
        (Reason::Interactive, "interactive"),
        (Reason::Bulk, "bulk"),
        (Reason::DatagramUnavailable, "datagram_unavailable"),
        (Reason::DatagramUnacked, "datagram_unacked"),
        (Reason::NatRebind, "nat_rebind"),
        (Reason::Nested, "nested"),
        (Reason::UserOverride, "user_override"),
    ];
    for (r, s) in all {
        assert_eq!(r.as_str(), s);
    }
}

// inputs from ConnStats --------------------------------------------------

#[test]
fn loss_is_lost_over_sent_growth() {
    let a = ConnStats {
        sent_packets: 1_000,
        lost_packets: Some(10),
        ..ConnStats::default()
    };
    let b = ConnStats {
        sent_packets: 2_000,
        lost_packets: Some(60),
        ..ConnStats::default()
    };
    assert!((loss_between(&a, &b) - 0.05).abs() < 1e-9);
    assert_eq!(loss_between(&b, &b), 0.0);
    let untracked = ConnStats {
        sent_packets: 3_000,
        lost_packets: None,
        ..ConnStats::default()
    };
    assert_eq!(loss_between(&a, &untracked), 0.0);
}

#[test]
fn path_stats_fill_the_observation() {
    let start = ConnStats::default();
    let now = ConnStats {
        rtt: ms(100),
        min_rtt: ms(40),
        cwnd: 250_000,
        sent_packets: 100,
        lost_packets: Some(4),
        ..ConnStats::default()
    };
    let o = Observed::default().with_path_stats(&now, &start, ms(7));
    assert_eq!(o.srtt, ms(100));
    assert_eq!(o.min_rtt, ms(40));
    assert_eq!(o.rtt_var, ms(7));
    assert_eq!(o.queue_delay(), ms(60));
    assert!((o.loss - 0.04).abs() < 1e-9);
    assert_eq!(o.est_bandwidth, Some(2_500_000));
    assert_eq!(o.bytes_in_flight, None);
    let zero = Observed::default().with_path_stats(&start, &start, Duration::ZERO);
    assert_eq!(zero.est_bandwidth, None);
}

#[test]
fn rtt_var_follows_the_samples() {
    let mut v = RttVar::default();
    assert_eq!(v.value(), Duration::ZERO);
    assert_eq!(v.update(ms(100)), ms(50)); // first sample: var = s / 2
    // A steady path decays the variation by 3/4 per sample.
    assert_eq!(v.update(ms(100)), Duration::from_micros(37_500));
    let steady = (0..60).fold(Duration::ZERO, |_, _| v.update(ms(100)));
    assert!(steady < ms(1), "{steady:?}");
    // A jump raises it again: |100 - 180| = 80 -> (3 * var + 80) / 4.
    let jumped = v.update(ms(180));
    assert!(jumped > ms(19) && jumped < ms(21), "{jumped:?}");
}

// bulk send budget -------------------------------------------------------

const YIELD: BulkYield = BulkYield::Yield {
    target: Duration::from_millis(25),
    floor_bytes_per_sec: 64 * 1024,
};

fn budget_at_2_5_mb_per_s() -> BulkBudget {
    let mut b = BulkBudget::new(Duration::ZERO);
    b.set_mode(Duration::ZERO, YIELD, Some(2_500_000));
    b
}

#[test]
fn budget_is_unlimited_while_off() {
    let mut b = BulkBudget::new(Duration::ZERO);
    assert_eq!(b.rate(), None);
    assert_eq!(b.grant(Duration::ZERO, 10_000_000), 10_000_000);
    assert_eq!(b.wait_for(Duration::ZERO, 10_000_000), Duration::ZERO);
    b.steer(ms(100), ms(500), ms(50));
    assert_eq!(b.rate(), None);
}

#[test]
fn budget_starts_at_the_bandwidth_estimate_and_halves_over_target() {
    let mut b = budget_at_2_5_mb_per_s();
    assert_eq!(b.rate(), Some(2_500_000));
    // 26 ms of queue is over the 25 ms target.
    b.steer(ms(50), ms(26), ms(50));
    assert_eq!(b.rate(), Some(1_250_000));
    b.steer(ms(100), ms(26), ms(50));
    assert_eq!(b.rate(), Some(625_000));
}

#[test]
fn budget_grows_by_two_percent_of_bandwidth_per_rtt_under_target() {
    let mut b = budget_at_2_5_mb_per_s();
    b.steer(ms(50), ms(100), ms(50)); // 1_250_000
    b.steer(ms(100), ms(25), ms(50)); // exactly at target counts as under
    assert_eq!(b.rate(), Some(1_300_000));
    b.steer(ms(150), ms(0), ms(50));
    assert_eq!(b.rate(), Some(1_350_000));
}

#[test]
fn budget_steers_at_most_once_per_rtt() {
    let mut b = budget_at_2_5_mb_per_s();
    b.steer(ms(50), ms(100), ms(50));
    let after = b.rate();
    b.steer(ms(60), ms(100), ms(50)); // 10 ms later: ignored
    b.steer(ms(99), ms(100), ms(50));
    assert_eq!(b.rate(), after);
    b.steer(ms(100), ms(100), ms(50));
    assert_eq!(b.rate(), Some(625_000));
}

#[test]
fn budget_never_goes_below_the_floor_or_above_the_estimate() {
    let mut b = budget_at_2_5_mb_per_s();
    for i in 1..=40 {
        b.steer(ms(50 * i), ms(500), ms(50));
    }
    assert_eq!(b.rate(), Some(64 * 1024));
    for i in 41..=400 {
        b.steer(ms(50 * i), ms(0), ms(50));
    }
    assert_eq!(b.rate(), Some(2_500_000));
}

#[test]
fn budget_grants_tokens_at_the_rate_and_caps_the_burst() {
    let mut b = budget_at_2_5_mb_per_s();
    b.steer(ms(50), ms(100), ms(50)); // 1_250_000 B/s
    // The bucket started full at the old rate's burst (125 000 B) and is
    // capped at the new rate's burst (62 500 B).
    assert_eq!(b.grant(ms(50), 1_000_000), 62_500);
    assert_eq!(b.grant(ms(50), 1_000), 0);
    // 10 ms refills 12 500 B.
    assert_eq!(b.grant(ms(60), 1_000_000), 12_500);
    // An idle second refills only up to one burst.
    assert_eq!(b.grant(ms(1_060), 1_000_000), 62_500);
}

#[test]
fn budget_wait_time_is_what_the_missing_tokens_need() {
    let mut b = BulkBudget::new(Duration::ZERO);
    b.set_mode(
        Duration::ZERO,
        BulkYield::Yield {
            target: ms(25),
            floor_bytes_per_sec: 64 * 1024,
        },
        Some(100_000),
    );
    assert_eq!(b.grant(Duration::ZERO, 1_000_000), 16_384); // 16 KiB minimum burst
    // 10 000 missing bytes at 100 000 B/s is 100 ms.
    assert_eq!(b.wait_for(Duration::ZERO, 10_000), ms(100));
    assert_eq!(b.wait_for(ms(100), 10_000), Duration::ZERO);
}

#[test]
fn budget_returns_to_unlimited_when_the_knob_goes_off() {
    let mut b = budget_at_2_5_mb_per_s();
    b.steer(ms(50), ms(100), ms(50));
    b.set_mode(ms(60), BulkYield::Off, Some(2_500_000));
    assert_eq!(b.rate(), None);
    assert_eq!(b.grant(ms(60), 5_000_000), 5_000_000);
    // Yielding again restarts from the estimate, not the old halved rate.
    b.set_mode(ms(2_000), YIELD, Some(2_500_000));
    assert_eq!(b.rate(), Some(2_500_000));
}

#[test]
fn budget_follows_a_shrinking_bandwidth_estimate() {
    let mut b = budget_at_2_5_mb_per_s();
    b.set_mode(ms(10), YIELD, Some(1_000_000));
    assert_eq!(b.rate(), Some(1_000_000));
}
