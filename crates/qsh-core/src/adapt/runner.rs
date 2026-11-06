//! The part of the runner (ADR-0052 decision 12) that feeds the carrier
//! knob: it turns `ConnStats` snapshots and the datagram carrier's own
//! bookkeeping into an [`Observed`], runs [`decide`] about once a second
//! (and at once when a datagram update crosses the unacked threshold), and
//! keeps the [`Knobs`] for the per-update choice. It reads no clock and no
//! connection: the caller passes `now` and the snapshot, so a test drives it
//! with made-up time.
//!
//! Only knob (c) is consumed so far; the others are decided and ignored.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use qsh_transport::ConnStats;

use super::{
    Carrier, DATAGRAM_RETEST_PERIOD, DATAGRAM_UNACKED_RTTS, Knobs, Observed, RttVar, StreamWhy,
    User, decide,
};

/// How often [`decide`] runs.
pub const TICK: Duration = Duration::from_secs(1);
/// Loss is measured over this window (decision 12, `loss`).
pub const LOSS_WINDOW: Duration = Duration::from_secs(5);
/// The RTT the unacked rule uses is never below this. A loopback RTT of
/// 0.1 ms would make "4 smoothed RTTs" shorter than one scheduler tick of
/// the peer that has to ack, and flip a healthy path to the stream.
pub const RTT_FLOOR: Duration = Duration::from_millis(50);
/// The connection counts as alive for the unacked rule while an
/// authenticated frame arrived this recently. Longer than the 15 s
/// keep-alive, so an idle but healthy connection still counts.
pub const ALIVE_WINDOW: Duration = Duration::from_secs(20);

/// Per-connection state for the carrier knob.
#[derive(Debug)]
pub struct CarrierRunner {
    knobs: Knobs,
    rtt_var: RttVar,
    window: VecDeque<(Instant, ConnStats)>,
    last_tick: Option<Instant>,
    last_datagram: bool,
    stuck_since: Option<Instant>,
    last_rx: u64,
    last_rx_moved: Instant,
    user: User,
}

/// What a [`CarrierRunner::tick`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tick {
    /// [`decide`] ran.
    pub ran: bool,
    /// The knobs went back from `Stream(datagram_unacked)` to `Datagram`
    /// for a re-test: the caller restarts its unacked clock.
    pub retest_started: bool,
    /// The carrier knob changed.
    pub carrier_changed: bool,
}

impl CarrierRunner {
    /// A runner that starts on the stream until the first tick says
    /// otherwise.
    pub fn new(now: Instant, user: User) -> Self {
        Self {
            knobs: Knobs::default(),
            rtt_var: RttVar::default(),
            window: VecDeque::new(),
            last_tick: None,
            last_datagram: false,
            stuck_since: None,
            last_rx: 0,
            last_rx_moved: now,
            user,
        }
    }

    /// The current knobs.
    pub fn knobs(&self) -> &Knobs {
        &self.knobs
    }

    /// Carrier for one update of `parts` parts (`Knobs::carrier_for_update`).
    pub fn carrier_for_update(&self, parts: u32) -> Carrier {
        self.knobs.carrier_for_update(parts)
    }

    /// Feed one observation. `datagram` is whether datagrams are usable at
    /// all (capability negotiated, `max_datagram_size()` is `Some`, the peer
    /// has shown it sends datagrams); `unacked_for` is the age of the oldest
    /// datagram update still unacked.
    pub fn tick(
        &mut self,
        now: Instant,
        stats: ConnStats,
        datagram: bool,
        unacked_for: Option<Duration>,
    ) -> Tick {
        if stats.rx_frames != self.last_rx {
            self.last_rx = stats.rx_frames;
            self.last_rx_moved = now;
        }
        self.window.push_back((now, stats));
        while self.window.len() > 2
            && self
                .window
                .get(1)
                .is_some_and(|(t, _)| now.duration_since(*t) >= LOSS_WINDOW)
        {
            self.window.pop_front();
        }
        let srtt = stats.rtt.max(RTT_FLOOR);
        let crossing = !matches!(
            self.knobs.carrier,
            Carrier::Stream(StreamWhy::DatagramUnacked)
        ) && unacked_for.is_some_and(|age| age > srtt * DATAGRAM_UNACKED_RTTS);
        let due = self.last_tick.is_none_or(|t| now.duration_since(t) >= TICK);
        // Datagrams becoming usable (or not) is a threshold crossing too:
        // waiting for the next tick would leave the first second on the
        // stream.
        let flipped = datagram != self.last_datagram;
        if !due && !crossing && !flipped {
            return Tick::default();
        }
        self.last_tick = Some(now);
        self.last_datagram = datagram;
        let rtt_var = self.rtt_var.update(stats.rtt);
        let start = self.window.front().map_or(stats, |(_, s)| *s);
        let mut observed = Observed {
            datagram,
            datagram_unacked_for: unacked_for,
            stream_acks_flowing: now.duration_since(self.last_rx_moved) < ALIVE_WINDOW,
            datagram_probe_due: self
                .stuck_since
                .is_some_and(|t| now.duration_since(t) >= DATAGRAM_RETEST_PERIOD),
            user: self.user,
            ..Observed::default()
        }
        .with_path_stats(&stats, &start, rtt_var);
        observed.srtt = observed.srtt.max(RTT_FLOOR);
        let before = self.knobs.carrier;
        self.knobs = decide(&observed, &self.knobs);
        let after = self.knobs.carrier;
        let stuck = matches!(after, Carrier::Stream(StreamWhy::DatagramUnacked));
        let was_stuck = matches!(before, Carrier::Stream(StreamWhy::DatagramUnacked));
        if stuck && !was_stuck {
            self.stuck_since = Some(now);
        } else if !stuck {
            self.stuck_since = None;
        }
        Tick {
            ran: true,
            retest_started: was_stuck && !stuck && datagram,
            carrier_changed: before != after,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(rtt_ms: u64, rx: u64) -> ConnStats {
        ConnStats {
            rtt: Duration::from_millis(rtt_ms),
            rx_frames: rx,
            ..ConnStats::default()
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn datagram_is_chosen_once_usable_and_the_stream_before() {
        let t0 = Instant::now();
        let mut r = CarrierRunner::new(t0, User::default());
        assert_eq!(
            r.knobs().carrier,
            Carrier::Stream(StreamWhy::DatagramUnavailable)
        );
        let tick = r.tick(t0, stats(20, 1), false, None);
        assert!(tick.ran && !tick.carrier_changed);
        assert_eq!(
            r.carrier_for_update(1),
            Carrier::Stream(StreamWhy::DatagramUnavailable)
        );
        let tick = r.tick(t0 + secs(1), stats(20, 2), true, None);
        assert!(tick.carrier_changed);
        assert_eq!(r.carrier_for_update(1), Carrier::Datagram);
    }

    #[test]
    fn it_runs_once_a_second_not_on_every_call() {
        let t0 = Instant::now();
        let mut r = CarrierRunner::new(t0, User::default());
        assert!(r.tick(t0, stats(20, 1), true, None).ran);
        assert!(
            !r.tick(t0 + Duration::from_millis(300), stats(20, 1), true, None)
                .ran
        );
        assert!(r.tick(t0 + secs(1), stats(20, 1), true, None).ran);
    }

    #[test]
    fn an_unacked_datagram_falls_back_at_once_and_is_retested_every_30_s() {
        let t0 = Instant::now();
        let mut r = CarrierRunner::new(t0, User::default());
        r.tick(t0, stats(20, 1), true, None);
        assert_eq!(r.carrier_for_update(1), Carrier::Datagram);
        // 4 x max(20 ms, 50 ms floor) = 200 ms: below it nothing happens.
        let t1 = t0 + Duration::from_millis(100);
        assert!(
            !r.tick(t1, stats(20, 2), true, Some(Duration::from_millis(150)))
                .ran
        );
        // Above it the threshold crossing runs decide between ticks.
        let t2 = t0 + Duration::from_millis(300);
        let tick = r.tick(t2, stats(20, 3), true, Some(Duration::from_millis(250)));
        assert!(tick.ran && tick.carrier_changed);
        assert_eq!(
            r.carrier_for_update(1),
            Carrier::Stream(StreamWhy::DatagramUnacked)
        );
        // Held through the next ticks, even with a clean unacked clock.
        r.tick(t0 + secs(2), stats(20, 4), true, None);
        assert_eq!(
            r.carrier_for_update(1),
            Carrier::Stream(StreamWhy::DatagramUnacked)
        );
        // After the retest period the datagram is tried again.
        let tick = r.tick(t2 + DATAGRAM_RETEST_PERIOD, stats(20, 5), true, None);
        assert!(tick.retest_started && tick.carrier_changed);
        assert_eq!(r.carrier_for_update(1), Carrier::Datagram);
    }

    #[test]
    fn a_dead_connection_is_not_blamed_on_datagrams() {
        let t0 = Instant::now();
        let mut r = CarrierRunner::new(t0, User::default());
        r.tick(t0, stats(20, 1), true, None);
        // No authenticated frame for longer than the alive window.
        let late = t0 + ALIVE_WINDOW + secs(1);
        r.tick(late, stats(20, 1), true, Some(secs(5)));
        assert_eq!(r.carrier_for_update(1), Carrier::Datagram);
    }

    #[test]
    fn many_parts_under_loss_go_over_the_stream_for_that_update_only() {
        let t0 = Instant::now();
        let mut r = CarrierRunner::new(t0, User::default());
        let mut lossy = stats(20, 1);
        r.tick(t0, lossy, true, None);
        lossy.sent_packets = 1000;
        lossy.lost_packets = Some(50);
        r.tick(t0 + secs(1), lossy, true, None);
        assert_eq!(r.carrier_for_update(2), Carrier::Datagram);
        assert_eq!(
            r.carrier_for_update(20),
            Carrier::Stream(StreamWhy::FragmentsLossy)
        );
    }
}
