//! The part of the runner (ADR-0052 decision 12) that feeds the carrier
//! knob: it turns `ConnStats` snapshots and the datagram carrier's own
//! bookkeeping into an [`Observed`], runs [`decide`] about once a second
//! (and at once when a datagram update crosses the unacked threshold), and
//! keeps the [`Knobs`] for the per-update choice. It reads no clock and no
//! connection: the caller passes `now` and the snapshot, so a test drives it
//! with made-up time.
//!
//! Knob (c) and knob (e) are consumed so far; the others are decided and
//! ignored. Knob (e) is applied by the control-stream `Ping` (ADR-0052
//! decision 13): [`CarrierRunner::next_ping_at`] says when the next one is
//! due and the caller writes it.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use qsh_transport::ConnStats;

use super::{
    Carrier, DATAGRAM_RETEST_PERIOD, DATAGRAM_UNACKED_RTTS, KEEP_ALIVE_DEFAULT, KEEP_ALIVE_MIN,
    Knobs, Observed, RttVar, StreamWhy, User, decide,
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
/// A peer address change only counts as a NAT rebind (decision 12 (e)) when
/// the connection had been quiet at least this long before it. Below it the
/// change is a path switch under traffic, not a lapsed binding, and
/// `clamp(g / 2, 1 s, 15 s)` would pin the floor on a one-second gap.
pub const NAT_REBIND_MIN_IDLE: Duration = Duration::from_secs(2);

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
    /// Where the peer was last seen, whether it moved since the last
    /// receive, and the idle time of a rebind not yet fed to [`decide`].
    peer: Option<SocketAddr>,
    rebind_pending: bool,
    rebind_idle: Option<Duration>,
    /// When the last keep-alive `Ping` went out.
    last_ping: Option<Instant>,
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
            peer: None,
            rebind_pending: false,
            rebind_idle: None,
            last_ping: None,
        }
    }

    /// Report where the peer's packets come from. A change since the last
    /// report is a NAT rebind when the connection had been idle: the idle
    /// time `g` is measured to the next [`Self::tick`] that sees the
    /// connection receive again.
    pub fn observe_peer(&mut self, addr: SocketAddr) {
        if self.peer.is_some_and(|p| p != addr) {
            self.rebind_pending = true;
        }
        self.peer = Some(addr);
    }

    /// Record a rebind after `idle` of quiet without a real address change
    /// (test hook: `Server::inject_nat_rebind`).
    pub fn inject_nat_rebind(&mut self, idle: Duration) {
        self.rebind_idle = Some(idle);
    }

    /// When the next keep-alive `Ping` is due, or `None` when quinn's own
    /// keep-alive is the whole story: the user pinned the interval, or the
    /// policy has not shortened it below the 15 s the transport already
    /// uses. Quinn's timer keeps running underneath, so this only ever adds
    /// pings, never replaces them (ADR-0052 decision 13: the interval can
    /// only get shorter).
    pub fn next_ping_at(&self) -> Option<Instant> {
        if self.user.keep_alive.is_some() {
            return None;
        }
        let every = self.knobs.keep_alive;
        if every >= KEEP_ALIVE_DEFAULT {
            return None;
        }
        // Defence in depth: never faster than ADR-0021's floor.
        let every = every.max(KEEP_ALIVE_MIN);
        Some(self.last_ping.unwrap_or(self.last_rx_moved) + every)
    }

    /// Whether a keep-alive `Ping` is due at `now`.
    pub fn ping_due(&self, now: Instant) -> bool {
        self.next_ping_at().is_some_and(|at| at <= now)
    }

    /// The caller wrote a keep-alive `Ping`.
    pub fn ping_sent(&mut self, now: Instant) {
        self.last_ping = Some(now);
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
            let quiet = now.duration_since(self.last_rx_moved);
            if self.rebind_pending && quiet >= NAT_REBIND_MIN_IDLE {
                self.rebind_idle = Some(quiet);
            }
            self.rebind_pending = false;
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
            nat_rebind_after_idle: self.rebind_idle.take(),
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

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    /// Drive a rebind after `quiet` of silence and return the runner.
    fn after_rebind(user: User, quiet: Duration) -> (CarrierRunner, Instant) {
        let t0 = Instant::now();
        let mut r = CarrierRunner::new(t0, user);
        r.observe_peer(addr(1000));
        r.tick(t0, stats(20, 1), false, None);
        // Silence, then traffic from a new address.
        r.observe_peer(addr(2000));
        let t1 = t0 + quiet;
        r.tick(t1, stats(20, 2), false, None);
        (r, t1)
    }

    #[test]
    fn no_ping_is_scheduled_until_the_policy_shortens_the_interval() {
        let t0 = Instant::now();
        let mut r = CarrierRunner::new(t0, User::default());
        r.tick(t0, stats(20, 1), false, None);
        assert_eq!(r.next_ping_at(), None);
        assert!(!r.ping_due(t0 + secs(60)));
    }

    #[test]
    fn a_rebind_after_a_quiet_spell_schedules_pings_at_half_the_gap() {
        let (mut r, t1) = after_rebind(User::default(), secs(10));
        assert_eq!(r.knobs().keep_alive, secs(5));
        assert!(r.knobs().reasons.contains(&super::super::Reason::NatRebind));
        // Anchored on the last frame received, then on the last ping.
        assert_eq!(r.next_ping_at(), Some(t1 + secs(5)));
        assert!(!r.ping_due(t1 + Duration::from_millis(4999)));
        assert!(r.ping_due(t1 + secs(5)));
        r.ping_sent(t1 + secs(5));
        assert_eq!(r.next_ping_at(), Some(t1 + secs(10)));
    }

    #[test]
    fn a_pinned_interval_never_gets_a_policy_ping() {
        let user = User {
            keep_alive: Some(secs(8)),
            ..User::default()
        };
        let (r, t1) = after_rebind(user, secs(10));
        assert_eq!(r.knobs().keep_alive, secs(8));
        assert_eq!(r.next_ping_at(), None);
        assert!(!r.ping_due(t1 + secs(600)));
    }

    #[test]
    fn a_change_under_traffic_or_in_the_same_second_is_not_a_rebind() {
        let (r, _) = after_rebind(User::default(), Duration::from_millis(1500));
        assert_eq!(r.knobs().keep_alive, KEEP_ALIVE_DEFAULT);
        assert_eq!(r.next_ping_at(), None);
        // Exactly at the idle floor it counts, and the interval is clamped
        // up to ADR-0021's 1 s.
        let (r, _) = after_rebind(User::default(), NAT_REBIND_MIN_IDLE);
        assert_eq!(r.knobs().keep_alive, KEEP_ALIVE_MIN);
    }

    #[test]
    fn the_same_address_is_not_a_rebind() {
        let t0 = Instant::now();
        let mut r = CarrierRunner::new(t0, User::default());
        r.observe_peer(addr(1000));
        r.tick(t0, stats(20, 1), false, None);
        r.observe_peer(addr(1000));
        r.tick(t0 + secs(30), stats(20, 2), false, None);
        assert_eq!(r.knobs().keep_alive, KEEP_ALIVE_DEFAULT);
    }
}
