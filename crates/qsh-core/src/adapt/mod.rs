//! Adaptive transport policy (ADR-0052 decisions 12, 13 and 15).
//!
//! [`decide`] is a pure function: it reads no clock and does no I/O, so one
//! table (`tests.rs`) pins every threshold. [`CarrierRunner`] calls it once a
//! second, and on threshold crossings, for knob (c) only; the runner for the
//! other knobs is not in this module.
//! `previous` is the last [`Knobs`] and is used only for hysteresis and for
//! the "shorten, never lengthen" keep-alive memory.
//!
//! Numbers the ADR states are used as stated. Where it leaves one open, the
//! choice is a constant below marked "Open number", with the reason beside it.

mod budget;
mod governor;
mod monitor;
mod rtt;
mod runner;
#[cfg(test)]
mod tests;

use std::time::Duration;

use qsh_transport::ConnStats;

pub use budget::BulkBudget;
pub use governor::{
    BULK_WINDOW, BulkGovernor, EVALUATE_PERIOD, GovernorCore, INTERACTIVE_WINDOW, MAX_PARK,
    PACE_GRANULE, Pace, process_adaptive, set_process_adaptive,
};
pub use monitor::{
    PolicyMonitor, PolicySampler, Sample, TARGET, screen_sync_label, to_json_line, transport_report,
};
pub use rtt::RttVar;
pub use runner::{
    ALIVE_WINDOW, CarrierRunner, KeepAliveMemory, LOSS_WINDOW, RTT_FLOOR, TICK, Tick,
};

/// Decision 12 (a): LEDBAT-like queue delay target.
pub const YIELD_TARGET: Duration = Duration::from_millis(25);
/// Decision 12 (a): starvation floor, absolute part.
pub const YIELD_FLOOR_BYTES_PER_SEC: u64 = 64 * 1024;
/// Decision 12 (a): starvation floor, share of the estimated bandwidth.
pub const YIELD_FLOOR_PERCENT: u64 = 5;

/// Decision 12 (b): screen update interval lower bound.
pub const FRAME_INTERVAL_MIN: Duration = Duration::from_millis(20);
/// Decision 12 (b): screen update interval upper bound.
pub const FRAME_INTERVAL_MAX: Duration = Duration::from_millis(250);
/// Decision 12 (b): collection time lower bound after the first change.
pub const COLLECT_MIN: Duration = Duration::from_millis(1);
/// Decision 12 (b): collection time upper bound.
pub const COLLECT_MAX: Duration = Duration::from_millis(8);
/// Open number: the interval used when `adaptive = "off"`. mosh's
/// `SEND_INTERVAL_MIN`, the value it settles on for a fast path.
pub const FIXED_FRAME_INTERVAL: Duration = Duration::from_millis(20);
/// Open number: the collection time used when `adaptive = "off"`. mosh's
/// `SEND_MINDELAY`.
pub const FIXED_COLLECT: Duration = Duration::from_millis(8);

/// Decision 12 (c): a datagram update unacked for more than this many
/// smoothed RTTs, while the stream is acked, means the path eats datagrams.
pub const DATAGRAM_UNACKED_RTTS: u32 = 4;
/// Decision 12 (c): the all-parts-arrive probability below which one update
/// goes over the stream.
pub const FRAGMENT_DELIVERY_MIN: f64 = 0.5;
/// Decision 12 (c): how often the runner re-tests datagrams after
/// `datagram_unacked`. The runner owns the clock and raises
/// [`Observed::datagram_probe_due`] on this period.
pub const DATAGRAM_RETEST_PERIOD: Duration = Duration::from_secs(30);

/// Decision 12 (d): prediction goes on above this.
pub const PREDICT_ON_ABOVE: Duration = Duration::from_millis(30);
/// Decision 12 (d): prediction goes off below this.
pub const PREDICT_OFF_BELOW: Duration = Duration::from_millis(20);
/// Decision 12 (d): underline goes on above this.
pub const UNDERLINE_ON_ABOVE: Duration = Duration::from_millis(80);
/// Decision 12 (d): underline drops back to plain display below this.
pub const UNDERLINE_OFF_BELOW: Duration = Duration::from_millis(50);

/// Decision 12 (e): keep-alive start value and ceiling for shortening
/// (ADR-0021).
pub const KEEP_ALIVE_DEFAULT: Duration = Duration::from_millis(15_000);
/// ADR-0021 decision 1 lower bound.
pub const KEEP_ALIVE_MIN: Duration = Duration::from_millis(1_000);
/// ADR-0021 decision 1 upper bound (only reachable through the user key).
pub const KEEP_ALIVE_MAX: Duration = Duration::from_millis(20_000);

/// Open number: loss rate at or above which `loss_high` is listed in
/// [`Knobs::reasons`]. Diagnostic only; no rule reads it.
pub const LOSS_HIGH_REASON: f64 = 0.02;

/// `--predict` as a pin on knob (d) (ADR-0053 decision 11). `auto` pins
/// nothing and is `None` in [`User::prediction`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredictPin {
    /// At least [`Prediction::Display`], whatever the RTT and
    /// `[transport].adaptive` say.
    Always,
    /// [`Prediction::Off`].
    Never,
}

/// What the user pinned (decision 15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct User {
    /// `[transport].adaptive`; `false` is `"off"`.
    pub adaptive: bool,
    /// `[transport].keep_alive_ms`, when set.
    pub keep_alive: Option<Duration>,
    /// `--predict`, when not `auto` (ADR-0053 decision 11).
    pub prediction: Option<PredictPin>,
}

impl User {
    /// The pins of this process: `[transport].adaptive` as
    /// [`set_process_adaptive`] last set it, and no keep-alive pin. Callers
    /// that know the keep-alive pin override it with struct update syntax.
    pub fn from_process() -> Self {
        Self {
            adaptive: process_adaptive(),
            keep_alive: None,
            prediction: None,
        }
    }
}

impl Default for User {
    fn default() -> Self {
        Self {
            adaptive: true,
            keep_alive: None,
            prediction: None,
        }
    }
}

/// One second of observations for one connection (decision 12 input).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Observed {
    /// Smoothed RTT.
    pub srtt: Duration,
    /// RTT variation (see [`RttVar`]). Carried for `qsh doctor` and the
    /// `qsh::adapt` log; no rule reads it.
    pub rtt_var: Duration,
    /// Smallest RTT over the recent window.
    pub min_rtt: Duration,
    /// Loss rate over the last 5 s, in `0.0..=1.0`.
    pub loss: f64,
    /// Estimated path bandwidth in bytes per second, if known.
    pub est_bandwidth: Option<u64>,
    /// Bytes in flight; quinn 0.11 does not publish it, so it stays `None`.
    pub bytes_in_flight: Option<u64>,
    /// Key input or a screen update within the last 2 s.
    pub interactive: bool,
    /// Tunnel or file stream bytes moved within the last second.
    pub bulk: bool,
    /// `max_datagram_size()` is `Some` and `datagram.v1` is negotiated.
    pub datagram: bool,
    /// Age of the oldest screen update sent as a datagram and still unacked,
    /// or `None` when nothing is outstanding. The runner restarts it when a
    /// probe goes out.
    pub datagram_unacked_for: Option<Duration>,
    /// Stream acks arrived recently, so the connection itself is alive.
    pub stream_acks_flowing: bool,
    /// [`DATAGRAM_RETEST_PERIOD`] has passed since the last probe.
    pub datagram_probe_due: bool,
    /// The connection rides inside a jump or proxy (always false in M22).
    pub nested: bool,
    /// The outer connection has a datagram path (meaningful when `nested`).
    pub outer_datagram: bool,
    /// Idle time `g` after which a peer address change (NAT rebind) was
    /// seen, when one was.
    pub nat_rebind_after_idle: Option<Duration>,
    /// User pins.
    pub user: User,
}

impl Default for Observed {
    fn default() -> Self {
        Self {
            srtt: Duration::ZERO,
            rtt_var: Duration::ZERO,
            min_rtt: Duration::ZERO,
            loss: 0.0,
            est_bandwidth: None,
            bytes_in_flight: None,
            interactive: false,
            bulk: false,
            datagram: false,
            datagram_unacked_for: None,
            stream_acks_flowing: true,
            datagram_probe_due: false,
            nested: false,
            outer_datagram: false,
            nat_rebind_after_idle: None,
            user: User::default(),
        }
    }
}

impl Observed {
    /// `srtt - min_rtt`, zero when the minimum is above the smoothed value.
    pub fn queue_delay(&self) -> Duration {
        self.srtt.saturating_sub(self.min_rtt)
    }

    /// Fill the path fields from two [`ConnStats`] snapshots: `now`, and
    /// `window_start` taken about 5 s earlier (the loss window). `rtt_var`
    /// comes from [`RttVar`] because quinn does not publish it. The
    /// bandwidth estimate is `cwnd / srtt`.
    #[must_use]
    pub fn with_path_stats(
        mut self,
        now: &ConnStats,
        window_start: &ConnStats,
        rtt_var: Duration,
    ) -> Self {
        self.srtt = now.rtt;
        self.rtt_var = rtt_var;
        self.min_rtt = now.min_rtt;
        self.loss = loss_between(window_start, now);
        let secs = now.rtt.as_secs_f64();
        self.est_bandwidth = (secs > 0.0 && now.cwnd > 0).then(|| (now.cwnd as f64 / secs) as u64);
        self
    }
}

/// `lost_packets` growth over `sent_packets` growth between two snapshots.
/// Zero when nothing was sent or the backend does not count losses.
pub fn loss_between(start: &ConnStats, end: &ConnStats) -> f64 {
    let sent = end.sent_packets.saturating_sub(start.sent_packets);
    let lost = end
        .lost_packets
        .unwrap_or(0)
        .saturating_sub(start.lost_packets.unwrap_or(0));
    if sent == 0 {
        0.0
    } else {
        (lost as f64 / sent as f64).min(1.0)
    }
}

/// Knob (a).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkYield {
    /// Bulk runs at full speed.
    Off,
    /// Bulk follows the LEDBAT-like budget ([`BulkBudget`]).
    Yield {
        /// Queue delay the budget steers towards.
        target: Duration,
        /// Starvation floor in bytes per second.
        floor_bytes_per_sec: u64,
    },
}

/// Why a screen update goes over the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamWhy {
    /// No datagram layer or capability.
    DatagramUnavailable,
    /// The path dropped datagram updates while the stream was acked.
    DatagramUnacked,
    /// This update has too many parts to arrive whole.
    FragmentsLossy,
}

/// Knob (c) and (f): where a message travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// QUIC DATAGRAM.
    Datagram,
    /// The ordered stream.
    Stream(StreamWhy),
}

/// Knob (d). The order is the order of aggressiveness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Prediction {
    /// No local prediction.
    Off,
    /// Predictions applied silently.
    Display,
    /// Predictions applied and underlined.
    Underline,
}

/// Why a knob has its value (decision 14's `reasons` vocabulary).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Prediction is on because the RTT is high.
    RttHigh,
    /// The RTT is below the prediction-off threshold.
    RttLow,
    /// Loss at or above [`LOSS_HIGH_REASON`].
    LossHigh,
    /// `queue_delay` is above the yield target.
    QueueDelayHigh,
    /// Interactive traffic is present while yielding.
    Interactive,
    /// Bulk traffic is present while yielding.
    Bulk,
    /// No datagram path.
    DatagramUnavailable,
    /// The path eats datagrams.
    DatagramUnacked,
    /// Keep-alive shortened after a NAT rebind.
    NatRebind,
    /// The connection is nested.
    Nested,
    /// A user pin decided a knob.
    UserOverride,
}

impl Reason {
    /// The string used in `DoctorData.transport.reasons`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RttHigh => "rtt_high",
            Self::RttLow => "rtt_low",
            Self::LossHigh => "loss_high",
            Self::QueueDelayHigh => "queue_delay_high",
            Self::Interactive => "interactive",
            Self::Bulk => "bulk",
            Self::DatagramUnavailable => "datagram_unavailable",
            Self::DatagramUnacked => "datagram_unacked",
            Self::NatRebind => "nat_rebind",
            Self::Nested => "nested",
            Self::UserOverride => "user_override",
        }
    }
}

/// Policy output (decision 12). Comparable, so the runner logs only changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Knobs {
    /// (a) bulk yielding.
    pub bulk_yield: BulkYield,
    /// (b) minimum time between screen updates.
    pub frame_interval: Duration,
    /// (b) time to collect changes after the first one.
    pub collect: Duration,
    /// (c) base carrier; per-update demotion is [`Knobs::carrier_for_update`].
    pub carrier: Carrier,
    /// Loss rate in parts per thousand, kept so the per-update rule needs
    /// no other input.
    pub loss_permille: u16,
    /// (d) prediction.
    pub prediction: Prediction,
    /// (e) keep-alive interval.
    pub keep_alive: Duration,
    /// (f) carrier for the outer connection, `None` when not nested.
    pub outer_carrier: Option<Carrier>,
    /// Why, for doctor and the `qsh::adapt` log.
    pub reasons: Vec<Reason>,
}

impl Default for Knobs {
    /// The state before the first [`decide`]: today's behavior.
    fn default() -> Self {
        Self {
            bulk_yield: BulkYield::Off,
            frame_interval: FIXED_FRAME_INTERVAL,
            collect: FIXED_COLLECT,
            carrier: Carrier::Stream(StreamWhy::DatagramUnavailable),
            loss_permille: 0,
            prediction: Prediction::Off,
            keep_alive: KEEP_ALIVE_DEFAULT,
            outer_carrier: None,
            reasons: Vec::new(),
        }
    }
}

impl Knobs {
    /// Carrier for one screen update of `parts` parts: the base carrier,
    /// except that a datagram update whose parts are unlikely to all arrive,
    /// `(1 - loss)^parts < 0.5`, goes over the stream.
    pub fn carrier_for_update(&self, parts: u32) -> Carrier {
        match self.carrier {
            Carrier::Datagram => {
                let delivery = (1.0 - f64::from(self.loss_permille) / 1000.0)
                    .powi(i32::try_from(parts).unwrap_or(i32::MAX));
                if delivery < FRAGMENT_DELIVERY_MIN {
                    Carrier::Stream(StreamWhy::FragmentsLossy)
                } else {
                    Carrier::Datagram
                }
            }
            stream => stream,
        }
    }
}

/// The policy. Pure: same inputs, same output.
pub fn decide(observed: &Observed, previous: &Knobs) -> Knobs {
    let mut reasons = Vec::new();
    let adaptive = observed.user.adaptive;
    if !adaptive {
        reasons.push(Reason::UserOverride);
    }
    let srtt = observed.srtt;

    // (a) bulk yielding
    let bulk_yield = if adaptive && observed.interactive && observed.bulk {
        reasons.extend([Reason::Interactive, Reason::Bulk]);
        let floor = YIELD_FLOOR_BYTES_PER_SEC.max(
            observed
                .est_bandwidth
                .map_or(0, |bw| bw / 100 * YIELD_FLOOR_PERCENT),
        );
        BulkYield::Yield {
            target: YIELD_TARGET,
            floor_bytes_per_sec: floor,
        }
    } else {
        BulkYield::Off
    };
    if adaptive && observed.queue_delay() > YIELD_TARGET {
        reasons.push(Reason::QueueDelayHigh);
    }

    // (b) screen update interval
    let (frame_interval, collect) = if adaptive {
        (
            (srtt / 2).clamp(FRAME_INTERVAL_MIN, FRAME_INTERVAL_MAX),
            (srtt / 8).clamp(COLLECT_MIN, COLLECT_MAX),
        )
    } else {
        (FIXED_FRAME_INTERVAL, FIXED_COLLECT)
    };

    // (c) carrier
    let carrier = if !observed.datagram {
        reasons.push(Reason::DatagramUnavailable);
        Carrier::Stream(StreamWhy::DatagramUnavailable)
    } else if !adaptive {
        Carrier::Datagram
    } else {
        let stuck_now = observed.stream_acks_flowing
            && observed
                .datagram_unacked_for
                .is_some_and(|age| age > srtt * DATAGRAM_UNACKED_RTTS);
        let held = previous.carrier == Carrier::Stream(StreamWhy::DatagramUnacked)
            && !observed.datagram_probe_due;
        if stuck_now || held {
            reasons.push(Reason::DatagramUnacked);
            Carrier::Stream(StreamWhy::DatagramUnacked)
        } else {
            Carrier::Datagram
        }
    };
    if adaptive && observed.loss >= LOSS_HIGH_REASON {
        reasons.push(Reason::LossHigh);
    }
    let loss_permille = (observed.loss.clamp(0.0, 1.0) * 1000.0).round() as u16;

    // (d) prediction, with hysteresis through `previous`
    let by_rtt = if srtt > UNDERLINE_ON_ABOVE {
        Prediction::Underline
    } else if srtt > PREDICT_ON_ABOVE {
        if previous.prediction == Prediction::Underline && srtt >= UNDERLINE_OFF_BELOW {
            Prediction::Underline
        } else {
            Prediction::Display
        }
    } else if srtt < PREDICT_OFF_BELOW {
        Prediction::Off
    } else {
        // 20..=30 ms: keep the previous state, but never underline this low.
        previous.prediction.min(Prediction::Display)
    };
    // `--predict` beats `[transport].adaptive` (ADR-0053 decision 11).
    let prediction = match observed.user.prediction {
        Some(PredictPin::Always) => by_rtt.max(Prediction::Display),
        Some(PredictPin::Never) => Prediction::Off,
        None if adaptive => by_rtt,
        None => Prediction::Off,
    };
    if observed.user.prediction.is_some() {
        reasons.push(Reason::UserOverride);
    } else if adaptive {
        if prediction != Prediction::Off {
            reasons.push(Reason::RttHigh);
        } else if srtt < PREDICT_OFF_BELOW {
            reasons.push(Reason::RttLow);
        }
    }

    // (e) keep-alive: only shorter, and only when the user left it unset.
    let keep_alive = if let Some(pinned) = observed.user.keep_alive {
        reasons.push(Reason::UserOverride);
        pinned.clamp(KEEP_ALIVE_MIN, KEEP_ALIVE_MAX)
    } else if !adaptive {
        KEEP_ALIVE_DEFAULT
    } else {
        let remembered = previous
            .keep_alive
            .clamp(KEEP_ALIVE_MIN, KEEP_ALIVE_DEFAULT);
        match observed.nat_rebind_after_idle {
            Some(g) => {
                let shorter = (g / 2).clamp(KEEP_ALIVE_MIN, KEEP_ALIVE_DEFAULT);
                if shorter < remembered {
                    reasons.push(Reason::NatRebind);
                }
                remembered.min(shorter)
            }
            None => remembered,
        }
    };

    // (f) outer carrier. Structural rather than tuned, so `adaptive = "off"`
    // does not change it.
    let outer_carrier = observed.nested.then(|| {
        reasons.push(Reason::Nested);
        if observed.outer_datagram {
            Carrier::Datagram
        } else {
            Carrier::Stream(StreamWhy::DatagramUnavailable)
        }
    });

    Knobs {
        bulk_yield,
        frame_interval,
        collect,
        carrier,
        loss_permille,
        prediction,
        keep_alive,
        outer_carrier,
        reasons,
    }
}
