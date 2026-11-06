//! What the policy decided, made visible (ADR-0052 decision 14): the
//! `transport` object of `qsh doctor <host>` and the `qsh::adapt` stderr
//! line of an interactive client share one report type and one sampler.
//!
//! [`PolicySampler`] has no clock and no connection: the caller passes `now`
//! and a [`ConnStats`] snapshot, so a test drives it with made-up time and
//! the doctor drives it with a few snapshots of a measurement connection.
//! [`PolicyMonitor`] binds one to a live client connection and a tokio timer.
//!
//! Nothing here can carry PTY content or key material: the report is
//! statistics and knob values.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use qsh_proto::DoctorTransport;
use qsh_transport::{ConnStats, Connection};

use super::{
    BulkGovernor, BulkYield, Carrier, Knobs, LOSS_WINDOW, Observed, Prediction, RttVar, TICK, User,
    decide, loss_between,
};

/// The tracing target of the stderr line (ADR-0052 decision 14). The CLI
/// prints the line as it is, with no level, timestamp or target prefix, the
/// way it prints `qsh::recovery`.
pub const TARGET: &str = "qsh::adapt";

/// `screen_sync` of the report: `"datagram"`, `"stream"` or `"off"`.
pub fn screen_sync_label(screen_sync: bool, carrier: Carrier) -> &'static str {
    match (screen_sync, carrier) {
        (false, _) => "off",
        (true, Carrier::Datagram) => "datagram",
        (true, Carrier::Stream(_)) => "stream",
    }
}

fn ms(d: Duration) -> f64 {
    // One decimal is the resolution anybody can act on; it also keeps the
    // fixture and the stderr line free of float noise.
    (d.as_secs_f64() * 10_000.0).round() / 10.0
}

/// Build the `transport` report from one policy step.
pub fn transport_report(
    observed: &Observed,
    knobs: &Knobs,
    screen_sync: bool,
    max_datagram: Option<usize>,
) -> DoctorTransport {
    let mut reasons: Vec<String> = Vec::new();
    for reason in &knobs.reasons {
        let name = reason.as_str();
        if !reasons.iter().any(|r| r == name) {
            reasons.push(name.to_string());
        }
    }
    DoctorTransport {
        rtt_ms: ms(observed.srtt),
        rtt_var_ms: ms(observed.rtt_var),
        min_rtt_ms: ms(observed.min_rtt),
        loss_pct: (observed.loss * 1000.0).round() / 10.0,
        max_datagram_bytes: max_datagram.map(|n| n as u64),
        screen_sync: screen_sync_label(screen_sync, knobs.carrier).to_string(),
        frame_interval_ms: u64::try_from(knobs.frame_interval.as_millis()).unwrap_or(u64::MAX),
        bulk_yield: match knobs.bulk_yield {
            BulkYield::Off => "off",
            BulkYield::Yield { .. } => "yield",
        }
        .to_string(),
        prediction: match knobs.prediction {
            Prediction::Off => "off",
            Prediction::Display => "display",
            Prediction::Underline => "underline",
        }
        .to_string(),
        keep_alive_ms: u64::try_from(knobs.keep_alive.as_millis()).unwrap_or(u64::MAX),
        nested: observed.nested,
        reasons,
    }
}

/// The one-line JSON record of the `qsh::adapt` target: `{"adapt":"policy"`
/// followed by the report's fields in their declared order, no newline.
pub fn to_json_line(report: &DoctorTransport) -> String {
    let body = serde_json::to_string(report).unwrap_or_else(|_| "{}".to_string());
    // `body` is `{...}`; the marker goes in front of its first field.
    let inner = body.trim_start_matches('{');
    format!(r#"{{"adapt":"policy",{inner}"#)
}

/// What a [`PolicySampler::step`] produced.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    /// The report for this step.
    pub report: DoctorTransport,
    /// A discrete knob (screen carrier, bulk yield, prediction, keep-alive,
    /// datagram availability) differs from the step before, or this is the
    /// first step. The continuously varying values (RTT, frame interval)
    /// do not count: a line per RTT jitter would bury the ones that matter.
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Discrete {
    screen_sync: String,
    bulk_yield: String,
    prediction: String,
    keep_alive_ms: u64,
    datagram: bool,
    nested: bool,
}

/// Runs [`decide`] over successive statistics snapshots.
#[derive(Debug)]
pub struct PolicySampler {
    user: User,
    screen_sync: bool,
    datagram_negotiated: bool,
    knobs: Knobs,
    rtt_var: RttVar,
    window: VecDeque<(Instant, ConnStats)>,
    last: Option<Discrete>,
}

impl PolicySampler {
    /// `screen_sync` says whether this connection runs screen sync at all;
    /// `datagram_negotiated` whether both ends advertised `datagram.v1`.
    pub fn new(user: User, screen_sync: bool, datagram_negotiated: bool) -> Self {
        Self {
            user,
            screen_sync,
            datagram_negotiated,
            knobs: Knobs::default(),
            rtt_var: RttVar::default(),
            window: VecDeque::new(),
            last: None,
        }
    }

    /// Feed one snapshot. `max_datagram` is what the connection reports
    /// now; `interactive` and `bulk` are the traffic the bulk governor saw.
    pub fn step(
        &mut self,
        now: Instant,
        stats: ConnStats,
        max_datagram: Option<usize>,
        interactive: bool,
        bulk: bool,
    ) -> Sample {
        self.window.push_back((now, stats));
        while self.window.len() > 2
            && self
                .window
                .get(1)
                .is_some_and(|(t, _)| now.duration_since(*t) >= LOSS_WINDOW)
        {
            self.window.pop_front();
        }
        let start = self.window.front().map_or(stats, |(_, s)| *s);
        let rtt_var = self.rtt_var.update(stats.rtt);
        let datagram = self.datagram_negotiated && max_datagram.is_some();
        let observed = Observed {
            interactive,
            bulk,
            datagram,
            user: self.user,
            ..Observed::default()
        }
        .with_path_stats(&stats, &start, rtt_var);
        self.knobs = decide(&observed, &self.knobs);
        let report = transport_report(&observed, &self.knobs, self.screen_sync, max_datagram);
        let discrete = Discrete {
            screen_sync: report.screen_sync.clone(),
            bulk_yield: report.bulk_yield.clone(),
            prediction: report.prediction.clone(),
            keep_alive_ms: report.keep_alive_ms,
            datagram,
            nested: report.nested,
        };
        let changed = self.last.as_ref() != Some(&discrete);
        self.last = Some(discrete);
        Sample { report, changed }
    }

    /// Loss over the snapshots held, for a caller that wants it without a
    /// step.
    pub fn loss(&self) -> f64 {
        match (self.window.front(), self.window.back()) {
            (Some((_, a)), Some((_, b))) => loss_between(a, b),
            _ => 0.0,
        }
    }
}

type Shared = Arc<Mutex<Option<DoctorTransport>>>;

/// The client's view of what the policy decided for its connection, kept
/// current by a task on the connection's runtime (ADR-0052 decision 14).
///
/// Dropping it stops the task. [`PolicyMonitor::current`] is what an
/// `Ops`-level reader (M23's status line) shows.
pub struct PolicyMonitor {
    shared: Shared,
    task: tokio::task::JoinHandle<()>,
}

impl PolicyMonitor {
    /// Start sampling. `connection` is asked on every tick for the live
    /// connection, because a recovery swaps it. `emit` writes the
    /// `qsh::adapt` line when a discrete knob changed; production passes
    /// [`PolicyMonitor::emit_line`].
    pub fn spawn(
        runtime: &tokio::runtime::Handle,
        connection: impl Fn() -> Connection + Send + 'static,
        mut sampler: PolicySampler,
        emit: impl Fn(&str) + Send + 'static,
    ) -> Self {
        let shared: Shared = Arc::new(Mutex::new(None));
        let published = Arc::clone(&shared);
        let task = runtime.spawn(async move {
            let mut ticker = tokio::time::interval(TICK);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let conn = connection();
                let governor = BulkGovernor::for_connection(&conn);
                let (interactive, bulk) = governor.activity();
                let sample = sampler.step(
                    Instant::now(),
                    conn.stats(),
                    conn.max_datagram_size(),
                    interactive,
                    bulk,
                );
                if sample.changed {
                    emit(&to_json_line(&sample.report));
                }
                *published.lock().unwrap_or_else(PoisonError::into_inner) = Some(sample.report);
            }
        });
        Self { shared, task }
    }

    /// The production `emit`: one `INFO` event on [`TARGET`] whose message
    /// is the whole line.
    pub fn emit_line(line: &str) {
        tracing::info!(target: TARGET, "{}", line);
    }

    /// The latest report, `None` before the first tick.
    pub fn current(&self) -> Option<DoctorTransport> {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for PolicyMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapt::StreamWhy;

    fn stats(rtt_ms: u64) -> ConnStats {
        ConnStats {
            rtt: Duration::from_millis(rtt_ms),
            min_rtt: Duration::from_millis(rtt_ms),
            ..ConnStats::default()
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn the_report_carries_the_documented_fields_and_nothing_else() {
        let mut sampler = PolicySampler::new(User::default(), true, true);
        let t0 = Instant::now();
        let sample = sampler.step(t0, stats(100), Some(1200), false, false);
        let line = to_json_line(&sample.report);
        assert!(!line.contains('\n'));
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("pure JSON");
        let mut keys: Vec<&str> = parsed
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "adapt",
                "bulk_yield",
                "frame_interval_ms",
                "keep_alive_ms",
                "loss_pct",
                "max_datagram_bytes",
                "min_rtt_ms",
                "nested",
                "prediction",
                "reasons",
                "rtt_ms",
                "rtt_var_ms",
                "screen_sync"
            ]
        );
        assert!(
            line.starts_with(r#"{"adapt":"policy","rtt_ms":100.0,"#),
            "{line}"
        );
        assert_eq!(parsed["screen_sync"], "datagram");
        assert_eq!(parsed["prediction"], "underline");
        assert_eq!(parsed["max_datagram_bytes"], 1200);
    }

    #[test]
    fn a_line_is_due_on_the_first_step_and_on_discrete_changes_only() {
        let mut sampler = PolicySampler::new(User::default(), true, true);
        let t0 = Instant::now();
        assert!(
            sampler
                .step(t0, stats(10), Some(1200), false, false)
                .changed
        );
        // RTT jitter that changes no discrete knob is not a line.
        assert!(
            !sampler
                .step(t0 + secs(1), stats(12), Some(1200), false, false)
                .changed
        );
        // Prediction crosses its threshold.
        let hot = sampler.step(t0 + secs(2), stats(120), Some(1200), false, false);
        assert!(hot.changed);
        assert_eq!(hot.report.prediction, "underline");
        // The datagram path disappears.
        let cold = sampler.step(t0 + secs(3), stats(120), None, false, false);
        assert!(cold.changed);
        assert_eq!(cold.report.screen_sync, "stream");
        assert!(
            cold.report
                .reasons
                .iter()
                .any(|r| r == "datagram_unavailable")
        );
    }

    #[test]
    fn without_screen_sync_the_carrier_reads_off() {
        let mut sampler = PolicySampler::new(User::default(), false, true);
        let sample = sampler.step(Instant::now(), stats(10), Some(1200), false, false);
        assert_eq!(sample.report.screen_sync, "off");
        assert_eq!(
            screen_sync_label(true, Carrier::Stream(StreamWhy::DatagramUnacked)),
            "stream"
        );
    }

    #[test]
    fn adaptive_off_reads_as_the_fixed_knobs_with_a_user_override_reason() {
        let user = User {
            adaptive: false,
            ..User::default()
        };
        let mut sampler = PolicySampler::new(user, true, true);
        let sample = sampler.step(Instant::now(), stats(200), Some(1200), true, true);
        let r = sample.report;
        assert_eq!(r.prediction, "off");
        assert_eq!(r.bulk_yield, "off");
        assert_eq!(r.frame_interval_ms, 20);
        assert_eq!(r.keep_alive_ms, 15_000);
        assert_eq!(r.screen_sync, "datagram");
        assert!(r.reasons.iter().any(|x| x == "user_override"));
        assert_eq!(
            r.reasons.iter().filter(|x| *x == "user_override").count(),
            1,
            "{:?}",
            r.reasons
        );
    }

    #[test]
    fn loss_is_a_percentage_over_the_window() {
        let mut sampler = PolicySampler::new(User::default(), true, true);
        let t0 = Instant::now();
        sampler.step(t0, stats(20), Some(1200), false, false);
        let mut lossy = stats(20);
        lossy.sent_packets = 1000;
        lossy.lost_packets = Some(25);
        let sample = sampler.step(t0 + secs(1), lossy, Some(1200), false, false);
        assert_eq!(sample.report.loss_pct, 2.5);
        assert!(sample.report.reasons.iter().any(|r| r == "loss_high"));
    }
}
