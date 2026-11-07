//! The attach driver's side of local echo prediction (ADR-0053 decisions 3,
//! 7 and 8, `docs/design/protocol.md` §18.12).
//!
//! [`Predictor`] is a clock-free state machine. [`PredictDriver`] is what the
//! attach driver holds next to it: it takes the wire types
//! ([`wire::ScreenEcho`], the policy knob of `adapt`), applies the user's
//! `--predict` choice ([`Predict`]), and on the reverse route, which has
//! no QUIC connection to read `srtt` from, derives the round-trip estimate
//! from the spacing between an `Input` and the `InputAck` that covers it
//! (decision 8, "역방향 route"). It still has no clock of its own: every
//! method takes `now`, so the driver tests walk time by hand.
//!
//! Holding a `ScreenEcho` until the state it names is applied is the
//! predictor's job and its bound is one report (decision 3, "하나만, 더
//! 새것이 오면 바꾼다"; decision 15, "보류한 `ScreenEcho` 하나"):
//! [`Predictor::on_echo`] keeps a report that is ahead of the applied state
//! and [`Predictor::on_state`] releases it. This module does not add a second
//! queue in front of it.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use qsh_proto::screen::ScreenState;
use qsh_proto::wire::{self, TtyEcho as WireTty};

use super::predict::{EchoReport, Overlay, PredictStats, Predictor, TtyEcho};
use crate::adapt::{self, Knobs, Observed, PredictPin, Prediction, TICK, User};
use crate::ops::Predict;

/// The tracing target of the engine's state lines (ADR-0053 decision 12).
pub const TARGET: &str = "qsh::predict";

/// Input `(end offset, sent at)` pairs kept for the reverse route's round-trip
/// samples. Past this the oldest is forgotten, which only costs samples.
pub const SENT_TIMES_MAX: usize = 64;

/// Round-trip estimate from `Input` to `InputAck` (reverse route).
struct InputRtt {
    pin: Option<PredictPin>,
    sent: VecDeque<(u64, Instant)>,
    srtt: Option<Duration>,
    knobs: Knobs,
    decided_at: Option<Instant>,
}

impl InputRtt {
    fn new(pin: Option<PredictPin>) -> Self {
        Self {
            pin,
            sent: VecDeque::new(),
            srtt: None,
            knobs: Knobs::default(),
            decided_at: None,
        }
    }

    fn sent(&mut self, end: u64, now: Instant) {
        if self.sent.back().is_some_and(|(e, _)| *e >= end) {
            return;
        }
        if self.sent.len() == SENT_TIMES_MAX {
            self.sent.pop_front();
        }
        self.sent.push_back((end, now));
    }

    /// An `InputAck` up to `acked`: the policy to apply now, if this ack
    /// yielded a sample and a decision is due.
    fn acked(&mut self, acked: u64, now: Instant) -> Option<Prediction> {
        let mut at = None;
        while let Some((end, sent_at)) = self.sent.front().copied() {
            if end > acked {
                break;
            }
            at = Some(sent_at);
            self.sent.pop_front();
        }
        let sample = now.saturating_duration_since(at?);
        // RFC 6298 smoothing, the same gain the policy's other estimators
        // use: srtt += (sample - srtt) / 8; the first sample is taken as is.
        let srtt = match self.srtt {
            None => sample,
            Some(prev) => {
                let (p, s) = (prev.as_secs_f64(), sample.as_secs_f64());
                Duration::from_secs_f64((p + (s - p) / 8.0).max(0.0))
            }
        };
        self.srtt = Some(srtt);
        // `decide` is a once-a-second function (hysteresis is defined per
        // tick); between ticks the policy stands.
        if self
            .decided_at
            .is_some_and(|t| now.saturating_duration_since(t) < TICK)
        {
            return None;
        }
        self.decided_at = Some(now);
        let observed = Observed {
            srtt,
            user: User {
                prediction: self.pin,
                ..User::from_process()
            },
            ..Observed::default()
        };
        self.knobs = adapt::decide(&observed, &self.knobs);
        Some(self.knobs.prediction)
    }
}

/// One screen-sync attach's prediction state. See the module documentation.
pub struct PredictDriver {
    predictor: Predictor,
    mode: Predict,
    /// `Some` on the reverse route only.
    rtt: Option<InputRtt>,
    /// What the last `qsh::predict` line said, to log changes only.
    logged: Option<LogKey>,
}

/// The parts of the engine state a `qsh::predict` line is written for.
#[derive(Clone, Copy, PartialEq, Eq)]
struct LogKey {
    drawing: bool,
    suspended: bool,
    blocked: Option<&'static str>,
}

impl PredictDriver {
    /// `capable` is whether both peers advertised `screen-echo.v1`;
    /// `reverse` selects the `InputAck` round-trip estimate over the
    /// policy monitor's `srtt`. `None` for [`Predict::Never`].
    pub fn new(mode: Predict, capable: bool, reverse: bool) -> Option<Self> {
        if mode == Predict::Never {
            return None;
        }
        let mut d = Self {
            predictor: Predictor::new(capable),
            mode,
            rtt: reverse.then(|| InputRtt::new(mode.pin())),
            logged: None,
        };
        // Until the first policy step nothing is known about the path: the
        // policy's own start value (`Knobs::default()`) is off, `always`
        // does not wait for it.
        d.set_policy(Prediction::Off);
        d.log();
        Some(d)
    }

    /// The policy knob changed (`PolicyMonitor`'s once-a-second step on the
    /// forward route, the estimate below on the reverse one).
    pub fn set_policy(&mut self, policy: Prediction) {
        let policy = match self.mode {
            Predict::Always => policy.max(Prediction::Display),
            Predict::Auto | Predict::Never => policy,
        };
        self.predictor.on_policy(policy);
        self.log();
    }

    /// The user typed `bytes`; `end` is the input offset after them.
    pub fn on_input(&mut self, bytes: &[u8], end: u64, now: Instant) {
        if let Some(rtt) = &mut self.rtt {
            rtt.sent(end, now);
        }
        self.predictor.on_input(bytes, end, now);
        self.log();
    }

    /// The host acknowledged input up to `acked`.
    pub fn on_input_ack(&mut self, acked: u64, now: Instant) {
        if let Some(policy) = self.rtt.as_mut().and_then(|r| r.acked(acked, now)) {
            self.set_policy(policy);
        }
        self.log();
    }

    /// The client applied host state `state_num`.
    pub fn on_state(&mut self, state: &ScreenState, state_num: u64, now: Instant) {
        self.predictor.on_state(state, state_num, now);
        self.log();
    }

    /// A `ScreenEcho` that passed the reader's checks. If it names a state
    /// the client has not applied yet, the predictor holds it (one report,
    /// the newest) until that state is applied.
    pub fn on_echo(&mut self, echo: &wire::ScreenEcho, now: Instant) {
        let tty = match echo.tty_echo() {
            WireTty::Unknown => TtyEcho::Unknown,
            WireTty::Kernel => TtyEcho::Kernel,
            WireTty::App => TtyEcho::App,
            WireTty::Secret => TtyEcho::Secret,
        };
        self.predictor.on_echo(
            EchoReport {
                state_num: echo.state_num,
                input_seq: echo.input_seq,
                tty,
            },
            now,
        );
        self.log();
    }

    /// A new connection took over.
    pub fn on_leg_change(&mut self) {
        self.predictor.on_leg_change();
        self.log();
    }

    /// Whether this attach holds the writer lease.
    pub fn on_writer(&mut self, writer: bool) {
        self.predictor.on_writer(writer);
        self.log();
    }

    /// The connection status line is (not) showing.
    pub fn on_status_line(&mut self, up: bool) {
        self.predictor.on_status_line(up);
        self.log();
    }

    /// Advance the clock: late confirmation forces underlining.
    pub fn on_tick(&mut self, now: Instant) {
        self.predictor.on_tick(now);
        self.log();
    }

    /// The cells to draw over the host screen.
    pub fn overlay(&self) -> Overlay {
        self.predictor.overlay()
    }

    /// When [`Self::on_tick`] next changes what is drawn.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.predictor.next_deadline()
    }

    /// Write a `qsh::predict` line when the engine's drawing state changed
    /// (ADR-0053 decision 12): on or off, suspended, blocked and why, with
    /// the counters. Never a character, a position or an input byte.
    fn log(&mut self) {
        use super::predict::Block;
        let p = &self.predictor;
        let key = LogKey {
            drawing: p.drawing(),
            suspended: p.is_suspended(),
            blocked: p.blocked().map(|b| match b {
                Block::NoCapability => "no_capability",
                Block::ReadOnly => "read_only",
                Block::Secret => "secret",
                Block::FullScreenApp => "full_screen_app",
            }),
        };
        if self.logged == Some(key) {
            return;
        }
        self.logged = Some(key);
        let stats = p.stats();
        let blocked = key
            .blocked
            .map_or_else(|| "null".to_string(), |b| format!("\"{b}\""));
        tracing::info!(
            target: TARGET,
            "{{\"predict\":\"state\",\"drawing\":{},\"suspended\":{},\"blocked\":{blocked},\"confirmed\":{},\"mispredicted\":{},\"echo_rejected\":{},\"echo_stale\":{}}}",
            key.drawing,
            key.suspended,
            stats.confirmed,
            stats.mispredicted,
            stats.echo_rejected,
            stats.echo_stale,
        );
    }

    /// The report waiting for its state, if any (at most one).
    pub fn held_echo(&self) -> Option<EchoReport> {
        self.predictor.held_echo()
    }

    /// Counters for the `qsh::predict` trace target.
    pub fn stats(&self) -> PredictStats {
        self.predictor.stats()
    }

    /// The predictor, for inspection.
    pub fn predictor(&self) -> &Predictor {
        &self.predictor
    }

    /// The smoothed `Input` to `InputAck` round trip (reverse route).
    pub fn input_srtt(&self) -> Option<Duration> {
        self.rtt.as_ref().and_then(|r| r.srtt)
    }
}

#[cfg(test)]
mod tests;
