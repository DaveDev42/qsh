//! Bulk send budget (ADR-0052 decision 12 (a)): a token bucket whose rate a
//! LEDBAT-like rule steers. Time is injected as a `Duration` since any fixed
//! origin, so tests need no clock and no sleeping.

use std::time::Duration;

use super::BulkYield;

/// Open number: the rate may grow by this share of the estimated bandwidth
/// per RTT while the queue is below target.
const GROW_PERCENT_PER_RTT: u64 = 2;
/// Open number: the bucket holds this much time worth of tokens.
const BURST_WINDOW: Duration = Duration::from_millis(50);
/// Open number: smallest bucket, so a low rate can still send a few packets.
const BURST_MIN_BYTES: u64 = 16 * 1024;

/// Send budget for tunnel and file streams.
#[derive(Clone, Debug)]
pub struct BulkBudget {
    mode: BulkYield,
    rate: u64,
    ceiling: u64,
    tokens: u64,
    last_refill: Duration,
    last_adjust: Duration,
}

impl BulkBudget {
    /// A budget that is not limiting (`Off`).
    pub fn new(now: Duration) -> Self {
        Self {
            mode: BulkYield::Off,
            rate: u64::MAX,
            ceiling: u64::MAX,
            tokens: 0,
            last_refill: now,
            last_adjust: now,
        }
    }

    /// Current rate in bytes per second, `None` while not limiting.
    pub fn rate(&self) -> Option<u64> {
        matches!(self.mode, BulkYield::Yield { .. }).then_some(self.rate)
    }

    /// Apply the policy's knob (a). Entering `Yield` starts at the estimated
    /// bandwidth (unbounded when unknown), so the first over-target step
    /// halves from the real rate.
    pub fn set_mode(&mut self, now: Duration, mode: BulkYield, est_bandwidth: Option<u64>) {
        match (self.mode, mode) {
            (BulkYield::Off, BulkYield::Yield { .. }) => {
                self.ceiling = est_bandwidth.unwrap_or(u64::MAX).max(floor_of(mode));
                self.rate = self.ceiling;
                self.mode = mode;
                self.tokens = self.burst();
                self.last_refill = now;
                self.last_adjust = now;
            }
            (BulkYield::Yield { .. }, BulkYield::Off) => {
                self.rate = u64::MAX;
                self.ceiling = u64::MAX;
            }
            (BulkYield::Yield { .. }, BulkYield::Yield { .. }) => {
                if let Some(bw) = est_bandwidth {
                    self.ceiling = bw.max(floor_of(mode));
                    self.rate = self.rate.min(self.ceiling);
                }
            }
            (BulkYield::Off, BulkYield::Off) => {}
        }
        self.mode = mode;
    }

    /// One steering step, at most once per `srtt`: queue delay above the
    /// target halves the rate, otherwise it grows a little. Never below the
    /// floor, never above the bandwidth estimate.
    pub fn steer(&mut self, now: Duration, queue_delay: Duration, srtt: Duration) {
        let BulkYield::Yield {
            target,
            floor_bytes_per_sec,
        } = self.mode
        else {
            return;
        };
        if now.saturating_sub(self.last_adjust) < srtt {
            return;
        }
        self.last_adjust = now;
        self.rate = if queue_delay > target {
            self.rate / 2
        } else {
            let step = (self.ceiling / 100).saturating_mul(GROW_PERCENT_PER_RTT);
            self.rate.saturating_add(step.max(1))
        };
        self.rate = self.rate.clamp(floor_bytes_per_sec, self.ceiling);
    }

    /// How many of `want` bytes may be sent at `now`; takes them.
    pub fn grant(&mut self, now: Duration, want: u64) -> u64 {
        if self.rate().is_none() {
            return want;
        }
        self.refill(now);
        let n = want.min(self.tokens);
        self.tokens -= n;
        n
    }

    /// How long until `bytes` (at most one burst) can be granted.
    pub fn wait_for(&mut self, now: Duration, bytes: u64) -> Duration {
        if self.rate().is_none() {
            return Duration::ZERO;
        }
        self.refill(now);
        let missing = bytes.min(self.burst()).saturating_sub(self.tokens);
        Duration::from_secs_f64(missing as f64 / self.rate as f64)
    }

    fn burst(&self) -> u64 {
        let by_rate = (u128::from(self.rate) * BURST_WINDOW.as_micros() / 1_000_000)
            .min(u128::from(u64::MAX)) as u64;
        by_rate.max(BURST_MIN_BYTES)
    }

    fn refill(&mut self, now: Duration) {
        let dt = now.saturating_sub(self.last_refill);
        self.last_refill = now.max(self.last_refill);
        let add =
            (u128::from(self.rate) * dt.as_micros() / 1_000_000).min(u128::from(u64::MAX)) as u64;
        self.tokens = self.tokens.saturating_add(add).min(self.burst());
    }
}

fn floor_of(mode: BulkYield) -> u64 {
    match mode {
        BulkYield::Yield {
            floor_bytes_per_sec,
            ..
        } => floor_bytes_per_sec,
        BulkYield::Off => 0,
    }
}
