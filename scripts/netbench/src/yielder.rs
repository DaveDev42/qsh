//! A port of qsh's bulk governor (`crates/qsh-core/src/adapt/{budget,governor}.rs`,
//! ADR-0052 decision 12 (a)) for `isolation = "yield"`. The bench links no qsh
//! code, so this is a re-implementation of the same rule on quinn's own
//! statistics, kept to the same numbers: a 25 ms queue-delay target, halving
//! once per smoothed RTT above it (or on loss with a queue at least half the
//! target), +2% of the ceiling per RTT below it, a floor of max(64 KiB/s, 5%
//! of the ceiling), a ceiling of 125% of the best 1 s delivery rate in the
//! last 60 s, a 10 ms token burst (16 KiB minimum), and 16 KiB write granules
//! while limiting. If the rule changes in qsh-core, change it here too, or
//! the bench stops measuring what ships.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TARGET: Duration = Duration::from_millis(25);
const FLOOR_MIN: f64 = 64.0 * 1024.0;
const FLOOR_PERCENT: f64 = 0.05;
const GROW_PERCENT: f64 = 0.02;
const BURST_WINDOW: Duration = Duration::from_millis(10);
const BURST_MIN: f64 = 16.0 * 1024.0;
const BUCKET: Duration = Duration::from_millis(250);
const SPAN: u64 = 4;
const MEMORY: Duration = Duration::from_secs(60);
const HEADROOM: f64 = 1.25;
const INTERACTIVE_WINDOW: Duration = Duration::from_secs(2);
const BULK_WINDOW: Duration = Duration::from_secs(1);
const EVALUATE_PERIOD: Duration = Duration::from_millis(20);
const MAX_PARK: Duration = Duration::from_millis(50);
const RTT_FLOOR: Duration = Duration::from_millis(50);
/// Stand-in for "no bound known" (finite, so `rate * 0.0` stays 0).
const UNBOUNDED: f64 = 1e12;
/// Write granule while limiting.
pub const GRANULE: usize = 16 * 1024;

struct Inner {
    epoch: Instant,
    limiting: bool,
    rate: f64,
    ceiling: f64,
    tokens: f64,
    last_refill: Instant,
    last_adjust: Instant,
    loss_pending: bool,
    lost_seen: Option<u64>,
    last_interactive: Option<Instant>,
    last_bulk: Option<Instant>,
    last_evaluated: Option<Instant>,
    min_rtt: Duration,
    delivered: VecDeque<(u64, u64)>,
}

pub struct Yielder {
    conn: quinn::Connection,
    inner: Mutex<Inner>,
}

impl Yielder {
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            conn,
            inner: Mutex::new(Inner::new(Instant::now())),
        }
    }

    /// A key arrived.
    pub fn note_interactive(&self) {
        self.inner.lock().expect("yielder").last_interactive = Some(Instant::now());
    }

    /// Write granule for a `len`-byte write.
    pub fn granule(&self, len: usize) -> usize {
        if self.inner.lock().expect("yielder").limiting {
            len.min(GRANULE)
        } else {
            len
        }
    }

    /// Wait until `bytes` may go out.
    pub async fn pace(&self, bytes: usize) {
        let mut remaining = bytes as f64;
        loop {
            let wait = {
                let now = Instant::now();
                let mut s = self.inner.lock().expect("yielder");
                if s.last_evaluated.is_none_or(|t| now - t >= EVALUATE_PERIOD) {
                    let path = self.conn.stats().path;
                    s.evaluate(now, path.rtt, path.lost_packets);
                }
                s.last_bulk = Some(now);
                match s.take(now, &mut remaining) {
                    None => return,
                    Some(d) => d,
                }
            };
            tokio::time::sleep(wait).await;
        }
    }
}

impl Inner {
    fn new(now: Instant) -> Self {
        Self {
            epoch: now,
            limiting: false,
            rate: UNBOUNDED,
            ceiling: UNBOUNDED,
            tokens: 0.0,
            last_refill: now,
            last_adjust: now,
            loss_pending: false,
            lost_seen: None,
            last_interactive: None,
            last_bulk: None,
            last_evaluated: None,
            min_rtt: Duration::MAX,
            delivered: VecDeque::new(),
        }
    }

    fn burst(&self) -> f64 {
        (self.rate * BURST_WINDOW.as_secs_f64()).max(BURST_MIN)
    }

    fn refill(&mut self, now: Instant) {
        let dt = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now.max(self.last_refill);
        self.tokens = (self.tokens + self.rate * dt).min(self.burst());
    }

    fn bucket_of(&self, now: Instant) -> u64 {
        (now.saturating_duration_since(self.epoch).as_nanos() / BUCKET.as_nanos()) as u64
    }

    fn record(&mut self, now: Instant, bytes: f64) {
        if bytes <= 0.0 {
            return;
        }
        let idx = self.bucket_of(now);
        match self.delivered.back_mut() {
            Some((i, b)) if *i == idx => *b += bytes as u64,
            _ => self.delivered.push_back((idx, bytes as u64)),
        }
        let oldest = idx.saturating_sub((MEMORY.as_nanos() / BUCKET.as_nanos()) as u64);
        while self.delivered.front().is_some_and(|(i, _)| *i < oldest) {
            self.delivered.pop_front();
        }
    }

    fn peak(&self, now: Instant) -> Option<f64> {
        let current = self.bucket_of(now);
        let mut best = 0u64;
        for &(end, _) in &self.delivered {
            if end >= current {
                continue;
            }
            let sum: u64 = self
                .delivered
                .iter()
                .filter(|(i, _)| *i + SPAN > end && *i <= end)
                .map(|(_, b)| *b)
                .sum();
            best = best.max(sum);
        }
        (best > 0).then(|| best as f64 / (BUCKET.as_secs_f64() * SPAN as f64))
    }

    fn evaluate(&mut self, now: Instant, rtt: Duration, lost: u64) {
        self.last_evaluated = Some(now);
        if !rtt.is_zero() {
            self.min_rtt = self.min_rtt.min(rtt);
        }
        let recent = |t: Option<Instant>, w: Duration| t.is_some_and(|t| now - t <= w);
        let want = recent(self.last_interactive, INTERACTIVE_WINDOW)
            && recent(self.last_bulk, BULK_WINDOW);
        let ceiling = self.peak(now).map(|p| p * HEADROOM);
        if want && !self.limiting {
            self.ceiling = ceiling.unwrap_or(UNBOUNDED).max(FLOOR_MIN);
            self.rate = self.ceiling;
            self.tokens = self.burst();
            self.last_refill = now;
            self.last_adjust = now;
            self.loss_pending = false;
        } else if !want {
            self.rate = UNBOUNDED;
            self.ceiling = UNBOUNDED;
        } else if let Some(c) = ceiling {
            self.ceiling = c.max(FLOOR_MIN);
            self.rate = self.rate.min(self.ceiling);
        }
        self.limiting = want;
        if self.lost_seen.is_some_and(|seen| lost > seen) {
            self.loss_pending = true;
        }
        self.lost_seen = Some(lost);
        if !self.limiting {
            return;
        }
        let srtt = rtt.max(RTT_FLOOR);
        if now - self.last_adjust < srtt {
            return;
        }
        self.last_adjust = now;
        let queue = rtt.saturating_sub(self.min_rtt.min(rtt));
        let lossy = std::mem::take(&mut self.loss_pending) && queue >= TARGET / 2;
        let floor = FLOOR_MIN.max(self.ceiling * FLOOR_PERCENT);
        self.rate = if queue > TARGET || lossy {
            self.rate / 2.0
        } else {
            self.rate + (self.ceiling * GROW_PERCENT).max(1.0)
        }
        .clamp(floor, self.ceiling);
    }

    /// Takes tokens; `None` when `remaining` is paid for, else how long to
    /// wait.
    fn take(&mut self, now: Instant, remaining: &mut f64) -> Option<Duration> {
        if !self.limiting {
            let all = std::mem::take(remaining);
            self.record(now, all);
            return None;
        }
        self.refill(now);
        let got = remaining.min(self.tokens);
        self.tokens -= got;
        *remaining -= got;
        self.record(now, got);
        if *remaining <= 0.0 {
            return None;
        }
        let missing = remaining.min(self.burst()) - self.tokens;
        Some(
            Duration::from_secs_f64(missing.max(0.0) / self.rate)
                .clamp(Duration::from_millis(1), MAX_PARK),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Bulk at 2.5 MB/s for three seconds.
    fn busy(t0: Instant) -> Inner {
        let mut s = Inner::new(t0);
        for i in 0..12 {
            let mut want = 625_000.0;
            s.take(t0 + ms(i * 250), &mut want);
        }
        s
    }

    #[test]
    fn yields_only_while_keys_and_bulk_are_both_recent() {
        let t0 = Instant::now();
        let mut s = busy(t0);
        s.last_bulk = Some(t0 + ms(3_000));
        s.evaluate(t0 + ms(3_000), ms(60), 0);
        assert!(!s.limiting);
        s.last_interactive = Some(t0 + ms(3_010));
        s.evaluate(t0 + ms(3_020), ms(60), 0);
        assert!(s.limiting);
        assert_eq!(s.rate, 3_125_000.0);
        s.last_bulk = Some(t0 + ms(5_050));
        s.evaluate(t0 + ms(5_100), ms(60), 0);
        assert!(!s.limiting, "two seconds after the last key");
    }

    #[test]
    fn halves_over_target_and_on_loss_with_a_standing_queue() {
        let t0 = Instant::now();
        let mut s = busy(t0);
        s.last_bulk = Some(t0 + ms(3_000));
        s.last_interactive = Some(t0 + ms(3_000));
        s.evaluate(t0 + ms(3_000), ms(50), 0);
        s.evaluate(t0 + ms(3_100), ms(100), 0);
        assert_eq!(s.rate, 1_562_500.0);
        // 15 ms of queue and a new loss: halves again.
        s.last_interactive = Some(t0 + ms(3_200));
        s.evaluate(t0 + ms(3_300), ms(65), 9);
        assert_eq!(s.rate, 781_250.0);
        // The loss was consumed by that step: no new loss, no halving.
        s.evaluate(t0 + ms(3_400), ms(65), 9);
        assert!(s.rate > 781_250.0);
    }
}
