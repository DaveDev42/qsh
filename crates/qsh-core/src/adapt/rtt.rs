//! RTT variation from once-a-second samples (quinn 0.11 does not publish
//! `rttvar`, ADR-0052 revision note on decision 12).

use std::time::Duration;

/// RFC 6298 style estimator: `srtt += (s - srtt)/8`,
/// `var += (|srtt - s| - var)/4`. The first sample sets `srtt = s`,
/// `var = s/2`. Pure; the caller owns the one-second cadence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RttVar {
    srtt_ns: Option<u128>,
    var_ns: u128,
}

impl RttVar {
    /// Feed one sample and return the new variation.
    pub fn update(&mut self, sample: Duration) -> Duration {
        let s = sample.as_nanos();
        match self.srtt_ns {
            None => {
                self.srtt_ns = Some(s);
                self.var_ns = s / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(s);
                self.var_ns = (self.var_ns * 3 + diff) / 4;
                self.srtt_ns = Some((srtt * 7 + s) / 8);
            }
        }
        self.value()
    }

    /// Current variation, zero before the first sample.
    pub fn value(&self) -> Duration {
        Duration::from_nanos(u64::try_from(self.var_ns).unwrap_or(u64::MAX))
    }
}
