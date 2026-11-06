//! The one-line JSON result and the numeric helpers behind it.

use crate::profile::{Link, Profile, Workload};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "qsh.netbench/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchResult {
    pub schema: String,
    pub profile: String,
    pub question: String,
    pub link: Link,
    pub workload: Workload,
    pub metrics: Metrics,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Staleness of screen states, milliseconds, one-way delay already removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staleness_ms: Option<Percentiles>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub states_produced: Option<u64>,
    /// States the receiver actually applied (datagram: only newer ones).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub states_applied: Option<u64>,
    /// Counted states for which no applied state at or after them ever arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub states_unresolved: Option<u64>,
    /// Datagram frames that never arrived, percent of those sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datagram_loss_pct: Option<f64>,
    /// Key echo round trip, milliseconds, raw (includes the link RTT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub echo_ms: Option<Percentiles>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub echo_missing: Option<u64>,
    /// Bulk goodput host to client, MB/s (1e6 bytes), over `duration_s`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk_mb_s: Option<f64>,
    /// `Connection::max_datagram_size()` at the end of the run, client side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_datagram_bytes: Option<u64>,
    /// Smoothed RTT the client's QUIC stack ended with, milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lost_packets: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Percentiles {
    pub n: u64,
    pub min: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

impl BenchResult {
    pub fn new(p: &Profile, metrics: Metrics) -> BenchResult {
        BenchResult {
            schema: SCHEMA.to_string(),
            profile: p.name.clone(),
            question: p.question.clone(),
            link: p.link.clone(),
            workload: p.workload.clone(),
            metrics,
        }
    }

    /// Exactly one line, no trailing newline.
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("result serializes")
    }
}

/// Nearest-rank percentiles of `samples` (milliseconds). `None` when empty.
pub fn percentiles(samples: &[f64]) -> Option<Percentiles> {
    if samples.is_empty() {
        return None;
    }
    let mut v: Vec<f64> = samples.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    let rank = |q: f64| -> f64 {
        let i = ((q * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1;
        round3(v[i])
    };
    Some(Percentiles {
        n: v.len() as u64,
        min: round3(v[0]),
        p50: rank(0.50),
        p95: rank(0.95),
        p99: rank(0.99),
        max: round3(v[v.len() - 1]),
    })
}

pub fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile::parse(
            "name = \"t\"\nquestion = \"q4\"\n[link]\nrtt_ms = 100\n[workload]\nkind = \"echo\"\n",
        )
        .unwrap()
    }

    #[test]
    fn nearest_rank_percentiles() {
        let s: Vec<f64> = (1..=100).map(f64::from).collect();
        let p = percentiles(&s).unwrap();
        assert_eq!(
            (p.n, p.min, p.p50, p.p95, p.p99, p.max),
            (100, 1.0, 50.0, 95.0, 99.0, 100.0)
        );
        assert!(percentiles(&[]).is_none());
        let one = percentiles(&[7.0]).unwrap();
        assert_eq!((one.p50, one.p99), (7.0, 7.0));
    }

    #[test]
    fn result_is_one_line_with_schema_and_round_trips() {
        let m = Metrics {
            echo_ms: percentiles(&[100.5, 101.0, 350.25]),
            echo_missing: Some(0),
            bulk_mb_s: Some(2.1),
            ..Metrics::default()
        };
        let r = BenchResult::new(&profile(), m);
        let line = r.to_line();
        assert!(!line.contains('\n'));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["schema"], "qsh.netbench/v1");
        assert_eq!(v["profile"], "t");
        assert_eq!(v["question"], "q4");
        assert_eq!(v["link"]["rtt_ms"], 100.0);
        assert_eq!(v["workload"]["kind"], "echo");
        assert_eq!(v["metrics"]["echo_ms"]["n"], 3);
        let back: BenchResult = serde_json::from_str(&line).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn absent_metrics_are_omitted_not_null() {
        let line = BenchResult::new(&profile(), Metrics::default()).to_line();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(v["metrics"].as_object().unwrap().is_empty());
    }

    #[test]
    fn unknown_result_fields_are_rejected() {
        let line = BenchResult::new(&profile(), Metrics::default()).to_line();
        let bad = line.replace("\"metrics\":{}", "\"metrics\":{\"surprise\":1}");
        assert!(serde_json::from_str::<BenchResult>(&bad).is_err());
    }
}
