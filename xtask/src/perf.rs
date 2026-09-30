//! `cargo xtask perf-judge`: the nightly perf trend judge.
//!
//! Inputs are the history file (`perf.jsonl`, one JSON point per line) and
//! the point for this run (a file holding one JSON point). The judge
//! compares the point against the median of the last [`BASELINE_POINTS`]
//! non-injected points already in the history, appends the point, trims the
//! history to [`RETENTION_POINTS`] lines, rewrites the file, and prints one
//! verdict line. Exit 0 is green (or "recorded, not judged"), exit 1 is red.
//! The point is recorded even when the verdict is red.
//!
//! Thresholds and storage are specified in `docs/design/testing.md`
//! (CI 규율). The judge is not a PR gate; `.github/workflows/perf.yml` runs it.

use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Points kept in the history file.
pub const RETENTION_POINTS: usize = 365;
/// Non-injected points the median is taken over; fewer means no verdict.
pub const BASELINE_POINTS: usize = 7;
/// Throughput at or below this fraction of the median is red.
pub const THROUGHPUT_FLOOR: f64 = 0.80;
/// Echo p95 at or above this multiple of the median is red.
pub const ECHO_CEILING: f64 = 1.50;

/// One run's data point, one line of `perf.jsonl`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub at: String,
    pub sha: String,
    pub runner: String,
    pub throughput_mbps: f64,
    pub raw_quinn_mbps: f64,
    pub echo_p95_ms: f64,
    pub rtt_ms: f64,
    /// True when a fixed delay was injected; such points never enter a median.
    #[serde(default)]
    pub injected: bool,
    #[serde(default)]
    pub inject_delay_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Fewer than [`BASELINE_POINTS`] non-injected points existed.
    Recorded {
        baseline_points: usize,
    },
    Green {
        throughput_ratio: f64,
        echo_ratio: Option<f64>,
    },
    Red {
        reasons: Vec<String>,
    },
}

impl Verdict {
    pub fn is_red(&self) -> bool {
        matches!(self, Verdict::Red { .. })
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Recorded { baseline_points } => write!(
                f,
                "perf-judge: RECORDED (baseline {baseline_points}/{BASELINE_POINTS} non-injected points, no verdict)"
            ),
            Verdict::Green {
                throughput_ratio,
                echo_ratio,
            } => {
                write!(
                    f,
                    "perf-judge: GREEN throughput {:.1}% of median",
                    throughput_ratio * 100.0
                )?;
                match echo_ratio {
                    Some(r) => write!(f, ", echo p95 {:.1}% of median", r * 100.0),
                    None => write!(f, ", echo p95 not compared (median is zero)"),
                }
            }
            Verdict::Red { reasons } => write!(f, "perf-judge: RED {}", reasons.join("; ")),
        }
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// Judge `point` against `history` (which must not yet contain it).
pub fn judge(history: &[Point], point: &Point) -> Verdict {
    let baseline: Vec<&Point> = history
        .iter()
        .rev()
        .filter(|p| !p.injected)
        .take(BASELINE_POINTS)
        .collect();
    if baseline.len() < BASELINE_POINTS {
        return Verdict::Recorded {
            baseline_points: baseline.len(),
        };
    }
    let tp_median = median(baseline.iter().map(|p| p.throughput_mbps).collect());
    let echo_median = median(baseline.iter().map(|p| p.echo_p95_ms).collect());

    let mut reasons = Vec::new();
    let throughput_ratio = if tp_median > 0.0 {
        point.throughput_mbps / tp_median
    } else {
        1.0
    };
    if tp_median > 0.0 && point.throughput_mbps <= tp_median * THROUGHPUT_FLOOR {
        reasons.push(format!(
            "throughput {:.1} MB/s is {:.1}% of the {BASELINE_POINTS}-point median {:.1} MB/s (red at or below {:.0}%)",
            point.throughput_mbps,
            throughput_ratio * 100.0,
            tp_median,
            THROUGHPUT_FLOOR * 100.0
        ));
    }
    let echo_ratio = (echo_median > 0.0).then(|| point.echo_p95_ms / echo_median);
    if echo_median > 0.0 && point.echo_p95_ms >= echo_median * ECHO_CEILING {
        reasons.push(format!(
            "echo p95 {:.3} ms is {:.1}% of the {BASELINE_POINTS}-point median {:.3} ms (red at or above {:.0}%)",
            point.echo_p95_ms,
            point.echo_p95_ms / echo_median * 100.0,
            echo_median,
            ECHO_CEILING * 100.0
        ));
    }
    if reasons.is_empty() {
        Verdict::Green {
            throughput_ratio,
            echo_ratio,
        }
    } else {
        Verdict::Red { reasons }
    }
}

/// Keep only the newest [`RETENTION_POINTS`] points.
pub fn trim(history: &mut Vec<Point>) {
    if history.len() > RETENTION_POINTS {
        let excess = history.len() - RETENTION_POINTS;
        history.drain(..excess);
    }
}

fn read_history(path: &Path) -> Result<Vec<Point>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(i, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("{}:{}: not a perf point", path.display(), i + 1))
        })
        .collect()
}

fn write_history(path: &Path, history: &[Point]) -> Result<()> {
    let mut out = String::new();
    for p in history {
        out.push_str(&serde_json::to_string(p)?);
        out.push('\n');
    }
    fs::write(path, out).with_context(|| format!("write {}", path.display()))
}

/// Entry point for `cargo xtask perf-judge --history <file> --point <file>`.
/// Returns the verdict; the history file has already been rewritten.
pub fn run(args: impl Iterator<Item = String>) -> Result<Verdict> {
    let mut history_path = None;
    let mut point_path = None;
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--history" => history_path = args.next(),
            "--point" => point_path = args.next(),
            other => bail!("unknown argument '{other}'"),
        }
    }
    let (Some(history_path), Some(point_path)) = (history_path, point_path) else {
        bail!("usage: cargo xtask perf-judge --history <perf.jsonl> --point <point.json>");
    };
    let point_text =
        fs::read_to_string(&point_path).with_context(|| format!("read {point_path}"))?;
    let point: Point = serde_json::from_str(point_text.trim())
        .with_context(|| format!("{point_path}: not a perf point"))?;

    let mut history = read_history(Path::new(&history_path))?;
    let verdict = judge(&history, &point);
    history.push(point);
    trim(&mut history);
    write_history(Path::new(&history_path), &history)?;
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(throughput: f64, echo: f64, injected: bool) -> Point {
        Point {
            at: "2026-10-01T00:00:00Z".into(),
            sha: "0".repeat(40),
            runner: "ubuntu-24.04".into(),
            throughput_mbps: throughput,
            raw_quinn_mbps: 1000.0,
            echo_p95_ms: echo,
            rtt_ms: 0.2,
            injected,
            inject_delay_ms: if injected { 50 } else { 0 },
        }
    }

    fn seven() -> Vec<Point> {
        (0..7).map(|_| point(100.0, 2.0, false)).collect()
    }

    #[test]
    fn perf_judge_is_green_within_the_threshold_of_the_last_seven_median() {
        // -19% throughput and +49% echo are both inside the thresholds.
        let v = judge(&seven(), &point(81.0, 2.98, false));
        assert!(matches!(v, Verdict::Green { .. }), "{v}");
        assert!(!v.is_red());
    }

    #[test]
    fn perf_judge_is_red_when_throughput_drops_past_twenty_percent() {
        let v = judge(&seven(), &point(80.0, 2.0, false));
        assert!(v.is_red(), "{v}");
        assert!(v.to_string().contains("throughput"));
    }

    #[test]
    fn perf_judge_is_red_when_echo_p95_rises_past_fifty_percent() {
        let v = judge(&seven(), &point(100.0, 3.0, false));
        assert!(v.is_red(), "{v}");
        assert!(v.to_string().contains("echo p95"));
    }

    #[test]
    fn perf_judge_records_without_judging_until_seven_points_exist() {
        let mut history: Vec<Point> = (0..6).map(|_| point(100.0, 2.0, false)).collect();
        // A collapse is not judged while the baseline is short.
        let v = judge(&history, &point(1.0, 500.0, false));
        assert_eq!(v, Verdict::Recorded { baseline_points: 6 });
        assert!(!v.is_red());
        history.push(point(100.0, 2.0, false));
        assert!(judge(&history, &point(1.0, 500.0, false)).is_red());
    }

    #[test]
    fn perf_judge_excludes_injected_points_from_the_median() {
        // Seven good points with injected slow points interleaved: the
        // median must stay 100, so 85 is green and 70 is red.
        let mut history = Vec::new();
        for _ in 0..7 {
            history.push(point(100.0, 2.0, false));
            history.push(point(5.0, 90.0, true));
        }
        assert!(!judge(&history, &point(85.0, 2.0, false)).is_red());
        assert!(judge(&history, &point(70.0, 2.0, false)).is_red());
        // Injected points alone never make a baseline.
        let only_injected: Vec<Point> = (0..9).map(|_| point(5.0, 90.0, true)).collect();
        assert_eq!(
            judge(&only_injected, &point(1.0, 1.0, false)),
            Verdict::Recorded { baseline_points: 0 }
        );
    }

    #[test]
    fn perf_history_trims_to_the_retention_bound() {
        let mut history: Vec<Point> = (0..RETENTION_POINTS + 5)
            .map(|i| point(i as f64, 1.0, false))
            .collect();
        trim(&mut history);
        assert_eq!(history.len(), RETENTION_POINTS);
        // The oldest five were dropped, the newest kept.
        assert_eq!(history[0].throughput_mbps, 5.0);
        assert_eq!(
            history.last().map(|p| p.throughput_mbps),
            Some((RETENTION_POINTS + 4) as f64)
        );
    }

    #[test]
    fn run_appends_the_point_even_when_red() {
        let dir = tempfile::tempdir().unwrap();
        let hist = dir.path().join("perf.jsonl");
        write_history(&hist, &seven()).unwrap();
        let pt = dir.path().join("point.json");
        fs::write(
            &pt,
            serde_json::to_string(&point(10.0, 2.0, false)).unwrap(),
        )
        .unwrap();
        let verdict = run([
            "--history".to_string(),
            hist.display().to_string(),
            "--point".to_string(),
            pt.display().to_string(),
        ]
        .into_iter())
        .unwrap();
        assert!(verdict.is_red());
        assert_eq!(read_history(&hist).unwrap().len(), 8);
    }
}
