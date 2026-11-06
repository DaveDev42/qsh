//! Profile files: one TOML file is one run (link shape plus workload).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Lower-case slug; also the result's `profile` field.
    pub name: String,
    /// Which of the six ADR-0052 context questions this profile answers (`q1`..`q6`).
    pub question: String,
    #[serde(default)]
    pub description: String,
    pub link: Link,
    pub workload: Workload,
}

/// Link shape, applied to each direction independently.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    /// Round-trip propagation delay; each direction gets half.
    pub rtt_ms: f64,
    /// Random loss per direction, percent.
    #[serde(default)]
    pub loss_pct: f64,
    /// Bottleneck rate per direction in Mbit/s; 0 means unshaped.
    #[serde(default)]
    pub rate_mbit: f64,
    /// Bottleneck queue depth in milliseconds of drain time at `rate_mbit`.
    /// Required when `rate_mbit` is set.
    #[serde(default)]
    pub queue_ms: u32,
    /// Interface MTU of both veth ends.
    #[serde(default = "default_mtu")]
    pub mtu: u32,
}

fn default_mtu() -> u32 {
    1500
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Host sends screen states; client measures staleness.
    Screen,
    /// Client sends key records on a bidi stream; host echoes them.
    Echo,
    /// Echo plus a saturating host-to-client bulk transfer.
    BulkEcho,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    Datagram,
    Stream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Path {
    /// The workload runs on a direct QUIC connection.
    Direct,
    /// The workload runs on an inner QUIC connection whose packets ride the
    /// outer connection's DATAGRAMs.
    NestedDatagram,
    /// Same, but the packets ride one outer stream.
    NestedStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cc {
    Bbr,
    Cubic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// Echo and bulk share one connection at equal priority.
    SameConn,
    /// Echo and bulk share one connection; the echo stream has higher priority.
    Priority,
    /// Bulk runs on a second connection.
    SeparateConn,
    /// Echo and bulk share one connection, the echo stream has higher
    /// priority, and the bulk writer yields to it with a port of qsh's bulk
    /// governor (`yielder.rs`, ADR-0052 decision 12 (a)).
    Yield,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub kind: Kind,
    #[serde(default = "default_carrier")]
    pub carrier: Carrier,
    #[serde(default = "default_path")]
    pub path: Path,
    #[serde(default = "default_cc")]
    pub cc: Cc,
    #[serde(default = "default_isolation")]
    pub isolation: Isolation,
    #[serde(default = "default_duration")]
    pub duration_s: u32,
    /// Samples produced earlier than this after the start are dropped.
    #[serde(default = "default_warmup")]
    pub warmup_s: u32,
    #[serde(default = "default_frame_interval")]
    pub frame_interval_ms: u32,
    #[serde(default = "default_state_bytes")]
    pub state_bytes: u32,
    #[serde(default = "default_key_interval")]
    pub key_interval_ms: u32,
    /// Outer connection's QUIC datagram send buffer in KiB; absent keeps the
    /// quinn default (1 MiB, which drops the oldest datagram when full).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datagram_send_buffer_kib: Option<u32>,
}

fn default_carrier() -> Carrier {
    Carrier::Stream
}
fn default_path() -> Path {
    Path::Direct
}
fn default_cc() -> Cc {
    Cc::Bbr
}
fn default_isolation() -> Isolation {
    Isolation::SameConn
}
fn default_duration() -> u32 {
    20
}
fn default_warmup() -> u32 {
    2
}
fn default_frame_interval() -> u32 {
    20
}
fn default_state_bytes() -> u32 {
    800
}
fn default_key_interval() -> u32 {
    50
}

impl Profile {
    pub fn parse(text: &str) -> anyhow::Result<Profile> {
        let p: Profile = toml::from_str(text)?;
        p.validate()?;
        Ok(p)
    }

    pub fn load(path: &std::path::Path) -> anyhow::Result<Profile> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
        Profile::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::ensure;
        let ok_name = !self.name.is_empty()
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        ensure!(ok_name, "name must be [a-z0-9-]+, got {:?}", self.name);
        ensure!(
            matches!(
                self.question.as_str(),
                "q1" | "q2" | "q3" | "q4" | "q5" | "q6"
            ),
            "question must be q1..q6, got {:?}",
            self.question
        );
        let l = &self.link;
        ensure!(
            l.rtt_ms.is_finite() && (0.0..=2000.0).contains(&l.rtt_ms),
            "rtt_ms must be in 0..=2000"
        );
        ensure!(
            l.loss_pct.is_finite() && (0.0..=50.0).contains(&l.loss_pct),
            "loss_pct must be in 0..=50"
        );
        ensure!(
            l.rate_mbit.is_finite() && (0.0..=10_000.0).contains(&l.rate_mbit),
            "rate_mbit must be in 0..=10000"
        );
        ensure!(
            l.rate_mbit == 0.0 || l.queue_ms > 0,
            "queue_ms is required when rate_mbit is set"
        );
        ensure!(
            l.rate_mbit > 0.0 || l.queue_ms == 0,
            "queue_ms without rate_mbit has no meaning"
        );
        ensure!((1280..=9000).contains(&l.mtu), "mtu must be in 1280..=9000");
        let w = &self.workload;
        ensure!(
            (1..=600).contains(&w.duration_s),
            "duration_s must be in 1..=600"
        );
        ensure!(
            w.warmup_s < w.duration_s,
            "warmup_s must be below duration_s"
        );
        ensure!(w.frame_interval_ms >= 1, "frame_interval_ms must be >= 1");
        ensure!(w.key_interval_ms >= 5, "key_interval_ms must be >= 5");
        ensure!(
            (32..=1100).contains(&w.state_bytes),
            "state_bytes must be in 32..=1100 so a state fits one datagram"
        );
        ensure!(
            !(w.isolation == Isolation::SeparateConn && w.path != Path::Direct),
            "isolation separate_conn needs path direct"
        );
        ensure!(
            w.kind == Kind::BulkEcho || w.isolation == Isolation::SameConn,
            "isolation only applies to kind bulk_echo"
        );
        Ok(())
    }

    /// One-way propagation delay in nanoseconds (subtracted from staleness).
    pub fn one_way_ns(&self) -> u64 {
        (self.link.rtt_ms * 1_000_000.0 / 2.0).round() as u64
    }

    /// `KEY=VALUE` lines the shell driver evals. Every value is a plain number
    /// or a slug, so the output is safe to `eval`.
    pub fn shell_env(&self) -> String {
        let l = &self.link;
        let delay_us = (l.rtt_ms * 1000.0 / 2.0).round() as u64;
        let rate_kbit = (l.rate_mbit * 1000.0).round() as u64;
        // tbf needs a burst of at least rate/HZ (HZ 250 worst case); keep it
        // small so the configured queue depth is what the profile measures.
        let burst_bytes = if rate_kbit == 0 {
            0
        } else {
            (rate_kbit * 1000 / 8 / 250 * 2).max(2 * u64::from(l.mtu))
        };
        // tbf's `limit` counts the bucket too (its backlog is limit - burst),
        // so the queue is `queue_ms` of drain time plus one burst.
        let limit_bytes = if rate_kbit == 0 {
            0
        } else {
            let queue = rate_kbit * 1000 / 8 * u64::from(l.queue_ms) / 1000;
            queue.max(2 * u64::from(l.mtu)) + burst_bytes
        };
        format!(
            "NB_NAME={}\nNB_DELAY_US={delay_us}\nNB_LOSS_PCT={}\nNB_RATE_KBIT={rate_kbit}\nNB_LIMIT_BYTES={limit_bytes}\nNB_BURST_BYTES={burst_bytes}\nNB_MTU={}\nNB_DURATION_S={}\n",
            self.name, l.loss_pct, l.mtu, self.workload.duration_s
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: &str = r#"
name = "t"
question = "q1"
[link]
rtt_ms = 150
[workload]
kind = "screen"
"#;

    #[test]
    fn minimal_profile_gets_defaults() {
        let p = Profile::parse(MIN).unwrap();
        assert_eq!(p.link.mtu, 1500);
        assert_eq!(p.link.loss_pct, 0.0);
        assert_eq!(p.workload.carrier, Carrier::Stream);
        assert_eq!(p.workload.cc, Cc::Bbr);
        assert_eq!(p.workload.path, Path::Direct);
        assert_eq!(p.workload.duration_s, 20);
        assert_eq!(p.one_way_ns(), 75_000_000);
    }

    #[test]
    fn unknown_keys_and_values_are_rejected() {
        assert!(Profile::parse(&MIN.replace("rtt_ms = 150", "rtt_ms = 150\nlag = 1")).is_err());
        assert!(Profile::parse(&MIN.replace("screen", "teleport")).is_err());
        assert!(Profile::parse(&MIN.replace("q1", "q9")).is_err());
        assert!(Profile::parse(&MIN.replace("\"t\"", "\"Bad Name\"")).is_err());
    }

    #[test]
    fn rate_and_queue_must_come_together() {
        let with_rate = MIN.replace("rtt_ms = 150", "rtt_ms = 150\nrate_mbit = 20");
        assert!(Profile::parse(&with_rate).is_err());
        let both = with_rate.replace("rate_mbit = 20", "rate_mbit = 20\nqueue_ms = 25");
        assert!(Profile::parse(&both).is_ok());
        let queue_only = MIN.replace("rtt_ms = 150", "rtt_ms = 150\nqueue_ms = 25");
        assert!(Profile::parse(&queue_only).is_err());
    }

    #[test]
    fn isolation_rules() {
        let iso = MIN.replace(
            "kind = \"screen\"",
            "kind = \"screen\"\nisolation = \"priority\"",
        );
        assert!(Profile::parse(&iso).is_err());
        let ok = MIN.replace(
            "kind = \"screen\"",
            "kind = \"bulk_echo\"\nisolation = \"priority\"",
        );
        assert!(Profile::parse(&ok).is_ok());
        let bad = MIN.replace(
            "kind = \"screen\"",
            "kind = \"bulk_echo\"\nisolation = \"separate_conn\"\npath = \"nested_stream\"",
        );
        assert!(Profile::parse(&bad).is_err());
    }

    #[test]
    fn shell_env_converts_queue_depth_to_bytes() {
        let t = MIN.replace(
            "rtt_ms = 150",
            "rtt_ms = 150\nloss_pct = 3\nrate_mbit = 20\nqueue_ms = 25",
        );
        let env = Profile::parse(&t).unwrap().shell_env();
        assert!(env.contains("NB_DELAY_US=75000\n"), "{env}");
        assert!(env.contains("NB_LOSS_PCT=3\n"), "{env}");
        assert!(env.contains("NB_RATE_KBIT=20000\n"), "{env}");
        // 20 Mbit/s = 2.5 MB/s; 25 ms of it is 62500 bytes, plus the 20000-byte bucket.
        assert!(env.contains("NB_LIMIT_BYTES=82500\n"), "{env}");
        assert!(env.contains("NB_BURST_BYTES=20000\n"), "{env}");
    }

    #[test]
    fn unshaped_link_has_no_limit() {
        let env = Profile::parse(MIN).unwrap().shell_env();
        assert!(env.contains("NB_RATE_KBIT=0\n"));
        assert!(env.contains("NB_LIMIT_BYTES=0\n"));
    }

    #[test]
    fn every_checked_in_profile_parses() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
        let mut n = 0;
        for e in std::fs::read_dir(dir).unwrap() {
            let path = e.unwrap().path();
            if path.extension().is_some_and(|x| x == "toml") {
                let p = Profile::load(&path).unwrap();
                assert_eq!(
                    path.file_stem().unwrap().to_str().unwrap(),
                    p.name,
                    "file name must match profile name"
                );
                n += 1;
            }
        }
        assert!(n >= 20, "expected the full profile set, found {n}");
    }
}
