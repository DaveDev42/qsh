//! Nightly perf job hooks for the two acceptance perf tests
//! (`tunnel_throughput.rs`, `tunnel_echo_under_load.rs`;
//! `docs/design/testing.md` CI 규율).
//!
//! - `QSH_PERF_OUT=<path>`: each perf test appends exactly one JSON line to
//!   that file after it has measured. When unset, nothing is written and the
//!   tests behave as they did before.
//! - `QSH_PERF_INJECT_DELAY_MS=<n>`: the test's loopback path gets a fixed
//!   one-way delay of `n` ms through the chaos proxy. This hook lives only in
//!   this harness crate; `qsh-core`, `qsh-transport` and the binary never
//!   read it.

use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

/// Env var naming the file the perf tests append a JSON line to.
pub const OUT_ENV: &str = "QSH_PERF_OUT";
/// Env var holding the injected one-way delay in milliseconds.
pub const INJECT_ENV: &str = "QSH_PERF_INJECT_DELAY_MS";

/// Seed for the delay-only chaos policy. Delay draws are fixed, so the seed
/// only has to exist.
pub const INJECT_SEED: u64 = 0x5eed_0013;

/// Parse an injected delay. Unset, empty, unparsable and zero all mean "no
/// injection", so a typo cannot silently slow a run.
pub fn parse_inject_delay_ms(raw: Option<&str>) -> u64 {
    raw.and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0)
}

/// The injected delay from the environment, `0` when none.
pub fn inject_delay_ms() -> u64 {
    parse_inject_delay_ms(std::env::var(INJECT_ENV).ok().as_deref())
}

/// A delay-only chaos policy for `ms` (`None` when `ms` is zero).
pub fn inject_policy(ms: u64) -> Option<crate::chaos::ChaosPolicy> {
    (ms > 0).then(|| {
        crate::chaos::ChaosPolicy::seeded(INJECT_SEED)
            .delay(crate::chaos::DelayDist::fixed(Duration::from_millis(ms)))
    })
}

/// Append `line` as one JSON line to `path`. `None` does nothing at all (no
/// file is created).
pub fn append_line(path: Option<&Path>, line: &Value) -> io::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut text = serde_json::to_string(line).map_err(io::Error::other)?;
    text.push('\n');
    // One write call keeps the line whole when two tests append in turn.
    file.write_all(text.as_bytes())
}

/// [`append_line`] to the path in `QSH_PERF_OUT`, if set and non-empty.
pub fn record(line: &Value) {
    let path = std::env::var_os(OUT_ENV).filter(|p| !p.is_empty());
    if let Err(err) = append_line(path.as_deref().map(Path::new), line) {
        panic!("{OUT_ENV}: could not append the perf line: {err}");
    }
}
