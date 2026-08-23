//! Recovery telemetry: how a session survived a dead path, and how long
//! it took (`docs/design/testing.md` L4, `docs/CLI.md` §6.4).
//!
//! SC3 ("≥95% of network transitions recover") is a measurement problem,
//! not a CI problem: the number comes from a real-device campaign, and the
//! campaign can only report it if every recovery leaves a machine-readable
//! trace. That trace starts in M2 so the M8 campaign has something to
//! count.
//!
//! **Exposure surface is deliberately narrow.** In M2 this is a structured
//! stderr diagnostic and nothing else:
//!
//! - tracing target [`TARGET`] (`qsh::recovery`), level `INFO`,
//! - rendered as a **single line of JSON** — the message *is* the JSON, so
//!   a campaign script can `grep '"recovery"'` and parse the line whole,
//! - fields `recovery`, `time_to_recovery_ms`, `session_ref` (M2), plus
//!   the additive `registration_wait_ms` (M3 Step 8, `docs/CLI.md` §6.4):
//!   `0` on the forward route, the measured re-registration wait on the
//!   reverse route. The `recovery` value set (`migrated`/`resumed`/
//!   `failed`) does not change — this is a field addition, not a new
//!   outcome.
//!
//! It is **not** a `qsh.event/v1` event and never reaches stdout: stdout
//! carries the contract envelope alone (CLI.md §2.2), and promoting
//! recovery to the event contract would freeze a field set we are still
//! learning the shape of. That promotion is a P1 decision.
//!
//! There is no field here that could carry a secret. `session_ref` is the
//! same public handle `qsh session list` prints; there is no token field,
//! no PTY content, no principal. `registration_wait_ms` is a plain
//! duration — it says nothing about *why* the wait happened, so it cannot
//! leak a resume token, a generation number, or anything else scoped to
//! this attach.

use std::fmt;
use std::time::Duration;

// tokio's monotonic clock, not `std::time::Instant`: it is the one a
// `#[tokio::test(start_paused = true)]` can advance, which is what lets
// the recovery tests assert a duration instead of sleeping for one
// (`docs/design/testing.md`: no `sleep()` in the correctness path).
use tokio::time::Instant;

/// The tracing target every recovery record carries. A campaign script
/// filters stderr on this (`QSH_LOG=qsh::recovery=info`) and the CLI
/// renders it specially so the line stays pure JSON.
pub const TARGET: &str = "qsh::recovery";

/// How a session got back to a live path.
///
/// The three-way split is the point: "it recovered" hides the difference
/// between QUIC keeping the connection alive across an address change and
/// the client having to rebuild everything from the resume token, and that
/// difference is what tells us whether migration is earning its keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recovery {
    /// The QUIC connection survived the path change — a rebind and/or
    /// peer-address migration was enough, no re-dial, no replay.
    Migrated,
    /// The connection died and the session was rebuilt on a new one via
    /// `session.attach` + the resume token. This is the correctness path;
    /// [`Recovery::Migrated`] is only ever a latency optimization on top.
    Resumed,
    /// Neither worked inside the deadline. Recorded, not swallowed: a
    /// silent failure is a campaign datapoint lost.
    Failed,
}

impl Recovery {
    /// The wire spelling used in the JSON line.
    pub fn as_str(self) -> &'static str {
        match self {
            Recovery::Migrated => "migrated",
            Recovery::Resumed => "resumed",
            Recovery::Failed => "failed",
        }
    }
}

impl fmt::Display for Recovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One recovery attempt, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// How it recovered — or that it did not.
    pub recovery: Recovery,
    /// Milliseconds from "this path is dead" to "bytes flow again". The
    /// clock starts at detection, not at the first symptom: a client that
    /// waits out a 45 s idle timeout and then reconnects has not met the
    /// 2 s bound, and starting the clock late would hide exactly that.
    pub time_to_recovery_ms: u64,
    /// The session this is about (`<host-alias>/<session_id>`, ADR-0007).
    pub session_ref: String,
    /// Milliseconds this recovery spent blocked on the target's
    /// re-registration before the resume itself could even start —
    /// `0` on the forward route (`DialReconnect`), which never waits on
    /// anything but its own dial; the measured wait on the reverse route
    /// (`LocalReconnect`, `PLAN.md` M3 Step 8, `docs/design/protocol.md`
    /// §11-4's Reattach mapping). Additive field (`docs/CLI.md` §6.4):
    /// added after the three fields M2 shipped, so an M2-era consumer
    /// that only reads those three keeps working unchanged. This is a
    /// **decomposition** of [`Self::time_to_recovery_ms`], not a second
    /// clock — `time_to_recovery_ms - registration_wait_ms` is the
    /// budget the resume itself actually spent, which is what lets a
    /// reverse-route recovery be judged against the same 2 s the forward
    /// route already is, instead of also being charged for the target's
    /// own backoff.
    pub registration_wait_ms: u64,
}

impl RecoveryReport {
    /// Assemble a report. `registration_wait_ms` is `0` for every route
    /// that never waits on a re-registration (the forward route, always);
    /// see the field's own doc.
    pub fn new(
        recovery: Recovery,
        elapsed: Duration,
        session_ref: impl Into<String>,
        registration_wait_ms: u64,
    ) -> Self {
        Self {
            recovery,
            // Saturating: a nonsense duration should skew a datapoint, not
            // panic a reconnect loop.
            time_to_recovery_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            session_ref: session_ref.into(),
            registration_wait_ms,
        }
    }

    /// The exact line emitted to stderr — compact JSON, no trailing
    /// newline, keys in a fixed order so a campaign log diffs cleanly.
    pub fn to_json_line(&self) -> String {
        // Hand-built rather than `serde_json::to_string` on a derived
        // `Serialize`: this string is the shape a campaign script reads,
        // and writing it out fixes the key order (serde_json's map sorts)
        // so a later field cannot silently reshuffle the line. Only
        // `session_ref` is free-form, so only it needs escaping.
        // `registration_wait_ms` is appended last — after the three keys
        // M2 shipped — so an existing prefix-matching consumer sees no
        // change to the keys it already knows.
        let session_ref = serde_json::Value::String(self.session_ref.clone());
        format!(
            r#"{{"recovery":"{}","time_to_recovery_ms":{},"session_ref":{},"registration_wait_ms":{}}}"#,
            self.recovery.as_str(),
            self.time_to_recovery_ms,
            session_ref,
            self.registration_wait_ms
        )
    }

    /// Emit the record on [`TARGET`] at `INFO`.
    ///
    /// The message *is* the JSON so that a subscriber which prints only
    /// the message (the CLI installs one for this target) produces a pure
    /// JSON line, while a default `fmt` subscriber still shows something
    /// readable. The typed fields ride along for anyone consuming tracing
    /// structurally.
    pub fn emit(&self) {
        tracing::info!(
            target: TARGET,
            recovery = self.recovery.as_str(),
            time_to_recovery_ms = self.time_to_recovery_ms,
            session_ref = %self.session_ref,
            registration_wait_ms = self.registration_wait_ms,
            "{}",
            self.to_json_line()
        );
    }
}

/// A running recovery: constructed the moment the path is declared dead,
/// resolved once the outcome is known.
///
/// Holding the start instant in a value that must be consumed to produce a
/// report is what keeps the measurement honest — there is no way to report
/// a recovery without having timed it from detection.
#[derive(Debug)]
pub struct RecoveryTimer {
    started: Instant,
    session_ref: String,
}

impl RecoveryTimer {
    /// Start timing at the point of detection.
    pub fn start(session_ref: impl Into<String>) -> Self {
        Self {
            started: Instant::now(),
            session_ref: session_ref.into(),
        }
    }

    /// How long the recovery has been running so far.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Resolve, emit and return the report. `registration_wait_ms` is the
    /// portion of the elapsed time (if any) that was spent waiting on a
    /// re-registration rather than performing the resume itself — see
    /// [`RecoveryReport::registration_wait_ms`]. Forward-route callers
    /// always pass `0`.
    pub fn finish(self, recovery: Recovery, registration_wait_ms: u64) -> RecoveryReport {
        let report = RecoveryReport::new(
            recovery,
            self.started.elapsed(),
            self.session_ref,
            registration_wait_ms,
        );
        report.emit();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_is_one_json_object_with_the_documented_fields() {
        let report = RecoveryReport::new(
            Recovery::Resumed,
            Duration::from_millis(412),
            "mac/01K0ABCD",
            0,
        );
        let line = report.to_json_line();
        assert!(!line.contains('\n'), "must be one line: {line}");
        assert_eq!(
            line,
            r#"{"recovery":"resumed","time_to_recovery_ms":412,"session_ref":"mac/01K0ABCD","registration_wait_ms":0}"#
        );

        let parsed: serde_json::Value = serde_json::from_str(&line).expect("pure JSON");
        let obj = parsed.as_object().expect("object");
        // Exactly the four documented fields — nothing that could carry a
        // token, a principal or PTY bytes has crept in.
        let mut keys: Vec<_> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "recovery",
                "registration_wait_ms",
                "session_ref",
                "time_to_recovery_ms"
            ]
        );
    }

    /// The additive field is not always zero: a reverse-route recovery
    /// carries its measured re-registration wait, and the wait can be
    /// read back out of the line exactly as written in.
    #[test]
    fn a_nonzero_registration_wait_round_trips_through_the_line() {
        let report = RecoveryReport::new(
            Recovery::Resumed,
            Duration::from_millis(900),
            "mac/01K0ABCD",
            650,
        );
        let line = report.to_json_line();
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("pure JSON");
        assert_eq!(parsed["registration_wait_ms"], 650);
        assert_eq!(parsed["time_to_recovery_ms"], 900);
    }

    #[test]
    fn every_outcome_has_a_stable_spelling() {
        assert_eq!(Recovery::Migrated.as_str(), "migrated");
        assert_eq!(Recovery::Resumed.as_str(), "resumed");
        assert_eq!(Recovery::Failed.as_str(), "failed");
        assert_eq!(Recovery::Failed.to_string(), "failed");
    }

    #[test]
    fn a_timer_measures_from_start_to_finish() {
        let timer = RecoveryTimer::start("mac/01K0");
        let report = timer.finish(Recovery::Migrated, 0);
        assert_eq!(report.recovery, Recovery::Migrated);
        assert_eq!(report.session_ref, "mac/01K0");
        assert_eq!(report.registration_wait_ms, 0);
        // No sleep, no wall-clock assumption: the only invariant a
        // monotonic clock owes us here is that it did not run backwards.
        assert!(report.time_to_recovery_ms < 60_000);
    }

    #[test]
    fn an_absurd_duration_saturates_instead_of_panicking() {
        let report = RecoveryReport::new(Recovery::Failed, Duration::MAX, "mac/01K0", 0);
        assert_eq!(report.time_to_recovery_ms, u64::MAX);
    }
}
