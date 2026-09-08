#!/usr/bin/env python3
"""summarize.py — judge a qsh soak-run CSV against BRIEF-5.md §4.4.

`crates/qsh-cli/tests/soak.rs` writes one CSV row per sample
(`t_secs,phase,listener_rss_kib,listener_fds,self_rss_kib,self_fds,
live_sessions,cycles,echo_p95_ms,abandoned_live` — pinned by
`soak_csv_header_is_pinned`, checked against that exact string below) and
already asserts the axes of §4.4 it can judge from inside a single short
run: idle RSS/fd bounds, echo p95, TTL reap, and (as `FD_GROWTH_CLIENT`) the
client-side fd-growth check — judged on the steady-phase quarters (growth
*during* cycling), with the boot-baseline-vs-drain-idle_end self-fd delta
recorded as an informational line only, never a violation (that span also
bundles in ramp's one-shot session-open/attach fd cost). Dial retries on a
retryable `OpError` during ramp/cycle opens are likewise recorded, not a
violation, in the test binary's own stderr — this script does not see them
since they never reach the CSV. This script re-derives the *same* §4.4 table
from the CSV, plus the two axes the test binary only ever records because a
120s short run has too few samples to fit them — the per-session buffer
bound and the RSS-trend regression slope — which is why `scripts/soak/
run.sh` treats a soak round as a pass only when both the test binary's own
assertions and this script's judgment agree.

The echo p95 bound is adaptive: `max(3 x same-run baseline, ECHO_P95_BOUND_MS)`.
soak.rs writes that same-run baseline into the CSV itself, as the
`echo_p95_ms` field of a single row tagged `phase == "ramp"` (neither
"boot", "steady", nor "drain", so it is invisible to every phase-filtered
check below). `evaluate()` derives `echo_baseline_ms` from that row when the
caller does not pass `--echo-baseline-ms` explicitly; the flag, when given,
still wins outright (PROGRESS-5.md §F2 — before this row existed, soak.rs
judged steady echo p95 against its own in-process baseline while this
script, never handed that number, silently fell back to the fixed floor:
two judges, two different bounds for the same run).

Stdlib only. Usage:

    scripts/soak/summarize.py samples.csv --sessions 100
    scripts/soak/summarize.py samples.csv --sessions 100 --json
    scripts/soak/summarize.py --self-test
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from typing import NamedTuple

# Kept as one contiguous literal (not split across concatenated strings)
# so `crates/qsh-cli/tests/soak.rs`'s `summarize_py_pins_the_same_csv_header`
# test can `include_str!` this file and grep for the exact `SOAK_CSV_HEADER`
# text byte-for-byte (REVIEW-5-B B10 / ARBITRATION-5 F2) — a value built
# from adjacent string literals never appears as one contiguous run in the
# file's own source text, only in the interpreter's evaluated result.
CSV_HEADER = "t_secs,phase,listener_rss_kib,listener_fds,self_rss_kib,self_fds,live_sessions,cycles,echo_p95_ms,abandoned_live"

IDLE_RSS_BOUND_KIB = 30 * 1024
PER_SESSION_BUFFER_BOUND_KIB = 8 * 1024
RSS_TREND_BOUND_KIB_PER_HOUR = 1024
FD_GROWTH_ALLOWANCE = 2
ECHO_P95_BOUND_MS = 50.0  # floor of the adaptive bound — see `evaluate`'s `echo_baseline_ms`
# `qsh_core::broker::REAPER_TICK`, mirrored (not importable from Rust) —
# `crates/qsh-cli/tests/soak.rs`'s `ttl_reap_deadline` uses the same value.
REAPER_TICK_SECS = 30
TREND_MIN_SPAN_SECS = 3600  # below this, too few samples for a fitted slope to mean anything
# Minimum steady-phase sample count before a fd-growth quarters check is
# trusted as a hard assert rather than downgraded to a recorded note —
# mirrors `crates/qsh-cli/tests/soak.rs`'s identical `MIN_QUARTER_SAMPLES`
# (REVIEW-5-B/C B8 / ARBITRATION-5 F2).
MIN_QUARTER_SAMPLES = 8

SNAPSHOT_HOURS = (0, 1, 6, 12, 24)


class Row(NamedTuple):
    t_secs: int
    phase: str
    listener_rss_kib: int | None
    listener_fds: int | None
    self_rss_kib: int | None
    self_fds: int | None
    live_sessions: int
    cycles: int
    echo_p95_ms: float | None
    abandoned_live: int


def _opt_int(value: str) -> int | None:
    value = value.strip()
    return None if value == "" else int(value)


def _opt_float(value: str) -> float | None:
    value = value.strip()
    return None if value == "" else float(value)


def read_rows(stream) -> list[Row]:
    reader = csv.reader(stream)
    try:
        header = next(reader)
    except StopIteration:
        return []
    got = ",".join(header)
    if got != CSV_HEADER:
        raise ValueError(
            f"CSV header does not match the soak.rs-pinned column order — "
            f"got {got!r}, want {CSV_HEADER!r} "
            f"(crates/qsh-cli/tests/soak.rs SOAK_CSV_HEADER)"
        )
    # Buffered (not streamed row-by-row) so a malformed row can be told
    # apart from "the last line in the file" (REVIEW-5-B B11 /
    # ARBITRATION-5 F2): a `qsh serve` subprocess or the harness itself
    # getting killed mid-write leaves a single truncated trailing row,
    # which is a normal, recoverable end-of-run artifact worth a warning
    # and a drop; the same wrong-column-count shape *anywhere else* in the
    # file is real corruption worth failing loudly on, naming the row.
    raw_rows = [fields for fields in reader if fields]
    rows: list[Row] = []
    last_index = len(raw_rows) - 1
    for i, fields in enumerate(raw_rows):
        if len(fields) != 10:
            # Row 1 is the header, so the first data row is row 2.
            row_number = i + 2
            if i == last_index:
                print(
                    f"summarize.py: dropping truncated trailing row {row_number} "
                    f"({len(fields)} column(s), want 10) — treated as an incomplete "
                    f"in-progress write, not corruption: {fields!r}",
                    file=sys.stderr,
                )
                continue
            raise ValueError(
                f"row {row_number} has {len(fields)} column(s), want 10: {fields!r}"
            )
        rows.append(
            Row(
                t_secs=int(fields[0]),
                phase=fields[1],
                listener_rss_kib=_opt_int(fields[2]),
                listener_fds=_opt_int(fields[3]),
                self_rss_kib=_opt_int(fields[4]),
                self_fds=_opt_int(fields[5]),
                live_sessions=int(fields[6]),
                cycles=int(fields[7]),
                echo_p95_ms=_opt_float(fields[8]),
                abandoned_live=int(fields[9]),
            )
        )
    return rows


def linear_regression_slope(points: list[tuple[float, float]]) -> float | None:
    """Ordinary least-squares slope, no numpy. `points` is (x, y); returns
    None when there are fewer than two distinct x values (an undefined
    slope, not a zero one — a flat line and "can't tell" must never render
    the same way)."""
    n = len(points)
    if n < 2:
        return None
    sum_x = sum(x for x, _ in points)
    sum_y = sum(y for _, y in points)
    mean_x = sum_x / n
    mean_y = sum_y / n
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in points)
    denominator = sum((x - mean_x) ** 2 for x, _ in points)
    if denominator == 0:
        return None
    return numerator / denominator


def quarter_split(values: list[int]) -> tuple[list[int], list[int]]:
    """First-quarter and last-quarter slices of a time-ordered series
    (§4.4's fd-growth axes compare these). At least one element each once
    the series is non-empty — a series of 1-3 samples puts everything in
    both quarters rather than raising, since that only makes *this
    function's* comparison stricter (comparing a value against itself),
    never silently skipped here. Whether the result is trusted as a hard
    assert or only recorded as a note when the series is short (fewer than
    MIN_QUARTER_SAMPLES total) is entirely the caller's call in `evaluate`
    — this function never downgrades or refuses to split (mirrors
    `crates/qsh-cli/tests/soak.rs`'s identical `quarter_split` — REVIEW-5-B/C
    B8 / ARBITRATION-5 F2)."""
    n = len(values)
    if n == 0:
        return [], []
    q = max(1, n // 4)
    return values[:q], values[-q:]


def evaluate(
    rows: list[Row],
    sessions: int,
    resume_ttl_secs: int | None = None,
    echo_baseline_ms: float | None = None,
) -> dict:
    violations: list[str] = []
    notes: list[str] = []

    boot_rows = [r for r in rows if r.phase == "boot"]
    steady_rows = [r for r in rows if r.phase == "steady"]
    drain_rows = [r for r in rows if r.phase == "drain"]

    result: dict = {"violations": violations, "notes": notes, "rows": len(rows)}

    if not boot_rows or not drain_rows:
        violations.append(
            f"CSV has {len(boot_rows)} boot row(s) and {len(drain_rows)} drain row(s) — "
            "need at least one of each to judge idle RSS/fd bounds"
        )
        return result

    baseline = boot_rows[0]
    idle_end = drain_rows[-1]
    result["baseline_rss_kib"] = baseline.listener_rss_kib
    result["idle_end_rss_kib"] = idle_end.listener_rss_kib
    result["baseline_fds"] = baseline.listener_fds
    result["idle_end_fds"] = idle_end.listener_fds

    # --- idle listener RSS ---
    for label, row in (("baseline", baseline), ("idle-end", idle_end)):
        if row.listener_rss_kib is not None and row.listener_rss_kib > IDLE_RSS_BOUND_KIB:
            violations.append(
                f"{label} listener RSS {row.listener_rss_kib} KiB exceeds "
                f"{IDLE_RSS_BOUND_KIB} KiB idle bound"
            )

    # --- per-session buffer ---
    listener_rss_series = [r.listener_rss_kib for r in rows if r.listener_rss_kib is not None]
    if listener_rss_series and baseline.listener_rss_kib is not None and sessions > 0:
        peak_rss = max(listener_rss_series)
        per_session = (peak_rss - baseline.listener_rss_kib) / sessions
        result["peak_rss_kib"] = peak_rss
        result["per_session_buffer_kib"] = per_session
        if per_session > PER_SESSION_BUFFER_BOUND_KIB:
            violations.append(
                f"per-session buffer {per_session:.1f} KiB (peak {peak_rss} KiB, baseline "
                f"{baseline.listener_rss_kib} KiB, {sessions} sessions) exceeds "
                f"{PER_SESSION_BUFFER_BOUND_KIB} KiB bound"
            )
        secondary_bound = IDLE_RSS_BOUND_KIB + PER_SESSION_BUFFER_BOUND_KIB * sessions
        result["peak_rss_secondary_bound_kib"] = secondary_bound
        if peak_rss > secondary_bound:
            notes.append(
                f"peak RSS {peak_rss} KiB exceeds the secondary bound "
                f"{secondary_bound} KiB (30 MiB + 8 MiB x {sessions}) — recorded only, "
                "§4.4 marks this axis as a secondary record, not an assertion"
            )

    # --- RSS trend (steady-phase regression slope) ---
    steady_points = [
        (float(r.t_secs), float(r.listener_rss_kib))
        for r in steady_rows
        if r.listener_rss_kib is not None
    ]
    span = (steady_rows[-1].t_secs - steady_rows[0].t_secs) if len(steady_rows) >= 2 else 0
    result["steady_span_secs"] = span
    slope_kib_per_sec = linear_regression_slope(steady_points)
    if slope_kib_per_sec is not None:
        slope_mib_per_hour = slope_kib_per_sec * 3600.0 / 1024.0
        result["rss_trend_mib_per_hour"] = slope_mib_per_hour
        if span < TREND_MIN_SPAN_SECS:
            notes.append(
                f"RSS trend slope {slope_mib_per_hour:.4f} MiB/h fitted over only {span}s of "
                f"steady state (< {TREND_MIN_SPAN_SECS}s) — recorded only, too few samples for "
                "the 24h-mode assertion"
            )
        elif slope_mib_per_hour >= RSS_TREND_BOUND_KIB_PER_HOUR / 1024.0:
            violations.append(
                f"RSS trend slope {slope_mib_per_hour:.4f} MiB/h over {span}s of steady state "
                f"meets or exceeds the {RSS_TREND_BOUND_KIB_PER_HOUR / 1024.0} MiB/h bound"
            )
    else:
        notes.append("RSS trend: not enough steady-phase RSS samples to fit a slope")

    # --- listener fd growth ---
    if baseline.listener_fds is not None and idle_end.listener_fds is not None:
        delta = idle_end.listener_fds - baseline.listener_fds
        if delta > FD_GROWTH_ALLOWANCE:
            violations.append(
                f"listener fd grew by {delta} (baseline {baseline.listener_fds}, idle-end "
                f"{idle_end.listener_fds}), exceeds the {FD_GROWTH_ALLOWANCE} allowance"
            )
    listener_fd_series = [r.listener_fds for r in steady_rows if r.listener_fds is not None]
    if 0 < len(listener_fd_series) < MIN_QUARTER_SAMPLES:
        notes.append(
            f"listener fd quarters check skipped — only {len(listener_fd_series)} steady "
            f"sample(s), fewer than the {MIN_QUARTER_SAMPLES} needed for the split to mean "
            "anything"
        )
    else:
        first_q, last_q = quarter_split(listener_fd_series)
        if first_q and last_q:
            delta_q = max(last_q) - max(first_q)
            result["listener_fd_quarter_delta"] = delta_q
            if delta_q > FD_GROWTH_ALLOWANCE:
                violations.append(
                    f"FD_GROWTH_LISTENER: listener fd steady-state quarter max grew by "
                    f"{delta_q} (first-quarter max {max(first_q)}, last-quarter max "
                    f"{max(last_q)}), exceeds the {FD_GROWTH_ALLOWANCE} allowance"
                )

    # --- self (test process) fd growth — a violation here is (iii)
    # reproducing, tagged the same way soak.rs tags it, never silently
    # merged into the generic message. Judged on the steady-phase quarters
    # only (growth *during* cycling) — the boot-baseline-vs-drain-idle_end
    # span is recorded as an informational note instead, never a violation,
    # since it also bundles in ramp's one-shot session-open/attach fd cost
    # (runtime warm-up), which is not what (iii) is about (main's F1 call,
    # PROGRESS-5.md S5 "self fd 판정식 불일치"). ---
    if baseline.self_fds is not None and idle_end.self_fds is not None:
        delta = idle_end.self_fds - baseline.self_fds
        result["self_fd_baseline_idle_end_delta"] = delta
        notes.append(
            f"self fd boot-baseline->drain-idle_end delta={delta} (baseline "
            f"{baseline.self_fds}, idle-end {idle_end.self_fds}) — runtime warm-up, recorded "
            "only, never a violation; the (iii) axis is judged on the steady-phase quarters "
            "check below"
        )
    self_fd_series = [r.self_fds for r in steady_rows if r.self_fds is not None]
    if 0 < len(self_fd_series) < MIN_QUARTER_SAMPLES:
        notes.append(
            f"self fd quarters check skipped — only {len(self_fd_series)} steady sample(s), "
            f"fewer than the {MIN_QUARTER_SAMPLES} needed for the split to mean anything"
        )
    else:
        first_q, last_q = quarter_split(self_fd_series)
        if first_q and last_q:
            delta_q = max(last_q) - max(first_q)
            result["self_fd_quarter_delta"] = delta_q
            if delta_q > FD_GROWTH_ALLOWANCE:
                violations.append(
                    f"FD_GROWTH_CLIENT: self fd steady-state quarter max grew by {delta_q} "
                    f"(first-quarter max {max(first_q)}, last-quarter max {max(last_q)}), "
                    f"exceeds the {FD_GROWTH_ALLOWANCE} allowance — M7 carryover (iii), the "
                    "per-pull dial fd cost, reproduced"
                )

    # --- echo p95 --- adaptive bound (REVIEW-5-C C9 / ARBITRATION-5 F2): a
    # fixed absolute number is what a shared, contended runner cannot
    # promise, so the bound becomes max(3 x baseline, the ECHO_P95_BOUND_MS
    # floor) — the same formula `adversarial_load.rs`'s T2 scenario uses
    # (`docs/design/testing.md:126`) and soak.rs's own verdict uses. The
    # baseline itself: an explicit `--echo-baseline-ms` always wins when
    # given (`"flag"`); otherwise it is derived from the CSV's own
    # `phase == "ramp"` row(s) — the same same-run baseline soak.rs measured
    # right after ramp and writes back into the CSV for exactly this
    # (`"ramp-row"`, PROGRESS-5.md §F2 — before that row existed, this
    # script had no way to see that number and silently judged every run
    # against the fixed floor instead). No ramp row and no flag leaves the
    # baseline unset (`"none"`) and the bound at the fixed floor, same as
    # before this row existed.
    echo_p95_baseline_source = "flag"
    if echo_baseline_ms is None:
        ramp_baselines = [
            r.echo_p95_ms for r in rows if r.phase == "ramp" and r.echo_p95_ms is not None
        ]
        if ramp_baselines:
            echo_baseline_ms = max(ramp_baselines)
            echo_p95_baseline_source = "ramp-row"
        else:
            echo_p95_baseline_source = "none"
    result["echo_p95_baseline_source"] = echo_p95_baseline_source
    echo_bound_ms = ECHO_P95_BOUND_MS
    if echo_baseline_ms is not None:
        echo_bound_ms = max(3.0 * echo_baseline_ms, ECHO_P95_BOUND_MS)
        result["echo_p95_baseline_ms"] = echo_baseline_ms
    result["echo_p95_bound_ms"] = echo_bound_ms
    echo_series = [r.echo_p95_ms for r in steady_rows if r.echo_p95_ms is not None]
    if echo_series:
        max_echo = max(echo_series)
        result["max_echo_p95_ms"] = max_echo
        if max_echo > echo_bound_ms:
            violations.append(
                f"echo p95 {max_echo:.3f}ms exceeds the {echo_bound_ms:.3f}ms bound "
                f"(max(3 x baseline {echo_baseline_ms}, {ECHO_P95_BOUND_MS}ms floor)) in at "
                "least one steady window"
            )

    # --- TTL reap --- (REVIEW-5-C C4 / REVIEW-5-B B7 / ARBITRATION-5 F2):
    # judged against `resume_ttl_secs + REAPER_TICK`, not an unconditional
    # "must be 0 at drain" — `resume_ttl_secs` is independently env-tunable
    # (up to 600s in 24h mode), and a run whose total elapsed time hasn't
    # reached that deadline yet has nothing to judge. The CSV has no
    # abandon-signal timestamp of its own, so this approximates it as the
    # boot row's t_secs (abandon is signaled immediately after ramp, close
    # to t=0) — same approximation `crates/qsh-cli/tests/soak.rs` makes by
    # measuring from its own in-process `abandon_signaled_at` instant,
    # which likewise lands right after boot.
    result["idle_end_abandoned_live"] = idle_end.abandoned_live
    if resume_ttl_secs is None:
        if idle_end.abandoned_live != 0:
            violations.append(
                f"{idle_end.abandoned_live} abandoned session(s) still counted live at drain — "
                "TTL reap did not run"
            )
    else:
        ttl_elapsed = idle_end.t_secs - baseline.t_secs
        deadline = resume_ttl_secs + REAPER_TICK_SECS
        result["ttl_reap_deadline_secs"] = deadline
        if ttl_elapsed >= deadline:
            if idle_end.abandoned_live != 0:
                violations.append(
                    f"{idle_end.abandoned_live} abandoned session(s) still counted live at "
                    f"drain ({ttl_elapsed}s since boot >= the {deadline}s resume_ttl+"
                    "REAPER_TICK deadline) — TTL reap did not run"
                )
        else:
            notes.append(
                f"TTL reap: only {ttl_elapsed}s elapsed since boot, short of the {deadline}s "
                f"resume_ttl+REAPER_TICK deadline — abandoned_live={idle_end.abandoned_live} "
                "not yet judged"
            )

    return result


def snapshot_rows(rows: list[Row]) -> list[dict]:
    """Nearest-sample row at each of the 0h/1h/6h/12h/24h marks
    (BRIEF-5.md §5), formatted for a direct paste into `docs/campaigns/
    m8-soak.md`'s record template. Nearest-sample, not interpolated —
    a soak run's sample interval (2s default, `QSH_SOAK_SAMPLE_SECS`) is
    far finer than these marks, so the nearest actual row is always close
    enough, and it is always a row that really happened."""
    out: list[dict] = []
    if not rows:
        return out
    for hours in SNAPSHOT_HOURS:
        target = hours * 3600
        nearest = min(rows, key=lambda r: abs(r.t_secs - target))
        out.append(
            {
                "hours": hours,
                "t_secs": nearest.t_secs,
                "phase": nearest.phase,
                "listener_rss_kib": nearest.listener_rss_kib,
                "listener_fds": nearest.listener_fds,
                "self_rss_kib": nearest.self_rss_kib,
                "self_fds": nearest.self_fds,
                "live_sessions": nearest.live_sessions,
                "cycles": nearest.cycles,
                "echo_p95_ms": nearest.echo_p95_ms,
                "abandoned_live": nearest.abandoned_live,
            }
        )
    return out


def render(result: dict, snapshots: list[dict]) -> str:
    lines: list[str] = []
    lines.append(f"rows read: {result['rows']}")
    lines.append("")
    lines.append("BRIEF-5.md §4.4 table")
    lines.append(f"  idle listener RSS       baseline={result.get('baseline_rss_kib')} KiB  "
                 f"idle_end={result.get('idle_end_rss_kib')} KiB  bound<={IDLE_RSS_BOUND_KIB} KiB")
    if "per_session_buffer_kib" in result:
        lines.append(
            f"  per-session buffer      {result['per_session_buffer_kib']:.1f} KiB/session  "
            f"(peak={result.get('peak_rss_kib')} KiB)  bound<={PER_SESSION_BUFFER_BOUND_KIB} KiB"
        )
    if "rss_trend_mib_per_hour" in result:
        lines.append(
            f"  RSS trend               {result['rss_trend_mib_per_hour']:.4f} MiB/h over "
            f"{result.get('steady_span_secs')}s steady  bound<{RSS_TREND_BOUND_KIB_PER_HOUR / 1024.0} MiB/h"
        )
    lines.append(f"  listener fd             baseline={result.get('baseline_fds')}  "
                 f"idle_end={result.get('idle_end_fds')}  allowance<=+{FD_GROWTH_ALLOWANCE}")
    if "listener_fd_quarter_delta" in result:
        lines.append(f"  listener fd (quarters)  delta={result['listener_fd_quarter_delta']}  "
                     f"allowance<=+{FD_GROWTH_ALLOWANCE}")
    if "self_fd_baseline_idle_end_delta" in result:
        lines.append(
            f"  self fd (baseline->idle_end)  delta={result['self_fd_baseline_idle_end_delta']}  "
            "informational only, never a violation (runtime warm-up)"
        )
    if "self_fd_quarter_delta" in result:
        lines.append(f"  self fd (quarters)      delta={result['self_fd_quarter_delta']}  "
                     f"allowance<=+{FD_GROWTH_ALLOWANCE}  (violation tagged FD_GROWTH_CLIENT)")
    if "max_echo_p95_ms" in result:
        baseline_note = (
            f" (baseline={result['echo_p95_baseline_ms']}ms via {result['echo_p95_baseline_source']})"
            if "echo_p95_baseline_ms" in result
            else f" (baseline source: {result['echo_p95_baseline_source']})"
        )
        lines.append(f"  echo p95 (max)          {result['max_echo_p95_ms']:.3f}ms  "
                     f"bound<={result.get('echo_p95_bound_ms', ECHO_P95_BOUND_MS):.3f}ms{baseline_note}")
    if "ttl_reap_deadline_secs" in result:
        lines.append(
            f"  TTL reap                abandoned_live at drain="
            f"{result.get('idle_end_abandoned_live')}  want=0 once elapsed>="
            f"{result['ttl_reap_deadline_secs']}s (resume_ttl+REAPER_TICK)"
        )
    else:
        lines.append(f"  TTL reap                abandoned_live at drain={result.get('idle_end_abandoned_live')}  "
                     "want=0")

    if result["notes"]:
        lines.append("")
        lines.append("notes (recorded, not asserted)")
        for note in result["notes"]:
            lines.append(f"  - {note}")

    lines.append("")
    if result["violations"]:
        lines.append(f"verdict: FAIL ({len(result['violations'])} violation(s))")
        for v in result["violations"]:
            lines.append(f"  - {v}")
    else:
        lines.append("verdict: pass")

    if snapshots:
        lines.append("")
        lines.append("snapshot rows (paste into docs/campaigns/m8-soak.md's record template)")
        lines.append(
            "  hour  t_secs  phase   listener_rss_kib  listener_fds  self_rss_kib  self_fds  "
            "live_sessions  cycles  echo_p95_ms  abandoned_live"
        )
        for s in snapshots:
            lines.append(
                f"  {s['hours']:>4}  {s['t_secs']:>6}  {s['phase']:<6}  "
                f"{s['listener_rss_kib']!s:>16}  {s['listener_fds']!s:>12}  "
                f"{s['self_rss_kib']!s:>12}  {s['self_fds']!s:>8}  "
                f"{s['live_sessions']!s:>13}  {s['cycles']!s:>6}  "
                f"{s['echo_p95_ms']!s:>11}  {s['abandoned_live']!s:>14}"
            )
    return "\n".join(lines)


## Both fixtures below carry 9 steady rows, not 4 — one more than
## MIN_QUARTER_SAMPLES(8) needs, so the self-test below exercises the real
## fd-growth quarters assert instead of always taking the "too few samples,
## downgrade to a note" branch (REVIEW-5-B/C B8 / ARBITRATION-5 F2). The
## time grid (0/900/1800/2700/3600/5400/7200/9000/10800) keeps exact hour
## marks at 0 and 3600 so `snapshot_rows`' 0h/1h nearest-sample self-test
## checks below still resolve to an exact match, not an interpolated
## nearest-neighbor guess.
PASSING_CSV = (
    CSV_HEADER + "\n"
    "0,boot,20000,10,15000,8,0,0,,0\n"
    "0,steady,20500,10,15200,8,8,0,12.5,0\n"
    "900,steady,20550,10,15200,8,8,1,13.0,0\n"
    "1800,steady,20600,10,15200,8,8,2,12.8,0\n"
    "2700,steady,20650,10,15200,8,8,3,13.2,0\n"
    "3600,steady,20700,10,15200,8,8,4,12.9,0\n"
    "5400,steady,20650,10,15200,8,8,5,13.1,0\n"
    "7200,steady,20600,10,15200,8,8,6,12.7,0\n"
    "9000,steady,20550,10,15200,8,8,7,13.3,0\n"
    "10800,steady,20500,10,15200,8,8,9,13.0,0\n"
    "10800,drain,20200,10,15100,8,0,9,,0\n"
)

VIOLATING_CSV = (
    CSV_HEADER + "\n"
    "0,boot,20000,10,15000,8,0,0,,0\n"
    "0,steady,22000,10,15200,10,8,0,12.5,0\n"
    "900,steady,32500,10,15205,11,8,1,25.0,0\n"
    "1800,steady,43000,11,15210,13,8,2,37.5,0\n"
    "2700,steady,53500,12,15215,14,8,3,50.0,0\n"
    "3600,steady,64000,12,15220,16,8,4,60.0,0\n"
    "5400,steady,74500,13,15230,18,8,5,70.0,0\n"
    "7200,steady,85000,13,15240,19,8,6,77.0,0\n"
    "9000,steady,88000,14,15250,20,8,7,85.0,0\n"
    "10800,steady,90000,14,15260,22,8,9,90.0,0\n"
    "10800,drain,75000,14,15100,20,0,9,,3\n"
)


def self_test() -> int:
    failures: list[str] = []

    def check(name: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    passing_rows = read_rows(PASSING_CSV.splitlines())
    check("passing: row count", len(passing_rows), 11)
    passing_result = evaluate(passing_rows, sessions=8)
    check("passing: no violations", passing_result["violations"], [])
    check("passing: baseline rss", passing_result["baseline_rss_kib"], 20000)
    check("passing: idle end fds", passing_result["idle_end_fds"], 10)
    check("passing: self fd baseline->idle_end delta", passing_result["self_fd_baseline_idle_end_delta"], 0)
    check(
        "passing: self fd baseline->idle_end is informational, not a violation",
        any(
            "self fd boot-baseline->drain-idle_end delta" in n and "runtime warm-up" in n
            for n in passing_result["notes"]
        ),
        True,
    )

    violating_rows = read_rows(VIOLATING_CSV.splitlines())
    violating_result = evaluate(violating_rows, sessions=8)
    check("violating: has violations", len(violating_result["violations"]) > 0, True)
    check(
        "violating: idle RSS flagged",
        any("idle-end listener RSS" in v for v in violating_result["violations"]),
        True,
    )
    check(
        "violating: per-session buffer flagged",
        any("per-session buffer" in v for v in violating_result["violations"]),
        True,
    )
    check(
        "violating: RSS trend flagged",
        any("RSS trend slope" in v for v in violating_result["violations"]),
        True,
    )
    check(
        "violating: listener fd flagged",
        any(v.startswith("listener fd") for v in violating_result["violations"]),
        True,
    )
    check(
        "violating: self fd tagged FD_GROWTH_CLIENT",
        any(v.startswith("FD_GROWTH_CLIENT") for v in violating_result["violations"]),
        True,
    )
    check(
        "violating: self fd baseline->idle_end delta",
        violating_result["self_fd_baseline_idle_end_delta"],
        12,
    )
    check(
        "violating: self fd baseline->idle_end delta is not itself a FD_GROWTH_CLIENT violation",
        any(
            "self fd boot-baseline->drain-idle_end delta" in v
            for v in violating_result["violations"]
        ),
        False,
    )
    check(
        "violating: echo p95 flagged",
        any(v.startswith("echo p95") for v in violating_result["violations"]),
        True,
    )
    check(
        "violating: TTL reap flagged",
        any("TTL reap did not run" in v for v in violating_result["violations"]),
        True,
    )
    check(
        "violating: listener fd quarters tagged FD_GROWTH_LISTENER",
        any(v.startswith("FD_GROWTH_LISTENER") for v in violating_result["violations"]),
        True,
    )

    # --resume-ttl-secs (B7/C4): the same VIOLATING_CSV's abandoned_live=3
    # at drain is not yet a violation when too little time has elapsed
    # since boot, and becomes one once the deadline has passed.
    ttl_not_yet_result = evaluate(violating_rows, sessions=8, resume_ttl_secs=100_000)
    check(
        "TTL reap: not yet judged when elapsed < resume_ttl+REAPER_TICK",
        any("not yet judged" in n for n in ttl_not_yet_result["notes"]),
        True,
    )
    check(
        "TTL reap: not a violation when not yet judged",
        any("TTL reap did not run" in v for v in ttl_not_yet_result["violations"]),
        False,
    )
    ttl_elapsed_result = evaluate(violating_rows, sessions=8, resume_ttl_secs=30)
    check(
        "TTL reap: flagged once elapsed >= resume_ttl+REAPER_TICK",
        any("TTL reap did not run" in v for v in ttl_elapsed_result["violations"]),
        True,
    )

    # --echo-baseline-ms (C9): the adaptive bound raises the ceiling above
    # the fixed 50ms floor, so a max_echo of 90ms — a hard violation with
    # no baseline — passes once the baseline is high enough to lift
    # max(3 x baseline, 50) past 90.
    echo_adaptive_result = evaluate(violating_rows, sessions=8, echo_baseline_ms=40.0)
    check(
        "echo p95: adaptive bound (3x40=120) absorbs a 90ms max that the fixed 50ms floor would flag",
        any(v.startswith("echo p95") for v in echo_adaptive_result["violations"]),
        False,
    )
    check("echo p95: bound recorded", echo_adaptive_result["echo_p95_bound_ms"], 120.0)
    check(
        "echo p95: explicit flag records source 'flag'",
        echo_adaptive_result["echo_p95_baseline_source"],
        "flag",
    )

    # PROGRESS-5.md §F2: the CSV's own "phase == ramp" row is where
    # `evaluate()` derives the echo p95 baseline when the caller passes no
    # `--echo-baseline-ms` — these three fixtures share the same steady-phase
    # echo p95 (max 80ms) and differ only in whether a ramp row is present
    # and whether the flag is passed, so the only thing that should move
    # between them is the bound and the recorded baseline source.
    RAMP_BASELINE_CSV = (
        CSV_HEADER + "\n"
        "0,boot,20000,10,15000,8,0,0,,0\n"
        "2,ramp,20000,10,15000,8,8,0,30.0,1\n"
        "2,steady,20100,10,15050,8,8,0,80.0,0\n"
        "4,steady,20100,10,15050,8,8,1,20.0,0\n"
        "6,drain,20050,10,15000,8,0,1,,0\n"
    )
    NO_RAMP_CSV = (
        CSV_HEADER + "\n"
        "0,boot,20000,10,15000,8,0,0,,0\n"
        "2,steady,20100,10,15050,8,8,0,80.0,0\n"
        "4,steady,20100,10,15050,8,8,1,20.0,0\n"
        "6,drain,20050,10,15000,8,0,1,,0\n"
    )

    # (a) ramp row present, baseline 30ms, no flag: bound = max(3x30, 50) =
    # 90, steady max 80ms <= 90 -> no echo violation.
    ramp_row_result = evaluate(read_rows(RAMP_BASELINE_CSV.splitlines()), sessions=8)
    check(
        "ramp-row baseline: derived from the CSV's ramp row",
        ramp_row_result.get("echo_p95_baseline_ms"),
        30.0,
    )
    check(
        "ramp-row baseline: source recorded as 'ramp-row'",
        ramp_row_result["echo_p95_baseline_source"],
        "ramp-row",
    )
    check("ramp-row baseline: bound is max(3x30, 50)=90", ramp_row_result["echo_p95_bound_ms"], 90.0)
    check(
        "ramp-row baseline: 80ms max under the 90ms bound is no violation",
        any(v.startswith("echo p95") for v in ramp_row_result["violations"]),
        False,
    )

    # (b) same steady data, no ramp row, no flag: nothing to derive a
    # baseline from, so the bound falls back to the fixed 50ms floor and the
    # same 80ms max is now a violation.
    no_ramp_result = evaluate(read_rows(NO_RAMP_CSV.splitlines()), sessions=8)
    check(
        "no ramp row: baseline source recorded as 'none'",
        no_ramp_result["echo_p95_baseline_source"],
        "none",
    )
    check("no ramp row: bound stays the fixed 50ms floor", no_ramp_result["echo_p95_bound_ms"], 50.0)
    check(
        "no ramp row: 80ms max over the 50ms floor is a violation",
        any(v.startswith("echo p95") for v in no_ramp_result["violations"]),
        True,
    )

    # (c) ramp row present (baseline 30ms) but --echo-baseline-ms 10 passed:
    # the flag wins outright over the CSV row, bound = max(3x10, 50) = 50,
    # so the same 80ms max is a violation again.
    flag_overrides_ramp_result = evaluate(
        read_rows(RAMP_BASELINE_CSV.splitlines()), sessions=8, echo_baseline_ms=10.0
    )
    check(
        "flag overrides ramp row: baseline source recorded as 'flag'",
        flag_overrides_ramp_result["echo_p95_baseline_source"],
        "flag",
    )
    check(
        "flag overrides ramp row: baseline is the flag's 10ms, not the ramp row's 30ms",
        flag_overrides_ramp_result["echo_p95_baseline_ms"],
        10.0,
    )
    check(
        "flag overrides ramp row: bound stays the fixed 50ms floor (max(3x10,50))",
        flag_overrides_ramp_result["echo_p95_bound_ms"],
        50.0,
    )
    check(
        "flag overrides ramp row: 80ms max over the 50ms bound is a violation",
        any(v.startswith("echo p95") for v in flag_overrides_ramp_result["violations"]),
        True,
    )

    # A regression fitted over a span shorter than an hour is recorded, never
    # asserted — too few samples for the 24h-mode judgment to mean anything.
    short_csv = (
        CSV_HEADER + "\n"
        "0,boot,20000,10,15000,8,0,0,,0\n"
        "0,steady,20200,10,15000,8,8,0,10.0,0\n"
        "60,steady,25000,10,15000,8,8,1,10.0,0\n"
        "60,drain,20100,10,15000,8,0,1,,0\n"
    )
    short_result = evaluate(read_rows(short_csv.splitlines()), sessions=8)
    check(
        "short span: trend recorded not asserted",
        any("recorded only, too few samples" in n for n in short_result["notes"]),
        True,
    )
    check(
        "short span: trend not a violation",
        any("RSS trend slope" in v for v in short_result["violations"]),
        False,
    )

    check("bad header rejected", None, None)
    try:
        read_rows(["t_secs,wrong,header"])
        failures.append("bad header: expected ValueError, got none")
    except ValueError:
        pass

    snaps = snapshot_rows(passing_rows)
    check("snapshot count", len(snaps), len(SNAPSHOT_HOURS))
    check("snapshot 0h nearest", snaps[0]["t_secs"], 0)
    check("snapshot 1h nearest", snaps[1]["t_secs"], 3600)
    check("snapshot 24h nearest is last row (only 3h of data)", snaps[4]["t_secs"], 10800)

    check("empty CSV", evaluate([], sessions=8)["rows"], 0)
    check(
        "empty CSV is a violation (no boot/drain rows)",
        len(evaluate([], sessions=8)["violations"]) > 0,
        True,
    )

    text = render(passing_result, snaps)
    check("render mentions verdict", "verdict: pass" in text, True)
    check("render never leaks a token-shaped word", "token" in text.lower(), False)

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} self-test failure(s)", file=sys.stderr)
        return 1
    print("self-test: all checks passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Judge a qsh soak-run CSV against BRIEF-5.md §4.4.",
    )
    parser.add_argument("csv", nargs="?", help="samples.csv path ('-' or omitted for stdin)")
    parser.add_argument(
        "--sessions", type=int, default=0,
        help="session count N used for the run (needed for the per-session buffer bound)",
    )
    parser.add_argument(
        "--resume-ttl-secs", type=int, default=None,
        help="QSH_SOAK_RESUME_TTL_SECS used for the run — when given, the TTL-reap check is "
             "judged against resume_ttl_secs + REAPER_TICK (30s) instead of an unconditional "
             "'abandoned_live must be 0 at drain' (crates/qsh-cli/tests/soak.rs's identical "
             "ttl_reap_deadline rule); omitted, the old unconditional check applies",
    )
    parser.add_argument(
        "--echo-baseline-ms", type=float, default=None,
        help="explicit override for the ramp-phase echo p95 baseline (ms) — when given, this "
             "wins outright over the CSV's own 'phase == ramp' row. Omitted (the normal case), "
             "the baseline is derived from that CSV row automatically, and the echo p95 bound "
             "becomes max(3 x baseline, 50ms), the same adaptive rule adversarial_load.rs's T2 "
             "scenario and crates/qsh-cli/tests/soak.rs use; with neither a ramp row nor this "
             "flag, the bound stays the fixed 50ms floor",
    )
    parser.add_argument("--json", action="store_true", help="emit the result as JSON")
    parser.add_argument("--self-test", action="store_true", help="run the built-in checks and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    source = args.csv or "-"
    try:
        if source == "-":
            rows = read_rows(sys.stdin)
        else:
            with open(source, "r", encoding="utf-8", newline="") as handle:
                rows = read_rows(handle)
    except (OSError, ValueError) as exc:
        print(f"summarize.py: {exc}", file=sys.stderr)
        return 2

    if args.sessions <= 0:
        print("summarize.py: --sessions N is required and must be > 0", file=sys.stderr)
        return 2

    result = evaluate(
        rows,
        sessions=args.sessions,
        resume_ttl_secs=args.resume_ttl_secs,
        echo_baseline_ms=args.echo_baseline_ms,
    )
    snaps = snapshot_rows(rows)

    if args.json:
        payload = dict(result)
        payload["snapshots"] = snaps
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render(result, snaps))

    return 1 if result["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
