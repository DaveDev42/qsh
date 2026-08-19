#!/usr/bin/env python3
"""summarize.py — tabulate qsh recovery telemetry from a mobility campaign.

The qsh client emits recovery telemetry as stderr structured diagnostics only
(docs/CLI.md §6.4, docs/design/testing.md L4): tracing target ``qsh::recovery``,
level INFO, **one line of JSON** carrying ``recovery`` (one of ``migrated`` /
``resumed`` / ``failed``), ``time_to_recovery_ms`` and ``session_ref``. Never a
stdout line, never PTY content, never a token.

This reads such a stderr capture (or several) and prints the migrated / resumed
/ failed breakdown plus the time-to-recovery distribution, so the operator
filling in docs/campaigns/m2-mobility.md does not tabulate by hand.

Pass/fail is the campaign's, pre-defined in that document: an event only counts
as a recovery within budget if ``time_to_recovery_ms`` <= the budget (2000 ms,
docs/design/testing.md L4). A recovery that arrived only because an idle timeout
eventually fired is over budget and therefore a FAIL — this tool reports it as
``over_budget`` and never quietly folds it into the success count.

Stdlib only. Usage:

    qsh dave@host 2>stderr.log            # operator's session, stderr captured
    scripts/mobility/summarize.py stderr.log
    scripts/mobility/summarize.py --json stderr.log
    scripts/mobility/summarize.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Iterable, Iterator, NamedTuple

CLASSES = ("migrated", "resumed", "failed")
DEFAULT_BUDGET_MS = 2000
PERCENTILES = (50, 90, 95, 99)


class Record(NamedTuple):
    recovery: str
    time_to_recovery_ms: int | None
    session_ref: str | None
    source: str
    lineno: int


def _candidate_objects(obj: Any) -> Iterator[dict]:
    """Yield the object itself and any nested dicts a tracing layer may wrap it
    in. The contract line is a flat object; being tolerant of a ``fields`` /
    ``span`` wrapper costs nothing and keeps the tool useful if the subscriber
    configuration changes."""
    if isinstance(obj, dict):
        yield obj
        for key in ("fields", "span", "record", "message"):
            nested = obj.get(key)
            if isinstance(nested, dict):
                yield from _candidate_objects(nested)


def parse_line(line: str, source: str, lineno: int) -> Record | None:
    """Return a Record if this stderr line is a recovery telemetry line."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    for candidate in _candidate_objects(obj):
        recovery = candidate.get("recovery")
        if not isinstance(recovery, str) or recovery not in CLASSES:
            continue
        raw = candidate.get("time_to_recovery_ms")
        ttr: int | None
        if isinstance(raw, bool):
            ttr = None
        elif isinstance(raw, int):
            ttr = raw
        elif isinstance(raw, float) and raw == int(raw):
            ttr = int(raw)
        else:
            ttr = None
        session_ref = candidate.get("session_ref")
        if not isinstance(session_ref, str):
            session_ref = None
        return Record(recovery, ttr, session_ref, source, lineno)
    return None


def parse_stream(stream: Iterable[str], source: str) -> list[Record]:
    out: list[Record] = []
    for lineno, line in enumerate(stream, start=1):
        record = parse_line(line, source, lineno)
        if record is not None:
            out.append(record)
    return out


def percentile(sorted_values: list[int], pct: float) -> int | None:
    """Nearest-rank percentile. Deterministic, no interpolation, no numpy."""
    if not sorted_values:
        return None
    rank = -(-len(sorted_values) * pct // 100)  # ceil(n * pct / 100)
    index = max(1, min(int(rank), len(sorted_values))) - 1
    return sorted_values[index]


def summarize(records: list[Record], budget_ms: int = DEFAULT_BUDGET_MS) -> dict:
    counts = {name: 0 for name in CLASSES}
    for record in records:
        counts[record.recovery] += 1

    recovered = [r for r in records if r.recovery in ("migrated", "resumed")]
    timed = sorted(r.time_to_recovery_ms for r in recovered if r.time_to_recovery_ms is not None)
    untimed = len(recovered) - len(timed)
    over_budget = [r for r in recovered if r.time_to_recovery_ms is not None and r.time_to_recovery_ms > budget_ms]

    total = len(records)
    within = len(recovered) - len(over_budget)
    return {
        "total": total,
        "counts": counts,
        "budget_ms": budget_ms,
        "within_budget": within,
        "over_budget": len(over_budget),
        "untimed": untimed,
        "within_budget_pct": (100.0 * within / total) if total else None,
        "percentiles_ms": {f"p{p}": percentile(timed, p) for p in PERCENTILES},
        "min_ms": timed[0] if timed else None,
        "max_ms": timed[-1] if timed else None,
        "over_budget_detail": [
            {
                "source": r.source,
                "line": r.lineno,
                "recovery": r.recovery,
                "time_to_recovery_ms": r.time_to_recovery_ms,
                "session_ref": r.session_ref,
            }
            for r in over_budget
        ],
    }


def render(summary: dict) -> str:
    lines: list[str] = []
    total = summary["total"]
    lines.append(f"recovery events: {total}")
    if total == 0:
        lines.append("  (no qsh::recovery lines found — was stderr captured at default verbosity?)")
        return "\n".join(lines)

    for name in CLASSES:
        count = summary["counts"][name]
        pct = 100.0 * count / total
        lines.append(f"  {name:<9} {count:>4}  ({pct:5.1f}%)")

    budget = summary["budget_ms"]
    lines.append("")
    lines.append(f"budget: {budget} ms (docs/design/testing.md L4 — re-dial + resume)")
    lines.append(f"  within budget  {summary['within_budget']:>4}  ({summary['within_budget_pct']:5.1f}% of all events)")
    lines.append(f"  over budget    {summary['over_budget']:>4}   <- FAIL per the pre-defined criterion")
    if summary["untimed"]:
        lines.append(f"  untimed        {summary['untimed']:>4}   (recovered, no time_to_recovery_ms field)")

    lines.append("")
    lines.append("time to recovery (ms, recovered events only)")
    if summary["min_ms"] is None:
        lines.append("  (none)")
    else:
        lines.append(f"  min {summary['min_ms']}   max {summary['max_ms']}")
        cells = "   ".join(
            f"{key} {value}" for key, value in summary["percentiles_ms"].items() if value is not None
        )
        lines.append(f"  {cells}")

    if summary["over_budget_detail"]:
        lines.append("")
        lines.append("over-budget events")
        for item in summary["over_budget_detail"]:
            lines.append(
                f"  {item['source']}:{item['line']}  {item['recovery']}  "
                f"{item['time_to_recovery_ms']} ms  {item['session_ref'] or '-'}"
            )
    return "\n".join(lines)


SAMPLE = """\
2026-08-19T10:00:00Z  starting session
{"recovery":"migrated","time_to_recovery_ms":180,"session_ref":"mac/01AAA"}
not json at all
{"level":"INFO","target":"qsh::other","message":"unrelated"}
{"recovery":"resumed","time_to_recovery_ms":1450,"session_ref":"mac/01AAA"}
{"recovery":"resumed","time_to_recovery_ms":9100,"session_ref":"mac/01AAA"}
{"recovery":"failed","time_to_recovery_ms":null,"session_ref":"mac/01AAA"}
{"fields":{"recovery":"migrated","time_to_recovery_ms":220,"session_ref":"mac/01BBB"}}
"""


def self_test() -> int:
    failures: list[str] = []

    def check(name: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    records = parse_stream(SAMPLE.splitlines(), "sample")
    check("records parsed", len(records), 5)
    check("non-json ignored", [r.recovery for r in records],
          ["migrated", "resumed", "resumed", "failed", "migrated"])
    check("nested fields object read", records[-1].session_ref, "mac/01BBB")
    check("null time is None", records[3].time_to_recovery_ms, None)

    summary = summarize(records)
    check("counts", summary["counts"], {"migrated": 2, "resumed": 2, "failed": 1})
    check("within budget", summary["within_budget"], 3)
    check("over budget", summary["over_budget"], 1)
    check("untimed", summary["untimed"], 0)
    check("min", summary["min_ms"], 180)
    check("max", summary["max_ms"], 9100)
    # nearest-rank over [180, 220, 1450, 9100]
    check("p50", summary["percentiles_ms"]["p50"], 220)
    check("p90", summary["percentiles_ms"]["p90"], 9100)

    check("percentile of empty", percentile([], 50), None)
    check("percentile single", percentile([7], 99), 7)
    check("percentile p100", percentile([1, 2, 3], 100), 3)

    # An idle-timeout-late recovery must never be counted as a success.
    late = parse_stream(['{"recovery":"resumed","time_to_recovery_ms":45000,"session_ref":"m/1"}'], "late")
    late_summary = summarize(late)
    check("late recovery is over budget", late_summary["over_budget"], 1)
    check("late recovery is not within budget", late_summary["within_budget"], 0)

    # A tighter budget reclassifies without touching the class counts.
    tight = summarize(records, budget_ms=200)
    check("tight budget over", tight["over_budget"], 3)
    check("tight budget counts unchanged", tight["counts"], summary["counts"])

    check("empty input", summarize([])["total"], 0)
    check("empty render mentions nothing found",
          "no qsh::recovery lines found" in render(summarize([])), True)

    # A token-shaped field must never be echoed by the renderer.
    text = render(summary)
    check("no token leak", "token" in text.lower(), False)

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} self-test failure(s)", file=sys.stderr)
        return 1
    print("self-test: all checks passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Tabulate qsh::recovery stderr telemetry from a mobility campaign.",
    )
    parser.add_argument("files", nargs="*", help="stderr capture files ('-' or none for stdin)")
    parser.add_argument("--budget-ms", type=int, default=DEFAULT_BUDGET_MS,
                        help=f"re-dial+resume budget in ms (default: {DEFAULT_BUDGET_MS})")
    parser.add_argument("--json", action="store_true", help="emit the summary as JSON")
    parser.add_argument("--self-test", action="store_true", help="run the built-in checks and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    records: list[Record] = []
    sources = args.files or ["-"]
    for source in sources:
        if source == "-":
            records += parse_stream(sys.stdin, "<stdin>")
        else:
            try:
                with open(source, "r", encoding="utf-8", errors="replace") as handle:
                    records += parse_stream(handle, source)
            except OSError as exc:
                print(f"summarize.py: {exc}", file=sys.stderr)
                return 2

    summary = summarize(records, budget_ms=args.budget_ms)
    if args.json:
        json.dump(summary, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
