#!/usr/bin/env bash
# Drive the 24h/100-session soak run (BRIEF-5.md §5, `crates/qsh-cli/tests/
# soak.rs`, `docs/campaigns/m8-soak.md`) under `[profile.soak]` and capture
# everything a campaign round needs to fill in the record template.
#
# This script does not judge anything itself — it runs the nextest binary
# (which asserts the always-checked axes of §4.4 and writes the CSV) and
# then hands the CSV to `summarize.py`, which asserts the record-only axes
# (per-session buffer, RSS trend) that need the full 24h of samples. Exit
# code is the logical OR of both: a soak run is a pass only if the test
# binary's own assertions passed AND the CSV shows no drift the test binary
# couldn't see with so few samples.
#
# Usage: scripts/soak/run.sh [--duration SECS] [--sessions N] [--out DIR]
#
# Env passthrough: QSH_SOAK_* variables already set in the caller's
# environment are respected as-is (`:=` below only fills in a var that is
# not already set) — every knob defaults to the full 24h/100-session vector
# (BRIEF-5.md §4.2), not the test binary's own short-mode defaults, so
# `QSH_SOAK_CYCLE_SECS=600 scripts/soak/run.sh` for a custom cycle length
# keeps working, and a plain `scripts/soak/run.sh` with no overrides runs
# the real 24h campaign shape rather than a debug-length short run.
# `QSH_LOAD_BIN` must already point at a release `qsh` binary; this script
# does not build one — the campaign procedure (docs/campaigns/m8-soak.md)
# builds it once up front so its sha256 is stable across the whole 24h
# window.
set -euo pipefail

DURATION=86400
SESSIONS=100
OUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --duration)
            if [ $# -lt 2 ]; then
                echo "run.sh: --duration requires a value" >&2
                exit 2
            fi
            DURATION=$2
            shift 2
            ;;
        --sessions)
            if [ $# -lt 2 ]; then
                echo "run.sh: --sessions requires a value" >&2
                exit 2
            fi
            SESSIONS=$2
            shift 2
            ;;
        --out)
            if [ $# -lt 2 ]; then
                echo "run.sh: --out requires a value" >&2
                exit 2
            fi
            OUT=$2
            shift 2
            ;;
        *)
            echo "run.sh: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

# Validated before anything is created on disk (C10/B14): a missing/
# non-executable QSH_LOAD_BIN must exit 2 with nothing left behind, not
# leave an empty $OUT directory for the caller to clean up.
if [ -z "${QSH_LOAD_BIN:-}" ]; then
    echo "run.sh: QSH_LOAD_BIN must point at a release qsh binary (this script does not build one — see docs/campaigns/m8-soak.md §4)" >&2
    exit 2
fi
if [ ! -x "$QSH_LOAD_BIN" ]; then
    echo "run.sh: QSH_LOAD_BIN=$QSH_LOAD_BIN is not an executable file" >&2
    exit 2
fi

if [ -z "$OUT" ]; then
    OUT="$ROOT/soak-out-$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$OUT"

# Full 24h/100-session vector (BRIEF-5.md §4.2) as the default for every
# QSH_SOAK_* knob — a caller-set value always wins (`:=` is a no-op when
# the var is already non-empty in the environment).
: "${QSH_SOAK_DURATION_SECS:=$DURATION}"
: "${QSH_SOAK_SESSIONS:=$SESSIONS}"
: "${QSH_SOAK_SAMPLE_SECS:=5}"
: "${QSH_SOAK_CYCLE_SECS:=60}"
: "${QSH_SOAK_CYCLE_FRACTION:=0.1}"
: "${QSH_SOAK_ABANDON:=5}"
: "${QSH_SOAK_RESUME_TTL_SECS:=600}"
export QSH_SOAK_DURATION_SECS QSH_SOAK_SESSIONS QSH_SOAK_SAMPLE_SECS QSH_SOAK_CYCLE_SECS \
    QSH_SOAK_CYCLE_FRACTION QSH_SOAK_ABANDON QSH_SOAK_RESUME_TTL_SECS
export QSH_LOAD_STRICT=1
export QSH_LOAD_BIN
CSV="$OUT/samples.csv"
export QSH_SOAK_CSV="$CSV"

# ulimit -n raised best-effort: a soak run's fd bound is about the listener
# and the test process not growing, not about starting near a low ceiling.
# A shell that already caps below the hard limit (e.g. a restrictive systemd
# unit) leaves this as a no-op rather than a failure — the resulting value
# still gets recorded below either way.
ulimit -n 65536 2>/dev/null || true

{
    echo "date (UTC): $(date -u +%FT%TZ)"
    uname -a
    echo "nproc: $(nproc 2>/dev/null || echo unknown)"
    uptime
    echo "ulimit -n: $(ulimit -n)"
    echo "qsh commit: $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
    if git -C "$ROOT" diff --quiet 2>/dev/null && [ -z "$(git -C "$ROOT" ls-files --others --exclude-standard 2>/dev/null)" ]; then
        echo "qsh working tree: clean"
    else
        echo "qsh working tree: DIRTY — record this in docs/campaigns/m8-soak.md's environment table"
    fi
    echo "binary: $QSH_LOAD_BIN"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$QSH_LOAD_BIN"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$QSH_LOAD_BIN"
    else
        echo "sha256: no sha256sum/shasum on PATH"
    fi
    echo "QSH_SOAK_DURATION_SECS: $QSH_SOAK_DURATION_SECS"
    echo "QSH_SOAK_SESSIONS: $QSH_SOAK_SESSIONS"
    echo "QSH_SOAK_SAMPLE_SECS: $QSH_SOAK_SAMPLE_SECS"
    echo "QSH_SOAK_CYCLE_SECS: $QSH_SOAK_CYCLE_SECS"
    echo "QSH_SOAK_CYCLE_FRACTION: $QSH_SOAK_CYCLE_FRACTION"
    echo "QSH_SOAK_ABANDON: $QSH_SOAK_ABANDON"
    echo "QSH_SOAK_RESUME_TTL_SECS: $QSH_SOAK_RESUME_TTL_SECS"
} >"$OUT/env.txt"
cat "$OUT/env.txt"

echo
echo "== soak run starting: $QSH_SOAK_SESSIONS session(s), ${QSH_SOAK_DURATION_SECS}s steady state, out=$OUT =="

# Every cargo invocation in this repo runs from the workspace root (C10/
# B14) — this script may be invoked from any cwd (a campaign's ssh session
# rarely lands exactly in the repo root).
cd "$ROOT"

# Outer wall-clock bound (B12's "outer bound", REVIEW-5-C C2 / ARBITRATION-5
# F2): `[profile.soak]`'s own `slow-timeout` never kills the test (period=
# 3600s, no terminate-after — S0/Q9's confirmed "warn, never kill"
# semantics), so a genuinely hung 24h run would otherwise wait forever for
# a human to notice. This `timeout` is the actual outer bound: the test's
# own intended duration plus 30 extra minutes for boot/ramp/drain and
# `summarize.py`'s own runtime, after which even a real hang is killed
# instead of silently occupying the host indefinitely.
set +e
timeout "$((QSH_SOAK_DURATION_SECS + 1800))" \
    cargo nextest run --profile soak -p qsh-cli --test soak 2>&1 | tee "$OUT/run.log"
TEST_STATUS=${PIPESTATUS[0]}
set -e

SUMMARIZE_STATUS=0
if [ -f "$CSV" ]; then
    echo
    echo "== summarize.py =="
    if ! python3 "$HERE/summarize.py" "$CSV" --sessions "$QSH_SOAK_SESSIONS" \
        --resume-ttl-secs "$QSH_SOAK_RESUME_TTL_SECS" | tee "$OUT/summary.txt"; then
        SUMMARIZE_STATUS=1
    fi
else
    echo "run.sh: no CSV at $CSV — the soak test did not run to completion (skipped, or crashed before writing a row)" >&2
    SUMMARIZE_STATUS=1
fi

if [ "$TEST_STATUS" -ne 0 ] || [ "$SUMMARIZE_STATUS" -ne 0 ]; then
    echo
    echo "run.sh: FAIL (test exit=$TEST_STATUS, summarize exit=$SUMMARIZE_STATUS) — see $OUT" >&2
    exit 1
fi

echo
echo "run.sh: PASS — see $OUT"
