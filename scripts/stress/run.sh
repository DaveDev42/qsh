#!/usr/bin/env bash
# Run a nextest filterset repeatedly while every logical CPU is saturated.
#
# A timing-sensitive test that is green on an idle machine can still race
# under load (commit 8fd4602 fixed a reverse-reset observation race that
# failed 16 of 80 runs under load). This harness reproduces that pressure
# locally. It is not part of the PR gate: shared runners give poor
# reproducibility and 50 rounds take tens of minutes.
#
# Usage: scripts/stress/run.sh <nextest-filterset> [rounds]
#
# rounds defaults to 50. Set QSH_ACCEPTANCE_SLOW=1 in the caller's
# environment to include the wall-clock tests; it is passed through as-is.
# Exit 0 when every round is green, 1 on the first red round, 2 on bad usage.
# The busy-loop processes are always reaped by the EXIT trap.
set -uo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <nextest-filterset> [rounds]" >&2
    exit 2
fi
FILTER=$1
ROUNDS=${2:-50}
case "$ROUNDS" in
    '' | *[!0-9]* | 0)
        echo "run.sh: rounds must be a positive integer" >&2
        exit 2
        ;;
esac

if command -v nproc >/dev/null 2>&1; then
    NCPU=$(nproc)
else
    NCPU=$(sysctl -n hw.logicalcpu)
fi

LOAD_PIDS=()
LOG=""
cleanup() {
    if [ ${#LOAD_PIDS[@]} -gt 0 ]; then
        kill "${LOAD_PIDS[@]}" 2>/dev/null || true
        wait "${LOAD_PIDS[@]}" 2>/dev/null || true
    fi
    if [ -n "$LOG" ]; then
        rm -f "$LOG"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Build first so compilation time is not spent under the busy loops.
if ! cargo nextest run --workspace --no-run >/dev/null 2>&1; then
    echo "run.sh: build failed" >&2
    exit 1
fi

for _ in $(seq "$NCPU"); do
    yes >/dev/null &
    LOAD_PIDS+=("$!")
done
echo "stress: $NCPU busy loops, filterset: $FILTER, rounds: $ROUNDS"

LOG=$(mktemp)

for round in $(seq "$ROUNDS"); do
    if ! cargo nextest run --workspace --no-fail-fast --no-tests=warn --status-level fail \
        --final-status-level none -E "$FILTER" >"$LOG" 2>&1; then
        echo "stress: round $round/$ROUNDS FAILED" >&2
        grep -E '^\s*(FAIL|SIGABRT|SIGSEGV|TIMEOUT|LEAK-FAIL)|^error' "$LOG" | sort -u >&2
        tail -n 40 "$LOG" >&2
        exit 1
    fi
    if [ "$round" -eq 1 ] && grep -qE "(^|[^0-9])0 tests run" "$LOG"; then
        echo "stress: warning: filterset matched 0 tests" >&2
    fi
done
echo "$ROUNDS/$ROUNDS passed under load"
