#!/usr/bin/env bash
# switch-macos.sh — repeatable Wi-Fi <-> tethering switch driver for the M2
# mobility campaign (PLAN.md Step 9, docs/campaigns/m2-mobility.md).
#
# This script only moves the laptop's link. It measures nothing: the numbers for
# the campaign come from the qsh client's `qsh::recovery` stderr diagnostics
# (docs/CLI.md §6.4, docs/design/testing.md L4), which
# scripts/mobility/summarize.py tabulates. What this script contributes is a
# reproducible switch sequence plus one record line per transition to correlate
# against those diagnostics.
#
# Root is not needed on the default path: `networksetup -setairportpower` is
# permitted for a console user. The `--method service` path uses
# `-setnetworkserviceenabled`, which does prompt for an administrator.

set -euo pipefail

PROGRAM=${0##*/}

# --- defaults ---------------------------------------------------------------
WIFI_DEVICE=""                # autodetected from the Wi-Fi hardware port
TETHER_SERVICE="iPhone USB"   # USB tethering shows up as a network service
METHOD="airport"              # airport | service
ITERATIONS=20
SETTLE_SECONDS=8              # dwell on each link before switching again
DRY_RUN=0
LOG_FILE=""

usage() {
    cat <<'USAGE'
Usage: switch-macos.sh [options]

Drives N Wi-Fi <-> tethering transitions on macOS and prints one JSON record
line per transition. Intended to run beside an interactive `qsh user@host`
session whose stderr is captured; feed that stderr to
scripts/mobility/summarize.py afterwards.

Options:
  --iterations N        Number of switch iterations (default: 20). Each
                        iteration is one round trip: wifi->tether then
                        tether->wifi, so two transitions and two record lines.
  --settle SECONDS      Seconds to stay on a link before switching (default: 8).
  --wifi-device DEV     Wi-Fi BSD device (default: autodetected, usually en0).
  --tether-service NAME Network service carrying the phone's tether
                        (default: "iPhone USB"). List them with:
                          networksetup -listallnetworkservices
  --method MODE         airport | service (default: airport).
                        airport: networksetup -setairportpower  (no admin)
                        service: networksetup -setnetworkserviceenabled
                                 (prompts for an administrator password)
  --dry-run             Touch nothing. Print exactly the commands that would
                        run, then exit 0.
  --log FILE            Append record lines to FILE as well as stdout.
  -h, --help            This text.

Exit codes: 0 ok, 2 bad usage, 3 missing interface/service or missing tool,
130 interrupted (original Wi-Fi power is restored on every exit path).
USAGE
}

log() { printf '%s\n' "$*" >&2; }
die() { log "$PROGRAM: $1"; exit "${2:-2}"; }

now_ms() {
    # GNU date has %3N; BSD date does not (it echoes an 'N'). Fall back through
    # python3, then whole seconds. Used only to correlate a transition with the
    # client's telemetry line, never to measure recovery.
    local ms
    if ms=$(date +%s%3N 2>/dev/null) && [ "${ms#*N}" = "$ms" ]; then
        printf '%s\n' "$ms"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import time; print(int(time.time()*1000))'
    else
        printf '%s000\n' "$(date +%s)"
    fi
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# --- argument parsing -------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --iterations) [ $# -ge 2 ] || die "--iterations needs a value"; ITERATIONS=$2; shift 2 ;;
        --iterations=*) ITERATIONS=${1#*=}; shift ;;
        --settle) [ $# -ge 2 ] || die "--settle needs a value"; SETTLE_SECONDS=$2; shift 2 ;;
        --settle=*) SETTLE_SECONDS=${1#*=}; shift ;;
        --wifi-device) [ $# -ge 2 ] || die "--wifi-device needs a value"; WIFI_DEVICE=$2; shift 2 ;;
        --wifi-device=*) WIFI_DEVICE=${1#*=}; shift ;;
        --tether-service) [ $# -ge 2 ] || die "--tether-service needs a value"; TETHER_SERVICE=$2; shift 2 ;;
        --tether-service=*) TETHER_SERVICE=${1#*=}; shift ;;
        --method) [ $# -ge 2 ] || die "--method needs a value"; METHOD=$2; shift 2 ;;
        --method=*) METHOD=${1#*=}; shift ;;
        --log) [ $# -ge 2 ] || die "--log needs a value"; LOG_FILE=$2; shift 2 ;;
        --log=*) LOG_FILE=${1#*=}; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

case "$ITERATIONS" in ''|*[!0-9]*) die "--iterations must be a positive integer" ;; esac
[ "$ITERATIONS" -ge 1 ] || die "--iterations must be at least 1"
case "$SETTLE_SECONDS" in ''|*[!0-9]*) die "--settle must be a non-negative integer" ;; esac
case "$METHOD" in airport|service) ;; *) die "--method must be airport or service" ;; esac

[ "$(uname -s)" = "Darwin" ] || die "this script is macOS-only; use switch-linux.sh" 3
command -v networksetup >/dev/null 2>&1 || die "networksetup not found" 3

# --- discovery (read-only; safe to do even under --dry-run) -----------------
if [ -z "$WIFI_DEVICE" ]; then
    WIFI_DEVICE=$(networksetup -listallhardwareports 2>/dev/null |
        awk '/^Hardware Port: Wi-Fi$/ {getline; print $2; exit}')
fi
[ -n "$WIFI_DEVICE" ] || die "could not autodetect the Wi-Fi device; pass --wifi-device" 3

if ! networksetup -listallhardwareports 2>/dev/null | grep -Fxq "Device: ${WIFI_DEVICE}"; then
    die "no such network device: ${WIFI_DEVICE}" 3
fi

SERVICES=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\*//')
if ! printf '%s\n' "$SERVICES" | grep -Fxq "$TETHER_SERVICE"; then
    log "$PROGRAM: no such network service: ${TETHER_SERVICE}"
    log "$PROGRAM: available services:"
    printf '%s\n' "$SERVICES" | sed 's/^/  - /' >&2
    exit 3
fi

WIFI_SERVICE=""
if printf '%s\n' "$SERVICES" | grep -Fxq "Wi-Fi"; then
    WIFI_SERVICE="Wi-Fi"
fi
if [ "$METHOD" = "service" ] && [ -z "$WIFI_SERVICE" ]; then
    die "--method service needs a network service named 'Wi-Fi'" 3
fi

ORIGINAL_WIFI_POWER=$(networksetup -getairportpower "$WIFI_DEVICE" 2>/dev/null | awk '{print $NF}')
[ -n "$ORIGINAL_WIFI_POWER" ] || ORIGINAL_WIFI_POWER="On"

# --- execution helpers ------------------------------------------------------
TRANSITIONS=0
RESTORED=0

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'DRY-RUN would run:'
        printf ' %q' "$@"
        printf '\n'
    else
        "$@"
    fi
}

pause() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'DRY-RUN would sleep %s\n' "$SETTLE_SECONDS"
    else
        sleep "$SETTLE_SECONDS"
    fi
}

record() {
    # One JSON object per line: run, direction, timestamps. The recovery
    # classification is deliberately NOT here — it comes from the client's
    # qsh::recovery lines, correlated by wall clock and session_ref.
    local run=$1 direction=$2 t0=$3 t1=$4 line
    line=$(printf '{"mobility":"switch","platform":"macos","run":%s,"direction":"%s","method":"%s","switch_started_ms":%s,"switch_issued_ms":%s,"at":"%s"}' \
        "$run" "$direction" "$METHOD" "$t0" "$t1" "$(now_iso)")
    printf '%s\n' "$line"
    if [ -n "$LOG_FILE" ] && [ "$DRY_RUN" -eq 0 ]; then
        printf '%s\n' "$line" >>"$LOG_FILE"
    fi
    TRANSITIONS=$((TRANSITIONS + 1))
}

wifi_up() {
    case "$METHOD" in
        airport) run networksetup -setairportpower "$WIFI_DEVICE" on ;;
        service) run networksetup -setnetworkserviceenabled "$WIFI_SERVICE" on ;;
    esac
}

wifi_down() {
    case "$METHOD" in
        airport) run networksetup -setairportpower "$WIFI_DEVICE" off ;;
        service) run networksetup -setnetworkserviceenabled "$WIFI_SERVICE" off ;;
    esac
}

# shellcheck disable=SC2329  # invoked by the EXIT trap
restore() {
    # Idempotent: the trap fires on EXIT, which also follows INT/TERM.
    [ "$RESTORED" -eq 0 ] || return 0
    RESTORED=1
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'DRY-RUN would restore: Wi-Fi power on %s -> %s\n' "$WIFI_DEVICE" "$ORIGINAL_WIFI_POWER"
        return 0
    fi
    log "$PROGRAM: restoring Wi-Fi power on ${WIFI_DEVICE} to ${ORIGINAL_WIFI_POWER}"
    case "$ORIGINAL_WIFI_POWER" in
        On|on) networksetup -setairportpower "$WIFI_DEVICE" on || log "$PROGRAM: restore failed" ;;
        *) networksetup -setairportpower "$WIFI_DEVICE" off || log "$PROGRAM: restore failed" ;;
    esac
    if [ "$METHOD" = "service" ] && [ -n "$WIFI_SERVICE" ]; then
        networksetup -setnetworkserviceenabled "$WIFI_SERVICE" on || log "$PROGRAM: service restore failed"
    fi
}

# shellcheck disable=SC2329  # invoked by the INT/TERM trap
on_signal() { log "$PROGRAM: interrupted"; exit 130; }
trap restore EXIT
trap on_signal INT TERM

# --- preflight summary ------------------------------------------------------
log "$PROGRAM: wifi_device=${WIFI_DEVICE} tether_service=${TETHER_SERVICE} method=${METHOD}"
log "$PROGRAM: iterations=${ITERATIONS} settle=${SETTLE_SECONDS}s original_wifi_power=${ORIGINAL_WIFI_POWER}"
if [ "$DRY_RUN" -eq 1 ]; then
    log "$PROGRAM: DRY RUN — no interface will be touched"
else
    log "$PROGRAM: LIVE RUN — this drops and restores the link ${ITERATIONS} times"
    log "$PROGRAM: capture the qsh session's stderr, e.g. 2>mobility-stderr.log"
fi

i=1
while [ "$i" -le "$ITERATIONS" ]; do
    # wifi -> tether: cut Wi-Fi; the tether service is next in the service order
    t0=$(now_ms)
    wifi_down
    t1=$(now_ms)
    record "$i" "wifi->tether" "$t0" "$t1"
    pause

    # tether -> wifi
    t0=$(now_ms)
    wifi_up
    t1=$(now_ms)
    record "$i" "tether->wifi" "$t0" "$t1"
    pause

    i=$((i + 1))
done

log "$PROGRAM: ${TRANSITIONS} transitions issued over ${ITERATIONS} iterations"
exit 0
