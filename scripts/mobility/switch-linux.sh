#!/usr/bin/env bash
# switch-linux.sh — repeatable Wi-Fi <-> tethering switch driver for the M2
# mobility campaign (PLAN.md Step 9, docs/campaigns/m2-mobility.md).
#
# Linux counterpart of switch-macos.sh, same contract: it only moves the link,
# it measures nothing. The campaign numbers come from the qsh client's
# `qsh::recovery` stderr diagnostics (docs/CLI.md §6.4, docs/design/testing.md
# L4) and are tabulated by scripts/mobility/summarize.py.
#
# Root is not needed on the default path: `nmcli radio wifi off|on` is allowed
# for an active local session under the stock polkit rules. `--method device`
# uses `nmcli device disconnect|connect`, which some distributions gate behind
# an authentication prompt.

set -euo pipefail

PROGRAM=${0##*/}

# --- defaults ---------------------------------------------------------------
WIFI_IFACE=""            # autodetected: first nmcli device of type wifi
TETHER_IFACE=""          # optional: phone tether device (usb0 / enp0s20u1 / a
                         # wifi device joined to the phone's hotspot). Only
                         # existence-checked; NetworkManager brings it up.
METHOD="radio"           # radio | device
ITERATIONS=20
SETTLE_SECONDS=8
DRY_RUN=0
LOG_FILE=""

usage() {
    cat <<'USAGE'
Usage: switch-linux.sh [options]

Drives N Wi-Fi <-> tethering transitions on Linux via nmcli and prints one JSON
record line per transition. Intended to run beside an interactive
`qsh user@host` session whose stderr is captured; feed that stderr to
scripts/mobility/summarize.py afterwards.

Options:
  --iterations N       Number of switch iterations (default: 20). Each
                       iteration is one round trip: wifi->tether then
                       tether->wifi, so two transitions and two record lines.
  --settle SECONDS     Seconds to stay on a link before switching (default: 8).
  --wifi-iface DEV     Wi-Fi device (default: first `nmcli device` of type wifi).
  --tether-iface DEV   Tether device to verify exists before starting
                       (e.g. usb0). Optional; it is never toggled, it only has
                       to be present so the route can fail over to it.
  --method MODE        radio | device (default: radio).
                       radio:  nmcli radio wifi off|on        (no root)
                       device: nmcli device disconnect|connect DEV
                               (may prompt for authentication)
  --dry-run            Touch nothing. Print exactly the commands that would
                       run, then exit 0.
  --log FILE           Append record lines to FILE as well as stdout.
  -h, --help           This text.

Exit codes: 0 ok, 2 bad usage, 3 missing interface or missing tool,
130 interrupted (the original radio/device state is restored on every exit path).
USAGE
}

log() { printf '%s\n' "$*" >&2; }
die() { log "$PROGRAM: $1"; exit "${2:-2}"; }

now_ms() {
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
        --wifi-iface) [ $# -ge 2 ] || die "--wifi-iface needs a value"; WIFI_IFACE=$2; shift 2 ;;
        --wifi-iface=*) WIFI_IFACE=${1#*=}; shift ;;
        --tether-iface) [ $# -ge 2 ] || die "--tether-iface needs a value"; TETHER_IFACE=$2; shift 2 ;;
        --tether-iface=*) TETHER_IFACE=${1#*=}; shift ;;
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
case "$METHOD" in radio|device) ;; *) die "--method must be radio or device" ;; esac

[ "$(uname -s)" = "Linux" ] || die "this script is Linux-only; use switch-macos.sh" 3
command -v nmcli >/dev/null 2>&1 || die "nmcli not found (NetworkManager required)" 3

# --- discovery (read-only; safe to do even under --dry-run) -----------------
DEVICES=$(nmcli -t -f DEVICE,TYPE device status 2>/dev/null || true)
[ -n "$DEVICES" ] || die "nmcli reported no devices" 3

if [ -z "$WIFI_IFACE" ]; then
    WIFI_IFACE=$(printf '%s\n' "$DEVICES" | awk -F: '$2 == "wifi" { print $1; exit }')
fi
[ -n "$WIFI_IFACE" ] || die "could not autodetect a wifi device; pass --wifi-iface" 3

if ! printf '%s\n' "$DEVICES" | awk -F: '{ print $1 }' | grep -Fxq "$WIFI_IFACE"; then
    log "$PROGRAM: no such device: ${WIFI_IFACE}"
    log "$PROGRAM: known devices:"
    printf '%s\n' "$DEVICES" | sed 's/^/  - /' >&2
    exit 3
fi

if [ -n "$TETHER_IFACE" ]; then
    if ! printf '%s\n' "$DEVICES" | awk -F: '{ print $1 }' | grep -Fxq "$TETHER_IFACE"; then
        log "$PROGRAM: no such device: ${TETHER_IFACE}"
        log "$PROGRAM: known devices:"
        printf '%s\n' "$DEVICES" | sed 's/^/  - /' >&2
        exit 3
    fi
fi

ORIGINAL_RADIO=$(nmcli -t radio wifi 2>/dev/null || printf 'enabled')

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
    local run=$1 direction=$2 t0=$3 t1=$4 line
    line=$(printf '{"mobility":"switch","platform":"linux","run":%s,"direction":"%s","method":"%s","switch_started_ms":%s,"switch_issued_ms":%s,"at":"%s"}' \
        "$run" "$direction" "$METHOD" "$t0" "$t1" "$(now_iso)")
    printf '%s\n' "$line"
    if [ -n "$LOG_FILE" ] && [ "$DRY_RUN" -eq 0 ]; then
        printf '%s\n' "$line" >>"$LOG_FILE"
    fi
    TRANSITIONS=$((TRANSITIONS + 1))
}

wifi_up() {
    case "$METHOD" in
        radio) run nmcli radio wifi on ;;
        device) run nmcli device connect "$WIFI_IFACE" ;;
    esac
}

wifi_down() {
    case "$METHOD" in
        radio) run nmcli radio wifi off ;;
        device) run nmcli device disconnect "$WIFI_IFACE" ;;
    esac
}

# shellcheck disable=SC2329  # invoked by the EXIT trap
restore() {
    [ "$RESTORED" -eq 0 ] || return 0
    RESTORED=1
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'DRY-RUN would restore: nmcli radio wifi -> %s\n' "$ORIGINAL_RADIO"
        return 0
    fi
    log "$PROGRAM: restoring radio wifi to ${ORIGINAL_RADIO}"
    case "$ORIGINAL_RADIO" in
        enabled) nmcli radio wifi on || log "$PROGRAM: restore failed" ;;
        *) nmcli radio wifi off || log "$PROGRAM: restore failed" ;;
    esac
    if [ "$METHOD" = "device" ] && [ "$ORIGINAL_RADIO" = "enabled" ]; then
        nmcli device connect "$WIFI_IFACE" || log "$PROGRAM: device restore failed"
    fi
}

# shellcheck disable=SC2329  # invoked by the INT/TERM trap
on_signal() { log "$PROGRAM: interrupted"; exit 130; }
trap restore EXIT
trap on_signal INT TERM

# --- preflight summary ------------------------------------------------------
log "$PROGRAM: wifi_iface=${WIFI_IFACE} tether_iface=${TETHER_IFACE:-<unset>} method=${METHOD}"
log "$PROGRAM: iterations=${ITERATIONS} settle=${SETTLE_SECONDS}s original_radio=${ORIGINAL_RADIO}"
if [ "$DRY_RUN" -eq 1 ]; then
    log "$PROGRAM: DRY RUN — no interface will be touched"
else
    log "$PROGRAM: LIVE RUN — this drops and restores the link ${ITERATIONS} times"
    log "$PROGRAM: capture the qsh session's stderr, e.g. 2>mobility-stderr.log"
fi

i=1
while [ "$i" -le "$ITERATIONS" ]; do
    t0=$(now_ms)
    wifi_down
    t1=$(now_ms)
    record "$i" "wifi->tether" "$t0" "$t1"
    pause

    t0=$(now_ms)
    wifi_up
    t1=$(now_ms)
    record "$i" "tether->wifi" "$t0" "$t1"
    pause

    i=$((i + 1))
done

log "$PROGRAM: ${TRANSITIONS} transitions issued over ${ITERATIONS} iterations"
exit 0
