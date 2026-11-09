#!/usr/bin/env bash
# run.sh — what a jump costs on a path where bandwidth is the bottleneck
# (ADR-0056 decision 25, DoD 13). Network namespaces, `tc netem`, real `qsh`
# binaries.
#
#   C ---- link cj ---- J ---- link jt ---- T
#    \                                     /
#     \------------- link ct -------------/
#
# Every link is 20 Mbit/s with $DELAY_MS ms of delay in each direction and a
# short drop-tail queue, on both ends' egress. The same file goes from C to T
# twice: straight over link ct (`qsh cp`), and through J over cj and jt
# (`qsh cp -J j`). Both paths are bottlenecked at 20 Mbit/s, so the ratio is
# what the second QUIC layer and the relay cost when CPU is not the limit.
# The goal is 80% of the direct rate, the figure ADR-0052's measurement uses.
# `jump_tunnel_throughput` (loopback, CPU-bound) holds the lower 50% bar.
#
# Prints one JSON line (`qsh.jumpbench/v1`) with the medians and the ratio.
# Report-only by default; JUMPBENCH_ENFORCE=1 makes a ratio under
# $JUMPBENCH_TARGET exit 1.
#
# Needs Linux, `ip`, `tc` (sch_netem), and a `qsh` binary. Root, or an
# unprivileged user namespace: run it as
#   unshare -rmn sh -c 'mount -t tmpfs none /run && mkdir -p /run/netns && exec scripts/jumpbench/run.sh'
# It uses only its own namespaces (qj-*) and temp config directories under
# $TMPDIR; it never touches the caller's ~/.config/qsh and never binds UDP
# 4433 (J and T serve on 7000).
#
# Environment:
#   QSH_ACCEPTANCE_NETNS=1   required, or the script skips with exit 0.
#   QSH_BIN                  the qsh binary (default: target/release/qsh).
#   DELAY_MS                 one-way delay per link end (default 5).
#   RATE                     link rate (default 20mbit).
#   QUEUE_PACKETS            netem queue limit in packets (default 100).
#   FILE_MIB                 file size in MiB (default 12).
#   RUNS                     copies per path; the median is used (default 3).
#   JUMPBENCH_TARGET         ratio goal (default 0.80).
#   JUMPBENCH_ENFORCE=1      exit 1 when the ratio is under the goal.
#
# Exit: 0 done (or skipped), 1 ratio under the goal with ENFORCE, 2 a step
# failed, 3 a prerequisite is missing.

set -euo pipefail

PROGRAM=${0##*/}
log() { printf '%s\n' "$*" >&2; }
die() { log "$PROGRAM: $1"; exit "${2:-2}"; }

case "${QSH_ACCEPTANCE_NETNS:-}" in
    "" | 0) log "SKIP: $PROGRAM needs QSH_ACCEPTANCE_NETNS=1"; exit 0 ;;
esac

[ "$(uname -s)" = Linux ] || die "Linux only" 3
for tool in ip tc; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool" 3
done

QSH_BIN=${QSH_BIN:-target/release/qsh}
[ -x "$QSH_BIN" ] || die "qsh binary not found or not executable: $QSH_BIN" 3
QSH_BIN=$(readlink -f "$QSH_BIN")
DELAY_MS=${DELAY_MS:-5}
RATE=${RATE:-20mbit}
QUEUE_PACKETS=${QUEUE_PACKETS:-100}
FILE_MIB=${FILE_MIB:-12}
RUNS=${RUNS:-3}
TARGET=${JUMPBENCH_TARGET:-0.80}
PORT=7000   # never 4433: a developer's own qsh may hold it
NS="qj-c qj-j qj-t"

J_CJ=10.77.1.2   # J on link cj
J_JT=10.77.2.1   # J on link jt
T_JT=10.77.2.2   # T on link jt
T_CT=10.77.3.2   # T on link ct

WORK=$(mktemp -d "${TMPDIR:-/tmp}/qsh-jumpbench.XXXXXX")
PIDS=()

stop_procs() {
    local pid
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
    done
    PIDS=()
}

cleanup() {
    stop_procs
    local ns
    for ns in $NS; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# link <ns1> <if1> <ip1/len> <ns2> <if2> <ip2/len>: a veth pair, addressed,
# up, with the rate and the delay on both ends' egress.
link() {
    local ns1=$1 if1=$2 ip1=$3 ns2=$4 if2=$5 ip2=$6
    ip link add "qjx-$$-1" type veth peer name "qjx-$$-2"
    ip link set "qjx-$$-1" netns "$ns1" name "$if1"
    ip link set "qjx-$$-2" netns "$ns2" name "$if2"
    ip -n "$ns1" addr add "$ip1" dev "$if1"
    ip -n "$ns2" addr add "$ip2" dev "$if2"
    ip -n "$ns1" link set "$if1" up
    ip -n "$ns2" link set "$if2" up
    ip netns exec "$ns1" tc qdisc add dev "$if1" root netem \
        delay "${DELAY_MS}ms" rate "$RATE" limit "$QUEUE_PACKETS" \
        || die "tc netem failed (is sch_netem available?)" 3
    ip netns exec "$ns2" tc qdisc add dev "$if2" root netem \
        delay "${DELAY_MS}ms" rate "$RATE" limit "$QUEUE_PACKETS"
}

for ns in $NS; do
    ip netns add "$ns" || die "cannot create a network namespace" 3
    ip -n "$ns" link set lo up
done
link qj-c cj 10.77.1.1/24 qj-j cj "$J_CJ/24"
link qj-j jt "$J_JT/24" qj-t jt "$T_JT/24"
link qj-c ct 10.77.3.1/24 qj-t ct "$T_CT/24"

# A party's own config tree under $WORK, so nothing reads ~/.config/qsh.
env_for() {
    mkdir -p "$WORK/$1/c" "$WORK/$1/s" "$WORK/$1/r" "$WORK/$1/h" "$WORK/$1/out"
    chmod 700 "$WORK/$1/r"
    printf '%s\n' "QSH_CONFIG_DIR=$WORK/$1/c" "QSH_STATE_DIR=$WORK/$1/s" \
        "XDG_RUNTIME_DIR=$WORK/$1/r" "HOME=$WORK/$1/h" "QSH_LOG=warn"
}

party() {
    local name=$1 vars
    shift
    mapfile -t vars < <(env_for "$name")
    ip netns exec "qj-$name" env "${vars[@]}" "$@"
}

spawn() {
    local name=$1 vars
    shift
    mapfile -t vars < <(env_for "$name")
    (exec ip netns exec "qj-$name" env "${vars[@]}" "$@") &
    PIDS+=($!)
}

qsh() { party "$1" "$QSH_BIN" "${@:2}"; }

pin() { # <who> <name> <whom> [address]
    local who=$1 name=$2 whom=$3 address=${4:-}
    local args=(trust add "$name" --cert-file "$WORK/$whom.pem" --role full)
    [ -n "$address" ] && args+=(--address "$address")
    qsh "$who" "${args[@]}" >/dev/null
}

wait_for() { # <seconds> <description> <command...>
    local limit=$1 what=$2 i
    shift 2
    for ((i = 0; i < limit * 10; i++)); do
        if "$@" 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    die "timed out waiting for $what" 2
}

now_ms() { date +%s%3N; }

for who in c j t; do
    qsh "$who" init --key-store file >/dev/null
    qsh "$who" identity export >"$WORK/$who.pem"
done
# C reaches T straight (t, over ct) and through J (tj, T as J sees it, over
# jt). Both pins carry T's certificate. J and T pin C with the full role,
# which grants forward.jump on J.
pin c j j "$J_CJ:$PORT"
pin c t t "$T_CT:$PORT"
pin c tj t "$T_JT:$PORT"
pin j c c
pin j t t "$T_JT:$PORT"
pin t c c

spawn j "$QSH_BIN" serve --bind "$J_CJ:$PORT" 2>"$WORK/j.log" >/dev/null
spawn t "$QSH_BIN" serve --bind "0.0.0.0:$PORT" 2>"$WORK/t.log" >/dev/null
wait_for 10 "J to listen" grep -q 'listening' "$WORK/j.log"
wait_for 10 "T to listen" grep -q 'listening' "$WORK/t.log"

head -c "$((FILE_MIB * 1024 * 1024))" /dev/urandom >"$WORK/payload.bin"

# copy <label> <jump flags...> -- <target>: one timed copy, in ms.
copy() {
    local label=$1 target=$2
    shift 2
    local dest="$WORK/t/out/$label.bin" start end
    rm -f "$dest"
    start=$(now_ms)
    qsh c --no-ssh cp "$@" "$WORK/payload.bin" "$target:$dest" >/dev/null \
        || die "$label: qsh cp failed" 2
    end=$(now_ms)
    cmp -s "$WORK/payload.bin" "$dest" || die "$label: the copy differs from the source" 2
    echo $((end - start))
}

median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }

# One warm-up copy per path, then RUNS timed ones, alternating the paths.
copy direct t >/dev/null
copy jump tj -J j >/dev/null
direct_ms=()
jump_ms=()
for ((i = 0; i < RUNS; i++)); do
    direct_ms+=("$(copy direct t)")
    jump_ms+=("$(copy jump tj -J j)")
done
d=$(printf '%s\n' "${direct_ms[@]}" | median)
j=$(printf '%s\n' "${jump_ms[@]}" | median)

bits=$((FILE_MIB * 1024 * 1024 * 8))
awk -v bits="$bits" -v d="$d" -v j="$j" -v rate="$RATE" -v delay="$DELAY_MS" -v target="$TARGET" 'BEGIN {
    dm = bits / (d / 1000) / 1e6; jm = bits / (j / 1000) / 1e6; r = jm / dm
    printf "{\"schema\":\"qsh.jumpbench/v1\",\"rate\":\"%s\",\"delay_ms\":%s,\"direct_mbps\":%.2f,\"jump_mbps\":%.2f,\"ratio\":%.3f,\"target\":%s}\n", rate, delay, dm, jm, r, target
}' | tee "$WORK/result.json"
ratio=$(grep -o '"ratio":[0-9.]*' "$WORK/result.json" | cut -d: -f2)

if [ "${JUMPBENCH_ENFORCE:-0}" = 1 ] && awk -v r="$ratio" -v t="$TARGET" 'BEGIN { exit !(r < t) }'; then
    die "ratio $ratio is under the goal $TARGET" 1
fi
