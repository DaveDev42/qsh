#!/usr/bin/env bash
# punch.sh — hole punching against the Linux kernel's own NAT (ADR-0054
# decision 24, DoD 13): network namespaces and nftables, real `qsh` binaries.
#
# Topology, rebuilt for every pair (the NAT boxes are the Linux conntrack
# NAT, the only NAT this script can build without a second machine):
#
#   A -- natA --\                     /-- R   (qsh listen, public address)
#                inet (a router) ----
#   B -- natB --/
#
# Every wan link carries 12.5 ms of netem delay in each direction, so each of
# A-R, B-R and A-B is 25 ms one way, the figure DoD 1 uses. Without the
# `sch_netem` module the delay is skipped and the script says so.
#
# NAT kinds (A and B each get one):
#   none  no NAT box: the host sits on the public segment itself.
#   masq  `masquerade`: endpoint-independent mapping, port preserved, address
#         and port dependent filtering. netsim's `port_restricted`.
#   rand  `masquerade fully-random`: a new random outside port per
#         destination. netsim's `symmetric`.
# The other netsim presets (full_cone, restricted) have no stock conntrack
# equivalent, so the table below is the three-by-three corner of ADR-0054
# decision 23 that the kernel can build:
#
#   A\B    none  masq  rand
#   none    ok    ok    ok
#   masq    ok    ok   FAIL
#   rand    ok   FAIL  FAIL
#
# A success runs `qsh exec` over the punched connection and takes the
# `adopted` line's elapsed_ms (route start to adopted connection, signalling
# included) from the `qsh::punch` log target; it must be <= $ADOPT_BOUND_MS.
# A failure must give up with details.punch.reason "timeout" inside the
# punch budget. A is told which rendezvous to use with `--rendezvous r`
# (ADR-0054 decision 19), so this script needs a build that has the flag.
#
# Needs root, Linux, ip, nft, and a `qsh` binary. It uses only its own
# namespaces (qn-*) and temp config directories under $TMPDIR; it never
# touches the caller's ~/.config/qsh and never binds UDP 4433 (R listens on
# 9000).
#
# Environment:
#   QSH_ACCEPTANCE_NETNS=1   required, or the script skips with exit 0.
#   QSH_BIN                  the qsh binary (default: target/release/qsh).
#   PUNCH_NETNS_PAIRS        pairs to run, "a:b a:b ..." (default: all nine).
#   PUNCH_NETNS_SMOKE=1      stop after B has registered through its NAT at R;
#                            needs no --rendezvous flag. Checks the topology.
#   ADOPT_BOUND_MS           adopted bound in ms (default 1000).
#
# Exit: 0 all pairs as expected (or skipped), 1 a pair differed, 3 a
# prerequisite is missing.

set -euo pipefail

PROGRAM=${0##*/}
log() { printf '%s\n' "$*" >&2; }
die() { log "$PROGRAM: $1"; exit "${2:-1}"; }

case "${QSH_ACCEPTANCE_NETNS:-}" in
    "" | 0) log "SKIP: $PROGRAM needs QSH_ACCEPTANCE_NETNS=1"; exit 0 ;;
esac

[ "$(uname -s)" = Linux ] || die "Linux only" 3
[ "$(id -u)" -eq 0 ] || die "run as root (sudo -E $0)" 3
for tool in ip nft; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool" 3
done

QSH_BIN=${QSH_BIN:-target/release/qsh}
[ -x "$QSH_BIN" ] || die "qsh binary not found or not executable: $QSH_BIN" 3
QSH_BIN=$(readlink -f "$QSH_BIN")
ADOPT_BOUND_MS=${ADOPT_BOUND_MS:-1000}
# 3 s signalling + 5 s window, plus a second of process start and exit.
GIVE_UP_BOUND_MS=${GIVE_UP_BOUND_MS:-9000}
PAIRS=${PUNCH_NETNS_PAIRS:-"none:none none:masq none:rand masq:none masq:masq masq:rand rand:none rand:masq rand:rand"}
SMOKE=${PUNCH_NETNS_SMOKE:-0}

R_IP=192.0.2.2
R_PORT=9000   # never 4433: a developer's own qsh may hold it
NS="qn-a qn-b qn-r qn-i qn-na qn-nb"

if [ "$SMOKE" != 1 ] && ! "$QSH_BIN" exec --help 2>&1 | grep -q -- '--rendezvous'; then
    die "$QSH_BIN has no --rendezvous flag (ADR-0054 decision 19); PUNCH_NETNS_SMOKE=1 checks only the topology" 3
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/qsh-netns.XXXXXX")
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

teardown() {
    stop_procs
    local ns
    for ns in $NS; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

cleanup() {
    teardown
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

NETEM=1
if ! ip netns add qn-probe 2>/dev/null; then
    die "cannot create a network namespace (root with CAP_SYS_ADMIN?)" 3
fi
ip link add qnprobe0 type veth peer name qnprobe1 2>/dev/null \
    || { ip netns del qn-probe; die "cannot create a veth pair" 3; }
if ! tc qdisc add dev qnprobe0 root netem delay 12.5ms 2>/dev/null; then
    NETEM=0
    log "$PROGRAM: sch_netem is not available; links run without the 25 ms delay"
fi
ip link del qnprobe0 2>/dev/null || true
ip netns del qn-probe 2>/dev/null || true

# link <ns1> <if1> <ip1/len> <ns2> <if2> <ip2/len>: a veth pair, addressed,
# up, with netem delay on both ends' egress.
link() {
    local ns1=$1 if1=$2 ip1=$3 ns2=$4 if2=$5 ip2=$6
    ip link add "qnx-$$-1" type veth peer name "qnx-$$-2"
    ip link set "qnx-$$-1" netns "$ns1" name "$if1"
    ip link set "qnx-$$-2" netns "$ns2" name "$if2"
    ip -n "$ns1" addr add "$ip1" dev "$if1"
    ip -n "$ns2" addr add "$ip2" dev "$if2"
    ip -n "$ns1" link set "$if1" up
    ip -n "$ns2" link set "$if2" up
}

delay() { # <ns> <if>
    [ "$NETEM" = 1 ] || return 0
    ip netns exec "$1" tc qdisc add dev "$2" root netem delay 12.5ms
}

# nat_box <ns> <kind>: forwarding plus the nftables rules for one NAT kind.
nat_box() {
    local ns=$1 kind=$2 flags=""
    ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
    [ "$kind" = rand ] && flags="fully-random"
    ip netns exec "$ns" nft -f - <<NFT
table ip qsh_nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname "wan" masquerade $flags
    }
}
table ip qsh_filter {
    chain input {
        type filter hook input priority 0; policy accept;
        # An unsolicited datagram for the box itself is dropped silently, as
        # a home router does, instead of drawing an ICMP unreachable.
        iifname "wan" meta l4proto udp drop
    }
}
NFT
}

# site <name> <kind> <wan prefix> <lan prefix>: host qn-<name> either on the
# public segment (none) or behind qn-n<name> (masq, rand).
site() {
    local name=$1 kind=$2 wan=$3 lan=$4
    if [ "$kind" = none ]; then
        link qn-i "i-$name" "$wan.1/24" "qn-$name" wan "$wan.2/24"
        delay qn-i "i-$name"; delay "qn-$name" wan
        ip -n "qn-$name" route add default via "$wan.1"
    else
        link qn-i "i-$name" "$wan.1/24" "qn-n$name" wan "$wan.2/24"
        delay qn-i "i-$name"; delay "qn-n$name" wan
        link "qn-n$name" lan "$lan.1/24" "qn-$name" lan "$lan.2/24"
        ip -n "qn-n$name" route add default via "$wan.1"
        ip -n "qn-$name" route add default via "$lan.1"
        nat_box "qn-n$name" "$kind"
    fi
}

build() { # <a kind> <b kind>
    local ns
    for ns in $NS; do
        # qn-na and qn-nb exist only for NAT kinds, but creating all is cheap.
        ip netns add "$ns"
        ip -n "$ns" link set lo up
    done
    ip netns exec qn-i sysctl -qw net.ipv4.ip_forward=1
    link qn-i i-r 192.0.2.1/24 qn-r wan "$R_IP/24"
    delay qn-i i-r; delay qn-r wan
    ip -n qn-r route add default via 192.0.2.1
    site a "$1" 198.51.100 10.10.1
    site b "$2" 203.0.113 10.10.2
}

# env_for <name>: the environment of one party: a config tree of its own
# under $WORK, so nothing here reads the caller's ~/.config/qsh.
env_for() {
    mkdir -p "$WORK/$1/c" "$WORK/$1/s" "$WORK/$1/r" "$WORK/$1/h"
    chmod 700 "$WORK/$1/r"
    printf '%s\n' "QSH_CONFIG_DIR=$WORK/$1/c" "QSH_STATE_DIR=$WORK/$1/s" \
        "XDG_RUNTIME_DIR=$WORK/$1/r" "HOME=$WORK/$1/h" \
        "QSH_LOG=warn,qsh::reverse=info,qsh::lifecycle=info,qsh::punch=info"
}

# party <name> <cmd...>: run a command in qn-<name>, in the foreground.
party() {
    local name=$1 vars
    shift
    mapfile -t vars < <(env_for "$name")
    ip netns exec "qn-$name" env "${vars[@]}" "$@"
}

# spawn <name> <cmd...>: the same in the background. The subshell execs, so
# the recorded pid is the program's own and stop_procs can kill it.
spawn() {
    local name=$1 vars
    shift
    mapfile -t vars < <(env_for "$name")
    (exec ip netns exec "qn-$name" env "${vars[@]}" "$@") &
    PIDS+=($!)
}

qsh() { party "$1" "$QSH_BIN" "${@:2}"; }

# pin <who> <name> <whom> [address]: who trusts whom's certificate. An
# address makes the pin dialable; without one the role must be explicit.
pin() {
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
    log "$PROGRAM: timed out waiting for $what"
    return 1
}

now_ms() { date +%s%3N; }

# expected <a> <b>: ok or fail, from the table in the header.
expected() {
    case "$1:$2" in
        masq:rand | rand:masq | rand:rand) echo fail ;;
        *) echo ok ;;
    esac
}

run_pair() { # <a kind> <b kind>
    local a=$1 b=$2 want pair="$1 x $2"
    want=$(expected "$a" "$b")
    teardown
    rm -rf "$WORK"/{a,b,r}
    build "$a" "$b"

    local who
    for who in a b r; do
        qsh "$who" init --key-store file >/dev/null
        qsh "$who" identity export >"$WORK/$who.pem"
    done
    # A pins R (dialable) and B (no address: the route punches at once).
    pin a r r "$R_IP:$R_PORT"
    pin a b b
    # R pins A and B; B pins R (dialable) and A.
    pin r a a
    pin r b b
    pin b r r "$R_IP:$R_PORT"
    pin b a a

    spawn r "$QSH_BIN" listen --bind "$R_IP:$R_PORT" 2>"$WORK/r.log" >/dev/null
    wait_for 10 "R to listen" grep -q 'listening' "$WORK/r.log" \
        || { cat "$WORK/r.log" >&2; return 1; }
    spawn b "$QSH_BIN" serve --to r 2>"$WORK/b.log" >/dev/null
    wait_for 15 "B to register at R through its NAT" grep -q 'registered' "$WORK/r.log" \
        || { log "--- R"; cat "$WORK/r.log" >&2; log "--- B"; cat "$WORK/b.log" >&2; return 1; }

    if [ "$SMOKE" = 1 ]; then
        log "ok    $pair: B registered at R through its NAT (smoke)"
        stop_procs
        return 0
    fi

    local start end took out err rc=0 adopted reason
    out="$WORK/a.out"
    err="$WORK/a.err"
    start=$(now_ms)
    qsh a --no-ssh --json exec --rendezvous r b -- echo punched >"$out" 2>"$err" || rc=$?
    end=$(now_ms)
    took=$((end - start))
    stop_procs

    if [ "$want" = ok ]; then
        if [ "$rc" -ne 0 ] || ! grep -q cHVuY2hlZAo= "$out"; then
            log "FAIL  $pair: expected a punched connection, exit $rc after ${took} ms"
            cat "$out" "$err" "$WORK/r.log" "$WORK/b.log" >&2
            return 1
        fi
        adopted=$(grep '"punch":"adopted"' "$err" | grep -o '"elapsed_ms":[0-9]*' | head -n1 | cut -d: -f2 || true)
        if [ -z "$adopted" ]; then
            log "FAIL  $pair: no adopted line on the qsh::punch target (the command may have gone direct)"
            cat "$err" >&2
            return 1
        fi
        if [ "$adopted" -gt "$ADOPT_BOUND_MS" ]; then
            log "FAIL  $pair: adopted after ${adopted} ms, bound ${ADOPT_BOUND_MS} ms"
            return 1
        fi
        log "ok    $pair: adopted ${adopted} ms, exec done ${took} ms"
        RESULTS+=("$pair $adopted")
    else
        reason=$(grep -o '"punch":{[^}]*}' "$out" | grep -o '"reason":"[a-z_]*"' | head -n1 || true)
        if [ "$rc" -eq 0 ]; then
            log "FAIL  $pair: expected the punch to give up, but the command succeeded"
            return 1
        fi
        if [ "$reason" != '"reason":"timeout"' ]; then
            log "FAIL  $pair: expected punch reason timeout, got '${reason:-none}'"
            cat "$out" "$err" >&2
            return 1
        fi
        if [ "$took" -gt "$GIVE_UP_BOUND_MS" ]; then
            log "FAIL  $pair: gave up after ${took} ms, bound ${GIVE_UP_BOUND_MS} ms"
            return 1
        fi
        log "ok    $pair: gave up (timeout) after ${took} ms"
    fi
}

RESULTS=()
failed=0
for pair in $PAIRS; do
    run_pair "${pair%%:*}" "${pair##*:}" || { failed=$((failed + 1)); log "FAIL  ${pair%%:*} x ${pair##*:}"; }
done

if [ "${#RESULTS[@]}" -gt 0 ]; then
    worst=$(printf '%s\n' "${RESULTS[@]}" | awk '{ if ($NF > m) m = $NF } END { print m }')
    log "adopted: ${#RESULTS[@]} punched pairs, worst ${worst} ms (bound ${ADOPT_BOUND_MS} ms), netem=${NETEM}"
fi
[ "$failed" -eq 0 ] || die "$failed pair(s) differed from the expected table" 1
log "$PROGRAM: all pairs as expected"
