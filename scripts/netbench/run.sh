#!/usr/bin/env bash
# Reproducible network bench driver (ADR-0052 decision 18 item 8).
#
#   scripts/netbench/run.sh [--out FILE] [--no-build] [PROFILE ...]
#
# PROFILE is a profile name (profiles/NAME.toml), a path, or a question
# prefix such as q5 (every profile whose name starts with "q5-"). With no
# PROFILE every profile runs. Each run prints one JSON line on stdout and, with
# --out, appends it to FILE. Logs go to stderr.
#
# Rootless: every run happens inside `unshare -rn` (a user and network
# namespace in which we are mapped to root). Inside it, a second network
# namespace holds the client; a veth pair joins the two and `tc` netem (delay,
# loss) plus tbf (rate, queue) shape each direction. Nothing here touches the
# host's network, and only ephemeral UDP ports are used, so a qsh serve on
# UDP 4433 is never involved.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
bin=${NETBENCH_BIN:-$here/target/release/netbench}

# ------------------------------------------------------------ inner (in netns)
if [ "${NB_INNER:-}" = 1 ]; then
  profile=$1
  eval "$("$bin" profile-env "$profile")"

  work=$(mktemp -d "${TMPDIR:-/tmp}/netbench.XXXXXX")
  holder=
  server=
  cleanup() {
    [ -n "$server" ] && kill "$server" 2>/dev/null || true
    [ -n "$holder" ] && kill "$holder" 2>/dev/null || true
    rm -rf "$work"
  }
  trap cleanup EXIT

  ip link set lo up
  # The client's network namespace is owned by our user namespace; a sleeping
  # process keeps it alive.
  unshare -n sleep 3600 &
  holder=$!
  me=$(readlink /proc/self/ns/net)
  for _ in $(seq 50); do
    [ "$(readlink "/proc/$holder/ns/net" 2>/dev/null || echo "$me")" != "$me" ] && break
    sleep 0.1
  done
  inclient() { nsenter -t "$holder" -n "$@"; }

  ip link add nbh type veth peer name nbc netns "$holder"
  inclient ip link set lo up
  ip addr add 10.99.0.1/24 dev nbh
  inclient ip addr add 10.99.0.2/24 dev nbc
  ip link set nbh mtu "$NB_MTU" up
  inclient ip link set nbc mtu "$NB_MTU" up

  shape() { # shape DEV [nsenter-prefix...]
    local dev=$1; shift
    local args=(limit 100000)
    [ "$NB_DELAY_US" -gt 0 ] && args+=(delay "${NB_DELAY_US}us")
    [ "$NB_LOSS_PCT" != 0 ] && args+=(loss "${NB_LOSS_PCT}%")
    "$@" tc qdisc add dev "$dev" root handle 1: netem "${args[@]}"
    if [ "$NB_RATE_KBIT" -gt 0 ]; then
      "$@" tc qdisc add dev "$dev" parent 1:1 handle 10: tbf \
        rate "${NB_RATE_KBIT}kbit" burst "$NB_BURST_BYTES" limit "$NB_LIMIT_BYTES"
    fi
  }
  shape nbh
  shape nbc nsenter -t "$holder" -n

  echo "netbench: $NB_NAME shaped (delay ${NB_DELAY_US}us/dir loss ${NB_LOSS_PCT}% rate ${NB_RATE_KBIT}kbit limit ${NB_LIMIT_BYTES}B mtu $NB_MTU)" >&2

  "$bin" serve --profile "$profile" --bind 10.99.0.1 --ready "$work/ready" --cert "$work/cert.der" \
    2>"$work/server.log" &
  server=$!
  for _ in $(seq 100); do
    [ -s "$work/ready" ] && break
    kill -0 "$server" 2>/dev/null || { cat "$work/server.log" >&2; echo "netbench: server exited early" >&2; exit 1; }
    sleep 0.1
  done
  [ -s "$work/ready" ] || { echo "netbench: server never became ready" >&2; exit 1; }

  rc=0
  inclient timeout $((NB_DURATION_S + 60)) "$bin" client --profile "$profile" --bind 10.99.0.2 \
    --ready "$work/ready" --cert "$work/cert.der" 2>"$work/client.log" || rc=$?
  if [ "$rc" != 0 ]; then
    echo "netbench: client failed (rc=$rc)" >&2
    cat "$work/client.log" "$work/server.log" >&2
    exit "$rc"
  fi
  exit 0
fi

# --------------------------------------------------------------------- outer
out=
build=1
want=()
while [ $# -gt 0 ]; do
  case $1 in
    --out) out=$2; shift 2 ;;
    --no-build) build=0; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) want+=("$1"); shift ;;
  esac
done

for tool in unshare nsenter ip tc timeout; do
  command -v "$tool" >/dev/null || { echo "netbench: missing $tool" >&2; exit 2; }
done
unshare -rn true 2>/dev/null || {
  echo "netbench: unshare -rn is not permitted here (user namespaces disabled?)" >&2; exit 2; }
unshare -rn sh -c 'ip link add nbt0 type veth peer name nbt1 && tc qdisc add dev nbt0 root handle 1: netem delay 1ms && tc qdisc add dev nbt0 parent 1:1 handle 10: tbf rate 1mbit burst 3000 limit 6000' \
  >/dev/null 2>&1 || {
  echo "netbench: veth/netem/tbf unavailable in a user namespace (need CONFIG_NET_SCH_NETEM and CONFIG_NET_SCH_TBF)" >&2; exit 2; }

if [ "$build" = 1 ]; then
  cargo build --release --locked --manifest-path "$here/Cargo.toml" >&2
fi

profiles=()
if [ ${#want[@]} -eq 0 ]; then
  for f in "$here"/profiles/*.toml; do profiles+=("$f"); done
else
  for w in "${want[@]}"; do
    if [ -f "$w" ]; then profiles+=("$w")
    elif [ -f "$here/profiles/$w.toml" ]; then profiles+=("$here/profiles/$w.toml")
    else
      found=0
      for f in "$here/profiles/$w"-*.toml; do [ -f "$f" ] && { profiles+=("$f"); found=1; }; done
      [ "$found" = 1 ] || { echo "netbench: no profile matches $w" >&2; exit 2; }
    fi
  done
fi

"$bin" check "${profiles[@]}"

failed=0
for f in "${profiles[@]}"; do
  line=$(NB_INNER=1 NETBENCH_BIN=$bin unshare -rn "$here/run.sh" "$f") || { echo "netbench: $(basename "$f") FAILED" >&2; failed=1; continue; }
  printf '%s\n' "$line"
  [ -n "$out" ] && printf '%s\n' "$line" >>"$out"
done
exit "$failed"
