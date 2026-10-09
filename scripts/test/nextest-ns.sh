#!/bin/sh
# nextest-ns.sh — run `cargo nextest run` inside a private network namespace.
#
# Why: a host firewall rule that drops loopback UDP (a leftover nftables
# table, e.g. `udp dport 60000-61000 drop` without a loopback exception)
# makes ~4% of QUIC test endpoints unreachable and the tests time out after
# 10 s. The testkit self-check (qsh_testkit::env_check) detects it and points
# here. nft tables are per network namespace, so a fresh netns has none of
# the host's rules. See docs/design/testing.md (CI discipline) and
# docs/campaigns/m8-soak.md section 2 items 8-9.
#
# How: `unshare -Urn` gives a user + network namespace (uid 0 inside), `ip
# link set lo up` brings loopback up, and a nested `unshare -U --map-user
# --map-group` maps back to the caller's uid/gid so tests do not run as
# root. Running as uid 0 breaks PTY tests (the session would look up root's
# home, /root, mode 0700).
#
# Usage: scripts/test/nextest-ns.sh [cargo nextest run arguments...]
#   scripts/test/nextest-ns.sh --workspace
# With no arguments it runs `--workspace`.
set -eu

# Inner stage: already inside both namespaces as the caller's uid/gid.
if [ "${QSH_NEXTEST_NS_INNER:-}" = 1 ]; then
    [ "$#" -gt 0 ] || set -- --workspace
    exec cargo nextest run "$@"
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "nextest-ns.sh: run as a normal user, not root (the nested user namespace maps back to your uid)" >&2
    exit 2
fi
uid=$(id -u)
gid=$(id -g)
[ "$#" -gt 0 ] || set -- --workspace

# Compile outside the namespace so crate downloads and build caches behave
# as usual; only the test run is isolated.
cargo nextest run "$@" --no-run

export QSH_NEXTEST_NS_INNER=1
exec unshare -Urn sh -c '
    uid=$1; gid=$2; self=$3; shift 3
    ip link set lo up || { echo "nextest-ns.sh: ip link set lo up failed (needs the iproute2 ip command)" >&2; exit 1; }
    exec unshare -U --map-user="$uid" --map-group="$gid" "$self" "$@"
' sh "$uid" "$gid" "$0" "$@"
