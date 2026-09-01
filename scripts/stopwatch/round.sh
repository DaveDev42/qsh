#!/usr/bin/env bash
# Prepare one round of the SC1 stopwatch campaign
# (docs/campaigns/m7-stopwatch.md) and verify §3's preconditions.
#
# This script does not measure anything. It tears the previous round's
# containers down, brings a fresh pair up, checks that both are in the
# "never configured" state, and prints the two commands the facilitator
# hands to the subject. The stopwatch starts after that, on a human.
#
# Plain `docker` on purpose: `docker compose` is a separate plugin that is
# not present on every daemon this repo gets pointed at, and two containers
# on one network do not need it.
#
# Usage: scripts/stopwatch/round.sh [N]
set -euo pipefail

ROUND=${1:-?}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

IMAGE=qsh-stopwatch:latest
NET=qsh-stopwatch-net
HOST_C=qsh-sw-host
CLIENT_C=qsh-sw-client

FAILED=0
fail() { printf '  FAIL  %s\n' "$*"; FAILED=1; }
ok()   { printf '  ok    %s\n' "$*"; }
cexec() { docker exec "$1" sh -c "$2"; }

echo "== round ${ROUND}: rebuilding from the working tree =="
git -C "$ROOT" rev-parse HEAD
if ! git -C "$ROOT" diff --quiet || \
   [ -n "$(git -C "$ROOT" ls-files --others --exclude-standard)" ]; then
    echo "  note: working tree is dirty — record this in §8's 'qsh 커밋 SHA' row"
fi

docker rm -f "$HOST_C" "$CLIENT_C" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker build -t "$IMAGE" -f "$HERE/Dockerfile" "$ROOT"
docker network create "$NET" >/dev/null

# Each round gets a home directory that exists only in RAM and dies with the
# container — no config, no state, no keystore carried over. The network
# alias is what the client types where the README says host.example.com.
docker run -d --name "$HOST_C" --hostname box \
    --network "$NET" --network-alias host \
    --tmpfs /home/dave:uid=1000,gid=1000,mode=0700 "$IMAGE" >/dev/null
docker run -d --name "$CLIENT_C" --hostname laptop \
    --network "$NET" --network-alias client \
    --tmpfs /home/dave:uid=1000,gid=1000,mode=0700 "$IMAGE" >/dev/null
sleep 1

echo
echo "== §3 preconditions =="
for c in "$HOST_C" "$CLIENT_C"; do
    echo "-- $c"
    # Config and state directories absent. XDG vars are unset in the image,
    # so these are the paths qsh derives by default.
    for d in .config/qsh .local/state/qsh; do
        if cexec "$c" "test -e /home/dave/$d"; then
            fail "/home/dave/$d exists"
        else
            ok "no /home/dave/$d"
        fi
    done

    # PATH shadowing — the dry run hit this on the dev machine (§9).
    n=$(cexec "$c" 'command -v qsh >/dev/null 2>&1 && ls -1 $(echo $PATH | tr ":" "\n" | sed "s|$|/qsh|") 2>/dev/null | wc -l' | tr -d '\r ')
    if [ "$n" = "1" ]; then ok "exactly one qsh on PATH"; else fail "PATH resolves $n qsh binaries"; fi

    # Nothing already on the README's port, no leftover daemons. Also §9.
    if cexec "$c" 'ss -lun 2>/dev/null | grep -q ":4433 "'; then
        fail "something is bound to udp/4433"
    else
        ok "udp/4433 free"
    fi
    if cexec "$c" 'pgrep qsh >/dev/null 2>&1'; then
        fail "a qsh process is already running"
    else
        ok "no qsh process"
    fi

    # The subject must be able to reach a real credential store or knowingly
    # fall back; see this directory's README on what that changes.
    if cexec "$c" 'test -n "$DBUS_SESSION_BUS_ADDRESS"'; then
        ok "Secret Service session bus present"
    else
        echo "  note  no Secret Service — qsh init will use the file keystore"
        echo "        (scripts/stopwatch/README.md: this makes a container"
        echo "         round more permissive than a real desktop round)"
    fi
done

echo "-- network path"
if cexec "$CLIENT_C" 'ping -c1 -W2 host >/dev/null 2>&1'; then
    ok "client reaches host by name (separate netns, bridge network — not loopback)"
else
    fail "client cannot reach host"
fi

echo
if [ "$FAILED" -ne 0 ]; then
    echo "PRECONDITIONS NOT MET — do not start the timer. Record this round as 무효 (§7)."
    exit 1
fi

cat <<EOF
PRECONDITIONS MET. The environment is ready; the measurement is not automated.

Facilitator, before starting the timer (§3 checklist items 6 and 7):
  - have the stopwatch and the §6 record table ready
  - open README.md's "First run" section for the subject, and nothing else

Two terminals, side by side (§4 fixes this layout):
  docker exec -it $HOST_C bash
  docker exec -it $CLIENT_C bash

Where the README says \`host.example.com:4433\`, this host answers to \`host\`.
Timer starts on the subject's first keystroke of \`qsh init --json\` and stops
when the remote shell prompt first appears on the client.

When the round is over:
  docker rm -f $HOST_C $CLIENT_C && docker network rm $NET
EOF
