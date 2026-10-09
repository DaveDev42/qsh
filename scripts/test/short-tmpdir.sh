#!/bin/sh
# short-tmpdir.sh — nextest setup script (.config/nextest.toml).
#
# A unix socket path must fit sun_path (108 bytes on Linux). Many tests bind
# sockets under tempfile directories, so a long $TMPDIR (~100 chars, e.g. a
# deep per-session scratch dir) makes ~120 tests fail with "path must be
# shorter than SUN_LEN". When $TMPDIR is longer than 48 bytes this script
# points the test processes at a short per-user directory under /tmp instead.
# A short $TMPDIR is left alone.
set -eu
[ -n "${NEXTEST_ENV:-}" ] || exit 0
cur="${TMPDIR:-/tmp}"
if [ "${#cur}" -le 48 ]; then
    exit 0
fi
short="/tmp/qsh-t-$(id -u)"
mkdir -p "$short"
chmod 700 "$short"
echo "qsh: TMPDIR '$cur' is ${#cur} bytes, too long for unix socket paths; tests use '$short'" >&2
echo "TMPDIR=$short" >> "$NEXTEST_ENV"
