#!/bin/sh
# All-or-none gate for a set of release signing secrets. Used by the macOS leg
# (Apple, six secrets) of .github/workflows/release.yml; Windows assets ship
# unsigned (ADR-0035 개정 이력, 2026-10-19). The three outcomes below are
# pinned in one place (xtask/tests/install_script/secret_gate.rs).
#
# Usage:
#   secret-gate.sh <output> <label> <doing> <skipping> <unsigned> <flag>...
#
#   output     key written to $GITHUB_OUTPUT, "true" or "false" (has-apple).
#   label      Name used in messages ("Apple").
#   doing      What runs when every secret is set ("signing and notarizing").
#   skipping   What is skipped otherwise ("codesign and notarization").
#   unsigned   Sentence for the `Unsigned release` warning on a tag push.
#   flag...    One "true"/"false" per secret: whether it is set. The workflow
#              computes them as `${{ secrets.NAME != '' }}` in `env:`, so no
#              secret value ever reaches this script.
#
# Env:
#   IS_TAG        "true" on a tag push (`startsWith(github.ref, 'refs/tags/')`).
#   GITHUB_OUTPUT File the output key is appended to (set by the runner).
#
# All set: writes <output>=true and exits 0.
# None set: writes <output>=false; a tag push gets an `Unsigned release`
#   warning, a branch run a plain notice; exits 0, so a repository without
#   credentials still ships what it ships today.
# Some set: writes <output>=false. A partial set is a misconfiguration. On a
#   tag the artifacts ship and the signing is being judged, so it is an error
#   (exit 1); on a branch dispatch the artifacts are thrown away and the
#   operator is mid-way through adding secrets, so it is a warning and a skip.

set -eu

if [ "$#" -lt 6 ]; then
    echo "usage: secret-gate.sh <output> <label> <doing> <skipping> <unsigned> <flag>..." >&2
    exit 2
fi

output="$1"
label="$2"
doing="$3"
skipping="$4"
unsigned="$5"
shift 5

total=$#
present=0
for flag in "$@"; do
    if [ "$flag" = "true" ]; then present=$((present + 1)); fi
done

is_tag="${IS_TAG:-false}"

if [ "$present" -eq "$total" ]; then
    echo "${output}=true" >> "$GITHUB_OUTPUT"
    echo "All ${total} ${label} signing secrets are set; ${doing}."
    exit 0
fi

echo "${output}=false" >> "$GITHUB_OUTPUT"
if [ "$present" -eq 0 ]; then
    if [ "$is_tag" = "true" ]; then
        echo "::warning title=Unsigned release::${unsigned}"
    else
        echo "No ${label} signing secrets are configured; skipping ${skipping}."
    fi
    exit 0
fi

msg="${label} signing is partially configured: ${present} of ${total} secrets are set."
if [ "$is_tag" = "true" ]; then
    echo "::error title=Partial ${label} signing config::${msg} Set all ${total} or none."
    exit 1
fi
echo "::warning title=Partial ${label} signing config::${msg} Skipping ${skipping}."
