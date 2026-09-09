#!/bin/bash -eu
set -euo pipefail
# OSS-Fuzz build script for qsh.
#
# Runs inside the base-builder-rust image (see Dockerfile) with $SRC/qsh
# as the working directory, $OUT and $WORK set by the OSS-Fuzz harness.
# base-builder-rust's cargo-fuzz is assumed to be the nightly-toolchain
# build of cargo-fuzz already on PATH there (verification needed — see
# Dockerfile comment); CARGO_FUZZ lets a caller override the command,
# which is what scripts/fuzz/oss-fuzz-local.sh does on a machine where
# `cargo fuzz` on PATH resolves to a stable toolchain instead of nightly.
CARGO_FUZZ="${CARGO_FUZZ:-cargo fuzz}"

cd fuzz

# CARGO_FUZZ may be a multi-word override such as "rustup run nightly
# cargo fuzz", so it must be left unquoted to word-split.
# shellcheck disable=SC2086
$CARGO_FUZZ build -O --debug-assertions

# cargo-fuzz's own target list is the source of truth (fuzz/README.md
# "Driving the target list from `cargo fuzz list`" / fuzz-smoke.yml carry
# the same rule) — a hard-coded name list here would drift from it.
# (a read loop rather than `mapfile`: macOS /bin/bash is 3.2 and lacks it)
FUZZ_TARGETS=()
# shellcheck disable=SC2086
while IFS= read -r fuzz_target; do FUZZ_TARGETS+=("$fuzz_target"); done < <($CARGO_FUZZ list)
if [ "${#FUZZ_TARGETS[@]}" -eq 0 ]; then
  echo "build.sh: \$CARGO_FUZZ list returned no targets" >&2
  exit 1
fi

# cargo-fuzz's own release output directory for this build profile —
# under the host triple cargo-fuzz built for (x86_64-unknown-linux-gnu
# inside the OSS-Fuzz image; whatever the local nightly toolchain reports
# when run through scripts/fuzz/oss-fuzz-local.sh, e.g. macOS aarch64).
HOST_TRIPLE="$(rustc -vV | /usr/bin/awk '/^host: /{print $2}')"
FUZZ_TARGET_DIR="target/$HOST_TRIPLE/release"

for target in "${FUZZ_TARGETS[@]}"; do
  cp "$FUZZ_TARGET_DIR/$target" "$OUT/"

  corpus_dir="corpus/$target"
  if [ -d "$corpus_dir" ]; then
    zip -j -r "$OUT/${target}_seed_corpus.zip" "$corpus_dir"
  fi

  # No target carries a .options file today (no dictionaries, no
  # non-default max_len) — add one alongside its binary here if that
  # changes.
done
