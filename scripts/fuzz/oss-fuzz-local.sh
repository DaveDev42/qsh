#!/usr/bin/env bash
# Local stand-in for the OSS-Fuzz build harness: sets SRC/OUT/WORK the way
# OSS-Fuzz's own build container would, then runs fuzz/oss-fuzz/build.sh
# unmodified against this checkout. Does not touch the workspace cargo
# (fuzz/ has its own [workspace] table — see fuzz/README.md), so it is
# safe to run alongside a workspace `cargo` invocation.
#
# On a machine where `cargo fuzz` on PATH is not the nightly build (this
# repo's own toolchain is stable-pinned via rust-toolchain.toml), set
# CARGO_FUZZ to override the command build.sh runs. `rustup run nightly
# cargo fuzz ...` is not reliable here: on a machine where PATH hardcodes
# a toolchain's own bin/ directory ahead of rustup's proxy shim (as
# fuzz/README.md warns), `rustup run nightly` still resolves the `cargo`
# it execs to that hardcoded stable binary, and the build fails with
# "the option `Z` is only accepted on the nightly compiler". Prepend the
# nightly toolchain's bin/ directly instead:
#   export PATH="$HOME/.rustup/toolchains/nightly-$(rustc -vV | \
#     awk '/^host: /{print $2}')/bin:$PATH"
#   scripts/fuzz/oss-fuzz-local.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

SRC="$(mktemp -d /tmp/qsh-ossfuzz-src.XXXXXX)"
OUT="$(mktemp -d /tmp/qsh-ossfuzz-out.XXXXXX)"
WORK="$(mktemp -d /tmp/qsh-ossfuzz-work.XXXXXX)"
export SRC OUT WORK

cleanup() {
  rm -rf "$SRC" "$WORK"
}
trap cleanup EXIT

echo "SRC=$SRC"
echo "OUT=$OUT"
echo "WORK=$WORK"

# OSS-Fuzz's Dockerfile does `git clone` into $SRC/qsh; stand that up as a
# copy of this checkout instead of cloning, so uncommitted work is
# exercised too (the tree here is legitimately all-uncommitted mid-step
# work, per this session's rules).
QSH_SRC="$SRC/qsh"
mkdir -p "$QSH_SRC"
git -C "$REPO_ROOT" ls-files -z | rsync -0 -a --files-from=- "$REPO_ROOT/" "$QSH_SRC/"
# rsync --files-from only copies tracked files; also bring over anything
# staged-but-uncommitted or newly added that git ls-files already reports
# (ls-files without -o already includes the index, so untracked new
# fuzz/oss-fuzz/*, scripts/fuzz/*, LICENSE-* files need an explicit pass
# since they are not yet tracked).
git -C "$REPO_ROOT" ls-files -z --others --exclude-standard | rsync -0 -a --files-from=- "$REPO_ROOT/" "$QSH_SRC/"

cp "$REPO_ROOT/fuzz/oss-fuzz/build.sh" "$QSH_SRC/"

cd "$QSH_SRC"
CARGO_FUZZ="${CARGO_FUZZ:-cargo fuzz}"
set +e
CARGO_FUZZ="$CARGO_FUZZ" bash -euo pipefail build.sh
rc=$?
set -e

echo
echo "build.sh exit code: $rc"
echo
printf '%-32s %10s\n' "file" "bytes"
printf '%-32s %10s\n' "--------------------------------" "----------"
shopt -s nullglob
out_files=("$OUT"/*)
shopt -u nullglob
if [ "${#out_files[@]}" -eq 0 ]; then
  echo "(OUT is empty)"
else
  for f in "${out_files[@]}"; do
    printf '%-32s %10s\n' "$(basename "$f")" "$(wc -c < "$f" | tr -d ' ')"
  done
fi

# Cross-check $OUT against the two things it's supposed to mirror, so a
# build that silently drops a target (or its seed zip) fails loudly
# instead of looking like a clean run — this is what caught S4's first
# false green (stable toolchain accepted the invocation but produced a
# short/empty $OUT while exiting 0).
if [ "$rc" -eq 0 ]; then
  seed_zip_count=0
  exe_count=0
  for f in "${out_files[@]}"; do
    case "$(basename "$f")" in
      *_seed_corpus.zip) seed_zip_count=$((seed_zip_count + 1)) ;;
      *) exe_count=$((exe_count + 1)) ;;
    esac
  done

  # shellcheck disable=SC2086
  target_count="$(cd "$REPO_ROOT/fuzz" && $CARGO_FUZZ list | /usr/bin/wc -l | tr -d ' ')"
  corpus_dir_count="$(/bin/ls -d "$REPO_ROOT"/fuzz/corpus/*/ 2>/dev/null | /usr/bin/wc -l | tr -d ' ')"

  if [ "$exe_count" -ne "$target_count" ]; then
    echo "oss-fuzz-local.sh: \$OUT has $exe_count executable(s) but" \
      "\$CARGO_FUZZ list reports $target_count target(s) — build dropped" \
      "or added a target" >&2
    rc=1
  fi
  if [ "$seed_zip_count" -ne "$corpus_dir_count" ]; then
    echo "oss-fuzz-local.sh: \$OUT has $seed_zip_count seed corpus zip(s)" \
      "but fuzz/corpus/ has $corpus_dir_count target dir(s) — seed" \
      "packaging is incomplete" >&2
    rc=1
  fi
fi

echo
echo "OUT retained at: $OUT (not cleaned up automatically — rm -rf it" \
  "once you're done inspecting it)"
exit "$rc"
