#!/bin/sh
# Renders the Windows package-manager manifests for one release tag from the
# templates under packaging/, using the digests in that release's SHA256SUMS.
# Shared by the `scoop-bucket` and `winget` jobs of
# .github/workflows/release.yml and by the maintainer who submits the first
# winget manifest by hand, so the job and the hand submission cannot differ.
#
# Usage:
#   render-manifests.sh <tag> <SHA256SUMS> <out-dir>
#
#   tag          Release tag, "v" plus semver (v0.1.0, v0.2.0-rc.1).
#   SHA256SUMS   The release's checksum file ("<hex>  <asset>" lines).
#   out-dir      Created if missing. Gets scoop/qsh.json and
#                winget/DaveDev42.qsh{,.installer,.locale.en-US}.yaml.
#
# Both Windows zips must have a digest line, and the digest must be 64 hex
# digits; anything else is an error and nothing is left in out-dir. The
# manifests never list the man pages: scoop and winget portable have no man
# path convention, and the same text is `qsh help`.
#
# Tests: `package_manifests::` in xtask/tests/install_script.rs.

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: render-manifests.sh <tag> <SHA256SUMS> <out-dir>" >&2
    exit 2
fi

tag="$1"
sums="$2"
out="$3"

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
root="$here/../.."

case "$tag" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "render-manifests: '$tag' is not a release tag (expected v<major>.<minor>.<patch>[-pre])" >&2
        exit 1
        ;;
esac
# Only characters a semver tag has; the tag is spliced into sed commands.
case "$tag" in
    *[!0-9A-Za-z.+-]*)
        echo "render-manifests: '$tag' has characters outside [0-9A-Za-z.+-]" >&2
        exit 1
        ;;
esac
version="${tag#v}"

if [ ! -f "$sums" ]; then
    echo "render-manifests: $sums is not a file" >&2
    exit 1
fi

# The digest SHA256SUMS lists for one asset, lowercase; fails when the asset
# has no line or the digest is not 64 hex digits.
digest_of() {
    asset="$1"
    sum="$(awk -v f="$asset" '$2 == f { print $1; exit }' "$sums" | tr 'A-F' 'a-f')"
    if [ -z "$sum" ]; then
        echo "render-manifests: $sums has no line for $asset" >&2
        return 1
    fi
    case "$sum" in
        *[!0-9a-f]*)
            echo "render-manifests: digest for $asset is not hex" >&2
            return 1
            ;;
    esac
    if [ "${#sum}" -ne 64 ]; then
        echo "render-manifests: digest for $asset is not 64 hex digits" >&2
        return 1
    fi
    printf '%s\n' "$sum"
}

x64="$(digest_of "qsh-${tag}-x86_64-pc-windows-msvc.zip")"
arm64="$(digest_of "qsh-${tag}-aarch64-pc-windows-msvc.zip")"
x64_upper="$(printf '%s' "$x64" | tr 'a-f' 'A-F')"
arm64_upper="$(printf '%s' "$arm64" | tr 'a-f' 'A-F')"

# Render into a scratch directory and move it into place last, so a failure
# midway leaves out-dir exactly as it was.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/scoop" "$scratch/winget"

render() {
    sed \
        -e "s|@TAG@|${tag}|g" \
        -e "s|@VERSION@|${version}|g" \
        -e "s|@SHA256_X64_UPPER@|${x64_upper}|g" \
        -e "s|@SHA256_ARM64_UPPER@|${arm64_upper}|g" \
        -e "s|@SHA256_X64@|${x64}|g" \
        -e "s|@SHA256_ARM64@|${arm64}|g" \
        "$1" > "$2"
    if grep -q '@[A-Z0-9_]*@' "$2"; then
        echo "render-manifests: unfilled placeholder in $2" >&2
        return 1
    fi
}

render "$root/packaging/scoop/qsh.json.in" "$scratch/scoop/qsh.json"
for t in "$root"/packaging/winget/*.yaml.in; do
    name="$(basename "$t" .in)"
    render "$t" "$scratch/winget/$name"
done

mkdir -p "$out/scoop" "$out/winget"
cp "$scratch/scoop/qsh.json" "$out/scoop/qsh.json"
cp "$scratch/winget/"*.yaml "$out/winget/"
echo "Rendered scoop and winget manifests for ${tag} into ${out}."
