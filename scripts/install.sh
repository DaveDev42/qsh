#!/bin/sh
# QSH installer — downloads a prebuilt release archive, verifies it against
# the release's SHA256SUMS, and installs the `qsh` binary. No Rust toolchain
# required.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh
#
# Env vars:
#   QSH_VERSION      Release tag to install, e.g. "v0.1.0-alpha.1".
#                     Defaults to the latest release.
#   QSH_INSTALL_DIR  Directory to install the `qsh` binary into.
#                     Defaults to "$HOME/.local/bin". Created if missing.
#   QSH_REPO         "owner/repo" to install from. Defaults to
#                     "DaveDev42/qsh". Mainly for forks/testing.
#
# This script never invokes sudo. If QSH_INSTALL_DIR is not writable, it
# fails with a message rather than escalating privileges on your behalf.
#
# What the checksum does and does not prove: SHA256SUMS is fetched from the
# same release as the archive, so it catches a truncated or corrupted
# download, not a compromised release. It is an integrity check, not a
# signature. Signed and notarized artifacts are M9.
#
# Archive naming is a contract with .github/workflows/release.yml:
# qsh-<tag>-<target>.tar.gz (.zip on Windows), with a SHA256SUMS file
# covering all archives in the release. Keep the two in sync if either
# changes.

set -eu

QSH_REPO="${QSH_REPO:-DaveDev42/qsh}"

log() {
    printf '%s\n' "$*" >&2
}

die() {
    log "install.sh: error: $*"
    exit 1
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        die "required command '$1' not found on PATH"
    fi
}

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Darwin)
            case "$arch" in
                arm64) echo "aarch64-apple-darwin" ;;
                x86_64) echo "x86_64-apple-darwin" ;;
                *) die "unsupported macOS architecture: $arch" ;;
            esac
            ;;
        Linux)
            case "$arch" in
                x86_64 | amd64) echo "x86_64-unknown-linux-gnu" ;;
                aarch64 | arm64) echo "aarch64-unknown-linux-gnu" ;;
                *) die "unsupported Linux architecture: $arch" ;;
            esac
            ;;
        MINGW* | MSYS* | CYGWIN*)
            die "Windows detected via a POSIX shell. This installer targets macOS/Linux. \
Download qsh-<version>-x86_64-pc-windows-msvc.zip manually from \
https://github.com/${QSH_REPO}/releases and unzip it."
            ;;
        *)
            die "unsupported OS: $os"
            ;;
    esac
}

# Resolves the tag of the latest release by following the redirect that
# /releases/latest issues, since the archive filename embeds the tag. The
# redirect must land on a /releases/tag/<tag> URL; anything else (a repo
# with no releases redirecting to the releases index, an interstitial) is
# treated as "no tag found" rather than guessed at.
resolve_latest_tag() {
    redirect="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/${QSH_REPO}/releases/latest")" ||
        die "failed to reach https://github.com/${QSH_REPO}/releases/latest \
(network error, or no release has been published yet). Set QSH_VERSION to \
pick a tag explicitly."

    case "$redirect" in
        */releases/tag/?*) ;;
        *) die "https://github.com/${QSH_REPO}/releases/latest did not resolve \
to a release tag (got: ${redirect}). Set QSH_VERSION to pick a tag explicitly." ;;
    esac

    echo "${redirect##*/}"
}

main() {
    need_cmd uname
    need_cmd curl
    need_cmd tar
    need_cmd mktemp
    need_cmd awk

    if [ -z "${QSH_INSTALL_DIR:-}" ]; then
        [ -n "${HOME:-}" ] ||
            die "neither QSH_INSTALL_DIR nor HOME is set; set QSH_INSTALL_DIR \
to the directory the binary should go in"
        QSH_INSTALL_DIR="$HOME/.local/bin"
    fi

    # sha256sum (GNU/most Linux) or shasum -a 256 (macOS) — pick whichever exists.
    if command -v sha256sum >/dev/null 2>&1; then
        sha256_cmd="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        sha256_cmd="shasum -a 256"
    else
        die "need either 'sha256sum' or 'shasum' on PATH to verify downloads"
    fi

    target="$(detect_target)" || exit 1
    log "detected target: $target"

    if [ -n "${QSH_VERSION:-}" ]; then
        version="$QSH_VERSION"
    else
        log "QSH_VERSION not set, resolving latest release..."
        version="$(resolve_latest_tag)" || exit 1
    fi
    [ -n "$version" ] || die "could not determine which release tag to install"
    base_url="https://github.com/${QSH_REPO}/releases/download/${version}"
    log "installing version: $version"

    asset="qsh-${version}-${target}.tar.gz"
    archive_url="${base_url}/${asset}"
    sums_url="${base_url}/SHA256SUMS"

    workdir="$(mktemp -d)" || die "failed to create temp directory"
    staged=""
    # Cleans the scratch directory and, if the install got as far as writing
    # a temp file into the destination directory, that too — so an
    # interrupted run leaves nothing behind and never a half-written binary
    # at the final path.
    trap 'rm -rf "$workdir"; if [ -n "$staged" ]; then rm -f "$staged"; fi' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    log "downloading ${archive_url}"
    curl -fsSL -o "${workdir}/${asset}" "$archive_url" ||
        die "failed to download ${archive_url} (does that version/target exist?)"

    log "downloading ${sums_url}"
    curl -fsSL -o "${workdir}/SHA256SUMS" "$sums_url" ||
        die "failed to download SHA256SUMS from ${sums_url}"

    # Fail closed: no entry, more than one entry, or anything that is not a
    # single 64-char hex digest aborts before the archive is unpacked. The
    # filename is matched as a whole field rather than as a regex, so the
    # dots in the asset name cannot match some other archive's line.
    log "verifying checksum"
    want="$(awk -v f="$asset" '$2 == f { print $1 }' "${workdir}/SHA256SUMS")" ||
        die "failed to read SHA256SUMS"
    case "$want" in
        "") die "SHA256SUMS has no entry for ${asset} — refusing to install" ;;
        *[!0-9a-fA-F]*) die "SHA256SUMS entry for ${asset} is not a single hex digest — refusing to install" ;;
    esac
    [ "${#want}" -eq 64 ] ||
        die "SHA256SUMS entry for ${asset} is ${#want} chars, expected 64 — refusing to install"

    got="$($sha256_cmd "${workdir}/${asset}" | awk '{ print $1 }')" ||
        die "failed to hash ${asset}"
    [ "$want" = "$got" ] ||
        die "checksum mismatch for ${asset}: expected ${want}, got ${got} — refusing to install"

    # Extract the one member the archive is supposed to hold, by name, so a
    # surprise path in the tarball cannot write outside the scratch dir.
    log "unpacking"
    tar xzf "${workdir}/${asset}" -C "$workdir" qsh ||
        die "${asset} did not contain a 'qsh' binary at the archive root"
    [ ! -L "${workdir}/qsh" ] || die "the 'qsh' entry in ${asset} is a symlink, not a binary"
    [ -f "${workdir}/qsh" ] || die "archive did not contain a 'qsh' binary"

    if [ -e "$QSH_INSTALL_DIR" ] && [ ! -d "$QSH_INSTALL_DIR" ]; then
        die "${QSH_INSTALL_DIR} exists and is not a directory"
    fi
    mkdir -p "$QSH_INSTALL_DIR" || die "failed to create ${QSH_INSTALL_DIR}"
    if [ ! -w "$QSH_INSTALL_DIR" ]; then
        die "${QSH_INSTALL_DIR} is not writable. Set QSH_INSTALL_DIR to a \
writable directory, or fix its permissions yourself — this installer never uses sudo."
    fi
    if [ -d "${QSH_INSTALL_DIR}/qsh" ]; then
        die "${QSH_INSTALL_DIR}/qsh is a directory; move it out of the way first"
    fi

    # Copy to a temp name inside the destination directory, then rename it
    # into place. The rename is atomic on the same filesystem, so a failure
    # mid-copy never leaves a partial binary at the final path, and a `qsh`
    # that is currently running keeps its own inode.
    staged="${QSH_INSTALL_DIR}/.qsh.install.$$"
    cp "${workdir}/qsh" "$staged" || die "failed to copy the binary into ${QSH_INSTALL_DIR}"
    chmod 0755 "$staged" || die "failed to make ${staged} executable"
    mv -f "$staged" "${QSH_INSTALL_DIR}/qsh" ||
        die "failed to move the binary into place at ${QSH_INSTALL_DIR}/qsh"
    staged=""

    # curl does not set com.apple.quarantine, but a proxy or a
    # download-then-run detour can. Clearing it is best effort; the binary
    # is not signed or notarized until M9, so macOS may still object.
    if [ "$(uname -s)" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
        xattr -d com.apple.quarantine "${QSH_INSTALL_DIR}/qsh" 2>/dev/null || true
    fi

    log "installed qsh ${version} to ${QSH_INSTALL_DIR}/qsh"

    case ":$PATH:" in
        *":${QSH_INSTALL_DIR}:"*) ;;
        *)
            log ""
            log "note: ${QSH_INSTALL_DIR} is not on your PATH. Add it, e.g.:"
            log "  export PATH=\"${QSH_INSTALL_DIR}:\$PATH\""
            ;;
    esac
}

main "$@"
