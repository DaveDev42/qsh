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
#   QSH_LIBC         Linux only: "gnu" (default) or "musl". The musl asset is
#                     a static binary for distributions whose glibc is older
#                     than the gnu build needs. Opt-in, never auto-detected:
#                     a glibc system runs the musl binary fine, so guessing
#                     would quietly move people off the tested artifact.
#                     x86_64 and aarch64. A tag cut before the aarch64 musl
#                     leg existed has no such asset; on aarch64 the installer
#                     checks that tag's SHA256SUMS first and says so.
#
#   QSH_INSECURE_SKIP_VERIFY
#                    Set to exactly "1" to skip BOTH the SHA256SUMS check and
#                     the provenance check. It prints a warning and is the
#                     only way past either check. Nothing then vouches that
#                     the archive is the one the release published.
#
#   QSH_MAN_DIR     Directory the man pages from the archive's `man/` go
#                     into. Defaults to "${XDG_DATA_HOME:-$HOME/.local/share}/
#                     man/man1". Created if missing.
#   QSH_NO_MAN       Set to exactly "1" to skip the man pages.
#
# Man pages are best effort: a problem with them prints a warning and never
# undoes the binary install. Archives cut before the pages shipped have no
# `man/` and are installed without a word about it.
#
# This script never invokes sudo. If QSH_INSTALL_DIR is not writable, it
# fails with a message rather than escalating privileges on your behalf.
#
# What the checks do and do not prove. SHA256SUMS is fetched from the same
# release as the archive, so it catches a truncated or corrupted download,
# not a compromised release. It is an integrity check, not a signature.
# Provenance is the stronger claim: when the GitHub CLI is installed and
# logged in, the installer runs `gh attestation verify` on the archive,
# which shows the file was produced by this repository's release.yml run
# from a named commit. It does not show that the commit is correct or safe
# to run. The installer fails closed on provenance: a failed verification
# installs nothing. Without a usable GitHub CLI (missing, or not logged in)
# it cannot verify, says "provenance not verified" on stderr, and installs
# on the checksum alone. Whether the macOS binaries are Developer ID signed
# and notarized depends on whether the release was cut with Apple
# credentials configured (docs/deploy/release-secrets.md); this installer
# does not check either way.
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

warn() {
    log "warning: $*"
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
            case "${QSH_LIBC:-gnu}" in
                gnu) libc="gnu" ;;
                musl) libc="musl" ;;
                *) die "QSH_LIBC must be 'gnu' or 'musl'" ;;
            esac
            case "$arch" in
                x86_64 | amd64) echo "x86_64-unknown-linux-${libc}" ;;
                aarch64 | arm64) echo "aarch64-unknown-linux-${libc}" ;;
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

# Resolves the tag of the latest release, since the archive filename
# embeds the tag. First choice is the redirect that /releases/latest
# issues — no rate limit, but GitHub excludes prereleases from it, so
# while only prereleases exist it points at the releases index instead of
# a tag. When the redirect does not land on /releases/tag/<tag>, fall
# back to the API and take the newest release of any kind, prereleases
# included. Anything still ambiguous is "no tag found", never a guess.
resolve_latest_tag() {
    redirect="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/${QSH_REPO}/releases/latest")" || redirect=""

    case "$redirect" in
        */releases/tag/?*)
            echo "${redirect##*/}"
            return 0
            ;;
    esac

    tag="$(curl -fsSL "https://api.github.com/repos/${QSH_REPO}/releases?per_page=1" |
        awk -F'"' '/"tag_name":/ { print $4; exit }')" || tag=""
    [ -n "$tag" ] ||
        die "could not resolve the latest release of ${QSH_REPO} (no release \
published yet, or the GitHub API was unreachable or rate limited). Set \
QSH_VERSION to pick a tag explicitly."
    echo "$tag"
}

# Checks the archive's build provenance with the GitHub CLI. Fail closed when
# `gh` can run the check and the check fails; degrade to a warning only when
# `gh` cannot run it at all (not installed, or not logged in).
verify_provenance() {
    [ -z "$skip_verify" ] || return 0

    if ! command -v gh >/dev/null 2>&1; then
        log "warning: provenance not verified: 'gh' (GitHub CLI) is not installed. \
Installing on the SHA256SUMS check alone. To verify, install gh, run \
'gh auth login', and re-run this script."
        return 0
    fi
    if ! gh auth status >/dev/null 2>&1; then
        log "warning: provenance not verified: 'gh' is not logged in. \
Installing on the SHA256SUMS check alone. To verify, run 'gh auth login' \
and re-run this script."
        return 0
    fi

    log "verifying provenance"
    gh attestation verify "$1" --repo "$QSH_REPO" >&2 ||
        die "provenance verification failed for $(basename "$1") — refusing to install"
}

# Installs the archive's `man/<name>.1` pages. Only members shaped exactly
# like that are extracted, and they are extracted by name; anything else
# (nested paths, other extensions, names outside `man/`) is reported and left
# in the archive. A member that comes out as anything but a regular file,
# which is what a symlink member does, is skipped. Each page is copied to a
# temporary name in the destination and renamed into place, like the binary.
# Returns non-zero when the pages as a whole could not be installed; the
# caller turns that into a warning and keeps the binary.
install_man_pages() {
    archive="$1"
    if [ -n "${QSH_MAN_DIR:-}" ]; then
        man_dir="$QSH_MAN_DIR"
    elif [ -n "${XDG_DATA_HOME:-}" ]; then
        man_dir="${XDG_DATA_HOME}/man/man1"
    elif [ -n "${HOME:-}" ]; then
        man_dir="${HOME}/.local/share/man/man1"
    else
        warn "neither QSH_MAN_DIR nor HOME is set; set QSH_MAN_DIR to install man pages"
        return 1
    fi

    members="$(tar tzf "$archive" 2>/dev/null)" || {
        warn "could not list the archive to look for man pages"
        return 1
    }
    page_re='^man/[A-Za-z0-9][A-Za-z0-9._-]*\.1$'
    pages="$(printf '%s\n' "$members" | awk -v re="$page_re" '$0 ~ re')"
    odd="$(printf '%s\n' "$members" |
        awk -v re="$page_re" '$0 != "" && $0 != "qsh" && $0 != "man/" && $0 !~ re')"

    if [ -n "$odd" ]; then
        printf '%s\n' "$odd" | while IFS= read -r member; do
            warn "not installing archive member '${member}': not a man/<name>.1 page"
        done
    fi
    # An archive from before the pages shipped: nothing to do, nothing to say.
    [ -n "$pages" ] || return 0

    set --
    for member in $pages; do
        set -- "$@" "$member"
    done
    tar xzf "$archive" -C "$workdir" "$@" || {
        warn "could not extract the man pages from the archive"
        return 1
    }

    if [ -e "$man_dir" ] && [ ! -d "$man_dir" ]; then
        warn "${man_dir} exists and is not a directory"
        return 1
    fi
    mkdir -p "$man_dir" || {
        warn "failed to create ${man_dir}"
        return 1
    }
    if [ ! -w "$man_dir" ]; then
        warn "${man_dir} is not writable; set QSH_MAN_DIR to a writable directory"
        return 1
    fi

    count=0
    for member in $pages; do
        name="${member#man/}"
        src="${workdir}/${member}"
        if [ -L "$src" ] || [ ! -f "$src" ]; then
            warn "not installing ${member}: it is not a regular file in the archive"
            continue
        fi
        if [ -d "${man_dir}/${name}" ]; then
            warn "not installing ${name}: ${man_dir}/${name} is a directory"
            continue
        fi
        man_staged="${man_dir}/.${name}.install.$$"
        if cp "$src" "$man_staged" && chmod 0644 "$man_staged" &&
            mv -f "$man_staged" "${man_dir}/${name}"; then
            count=$((count + 1))
        else
            warn "failed to install ${name} into ${man_dir}"
            rm -f "$man_staged"
        fi
        man_staged=""
    done
    log "installed ${count} man page(s) to ${man_dir}"

    # Whether `man` finds them depends on the platform: man-db maps
    # ~/.local/bin to ~/.local/share/man on its own, macOS does not. Ask
    # `manpath` when there is one; without it, say how to add the directory.
    man_root="$(dirname "$man_dir")"
    case ":$(manpath 2>/dev/null):" in
        *":${man_root}:"*) ;;
        *)
            log ""
            log "note: ${man_root} may not be on your MANPATH. Add it, e.g.:"
            log "  export MANPATH=\"${man_root}:\${MANPATH:-}\""
            ;;
    esac
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
    man_staged=""
    trap 'rm -rf "$workdir"; if [ -n "$staged" ]; then rm -f "$staged"; fi; if [ -n "$man_staged" ]; then rm -f "$man_staged"; fi' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    skip_verify=""
    if [ "${QSH_INSECURE_SKIP_VERIFY:-}" = "1" ]; then
        skip_verify=1
        log "warning: QSH_INSECURE_SKIP_VERIFY=1 is set: skipping BOTH the \
SHA256SUMS check and the provenance check. Nothing vouches that this archive \
is the one ${QSH_REPO} published."
    fi

    sums_fetched=""
    if [ "$target" = "aarch64-unknown-linux-musl" ]; then
        # Tags cut before the aarch64 musl leg existed carry no such asset.
        # This branch alone reads SHA256SUMS before the archive so that case
        # ends with a message that names the fix instead of a bare 404. Every
        # other target keeps the archive-first order below.
        log "downloading ${sums_url}"
        curl -fsSL -o "${workdir}/SHA256SUMS" "$sums_url" ||
            die "failed to download SHA256SUMS from ${sums_url}"
        sums_fetched=1
        awk -v f="$asset" '$2 == f { found = 1 } END { exit !found }' \
            "${workdir}/SHA256SUMS" ||
            die "no aarch64 musl asset is published for ${version}; unset \
QSH_LIBC to install the glibc build"
    fi

    log "downloading ${archive_url}"
    curl -fsSL -o "${workdir}/${asset}" "$archive_url" ||
        die "failed to download ${archive_url} (does that version/target exist?)"

    if [ -z "$sums_fetched" ] && [ -z "$skip_verify" ]; then
        log "downloading ${sums_url}"
        curl -fsSL -o "${workdir}/SHA256SUMS" "$sums_url" ||
            die "failed to download SHA256SUMS from ${sums_url}"
    fi

    if [ -z "$skip_verify" ]; then
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
    fi

    verify_provenance "${workdir}/${asset}"

    # Extract the `qsh` member by name -- the archive also carries the man
    # pages under `man/`, which install_man_pages extracts the same way --
    # so a surprise path in the tarball cannot write outside the scratch dir.
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
    # download-then-run detour can. Clearing it is best effort; whether the
    # binary is signed and notarized depends on how the release was cut
    # (docs/deploy/release-secrets.md), and this script does not check, so
    # macOS may still object.
    if [ "$(uname -s)" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
        xattr -d com.apple.quarantine "${QSH_INSTALL_DIR}/qsh" 2>/dev/null || true
    fi

    log "installed qsh ${version} to ${QSH_INSTALL_DIR}/qsh"

    if [ "${QSH_NO_MAN:-}" != "1" ]; then
        install_man_pages "${workdir}/${asset}" ||
            warn "man pages were not installed; the qsh binary is installed regardless"
    fi

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
