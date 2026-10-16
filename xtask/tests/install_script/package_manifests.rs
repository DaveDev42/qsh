//! Tests for `scripts/release/render-manifests.sh`, which fills the scoop and
//! winget templates under `packaging/` from a release's `SHA256SUMS`. The
//! script is run against a scratch `SHA256SUMS`; nothing reaches a package
//! manager, a bucket repository or the network.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const TAG: &str = "v0.3.1";
const X64: &str = "qsh-v0.3.1-x86_64-pc-windows-msvc.zip";
const ARM64: &str = "qsh-v0.3.1-aarch64-pc-windows-msvc.zip";
/// Distinct, recognizable digests, so a swapped architecture shows.
const X64_SUM: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ARM64_SUM: &str = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/release/render-manifests.sh")
}

/// A `SHA256SUMS` the way `sha256sum -- *` writes it, with the other assets
/// of a release around the two Windows zips.
fn sums(lines: &[(&str, &str)]) -> String {
    let mut text = String::new();
    for (digest, name) in lines {
        text.push_str(&format!("{digest}  {name}\n"));
    }
    text
}

fn full_sums() -> String {
    sums(&[
        (
            "2222222222222222222222222222222222222222222222222222222222222222",
            "install.ps1",
        ),
        (
            "3333333333333333333333333333333333333333333333333333333333333333",
            "qsh-v0.3.1-aarch64-apple-darwin.tar.gz",
        ),
        (ARM64_SUM, ARM64),
        (X64_SUM, X64),
    ])
}

struct Rendered {
    out: Output,
    dir: TempDir,
}

impl Rendered {
    fn root(&self) -> PathBuf {
        self.dir.path().join("out")
    }
    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.root().join(rel))
            .unwrap_or_else(|e| panic!("{rel}: {e}; stderr: {}", self.stderr()))
    }
    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.out.stderr).into_owned()
    }
}

fn render(tag: &str, sums_text: &str) -> Rendered {
    let dir = tempfile::tempdir().unwrap();
    let sums_path = dir.path().join("SHA256SUMS");
    fs::write(&sums_path, sums_text).unwrap();
    let out = Command::new("/bin/sh")
        .arg(script())
        .arg(tag)
        .arg(&sums_path)
        .arg(dir.path().join("out"))
        .output()
        .unwrap();
    Rendered { out, dir }
}

#[test]
fn scoop_manifest_renders_both_architectures_with_hashes_from_sha256sums() {
    let r = render(TAG, &full_sums());
    assert!(r.out.status.success(), "{}", r.stderr());
    let manifest: serde_json::Value = serde_json::from_str(&r.read("scoop/qsh.json")).unwrap();

    assert_eq!(manifest["version"], "0.3.1");
    assert_eq!(manifest["bin"], "qsh.exe");
    let base = "https://github.com/DaveDev42/qsh/releases/download/v0.3.1";
    let arch = &manifest["architecture"];
    assert_eq!(arch["64bit"]["url"], format!("{base}/{X64}"));
    assert_eq!(arch["64bit"]["hash"], X64_SUM);
    assert_eq!(arch["arm64"]["url"], format!("{base}/{ARM64}"));
    assert_eq!(arch["arm64"]["hash"], ARM64_SUM);
    assert_eq!(
        arch.as_object().unwrap().len(),
        2,
        "only the two Windows architectures"
    );

    // Scoop spells several licenses with a pipe, not an SPDX `OR`.
    assert_eq!(manifest["license"], "MIT|Apache-2.0");

    // Scoop's own bumping: checkver follows the GitHub releases, and the
    // autoupdate block names both zips and reads digests from SHA256SUMS.
    assert_eq!(
        manifest["checkver"]["github"],
        "https://github.com/DaveDev42/qsh"
    );
    let auto = &manifest["autoupdate"];
    assert_eq!(
        auto["architecture"]["64bit"]["url"],
        "https://github.com/DaveDev42/qsh/releases/download/v$version/qsh-v$version-x86_64-pc-windows-msvc.zip"
    );
    assert_eq!(
        auto["architecture"]["arm64"]["url"],
        "https://github.com/DaveDev42/qsh/releases/download/v$version/qsh-v$version-aarch64-pc-windows-msvc.zip"
    );
    assert_eq!(
        auto["hash"]["url"],
        "https://github.com/DaveDev42/qsh/releases/download/v$version/SHA256SUMS"
    );
    assert!(
        auto["hash"]["regex"].as_str().unwrap().contains("$sha256"),
        "the hash regex must capture the digest"
    );

    // No man pages: scoop has no man path convention.
    let text = r.read("scoop/qsh.json");
    assert!(
        !text.contains("man/") && !text.contains("\"man\""),
        "{text}"
    );
    assert!(!text.contains('@'), "unfilled placeholder: {text}");
}

#[test]
fn winget_manifest_renders_a_portable_zip_installer() {
    // A prerelease tag names different assets; same digests.
    let r = render(
        "v0.3.1-rc.2",
        &full_sums().replace("v0.3.1-", "v0.3.1-rc.2-"),
    );
    assert!(r.out.status.success(), "{}", r.stderr());

    let version = r.read("winget/DaveDev42.qsh.yaml");
    let installer = r.read("winget/DaveDev42.qsh.installer.yaml");
    let locale = r.read("winget/DaveDev42.qsh.locale.en-US.yaml");

    for (name, text, kind) in [
        ("version", &version, "version"),
        ("installer", &installer, "installer"),
        ("locale", &locale, "defaultLocale"),
    ] {
        assert!(
            text.contains("PackageIdentifier: DaveDev42.qsh\n"),
            "{name}: {text}"
        );
        assert!(
            text.contains("PackageVersion: 0.3.1-rc.2\n"),
            "{name}: {text}"
        );
        assert!(
            text.contains(&format!("ManifestType: {kind}\n")),
            "{name}: {text}"
        );
        assert!(!text.contains('@'), "{name}: unfilled placeholder: {text}");
    }
    assert!(locale.contains("PackageLocale: en-US\n"));
    assert!(version.contains("DefaultLocale: en-US\n"));

    // Portable inside a zip, with the executable at the zip root and a
    // `qsh` command alias; nothing about man pages.
    assert!(installer.contains("\nInstallerType: zip\n"), "{installer}");
    assert!(installer.contains("\nNestedInstallerType: portable\n"));
    assert!(installer.contains("- RelativeFilePath: qsh.exe\n  PortableCommandAlias: qsh\n"));
    assert!(!installer.contains("man/") && !installer.contains(".1\n"));

    // Both architectures, URLs on the tagged release, digests from SHA256SUMS
    // (winget spells them in upper case).
    let base = "https://github.com/DaveDev42/qsh/releases/download/v0.3.1-rc.2";
    assert_eq!(installer.matches("- Architecture:").count(), 2);
    let x64 = format!(
        "- Architecture: x64\n  InstallerUrl: {base}/qsh-v0.3.1-rc.2-x86_64-pc-windows-msvc.zip\n  InstallerSha256: {}\n",
        X64_SUM.to_uppercase()
    );
    let arm64 = format!(
        "- Architecture: arm64\n  InstallerUrl: {base}/qsh-v0.3.1-rc.2-aarch64-pc-windows-msvc.zip\n  InstallerSha256: {}\n",
        ARM64_SUM.to_uppercase()
    );
    assert!(installer.contains(&x64), "{installer}");
    assert!(installer.contains(&arm64), "{installer}");
}

/// A release missing a Windows zip, or a damaged digest, must not render a
/// manifest with a blank or stale hash, and must leave the target alone.
#[test]
fn render_manifests_refuses_incomplete_or_malformed_checksums() {
    let missing_arm = sums(&[(X64_SUM, X64)]);
    let short = sums(&[(X64_SUM, X64), (&ARM64_SUM[..63], ARM64)]);
    let not_hex = sums(&[(X64_SUM, X64), (&format!("{}Z", &ARM64_SUM[..63]), ARM64)]);
    for (label, text) in [
        ("missing arm64", missing_arm),
        ("short digest", short),
        ("non-hex digest", not_hex),
    ] {
        let r = render(TAG, &text);
        assert!(!r.out.status.success(), "{label}: rendered anyway");
        assert!(
            !r.root().exists(),
            "{label}: left files behind: {}",
            r.stderr()
        );
    }
    for tag in ["0.3.1", "latest", "v1.0.0; rm -rf /", "v1"] {
        let r = render(tag, &full_sums());
        assert!(!r.out.status.success(), "{tag}: accepted");
    }
}
