//! Tests for `scripts/release/secret-gate.sh`, the all-or-none gate the
//! macOS and Windows legs of `release.yml` share. The script is run with fake
//! flags and a scratch `GITHUB_OUTPUT`; it never sees a secret value.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const RELEASE_YML: &str = include_str!("../../../.github/workflows/release.yml");

fn gate_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/release/secret-gate.sh")
}

/// The arguments the workflow passes for one platform: output key, label,
/// what runs when every secret is set, what is skipped otherwise, and the
/// warning a tag push gets when none is set.
struct Platform {
    output: &'static str,
    label: &'static str,
    doing: &'static str,
    skipping: &'static str,
    unsigned: &'static str,
    secrets: usize,
}

const APPLE: Platform = Platform {
    output: "has-apple",
    label: "Apple",
    doing: "signing and notarizing",
    skipping: "codesign and notarization",
    unsigned: "No Apple signing secrets are configured; this tag ships an ad-hoc signed macOS binary that Gatekeeper rejects on a quarantined download.",
    secrets: 6,
};

const WINDOWS: Platform = Platform {
    output: "has-windows",
    label: "Windows",
    doing: "signing",
    skipping: "Authenticode signing",
    unsigned: "No Windows signing secrets are configured; this tag ships unsigned Windows binaries that SmartScreen flags on a downloaded copy.",
    secrets: 4,
};

/// The scratch platforms above must be the arguments `release.yml` really
/// passes, or the three outcomes are pinned against text nobody ships.
#[test]
fn secret_gate_platforms_match_the_arguments_release_yml_passes() {
    for platform in [&APPLE, &WINDOWS] {
        let call = format!(
            "bash scripts/release/secret-gate.sh {} {} \\\n            \"{}\" \\\n            \"{}\" \\\n            \"{}\" \\\n",
            platform.output, platform.label, platform.doing, platform.skipping, platform.unsigned
        );
        assert!(
            RELEASE_YML.contains(&call),
            "release.yml does not call the gate with the {} arguments:\n{call}",
            platform.label
        );
        let flags = RELEASE_YML
            .split(&call)
            .nth(1)
            .and_then(|rest| rest.split("\n\n").next())
            .unwrap_or_default();
        assert_eq!(
            flags.matches("\"$HAS_").count(),
            platform.secrets,
            "{}: flag count in release.yml: {flags}",
            platform.label
        );
    }
}

struct Run {
    out: Output,
    /// What the script appended to `$GITHUB_OUTPUT`.
    github_output: String,
    stdout: String,
}

/// Runs the gate with the first `set` of the platform's secrets present.
fn gate(platform: &Platform, set: usize, is_tag: bool) -> Run {
    let dir: TempDir = tempfile::tempdir().unwrap();
    let github_output = dir.path().join("github_output");
    fs::write(&github_output, "").unwrap();
    let flags: Vec<&str> = (0..platform.secrets)
        .map(|i| if i < set { "true" } else { "false" })
        .collect();
    let out = Command::new("/bin/sh")
        .arg(gate_script())
        .args([
            platform.output,
            platform.label,
            platform.doing,
            platform.skipping,
            platform.unsigned,
        ])
        .args(&flags)
        .env_clear()
        .env("GITHUB_OUTPUT", &github_output)
        .env("IS_TAG", if is_tag { "true" } else { "false" })
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    Run {
        out,
        github_output: fs::read_to_string(&github_output).unwrap(),
        stdout,
    }
}

fn annotations(run: &Run) -> Vec<&str> {
    run.stdout
        .lines()
        .filter(|l| l.starts_with("::"))
        .collect::<Vec<_>>()
}

#[test]
fn secret_gate_signs_when_all_secrets_are_present() {
    for platform in [&APPLE, &WINDOWS] {
        for is_tag in [true, false] {
            let run = gate(platform, platform.secrets, is_tag);
            assert!(
                run.out.status.success(),
                "{}: {}",
                platform.label,
                run.stdout
            );
            assert_eq!(
                run.github_output,
                format!("{}=true\n", platform.output),
                "{} tag={is_tag}",
                platform.label
            );
            assert!(
                run.stdout.contains(&format!(
                    "All {} {} signing secrets are set; {}.",
                    platform.secrets, platform.label, platform.doing
                )),
                "{}: {}",
                platform.label,
                run.stdout
            );
            assert!(
                annotations(&run).is_empty(),
                "a full set must not warn or fail: {}",
                run.stdout
            );
        }
    }
}

#[test]
fn secret_gate_skips_with_a_warning_when_none_are_present() {
    for platform in [&APPLE, &WINDOWS] {
        // A tag push stays green but says loudly that the release is unsigned.
        let tag = gate(platform, 0, true);
        assert!(
            tag.out.status.success(),
            "{}: {}",
            platform.label,
            tag.stdout
        );
        assert_eq!(tag.github_output, format!("{}=false\n", platform.output));
        assert_eq!(
            annotations(&tag),
            vec![format!(
                "::warning title=Unsigned release::{}",
                platform.unsigned
            )],
            "{}",
            platform.label
        );

        // A branch dispatch just notes the skip: no annotation to read past.
        let branch = gate(platform, 0, false);
        assert!(branch.out.status.success(), "{}", branch.stdout);
        assert_eq!(branch.github_output, format!("{}=false\n", platform.output));
        assert!(annotations(&branch).is_empty(), "{}", branch.stdout);
        assert!(
            branch.stdout.contains(&format!(
                "No {} signing secrets are configured; skipping {}.",
                platform.label, platform.skipping
            )),
            "{}",
            branch.stdout
        );
    }
}

#[test]
fn secret_gate_fails_a_tag_push_when_some_are_present() {
    for platform in [&APPLE, &WINDOWS] {
        for set in 1..platform.secrets {
            // On a tag the artifacts ship, so a half-configured set is an error.
            let tag = gate(platform, set, true);
            assert_eq!(
                tag.out.status.code(),
                Some(1),
                "{} with {set} secrets on a tag must fail: {}",
                platform.label,
                tag.stdout
            );
            assert_eq!(tag.github_output, format!("{}=false\n", platform.output));
            let notes = annotations(&tag);
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert!(
                notes[0].starts_with(&format!(
                    "::error title=Partial {} signing config::",
                    platform.label
                )) && notes[0].contains(&format!(
                    "{set} of {} secrets are set. Set all {} or none.",
                    platform.secrets, platform.secrets
                )),
                "{}",
                notes[0]
            );

            // On a branch dispatch the artifacts are thrown away: warn and skip.
            let branch = gate(platform, set, false);
            assert!(branch.out.status.success(), "{}", branch.stdout);
            assert_eq!(branch.github_output, format!("{}=false\n", platform.output));
            let notes = annotations(&branch);
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert!(
                notes[0].starts_with(&format!(
                    "::warning title=Partial {} signing config::",
                    platform.label
                )) && notes[0].ends_with(&format!("Skipping {}.", platform.skipping)),
                "{}",
                notes[0]
            );
        }
    }
}
