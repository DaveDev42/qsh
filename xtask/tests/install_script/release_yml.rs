//! Structural checks of `.github/workflows/release.yml` against the scripts
//! it calls. A workflow only runs on a tag or a dispatch, so these are the
//! cheap guard that a rename or a dropped step is caught by the PR gate.

const RELEASE_YML: &str = include_str!("../../../.github/workflows/release.yml");

fn index_of(needle: &str) -> usize {
    RELEASE_YML
        .find(needle)
        .unwrap_or_else(|| panic!("release.yml has no `{needle}`"))
}

#[test]
fn release_yml_gates_apple_signing_through_the_shared_script() {
    assert_eq!(
        RELEASE_YML
            .matches("bash scripts/release/secret-gate.sh")
            .count(),
        1,
        "the Apple gate must call the shared script"
    );
    assert!(
        !RELEASE_YML.contains("present=$((present + 1))"),
        "an inline copy of the gate logic is back in release.yml"
    );
    let apple = index_of("name: Check for Apple signing secrets");
    let toolchain = index_of("actions-rust-lang/setup-rust-toolchain");
    assert!(
        apple < toolchain,
        "a misconfiguration must fail before the release compile"
    );
}

/// The published asset set lives in the build matrix and in two completeness
/// checks (the release job and the dispatch dry run). All three must name
/// both Windows targets, and both checks must require the installer.
#[test]
fn release_yml_lists_both_windows_targets_everywhere_assets_are_listed() {
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        assert!(
            RELEASE_YML.contains(&format!("target: {target}")),
            "{target} is missing from the build matrix"
        );
    }
    let lists: Vec<&str> = RELEASE_YML
        .match_indices("for target in \\")
        .map(|(i, _)| {
            let rest = &RELEASE_YML[i..];
            &rest[..rest.find("; do").unwrap()]
        })
        .collect();
    assert_eq!(lists.len(), 2, "expected the release and dry-run lists");
    for list in lists {
        for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
            assert!(list.contains(target), "{target} missing from:\n{list}");
        }
    }
    assert_eq!(
        RELEASE_YML.matches("check_asset install.ps1").count(),
        2,
        "both completeness checks must require the installer asset"
    );
}

/// Windows assets ship unsigned (ADR-0035 개정 이력, 2026-10-19): the
/// workflow carries no Authenticode step, and the installer is still staged
/// and packaging still runs.
#[test]
fn release_yml_ships_windows_assets_unsigned() {
    for gone in [
        "esigner-codesign",
        "WINDOWS_SIGN_",
        "verify-signature.ps1",
        "signtool",
        "Check for Windows signing secrets",
    ] {
        assert!(
            !RELEASE_YML.contains(gone),
            "release.yml still has `{gone}`"
        );
    }
    let order = [
        "cargo build --release -p qsh-cli --target",
        "name: Stage install.ps1",
        "name: Release smoke (functional)",
        "name: Package archive (windows)",
    ];
    let positions: Vec<usize> = order.iter().map(|n| index_of(n)).collect();
    assert!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "Windows steps are out of order: {positions:?}"
    );
}

/// The text of one top-level job: from its `  name:` header line to the next
/// line at job indent (the next job, or a comment block that introduces it).
fn job_text(name: &str) -> &'static str {
    let header = format!("\n  {name}:\n");
    let start = RELEASE_YML
        .find(&header)
        .unwrap_or_else(|| panic!("release.yml has no job `{name}`"))
        + 1;
    let rest = &RELEASE_YML[start..];
    let mut offset = rest.find('\n').unwrap() + 1;
    for line in rest[offset..].lines() {
        if line.starts_with("  ") && !line.starts_with("   ") {
            break;
        }
        offset += line.len() + 1;
    }
    &rest[..offset.min(rest.len())]
}

/// The step texts of one job, in order. A step starts at `      - ` (six
/// spaces) and runs to the next one.
fn steps_of(job: &'static str) -> Vec<&'static str> {
    let steps_at = job.find("\n    steps:\n").expect("job has steps") + 1;
    let body = &job[steps_at..];
    let mut starts: Vec<usize> = body
        .match_indices("\n      - ")
        .map(|(i, _)| i + 1)
        .collect();
    starts.push(body.len());
    starts.windows(2).map(|w| &body[w[0]..w[1]]).collect()
}

/// A repository without the package-manager secrets must end green with
/// the steps skipped: tag pushes only and never a prerelease tag, a
/// presence flag computed from the secret, every later step conditional on
/// it, and a job-level `continue-on-error` so a failure on the
/// package-manager side cannot red the release. The flag step is also run
/// with the secret absent.
#[test]
fn package_jobs_skip_green_without_secrets() {
    for (job, secret, flag) in [
        ("scoop-bucket", "SCOOP_BUCKET_DEPLOY_KEY", "has-key"),
        ("winget", "WINGET_PAT", "has-pat"),
    ] {
        let text = job_text(job);
        let (head, _) = text.split_once("\n    steps:\n").unwrap();
        assert!(
            head.contains("needs: release"),
            "{job}: runs before release"
        );
        assert!(
            head.contains("if: startsWith(github.ref, 'refs/tags/')"),
            "{job}: not limited to tag pushes"
        );
        assert!(
            head.contains("&& !contains(github.ref_name, '-')"),
            "{job}: runs for prerelease tags"
        );
        assert!(
            head.contains("\n    continue-on-error: true\n"),
            "{job}: a failure would red the release"
        );

        let steps = steps_of(text);
        assert!(
            steps.len() >= 3,
            "{job}: expected a flag step and work steps"
        );
        let check = steps[0];
        assert!(
            check.contains("id: check"),
            "{job}: first step is not the flag"
        );
        assert!(
            check.contains(&format!("${{{{ secrets.{secret} != '' }}}}")),
            "{job}: the flag must come from `secrets.{secret} != ''`"
        );
        assert!(
            !check.contains("\n        if:"),
            "{job}: the flag step must always run"
        );
        let condition = format!("steps.check.outputs.{flag} == 'true'");
        for step in &steps[1..] {
            let first = step.lines().next().unwrap();
            assert!(
                step.contains("if: ") && step.contains(&condition),
                "{job}: step `{first}` is not gated on the flag"
            );
        }
        // The secret is read by the flag step and by gated steps only.
        assert_eq!(
            RELEASE_YML.matches(&format!("secrets.{secret}")).count(),
            text.matches(&format!("secrets.{secret}")).count(),
            "{secret} is used outside {job}"
        );
        assert!(
            text.contains("render-manifests.sh"),
            "{job}: does not render through the shared script"
        );
    }
}

/// The flag step with the secret absent writes `false`, which no later step
/// accepts as its condition.
#[cfg(unix)]
#[test]
fn package_job_flag_steps_write_false_without_the_secret() {
    use std::process::Command;
    for (job, var, flag) in [
        ("scoop-bucket", "HAS_KEY", "has-key"),
        ("winget", "HAS_PAT", "has-pat"),
    ] {
        let check = steps_of(job_text(job))[0];
        let run = check
            .lines()
            .find_map(|l| l.trim().strip_prefix("run: "))
            .unwrap_or_else(|| panic!("{job}: flag step has no one-line run"));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::write(&out, "").unwrap();
        let status = Command::new("/bin/sh")
            .args(["-c", run])
            .env_clear()
            .env(var, "false")
            .env("GITHUB_OUTPUT", &out)
            .status()
            .unwrap();
        assert!(status.success(), "{job}: flag step failed");
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            format!("{flag}=false\n")
        );
    }
}
