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
