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
fn release_yml_gates_both_signing_legs_through_the_shared_script() {
    assert_eq!(
        RELEASE_YML
            .matches("bash scripts/release/secret-gate.sh")
            .count(),
        2,
        "the Apple and the Windows gate must both call the shared script"
    );
    assert!(
        !RELEASE_YML.contains("present=$((present + 1))"),
        "an inline copy of the gate logic is back in release.yml"
    );
    let apple = index_of("name: Check for Apple signing secrets");
    let windows = index_of("name: Check for Windows signing secrets");
    let toolchain = index_of("actions-rust-lang/setup-rust-toolchain");
    assert!(
        apple < toolchain && windows < toolchain,
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

/// Signing is judged on the bytes that ship: the gate fails fast, then build,
/// sign, verify, smoke, package.
#[test]
fn release_yml_orders_the_windows_signing_chain_before_packaging() {
    let order = [
        "name: Check for Windows signing secrets",
        "cargo build --release -p qsh-cli --target",
        "uses: sslcom/esigner-codesign@",
        "name: Verify the signature (windows)",
        "name: Release smoke (functional)",
        "name: Package archive (windows)",
    ];
    let positions: Vec<usize> = order.iter().map(|n| index_of(n)).collect();
    assert!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "Windows steps are out of order: {positions:?}"
    );
    assert!(
        RELEASE_YML.contains("verify-signature.ps1") && RELEASE_YML.contains("verify /pa /v"),
        "the verify step must run both signtool and the verdict script"
    );
}
