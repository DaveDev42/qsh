//! Tests for `scripts/release/verify-signature.ps1`, the verdict half of the
//! release workflow's signature check. Nothing here needs a certificate: the
//! verdict function is fed the fields it judges, and the end-to-end case runs
//! the script on a binary that is not signed at all.

use std::fs;

use tempfile::TempDir;

use super::pwsh;

const VERIFY_SIGNATURE_PS1: &str = include_str!("../../../scripts/release/verify-signature.ps1");

fn sandbox() -> TempDir {
    tempfile::tempdir().unwrap()
}

/// The release workflow must fail a leg whose binary is not signed, and say
/// why. This test binary is built by cargo and carries no signature.
#[test]
fn windows_signature_check_fails_on_an_unsigned_binary() {
    let dir = sandbox();
    let script = pwsh::write_script(dir.path(), "verify-signature.ps1", VERIFY_SIGNATURE_PS1);
    let unsigned = dir.path().join("unsigned.exe");
    fs::copy(std::env::current_exe().unwrap(), &unsigned).unwrap();

    let out = pwsh::run_file(
        &script,
        &[
            "-Path",
            unsigned.to_str().unwrap(),
            "-ExpectedSubject",
            "CN=qsh-test",
        ],
    )
    .output()
    .unwrap();

    let text = pwsh::text(&out);
    assert!(!out.status.success(), "an unsigned binary passed:\n{text}");
    assert!(text.contains("NotSigned"), "status not named:\n{text}");
    assert!(text.contains("FAIL"), "no per-file verdict:\n{text}");
}

#[test]
fn windows_signature_check_judges_status_subject_and_timestamp() {
    let dir = sandbox();
    let script = pwsh::write_script(dir.path(), "verify-signature.ps1", VERIFY_SIGNATURE_PS1);
    let driver = pwsh::write_script(
        dir.path(),
        "driver.ps1",
        r#"$ErrorActionPreference = 'Stop'
. $env:QSH_TEST_SCRIPT
function Assert($cond, $msg) { if (-not $cond) { throw "assertion failed: $msg" } }
function Problems($status, $subject, $simple, $ts, $expected) {
    return @(Get-QshSignatureProblems -Status $status -Subject $subject -SimpleName $simple -HasTimestamp $ts -ExpectedSubject $expected)
}

$full = 'CN=Dave Choi, O=Dave Choi, C=KR'
Assert ((Problems 'Valid' $full 'Dave Choi' $true $full).Count -eq 0) 'full subject match passes'
Assert ((Problems 'Valid' $full 'Dave Choi' $true 'dave choi').Count -eq 0) 'simple name match passes, ignoring case'

$p = @(Problems 'NotSigned' '' '' $false $full)
Assert ($p.Count -eq 3) "unsigned reports status, signer and timestamp: $p"
Assert (($p -join ' ') -match 'NotSigned') 'unsigned names its status'

$p = @(Problems 'HashMismatch' $full 'Dave Choi' $true $full)
Assert ($p.Count -eq 1 -and $p[0] -match 'HashMismatch') "a tampered file fails on status alone: $p"

$p = @(Problems 'Valid' 'CN=Someone Else' 'Someone Else' $true $full)
Assert ($p.Count -eq 1 -and $p[0] -match 'signer') "a valid signature by another signer fails: $p"

$p = @(Problems 'Valid' $full 'Dave Choi' $false $full)
Assert ($p.Count -eq 1 -and $p[0] -match 'timestamp') "a signature without a timestamp fails: $p"

# An empty expected subject must be an error, never a pass.
$threw = $false
try { Test-QshFileSignature -Path @('x.exe') -ExpectedSubject '' | Out-Null } catch { $threw = $true }
Assert $threw 'an empty expected subject throws'
$threw = $false
try { Test-QshFileSignature -Path @('x.exe') -ExpectedSubject '   ' | Out-Null } catch { $threw = $true }
Assert $threw 'a blank expected subject throws'
"#,
    );

    let out = pwsh::run_file(&driver, &[])
        .env("QSH_TEST_SCRIPT", &script)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", pwsh::text(&out));
}
