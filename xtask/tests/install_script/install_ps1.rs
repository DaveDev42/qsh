//! Tests for `scripts/install.ps1` and `scripts/release/package-windows.ps1`,
//! run against a fake release with no network access.
//!
//! Each test builds a release in its own temp directory: a stand-in `qsh.exe`
//! and two man pages packed by the real `package-windows.ps1` into the zip
//! name the workflow publishes, plus a `SHA256SUMS`. The installer is run by
//! a small driver script that defines an `Invoke-WebRequest` function before
//! calling it. A function shadows the cmdlet inside the installer, so the
//! stand-in maps a request URL to a file of the fake release and logs the URL,
//! the way the `curl` stand-in does for `install.sh`, with no seam in the
//! installer itself. The profile, the temp directory and the install
//! directories are all inside the sandbox, and `QSH_NO_MODIFY_PATH=1` keeps
//! the real user PATH out of it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use tempfile::TempDir;

use super::pwsh;

const INSTALL_PS1: &str = include_str!("../../../scripts/install.ps1");
const PACKAGE_PS1: &str = include_str!("../../../scripts/release/package-windows.ps1");

const TAG: &str = "v9.9.9";
const X86_64: &str = "x86_64-pc-windows-msvc";
const AARCH64: &str = "aarch64-pc-windows-msvc";
const FAKE_EXE: &str = "MZ fake qsh.exe";

const DRIVER: &str = r#"$ErrorActionPreference = 'Stop'
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, $Headers)
    Add-Content -LiteralPath $env:FAKE_LOG -Value $Uri
    $src = Join-Path $env:FAKE_RELEASE $Uri.Substring($Uri.LastIndexOf('/') + 1)
    if (-not (Test-Path -LiteralPath $src)) { throw "404 Not Found: $Uri" }
    Copy-Item -LiteralPath $src -Destination $OutFile
}
& $env:QSH_TEST_SCRIPT
"#;

const WRITE_SUMS: &str = r#"$ErrorActionPreference = 'Stop'
$lines = Get-ChildItem -LiteralPath $env:FAKE_RELEASE -File |
    Where-Object { $_.Name -ne 'SHA256SUMS' } |
    Sort-Object Name |
    ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.Name }
[System.IO.File]::WriteAllText((Join-Path $env:FAKE_RELEASE 'SHA256SUMS'), (($lines -join "`n") + "`n"))
"#;

/// A fake release plus the sandbox the installer runs in.
struct Fixture {
    root: TempDir,
    target: &'static str,
}

impl Fixture {
    /// A good release for `target`: the zip, and sums that match it.
    fn new(target: &'static str) -> Self {
        let root = tempfile::tempdir().unwrap();
        for dir in ["release", "stage/man", "profile", "tmp", "scripts"] {
            fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        let fx = Self { root, target };
        let scripts = fx.root.path().join("scripts");
        pwsh::write_script(&scripts, "install.ps1", INSTALL_PS1);
        pwsh::write_script(&scripts, "package-windows.ps1", PACKAGE_PS1);
        pwsh::write_script(&scripts, "driver.ps1", DRIVER);
        pwsh::write_script(&scripts, "write-sums.ps1", WRITE_SUMS);
        fs::write(fx.stage().join("qsh.exe"), FAKE_EXE).unwrap();
        fs::write(fx.stage().join("man/qsh.1"), ".TH QSH 1\n").unwrap();
        fs::write(fx.stage().join("man/qsh-cp.1"), ".TH QSH-CP 1\n").unwrap();
        let out = pwsh::run_file(
            &scripts.join("package-windows.ps1"),
            &[
                "-Binary",
                fx.stage().join("qsh.exe").to_str().unwrap(),
                "-ManDir",
                fx.stage().join("man").to_str().unwrap(),
                "-Asset",
                fx.archive().to_str().unwrap(),
            ],
        )
        .output()
        .unwrap();
        assert!(out.status.success(), "{}", pwsh::text(&out));
        fx.write_sums();
        fx
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    fn stage(&self) -> PathBuf {
        self.path("stage")
    }

    fn release(&self) -> PathBuf {
        self.path("release")
    }

    fn asset(&self) -> String {
        format!("qsh-{TAG}-{}.zip", self.target)
    }

    fn archive(&self) -> PathBuf {
        self.release().join(self.asset())
    }

    fn sums(&self) -> PathBuf {
        self.release().join("SHA256SUMS")
    }

    fn profile(&self) -> PathBuf {
        self.path("profile")
    }

    fn install_dir(&self) -> PathBuf {
        self.path("install")
    }

    fn man_dir(&self) -> PathBuf {
        self.path("man-out")
    }

    fn write_sums(&self) {
        let out = pwsh::run_file(&self.path("scripts/write-sums.ps1"), &[])
            .env("FAKE_RELEASE", self.release())
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", pwsh::text(&out));
    }

    fn architecture(&self) -> &'static str {
        if self.target == AARCH64 {
            "ARM64"
        } else {
            "AMD64"
        }
    }

    /// Runs the installer with the sandbox's defaults, then `extra_env`.
    fn run(&self, extra_env: &[(&str, &str)]) -> Output {
        let mut cmd = pwsh::run_file(&self.path("scripts/driver.ps1"), &[]);
        for name in [
            "QSH_INSTALL_DIR",
            "QSH_MAN_DIR",
            "QSH_NO_MAN",
            "QSH_REPO",
            "QSH_INSECURE_SKIP_VERIFY",
            "PROCESSOR_ARCHITEW6432",
        ] {
            cmd.env_remove(name);
        }
        cmd.env("USERPROFILE", self.profile())
            .env("TEMP", self.path("tmp"))
            .env("TMP", self.path("tmp"))
            .env("QSH_VERSION", TAG)
            .env("QSH_NO_MODIFY_PATH", "1")
            .env("PROCESSOR_ARCHITECTURE", self.architecture())
            .env("FAKE_RELEASE", self.release())
            .env("FAKE_LOG", self.path("requests.log"))
            .env("QSH_TEST_SCRIPT", self.path("scripts/install.ps1"));
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    /// Like `run`, with the install and man directories inside the sandbox.
    fn run_into_sandbox(&self, extra_env: &[(&str, &str)]) -> Output {
        let install = self.install_dir();
        let man = self.man_dir();
        let mut env = vec![
            ("QSH_INSTALL_DIR", install.to_str().unwrap()),
            ("QSH_MAN_DIR", man.to_str().unwrap()),
        ];
        env.extend_from_slice(extra_env);
        self.run(&env)
    }

    /// Requested URLs, in order.
    fn requests(&self) -> Vec<String> {
        fs::read_to_string(self.path("requests.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Replaces the SHA256SUMS line of the archive with `digest`.
    fn set_sums_digest(&self, digest: &str) {
        fs::write(self.sums(), format!("{digest}  {}\n", self.asset())).unwrap();
    }
}

fn assert_ok(out: &Output) {
    assert!(
        out.status.success(),
        "installer failed:\n{}",
        pwsh::text(out)
    );
}

fn assert_refused(out: &Output, why: &str) {
    let text = pwsh::text(out);
    assert!(
        !out.status.success(),
        "installer should have refused:\n{text}"
    );
    assert!(text.contains(why), "expected `{why}` in:\n{text}");
}

fn assert_nothing_installed(fx: &Fixture) {
    assert!(
        !fx.install_dir().join("qsh.exe").exists(),
        "qsh.exe was installed"
    );
    let pages = fs::read_dir(fx.man_dir()).map(|d| d.count()).unwrap_or(0);
    assert_eq!(pages, 0, "man pages were installed");
}

fn installed_exe(fx: &Fixture) -> String {
    fs::read_to_string(fx.install_dir().join("qsh.exe")).unwrap()
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn install_ps1_installs_the_binary_and_every_man_page() {
    let fx = Fixture::new(X86_64);
    let out = fx.run_into_sandbox(&[]);
    assert_ok(&out);
    assert_eq!(installed_exe(&fx), FAKE_EXE);
    assert_eq!(listing(&fx.man_dir()), ["qsh-cp.1", "qsh.1"]);
    // Nothing is left behind next to the binary: no staging file.
    assert_eq!(listing(&fx.install_dir()), ["qsh.exe"]);
    let urls = fx.requests();
    assert_eq!(urls.len(), 2, "{urls:?}");
    assert!(urls.iter().all(|u| u.starts_with(&format!(
        "https://github.com/DaveDev42/qsh/releases/download/{TAG}/"
    ))));
}

/// The checksum is compared before the zip is opened. The archive below is
/// not a zip at all: had the installer opened it first, the error would be
/// about the archive, not the digest.
#[test]
fn install_ps1_verifies_the_checksum_before_extracting() {
    let fx = Fixture::new(X86_64);
    fs::write(fx.archive(), b"this is not a zip archive").unwrap();

    let out = fx.run_into_sandbox(&[]);
    assert_refused(&out, "checksum mismatch");
    assert!(!pwsh::text(&out).contains("not a readable zip"));
    assert_nothing_installed(&fx);

    // With sums that match the bytes, the check passes and only then does
    // the installer open the archive and fail on it.
    fx.write_sums();
    let out = fx.run_into_sandbox(&[]);
    assert_refused(&out, "not a readable zip");
    assert!(!pwsh::text(&out).contains("checksum mismatch"));
    assert_nothing_installed(&fx);
}

#[test]
fn install_ps1_refuses_a_sums_file_without_exactly_one_entry() {
    let fx = Fixture::new(X86_64);
    let asset = fx.asset();

    fs::write(
        fx.sums(),
        format!("{}  qsh-v1.0.0-other.zip\n", "a".repeat(64)),
    )
    .unwrap();
    assert_refused(&fx.run_into_sandbox(&[]), "no entry");
    assert_nothing_installed(&fx);

    let line = format!("{}  {asset}\n", "a".repeat(64));
    fs::write(fx.sums(), format!("{line}{line}")).unwrap();
    assert_refused(&fx.run_into_sandbox(&[]), "2 entries");
    assert_nothing_installed(&fx);

    fx.set_sums_digest("not-a-digest");
    assert_refused(&fx.run_into_sandbox(&[]), "64-character");
    assert_nothing_installed(&fx);
}

#[test]
fn install_ps1_has_no_way_to_skip_the_checksum() {
    let fx = Fixture::new(X86_64);
    fx.set_sums_digest(&"0".repeat(64));
    for value in ["1", "0", "true", "yes", ""] {
        let out = fx.run_into_sandbox(&[("QSH_INSECURE_SKIP_VERIFY", value)]);
        assert_refused(&out, "checksum mismatch");
        assert_nothing_installed(&fx);
    }
}

#[test]
fn install_ps1_refuses_an_unknown_architecture() {
    let fx = Fixture::new(X86_64);
    for arch in ["x86", "IA64", ""] {
        let out = fx.run_into_sandbox(&[("PROCESSOR_ARCHITECTURE", arch)]);
        assert_refused(&out, "unsupported Windows architecture");
        assert!(
            fx.requests().is_empty(),
            "`{arch}`: the installer downloaded before it knew the architecture: {:?}",
            fx.requests()
        );
        assert_nothing_installed(&fx);
    }
}

#[test]
fn install_ps1_picks_the_zip_that_matches_the_machine() {
    for (target, other) in [(X86_64, AARCH64), (AARCH64, X86_64)] {
        let fx = Fixture::new(target);
        let out = fx.run_into_sandbox(&[]);
        assert_ok(&out);
        let urls = fx.requests();
        assert!(
            urls.iter()
                .any(|u| u.ends_with(&format!("qsh-{TAG}-{target}.zip"))),
            "{urls:?}"
        );
        assert!(urls.iter().all(|u| !u.contains(other)), "{urls:?}");
    }
    // A 32-bit process on a 64-bit machine reports the machine in
    // PROCESSOR_ARCHITEW6432.
    let fx = Fixture::new(AARCH64);
    let out = fx.run_into_sandbox(&[
        ("PROCESSOR_ARCHITECTURE", "x86"),
        ("PROCESSOR_ARCHITEW6432", "ARM64"),
    ]);
    assert_ok(&out);
}

/// Everything lands under the user profile and the script never asks for
/// more: no elevation request, no machine-wide location or environment.
#[test]
fn install_ps1_does_not_require_elevation() {
    for forbidden in [
        "RunAsAdministrator",
        "RunAs",
        "HKLM",
        "HKEY_LOCAL_MACHINE",
        "'Machine'",
        "\"Machine\"",
        "Program Files",
        "ProgramFiles",
        "Start-Process",
        "#Requires",
    ] {
        assert!(
            !INSTALL_PS1.contains(forbidden),
            "install.ps1 mentions `{forbidden}`"
        );
    }

    // With no directory override at all, the defaults are under USERPROFILE.
    let fx = Fixture::new(X86_64);
    let out = fx.run(&[]);
    assert_ok(&out);
    assert_eq!(
        fs::read_to_string(fx.profile().join(".local/bin/qsh.exe")).unwrap(),
        FAKE_EXE
    );
    assert_eq!(
        listing(&fx.profile().join(".local/share/man/man1")),
        ["qsh-cp.1", "qsh.1"]
    );
}

#[test]
fn install_ps1_skips_man_pages_with_qsh_no_man() {
    let fx = Fixture::new(X86_64);
    let out = fx.run_into_sandbox(&[("QSH_NO_MAN", "1")]);
    assert_ok(&out);
    assert_eq!(installed_exe(&fx), FAKE_EXE);
    assert!(!fx.man_dir().exists());
}

#[test]
fn install_ps1_keeps_the_binary_when_man_installation_fails() {
    let fx = Fixture::new(X86_64);
    // A file where the man directory should be.
    fs::write(fx.man_dir(), "in the way").unwrap();
    let out = fx.run_into_sandbox(&[]);
    assert_ok(&out);
    assert!(pwsh::text(&out).contains("man pages were not installed"));
    assert_eq!(installed_exe(&fx), FAKE_EXE);
}

#[test]
fn install_ps1_adds_the_install_dir_to_the_user_path_once() {
    let fx = Fixture::new(X86_64);
    let driver = pwsh::write_script(
        &fx.path("scripts"),
        "path.ps1",
        r#"$ErrorActionPreference = 'Stop'
. $env:QSH_TEST_SCRIPT
function Assert($cond, $msg) { if (-not $cond) { throw "assertion failed: $msg" } }

Assert ($null -eq (Add-QshDirToPathString 'C:\a;C:\Tools\bin\;C:\b' 'c:\tools\BIN')) 'an entry already there, compared without case or trailing slash'
Assert ((Add-QshDirToPathString 'C:\a' 'C:\x') -ceq 'C:\a;C:\x') 'appended'
Assert ((Add-QshDirToPathString '' 'C:\x') -ceq 'C:\x') 'into an empty PATH'
Assert ((Add-QshDirToPathString 'C:\a;' 'C:\x') -ceq 'C:\a;C:\x') 'after a trailing semicolon'
Assert ($null -eq (Add-QshDirToPathString '%USERPROFILE%\bin' "$env:USERPROFILE\bin")) 'a %VAR% entry is compared expanded'

# The registry side, against a scratch key so the real user PATH is never touched.
$sub = 'Software\qsh-xtask-test-' + [Guid]::NewGuid().ToString('N')
$key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($sub)
try {
    $key.SetValue('Path', '%USERPROFILE%\bin;C:\a', [Microsoft.Win32.RegistryValueKind]::ExpandString)
    $key.Close()
    Assert (Update-QshUserPath 'C:\qsh-test\bin' $sub) 'the first call changes the PATH'
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($sub)
    $value = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    Assert ($value -ceq '%USERPROFILE%\bin;C:\a;C:\qsh-test\bin') "the existing entries survive unexpanded, got: $value"
    Assert ($key.GetValueKind('Path') -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) 'the value keeps its registry type'
    $key.Close()
    Assert (-not (Update-QshUserPath 'C:\qsh-test\bin' $sub)) 'the second call is a no-op'
} finally {
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($sub, $false)
}
"#,
    );
    let out = pwsh::run_file(&driver, &[])
        .env("USERPROFILE", fx.profile())
        .env("QSH_TEST_SCRIPT", fx.path("scripts/install.ps1"))
        .output()
        .unwrap();
    assert_ok(&out);
}

/// Windows PowerShell 5.1 reads a BOM-less file as the ANSI code page; plain
/// ASCII with LF endings reads the same on every checkout.
#[test]
fn install_ps1_is_plain_ascii() {
    assert!(INSTALL_PS1.is_ascii());
    assert!(
        !INSTALL_PS1.contains('\r'),
        "install.ps1 must use LF endings so the file is the same on every checkout"
    );
}

#[test]
fn package_windows_ps1_packs_the_binary_and_every_man_page_and_nothing_else() {
    let fx = Fixture::new(X86_64);
    let list = pwsh::write_script(
        &fx.path("scripts"),
        "list.ps1",
        r#"Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($env:ZIP)
try { $zip.Entries | ForEach-Object { $_.FullName } } finally { $zip.Dispose() }
"#,
    );
    let out = pwsh::run_file(&list, &[])
        .env("ZIP", fx.archive())
        .output()
        .unwrap();
    assert_ok(&out);
    let members: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(members, ["qsh.exe", "man/qsh-cp.1", "man/qsh.1"]);

    // No pages, or no binary, is a packaging bug and fails the step.
    let empty = fx.path("empty-man");
    fs::create_dir_all(&empty).unwrap();
    let out = pwsh::run_file(
        &fx.path("scripts/package-windows.ps1"),
        &[
            "-Binary",
            fx.stage().join("qsh.exe").to_str().unwrap(),
            "-ManDir",
            empty.to_str().unwrap(),
            "-Asset",
            fx.path("never.zip").to_str().unwrap(),
        ],
    )
    .output()
    .unwrap();
    assert_refused(&out, "no *.1 pages");
    assert!(!fx.path("never.zip").exists());

    let out = pwsh::run_file(
        &fx.path("scripts/package-windows.ps1"),
        &[
            "-Binary",
            fx.path("missing.exe").to_str().unwrap(),
            "-ManDir",
            fx.stage().join("man").to_str().unwrap(),
            "-Asset",
            fx.path("never.zip").to_str().unwrap(),
        ],
    )
    .output()
    .unwrap();
    assert_refused(&out, "-Binary must name an existing file");
}
