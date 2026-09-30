//! Tests for `scripts/install.sh`, run against a fake release with no
//! network access.
//!
//! Each test builds a release in its own temp directory (a `qsh` stand-in
//! shell script inside a tar.gz, optional `man/*.1` members, a `SHA256SUMS`),
//! puts `curl`, `uname` and `gh` stand-ins first on `PATH`, and runs
//! `sh scripts/install.sh` with a temp `HOME`. The `curl` stand-in maps a
//! request URL to a file of the fake release and appends the URL to a log, so
//! a test can assert which assets the installer asked for and in what order.
//! Nothing is installed outside the temp directories.
//!
//! Lives in `xtask` because it is an unpublished crate: no tarball policy
//! applies to these files.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const TAG: &str = "v9.9.9";

fn install_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/install.sh")
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn sha256_of(path: &Path) -> String {
    let out = if Command::new("sha256sum").arg("--version").output().is_ok() {
        Command::new("sha256sum").arg(path).output().unwrap()
    } else {
        Command::new("shasum")
            .args(["-a", "256"])
            .arg(path)
            .output()
            .unwrap()
    };
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// A fake release plus the sandbox the installer runs in.
struct Fixture {
    root: TempDir,
    target: String,
    /// Directory whose files the `curl` stand-in serves by basename.
    release: PathBuf,
    /// Directory the archive is packed from.
    stage: PathBuf,
    /// Archive members in `tar` argument order.
    members: Vec<String>,
}

impl Fixture {
    /// A release whose archive for `target` holds only a `qsh` stand-in.
    fn new(target: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let release = root.path().join("release");
        let stage = root.path().join("stage");
        fs::create_dir_all(&release).unwrap();
        fs::create_dir_all(&stage).unwrap();
        fs::create_dir_all(root.path().join("bin")).unwrap();
        fs::create_dir_all(root.path().join("home")).unwrap();
        fs::create_dir_all(root.path().join("tmp")).unwrap();
        write_executable(&stage.join("qsh"), "#!/bin/sh\necho fake-qsh \"$@\"\n");
        let fx = Self {
            root,
            target: target.to_string(),
            release,
            stage,
            members: vec!["qsh".to_string()],
        };
        fx.write_stubs();
        fx
    }

    fn asset(&self) -> String {
        format!("qsh-{TAG}-{}.tar.gz", self.target)
    }

    fn archive_path(&self) -> PathBuf {
        self.release.join(self.asset())
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn install_dir(&self) -> PathBuf {
        self.root.path().join("install")
    }

    fn log_path(&self) -> PathBuf {
        self.root.path().join("curl.log")
    }

    fn stubs(&self) -> PathBuf {
        self.root.path().join("bin")
    }

    fn write_stubs(&self) {
        // The installer runs with `PATH` set to this directory alone, so a
        // `gh` or `curl` installed on the machine running the tests can never
        // leak in. Only the tools the installer needs are linked through.
        for tool in [
            "awk",
            "basename",
            "chmod",
            "cp",
            "gzip",
            "mkdir",
            "mktemp",
            "mv",
            "rm",
            "sha256sum",
            "shasum",
            "tar",
        ] {
            for dir in ["/usr/bin", "/bin"] {
                let real = Path::new(dir).join(tool);
                if real.exists() {
                    std::os::unix::fs::symlink(&real, self.stubs().join(tool)).unwrap();
                    break;
                }
            }
        }
        // Serves `$FAKE_RELEASE/<basename of the URL>` to `-o <file>`, logs
        // every URL, and exits 22 (curl's `-f` HTTP error) for unknown files.
        write_executable(
            &self.stubs().join("curl"),
            r#"#!/bin/sh
out=""
url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -w) shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
printf '%s\n' "$url" >> "$FAKE_LOG"
src="$FAKE_RELEASE/${url##*/}"
[ -f "$src" ] || exit 22
cp "$src" "$out"
"#,
        );
        write_executable(
            &self.stubs().join("uname"),
            r#"#!/bin/sh
case "$1" in
    -s) echo "$FAKE_UNAME_S" ;;
    -m) echo "$FAKE_UNAME_M" ;;
    *) echo "$FAKE_UNAME_S" ;;
esac
"#,
        );
    }

    /// Puts a `gh` stand-in on `PATH`. `gh auth status` exits `auth_rc` and
    /// `gh attestation verify` exits `verify_rc`. Every `attestation`
    /// invocation appends its arguments, and whether the binary was already
    /// installed at that moment, to `gh.log`.
    fn with_gh(&self, auth_rc: i32, verify_rc: i32) {
        write_executable(
            &self.stubs().join("gh"),
            &format!(
                r#"#!/bin/sh
case "$1" in
    auth) exit {auth_rc} ;;
    attestation)
        if [ -e "$QSH_INSTALL_DIR/qsh" ]; then installed=yes; else installed=no; fi
        printf 'installed=%s args=%s\n' "$installed" "$*" >> "$FAKE_GH_LOG"
        exit {verify_rc} ;;
esac
exit 64
"#
            ),
        );
    }

    fn gh_log_path(&self) -> PathBuf {
        self.root.path().join("gh.log")
    }

    /// Lines the `gh` stand-in logged for `attestation` calls.
    fn gh_calls(&self) -> Vec<String> {
        fs::read_to_string(self.gh_log_path())
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn pack(&self) {
        let status = Command::new("tar")
            .arg("czf")
            .arg(self.archive_path())
            .arg("-C")
            .arg(&self.stage)
            .args(&self.members)
            .status()
            .unwrap();
        assert!(status.success(), "tar failed");
    }

    /// Writes `SHA256SUMS` with a correct line for every archive in the
    /// release directory.
    fn write_sums(&self) {
        let mut names: Vec<String> = fs::read_dir(&self.release)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "SHA256SUMS")
            .collect();
        names.sort();
        let mut sums = String::new();
        for n in names {
            sums.push_str(&format!("{}  {}\n", sha256_of(&self.release.join(&n)), n));
        }
        fs::write(self.release.join("SHA256SUMS"), sums).unwrap();
    }

    /// Packs the archive and writes matching sums: the ordinary good release.
    fn publish(&self) {
        self.pack();
        self.write_sums();
    }

    fn uname(&self) -> (&'static str, &'static str) {
        if self.target.contains("apple-darwin") {
            (
                "Darwin",
                if self.target.starts_with("aarch64") {
                    "arm64"
                } else {
                    "x86_64"
                },
            )
        } else if self.target.starts_with("aarch64") {
            ("Linux", "aarch64")
        } else {
            ("Linux", "x86_64")
        }
    }

    fn command(&self, extra_env: &[(&str, &str)]) -> Command {
        let (s, m) = self.uname();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(install_script())
            .env_clear()
            .env("PATH", self.stubs())
            .env("HOME", self.home())
            .env("TMPDIR", self.root.path().join("tmp"))
            .env("QSH_VERSION", TAG)
            .env("QSH_INSTALL_DIR", self.install_dir())
            .env("FAKE_RELEASE", &self.release)
            .env("FAKE_LOG", self.log_path())
            .env("FAKE_GH_LOG", self.gh_log_path())
            .env("FAKE_UNAME_S", s)
            .env("FAKE_UNAME_M", m);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd
    }

    fn run(&self, extra_env: &[(&str, &str)]) -> Output {
        self.command(extra_env).output().unwrap()
    }

    /// Requested URLs, in order.
    fn requests(&self) -> Vec<String> {
        fs::read_to_string(self.log_path())
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn installed_qsh(&self) -> PathBuf {
        self.install_dir().join("qsh")
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_ok(out: &Output) {
    assert!(out.status.success(), "installer failed: {}", stderr(out));
}

fn assert_installed(fx: &Fixture) {
    let bin = fx.installed_qsh();
    assert!(bin.is_file(), "no binary at {}", bin.display());
    assert_eq!(
        fs::metadata(&bin).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

fn archive_index(fx: &Fixture) -> Option<usize> {
    fx.requests().iter().position(|u| u.ends_with(&fx.asset()))
}

fn sums_index(fx: &Fixture) -> Option<usize> {
    fx.requests()
        .iter()
        .position(|u| u.ends_with("/SHA256SUMS"))
}

#[test]
fn install_defaults_to_gnu_on_x86_64_and_aarch64_linux() {
    for (arch, target) in [
        ("x86_64", "x86_64-unknown-linux-gnu"),
        ("aarch64", "aarch64-unknown-linux-gnu"),
    ] {
        let fx = Fixture::new(target);
        fx.publish();
        let out = fx.run(&[]);
        assert_ok(&out);
        assert!(
            stderr(&out).contains(&format!("detected target: {target}")),
            "{arch}: {}",
            stderr(&out)
        );
        assert_installed(&fx);
        // Archive first, sums second: the default order is not allowed to
        // change.
        assert_eq!(
            fx.requests(),
            vec![
                format!(
                    "https://github.com/DaveDev42/qsh/releases/download/{TAG}/{}",
                    fx.asset()
                ),
                format!("https://github.com/DaveDev42/qsh/releases/download/{TAG}/SHA256SUMS"),
            ],
            "{arch}"
        );
    }
}

#[test]
fn install_picks_x86_64_musl_when_qsh_libc_is_musl() {
    let fx = Fixture::new("x86_64-unknown-linux-musl");
    fx.publish();
    let out = fx.run(&[("QSH_LIBC", "musl")]);
    assert_ok(&out);
    assert!(stderr(&out).contains("detected target: x86_64-unknown-linux-musl"));
    assert_installed(&fx);
    assert!(archive_index(&fx).unwrap() < sums_index(&fx).unwrap());
}

#[test]
fn install_picks_aarch64_musl_when_the_tag_publishes_it() {
    let fx = Fixture::new("aarch64-unknown-linux-musl");
    fx.publish();
    let out = fx.run(&[("QSH_LIBC", "musl")]);
    assert_ok(&out);
    assert!(stderr(&out).contains("detected target: aarch64-unknown-linux-musl"));
    assert_installed(&fx);
    // Only this branch reads SHA256SUMS before the archive, and it reads it
    // once.
    assert!(sums_index(&fx).unwrap() < archive_index(&fx).unwrap());
    assert_eq!(fx.requests().len(), 2, "{:?}", fx.requests());
}

#[test]
fn install_aarch64_musl_ends_as_today_when_the_tag_lacks_the_asset() {
    // The tag publishes the glibc aarch64 asset only.
    let gnu = Fixture::new("aarch64-unknown-linux-gnu");
    gnu.publish();
    let mut fx = Fixture::new("aarch64-unknown-linux-musl");
    fx.release = gnu.release.clone();
    let out = fx.run(&[("QSH_LIBC", "musl")]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains(&format!(
            "no aarch64 musl asset is published for {TAG}; unset QSH_LIBC to install the glibc build"
        )),
        "{}",
        stderr(&out)
    );
    assert!(
        archive_index(&fx).is_none(),
        "the archive must not be requested"
    );
    assert!(!fx.installed_qsh().exists());
}

#[test]
fn install_rejects_an_unknown_qsh_libc() {
    let fx = Fixture::new("x86_64-unknown-linux-gnu");
    fx.publish();
    let out = fx.run(&[("QSH_LIBC", "uclibc")]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("QSH_LIBC must be 'gnu' or 'musl'"));
    assert!(fx.requests().is_empty());
    assert!(!fx.installed_qsh().exists());
}

#[test]
fn install_refuses_a_checksum_mismatch() {
    let fx = Fixture::new("x86_64-unknown-linux-gnu");
    fx.pack();
    fs::write(
        fx.release.join("SHA256SUMS"),
        format!("{}  {}\n", "0".repeat(64), fx.asset()),
    )
    .unwrap();
    let out = fx.run(&[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("checksum mismatch"),
        "{}",
        stderr(&out)
    );
    assert!(!fx.installed_qsh().exists());
}

fn tamper_sums(fx: &Fixture) {
    fs::write(
        fx.release.join("SHA256SUMS"),
        format!("{}  {}\n", "0".repeat(64), fx.asset()),
    )
    .unwrap();
}

#[test]
fn install_verifies_provenance_with_gh_when_available() {
    let fx = Fixture::new("x86_64-unknown-linux-gnu");
    fx.publish();
    fx.with_gh(0, 0);
    let out = fx.run(&[]);
    assert_ok(&out);
    assert_installed(&fx);
    let calls = fx.gh_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    let call = &calls[0];
    // Verified before anything is installed, against the archive that was
    // downloaded, for this repository.
    assert!(
        call.starts_with("installed=no args=attestation verify "),
        "{call}"
    );
    assert!(call.contains(&fx.asset()), "{call}");
    assert!(call.ends_with(" --repo DaveDev42/qsh"), "{call}");
    assert!(!stderr(&out).contains("provenance not verified"));
}

#[test]
fn install_refuses_when_provenance_verification_fails() {
    let fx = Fixture::new("x86_64-unknown-linux-gnu");
    fx.publish();
    fx.with_gh(0, 1);
    let out = fx.run(&[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("provenance verification failed"),
        "{}",
        stderr(&out)
    );
    assert_eq!(fx.gh_calls().len(), 1);
    assert!(!fx.installed_qsh().exists());
}

#[test]
fn install_warns_and_continues_with_checksum_only_when_gh_is_absent() {
    let fx = Fixture::new("x86_64-unknown-linux-gnu");
    fx.publish();
    let out = fx.run(&[]);
    assert_ok(&out);
    assert_installed(&fx);
    assert!(
        stderr(&out).contains("provenance not verified"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn install_treats_an_unauthenticated_gh_as_absent() {
    let fx = Fixture::new("x86_64-unknown-linux-gnu");
    fx.publish();
    // Verification would fail if it were attempted.
    fx.with_gh(1, 1);
    let out = fx.run(&[]);
    assert_ok(&out);
    assert_installed(&fx);
    assert!(stderr(&out).contains("provenance not verified"));
    assert!(fx.gh_calls().is_empty());
}

#[test]
fn install_skip_verify_flag_skips_both_and_warns() {
    let fx = Fixture::new("x86_64-unknown-linux-gnu");
    fx.pack();
    // A checksum that cannot match and a verifier that would fail: only the
    // flag gets past them.
    tamper_sums(&fx);
    fx.with_gh(0, 1);
    let out = fx.run(&[("QSH_INSECURE_SKIP_VERIFY", "1")]);
    assert_ok(&out);
    assert_installed(&fx);
    let err = stderr(&out);
    assert!(err.contains("QSH_INSECURE_SKIP_VERIFY=1"), "{err}");
    assert!(err.contains("SHA256SUMS check"), "{err}");
    assert!(err.contains("provenance check"), "{err}");
    assert!(fx.gh_calls().is_empty());
    assert!(
        !fx.requests().iter().any(|u| u.ends_with("/SHA256SUMS")),
        "{:?}",
        fx.requests()
    );
}

#[test]
fn install_never_skips_the_checksum_without_the_explicit_flag() {
    for flag in [None, Some("0"), Some("true"), Some("")] {
        let fx = Fixture::new("x86_64-unknown-linux-gnu");
        fx.pack();
        tamper_sums(&fx);
        let env: Vec<(&str, &str)> = flag
            .map(|v| vec![("QSH_INSECURE_SKIP_VERIFY", v)])
            .unwrap_or_default();
        let out = fx.run(&env);
        assert!(!out.status.success(), "flag {flag:?} skipped the checksum");
        assert!(
            stderr(&out).contains("checksum mismatch"),
            "{}",
            stderr(&out)
        );
        assert!(!fx.installed_qsh().exists());
    }
}
