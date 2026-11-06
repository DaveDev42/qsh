//! Installing `qsh` on the remote with consent (ADR-0051 decision 3), end to
//! end against the testkit's fake `ssh` and a loopback asset server: no
//! sshd and nothing from GitHub.
//!
//! The fake plays a remote with no `qsh` (`missing_until` the installed file
//! exists), answers the OS probe, and scripts what each install call does. A
//! scripted install touches the file it reports, so the responder call that
//! follows finds `qsh` and runs the real `qsh pair ssh-respond` (the fake
//! runs the remote responder locally). The one Unix-only test runs the real
//! remote script under `sh` with a throwaway `HOME`.
//!
//! The same tests run on every platform: on Windows the fake answers the
//! Windows probe and the install calls are `powershell -EncodedCommand`
//! words; the scripts' own text is pinned in `qsh-core`
//! (`ssh_bootstrap::install::tests`).

use std::path::PathBuf;
use std::process::{Output, Stdio};

use qsh_testkit::asset_server::{AssetServer, sha256_hex};
use serde_json::Value;

use crate::common::{exit_code, sole_envelope};
use crate::ssh_bootstrap::pair::{World, store};

fn tag() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

const EXE: &str = if cfg!(windows) { "qsh.exe" } else { "qsh" };

/// The remote of one test: where the install lands, and the release the
/// asset server holds.
pub(crate) struct Remote {
    server: AssetServer,
    installed: PathBuf,
    asset: String,
    archive: Vec<u8>,
}

/// Make `w`'s fake ssh a remote with no usable `qsh` (`missing_exit` 127 is
/// "no qsh", 2 is "too old"), serving a release for it.
pub(crate) fn remote(w: &mut World, missing_exit: i32, plan: &str) -> Remote {
    let installed = w.remote.home_dir().join(".local").join("bin").join(EXE);
    let asset = if cfg!(windows) {
        w.fake.probe_windows("AMD64");
        format!("qsh-{}-x86_64-pc-windows-msvc.zip", tag())
    } else {
        w.fake.probe_unix("Linux x86_64");
        format!("qsh-{}-x86_64-unknown-linux-gnu.tar.gz", tag())
    };
    w.fake
        .missing_until(&installed, missing_exit)
        .install_plan(plan)
        .install_report(&installed)
        .install_touch(&installed);
    let archive = b"pretend this is a release archive".to_vec();
    let server = AssetServer::start();
    server.put_release(&tag(), &asset, &archive, None);
    Remote {
        server,
        installed,
        asset,
        archive,
    }
}

/// `qsh pair ssh box ... --json` with the release server and no `gh`.
pub(crate) fn pair(w: &World, remote: Option<&Remote>, extra: &[&str]) -> Output {
    let mut args = vec!["pair", "ssh", "box", "--remote-as", "laptop"];
    args.extend_from_slice(extra);
    args.push("--json");
    let mut command = w.client.command(&args);
    command
        .stdin(Stdio::null())
        .env("QSH_GH", w.client.home_dir().join("no-such-gh"));
    if let Some(remote) = remote {
        command.env("QSH_RELEASE_BASE_URL", remote.server.base_url());
    }
    command.output().expect("run qsh")
}

pub(crate) fn envelope(out: &Output) -> Value {
    sole_envelope(&out.stdout, &["pair", "ssh"])
}

/// What each ssh call was, in order: `g` (`ssh -G`), `uname`, `cmd` (the
/// Windows probe), `install` (an `sh -c` or `powershell` script), and
/// `responder` (anything else, the remote `qsh`).
fn kinds(w: &World) -> Vec<&'static str> {
    w.fake
        .calls()
        .iter()
        .map(|args| {
            if args.first().map(String::as_str) == Some("-G") {
                return "g";
            }
            let words = remote_words(args);
            match words.first().map(String::as_str) {
                Some("uname") => "uname",
                Some("cmd") => "cmd",
                Some("sh") | Some("powershell") => "install",
                _ => "responder",
            }
        })
        .collect()
}

fn remote_words(args: &[String]) -> Vec<String> {
    match args.iter().position(|arg| arg == "--") {
        Some(dashes) => args[dashes + 2..].to_vec(),
        None => Vec::new(),
    }
}

/// The probe calls the fake sees before an install.
fn probes() -> Vec<&'static str> {
    if cfg!(windows) {
        vec!["uname", "cmd"]
    } else {
        vec!["uname"]
    }
}

fn expected_kinds(before_install: &[&'static str], installs: usize) -> Vec<&'static str> {
    let mut kinds = before_install.to_vec();
    kinds.extend(probes());
    kinds.extend(std::iter::repeat_n("install", installs));
    kinds.push("responder");
    kinds
}

fn last_responder_word(w: &World) -> String {
    let calls = w.fake.calls();
    let last = calls.last().expect("a call");
    remote_words(last).first().cloned().expect("a word")
}

#[test]
fn remote_install_with_the_flag_runs_the_installer_then_the_responder_by_absolute_path() {
    let mut w = World::new();
    let r = remote(&mut w, 127, "0");
    let out = pair(&w, Some(&r), &["--install-remote"]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 0, "{got}");

    let installed = &got["data"]["installed"];
    assert_eq!(installed["version"], tag(), "{got}");
    assert_eq!(
        installed["path"],
        r.installed.display().to_string(),
        "{got}"
    );
    assert_eq!(installed["method"], "remote_installer", "{got}");
    assert_eq!(installed["upgraded"], false, "{got}");
    assert_eq!(got["data"]["remote"]["created"], true, "{got}");

    // -G once, the responder that found no qsh, the probe, the installer,
    // then the responder by the installed path.
    assert_eq!(kinds(&w), expected_kinds(&["g", "responder"], 1));
    assert_eq!(last_responder_word(&w), r.installed.display().to_string());
    // Path 1 never touches this machine's download.
    assert!(r.server.requests().is_empty(), "{:?}", r.server.requests());
    // The install call names the pinned tag.
    let calls = w.fake.calls();
    let install = calls
        .iter()
        .find(|args| {
            matches!(
                remote_words(args).first().map(String::as_str),
                Some("sh" | "powershell")
            )
        })
        .unwrap();
    let words = remote_words(install);
    if cfg!(windows) {
        assert_eq!(words[0], "powershell");
        assert!(words.iter().any(|w| w == "-EncodedCommand"), "{words:?}");
    } else {
        assert!(
            words[2].contains(&format!("QSH_VERSION={}", tag())),
            "{words:?}"
        );
    }

    // The pin keeps the path, so the next bootstrap uses it.
    let pin = store(&w.client).find("box").cloned().expect("local pin");
    assert_eq!(
        pin.remote_qsh.as_deref(),
        Some(r.installed.to_str().unwrap())
    );
}

#[test]
fn a_second_bootstrap_of_the_same_pin_runs_the_recorded_remote_qsh() {
    let mut w = World::new();
    let r = remote(&mut w, 127, "0");
    let out = pair(&w, Some(&r), &["--install-remote"]);
    assert_eq!(exit_code(&out), 0, "{}", envelope(&out));

    let before = w.fake.calls().len();
    let out = pair(&w, Some(&r), &[]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 0, "{got}");
    assert!(got["data"].get("installed").is_none(), "{got}");
    let calls = w.fake.calls();
    assert_eq!(calls.len(), before + 2, "-G and the responder only");
    assert_eq!(last_responder_word(&w), r.installed.display().to_string());
}

#[test]
fn remote_install_streams_the_archive_when_the_remote_cannot_reach_github() {
    let mut w = World::new();
    // The installer call exits 71 (cannot reach the release host).
    let r = remote(&mut w, 127, "71,0");
    let out = pair(&w, Some(&r), &["--install-remote"]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 0, "{got}");
    assert_eq!(got["data"]["installed"]["method"], "streamed", "{got}");
    assert_eq!(got["data"]["installed"]["upgraded"], false, "{got}");

    assert_eq!(kinds(&w), expected_kinds(&["g", "responder"], 2));
    // The second install call received exactly the archive on stdin; the
    // first (the installer) received nothing.
    assert_eq!(w.fake.install_stdin(0), b"");
    assert_eq!(w.fake.install_stdin(1), r.archive);
    // This machine fetched `SHA256SUMS` and the archive, nothing else.
    let mut seen = r.server.requests();
    seen.sort();
    let mut want = vec![
        format!("{}/SHA256SUMS", tag()),
        format!("{}/{}", tag(), r.asset),
    ];
    want.sort();
    assert_eq!(seen, want);
    // The remote re-checks the digest this machine verified.
    let calls = w.fake.calls();
    let stream = calls
        .iter()
        .filter(|args| {
            matches!(
                remote_words(args).first().map(String::as_str),
                Some("sh" | "powershell")
            )
        })
        .nth(1)
        .unwrap();
    if !cfg!(windows) {
        assert!(
            remote_words(stream)[2].contains(&sha256_hex(&r.archive)),
            "{stream:?}"
        );
    }
}

#[test]
fn a_checksum_mismatch_installs_nothing_and_sends_nothing() {
    let mut w = World::new();
    let r = remote(&mut w, 127, "71,0");
    // SHA256SUMS lists another digest than the archive has.
    r.server
        .put_release(&tag(), &r.asset, &r.archive, Some(&"ab".repeat(32)));
    let out = pair(&w, Some(&r), &["--install-remote"]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 255, "{got}");
    assert_eq!(got["error"]["code"], "REMOTE_ERROR", "{got}");
    assert_eq!(
        got["error"]["details"]["reason"], "remote_install_failed",
        "{got}"
    );
    assert_eq!(got["error"]["details"]["stage"], "checksum", "{got}");
    assert!(
        got["error"]["message"]
            .as_str()
            .unwrap()
            .contains("checksum mismatch"),
        "{got}"
    );
    // Only the installer call ran; the archive never reached ssh.
    let mut want = vec!["g", "responder"];
    want.extend(probes());
    want.push("install");
    assert_eq!(kinds(&w), want);
    assert!(!r.installed.exists());
    assert!(!w.client.config_dir().join("trust.toml").exists());
}

#[test]
fn an_installer_that_refuses_is_not_retried_by_streaming() {
    let mut w = World::new();
    let r = remote(&mut w, 127, "72,0");
    let out = pair(&w, Some(&r), &["--install-remote"]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 255, "{got}");
    assert_eq!(
        got["error"]["details"]["reason"], "remote_install_failed",
        "{got}"
    );
    assert_eq!(got["error"]["details"]["stage"], "installer", "{got}");
    assert_eq!(got["error"]["details"]["remote_exit"], 72, "{got}");
    assert!(r.server.requests().is_empty());
    let installs = kinds(&w).iter().filter(|k| **k == "install").count();
    assert_eq!(installs, 1);
    assert!(!r.installed.exists());
}

#[test]
fn a_remote_without_a_release_target_is_remote_arch_unsupported() {
    let mut w = World::new();
    let r = remote(&mut w, 127, "0");
    // Replace the probe with one nothing ships for.
    if cfg!(windows) {
        w.fake.probe_windows("x86");
    } else {
        w.fake.probe_unix("FreeBSD amd64");
    }
    let out = pair(&w, Some(&r), &["--install-remote"]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 255, "{got}");
    assert_eq!(got["error"]["code"], "UNSUPPORTED", "{got}");
    assert_eq!(
        got["error"]["details"]["reason"], "remote_arch_unsupported",
        "{got}"
    );
    assert!(got["error"]["details"]["arch"].is_string(), "{got}");
    assert!(!kinds(&w).contains(&"install"), "{:?}", kinds(&w));
    assert!(r.server.requests().is_empty());
    assert!(!w.client.config_dir().join("trust.toml").exists());
}

#[test]
fn a_windows_remote_gets_the_zip_asset_and_a_powershell_script() {
    let mut w = World::new();
    let r = remote(&mut w, 127, "71,0");
    // Override the probe and the reported path with a Windows remote on ARM.
    w.fake.probe_windows("ARM64");
    let reported = if cfg!(windows) {
        r.installed.clone()
    } else {
        PathBuf::from(r"C:\Users\dave\.local\bin\qsh.exe")
    };
    w.fake.install_report(&reported);
    if !cfg!(windows) {
        // On this machine the reported file cannot exist: the responder
        // call that follows is simply not gated.
        w.fake
            .missing_until(&r.installed, 127)
            .install_touch(&r.installed);
    }
    let asset = format!("qsh-{}-aarch64-pc-windows-msvc.zip", tag());
    r.server.put_release(&tag(), &asset, b"zip bytes", None);
    let out = pair(&w, Some(&r), &["--install-remote"]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 0, "{got}");
    assert_eq!(got["data"]["installed"]["method"], "streamed", "{got}");
    assert_eq!(
        got["data"]["installed"]["path"],
        reported.display().to_string(),
        "{got}"
    );
    assert_eq!(w.fake.install_stdin(1), b"zip bytes");
    assert!(
        r.server.requests().contains(&format!("{}/{asset}", tag())),
        "{:?}",
        r.server.requests()
    );
    let calls = w.fake.calls();
    for call in calls.iter().filter(|c| {
        matches!(
            remote_words(c).first().map(String::as_str),
            Some("sh" | "powershell")
        )
    }) {
        assert_eq!(remote_words(call)[0], "powershell", "{call:?}");
    }
}

#[test]
fn a_too_old_remote_is_upgraded_with_the_flag_and_reported_as_an_upgrade() {
    let mut w = World::new();
    let r = remote(&mut w, 2, "0");
    let out = pair(&w, Some(&r), &["--install-remote"]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 0, "{got}");
    assert_eq!(got["data"]["installed"]["upgraded"], true, "{got}");
    assert_eq!(
        got["data"]["installed"]["method"], "remote_installer",
        "{got}"
    );
}

#[test]
fn without_the_flag_a_run_with_no_terminal_ends_as_it_did_and_runs_nothing_extra() {
    let mut w = World::new();
    let r = remote(&mut w, 127, "0");
    // `--json`: machine mode.
    let out = pair(&w, Some(&r), &[]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 255, "{got}");
    assert_eq!(
        got["error"]["details"]["reason"], "remote_qsh_missing",
        "{got}"
    );
    assert_eq!(kinds(&w), ["g", "responder"]);

    // Human mode with stdin that is not a terminal.
    let mut command = w.client.command(&["pair", "ssh", "box"]);
    let human = command.stdin(Stdio::null()).output().expect("run qsh");
    assert_eq!(exit_code(&human), 255);
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(
        stderr.contains("remote_qsh_missing") || stderr.contains("did not find"),
        "{stderr}"
    );
    assert!(!stderr.contains("[Y/n]"), "{stderr}");
    assert_eq!(kinds(&w), ["g", "responder", "g", "responder"]);
    assert!(!r.installed.exists());
}

#[test]
fn no_install_remote_wins_over_everything_and_conflicts_with_install_remote() {
    let mut w = World::new();
    let r = remote(&mut w, 127, "0");
    let out = pair(&w, Some(&r), &["--no-install-remote"]);
    let got = envelope(&out);
    assert_eq!(exit_code(&out), 255, "{got}");
    assert_eq!(
        got["error"]["details"]["reason"], "remote_qsh_missing",
        "{got}"
    );
    assert_eq!(kinds(&w), ["g", "responder"]);

    let both = pair(&w, Some(&r), &["--install-remote", "--no-install-remote"]);
    assert_eq!(
        exit_code(&both),
        2,
        "{}",
        String::from_utf8_lossy(&both.stderr)
    );
    assert_eq!(kinds(&w), ["g", "responder"], "clap refused before any ssh");
}

/// The real remote script, run under `sh` with a throwaway `HOME`: the
/// archive streamed over stdin is checked, unpacked and renamed into
/// `~/.local/bin`.
#[cfg(unix)]
#[test]
fn remote_install_runs_the_real_stream_script_under_sh() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut w = World::new();
    let r = remote(&mut w, 127, "71,run");
    // A real tar.gz holding a `qsh` member.
    let work = tempfile::tempdir().unwrap();
    let body = b"#!/bin/sh\nexit 0\n";
    std::fs::write(work.path().join("qsh"), body).unwrap();
    let archive_path = work.path().join("a.tar.gz");
    let status = std::process::Command::new("tar")
        .arg("czf")
        .arg(&archive_path)
        .arg("-C")
        .arg(work.path())
        .arg("qsh")
        .status()
        .expect("run tar");
    assert!(status.success());
    let archive = std::fs::read(&archive_path).unwrap();
    r.server.put_release(&tag(), &r.asset, &archive, None);
    w.fake.install_home(w.remote.home_dir());

    let out = pair(&w, Some(&r), &["--install-remote"]);
    let got = envelope(&out);
    assert_eq!(
        exit_code(&out),
        0,
        "{got}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(got["data"]["installed"]["method"], "streamed", "{got}");
    assert_eq!(std::fs::read(&r.installed).unwrap(), body);
    let mode = std::fs::metadata(&r.installed)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "{mode:o}");
    // Nothing else was left in the install directory.
    let names: Vec<_> = std::fs::read_dir(r.installed.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["qsh"], "{names:?}");
}
