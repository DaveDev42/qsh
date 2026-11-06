//! Unit tests of the remote install helpers that need no process: the
//! platform tables, the consent order, the checksum rule, the remote
//! scripts' text. The whole flow runs against the fake ssh in
//! `qsh-cli/tests/it/remote_install.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;

use super::fetch::checksum_for;
use super::scripts::{self, powershell_words};
use super::*;
use crate::prompts::Prompt;

fn source() -> ReleaseSource {
    ReleaseSource::new("DaveDev42/qsh").unwrap()
}

#[test]
fn uname_maps_to_the_release_targets_and_refuses_the_rest() {
    for (text, target) in [
        ("Linux x86_64\n", "x86_64-unknown-linux-gnu"),
        ("Linux aarch64\n", "aarch64-unknown-linux-gnu"),
        ("Linux arm64\n", "aarch64-unknown-linux-gnu"),
        ("Darwin arm64\n", "aarch64-apple-darwin"),
        ("Darwin x86_64\n", "x86_64-apple-darwin"),
        ("\n  Linux amd64  \n", "x86_64-unknown-linux-gnu"),
    ] {
        let platform = platform_from_uname(text).unwrap_or_else(|e| panic!("{text:?}: {e:?}"));
        assert_eq!(platform.target, target, "{text:?}");
        assert!(!platform.windows);
    }
    for text in [
        "FreeBSD amd64",
        "Linux riscv64",
        "Linux armv7l",
        "Darwin i386",
        "MINGW64_NT-10.0 x86_64",
        "",
    ] {
        assert!(platform_from_uname(text).is_err(), "{text:?}");
    }
    // Remote-authored words are cut to printable characters.
    let (os, arch) = platform_from_uname("Odd\x1b[31mOS arch\u{202e}x").unwrap_err();
    assert!(os.chars().all(|c| c.is_ascii_graphic()), "{os:?}");
    assert!(arch.chars().all(|c| c.is_ascii_graphic()), "{arch:?}");
}

#[test]
fn the_windows_probe_maps_amd64_and_arm64_and_prefers_the_wow_variable() {
    let ver = "Microsoft Windows [Version 10.0.26100.1]";
    for (tail, target) in [
        (
            "AMD64\r\n%PROCESSOR_ARCHITEW6432%",
            "x86_64-pc-windows-msvc",
        ),
        (
            "ARM64\r\n%PROCESSOR_ARCHITEW6432%",
            "aarch64-pc-windows-msvc",
        ),
        // A 32-bit shell on 64-bit Windows says x86 and names the machine
        // in the second variable.
        ("x86\r\nAMD64", "x86_64-pc-windows-msvc"),
        ("x86\r\nARM64", "aarch64-pc-windows-msvc"),
    ] {
        let text = format!("\r\n{ver}\r\n{tail}\r\n");
        let platform = platform_from_windows(&text).unwrap_or_else(|e| panic!("{text:?}: {e:?}"));
        assert_eq!(platform.target, target, "{text:?}");
        assert!(platform.windows);
    }
    assert!(platform_from_windows(&format!("{ver}\nx86\n%PROCESSOR_ARCHITEW6432%")).is_err());
    assert!(platform_from_windows("AMD64\nAMD64").is_err());
}

#[test]
fn an_unsupported_remote_is_remote_arch_unsupported_with_no_new_code() {
    let err = arch_unsupported("FreeBSD", "amd64");
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert_eq!(err.details["reason"], "remote_arch_unsupported");
    assert_eq!(err.details["os"], "FreeBSD");
    assert_eq!(err.details["arch"], "amd64");
    assert!(!err.retryable);
}

#[test]
fn asset_names_follow_the_release_contract() {
    let unix = platform_from_uname("Linux x86_64").unwrap();
    assert_eq!(
        unix.asset_name("v1.2.3"),
        "qsh-v1.2.3-x86_64-unknown-linux-gnu.tar.gz"
    );
    let win = platform_from_windows("Microsoft Windows [x]\nARM64\nx").unwrap();
    assert_eq!(
        win.asset_name("v1.2.3"),
        "qsh-v1.2.3-aarch64-pc-windows-msvc.zip"
    );
    assert_eq!(release_tag(), format!("v{}", env!("CARGO_PKG_VERSION")));
}

#[test]
fn only_the_two_responder_failures_are_installable() {
    let err = |reason: &str| {
        OpError::new(ErrorCode::RemoteError, "x").with_details(json!({ "reason": reason }))
    };
    assert_eq!(
        InstallReason::of(&err("remote_qsh_missing")),
        Some(InstallReason::Missing)
    );
    assert_eq!(
        InstallReason::of(&err("remote_qsh_too_old")),
        Some(InstallReason::TooOld)
    );
    for other in ["remote_command_failed", "ssh_failed", "bootstrap_protocol"] {
        assert_eq!(InstallReason::of(&err(other)), None, "{other}");
    }
    assert_eq!(
        InstallReason::of(&OpError::new(ErrorCode::RemoteError, "x")),
        None
    );
}

/// Records what it was asked and answers a fixed way.
struct Scripted {
    answer: Option<bool>,
    asked: AtomicUsize,
    last: std::sync::Mutex<Option<(&'static str, String)>>,
}

impl Scripted {
    fn new(answer: Option<bool>) -> Self {
        Self {
            answer,
            asked: AtomicUsize::new(0),
            last: Default::default(),
        }
    }
}

impl Prompter for Scripted {
    fn ask(&self, prompt: &Prompt) -> Option<bool> {
        self.ask_text(prompt, prompt.question)
    }

    fn ask_text(&self, prompt: &Prompt, question: &str) -> Option<bool> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = Some((prompt.id, question.to_string()));
        self.answer
    }
}

#[test]
fn a_flag_decides_before_the_prompter_is_consulted() {
    for reason in [InstallReason::Missing, InstallReason::TooOld] {
        let asked_yes = Scripted::new(Some(true));
        assert!(!consent(InstallRemote::No, &asked_yes, reason, "box", "v1"));
        assert_eq!(asked_yes.asked.load(Ordering::SeqCst), 0);

        let asked_no = Scripted::new(Some(false));
        assert!(consent(InstallRemote::Yes, &asked_no, reason, "box", "v1"));
        assert_eq!(asked_no.asked.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn without_a_flag_the_answer_is_the_prompt_and_not_asked_means_no() {
    let yes = Scripted::new(Some(true));
    assert!(consent(
        InstallRemote::Ask,
        &yes,
        InstallReason::Missing,
        "box",
        "v1.2.3"
    ));
    let (id, text) = yes.last.lock().unwrap().clone().unwrap();
    assert_eq!(id, "ssh.install_remote");
    assert!(text.contains("box has no qsh"), "{text}");
    assert!(text.contains("v1.2.3"), "{text}");
    assert!(text.contains("~/.local/bin"), "{text}");
    assert!(text.contains("serve"), "{text}");

    let no = Scripted::new(Some(false));
    assert!(!consent(
        InstallRemote::Ask,
        &no,
        InstallReason::TooOld,
        "box",
        "v1"
    ));
    assert_eq!(
        no.last.lock().unwrap().clone().unwrap().0,
        "ssh.upgrade_remote"
    );

    // No terminal, `--json`: the prompter says "not asked".
    let silent = Scripted::new(None);
    assert!(!consent(
        InstallRemote::Ask,
        &silent,
        InstallReason::Missing,
        "box",
        "v1"
    ));
    assert!(!consent(
        InstallRemote::Ask,
        &crate::prompts::NoPrompter,
        InstallReason::TooOld,
        "box",
        "v1"
    ));
}

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn checksum_for_is_fail_closed_like_the_installer() {
    let asset = "qsh-v1-x86_64-unknown-linux-gnu.tar.gz";
    let good = format!("{DIGEST}  {asset}\n{DIGEST}  other.tar.gz\n");
    assert_eq!(checksum_for(&good, asset).unwrap(), DIGEST);
    // Binary-mode marker and upper case are accepted, and lowered.
    let marked = format!("{}  *{asset}\n", DIGEST.to_ascii_uppercase());
    assert_eq!(checksum_for(&marked, asset).unwrap(), DIGEST);

    for (name, sums) in [
        ("no entry", format!("{DIGEST}  other.tar.gz\n")),
        (
            "duplicate",
            format!("{DIGEST}  {asset}\n{DIGEST}  {asset}\n"),
        ),
        ("short digest", format!("abc123  {asset}\n")),
        ("not hex", format!("{}  {asset}\n", "z".repeat(64))),
        // A name that only contains the asset's name is another file.
        ("substring", format!("{DIGEST}  x{asset}\n")),
        ("empty", String::new()),
    ] {
        let err = checksum_for(&sums, asset).expect_err(name);
        assert_eq!(err.details["reason"], "remote_install_failed", "{name}");
        assert_eq!(err.details["stage"], "checksum", "{name}");
    }
}

#[test]
fn the_release_source_defaults_to_github_and_validates_what_reaches_a_remote() {
    let github = source();
    assert_eq!(
        github.assets_url("v1"),
        "https://github.com/DaveDev42/qsh/releases/download/v1"
    );
    assert_eq!(
        github.installer_url("v1", false),
        "https://raw.githubusercontent.com/DaveDev42/qsh/v1/scripts/install.sh"
    );
    assert!(
        github
            .installer_url("v1", true)
            .ends_with("/scripts/install.ps1")
    );

    let mirror = source().with_base_url("http://127.0.0.1:9/m/").unwrap();
    assert_eq!(mirror.assets_url("v1"), "http://127.0.0.1:9/m/v1");
    assert_eq!(
        mirror.installer_url("v1", true),
        "http://127.0.0.1:9/m/v1/install.ps1"
    );

    for bad in ["a b", "a;b", "a'b", "a$b", "", "a\"b"] {
        assert!(ReleaseSource::new(bad).is_err(), "{bad:?}");
    }
    for bad in [
        "ftp://x",
        "http://x/a b",
        "http://x/'",
        "http://x/$(id)",
        "http://x/;",
    ] {
        assert!(source().with_base_url(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn only_an_absolute_qsh_path_of_printable_characters_is_accepted() {
    assert!(valid_installed_path("/home/dave/.local/bin/qsh", false));
    assert!(valid_installed_path(
        r"C:\Users\dave\.local\bin\qsh.exe",
        true
    ));
    for (path, windows) in [
        ("", false),
        ("qsh", false),
        ("bin/qsh", false),
        ("/home/dave/.local/bin/other", false),
        ("/home/dave/qsh\n", false),
        ("/home/dave/\x1b[0m/qsh", false),
        (r"C:\Users\dave\qsh", true),
        (r"\Users\dave\qsh.exe", true),
        ("/home/dave/.local/bin/qsh", true),
        (r"C:\Users\dave\.local\bin\qsh.exe", false),
    ] {
        assert!(!valid_installed_path(path, windows), "{path:?} {windows}");
    }
}

#[test]
fn install_exit_codes_map_to_remote_install_failed_with_the_stage() {
    for code in [72, 74, 75, 76, 77, 78, 3] {
        let err = exit_error(code, "stream");
        assert_eq!(err.code, ErrorCode::RemoteError);
        assert_eq!(err.details["reason"], "remote_install_failed");
        assert_eq!(err.details["stage"], "stream");
        assert_eq!(err.details["remote_exit"], code);
    }
    assert!(
        exit_error(76, "stream")
            .message
            .contains("nothing was installed")
    );
}

#[test]
fn the_unix_scripts_are_one_line_without_single_quotes_and_never_use_sudo() {
    let words = scripts::unix_installer_words(&source(), "v1.2.3");
    let stream = scripts::unix_stream_words(DIGEST);
    for words in [&words, &stream] {
        assert_eq!(&words[..2], ["sh", "-c"]);
        let quoted = &words[2];
        assert!(
            quoted.starts_with('\'') && quoted.ends_with('\''),
            "{quoted}"
        );
        let inner = &quoted[1..quoted.len() - 1];
        assert!(!inner.contains('\''), "{inner}");
        assert!(!inner.contains('\n'), "{inner}");
        assert!(!inner.contains("sudo"), "{inner}");
        assert!(inner.contains("$HOME/.local/bin"), "{inner}");
    }
    let installer = &words[2];
    assert!(installer.contains("QSH_VERSION=v1.2.3"), "{installer}");
    assert!(installer.contains("QSH_REPO=DaveDev42/qsh"), "{installer}");
    assert!(
        installer.contains("raw.githubusercontent.com/DaveDev42/qsh/v1.2.3/scripts/install.sh"),
        "{installer}"
    );
    assert!(installer.contains("exit 71"), "{installer}");
    let streamed = &stream[2];
    assert!(streamed.contains(DIGEST), "{streamed}");
    assert!(streamed.contains("mv -f"), "{streamed}");
}

/// Syntax-check the Unix scripts with the platform `sh` (`-n` parses
/// without running anything).
#[cfg(unix)]
#[test]
fn the_unix_scripts_parse_under_sh() {
    for words in [
        scripts::unix_installer_words(&source(), "v1.2.3"),
        scripts::unix_stream_words(DIGEST),
    ] {
        let script = words[2]
            .strip_prefix('\'')
            .and_then(|s| s.strip_suffix('\''))
            .unwrap();
        let out = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(script)
            .output()
            .expect("run sh -n");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn decode_powershell(words: &[String]) -> String {
    assert_eq!(words[0], "powershell");
    assert_eq!(words[words.len() - 2], "-EncodedCommand");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(words.last().unwrap())
        .unwrap();
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).unwrap()
}

#[test]
fn the_windows_scripts_travel_as_one_encoded_token_that_fits_a_command_line() {
    let installer = scripts::windows_installer_words(&source(), "v1.2.3");
    let stream = scripts::windows_stream_words(DIGEST);
    for words in [&installer, &stream] {
        // Every word is plain to cmd.exe, PowerShell and POSIX shells alike.
        for word in words.iter() {
            assert!(
                word.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '/' | '=')),
                "{word}"
            );
        }
        // cmd.exe's command line limit is 8191 characters.
        let total: usize = words.iter().map(|w| w.len() + 1).sum();
        assert!(total < 8000, "{total}");
    }
    let text = decode_powershell(&installer);
    assert!(text.contains("QSH_VERSION='v1.2.3'"), "{text}");
    assert!(text.contains("install.ps1"), "{text}");
    assert!(text.contains("QSH_NO_MODIFY_PATH='1'"), "{text}");
    assert!(text.contains("exit 71"), "{text}");
    let text = decode_powershell(&stream);
    assert!(text.contains(DIGEST), "{text}");
    assert!(text.contains("exit 76"), "{text}");
    assert!(text.contains("OpenStandardInput"), "{text}");
    assert!(!text.to_ascii_lowercase().contains("sudo"), "{text}");
    // The encoder is plain UTF-16LE base64.
    assert_eq!(
        decode_powershell(&powershell_words("Write-Output 'é'")),
        "Write-Output 'é'"
    );
}

/// Run the real streamed-install script under `sh` with a throwaway `HOME`:
/// the remote re-checks the digest and installs nothing on a mismatch.
#[cfg(unix)]
mod remote_script {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    use super::*;

    fn run(digest: &str, archive: &[u8], home: &std::path::Path) -> (i32, String) {
        let words = scripts::unix_stream_words(digest);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(words.join(" "))
            .env("HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(archive).unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    fn tarball() -> Vec<u8> {
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("qsh"), b"binary").unwrap();
        let out = work.path().join("a.tgz");
        let status = Command::new("tar")
            .arg("czf")
            .arg(&out)
            .arg("-C")
            .arg(work.path())
            .arg("qsh")
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::read(out).unwrap()
    }

    #[test]
    fn a_digest_mismatch_on_the_remote_exits_76_and_installs_nothing() {
        let home = tempfile::tempdir().unwrap();
        let (code, stdout) = run(DIGEST, &tarball(), home.path());
        assert_eq!(code, scripts::EXIT_SHA_MISMATCH);
        assert!(!stdout.contains("QSH_INSTALLED"), "{stdout}");
        assert!(!home.path().join(".local/bin/qsh").exists());
    }

    #[test]
    fn a_matching_archive_is_renamed_into_place_and_reported() {
        let home = tempfile::tempdir().unwrap();
        let archive = tarball();
        let digest = super::fetch::sha256_bytes(&archive);
        let (code, stdout) = run(&digest, &archive, home.path());
        assert_eq!(code, 0, "{stdout}");
        let installed = home.path().join(".local/bin/qsh");
        assert_eq!(std::fs::read(&installed).unwrap(), b"binary");
        assert_eq!(
            stdout.trim(),
            format!("QSH_INSTALLED={}", installed.display())
        );
    }

    #[test]
    fn garbage_with_the_right_digest_is_a_bad_archive_and_installs_nothing() {
        let home = tempfile::tempdir().unwrap();
        let junk = b"not a tarball";
        let digest = super::fetch::sha256_bytes(junk);
        let (code, _) = run(&digest, junk, home.path());
        assert_eq!(code, scripts::EXIT_BAD_ARCHIVE);
        assert!(!home.path().join(".local/bin/qsh").exists());
    }
}

/// Threat model A19: the install question tells the user that connecting also
/// starts a serve (a UDP listener) on the remote, and the upgrade question
/// that a running serve is left alone.
#[test]
fn the_install_question_names_the_serve_it_will_start() {
    let missing = question(InstallReason::Missing, "box", "v1.2.3");
    assert!(missing.contains("box has no qsh"), "{missing}");
    assert!(missing.contains("v1.2.3"), "{missing}");
    assert!(missing.contains("start a serve"), "{missing}");
    let old = question(InstallReason::TooOld, "box", "v1.2.3");
    assert!(old.contains("running serve is left alone"), "{old}");
}
