//! A stand-in for the system `ssh`, built by `qsh-testkit` for the SSH
//! bootstrap tests (ADR-0044, consequences section). It is a real executable
//! and not a shell script so the same program runs on Linux, macOS and
//! Windows.
//!
//! `qsh_testkit::fake_ssh::FakeSsh` copies this executable into a private
//! directory, writes `fake-ssh.cfg` next to the copy and points
//! `[ssh].program` (or `PATH`) at it. Nothing is read from the environment,
//! so tests that run in one process do not share settings.
//!
//! Every call appends its argv to `argv.<n>` (arguments NUL-terminated, the
//! program name left out) and writes its process id to `last.pid`. Then:
//!
//! - `-G` as the first argument prints the file named by `g_file` (a minimal
//!   `hostname` stanza when unset) and exits with `g_exit` (0).
//! - Anything else is the responder call. It prints `stderr` to stderr, the
//!   file named by `script` to stdout, then, in this order:
//!   - blocks forever when `hang` is set;
//!   - runs a local responder when `respond_bin` is set (below) and exits
//!     with its status;
//!   - copies stdin to the file named by `stdin_log` when that is set, and
//!     exits with `exit` (0).
//!
//! The local responder mode stands in for the remote `qsh pair ssh-respond`.
//! `respond_bin` is the `qsh` to run, `respond_config_dir` and
//! `respond_state_dir` become its `QSH_CONFIG_DIR` and `QSH_STATE_DIR` (the
//! remote account's tree, not the caller's), and its stdin and stdout are
//! the fake's own, so the client talks to it exactly as it would to ssh.
//! The remote command is the words after the destination in the recorded
//! argv, `<remote_qsh> pair ssh-respond`:
//!
//! - By default the first word (what the caller asked the remote shell to
//!   run) is replaced by `respond_bin` and the rest are its arguments.
//! - With `respond_shell=1` the words are joined with single spaces and
//!   handed to a shell, as sshd does: `sh -c` on Unix, `cmd.exe /C` on
//!   Windows. Then the first word must itself name an executable, and its
//!   quoting is what the shell makes of it. `respond_bin` is not used.
//! - With `respond_crlf=1` the responder's stdout is passed on with every
//!   `\n` turned into `\r\n`, as a Windows remote with a translating
//!   console would deliver it.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

fn main() {
    #[cfg(unix)]
    // SAFETY: restoring the default dispositions of two signals at startup,
    // before any thread exists. A test runner may have started this process
    // with SIGINT ignored; the real ssh dies of SIGINT, so this must too.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let dir = exe.parent().expect("exe has a parent directory");
    let cfg = read_cfg(&dir.join("fake-ssh.cfg"));
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    record(dir, &args);
    let _ = fs::write(dir.join("last.pid"), std::process::id().to_string());

    if args.first().map(String::as_str) == Some("-G") {
        match cfg.get("g_file") {
            Some(path) => {
                let bytes = fs::read(path).expect("read g_file");
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(&bytes);
                let _ = out.flush();
            }
            None => print!("hostname 127.0.0.1\nuser fake\nproxyjump none\n"),
        }
        std::process::exit(int(&cfg, "g_exit"));
    }

    if let Some(text) = cfg.get("stderr") {
        eprintln!("{text}");
    }
    if let Some(path) = cfg.get("script") {
        let bytes = fs::read(path).expect("read script");
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(&bytes);
        let _ = out.flush();
    }
    if cfg.get("hang").is_some_and(|v| v == "1") {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
    if cfg.contains_key("respond_bin") {
        std::process::exit(run_local_responder(&cfg, &args));
    }
    if let Some(path) = cfg.get("stdin_log") {
        let mut input = Vec::new();
        let _ = std::io::stdin().lock().read_to_end(&mut input);
        let _ = fs::write(path, input);
    }
    std::process::exit(int(&cfg, "exit"));
}

/// The words of the remote command: everything after the destination
/// operand that follows the first `--`.
fn remote_words(args: &[String]) -> Vec<String> {
    match args.iter().position(|arg| arg == "--") {
        Some(dashes) => args.iter().skip(dashes + 2).cloned().collect(),
        None => Vec::new(),
    }
}

/// Run the local stand-in for the remote `qsh pair ssh-respond` and return
/// the exit status to report.
fn run_local_responder(cfg: &HashMap<String, String>, args: &[String]) -> i32 {
    let words = remote_words(args);
    let flag = |key: &str| cfg.get(key).is_some_and(|v| v == "1");
    let mut command = if flag("respond_shell") {
        shell_command(&words.join(" "))
    } else {
        let mut direct = Command::new(cfg.get("respond_bin").expect("respond_bin"));
        direct.args(words.iter().skip(1));
        direct
    };
    for key in ["respond_config_dir", "respond_state_dir"] {
        assert!(cfg.contains_key(key), "{key} is required with respond_bin");
    }
    command
        .env("QSH_CONFIG_DIR", &cfg["respond_config_dir"])
        .env("QSH_STATE_DIR", &cfg["respond_state_dir"])
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("QSH_LOG")
        .env_remove("RUST_LOG")
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit());
    if !flag("respond_crlf") {
        let status = command.status().expect("start the local responder");
        return status.code().unwrap_or(255);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the local responder");
    let mut pipe = child.stdout.take().expect("responder stdout");
    let mut out = std::io::stdout().lock();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut translated = Vec::with_capacity(n + 8);
        for &b in &chunk[..n] {
            if b == b'\n' {
                translated.push(b'\r');
            }
            translated.push(b);
        }
        let _ = out.write_all(&translated);
        let _ = out.flush();
    }
    child
        .wait()
        .ok()
        .and_then(|status| status.code())
        .unwrap_or(255)
}

#[cfg(unix)]
fn shell_command(line: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(line);
    command
}

#[cfg(windows)]
fn shell_command(line: &str) -> Command {
    use std::os::windows::process::CommandExt as _;
    let mut command = Command::new("cmd.exe");
    command.arg("/C").raw_arg(line);
    command
}

fn int(cfg: &HashMap<String, String>, key: &str) -> i32 {
    cfg.get(key).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// `key=value` lines; the value is everything after the first `=`.
fn read_cfg(path: &Path) -> HashMap<String, String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn record(dir: &Path, args: &[String]) {
    for n in 0.. {
        let path = dir.join(format!("argv.{n}"));
        if let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(path) {
            for arg in args {
                let _ = file.write_all(arg.as_bytes());
                let _ = file.write_all(&[0]);
            }
            return;
        }
    }
}
