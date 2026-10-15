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
//!   file named by `script` to stdout, then, in this order, blocks forever
//!   when `hang` is set, copies stdin to the file named by `stdin_log` when
//!   that is set, and exits with `exit` (0).
//!
//! The mode that runs a local `qsh pair ssh-respond` against another
//! `QSH_CONFIG_DIR` belongs to the responder step and is not here yet.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

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
    if let Some(path) = cfg.get("stdin_log") {
        let mut input = Vec::new();
        let _ = std::io::stdin().lock().read_to_end(&mut input);
        let _ = fs::write(path, input);
    }
    std::process::exit(int(&cfg, "exit"));
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
