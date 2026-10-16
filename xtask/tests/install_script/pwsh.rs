//! Shared plumbing for the Windows-only tests: find a PowerShell and run a
//! script from a temp directory. The scripts under test are embedded with
//! `include_str!` by their modules and written next to the fixture, so the
//! tests do not depend on where the checkout lives or on the machine's
//! execution policy for files from the network.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

/// `pwsh` (PowerShell 7) when it is installed, else the Windows PowerShell
/// that ships with the OS. The scripts are written for both, and
/// `QSH_TEST_POWERSHELL=powershell` runs the suite against Windows PowerShell
/// 5.1 even where `pwsh` exists, which is what `irm | iex` runs by default.
fn powershell() -> &'static str {
    static SHELL: OnceLock<String> = OnceLock::new();
    SHELL.get_or_init(|| {
        if let Ok(shell) = std::env::var("QSH_TEST_POWERSHELL") {
            return shell;
        }
        let has_pwsh = Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command", "exit 0"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        (if has_pwsh { "pwsh" } else { "powershell" }).to_string()
    })
}

/// Writes `body` as `dir/name` and returns the path.
pub fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    path
}

/// `powershell -File script args...`, with the execution policy bypassed so a
/// stricter policy on the machine cannot turn a test into a policy test.
pub fn run_file(script: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(powershell());
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ])
    .arg(script)
    .args(args);
    cmd
}

/// Standard output and standard error joined, lossily.
pub fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
