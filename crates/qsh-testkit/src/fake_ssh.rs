//! The fake `ssh` of the SSH bootstrap tests (ADR-0044, consequences section;
//! `docs/design/testing.md`).
//!
//! No sshd and no OpenSSH configuration are involved: [`FakeSsh`] copies the
//! `qsh-fake-ssh` executable (built from `src/bin/qsh-fake-ssh.rs`, a Rust
//! program rather than a script so Windows runs the same thing) into a
//! private directory, and configures it through a file next to the copy.
//! The tests point `[ssh].program` at [`FakeSsh::program`], or put
//! [`FakeSsh::dir`] first on `PATH`.
//!
//! What a real OpenSSH does and this does not (ProxyJump, agents, encrypted
//! keys, host key prompts, `RemoteCommand` clashes) is covered by the manual
//! campaign, not here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tempfile::TempDir;

const BIN_NAME: &str = "qsh-fake-ssh";

/// A fake `ssh` in its own directory. Dropping it removes the directory.
pub struct FakeSsh {
    dir: TempDir,
    program: PathBuf,
    cfg: BTreeMap<&'static str, String>,
}

impl FakeSsh {
    /// A fresh fake. The `-G` call answers with a minimal `hostname` stanza,
    /// the responder call prints nothing and exits 0, until configured.
    ///
    /// # Panics
    ///
    /// If the `qsh-fake-ssh` executable cannot be found or built.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let name = if cfg!(windows) { "ssh.exe" } else { "ssh" };
        let program = dir.path().join(name);
        std::fs::copy(locate_bin(), &program).expect("copy qsh-fake-ssh");
        Self {
            dir,
            program,
            cfg: BTreeMap::new(),
        }
    }

    /// The fake's executable: what `[ssh].program` should name.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The fake's directory: put it first on `PATH` to have a bare `ssh`
    /// resolve to the fake.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Make the `-G` call print `output`.
    pub fn g_output(&mut self, output: &[u8]) -> &mut Self {
        let path = self.dir().join("g.out");
        std::fs::write(&path, output).expect("write g.out");
        self.set("g_file", path.display().to_string())
    }

    /// Make the `-G` call exit with `code`.
    pub fn g_exit(&mut self, code: i32) -> &mut Self {
        self.set("g_exit", code.to_string())
    }

    /// Make the `-G` call block forever, like an `ssh -G` stuck on a slow
    /// resolver or a hanging `Match exec`. Only a signal ends it.
    pub fn g_hang(&mut self) -> &mut Self {
        self.set("g_hang", "1".to_string())
    }

    /// Make the `-G` call print `text` and a newline to stderr, as the first
    /// thing the fake does after it records its argv. A test reads it on the
    /// caller's stderr to learn where ssh first ran.
    pub fn g_stderr(&mut self, text: &str) -> &mut Self {
        self.set("g_stderr", text.to_string())
    }

    /// Make the responder call wait, after its `stderr` line, until `path`
    /// exists, like an ssh waiting at a prompt for a person. The test
    /// releases it by creating the file.
    pub fn gate_file(&mut self, path: &Path) -> &mut Self {
        self.set("gate_file", path.display().to_string())
    }

    /// Make the responder call record the input mode of its console before it
    /// waits at [`Self::gate_file`], the way an ssh about to ask for a
    /// password would find it. Read the result with [`Self::console_mode`].
    pub fn record_console_mode(&mut self) -> &mut Self {
        let path = self.dir().join("console.mode");
        self.set("console_mode_file", path.display().to_string())
    }

    /// The console input mode the responder call recorded: `Some(None)` when
    /// it had no console to ask, `None` while it has not recorded anything.
    pub fn console_mode(&self) -> Option<Option<u32>> {
        let text = std::fs::read_to_string(self.dir().join("console.mode")).ok()?;
        Some(text.trim().parse().ok())
    }

    /// Make the responder call print `bytes` to stdout first: the remote
    /// shell's rc output, the `hello`, tampered lines.
    pub fn script(&mut self, bytes: &[u8]) -> &mut Self {
        let path = self.dir().join("script.out");
        std::fs::write(&path, bytes).expect("write script.out");
        self.set("script", path.display().to_string())
    }

    /// Make the responder call print `text` and a newline to stderr, as ssh
    /// does with its own diagnostics.
    pub fn stderr(&mut self, text: &str) -> &mut Self {
        self.set("stderr", text.to_string())
    }

    /// Make the responder call exit with `code` after its output.
    pub fn exit(&mut self, code: i32) -> &mut Self {
        self.set("exit", code.to_string())
    }

    /// Make the responder call block forever after its output, like an ssh
    /// waiting at a password prompt. Only a signal ends it.
    pub fn hang(&mut self) -> &mut Self {
        self.set("hang", "1".to_string())
    }

    /// Make the responder call copy its stdin to a file until end of input.
    /// Read the result with [`Self::stdin_log`].
    pub fn record_stdin(&mut self) -> &mut Self {
        let path = self.dir().join("stdin.log");
        self.set("stdin_log", path.display().to_string())
    }

    /// Make the responder call run `qsh_bin pair ssh-respond` against the
    /// tree `config_dir`/`state_dir` (the remote account's, not the caller's)
    /// with the fake's own stdin and stdout, in place of printing a script.
    /// The remote qsh word the caller put in the ssh argv is replaced by
    /// `qsh_bin`; see [`Self::respond_through_shell`] to keep it.
    pub fn run_local_responder(
        &mut self,
        qsh_bin: &Path,
        config_dir: &Path,
        state_dir: &Path,
    ) -> &mut Self {
        self.set("respond_bin", qsh_bin.display().to_string());
        self.set("respond_config_dir", config_dir.display().to_string());
        self.set("respond_state_dir", state_dir.display().to_string())
    }

    /// With [`Self::run_local_responder`]: hand the remote command (the
    /// caller's remote qsh word included, quoting and all) to a shell, as
    /// sshd does: `sh -c` on Unix, `cmd.exe /C` on Windows.
    pub fn respond_through_shell(&mut self) -> &mut Self {
        self.set("respond_shell", "1".to_string())
    }

    /// With [`Self::run_local_responder`]: deliver the responder's stdout
    /// with every `\n` turned into `\r\n`, like a Windows remote whose
    /// console translates line ends.
    pub fn respond_with_crlf(&mut self) -> &mut Self {
        self.set("respond_crlf", "1".to_string())
    }

    /// What the responder call received on stdin; empty before it ended.
    pub fn stdin_log(&self) -> Vec<u8> {
        std::fs::read(self.dir().join("stdin.log")).unwrap_or_default()
    }

    /// The arguments of every call so far, oldest first, program name left
    /// out. Empty when ssh was never run.
    pub fn calls(&self) -> Vec<Vec<String>> {
        let mut calls = Vec::new();
        for n in 0.. {
            let Ok(bytes) = std::fs::read(self.dir().join(format!("argv.{n}"))) else {
                break;
            };
            let mut args: Vec<String> = bytes
                .split(|b| *b == 0)
                .map(|arg| String::from_utf8_lossy(arg).into_owned())
                .collect();
            // Every argument is NUL-terminated, so the split leaves one
            // empty tail.
            args.pop();
            calls.push(args);
        }
        calls
    }

    /// The process id of the most recent call, once it started. Polls until
    /// `within` has passed.
    pub fn wait_for_pid(&self, within: Duration) -> Option<u32> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(pid) = std::fs::read_to_string(self.dir().join("last.pid"))
                .ok()
                .and_then(|text| text.trim().parse().ok())
            {
                return Some(pid);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn set(&mut self, key: &'static str, value: String) -> &mut Self {
        self.cfg.insert(key, value);
        let text: String = self.cfg.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        std::fs::write(self.dir().join("fake-ssh.cfg"), text).expect("write fake-ssh.cfg");
        self
    }
}

impl Default for FakeSsh {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the `qsh-fake-ssh` executable cargo built for this workspace
/// ([`crate::testbin::locate`]: `QSH_FAKE_SSH_BIN`, then next to the running
/// test executable, then one `cargo build`).
fn locate_bin() -> PathBuf {
    crate::testbin::locate(BIN_NAME, "QSH_FAKE_SSH_BIN")
}
