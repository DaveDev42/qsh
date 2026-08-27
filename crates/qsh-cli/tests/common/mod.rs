//! Shared subprocess helpers for the `qsh-cli` integration tests
//! (`docs/design/testing.md` L6).
//!
//! Every test gets its own [`Sandbox`] — a private `QSH_CONFIG_DIR` /
//! `QSH_STATE_DIR` pair — and always asks for `--key-store file`, so the
//! suite never touches the developer's real config directory or the OS
//! credential store. [`ServeGuard`] runs a real `qsh serve` child on
//! `127.0.0.1:0` and [`Fleet`] wires a host and a client together the way
//! `docs/ROADMAP.md` M1 describes: two identities, each pinning the other.
//!
//! Nothing here sleeps for correctness: the only wait is a bounded
//! `recv_timeout` on the `qsh serve: listening on …` line.

// This module is compiled into several test binaries; each one uses a
// different subset of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;

/// The client's alias for the serving host (`qsh exec box …`).
pub const HOST_ALIAS: &str = "box";

/// The host's alias for the client — it authenticates as `device:laptop`,
/// which is what the audit records show.
pub const CLIENT_ALIAS: &str = "laptop";

/// The principal the host records for [`CLIENT_ALIAS`].
pub const CLIENT_PRINCIPAL: &str = "device:laptop";

/// How long we are willing to wait for `qsh serve` to report its bound
/// address before declaring the test broken.
const SERVE_START_TIMEOUT: Duration = Duration::from_secs(10);

/// The stderr line `qsh serve` prints once it is listening
/// (`docs/CLI.md` §6.12).
const LISTENING_PREFIX: &str = "qsh serve: listening on ";

/// The second stderr line `qsh serve` prints at startup.
const IDENTITY_PREFIX: &str = "qsh serve: identity ";

/// An isolated `qsh` config/state directory pair plus the subprocess
/// plumbing to run the binary against it.
pub struct Sandbox {
    _dir: TempDir,
    config: PathBuf,
    state: PathBuf,
}

impl Sandbox {
    /// A fresh, empty sandbox (no identity yet).
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("config");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&config).expect("create config dir");
        std::fs::create_dir_all(&state).expect("create state dir");
        Self {
            _dir: dir,
            config,
            state,
        }
    }

    /// A sandbox that already ran `qsh init --key-store file`.
    pub fn initialized() -> Self {
        let sandbox = Self::new();
        sandbox.init();
        sandbox
    }

    /// This sandbox's `QSH_CONFIG_DIR`.
    pub fn config_dir(&self) -> &Path {
        &self.config
    }

    /// This sandbox's `QSH_STATE_DIR` (where `audit.log` lands).
    pub fn state_dir(&self) -> &Path {
        &self.state
    }

    /// A `qsh` [`Command`] with the environment scrubbed of anything that
    /// could redirect it at the developer's real configuration.
    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_qsh"));
        command
            .args(args)
            .env("QSH_CONFIG_DIR", &self.config)
            .env("QSH_STATE_DIR", &self.state)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            // `host.list`'s reverse source scans `Paths::runtime_dir()` for
            // `<pid>.sock` candidates (`docs/design/architecture.md` §7):
            // without this, a sandboxed test would inherit whatever
            // `XDG_RUNTIME_DIR` the CI runner/dev box happens to export and
            // could stumble onto an unrelated process's socket there.
            // Scrubbed here so every sandbox falls back deterministically
            // to `<state_dir>/run` (`Paths::runtime_dir`'s documented
            // two-tier rule) — the same reason `localctl_perms.rs`'s
            // `ListenGuard` scrubs it for its own `qsh listen` child.
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("QSH_LOG")
            .env_remove("RUST_LOG");
        command
    }

    /// Run `qsh` to completion with no stdin.
    pub fn qsh(&self, args: &[&str]) -> Output {
        self.command(args)
            .stdin(Stdio::null())
            .output()
            .expect("failed to run qsh")
    }

    /// Run `qsh` to completion, feeding `input` on stdin (a pipe, so the
    /// CLI forwards it to the remote command).
    pub fn qsh_with_stdin(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn qsh");
        child
            .stdin
            .take()
            .expect("stdin pipe")
            .write_all(input)
            .expect("write stdin");
        child.wait_with_output().expect("wait for qsh")
    }

    /// Run `qsh` in JSON mode and assert stdout is exactly one `qsh.cli/v1`
    /// line. Returns `(exit code, envelope)`.
    pub fn json(&self, args: &[&str]) -> (i32, Value) {
        let output = self.qsh(args);
        let value = sole_envelope(&output.stdout, args);
        (exit_code(&output), value)
    }

    /// `qsh init --key-store file --json`, asserted to succeed.
    pub fn init(&self) -> Value {
        let (code, value) = self.json(&["init", "--json", "--key-store", "file"]);
        assert_eq!(code, 0, "init failed: {value}");
        value
    }

    /// This sandbox's device fingerprint (initializing it if needed).
    pub fn fingerprint(&self) -> String {
        self.init()["data"]["fingerprint"]
            .as_str()
            .expect("fingerprint")
            .to_string()
    }

    /// Pin `name` without connecting (`docs/CLI.md` §6.11).
    pub fn trust_add(&self, name: &str, address: Option<&str>, fingerprint: &str) {
        let mut args = vec!["trust", "add", name, "--fingerprint", fingerprint, "--json"];
        if let Some(address) = address {
            args.extend_from_slice(&["--address", address]);
        }
        let (code, value) = self.json(&args);
        assert_eq!(code, 0, "trust add {name} failed: {value}");
    }

    /// Every audit record written so far, oldest first. An absent log is an
    /// empty list — the file is created lazily on the first decision.
    pub fn audit_records(&self) -> Vec<Value> {
        let path = self.state.join("audit.log");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        text.lines()
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("audit line is not JSON: {e}: {line:?}"))
            })
            .collect()
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

/// The exit code of a finished child, which on Unix is absent only when it
/// died of a signal — never expected here.
pub fn exit_code(output: &Output) -> i32 {
    output
        .status
        .code()
        .unwrap_or_else(|| panic!("qsh was killed by a signal: {:?}", output.status))
}

/// Parse stdout as exactly one `qsh.cli/v1` envelope (`docs/CLI.md` §2.2:
/// every machine-mode stdout line is pure JSON).
pub fn sole_envelope(stdout: &[u8], args: &[&str]) -> Value {
    let stdout = std::str::from_utf8(stdout).expect("stdout must be utf-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one JSON line for {args:?}, got {stdout:?}"
    );
    let value: Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("stdout is not JSON for {args:?}: {e}: {stdout:?}"));
    assert_eq!(value["schema"], "qsh.cli/v1", "for {args:?}");
    assert!(
        value["request_id"].as_str().is_some(),
        "missing request_id for {args:?}"
    );
    value
}

/// Everything a finished [`ServeGuard`] captured.
pub struct ServeOutput {
    /// Raw stdout bytes. Must always be empty (`docs/CLI.md` §6.12).
    pub stdout: Vec<u8>,
    /// stderr, split into lines.
    pub stderr: Vec<String>,
}

impl ServeOutput {
    /// Whether any stderr line starts with `prefix`.
    pub fn has_stderr_line_starting_with(&self, prefix: &str) -> bool {
        self.stderr.iter().any(|line| line.starts_with(prefix))
    }
}

/// A running `qsh serve` child bound to `127.0.0.1:0`, killed on drop.
pub struct ServeGuard {
    child: Child,
    addr: String,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<String>>>,
    readers: Vec<JoinHandle<()>>,
}

impl ServeGuard {
    /// Start `qsh serve --bind 127.0.0.1:0` in `host` and wait (bounded)
    /// for it to report the address it actually bound.
    pub fn start(host: &Sandbox) -> Self {
        Self::start_with(host, &[])
    }

    /// Like [`start`](Self::start) with extra leading arguments (e.g.
    /// `-vv`).
    pub fn start_with(host: &Sandbox, extra: &[&str]) -> Self {
        let mut args: Vec<&str> = extra.to_vec();
        args.extend_from_slice(&["serve", "--bind", "127.0.0.1:0"]);
        let mut child = host
            .command(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn qsh serve");

        let stdout_pipe = child.stdout.take().expect("serve stdout pipe");
        let stderr_pipe = child.stderr.take().expect("serve stderr pipe");

        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = mpsc::channel::<String>();

        let mut readers = Vec::with_capacity(2);
        readers.push({
            let sink = Arc::clone(&stdout);
            thread::spawn(move || {
                let mut pipe = stdout_pipe;
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                sink.lock().unwrap_or_else(|e| e.into_inner()).extend(buf);
            })
        });
        readers.push({
            let sink = Arc::clone(&stderr);
            thread::spawn(move || {
                for line in BufReader::new(stderr_pipe).lines().map_while(Result::ok) {
                    if let Some(addr) = line.strip_prefix(LISTENING_PREFIX) {
                        let _ = tx.send(addr.to_string());
                    }
                    sink.lock().unwrap_or_else(|e| e.into_inner()).push(line);
                }
            })
        });

        let addr = rx.recv_timeout(SERVE_START_TIMEOUT).unwrap_or_else(|err| {
            let lines = stderr.lock().unwrap_or_else(|e| e.into_inner()).join("\n");
            panic!("qsh serve never reported a bound address ({err}); stderr:\n{lines}")
        });

        Self {
            child,
            addr,
            stdout,
            stderr,
            readers,
        }
    }

    /// The `host:port` the child actually bound.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The child's process id, for a test that has to stop the host
    /// answering (`SIGSTOP`) rather than take it away.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Send `signal` to the child — unlike [`finish`](Self::finish), this
    /// does not kill it, so a caller testing a *graceful* shutdown path
    /// (SIGTERM drain, `docs/CLI.md` §6.12) can watch the child exit on its
    /// own. Unix only: `nix` (this crate's `[target.'cfg(unix)']`
    /// dependency) is not linked on Windows, exactly like
    /// `session_kill9.rs`'s own signal use.
    #[cfg(unix)]
    pub fn signal(&self, signal: nix::sys::signal::Signal) {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(self.child.id() as i32), signal);
    }

    /// Wait up to `timeout` for the child to exit **on its own** — no kill.
    /// `Some` once it has, `None` if `timeout` passed first. Complements
    /// [`signal`](Self::signal): send SIGTERM, then bound how long the
    /// drain it triggers is allowed to take.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Everything the child wrote, once it is known to be gone (after
    /// [`wait_timeout`](Self::wait_timeout) returned `Some`) — joins the
    /// reader threads without touching the process itself, unlike
    /// [`finish`](Self::finish).
    pub fn captured(&mut self) -> ServeOutput {
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        ServeOutput {
            stdout: self
                .stdout
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            stderr: self
                .stderr
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }

    /// Stop the child and return everything it wrote. Idempotent.
    pub fn finish(&mut self) -> ServeOutput {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        ServeOutput {
            stdout: self
                .stdout
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            stderr: self
                .stderr
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }
}

impl Drop for ServeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

/// A host running `qsh serve` plus a client that is pinned by it and pins
/// it back — the minimal two-identity setup M1's acceptance criteria
/// describe.
pub struct Fleet {
    /// The serving side.
    pub host: Sandbox,
    /// The dialing side; knows the host as [`HOST_ALIAS`].
    pub client: Sandbox,
    /// The running `qsh serve` child.
    pub serve: ServeGuard,
    /// The host's device fingerprint.
    pub host_fingerprint: String,
    /// The client's device fingerprint.
    pub client_fingerprint: String,
}

impl Fleet {
    /// Bring up the pair. The host pins the client *before* the listener
    /// starts, so no test depends on when the trust store is re-read.
    pub fn start() -> Self {
        Self::start_with(&[])
    }

    /// Like [`start`](Self::start), passing `extra` arguments to `qsh serve`.
    pub fn start_with(extra: &[&str]) -> Self {
        let host = Sandbox::new();
        let client = Sandbox::new();
        let host_fingerprint = host.fingerprint();
        let client_fingerprint = client.fingerprint();

        host.trust_add(CLIENT_ALIAS, None, &client_fingerprint);
        let serve = ServeGuard::start_with(&host, extra);
        client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fingerprint);

        Self {
            host,
            client,
            serve,
            host_fingerprint,
            client_fingerprint,
        }
    }

    /// The address the host is listening on.
    pub fn addr(&self) -> &str {
        self.serve.addr()
    }

    /// A third identity that pins the host but is *not* pinned by it — the
    /// untrusted peer of M1's second acceptance criterion.
    pub fn rogue(&self) -> Sandbox {
        let rogue = Sandbox::new();
        rogue.init();
        rogue.trust_add(HOST_ALIAS, Some(self.addr()), &self.host_fingerprint);
        rogue
    }

    /// Run `qsh exec box …` from the client in JSON mode.
    pub fn exec_json(&self, extra: &[&str]) -> (i32, Value) {
        let mut args = vec!["exec", HOST_ALIAS, "--json"];
        args.extend_from_slice(extra);
        self.client.json(&args)
    }
}

/// The complete set of keys a `qsh_core::audit::AuditRecord` may carry (`docs/design/architecture.md` §6). Anything else would mean a
/// payload field leaked into the audit log.
pub const AUDIT_KEYS: &[&str] = &[
    "ts",
    "request_id",
    "principal",
    "auth_path",
    "action",
    "resource",
    "decision",
    "rule",
    "peer_addr",
];

/// The stderr line `qsh listen` prints once it is up (`main.rs`'s
/// `run_listen`) — shared by every test binary that spawns a real `qsh
/// listen` process (`hosts_reverse.rs`, `localctl_perms.rs` each keep
/// their own private copy of this constant and the guard below for
/// reasons documented in their own module docs; this `pub` copy is for
/// `reverse_e2e.rs`, `exit_code_matrix.rs` and `jsonl_purity.rs`, which
/// have no such reason to duplicate it three more times).
#[cfg(unix)]
const LISTEN_LISTENING_PREFIX: &str = "qsh listen: listening on ";

/// How long we wait for `qsh listen` to report its bound address —
/// mirrors [`ServeGuard`]'s own budget.
#[cfg(unix)]
const LISTEN_START_TIMEOUT: Duration = Duration::from_secs(10);

/// A running real `qsh listen` child (the reverse-mode controller),
/// killed on drop.
#[cfg(unix)]
pub struct ListenGuard {
    child: Child,
    addr: String,
}

#[cfg(unix)]
impl ListenGuard {
    /// Start `qsh listen --bind 127.0.0.1:0` in `sandbox` and wait
    /// (bounded) for it to report the address it actually bound.
    pub fn start(sandbox: &Sandbox) -> Self {
        Self::start_with(sandbox, "127.0.0.1:0")
    }

    /// Like [`start`](Self::start), with an explicit `--bind` value —
    /// e.g. a fixed port, to provoke a real `EADDRINUSE` bind conflict.
    pub fn start_with(sandbox: &Sandbox, bind: &str) -> Self {
        let mut child = sandbox
            .command(&["listen", "--bind", bind])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn qsh listen");

        if let Some(mut out) = child.stdout.take() {
            thread::spawn(move || {
                let _ = std::io::copy(&mut out, &mut std::io::sink());
            });
        }

        let stderr = child.stderr.take().expect("listen stderr pipe");
        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Some(addr) = line.strip_prefix(LISTEN_LISTENING_PREFIX) {
                    let _ = tx.send(addr.to_string());
                }
            }
        });
        let addr = rx
            .recv_timeout(LISTEN_START_TIMEOUT)
            .expect("qsh listen never reported a bound address");

        Self { child, addr }
    }

    /// Attempt to start `qsh listen --bind <bind>`, but do not block
    /// waiting for a "listening on" line — for a bind-conflict scenario
    /// where the child is expected to fail setup and exit instead.
    /// Returns the finished [`Output`] once the child exits (bounded).
    pub fn run_to_completion(sandbox: &Sandbox, bind: &str, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = extra.to_vec();
        args.extend_from_slice(&["listen", "--bind", bind]);
        sandbox.qsh(&args)
    }

    /// The `host:port` the child actually bound.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

#[cfg(unix)]
impl Drop for ListenGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A running real `qsh reverse` child (the reverse-mode target), killed on
/// drop. [`Self::shut_down`] sends `SIGTERM` and waits (bounded) for the
/// graceful-shutdown path so a caller does not have to wait out QUIC's
/// idle timeout for a clean disconnect to register (mirrors
/// `hosts_reverse.rs`'s own private `ReverseGuard`).
#[cfg(unix)]
pub struct ReverseGuard {
    child: Child,
}

#[cfg(unix)]
impl ReverseGuard {
    /// `qsh reverse <controller>` in `sandbox`. Never blocks waiting for
    /// registration to succeed — the target retries forever on its own
    /// (`docs/design/protocol.md` §11-4), so callers poll the
    /// *controller's* view (`hosts_array`) instead.
    pub fn start(sandbox: &Sandbox, controller: &str) -> Self {
        Self::start_with(sandbox, &["reverse", controller])
    }

    /// Like [`start`](Self::start), with the full argv (e.g. plus
    /// `--offered-name` or a verbosity flag).
    pub fn start_with(sandbox: &Sandbox, args: &[&str]) -> Self {
        let mut child = sandbox
            .command(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn qsh reverse");
        if let Some(mut out) = child.stdout.take() {
            thread::spawn(move || {
                let _ = std::io::copy(&mut out, &mut std::io::sink());
            });
        }
        if let Some(mut err) = child.stderr.take() {
            thread::spawn(move || {
                let _ = std::io::copy(&mut err, &mut std::io::sink());
            });
        }
        Self { child }
    }

    /// This process's pid — for an "owns no listening socket" assertion
    /// from outside the process (`lsof`/`/proc`).
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// `SIGTERM`, then wait up to 5s for the child to actually exit —
    /// bounded, never a bare kill-and-hope.
    pub fn shut_down(mut self) {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.child.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(unix)]
impl Drop for ReverseGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `qsh hosts --json` in `sandbox`, asserted to succeed, returning the
/// `data.hosts` array — shared by every reverse-registration test that
/// needs to poll the controller's live view (mirrors `hosts_reverse.rs`'s
/// own private helper of the same name).
pub fn hosts_array(sandbox: &Sandbox) -> Vec<Value> {
    let (code, envelope) = sandbox.json(&["hosts", "--json"]);
    assert_eq!(code, 0, "{envelope}");
    envelope["data"]["hosts"]
        .as_array()
        .expect("data.hosts array")
        .clone()
}

/// Poll `f` — a bare, uncached read every time — until it returns `Some`,
/// or fail after `deadline` (a hard deadline, never a fixed sleep standing
/// in for one; mirrors `wait_for_audit`/`hosts_reverse.rs::poll_until`).
pub fn poll_until<T>(what: &str, deadline: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let until = std::time::Instant::now() + deadline;
    loop {
        if let Some(value) = f() {
            return value;
        }
        if std::time::Instant::now() >= until {
            panic!("timed out waiting for {what}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Block until `host`'s audit log contains a record matching `predicate`,
/// or fail after a bounded deadline.
///
/// The host writes its audit line from another process, so there is no
/// in-process event to await; this polls the (append-only, line-buffered)
/// log with a hard deadline rather than sleeping a fixed amount.
pub fn wait_for_audit(
    host: &Sandbox,
    what: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Vec<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let records = host.audit_records();
        if records.iter().any(&predicate) {
            return records;
        }
        if std::time::Instant::now() >= deadline {
            panic!("no audit record matching {what} within 10s; log: {records:#?}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}
