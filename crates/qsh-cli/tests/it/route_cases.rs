//! The cases `windows_forward_e2e.rs` and `windows_reverse_e2e.rs` share, and
//! the two routes they run over (ADR-0035 decisions 1, 2 and 14).
//!
//! A case takes a [`Route`] and drives only real `qsh` processes through it:
//! the forward route is a `qsh serve` host that pins a client, the reverse
//! route is a `qsh listen` controller with a `qsh serve --to` target
//! registered on it and the client running in the controller's sandbox (the
//! client finds the daemon through the sandbox's runtime directory, so it has
//! to share it). No test-only harness stands in for either side, so the same
//! function proves the same behaviour on both routes and only the way the
//! route is built differs.
//!
//! Half-close works through both routes the same way on every platform: a
//! client that shuts only its write side has that end delivered to the
//! destination, which can still answer. (On Windows the local conduit is a
//! byte-mode pipe and carries the close as a chunk-framing end marker,
//! ADR-0035 decision 14.)

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{Fleet, HOST_ALIAS, ListenGuard, ReverseGuard, Sandbox, hosts_array, poll_until};
use qsh_testkit::net_probe::free_port;
use serde_json::Value;

/// How long one blocking socket read or write may take before the case fails.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a registration or a tunnel may take to show up.
pub const READY_DEADLINE: Duration = Duration::from_secs(30);

/// Bytes sent through a tunnel: more than one splice buffer, and not a
/// repeat of any single buffer's worth, so a dropped or reordered chunk
/// cannot look correct.
const PAYLOAD_LEN: usize = 96 * 1024;

/// The name the controller's trust store gives the reverse target.
pub const REVERSE_NAME: &str = "nat-target";

/// The alias the target's trust store uses for the controller it dials.
pub const CONTROLLER_ALIAS: &str = "hub";

/// A route from a client to a host, as a case sees it.
pub trait Route {
    /// The sandbox every client command of the case runs in.
    fn client(&self) -> &Sandbox;
    /// The name of the host, as the client knows it.
    fn host(&self) -> &str;
    /// The host's own sandbox: the one whose config and state directories the
    /// host protects.
    fn host_sandbox(&self) -> &Sandbox;
}

/// Client to a `qsh serve` host over QUIC.
pub struct ForwardRoute {
    pub fleet: Fleet,
}

impl ForwardRoute {
    pub fn start() -> Self {
        Self {
            fleet: Fleet::start(),
        }
    }
}

impl ForwardRoute {
    /// Like [`Self::start`], with the host pinning the client with the
    /// `full` role: the route `qsh cp` cases need.
    pub fn start_full() -> Self {
        Self {
            fleet: Fleet::start_full(),
        }
    }
}

impl Route for ForwardRoute {
    fn client(&self) -> &Sandbox {
        &self.fleet.client
    }

    fn host(&self) -> &str {
        HOST_ALIAS
    }

    fn host_sandbox(&self) -> &Sandbox {
        &self.fleet.host
    }
}

/// Client to a `qsh serve --to` target registered on a `qsh listen` daemon
/// of the same sandbox.
pub struct ReverseRoute {
    /// The controller, and the sandbox the client commands run in.
    pub controller: Sandbox,
    /// The target's own sandbox.
    pub target: Sandbox,
    pub listen: ListenGuard,
    pub reverse: ReverseGuard,
}

impl ReverseRoute {
    /// Controller, target, and the registration between them, up and
    /// reachable from the controller's `qsh hosts`.
    pub fn start() -> Self {
        let route = Self::start_unregistered(None, "none");
        route.wait_registered();
        route
    }

    /// Like [`Self::start`], with the target pinning the controller with the
    /// `full` role: the route `qsh cp` cases need.
    pub fn start_full() -> Self {
        let route = Self::start_unregistered(None, "full");
        route.wait_registered();
        route
    }

    /// Like [`Self::start`], with the controller on `bind` instead of an
    /// ephemeral port, so a restarted controller can come back to the address
    /// the target dials. Waits for the registration as well.
    pub fn start_at(bind: &str) -> Self {
        let route = Self::start_unregistered(Some(bind), "none");
        route.wait_registered();
        route
    }

    fn start_unregistered(bind: Option<&str>, controller_role: &str) -> Self {
        let controller = Sandbox::initialized();
        let target = Sandbox::initialized();
        let target_fp = target.fingerprint();
        let controller_fp = controller.fingerprint();

        // The controller pins the target by fingerprint only, with no
        // address: the only route to `REVERSE_NAME` is a live registration,
        // never a forward dial.
        controller.trust_add(REVERSE_NAME, None, &target_fp);
        let listen = match bind {
            Some(bind) => ListenGuard::start_with(&controller, bind),
            None => ListenGuard::start(&controller),
        };
        target.trust_add_with_role(
            CONTROLLER_ALIAS,
            Some(listen.addr()),
            &controller_fp,
            controller_role,
        );
        fast_reconnect(&target);
        let reverse = ReverseGuard::start_serve_to(&target, CONTROLLER_ALIAS);
        Self {
            controller,
            target,
            listen,
            reverse,
        }
    }

    /// Wait until the controller's `qsh hosts` shows the target as a
    /// reachable reverse entry.
    pub fn wait_registered(&self) {
        wait_reverse_entry(&self.controller, "reachable", READY_DEADLINE);
    }
}

impl Route for ReverseRoute {
    fn client(&self) -> &Sandbox {
        &self.controller
    }

    fn host(&self) -> &str {
        REVERSE_NAME
    }

    fn host_sandbox(&self) -> &Sandbox {
        &self.target
    }
}

/// A target that retries quickly, so a controller that goes away and comes
/// back is found again within a test's patience instead of a backoff's.
fn fast_reconnect(target: &Sandbox) {
    std::fs::write(
        target.config_dir().join("config.toml"),
        "[reverse]\nbackoff_initial_ms = 100\nbackoff_max_ms = 400\nbackoff_jitter_pct = 0\n",
    )
    .expect("write the target's config.toml");
}

/// Poll `qsh hosts` in `controller` until the reverse entry for
/// [`REVERSE_NAME`] is in `state`, and return it.
pub fn wait_reverse_entry(controller: &Sandbox, state: &str, deadline: Duration) -> Value {
    poll_until(
        &format!("the reverse entry to be {state}"),
        deadline,
        || {
            hosts_array(controller)
                .into_iter()
                .find(|h| h["name"] == REVERSE_NAME && h["connection_mode"] == "reverse")
                .filter(|h| h["state"] == state)
        },
    )
}

/// The reverse entries `qsh hosts` shows right now.
pub fn reverse_entries(controller: &Sandbox) -> Vec<Value> {
    hosts_array(controller)
        .into_iter()
        .filter(|h| h["connection_mode"] == "reverse")
        .collect()
}

// ---------------------------------------------------------------------------
// Destinations and the client side of a tunnel
// ---------------------------------------------------------------------------

/// A loopback TCP echo server: every connection is echoed back until the
/// peer closes. The accept loop is detached and lives as long as the test
/// process.
pub fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the echo server");
    let addr = listener.local_addr().expect("echo server address");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            thread::spawn(move || {
                let mut reader = stream.try_clone().expect("clone the echo socket");
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
                // Send the end of stream before the sockets close. A plain
                // drop of the two handles can reset the connection on
                // Windows, which discards echoed bytes the peer has not
                // read yet.
                let _ = writer.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    addr
}

/// [`start_echo`] bound to `ip` instead of the loopback address.
pub fn start_echo_at(ip: Ipv4Addr) -> SocketAddr {
    let listener = TcpListener::bind((ip, 0)).expect("bind the echo server off loopback");
    let addr = listener.local_addr().expect("echo server address");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            thread::spawn(move || {
                let mut reader = stream.try_clone().expect("clone the echo socket");
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
                let _ = writer.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    addr
}

/// A loopback TCP server that writes `greeting` to each connection and closes
/// it at once, without reading.
pub fn start_greeter(greeting: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the greeter");
    let addr = listener.local_addr().expect("greeter address");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = stream.write_all(greeting);
            let _ = stream.flush();
        }
    });
    addr
}

fn payload() -> Vec<u8> {
    (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect()
}

/// Write `payload` into `127.0.0.1:<port>`, shut only the write side, and read
/// the reply to its end. The echo destination closes its side only after it has seen the
/// client's end of stream, so a close that did not travel through the route
/// leaves the read waiting until the timeout. The write runs on its own
/// thread because a payload larger than the socket buffers would otherwise
/// deadlock against an echo that is itself blocked writing to us.
pub fn round_trip(port: u16, payload: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut writer = socket.try_clone()?;
    let sender = thread::spawn(move || -> std::io::Result<()> {
        writer.write_all(&payload)?;
        writer.flush()?;
        writer.shutdown(std::net::Shutdown::Write)
    });
    let mut back = Vec::new();
    let read = {
        let mut reader = socket;
        reader.read_to_end(&mut back)
    };
    let sent = sender.join().expect("the sender thread panicked");
    read.and(sent).map(|_| back)
}

/// Compare an echoed payload with what was sent, naming the length and the
/// first differing offset when they differ.
fn assert_same_payload(back: &[u8], sent: &[u8], what: &str) {
    if back != sent {
        let first = back.iter().zip(sent).position(|(a, b)| a != b);
        panic!(
            "{what} corrupted the payload: got {} bytes, sent {}, first difference at {first:?}",
            back.len(),
            sent.len()
        );
    }
}

/// A running `qsh tunnel open … --json` child, killed on drop. The process
/// is the tunnel's holder (`docs/CLI.md` §6.14), so killing it is the
/// teardown of a forward route's tunnel.
pub struct TunnelHolder {
    child: Child,
    /// Everything after the envelope line, read on a thread so a full pipe
    /// never blocks the child.
    reader: Option<thread::JoinHandle<String>>,
    /// The holder's stderr lines so far, collected only by
    /// [`Self::open_supervised`].
    stderr: Arc<Mutex<Vec<String>>>,
}

impl TunnelHolder {
    /// `qsh tunnel open <host> <flag> <spec> --json` in the route's client
    /// sandbox; returns the holder and the envelope it printed.
    pub fn open(route: &impl Route, flag: &str, spec: &str) -> (Self, Value) {
        Self::spawn(route, flag, spec, &[])
    }

    /// Like [`Self::open`] with `--supervise <budget_ms>`, collecting the
    /// supervisor's stderr lines for [`Self::wait_supervise`].
    pub fn open_supervised(
        route: &impl Route,
        flag: &str,
        spec: &str,
        budget_ms: u32,
    ) -> (Self, Value) {
        Self::spawn(route, flag, spec, &["--supervise", &budget_ms.to_string()])
    }

    fn spawn(route: &impl Route, flag: &str, spec: &str, extra: &[&str]) -> (Self, Value) {
        let mut args = vec!["tunnel", "open", route.host(), flag, spec, "--json"];
        args.extend_from_slice(extra);
        let mut command: Command = route.client().command(&args);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qsh tunnel open");
        let stderr = Arc::new(Mutex::new(Vec::new()));
        if !extra.is_empty() {
            let pipe = child.stderr.take().expect("tunnel open stderr pipe");
            let sink = Arc::clone(&stderr);
            thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    sink.lock().unwrap_or_else(|e| e.into_inner()).push(line);
                }
            });
        }
        let mut stdout = BufReader::new(child.stdout.take().expect("tunnel open stdout pipe"));
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            let _ = stdout.read_line(&mut line);
            let _ = tx.send(line);
            let mut rest = String::new();
            let _ = stdout.read_to_string(&mut rest);
            rest
        });
        let mut holder = Self {
            child,
            reader: Some(reader),
            stderr,
        };
        let line = rx.recv_timeout(READY_DEADLINE).unwrap_or_else(|err| {
            panic!(
                "qsh tunnel open printed no envelope within {READY_DEADLINE:?} ({err}); \
                 stderr:\n{}",
                holder.stderr_text()
            )
        });
        assert!(
            !line.trim().is_empty(),
            "qsh tunnel open printed no envelope; stderr:\n{}",
            holder.stderr_text()
        );
        let envelope: Value = serde_json::from_str(line.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON: {e}: {line:?}"));
        assert_eq!(envelope["schema"], "qsh.cli/v1");
        assert_eq!(
            envelope["ok"], true,
            "qsh tunnel open did not succeed: {envelope}"
        );
        (holder, envelope)
    }

    /// The holder's stderr: what a collecting open gathered, else whatever
    /// the pipe holds now.
    fn stderr_text(&mut self) -> String {
        let collected = self.stderr.lock().unwrap_or_else(|e| e.into_inner());
        if collected.is_empty() {
            drop(collected);
            common::drain_stderr(&mut self.child)
        } else {
            collected.join("\n")
        }
    }

    /// The supervisor's diagnostic lines (`{"supervise":…}`) on stderr so
    /// far, in order. Only a holder from [`Self::open_supervised`] has any.
    pub fn supervise_lines(&self) -> Vec<Value> {
        self.stderr
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|line| line.starts_with("{\"supervise\""))
            .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
            .collect()
    }

    /// Wait until the supervisor has logged at least `count` lines of `kind`
    /// (`lost`, `reestablished`, …); returns them.
    pub fn wait_supervise(&self, kind: &str, count: usize, deadline: Duration) -> Vec<Value> {
        poll_until(
            &format!("{count} `{kind}` supervise line(s)"),
            deadline,
            || {
                let seen: Vec<Value> = self
                    .supervise_lines()
                    .into_iter()
                    .filter(|line| line["supervise"] == kind)
                    .collect();
                (seen.len() >= count).then_some(seen)
            },
        )
    }

    /// Whether the holder is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Kill the holder and return the rest of its stdout, which must be empty:
    /// machine mode prints one envelope line and nothing else.
    pub fn finish(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reader
            .take()
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default()
    }
}

impl Drop for TunnelHolder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

/// `qsh exec <host> -- cmd /c …` returns the remote's streams and exit code
/// through the route (`docs/CLI.md` §6.8).
pub fn exec_round_trip(route: &impl Route) {
    let args = [
        "exec",
        route.host(),
        "--json",
        "--",
        "cmd",
        "/c",
        "echo hello&exit 7",
    ];
    let (code, value) = route.client().json(&args);

    assert_eq!(code, 7, "the process exit code is the remote one: {value}");
    assert_eq!(value["command"], "exec.run");
    assert_eq!(value["ok"], true, "{value}");
    let data = &value["data"];
    assert_eq!(data["remote_exit_code"], 7, "{value}");
    assert_eq!(data["stdout_b64"], BASE64.encode("hello\r\n"), "{value}");
}

/// How long the host may run the tree in [`exec_timeout_kills_the_whole_tree`]
/// before its deadline ends it. The deadline starts with the command, so it
/// has to leave room for `ping` to start on a loaded runner.
const TREE_TIMEOUT_MS: &str = "10000";

/// A timeout ends the whole tree on the host, not just the program `argv[0]`
/// named (ADR-0035 decision 23; the process group kill on unix). `cmd` runs
/// `ping`, whose output goes to a file `ping` itself holds open without
/// delete sharing. Once the file has content `ping` is running; after the
/// timeout the file can be deleted only if no process of the tree still has
/// it open.
pub fn exec_timeout_kills_the_whole_tree(route: &impl Route) {
    let dir = tempfile::tempdir().expect("a marker directory");
    let marker = dir.path().join("ping.txt");
    let marker_arg = marker.to_str().expect("the marker path is UTF-8");
    let args = [
        "exec",
        route.host(),
        "--json",
        "--timeout",
        TREE_TIMEOUT_MS,
        "--",
        "cmd",
        "/c",
        "ping",
        "-n",
        "120",
        "127.0.0.1",
        ">",
        marker_arg,
    ];
    let exec = route
        .client()
        .command(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qsh exec");

    poll_until("ping to write its first line", READY_DEADLINE, || {
        std::fs::metadata(&marker)
            .is_ok_and(|meta| meta.len() > 0)
            .then_some(())
    });
    let output = exec.wait_with_output().expect("wait for qsh exec");
    let value = common::sole_envelope(&output.stdout, &args);
    assert_eq!(common::exit_code(&output), 255, "{value}");
    assert_eq!(value["error"]["code"], "TIMEOUT", "{value}");

    poll_until(
        "the killed tree to release the file ping held open",
        READY_DEADLINE,
        || std::fs::remove_file(&marker).ok(),
    );
}

// ---------------------------------------------------------------------------
// Host state: the audit log and acl.toml (ADR-0035 decision 24)
// ---------------------------------------------------------------------------

/// What `acl.toml` writes in [`plant_everyone_writable_acl`]. The principal is
/// a marker no diagnostic may echo.
const MARKER_ACL: &str =
    "[[acl]]\nprincipal = \"device:marker-never-logged\"\nallow = [\"exec.run\"]\n";

/// Write an `acl.toml` into `sandbox` that `Everyone` can write to, the way
/// an operator's slip would: the file is made owner-only like any qsh file,
/// then `icacls` adds a write ACE for `S-1-1-0`. Returns its path.
pub fn plant_everyone_writable_acl(sandbox: &Sandbox) -> std::path::PathBuf {
    let path = sandbox.config_dir().join("acl.toml");
    qsh_core::config::write_private_file(&path, MARKER_ACL.as_bytes()).expect("write acl.toml");
    let output = Command::new("icacls")
        .arg(&path)
        .args(["/grant", "*S-1-1-0:(W)"])
        .output()
        .expect("run icacls");
    assert!(
        output.status.success(),
        "icacls could not grant Everyone write: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

/// A stderr line without its ANSI colour codes, which the human formatter
/// writes even to a pipe.
fn plain(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip `ESC [ ... <final byte>`.
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The `acl.toml` DACL warning must show up in `stderr` (polled, since the
/// host writes it while starting) with the same structural fields on every
/// run mode: the path, the offending SID and how many there are, the reason,
/// and nothing from the file (`docs/design/threat-model.md` §4 E).
pub fn assert_acl_dacl_warning(stderr: impl Fn() -> Vec<String>, acl_path: &std::path::Path) {
    let line = poll_until(
        "the acl.toml DACL warning on stderr",
        READY_DEADLINE,
        || {
            stderr()
                .iter()
                .map(|line| plain(line))
                .find(|line| line.contains("acl.toml's DACL"))
        },
    );
    assert!(line.contains("WARN"), "{line}");
    assert!(
        line.contains(&format!("path={}", acl_path.display())),
        "the warning names the file: {line}"
    );
    assert!(line.contains("sid=S-1-1-0"), "{line}");
    assert!(line.contains("sid_count=1"), "{line}");
    assert!(line.contains("reason=\"write_ace\""), "{line}");
    // No unix `mode`, no ACE mask, nothing the file says.
    assert!(!line.contains("mode="), "{line}");
    assert!(!line.contains("marker-never-logged"), "{line}");
    let all: Vec<String> = stderr().iter().map(|line| plain(line)).collect();
    assert_eq!(
        all.iter().filter(|l| l.contains("acl.toml's DACL")).count(),
        1,
        "one warning per start: {all:?}"
    );
}

/// A decision made through the route lands in the host's `<state>/audit.log`,
/// and the writer's sidecar lock file (`audit.log.lock`) is there next to it
/// (ADR-0035 decision 24). The host is the machine that decided: the serving
/// side on the forward route and the target on the reverse one.
pub fn audit_record_and_lock_file_land_in_the_hosts_state_directory(
    route: &impl Route,
    host: &Sandbox,
) {
    let (code, value) =
        route
            .client()
            .json(&["exec", route.host(), "--json", "--", "cmd", "/c", "exit 0"]);
    assert_eq!(code, 0, "{value}");

    let record = poll_until("the host's exec.run audit record", READY_DEADLINE, || {
        host.audit_records_tolerant()
            .into_iter()
            .find(|r| r["action"] == "exec.run")
    });
    assert_eq!(record["decision"], "allow", "{record}");
    assert!(
        host.state_dir().join("audit.log.lock").is_file(),
        "the writer's lock file is next to the log in {}",
        host.state_dir().display()
    );
}

// ---------------------------------------------------------------------------
// PTY sessions
// ---------------------------------------------------------------------------

/// How long a PTY session may take to end or to be closed before the case
/// fails.
const SESSION_DEADLINE: Duration = Duration::from_secs(60);

/// Pull `session read --wait` until the session's `session.exit`, feeding
/// both cursors back, and return the output bytes and the exit event.
pub fn read_until_exit(route: &impl Route, session_ref: &str) -> (Vec<u8>, Value) {
    let mut output = Vec::new();
    let (mut after, mut ctl_after) = (0u64, 0u64);
    let deadline = std::time::Instant::now() + SESSION_DEADLINE;
    loop {
        let (code, read) = route.client().json(&[
            "session",
            "read",
            session_ref,
            "--json",
            "--after",
            &after.to_string(),
            "--ctl-after",
            &ctl_after.to_string(),
            "--wait",
            "5000",
        ]);
        assert_eq!(code, 0, "{read}");
        after = read["data"]["next_after"].as_u64().expect("next_after");
        ctl_after = read["data"]["next_ctl_after"]
            .as_u64()
            .expect("next_ctl_after");
        for event in read["data"]["events"].as_array().expect("events") {
            match event["type"].as_str() {
                Some("session.output") => output.extend(
                    BASE64
                        .decode(event["data_b64"].as_str().expect("data_b64"))
                        .expect("data_b64 is Base64"),
                ),
                Some("session.exit") => return (output, event.clone()),
                _ => {}
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the session never exited; output so far: {:?}",
            String::from_utf8_lossy(&output)
        );
    }
}

/// `qsh session open <host> --json [-- argv]`; returns the `session_ref`.
pub fn open_session(route: &impl Route, argv: &[&str]) -> String {
    let mut args = vec!["session", "open", route.host(), "--json"];
    if !argv.is_empty() {
        args.push("--");
        args.extend_from_slice(argv);
    }
    let (code, opened) = route.client().json(&args);
    assert_eq!(code, 0, "{opened}");
    assert_eq!(opened["command"], "session.open", "{opened}");
    opened["data"]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string()
}

/// A PTY session running a command: its output and exit code come back
/// through the route, and `session close` on the exited session removes it
/// (`docs/CLI.md` §6.3, §6.4).
pub fn pty_session_runs_a_command(route: &impl Route) {
    let session_ref = open_session(route, &["cmd", "/c", "echo qsh%OS%pty&exit 5"]);
    let (output, exit) = read_until_exit(route, &session_ref);
    let text = String::from_utf8_lossy(&output);

    assert!(
        text.contains("qshWindows_NTpty"),
        "the command ran and its output came back through the pseudo-console: {text:?}"
    );
    assert_eq!(exit["exit_code"], 5, "{exit}");
    assert!(exit["signal"].is_null(), "{exit}");

    let (code, got) = route
        .client()
        .json(&["session", "get", &session_ref, "--json"]);
    assert_eq!(code, 0, "{got}");
    assert_eq!(got["data"]["state"], "exited", "{got}");

    let (code, closed) = route
        .client()
        .json(&["session", "close", &session_ref, "--json"]);
    assert_eq!(code, 0, "{closed}");
    let (_, gone) = route
        .client()
        .json(&["session", "get", &session_ref, "--json"]);
    assert_eq!(gone["error"]["code"], "SESSION_NOT_FOUND", "{gone}");
}

/// An empty argv runs the account's command interpreter, which reads what
/// `session write` sends and ends with the exit code it was told to.
pub fn pty_session_default_shell_takes_input(route: &impl Route) {
    let session_ref = open_session(route, &[]);

    let line = "echo qsh%OS%shell&exit 3\r\n";
    let (code, written) = route.client().json(&[
        "session",
        "write",
        &session_ref,
        "--json",
        "--data-b64",
        &BASE64.encode(line),
    ]);
    assert_eq!(code, 0, "{written}");

    let (output, exit) = read_until_exit(route, &session_ref);
    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("qshWindows_NTshell"),
        "the shell executed the line it was sent: {text:?}"
    );
    assert_eq!(exit["exit_code"], 3, "{exit}");
}

/// `out` without CSI (`ESC [ ... final`) and OSC (`ESC ] ... BEL`)
/// sequences, which ConPTY interleaves with the text.
pub fn strip_vt(out: &str) -> String {
    let mut plain = String::with_capacity(out.len());
    let mut chars = out.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            plain.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&c) {
                        break;
                    }
                }
            }
            Some(']') => {
                for c in chars.by_ref() {
                    if c == '\u{7}' {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    plain
}

/// `session resize` reaches the host's pseudo-console: `mode con` reads the
/// console's screen buffer, so the size a client set is the size the child
/// reports. The child waits on `set /p` until the resize is done and the
/// `session write` releases it.
pub fn pty_session_resize_is_applied(route: &impl Route) {
    let session_ref = open_session(route, &["cmd", "/c", "set /p wait=& mode con"]);

    let (code, resized) = route.client().json(&[
        "session",
        "resize",
        &session_ref,
        "--cols",
        "133",
        "--rows",
        "47",
        "--json",
    ]);
    assert_eq!(code, 0, "{resized}");
    let (code, written) = route.client().json(&[
        "session",
        "write",
        &session_ref,
        "--json",
        "--data-b64",
        &BASE64.encode("\r\n"),
    ]);
    assert_eq!(code, 0, "{written}");

    let (output, _) = read_until_exit(route, &session_ref);
    let plain = strip_vt(&String::from_utf8_lossy(&output));
    // The labels are localised and the order is not: `mode con` prints the
    // buffer's lines, then its columns.
    let numbers: Vec<u32> = plain
        .lines()
        .filter_map(|line| {
            let (_, rest) = line.rsplit_once([':', '\u{ff1a}'])?;
            rest.trim().parse().ok()
        })
        .collect();
    assert_eq!(
        numbers.get(..2),
        Some(&[47, 133][..]),
        "the child reports the resized console: {plain:?}"
    );
}

/// `session close` ends a session whose shell is still running: the default
/// escalation (the pseudo-console's close first) and `--signal KILL` (the job
/// is terminated at once) both remove it, so nothing is left to attach to.
pub fn pty_session_close_ends_a_running_session(route: &impl Route) {
    for signal in [None, Some("KILL")] {
        let session_ref = open_session(route, &[]);

        let mut args = vec!["session", "close", session_ref.as_str(), "--json"];
        if let Some(signal) = signal {
            args.extend_from_slice(&["--signal", signal]);
        }
        let (code, closed) = route.client().json(&args);
        assert_eq!(code, 0, "close with signal {signal:?}: {closed}");

        let (code, gone) = route
            .client()
            .json(&["session", "get", &session_ref, "--json"]);
        assert_ne!(code, 0, "{gone}");
        assert_eq!(gone["error"]["code"], "SESSION_NOT_FOUND", "{gone}");
    }
}

/// Pull `session read --wait` until the session's output holds `needle`, and
/// return the output read so far. The session may still be running.
pub fn read_until_output(route: &impl Route, session_ref: &str, needle: &str) -> String {
    let mut output = Vec::new();
    let (mut after, mut ctl_after) = (0u64, 0u64);
    let deadline = std::time::Instant::now() + SESSION_DEADLINE;
    loop {
        let (code, read) = route.client().json(&[
            "session",
            "read",
            session_ref,
            "--json",
            "--after",
            &after.to_string(),
            "--ctl-after",
            &ctl_after.to_string(),
            "--wait",
            "5000",
        ]);
        assert_eq!(code, 0, "{read}");
        after = read["data"]["next_after"].as_u64().expect("next_after");
        ctl_after = read["data"]["next_ctl_after"]
            .as_u64()
            .expect("next_ctl_after");
        for event in read["data"]["events"].as_array().expect("events") {
            if event["type"].as_str() == Some("session.output") {
                output.extend(
                    BASE64
                        .decode(event["data_b64"].as_str().expect("data_b64"))
                        .expect("data_b64 is Base64"),
                );
            }
        }
        let text = String::from_utf8_lossy(&output).into_owned();
        if text.contains(needle) {
            return text;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{needle:?} never appeared; output so far: {text:?}"
        );
    }
}

/// `session close --signal <SIG>` for each of the seven values (and with no
/// signal, which is `HUP`) reaches a program on the session's console as the
/// event ADR-0035 decision 22 names, and the session is gone afterwards.
///
/// The evidence is what the program received, not the exit code of `qsh`:
/// `qsh-signal-probe` writes the event it got into a report file before it
/// ends, and the file is read after the close has removed the session. `KILL`
/// reaches no program, so its report stays empty.
pub fn session_close_with_each_signal_ends_the_session(route: &impl Route) {
    use qsh_testkit::signal_probe::{self, CTRL_BREAK, CTRL_C, CTRL_CLOSE, USR1, USR2};

    let probe = signal_probe::bin();
    let dir = tempfile::tempdir().expect("a report directory");
    let rows = [
        (None, Some(CTRL_CLOSE)),
        (Some("HUP"), Some(CTRL_CLOSE)),
        (Some("INT"), Some(CTRL_C)),
        (Some("QUIT"), Some(CTRL_BREAK)),
        (Some("TERM"), Some(CTRL_CLOSE)),
        (Some("USR1"), Some(USR1)),
        (Some("USR2"), Some(USR2)),
        (Some("KILL"), None),
    ];
    for (n, (signal, event)) in rows.into_iter().enumerate() {
        let label = signal.unwrap_or("(none)");
        let report = dir.path().join(format!("report-{n}.txt"));
        let session_ref = open_session(
            route,
            &[
                probe.to_str().expect("the probe path is UTF-8"),
                "exit",
                "--report",
                report.to_str().expect("the report path is UTF-8"),
            ],
        );
        // The probe prints this once its handlers are installed; a signal
        // sent earlier could land before it can see it.
        read_until_output(route, &session_ref, signal_probe::READY);

        let mut args = vec!["session", "close", session_ref.as_str(), "--json"];
        if let Some(signal) = signal {
            args.extend_from_slice(&["--signal", signal]);
        }
        let (code, closed) = route.client().json(&args);
        assert_eq!(code, 0, "close with signal {label}: {closed}");
        let (code, gone) = route
            .client()
            .json(&["session", "get", &session_ref, "--json"]);
        assert_ne!(code, 0, "{label}: {gone}");
        assert_eq!(
            gone["error"]["code"], "SESSION_NOT_FOUND",
            "{label}: {gone}"
        );

        let received = std::fs::read_to_string(&report).unwrap_or_default();
        let received: Vec<&str> = received.lines().collect();
        match event {
            Some(event) => assert_eq!(received, [event.name], "close with signal {label}"),
            None => assert!(
                received.is_empty(),
                "KILL reached the program: {received:?}"
            ),
        }
        eprintln!("close --signal {label}: the program received {received:?}");
    }
}

/// `qsh tunnel open --local`: a TCP write to the local port reaches the
/// destination the host dials and comes back.
pub fn local_tunnel_echo(route: &impl Route) {
    let echo = start_echo();
    let local_port = free_port();
    let spec = format!("{local_port}:127.0.0.1:{}", echo.port());

    let (mut tunnel, envelope) = TunnelHolder::open(route, "--local", &spec);
    let data = &envelope["data"];
    assert_eq!(envelope["command"], "tunnel.open");
    assert_eq!(data["mode"], "local");
    assert_eq!(data["host"], route.host());
    assert_eq!(data["bind"], format!("127.0.0.1:{local_port}"));
    assert_eq!(data["forward_to"], format!("127.0.0.1:{}", echo.port()));

    let sent = payload();
    let back = round_trip(local_port, sent.clone()).expect("round trip through the local forward");
    assert_same_payload(&back, &sent, "the local forward");

    assert!(tunnel.is_running(), "the holder exited while serving");
    let rest = tunnel.finish();
    assert!(
        rest.is_empty(),
        "machine mode printed more than one stdout line: {rest:?}"
    );
}

/// `qsh tunnel open --remote`: the host binds a port on its loopback and each
/// connection to it comes back to the requester's destination.
pub fn remote_tunnel_echo(route: &impl Route) {
    let echo = start_echo();
    let remote_port = free_port();
    let spec = format!("{remote_port}:127.0.0.1:{}", echo.port());

    let (mut tunnel, envelope) = TunnelHolder::open(route, "--remote", &spec);
    let data = &envelope["data"];
    assert_eq!(data["mode"], "remote");
    assert_eq!(data["host"], route.host());
    assert_eq!(data["bind"], format!("127.0.0.1:{remote_port}"));
    assert_eq!(data["forward_to"], format!("127.0.0.1:{}", echo.port()));

    let sent = payload();
    let back =
        round_trip(remote_port, sent.clone()).expect("round trip through the remote forward");
    assert_same_payload(&back, &sent, "the remote forward");

    assert!(tunnel.is_running(), "the holder exited while serving");
    let rest = tunnel.finish();
    assert!(
        rest.is_empty(),
        "machine mode printed more than one stdout line: {rest:?}"
    );
}

/// A destination that closes its side first: the local client reads what it
/// sent and then the end of the stream, without ever writing. The end is
/// delivered and nothing waits for the client to speak.
pub fn local_tunnel_delivers_the_destinations_close(route: &impl Route) {
    let greeter = start_greeter(b"hello from the destination");
    let local_port = free_port();
    let spec = format!("{local_port}:127.0.0.1:{}", greeter.port());

    let (tunnel, _envelope) = TunnelHolder::open(route, "--local", &spec);

    let mut socket = TcpStream::connect(("127.0.0.1", local_port)).expect("connect to the forward");
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("read timeout");
    let mut got = Vec::new();
    let read = socket.read_to_end(&mut got);
    assert!(
        read.is_ok() || !got.is_empty(),
        "the destination's close never reached the client: {read:?}"
    );
    assert_eq!(got, b"hello from the destination");
    drop(tunnel);
}

/// `qsh hosts` and `qsh host get` name the route's host.
pub fn hosts_names_the_host(route: &impl Route, mode: &str) {
    let hosts = hosts_array(route.client());
    let entry = hosts
        .iter()
        .find(|h| h["name"] == route.host() && h["connection_mode"] == mode)
        .unwrap_or_else(|| panic!("no {mode} entry for {} in {hosts:?}", route.host()));
    assert_eq!(entry["name"], route.host());

    let (code, got) = route
        .client()
        .json(&["host", "get", route.host(), "--json"]);
    assert_eq!(code, 0, "{got}");
    assert_eq!(got["data"]["connection_mode"], mode, "{got}");
}

/// `qsh tunnel open --dynamic`: the SOCKS5 listener the holder binds takes a
/// `CONNECT` the test sends itself (no curl), the host dials the destination,
/// and bytes come back unchanged. A destination on the host's own loopback is
/// refused with a non-zero reply and the listener stays up (ADR-0019
/// decision 3).
///
/// The destination that succeeds has to be off loopback, so the case needs a
/// local IPv4 route; without one it is skipped off CI and fails on CI
/// ([`qsh_testkit::net_probe::in_ci`]).
pub fn dynamic_forward_connect(route: &impl Route) {
    let lan = qsh_testkit::gap_or_return!(
        qsh_testkit::net_probe::require_non_loopback_v4_route(
            "no non-loopback IPv4 route on this host"
        ),
        "dynamic_forward_connect"
    );
    let echo = start_echo_at(lan);
    let loopback_echo = start_echo();
    let port = free_port();

    let (mut tunnel, envelope) = TunnelHolder::open(route, "--dynamic", &port.to_string());
    let data = &envelope["data"];
    assert_eq!(envelope["command"], "tunnel.dynamic", "{envelope}");
    assert_eq!(data["mode"], "dynamic", "{envelope}");
    assert_eq!(data["host"], route.host(), "{envelope}");
    assert_eq!(data["dial_policy"], "deny_host_local", "{envelope}");
    assert_eq!(data["bind"], format!("127.0.0.1:{port}"), "{envelope}");

    // A destination on the host's own loopback is filtered.
    let mut refused = socks_connect(port, loopback_echo);
    let mut reply = [0u8; 10];
    refused
        .read_exact(&mut reply)
        .expect("read the reply to a filtered CONNECT");
    assert_eq!(reply[0], 0x05, "{reply:?}");
    assert_ne!(
        reply[1], 0x00,
        "a CONNECT to the host's loopback must be refused: {reply:?}"
    );
    drop(refused);

    // The one off loopback is dialed and echoed.
    let mut socket = socks_connect(port, echo);
    socket
        .read_exact(&mut reply)
        .expect("read the reply to a CONNECT");
    assert_eq!(
        reply[1],
        0x00,
        "CONNECT to {echo} through the {} route failed: {reply:?}",
        route.host()
    );
    let sent = payload();
    let writer = socket.try_clone().expect("clone the SOCKS socket");
    let sender = thread::spawn({
        let sent = sent.clone();
        move || -> std::io::Result<()> {
            let mut writer = writer;
            writer.write_all(&sent)?;
            writer.flush()?;
            writer.shutdown(std::net::Shutdown::Write)
        }
    });
    let mut back = Vec::new();
    socket
        .read_to_end(&mut back)
        .expect("read the echo through the SOCKS tunnel");
    sender
        .join()
        .expect("the sender thread panicked")
        .expect("write through the SOCKS tunnel");
    assert_same_payload(&back, &sent, "the dynamic forward");

    assert!(tunnel.is_running(), "the holder exited while serving");
    let rest = tunnel.finish();
    assert!(
        rest.is_empty(),
        "machine mode printed more than one stdout line: {rest:?}"
    );
}

/// Greet the SOCKS5 listener on `port` and send a no-auth IPv4 `CONNECT` to
/// `target`; the reply is left unread.
fn socks_connect(port: u16, target: SocketAddr) -> TcpStream {
    let SocketAddr::V4(target) = target else {
        panic!("the destinations of this case are IPv4");
    };
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the SOCKS port");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("write timeout");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .expect("write the greeting");
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .expect("read the method selection");
    assert_eq!(method, [0x05, 0x00], "the listener must select no-auth");
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).expect("write the CONNECT");
    stream
}

// ---------------------------------------------------------------------------
// `qsh cp` against a Windows host (ADR-0029, ADR-0035 decision 26)
// ---------------------------------------------------------------------------

/// A deterministic byte pattern, so a reordered or dropped chunk shows.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed)
                .wrapping_add((i >> 8) as u8)
        })
        .collect()
}

/// `path` as a remote operand for `host`, in the backslash spelling.
fn remote_back(route: &impl Route, path: &std::path::Path) -> String {
    format!("{}:{}", route.host(), path.display())
}

/// The same operand with forward slashes: a Windows host reads both.
fn remote_slash(route: &impl Route, path: &std::path::Path) -> String {
    format!(
        "{}:{}",
        route.host(),
        path.display().to_string().replace('\\', "/")
    )
}

fn no_part_files(dir: &std::path::Path) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let name = entry.expect("entry").file_name();
        let name = name.to_string_lossy().into_owned();
        assert!(
            !name.ends_with(".part"),
            "a temp file was left in {dir:?}: {name}"
        );
    }
}

/// `put`, `get`, `-r` and `-p` against a Windows host that pins the client
/// with the `full` role, on whichever route `route` is. The host's disk is
/// this machine's, so the bytes at the middle hop are checked too.
pub fn cp_round_trip(route: &impl Route) {
    let work = tempfile::tempdir().expect("work dir");
    let hostdir = work.path().join("host");
    std::fs::create_dir(&hostdir).unwrap();
    let client = route.client();

    // put, the backslash spelling of a drive path.
    let body = pattern(300 * 1024 + 17, 3);
    let src = work.path().join("src.bin");
    std::fs::write(&src, &body).unwrap();
    let stored = hostdir.join("up.bin");
    let (code, put) = client.json(&[
        "cp",
        "--json",
        src.to_str().unwrap(),
        &remote_back(route, &stored),
    ]);
    assert_eq!(code, 0, "put failed: {put}");
    assert_eq!(put["data"]["direction"], "put", "{put}");
    assert_eq!(put["data"]["files"], 1, "{put}");
    assert_eq!(put["data"]["bytes"], body.len() as u64, "{put}");
    assert_eq!(
        std::fs::read(&stored).unwrap(),
        body,
        "the host holds the bytes"
    );

    // get, the forward-slash spelling of the same path.
    let back = work.path().join("back.bin");
    let (code, get) = client.json(&[
        "cp",
        "--json",
        &remote_slash(route, &stored),
        back.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "get failed: {get}");
    assert_eq!(get["data"]["direction"], "get", "{get}");
    assert_eq!(
        get["data"]["entries"][0]["blake3"], put["data"]["entries"][0]["blake3"],
        "{get}"
    );
    assert_eq!(std::fs::read(&back).unwrap(), body);

    // Into an existing directory under the source's name.
    let (code, value) = client.json(&[
        "cp",
        "--json",
        src.to_str().unwrap(),
        &remote_back(route, &hostdir),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(std::fs::read(hostdir.join("src.bin")).unwrap(), body);

    // Overwrite replaces; `--no-clobber` skips.
    let newer = pattern(1000, 9);
    std::fs::write(&src, &newer).unwrap();
    let (code, value) = client.json(&[
        "cp",
        "--json",
        "--no-clobber",
        src.to_str().unwrap(),
        &remote_back(route, &stored),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(
        std::fs::read(&stored).unwrap(),
        body,
        "--no-clobber kept the old file"
    );
    let (code, value) = client.json(&[
        "cp",
        "--json",
        src.to_str().unwrap(),
        &remote_back(route, &stored),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(std::fs::read(&stored).unwrap(), newer);

    // -r: a tree with a nested directory and an empty one, both ways.
    let tree = work.path().join("tree");
    std::fs::create_dir_all(tree.join("sub/deeper")).unwrap();
    std::fs::create_dir(tree.join("empty")).unwrap();
    std::fs::write(tree.join("a.txt"), b"alpha").unwrap();
    std::fs::write(tree.join("sub/b.bin"), pattern(70_000, 5)).unwrap();
    std::fs::write(tree.join("sub/deeper/c.txt"), b"gamma").unwrap();
    let up = hostdir.join("tree-up");
    let (code, value) = client.json(&[
        "cp",
        "--json",
        "-r",
        tree.to_str().unwrap(),
        &remote_back(route, &up),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(std::fs::read(up.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(
        std::fs::read(up.join("sub/b.bin")).unwrap(),
        pattern(70_000, 5)
    );
    assert_eq!(
        std::fs::read(up.join("sub/deeper/c.txt")).unwrap(),
        b"gamma"
    );
    assert!(up.join("empty").is_dir(), "the empty directory is created");
    let down = work.path().join("tree-down");
    let (code, value) = client.json(&[
        "cp",
        "--json",
        "-r",
        &remote_back(route, &up),
        down.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(
        std::fs::read(down.join("sub/b.bin")).unwrap(),
        pattern(70_000, 5)
    );
    assert_eq!(
        std::fs::read(down.join("sub/deeper/c.txt")).unwrap(),
        b"gamma"
    );
    assert!(down.join("empty").is_dir());

    // -p: the modification time survives both ways.
    let old = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_500_000_000);
    std::fs::File::options()
        .write(true)
        .open(&src)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let kept = hostdir.join("kept.bin");
    let (code, value) = client.json(&[
        "cp",
        "--json",
        "-p",
        src.to_str().unwrap(),
        &remote_back(route, &kept),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(std::fs::metadata(&kept).unwrap().modified().unwrap(), old);
    let kept_back = work.path().join("kept-back.bin");
    let (code, value) = client.json(&[
        "cp",
        "--json",
        "-p",
        &remote_back(route, &kept),
        kept_back.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(
        std::fs::metadata(&kept_back).unwrap().modified().unwrap(),
        old
    );

    no_part_files(&hostdir);
    no_part_files(work.path());
}

/// The first failure of a `cp --json` run that failed, as its code.
fn first_failure_code(value: &Value) -> String {
    value["error"]["details"]["failures"][0]["code"]
        .as_str()
        .or_else(|| value["error"]["code"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// A Windows host refuses its own state paths whatever the role, in every
/// spelling of them, and refuses UNC and device paths as malformed
/// (ADR-0029 decisions 5, 6 and 23, ADR-0035 decision 26).
pub fn cp_refuses_state_paths_and_reparse_points(route: &impl Route) {
    let work = tempfile::tempdir().expect("work dir");
    let client = route.client();
    let config = route.host_sandbox().config_dir().to_path_buf();
    let trust = config.join("trust.toml");
    assert!(trust.exists(), "the host's trust.toml is the target");
    let trust_before = std::fs::read(&trust).unwrap();

    // get of a state file: refused, and nothing is created locally.
    let out = work.path().join("stolen.toml");
    for spelling in [
        remote_back(route, &trust),
        remote_slash(route, &trust),
        format!(
            "{}:{}",
            route.host(),
            trust.display().to_string().to_uppercase()
        ),
    ] {
        let (code, value) = client.json(&["cp", "--json", &spelling, out.to_str().unwrap()]);
        assert_eq!(code, 255, "{spelling}: {value}");
        assert_eq!(
            first_failure_code(&value),
            "PERMISSION_DENIED",
            "{spelling}: {value}"
        );
        assert!(!out.exists(), "nothing was written for {spelling}");
    }

    // put into the config directory, existing or new name, and the
    // directory itself.
    let src = work.path().join("evil.toml");
    std::fs::write(&src, b"role = \"full\"\n").unwrap();
    for target in [
        trust.clone(),
        config.join("acl.toml"),
        config.join("fresh.toml"),
        config.clone(),
    ] {
        let (code, value) = client.json(&[
            "cp",
            "--json",
            src.to_str().unwrap(),
            &remote_back(route, &target),
        ]);
        assert_eq!(code, 255, "{target:?}: {value}");
        assert_eq!(
            first_failure_code(&value),
            "PERMISSION_DENIED",
            "{target:?}: {value}"
        );
    }
    assert!(!config.join("fresh.toml").exists());
    assert_eq!(
        std::fs::read(&trust).unwrap(),
        trust_before,
        "trust.toml untouched"
    );

    // A junction in an ordinary directory that leads into the config
    // directory is judged by where it lands.
    let junction = work.path().join("link");
    let made = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&config)
        .output()
        .expect("run cmd");
    assert!(
        made.status.success(),
        "mklink /J: {}",
        String::from_utf8_lossy(&made.stdout)
    );
    let (code, value) = client.json(&[
        "cp",
        "--json",
        &remote_back(route, &junction.join("trust.toml")),
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(first_failure_code(&value), "PERMISSION_DENIED", "{value}");
    let (code, value) = client.json(&[
        "cp",
        "--json",
        src.to_str().unwrap(),
        &remote_back(route, &junction.join("planted.toml")),
    ]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(first_failure_code(&value), "PERMISSION_DENIED", "{value}");
    assert!(!config.join("planted.toml").exists());
    assert!(!out.exists());

    // UNC and device namespaces are malformed before any decision.
    for bad in [
        r"\\server\share\x",
        r"\\?\C:\Windows\win.ini",
        r"\\.\pipe\x",
    ] {
        let (code, value) = client.json(&[
            "cp",
            "--json",
            &format!("{}:{bad}", route.host()),
            out.to_str().unwrap(),
        ]);
        assert_eq!(code, 255, "{bad}: {value}");
        assert_eq!(
            first_failure_code(&value),
            "INVALID_ARGUMENT",
            "{bad}: {value}"
        );
        assert!(!out.exists());
    }
    // Remove the junction itself, not what it points to.
    std::fs::remove_dir(&junction).expect("remove the junction");
    assert!(trust.exists());
}

/// `session write` of `text` into the session, asserted to succeed.
pub fn write_to_session(route: &impl Route, session_ref: &str, text: &str) {
    let (code, written) = route.client().json(&[
        "session",
        "write",
        session_ref,
        "--json",
        "--data-b64",
        &BASE64.encode(text),
    ]);
    assert_eq!(code, 0, "{written}");
}

/// The sessions `qsh sessions <host> --json` lists through the route.
pub fn sessions_on(route: &impl Route) -> Vec<Value> {
    let (code, listed) = route.client().json(&["sessions", route.host(), "--json"]);
    assert_eq!(code, 0, "{listed}");
    listed["data"]["sessions"]
        .as_array()
        .expect("sessions")
        .clone()
}
