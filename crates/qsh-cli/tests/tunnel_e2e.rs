//! L5 local-forward acceptance: the **shipped binary** carries bytes from a
//! local port to a remote destination (`PLAN.md` M4 Step 3 (c), DoD 1).
//!
//! Everything here runs real processes. A real `qsh serve` is the host, a
//! real `qsh` is the client — the interactive `qsh [user@]host -L …` form
//! under a pty for the DoD's own closing tool, and `qsh tunnel open …
//! --json` for the machine-mode surface (`docs/CLI.md` §6.9). The only
//! in-process part is the *destination*: a plain TCP echo server on
//! loopback, which stands in for "a service running on the host" — the
//! host serves on this same machine, so its `127.0.0.1:<port>` is this
//! listener.
//!
//! ## What each test is allowed to conclude
//!
//! The round trips prove the whole path — local listener, `TCP_CONNECT`
//! stream, the host's inline `forward.local` authorization, the dial, and
//! the raw splice (`docs/design/protocol.md` §7, §5) — because the bytes
//! could not come back otherwise. The audit assertions prove the *other*
//! half of the deal: a privileged op leaves a structural record
//! (`docs/PRD.md` §13, SC6). Nothing asserts on payload anywhere in the
//! log, because the tunnel never writes payload anywhere but the socket.
//!
//! ## Ports
//!
//! No port is hardcoded: the echo server binds `:0` and the forward's
//! listen port comes from [`free_port`]. DoD 1's `8080` is illustrative
//! (`PLAN.md` Step 3 (c): "port 0 bind으로 실제 포트를 얻어"), and the
//! grammar settled in Step 1 rejects a `0` *listen* port
//! (`parse_forward_spec`, `1..=65535`), so the spec cannot ask the kernel
//! for one on a command line — the test picks a free one and passes it
//! concretely.
//!
//! Unix only, like every other pty-driven L5 file here: the interactive
//! form is `cfg(unix)` in the client (`crates/qsh-cli/src/tui/`), and
//! `expectrl` is a `cfg(unix)` dev-dependency. Windows still compiles this
//! crate's tests; this file simply contains none there.

#![cfg(unix)]

mod common;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use common::{CLIENT_PRINCIPAL, Fleet, HOST_ALIAS, Sandbox, exit_code};
use expectrl::session::OsSession;
use expectrl::{Expect as _, Session};
use serde_json::Value;

/// How long any single `expect` on the pty waits, and how long a byte is
/// allowed to take to come back through the tunnel. Generous on purpose:
/// the failure worth reporting is "never arrived", not "arrived late".
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The payload every round trip carries. Bigger than one TCP segment and
/// than the client's stdin chunking, small enough to stay quick; the
/// "larger than one splice buffer" case is the L3 suite's
/// (`crates/qsh-testkit/tests/tunnel_loopback.rs`).
const PAYLOAD_LEN: usize = 96 * 1024;

// ---------------------------------------------------------------------------
// The destination
// ---------------------------------------------------------------------------

/// A loopback TCP echo server: every connection is echoed back verbatim
/// until the peer half-closes, then this side half-closes too. The
/// accept loop is detached — it lives as long as the test process, which
/// under `nextest` is one process per test.
fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the echo server");
    let addr = listener.local_addr().expect("echo server address");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            thread::spawn(move || {
                let mut reader = stream.try_clone().expect("clone the echo socket");
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
                let _ = writer.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

/// A port nothing is listening on: bound and released, so the kernel is
/// the one that says it was free. Inherently a small race — nothing else
/// in this process claims it, and a stray claim would only turn the
/// "refused" case into a passing round trip, i.e. a loud failure rather
/// than a silent pass.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a free port");
    listener.local_addr().expect("picked port").port()
}

/// `PAYLOAD_LEN` bytes that are not a repeat of any single buffer's worth,
/// so a mis-ordered or dropped chunk cannot look correct.
fn payload() -> Vec<u8> {
    (0..PAYLOAD_LEN)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<u8>>()
}

/// Write `payload` into `127.0.0.1:<port>` and read everything that comes
/// back, half-closing after the write so the far end sees an EOF.
///
/// The write runs on its own thread: a payload larger than the socket
/// buffers would otherwise deadlock a write-then-read sequence against an
/// echo that is itself blocked writing to us.
fn round_trip(port: u16, payload: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut writer = socket.try_clone()?;
    let sender = thread::spawn(move || -> std::io::Result<()> {
        writer.write_all(&payload)?;
        writer.flush()?;
        writer.shutdown(Shutdown::Write)
    });
    let mut back = Vec::new();
    let read = {
        let mut reader = socket;
        reader.read_to_end(&mut back).map(|_| ())
    };
    let sent = sender.join().expect("the sender thread panicked");
    // Report a read failure first: on a refused tunnel the write often
    // succeeds into the local buffer and only the read observes the reset.
    read.and(sent).map(|()| back)
}

/// The bytes a *refused* tunnel delivers: none. Either the local socket is
/// reset (an error) or it closes empty — which one depends on whether the
/// reset overtakes the data already queued, so pinning either alone would
/// be a flaky assertion about timing rather than about behavior.
fn assert_no_payload(result: std::io::Result<Vec<u8>>, what: &str) {
    if let Ok(back) = result {
        assert!(
            back.is_empty(),
            "{what}: a refused forward returned {} bytes",
            back.len()
        );
    }
}

// ---------------------------------------------------------------------------
// The client under a pty
// ---------------------------------------------------------------------------

/// A `qsh` client running under its own pty.
///
/// A deliberate small copy of `tui_expect.rs`'s helper rather than a
/// shared one in `common`: that module is compiled into every test binary
/// in this crate, including the ones that must build on Windows, and
/// `expectrl` is a `cfg(unix)` dev-dependency.
struct PtyClient {
    session: OsSession,
}

impl PtyClient {
    fn spawn(sandbox: &Sandbox, args: &[&str]) -> Self {
        let mut command = sandbox.command(args);
        command.env("TERM", "xterm-256color");
        let mut session = Session::spawn(command).expect("spawn qsh under a pty");
        session.set_expect_timeout(Some(IO_TIMEOUT));
        Self { session }
    }

    /// Wait for `needle`, or fail naming what never arrived.
    fn expect(&mut self, needle: &str) {
        if let Err(err) = self.session.expect(needle) {
            panic!("waiting for {needle:?}: {err}");
        }
    }

    /// Type bytes at the client verbatim; Enter is CR, what a terminal
    /// actually sends.
    fn type_(&mut self, keys: &str) {
        self.session.send(keys).expect("send to the client's pty");
    }

    /// Run `echo` in the attached shell and wait for its output. The
    /// marker is split by an empty quote so the echo of the typed line
    /// cannot satisfy the expectation.
    fn shell_round_trip(&mut self, marker: &str) {
        self.type_(&format!("echo {marker}''-OK\r"));
        self.expect(&format!("{marker}-OK"));
    }
}

// ---------------------------------------------------------------------------
// A held `qsh tunnel open` child
// ---------------------------------------------------------------------------

/// A running `qsh tunnel open … --json` child, killed on drop. The
/// process *is* the tunnel's holder (`PLAN.md` M4 §4.1 #1), so there is no
/// close RPC: killing it is the whole teardown.
struct TunnelGuard {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
}

impl TunnelGuard {
    /// Start the child and return it together with the single envelope it
    /// prints before it starts holding.
    fn start(client: &Sandbox, spec: &str) -> (Self, Value) {
        let mut command: Command =
            client.command(&["tunnel", "open", HOST_ALIAS, "--local", spec, "--json"]);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qsh tunnel open");
        let mut stdout = BufReader::new(child.stdout.take().expect("tunnel open stdout pipe"));
        let mut line = String::new();
        // The child flushes stdout before it blocks, so this returns as
        // soon as the tunnel is up — no sleep, and a failure to start
        // shows as an EOF (empty line) rather than a hang.
        stdout.read_line(&mut line).expect("read the envelope line");
        assert!(
            !line.trim().is_empty(),
            "qsh tunnel open printed no envelope; stderr:\n{}",
            drain_stderr(&mut child)
        );
        let envelope: Value = serde_json::from_str(line.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON: {e}: {line:?}"));
        assert_eq!(envelope["schema"], "qsh.cli/v1");
        (Self { child, stdout }, envelope)
    }

    /// Whether the child is still holding the tunnel.
    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Kill the child and return everything else it wrote to stdout —
    /// which must be nothing: machine mode is one JSON line per command
    /// (`docs/CLI.md` §2.2), and the end of a held tunnel is reported on
    /// stderr.
    fn finish(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut rest = String::new();
        let _ = self.stdout.read_to_string(&mut rest);
        rest
    }
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Everything a failed child wrote to stderr, for a panic message.
fn drain_stderr(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut text);
    }
    text
}

/// The host's `forward.local` audit records for `destination`, once there
/// are at least `want` of them — then asserted to be exactly `want`.
///
/// Polled with a hard deadline rather than read once: the host writes
/// these from another process, so a decision that has been *made* (the
/// bytes came back, so it must have been) can still be a few microseconds
/// from being *on disk*. Waiting for `want` and then demanding exactly
/// `want` is what makes "one decision per tunnel connection" a real
/// assertion instead of a race.
fn forward_audit(host: &Sandbox, destination: &str, want: usize) -> Vec<Value> {
    let records = common::poll_until(
        &format!("{want} forward.local record(s) for {destination}"),
        IO_TIMEOUT,
        || {
            let records: Vec<Value> = host
                .audit_records()
                .into_iter()
                .filter(|record| {
                    record["action"] == "forward.local" && record["resource"] == destination
                })
                .collect();
            (records.len() >= want).then_some(records)
        },
    );
    assert_eq!(
        records.len(),
        want,
        "expected exactly {want} forward.local record(s) for {destination}, got {records:#?}"
    );
    records
}

// ---------------------------------------------------------------------------
// DoD 1 — the interactive form
// ---------------------------------------------------------------------------

/// **DoD 1 (local leg).** `qsh [user@]host -L <lport>:127.0.0.1:<echo>`
/// under a real terminal: a TCP write to the local port reaches the
/// destination on the host and comes back, while the shell on the same
/// connection keeps working (`PLAN.md` M4 Step 3 (c) L5, `docs/PRD.md`
/// §131-135).
#[test]
fn the_interactive_form_forwards_a_local_port_to_the_remote_destination() {
    let fleet = Fleet::start();
    let echo = start_echo();
    let local_port = free_port();
    let spec = format!("{local_port}:127.0.0.1:{}", echo.port());

    let mut client = PtyClient::spawn(&fleet.client, &[HOST_ALIAS, "-L", &spec]);

    // The startup line is the deterministic "the listener is bound"
    // signal (stderr, merged into the pty's stream) — never a sleep.
    client.expect(&format!(
        "qsh: forwarding 127.0.0.1:{local_port} -> 127.0.0.1:{} on {HOST_ALIAS}",
        echo.port()
    ));

    let sent = payload();
    let back = round_trip(local_port, sent.clone()).expect("round trip through the local forward");
    assert_eq!(
        back.len(),
        sent.len(),
        "the forward returned {} of {} bytes",
        back.len(),
        sent.len()
    );
    assert!(back == sent, "the forward corrupted the payload");

    // The session on the same connection is unaffected: a tunnel that
    // starved or wedged the PTY would show up here (`docs/design/protocol.md` §12).
    client.shell_round_trip("QSH-FORWARD");

    // The host audited the decision, structurally and once per connection.
    let destination = format!("127.0.0.1:{}", echo.port());
    let records = forward_audit(&fleet.host, &destination, 1);
    let record = &records[0];
    assert_eq!(record["decision"], "allow");
    assert_eq!(record["principal"], CLIENT_PRINCIPAL);
    assert_eq!(record["resource"], destination.as_str());

    // A second connection is authorized again — the ticket exception in
    // `docs/design/protocol.md` §7 is per stream, not per session.
    let back = round_trip(local_port, b"second".to_vec()).expect("second round trip");
    assert_eq!(back, b"second");
    // Each tunnel connection owes its own decision: the ticket exception
    // in `docs/design/protocol.md` §7 is per stream, not per session.
    let _ = forward_audit(&fleet.host, &destination, 2);

    client.type_("exit\r");
    let _ = client.session.expect(expectrl::Eof);

    // The forward dies with the client process: nothing holds the port.
    let listener = common::poll_until("the forwarded port to be released", IO_TIMEOUT, || {
        TcpListener::bind(("127.0.0.1", local_port)).ok()
    });
    drop(listener);
}

// ---------------------------------------------------------------------------
// The machine-mode surface
// ---------------------------------------------------------------------------

/// `qsh tunnel open host --local … --json`: one envelope naming the bound
/// address, then the process holds the tunnel open (`docs/CLI.md` §6.9,
/// `PLAN.md` M4 §4.1 #1).
#[test]
fn tunnel_open_reports_the_bound_forward_and_holds_it() {
    let fleet = Fleet::start();
    let echo = start_echo();
    let local_port = free_port();
    let spec = format!("{local_port}:127.0.0.1:{}", echo.port());

    let (mut tunnel, envelope) = TunnelGuard::start(&fleet.client, &spec);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(envelope["command"], "tunnel.open");
    let data = &envelope["data"];
    assert_eq!(data["mode"], "local");
    assert_eq!(data["host"], HOST_ALIAS);
    assert_eq!(data["bind"], format!("127.0.0.1:{local_port}"));
    assert_eq!(data["forward_to"], format!("127.0.0.1:{}", echo.port()));
    // A fixed-port forward reports the port it bound too — `docs/CLI.md`
    // §6.9's own `Tunnel` example carries `actual_port` for exactly this
    // shape, and a machine caller should never have to re-split `bind` to
    // find it.
    assert_eq!(data["actual_port"], local_port, "{envelope}");
    assert!(
        data["tunnel_id"].as_str().is_some_and(|id| !id.is_empty()),
        "{envelope}"
    );

    let sent = payload();
    let back = round_trip(local_port, sent.clone()).expect("round trip through the held tunnel");
    assert!(back == sent, "the held tunnel corrupted the payload");

    let destination = format!("127.0.0.1:{}", echo.port());
    let records = forward_audit(&fleet.host, &destination, 1);
    assert_eq!(records[0]["decision"], "allow");

    assert!(tunnel.is_running(), "the holder exited while serving");
    let rest = tunnel.finish();
    assert!(
        rest.is_empty(),
        "machine mode printed more than one stdout line: {rest:?}"
    );
}

/// An allowed forward to a destination that refuses the connection: the
/// host answers `ConnectResult{ok:false, CONNECTION_FAILED}`, the local
/// socket carries no payload, and the forward keeps serving
/// (`docs/design/protocol.md` §7).
#[test]
fn a_forward_to_a_dead_destination_delivers_nothing_and_survives() {
    let fleet = Fleet::start();
    let dead = free_port();
    let local_port = free_port();
    let spec = format!("{local_port}:127.0.0.1:{dead}");

    let (mut tunnel, envelope) = TunnelGuard::start(&fleet.client, &spec);
    assert_eq!(envelope["ok"], true, "{envelope}");

    assert_no_payload(
        round_trip(local_port, b"nobody is home".to_vec()),
        "dead destination",
    );

    // The dial was still authorized before it was attempted — the failure
    // is the destination's, not the gate's.
    let records = forward_audit(&fleet.host, &format!("127.0.0.1:{dead}"), 1);
    assert_eq!(records[0]["decision"], "allow");

    // One refused connection must not end the forward.
    assert!(
        tunnel.is_running(),
        "a refused connection killed the holder"
    );
    assert_no_payload(
        round_trip(local_port, b"still nobody".to_vec()),
        "second dead destination attempt",
    );
    assert!(
        tunnel.is_running(),
        "the holder exited after a second refusal"
    );
}

// ---------------------------------------------------------------------------
// Nothing is created before the spec is accepted
// ---------------------------------------------------------------------------

/// A non-loopback bind is refused before anything exists: no session on
/// the host, no listener locally (`PLAN.md` M4 §4.1 #3, `docs/PRD.md` §9
/// "no resource before authorization").
#[test]
fn a_non_loopback_bind_is_refused_before_a_session_exists() {
    let fleet = Fleet::start();
    let local_port = free_port();
    let spec = format!("0.0.0.0:{local_port}:127.0.0.1:9");

    let output = fleet
        .client
        .command(&[HOST_ALIAS, "-L", &spec])
        .stdin(Stdio::null())
        .output()
        .expect("run the interactive form");
    assert_eq!(exit_code(&output), 255, "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "a refused spec wrote to stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("INVALID_ARGUMENT"),
        "expected INVALID_ARGUMENT, got: {stderr}"
    );

    // Nothing was opened on the host…
    let (code, listed) = fleet.client.json(&["sessions", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{listed}");
    assert_eq!(
        listed["data"]["sessions"].as_array().map(Vec::len),
        Some(0),
        "a refused forward spec still opened a session: {listed}"
    );
    // …and nothing bound the port it asked for.
    TcpListener::bind(("127.0.0.1", local_port)).expect("the refused spec bound the local port");
}

/// A malformed spec is the same story, and it is `INVALID_ARGUMENT` from
/// `qsh-core`'s parser rather than a clap usage error — the CLI attaches
/// no `value_parser`, so the single spec→`ErrorCode` mapping lives in one
/// place (`docs/CLI.md` §3.3).
#[test]
fn a_malformed_spec_is_an_error_envelope_not_a_usage_error() {
    let fleet = Fleet::start();

    let (code, envelope) = fleet.client.json(&[
        "tunnel", "open", HOST_ALIAS, "--local", "nonsense", "--json",
    ]);
    assert_eq!(code, 255, "{envelope}");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(envelope["error"]["code"], "INVALID_ARGUMENT", "{envelope}");
}
