//! `-D` (SOCKS5 dynamic forwarding), implemented (ADR-0019, `docs/CLI.md`
//! §6.9). Replaces `dynamic_forward_stub.rs`, whose whole premise — every
//! spelling of `-D` always answers `UNSUPPORTED` and creates nothing — is
//! the retired contract (`crates/qsh-core/src/ops/tunnel.rs`'s
//! `DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE`/`_GUIDANCE` and
//! `dynamic_forward_unsupported()` are gone).
//!
//! The "creates nothing" property does not disappear — it moves onto every
//! *failure* path `-D` still has in this file (a non-loopback bind, a
//! rejected flag combination, a malformed handshake): each such test here
//! re-binds the port (or checks
//! the host's audit log) afterward as its own proof, the same technique the
//! old stub file used for its one all-the-time refusal. The remaining
//! failure path, a peer without `dial-filter.v1`, is deliberately not here
//! either — see below.
//!
//! Two tests from the step plan are deliberately not here:
//! `dash_d_refuses_before_bind_when_peer_lacks_capability` (standalone) and
//! its interactive twin. Every real `qsh serve`/`qsh listen` this crate can
//! spawn advertises `dial-filter.v1` unconditionally (it is a fixed entry
//! in `qsh_proto::wire::LOCAL_CAPABILITIES`), so there is no live peer in
//! this codebase — forward or reverse — to dial that lacks it: simulating
//! one would mean hand-rolling a second QUIC/wire peer, or a second
//! `qsh.local.v1` daemon, with a stripped-down handshake, which is a
//! different, much larger undertaking than a CLI black-box test. Both
//! refusal paths are covered where a fake peer is cheap to build instead:
//! `crates/qsh-core/src/ops/tunnel.rs`'s own
//! `tunnel_dynamic_without_dial_filter_capability_is_unsupported_and_binds_nothing`
//! (forward route, using the `#[cfg(test)]` `Connected::for_test_forward`
//! seam) and
//! `tunnel_dynamic_over_reverse_without_dial_filter_capability_is_unsupported_and_binds_nothing`
//! (reverse route, hand-rolling a fake `qsh.local.v1` daemon over a UDS
//! pair) — and `open_dynamic_forwards`/`Ops::session_open_for_dynamic` (the
//! interactive form's own path, ADR-0020 decisions 2–3) run through the exact
//! same `require_dial_filter_capability()` predicate on both routes, not a
//! second independently re-derived `if`, so those two unit tests already
//! cover every call site's behavior, standalone and interactive alike.
//!
//! Every test here runs on both OSes. The interactive tests drive the client
//! in a pseudo-terminal through `tunnel_e2e::PtyClient` (expectrl on unix, a
//! ConPTY on Windows), and the reverse-route cases use the daemon's local
//! control channel, a Unix socket or a named pipe. Windows additionally has
//! the shorter `windows_forward_e2e::dynamic_forward_connect` and
//! `windows_reverse_e2e::dynamic_forward_connect`, a SOCKS5 CONNECT written
//! by the test with no curl.

use crate::common;

use qsh_testkit::net_probe::free_port;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::Stdio;
use std::time::Duration;

use common::{DynamicTunnelGuard, Fleet, HOST_ALIAS, Sandbox, exit_code};
use serde_json::Value;

use crate::tunnel_e2e::PtyClient;

/// `qsh`'s own runtime-failure exit code (`docs/CLI.md` §4) — a private
/// copy, same self-containment reasoning `exit_code_matrix.rs`'s own copy
/// documents.
const EXIT_RUNTIME_FAILURE: i32 = 255;

/// clap's usage-error exit code (`docs/CLI.md` §4) — private copy, same
/// reasoning as [`EXIT_RUNTIME_FAILURE`].
const EXIT_USAGE: i32 = 2;

/// Speak just enough SOCKS5 to prove a listener really is one: the
/// greeting (version 5, one method, no-auth) and the method-select reply
/// it must get back (`0x05 0x00` — ADR-0019 decision 7, no-auth is the
/// only method offered or accepted).
fn socks5_greet(stream: &mut TcpStream) {
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .expect("write the socks5 greeting");
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .expect("read the socks5 method-select reply");
    assert_eq!(
        reply,
        [0x05, 0x00],
        "a real SOCKS5 listener must select no-auth"
    );
}

// ---------------------------------------------------------------------
// `qsh tunnel open --dynamic`
//
// The held-child harness itself (`DynamicTunnelGuard`) moved to
// `tests/it/common/mod.rs` once `socks_curl.rs` (the ADR-0019 / docs/CLI.md
// §6.9 curl acceptance test) needed the identical shape.
// ---------------------------------------------------------------------

/// The success path end to end: one `qsh.cli/v1` envelope naming
/// `tunnel.dynamic`, shaped like `DynamicTunnel` (no `forward_to` — ADR-0019
/// decision 11), a real SOCKS5 listener behind the `bind` it names, and
/// then a hold with nothing further on stdout until the process is killed.
#[test]
fn tunnel_open_dynamic_json_emits_one_envelope_then_holds() {
    let fleet = Fleet::start();
    let port = free_port();
    let (mut guard, envelope) = DynamicTunnelGuard::start(&fleet.client, &port.to_string());

    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(envelope["command"], "tunnel.dynamic", "{envelope}");
    let data = &envelope["data"];
    assert_eq!(data["mode"], "dynamic", "{envelope}");
    assert_eq!(data["protocol"], "socks5", "{envelope}");
    assert_eq!(data["dial_policy"], "deny_host_local", "{envelope}");
    assert_eq!(data["host"], HOST_ALIAS, "{envelope}");
    assert!(
        data.get("tunnel_id")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty()),
        "{envelope}"
    );
    assert!(
        data.get("forward_to").is_none(),
        "tunnel.dynamic's data must have no forward_to field: {envelope}"
    );

    let bind = data["bind"].as_str().expect("bind string").to_string();
    let mut socket = TcpStream::connect(&bind).expect("connect to the dynamic listener");
    socks5_greet(&mut socket);
    drop(socket);

    assert!(
        guard.is_running(),
        "the holder must still be running after one client's handshake"
    );

    let rest = guard.finish();
    assert!(
        rest.is_empty(),
        "no output after the first envelope: {rest:?}"
    );

    // The port is free again once the holder is gone.
    TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("port {port} was not re-bindable after the holder exited: {e}"));
}

/// `--dynamic` conflicts with `--local`/`--remote` at the clap layer (a
/// usage error, exit `2`, nothing on stdout in either mode) — `cli.rs`'s
/// own unit tests already cover every flag-order combination; this is the
/// one black-box check that a real process agrees, plus the zero-resource
/// proof clap's own parser cannot give.
#[test]
fn tunnel_open_dynamic_rejects_local_and_remote_together() {
    let sandbox = Sandbox::initialized();
    let port = free_port();

    let out = sandbox.qsh(&[
        "tunnel",
        "open",
        "box",
        "--dynamic",
        &port.to_string(),
        "--local",
        "8080:localhost:80",
    ]);
    assert_eq!(exit_code(&out), EXIT_USAGE, "{out:?}");
    assert!(
        out.stdout.is_empty(),
        "a clap usage error must write nothing to stdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("port {port} was not re-bindable after the usage error: {e}"));
}

/// `--dynamic` given twice parses fine at the clap layer
/// (`ArgAction::Append`) but is refused by `Ops` with `INVALID_ARGUMENT`
/// ("one listener per `tunnel open`", ADR-0019 decision 1) before either
/// spec is even looked at — no host needs to exist for this refusal to
/// fire.
#[test]
fn tunnel_open_dynamic_given_twice_is_invalid_argument() {
    let sandbox = Sandbox::initialized();
    let port_a = free_port();
    let port_b = free_port();

    let args = [
        "tunnel",
        "open",
        "box",
        "--dynamic",
        &port_a.to_string(),
        "--dynamic",
        &port_b.to_string(),
        "--json",
    ];
    let (code, envelope) = sandbox.json(&args);
    assert_eq!(code, EXIT_RUNTIME_FAILURE, "{envelope}");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(envelope["command"], "tunnel.dynamic", "{envelope}");
    assert_eq!(envelope["error"]["code"], "INVALID_ARGUMENT", "{envelope}");

    for port in [port_a, port_b] {
        TcpListener::bind(("127.0.0.1", port))
            .unwrap_or_else(|e| panic!("port {port} was not re-bindable after the refusal: {e}"));
    }
}

/// A non-loopback `bind:` is refused before a connection is even dialed
/// (ADR-0019 decision 9, same rule `-L` follows) — no host needs to exist,
/// same as the "given twice" case above.
#[test]
fn non_loopback_bind_is_invalid_argument_and_binds_nothing() {
    let sandbox = Sandbox::initialized();
    let port = free_port();
    let spec = format!("0.0.0.0:{port}");

    let args = ["tunnel", "open", "box", "--dynamic", &spec, "--json"];
    let (code, envelope) = sandbox.json(&args);
    assert_eq!(code, EXIT_RUNTIME_FAILURE, "{envelope}");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(envelope["error"]["code"], "INVALID_ARGUMENT", "{envelope}");

    TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
        panic!("port {port} was not re-bindable on 0.0.0.0 after the refusal: {e}")
    });
}

// ---------------------------------------------------------------------
// The interactive form
// ---------------------------------------------------------------------

/// `qsh [user@]host -D <port>` opens a real SOCKS5 listener beside the
/// session — announced on stderr (`human::print_dynamic_forward_started`)
/// before the shell prompt, and still live after a client speaks to it,
/// exactly like `-L`'s own interactive listener.
#[test]
fn interactive_dash_d_opens_listener_beside_session() {
    let fleet = Fleet::start();
    let port = free_port();
    let port_str = port.to_string();

    let mut client = PtyClient::spawn(&fleet.client, &[HOST_ALIAS, "-D", &port_str]);
    client.expect("dynamic forward (socks5) listening on");
    client.shell_round_trip("DASH_D_BESIDE_SESSION");

    let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("connect to the -D listener");
    socks5_greet(&mut socket);
    drop(socket);

    // The session, and the listener, both survive a client's handshake.
    client.shell_round_trip("DASH_D_STILL_ALIVE");

    client.type_("exit\r");
}

/// The interactive form's "creates nothing" property, restored after
/// `dynamic_forward_stub.rs`'s retirement (found missing in review): a
/// non-loopback `-D` bind, combined with a valid `-L` on the same command
/// line, is refused before `session.open` — same technique
/// `tunnel_e2e.rs`'s `a_non_loopback_bind_is_refused_before_a_session_exists`
/// uses for `-L` alone. `parse_dynamic_forwards` runs (and fails) before
/// `session.open` regardless of flag order (`tui::session_loop::run`'s own doc),
/// so the `-L` spec here never gets a chance to open anything either.
///
/// The test drives the interactive form with no terminal on stdin. The
/// refusal itself happens in the client before any connection, the same on
/// every platform (`tui::run` has no per-platform branch).
#[test]
fn interactive_dash_d_non_loopback_bind_creates_no_session_even_combined_with_local_forward() {
    let fleet = Fleet::start();
    let dynamic_port = free_port();
    let local_port = free_port();
    let dynamic_spec = format!("0.0.0.0:{dynamic_port}");
    let local_spec = format!("{local_port}:localhost:1");

    let output = fleet
        .client
        .command(&[HOST_ALIAS, "-D", &dynamic_spec, "-L", &local_spec])
        .stdin(Stdio::null())
        .output()
        .expect("run the interactive form");
    assert_eq!(exit_code(&output), EXIT_RUNTIME_FAILURE, "{output:?}");
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

    let (code, listed) = fleet.client.json(&["sessions", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{listed}");
    assert_eq!(
        listed["data"]["sessions"].as_array().map(Vec::len),
        Some(0),
        "a refused -D spec still opened a session: {listed}"
    );
    TcpListener::bind(("127.0.0.1", dynamic_port))
        .expect("the refused -D spec bound its own listen port");
    TcpListener::bind(("127.0.0.1", local_port))
        .expect("the refused -D spec bound the companion -L's listen port");
}

/// `docs/CLI.md` §7's machine-mode gate answers `INVALID_ARGUMENT` before
/// `-D`'s own reverse-route/capability refusals ever get a turn, because
/// the interactive form has no JSON output mode at all — no host needs to
/// exist for this to fire, since the gate runs before target resolution.
#[test]
fn interactive_dash_d_with_json_is_section_7_invalid_argument_first() {
    let sandbox = Sandbox::initialized();
    let args = ["box", "-D", "1080", "--json"];
    let (code, envelope) = sandbox.json(&args);
    assert_eq!(code, EXIT_RUNTIME_FAILURE, "{envelope}");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "INVALID_ARGUMENT",
        "§7 must win over -D's own refusals when --json is present: {envelope}"
    );
}

// ---------------------------------------------------------------------
// The codec's own refusal shapes, observed from outside
// ---------------------------------------------------------------------

/// A non-SOCKS5 first byte (here, a plain HTTP request) gets zero bytes
/// back and opens no `TCP_CONNECT` stream on the host (ADR-0019 decision
/// 7) — the listener itself survives, and a second, well-formed client can
/// still use it afterward.
#[test]
fn http_request_to_socks_port_gets_no_reply_and_no_tunnel_stream() {
    let fleet = Fleet::start();
    let port = free_port();
    let (mut guard, envelope) = DynamicTunnelGuard::start(&fleet.client, &port.to_string());
    let bind = envelope["data"]["bind"]
        .as_str()
        .expect("bind string")
        .to_string();

    let mut socket = TcpStream::connect(&bind).expect("connect to the dynamic listener");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set a read timeout");
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .expect("write the http request");
    let mut reply = [0u8; 16];
    match socket.read(&mut reply) {
        Ok(0) => {}
        Ok(n) => panic!(
            "a non-SOCKS5 first byte must get zero bytes back, got {n}: {:?}",
            &reply[..n]
        ),
        Err(err) => assert!(
            !matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "the listener never closed the connection: {err}"
        ),
    }
    drop(socket);

    assert!(
        guard.is_running(),
        "the listener itself must survive a rejected client"
    );

    let audit = fleet.host.audit_records();
    assert!(
        audit
            .iter()
            .all(|record| record["action"] != "forward.local"),
        "a rejected non-SOCKS5 first byte must never open a TCP_CONNECT stream (no forward.local \
         audit line): {audit:?}"
    );

    let _ = guard.finish();
}

// ---------------------------------------------------------------------
// `--help` carries the ACL note
// ---------------------------------------------------------------------

/// Slice clap's rendered `--help` text down to one flag's own entry
/// (copied from the retired `dynamic_forward_stub.rs`'s own helper of the
/// same name and shape — `acl_docs.rs`'s `heading_section_slice` for docs,
/// this for `--help` text, same F5 rationale).
fn flag_help_slice<'a>(help: &'a str, header: &str) -> &'a str {
    let start = help
        .find(header)
        .unwrap_or_else(|| panic!("--help must contain the flag header {header:?}: {help}"));
    let rest = &help[start..];
    let end = rest[header.len()..]
        .find("\n  -")
        .map(|i| i + header.len())
        .unwrap_or(rest.len());
    &rest[..end]
}

/// Both `-D` spellings' own `--help` entries quote
/// `qsh_core::ops::tunnel::DYNAMIC_FORWARD_ACL_NOTE` verbatim — the security
/// fact that replaced the P0 stub's refusal wording as the thing every
/// `-D` doc surface must disclose (ADR-0019 decision 14). No host needed:
/// `--help` never dials anything.
#[test]
fn qsh_help_and_tunnel_open_help_carry_the_acl_note() {
    let sandbox = Sandbox::new();

    let output = sandbox.qsh(&["--help"]);
    let help = String::from_utf8_lossy(&output.stdout);
    let section = flag_help_slice(&help, "  -D <SPEC>");
    assert!(
        section.contains(qsh_core::ops::tunnel::DYNAMIC_FORWARD_ACL_NOTE),
        "qsh --help's own -D entry (not merely somewhere in --help) must quote \
         DYNAMIC_FORWARD_ACL_NOTE verbatim: {section}"
    );

    let output = sandbox.qsh(&["tunnel", "open", "--help"]);
    let help = String::from_utf8_lossy(&output.stdout);
    let section = flag_help_slice(&help, "  -D, --dynamic <SPEC>");
    assert!(
        section.contains(qsh_core::ops::tunnel::DYNAMIC_FORWARD_ACL_NOTE),
        "qsh tunnel open --help's own --dynamic entry (not merely somewhere in --help) must \
         quote DYNAMIC_FORWARD_ACL_NOTE verbatim: {section}"
    );
}
