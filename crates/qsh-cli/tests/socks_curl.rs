//! `socks_curl` — the ADR-0019 / `docs/CLI.md` §6.9 curl acceptance test: a
//! real `curl --socks5-hostname` driven through the real `qsh` binary's
//! `-D` SOCKS5 listener. Every
//! other `-D` test in this workspace drives the wire protocol from the
//! client side — a hand-rolled SOCKS5 codec (`dynamic_forward.rs`'s
//! `socks5_greet`, `dynamic_loopback.rs`'s
//! `connect_request_ipv4`/`read_rep`) — which proves `qsh` implements
//! SOCKS5 correctly but never proves a real, independent SOCKS5 client
//! (one that has never read this codebase) can actually use it. `curl` is
//! that independent client.
//!
//! **`--socks5-hostname` positive coverage is split in two.**
//! [`positive_path_curl_round_trips_through_the_socks_listener`] builds its
//! URL from an IPv4 literal, so curl emits ATYP `0x01` there — byte for
//! byte what plain `--socks5` would send, proving the round trip but not
//! the name-resolution half of `--socks5-hostname`.
//! [`positive_path_by_hostname_sends_a_real_domainname_connect`] is the
//! DOMAINNAME (ATYP `0x03`) twin, but there is no portable LAN-resolvable
//! name to depend on, so it only runs when the runner's own hostname
//! happens to resolve to the same address [`require_reachable_lan_ip`]
//! probed; otherwise that is an environmental gap, not a product one, and
//! it prints a skip line the same way a missing `curl` does.
//!
//! `#![cfg(unix)]`: `DynamicTunnelGuard::terminate_and_wait` (the process
//! teardown [`port_rebinds_after_the_holder_exits_and_the_new_listener_still_works`]
//! needs) sends a real `SIGTERM` — `qsh tunnel open --dynamic` installs no
//! signal handler on this path (`run_tunnel_open_dynamic` in
//! `crates/qsh-cli/src/main.rs` ends in `Ops::tunnel_dynamic`'s
//! `TunnelHold::hold()`, whose `wait_for_end` selects only on the forward's
//! own listener failing or the connection dying — no signal arm; contrast
//! `run_serve`/`run_listen`/`run_reverse`, which do wire in
//! `shutdown_signal`), so this is process death by the default
//! disposition, not a graceful release, that frees the listen port — and
//! this file's own `locate_curl` checks the executable bit via
//! `std::os::unix::fs::PermissionsExt` — both unix only, same reasoning
//! `dynamic_forward.rs`'s own `cfg(unix)` items give.
//!
//! **Skip/strict convention.** `locate_curl`/`curl_required`/`skip` below
//! are this file's own copy of `tui_expect.rs`'s `locate`/
//! `required_by_strict`/`skip(binary)` shape, simplified the way
//! `reverse_blackout.rs` simplifies the same convention to a single
//! hardcoded reason: this file needs exactly one binary (`curl`), not a set
//! of five to enumerate. Off CI (`QSH_ACCEPTANCE_STRICT` unset), a missing
//! `curl` is a printed `SKIP:` line; with `QSH_ACCEPTANCE_STRICT` naming
//! `curl` (or `1`/`all`), a missing `curl` is a panic — never a silent
//! downgrade to a skip once a runner has promised it
//! (`.github/workflows/ci.yml`'s `acceptance` job does).
//!
//! **Five checks**, each its own `#[test]` so a `curl`-less runner reports
//! five skips, not one: the positive path by IPv4 literal, the positive
//! path again by hostname — best-effort, only when the runner's own
//! hostname happens to resolve to its own LAN address, and a printed skip
//! line otherwise, on CI included; see [`require_lan_hostname`] — the
//! host-local filter (by name and by literal), an ACL deny with its
//! structural audit record, and a port re-bind after the holder exits.
//!
//! `DynamicTunnelGuard` (the held `qsh tunnel open --dynamic` child) lives
//! in `tests/common/mod.rs` — moved there from `dynamic_forward.rs` once
//! this file needed the identical shape, rather than copy-pasting it a
//! second time.

#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use common::{
    AUDIT_KEYS, CLIENT_ALIAS, DynamicTunnelGuard, Fleet, HOST_ALIAS, Sandbox, ServeGuard,
};
use serde_json::Value;

// ---------------------------------------------------------------------
// The skip/strict convention (`tui_expect.rs`/`reverse_blackout.rs`'s own
// shape, single-binary)
// ---------------------------------------------------------------------

/// Resolve `curl` on the runner's `PATH`, checking it is actually
/// executable (a non-executable `curl` on `PATH` would otherwise turn a
/// clean skip into a confusing failure inside `Command::output`) — same
/// technique as `tui_expect.rs::locate`.
fn locate_curl() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("curl"))
        .find(|candidate| {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(candidate)
                .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

/// Whether this run promised `curl` via `QSH_ACCEPTANCE_STRICT` — same
/// vocabulary as `tui_expect.rs::required_by_strict` (unset/`0` = nothing
/// required, `1`/`all` = everything, or a comma-separated list naming
/// `curl`).
fn curl_required() -> bool {
    let Some(value) = std::env::var_os("QSH_ACCEPTANCE_STRICT") else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim();
    if value.is_empty() || value == "0" {
        return false;
    }
    if value == "1" || value == "all" {
        return true;
    }
    value.split(',').any(|name| name.trim() == "curl")
}

/// Announce a skipped `socks_curl` check, loudly enough to find in a CI
/// log — or fail, when [`curl_required`] says this runner promised `curl`.
/// Never downgrades a failure to a skip.
fn skip() {
    assert!(
        !curl_required(),
        "QSH_ACCEPTANCE_STRICT requires curl, but it is not installed on this runner"
    );
    eprintln!("SKIP: curl is not installed on this runner");
}

// ---------------------------------------------------------------------
// Small local helpers
// ---------------------------------------------------------------------

/// A port nothing is listening on, released back to the kernel — same
/// technique as `dynamic_forward.rs`'s/`tunnel_e2e.rs`'s own copies.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a free port");
    listener.local_addr().expect("picked port").port()
}

/// [`qsh_testkit::net_probe::require_non_loopback_v4`] from synchronous
/// test code. This file's checks are plain `#[test]`s driving real `qsh`
/// and `curl` subprocesses, so a one-shot runtime for the one async probe
/// call is cheaper than promoting every test to `#[tokio::test]` — the same
/// technique `dynamic_forward.rs`'s own reverse-route tests use
/// (`tokio::runtime::Runtime::new()` + `block_on`) for the identical probe.
fn require_reachable_lan_ip() -> qsh_testkit::net_probe::Gap<Ipv4Addr> {
    let rt = tokio::runtime::Runtime::new().expect("build a tokio runtime for the route probe");
    rt.block_on(qsh_testkit::net_probe::require_non_loopback_v4(
        "no reachable non-loopback address on this host",
    ))
}

/// A name that a real SOCKS5 `DOMAINNAME` `CONNECT` can carry across the
/// wire and that this host's own resolver turns back into `ip` — the one
/// piece [`require_reachable_lan_ip`] cannot supply on its own, since there
/// is no name this workspace can assume is LAN-resolvable on every runner
/// (the obvious candidate, the runner's own hostname, usually maps to
/// `127.0.1.1`, which the host-local filter would then correctly refuse).
///
/// This asks the runner's own hostname (`hostname(1)`, unix-only same as
/// this whole file) and keeps it only when forward-resolving it — via the
/// same OS resolver `qsh`'s `TokioResolver` uses — lands on exactly `ip`.
/// Unlike [`require_reachable_lan_ip`]'s `Gap::Fail` on CI, a mismatch here
/// is always `Gap::Skip`, never `Gap::Fail`: whether a runner's hostname
/// happens to resolve to its own LAN address is an accident of how that
/// runner was provisioned, not a fact this suite's contract promises, so
/// treating a mismatch as a CI failure would fail the build over something
/// `-D` has no say in.
fn require_lan_hostname(ip: Ipv4Addr) -> qsh_testkit::net_probe::Gap<String> {
    use qsh_testkit::net_probe::Gap;

    let reason = "no local hostname resolves to the probed LAN address";
    let candidate = Command::new("hostname")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|name| !name.is_empty());
    let Some(candidate) = candidate else {
        return Gap::Skip(reason.to_string());
    };
    let resolves_to_ip = (candidate.as_str(), 0u16)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|addr| addr.ip()).any(|got| got == IpAddr::V4(ip)))
        .unwrap_or(false);
    if resolves_to_ip {
        Gap::Ready(candidate)
    } else {
        Gap::Skip(format!("{reason}: {candidate:?} does not resolve to {ip}"))
    }
}

/// Run `curl --socks5-hostname <socks_bind> <url>` and return its output.
/// `--max-time` bounds the call so a qsh regression that hangs instead of
/// answering a REP shows up as a bounded test failure, not a stuck nextest
/// slow-timeout (`docs/CLI.md`'s "no sleep()-based waiting" discipline,
/// applied to an external process rather than an in-process poll).
fn curl_get(curl: &Path, socks_bind: &str, url: &str) -> std::process::Output {
    Command::new(curl)
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "20",
            "--socks5-hostname",
            socks_bind,
            url,
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to run curl: {e}"))
}

/// Assert `output` is `curl` failing to complete a request through a SOCKS5
/// proxy because `-D` refused the `CONNECT` — non-zero exit, and stderr
/// carries curl's specific refusal wording. Curl >=7.73 reports a SOCKS
/// proxy failure as exit 97 (`CURLE_PROXY`), but this checks the message
/// rather than hard-coding that exit code so an older curl on some runner
/// does not turn a correct refusal into a false red — see
/// `host_local_filter_blocks_curl_by_name_and_by_literal` and
/// `acl_deny_blocks_curl_and_leaves_one_structural_audit_record`, this
/// helper's two callers.
///
/// Matches curl's own "can't complete socks5 connection" wording rather
/// than the bare substring `"socks"`: curl also puts `"SOCKS5"` in its
/// message for a truncated or absent handshake response (e.g. "Unable to
/// receive initial SOCKS5 response."), which a bare substring match would
/// wrongly accept as the REP `0x02` refusal this helper is meant to pin.
fn assert_curl_failed_via_socks(output: &std::process::Output) {
    assert!(
        !output.status.success(),
        "curl unexpectedly succeeded reaching a destination `-D` must refuse: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        stderr.contains("can't complete socks5 connection"),
        "expected curl's stderr to report a SOCKS5 refusal, got exit {:?}, stderr: {stderr:?}",
        output.status.code()
    );
}

/// A minimal HTTP/1.1 responder: accepts a connection, drains the request
/// through the blank line ending the headers, writes `body` back with a
/// `Content-Length`, and closes — the `curl` twin of `dynamic_forward.rs`'s
/// `socks5_greet`/`dynamic_loopback.rs`'s `greet_no_auth`, which drive the
/// SOCKS5 codec directly rather than sit behind a real HTTP request. Counts
/// every accept so a test can assert a destination genuinely was, or was
/// not, dialed.
struct HttpResponder {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    _thread: JoinHandle<()>,
}

impl HttpResponder {
    /// Bind on `ip`, port `0` (kernel-assigned), and start serving `body`
    /// to every connection in a background thread.
    fn start(ip: Ipv4Addr, body: &'static str) -> Self {
        let listener = TcpListener::bind((ip, 0)).expect("bind the http responder");
        let addr = listener.local_addr().expect("responder addr");
        let accepts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepts);
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                let mut reader =
                    BufReader::new(stream.try_clone().expect("clone the responder stream"));
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if line == "\r\n" || line == "\n" => break,
                        Ok(_) => {}
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
        Self {
            addr,
            accepts,
            _thread: thread,
        }
    }

    /// This responder's bound port.
    fn port(&self) -> u16 {
        self.addr.port()
    }

    /// How many connections this responder has accepted so far.
    fn accept_count(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------
// (a) Positive path
// ---------------------------------------------------------------------

/// The positive path: a real `curl --socks5-hostname` `CONNECT` through the
/// `-D` listener reaches a real, non-loopback HTTP responder and gets its
/// body back verbatim — `-D`'s whole reason to exist, proven against an
/// independent SOCKS5 client instead of this crate's own codec probes.
///
/// The URL is an IPv4 literal, so curl sends ATYP `0x01` here — exactly
/// what plain `--socks5` would send too. This proves the round trip but
/// not `--socks5-hostname`'s distinguishing behavior (remote name
/// resolution); [`positive_path_by_hostname_sends_a_real_domainname_connect`]
/// is the DOMAINNAME twin.
#[test]
fn positive_path_curl_round_trips_through_the_socks_listener() {
    let Some(curl) = locate_curl() else {
        skip();
        return;
    };
    let ip = qsh_testkit::gap_or_return!(
        require_reachable_lan_ip(),
        "positive_path_curl_round_trips_through_the_socks_listener"
    );

    let fleet = Fleet::start();
    let port = free_port();
    let (mut guard, envelope) = DynamicTunnelGuard::start(&fleet.client, &port.to_string());
    let bind = envelope["data"]["bind"]
        .as_str()
        .expect("bind string")
        .to_string();

    const BODY: &str = "socks-curl-positive-path";
    let responder = HttpResponder::start(ip, BODY);
    let url = format!("http://{ip}:{}/", responder.port());

    let output = curl_get(&curl, &bind, &url);
    assert!(
        output.status.success(),
        "curl through the -D listener must succeed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        stdout, BODY,
        "curl's body must be exactly what the responder sent"
    );
    assert_eq!(
        responder.accept_count(),
        1,
        "the responder must see exactly one accept"
    );

    assert!(
        guard.is_running(),
        "the listener must survive one real client's round trip"
    );
    let rest = guard.finish();
    assert!(
        rest.is_empty(),
        "no output after the first envelope: {rest:?}"
    );
}

// ---------------------------------------------------------------------
// (a2) Positive path, by hostname — the ATYP `0x03` (DOMAINNAME) twin
// ---------------------------------------------------------------------

/// The positive path again, but the URL names the destination by hostname
/// instead of by IPv4 literal, so curl emits a real SOCKS5 DOMAINNAME
/// `CONNECT` and `qsh`'s own resolver — not curl's — turns the name back
/// into an address. This is the half of `--socks5-hostname` the IPv4-literal
/// [`positive_path_curl_round_trips_through_the_socks_listener`] cannot
/// exercise.
///
/// Best-effort: see [`require_lan_hostname`]'s own doc for why a mismatch
/// here is always a skip, on CI or off it.
#[test]
fn positive_path_by_hostname_sends_a_real_domainname_connect() {
    let Some(curl) = locate_curl() else {
        skip();
        return;
    };
    let ip = qsh_testkit::gap_or_return!(
        require_reachable_lan_ip(),
        "positive_path_by_hostname_sends_a_real_domainname_connect"
    );
    let hostname = qsh_testkit::gap_or_return!(
        require_lan_hostname(ip),
        "positive_path_by_hostname_sends_a_real_domainname_connect"
    );

    let fleet = Fleet::start();
    let port = free_port();
    let (mut guard, envelope) = DynamicTunnelGuard::start(&fleet.client, &port.to_string());
    let bind = envelope["data"]["bind"]
        .as_str()
        .expect("bind string")
        .to_string();

    const BODY: &str = "socks-curl-positive-path-by-hostname";
    let responder = HttpResponder::start(ip, BODY);
    let url = format!("http://{hostname}:{}/", responder.port());

    let output = curl_get(&curl, &bind, &url);
    assert!(
        output.status.success(),
        "curl through the -D listener must succeed resolving {hostname:?}: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        stdout, BODY,
        "curl's body must be exactly what the responder sent"
    );
    assert_eq!(
        responder.accept_count(),
        1,
        "the responder must see exactly one accept"
    );

    assert!(
        guard.is_running(),
        "the listener must survive one real client's round trip"
    );
    let rest = guard.finish();
    assert!(
        rest.is_empty(),
        "no output after the first envelope: {rest:?}"
    );
}

// ---------------------------------------------------------------------
// (b) Host-local filter
// ---------------------------------------------------------------------

/// The host-local filter: `-D` sends `deny_host_local: true` on every
/// `CONNECT`, unconditionally (ADR-0019) — so a real SOCKS5 client aimed at
/// a loopback destination, whether by name (`localhost`) or by literal
/// (`127.0.0.1`), must be refused through the same listener, and the
/// loopback responder must never see either attempt.
#[test]
fn host_local_filter_blocks_curl_by_name_and_by_literal() {
    let Some(curl) = locate_curl() else {
        skip();
        return;
    };

    let fleet = Fleet::start();
    let port = free_port();
    let (mut guard, envelope) = DynamicTunnelGuard::start(&fleet.client, &port.to_string());
    let bind = envelope["data"]["bind"]
        .as_str()
        .expect("bind string")
        .to_string();

    let responder = HttpResponder::start(Ipv4Addr::LOCALHOST, "host-local-must-never-be-reached");
    let hport = responder.port();

    for host in ["localhost", "127.0.0.1"] {
        let url = format!("http://{host}:{hport}/");
        let output = curl_get(&curl, &bind, &url);
        assert_curl_failed_via_socks(&output);
    }

    assert_eq!(
        responder.accept_count(),
        0,
        "the host-local filter must never let curl reach the loopback responder"
    );

    assert!(
        guard.is_running(),
        "the listener must survive two refused clients"
    );
    let rest = guard.finish();
    assert!(
        rest.is_empty(),
        "no output after the first envelope: {rest:?}"
    );
}

// ---------------------------------------------------------------------
// (c) ACL deny
// ---------------------------------------------------------------------

/// ACL deny: a target whose `acl.toml` grants nothing refuses a real
/// `curl` `CONNECT` the same way the host-local filter does (`REP 0x02`,
/// `docs/CLI.md` §6.9's REP table) — the CLI-driven twin of `qsh-testkit`'s
/// `dynamic_loopback.rs::acl_deny_gives_rep_02_and_zero_dials`. The host's
/// audit log gets exactly one structural `forward.local` deny record — no
/// field beyond [`AUDIT_KEYS`] (`docs/design/architecture.md` §6: never a
/// payload).
#[test]
fn acl_deny_blocks_curl_and_leaves_one_structural_audit_record() {
    let Some(curl) = locate_curl() else {
        skip();
        return;
    };
    // Unlike the positive path, a denied CONNECT is never dialed at all, so
    // this only needs a route to refuse — not a live, hairpin-probed round
    // trip (`dynamic_loopback.rs::acl_deny_gives_rep_02_and_zero_dials`
    // makes the identical choice, for the identical reason).
    let ip = qsh_testkit::gap_or_return!(
        qsh_testkit::net_probe::require_non_loopback_v4_route(
            "no non-loopback IPv4 route on this host"
        ),
        "acl_deny_blocks_curl_and_leaves_one_structural_audit_record"
    );

    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    // No acl.toml planted: default-deny denies every action, including the
    // `forward.local` re-use `-D`'s CONNECT authorization is (§2.5) —
    // opening the listener itself needs no ACL grant either way (§6.9's
    // own "open 시점에 ACL 검사는 없다").
    let serve = ServeGuard::start_without_policy(&host, &[]);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let port = free_port();
    let (mut guard, envelope) = DynamicTunnelGuard::start(&client, &port.to_string());
    let bind = envelope["data"]["bind"]
        .as_str()
        .expect("bind string")
        .to_string();

    let responder = HttpResponder::start(ip, "acl-deny-must-never-be-reached");
    let url = format!("http://{ip}:{}/", responder.port());

    let output = curl_get(&curl, &bind, &url);
    assert_curl_failed_via_socks(&output);
    assert_eq!(
        responder.accept_count(),
        0,
        "an ACL-denied CONNECT must dial nothing"
    );

    let audit = common::wait_for_audit(&host, "a forward.local deny", |record| {
        record["action"] == "forward.local"
    });
    let forward_local: Vec<&Value> = audit
        .iter()
        .filter(|record| record["action"] == "forward.local")
        .collect();
    assert_eq!(forward_local.len(), 1, "{audit:?}");
    assert_eq!(forward_local[0]["decision"], "deny", "{forward_local:?}");
    for record in &forward_local {
        let fields = record.as_object().expect("audit record is a JSON object");
        for key in fields.keys() {
            assert!(
                AUDIT_KEYS.contains(&key.as_str()),
                "audit record carries a non-structural field {key:?}: {record}"
            );
        }
    }

    assert!(
        guard.is_running(),
        "the listener must survive a denied client"
    );
    let rest = guard.finish();
    assert!(
        rest.is_empty(),
        "no output after the first envelope: {rest:?}"
    );
}

// ---------------------------------------------------------------------
// (d) Port re-bind after exit
// ---------------------------------------------------------------------

/// Port re-bind after exit: terminating the `tunnel open --dynamic` holder
/// ends the process (`terminate_and_wait`'s own doc — this path installs no
/// signal handler, so `SIGTERM` is plain process death, not a graceful
/// listener release). What this pins is not `SO_REUSEADDR` (tokio's
/// `TcpListener::bind`, `crates/qsh-core/src/tunnel/dynamic.rs`'s
/// `bind_with_limits`, sets it exactly as `std` does, so that alone
/// distinguishes nothing) but two separate facts: the holder's death
/// actually releases the port — a listener leaked into a surviving process
/// would give `EADDRINUSE` on the second bind below, and `SO_REUSEADDR`
/// does not let a fresh bind steal an address an active listen socket still
/// holds — and the second `qsh tunnel open --dynamic` on that same port is
/// a real, independently working listener, not just a successful `bind()`:
/// its own envelope reports the same `actual_port`, and a second curl round
/// trip actually gets served through it.
#[test]
fn port_rebinds_after_the_holder_exits_and_the_new_listener_still_works() {
    let Some(curl) = locate_curl() else {
        skip();
        return;
    };
    let ip = qsh_testkit::gap_or_return!(
        require_reachable_lan_ip(),
        "port_rebinds_after_the_holder_exits_and_the_new_listener_still_works"
    );

    let fleet = Fleet::start();
    let port = free_port();
    let spec = port.to_string();

    let (guard, envelope) = DynamicTunnelGuard::start(&fleet.client, &spec);
    assert_eq!(envelope["data"]["actual_port"], port, "{envelope}");
    let bind = envelope["data"]["bind"]
        .as_str()
        .expect("bind string")
        .to_string();

    const FIRST_BODY: &str = "socks-curl-port-rebind-first";
    let first_responder = HttpResponder::start(ip, FIRST_BODY);
    let first_url = format!("http://{ip}:{}/", first_responder.port());
    let first_output = curl_get(&curl, &bind, &first_url);
    assert!(
        first_output.status.success(),
        "curl through the first listener must succeed: {first_output:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&first_output.stdout),
        FIRST_BODY,
        "curl's body must be exactly what the first responder sent"
    );
    assert_eq!(first_responder.accept_count(), 1);

    let exited = guard.terminate_and_wait(Duration::from_secs(5));
    assert!(
        exited,
        "the tunnel open child did not exit within 5s of SIGTERM"
    );

    let (mut guard2, envelope2) = DynamicTunnelGuard::start(&fleet.client, &spec);
    assert_eq!(
        envelope2["data"]["actual_port"], port,
        "qsh must re-open the exact same port: {envelope2}"
    );
    let bind2 = envelope2["data"]["bind"]
        .as_str()
        .expect("bind string")
        .to_string();

    const BODY: &str = "socks-curl-port-rebind";
    let responder = HttpResponder::start(ip, BODY);
    let url = format!("http://{ip}:{}/", responder.port());
    let output = curl_get(&curl, &bind2, &url);
    assert!(
        output.status.success(),
        "curl through the re-opened listener must succeed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(stdout, BODY);
    assert_eq!(responder.accept_count(), 1);

    assert!(
        guard2.is_running(),
        "the re-opened listener must survive one round trip"
    );
    let rest = guard2.finish();
    assert!(
        rest.is_empty(),
        "no output after the second envelope: {rest:?}"
    );
}
