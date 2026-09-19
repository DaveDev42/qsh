//! `-D` (SOCKS5 dynamic forwarding), end to end against a **real** host
//! (ADR-0019; `docs/design/testing.md` L3's tunnel-suite twin of
//! `tunnel_loopback.rs`, which only covers `-L`).
//!
//! **Why this suite needs a non-loopback destination and `tunnel_loopback.rs`
//! does not.** `-D` sends `StreamHeader.deny_host_local: true` on every
//! `CONNECT` it opens, unconditionally (`TunnelHarness::dynamic_forward`'s own
//! doc) — so a destination on `127.0.0.1` is filtered by the very property
//! under test, not reached by it. Most tests here therefore ask the kernel
//! for a real, non-loopback source address via
//! [`qsh_testkit::net_probe`] (the same technique `qsh trust invite` uses
//! internally, `crates/qsh-core/src/trust/invite_address/route.rs::
//! observe_source_addresses` — reimplemented there rather than shared,
//! since that function is `pub(crate)` to `qsh-core`), bind a destination
//! at the returned address, and — off CI — skip with a printed reason on a
//! host with no such route (a sandboxed runner with only loopback). On CI,
//! the same gap fails the test instead: see [`net_probe::Gap`]'s own doc
//! for why a silent skip there would hide a real regression.
//!
//! A route existing is not enough on its own: some networks assign this
//! host a real, non-host-local address and still never loop a connection
//! back to it (client-isolated Wi-Fi, a router with no hairpin NAT — the OS
//! routing table can call the address `local` while the TCP handshake
//! itself never completes, observed running this very suite).
//! [`net_probe::usable_non_loopback_v4`] probes a real self-connect with a
//! short bound before handing the address out. A passing probe is still
//! not a guarantee: the same run that motivated the probe also showed a
//! probed-usable address taking anywhere from under a second to well over
//! a minute for one real round trip (a network hairpinning inconsistently,
//! not simply refusing to), so every test built on it additionally wraps
//! its real exchange in [`NETWORK_BOUND`] via [`net_probe::bound_or_gap`].
//! [`acl_deny_gives_rep_02_and_zero_dials`] only needs an address a
//! *client* denial refuses to dial in the first place, never one this host
//! can actually reach, so it uses the unprobed
//! [`net_probe::require_non_loopback_v4_route`] directly.
//! [`unresolvable_name_gives_rep_04`] and
//! [`localhost_name_is_filtered_rep_02_and_the_loopback_server_sees_no_accept`]
//! need no such address at all (the first never gets past resolution; the
//! second's whole point is that a *loopback* destination is refused), so
//! neither gates on anything.
//!
//! Each test drives [`TunnelHarness::dynamic_forward`] (the real
//! [`qsh_core::tunnel::DynamicForwardHandle`] the CLI's own `-D`/`--dynamic`
//! bind) with a small hand-rolled SOCKS5 client — greeting, `CONNECT`,
//! read the ten-byte reply — since [`TunnelHarness::tcp_connect`] bypasses
//! SOCKS entirely (it exists for `-L`'s own suite) and cannot drive this
//! listener.
//!
//! IPv4 only: `net_probe::find_non_loopback_v4` is the IPv4 half of
//! `route.rs`'s own two-axis observation, which is enough to cover every
//! REP this suite pins — none of them is ATYP-specific.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::DenyAll;
use qsh_core::quota::QuotaLimits;
use qsh_proto::wire;
use qsh_testkit::gap_or_return;
use qsh_testkit::net_probe::{self, LanEcho};
use qsh_testkit::tunnel::TunnelHarness;
use qsh_transport::{FramedRecv, FramedSend};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------
// Local scaffolding
// ---------------------------------------------------------------------

/// Send a one-method (no-auth) greeting and assert it is accepted
/// (ADR-0019 decision 7) — reimplemented here rather than shared with
/// `crates/qsh-cli/tests/dynamic_forward.rs`'s own copy of the same dozen
/// lines, since that helper lives in a different crate's integration
/// tests, not a library either crate can depend on.
async fn greet_no_auth(tcp: &mut TcpStream) {
    tcp.write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write the socks5 greeting");
    let mut reply = [0u8; 2];
    tcp.read_exact(&mut reply)
        .await
        .expect("read the socks5 method-select reply");
    assert_eq!(
        reply,
        [0x05, 0x00],
        "a real SOCKS5 listener must select no-auth"
    );
}

/// A `CONNECT` request naming an IPv4 literal destination (ATYP `0x01`).
fn connect_request_ipv4(addr: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = addr else {
        panic!("this helper only builds IPv4 CONNECT requests")
    };
    let mut v = vec![0x05, 0x01, 0x00, 0x01];
    v.extend_from_slice(&v4.ip().octets());
    v.extend_from_slice(&v4.port().to_be_bytes());
    v
}

/// A `CONNECT` request naming a domain destination (ATYP `0x03`).
fn connect_request_domain(host: &str, port: u16) -> Vec<u8> {
    let mut v = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    v.extend_from_slice(host.as_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v
}

/// Read the fixed ten-byte SOCKS5 reply (`VER REP RSV ATYP BND.ADDR
/// BND.PORT`, `BND` always `0.0.0.0:0` — ADR-0019 decision 8).
async fn read_rep(tcp: &mut TcpStream) -> [u8; 10] {
    let mut rep = [0u8; 10];
    tcp.read_exact(&mut rep)
        .await
        .expect("read the socks5 REP frame");
    rep
}

/// The host's `forward.local` audit records, in order — same filter
/// `tunnel_loopback.rs`'s own private helper of the same name uses (`-D`
/// rides the identical inline gate `-L` does, `crates/qsh-core/src/server/
/// tunnels.rs`'s own doc, so the action name is unchanged).
fn forward_local(h: &TunnelHarness) -> Vec<qsh_core::audit::AuditRecord> {
    h.audit()
        .records()
        .into_iter()
        .filter(|r| r.action == "forward.local")
        .collect()
}

/// Bound on a real, non-loopback round trip once
/// [`net_probe::usable_non_loopback_v4`]'s own short probe has already
/// succeeded once for the same address.
///
/// A passing probe does not guarantee the *next* connection on the same
/// address is fast too: this module's own doc records a run of this suite
/// where a probed-usable address still took anywhere from under a second to
/// well over a minute for a single real round trip, on a network that
/// simply hairpins a host's own address inconsistently rather than not at
/// all. Comfortably above `crates/qsh-core/src/tunnel/dial.rs::
/// TUNNEL_DIAL_TIMEOUT` (10s — [`closed_port_gives_rep_05`]'s own internal
/// bound) and comfortably below `.config/nextest.toml`'s 60s slow-test
/// threshold, so a network having one of *those* bad moments passes this
/// bound and hits [`net_probe::Gap`]'s own policy — skip quickly and
/// quietly off CI, fail on CI — instead of ever nearing nextest's own
/// hang-detection window.
const NETWORK_BOUND: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

/// The baseline: a real `CONNECT` to a real, non-loopback destination opens
/// a genuine byte pipe and round-trips a payload — `-D`'s whole reason to
/// exist, proven against the production listener rather than the fake-host
/// unit tests in `crates/qsh-core/src/tunnel/dynamic/tests.rs`.
#[tokio::test(flavor = "multi_thread")]
async fn socks_connect_to_echo_round_trips_bytes() {
    let iface_ip = gap_or_return!(
        net_probe::require_non_loopback_v4("no reachable non-loopback address on this host").await,
        "socks_connect_to_echo_round_trips_bytes"
    );
    let h = TunnelHarness::start().await;
    let echo = LanEcho::start(iface_ip).await.expect("bind lan echo");
    let forward = h.dynamic_forward().await;

    let gap = net_probe::bound_or_gap(
        "a real round trip did not finish within the network bound on this host's network",
        NETWORK_BOUND,
        async {
            let mut sock = TcpStream::connect(forward.local_addr())
                .await
                .expect("connect to the -D listener");
            greet_no_auth(&mut sock).await;
            sock.write_all(&connect_request_ipv4(echo.addr()))
                .await
                .expect("write the CONNECT request");
            let rep = read_rep(&mut sock).await;
            assert_eq!(rep[1], 0x00, "expected a success REP: {rep:?}");

            let payload = b"hello over a real interface".to_vec();
            sock.write_all(&payload).await.expect("write the payload");
            sock.shutdown().await.expect("half-close the write side");
            let mut got = Vec::new();
            sock.read_to_end(&mut got).await.expect("read the echo");
            assert_eq!(got, payload);
        },
    )
    .await;
    gap_or_return!(gap, "socks_connect_to_echo_round_trips_bytes");

    h.shutdown().await;
}

/// A denied principal gets `REP 0x02` (`Rep::NotAllowedByRuleset`, ADR-0019
/// decision 8's REP table) and the destination is never dialed — the ACL
/// gate runs, and refuses, before `authorize_and_dial_tunnel` ever reaches
/// the dialer (`crates/qsh-core/src/server/tunnels.rs`'s own doc on
/// ordering).
#[tokio::test(flavor = "multi_thread")]
async fn acl_deny_gives_rep_02_and_zero_dials() {
    let iface_ip = gap_or_return!(
        net_probe::require_non_loopback_v4_route("no non-loopback IPv4 route on this host"),
        "acl_deny_gives_rep_02_and_zero_dials"
    );
    let h = TunnelHarness::start_with(Arc::new(DenyAll)).await;
    let spy = TcpListener::bind((iface_ip, 0))
        .await
        .expect("bind the spy destination");
    let spy_addr = spy.local_addr().expect("spy addr");

    let forward = h.dynamic_forward().await;
    let mut sock = TcpStream::connect(forward.local_addr())
        .await
        .expect("connect to the -D listener");
    greet_no_auth(&mut sock).await;
    sock.write_all(&connect_request_ipv4(spy_addr))
        .await
        .expect("write the CONNECT request");
    let rep = read_rep(&mut sock).await;
    assert_eq!(rep[1], 0x02, "expected NotAllowedByRuleset REP: {rep:?}");

    let accept = tokio::time::timeout(Duration::from_millis(200), spy.accept()).await;
    assert!(
        accept.is_err(),
        "a denied CONNECT must dial nothing: {accept:?}"
    );

    let audit = forward_local(&h);
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].decision, "deny");

    h.shutdown().await;
}

/// A domain name that can never resolve (RFC 2606's `.invalid`) gets `REP
/// 0x04` (`Rep::HostUnreachable`) — `DialError::Resolve` mapped to
/// `ErrorCode::HostNotFound` (`crates/qsh-core/src/tunnel/dial.rs`), then
/// to `Rep::HostUnreachable` (`crates/qsh-proto/src/socks5.rs`'s own
/// `from_error_code`). No non-loopback address is needed: resolution fails
/// before the host-local filter ever runs.
#[tokio::test(flavor = "multi_thread")]
async fn unresolvable_name_gives_rep_04() {
    let h = TunnelHarness::start().await;
    let forward = h.dynamic_forward().await;

    let mut sock = TcpStream::connect(forward.local_addr())
        .await
        .expect("connect to the -D listener");
    greet_no_auth(&mut sock).await;
    sock.write_all(&connect_request_domain(
        "definitely-unresolvable.invalid",
        80,
    ))
    .await
    .expect("write the CONNECT request");
    let rep = read_rep(&mut sock).await;
    assert_eq!(rep[1], 0x04, "expected HostUnreachable REP: {rep:?}");

    h.shutdown().await;
}

/// A reachable, non-loopback address with nothing listening gets `REP
/// 0x05` (`Rep::ConnectionRefused`) — `DialError::Connect` mapped to
/// `ErrorCode::ConnectionFailed`, then to `Rep::ConnectionRefused`.
#[tokio::test(flavor = "multi_thread")]
async fn closed_port_gives_rep_05() {
    let iface_ip = gap_or_return!(
        net_probe::require_non_loopback_v4("no reachable non-loopback address on this host").await,
        "closed_port_gives_rep_05"
    );
    let port = net_probe::dead_port_on(iface_ip)
        .await
        .expect("reserve a dead port");
    let h = TunnelHarness::start().await;
    let forward = h.dynamic_forward().await;

    let gap = net_probe::bound_or_gap(
        "the REP did not arrive within the network bound on this host's network",
        NETWORK_BOUND,
        async {
            let mut sock = TcpStream::connect(forward.local_addr())
                .await
                .expect("connect to the -D listener");
            greet_no_auth(&mut sock).await;
            sock.write_all(&connect_request_ipv4(SocketAddr::new(
                IpAddr::V4(iface_ip),
                port,
            )))
            .await
            .expect("write the CONNECT request");
            let rep = read_rep(&mut sock).await;
            assert_eq!(rep[1], 0x05, "expected ConnectionRefused REP: {rep:?}");
        },
    )
    .await;
    gap_or_return!(gap, "closed_port_gives_rep_05");

    h.shutdown().await;
}

/// A principal already at its `max_tunnel_streams_per_forward` cap for one
/// destination gets `REP 0x01` (`Rep::GeneralFailure` — decision 8's "로컬:
/// 기타" row, which `RESOURCE_EXHAUSTED` falls into: `Rep::from_error_code`
/// has no dedicated arm for it) — the host-side quota, not `-D`'s own
/// client-side connection-rate limiter (that one *waits* for a token
/// within the handshake deadline before ever answering `REP 0x01`,
/// ADR-0019 decision 9's amendment; this quota is a single already-full
/// reservation, answered immediately, no waiting involved).
///
/// The first stream is opened by hand (not through the `-D` listener) and
/// held open for the whole test, exactly like `quota.rs`'s own
/// `tcp_connect_past_the_forward_quota_answers_resource_exhausted_and_dials_nothing`
/// — `TunnelHarness::tcp_connect` would drop its stream (and so free the
/// permit) the instant it returns, defeating "past the quota" before the
/// second attempt ever runs.
#[tokio::test(flavor = "multi_thread")]
async fn quota_exhaustion_gives_rep_01() {
    let iface_ip = gap_or_return!(
        net_probe::require_non_loopback_v4("no reachable non-loopback address on this host").await,
        "quota_exhaustion_gives_rep_01"
    );
    let h = TunnelHarness::start_with_quotas(QuotaLimits {
        max_tunnel_streams_per_forward: 1,
        ..QuotaLimits::default()
    })
    .await;
    let echo = LanEcho::start(iface_ip).await.expect("bind lan echo");
    let forward = h.dynamic_forward().await;

    let gap = net_probe::bound_or_gap(
        "the round trip did not finish within the network bound on this host's network",
        NETWORK_BOUND,
        async {
            // Fill the one-slot forward cap: a real TCP_CONNECT to the same
            // destination the -D attempt below will also name, held open.
            let (send, recv) = h
                .connection()
                .open_bi()
                .await
                .expect("open the first tunnel stream");
            let mut held_send = FramedSend::data(send);
            held_send.set_priority(wire::PRIORITY_TUNNEL);
            held_send
                .send(&wire::StreamHeader {
                    kind: wire::StreamKind::TcpConnect as i32,
                    ticket: Vec::new(),
                    host: iface_ip.to_string(),
                    port: u32::from(echo.port()),
                    deny_host_local: false,
                })
                .await
                .expect("send the first TCP_CONNECT header");
            let mut held_recv = FramedRecv::data(recv);
            let first: wire::ConnectResult = held_recv
                .recv()
                .await
                .expect("read the first ConnectResult")
                .expect("§7 requires a ConnectResult either way");
            assert!(first.ok, "{first:?}");

            // Second attempt, same destination, through the real -D listener.
            let mut sock = TcpStream::connect(forward.local_addr())
                .await
                .expect("connect to the -D listener");
            greet_no_auth(&mut sock).await;
            sock.write_all(&connect_request_ipv4(echo.addr()))
                .await
                .expect("write the second CONNECT request");
            let rep = read_rep(&mut sock).await;
            assert_eq!(rep[1], 0x01, "expected GeneralFailure REP: {rep:?}");

            // The first stream is still alive — this quota refusal must not
            // have torn it down.
            drop(held_send);
            drop(held_recv);
        },
    )
    .await;
    gap_or_return!(gap, "quota_exhaustion_gives_rep_01");

    h.shutdown().await;
}

/// A domain name that resolves to loopback (`localhost`) is filtered the
/// same as any other host-local literal — `REP 0x02`, and the loopback
/// "server" a naive implementation would have reached never sees a single
/// `accept()`.
#[tokio::test(flavor = "multi_thread")]
async fn localhost_name_is_filtered_rep_02_and_the_loopback_server_sees_no_accept() {
    let h = TunnelHarness::start().await;
    let loop_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the loopback spy");
    let loop_port = loop_listener.local_addr().expect("spy addr").port();

    let forward = h.dynamic_forward().await;
    let mut sock = TcpStream::connect(forward.local_addr())
        .await
        .expect("connect to the -D listener");
    greet_no_auth(&mut sock).await;
    sock.write_all(&connect_request_domain("localhost", loop_port))
        .await
        .expect("write the CONNECT request");
    let rep = read_rep(&mut sock).await;
    assert_eq!(
        rep[1], 0x02,
        "expected NotAllowedByRuleset REP for a loopback name: {rep:?}"
    );

    let accept = tokio::time::timeout(Duration::from_millis(200), loop_listener.accept()).await;
    assert!(
        accept.is_err(),
        "the host-local filter must never dial the loopback server: {accept:?}"
    );

    h.shutdown().await;
}

/// A successful `CONNECT`'s audit line names the real destination — the
/// same `forward.local` action `-L` writes (`crates/qsh-core/src/server/
/// tunnels.rs`'s own doc: the host does not know or care whether the
/// stream came from `-L` or `-D`), with the canonical `host:port` resource
/// `-D`'s SOCKS request actually named.
#[tokio::test(flavor = "multi_thread")]
async fn audit_line_carries_forward_local_and_destination() {
    let iface_ip = gap_or_return!(
        net_probe::require_non_loopback_v4("no reachable non-loopback address on this host").await,
        "audit_line_carries_forward_local_and_destination"
    );
    let h = TunnelHarness::start().await;
    let echo = LanEcho::start(iface_ip).await.expect("bind lan echo");
    let forward = h.dynamic_forward().await;

    let gap = net_probe::bound_or_gap(
        "a real round trip did not finish within the network bound on this host's network",
        NETWORK_BOUND,
        async {
            let mut sock = TcpStream::connect(forward.local_addr())
                .await
                .expect("connect to the -D listener");
            greet_no_auth(&mut sock).await;
            sock.write_all(&connect_request_ipv4(echo.addr()))
                .await
                .expect("write the CONNECT request");
            let rep = read_rep(&mut sock).await;
            assert_eq!(rep[1], 0x00, "{rep:?}");
            drop(sock);

            let audit = forward_local(&h);
            assert_eq!(audit.len(), 1, "{audit:?}");
            assert_eq!(audit[0].decision, "allow");
            assert_eq!(audit[0].resource, format!("{iface_ip}:{}", echo.port()));
        },
    )
    .await;
    gap_or_return!(gap, "audit_line_carries_forward_local_and_destination");

    h.shutdown().await;
}

/// Payload bytes written in the **same** `write_all` as the `CONNECT`
/// request — before the REP is even read back — arrive at the destination
/// intact. The unit-tested twin of this
/// (`handshake_and_payload_pipelined_in_one_write_are_forwarded_correctly`
/// in `crates/qsh-core/src/tunnel/dynamic/tests.rs`) proves the driver
/// reads pipelined bytes off its own decoder correctly against a fake
/// peer; this proves the same property survives a real destination and a
/// real splice.
#[tokio::test(flavor = "multi_thread")]
async fn pipelined_data_after_connect_arrives_intact() {
    let iface_ip = gap_or_return!(
        net_probe::require_non_loopback_v4("no reachable non-loopback address on this host").await,
        "pipelined_data_after_connect_arrives_intact"
    );
    let h = TunnelHarness::start().await;
    let echo = LanEcho::start(iface_ip).await.expect("bind lan echo");
    let forward = h.dynamic_forward().await;

    let gap = net_probe::bound_or_gap(
        "a real round trip did not finish within the network bound on this host's network",
        NETWORK_BOUND,
        async {
            let mut sock = TcpStream::connect(forward.local_addr())
                .await
                .expect("connect to the -D listener");
            greet_no_auth(&mut sock).await;

            let payload = b"pipelined right behind the request".to_vec();
            let mut out = connect_request_ipv4(echo.addr());
            out.extend_from_slice(&payload);
            sock.write_all(&out)
                .await
                .expect("write the CONNECT request and payload in one write");

            let rep = read_rep(&mut sock).await;
            assert_eq!(rep[1], 0x00, "{rep:?}");

            sock.shutdown().await.expect("half-close the write side");
            let mut got = Vec::new();
            sock.read_to_end(&mut got).await.expect("read the echo");
            assert_eq!(got, payload, "pipelined bytes must not be dropped");
        },
    )
    .await;
    gap_or_return!(gap, "pipelined_data_after_connect_arrives_intact");

    h.shutdown().await;
}
