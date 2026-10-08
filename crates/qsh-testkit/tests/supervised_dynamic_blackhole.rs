//! `--supervise -D` through a 50-second blackhole (ADR-0023 decisions 5, 9
//! and 10, `docs/design/testing.md` L4 and L10): the SOCKS5 listener stays
//! bound for the whole outage, and the first `CONNECT` after the path comes
//! back succeeds within one backoff step plus one redial deadline.
//!
//! The real host is an in-process [`LoopbackHarness`] behind a
//! [`ChaosProxy`]; the client is the product `Ops::tunnel_dynamic` with its
//! own identity, pinned by the host. Nothing is mocked between the SOCKS
//! client and the destination.
//!
//! What "stays bound" means here: once a second, for the whole blackhole, a
//! plain TCP connect to the listener must succeed. A refused connect is the
//! failure, because it is what a released listener looks like. The connect
//! is not followed by a `CONNECT` request: what the listener answers while
//! disconnected is `qsh-cli`'s `supervised_dynamic_connect_during_disconnect_gets_rep_01`.
//!
//! Wall-clock bound, so it is gated like the other slow acceptance tests:
//! it runs only with `QSH_ACCEPTANCE_SLOW` set (the `acceptance` job in
//! `.github/workflows/ci.yml` sets it) and prints a skip line otherwise.

#![cfg(unix)]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use qsh_core::acl::AllowAllPinned;
use qsh_core::{Ops, Paths, Principal};
use qsh_proto::{IdentityInitReq, KeyStoreMode, TrustAddReq, TunnelDynamicReq};
use qsh_testkit::chaos::{ChaosPolicy, ChaosProxy};
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_testkit::net_probe::free_port;
use qsh_testkit::net_probe::{self, Gap, LanEcho};
use qsh_transport::{Fingerprint, StaticTrust};

/// How long the path is dead.
const BLACKHOLE: Duration = Duration::from_secs(50);

/// The supervisor's fast-window backoff cap (`crates/qsh-core/src/tunnel/
/// supervise/backoff.rs` `FAST_CAP`, ADR-0023 decision 10). Restated so a
/// change to it fails this test instead of quietly passing.
const FAST_CAP: Duration = Duration::from_secs(2);

/// One redial attempt's bound (`crates/qsh-core/src/client/reconnect.rs`
/// `REDIAL_DEADLINE`, testing.md L4), restated for the same reason.
const REDIAL_DEADLINE: Duration = Duration::from_secs(2);

/// Room for what the bounds do not model: a loaded runner, the SOCKS
/// handshake and the echo round trip.
const SLACK: Duration = Duration::from_secs(4);

/// The disconnection budget. Longer than the blackhole plus recovery, so
/// nothing but the test's own outage matters.
const BUDGET_MS: u32 = 300_000;

fn slow_requested() -> bool {
    std::env::var_os("QSH_ACCEPTANCE_SLOW")
        .map(|v| v.to_string_lossy().trim().to_string())
        .is_some_and(|v| !v.is_empty() && v != "0")
}

/// One SOCKS5 `CONNECT` to `dest`, then an echo round trip. `Ok` only if
/// the whole path answered.
fn socks_echo(proxy_port: u16, dest: SocketAddr) -> std::io::Result<()> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method)?;
    let SocketAddr::V4(dest) = dest else {
        return Err(std::io::Error::other("the destination must be IPv4"));
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&dest.ip().octets());
    request.extend_from_slice(&dest.port().to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply)?;
    if reply[1] != 0x00 {
        return Err(std::io::Error::other(format!("REP {:#04x}", reply[1])));
    }
    stream.write_all(b"ping")?;
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed)?;
    if &echoed != b"ping" {
        return Err(std::io::Error::other("the echo came back different"));
    }
    Ok(())
}

#[test]
fn supervised_dynamic_listener_stays_bound_through_a_50_second_blackhole_and_connects_after_it() {
    if !slow_requested() {
        eprintln!("SKIP: the 50-second supervised blackhole gate requires QSH_ACCEPTANCE_SLOW=1");
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    // The client: a real `Ops` with its own identity on disk.
    let dir = tempfile::tempdir().expect("tempdir");
    let ops = Ops::new(Paths::new(
        dir.path().join("config"),
        dir.path().join("state"),
    ));
    let identity = ops
        .identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
            ..Default::default()
        })
        .expect("client identity");
    let client_fingerprint: Fingerprint = identity
        .fingerprint
        .parse()
        .expect("the client fingerprint parses");

    let iface_ip = match runtime.block_on(net_probe::require_non_loopback_v4(
        "no reachable non-loopback address on this host",
    )) {
        Gap::Ready(ip) => ip,
        Gap::Skip(reason) => {
            eprintln!("SKIP: {reason}");
            return;
        }
        Gap::Fail(reason) => panic!("{reason}"),
    };
    let echo = runtime
        .block_on(LanEcho::start(iface_ip))
        .expect("bind lan echo");

    // The host pins the client's real fingerprint; the client reaches it
    // only through the chaos proxy.
    let host = runtime.block_on(LoopbackHarness::start_custom(
        std::sync::Arc::new(AllowAllPinned),
        make_identity(),
        StaticTrust::empty().with_pin(client_fingerprint, Principal::Device("laptop".into())),
    ));
    let proxy = runtime
        .block_on(ChaosProxy::start(
            host.host_addr,
            ChaosPolicy::seeded(0x0023_B1AC),
        ))
        .expect("chaos proxy");
    ops.trust_add(TrustAddReq {
        name: "box".into(),
        address: Some(proxy.addr().to_string()),
        fingerprint: Some(host.server_identity.fingerprint.to_string()),
        cert_pem: None,
    })
    .expect("pin the host");

    let listen_port = free_port();
    let hold = ops
        .tunnel_dynamic(TunnelDynamicReq {
            host: "box".into(),
            bind: None,
            listen_port: u32::from(listen_port),
            supervise_ms: Some(BUDGET_MS),
            accept_hold_ms: None,
        })
        .expect("open the supervised -D tunnel");
    socks_echo(listen_port, echo.addr()).expect("a CONNECT works before the outage");

    // ---- the path dies ----
    let started = Instant::now();
    runtime.block_on(proxy.blackhole(BLACKHOLE));
    let mut probes = 0u32;
    while started.elapsed() < BLACKHOLE {
        match TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], listen_port)),
            Duration::from_secs(1),
        ) {
            Ok(_) => {}
            Err(err) => panic!(
                "the listener stopped accepting {:?} into the outage (probe {probes}): {err}; {}",
                started.elapsed(),
                proxy.context()
            ),
        }
        probes += 1;
        std::thread::sleep(Duration::from_secs(1));
    }
    assert!(probes >= 40, "the probe loop barely ran: {probes} probes");

    // ---- the path is back ----
    let back = started + BLACKHOLE;
    let deadline = back + FAST_CAP + REDIAL_DEADLINE + SLACK;
    loop {
        match socks_echo(listen_port, echo.addr()) {
            Ok(()) => break,
            Err(err) if Instant::now() < deadline => {
                // REP 0x01 while the carrier is not back yet; anything
                // else waits out the same bound.
                eprintln!("waiting for the tunnel: {err}");
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(err) => panic!(
                "no CONNECT succeeded within {:?} of the path returning: {err}; {}",
                deadline.saturating_duration_since(back),
                proxy.context()
            ),
        }
    }
    let recovered_after = Instant::now().saturating_duration_since(back);
    eprintln!("first CONNECT after the blackhole succeeded {recovered_after:?} after it ended");
    assert!(
        recovered_after <= FAST_CAP + REDIAL_DEADLINE + SLACK,
        "recovery took {recovered_after:?}"
    );

    hold.close();
    runtime.block_on(host.shutdown());
}
