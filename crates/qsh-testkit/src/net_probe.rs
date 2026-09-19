//! Non-loopback IPv4 route discovery, plus the CI-aware skip-or-fail policy
//! for tests that need a real network path — shared by
//! `crates/qsh-testkit/tests/dynamic_loopback.rs` and any future `-D`/`-L`
//! reverse-route suite that needs the same address.
//!
//! **Why a probe, not just a route.** A route existing in the kernel
//! routing table is not enough on its own: some networks assign a host a
//! real, non-host-local address and still never loop a connection back to
//! it (client-isolated Wi-Fi, a router with no hairpin NAT — the OS routing
//! table calls the address `local` while the TCP handshake itself never
//! completes). [`usable_non_loopback_v4`] probes a real self-connect with a
//! short bound before handing the address out.
//!
//! **Why CI changes the policy.** A silent skip is fine on a developer's
//! Wi-Fi, where the network shape above is common and unrelated to
//! anything the test is pinning. On a CI runner, the same silent skip
//! would let a real qsh regression that hangs or breaks host-local
//! filtering quietly turn a pinned test into a no-op instead of a red
//! build (`docs/design/testing.md` L6's "a stale skip hides a code path
//! that quietly stopped running" rule, applied to network reachability
//! instead of an error code). GitHub Actions sets `CI=true`
//! (<https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables>);
//! [`in_ci`] treats any non-empty value as "yes", matching every other CI
//! system that follows the same convention.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

/// True when running under a CI runner (`CI` set to any non-empty value —
/// GitHub Actions' own default, and the convention every other major CI
/// system follows). No test in this workspace reads this to change what it
/// asserts, only whether an environmental gap is a skip or a failure.
pub fn in_ci() -> bool {
    std::env::var("CI").is_ok_and(|v| !v.is_empty())
}

/// Ask the kernel which IPv4 source address a packet toward a real,
/// never-transmitted destination (RFC 5737 TEST-NET-1, discard port) would
/// carry — `connect(2)` on a UDP socket sends no packet, it only resolves a
/// route and records a source address, synchronously and in memory. `None`
/// on a host with no IPv4 default route at all.
pub fn find_non_loopback_v4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// [`find_non_loopback_v4`], plus a bounded live probe that a connection
/// really does loop back to this address: bind a listener on it, then try
/// to connect to that same listener from this same process within two
/// seconds. `None` either way is the same "no usable address" signal
/// [`find_non_loopback_v4`] already gives a caller for a missing route.
pub async fn usable_non_loopback_v4() -> Option<Ipv4Addr> {
    let ip = find_non_loopback_v4()?;
    let listener = TcpListener::bind((ip, 0)).await.ok()?;
    let addr = listener.local_addr().ok()?;
    let accept = tokio::spawn(async move { listener.accept().await });
    let probe = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await;
    accept.abort();
    match probe {
        Ok(Ok(_stream)) => Some(ip),
        _ => None,
    }
}

/// What a caller must do about an environmental gap (no route, a failed
/// hairpin probe, a round trip that outran its bound): [`in_ci`] decides
/// once, here, so every call site applies the same policy instead of
/// re-deriving it.
pub enum Gap<T> {
    /// The thing being probed for was there — proceed with it.
    Ready(T),
    /// Off CI: print `reason` and the caller returns early, no failure.
    Skip(String),
    /// On CI: the caller must `panic!(reason)` — a silent skip here would
    /// hide a real qsh regression instead of reporting it
    /// (`docs/design/testing.md` L6's rule, applied to network
    /// reachability rather than an error code).
    Fail(String),
}

/// [`usable_non_loopback_v4`], gated by [`in_ci`]: off CI, a missing route
/// or a failed hairpin probe is [`Gap::Skip`]. On CI, the same gap is
/// [`Gap::Fail`].
pub async fn require_non_loopback_v4(reason: &str) -> Gap<Ipv4Addr> {
    match usable_non_loopback_v4().await {
        Some(ip) => Gap::Ready(ip),
        None if in_ci() => Gap::Fail(reason.to_string()),
        None => Gap::Skip(reason.to_string()),
    }
}

/// [`find_non_loopback_v4`] (the unprobed route lookup — no hairpin needed,
/// only a route to refuse dialing), gated by the same [`in_ci`] policy as
/// [`require_non_loopback_v4`].
pub fn require_non_loopback_v4_route(reason: &str) -> Gap<Ipv4Addr> {
    match find_non_loopback_v4() {
        Some(ip) => Gap::Ready(ip),
        None if in_ci() => Gap::Fail(reason.to_string()),
        None => Gap::Skip(reason.to_string()),
    }
}

/// Run `fut`, bounded by `bound` — the same [`in_ci`] policy as
/// [`require_non_loopback_v4`], applied to a real round trip that is slow
/// rather than absent: a timeout is [`Gap::Skip`] off CI, [`Gap::Fail`] on
/// CI, so a network-bound qsh regression (a hang, a stalled splice) turns
/// the build red there instead of a silent skip line.
pub async fn bound_or_gap<F, T>(reason: &str, bound: Duration, fut: F) -> Gap<T>
where
    F: Future<Output = T>,
{
    match tokio::time::timeout(bound, fut).await {
        Ok(value) => Gap::Ready(value),
        Err(_) if in_ci() => Gap::Fail(reason.to_string()),
        Err(_) => Gap::Skip(reason.to_string()),
    }
}

/// Resolve a [`Gap<T>`] at a test call site: on [`Gap::Ready`], evaluate to
/// the inner value; on [`Gap::Skip`], print the reason and `return` out of
/// the enclosing test function; on [`Gap::Fail`], `panic!` with the reason
/// so CI reports it as a failed test, not a hang or a quiet pass.
#[macro_export]
macro_rules! gap_or_return {
    ($gap:expr, $test_name:literal) => {
        match $gap {
            $crate::net_probe::Gap::Ready(value) => value,
            $crate::net_probe::Gap::Skip(reason) => {
                eprintln!("skipping {}: {reason}", $test_name);
                return;
            }
            $crate::net_probe::Gap::Fail(reason) => {
                panic!("{}: {reason} (CI requires a usable route/bound; see crates/qsh-testkit/src/net_probe.rs)", $test_name)
            }
        }
    };
}

/// A TCP echo server bound off loopback, at a caller-chosen address — every
/// success-path test that needs to get past `-D`'s unconditional
/// `deny_host_local` needs one (`crates/qsh_testkit::tunnel::EchoServer`
/// only ever binds `127.0.0.1`).
pub struct LanEcho {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl LanEcho {
    /// Bind and start echoing on `ip`, port `0` (kernel-assigned).
    pub async fn start(ip: Ipv4Addr) -> io::Result<Self> {
        let listener = TcpListener::bind((ip, 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.into_split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                    // Half-close, not drop: a test reading to EOF must see
                    // an orderly end, not a reset.
                    use tokio::io::AsyncWriteExt as _;
                    let _ = write.shutdown().await;
                });
            }
        });
        Ok(Self { addr, task })
    }

    /// This echo server's bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// This echo server's bound port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for LanEcho {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A non-loopback port with nothing behind it, at a caller-chosen address.
pub async fn dead_port_on(ip: Ipv4Addr) -> io::Result<u16> {
    let listener = TcpListener::bind((ip, 0)).await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}
