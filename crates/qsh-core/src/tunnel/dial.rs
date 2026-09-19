//! The tunnel destination dial seam, extended by ADR-0019 decision 3 for
//! the host-local dial filter.
//!
//! Exists for one reason: the host must be able to prove — in a unit test,
//! with no network — that a `TCP_CONNECT` stream whose `forward.local`
//! check was denied performed **zero** dials (`docs/PRD.md` §9 "no resource
//! before authorization", `docs/design/testing.md` L2, `docs/design/
//! protocol.md` §13's "socket creation is 0 on the un-authorized path"
//! invariant). "Zero dials" is only assertable if dialing goes through a
//! seam a test can instrument, so it does — and the production
//! implementation ([`SystemDialer`]) is the only one shipped.
//!
//! Deliberately tiny and `pub(crate)`: it is not a transport abstraction
//! (ADR-0005 forbids a `Transport`/`StreamMux` trait), it is one function
//! — "give me a TCP connection to this destination" — with the resolve
//! failure separated from the connect failure so the caller can pick the
//! right `ErrorCode` (`docs/CLI.md` §3.3: `HOST_NOT_FOUND` vs
//! `CONNECTION_FAILED`, and `PLAN.md` M4 "전 step 공통 계약 규율" spells
//! out exactly that split).
//!
//! ADR-0019 decision 3 adds a second, orthogonal seam inside
//! [`SystemDialer`]: resolution ([`Resolver`]) is split from connection
//! ([`Connector`]) so a test can inject fake resolutions (loopback,
//! link-local, IPv4-mapped literals, …) without owning a DNS server, and
//! can count real connect attempts without needing the filter itself to
//! be wrong for the count to be interesting. Both default to the real
//! thing ([`TokioResolver`], [`TcpConnector`]); production always uses
//! both defaults.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use qsh_proto::ErrorCode;
use tokio::net::TcpStream;

/// Bound on how long one tunnel destination dial — resolve *and* connect —
/// may take before it is reported as [`ErrorCode::ConnectionFailed`].
///
/// Same spirit and same value as the transport's own
/// [`qsh_transport::DEFAULT_DIAL_TIMEOUT`]: a destination that has not
/// answered in ten seconds should fail fast rather than park. Unbounded is
/// not an option here, and the reason is structural rather than tidiness —
/// a blackholed destination (a dropped SYN, a resolver that never answers)
/// holds a host task, a file descriptor and, above all, one of the 1024
/// concurrent bidi streams
/// [`qsh_transport::MAX_CONCURRENT_BIDI_STREAMS`] allows per connection.
/// A requester that opens tunnels to a blackhole faster than the OS gives
/// up would otherwise exhaust that whole budget and starve the *other*
/// streams on the same connection, PTY sessions included.
pub(crate) const TUNNEL_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// The host-local dial filter's on/off switch for one `TCP_CONNECT`
/// (ADR-0019 decision 3): `deny_host_local` is `StreamHeader.deny_host_local`
/// verbatim, so a caller that never looked at ADR-0019 still gets the
/// unfiltered, pre-ADR-0019 behavior by constructing this with `false`.
///
/// Not an authorization seam — see [`is_host_local`]'s own doc for why a
/// dial `DialPolicy::deny_host_local: true` refusal is not an ACL decision
/// and does not need one of its own to be meaningful.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DialPolicy {
    /// When true, every address [`Resolver::resolve`] returns is checked
    /// against [`is_host_local`] before `connect`, and a resolution that
    /// filters down to nothing is [`DialError::Filtered`] rather than an
    /// attempt.
    pub(crate) deny_host_local: bool,
}

/// Why a tunnel destination could not be reached. Carries no payload and
/// no peer-supplied text into the log — only the category and the
/// underlying `io::Error` (which callers turn into a fixed message).
#[derive(Debug)]
pub(crate) enum DialError {
    /// The destination host did not resolve to any address.
    Resolve(io::Error),
    /// It resolved, but no address could be connected to.
    Connect(io::Error),
    /// It resolved to at least one address, but [`DialPolicy::deny_host_local`]
    /// filtered every one of them out (ADR-0019 decision 3). Distinct from
    /// [`DialError::Resolve`] (which means the resolver itself came back
    /// empty) — this means the resolver answered, and the policy is what
    /// refused the destination.
    Filtered,
}

impl DialError {
    /// The `docs/CLI.md` §3.3 code this failure reports to the requester in
    /// [`qsh_proto::wire::ConnectResult`]. [`DialError::Filtered`] maps to
    /// [`ErrorCode::PermissionDenied`] (ADR-0019 decision 3) — the same
    /// code the ACL gate above this seam already uses for a `forward.local`
    /// deny, so the wire code alone does not distinguish the two; the
    /// `ConnectResult.message` text does ([`FILTERED_MESSAGE`] vs
    /// `crate::acl::PERMISSION_DENIED_MESSAGE`). No new `ErrorCode` is
    /// invented for the filter (`docs/CLI.md` §3.3 vocabulary).
    pub(crate) fn code(&self) -> ErrorCode {
        match self {
            DialError::Resolve(_) => ErrorCode::HostNotFound,
            DialError::Connect(_) => ErrorCode::ConnectionFailed,
            DialError::Filtered => ErrorCode::PermissionDenied,
        }
    }
}

/// [`DialError::Filtered`]'s fixed message, reused verbatim wherever the
/// text (not just the `ErrorCode`) needs to be handed to a caller —
/// deliberately generic: it can reach a peer inside a `ConnectResult.
/// message` (§7), and ADR-0019 decision 3 says resolved IPs never appear
/// in a log or a reply, only the category, never which address(es) were
/// filtered.
pub(crate) const FILTERED_MESSAGE: &str =
    "destination resolved only to host-local addresses, which are not dialed for this stream";

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::Resolve(err) => write!(f, "destination did not resolve: {err}"),
            DialError::Connect(err) => write!(f, "destination refused the connection: {err}"),
            DialError::Filtered => f.write_str(FILTERED_MESSAGE),
        }
    }
}

/// Future returned by [`TunnelDialer::dial`]. Boxed so the trait stays
/// object-safe — the host holds it as `&dyn TunnelDialer` so a test can
/// substitute a counting double.
pub(crate) type DialFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TcpStream, DialError>> + Send + 'a>>;

/// "Open a TCP connection to `host:port`." Nothing else: this trait must
/// never learn about ACL, tickets or streams — the authorization decision
/// is the *caller's* and happens strictly before the first call to
/// [`dial`](Self::dial) (`crate::server::Server::authorize_and_dial_tunnel`).
///
/// `policy` is `StreamHeader.deny_host_local` folded into a [`DialPolicy`]
/// by the caller (ADR-0019 decision 3) — a dialer must honor it, but must
/// never invent filtering of its own the caller did not ask for.
pub(crate) trait TunnelDialer: Send + Sync {
    /// Connect to `host:port`, resolving `host` if it is a name.
    fn dial<'a>(&'a self, host: &'a str, port: u16, policy: &'a DialPolicy) -> DialFuture<'a>;
}

/// Future returned by [`Resolver::resolve`].
pub(crate) type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// The name-resolution half of [`SystemDialer`], seamed out so a test can
/// inject a resolution (a host-local address, a mix of filtered and real
/// ones, …) without a real resolver in the loop. Production always uses
/// [`TokioResolver`]; only tests build anything else.
pub(crate) trait Resolver: Send + Sync {
    /// Resolve `host` for `port`, in the same order a caller should try
    /// them in.
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

/// The real resolver: `tokio::net::lookup_host`, exactly as `dial_unbounded`
/// called it before ADR-0019.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TokioResolver;

impl Resolver for TokioResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// Future returned by [`Connector::connect`].
pub(crate) type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>>;

/// The connect half of [`SystemDialer`], seamed out so a test can count
/// real connect attempts (in order, to real addresses) separately from
/// whether the filter let them through at all. Production always uses
/// [`TcpConnector`]; only tests build anything else.
pub(crate) trait Connector: Send + Sync {
    /// Connect to `addr`.
    fn connect<'a>(&'a self, addr: SocketAddr) -> ConnectFuture<'a>;
}

/// The real connector: a plain TCP connect with the same `TCP_NODELAY`
/// best-effort `dial_unbounded` always applied.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TcpConnector;

impl Connector for TcpConnector {
    fn connect<'a>(&'a self, addr: SocketAddr) -> ConnectFuture<'a> {
        Box::pin(async move {
            let stream = TcpStream::connect(addr).await?;
            // Interactive forwards are latency-sensitive
            // (`docs/design/protocol.md` §12) — Nagle on a
            // spliced pipe just adds delay. Best effort.
            let _ = stream.set_nodelay(true);
            Ok(stream)
        })
    }
}

/// The one implementation that ships: the operating system's resolver and
/// TCP stack, under a [`TUNNEL_DIAL_TIMEOUT`] bound.
pub(crate) struct SystemDialer {
    /// How long resolve + connect together may take. Configurable only so
    /// a test can bound itself in milliseconds instead of waiting out the
    /// production default; production always uses that default.
    timeout: Duration,
    resolver: Box<dyn Resolver>,
    connector: Box<dyn Connector>,
}

impl Default for SystemDialer {
    fn default() -> Self {
        Self {
            timeout: TUNNEL_DIAL_TIMEOUT,
            resolver: Box::new(TokioResolver),
            connector: Box::new(TcpConnector),
        }
    }
}

impl SystemDialer {
    /// A dialer with a non-default bound. Test-only — see
    /// [`SystemDialer::timeout`].
    #[cfg(test)]
    pub(crate) fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            ..Self::default()
        }
    }

    /// A dialer whose resolution is `resolver` instead of the real DNS —
    /// for tests that need a specific, deterministic address list (a
    /// host-local literal, a mix of filtered and real addresses, …)
    /// without depending on what the test host's resolver actually returns.
    #[cfg(test)]
    pub(crate) fn with_resolver(resolver: impl Resolver + 'static) -> Self {
        Self {
            resolver: Box::new(resolver),
            ..Self::default()
        }
    }

    /// Both seams at once, for a test that needs to count connect attempts
    /// against an injected resolution (`dynamic_dial_skips_filtered_
    /// addresses_and_connects_to_the_rest`'s own case).
    #[cfg(test)]
    pub(crate) fn with_resolver_and_connector(
        resolver: impl Resolver + 'static,
        connector: impl Connector + 'static,
    ) -> Self {
        Self {
            resolver: Box::new(resolver),
            connector: Box::new(connector),
            ..Self::default()
        }
    }
}

impl TunnelDialer for SystemDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16, policy: &'a DialPolicy) -> DialFuture<'a> {
        let bound = self.timeout;
        Box::pin(async move {
            // The whole thing is bounded, resolver included: a resolver
            // that never answers parks a task exactly as thoroughly as a
            // blackholed SYN does.
            match tokio::time::timeout(
                bound,
                dial_unbounded(
                    host,
                    port,
                    policy,
                    self.resolver.as_ref(),
                    self.connector.as_ref(),
                ),
            )
            .await
            {
                Ok(result) => result,
                // Expiry is a destination that could not be reached, which
                // is what `CONNECTION_FAILED` already means — M4 invents no
                // new `ErrorCode` (`PLAN.md` §4.1 #9).
                Err(_elapsed) => Err(DialError::Connect(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "destination did not answer in time",
                ))),
            }
        })
    }
}

/// Resolve and connect with no bound of its own — always called inside
/// [`SystemDialer::dial`]'s timeout, never on its own.
///
/// Resolves **once**: `policy`'s filter is applied to that one resolution
/// and connects only proceed against the addresses that survive it, in the
/// resolver's own order (ADR-0019 decision 3 — "해석은 한 번만 하고 검사한
/// 주소로만 연결하므로 검사와 연결 사이의 경합이 없다"). There is no
/// re-resolve on a later address in the list, so a DNS answer that changes
/// between addresses cannot reintroduce a filtered address that was never
/// checked.
async fn dial_unbounded(
    host: &str,
    port: u16,
    policy: &DialPolicy,
    resolver: &dyn Resolver,
    connector: &dyn Connector,
) -> Result<TcpStream, DialError> {
    // Resolve first so "no such host" is distinguishable from
    // "host is there but refused" — the two get different
    // `ErrorCode`s (`DialError::code`).
    let resolved = resolver
        .resolve(host, port)
        .await
        .map_err(DialError::Resolve)?;
    if resolved.is_empty() {
        return Err(DialError::Resolve(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses for destination",
        )));
    }
    let candidates: Vec<SocketAddr> = if policy.deny_host_local {
        resolved
            .into_iter()
            .filter(|addr| !is_host_local(addr.ip()))
            .collect()
    } else {
        resolved
    };
    if candidates.is_empty() {
        // The resolver answered (checked above); the policy is what
        // refused every address it gave back.
        return Err(DialError::Filtered);
    }
    let mut last: Option<io::Error> = None;
    for addr in candidates {
        match connector.connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last = Some(err),
        }
    }
    // `candidates` is non-empty (checked above), so the loop ran at least
    // once and `last` is always `Some` here.
    Err(DialError::Connect(last.unwrap_or_else(|| {
        io::Error::other("no candidate address was attempted")
    })))
}

/// ADR-0019 decision 3's host-local address categories: loopback, "this
/// network", unspecified, link-local, multicast, IPv4 broadcast, and the
/// IPv4-mapped/IPv4-compatible IPv6 forms of the IPv4 ones. Not an
/// authorization seam — a malicious client can omit `deny_host_local`
/// entirely and dial these addresses through today's unfiltered `-L` path,
/// which is already reachable with `forward.local` alone. This function
/// exists to protect a client's *own* proxy from being steered at
/// resolve-time by content it did not choose to trust (ADR-0019's SOCKS
/// threat model: a web page behind `-D`, remote DNS, TTL-0 rebinding), not
/// to add a permission boundary between principals.
pub(crate) fn is_host_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_host_local_v4(v4),
        IpAddr::V6(v6) => is_host_local_v6(&v6),
    }
}

fn is_host_local_v4(v4: Ipv4Addr) -> bool {
    // "This network" (0.0.0.0/8) subsumes the all-zeros unspecified
    // address; Linux in particular treats a connect to 0.0.0.0 as a
    // connect to itself (ADR-0019 decision 3's own parenthetical).
    v4.octets()[0] == 0
        || v4.is_loopback() // 127.0.0.0/8
        || v4.is_link_local() // 169.254.0.0/16
        || v4.is_multicast()
        || v4.is_broadcast() // 255.255.255.255
}

fn is_host_local_v6(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() // ::1
        || v6.is_unspecified() // ::
        || is_unicast_link_local_v6(v6) // fe80::/10
        || v6.is_multicast()
    {
        return true;
    }
    // IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`,
    // deprecated) forms: if either unwraps to an embedded IPv4 address,
    // that address's own category decides, so `::ffff:127.0.0.1` and
    // `::127.0.0.1` are host-local exactly when `127.0.0.1` is.
    if let Some(v4) = embedded_ipv4(v6) {
        return is_host_local_v4(v4);
    }
    false
}

/// `fe80::/10`: the top 10 bits of the address are `1111111010`. Written by
/// hand rather than via an unstable `is_unicast_link_local` — this is a
/// fixed-width bitmask check, not something a future std API changes the
/// meaning of.
fn is_unicast_link_local_v6(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// If `v6` is an IPv4-mapped (`::ffff:0:0/96`) or IPv4-compatible
/// (`::0.0.0.0/96`, RFC 4291 §2.5.5.1, deprecated) address, the IPv4
/// address it embeds.
fn embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = v6.segments();
    if seg[0] == 0
        && seg[1] == 0
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && (seg[5] == 0xffff || seg[5] == 0)
    {
        return Some(Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const UNFILTERED: DialPolicy = DialPolicy {
        deny_host_local: false,
    };
    const FILTERED: DialPolicy = DialPolicy {
        deny_host_local: true,
    };

    /// A [`Resolver`] that always answers with a fixed list, counting how
    /// many times it was asked — the vehicle for "resolves exactly once"
    /// and "the filter never re-resolves".
    struct FixedResolver {
        addrs: Vec<SocketAddr>,
        calls: Arc<AtomicUsize>,
    }

    impl FixedResolver {
        fn new(addrs: Vec<SocketAddr>) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    addrs,
                    calls: Arc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl Resolver for FixedResolver {
        fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolveFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let addrs = self.addrs.clone();
            Box::pin(async move { Ok(addrs) })
        }
    }

    /// A [`Connector`] that records every address it was asked to connect
    /// to, in order, and always fails — a real connect is never needed to
    /// prove "the filter decided which addresses this dialer would have
    /// tried", only that the decision happened before any attempt.
    struct RecordingConnector {
        attempted: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    }

    impl RecordingConnector {
        fn new() -> (Self, Arc<std::sync::Mutex<Vec<SocketAddr>>>) {
            let attempted = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    attempted: Arc::clone(&attempted),
                },
                attempted,
            )
        }
    }

    impl Connector for RecordingConnector {
        fn connect<'a>(&'a self, addr: SocketAddr) -> ConnectFuture<'a> {
            self.attempted.lock().unwrap().push(addr);
            Box::pin(async move {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "RecordingConnector never actually connects",
                ))
            })
        }
    }

    fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(ip), port))
    }

    fn v6(ip: Ipv6Addr, port: u16) -> SocketAddr {
        SocketAddr::from((ip, port))
    }

    // ----------------------------------------------------------------
    // `is_host_local` category table (ADR-0019 decision 3's list).
    // ----------------------------------------------------------------

    #[test]
    fn host_local_categories_are_all_recognized() {
        let local: &[IpAddr] = &[
            // loopback
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            // "this network" (also covers IPv4 unspecified)
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)),
            // IPv6 unspecified
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            // link-local
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V6("fe80::1".parse().unwrap()),
            // multicast
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6("ff02::1".parse().unwrap()),
            // IPv4 broadcast
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            // IPv4-mapped and IPv4-compatible forms
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
            IpAddr::V6("::127.0.0.1".parse().unwrap()),
            IpAddr::V6("::ffff:169.254.169.254".parse().unwrap()),
        ];
        for ip in local {
            assert!(is_host_local(*ip), "{ip} must be host-local");
        }
    }

    #[test]
    fn ordinary_addresses_are_not_host_local() {
        let public: &[IpAddr] = &[
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // example.com-ish
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),      // RFC 1918: not filtered by ADR-0019
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            IpAddr::V6("::ffff:93.184.216.34".parse().unwrap()),
        ];
        for ip in public {
            assert!(!is_host_local(*ip), "{ip} must not be host-local");
        }
    }

    // ----------------------------------------------------------------
    // Dial-level behavior: injected resolver + connect counter.
    // ----------------------------------------------------------------

    /// Every host-local category the resolver can answer with must be
    /// refused with `Filtered`, and — the point of `RecordingConnector` —
    /// zero connect attempts, including the two IPv6-embedded forms and
    /// the "this network" literal ADR-0019 decision 3 calls out by name.
    #[tokio::test]
    async fn dynamic_dial_refuses_every_loopback_and_link_local_resolution() {
        for addr in [
            v4([127, 0, 0, 1], 80),
            v4([169, 254, 169, 254], 80),
            v4([0, 1, 2, 3], 80),
            v4([0, 0, 0, 0], 80),
            v4([224, 0, 0, 1], 80),
            v4([255, 255, 255, 255], 80),
            v6(Ipv6Addr::LOCALHOST, 80),
            v6(Ipv6Addr::UNSPECIFIED, 80),
            v6("fe80::1".parse().unwrap(), 80),
            v6("ff02::1".parse().unwrap(), 80),
            v6("::ffff:127.0.0.1".parse().unwrap(), 80),
            v6("::127.0.0.1".parse().unwrap(), 80),
        ] {
            let (resolver, resolve_calls) = FixedResolver::new(vec![addr]);
            let (connector, attempted) = RecordingConnector::new();
            let dialer = SystemDialer::with_resolver_and_connector(resolver, connector);

            let err = dialer
                .dial("attacker-controlled.example", 80, &FILTERED)
                .await
                .expect_err("a fully host-local resolution must be Filtered");
            assert!(matches!(err, DialError::Filtered), "{addr}: {err}");
            assert_eq!(err.code(), ErrorCode::PermissionDenied);
            assert_eq!(resolve_calls.load(Ordering::SeqCst), 1, "{addr}");
            assert!(
                attempted.lock().unwrap().is_empty(),
                "{addr}: a filtered address must never reach the connector"
            );
        }
    }

    /// A mix of filtered and real addresses: the filtered one is never
    /// handed to the connector at all, both survivors are (in resolver
    /// order), and the resolver is asked exactly once — ADR-0019 decision
    /// 3's "resolve once, filter, connect only to survivors" property,
    /// pinned on the one test that actually reaches the connector rather
    /// than only on fully-filtered lists that return before the connect
    /// loop runs. Uses [`RecordingConnector`] (which never actually opens
    /// a socket) rather than a real destination — the property under test
    /// is *which* addresses reach the connector, in what order, and how
    /// many times the resolver was asked, not whether a connect can
    /// succeed, and a real non-loopback destination is not something a
    /// unit test can assume exists on every CI runner.
    ///
    /// This is also the regression test for the check-then-connect race
    /// ADR-0019 decision 3 rules out: a `dial_unbounded` that re-resolved
    /// before each connect (instead of filtering the one resolution up
    /// front) would still pass every fully-filtered test above, but would
    /// fail `resolve_calls == 1` here.
    #[tokio::test]
    async fn dynamic_dial_skips_filtered_addresses_and_connects_to_the_rest() {
        let filtered_addr = v4([169, 254, 169, 254], 80);
        let survivor_a = v4([93, 184, 216, 34], 80);
        let survivor_b = v4([192, 0, 2, 55], 80);
        let (resolver, resolve_calls) =
            FixedResolver::new(vec![filtered_addr, survivor_a, survivor_b]);
        let (connector, attempted) = RecordingConnector::new();
        let dialer = SystemDialer::with_resolver_and_connector(resolver, connector);

        let err = dialer
            .dial("mixed.example", 80, &FILTERED)
            .await
            .expect_err("RecordingConnector never actually connects");
        assert!(
            matches!(err, DialError::Connect(_)),
            "the survivors must have been attempted (and failed), not Filtered: {err}"
        );
        assert_eq!(
            attempted.lock().unwrap().as_slice(),
            [survivor_a, survivor_b],
            "the filtered address must never be handed to the connector, \
             and both survivors must be, in resolver order"
        );
        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            1,
            "one resolution feeds every connect attempt in this dial; \
             a re-resolve here would be the check-then-connect race \
             ADR-0019 decision 3 rules out"
        );
    }

    /// The resolver is asked exactly once per dial, independent of how
    /// many addresses come back or how many of them the filter removes —
    /// ADR-0019 decision 3's "no re-resolve" no-race property, on a fully
    /// filtered list (no connect attempt at all). The companion case where
    /// connects actually happen is
    /// `dynamic_dial_skips_filtered_addresses_and_connects_to_the_rest`.
    #[tokio::test]
    async fn dynamic_dial_resolves_once() {
        let filtered_addr = v4([127, 0, 0, 1], 80);
        let (resolver, calls) = FixedResolver::new(vec![filtered_addr]);
        let (connector, _attempted) = RecordingConnector::new();
        let dialer = SystemDialer::with_resolver_and_connector(resolver, connector);

        let _ = dialer.dial("only-local.example", 80, &FILTERED).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// `deny_host_local: false` is byte-for-byte today's (pre-ADR-0019)
    /// behavior: a host-local resolution is dialed exactly as it always
    /// was, filter or no filter.
    #[tokio::test]
    async fn plain_dial_is_unfiltered() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (resolver, _calls) = FixedResolver::new(vec![addr]);
        let dialer = SystemDialer::with_resolver(resolver);

        let stream = dialer
            .dial("localhost", addr.port(), &UNFILTERED)
            .await
            .expect("an unfiltered dial to a loopback address must succeed");
        drop(stream);
        let (accepted, _peer) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("the loopback destination must have been connected to")
            .expect("accept");
        drop(accepted);
    }

    /// A destination that will never answer must come back as
    /// `CONNECTION_FAILED` on a bound, not park a host task and one of the
    /// connection's 1024 stream slots forever
    /// ([`TUNNEL_DIAL_TIMEOUT`]'s own doc).
    ///
    /// `192.0.2.1` is RFC 5737 TEST-NET-1: reserved for documentation and
    /// never routed, so the dial either blackholes (the timeout fires) or
    /// is rejected by the local stack (the connect fails) — the assertion
    /// holds for both, which is what makes it deterministic on a CI runner
    /// whose network policy is not ours to choose. The bound is injected
    /// in milliseconds so the test never waits out the 10 s default.
    #[tokio::test]
    async fn a_blackholed_destination_fails_with_connection_failed_rather_than_hanging() {
        let dialer = SystemDialer::with_timeout(Duration::from_millis(150));
        let started = std::time::Instant::now();

        let err = dialer
            .dial("192.0.2.1", 9, &UNFILTERED)
            .await
            .expect_err("TEST-NET-1 must not yield a socket");

        assert_eq!(
            err.code(),
            ErrorCode::ConnectionFailed,
            "a dial that never lands is CONNECTION_FAILED, not HOST_NOT_FOUND"
        );
        assert!(
            started.elapsed() < TUNNEL_DIAL_TIMEOUT,
            "the injected bound must have applied, not the default: {:?}",
            started.elapsed()
        );
    }

    /// The bound is real, and it is the *dialer's*: the same address with
    /// a production-shaped bound would take 10 s, so a test that only
    /// asserted "eventually errors" would not distinguish a working
    /// timeout from an absent one. This asserts the timeout path itself —
    /// an expiry maps onto `CONNECTION_FAILED` with a `TimedOut` cause.
    #[tokio::test]
    async fn an_expired_dial_is_a_connect_failure_not_a_resolve_failure() {
        // A resolvable-but-unreachable literal plus a 1 ms bound: too
        // short for any real connect to complete, so the timeout arm is
        // the one under test.
        let dialer = SystemDialer::with_timeout(Duration::from_millis(1));
        let err = dialer
            .dial("192.0.2.1", 9, &UNFILTERED)
            .await
            .expect_err("no socket");
        match err {
            DialError::Connect(_) => {}
            other => panic!(
                "an expiry must not be reported as anything but a connect failure: {other:?}"
            ),
        }
        assert_eq!(err.code(), ErrorCode::ConnectionFailed);
    }
}
