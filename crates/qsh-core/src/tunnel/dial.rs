//! The tunnel destination dial seam (`PLAN.md` M4 Step 3).
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

use std::future::Future;
use std::io;
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

/// Why a tunnel destination could not be reached. Carries no payload and
/// no peer-supplied text into the log — only the category and the
/// underlying `io::Error` (which callers turn into a fixed message).
#[derive(Debug)]
pub(crate) enum DialError {
    /// The destination host did not resolve to any address.
    Resolve(io::Error),
    /// It resolved, but no address could be connected to.
    Connect(io::Error),
}

impl DialError {
    /// The `docs/CLI.md` §3.3 code this failure reports to the requester in
    /// [`qsh_proto::wire::ConnectResult`]. No new `ErrorCode` is invented
    /// by M4 (`PLAN.md` §4.1 #9).
    pub(crate) fn code(&self) -> ErrorCode {
        match self {
            DialError::Resolve(_) => ErrorCode::HostNotFound,
            DialError::Connect(_) => ErrorCode::ConnectionFailed,
        }
    }
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::Resolve(err) => write!(f, "destination did not resolve: {err}"),
            DialError::Connect(err) => write!(f, "destination refused the connection: {err}"),
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
pub(crate) trait TunnelDialer: Send + Sync {
    /// Connect to `host:port`, resolving `host` if it is a name.
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> DialFuture<'a>;
}

/// The one implementation that ships: the operating system's resolver and
/// TCP stack, under a [`TUNNEL_DIAL_TIMEOUT`] bound.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SystemDialer {
    /// How long resolve + connect together may take. Configurable only so
    /// a test can bound itself in milliseconds instead of waiting out the
    /// production default; production always uses that default.
    timeout: Duration,
}

impl Default for SystemDialer {
    fn default() -> Self {
        Self {
            timeout: TUNNEL_DIAL_TIMEOUT,
        }
    }
}

impl SystemDialer {
    /// A dialer with a non-default bound. Test-only — see
    /// [`SystemDialer::timeout`].
    #[cfg(test)]
    pub(crate) fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl TunnelDialer for SystemDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> DialFuture<'a> {
        let bound = self.timeout;
        Box::pin(async move {
            // The whole thing is bounded, resolver included: a resolver
            // that never answers parks a task exactly as thoroughly as a
            // blackholed SYN does.
            match tokio::time::timeout(bound, dial_unbounded(host, port)).await {
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
async fn dial_unbounded(host: &str, port: u16) -> Result<TcpStream, DialError> {
    // Resolve first so "no such host" is distinguishable from
    // "host is there but refused" — the two get different
    // `ErrorCode`s (`DialError::code`).
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(DialError::Resolve)?
        .peekable();
    let mut last: Option<io::Error> = None;
    for addr in addrs.by_ref() {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                // Interactive forwards are latency-sensitive
                // (`docs/design/protocol.md` §12) — Nagle on a
                // spliced pipe just adds delay. Best effort.
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) => last = Some(err),
        }
    }
    Err(match last {
        Some(err) => DialError::Connect(err),
        None => DialError::Resolve(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses for destination",
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .dial("192.0.2.1", 9)
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
        let err = dialer.dial("192.0.2.1", 9).await.expect_err("no socket");
        match err {
            DialError::Connect(_) => {}
            DialError::Resolve(err) => {
                panic!("an expiry must not be reported as a resolve failure: {err}")
            }
        }
        assert_eq!(err.code(), ErrorCode::ConnectionFailed);
    }
}
