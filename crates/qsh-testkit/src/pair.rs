//! [`HostedPair`]: the connected-pair abstraction the mechanical proof of
//! role-axis independence (`PLAN.md` M3 Step 3 PR 3b, `docs/design/
//! testing.md` L3) is built on.
//!
//! `session_loopback.rs`/`attach_loopback.rs`/`resume_loopback.rs` were
//! written against [`crate::loopback::LoopbackHarness`]'s concrete fields
//! and methods — a real host, one pinned client, `h.session()` dialing
//! fresh. Step 3 adds a second, role-swapped topology
//! ([`crate::reverse::ReversePairHarness`]): the party that *dials* (a
//! `qsh reverse` target) is the one that holds the broker and serves
//! requests, and the party that *accepts* (a `qsh listen` controller) is
//! the one that drives them — the opposite pairing from forward, on the
//! same `Ops`/session code. This trait is the seam that lets one scenario
//! function's body run unmodified against either topology: every primitive
//! a scenario needs — a fresh client-role [`Session`], a raw client-role
//! control stream for tests that pipeline [`wire::ControlMessage`]s
//! directly, and read access to the *host* side's broker/pipes/audit/
//! server — is named here without saying which side dialed.
//!
//! What does **not** move behind this trait: constructing a harness with a
//! non-default [`qsh_core::acl::Authorizer`], and anything involving a
//! *second, distinct* principal reaching the same host. The latter has no
//! reverse-mode analogue at all — see [`crate::reverse::ReversePairHarness`]'s
//! module docs — which is exactly why `resume_loopback.rs`'s three
//! multi-principal scenarios stay forward-only (named exclusions, not
//! silent ones).

use std::future::Future;
use std::sync::Arc;

use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Broker, PipeFactory};
use qsh_core::client::Session;
use qsh_core::server::Server;
use qsh_transport::{Connection, FramedStream};

/// A connected pair, named by the primitives a scenario needs rather than
/// by which side physically dialed. Implemented by
/// [`crate::loopback::LoopbackHarness`] (forward: the listener holds the
/// broker) and [`crate::reverse::ReversePairHarness`] (reverse: the dialer
/// does).
pub trait HostedPair: Sized {
    /// The host side's request dispatcher — `pending_tickets()` is the
    /// primitive every ticket-lifecycle assertion needs, and it is the same
    /// `qsh_core::server::Server` type regardless of which side dialed.
    fn server(&self) -> &Arc<Server>;

    /// The host side's session broker — same `Arc<Broker>` a scenario
    /// plants an out-of-band session into or reads `session_count()` from
    /// in either direction.
    fn broker(&self) -> &Arc<Broker>;

    /// The host side's pipe-backed session sources — `take()`/
    /// `take_with_spec()` hand back the "child" a scenario drives, in
    /// either direction (`docs/design/testing.md` §3: zero PTY code).
    fn pipes(&self) -> &Arc<PipeFactory>;

    /// Every audit record the host side produced.
    fn audit(&self) -> &Arc<MemoryAuditSink>;

    /// A fresh connection, `Hello`-negotiated and wrapped as a client-role
    /// [`Session`] — `h.session()` either direction. Forward: dial the
    /// host. Reverse: the target dials the controller and serves as host on
    /// that connection; this hands back the *controller's* client-role
    /// handle on it.
    fn session(&self) -> impl Future<Output = Session> + Send;

    /// [`Self::session`] without the [`Session`] wrapper — the client-role
    /// [`Connection`] and its already-negotiated control [`FramedStream`],
    /// for scenarios that pipeline raw `wire::ControlMessage`s directly to
    /// exercise the dispatch loop's ordering/backpressure behaviour instead
    /// of going through the typed client API.
    fn raw_session(&self) -> impl Future<Output = (Connection, FramedStream)> + Send;

    /// Stop the pair and, where the topology supports it, wait for a clean
    /// drain.
    fn shutdown(self) -> impl Future<Output = ()> + Send;
}
