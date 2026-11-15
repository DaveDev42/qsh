//! [`HostedPair`]: the connected-pair abstraction `session_loopback.rs`,
//! `attach_loopback.rs` and `resume_loopback.rs` run their scenarios on.
//!
//! The scenarios were written for two topologies, a forward host and a
//! role-swapped reverse one. ADR-0068 retired the reverse topology, so
//! [`crate::loopback::LoopbackHarness`] is the only implementor now; the
//! trait stays as the seam that names every primitive a scenario needs (a
//! fresh client-role [`Session`], a raw client-role control stream for tests
//! that pipeline [`qsh_proto::wire::ControlMessage`]s directly, and read
//! access to the host side's broker/pipes/audit/server).

use std::future::Future;
use std::sync::Arc;

use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Broker, PipeFactory};
use qsh_core::client::Session;
use qsh_core::server::Server;
use qsh_transport::{Connection, FramedStream};

/// A connected pair, named by the primitives a scenario needs rather than
/// by which side physically dialed. Implemented by
/// [`crate::loopback::LoopbackHarness`] (the listener holds the broker).
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
    /// [`Session`]: dial the host.
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
