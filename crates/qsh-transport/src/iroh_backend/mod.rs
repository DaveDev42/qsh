//! The iroh relay backend (ADR-0061).
//!
//! A second transport (compiled in by default, ADR-0061 decision 13) next to QUIC-over-UDP: iroh reaches a peer
//! by its Ed25519 public key over a direct path, a holepunched path or a
//! relay, inside one connection. Nothing outside this module names iroh or
//! noq; the connection comes out as a [`Connection`](crate::Connection)
//! like any other.
//!
//! - `conn`: the [`MuxConn`](crate::mux::MuxConn) / `SendHalf` / `RecvHalf`
//!   implementations.
//! - `endpoint`: [`IrohEndpoint`] (bind, dial, accept) and the pin check.
//! - `key`: the qsh identity key as an iroh key, and the fingerprint of an
//!   endpoint id.
//! - `errors`: noq errors into the transport-neutral ones.

mod conn;
mod endpoint;
mod errors;
mod key;
#[cfg(test)]
mod size_guard;

pub(crate) use conn::{IrohConn, IrohRecv, IrohSend};
pub(crate) use endpoint::verify_iroh_peer;
pub use endpoint::{
    DEFAULT_RELAY_URL, IROH_ALPN, IrohConfig, IrohEndpoint, IrohIncoming, IrohPeer, IrohRelay,
    IrohRelayTrust,
};
pub use key::fingerprint_of_ed25519_key;
