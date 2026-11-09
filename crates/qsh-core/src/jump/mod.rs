//! Jump chaining (ADR-0056, `docs/design/protocol.md` §21).
//!
//! [`middle`] is the intermediate peer J: it opens a `connect`ed UDP socket
//! toward the next hop on a client's `JUMP` stream and carries the packets of
//! the inner QUIC connection between that socket and the outer connection,
//! without ever reading anything but the clear-text QUIC header fields its
//! gate needs. [`chain`] is the client: it walks a list of hops over `PacketPipe`s
//! ([`dial_chain`]), and [`report`] words a failure.

pub mod carrier;
pub mod chain;
pub mod middle;
pub mod relay;
pub mod report;

pub use chain::{
    ChainConn, ChainInfo, ChannelInfo, HopPin, JumpPlan, MAX_JUMP_HOPS, PumpEnd, ReverseHop,
    dial_chain, dial_chain_via_daemon,
};
pub use middle::{
    CloseReason, JUMP_GATE_TIMEOUT, JUMP_IDLE, JUMP_RESOLVE_TIMEOUT, JumpOptions, JumpStats,
    MAX_JUMP_CHANNELS_PER_CONN,
};

/// The tracing target of the jump lines (ADR-0056 decision 19). The lines are
/// opt-in: they are emitted at `debug`, which the default filter drops.
pub const TARGET: &str = "qsh::jump";
pub use relay::{JUMP_OPEN_TIMEOUT, MAX_JUMP_CHANNELS_PER_HUB, RelayEnd, RelayStats};
pub use report::{JumpFailure, Stage};
