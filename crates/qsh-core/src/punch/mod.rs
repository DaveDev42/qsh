//! Hole punching, the part that needs no signalling (ADR-0054 decisions 13
//! to 15). Candidates come in as plain addresses; a later step brings them
//! from a rendezvous over `punch.v1`.
//!
//! * [`schedule`]: the send schedule as a pure function of elapsed time.
//! * [`run_initiator`]: end A. Sends punch datagrams, dials every candidate
//!   from the same socket, learns peer-reflexive candidates from the target's
//!   punches, adopts the first pin-checked handshake and closes the rest with
//!   `0x1006`.
//! * [`run_target`]: end B. Opens a server window, sends punch datagrams, and
//!   hands every verified inbound connection to the caller until the window
//!   closes.
//!
//! Everything QUIC-shaped goes through [`qsh_transport::PunchEndpoint`]; this
//! module names no quinn type and builds no datagram bytes (it can only ask
//! for a tag to be sent).

mod initiator;
pub mod schedule;
mod target;

use std::time::Duration;

pub use initiator::{Adopted, GiveUp, InitiatorParams, run_initiator};
pub use target::{TargetParams, TargetReport, run_target};

/// Offsets from t=0 at which each candidate gets a punch datagram
/// (ADR-0054 decision 14).
pub const PUNCH_OFFSETS_MS: [u64; 8] = [0, 50, 100, 200, 400, 800, 1600, 3200];

/// Candidates one side sends over the wire, and peer-reflexive candidates A
/// adds on its own (decision 8). Defined with the wire messages.
pub use qsh_proto::punch::{MAX_PEER_REFLEXIVE, MAX_PUNCH_CANDIDATES};

/// Punch datagrams one end sends in one attempt: eight candidates, eight
/// offsets (decision 14).
pub const MAX_PUNCH_DATAGRAMS: usize = MAX_PUNCH_CANDIDATES * PUNCH_OFFSETS_MS.len();

/// The round-trip guess of A's handshakes (decision 14).
pub const PUNCH_INITIAL_RTT: Duration = Duration::from_millis(100);

/// How long B's server window stays open (decision 14).
pub const PUNCH_TARGET_WINDOW: Duration = Duration::from_secs(6);

/// Handshakes B accepts from one offer (decision 14).
pub const MAX_HANDSHAKES_PER_OFFER: usize = 4;

/// Signalling budget (decision 16). Unused until the signalling step.
pub const PUNCH_SIGNAL_BUDGET: Duration = Duration::from_millis(3000);

/// From the answer to adoption (decision 16).
pub const PUNCH_WINDOW: Duration = Duration::from_millis(5000);

/// The TLS server name A dials with. Informational: the verifier ignores it
/// and SNI is off.
pub const PUNCH_SERVER_NAME: &str = "qsh";

#[cfg(test)]
mod tests;
