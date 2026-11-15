//! What is left of qsh's own hole punching (ADR-0054) after ADR-0068 turned
//! it off for good: the `[punch].mode` vocabulary, which still parses and
//! does nothing, the `qsh::punch` log target, and the local-address source
//! the route memory shares. The client never starts a punch and no host
//! relays or accepts one: a `PunchRequest` or `PunchOffer` is answered
//! `UNSUPPORTED`, the answer a peer with `[punch].mode = "off"` always gave
//! (ADR-0054 decision 9). The wire messages and the `punch.v1` capability
//! stay in `qsh-proto`.

pub mod addrs;
pub mod log;

use std::sync::Arc;

pub use addrs::{FixedAddrs, LocalAddrs, RouteAddrs};
pub use log::TARGET;

/// `[punch].mode` (ADR-0054 decision 19). Both spellings still parse; neither
/// changes anything since ADR-0068.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PunchMode {
    /// The default spelling.
    #[default]
    Auto,
    /// `--no-punch`.
    Off,
}

impl PunchMode {
    /// The spelling the flag and the config key use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Off => "off",
        }
    }
}

/// What a process still configures of the retired punch settings:
/// [`Ops::with_punch`](crate::Ops::with_punch) installs it. `mode` is
/// carried and ignored.
#[derive(Clone)]
pub struct ClientPunch {
    /// `auto` or `off`; no effect.
    pub mode: PunchMode,
    /// Where the local source addresses come from (the route memory's
    /// network-change test).
    pub local_addrs: Arc<dyn LocalAddrs>,
}

impl Default for ClientPunch {
    fn default() -> Self {
        Self {
            mode: PunchMode::Auto,
            local_addrs: Arc::new(RouteAddrs),
        }
    }
}

impl std::fmt::Debug for ClientPunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientPunch")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}
