//! What the client route needs to punch to one host (ADR-0054 decisions 4,
//! 16, 17): the settings, the rendezvous candidates, and the closed
//! vocabulary of reasons for giving up.

use std::sync::Arc;
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_transport::{Fingerprint, LocalIdentity, SocketSource, TrustEvaluator};

use crate::ops::OpError;

use super::{LocalAddrs, PUNCH_HEAD_START, RouteAddrs};

/// `[punch].mode` (ADR-0054 decision 19).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PunchMode {
    /// Punch when there is a rendezvous candidate and the direct route does
    /// not stand quickly.
    #[default]
    Auto,
    /// Never start a punch.
    Off,
}

/// Where a fresh endpoint's UDP socket comes from. Production leaves this
/// unset (the OS); the netsim tests give each endpoint a virtual socket.
pub type SocketFactory = Arc<dyn Fn() -> SocketSource + Send + Sync>;

/// How one process punches. [`Ops::with_punch`](crate::Ops::with_punch)
/// installs it; the default punches nowhere, because no rendezvous is
/// configured.
#[derive(Clone)]
pub struct ClientPunch {
    /// `auto` or `off`.
    pub mode: PunchMode,
    /// Rendezvous peers by pin name, in the order to try them. This is
    /// `--rendezvous` (which, when given, replaces the pin's own list).
    /// Empty means no rendezvous is configured and the route is the direct
    /// dial alone.
    pub rendezvous: Vec<String>,
    /// How long the direct dial runs alone first.
    pub head_start: Duration,
    /// Where the local host candidates come from.
    pub local_addrs: Arc<dyn LocalAddrs>,
    /// Source of the punching endpoint's socket (and of the direct dial's,
    /// when set). `None` is the OS.
    pub socket: Option<SocketFactory>,
}

impl Default for ClientPunch {
    fn default() -> Self {
        Self {
            mode: PunchMode::Auto,
            rendezvous: Vec::new(),
            head_start: PUNCH_HEAD_START,
            local_addrs: Arc::new(RouteAddrs),
            socket: None,
        }
    }
}

impl std::fmt::Debug for ClientPunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientPunch")
            .field("mode", &self.mode)
            .field("rendezvous", &self.rendezvous)
            .field("head_start", &self.head_start)
            .field("socket", &self.socket.is_some())
            .finish_non_exhaustive()
    }
}

/// Why a punch ended without a connection (ADR-0054 decision 17). The
/// strings are the contract: `details.punch.reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GiveUpReason {
    /// No usable rendezvous candidate.
    NoRendezvous,
    /// The rendezvous could not be dialed.
    RendezvousUnreachable,
    /// The rendezvous lacks `punch.v1`, has it off, or takes no such peer.
    RendezvousUnsupported,
    /// The rendezvous refused this device.
    RendezvousDenied,
    /// The rendezvous holds no live registration of the target.
    TargetNotRegistered,
    /// The target lacks `punch.v1` or has it off.
    TargetUnsupported,
    /// The target refused this device.
    TargetDenied,
    /// A rate or concurrency limit stopped the attempt.
    RateLimited,
    /// After the `-4`/`-6` filter no candidate pair was left.
    NoCandidatePair,
    /// Every handshake reached some other pinned peer than the target.
    PeerMismatch,
    /// The window ended, or the answer never came.
    Timeout,
}

impl GiveUpReason {
    /// All eleven, in the ADR's order.
    pub const ALL: [GiveUpReason; 11] = [
        Self::NoRendezvous,
        Self::RendezvousUnreachable,
        Self::RendezvousUnsupported,
        Self::RendezvousDenied,
        Self::TargetNotRegistered,
        Self::TargetUnsupported,
        Self::TargetDenied,
        Self::RateLimited,
        Self::NoCandidatePair,
        Self::PeerMismatch,
        Self::Timeout,
    ];

    /// The word in `details.punch.reason`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRendezvous => "no_rendezvous",
            Self::RendezvousUnreachable => "rendezvous_unreachable",
            Self::RendezvousUnsupported => "rendezvous_unsupported",
            Self::RendezvousDenied => "rendezvous_denied",
            Self::TargetNotRegistered => "target_not_registered",
            Self::TargetUnsupported => "target_unsupported",
            Self::TargetDenied => "target_denied",
            Self::RateLimited => "rate_limited",
            Self::NoCandidatePair => "no_candidate_pair",
            Self::PeerMismatch => "peer_mismatch",
            Self::Timeout => "timeout",
        }
    }

    /// Whether the next rendezvous candidate is worth trying: the signal
    /// failed at or before this rendezvous (decision 4).
    pub const fn tries_next_rendezvous(self) -> bool {
        matches!(
            self,
            Self::RendezvousUnreachable
                | Self::RendezvousUnsupported
                | Self::RendezvousDenied
                | Self::TargetNotRegistered
        )
    }
}

impl std::fmt::Display for GiveUpReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a punch ended badly: through which rendezvous (the pin name on this
/// device, never an address) and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PunchFailure {
    /// The rendezvous pin name last used; the first configured name when
    /// none was usable.
    pub rendezvous: String,
    /// The reason.
    pub reason: GiveUpReason,
}

impl PunchFailure {
    /// The `details.punch` object.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "rendezvous": self.rendezvous, "reason": self.reason.as_str() })
    }

    /// The tail of the human error line.
    pub fn human_suffix(&self) -> String {
        format!(
            "; hole punching via {} failed: {}",
            self.rendezvous, self.reason
        )
    }

    /// Adds the punch to the error the direct route produced
    /// (`details.punch`, and a clause on the human line). Only the two
    /// reachability codes carry it; any other error, an authentication
    /// failure above all, is left exactly as it was.
    #[must_use]
    pub fn attach_to(&self, mut op: OpError) -> OpError {
        if !matches!(op.code, ErrorCode::ConnectionFailed | ErrorCode::Timeout) {
            return op;
        }
        match &mut op.details {
            serde_json::Value::Null => {
                op.details = serde_json::json!({ "punch": self.to_json() });
            }
            serde_json::Value::Object(map) => {
                map.insert("punch".to_string(), self.to_json());
            }
            _ => return op,
        }
        op.message.push_str(&self.human_suffix());
        op
    }
}

/// A rendezvous candidate: a peer pinned here with an address.
#[derive(Clone, Debug)]
pub struct RendezvousPeer {
    /// The pin's name.
    pub name: String,
    /// The certificate fingerprint it must present.
    pub fingerprint: Fingerprint,
    /// Where to dial it (`host:port`).
    pub address: String,
}

/// Everything one route needs to punch to one host.
#[derive(Clone)]
pub struct PunchPlan {
    pub(crate) env: ClientPunch,
    /// The target's pinned fingerprint: the only certificate a punched
    /// handshake may present (decision 12).
    pub(crate) target: Fingerprint,
    /// Usable candidates, at most two are tried.
    pub(crate) rendezvous: Vec<RendezvousPeer>,
    /// The first name that was asked for, for the report when none was
    /// usable.
    pub(crate) first_name: String,
    pub(crate) device_name: String,
    pub(crate) identity: LocalIdentity,
    pub(crate) evaluator: Arc<dyn TrustEvaluator>,
}

impl std::fmt::Debug for PunchPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchPlan")
            .field("rendezvous", &self.rendezvous)
            .finish_non_exhaustive()
    }
}

impl PunchPlan {
    /// Builds a plan; `None` when punching is off or no rendezvous name was
    /// asked for.
    pub(crate) fn new(
        env: &ClientPunch,
        target: Fingerprint,
        rendezvous: Vec<RendezvousPeer>,
        device_name: String,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
    ) -> Option<Arc<Self>> {
        if env.mode == PunchMode::Off {
            return None;
        }
        let first_name = env.rendezvous.first()?.clone();
        Some(Arc::new(Self {
            env: env.clone(),
            target,
            rendezvous,
            first_name,
            device_name,
            identity,
            evaluator,
        }))
    }

    /// Whether any rendezvous candidate is usable.
    pub(crate) fn has_rendezvous(&self) -> bool {
        !self.rendezvous.is_empty()
    }

    /// The failure to report when there was nothing to punch through.
    pub(crate) fn no_rendezvous(&self) -> PunchFailure {
        PunchFailure {
            rendezvous: self.first_name.clone(),
            reason: GiveUpReason::NoRendezvous,
        }
    }
}
