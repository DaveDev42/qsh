//! The reverse route of the supervisor (ADR-0023 decisions 4 and 7).
//!
//! The carrier here is a `LOCAL_CONTROL` conduit to this machine's own
//! `qsh listen` daemon plus the registration it reported. Nothing is dialed:
//! losing the carrier means the conduit ended, a per-accept identity check
//! failed (7-5), or the daemon could not be reached. Getting it back means
//! asking a daemon again (7-1), and a forward pin of the same name is never
//! a candidate (decision 22).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::local::LOCAL_WAIT_MAX;
use qsh_proto::wire;
use tokio::time::Instant;

use super::{
    AbortOnDrop, AttemptError, Ended, Established, Supervisor, control_pump, permission_denied,
};
use crate::client::Session;
use crate::client::wake;
use crate::localctl::client::{ExpectedPeer, open_control};
use crate::ops::OpError;
use crate::tunnel::local::ForwardCarrier;

/// What the reverse supervisor remembers about the route.
pub(in crate::ops::tunnel) struct ReverseRoute {
    /// The alias the user typed; the `host` on every diagnostic line.
    pub(in crate::ops::tunnel) alias: String,
    /// The name the daemon is asked for (`LocalHello.host`).
    pub(in crate::ops::tunnel) host: String,
    /// Where daemons leave their sockets.
    pub(in crate::ops::tunnel) runtime_dir: PathBuf,
    /// The socket of the daemon the carrier was last confirmed on.
    pub(in crate::ops::tunnel) socket: PathBuf,
    /// The registration generation the carrier was last confirmed at.
    pub(in crate::ops::tunnel) generation: u64,
}

/// A reverse carrier that passed its checks.
pub(in crate::ops::tunnel) struct ReverseEstablished {
    pub(super) session: Session,
    pub(super) socket: PathBuf,
    pub(super) generation: u64,
}

/// The `wait_ms` of a re-establishment: what is left of the budget, never
/// more than the daemon honors (decision 7-1).
fn wait_ms(remaining: Duration) -> u32 {
    u32::try_from(remaining.min(LOCAL_WAIT_MAX).as_millis()).unwrap_or(u32::MAX)
}

impl Supervisor {
    /// Watch the `LOCAL_CONTROL` conduit and the identity reports of the
    /// accept path until the carrier is lost (decision 4).
    pub(super) async fn monitor_reverse(&mut self, session: Session) -> Ended {
        let probes = Arc::new(tokio::sync::Notify::new());
        self.watch.revive();
        let mut pump = AbortOnDrop(tokio::spawn(control_pump(
            session,
            self.watch.clone(),
            probes,
        )));
        let mut wake_log = wake::subscribe();
        let mut denied_open = true;
        let mut changed_open = true;
        loop {
            tokio::select! {
                _ = &mut pump.0 => return Ended::Lost(None),
                denied = async {
                    if denied_open {
                        self.denied_rx.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => match denied {
                    Some(carrier) => {
                        if self.denial_ends_the_tunnel(&carrier) {
                            return Ended::Fatal(permission_denied());
                        }
                    }
                    None => denied_open = false,
                },
                changed = async {
                    if changed_open {
                        self.changed_rx.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => match changed {
                    Some(carrier) => {
                        // A report about a superseded carrier says nothing
                        // about the current one.
                        if Arc::ptr_eq(&carrier, &self.current) {
                            return Ended::Lost(None);
                        }
                    }
                    None => changed_open = false,
                },
                changed = wake_log.changed() => {
                    if changed.is_ok() {
                        let event = *wake_log.borrow_and_update();
                        self.log_wake(event);
                    }
                }
            }
        }
    }

    /// One attempt to get a verified reverse carrier back (decisions 7-1
    /// through 7-3).
    pub(super) async fn attempt_reverse(
        &self,
        route: &ReverseRoute,
    ) -> Result<Established, AttemptError> {
        let socket =
            crate::ops::host::find_reverse_socket(&route.runtime_dir, &route.host, &route.socket)
                .await
                .map_err(AttemptError::daemon)?;
        // A daemon that restarted starts its generations over, so the last
        // one is only meaningful against the socket it came from.
        let known = (socket == route.socket).then_some(route.generation);
        let wait = wait_ms(self.budget.remaining(Instant::now()));
        let handshake = open_control(&socket, &route.host, wait, known)
            .await
            .map_err(AttemptError::daemon)?;
        if handshake.peer_fingerprint != self.params.fingerprint {
            // Dropping the handshake closes the conduit; no request has
            // been sent on it (decision 7-2).
            return Err(AttemptError::check(OpError::new(
                ErrorCode::AuthFailed,
                "the peer registered under this host name is no longer the one the tunnel was \
                 opened to",
            )));
        }
        if self.params.require_dial_filter
            && !handshake
                .capabilities
                .iter()
                .any(|c| c == wire::CAP_DIAL_FILTER_V1)
        {
            return Err(AttemptError::check(
                super::super::dynamic_forward_reverse_capability_unsupported(),
            ));
        }
        let generation = handshake.generation;
        let session = Session::from_local_control(
            handshake.conduit,
            handshake.capabilities,
            handshake.host,
            socket.clone(),
            handshake.peer_fingerprint,
            generation,
        );
        Ok(Established::Reverse(ReverseEstablished {
            session,
            socket,
            generation,
        }))
    }

    /// Record the new registration and build the carrier that rides it.
    pub(super) fn install_reverse(
        &mut self,
        next: ReverseEstablished,
    ) -> (ForwardCarrier, Session) {
        let ReverseEstablished {
            session,
            socket,
            generation,
        } = next;
        let mut host = String::new();
        if let super::Route::Reverse(route) = &mut self.params.route {
            route.socket = socket.clone();
            route.generation = generation;
            host = route.host.clone();
        }
        let carrier = ForwardCarrier::Local {
            socket,
            host,
            expect: Some(ExpectedPeer {
                fingerprint: self.params.fingerprint.clone(),
                generation,
            }),
        };
        (carrier, session)
    }
}
