//! End A's whole punch: signal a rendezvous, run the schedule, adopt the
//! first pin-checked handshake (ADR-0054 decisions 4, 8, 10, 12, 16, 17).
//!
//! The race with a direct dial, and the budget it shares, are `ops::route`'s;
//! this module takes the deadline it is given and never goes past it.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

use qsh_proto::ErrorCode;
use qsh_proto::punch::{AttemptId, check_candidates};
use qsh_proto::wire::{
    self, ControlMessage, Hello, PunchCandidate, PunchCandidateKind, PunchRefusal, PunchRequest,
    control_message, response,
};
use qsh_transport::{
    Connection, DialError, Endpoint, PunchEndpoint, SocketSource, TransportTuning,
};
use tokio::time::{Instant, timeout_at};

use super::{
    GiveUp, GiveUpReason, InitiatorParams, PUNCH_INITIAL_RTT, PUNCH_SERVER_NAME,
    PUNCH_SIGNAL_BUDGET, PUNCH_WINDOW, PunchFailure, PunchPlan, RendezvousPeer,
    host_candidate_messages, host_candidates, is_public, run_initiator,
};

/// A connection that won the punch.
#[derive(Debug)]
pub(crate) struct PunchWin {
    /// The verified connection to the target.
    pub connection: Connection,
    /// The endpoint that carries it.
    pub endpoint: Endpoint,
}

/// Closes the endpoint when the attempt is dropped before it adopted
/// anything (the direct dial won, or the deadline passed).
struct EndpointGuard(Option<PunchEndpoint>);

impl EndpointGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if let Some(ep) = self.0.take() {
            ep.close(0, b"done");
        }
    }
}

/// Closes a connection when dropped.
struct CloseOnDrop(Connection);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close(0, b"done");
    }
}

/// What a rendezvous told us.
struct Signaled {
    attempt: AttemptId,
    /// Target candidates (validated), the derived one included.
    candidates: Vec<SocketAddr>,
}

/// One punch attempt on a fresh endpoint. `deadline` bounds everything: the
/// signalling gets [`PUNCH_SIGNAL_BUDGET`] and the window [`PUNCH_WINDOW`],
/// each cut short by it.
pub(crate) async fn attempt(
    plan: &PunchPlan,
    tuning: TransportTuning,
    deadline: Instant,
) -> Result<PunchWin, PunchFailure> {
    let start = Instant::now();
    let first = plan
        .rendezvous
        .first()
        .ok_or_else(|| plan.no_rendezvous())?;
    let failed = |peer: &RendezvousPeer, reason| PunchFailure {
        rendezvous: peer.name.clone(),
        reason,
    };
    tracing::info!(target: "qsh::punch", event = "attempt", rendezvous = %first.name);

    let source = plan
        .env
        .socket
        .as_ref()
        .map_or(SocketSource::Os, |make| make());
    let ep = PunchEndpoint::new(
        source,
        plan.identity.clone(),
        plan.evaluator.clone(),
        tuning,
    )
    .map_err(|_| failed(first, GiveUpReason::RendezvousUnreachable))?;
    let mut guard = EndpointGuard(Some(ep.clone()));

    let signal_deadline = deadline.min(start + PUNCH_SIGNAL_BUDGET);
    let mut outcome: Result<(Signaled, &RendezvousPeer), PunchFailure> =
        Err(failed(first, GiveUpReason::RendezvousUnreachable));
    for peer in plan.rendezvous.iter().take(2) {
        match signal(&ep, plan, peer, signal_deadline).await {
            Ok(signaled) => {
                outcome = Ok((signaled, peer));
                break;
            }
            Err(reason) => {
                outcome = Err(failed(peer, reason));
                if !reason.tries_next_rendezvous() {
                    break;
                }
            }
        }
    }
    let (signaled, peer) = outcome?;
    tracing::info!(
        target: "qsh::punch",
        event = "signaled",
        rendezvous = %peer.name,
        candidates = signaled.candidates.len()
    );

    // The window runs from the answer, and never past the route's deadline.
    let budget = PUNCH_WINDOW.min(deadline.saturating_duration_since(Instant::now()));
    let params = InitiatorParams {
        attempt_id: signaled.attempt,
        expected_peer: plan.target,
        candidates: signaled.candidates,
        budget,
    };
    match run_initiator(&ep, &params).await {
        Ok(adopted) => {
            guard.disarm();
            tracing::info!(
                target: "qsh::punch",
                event = "adopted",
                rendezvous = %peer.name,
                peer_reflexive = adopted.peer_reflexive,
                elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
            );
            Ok(PunchWin {
                connection: adopted.connection,
                endpoint: ep.endpoint(),
            })
        }
        Err(give_up) => {
            let reason = match give_up {
                GiveUp::NoCandidate => GiveUpReason::NoCandidatePair,
                GiveUp::Timeout { failed_dials } => {
                    let all_mismatched = !failed_dials.is_empty()
                        && failed_dials
                            .iter()
                            .all(|(_, e)| matches!(e, DialError::LocalRejected { .. }));
                    if all_mismatched {
                        GiveUpReason::PeerMismatch
                    } else {
                        GiveUpReason::Timeout
                    }
                }
            };
            tracing::info!(
                target: "qsh::punch",
                event = "gave_up",
                rendezvous = %peer.name,
                reason = reason.as_str()
            );
            Err(failed(peer, reason))
        }
    }
}

fn hello(plan: &PunchPlan) -> Hello {
    Hello {
        versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
        device_name: plan.device_name.clone(),
        capabilities: wire::LOCAL_CAPABILITIES
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        reverse: None,
    }
}

/// Dials `peer` from the punching endpoint, sends the `PunchRequest` and
/// reads the reply, all before `deadline`.
async fn signal(
    ep: &PunchEndpoint,
    plan: &PunchPlan,
    peer: &RendezvousPeer,
    deadline: Instant,
) -> Result<Signaled, GiveUpReason> {
    let connected = AtomicBool::new(false);
    let work = async {
        let addrs = crate::ops::resolve_all(&peer.address)
            .await
            .map_err(|_| GiveUpReason::RendezvousUnreachable)?;
        let addr = *addrs.first().ok_or(GiveUpReason::RendezvousUnreachable)?;
        let conn = ep
            .dial(
                addr,
                PUNCH_SERVER_NAME,
                PUNCH_INITIAL_RTT,
                &peer.fingerprint,
            )
            .await
            .map_err(|e| match e {
                DialError::RemoteRejected => GiveUpReason::RendezvousDenied,
                _ => GiveUpReason::RendezvousUnreachable,
            })?;
        // R's job ends with the reply; the connection never outlives it.
        let _close = CloseOnDrop(conn.clone());
        connected.store(true, Ordering::Relaxed);

        let (mut ctl, peer_hello) = crate::handshake::initiate(&conn, hello(plan))
            .await
            .map_err(|e| match e {
                crate::handshake::HelloError::Remote { code, .. } => match code {
                    ErrorCode::Unsupported => GiveUpReason::RendezvousUnsupported,
                    ErrorCode::PermissionDenied => GiveUpReason::RendezvousDenied,
                    ErrorCode::ResourceExhausted => GiveUpReason::RateLimited,
                    _ => GiveUpReason::RendezvousUnreachable,
                },
                _ => GiveUpReason::RendezvousUnreachable,
            })?;
        if !peer_hello
            .capabilities
            .iter()
            .any(|c| c == wire::CAP_PUNCH_V1)
        {
            return Err(GiveUpReason::RendezvousUnsupported);
        }

        // Our host candidates, from the socket the dial to R used.
        let port = ep
            .local_addr()
            .map_err(|_| GiveUpReason::RendezvousUnreachable)?
            .port();
        let observed = plan.env.local_addrs.observe();
        let mine = host_candidates(&observed, port);
        let filtered = crate::client_path::filter_addresses(mine.clone());
        if !observed.is_empty() && filtered.is_empty() {
            return Err(GiveUpReason::NoCandidatePair);
        }
        let attempt: AttemptId = rand::random();
        let request = PunchRequest {
            attempt_id: attempt.to_vec(),
            target_fingerprint: plan.target.as_bytes().to_vec(),
            candidates: host_candidate_messages(&filtered),
        };
        ctl.send
            .send(&ControlMessage::new(
                1,
                control_message::Body::PunchRequest(request),
            ))
            .await
            .map_err(|_| GiveUpReason::RendezvousUnreachable)?;

        let reply = loop {
            let msg = ctl
                .recv
                .recv::<ControlMessage>()
                .await
                .map_err(|_| GiveUpReason::RendezvousUnreachable)?
                .ok_or(GiveUpReason::RendezvousUnreachable)?;
            if msg.request_id != 1 {
                continue;
            }
            match msg.body {
                Some(control_message::Body::Response(wire::Response { body: Some(body) })) => {
                    break body;
                }
                _ => continue,
            }
        };
        let reply = match reply {
            response::Body::PunchReply(reply) => reply,
            response::Body::Error(err) => {
                return Err(match err.error_code() {
                    ErrorCode::PermissionDenied => GiveUpReason::RendezvousDenied,
                    ErrorCode::ResourceExhausted => GiveUpReason::RateLimited,
                    ErrorCode::Unsupported => GiveUpReason::RendezvousUnsupported,
                    _ => GiveUpReason::RendezvousUnreachable,
                });
            }
            _ => return Err(GiveUpReason::RendezvousUnsupported),
        };
        match reply.refusal() {
            PunchRefusal::None => {}
            PunchRefusal::TargetNotRegistered => return Err(GiveUpReason::TargetNotRegistered),
            PunchRefusal::TargetUnsupported => return Err(GiveUpReason::TargetUnsupported),
            PunchRefusal::TargetDenied => return Err(GiveUpReason::TargetDenied),
            PunchRefusal::TargetBusy => return Err(GiveUpReason::RateLimited),
            PunchRefusal::TargetTimeout => return Err(GiveUpReason::Timeout),
        }
        if reply.validate().is_err() {
            return Err(GiveUpReason::RendezvousUnsupported);
        }
        let checked =
            check_candidates(&reply.candidates).map_err(|_| GiveUpReason::RendezvousUnsupported)?;
        let mut candidates = checked.accepted;

        // Decision 3: when R is behind the target's NAT, the address R saw
        // for the target is private. The target's outside address is then
        // probably the one we reached R at, with the port R saw.
        if reply.target_reflexive_private {
            let reflexive_port = reply
                .candidates
                .iter()
                .filter(|c| c.kind == PunchCandidateKind::Reflexive as i32)
                .find_map(PunchCandidate::socket_addr)
                .map(|a| a.port());
            if let (Some(port), IpAddr::V4(v4)) = (reflexive_port, addr.ip().to_canonical())
                && is_public(IpAddr::V4(v4))
            {
                let derived = SocketAddr::new(IpAddr::V4(v4), port);
                if !candidates.contains(&derived) {
                    candidates.push(derived);
                }
            }
        }
        let candidates = crate::client_path::filter_addresses(candidates);
        if candidates.is_empty() {
            return Err(GiveUpReason::NoCandidatePair);
        }
        Ok(Signaled {
            attempt,
            candidates,
        })
    };
    match timeout_at(deadline, work).await {
        Ok(result) => result,
        Err(_) if connected.load(Ordering::Relaxed) => Err(GiveUpReason::Timeout),
        Err(_) => Err(GiveUpReason::RendezvousUnreachable),
    }
}
