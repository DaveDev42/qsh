//! End A's whole punch: signal a rendezvous, run the schedule, adopt the
//! first pin-checked handshake (ADR-0054 decisions 4, 8, 10, 12, 16, 17).
//!
//! The race with a direct dial, and the budget it shares, are `ops::route`'s;
//! this module takes the deadline it is given and never goes past it.

use std::collections::HashMap;
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
    host_candidate_messages, host_candidates, is_public, log, run_initiator,
};

/// A connection that won the punch.
#[derive(Debug)]
pub(crate) struct PunchWin {
    /// The verified connection to the target.
    pub connection: Connection,
    /// The endpoint that carries it.
    pub endpoint: Endpoint,
    /// What won, for `qsh doctor` and the `qsh::punch` line. No address.
    pub info: WinInfo,
}

/// How a punch was won: words and numbers only, never an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WinInfo {
    /// The rendezvous pin's name.
    pub rendezvous: String,
    /// `host`, `reflexive` or `peer_reflexive` ([`log::KIND_HOST`] and kin).
    pub kind: &'static str,
    /// `ipv4` or `ipv6`.
    pub family: &'static str,
    /// From the start of the attempt to the adopted handshake.
    pub elapsed_ms: u64,
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
    /// What kind each candidate is.
    kinds: HashMap<SocketAddr, &'static str>,
    /// Candidates the shape check dropped.
    rejected: usize,
}

/// A failed attempt with the one number the log line adds: datagrams the
/// punching socket dropped for carrying a tag nobody expected.
struct Failed {
    failure: PunchFailure,
    tag_rejected: u64,
}

impl From<PunchFailure> for Failed {
    fn from(failure: PunchFailure) -> Self {
        Self {
            failure,
            tag_rejected: 0,
        }
    }
}

fn ms_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
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
    let Some(first) = plan.rendezvous.first() else {
        let failure = plan.no_rendezvous();
        log::gave_up(&failure.rendezvous, failure.reason.as_str(), 0, 0);
        return Err(failure);
    };
    log::attempt(&first.name);
    match attempt_inner(plan, tuning, deadline, start, first).await {
        Ok(win) => Ok(win),
        Err(Failed {
            failure,
            tag_rejected,
        }) => {
            log::gave_up(
                &failure.rendezvous,
                failure.reason.as_str(),
                ms_since(start),
                tag_rejected,
            );
            Err(failure)
        }
    }
}

async fn attempt_inner(
    plan: &PunchPlan,
    tuning: TransportTuning,
    deadline: Instant,
    start: Instant,
    first: &RendezvousPeer,
) -> Result<PunchWin, Failed> {
    let failed = |peer: &RendezvousPeer, reason| PunchFailure {
        rendezvous: peer.name.clone(),
        reason,
    };

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
    .map_err(|_| Failed::from(failed(first, GiveUpReason::RendezvousUnreachable)))?;
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
    let (signaled, peer) = outcome.map_err(Failed::from)?;
    let mut counts = log::CandidateCounts::default();
    for addr in &signaled.candidates {
        let kind = signaled.kinds.get(addr).copied().unwrap_or(log::KIND_HOST);
        counts.add(kind, addr);
    }
    log::signaled(&peer.name, &counts, signaled.rejected, ms_since(start));

    // The window runs from the answer, and never past the route's deadline.
    let budget = PUNCH_WINDOW.min(deadline.saturating_duration_since(Instant::now()));
    let params = InitiatorParams {
        attempt_id: signaled.attempt,
        expected_peer: plan.target,
        candidates: signaled.candidates.clone(),
        budget,
    };
    match run_initiator(&ep, &params).await {
        Ok(adopted) => {
            guard.disarm();
            let kind = if adopted.peer_reflexive {
                log::KIND_PEER_REFLEXIVE
            } else {
                signaled
                    .kinds
                    .get(&adopted.remote)
                    .copied()
                    .unwrap_or(log::KIND_HOST)
            };
            let family = log::family_of(&adopted.remote);
            let elapsed_ms = ms_since(start);
            log::adopted(
                &peer.name,
                kind,
                family,
                elapsed_ms,
                ep.stats().punch_rejected,
                adopted.losers_closed,
            );
            Ok(PunchWin {
                connection: adopted.connection,
                endpoint: ep.endpoint(),
                info: WinInfo {
                    rendezvous: peer.name.clone(),
                    kind,
                    family,
                    elapsed_ms,
                },
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
            Err(Failed {
                failure: failed(peer, reason),
                tag_rejected: ep.stats().punch_rejected,
            })
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
        let rejected = checked.dropped;
        let mut kinds: HashMap<SocketAddr, &'static str> = HashMap::new();
        for c in &reply.candidates {
            if let Some(addr) = c.socket_addr() {
                let kind = if c.kind == PunchCandidateKind::Reflexive as i32 {
                    log::KIND_REFLEXIVE
                } else {
                    log::KIND_HOST
                };
                kinds.entry(addr).or_insert(kind);
            }
        }

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
                    kinds.insert(derived, log::KIND_REFLEXIVE);
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
            kinds,
            rejected,
        })
    };
    match timeout_at(deadline, work).await {
        Ok(result) => result,
        Err(_) if connected.load(Ordering::Relaxed) => Err(GiveUpReason::Timeout),
        Err(_) => Err(GiveUpReason::RendezvousUnreachable),
    }
}
