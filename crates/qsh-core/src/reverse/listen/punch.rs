//! The rendezvous role of [`Listen`] (ADR-0054 decisions 6, 10, 11,
//! `docs/design/protocol.md` §19): a peer that registers nothing but speaks
//! `punch.v1` is a **punching connection**. It sends one `PunchRequest` (and
//! `Ping`s); this relays it as a `PunchOffer` over the target's registration
//! connection and returns B's answer, with the reflexive addresses R saw, as
//! a `PunchReply`.
//!
//! Order of events for a request: on/off switch, `host.punch` for the
//! requester ([`check_punch`], which audits), message shape, rate table,
//! only then the registration lookup. Nothing is created before the
//! authorization, and a refusal says nothing about whether a registration
//! exists.
//!
//! R never alters what it relays and holds no address in a log line or audit
//! record: the `qsh::punch` events carry counts only.

use std::net::SocketAddr;

use qsh_proto::punch::{AttemptId, check_candidates};
use qsh_proto::wire::{
    PunchCandidate, PunchCandidateKind, PunchOffer, PunchRefusal, PunchReply, PunchRequest,
    control_message, response,
};

use super::*;
use crate::acl::{PunchOp, Requester, check_punch};
use crate::punch::{LimitHit, PUNCH_ANSWER_TIMEOUT, RENDEZVOUS_IDLE, is_public};
use qsh_transport::PeerAddr;

/// Unmaps an IPv4-mapped peer address, the form a dual-stack listener sees.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The reflexive address a connection's peer presents: its canonical socket
/// address. A peer without one (a relay path, ADR-0061; never produced yet)
/// yields `0.0.0.0:0`, which `valid_punch_candidate` rejects, so such a peer
/// contributes no reflexive candidate, the same as a non-public address.
fn reflexive(peer: &PeerAddr) -> SocketAddr {
    canonical(
        peer.socket_addr()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
    )
}

fn refusal_reply(request_id: u64, refusal: PunchRefusal) -> wire::ControlMessage {
    wire::ControlMessage::response(
        request_id,
        response::Body::PunchReply(PunchReply {
            refusal: refusal as i32,
            ..PunchReply::default()
        }),
    )
}

fn error_reply(
    request_id: u64,
    code: ErrorCode,
    message: &str,
    retryable: bool,
) -> wire::ControlMessage {
    wire::ControlMessage::error(request_id, wire::Error::new(code, message, retryable))
}

/// What B's answer to an offer means for A.
enum Relayed {
    Answer(qsh_proto::wire::PunchAnswer),
    Refused(PunchRefusal),
}

impl Listen {
    /// `decide_registration`'s branch for a peer without `Hello.reverse`:
    /// `Some` when it is a punching initiator (the verdict is the reply to
    /// its `Hello`), `None` when it is not and the old refusal applies. The
    /// connection-count quota is applied here too, after the cheap checks.
    pub(super) fn admit_punch_peer(
        &self,
        peer_hello: &Hello,
        punch_cell: &Mutex<Option<OwnedSemaphorePermit>>,
        refused: Option<crate::quota::QuotaKind>,
    ) -> Option<Result<Hello, wire::Error>> {
        if !self.rendezvous.enabled()
            || !peer_hello
                .capabilities
                .iter()
                .any(|c| c == wire::CAP_PUNCH_V1)
        {
            return None;
        }
        if let Some(kind) = refused {
            return Some(Err(wire::Error::new(
                ErrorCode::ResourceExhausted,
                kind.wire_message(),
                true,
            )));
        }
        let Some(permit) = self.rendezvous.try_client() else {
            return Some(Err(wire::Error::new(
                ErrorCode::ResourceExhausted,
                "too many hole-punching connections",
                true,
            )));
        };
        *punch_cell.lock().unwrap_or_else(|e| e.into_inner()) = Some(permit);
        Some(Ok(self.local_hello()))
    }

    /// Serves one punching connection until the answer is out and the peer
    /// has left, or [`RENDEZVOUS_IDLE`] passes without a request / after the
    /// answer. `_permit` keeps the connection counted against
    /// `RENDEZVOUS_MAX_CLIENTS` for as long as it lives.
    pub(super) async fn serve_punch_connection(
        self: Arc<Self>,
        conn: Connection,
        mut ctl: FramedStream,
        _permit: OwnedSemaphorePermit,
    ) {
        let mut deadline = tokio::time::Instant::now() + RENDEZVOUS_IDLE;
        let mut answered = false;
        loop {
            let msg =
                match tokio::time::timeout_at(deadline, ctl.recv.recv::<wire::ControlMessage>())
                    .await
                {
                    Ok(Ok(Some(msg))) => msg,
                    _ => break,
                };
            let id = msg.request_id;
            match msg.body {
                Some(control_message::Body::Ping(_)) => {
                    let pong =
                        wire::ControlMessage::new(id, control_message::Body::Pong(wire::Pong {}));
                    if ctl.send.send(&pong).await.is_err() {
                        break;
                    }
                }
                Some(control_message::Body::PunchRequest(req)) if !answered => {
                    answered = true;
                    let (reply, terminal) = self.relay_punch(&conn, id, req).await;
                    if ctl.send.send(&reply).await.is_err() {
                        break;
                    }
                    deadline = tokio::time::Instant::now() + RENDEZVOUS_IDLE;
                    if terminal {
                        // Let the refusal reach the peer before the close.
                        if ctl.send.finish().is_ok() {
                            let _ = tokio::time::timeout(
                                crate::handshake::REJECTION_DRAIN_TIMEOUT,
                                ctl.send.stopped(),
                            )
                            .await;
                        }
                        break;
                    }
                }
                _ => {
                    let refusal = error_reply(
                        id,
                        ErrorCode::Unsupported,
                        "a hole-punching connection answers one PunchRequest and Ping",
                        false,
                    );
                    if ctl.send.send(&refusal).await.is_err() {
                        break;
                    }
                }
            }
        }
        conn.close(0, b"punch done");
    }

    /// The live registration whose controller-side certificate is
    /// `fingerprint` (`None` when there is none or it is not live now).
    fn registration_for(&self, fingerprint: &[u8]) -> Option<(Connection, Arc<ControlHub>)> {
        self.hubs_snapshot().into_iter().find_map(|(name, _)| {
            let (conn, hub) = self.connection_for(&name)?;
            let fp = conn.peer_fingerprint()?;
            (fp.as_bytes().as_slice() == fingerprint).then_some((conn, hub))
        })
    }

    /// Forwards `offer` over `hub`'s registration connection and waits for
    /// B's answer for [`PUNCH_ANSWER_TIMEOUT`].
    async fn relay_offer(&self, hub: &ControlHub, offer: PunchOffer) -> Relayed {
        let (conduit, mut inbox) = hub.register_conduit();
        let sent = hub.send_request(conduit, 1, control_message::Body::PunchOffer(offer));
        let outcome = match sent {
            Err(HubSendError::HostDead) => Relayed::Refused(PunchRefusal::TargetNotRegistered),
            Err(_) => Relayed::Refused(PunchRefusal::TargetBusy),
            Ok(()) => {
                let wait = async {
                    loop {
                        match inbox.recv().await {
                            Some(ConduitInbound::Response { body, .. }) => {
                                return match body.body {
                                    Some(response::Body::PunchAnswer(answer)) => {
                                        Relayed::Answer(answer)
                                    }
                                    Some(response::Body::Error(err)) => Relayed::Refused(match err
                                        .error_code()
                                    {
                                        ErrorCode::Unsupported => PunchRefusal::TargetUnsupported,
                                        ErrorCode::ResourceExhausted => PunchRefusal::TargetBusy,
                                        _ => PunchRefusal::TargetDenied,
                                    }),
                                    _ => Relayed::Refused(PunchRefusal::TargetUnsupported),
                                };
                            }
                            Some(ConduitInbound::Event(_)) => {}
                            Some(ConduitInbound::HostDead) | None => {
                                return Relayed::Refused(PunchRefusal::TargetNotRegistered);
                            }
                        }
                    }
                };
                tokio::time::timeout(PUNCH_ANSWER_TIMEOUT, wait)
                    .await
                    .unwrap_or(Relayed::Refused(PunchRefusal::TargetTimeout))
            }
        };
        hub.unregister_conduit(conduit);
        outcome
    }

    /// One `PunchRequest`. Returns the reply and whether the connection
    /// should close after it (the request itself was wrong or refused).
    ///
    /// `pub(crate)`: the combined endpoint's `Server` runs it for a forward
    /// connection that turned out to be a punching one (ADR-0059 decision
    /// 5), off its control loop because it waits up to
    /// [`PUNCH_ANSWER_TIMEOUT`] for the target.
    pub(crate) async fn relay_punch(
        &self,
        conn: &Connection,
        request_id: u64,
        req: PunchRequest,
    ) -> (wire::ControlMessage, bool) {
        // 1. Authorization, before any state exists. A peer whose
        //    certificate fingerprint cannot be read gets the same refusal.
        let Some(initiator) = conn.peer_fingerprint() else {
            return (
                error_reply(
                    request_id,
                    ErrorCode::PermissionDenied,
                    crate::acl::PERMISSION_DENIED_MESSAGE,
                    false,
                ),
                true,
            );
        };
        let requester = Requester::new(
            conn.principal(),
            conn.auth_path(),
            Some(crate::broker::PeerFingerprint::new(*initiator.as_bytes())),
        );
        if let Err(denied) = check_punch(
            self.authorizer.as_ref(),
            self.audit.as_ref(),
            PunchOp::Request,
            &requester,
        ) {
            return (
                error_reply(request_id, denied.code, &denied.message, denied.retryable),
                true,
            );
        }

        // 2. Shape. Nothing is created yet, but a malformed request is not
        //    answered further.
        let invalid = |what: &str| {
            (
                error_reply(request_id, ErrorCode::InvalidArgument, what, false),
                true,
            )
        };
        if req.validate().is_err() {
            return invalid("malformed punch request");
        }
        let Some(attempt_id) = req.attempt() else {
            return invalid("malformed punch request");
        };
        let Ok(checked) = check_candidates(&req.candidates) else {
            return invalid("too many candidates");
        };

        // 3. Rate: one attempt in flight and six a minute per initiator.
        let slot = match self.rendezvous.begin_attempt(*initiator.as_bytes()) {
            Ok(slot) => slot,
            Err(hit) => {
                let message = match hit {
                    LimitHit::InFlight => "a punch attempt is already in flight",
                    LimitHit::Rate => "too many punch attempts",
                };
                crate::punch::log::emit(
                    "relayed",
                    serde_json::json!({ "outcome": "rate_limited" }),
                );
                return (
                    error_reply(request_id, ErrorCode::ResourceExhausted, message, true),
                    false,
                );
            }
        };

        // 4. The registration, then the offer.
        let reply = self
            .relay_to_target(
                conn,
                request_id,
                attempt_id,
                &req,
                checked.accepted,
                checked.dropped,
            )
            .await;
        drop(slot);
        (reply, false)
    }

    async fn relay_to_target(
        &self,
        conn: &Connection,
        request_id: u64,
        attempt_id: AttemptId,
        req: &PunchRequest,
        mut initiator_candidates: Vec<SocketAddr>,
        dropped: usize,
    ) -> wire::ControlMessage {
        let refuse = |refusal: PunchRefusal, outcome: &str| {
            crate::punch::log::emit("relayed", serde_json::json!({ "outcome": outcome }));
            refusal_reply(request_id, refusal)
        };
        let Some((target_conn, hub)) = self.registration_for(&req.target_fingerprint) else {
            return refuse(PunchRefusal::TargetNotRegistered, "target_not_registered");
        };
        let (_, _, _, capabilities) = hub.ack_fields();
        if !capabilities.iter().any(|c| c == wire::CAP_PUNCH_V1) {
            return refuse(PunchRefusal::TargetUnsupported, "target_unsupported");
        }

        // A's reflexive is the address this connection arrived from. The
        // offer carries at most eight candidates, so the host list yields a
        // slot to it.
        let initiator_reflexive = reflexive(&conn.remote_address());
        let reflexive_ok = qsh_proto::punch::valid_punch_candidate(
            &ip_bytes(initiator_reflexive),
            u32::from(initiator_reflexive.port()),
        )
        .is_some();
        if reflexive_ok {
            initiator_candidates.retain(|c| *c != initiator_reflexive);
            initiator_candidates.truncate(qsh_proto::punch::MAX_PUNCH_CANDIDATES - 1);
        }
        let mut offered: Vec<PunchCandidate> = initiator_candidates
            .iter()
            .map(|a| PunchCandidate::from_addr(*a, PunchCandidateKind::Host))
            .collect();
        if reflexive_ok {
            offered.push(PunchCandidate::from_addr(
                initiator_reflexive,
                PunchCandidateKind::Reflexive,
            ));
        }
        let offer = PunchOffer {
            attempt_id: attempt_id.to_vec(),
            initiator_fingerprint: conn
                .peer_fingerprint()
                .map(|f| f.as_bytes().to_vec())
                .unwrap_or_default(),
            candidates: offered,
        };

        let answer = match self.relay_offer(&hub, offer).await {
            Relayed::Answer(answer) => answer,
            Relayed::Refused(refusal) => {
                return refuse(refusal, refusal_name(refusal));
            }
        };
        let Ok(answered) = answer
            .validate()
            .map(|()| check_candidates(&answer.candidates))
        else {
            return refuse(PunchRefusal::TargetUnsupported, "bad_answer");
        };
        let Ok(mut answered) = answered else {
            return refuse(PunchRefusal::TargetUnsupported, "bad_answer");
        };

        // B's reflexive is the address its registration connection arrived
        // from; when that is not an address a stranger can send to, R and B
        // share a NAT and A derives a candidate (decision 8).
        let target_reflexive = reflexive(&target_conn.remote_address());
        let target_reflexive_ok = qsh_proto::punch::valid_punch_candidate(
            &ip_bytes(target_reflexive),
            u32::from(target_reflexive.port()),
        )
        .is_some();
        if target_reflexive_ok {
            answered.accepted.retain(|c| *c != target_reflexive);
            answered
                .accepted
                .truncate(qsh_proto::punch::MAX_PUNCH_CANDIDATES - 1);
        }
        let mut candidates: Vec<PunchCandidate> = answered
            .accepted
            .iter()
            .map(|a| PunchCandidate::from_addr(*a, PunchCandidateKind::Host))
            .collect();
        if target_reflexive_ok {
            candidates.push(PunchCandidate::from_addr(
                target_reflexive,
                PunchCandidateKind::Reflexive,
            ));
        }
        crate::punch::log::emit(
            "relayed",
            serde_json::json!({
                "outcome": "answered",
                "offered_candidates": initiator_candidates.len() + usize::from(reflexive_ok),
                "answered_candidates": candidates.len(),
                "dropped_candidates": dropped + answered.dropped,
            }),
        );
        wire::ControlMessage::response(
            request_id,
            response::Body::PunchReply(PunchReply {
                candidates,
                initiator_reflexive: reflexive_ok.then(|| {
                    PunchCandidate::from_addr(initiator_reflexive, PunchCandidateKind::Reflexive)
                }),
                target_reflexive_private: target_reflexive_ok && !is_public(target_reflexive.ip()),
                refusal: PunchRefusal::None as i32,
            }),
        )
    }
}

fn ip_bytes(addr: SocketAddr) -> Vec<u8> {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn refusal_name(refusal: PunchRefusal) -> &'static str {
    match refusal {
        PunchRefusal::None => "none",
        PunchRefusal::TargetNotRegistered => "target_not_registered",
        PunchRefusal::TargetUnsupported => "target_unsupported",
        PunchRefusal::TargetDenied => "target_denied",
        PunchRefusal::TargetBusy => "target_busy",
        PunchRefusal::TargetTimeout => "target_timeout",
    }
}
