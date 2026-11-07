//! End B of hole punching on a [`Server`] (ADR-0054 decisions 6, 10, 11, 12,
//! 14): the `PunchOffer` a rendezvous relays over this host's registration
//! connection, and the `RendezvousQuery` any connection may ask.
//!
//! `PunchOffer` needs a live registration (`ConnCtx::is_reverse_registration`):
//! only the controller this host registered with may ask it to open a window.
//! The order is the usual one: shape, then the `host.punch` decision for the
//! initiator named in the offer ([`check_punch`], which audits), then the
//! rate table and the window cap, and only then a server window, a socket
//! send or any other state.

use qsh_proto::punch::check_candidates;
use qsh_proto::wire::{PunchAnswer, PunchOffer, RendezvousList, response};
use qsh_transport::endpoint::CLOSE_CODE_UNVERIFIED_PEER;

use super::*;
use crate::acl::{PunchOp, check_punch, refuse_unpinned_punch};
use crate::punch::{OfferRefusal, PunchTarget, host_candidate_messages};

fn unsupported(request_id: u64) -> ControlMessage {
    ControlMessage::error(
        request_id,
        wire::Error::new(
            ErrorCode::Unsupported,
            "hole-punching requests are not served by this peer",
            false,
        ),
    )
}

fn denied(request_id: u64, err: crate::ops::OpError) -> ControlMessage {
    ControlMessage::error(
        request_id,
        wire::Error::new(err.code, err.message, err.retryable),
    )
}

impl Server {
    /// Gives this host the hole-punching target service
    /// (`crate::reverse::target` does this for `qsh serve --to`). Without it
    /// every punch message is answered `UNSUPPORTED`. A later call replaces
    /// the service (the host re-opens its socket after a lost registration);
    /// windows already open finish on the old one.
    pub fn set_punch_target(&self, target: Arc<PunchTarget>) {
        *self.punch.lock().unwrap_or_else(|e| e.into_inner()) = Some(target);
    }

    /// The service, if one was set.
    pub fn punch_target(&self) -> Option<Arc<PunchTarget>> {
        self.punch.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// `PunchOffer`: open a window for the initiator the offer names and
    /// answer with this host's candidates. Reached from
    /// [`Server::serve_control`] only (it needs the `Arc` to hand the
    /// connections the window accepts to the normal serve path). Public and
    /// hidden so the deny-seam sweep in `qsh-testkit` can drive the check
    /// without a registration connection.
    #[doc(hidden)]
    pub fn handle_punch_offer(
        self: &Arc<Self>,
        ctx: &ConnCtx,
        request_id: u64,
        offer: &PunchOffer,
    ) -> ControlMessage {
        let Some(target) = self.punch_target().filter(|t| t.enabled()) else {
            return unsupported(request_id);
        };
        if !ctx.is_reverse_registration || !ctx.has_capability(wire::CAP_PUNCH_V1) {
            return unsupported(request_id);
        }
        let invalid = |what: &str| {
            ControlMessage::error(
                request_id,
                wire::Error::new(ErrorCode::InvalidArgument, what, false),
            )
        };
        if offer.validate().is_err() {
            return invalid("malformed punch offer");
        }
        let (Some(attempt_id), Ok(initiator)) = (
            offer.attempt(),
            <[u8; 32]>::try_from(offer.initiator_fingerprint.as_slice()),
        ) else {
            return invalid("malformed punch offer");
        };

        // The initiator is judged as the pin this host's trust store has for
        // its fingerprint, before anything exists.
        match target.pinned_principal(&initiator) {
            Some(principal) => {
                let requester = Requester::new(
                    &principal,
                    AuthPath::Pin,
                    Some(PeerFingerprint::new(initiator)),
                );
                if let Err(err) = check_punch(
                    self.authorizer.as_ref(),
                    self.audit.as_ref(),
                    PunchOp::Offer,
                    &requester,
                ) {
                    return denied(request_id, err);
                }
            }
            None => {
                let err = refuse_unpinned_punch(
                    self.audit.as_ref(),
                    PunchOp::Offer,
                    qsh_transport::Fingerprint::from_bytes(initiator),
                );
                return denied(request_id, err);
            }
        }

        let Ok(checked) = check_candidates(&offer.candidates) else {
            return invalid("too many candidates");
        };
        if checked.accepted.is_empty() {
            return invalid("no usable candidate");
        }

        let server = self.clone();
        let gate = target.clone();
        let opened = target.open_offer(attempt_id, initiator, checked.accepted, move |conn| {
            // Several windows can be open at once and an Initial reaches
            // whichever window's loop accepts it, so the check is "does a
            // window for this peer exist", not "is this my window"
            // (decision 12). Anything else is closed as an unexpected peer.
            let expected = conn
                .peer_fingerprint()
                .is_some_and(|fp| gate.has_window_for(fp.as_bytes()));
            if !expected {
                conn.close(CLOSE_CODE_UNVERIFIED_PEER, b"unexpected peer");
                return;
            }
            tokio::spawn(server.clone().serve_connection(conn));
        });
        match opened {
            Ok(host) => ControlMessage::response(
                request_id,
                response::Body::PunchAnswer(PunchAnswer {
                    candidates: host_candidate_messages(&host),
                }),
            ),
            Err(OfferRefusal::Rate | OfferRefusal::Windows) => ControlMessage::error(
                request_id,
                wire::Error::new(
                    ErrorCode::ResourceExhausted,
                    "too many punch attempts",
                    true,
                ),
            ),
        }
    }

    /// `RendezvousQuery`: the controllers this host is registered with, as
    /// fingerprints. Authorized as `host.punch` for the asking connection
    /// (ADR-0054 decision 6).
    #[doc(hidden)]
    pub fn handle_rendezvous_query(&self, ctx: &ConnCtx, request_id: u64) -> ControlMessage {
        let Some(target) = self.punch_target().filter(|t| t.enabled()) else {
            return unsupported(request_id);
        };
        if !ctx.has_capability(wire::CAP_PUNCH_V1) {
            return unsupported(request_id);
        }
        if let Err(err) = check_punch(
            self.authorizer.as_ref(),
            self.audit.as_ref(),
            PunchOp::Rendezvous,
            &ctx.requester(),
        ) {
            return denied(request_id, err);
        }
        ControlMessage::response(
            request_id,
            response::Body::RendezvousList(RendezvousList {
                fingerprints: target
                    .rendezvous_fingerprints()
                    .into_iter()
                    .map(|fp| fp.to_vec())
                    .collect(),
            }),
        )
    }
}
