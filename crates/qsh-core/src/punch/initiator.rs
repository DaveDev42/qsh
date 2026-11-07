//! End A of a punch: the side that dials (ADR-0054 decisions 8, 14, 15).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use qsh_proto::punch::{AttemptId, PunchDirection, punch_tag};
use qsh_transport::{
    CLOSE_CODE_NOT_ADOPTED, Connection, DialError, Fingerprint, NOT_ADOPTED_REASON, PunchEndpoint,
};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};

use super::schedule::Schedule;
use super::{MAX_PEER_REFLEXIVE, MAX_PUNCH_CANDIDATES, PUNCH_INITIAL_RTT, PUNCH_SERVER_NAME};

/// What A needs to run one attempt.
#[derive(Clone, Debug)]
pub struct InitiatorParams {
    /// Names the attempt; both ends derive their tags from it.
    pub attempt_id: AttemptId,
    /// The certificate fingerprint the peer must present.
    pub expected_peer: Fingerprint,
    /// B's candidate addresses (at most [`MAX_PUNCH_CANDIDATES`] are used).
    pub candidates: Vec<SocketAddr>,
    /// How long to try, from t=0, before giving up.
    pub budget: Duration,
}

/// A connection that won.
#[derive(Debug)]
pub struct Adopted {
    /// The verified connection.
    pub connection: Connection,
    /// The address that answered.
    pub remote: SocketAddr,
    /// Whether the address was learned from B's punch datagram rather than
    /// handed in.
    pub peer_reflexive: bool,
    /// Time from t=0 to the adopted handshake.
    pub elapsed: Duration,
    /// Handshakes that completed and were closed with `0x1006`.
    pub losers_closed: usize,
}

/// Why A stopped without a connection.
#[derive(Debug)]
pub enum GiveUp {
    /// No candidate to try.
    NoCandidate,
    /// The budget ran out. `failed_dials` handshakes had ended in an error
    /// (not merely stayed unanswered).
    Timeout {
        /// Dials that returned an error before the budget ran out.
        failed_dials: Vec<(SocketAddr, DialError)>,
    },
}

type DialResult = (SocketAddr, Result<Connection, DialError>);

fn spawn_dial(
    set: &mut JoinSet<DialResult>,
    ep: &PunchEndpoint,
    addr: SocketAddr,
    expected: Fingerprint,
) {
    let ep = ep.clone();
    set.spawn(async move {
        let r = ep
            .dial(addr, PUNCH_SERVER_NAME, PUNCH_INITIAL_RTT, &expected)
            .await;
        (addr, r)
    });
}

/// Runs end A: t=0 is the call. Sends the schedule's punch datagrams, dials
/// each candidate at once, dials any address B's punches reveal (at most
/// [`MAX_PEER_REFLEXIVE`]), and returns the first handshake that passes the
/// pin check. Handshakes still running are abandoned and ones already
/// complete are closed with `0x1006`. The endpoint is left open for the
/// caller (it carries the adopted connection).
pub async fn run_initiator(
    ep: &PunchEndpoint,
    params: &InitiatorParams,
) -> Result<Adopted, GiveUp> {
    let mut candidates = params.candidates.clone();
    candidates.dedup();
    let mut seen = HashSet::new();
    candidates.retain(|c| seen.insert(*c));
    candidates.truncate(MAX_PUNCH_CANDIDATES);
    if candidates.is_empty() {
        return Err(GiveUp::NoCandidate);
    }

    let start = Instant::now();
    let deadline = start + params.budget;
    let send_tag = punch_tag(&params.attempt_id, PunchDirection::AToB);
    let mut inbox = ep.expect(punch_tag(&params.attempt_id, PunchDirection::BToA));
    let mut schedule = Schedule::new(candidates.len());
    let mut dials: JoinSet<DialResult> = JoinSet::new();
    let mut learned: Vec<SocketAddr> = Vec::new();
    let mut failed = Vec::new();

    for c in &candidates {
        spawn_dial(&mut dials, ep, *c, params.expected_peer);
    }

    loop {
        for idx in schedule.due(start.elapsed()) {
            // A send that fails is a lost packet; the schedule repeats.
            let _ = ep.send_punch(candidates[idx], &send_tag).await;
        }
        let wake = schedule
            .next_at()
            .map_or(deadline, |at| (start + at).min(deadline));

        tokio::select! {
            biased;
            joined = dials.join_next(), if !dials.is_empty() => {
                let Some(Ok((addr, result))) = joined else { continue };
                match result {
                    Ok(connection) => {
                        // Handshakes that finished in the same instant are
                        // ready to be joined after the dial tasks have had a
                        // turn; those are connections that stand and lose.
                        // The rest are abandoned half-way.
                        for _ in 0..2 {
                            tokio::task::yield_now().await;
                        }
                        let mut losers_closed = 0;
                        while let Some(late) = dials.try_join_next() {
                            if let Ok((_, Ok(loser))) = late {
                                loser.close(CLOSE_CODE_NOT_ADOPTED, NOT_ADOPTED_REASON);
                                losers_closed += 1;
                            }
                        }
                        dials.abort_all();
                        while let Some(late) = dials.join_next().await {
                            if let Ok((_, Ok(loser))) = late {
                                loser.close(CLOSE_CODE_NOT_ADOPTED, NOT_ADOPTED_REASON);
                                losers_closed += 1;
                            }
                        }
                        return Ok(Adopted {
                            connection,
                            remote: addr,
                            peer_reflexive: learned.contains(&addr),
                            elapsed: start.elapsed(),
                            losers_closed,
                        });
                    }
                    Err(err) => failed.push((addr, err)),
                }
            }
            arrival = inbox.recv() => {
                let Some(arrival) = arrival else { continue };
                if !candidates.contains(&arrival.from)
                    && !learned.contains(&arrival.from)
                    && learned.len() < MAX_PEER_REFLEXIVE
                {
                    learned.push(arrival.from);
                    spawn_dial(&mut dials, ep, arrival.from, params.expected_peer);
                }
            }
            () = sleep_until(wake) => {
                if Instant::now() >= deadline {
                    dials.abort_all();
                    while dials.join_next().await.is_some() {}
                    return Err(GiveUp::Timeout { failed_dials: failed });
                }
            }
        }
    }
}
