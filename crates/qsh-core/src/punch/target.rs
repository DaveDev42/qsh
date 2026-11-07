//! End B of a punch: the side with a server window (ADR-0054 decisions 7,
//! 14, 15).

use std::net::SocketAddr;
use std::time::Duration;

use qsh_proto::punch::{AttemptId, PunchDirection, punch_tag};
use qsh_transport::{Connection, PunchEndpoint, PunchWindow};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};

use super::schedule::Schedule;
use super::{MAX_HANDSHAKES_PER_OFFER, MAX_PUNCH_CANDIDATES};

/// What B needs to serve one attempt.
#[derive(Clone, Debug)]
pub struct TargetParams {
    /// Names the attempt; both ends derive their tags from it.
    pub attempt_id: AttemptId,
    /// A's candidate addresses (at most [`MAX_PUNCH_CANDIDATES`] are used).
    pub candidates: Vec<SocketAddr>,
    /// How long the server window stays open from t=0.
    pub window: Duration,
}

/// What happened in a window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetReport {
    /// `false` when no window could be opened (too many open already); the
    /// rest is then zero.
    pub window_opened: bool,
    /// Punch datagrams sent.
    pub punches_sent: usize,
    /// A's punch datagrams that reached this end.
    pub punches_heard: usize,
    /// Initials answered with Retry (address not yet validated).
    pub retried: usize,
    /// Validated attempts turned into handshakes.
    pub handshakes: usize,
    /// Attempts refused because [`MAX_HANDSHAKES_PER_OFFER`] was reached.
    pub refused: usize,
    /// Handshakes that ended with a peer the trust check rejected, or failed.
    pub failed: usize,
    /// Verified connections handed to the caller.
    pub connections: usize,
}

/// Runs end B: t=0 is the call. Opens a server window on `ep`, sends the
/// schedule's punch datagrams to A's candidates, answers unvalidated Initials
/// with Retry, and passes every connection that completes its handshake and
/// the pin check to `on_connection` (at most [`MAX_HANDSHAKES_PER_OFFER`]
/// handshakes). Returns when the window closes, taking the server
/// configuration down with it; connections already handed over stay up.
pub async fn run_target<F>(
    ep: &PunchEndpoint,
    params: &TargetParams,
    on_connection: F,
) -> TargetReport
where
    F: FnMut(Connection),
{
    let Some(window) = ep.open_window() else {
        return TargetReport::default();
    };
    run_target_in(ep, window, params, on_connection).await
}

/// [`run_target`] on a window the caller already opened. The target service
/// opens it first so a full endpoint (too many windows) can be refused with
/// `TARGET_BUSY` before the answer goes out; the window closes when this
/// returns.
pub async fn run_target_in<F>(
    ep: &PunchEndpoint,
    window: PunchWindow,
    params: &TargetParams,
    mut on_connection: F,
) -> TargetReport
where
    F: FnMut(Connection),
{
    let _window = window;
    let mut report = TargetReport {
        window_opened: true,
        ..TargetReport::default()
    };

    let mut candidates = params.candidates.clone();
    candidates.dedup();
    candidates.truncate(MAX_PUNCH_CANDIDATES);
    let start = Instant::now();
    let end = start + params.window;
    let send_tag = punch_tag(&params.attempt_id, PunchDirection::BToA);
    let mut inbox = ep.expect(punch_tag(&params.attempt_id, PunchDirection::AToB));
    let mut schedule = Schedule::new(candidates.len());
    let mut handshakes: JoinSet<Option<Connection>> = JoinSet::new();

    loop {
        for idx in schedule.due(start.elapsed()) {
            if ep.send_punch(candidates[idx], &send_tag).await.is_ok() {
                report.punches_sent += 1;
            }
        }
        let wake = schedule.next_at().map_or(end, |at| (start + at).min(end));

        tokio::select! {
            biased;
            incoming = ep.accept() => {
                let Some(incoming) = incoming else { break };
                if !incoming.remote_address_validated() {
                    match incoming.retry() {
                        Ok(()) => report.retried += 1,
                        Err(unretryable) => unretryable.ignore(),
                    }
                } else if report.handshakes >= MAX_HANDSHAKES_PER_OFFER {
                    report.refused += 1;
                    incoming.refuse();
                } else {
                    report.handshakes += 1;
                    handshakes.spawn(async move { incoming.accept().await.ok() });
                }
            }
            joined = handshakes.join_next(), if !handshakes.is_empty() => {
                match joined {
                    Some(Ok(Some(connection))) => {
                        report.connections += 1;
                        on_connection(connection);
                    }
                    Some(_) => report.failed += 1,
                    None => {}
                }
            }
            arrival = inbox.recv() => {
                if arrival.is_some() {
                    report.punches_heard += 1;
                }
            }
            () = sleep_until(wake) => {
                if Instant::now() >= end {
                    break;
                }
            }
        }
    }
    handshakes.abort_all();
    report
}
