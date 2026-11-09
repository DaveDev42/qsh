//! The forward route's dial: a direct dial, and the hole-punching race that
//! joins it (ADR-0054 decisions 4 and 16).
//!
//! Order, `docs/CLI.md` §6.1: a live reverse registration is chosen before
//! this runs (`Ops::resolve_route`). Here a host with an address is dialed
//! directly; when that has not stood after `head_start` (1 s), or failed
//! sooner, a punch starts beside it and the first connection that stands is
//! used. A host with no address punches at once. The whole race lives inside
//! the one dial timeout the command already has (10 s, or `-o
//! ConnectTimeout`), so punching never makes a command wait longer.
//!
//! A recovery re-dial runs the same race again ([`Dial::Redial`], ADR-0054
//! decision 18): the local addresses and the rendezvous are taken afresh, so
//! a changed local address means a new punch. Its time limit is the head
//! start plus the 8 s punch budget in place of the command's dial timeout,
//! and [`redial_deadline`] is what the recovery loop waits for one attempt.
//!
//! A punch that fails is not an error by itself: the command's error is the
//! one the direct dial produced, with `details.punch{rendezvous, reason}`
//! added. The ssh revival that follows (`Ops::revive_target`) sees that same
//! error.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_transport::{
    Connection, DialError, Dialed, Dialer, Endpoint, PunchEndpoint, TransportTuning,
    default_dial_timeout,
};
use tokio::time::{Instant, sleep, sleep_until};

use crate::client::reconnect::REDIAL_DEADLINE;
use crate::ops::exec::map_dial_error;
use crate::ops::{AddressResolver, OpError};
use crate::punch::{PUNCH_BUDGET, PunchFailure, PunchPlan, attempt};

/// What a dial is for, which decides how long the whole route may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dial {
    /// A command's first dial: the command's dial timeout (10 s, or `-o
    /// ConnectTimeout`).
    Command,
    /// A recovery or supervised re-dial.
    Redial,
}

/// The longest one re-dial attempt may take (ADR-0054 decision 18). A host
/// that can be punched to gets the 8 s punch budget, after the head start
/// when a direct dial runs first (at most 9 s, inside a command's 10 s dial
/// timeout); any other host keeps [`REDIAL_DEADLINE`].
pub(crate) fn redial_deadline(plan: Option<&Arc<PunchPlan>>, has_address: bool) -> Duration {
    match plan {
        Some(plan) if plan.has_rendezvous() => {
            let head = if has_address {
                plan.env.head_start
            } else {
                Duration::ZERO
            };
            head.saturating_add(PUNCH_BUDGET).max(REDIAL_DEADLINE)
        }
        _ => REDIAL_DEADLINE,
    }
}

/// A connection of the forward route and the endpoint that carries it.
#[derive(Debug)]
pub(crate) struct Routed {
    /// The verified connection.
    pub connection: Connection,
    /// Kept for the connection's life.
    pub endpoint: Endpoint,
}

impl From<Dialed> for Routed {
    fn from(d: Dialed) -> Self {
        Self {
            connection: d.connection,
            endpoint: d.endpoint,
        }
    }
}

/// Why the direct route gave nothing.
#[derive(Debug)]
pub(crate) enum DirectFail {
    /// The address did not resolve.
    Resolve(OpError),
    /// Every resolved address was dialed and failed; `attempted` of them.
    Dial { err: DialError, attempted: usize },
    /// The host has no address; only a punch could have reached it.
    NoAddress,
}

/// A failed route: the direct failure, plus the punch's when one ran.
#[derive(Debug)]
pub(crate) struct RouteError {
    pub direct: DirectFail,
    pub punch: Option<PunchFailure>,
}

impl RouteError {
    fn plain(direct: DirectFail) -> Self {
        Self {
            direct,
            punch: None,
        }
    }

    /// The command's error: what the direct dial said, naming the punch
    /// when it was tried (`details.punch`, and a clause on the human line).
    pub(crate) fn into_op(self, address: &str) -> OpError {
        let op = match self.direct {
            DirectFail::Resolve(op) => op,
            DirectFail::Dial { err, attempted } => map_dial_error(err, address, attempted),
            DirectFail::NoAddress => OpError::new(
                ErrorCode::ConnectionFailed,
                "no address is recorded for this host and it could not be reached by hole punching",
            ),
        };
        match &self.punch {
            Some(punch) => punch.attach_to(op),
            None => op,
        }
    }
}

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The direct dial: resolve, then each address in turn.
async fn direct_dial(
    dialer: &Dialer,
    sim: Option<&Arc<PunchPlan>>,
    tuning: TransportTuning,
    address: &str,
    server_name: &str,
    resolver: &dyn AddressResolver,
) -> Result<Routed, DirectFail> {
    let addrs = crate::ops::resolve_all_with(resolver, address)
        .await
        .map_err(DirectFail::Resolve)?;
    // A simulated network gives the direct dial the same kind of virtual
    // socket the punch uses; production dials from its own OS socket.
    let simulated = match sim.and_then(|plan| plan.env.socket.as_ref().map(|make| (plan, make))) {
        Some((plan, make)) => {
            let ep = PunchEndpoint::new(
                make(),
                plan.identity.clone(),
                plan.evaluator.clone(),
                tuning,
            )
            .map_err(|e| DirectFail::Dial {
                err: DialError::Setup(e),
                attempted: 0,
            })?;
            ep.set_dial_timeout(default_dial_timeout());
            Some(ep)
        }
        None => None,
    };
    let dialed = crate::ops::dial_first_reachable(&addrs, |addr: SocketAddr| {
        let simulated = simulated.clone();
        async move {
            match simulated {
                Some(ep) => ep.dial_trusted(addr, server_name).await,
                None => dialer.dial(addr, server_name).await,
            }
        }
    })
    .await
    .map_err(|(err, attempted)| DirectFail::Dial { err, attempted })?;
    Ok(dialed.into())
}

fn punch_future(
    plan: &Arc<PunchPlan>,
    tuning: TransportTuning,
    deadline: Instant,
) -> BoxFut<'_, Result<crate::punch::PunchWin, PunchFailure>> {
    Box::pin(attempt(plan, tuning, deadline))
}

enum Event {
    Direct(Result<Routed, DirectFail>),
    Punch(Result<crate::punch::PunchWin, PunchFailure>),
    HeadStart,
    Deadline,
}

/// Resolves a boxed future in an `Option`, or never.
async fn within<T>(slot: &mut Option<BoxFut<'_, T>>) -> T {
    match slot {
        Some(fut) => fut.await,
        None => std::future::pending().await,
    }
}

/// Dials a host the forward way. With no `plan` this is the direct dial
/// alone, exactly as before the punch existed.
pub(crate) async fn dial_routed(
    dialer: &Dialer,
    address: &str,
    server_name: &str,
    plan: Option<&Arc<PunchPlan>>,
    tuning: TransportTuning,
    resolver: &dyn AddressResolver,
    kind: Dial,
) -> Result<Routed, RouteError> {
    let has_address = !address.is_empty();
    let Some(plan) = plan else {
        return direct_dial(dialer, None, tuning, address, server_name, resolver)
            .await
            .map_err(RouteError::plain);
    };

    // A rendezvous was asked for but none is usable: the direct dial alone,
    // with the reason on its failure.
    if !plan.has_rendezvous() {
        return direct_dial(dialer, Some(plan), tuning, address, server_name, resolver)
            .await
            .map_err(|direct| RouteError {
                direct,
                punch: Some(plan.no_rendezvous()),
            });
    }

    let started = Instant::now();
    let mut timeout = match kind {
        Dial::Command => default_dial_timeout(),
        Dial::Redial => redial_deadline(Some(plan), has_address),
    };
    let deadline = started + timeout;
    let head = sleep(plan.env.head_start);
    tokio::pin!(head);
    let overall = sleep_until(deadline);
    tokio::pin!(overall);

    let mut direct: Option<BoxFut<'_, Result<Routed, DirectFail>>> = has_address.then(|| {
        Box::pin(direct_dial(
            dialer,
            Some(plan),
            tuning,
            address,
            server_name,
            resolver,
        )) as BoxFut<'_, _>
    });
    let mut punch: Option<BoxFut<'_, Result<crate::punch::PunchWin, PunchFailure>>> = None;
    let mut direct_failed: Option<DirectFail> = None;
    let mut punch_failed: Option<PunchFailure> = None;
    let mut punch_started = false;
    if direct.is_none() {
        punch = Some(punch_future(plan, tuning, deadline));
        punch_started = true;
    }

    let expired = loop {
        if direct.is_none() && punch.is_none() {
            break false;
        }
        let event = tokio::select! {
            biased;
            r = within(&mut direct) => Event::Direct(r),
            r = within(&mut punch) => Event::Punch(r),
            () = &mut head, if !punch_started && direct.is_some() => Event::HeadStart,
            () = &mut overall => Event::Deadline,
        };
        match event {
            Event::Direct(Ok(routed)) => return Ok(routed),
            Event::Direct(Err(fail)) => {
                direct = None;
                direct_failed = Some(fail);
                if !punch_started {
                    punch = Some(punch_future(plan, tuning, deadline));
                    punch_started = true;
                }
            }
            Event::Punch(Ok(win)) => {
                return Ok(Routed {
                    connection: win.connection,
                    endpoint: win.endpoint,
                });
            }
            Event::Punch(Err(fail)) => {
                punch = None;
                punch_failed = Some(fail);
                // A re-dial whose punch is over has no use for the rest of
                // the punch budget: the direct dial keeps the time a
                // direct-only re-dial always had, and the recovery loop's
                // backoff and attempt count take over from there.
                if kind == Dial::Redial && direct.is_some() {
                    timeout = REDIAL_DEADLINE;
                    overall
                        .as_mut()
                        .reset((started + REDIAL_DEADLINE).max(Instant::now()));
                }
            }
            Event::HeadStart => {
                punch = Some(punch_future(plan, tuning, deadline));
                punch_started = true;
            }
            Event::Deadline => break true,
        }
    };

    // Whatever was still running at the deadline is abandoned (dropping the
    // futures abandons the handshakes and closes the punching endpoint).
    let direct_error = match direct_failed {
        Some(fail) => fail,
        None if has_address => DirectFail::Dial {
            err: DialError::Timeout(timeout),
            attempted: 1,
        },
        None => DirectFail::NoAddress,
    };
    let punch_error = match punch_failed {
        Some(fail) => Some(fail),
        None if punch_started && expired => Some(PunchFailure {
            rendezvous: plan
                .rendezvous
                .first()
                .map_or_else(String::new, |r| r.name.clone()),
            reason: crate::punch::GiveUpReason::Timeout,
        }),
        None => None,
    };
    drop(direct);
    drop(punch);
    Err(RouteError {
        direct: direct_error,
        punch: punch_error,
    })
}
