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
//! The iroh relay route (ADR-0061, `docs/CLI.md` §6.1) is the last route and
//! only a pin with `routes = ["iroh"]` and a recorded `key` has it. A pin
//! with no address and no usable rendezvous dials iroh at once. Otherwise
//! iroh starts beside the direct dial and the punch when none of them has
//! stood after `[iroh].head_start_ms` (1 s), or when all of them failed
//! sooner. The first connection that stands wins; the rest are dropped,
//! which closes them. Everything stays inside the one dial timeout.
//!
//! A punch that fails is not an error by itself: the command's error is the
//! one the direct dial produced, with `details.punch{rendezvous, reason}`
//! added. The ssh revival that follows (`Ops::revive_target`) sees that same
//! error.

// `RouteError` carries up to three route failures (direct, punch, iroh) and is
// only built when a dial has already failed, so its size is not on a hot path.
#![allow(clippy::result_large_err)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_transport::{
    Connection, DialError, Dialed, Dialer, Endpoint, IrohEndpoint, PeerBinding, PunchEndpoint,
    TransportTuning, default_dial_timeout,
};
use tokio::time::{Instant, sleep, sleep_until};

use crate::client::reconnect::REDIAL_DEADLINE;
use crate::iroh_settings::IrohPlan;
use crate::jump::{JumpFailure, JumpPlan, Stage};
use crate::ops::exec::map_dial_error;
use crate::ops::{AddressResolver, OpError};
use crate::punch::{PUNCH_BUDGET, PunchFailure, PunchPlan, attempt};
use crate::route_memory::{RouteMemory, Stance};
use crate::trust::key_fill::PinKeyFill;

/// What a dial is for, which decides how long the whole route may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dial {
    /// A command's first dial: the command's dial timeout (10 s, or `-o
    /// ConnectTimeout`).
    Command,
    /// A recovery or supervised re-dial.
    Redial,
}

/// The time the iroh route gets once it starts, in a re-dial: the relay
/// connection takes about half a second, and a slow network a few more.
const IROH_REDIAL_BUDGET: Duration = Duration::from_secs(8);

/// The longest one re-dial attempt may take (ADR-0054 decision 18). A host
/// that can be punched to gets the 8 s punch budget, after the head start
/// when a direct dial runs first (at most 9 s, inside a command's 10 s dial
/// timeout); any other host keeps [`REDIAL_DEADLINE`]. A host with an iroh
/// route also gets [`IROH_REDIAL_BUDGET`] after the iroh head start (none
/// when iroh is the only route).
pub(crate) fn redial_deadline(
    plan: Option<&Arc<PunchPlan>>,
    has_address: bool,
    iroh: Option<&Arc<IrohPlan>>,
) -> Duration {
    let rendezvous = plan.is_some_and(|p| p.has_rendezvous());
    let base = match plan {
        Some(plan) if rendezvous => {
            let head = if has_address {
                plan.env.head_start
            } else {
                Duration::ZERO
            };
            head.saturating_add(PUNCH_BUDGET).max(REDIAL_DEADLINE)
        }
        _ => REDIAL_DEADLINE,
    };
    match iroh {
        Some(iroh) => {
            let head = if has_address || rendezvous {
                iroh.head_start()
            } else {
                Duration::ZERO
            };
            base.max(head.saturating_add(IROH_REDIAL_BUDGET))
        }
        None => base,
    }
}

/// A connection of the forward route and the endpoint that carries it.
#[derive(Debug)]
pub(crate) struct Routed {
    /// The verified connection.
    pub connection: Connection,
    /// Kept for the connection's life.
    pub endpoint: Endpoint,
    /// The connection came from a punch race, so the endpoint also holds the
    /// closed candidates that lost it. Also set for an iroh connection, whose
    /// endpoint closes with a bounded wait.
    pub punched: bool,
}

impl From<Dialed> for Routed {
    fn from(d: Dialed) -> Self {
        Self {
            connection: d.connection,
            endpoint: d.endpoint,
            punched: false,
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
    /// A jump chain to the host failed; the error carries `details.jump`.
    Chain(Box<OpError>),
}

/// A failed route: the direct failure, plus the punch's when one ran.
#[derive(Debug)]
pub(crate) struct RouteError {
    pub direct: DirectFail,
    pub punch: Option<PunchFailure>,
    /// Why the iroh route gave nothing, when it was tried.
    pub iroh: Option<Box<OpError>>,
}

impl RouteError {
    fn plain(direct: DirectFail) -> Self {
        Self {
            direct,
            punch: None,
            iroh: None,
        }
    }

    /// The command's error: what the direct dial said, naming the punch
    /// when it was tried (`details.punch`, and a clause on the human line).
    pub(crate) fn into_op(self, address: &str) -> OpError {
        let iroh = self.iroh;
        // A host with no address that only the iroh route could reach: the
        // iroh failure is the answer (it is the only route that was tried).
        if let (DirectFail::NoAddress, Some(iroh)) = (&self.direct, &iroh) {
            return match &self.punch {
                Some(punch) => punch.attach_to((**iroh).clone()),
                None => (**iroh).clone(),
            };
        }
        let op = match self.direct {
            DirectFail::Resolve(op) => op,
            DirectFail::Dial { err, attempted } => map_dial_error(err, address, attempted),
            DirectFail::NoAddress => OpError::new(
                ErrorCode::ConnectionFailed,
                "no address is recorded for this host and it could not be reached by hole punching",
            ),
            DirectFail::Chain(op) => *op,
        };
        let op = match &self.punch {
            Some(punch) => punch.attach_to(op),
            None => op,
        };
        match iroh {
            None => op,
            // The relay route reached the host and the host refused us: that
            // is the better answer than an unreachable address.
            Some(iroh)
                if iroh.code == ErrorCode::AuthFailed && op.code != ErrorCode::AuthFailed =>
            {
                *iroh
            }
            Some(iroh) => attach_iroh(op, &iroh),
        }
    }
}

/// `details.iroh{tried, code}` on a failure that also tried the relay route.
fn attach_iroh(mut op: OpError, iroh: &OpError) -> OpError {
    let note = serde_json::json!({ "tried": true, "code": iroh.code.to_string() });
    match &mut op.details {
        serde_json::Value::Null => op.details = serde_json::json!({ "iroh": note }),
        serde_json::Value::Object(map) => {
            map.insert("iroh".to_string(), note);
        }
        _ => {}
    }
    op
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
    // The simulated direct dial reaches the host's pin and nobody else
    // (ADR-0060), the key the punch itself expects.
    let plan_target = sim.map(|plan| plan.target);
    let dialed = crate::ops::dial_first_reachable(&addrs, |addr: SocketAddr| {
        let simulated = simulated.clone();
        async move {
            match simulated {
                Some(ep) => match plan_target {
                    Some(target) => {
                        ep.dial_trusted_bound(addr, server_name, PeerBinding::Pin(target))
                            .await
                    }
                    None => ep.dial_trusted(addr, server_name).await,
                },
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

/// Dials a host the forward way: through its jump chain when it has one
/// (ADR-0056 decision 13: then the chain is the whole route), otherwise
/// [`dial_routed_plain`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dial_routed(
    dialer: &Dialer,
    address: &str,
    server_name: &str,
    plan: Option<&Arc<PunchPlan>>,
    iroh: Option<&Arc<IrohPlan>>,
    jump: Option<&Arc<JumpPlan>>,
    fill: Option<&Arc<PinKeyFill>>,
    tuning: TransportTuning,
    resolver: &dyn AddressResolver,
    kind: Dial,
) -> Result<Routed, RouteError> {
    match jump {
        Some(jump) => dial_jump(dialer, jump, tuning, resolver, kind).await,
        None => {
            let routed = dial_routed_plain(
                dialer,
                address,
                server_name,
                plan,
                iroh,
                tuning,
                resolver,
                kind,
            )
            .await?;
            // A connection that passed the pin check over a direct or
            // punched path teaches the pin its key (CLI.md §6.11).
            if let Some(fill) = fill {
                fill.note(&routed.connection);
            }
            Ok(routed)
        }
    }
}

/// The first peer of a chain is reached the ordinary way, punching
/// included (decision 13); the rest of the chain goes over it.
async fn dial_jump(
    dialer: &Dialer,
    jump: &Arc<JumpPlan>,
    tuning: TransportTuning,
    resolver: &dyn AddressResolver,
    kind: Dial,
) -> Result<Routed, RouteError> {
    let budget = match kind {
        Dial::Command => default_dial_timeout(),
        Dial::Redial => (redial_deadline(
            jump.first_punch.as_ref(),
            !jump.step(0).address.is_empty(),
            None,
        ) + Duration::from_secs(jump.hops.len() as u64))
        .min(default_dial_timeout()),
    };
    let deadline = Instant::now() + budget;
    let first = jump.step(0);
    let fail = |failure: JumpFailure, route: Option<OpError>| {
        let message = route
            .as_ref()
            .map_or_else(String::new, |op| op.message.clone());
        RouteError::plain(DirectFail::Chain(Box::new(failure.into_op(message, route))))
    };
    // A first hop that registered reverse on this machine has no connection
    // to dial: the local daemon holds it, and the chain's first channel is
    // opened through the daemon (ADR-0056 decision 14).
    if jump.first_reverse.is_some() {
        let chained = crate::jump::dial_chain_via_daemon(jump, dialer, deadline)
            .await
            .map_err(|op| RouteError::plain(DirectFail::Chain(Box::new(op))))?;
        return Ok(Routed {
            connection: chained.connection,
            endpoint: chained.endpoint,
            punched: false,
        });
    }
    let server_name = crate::ops::server_name_for(&first.address);
    let first_hop = tokio::time::timeout_at(
        deadline,
        dial_routed_plain(
            dialer,
            &first.address,
            &server_name,
            jump.first_punch.as_ref(),
            // A chain never opens a hop over iroh (ADR-0061 decision 14).
            None,
            tuning,
            resolver,
            kind,
        ),
    )
    .await;
    let routed = match first_hop {
        Ok(Ok(routed)) => routed,
        Ok(Err(err)) => {
            let op = err.into_op(&first.address);
            let stage = if op.code == ErrorCode::AuthFailed {
                Stage::Auth
            } else {
                Stage::Dial
            };
            return Err(fail(
                JumpFailure {
                    hop: 1,
                    hops: jump.hop_count(),
                    name: first.name.clone(),
                    stage,
                },
                Some(op),
            ));
        }
        Err(_) => {
            return Err(fail(
                JumpFailure {
                    hop: 1,
                    hops: jump.hop_count(),
                    name: first.name.clone(),
                    stage: Stage::Dial,
                },
                Some(map_dial_error(
                    DialError::Timeout(budget),
                    &first.address,
                    1,
                )),
            ));
        }
    };
    let chained =
        crate::jump::dial_chain(jump, dialer, (routed.connection, routed.endpoint), deadline)
            .await
            .map_err(|op| RouteError::plain(DirectFail::Chain(Box::new(op))))?;
    Ok(Routed {
        connection: chained.connection,
        endpoint: chained.endpoint,
        punched: false,
    })
}

/// Dials a host the forward way, the iroh relay route included when the pin
/// has one. With no `iroh` this is [`dial_direct_punch`] alone, exactly as
/// before the relay route existed: no endpoint is built and no relay is
/// contacted.
#[allow(clippy::too_many_arguments)]
async fn dial_routed_plain(
    dialer: &Dialer,
    address: &str,
    server_name: &str,
    plan: Option<&Arc<PunchPlan>>,
    iroh: Option<&Arc<IrohPlan>>,
    tuning: TransportTuning,
    resolver: &dyn AddressResolver,
    kind: Dial,
) -> Result<Routed, RouteError> {
    let Some(iroh) = iroh else {
        return dial_direct_punch(dialer, address, server_name, plan, tuning, resolver, kind).await;
    };
    let has_address = !address.is_empty();
    let has_other = has_address || plan.is_some_and(|p| p.has_rendezvous());
    let timeout = match kind {
        Dial::Command => default_dial_timeout(),
        Dial::Redial => redial_deadline(plan, has_address, Some(iroh)),
    };
    let deadline = Instant::now() + timeout;
    if !has_other {
        // Nothing else can reach this host: iroh at once, no head start.
        return dial_iroh(iroh, deadline).await.map_err(|op| RouteError {
            direct: DirectFail::NoAddress,
            punch: None,
            iroh: Some(Box::new(op)),
        });
    }

    // What this device remembers about the pin (`docs/CLI.md` §6.1 "route
    // 기억"): in a rest the direct dial and the punch wait behind iroh, after
    // a rest they run beside it, and otherwise the head start decides.
    let stance = iroh
        .memory
        .as_ref()
        .map_or(Stance::Normal, RouteMemory::stance);
    let dial_other = || -> BoxFut<'_, Result<Routed, RouteError>> {
        Box::pin(dial_direct_punch(
            dialer,
            address,
            server_name,
            plan,
            tuning,
            resolver,
            kind,
        ))
    };
    let mut other: Option<BoxFut<'_, Result<Routed, RouteError>>> =
        (stance != Stance::Skip).then(dial_other);
    // A pin in a rest: they start only when iroh has failed, so a relay that
    // is down does not lock a pin out of the path that may be open again.
    let mut other_pending = stance == Stance::Skip;
    let mut other_ran = !other_pending;
    let mut iroh_fut: Option<BoxFut<'_, Result<Routed, OpError>>> = None;
    let mut iroh_started = false;
    let mut other_failed: Option<RouteError> = None;
    let mut iroh_failed: Option<OpError> = None;
    let head = sleep(iroh.head_start());
    tokio::pin!(head);
    let overall = sleep_until(deadline);
    tokio::pin!(overall);
    if stance != Stance::Normal || iroh.head_start().is_zero() {
        iroh_fut = Some(Box::pin(dial_iroh(iroh, deadline)));
        iroh_started = true;
    }
    let remember = |won_by_iroh: bool, other_ran: bool| {
        if let Some(memory) = &iroh.memory {
            if won_by_iroh {
                memory.note_iroh_won(other_ran);
            } else if stance != Stance::Normal {
                memory.note_other_won();
            }
        }
    };

    loop {
        if other.is_none() && iroh_fut.is_none() {
            break;
        }
        enum Ev {
            Other(Result<Routed, RouteError>),
            Iroh(Result<Routed, OpError>),
            HeadStart,
            Deadline,
        }
        let event = tokio::select! {
            biased;
            r = within(&mut other) => Ev::Other(r),
            r = within(&mut iroh_fut) => Ev::Iroh(r),
            () = &mut head, if !iroh_started && other.is_some() => Ev::HeadStart,
            () = &mut overall => Ev::Deadline,
        };
        match event {
            // The loser is dropped on return, which abandons its handshake
            // and closes its endpoint.
            Ev::Other(Ok(routed)) => {
                remember(false, other_ran);
                return Ok(routed);
            }
            Ev::Iroh(Ok(routed)) => {
                remember(true, other_ran);
                return Ok(routed);
            }
            Ev::Other(Err(fail)) => {
                other = None;
                other_failed = Some(fail);
                if !iroh_started {
                    iroh_fut = Some(Box::pin(dial_iroh(iroh, deadline)));
                    iroh_started = true;
                }
            }
            Ev::Iroh(Err(op)) => {
                iroh_fut = None;
                iroh_failed = Some(op);
                if other_pending {
                    other_pending = false;
                    other_ran = true;
                    other = Some(dial_other());
                }
            }
            Ev::HeadStart => {
                iroh_fut = Some(Box::pin(dial_iroh(iroh, deadline)));
                iroh_started = true;
            }
            Ev::Deadline => break,
        }
    }
    drop(other);
    drop(iroh_fut);
    let mut err = other_failed.unwrap_or_else(|| {
        RouteError::plain(DirectFail::Dial {
            err: DialError::Timeout(timeout),
            attempted: 1,
        })
    });
    err.iroh = iroh_failed.map(Box::new);
    Err(err)
}

/// Dials the pin by key over iroh: builds the endpoint, homed on the relay
/// the plan names, and dials. The endpoint lives as long as the connection.
///
/// The endpoint is a client endpoint: it binds a fresh random iroh key, so
/// this command and any other client process of this machine each have an
/// `EndpointId` of their own and the relay keeps all of them, and it proves
/// the machine's qsh identity to the host in-band (protocol §22.8).
async fn dial_iroh(plan: &Arc<IrohPlan>, deadline: Instant) -> Result<Routed, OpError> {
    let label = format!("{} over the iroh relay route", plan.name);
    let endpoint = IrohEndpoint::bind_client(
        &plan.identity,
        plan.evaluator.clone(),
        plan.target.config.clone(),
    )
    .await
    .map_err(|e| map_dial_error(DialError::Setup(e), &label, 1))?;
    let left = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1));
    let endpoint = endpoint.with_timeout(left);
    let connection = endpoint
        .dial(&plan.target.peer)
        .await
        .map_err(|e| map_dial_error(e, &label, 1))?;
    Ok(Routed {
        connection,
        endpoint: Endpoint::from_iroh(endpoint),
        punched: true,
    })
}

/// The direct dial and the hole-punching race. With no `plan` this is the
/// direct dial alone, exactly as before the punch existed.
async fn dial_direct_punch(
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
                iroh: None,
            });
    }

    let started = Instant::now();
    let mut timeout = match kind {
        Dial::Command => default_dial_timeout(),
        Dial::Redial => redial_deadline(Some(plan), has_address, None),
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
                    punched: true,
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
        None if punch_started && expired => {
            // The route's deadline cut the attempt off before it could say so.
            let failure = PunchFailure {
                rendezvous: plan
                    .rendezvous
                    .first()
                    .map_or_else(String::new, |r| r.name.clone()),
                reason: crate::punch::GiveUpReason::Timeout,
            };
            crate::punch::log::emit(
                "gave_up",
                serde_json::json!({
                    "rendezvous": failure.rendezvous,
                    "reason": failure.reason.as_str(),
                    "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                }),
            );
            Some(failure)
        }
        None => None,
    };
    drop(direct);
    drop(punch);
    Err(RouteError {
        direct: direct_error,
        punch: punch_error,
        iroh: None,
    })
}
