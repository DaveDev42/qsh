//! The forward route's dial: a direct dial, with the iroh relay route beside
//! it when the pin has one (ADR-0061). qsh's own hole-punching route
//! (ADR-0054) was retired with ADR-0068 and is not part of the route any
//! more.
//!
//! Order, `docs/CLI.md` §6.1: a live reverse registration is chosen before
//! this runs (`Ops::resolve_route`). Here a host with an address is dialed
//! directly. The whole route lives inside the one dial timeout the command
//! already has (10 s, or `-o ConnectTimeout`).
//!
//! The iroh relay route is the last route and only a pin with
//! `routes = ["iroh"]` and a recorded `key` has it. A pin with no address
//! dials iroh at once. Otherwise iroh starts beside the direct dial when it
//! has not stood after `[iroh].head_start_ms` (1 s), or when it failed
//! sooner. The first connection that stands wins; the rest are dropped,
//! which closes them. Everything stays inside the one dial timeout.
//!
//! A recovery re-dial runs the same route again ([`Dial::Redial`]) and
//! [`redial_deadline`] is what the recovery loop waits for one attempt.

// `RouteError` carries up to two route failures (direct, iroh) and is
// only built when a dial has already failed, so its size is not on a hot path.
#![allow(clippy::result_large_err)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_transport::{
    Connection, DialError, Dialed, Dialer, Endpoint, IrohEndpoint, TransportTuning,
    default_dial_timeout,
};
use tokio::time::{Instant, sleep, sleep_until};

use crate::client::reconnect::REDIAL_DEADLINE;
use crate::iroh_settings::IrohPlan;
use crate::jump::{JumpFailure, JumpPlan, Stage};
use crate::ops::exec::map_dial_error;
use crate::ops::{AddressResolver, OpError};
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

/// The longest one re-dial attempt may take: [`REDIAL_DEADLINE`], and a host
/// with an iroh route also gets [`IROH_REDIAL_BUDGET`] after the iroh head
/// start (none when iroh is the only route).
pub(crate) fn redial_deadline(has_address: bool, iroh: Option<&Arc<IrohPlan>>) -> Duration {
    match iroh {
        Some(iroh) => {
            let head = if has_address {
                iroh.head_start()
            } else {
                Duration::ZERO
            };
            REDIAL_DEADLINE.max(head.saturating_add(IROH_REDIAL_BUDGET))
        }
        None => REDIAL_DEADLINE,
    }
}

/// A connection of the forward route and the endpoint that carries it.
#[derive(Debug)]
pub(crate) struct Routed {
    /// The verified connection.
    pub connection: Connection,
    /// Kept for the connection's life.
    pub endpoint: Endpoint,
    /// The endpoint closes with a bounded wait instead of a full drain: set
    /// for an iroh connection (the name is from the punch route it once
    /// shared this with).
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
    /// The host has no address; only the iroh route could have reached it.
    NoAddress,
    /// A jump chain to the host failed; the error carries `details.jump`.
    Chain(Box<OpError>),
}

/// A failed route: the direct failure, plus the iroh route's when it ran.
#[derive(Debug)]
pub(crate) struct RouteError {
    pub direct: DirectFail,
    /// Why the iroh route gave nothing, when it was tried.
    pub iroh: Option<Box<OpError>>,
}

impl RouteError {
    fn plain(direct: DirectFail) -> Self {
        Self { direct, iroh: None }
    }

    /// The command's error: what the direct dial said, naming the iroh route
    /// when it was tried (`details.iroh`).
    pub(crate) fn into_op(self, address: &str) -> OpError {
        let iroh = self.iroh;
        // A host with no address that only the iroh route could reach: the
        // iroh failure is the answer (it is the only route that was tried).
        if let (DirectFail::NoAddress, Some(iroh)) = (&self.direct, &iroh) {
            return (**iroh).clone();
        }
        let op = match self.direct {
            DirectFail::Resolve(op) => op,
            DirectFail::Dial { err, attempted } => map_dial_error(err, address, attempted),
            DirectFail::NoAddress => OpError::new(
                ErrorCode::ConnectionFailed,
                "no address is recorded for this host",
            ),
            DirectFail::Chain(op) => *op,
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
pub(crate) fn attach_iroh(mut op: OpError, iroh: &OpError) -> OpError {
    let mut note = serde_json::json!({ "tried": true, "code": iroh.code.to_string() });
    if let Some(reason) = iroh
        .details
        .pointer("/iroh/reason")
        .and_then(|r| r.as_str())
        && let Some(map) = note.as_object_mut()
    {
        map.insert("reason".to_string(), serde_json::json!(reason));
    }
    match &mut op.details {
        serde_json::Value::Null => op.details = serde_json::json!({ "iroh": note }),
        serde_json::Value::Object(map) => {
            map.insert("iroh".to_string(), note);
        }
        _ => {}
    }
    op
}

/// The direct dial: resolve, then each address in turn.
async fn direct_dial(
    dialer: &Dialer,
    address: &str,
    server_name: &str,
    resolver: &dyn AddressResolver,
) -> Result<Routed, DirectFail> {
    let addrs = crate::ops::resolve_all_with(resolver, address)
        .await
        .map_err(DirectFail::Resolve)?;
    let dialed =
        crate::ops::dial_first_reachable(&addrs, |addr: SocketAddr| dialer.dial(addr, server_name))
            .await
            .map_err(|(err, attempted)| DirectFail::Dial { err, attempted })?;
    Ok(dialed.into())
}

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
    iroh: Option<&Arc<IrohPlan>>,
    jump: Option<&Arc<JumpPlan>>,
    fill: Option<&Arc<PinKeyFill>>,
    _tuning: TransportTuning,
    resolver: &dyn AddressResolver,
    kind: Dial,
) -> Result<Routed, RouteError> {
    match jump {
        Some(jump) => dial_jump(dialer, jump, resolver, kind).await,
        None => {
            let routed =
                dial_routed_plain(dialer, address, server_name, iroh, resolver, kind).await?;
            // A connection that passed the pin check over a direct path
            // teaches the pin its key (CLI.md §6.11).
            if let Some(fill) = fill {
                fill.note(&routed.connection);
            }
            Ok(routed)
        }
    }
}

/// The first peer of a chain is reached the ordinary way (decision 13); the
/// rest of the chain goes over it.
async fn dial_jump(
    dialer: &Dialer,
    jump: &Arc<JumpPlan>,
    resolver: &dyn AddressResolver,
    kind: Dial,
) -> Result<Routed, RouteError> {
    let budget = match kind {
        Dial::Command => default_dial_timeout(),
        Dial::Redial => (redial_deadline(!jump.step(0).address.is_empty(), None)
            + Duration::from_secs(jump.hops.len() as u64))
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
            // A chain never opens a hop over iroh (ADR-0061 decision 14).
            None,
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
/// has one. With no `iroh` this is the direct dial alone, exactly as before
/// the relay route existed: no endpoint is built and no relay is contacted.
async fn dial_routed_plain(
    dialer: &Dialer,
    address: &str,
    server_name: &str,
    iroh: Option<&Arc<IrohPlan>>,
    resolver: &dyn AddressResolver,
    kind: Dial,
) -> Result<Routed, RouteError> {
    let Some(iroh) = iroh else {
        return direct_dial(dialer, address, server_name, resolver)
            .await
            .map_err(RouteError::plain);
    };
    let has_address = !address.is_empty();
    let timeout = match kind {
        Dial::Command => default_dial_timeout(),
        Dial::Redial => redial_deadline(has_address, Some(iroh)),
    };
    let deadline = Instant::now() + timeout;
    if !has_address {
        // Nothing else can reach this host: iroh at once, no head start.
        return dial_iroh(iroh, deadline).await.map_err(|op| RouteError {
            direct: DirectFail::NoAddress,
            iroh: Some(Box::new(op)),
        });
    }

    // What this device remembers about the pin (`docs/CLI.md` §6.1 "route
    // 기억"): in a rest the direct dial waits behind iroh, after
    // a rest they run beside it, and otherwise the head start decides.
    let stance = iroh
        .memory
        .as_ref()
        .map_or(Stance::Normal, RouteMemory::stance);
    let dial_other = || -> BoxFut<'_, Result<Routed, RouteError>> {
        Box::pin(async move {
            direct_dial(dialer, address, server_name, resolver)
                .await
                .map_err(RouteError::plain)
        })
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
    // A relay that hangs instead of refusing would hold the dial to its
    // deadline and leave the fallback no time, so a rest gives iroh a bounded
    // share of the dial before the others start beside it.
    let patience = sleep(rest_patience(timeout));
    tokio::pin!(patience);
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
            Patience,
            Deadline,
        }
        let event = tokio::select! {
            biased;
            r = within(&mut other) => Ev::Other(r),
            r = within(&mut iroh_fut) => Ev::Iroh(r),
            () = &mut head, if !iroh_started && other.is_some() => Ev::HeadStart,
            () = &mut patience, if other_pending => Ev::Patience,
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
            Ev::Patience => {
                // iroh is still going: the others start beside it. A win by
                // them ends the rest, a win by iroh lengthens it.
                other_pending = false;
                other_ran = true;
                other = Some(dial_other());
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

/// How long iroh has the dial to itself in a rest before the direct dial
/// starts beside it (`docs/CLI.md` §6.1 "route 기억").
const REST_PATIENCE: Duration = Duration::from_secs(2);

/// [`REST_PATIENCE`], held to half of a dial that is shorter than twice it.
fn rest_patience(dial: Duration) -> Duration {
    REST_PATIENCE.min(dial / 2)
}

/// Dials the pin by key over iroh: builds the endpoint, homed on the relay
/// the plan names, and dials. The endpoint lives as long as the connection.
///
/// The endpoint is a client endpoint: it binds a fresh random iroh key, so
/// this command and any other client process of this machine each have an
/// `EndpointId` of their own and the relay keeps all of them, and it proves
/// the machine's qsh identity to the host in-band (protocol §22.8).
pub(crate) async fn dial_iroh(plan: &Arc<IrohPlan>, deadline: Instant) -> Result<Routed, OpError> {
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
    // A dial with time to spare keeps the end of it to find out why it
    // failed (`details.iroh.reason`); a short one spends all of it dialing.
    let reserve = if left > RELAY_DIAGNOSIS_MIN_BUDGET {
        RELAY_DIAGNOSIS
    } else {
        Duration::ZERO
    };
    let endpoint = endpoint.with_timeout(left - reserve);
    match endpoint.dial(&plan.target.peer).await {
        Ok(connection) => Ok(Routed {
            connection,
            endpoint: Endpoint::from_iroh(endpoint),
            punched: true,
        }),
        Err(err) => {
            let reason = relay_failure_reason(plan, &endpoint, &err, reserve).await;
            let op = map_dial_error(err, &label, 1);
            Err(match reason {
                Some(reason) => with_iroh_reason(op, reason),
                None => op,
            })
        }
    }
}

/// What a relay dial keeps at the end of its time to say why it failed.
const RELAY_DIAGNOSIS: Duration = Duration::from_millis(1500);

/// A dial with less time than this spends all of it dialing.
const RELAY_DIAGNOSIS_MIN_BUDGET: Duration = Duration::from_secs(4);

/// How long the endpoint gets to say it reached its relay before the relay
/// is checked from the outside.
const RELAY_ONLINE_GRACE: Duration = Duration::from_millis(150);

/// `details.iroh.reason` for a failed relay dial (`docs/CLI.md` §3.3), or
/// `None` when the failure is not a relay-stage one: the peer refused us, the
/// endpoint could not be built, or the relay is fine and the peer is not
/// there.
///
/// A dial that did not stand tells nothing about the relay by itself. The
/// endpoint says whether it reached its home relay; when it did not, the
/// relay is checked from the outside the way `qsh doctor` does, which names
/// the stage, within `budget`.
async fn relay_failure_reason(
    plan: &IrohPlan,
    endpoint: &IrohEndpoint,
    err: &DialError,
    budget: Duration,
) -> Option<&'static str> {
    match err {
        DialError::Setup(_) | DialError::LocalRejected { .. } | DialError::RemoteRejected => {
            return None;
        }
        DialError::Failed(inner) if inner.is_crypto_failure() => return None,
        DialError::Failed(inner) if inner.is_no_route() => {
            return Some(REASON_NO_RELAY);
        }
        _ => {}
    }
    if tokio::time::timeout(RELAY_ONLINE_GRACE, endpoint.online())
        .await
        .is_ok()
    {
        return None;
    }
    // The check connects straight to the relay host. A relay connection that
    // follows a proxy the environment names did not go there, so the check
    // would send a connection the proxy setting forbids, and its answer would
    // describe another path: no reason is better than a wrong one.
    if !relay_check_applies(
        plan.target.config.proxy_from_env,
        qsh_transport::proxy_in_environment(),
    ) {
        return None;
    }
    if budget.is_zero() {
        return Some(REASON_RELAY_UNREACHABLE);
    }
    // Every candidate is checked at once, so a set of several costs one
    // budget, not one each.
    let mut checks = tokio::task::JoinSet::new();
    for url in &plan.target.relay_urls {
        let url = url.clone();
        let trust = plan.target.config.relay_trust.clone();
        checks.spawn(async move { qsh_transport::probe_relay(&url, &trust, budget).await });
    }
    let mut checked = Vec::new();
    while let Some(done) = checks.join_next().await {
        match done {
            Ok(result) => checked.push(result),
            // A check that did not finish says nothing about its relay.
            Err(_) => continue,
        }
    }
    reason_of_probes(&checked)
}

/// Whether the outside relay check may run: not when the relay connection
/// goes through a proxy from the environment.
fn relay_check_applies(proxy_from_env: bool, proxy_in_environment: bool) -> bool {
    !(proxy_from_env && proxy_in_environment)
}

pub(crate) const REASON_RELAY_UNREACHABLE: &str = "relay_unreachable";
pub(crate) const REASON_RELAY_TLS: &str = "relay_tls";
pub(crate) const REASON_RELAY_UPGRADE: &str = "relay_upgrade";
pub(crate) const REASON_NO_RELAY: &str = "no_relay_configured";

/// The reason word for the outcome of the relay check run after a dial that
/// did not stand. A relay that passes the check is not what failed.
pub(crate) fn reason_of_probe(
    checked: &Result<(), qsh_transport::RelayProbeFailure>,
) -> Option<&'static str> {
    use qsh_transport::RelayProbeStage as Stage;
    match checked {
        Ok(()) => None,
        Err(failure) => Some(match failure.stage {
            Stage::Resolve | Stage::Connect | Stage::Timeout => REASON_RELAY_UNREACHABLE,
            Stage::Tls => REASON_RELAY_TLS,
            Stage::Http | Stage::Upgrade => REASON_RELAY_UPGRADE,
        }),
    }
}

/// The reason word for the relay checks of a candidate set. One candidate that
/// passes means the relay layer is not what failed. When none passes, a
/// candidate that was reached but broke (its certificate, its upgrade) is the
/// more specific answer, so `relay_unreachable` is the reason only when no
/// candidate could be reached at all (ADR-0062).
pub(crate) fn reason_of_probes(
    checked: &[Result<(), qsh_transport::RelayProbeFailure>],
) -> Option<&'static str> {
    if checked.is_empty() || checked.iter().any(Result::is_ok) {
        return None;
    }
    let reasons: Vec<&'static str> = checked
        .iter()
        .filter_map(|result| reason_of_probe(result))
        .collect();
    [REASON_RELAY_TLS, REASON_RELAY_UPGRADE]
        .into_iter()
        .find(|reason| reasons.contains(reason))
        .or(Some(REASON_RELAY_UNREACHABLE))
}

/// `op` with `details.iroh.reason` set.
fn with_iroh_reason(mut op: OpError, reason: &str) -> OpError {
    let note = serde_json::json!({ "reason": reason });
    match &mut op.details {
        serde_json::Value::Null => op.details = serde_json::json!({ "iroh": note }),
        serde_json::Value::Object(map) => {
            map.insert("iroh".to_string(), note);
        }
        _ => {}
    }
    op
}

#[cfg(test)]
mod tests {
    use qsh_transport::{RelayProbeFailure, RelayProbeStage};

    use super::*;

    fn failed(stage: RelayProbeStage) -> Result<(), RelayProbeFailure> {
        Err(RelayProbeFailure {
            stage,
            detail: String::new(),
        })
    }

    #[test]
    fn the_stage_of_a_failed_relay_check_names_the_reason() {
        use RelayProbeStage as S;
        let reasons: Vec<_> = [
            S::Resolve,
            S::Connect,
            S::Tls,
            S::Http,
            S::Upgrade,
            S::Timeout,
        ]
        .into_iter()
        .map(|stage| reason_of_probe(&failed(stage)))
        .collect();
        assert_eq!(
            reasons,
            [
                Some("relay_unreachable"),
                Some("relay_unreachable"),
                Some("relay_tls"),
                Some("relay_upgrade"),
                Some("relay_upgrade"),
                Some("relay_unreachable"),
            ]
        );
        // A relay that passes the check is not what failed.
        assert_eq!(reason_of_probe(&Ok(())), None);
    }

    #[test]
    fn a_candidate_set_is_unreachable_only_when_no_candidate_is_reachable() {
        use RelayProbeStage as S;
        // One candidate that passes: the relay layer is not what failed.
        assert_eq!(
            reason_of_probes(&[failed(S::Connect), Ok(()), failed(S::Timeout)]),
            None
        );
        // None passes and none was reached.
        assert_eq!(
            reason_of_probes(&[failed(S::Connect), failed(S::Timeout), failed(S::Resolve)]),
            Some("relay_unreachable")
        );
        // A candidate that was reached but broke is the more specific answer.
        assert_eq!(
            reason_of_probes(&[failed(S::Connect), failed(S::Upgrade)]),
            Some("relay_upgrade")
        );
        assert_eq!(
            reason_of_probes(&[failed(S::Upgrade), failed(S::Tls), failed(S::Connect)]),
            Some("relay_tls")
        );
        // No check ran: no reason is better than a wrong one.
        assert_eq!(reason_of_probes(&[]), None);
    }

    #[test]
    fn the_relay_check_does_not_bypass_a_proxy_the_connection_follows() {
        assert!(!relay_check_applies(true, true));
        assert!(relay_check_applies(true, false));
        // `[iroh].proxy = "off"`: the connection is direct, so is the check.
        assert!(relay_check_applies(false, true));
        assert!(relay_check_applies(false, false));
    }

    #[test]
    fn the_reason_rides_along_with_the_route_failure() {
        let direct = OpError::new(ErrorCode::ConnectionFailed, "no response");
        let iroh = with_iroh_reason(
            OpError::new(ErrorCode::ConnectionFailed, "relay"),
            REASON_RELAY_TLS,
        );
        assert_eq!(iroh.details["iroh"]["reason"], "relay_tls");
        let op = attach_iroh(direct, &iroh);
        assert_eq!(op.details["iroh"]["tried"], true);
        assert_eq!(op.details["iroh"]["code"], "CONNECTION_FAILED");
        assert_eq!(op.details["iroh"]["reason"], "relay_tls");

        // No reason, none invented.
        let bare = attach_iroh(
            OpError::new(ErrorCode::ConnectionFailed, "no response"),
            &OpError::new(ErrorCode::ConnectionFailed, "peer offline"),
        );
        assert!(bare.details["iroh"].get("reason").is_none());
    }

    #[test]
    fn a_reason_is_added_next_to_the_details_a_failure_already_has() {
        let op = OpError::new(ErrorCode::ConnectionFailed, "x")
            .with_details(serde_json::json!({ "timeout_ms": 5 }));
        let op = with_iroh_reason(op, REASON_RELAY_UPGRADE);
        assert_eq!(op.details["timeout_ms"], 5);
        assert_eq!(op.details["iroh"]["reason"], "relay_upgrade");
    }
}
