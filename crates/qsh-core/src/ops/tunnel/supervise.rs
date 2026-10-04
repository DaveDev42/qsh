//! The supervisor of a `--supervise` tunnel (ADR-0023).
//!
//! One task per tunnel, living inside the process that opened it
//! (decision 3). It owns the control stream of the current connection, a
//! `PathWatch` over it, and the `watch` channel the `-L`/`-D` accept loops
//! read their carrier from. It never touches the listener or the tunnel id.
//!
//! Two routes share the loop below and differ in what "the carrier" is. The
//! forward route (this file) re-dials a QUIC connection to the address the
//! first open resolved. The reverse route ([`reverse`]) asks this machine's
//! `qsh listen` daemon again and never dials anything, so a forward pin of
//! the same name is never a candidate (decisions 4 and 22).
//!
//! ```text
//!   monitor ── path dead / control stream gone ──▶ Disconnected ──▶ attempt
//!      ▲                                                              │
//!      └──────── Live(new carrier) ◀── fingerprint + capability ◀─────┘
//! ```
//!
//! A carrier only becomes `Live` after the peer's TLS fingerprint matches the
//! first open's and the capability the first open relied on is still offered
//! (decisions 7-2 and 7-3). `-L`/`-D` send no control message on the new
//! connection: the peer authorizes every `TCP_CONNECT` per stream
//! (decision 8).
//!
//! The pure decisions (spacing, budget, retryability) live in
//! [`crate::tunnel::supervise`]; this module is the I/O around them.

use std::sync::Arc;
use std::time::Duration;

use qsh_proto::{ErrorCode, wire};
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use serde::Serialize;
use tokio::sync::{Notify, mpsc, watch};
use tokio::time::Instant;

use crate::client::pathwatch::{PathWatch, watch_path_with_wake};
use crate::client::reconnect::{PathBinder, REDIAL_DEADLINE};
use crate::client::wake::{self, WakeEvent};
use crate::client::{ControlIn, Session};
use crate::ops::exec::{map_client_error, map_dial_error};
use crate::ops::session::{Link, RecoveryConfig, probe_alive};
use crate::ops::{OpError, PeerTarget};
use crate::reverse::{ReconnectCause, classify_connection_error};
use crate::tunnel::carrier::{ActivityHook, CarrierState, CarrierView, HoldSignal, hold_gate};
use crate::tunnel::local::ForwardCarrier;
use crate::tunnel::supervise::TARGET;
use crate::tunnel::supervise::backoff::{Backoff, Pacer, Waited};
use crate::tunnel::supervise::budget::Budget;
use crate::tunnel::supervise::classify::{Disposition, Source, classify};

mod remote;
#[cfg(unix)]
mod reverse;
pub(super) use remote::{RemoteHandle, RemoteTunnel};
#[cfg(unix)]
pub(super) use reverse::ReverseRoute;

/// The channel ends a supervised forward is built around. Created before
/// the listener so the accept loop can be handed its [`CarrierView`], and
/// consumed by [`spawn`] once the forward's `tunnel_id` is known.
pub(super) struct Wiring {
    view: CarrierView,
    tx: watch::Sender<CarrierState>,
    watch: PathWatch,
    denied_rx: mpsc::UnboundedReceiver<Arc<ForwardCarrier>>,
    changed_rx: mpsc::UnboundedReceiver<Arc<ForwardCarrier>>,
    initial: Arc<ForwardCarrier>,
    /// The supervisor's end of the accept-hold gate, when there is one.
    hold: Option<HoldSignal>,
}

impl Wiring {
    /// Wire a supervised forward over `initial`, the carrier the first open
    /// succeeded on. `accept_hold` is `--accept-hold` (decision 19): how
    /// long a connection that arrives while disconnected may be kept.
    pub(super) fn new(
        initial: ForwardCarrier,
        recovery: &RecoveryConfig,
        accept_hold: Option<Duration>,
    ) -> Self {
        let initial = Arc::new(initial);
        let (tx, rx) = watch::channel(CarrierState::Live(Arc::clone(&initial)));
        let watch = PathWatch::new(recovery.watch);
        let (denied_tx, denied_rx) = mpsc::unbounded_channel();
        let (changed_tx, changed_rx) = mpsc::unbounded_channel();
        let hook_watch = watch.clone();
        let activity: ActivityHook = Arc::new(move || hook_watch.activity());
        let mut view = CarrierView::watching(rx, Some(activity))
            .with_denied(denied_tx)
            .with_changed(changed_tx);
        let hold = accept_hold.map(|window| {
            let (gate, signal) = hold_gate(window);
            view = view.clone().with_hold(gate);
            signal
        });
        Self {
            view,
            tx,
            watch,
            denied_rx,
            changed_rx,
            initial,
            hold,
        }
    }

    /// The view to start the listener with.
    pub(super) fn view(&self) -> CarrierView {
        self.view.clone()
    }
}

/// Everything else the supervisor needs, all fixed at the first open.
pub(super) struct Params {
    /// How the carrier is found again.
    pub(super) route: Route,
    /// The peer fingerprint the first open verified (decision 7-2).
    pub(super) fingerprint: String,
    /// Whether the tunnel relies on `dial-filter.v1` (`-D`, decision 7-3).
    pub(super) require_dial_filter: bool,
    /// The disconnection budget (`--supervise`).
    pub(super) total: Duration,
    pub(super) tunnel_id: String,
    /// `"local"` or `"dynamic"`.
    pub(super) mode: &'static str,
    pub(super) recovery: RecoveryConfig,
    /// `[transport]` as read at the first open; every redial uses it.
    pub(super) tuning: qsh_transport::TransportTuning,
}

/// How a lost carrier is found again (decision 4).
pub(super) enum Route {
    Forward {
        /// The resolved peer; re-dialed as is, never re-resolved from
        /// `hosts.toml`.
        target: PeerTarget,
        /// Shared with the tunnel's `Connected`, so closing the tunnel
        /// closes the current pair.
        link: Link,
    },
    /// This machine's `qsh listen` daemon, asked again.
    #[cfg(unix)]
    Reverse(reverse::ReverseRoute),
}

impl Route {
    fn label(&self) -> &'static str {
        match self {
            Route::Forward { .. } => "forward",
            #[cfg(unix)]
            Route::Reverse(_) => "reverse",
        }
    }
}

/// A running supervisor. Dropping it stops the supervision and releases
/// everything the task holds.
pub(super) struct SuperviseTask {
    handle: tokio::task::JoinHandle<SuperviseEnd>,
}

/// How a supervised tunnel ended.
pub(super) enum SuperviseEnd {
    /// The budget ran out or an error that retrying cannot mend.
    Failed(OpError),
    /// An operator closed the registration (decision 14): a deliberate end.
    Closed,
}

impl SuperviseTask {
    /// Resolves with how the tunnel ended. Never resolves while the tunnel
    /// is being kept alive.
    pub(super) async fn finished(&mut self) -> SuperviseEnd {
        match (&mut self.handle).await {
            Ok(end) => end,
            Err(err) => SuperviseEnd::Failed(OpError::new(
                ErrorCode::Internal,
                format!("the tunnel supervisor stopped unexpectedly: {err}"),
            )),
        }
    }
}

impl Drop for SuperviseTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Start supervising. Must run inside the tunnel's runtime.
pub(super) fn spawn(
    wiring: Wiring,
    params: Params,
    session: Session,
    remote: Option<RemoteTunnel>,
) -> SuperviseTask {
    let mut supervisor = Supervisor::new(wiring, params);
    supervisor.remote = remote;
    let handle = tokio::spawn(supervisor.run(session));
    SuperviseTask { handle }
}

/// One supervise diagnostic line (decision 12). Field order is the wire
/// order: `supervise` is first.
#[derive(Serialize)]
struct Line<'a> {
    supervise: &'static str,
    at: String,
    tunnel_id: &'a str,
    mode: &'static str,
    route: &'static str,
    /// The host alias, on the reverse route only (decision 12).
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outage_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slept_ms: Option<u64>,
    /// The registration generation a reverse carrier was confirmed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
    /// The id a `-R` tunnel had before it was re-opened (decision 13).
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_tunnel_id: Option<&'a str>,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Why a monitored carrier stopped being one.
enum Ended {
    /// The path died or the connection closed; `cause` is the diagnostic
    /// vocabulary word, absent when the loss does not say (a
    /// `LOCAL_CONTROL` end, decision 12).
    Lost(Option<&'static str>),
    /// The tunnel ends, without a retry.
    Fatal(OpError),
    /// An operator closed the tunnel (decision 14). Only the reverse route
    /// can tell, and that route is unix-only.
    #[cfg_attr(not(unix), allow(dead_code))]
    Closed,
}

/// One failed re-establishment attempt.
struct AttemptError {
    op: OpError,
    source: Source,
    cause: Option<ReconnectCause>,
}

impl AttemptError {
    fn dial(op: OpError, cause: ReconnectCause) -> Self {
        Self {
            op,
            source: Source::LocalDial,
            cause: Some(cause),
        }
    }

    fn check(op: OpError) -> Self {
        Self {
            op,
            source: Source::SupervisorCheck,
            cause: None,
        }
    }

    /// Asking this machine's own daemon failed.
    #[cfg(unix)]
    fn daemon(op: OpError) -> Self {
        Self {
            op,
            source: Source::LocalDaemon,
            cause: None,
        }
    }
}

/// What a successful attempt produced.
enum Established {
    Forward {
        endpoint: qsh_transport::Endpoint,
        connection: qsh_transport::Connection,
        session: Session,
    },
    #[cfg(unix)]
    Reverse(reverse::ReverseEstablished),
}

impl Established {
    /// The new carrier's control stream.
    fn session_mut(&mut self) -> &mut Session {
        match self {
            Established::Forward { session, .. } => session,
            #[cfg(unix)]
            Established::Reverse(next) => &mut next.session,
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Supervisor {
    params: Params,
    tx: watch::Sender<CarrierState>,
    watch: PathWatch,
    denied_rx: mpsc::UnboundedReceiver<Arc<ForwardCarrier>>,
    /// Carriers whose registration turned out to have changed (decision
    /// 7-5). Read by the reverse monitor only.
    #[cfg_attr(not(unix), allow(dead_code))]
    changed_rx: mpsc::UnboundedReceiver<Arc<ForwardCarrier>>,
    current: Arc<ForwardCarrier>,
    /// How many times the carrier has been replaced. Peer denials only end
    /// the tunnel once this is nonzero: a tunnel that never lost its first
    /// connection behaves exactly as an unsupervised one there.
    generation: u32,
    pacer: Pacer<StdRng>,
    budget: Budget,
    /// Control pumps of superseded connections, kept so an old connection
    /// that comes back keeps being answered. Aborted with the supervisor.
    old_pumps: Vec<AbortOnDrop>,
    /// Tells the accept-hold gate when an attempt runs or starts next.
    hold: Option<HoldSignal>,
    /// The registration a `-R` tunnel keeps on the peer.
    remote: Option<RemoteTunnel>,
}

impl Supervisor {
    fn new(wiring: Wiring, params: Params) -> Self {
        let Wiring {
            view: _,
            tx,
            watch,
            denied_rx,
            changed_rx,
            initial,
            hold,
        } = wiring;
        let backoff = Backoff::new(StdRng::from_rng(&mut rand::rng()));
        let pacer = Pacer::new(backoff, wake::subscribe());
        let budget = Budget::new(params.total, Instant::now());
        Self {
            params,
            tx,
            watch,
            denied_rx,
            changed_rx,
            current: initial,
            generation: 0,
            pacer,
            budget,
            old_pumps: Vec::new(),
            hold,
            remote: None,
        }
    }

    /// An attempt is running or about to (accept-hold, decision 19).
    fn hold_attempting(&self) {
        if let Some(hold) = &self.hold {
            hold.attempting();
        }
    }

    fn line(&self, kind: &'static str) -> Line<'_> {
        Line {
            supervise: kind,
            at: crate::config::now_rfc3339(),
            tunnel_id: &self.params.tunnel_id,
            mode: self.params.mode,
            route: self.params.route.label(),
            host: self.route_host(),
            cause: None,
            attempt: None,
            code: None,
            outage_ms: None,
            slept_ms: None,
            generation: None,
            previous_tunnel_id: None,
        }
    }

    /// The host alias a reverse route's lines carry.
    fn route_host(&self) -> Option<&str> {
        match &self.params.route {
            Route::Forward { .. } => None,
            #[cfg(unix)]
            Route::Reverse(route) => Some(route.alias.as_str()),
        }
    }

    fn emit(line: &Line<'_>) {
        let json = serde_json::to_string(line).unwrap_or_else(|_| "{}".to_string());
        tracing::info!(target: TARGET, "{}", json);
    }

    fn outage_ms(&self) -> u64 {
        millis(self.budget.outage(Instant::now()))
    }

    async fn run(mut self, first: Session) -> SuperviseEnd {
        let mut session = first;
        loop {
            let ended = self.monitor(session).await;
            if let Some(remote) = &self.remote {
                remote.clear_pump();
            }
            match ended {
                Ended::Fatal(err) => return SuperviseEnd::Failed(self.give_up(err)),
                Ended::Closed => {
                    Self::emit(&self.line("closed"));
                    return SuperviseEnd::Closed;
                }
                Ended::Lost(cause) => {
                    let now = Instant::now();
                    if self.budget.lost(now) {
                        self.pacer.backoff_mut().reset();
                    }
                    self.pacer.backoff_mut().lost(now);
                    // Before anything slow: new connections are refused, not
                    // queued, from this instant (decision 5). An accept-hold
                    // window opens with it, and first, so that no connection
                    // sees "down" without also seeing an attempt coming.
                    self.hold_attempting();
                    let _ = self.tx.send(CarrierState::Disconnected);
                    let mut line = self.line("lost");
                    line.cause = cause;
                    Self::emit(&line);
                    match self.reestablish().await {
                        Ok(next) => session = next,
                        Err(err) => return SuperviseEnd::Failed(self.give_up(err)),
                    }
                }
            }
        }
    }

    /// The tunnel is over: say so on the diagnostic channel and hand the
    /// error back for the caller to render.
    fn give_up(&self, err: OpError) -> OpError {
        let code = err.code.to_string();
        let mut line = self.line("gave_up");
        line.code = Some(&code);
        line.outage_ms = Some(self.outage_ms());
        Self::emit(&line);
        err
    }

    /// Watch the current carrier until it is lost, or until a fatal answer.
    async fn monitor(&mut self, session: Session) -> Ended {
        let link = match &self.params.route {
            Route::Forward { link, .. } => link.clone(),
            #[cfg(unix)]
            Route::Reverse(_) => return self.monitor_reverse(session).await,
        };
        self.monitor_forward(session, link).await
    }

    /// A peer `PERMISSION_DENIED` ends a tunnel that has already been
    /// re-established (decision 9); a first-connection denial behaves as it
    /// does without `--supervise`.
    fn denial_ends_the_tunnel(&self, denied: &Arc<ForwardCarrier>) -> bool {
        self.generation > 0 && Arc::ptr_eq(denied, &self.current)
    }

    /// [`Self::monitor`] on the forward route: a `PathWatch` over the
    /// control stream of the current connection.
    async fn monitor_forward(&mut self, session: Session, link: Link) -> Ended {
        enum Step {
            /// The watchdog declared the path dead.
            Dead,
            /// The control stream ended.
            PumpGone,
            /// Nothing to act on; look again.
            Again,
        }
        let connection = link.connection();
        let probes = Arc::new(Notify::new());
        self.watch.revive();
        let mut pump = tokio::spawn(control_pump(
            session,
            self.watch.clone(),
            Arc::clone(&probes),
            self.remote.as_mut().map(RemoteTunnel::pump_channel),
        ));
        let mut wake_log = wake::subscribe();
        let mut denied_open = true;
        loop {
            let dog = AbortOnDrop(tokio::spawn(watch_path_with_wake(
                connection.clone(),
                self.watch.clone(),
                Arc::clone(&probes),
                wake::subscribe(),
            )));
            let step = loop {
                let step = tokio::select! {
                    () = self.watch.dead() => Step::Dead,
                    _ = &mut pump => Step::PumpGone,
                    denied = async {
                        if denied_open {
                            self.denied_rx.recv().await
                        } else {
                            std::future::pending().await
                        }
                    } => {
                        match denied {
                            Some(carrier) => {
                                if self.denial_ends_the_tunnel(&carrier) {
                                    return Ended::Fatal(permission_denied());
                                }
                            }
                            None => denied_open = false,
                        }
                        Step::Again
                    }
                    changed = wake_log.changed() => {
                        if changed.is_ok() {
                            let event = *wake_log.borrow_and_update();
                            self.log_wake(event);
                        }
                        Step::Again
                    }
                };
                if !matches!(step, Step::Again) {
                    break step;
                }
            };
            drop(dog);
            match step {
                Step::Dead => {
                    if self.try_migrate(&link, &probes).await {
                        continue;
                    }
                    // Kept answering on its own so an old connection that
                    // comes back is not starved (decision 5).
                    self.old_pumps.retain(|p| !p.0.is_finished());
                    self.old_pumps.push(AbortOnDrop(pump));
                }
                Step::PumpGone | Step::Again => {}
            }
            return Ended::Lost(Some(cause_of(&connection)));
        }
    }

    /// Decision 4: after a death verdict, one cheap try to keep the same
    /// connection alive by moving to a new local socket.
    async fn try_migrate(&mut self, link: &Link, probes: &Arc<Notify>) -> bool {
        if !self.params.recovery.migration {
            return false;
        }
        let endpoint = link.endpoint();
        if PathBinder::rebind(&endpoint).is_err() {
            return false;
        }
        let rtt = link.connection().quinn().stats().path.rtt;
        if probe_alive(&self.watch, probes, rtt).await {
            self.watch.revive();
            true
        } else {
            false
        }
    }

    fn log_wake(&self, event: WakeEvent) {
        let mut line = self.line("wake");
        line.slept_ms = Some(event.slept_ms);
        Self::emit(&line);
    }

    /// Attempt until a carrier is back or the tunnel must end.
    async fn reestablish(&mut self) -> Result<Session, OpError> {
        let mut attempt: u32 = 0;
        let mut last: Option<OpError> = None;
        loop {
            if self.budget.exhausted(Instant::now()) {
                return Err(last.unwrap_or_else(|| {
                    OpError::new(
                        ErrorCode::ConnectionFailed,
                        "the tunnel's connection was lost and the supervise budget is spent",
                    )
                }));
            }
            self.budget.note_attempt();
            attempt += 1;
            self.hold_attempting();
            let attempted = match self.attempt().await {
                Ok(mut next) => match self.reissue(&mut next).await {
                    Ok(reissued) => Ok((next, reissued)),
                    Err(err) => {
                        Self::discard(next);
                        Err(err)
                    }
                },
                Err(err) => Err(err),
            };
            match attempted {
                Ok((next, reissued)) => return Ok(self.install(next, reissued)),
                Err(err) => {
                    if classify(err.source, &err.op.code, err.op.retryable) == Disposition::Stop {
                        return Err(err.op);
                    }
                    if err.cause == Some(ReconnectCause::Refused) {
                        self.pacer.backoff_mut().refused();
                    }
                    let code = err.op.code.to_string();
                    let mut line = self.line("retry");
                    line.cause = err.cause.map(ReconnectCause::as_str);
                    line.attempt = Some(attempt);
                    line.code = Some(&code);
                    line.outage_ms = Some(self.outage_ms());
                    Self::emit(&line);
                    last = Some(err.op);
                }
            }
            let remaining = self.budget.remaining(Instant::now());
            let hold = self.hold.as_ref();
            let waited = tokio::select! {
                waited = self.pacer.wait_planned(|delay| {
                    if let Some(hold) = hold {
                        hold.next_in(delay);
                    }
                }) => waited,
                () = tokio::time::sleep(remaining) => {
                    return Err(last.unwrap_or_else(|| {
                        OpError::new(
                            ErrorCode::ConnectionFailed,
                            "the tunnel's connection was lost and the supervise budget is spent",
                        )
                    }));
                }
            };
            if let Waited::Woken(event) = waited {
                self.log_wake(event);
                self.budget.note_wake();
            }
        }
    }

    /// Swap the new carrier in and open the gate (decision 5).
    fn install(&mut self, next: Established, reissued: Option<remote::Reissued>) -> Session {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut generation = None;
        #[cfg_attr(not(unix), allow(irrefutable_let_patterns))]
        let (carrier, session) = match next {
            Established::Forward {
                endpoint,
                connection,
                session,
            } => {
                if let Route::Forward { link, .. } = &self.params.route {
                    // The old pair is dropped, not closed: connections a
                    // splice still rides keep working until they end on
                    // their own.
                    let _old = link.replace(endpoint, connection.clone());
                }
                (ForwardCarrier::Quic(connection), session)
            }
            #[cfg(unix)]
            Established::Reverse(next) => {
                generation = Some(next.generation);
                self.install_reverse(next)
            }
        };
        let carrier = Arc::new(carrier);
        self.current = Arc::clone(&carrier);
        self.generation = self.generation.saturating_add(1);
        self.budget.reestablished(Instant::now());
        let _ = self.tx.send(CarrierState::Live(carrier));
        if let Some(hold) = &self.hold {
            hold.idle();
        }
        let previous = reissued.and_then(|reissued| self.adopt(reissued));
        let mut line = self.line("reestablished");
        line.outage_ms = Some(self.outage_ms());
        line.generation = generation;
        line.previous_tunnel_id = previous.as_deref();
        Self::emit(&line);
        session
    }

    /// A carrier that was dialed but could not be used: close it so the
    /// peer does not keep a connection nobody reads.
    fn discard(next: Established) {
        match next {
            Established::Forward { connection, .. } => connection.close(0, b"done"),
            #[cfg(unix)]
            Established::Reverse(_) => {}
        }
    }

    /// One attempt to get a verified carrier back.
    async fn attempt(&self) -> Result<Established, AttemptError> {
        match &self.params.route {
            Route::Forward { target, .. } => self.attempt_forward(target).await,
            #[cfg(unix)]
            Route::Reverse(route) => self.attempt_reverse(route).await,
        }
    }

    /// One dial plus the two identity checks, bounded by [`REDIAL_DEADLINE`].
    async fn attempt_forward(&self, target: &PeerTarget) -> Result<Established, AttemptError> {
        let (endpoint, connection, session) =
            match tokio::time::timeout(REDIAL_DEADLINE, dial(target, self.params.tuning)).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(AttemptError::dial(
                        OpError::new(
                            ErrorCode::ConnectionFailed,
                            "no response from the peer within the redial deadline",
                        ),
                        ReconnectCause::DialTimeout,
                    ));
                }
            };
        let seen = connection.peer_fingerprint().map(|fp| fp.to_string());
        if seen.as_deref() != Some(self.params.fingerprint.as_str()) {
            connection.close(0, b"peer changed");
            return Err(AttemptError::check(OpError::new(
                ErrorCode::AuthFailed,
                "the peer at this address is no longer the one the tunnel was opened to",
            )));
        }
        if self.params.require_dial_filter
            && !session
                .capabilities
                .iter()
                .any(|c| c == wire::CAP_DIAL_FILTER_V1)
        {
            connection.close(0, b"capability");
            return Err(AttemptError::check(
                super::dynamic_forward_capability_unsupported(),
            ));
        }
        Ok(Established::Forward {
            endpoint,
            connection,
            session,
        })
    }
}

/// Dial and negotiate. The same steps as `dial_peer`, keeping the failure's
/// kind so the retry line can name it (decision 12).
async fn dial(
    target: &PeerTarget,
    tuning: qsh_transport::TransportTuning,
) -> Result<(qsh_transport::Endpoint, qsh_transport::Connection, Session), AttemptError> {
    let device_name = target.identity.identity.device_id.clone();
    let dialer = qsh_transport::Dialer::new(
        target.identity.local.clone(),
        target.trust.clone() as Arc<dyn qsh_transport::TrustEvaluator>,
    )
    .with_tuning(tuning);
    let address = target.address.clone();
    let addrs = crate::ops::resolve_all(&address)
        .await
        .map_err(|op| AttemptError::dial(op, ReconnectCause::Resolve))?;
    let dialed =
        crate::ops::dial_first_reachable(&addrs, |addr| dialer.dial(addr, &target.server_name))
            .await
            .map_err(|(err, attempted)| {
                let cause = cause_of_dial_error(&err);
                AttemptError::dial(map_dial_error(err, &address, attempted), cause)
            })?;
    let endpoint = dialed.endpoint.clone();
    let connection = dialed.connection.clone();
    match Session::negotiate(dialed.connection, &device_name).await {
        Ok(session) => Ok((endpoint, connection, session)),
        Err(err) => {
            connection.close(0, b"done");
            Err(AttemptError {
                op: map_client_error(err),
                source: Source::Peer,
                cause: None,
            })
        }
    }
}

/// The `cause` word for a failed dial (decision 12's mapping).
fn cause_of_dial_error(err: &qsh_transport::DialError) -> ReconnectCause {
    use qsh_transport::DialError;
    match err {
        DialError::Timeout(_) => ReconnectCause::DialTimeout,
        DialError::LocalRejected { .. } | DialError::RemoteRejected => ReconnectCause::TlsRejected,
        DialError::Refused | DialError::Connect(_) => ReconnectCause::Refused,
        DialError::Failed(inner) => {
            if qsh_transport::endpoint::is_crypto_failure(inner) {
                ReconnectCause::TlsRejected
            } else {
                ReconnectCause::Refused
            }
        }
        DialError::Setup(_) => ReconnectCause::Local,
    }
}

/// The `cause` word for a lost carrier: whatever the connection itself says,
/// else the watchdog's verdict.
fn cause_of(connection: &qsh_transport::Connection) -> &'static str {
    match connection.close_reason() {
        Some(err) => classify_connection_error(&err).as_str(),
        None => ReconnectCause::PathDead.as_str(),
    }
}

fn permission_denied() -> OpError {
    OpError::new(
        ErrorCode::PermissionDenied,
        "the peer's access policy no longer allows this forward; it changes only when the peer \
         restarts with a different acl.toml",
    )
}

/// Sole owner of one connection's control stream: sends the liveness pings
/// the watchdog asks for and feeds every answer to it.
///
/// A `-R` tunnel's pump also carries the holder's parting `RemoteForwardClose`
/// (decision 11): only the owner of the stream can send on it.
async fn control_pump(
    mut session: Session,
    watch: PathWatch,
    probes: Arc<Notify>,
    mut cmds: Option<mpsc::UnboundedReceiver<remote::PumpCmd>>,
) {
    loop {
        tokio::select! {
            biased;
            () = probes.notified() => {
                if session.send_ping().await.is_err() {
                    return;
                }
            }
            cmd = async {
                match &mut cmds {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => match cmd {
                Some(remote::PumpCmd::Close { forward_id, done }) => {
                    let _ = session.rfwd_close(wire::RemoteForwardClose { forward_id }).await;
                    let _ = done.send(());
                }
                None => cmds = None,
            },
            message = session.next_control() => match message {
                Ok(Some(ControlIn::Pong)) => watch.inbound(),
                Ok(Some(ControlIn::Ping { request_id })) => {
                    watch.inbound();
                    if session.send_pong(request_id).await.is_err() {
                        return;
                    }
                }
                Ok(Some(ControlIn::Request { request_id })) => {
                    watch.traffic();
                    if session.reject_unsupported(request_id).await.is_err() {
                        return;
                    }
                }
                Ok(Some(ControlIn::Event(_))) => watch.traffic(),
                Ok(None) | Err(_) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests;
