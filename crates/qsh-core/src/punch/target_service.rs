//! End B's service: what a target keeps to answer `PunchOffer` and
//! `RendezvousQuery` (ADR-0054 decisions 6, 10, 11, 14). The wire handlers
//! live in `server::punch`; this holds the state they share: the punching
//! endpoint, the per-initiator rate table, the open windows and the
//! rendezvous fingerprints.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use qsh_proto::punch::{AttemptId, MAX_RENDEZVOUS_FINGERPRINTS};
use qsh_transport::{Connection, Fingerprint, Principal, PunchEndpoint, TrustEvaluator};

use super::addrs::{LocalAddrs, host_candidates};
use super::limits::{AttemptLimiter, LimitHit};
use super::{PUNCH_TARGET_WINDOW, TargetParams, TargetReport, run_target_in};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Why an offer opened no window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferRefusal {
    /// The initiator started `PUNCH_RATE` attempts in the last window.
    Rate,
    /// `MAX_PUNCH_WINDOWS` windows are open already.
    Windows,
}

#[derive(Default)]
struct Controllers {
    /// Controllers this process holds a live registration with.
    live: Vec<[u8; 32]>,
    /// Controllers `[serve].to` names, resolved to pins at start.
    configured: Vec<[u8; 32]>,
}

/// B's hole-punching state. One per `qsh serve --to` process, handed to the
/// [`Server`](crate::server::Server) with `set_punch_target`.
pub struct PunchTarget {
    endpoint: PunchEndpoint,
    evaluator: Arc<dyn TrustEvaluator>,
    local_addrs: Arc<dyn LocalAddrs>,
    window: Duration,
    enabled: bool,
    limiter: Mutex<AttemptLimiter>,
    /// Open windows by id and the initiator each one serves.
    open: Mutex<Vec<(u64, [u8; 32])>>,
    next_window: AtomicU64,
    controllers: Mutex<Controllers>,
}

impl std::fmt::Debug for PunchTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchTarget")
            .field("enabled", &self.enabled)
            .field("open_windows", &self.open_windows())
            .finish_non_exhaustive()
    }
}

impl PunchTarget {
    /// The service over `endpoint`, which must be the endpoint the
    /// registration connection is dialed from (the NAT mapping the window
    /// uses is that socket's).
    pub fn new(
        endpoint: PunchEndpoint,
        evaluator: Arc<dyn TrustEvaluator>,
        local_addrs: Arc<dyn LocalAddrs>,
    ) -> Self {
        Self {
            endpoint,
            evaluator,
            local_addrs,
            window: PUNCH_TARGET_WINDOW,
            enabled: true,
            limiter: Mutex::new(AttemptLimiter::new(false)),
            open: Mutex::new(Vec::new()),
            next_window: AtomicU64::new(1),
            controllers: Mutex::new(Controllers::default()),
        }
    }

    /// `[punch].mode = "off"`: the service answers `UNSUPPORTED`.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// A shorter or longer window than ADR-0054's six seconds, for tests.
    #[must_use]
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Whether offers and queries are served.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The punching endpoint (its counters tell a test that nothing was
    /// opened or sent).
    pub fn endpoint(&self) -> &PunchEndpoint {
        &self.endpoint
    }

    /// Windows open now.
    pub fn open_windows(&self) -> usize {
        lock(&self.open).len()
    }

    /// The principal this host's trust store gives the key `fingerprint`, if
    /// the key is pinned. The offer's initiator is judged as this principal
    /// (ADR-0054 decision 6).
    pub fn pinned_principal(&self, fingerprint: &[u8; 32]) -> Option<Principal> {
        self.evaluator
            .lookup_pin(&Fingerprint::from_bytes(*fingerprint))
    }

    /// Records that this process holds a live registration with `controller`.
    pub fn note_registered(&self, controller: [u8; 32]) {
        let mut c = lock(&self.controllers);
        c.live.retain(|f| *f != controller);
        c.live.insert(0, controller);
    }

    /// The registration with `controller` ended.
    pub fn note_lost(&self, controller: &[u8; 32]) {
        lock(&self.controllers).live.retain(|f| f != controller);
    }

    /// The controllers `[serve].to` names, as pinned fingerprints.
    pub fn set_configured(&self, controllers: Vec<[u8; 32]>) {
        lock(&self.controllers).configured = controllers;
    }

    /// The fingerprints a `RendezvousList` carries: live registrations first,
    /// then configured ones, no duplicates, at most
    /// [`MAX_RENDEZVOUS_FINGERPRINTS`].
    pub fn rendezvous_fingerprints(&self) -> Vec<[u8; 32]> {
        let c = lock(&self.controllers);
        let mut out: Vec<[u8; 32]> = Vec::new();
        for fp in c.live.iter().chain(c.configured.iter()) {
            if !out.contains(fp) {
                out.push(*fp);
            }
        }
        out.truncate(MAX_RENDEZVOUS_FINGERPRINTS);
        out
    }

    /// Whether a window for `initiator` is open now. A connection that
    /// completed its handshake is served only if this holds (ADR-0054
    /// decision 12); with several windows open, an Initial may be accepted
    /// by any window's loop, so the question is asked of all of them.
    pub fn has_window_for(&self, initiator: &[u8; 32]) -> bool {
        lock(&self.open).iter().any(|(_, fp)| fp == initiator)
    }

    /// Counts an attempt of `initiator` against the rate limit.
    fn admit(&self, initiator: &[u8; 32]) -> Result<(), OfferRefusal> {
        lock(&self.limiter)
            .try_begin(initiator, Instant::now())
            .map_err(|hit| match hit {
                LimitHit::Rate | LimitHit::InFlight => OfferRefusal::Rate,
            })
    }

    /// Opens a window for one offer and starts the schedule. Returns the host
    /// candidates to answer with. Nothing is opened (and nothing sent) when
    /// the rate limit or the window cap says no. `on_connection` receives
    /// every verified inbound connection the window accepts; the caller
    /// checks it against [`Self::has_window_for`].
    pub fn open_offer(
        self: &Arc<Self>,
        attempt_id: AttemptId,
        initiator: [u8; 32],
        candidates: Vec<SocketAddr>,
        on_connection: impl FnMut(Connection) + Send + 'static,
    ) -> Result<Vec<SocketAddr>, OfferRefusal> {
        self.admit(&initiator)?;
        let Some(window) = self.endpoint.open_window() else {
            return Err(OfferRefusal::Windows);
        };
        let port = self.endpoint.local_addr().map_or(0, |a| a.port());
        let answer = host_candidates(&self.local_addrs.observe(), port);

        let id = self.next_window.fetch_add(1, Ordering::Relaxed);
        lock(&self.open).push((id, initiator));
        let this = self.clone();
        let params = TargetParams {
            attempt_id,
            candidates,
            window: self.window,
        };
        tokio::spawn(async move {
            let _guard = OpenGuard { target: &this, id };
            let report = run_target_in(&this.endpoint, window, &params, on_connection).await;
            log_window_closed(&report);
        });
        tracing::info!(
            target: "qsh::punch",
            event = "window_opened",
            answer_candidates = answer.len(),
            "punch window opened"
        );
        Ok(answer)
    }
}

struct OpenGuard<'a> {
    target: &'a PunchTarget,
    id: u64,
}

impl Drop for OpenGuard<'_> {
    fn drop(&mut self) {
        lock(&self.target.open).retain(|(id, _)| *id != self.id);
    }
}

fn log_window_closed(report: &TargetReport) {
    tracing::info!(
        target: "qsh::punch",
        event = "window_closed",
        punches_sent = report.punches_sent,
        punches_heard = report.punches_heard,
        handshakes = report.handshakes,
        connections = report.connections,
        refused = report.refused,
        failed = report.failed,
        "punch window closed"
    );
}
