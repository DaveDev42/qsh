//! The `-R` half of the supervisor (ADR-0023 decisions 7-4, 11, 13 and 14).
//!
//! A `-R` tunnel has no local listener to keep. What the supervisor keeps
//! is a registration on the peer, and a registration dies with the
//! connection that made it. Getting one back means asking again on the
//! new carrier: close the old `forward_id`, open the same bind again, and
//! point a fresh acceptor at the new `forward_id`. Every step goes through
//! the peer's choke point like the first open did (decision 8).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_proto::{ErrorCode, wire};
use tokio::sync::{mpsc, oneshot};

use super::{AttemptError, Established, Route, Supervisor};
use crate::client::ClientError;
use crate::ops::exec::map_client_error;
use crate::tunnel::remote::RemoteForwardAcceptor;
use crate::tunnel::supervise::classify::Source;

/// How many times a re-open that lost its bind race with the close it just
/// sent is sent again (decision 7-4). An old peer answers the close before
/// its listener is actually gone; one that has decision 16's fix never
/// needs this.
const BIND_RETRIES: u32 = 3;

/// The gap between those re-sends, on the tokio clock.
const BIND_RETRY_INTERVAL: Duration = Duration::from_millis(200);

/// How long the close-then-open on a fresh carrier may take in all. The
/// peer answers from memory and a single bind, so this only bounds a peer
/// that accepted the connection and then stopped answering; the attempt
/// then counts as a transient failure and the next one dials again.
const REISSUE_DEADLINE: Duration = Duration::from_secs(10);

/// The most a shutdown waits for the peer to acknowledge the close it is
/// sent (decision 11).
const SIGNAL_CLOSE_WAIT: Duration = Duration::from_secs(1);

/// A request for the task that owns the control stream.
pub(super) enum PumpCmd {
    Close {
        forward_id: String,
        done: oneshot::Sender<()>,
    },
}

/// What the tunnel's holder can reach while the supervisor runs.
struct Shared {
    /// The `forward_id` the peer currently knows the tunnel by.
    forward_id: Mutex<String>,
    /// The command channel of the control pump of the live carrier; empty
    /// while the tunnel is disconnected.
    pump: Mutex<Option<mpsc::UnboundedSender<PumpCmd>>>,
}

/// The holder's end: enough to say goodbye to the peer on a shutdown.
#[derive(Clone)]
pub(in crate::ops::tunnel) struct RemoteHandle(Arc<Shared>);

impl RemoteHandle {
    /// Ask the peer to close the current registration over the live
    /// carrier, if there is one, waiting at most [`SIGNAL_CLOSE_WAIT`].
    /// Best effort: every failure is swallowed.
    pub(in crate::ops::tunnel) async fn close_best_effort(&self) {
        let pump = self
            .0
            .pump
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(pump) = pump else {
            return;
        };
        let forward_id = self
            .0
            .forward_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (done, wait) = oneshot::channel();
        if pump.send(PumpCmd::Close { forward_id, done }).is_err() {
            return;
        }
        let _ = tokio::time::timeout(SIGNAL_CLOSE_WAIT, wait).await;
    }
}

/// The supervisor's `-R` state: the registration it keeps, and what it
/// needs to ask for the same one again.
pub(in crate::ops::tunnel) struct RemoteTunnel {
    /// Dispatches the current registration's `TCP_ACCEPTED` streams.
    acceptor: RemoteForwardAcceptor,
    /// The first open's request with `bind_port` set to the port it got,
    /// so a tunnel opened on port 0 asks for the same port again.
    open: wire::RemoteForwardOpen,
    /// Where this machine dials each accepted connection.
    target_host: String,
    target_port: u16,
    /// The registration's current id.
    forward_id: String,
    /// Claim loops that found their forward gone (reverse route only).
    vanished: Option<mpsc::UnboundedReceiver<String>>,
    shared: Arc<Shared>,
    /// The command channel of the first carrier, made with the tunnel so a
    /// shutdown that arrives before the supervisor has started monitoring
    /// still reaches the peer.
    first_pump: Option<mpsc::UnboundedReceiver<PumpCmd>>,
}

impl RemoteTunnel {
    /// Take over the registration the first open made. `open` is the
    /// request that made it and `opened` the peer's answer.
    pub(in crate::ops::tunnel) fn new(
        acceptor: RemoteForwardAcceptor,
        mut open: wire::RemoteForwardOpen,
        opened: &wire::RemoteForwardOpened,
        vanished: Option<mpsc::UnboundedReceiver<String>>,
    ) -> (Self, RemoteHandle) {
        let target_host = open.forward_host.clone();
        let target_port = u16::try_from(open.forward_port).unwrap_or(u16::MAX);
        open.bind_port = opened.actual_port;
        open.claim_token = Vec::new();
        let (pump_tx, first_pump) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            forward_id: Mutex::new(opened.forward_id.clone()),
            pump: Mutex::new(Some(pump_tx)),
        });
        let handle = RemoteHandle(Arc::clone(&shared));
        (
            Self {
                acceptor,
                open,
                target_host,
                target_port,
                forward_id: opened.forward_id.clone(),
                vanished,
                shared,
                first_pump: Some(first_pump),
            },
            handle,
        )
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) fn forward_id(&self) -> &str {
        &self.forward_id
    }

    /// A fresh command channel for the control pump of a newly monitored
    /// carrier.
    pub(super) fn pump_channel(&mut self) -> mpsc::UnboundedReceiver<PumpCmd> {
        if let Some(first) = self.first_pump.take() {
            return first;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        *self.shared.pump.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        rx
    }

    /// The carrier is gone; nobody can be asked anything over it.
    pub(super) fn clear_pump(&self) {
        *self.shared.pump.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// The next claim loop that found its forward gone, if this route
    /// reports them.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) async fn vanished(&mut self) -> Option<String> {
        match &mut self.vanished {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }

    /// Stop listening for a channel that has closed.
    #[cfg(unix)]
    pub(super) fn stop_watching_vanished(&mut self) {
        self.vanished = None;
    }
}

/// A registration made on a new carrier, not yet installed.
pub(super) struct Reissued {
    acceptor: RemoteForwardAcceptor,
    forward_id: String,
    vanished: Option<mpsc::UnboundedReceiver<String>>,
}

impl Supervisor {
    /// Decision 7-4: on the new carrier, close the old registration and
    /// open the same one again. `Ok(None)` for a tunnel that is not `-R`.
    pub(super) async fn reissue(
        &self,
        next: &mut Established,
    ) -> Result<Option<Reissued>, AttemptError> {
        let Some(remote) = &self.remote else {
            return Ok(None);
        };
        match tokio::time::timeout(REISSUE_DEADLINE, self.reissue_on(remote, next)).await {
            Ok(result) => result.map(Some),
            Err(_) => Err(self.transient("the peer did not answer the re-opened forward in time")),
        }
    }

    async fn reissue_on(
        &self,
        remote: &RemoteTunnel,
        next: &mut Established,
    ) -> Result<Reissued, AttemptError> {
        let (acceptor, vanished) = self.new_acceptor(next).await;
        let session = next.session_mut();
        // The old registration usually died with its connection, and a
        // peer that has already forgotten it says so. Both outcomes mean
        // the same thing: it is gone.
        let closed = session
            .rfwd_close(wire::RemoteForwardClose {
                forward_id: remote.forward_id.clone(),
            })
            .await;
        match closed {
            Ok(()) => {}
            Err(ClientError::Remote {
                code: ErrorCode::InvalidArgument,
                ..
            }) => {}
            Err(err) => return Err(self.request_failed(err)),
        }
        let mut open = remote.open.clone();
        open.claim_token = acceptor
            .claim_token()
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let mut resent = 0;
        let opened = loop {
            match session.rfwd_open(open.clone()).await {
                Ok(opened) => break opened,
                // The close was answered, yet the bind still fails: an
                // older peer whose listener is not gone yet. Only this
                // answer is worth re-sending; once the tries are spent the
                // port belongs to someone else.
                Err(ClientError::Remote {
                    code: ErrorCode::ConnectionFailed,
                    ..
                }) if resent < BIND_RETRIES => {
                    resent += 1;
                    tokio::time::sleep(BIND_RETRY_INTERVAL).await;
                }
                Err(err) => return Err(self.request_failed(err)),
            }
        };
        acceptor.register(
            opened.forward_id.clone(),
            remote.target_host.clone(),
            remote.target_port,
        );
        Ok(Reissued {
            acceptor,
            forward_id: opened.forward_id,
            vanished,
        })
    }

    /// The acceptor for a new carrier.
    async fn new_acceptor(
        &self,
        next: &Established,
    ) -> (
        RemoteForwardAcceptor,
        Option<mpsc::UnboundedReceiver<String>>,
    ) {
        match next {
            Established::Forward { connection, .. } => {
                (RemoteForwardAcceptor::spawn(connection.clone()).await, None)
            }
            #[cfg(unix)]
            Established::Reverse(next) => {
                let host = match &self.params.route {
                    Route::Reverse(route) => route.host.clone(),
                    Route::Forward { .. } => String::new(),
                };
                let (tx, rx) = mpsc::unbounded_channel();
                let acceptor = RemoteForwardAcceptor::spawn_reverse_watching(
                    next.socket.clone(),
                    host,
                    Some(tx),
                )
                .await;
                (acceptor, Some(rx))
            }
        }
    }

    /// A request on the fresh carrier failed. A peer's answer is
    /// classified by its code and `retryable`; a carrier that broke under
    /// the request is an ordinary lost attempt.
    fn request_failed(&self, err: ClientError) -> AttemptError {
        match err {
            ClientError::Remote { .. } | ClientError::Protocol(_) | ClientError::Unsupported(_) => {
                AttemptError::peer(map_client_error(err))
            }
            other => {
                let op = map_client_error(other);
                self.transient(&op.message)
            }
        }
    }

    /// A failure the next attempt may not repeat: the carrier could not be
    /// used, through no answer of the peer's.
    fn transient(&self, what: &str) -> AttemptError {
        let op = crate::ops::OpError::new(ErrorCode::ConnectionFailed, what.to_string());
        let source = match &self.params.route {
            Route::Forward { .. } => Source::LocalDial,
            #[cfg(unix)]
            Route::Reverse(_) => Source::LocalDaemon,
        };
        AttemptError {
            op,
            source,
            cause: None,
        }
    }

    /// Make the new registration the current one: the old acceptor goes
    /// (connections it already relays drain on their own), and the id the
    /// tunnel is known by changes (decision 13). Returns the id it had.
    pub(super) fn adopt(&mut self, reissued: Reissued) -> Option<String> {
        let remote = self.remote.as_mut()?;
        let Reissued {
            acceptor,
            forward_id,
            vanished,
        } = reissued;
        remote.acceptor = acceptor;
        remote.vanished = vanished;
        let previous = std::mem::replace(&mut remote.forward_id, forward_id.clone());
        *remote
            .shared
            .forward_id
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = forward_id.clone();
        self.params.tunnel_id = forward_id;
        Some(previous)
    }
}

/// Source used for failures classified by the peer's own answer.
impl AttemptError {
    fn peer(op: crate::ops::OpError) -> Self {
        Self {
            op,
            source: Source::Peer,
            cause: None,
        }
    }
}
