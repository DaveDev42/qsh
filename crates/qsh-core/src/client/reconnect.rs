//! Surviving a dead path: active migration, re-dial + resume, and the
//! bookkeeping that makes the stitched stream indistinguishable from one
//! that never broke (`docs/design/protocol.md` §2, §10).
//!
//! The division of labour is the load-bearing idea:
//!
//! - **Migration is a latency optimization.** When only the local address
//!   changed, rebinding the endpoint lets QUIC carry the same connection
//!   over the new path — no handshake, no replay, nothing to stitch. It is
//!   attempted first because it is cheap, and **nothing here depends on it
//!   succeeding**: every caller falls through to resume, and the tests
//!   cover the resume path with migration disabled entirely.
//! - **Resume is the correctness path.** A new connection, a
//!   `session.attach` carrying the resume credential and `last_output_seq`,
//!   replay from exactly that offset, and retransmission of the input the
//!   host never acked.
//!
//! Two small pieces of state make the stitch safe:
//!
//! - [`OutputCursor`] drops (or trims) anything at or below the offset we
//!   already delivered. The host is supposed to replay from exactly `L`,
//!   so this is defence in depth — a host that replays generously, or a
//!   racing frame from the old connection, must not produce a doubled
//!   line on the user's terminal.
//! - [`PendingInput`] keeps the un-acked input tail, capped at
//!   [`UNACKED_INPUT_MAX`]. Exceeding the cap is an **error**, not silent
//!   buffering: input that cannot be replayed after a break is input the
//!   user believes they typed and the shell never saw.
//!
//! The whole recovery runs under a deadline ([`REDIAL_DEADLINE`] on the
//! forward route, which redials the peer itself; a route-supplied,
//! possibly wider bound on any route whose reconnect step waits on
//! something other than its own dial — see `Reconnect::attempt_deadline`).
//! That bound is the difference between "qsh recovered" and "QUIC's 45 s
//! idle timeout eventually fired and something reconnected" —
//! `docs/design/testing.md` L4 defines the latter as a failure, so it is
//! enforced here in code
//! rather than described in a comment.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use thiserror::Error;

use crate::client::{AttachEvent, ClientError};
use crate::telemetry::{Recovery, RecoveryReport, RecoveryTimer};

/// How long a recovery may take, measured from the moment the path is
/// declared dead to the moment bytes flow again.
///
/// Two seconds is the criterion `docs/design/testing.md` L4 and
/// M2 plan Step 7 (2473c88) fix in advance so SC3 cannot be passed by accident: quinn's
/// idle timeout is 45 s, so anything that waits for the connection to time
/// out on its own is an order of magnitude outside this and is classified
/// [`Recovery::Failed`].
pub const REDIAL_DEADLINE: Duration = Duration::from_secs(2);

/// Ceiling on input sent but not yet acknowledged by the host.
///
/// A recovery has to be able to retransmit everything the host has not
/// applied, so the retransmit buffer bounds how much input can be in
/// flight. 64 KiB is far beyond what interactive typing produces and still
/// small enough that a paste into a wedged session fails loudly instead of
/// growing without limit.
pub const UNACKED_INPUT_MAX: usize = 64 * 1024;

/// Why a recovery could not be completed.
#[derive(Debug, Error)]
pub enum ResumeError {
    /// More input is outstanding than [`UNACKED_INPUT_MAX`] allows. The
    /// session is not silently degraded: the caller surfaces this, because
    /// the alternative is dropping keystrokes the user believes landed.
    #[error("un-acked input reached {unacked} bytes (limit {UNACKED_INPUT_MAX})")]
    UnackedInputOverflow {
        /// Bytes outstanding when the limit was hit.
        unacked: usize,
    },
    /// The host resumed at an input offset older than the oldest byte we
    /// still hold, so the gap cannot be retransmitted. Fail closed rather
    /// than feed the shell a hole.
    #[error("host resumed input at {applied} but the oldest byte held is {oldest}")]
    InputUnrecoverable {
        /// Offset the host says it has applied.
        applied: u64,
        /// Oldest offset still retransmittable.
        oldest: u64,
    },
    /// Neither migration nor re-dial finished inside the attempt's
    /// deadline ([`REDIAL_DEADLINE`] on the forward route,
    /// [`Reconnect::attempt_deadline`]'s override on the reverse route).
    /// Carries the deadline that was actually applied so the message
    /// (`map_resume_error`, `crate::ops::session`) reports what really
    /// happened rather than always naming [`REDIAL_DEADLINE`] even on a
    /// route that waited far longer than that by design.
    #[error("recovery exceeded the {} ms deadline", .0.as_millis())]
    Deadline(Duration),
    /// The re-dial or the `session.attach` itself failed.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// The rebuild failed for a local reason rather than a wire one — the
    /// resume credential could not be read back, or its successor could
    /// not be made durable. Carried verbatim so the frontend sees the same
    /// error code it would have seen from a first attach.
    #[error(transparent)]
    Local(#[from] crate::ops::OpError),
}

/// The endpoint-level operation migration needs: move the local socket to
/// a fresh ephemeral port so QUIC can advertise the new path.
///
/// A trait rather than a concrete `Endpoint` for one reason: the recovery
/// driver's tests must be able to run the migration branch — including the
/// branch where migration fails — without a real interface change.
pub trait PathBinder: Send + Sync {
    /// Bind a fresh local socket and hand it to the endpoint, returning
    /// the new local address.
    fn rebind(&self) -> io::Result<SocketAddr>;
}

impl PathBinder for qsh_transport::Endpoint {
    fn rebind(&self) -> io::Result<SocketAddr> {
        self.rebind_ephemeral()
    }
}

/// What [`Reconnect::reconnect`] returns: a boxed, `Send` future producing
/// a fresh attach or the reason it could not be built.
pub type ReconnectFuture<'a> = Pin<
    Box<dyn Future<Output = Result<(super::Session, super::Attached), ResumeError>> + Send + 'a>,
>;

/// The one step in a recovery that the forward and reverse routes cannot
/// share: producing a fresh, resumed attach.
///
/// Everything else in a recovery — detecting the death, backing off
/// between attempts, the [`REDIAL_DEADLINE`] budget, and the
/// `qsh::recovery` telemetry — is identical for both routes and lives in
/// [`recover`]. What differs is *how* a new `(Session, Attached)` pair
/// resumed at `last_output_seq` gets built: the forward route dials the
/// peer itself (`DialReconnect`, `crate::ops::session`), the reverse route
/// has no dial of its own to make and instead waits for the target to
/// re-register with the daemon (`LocalReconnect`, added in a later step).
/// A trait — rather than a closure, as `recover` itself still takes for
/// the migration probe — because an implementation may need to carry
/// state across attempts (the forward route's in-flight redemption task,
/// which a timed-out attempt must be able to adopt rather than abandon:
/// see `spawn_reattach`'s doc for why that task can never simply be
/// dropped).
///
/// The `Send + Sync` bound and the boxed-future return (rather than an
/// `async fn`) are here because this trait is used as `&dyn Reconnect` —
/// `qsh-core` has no `async_trait` dependency, so a trait object requires
/// the desugaring done by hand.
pub trait Reconnect: Send + Sync {
    /// Whether a previous, uncompleted [`reconnect`](Reconnect::reconnect)
    /// call is still running and would be adopted rather than restarted by
    /// the next call.
    ///
    /// Used only to decide whether an attempt still has a "live leg" worth
    /// migration-probing: once a reconnect is in flight there is no leg
    /// left to save. Default `false` — a route with nothing that must
    /// survive a cancelled `.await` never needs to override it.
    fn has_pending(&self) -> bool {
        false
    }

    /// Produce a fresh attach resumed at `last_output_seq`
    /// (`docs/design/protocol.md` §10 Reattach steps 1–5, or whatever the
    /// implementation's route maps those steps to).
    fn reconnect(&self, last_output_seq: u64) -> ReconnectFuture<'_>;

    /// Milliseconds the most recently *completed*
    /// [`reconnect`](Reconnect::reconnect) call spent blocked on
    /// something outside `qsh`'s own control before the resume itself
    /// could even begin — Step 8's reverse-route wait for the target's
    /// next registration (`LocalReconnect`, `docs/design/protocol.md`
    /// §11-4's Reattach mapping; `docs/CLI.md` §6.4's
    /// `registration_wait_ms`). [`recover`] reads this only after its
    /// attempt has resolved, so it always reflects the wait the just-
    /// finished call actually measured, never one still in flight.
    ///
    /// Default `0` — the forward route (`DialReconnect`) never waits on
    /// anything but its own dial, so it never overrides this.
    fn registration_wait_ms(&self) -> u64 {
        0
    }

    /// The ceiling [`recover`] applies to one attempt of this route's
    /// [`reconnect`](Reconnect::reconnect).
    ///
    /// Default [`REDIAL_DEADLINE`] — the forward route redials the peer
    /// itself, so the whole attempt (redial + resume) is properly held to
    /// that 2 s budget and never overrides this.
    ///
    /// The reverse route (`LocalReconnect`, M3 plan Step 8 (2473c88)) *does*
    /// override it: `RecoveryConfig::registration_wait`'s own doc is
    /// explicit that the 2 s budget covers only "the resume *after* a
    /// registration is observed" (`docs/design/protocol.md` §11-4's "재등록
    /// 시점부터 resume 완료까지 2초"), not the wait *for* one, which can
    /// legitimately run as long as the target's own reconnect backoff.
    /// Folding that wait into a flat [`REDIAL_DEADLINE`] here would silently
    /// break that promise: the wait would be cut off after 2 s regardless
    /// of `registration_wait`, and the in-flight redemption task
    /// (`LocalReconnect::in_flight`) would be adopted and re-awaited by
    /// every subsequent attempt in slices no bigger than 2 s each — which
    /// only ever adds up to the full wait if `RecoveryConfig::attempts` is
    /// inflated well past its production default to compensate (exactly
    /// the gap a reviewer of this step's first draft caught: the shipped
    /// default of 3 attempts gives up after roughly 7 s of wall time,
    /// nowhere near the 60 s blackout the milestone's DoD requires).
    /// Overriding this method instead lets a *single* attempt's deadline
    /// legitimately cover the whole registration wait, so the 2 s budget
    /// this const still names goes exactly where the doc always said it
    /// would: the resume steps after registration, not the wait for it.
    fn attempt_deadline(&self) -> Duration {
        REDIAL_DEADLINE
    }
}

/// How a recovery ended, with whatever the resume produced.
#[derive(Debug)]
pub enum Recovered<T> {
    /// The existing connection survived the path change; there was
    /// nothing to rebuild.
    Migrated,
    /// The connection was rebuilt and the session re-attached. Carries
    /// whatever the re-attach closure returned (typically the new
    /// [`crate::client::Session`] plus its [`crate::client::Attached`]).
    Resumed(T),
}

/// One resolved recovery: the outcome and the telemetry record that was
/// emitted for it.
///
/// The report exists on the failure path too — an unrecovered session is
/// precisely the datapoint the SC3 campaign must not lose.
#[derive(Debug)]
pub struct RecoveryOutcome<T> {
    /// What happened, or why nothing did.
    pub outcome: Result<Recovered<T>, ResumeError>,
    /// The record emitted on `qsh::recovery`.
    pub report: RecoveryReport,
}

impl<T> RecoveryOutcome<T> {
    /// Whether the session is live again.
    pub fn is_recovered(&self) -> bool {
        self.outcome.is_ok()
    }
}

/// Drive one recovery for `session_ref`, from detection to live bytes.
///
/// The sequence is: ask whether the connection survived on its own, help
/// it with a rebind and ask again, then rebuild.
///
/// `probe` answers "does the existing connection still work?" and is
/// called at most twice — it must be quick, because every millisecond it
/// spends is a millisecond of the deadline the resume path does not get.
/// `binder` is the migration aid: `None`, or a rebind that fails, simply
/// skips that middle step. `reattach` re-dials and performs
/// `session.attach` with the resume credential; whatever it returns is
/// handed back in [`Recovered::Resumed`]. `registration_wait_ms` is read
/// exactly once, after `reattach` (if it ran at all) has resolved — it is
/// the [`Reconnect`] implementation's own
/// [`registration_wait_ms`](Reconnect::registration_wait_ms), threaded
/// through as a plain getter rather than the trait object itself because
/// the actual reconnect call already went through `reattach`'s closure
/// (built by the caller, which is what lets it also stop the pumps first —
/// see `recover_attach`'s call site); this is only ever asked *after*.
///
/// The entire sequence is bounded by `deadline` — [`REDIAL_DEADLINE`] on
/// the forward route, wider on the reverse route so the registration wait
/// it also has to cover does not get cut off (`Reconnect::attempt_deadline`'s
/// own doc; the caller passes `reconnect.attempt_deadline()` here). Overrunning
/// it is [`Recovery::Failed`], even if the attach would have succeeded a
/// moment later: a late recovery is the failure mode this deadline exists
/// to name.
///
/// `recover` itself does not guarantee any interval between attempts; a
/// caller that retries in a loop brings its own backoff, the way
/// `crate::ops::session::RecoveryConfig::backoff` does.
pub async fn recover<P, PFut, R, RFut, T, E, G>(
    session_ref: &str,
    binder: Option<&dyn PathBinder>,
    deadline: Duration,
    mut probe: P,
    reattach: R,
    registration_wait_ms: G,
) -> RecoveryOutcome<T>
where
    P: FnMut() -> PFut,
    PFut: Future<Output = bool>,
    R: FnOnce() -> RFut,
    RFut: Future<Output = Result<T, E>>,
    E: Into<ResumeError>,
    G: FnOnce() -> u64,
{
    let timer = RecoveryTimer::start(session_ref);

    let attempt = async {
        // QUIC may have carried the connection across the new path by
        // itself — a peer address change it validated without help.
        if probe().await {
            return Ok(Recovered::Migrated);
        }
        // Otherwise offer it a fresh local socket and ask once more. This
        // is the case where the *local* interface went away: quinn cannot
        // migrate off a socket that no longer routes anywhere.
        if let Some(binder) = binder {
            match binder.rebind() {
                Ok(addr) => {
                    tracing::debug!(local_addr = %addr, "rebound endpoint for migration");
                    if probe().await {
                        return Ok(Recovered::Migrated);
                    }
                }
                Err(err) => {
                    // Nothing here is fatal. A rebind that cannot get a
                    // socket just means the cheap path is unavailable.
                    tracing::debug!(error = %err, "rebind failed; falling back to resume");
                }
            }
        }
        reattach().await.map(Recovered::Resumed).map_err(Into::into)
    };

    let outcome = match tokio::time::timeout(deadline, attempt).await {
        Ok(outcome) => outcome,
        Err(_) => Err(ResumeError::Deadline(deadline)),
    };

    let recovery = match &outcome {
        Ok(Recovered::Migrated) => Recovery::Migrated,
        Ok(Recovered::Resumed(_)) => Recovery::Resumed,
        Err(_) => Recovery::Failed,
    };
    let report = timer.finish(recovery, registration_wait_ms());
    RecoveryOutcome { outcome, report }
}

/// The client's view of how far the session's output has been delivered.
///
/// Resume asks the host to replay from exactly `L`, so in the common case
/// this changes nothing. It earns its place in the two cases where the
/// stream is not exactly what was asked for: a frame still in flight on
/// the connection that just died, and a host that replays from a
/// conservative earlier offset. Either would otherwise redraw part of the
/// terminal.
#[derive(Debug, Clone, Default)]
pub struct OutputCursor {
    last_seq: u64,
}

impl OutputCursor {
    /// A cursor that has delivered everything up to `last_seq`.
    pub fn new(last_seq: u64) -> Self {
        Self { last_seq }
    }

    /// The highest cumulative offset delivered so far — the `L` a resume
    /// asks the host to continue from.
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// Filter one event. `None` means "already delivered, drop it";
    /// otherwise the event to hand on, with any overlapping prefix of an
    /// `Output` trimmed away.
    pub fn accept(&mut self, event: AttachEvent) -> Option<AttachEvent> {
        match event {
            AttachEvent::Output { sequence, data } => {
                // `sequence` is the offset *after* `data`, so the frame
                // covers `(sequence - len, sequence]`.
                let start = sequence.saturating_sub(data.len() as u64);
                if sequence <= self.last_seq {
                    return None;
                }
                let skip = self.last_seq.saturating_sub(start) as usize;
                self.last_seq = sequence;
                // The overlap can never *exceed* the frame: `start` is
                // `sequence - len`, so `skip` is at most `len`. It can equal
                // it, and legitimately does for the empty frame a host is
                // free to send (`SessionFrame::validate` only caps the chunk
                // size, so `Output{sequence: L+1, data: []}` is on the wire's
                // menu) — that yields an empty slice, which is the right
                // answer. What must never happen is the other direction:
                // if the overlap ever did cover the whole frame, the answer
                // is "nothing left", never "all of it", because emitting the
                // frame whole is the doubled output this type exists to
                // prevent. The saturating slice enforces exactly that, and
                // the assertion guards the arithmetic rather than the wire.
                debug_assert!(skip <= data.len(), "overlap ran past the frame");
                let data = data.get(skip..).unwrap_or_default().to_vec();
                Some(AttachEvent::Output { sequence, data })
            }
            // A gap moves the cursor forward to where the host can
            // actually continue; the caller is told, because output was
            // genuinely lost (`docs/CLI.md` §6.4).
            AttachEvent::Gap {
                requested_after,
                available_from,
            } => {
                self.last_seq = self.last_seq.max(available_from);
                Some(AttachEvent::Gap {
                    requested_after,
                    available_from,
                })
            }
            AttachEvent::Exit { final_seq, .. } => {
                self.last_seq = self.last_seq.max(final_seq);
                Some(event)
            }
            other => Some(other),
        }
    }
}

/// Input sent to the host but not yet acknowledged, held so it can be
/// retransmitted after a resume.
///
/// Offsets are the session's cumulative input axis (protocol.md §10-5), so
/// the buffer covers `(acked, sent]` and a resume simply asks it to rewind
/// to whatever the host says it applied.
#[derive(Debug, Clone)]
pub struct PendingInput {
    acked: u64,
    sent: u64,
    buf: VecDeque<u8>,
}

impl PendingInput {
    /// A buffer continuing from `base` — the `input_seq` an attach was
    /// handed, so a resumed attach numbers its bytes on the host's axis
    /// rather than restarting at zero.
    pub fn new(base: u64) -> Self {
        Self {
            acked: base,
            sent: base,
            buf: VecDeque::new(),
        }
    }

    /// Cumulative offset of the last byte handed to the transport.
    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// Cumulative offset the host has confirmed applying.
    pub fn acked(&self) -> u64 {
        self.acked
    }

    /// Bytes outstanding.
    pub fn unacked_len(&self) -> usize {
        self.buf.len()
    }

    /// Record `data` as sent, returning the new cumulative offset.
    ///
    /// Fails with [`ResumeError::UnackedInputOverflow`] once the
    /// outstanding tail would pass [`UNACKED_INPUT_MAX`]. The bytes are
    /// **not** buffered in that case: a caller that ignored the error and
    /// kept typing would otherwise build a retransmit buffer it cannot
    /// honour.
    pub fn push(&mut self, data: &[u8]) -> Result<u64, ResumeError> {
        let would_be = self.buf.len() + data.len();
        if would_be > UNACKED_INPUT_MAX {
            return Err(ResumeError::UnackedInputOverflow { unacked: would_be });
        }
        self.buf.extend(data.iter().copied());
        self.sent += data.len() as u64;
        Ok(self.sent)
    }

    /// Apply an `InputAck`: everything at or below `acked_input_seq` is
    /// the host's problem now and can be released.
    pub fn ack(&mut self, acked_input_seq: u64) {
        let acked = acked_input_seq.min(self.sent);
        if acked <= self.acked {
            return;
        }
        let drop = (acked - self.acked) as usize;
        self.buf.drain(..drop.min(self.buf.len()));
        self.acked = acked;
    }

    /// Rewind to the offset a resumed attach was told the host had
    /// applied, and return the tail to retransmit.
    ///
    /// `applied` above `sent` is legitimate — the host applied bytes whose
    /// ack never made it back — and simply empties the buffer. `applied`
    /// below the oldest byte still held is not recoverable, and says so
    /// rather than sending a hole.
    pub fn rebase(&mut self, applied: u64) -> Result<&[u8], ResumeError> {
        if applied < self.acked {
            return Err(ResumeError::InputUnrecoverable {
                applied,
                oldest: self.acked,
            });
        }
        if applied >= self.sent {
            self.buf.clear();
            self.acked = applied;
            self.sent = applied;
            return Ok(&[]);
        }
        let drop = (applied - self.acked) as usize;
        self.buf.drain(..drop);
        self.acked = applied;
        Ok(self.buf.make_contiguous())
    }

    /// The outstanding tail without rewinding.
    pub fn unacked(&mut self) -> &[u8] {
        self.buf.make_contiguous()
    }
}

#[cfg(test)]
mod tests;
