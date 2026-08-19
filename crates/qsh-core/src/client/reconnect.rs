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
//! The whole recovery runs under [`REDIAL_DEADLINE`]. That bound is the
//! difference between "qsh recovered" and "QUIC's 45 s idle timeout
//! eventually fired and something reconnected" — `docs/design/testing.md`
//! L4 defines the latter as a failure, so it is enforced here in code
//! rather than described in a comment.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use thiserror::Error;

use crate::client::{AttachEvent, ClientError};
use crate::telemetry::{Recovery, RecoveryReport, RecoveryTimer};

/// How long a recovery may take, measured from the moment the path is
/// declared dead to the moment bytes flow again.
///
/// Two seconds is the criterion `docs/design/testing.md` L4 and PLAN.md
/// §Step 7 fix in advance so SC3 cannot be passed by accident: quinn's
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
    /// Neither migration nor re-dial finished inside [`REDIAL_DEADLINE`].
    #[error("recovery exceeded the {} ms deadline", REDIAL_DEADLINE.as_millis())]
    Deadline,
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
        // Same family, unspecified address, ephemeral port: the point is a
        // new local path, and letting the OS pick is what makes this work
        // when the old interface is already gone.
        let bind: SocketAddr = match self.local_addr()? {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = std::net::UdpSocket::bind(bind)?;
        qsh_transport::Endpoint::rebind(self, socket)?;
        self.local_addr()
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
/// handed back in [`Recovered::Resumed`].
///
/// The entire sequence is bounded by [`REDIAL_DEADLINE`]. Overrunning it
/// is [`Recovery::Failed`], even if the attach would have succeeded a
/// moment later: a late recovery is the failure mode this deadline exists
/// to name.
pub async fn recover<P, PFut, R, RFut, T, E>(
    session_ref: &str,
    binder: Option<&dyn PathBinder>,
    mut probe: P,
    reattach: R,
) -> RecoveryOutcome<T>
where
    P: FnMut() -> PFut,
    PFut: Future<Output = bool>,
    R: FnOnce() -> RFut,
    RFut: Future<Output = Result<T, E>>,
    E: Into<ResumeError>,
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

    let outcome = match tokio::time::timeout(REDIAL_DEADLINE, attempt).await {
        Ok(outcome) => outcome,
        Err(_) => Err(ResumeError::Deadline),
    };

    let recovery = match &outcome {
        Ok(Recovered::Migrated) => Recovery::Migrated,
        Ok(Recovered::Resumed(_)) => Recovery::Resumed,
        Err(_) => Recovery::Failed,
    };
    let report = timer.finish(recovery);
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
mod tests {
    use super::*;

    fn output(sequence: u64, data: &str) -> AttachEvent {
        AttachEvent::Output {
            sequence,
            data: data.as_bytes().to_vec(),
        }
    }

    fn text(event: Option<AttachEvent>) -> Option<String> {
        match event {
            Some(AttachEvent::Output { data, .. }) => Some(String::from_utf8(data).expect("utf8")),
            _ => None,
        }
    }

    #[test]
    fn the_deadline_is_the_documented_two_seconds() {
        // The number is a contract (`docs/design/testing.md` L4), not a
        // tuning knob: a change here changes what SC3 measures.
        assert_eq!(REDIAL_DEADLINE, Duration::from_secs(2));
        assert!(
            REDIAL_DEADLINE < Duration::from_secs(45),
            "the deadline must be well inside quinn's idle timeout, or \
             waiting for the timeout would count as a recovery"
        );
    }

    #[test]
    fn already_delivered_output_is_dropped() {
        let mut cursor = OutputCursor::new(10);
        assert!(cursor.accept(output(4, "abcd")).is_none());
        assert!(cursor.accept(output(10, "j")).is_none());
        assert_eq!(cursor.last_seq(), 10);
    }

    #[test]
    fn an_overlapping_frame_is_trimmed_not_dropped() {
        let mut cursor = OutputCursor::new(10);
        // Covers offsets 7..=12; 7..=10 are already on screen.
        let kept = cursor.accept(output(12, "hijkl"));
        assert_eq!(text(kept).as_deref(), Some("kl"));
        assert_eq!(cursor.last_seq(), 12);
    }

    /// A host is free to send an empty `Output` frame — `validate()` caps
    /// the chunk size and nothing more — and one whose `sequence` is past
    /// the cursor used to trip an assertion that assumed every accepted
    /// frame carried at least one byte. In a debug build (every `cargo
    /// test` binary, and every `qsh` a developer runs) that is a panic a
    /// misbehaving or hostile host can trigger from the wire.
    #[test]
    fn an_empty_output_frame_past_the_cursor_is_accepted_not_a_panic() {
        let mut cursor = OutputCursor::new(10);
        // `Output{sequence: L + 1, data: []}` — the exact shape that panicked.
        let kept = cursor.accept(output(11, ""));
        assert_eq!(
            text(kept).as_deref(),
            Some(""),
            "an empty frame carries no bytes, so nothing is delivered"
        );
        // The cursor still follows the host's offset, and real output after
        // it is neither dropped nor doubled.
        assert_eq!(cursor.last_seq(), 11);
        assert_eq!(
            text(cursor.accept(output(15, "abcd"))).as_deref(),
            Some("abcd")
        );
    }

    /// The same frame at or below the cursor takes the ordinary
    /// already-delivered path.
    #[test]
    fn an_empty_output_frame_at_the_cursor_is_dropped() {
        let mut cursor = OutputCursor::new(10);
        assert!(cursor.accept(output(10, "")).is_none());
        assert!(cursor.accept(output(3, "")).is_none());
        assert_eq!(cursor.last_seq(), 10);
    }

    #[test]
    fn fresh_output_passes_through_whole() {
        let mut cursor = OutputCursor::new(10);
        assert_eq!(
            text(cursor.accept(output(14, "abcd"))).as_deref(),
            Some("abcd")
        );
        assert_eq!(cursor.last_seq(), 14);
    }

    #[test]
    fn a_gap_moves_the_cursor_to_where_the_host_can_continue() {
        let mut cursor = OutputCursor::new(10);
        let event = cursor.accept(AttachEvent::Gap {
            requested_after: 10,
            available_from: 100,
        });
        assert!(
            matches!(event, Some(AttachEvent::Gap { .. })),
            "gap must reach the caller"
        );
        assert_eq!(cursor.last_seq(), 100);
        // Output that follows the gap is not mistaken for a duplicate.
        assert_eq!(
            text(cursor.accept(output(104, "abcd"))).as_deref(),
            Some("abcd")
        );
    }

    #[test]
    fn input_is_released_as_it_is_acked() {
        let mut pending = PendingInput::new(0);
        assert_eq!(pending.push(b"hello").unwrap(), 5);
        assert_eq!(pending.push(b" world").unwrap(), 11);
        assert_eq!(pending.unacked_len(), 11);
        pending.ack(5);
        assert_eq!(pending.unacked(), b" world");
        pending.ack(11);
        assert_eq!(pending.unacked_len(), 0);
    }

    #[test]
    fn a_resume_retransmits_exactly_what_the_host_did_not_apply() {
        let mut pending = PendingInput::new(100);
        pending.push(b"abcdef").unwrap();
        pending.ack(102);
        // Host says it applied through 104: "ef" is all that is missing.
        assert_eq!(pending.rebase(104).unwrap(), b"ef");
        assert_eq!(pending.acked(), 104);
        assert_eq!(pending.sent(), 106);
    }

    #[test]
    fn a_host_that_applied_everything_leaves_nothing_to_retransmit() {
        let mut pending = PendingInput::new(0);
        pending.push(b"abcdef").unwrap();
        assert_eq!(pending.rebase(6).unwrap(), b"");
        assert_eq!(pending.sent(), 6);
        // …and the axis continues from there, not from zero.
        assert_eq!(pending.push(b"gh").unwrap(), 8);
    }

    #[test]
    fn an_unreachable_input_offset_fails_instead_of_sending_a_hole() {
        let mut pending = PendingInput::new(0);
        pending.push(b"abcdef").unwrap();
        pending.ack(6);
        let err = pending.rebase(3).unwrap_err();
        assert!(
            matches!(
                err,
                ResumeError::InputUnrecoverable {
                    applied: 3,
                    oldest: 6
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn overflowing_the_unacked_cap_is_an_error_not_silent_buffering() {
        let mut pending = PendingInput::new(0);
        pending.push(&vec![b'x'; UNACKED_INPUT_MAX]).unwrap();
        let err = pending.push(b"one too many").unwrap_err();
        assert!(
            matches!(err, ResumeError::UnackedInputOverflow { .. }),
            "{err}"
        );
        // The rejected bytes were not buffered: the buffer still holds
        // exactly what can be retransmitted.
        assert_eq!(pending.unacked_len(), UNACKED_INPUT_MAX);
        assert_eq!(pending.sent(), UNACKED_INPUT_MAX as u64);
    }

    struct FakeBinder {
        result: io::Result<SocketAddr>,
    }

    impl PathBinder for FakeBinder {
        fn rebind(&self) -> io::Result<SocketAddr> {
            match &self.result {
                Ok(addr) => Ok(*addr),
                Err(e) => Err(io::Error::new(e.kind(), "rebind failed")),
            }
        }
    }

    fn ok_binder() -> FakeBinder {
        FakeBinder {
            result: Ok("127.0.0.1:9999".parse().unwrap()),
        }
    }

    fn failing_binder() -> FakeBinder {
        FakeBinder {
            result: Err(io::Error::other("no socket")),
        }
    }

    #[tokio::test]
    async fn a_connection_that_survived_on_its_own_needs_no_rebind() {
        let binder = FakeBinder {
            result: Err(io::Error::other("must not be called")),
        };
        let out: RecoveryOutcome<&str> = recover(
            "mac/01K0",
            Some(&binder),
            || async { true },
            || async {
                panic!("must not re-dial when the connection is alive");
                #[allow(unreachable_code)]
                Ok::<&str, ClientError>("")
            },
        )
        .await;
        assert!(matches!(out.outcome, Ok(Recovered::Migrated)));
        assert_eq!(out.report.recovery, Recovery::Migrated);
        assert_eq!(out.report.session_ref, "mac/01K0");
    }

    #[tokio::test]
    async fn a_rebind_that_revives_the_connection_counts_as_migrated() {
        let binder = ok_binder();
        // Dead before the rebind, alive after: the local interface moved.
        let mut answers = [false, true].into_iter();
        let out: RecoveryOutcome<&str> = recover(
            "mac/01K0",
            Some(&binder),
            || {
                let answer = answers.next().expect("probed more than twice");
                async move { answer }
            },
            || async {
                panic!("must not re-dial when the rebind was enough");
                #[allow(unreachable_code)]
                Ok::<&str, ClientError>("")
            },
        )
        .await;
        assert!(matches!(out.outcome, Ok(Recovered::Migrated)));
        assert_eq!(out.report.recovery, Recovery::Migrated);
    }

    #[tokio::test]
    async fn a_dead_connection_falls_through_to_resume() {
        let binder = ok_binder();
        let out = recover(
            "mac/01K0",
            Some(&binder),
            || async { false },
            || async { Ok::<_, ClientError>("attached") },
        )
        .await;
        assert!(matches!(out.outcome, Ok(Recovered::Resumed("attached"))));
        assert_eq!(out.report.recovery, Recovery::Resumed);
    }

    #[tokio::test]
    async fn a_failed_rebind_does_not_stop_the_resume() {
        // The whole point of "migration is only an optimization": the
        // recovery must not be able to fail *because* migration failed.
        let binder = failing_binder();
        let out = recover(
            "mac/01K0",
            Some(&binder),
            || async { false },
            || async { Ok::<_, ClientError>("attached") },
        )
        .await;
        assert!(matches!(out.outcome, Ok(Recovered::Resumed("attached"))));
        assert_eq!(out.report.recovery, Recovery::Resumed);
    }

    #[tokio::test]
    async fn with_no_binder_recovery_is_pure_resume() {
        let out = recover(
            "mac/01K0",
            None,
            || async { false },
            || async { Ok::<_, ClientError>("attached") },
        )
        .await;
        assert!(matches!(out.outcome, Ok(Recovered::Resumed("attached"))));
    }

    #[tokio::test(start_paused = true)]
    async fn a_recovery_that_overruns_the_deadline_is_a_failure() {
        // Paused clock: the deadline is asserted, never slept through.
        let out: RecoveryOutcome<&str> = recover(
            "mac/01K0",
            None,
            || async { false },
            || async {
                tokio::time::sleep(REDIAL_DEADLINE * 2).await;
                Ok::<_, ClientError>("too late")
            },
        )
        .await;
        assert!(matches!(out.outcome, Err(ResumeError::Deadline)), "{out:?}");
        assert_eq!(out.report.recovery, Recovery::Failed);
        assert_eq!(
            out.report.time_to_recovery_ms,
            REDIAL_DEADLINE.as_millis() as u64,
            "the record must show the deadline, not the wall time of the test"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_recovery_inside_the_deadline_is_recorded_with_its_duration() {
        let out = recover(
            "mac/01K0",
            None,
            || async { false },
            || async {
                tokio::time::sleep(Duration::from_millis(350)).await;
                Ok::<_, ClientError>("attached")
            },
        )
        .await;
        assert!(out.is_recovered());
        assert_eq!(out.report.time_to_recovery_ms, 350);
        assert!(
            u128::from(out.report.time_to_recovery_ms) <= REDIAL_DEADLINE.as_millis(),
            "{:?}",
            out.report
        );
    }
}
