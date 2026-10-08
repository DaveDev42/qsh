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
        REDIAL_DEADLINE,
        || async { true },
        || async {
            panic!("must not re-dial when the connection is alive");
            #[allow(unreachable_code)]
            Ok::<&str, ClientError>("")
        },
        || 0,
    )
    .await;
    assert!(matches!(out.outcome, Ok(Recovered::Migrated)));
    assert_eq!(out.report.recovery, Recovery::Migrated);
    assert_eq!(out.report.session_ref, "mac/01K0");
    assert_eq!(out.report.registration_wait_ms, 0);
}

#[tokio::test]
async fn a_rebind_that_revives_the_connection_counts_as_migrated() {
    let binder = ok_binder();
    // Dead before the rebind, alive after: the local interface moved.
    let mut answers = [false, true].into_iter();
    let out: RecoveryOutcome<&str> = recover(
        "mac/01K0",
        Some(&binder),
        REDIAL_DEADLINE,
        || {
            let answer = answers.next().expect("probed more than twice");
            async move { answer }
        },
        || async {
            panic!("must not re-dial when the rebind was enough");
            #[allow(unreachable_code)]
            Ok::<&str, ClientError>("")
        },
        || 0,
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
        REDIAL_DEADLINE,
        || async { false },
        || async { Ok::<_, ClientError>("attached") },
        || 0,
    )
    .await;
    assert!(matches!(out.outcome, Ok(Recovered::Resumed("attached"))));
    assert_eq!(out.report.recovery, Recovery::Resumed);
    assert_eq!(out.report.registration_wait_ms, 0);
}

#[tokio::test]
async fn a_failed_rebind_does_not_stop_the_resume() {
    // The whole point of "migration is only an optimization": the
    // recovery must not be able to fail *because* migration failed.
    let binder = failing_binder();
    let out = recover(
        "mac/01K0",
        Some(&binder),
        REDIAL_DEADLINE,
        || async { false },
        || async { Ok::<_, ClientError>("attached") },
        || 0,
    )
    .await;
    assert!(matches!(out.outcome, Ok(Recovered::Resumed("attached"))));
    assert_eq!(out.report.recovery, Recovery::Resumed);
    assert_eq!(out.report.registration_wait_ms, 0);
}

#[tokio::test]
async fn with_no_binder_recovery_is_pure_resume() {
    let out = recover(
        "mac/01K0",
        None,
        REDIAL_DEADLINE,
        || async { false },
        || async { Ok::<_, ClientError>("attached") },
        || 0,
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
        REDIAL_DEADLINE,
        || async { false },
        || async {
            tokio::time::sleep(REDIAL_DEADLINE * 2).await;
            Ok::<_, ClientError>("too late")
        },
        || 0,
    )
    .await;
    assert!(
        matches!(out.outcome, Err(ResumeError::Deadline(_))),
        "{out:?}"
    );
    assert_eq!(out.report.recovery, Recovery::Failed);
    assert_eq!(
        out.report.time_to_recovery_ms,
        REDIAL_DEADLINE.as_millis() as u64,
        "the record must show the deadline, not the wall time of the test"
    );
    assert_eq!(out.report.registration_wait_ms, 0);
}

#[tokio::test(start_paused = true)]
async fn a_recovery_inside_the_deadline_is_recorded_with_its_duration() {
    let out = recover(
        "mac/01K0",
        None,
        REDIAL_DEADLINE,
        || async { false },
        || async {
            tokio::time::sleep(Duration::from_millis(350)).await;
            Ok::<_, ClientError>("attached")
        },
        || 0,
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

/// `recover` reads `registration_wait_ms` from the closure it is
/// handed — proof, independent of any particular [`Reconnect`]
/// implementation, that the value a route reports actually reaches
/// the emitted report rather than being silently dropped on the floor
/// (`docs/CLI.md` §6.4: forward always `0`, reverse the measured
/// wait).
#[tokio::test]
async fn a_nonzero_registration_wait_reaches_the_report() {
    let out = recover(
        "mac/01K0",
        None,
        REDIAL_DEADLINE,
        || async { false },
        || async { Ok::<_, ClientError>("attached") },
        || 640,
    )
    .await;
    assert!(out.is_recovered());
    assert_eq!(out.report.registration_wait_ms, 640);
}
