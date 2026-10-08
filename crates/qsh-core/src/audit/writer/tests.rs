use qsh_transport::Principal;

use super::*;
use crate::acl::{Action, Decision};

/// A record whose JSON encoding is a small, near-constant size
/// regardless of `i` (single/double-digit request ids), so rotation
/// math in the tests below stays predictable without hardcoding
/// `serde_json`'s exact byte count.
fn record_for(i: u64) -> AuditRecord {
    AuditRecord::now(
        i,
        &Principal::Device("laptop".into()),
        qsh_transport::AuthPath::Pin,
        Action::ExecRun,
        "exec",
        Decision::Allow,
        None,
        "127.0.0.1:4433".parse().unwrap(),
    )
}

fn read_all_lines(dir: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "lock") {
            continue; // F6's sidecar lock file: never audit content.
        }
        let text = fs::read_to_string(&path).unwrap();
        lines.extend(text.lines().map(str::to_string));
    }
    lines
}

#[test]
fn rotation_triggers_with_no_line_truncated_or_lost() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    // Small enough to force several rotations; `retain` generous
    // enough that nothing this test writes is ever evicted (that's
    // the separate retention test below).
    let (sink, handle) = RotatingAuditSink::spawn_joinable(&path, 500, 50, 64);
    let total = 20u64;
    for i in 0..total {
        sink.record(&record_for(i)).unwrap();
    }
    drop(sink);
    handle.join().unwrap();

    assert!(path.exists(), "audit.log restarted after rotating");
    assert!(
        rotated_path(&path, 1).exists(),
        "at least one rotation happened"
    );

    let lines = read_all_lines(dir.path());
    assert_eq!(
        lines.len() as u64,
        total,
        "zero record loss across rotation"
    );
    for line in &lines {
        let record: AuditRecord =
            serde_json::from_str(line).expect("every line is valid, untruncated JSON");
        assert_eq!(record.decision, "allow");
    }
}

#[test]
fn retention_keeps_exactly_retain_plus_active_and_bounds_directory_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let max_bytes = 200u64;
    let retain = 2u32;
    let (sink, handle) = RotatingAuditSink::spawn_joinable(&path, max_bytes, retain, 64);
    // Comfortably more than enough rotations to reach steady state.
    for i in 0..15u64 {
        sink.record(&record_for(i)).unwrap();
    }
    drop(sink);
    handle.join().unwrap();

    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|name| !name.ends_with(".lock"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["audit.log", "audit.log.1", "audit.log.2"],
        "older rotated files are unlinked beyond retain"
    );

    let total_bytes: u64 = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| !p.extension().is_some_and(|ext| ext == "lock"))
        .map(|p| fs::metadata(p).unwrap().len())
        .sum();
    // One line's worth of slack per file: a write that pushes a file
    // past `max_bytes` still lands in *that* file (rotation happens
    // before the next line, not the one that triggered it).
    let slack = 512u64;
    assert!(
        total_bytes <= max_bytes * u64::from(retain + 1) + slack,
        "directory bytes {total_bytes} exceed the max_bytes*(retain+1) budget"
    );
}

#[test]
fn queue_saturation_denies_the_second_decision_while_the_writer_is_stalled() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let (sink, gate, handle) = RotatingAuditSink::spawn_stalled(&path, 64 * 1024, 2, 1);

    // queue_depth=1: the first record fills the only slot; the second
    // is refused outright — the writer never touches the channel
    // before this point (it is parked on `gate.recv()`), so this is
    // deterministic, not a race against the writer draining.
    assert_eq!(sink.record(&record_for(0)), Ok(()));
    assert_eq!(sink.record(&record_for(1)), Err(AuditError::QueueFull));

    drop(sink);
    gate.send(()).unwrap();
    handle.join().unwrap();
}

#[test]
fn record_returns_immediately_while_the_writer_is_stalled_and_the_queue_has_room() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let (sink, gate, handle) = RotatingAuditSink::spawn_stalled(&path, 64 * 1024, 2, 4);

    // If `record()` ever blocked on the writer (e.g. a regression to a
    // blocking `send()` instead of `try_send()`), these calls would
    // hang here and the test would time out rather than reach the
    // asserts — that hang *is* the failure mode this test guards
    // against, no timing measurement needed.
    assert_eq!(sink.record(&record_for(0)), Ok(()));
    assert_eq!(sink.record(&record_for(1)), Ok(()));

    drop(sink);
    gate.send(()).unwrap();
    handle.join().unwrap();
}

#[cfg(unix)]
#[test]
fn rotated_files_and_directory_keep_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("state");
    let path = sub.join("audit.log");
    let (sink, handle) = RotatingAuditSink::spawn_joinable(&path, 200, 3, 64);
    for i in 0..10u64 {
        sink.record(&record_for(i)).unwrap();
    }
    drop(sink);
    handle.join().unwrap();

    let dmode = fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
    assert_eq!(dmode, 0o700);
    for name in ["audit.log", "audit.log.1"] {
        let p = sub.join(name);
        assert!(p.exists(), "{name} should exist");
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{name} mode");
    }
}

#[test]
fn path_reports_the_active_log_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sink = RotatingAuditSink::spawn(&path, 64 * 1024, 5, 16);
    assert_eq!(sink.path(), path);
}

// ---- F2: shutdown drain -------------------------------------------

/// The mandatory F2 test: `RotatingAuditSink::spawn`'s `Drop` now joins
/// the writer thread, so the instant it returns every accepted record
/// must already be durable — no polling, no `sleep()`. Without F2 the
/// verifier measured 229/1000 records on disk at this point.
#[test]
fn dropping_the_last_arc_flushes_every_enqueued_record_before_the_writer_exits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sink = RotatingAuditSink::spawn(&path, 64 * 1024 * 1024, 5, 1024);
    let n = 1000u64;
    for i in 0..n {
        sink.record(&record_for(i))
            .expect("queue has room for 1000");
    }
    drop(sink); // last (only) owner: Drop joins the writer synchronously.

    let on_disk = fs::read_to_string(&path)
        .map(|s| s.lines().count())
        .unwrap_or(0);
    assert_eq!(
        on_disk as u64, n,
        "every accepted record must be durable once the last Arc drops"
    );
}

// ---- F3: partial-line repair ---------------------------------------

/// Direct unit coverage of the truncate mechanism itself: forcing a
/// genuine, byte-partial `write_all` failure deterministically on a
/// real file (without an actual disk-full condition) is impractical —
/// `O_APPEND` writes on a local filesystem either fully succeed or
/// fail outright, so this instead manufactures exactly the on-disk
/// state a partial write would leave (a torn, newline-less fragment
/// past the last confirmed-good offset) and asserts `repair_partial_write`
/// removes it. The end-to-end pipeline (genuine failure → repair →
/// automatic recovery → every surviving line still valid JSON) is
/// covered by the F4 test below.
#[test]
fn repair_partial_write_truncates_a_torn_fragment_back_to_the_last_known_good_offset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut file = RotatingFile::new(path.clone(), 64 * 1024, 5);
    file.write_line(b"{\"a\":1}\n").unwrap();
    file.write_line(b"{\"a\":2}\n").unwrap();
    let good_len = file.bytes_written;

    // Model exactly what a `write_all` that failed partway through a
    // third line would leave behind: `bytes_written` itself is
    // untouched (the real writer only advances it after success), but
    // extra, torn bytes are now on disk past that offset.
    {
        let mut raw = OpenOptions::new().append(true).open(&path).unwrap();
        raw.write_all(b"{\"a\":3, \"unterminat").unwrap();
    }
    assert!(fs::metadata(&path).unwrap().len() > good_len);

    file.repair_partial_write();

    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        good_len,
        "the torn fragment must be truncated off"
    );
    let text = fs::read_to_string(&path).unwrap();
    for line in text.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("no torn line survives repair");
    }
    assert!(text.ends_with('\n'));

    // And the handle is still perfectly usable afterward — O_APPEND
    // means no seek was needed.
    file.write_line(b"{\"a\":4}\n").unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 3);
}

// ---- F1 / F4: real-latch trip and automatic recovery ---------------

// A minimal hand-rolled `tracing::Subscriber` that captures every
// event's target and rendered fields — same precedent as
// `acl/load.rs`'s `capture` module. Installed via
// `set_global_default` rather than the (thread-local) `with_default`:
// the writer thread is a real, separately spawned OS thread, and only
// a *global* default is visible from a thread that never called
// `with_default`/`set_default` itself.
#[cfg_attr(not(unix), allow(dead_code))]
mod capture {
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};

    #[derive(Default)]
    pub(super) struct Sink {
        pub(super) events: Mutex<Vec<(String, String)>>, // (target, rendered fields)
    }

    struct Rec(String);
    impl Visit for Rec {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{}={:?} ", field.name(), value));
        }
    }

    pub(super) struct Sub(pub(super) Arc<Sink>);
    impl tracing::Subscriber for Sub {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::Id, _: &tracing::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut rec = Rec(String::new());
            event.record(&mut rec);
            self.0
                .events
                .lock()
                .unwrap()
                .push((event.metadata().target().to_string(), rec.0));
        }
        fn enter(&self, _: &tracing::Id) {}
        fn exit(&self, _: &tracing::Id) {}
    }
}

/// The mandatory F1/F4 test: trip the latch with a **genuine** I/O
/// failure (a 0o500 directory — deterministic, no test double), repair
/// it, and prove the *production* retry path (not the test) clears the
/// latch on its own: `record()` starts succeeding again, the trip and
/// recovery diagnostics each fire exactly once, every record that was
/// allowed before the trip eventually lands, and no record that was
/// ever refused (`Err(Degraded)`) produces a line on disk.
#[cfg(unix)]
#[test]
fn genuine_io_failure_latches_and_recovers_automatically_through_the_retry_path() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    fs::create_dir(&state).unwrap();
    let path = state.join("audit.log");

    // `create_private_dir` no-ops when the directory already exists,
    // so it never chmods this back — `OpenOptions::create` then fails
    // EACCES inside a 0o500 directory. Deterministic, no disk-full
    // simulation needed (precedent: the adversarial-verification
    // harness's own L1 experiment).
    fs::set_permissions(&state, fs::Permissions::from_mode(0o500)).unwrap();

    let sink = Arc::new(capture::Sink::default());
    let sub = capture::Sub(sink.clone());
    tracing::subscriber::set_global_default(sub)
        .expect("no other test in this process sets a global subscriber");

    let retry_tick = Duration::from_millis(15);
    let (audit, handle) =
        RotatingAuditSink::spawn_joinable_with_retry_tick(&path, 64 * 1024, 5, 8, retry_tick);

    // Drive calls until the latch trips. Bounded busy-poll on the
    // observable `record()` result, never a `sleep()` — same shape as
    // the adversarial-verification harness's L1 experiment.
    let mut allowed_before_trip = 0u64;
    let mut trip_seen = false;
    for i in 0..200_000u64 {
        match audit.record(&record_for(i)) {
            Ok(()) => allowed_before_trip += 1,
            Err(AuditError::QueueFull) => {}
            Err(AuditError::Degraded) => {
                trip_seen = true;
                break;
            }
        }
        std::thread::yield_now();
    }
    assert!(trip_seen, "a real EACCES must latch the writer degraded");

    // Every call while still degraded is refused at the door — none
    // of these denied ops may ever reach the file.
    const DENIED_BASE: u64 = 1_000_000;
    for i in 0..1000u64 {
        assert_eq!(
            audit.record(&record_for(DENIED_BASE + i)),
            Err(AuditError::Degraded)
        );
    }

    // Repair: the directory is writable again. The *production* retry
    // path clears the latch on its own — poll the observable
    // `is_degraded()` flag, bounded, never a fixed sleep.
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let mut spins = 0u64;
    while audit.is_degraded() && spins < 50_000_000 {
        std::thread::yield_now();
        spins += 1;
    }
    assert!(
        !audit.is_degraded(),
        "the latch must clear through the automatic retry path"
    );

    // A fresh record() now succeeds.
    assert_eq!(audit.record(&record_for(999)), Ok(()));

    drop(audit);
    handle.join().unwrap();

    let text = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(text.ends_with('\n'));
    for line in &lines {
        let record: AuditRecord =
            serde_json::from_str(line).expect("every surviving line is valid JSON");
        let id: u64 = record.request_id.parse().unwrap();
        assert!(
            id < DENIED_BASE,
            "a denied op must never produce an audit line: {record:?}"
        );
    }
    assert_eq!(
        lines.len() as u64,
        allowed_before_trip + 1,
        "every pending (pre-trip allowed) record must land, plus the one post-recovery record"
    );

    let events = sink.events.lock().unwrap();
    let audit_events: Vec<&(String, String)> =
        events.iter().filter(|(t, _)| t == "qsh::audit").collect();
    let trips = audit_events
        .iter()
        .filter(|(_, fields)| fields.contains("degraded"))
        .count();
    let recoveries = audit_events
        .iter()
        .filter(|(_, fields)| fields.contains("recovered"))
        .count();
    assert_eq!(
        trips, 1,
        "the trip diagnostic must fire exactly once: {audit_events:?}"
    );
    assert_eq!(
        recoveries, 1,
        "the recovery diagnostic must fire exactly once: {audit_events:?}"
    );
}

// ---- F5: stale rotated files ---------------------------------------

#[test]
fn stale_rotated_files_above_retain_are_swept_on_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    // Simulate a host that previously ran with a larger `retain`.
    for n in 1..=4u32 {
        fs::write(rotated_path(&path, n), "x".repeat(50)).unwrap();
    }
    let (sink, handle) = RotatingAuditSink::spawn_joinable(&path, 100, 2, 64);
    for i in 0..30u64 {
        sink.record(&record_for(i)).unwrap();
    }
    drop(sink);
    handle.join().unwrap();

    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|name| !name.ends_with(".lock"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["audit.log", "audit.log.1", "audit.log.2"],
        "files above retain must be reclaimed"
    );
}

// ---- F6: multi-process (multi-writer) safety of rotation -----------

/// Two `RotatingAuditSink`s on the same path, writing concurrently from
/// two threads with a small `max_bytes` (forcing frequent rotation
/// contention) and a large `retain` (so retention itself never evicts
/// anything — any missing line is loss, not policy). Without F6's
/// flock + revalidate, the verifier measured 129/600 lines lost.
#[cfg(unix)]
#[test]
fn two_sinks_on_one_path_interleave_without_losing_or_corrupting_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let n = 150u64;
    let (sink_a, handle_a) = RotatingAuditSink::spawn_joinable(&path, 400, 500, 64);
    let (sink_b, handle_b) = RotatingAuditSink::spawn_joinable(&path, 400, 500, 64);

    fn record_retrying(sink: &RotatingAuditSink, record: &AuditRecord) {
        loop {
            match sink.record(record) {
                Ok(()) => return,
                Err(AuditError::QueueFull) => std::thread::yield_now(),
                Err(AuditError::Degraded) => {
                    panic!("this test must never see a real write failure")
                }
            }
        }
    }

    std::thread::scope(|scope| {
        scope.spawn(|| {
            for i in 0..n {
                record_retrying(&sink_a, &record_for(i));
            }
        });
        scope.spawn(|| {
            for i in 0..n {
                record_retrying(&sink_b, &record_for(1_000_000 + i));
            }
        });
    });

    drop(sink_a);
    drop(sink_b);
    handle_a.join().unwrap();
    handle_b.join().unwrap();

    let mut total_lines = 0usize;
    let mut bad = 0usize;
    for entry in fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "lock") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        for line in text.lines() {
            total_lines += 1;
            if serde_json::from_str::<serde_json::Value>(line).is_err() {
                bad += 1;
            }
        }
    }
    assert_eq!(
        total_lines,
        (2 * n) as usize,
        "no record may be lost to a concurrent co-writer"
    );
    assert_eq!(bad, 0, "no interleaved writer may corrupt a line");
}
