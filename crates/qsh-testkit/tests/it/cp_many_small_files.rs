//! M15 plan Step 15 (1a4af3b) / `docs/ROADMAP.md` M15 DoD "복사 중 PTY echo"
//! (ADR-0029 decisions 14 and 15, `docs/design/testing.md` L9/L10): a
//! recursive `qsh cp` of a tree of thousands of small files runs
//! concurrently, on the **same QUIC connection**, with PTY-echo round trips,
//! against a host whose audit sink is the production
//! [`RotatingAuditSink`] (bounded queue, fail-closed), and
//!
//! - the echo p95 stays inside the budget `file_copy_echo_under_load` and the
//!   tunnel harnesses use, the measured RTT plus 10ms, and
//! - the audit writer keeps up: no record is refused because the queue was
//!   full, and the copy itself never fails on an audit refusal.
//!
//! It is the many-small-files sibling of `file_copy_echo_under_load.rs`,
//! which moves two 32 MiB files. Small files stress a different resource:
//! every file is its own `file.read` or `file.write` and so its own audit
//! record, which is what the bounded queue of ADR-0029 decision 14's
//! "audit writer throughput" risk is about. The numbers it prints
//! (records per second, queue-full refusals, files per second) are what the
//! commit that landed `-r` records.
//!
//! The load alternates a recursive get and a recursive put of the same
//! 1000-file tree for the whole window (several thousand files), deleting
//! each copy's output as soon as it is done.
//!
//! After the measurement a probe pushes [`DRAIN_PROBE_RECORDS`] records at a
//! fresh production writer as fast as it will take them, which says how many
//! records per second the writer can drain. The copy's own demand is the
//! lower number: a file costs a disk `fsync` or two, which is slower than
//! the record it writes, so the audit queue is never the bottleneck.
//!
//! Gated like the other acceptance tests: `QSH_ACCEPTANCE_STRICT` or
//! `QSH_ACCEPTANCE_SLOW` turns it on, a plain run prints SKIP.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use qsh_core::acl::{Role, load_or_deny};
use qsh_core::audit::{AuditError, AuditRecord, AuditSink, RotatingAuditSink};
use qsh_core::broker::PipeHandle;
use qsh_core::client::AttachEvent;
use qsh_core::config::{AuditConfig, Paths};
use qsh_core::file::guard::FsNormalizer;
use qsh_core::ops::{CancelToken, FileCopyObserver, file_copy_over};
use qsh_core::trust::SharedTrustStore;
use qsh_proto::{FileCopyEntry, FileCopyReq, wire};
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_transport::{Principal, StaticTrust};

/// Wall-clock length of the concurrent copy+echo measurement.
const MEASUREMENT_DURATION: Duration = Duration::from_secs(15);

/// Floor on echo samples (same meaning as in the tunnel harness).
const MIN_SAMPLES: usize = 200;

/// Hang guard on one echo round.
const ROUND_TIMEOUT: Duration = Duration::from_secs(2);

/// Bytes in one echo round's marker (a big-endian round index).
const MARKER_BYTES: usize = 4;

/// `testing.md` L10's literal bound.
const MAX_MARGIN_MS: f64 = 10.0;

/// Directories and files per directory: 1000 files per copy. A get and a
/// put each fit well inside the measurement window, so both directions are
/// measured.
const DIRS: usize = 20;
const FILES_PER_DIR: usize = 50;

/// The copy must have moved at least this many files while the echo was
/// measured, or it did not load the connection and proves nothing.
const MIN_COPIED_FILES: u64 = 1000;

/// Records the audit-drain probe pushes through a fresh writer.
const DRAIN_PROBE_RECORDS: u64 = 100_000;

fn env_flag(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim();
    !(value.is_empty() || value == "0")
}

fn gate_requested() -> bool {
    env_flag("QSH_ACCEPTANCE_STRICT") || env_flag("QSH_ACCEPTANCE_SLOW")
}

fn skip() {
    eprintln!(
        "SKIP: the cp_many_small_files p95 gate requires QSH_ACCEPTANCE_SLOW=1 or \
         QSH_ACCEPTANCE_STRICT=1 (neither set on this run) - `.github/workflows/ci.yml`'s \
         acceptance job sets QSH_ACCEPTANCE_STRICT"
    );
}

/// Nearest-rank percentile (`p` in `[0, 1]`) over `samples`.
fn percentile(mut samples: Vec<f64>, p: f64) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let n = samples.len();
    let idx = ((n as f64) * p).ceil() as usize;
    samples[idx.saturating_sub(1).min(n - 1)]
}

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// Host-side "PTY" stand-in: echo every input chunk straight back.
async fn echo_loop(mut pipe: PipeHandle) {
    loop {
        let mut chunk = match pipe.read_input(MARKER_BYTES).await {
            Ok(bytes) if !bytes.is_empty() => bytes,
            _ => return,
        };
        while chunk.len() < MARKER_BYTES {
            match pipe.read_input(MARKER_BYTES - chunk.len()).await {
                Ok(more) if !more.is_empty() => chunk.extend_from_slice(&more),
                _ => return,
            }
        }
        if pipe.write_output(&chunk).await.is_err() {
            return;
        }
    }
}

/// The production audit writer behind a pair of counters: records it took
/// and records it refused (queue full or degraded), which is exactly the
/// fail-closed signal ADR-0029 decision 14 worries about.
struct CountingSink {
    inner: RotatingAuditSink,
    accepted: AtomicU64,
    queue_full: AtomicU64,
    degraded: AtomicU64,
}

impl AuditSink for CountingSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let result = self.inner.record(record);
        match &result {
            Ok(()) => self.accepted.fetch_add(1, Ordering::Relaxed),
            Err(AuditError::QueueFull) => self.queue_full.fetch_add(1, Ordering::Relaxed),
            Err(AuditError::Degraded) => self.degraded.fetch_add(1, Ordering::Relaxed),
        };
        result
    }
}

/// Counts the finished items of every copy.
#[derive(Default)]
struct Counter {
    files: AtomicU64,
    failed: AtomicU64,
}

impl FileCopyObserver for Counter {
    fn entry(&self, entry: &FileCopyEntry) {
        match entry.status.as_str() {
            "copied" => self.files.fetch_add(1, Ordering::Relaxed),
            "failed" => self.failed.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }
}

struct HostTree {
    _dir: tempfile::TempDir,
    paths: Paths,
    /// The tree both directions copy (served by the host for a get, the
    /// local source of a put).
    tree: PathBuf,
    /// Where gets land.
    out: PathBuf,
    /// Where puts land.
    stored: PathBuf,
}

fn small_file_bytes(dir: usize, file: usize) -> Vec<u8> {
    let len = (dir * 31 + file * 17) % 2048;
    (0..len)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add((dir + file) as u8))
        .collect()
}

impl HostTree {
    fn new(client_fingerprint: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canonical tempdir");
        let host = root.join("host");
        let tree = root.join("tree");
        let out = root.join("out");
        let stored = root.join("stored");
        for d in [
            &tree,
            &out,
            &stored,
            &host.join("config/identity"),
            &host.join("state"),
            &host.join("run"),
        ] {
            std::fs::create_dir_all(d).expect("create dir");
        }
        for d in 0..DIRS {
            let sub = tree.join(format!("d{d:02}"));
            std::fs::create_dir(&sub).expect("create tree dir");
            for f in 0..FILES_PER_DIR {
                std::fs::write(sub.join(format!("f{f:03}.dat")), small_file_bytes(d, f))
                    .expect("write tree file");
            }
        }
        let paths =
            Paths::new(host.join("config"), host.join("state")).with_runtime_dir(host.join("run"));
        let trust_text = format!(
            "[[peer]]\nname = \"laptop\"\nfingerprint = \"{client_fingerprint}\"\n\
             address = \"\"\nadded_at = \"2026-10-14T00:00:00Z\"\nrole = \"full\"\n\n"
        );
        std::fs::write(paths.trust_file(), trust_text).expect("write trust.toml");
        Self {
            _dir: dir,
            paths,
            tree,
            out,
            stored,
        }
    }
}

/// How many records per second a fresh production writer drains when a
/// producer offers them as fast as it can (retrying each refused record).
fn audit_drain_probe(paths: Paths) -> f64 {
    let config = AuditConfig::default();
    let path = config.path(&paths).with_file_name("drain-probe.log");
    let sink = RotatingAuditSink::spawn(
        path,
        config.max_bytes(),
        config.retain(),
        config.queue_depth(),
    );
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().expect("addr");
    let record = AuditRecord::handshake_rejected(peer, "probe");
    let started = Instant::now();
    let mut sent = 0u64;
    while sent < DRAIN_PROBE_RECORDS {
        match sink.record(&record) {
            Ok(()) => sent += 1,
            Err(AuditError::QueueFull) => std::thread::yield_now(),
            Err(AuditError::Degraded) => panic!("the probe writer degraded"),
        }
    }
    // Dropping the sink joins the writer after it drained the queue.
    drop(sink);
    DRAIN_PROBE_RECORDS as f64 / started.elapsed().as_secs_f64()
}

async fn remove_tree(path: PathBuf) {
    tokio::task::spawn_blocking(move || {
        let _ = std::fs::remove_dir_all(&path);
    })
    .await
    .expect("remove task");
}

#[tokio::test(flavor = "multi_thread")]
async fn cp_many_small_files_stays_within_the_echo_budget() {
    if !gate_requested() {
        skip();
        return;
    }

    let client = make_identity();
    let tree = HostTree::new(&client.fingerprint.to_string());
    let trust = SharedTrustStore::open(tree.paths.trust_file()).expect("open trust.toml");
    let (authorizer, _diagnostic) = load_or_deny(&tree.paths, Role::Serve, trust);
    let host_trust =
        StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));

    // The production audit writer with its production defaults.
    let audit_config = AuditConfig::default();
    let sink = Arc::new(CountingSink {
        inner: RotatingAuditSink::spawn(
            audit_config.path(&tree.paths),
            audit_config.max_bytes(),
            audit_config.retain(),
            audit_config.queue_depth(),
        ),
        accepted: AtomicU64::new(0),
        queue_full: AtomicU64::new(0),
        degraded: AtomicU64::new(0),
    });
    let h = LoopbackHarness::start_custom_with_audit_sink(
        authorizer,
        client,
        host_trust,
        sink.clone() as Arc<dyn AuditSink>,
    )
    .await;
    h.server.set_path_normalizer(Arc::new(FsNormalizer));
    h.server.set_file_host(tree.paths.clone(), audit_config);

    let mut session = h.session().await;
    let connection = session.connection().clone();

    // The PTY-echo stand-in, opened the production way.
    let opened = session
        .session_open(open_req())
        .await
        .expect("session.open");
    let pipe = h.pipes.take().expect("pipe handle for the opened session");
    let mut attached = session
        .attach(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: opened.resume_token.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: false,
        })
        .await
        .expect("attach the PTY-echo session");
    tokio::spawn(echo_loop(pipe));

    // The load: a recursive get, then a recursive put, of the same tree.
    let cancel = CancelToken::new();
    let counter = Arc::new(Counter::default());
    let accepted_before = sink.accepted.load(Ordering::Relaxed);
    let started = Instant::now();
    let load = {
        let cancel = cancel.clone();
        let counter = Arc::clone(&counter);
        let tree_dir = tree.tree.clone();
        let out = tree.out.clone();
        let stored = tree.stored.clone();
        tokio::spawn(async move {
            let mut rounds = 0u32;
            let mut failures = Vec::new();
            while !cancel.is_canceled() {
                let get = FileCopyReq {
                    sources: vec![format!("box:{}", tree_dir.display())],
                    destination: out.display().to_string(),
                    recursive: true,
                    preserve: false,
                    no_clobber: false,
                };
                let put = FileCopyReq {
                    sources: vec![tree_dir.display().to_string()],
                    destination: format!("box:{}", stored.display()),
                    recursive: true,
                    preserve: false,
                    no_clobber: false,
                };
                for req in [get, put] {
                    let observer: Arc<dyn FileCopyObserver> = counter.clone();
                    match file_copy_over(&mut session, &req, observer, &cancel).await {
                        Ok(_) => {}
                        Err(_) if cancel.is_canceled() => {}
                        Err(err) => failures.push(format!("{err:?}")),
                    }
                    remove_tree(out.join("tree")).await;
                    remove_tree(stored.join("tree")).await;
                }
                rounds += 1;
            }
            (session, rounds, failures)
        })
    };

    let mut margins_ms = Vec::new();
    let mut clamped_zero = 0usize;
    let deadline = Instant::now() + MEASUREMENT_DURATION;
    let mut next_round: u32 = 0;
    while Instant::now() < deadline {
        let round = next_round;
        next_round = next_round.wrapping_add(1);
        let marker = round.to_be_bytes().to_vec();

        let send_at = Instant::now();
        attached
            .send_input(&marker)
            .await
            .expect("send one echo round's input");

        let (echoed, recv_at) = loop {
            let event = tokio::time::timeout(ROUND_TIMEOUT, attached.next())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "round {round}: no attach-stream event within {ROUND_TIMEOUT:?} - the \
                         tree copy is starving PTY-echo delivery"
                    )
                })
                .expect("attach stream read")
                .expect("attach stream ended before this round's echo");
            match event {
                AttachEvent::Output { data, .. } => break (data, Instant::now()),
                AttachEvent::InputAck { .. } => continue,
                other => panic!("round {round}: unexpected attach event {other:?}"),
            }
        };
        assert_eq!(
            echoed, marker,
            "round {round}: echoed bytes must match what this round sent"
        );

        let rtt = connection.rtt();
        let elapsed = recv_at.saturating_duration_since(send_at);
        let margin = match elapsed.checked_sub(rtt) {
            Some(margin) => margin,
            None => {
                clamped_zero += 1;
                Duration::ZERO
            }
        };
        margins_ms.push(margin.as_secs_f64() * 1000.0);
    }

    let measured_for = started.elapsed();
    let copied_during = counter.files.load(Ordering::Relaxed);
    let records_during = sink.accepted.load(Ordering::Relaxed) - accepted_before;
    cancel.cancel();
    let (session, copy_rounds, failures) = tokio::time::timeout(Duration::from_secs(60), load)
        .await
        .expect("the background copy stopped after cancel")
        .expect("the copy task did not panic");
    attached.finish();
    session.close();
    h.shutdown().await;

    let drain = audit_drain_probe(tree.paths.clone());
    let queue_full = sink.queue_full.load(Ordering::Relaxed);
    let degraded = sink.degraded.load(Ordering::Relaxed);
    let failed_items = counter.failed.load(Ordering::Relaxed);
    let secs = measured_for.as_secs_f64();
    let rounds = margins_ms.len();
    let p95 = percentile(margins_ms.clone(), 0.95);
    let max = margins_ms.iter().cloned().fold(f64::MIN, f64::max);
    let min = margins_ms.iter().cloned().fold(f64::MAX, f64::min);
    let report = format!(
        "p95={p95:.3}ms (required < {MAX_MARGIN_MS}ms), min={min:.3}ms max={max:.3}ms, \
         rounds={rounds} (min {MIN_SAMPLES}), clamped_zero={clamped_zero}, \
         duration={MEASUREMENT_DURATION:?}, files={copied_during} ({:.0}/s, min {MIN_COPIED_FILES}), \
         audit_records={records_during} ({:.0}/s), audit_queue_full={queue_full}, \
         audit_degraded={degraded}, failed_items={failed_items}, copy_rounds={copy_rounds}, \
         audit_drain_capacity={drain:.0}/s",
        copied_during as f64 / secs,
        records_during as f64 / secs,
    );
    eprintln!("cp_many_small_files: {report}");
    assert!(
        failures.is_empty(),
        "a tree copy failed under load: {failures:?} - {report}"
    );
    assert_eq!(
        (queue_full, degraded, failed_items),
        (0, 0, 0),
        "the audit writer refused records or an item failed - {report}"
    );
    assert!(
        rounds >= MIN_SAMPLES,
        "harness fault: only {rounds} echo rounds fit in {MEASUREMENT_DURATION:?} (need \
         {MIN_SAMPLES} for a meaningful p95) - {report}"
    );
    assert!(
        copied_during >= MIN_COPIED_FILES,
        "harness fault: the copy moved too few files while the echo was measured, so the \
         connection was not loaded - {report}"
    );
    assert!(
        p95 < MAX_MARGIN_MS,
        "PTY-echo p95 under a concurrent qsh cp -r of small files exceeded measured RTT + 10ms: \
         {report}"
    );
}
