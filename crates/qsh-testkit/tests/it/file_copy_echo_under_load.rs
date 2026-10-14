//! M15 plan Step 14 (1a4af3b) / `docs/ROADMAP.md` M15 DoD "복사 중 PTY echo"
//! (ADR-0029 decision 15, `docs/design/testing.md` L9/L10): a `qsh cp`
//! transfer runs *concurrently*, on the **same QUIC connection**, with
//! repeated PTY-echo round trips over a `SESSION_DATA` attach stream, and the
//! echo p95 stays inside the budget the tunnel harnesses use, the measured
//! RTT plus 10ms.
//!
//! It is the file-transfer sibling of `tunnel_echo_under_load.rs` (read that
//! file's module doc for why one connection, why a client-originated round
//! trip and why a wall-clock bound). What differs:
//!
//! - The saturating load is [`qsh_core::ops::file_copy_over`], the production
//!   copy engine, run on the very [`Session`] the PTY attach was opened from.
//!   Its `FILE_DATA` streams ride band 0 (`PRIORITY_TUNNEL`) with the send
//!   depth cap and the stall ledger, the three knobs decision 15 names.
//! - The copy is a **get** of two 32 MiB files per call (two transfers at a
//!   time, `FILE_COPY_PARALLEL`), repeated back to back for the whole
//!   measurement. A get is the direction that makes the *host's* send
//!   scheduler arbitrate file bytes against PTY output, as in the tunnel
//!   test. The client's local disk write (temp file, `fsync`, rename) is
//!   part of the load.
//! - The host is a real `Server` with `set_file_host`, pinned to the harness
//!   client with the `full` role (`trust.toml`), so the copy is authorized
//!   exactly as in production.
//!
//! Gated like `tunnel_echo_under_load.rs`: `QSH_ACCEPTANCE_STRICT` or
//! `QSH_ACCEPTANCE_SLOW` turns it on, a plain run prints SKIP. `ci.yml`'s
//! acceptance job sets `QSH_ACCEPTANCE_STRICT`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use qsh_core::acl::{Role, load_or_deny};
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
const MEASUREMENT_DURATION: Duration = Duration::from_secs(10);

/// Floor on samples collected (same meaning as in the tunnel harness).
const MIN_SAMPLES: usize = 200;

/// Hang guard on one round.
const ROUND_TIMEOUT: Duration = Duration::from_secs(2);

/// Bytes in one echo round's marker (a big-endian round index).
const MARKER_BYTES: usize = 4;

/// `testing.md` L10's literal bound.
const MAX_MARGIN_MS: f64 = 10.0;

/// Size of each file the copy loop moves.
const FILE_BYTES: usize = 32 * 1024 * 1024;

/// The copy must have moved at least this much while the echo was measured,
/// or the run did not load the connection and proves nothing.
const MIN_COPIED_BYTES: u64 = 4 * FILE_BYTES as u64;

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
        "SKIP: the file_copy_echo_under_load p95 gate requires QSH_ACCEPTANCE_SLOW=1 or \
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

/// Counts the bytes of every finished item.
#[derive(Default)]
struct Counter {
    bytes: AtomicU64,
}

impl FileCopyObserver for Counter {
    fn entry(&self, entry: &FileCopyEntry) {
        if let Some(bytes) = entry.bytes {
            self.bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

/// A host state tree whose `trust.toml` pins the harness client as `laptop`
/// with the `full` role, and a directory of files to serve.
struct HostTree {
    _dir: tempfile::TempDir,
    paths: Paths,
    share: PathBuf,
    out: PathBuf,
}

fn write_file(path: &Path, seed: u8) {
    use std::io::Write as _;
    let mut file = std::fs::File::create(path).expect("create served file");
    let mut chunk = vec![0u8; 1 << 20];
    for (i, byte) in chunk.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(31).wrapping_add(seed);
    }
    for _ in 0..FILE_BYTES / chunk.len() {
        file.write_all(&chunk).expect("write served file");
    }
    file.sync_all().expect("sync served file");
}

impl HostTree {
    fn new(client_fingerprint: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canonical tempdir");
        let host = root.join("host");
        let share = root.join("share");
        let out = root.join("out");
        for d in [
            &share,
            &out,
            &host.join("config/identity"),
            &host.join("state"),
            &host.join("run"),
        ] {
            std::fs::create_dir_all(d).expect("create dir");
        }
        write_file(&share.join("a.bin"), 1);
        write_file(&share.join("b.bin"), 2);
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
            share,
            out,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn file_copy_echo_under_load() {
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
    let h = LoopbackHarness::start_custom(authorizer, client, host_trust).await;
    h.server.set_path_normalizer(Arc::new(FsNormalizer));
    h.server
        .set_file_host(tree.paths.clone(), AuditConfig::default());

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

    // The load: get both served files, over and over, on the same session.
    let cancel = CancelToken::new();
    let counter = Arc::new(Counter::default());
    let load = {
        let cancel = cancel.clone();
        let counter = Arc::clone(&counter);
        let req = FileCopyReq {
            sources: vec![
                format!("box:{}", tree.share.join("a.bin").display()),
                format!("box:{}", tree.share.join("b.bin").display()),
            ],
            destination: tree.out.display().to_string(),
            recursive: false,
            preserve: false,
            no_clobber: false,
        };
        tokio::spawn(async move {
            let mut copies = 0u32;
            while !cancel.is_canceled() {
                let observer: Arc<dyn FileCopyObserver> = counter.clone();
                match file_copy_over(&mut session, &req, observer, &cancel).await {
                    Ok(data) => {
                        assert_eq!(data.files, 2, "{data:?}");
                        copies += 1;
                    }
                    Err(err) if cancel.is_canceled() => {
                        eprintln!("copy ended by the harness: {err:?}");
                    }
                    Err(err) => panic!("the background copy failed: {err:?}"),
                }
            }
            (session, copies)
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
                         file copy is starving PTY-echo delivery"
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

    let copied_during = counter.bytes.load(Ordering::Relaxed);
    cancel.cancel();
    let (session, copies) = tokio::time::timeout(Duration::from_secs(30), load)
        .await
        .expect("the background copy stopped after cancel")
        .expect("the copy task did not panic");
    attached.finish();
    session.close();
    h.shutdown().await;

    let rounds = margins_ms.len();
    let p95 = percentile(margins_ms.clone(), 0.95);
    let max = margins_ms.iter().cloned().fold(f64::MIN, f64::max);
    let min = margins_ms.iter().cloned().fold(f64::MAX, f64::min);
    let report = format!(
        "p95={p95:.3}ms (required < {MAX_MARGIN_MS}ms), min={min:.3}ms max={max:.3}ms, \
         rounds={rounds} (min {MIN_SAMPLES}), clamped_zero={clamped_zero}, \
         duration={MEASUREMENT_DURATION:?}, copied_bytes={copied_during} (min {MIN_COPIED_BYTES}), \
         copy_calls={copies}"
    );
    eprintln!("file_copy_echo_under_load: {report}");
    assert!(
        rounds >= MIN_SAMPLES,
        "harness fault: only {rounds} echo rounds fit in {MEASUREMENT_DURATION:?} (need \
         {MIN_SAMPLES} for a meaningful p95) - {report}"
    );
    assert!(
        copied_during >= MIN_COPIED_BYTES,
        "harness fault: the copy moved too little while the echo was measured, so the connection \
         was not loaded - {report}"
    );
    assert!(
        p95 < MAX_MARGIN_MS,
        "PTY-echo p95 under a concurrent qsh cp exceeded measured RTT + 10ms: {report}"
    );
}
