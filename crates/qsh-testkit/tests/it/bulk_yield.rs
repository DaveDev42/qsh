//! Bulk yields to interactive traffic on a shared bottleneck (ADR-0052
//! decision 12 (a), decision 18 item 6).
//!
//! One QUIC connection carries a saturating tunnel (host to client, the
//! direction PTY output shares with it) and a PTY-echo session, through a
//! chaos proxy that makes the path a 20 Mbit/s link with a 25 ms one-way
//! delay (RTT 50 ms) and a drop-tail queue. Two queue depths are run: deep
//! (600 ms of drain time) and shallow (20 ms). The gates:
//!
//! - **Echo.** With the tunnel saturated, the round trip of a key echo has
//!   p95 <= the connection's `min_rtt` + 50 ms.
//! - **Throughput.** With no interactive traffic, the tunnel alone carries
//!   >= 80% of the link rate.
//!
//! The saturating load is either a tunnel ([`Load::Tunnel`]) or a `qsh cp`
//! get ([`Load::FileCopy`], `FILE_DATA` streams run by the production copy
//! engine on the same session as the PTY attach). Both are bulk senders that
//! pay the same budget (protocol.md "bulk 양보"), so the cp scenario checks that
//! `FILE_DATA` keeps the echo as well as a tunnel does.
//!
//! The throughput phase runs first, with the echo session attached but
//! silent, so the budget has to switch itself off when nobody types. Gated by
//! `QSH_ACCEPTANCE_SLOW` like the other acceptance gates.

use std::net::SocketAddr;
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
use qsh_core::tunnel::LocalForwardHandle;
use qsh_proto::{FileCopyEntry, FileCopyReq, wire};
use qsh_testkit::chaos::{ChaosPolicy, DelayDist};
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_testkit::tunnel::{FloodServer, ephemeral_local_spec};
use qsh_transport::{Principal, StaticTrust};
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpStream;

/// The link: 20 Mbit/s.
const LINK_BITS_PER_SEC: u64 = 20_000_000;
const LINK_BYTES_PER_SEC: f64 = LINK_BITS_PER_SEC as f64 / 8.0;
/// One-way propagation delay; the RTT is twice this.
const ONE_WAY: Duration = Duration::from_millis(25);
/// ADR-0052 decision 18 item 6: echo p95 may exceed `min_rtt` by this much.
const ECHO_MARGIN_MS: f64 = 50.0;
/// ADR-0052 decision 18 item 6: tunnel share of the link without interactive
/// traffic.
const MIN_LINK_SHARE: f64 = 0.80;
/// The same floor for the cp load; see `min_share` in `run`.
const MIN_CP_LINK_SHARE: f64 = 0.70;
/// Settling time before a phase is measured (BBR start-up, budget ramp).
const WARMUP: Duration = Duration::from_secs(4);
/// Throughput phase length after the warm-up.
const THROUGHPUT_WINDOW: Duration = Duration::from_secs(6);
/// Echo phase length after the warm-up.
const ECHO_WINDOW: Duration = Duration::from_secs(15);
/// A key every this often, like a person typing quickly.
const KEY_INTERVAL: Duration = Duration::from_millis(50);
const MIN_SAMPLES: usize = 100;
const ROUND_TIMEOUT: Duration = Duration::from_secs(5);
const MARKER_BYTES: usize = 4;
/// Size of each file the cp load serves, and how many per copy call. Small
/// enough that the per-file byte counter moves several times a second at the
/// link rate, so a 6 s window can be read off it.
const CP_FILE_BYTES: usize = 1024 * 1024;
const CP_FILES: usize = 32;

/// What saturates the link while the echo is measured.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Load {
    Tunnel,
    FileCopy,
}

fn gate_requested() -> bool {
    ["QSH_ACCEPTANCE_SLOW", "QSH_ACCEPTANCE_STRICT"]
        .iter()
        .any(|n| {
            std::env::var(n).is_ok_and(|v| {
                let v = v.trim().to_lowercase();
                !(v.is_empty() || v == "0")
            })
        })
}

fn percentile(mut samples: Vec<f64>, p: f64) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let n = samples.len();
    let idx = ((n as f64) * p).ceil() as usize;
    samples[idx.saturating_sub(1).min(n - 1)]
}

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

/// Count what the tunnel delivers; the total is read through the counter.
async fn drain(addr: SocketAddr, total: Arc<AtomicU64>) {
    let mut conn = TcpStream::connect(addr)
        .await
        .expect("connect the -L listener");
    conn.set_nodelay(true).ok();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match conn.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                total.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }
}

/// Adds the bytes of every finished copy item to a shared counter.
struct CopyCounter(Arc<AtomicU64>);

impl FileCopyObserver for CopyCounter {
    fn entry(&self, entry: &FileCopyEntry) {
        if let Some(bytes) = entry.bytes {
            self.0.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

/// The directory as the host spells it: canonical, and on Windows without
/// the `\\?\` prefix the system puts on a final path.
fn canonical_host_path(path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(path).expect("canonical tempdir");
    match canonical.to_str().and_then(|p| p.strip_prefix(r"\\?\")) {
        Some(plain) => PathBuf::from(plain),
        None => canonical,
    }
}

/// A host state tree whose `trust.toml` pins the harness client with the
/// `full` role, a directory of files to serve and one to copy into.
struct CpTree {
    _dir: tempfile::TempDir,
    paths: Paths,
    share: PathBuf,
    out: PathBuf,
}

impl CpTree {
    fn new(client_fingerprint: &str) -> Self {
        use std::io::Write as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = canonical_host_path(dir.path());
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
        let chunk: Vec<u8> = (0..CP_FILE_BYTES)
            .map(|i| (i as u8).wrapping_mul(31))
            .collect();
        for n in 0..CP_FILES {
            let mut file = std::fs::File::create(share.join(format!("f{n:02}.bin")))
                .expect("create served file");
            file.write_all(&chunk).expect("write served file");
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
            share,
            out,
        }
    }

    fn request(&self) -> FileCopyReq {
        FileCopyReq {
            sources: (0..CP_FILES)
                .map(|n| format!("box:{}", self.share.join(format!("f{n:02}.bin")).display()))
                .collect(),
            destination: self.out.display().to_string(),
            recursive: false,
            preserve: false,
            no_clobber: false,
        }
    }
}

async fn run(name: &str, queue: Duration, adaptive: bool, load: Load) {
    if !gate_requested() {
        eprintln!("SKIP: {name} needs QSH_ACCEPTANCE_SLOW=1");
        return;
    }
    // `[transport].adaptive = "off"` (set before any connection exists).
    qsh_core::adapt::set_process_adaptive(adaptive);
    let policy = ChaosPolicy::seeded(0xB01C)
        .delay(DelayDist::fixed(ONE_WAY))
        .rate_with_queue_delay(LINK_BITS_PER_SEC, queue);
    let tree;
    let h = match load {
        Load::Tunnel => {
            tree = None;
            LoopbackHarness::start_chaotic(policy).await
        }
        Load::FileCopy => {
            // The host is a real `Server` with `set_file_host`, pinned to the
            // harness client with the `full` role, as in production.
            let client = make_identity();
            let t = CpTree::new(&client.fingerprint.to_string());
            let trust = SharedTrustStore::open(t.paths.trust_file()).expect("open trust.toml");
            let (authorizer, _diagnostic) = load_or_deny(&t.paths, Role::Serve, trust);
            let host_trust = StaticTrust::empty()
                .with_pin(client.fingerprint, Principal::Device("laptop".into()));
            let h =
                LoopbackHarness::start_chaotic_custom(authorizer, client, host_trust, policy).await;
            h.server.set_path_normalizer(Arc::new(FsNormalizer));
            h.server
                .set_file_host(t.paths.clone(), AuditConfig::default());
            tree = Some(t);
            h
        }
    };
    let mut session = h.session().await;
    let connection = session.connection().clone();
    let total = Arc::new(AtomicU64::new(0));

    // The tunnel load starts before the session opens, as it always has.
    let tunnel = if load == Load::Tunnel {
        let (flood, flood_done) = FloodServer::start().await.expect("bind flood source");
        let forward = LocalForwardHandle::start(
            &ephemeral_local_spec("127.0.0.1", flood.addr().port()),
            connection.clone(),
        )
        .await
        .expect("bind the saturating local forward");
        let drain_task = tokio::spawn(drain(forward.local_addr(), total.clone()));
        Some((flood, forward, drain_task, flood_done))
    } else {
        None
    };

    let opened = session
        .session_open(wire::SessionOpen {
            argv: vec!["sh".into()],
            cols: 80,
            rows: 24,
            term: "xterm-256color".into(),
            ..Default::default()
        })
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
            screen: None,
            agent_channel: Vec::new(),
        })
        .await
        .expect("attach the PTY-echo session");
    tokio::spawn(echo_loop(pipe));

    // The cp load: get the files over and over on the very session the PTY
    // attach was opened from, until cancelled.
    let cancel = CancelToken::new();
    let (mut session, cp_task) = match &tree {
        None => (Some(session), None),
        Some(tree) => {
            let req = tree.request();
            let cancel = cancel.clone();
            let counter = Arc::new(CopyCounter(total.clone()));
            let task = tokio::spawn(async move {
                while !cancel.is_canceled() {
                    let observer: Arc<dyn FileCopyObserver> = counter.clone();
                    match file_copy_over(&mut session, &req, observer, &cancel).await {
                        Ok(data) => assert_eq!(data.files as usize, CP_FILES, "{data:?}"),
                        Err(err) if cancel.is_canceled() => {
                            eprintln!("copy ended by the harness: {err:?}");
                        }
                        Err(err) => panic!("the background copy failed: {err:?}"),
                    }
                }
                session
            });
            (None, Some(task))
        }
    };

    // Phase 1: the tunnel alone.
    tokio::time::sleep(WARMUP).await;
    let (b0, t0) = (total.load(Ordering::Relaxed), Instant::now());
    tokio::time::sleep(THROUGHPUT_WINDOW).await;
    let (b1, t1) = (total.load(Ordering::Relaxed), Instant::now());
    let tunnel_alone = (b1 - b0) as f64 / (t1 - t0).as_secs_f64();

    // Phase 2: typing on top of the saturated tunnel.
    let drops_before = h.chaos.as_ref().map_or(0, |c| c.stats().queue_dropped);
    let mut echo_ms = Vec::new();
    let mut min_rtt_ms = f64::MAX;
    let start = Instant::now();
    let warm_until = start + WARMUP;
    let end = warm_until + ECHO_WINDOW;
    let (mut c0, mut ct0) = (0u64, warm_until);
    let mut round = 0u32;
    let mut next_key = start;
    let mut measured = false;
    while Instant::now() < end {
        tokio::time::sleep_until(next_key.into()).await;
        next_key += KEY_INTERVAL;
        let marker = round.to_be_bytes().to_vec();
        round += 1;
        let sent = Instant::now();
        attached.send_input(&marker).await.expect("send a key");
        let recv_at = loop {
            let event = tokio::time::timeout(ROUND_TIMEOUT, attached.next())
                .await
                .unwrap_or_else(|_| panic!("round {round}: no echo within {ROUND_TIMEOUT:?}"))
                .expect("attach stream read")
                .expect("attach stream ended");
            match event {
                AttachEvent::Output { data, .. } => {
                    assert_eq!(data, marker, "round {round}: echoed bytes");
                    break Instant::now();
                }
                AttachEvent::InputAck { .. } => continue,
                other => panic!("round {round}: unexpected attach event {other:?}"),
            }
        };
        if sent >= warm_until {
            if !measured {
                measured = true;
                c0 = total.load(Ordering::Relaxed);
                ct0 = Instant::now();
            }
            echo_ms.push(recv_at.saturating_duration_since(sent).as_secs_f64() * 1000.0);
            min_rtt_ms = min_rtt_ms.min(connection.stats().min_rtt.as_secs_f64() * 1000.0);
        }
    }
    let c1 = total.load(Ordering::Relaxed);
    let tunnel_typing = (c1 - c0) as f64 / ct0.elapsed().as_secs_f64();

    let drops = h
        .chaos
        .as_ref()
        .map_or(0, |c| c.stats().queue_dropped)
        .saturating_sub(drops_before);
    attached.finish();
    if let Some(task) = cp_task {
        cancel.cancel();
        session = Some(
            tokio::time::timeout(Duration::from_secs(30), task)
                .await
                .expect("the background copy stopped after cancel")
                .expect("the copy task did not panic"),
        );
    }
    session.take().expect("the session").close();
    if let Some((flood, forward, drain_task, flood_done)) = tunnel {
        drop(forward);
        drain_task.abort();
        let _ = flood_done.await;
        drop(flood);
    }
    h.shutdown().await;

    let p50 = percentile(echo_ms.clone(), 0.5);
    let p95 = percentile(echo_ms.clone(), 0.95);
    let max = echo_ms.iter().copied().fold(f64::MIN, f64::max);
    let share_alone = tunnel_alone / LINK_BYTES_PER_SEC;
    let share_typing = tunnel_typing / LINK_BYTES_PER_SEC;
    // The cp load is read off a per-file byte counter, so one finished
    // 1 MiB file moves the 6 s window by about 7% of the link, and each file
    // costs the copy engine request round trips the tunnel does not pay.
    // Its floor is lower for that reason; the echo gate is the same.
    let min_share = match load {
        Load::Tunnel => MIN_LINK_SHARE,
        Load::FileCopy => MIN_CP_LINK_SHARE,
    };
    let report = format!(
        "{name}: echo p50={p50:.1}ms p95={p95:.1}ms max={max:.1}ms (min_rtt={min_rtt_ms:.1}ms, \
         bar min_rtt+{ECHO_MARGIN_MS}), samples={}, tunnel alone={:.2} MB/s ({:.0}% of link), \
         tunnel while typing={:.2} MB/s ({:.0}%), queue_dropped while typing={drops}",
        echo_ms.len(),
        tunnel_alone / 1e6,
        share_alone * 100.0,
        tunnel_typing / 1e6,
        share_typing * 100.0,
    );
    eprintln!("{report}");
    if !adaptive {
        // Nothing yields: the bulk fills the 600 ms queue and the echo waits
        // behind it, as it did before the budget existed.
        assert!(
            p95 > min_rtt_ms + 2.0 * ECHO_MARGIN_MS,
            "adaptive = off must leave bulk alone, but the echo was protected: {report}"
        );
        assert!(
            share_alone >= min_share,
            "bulk without interactive traffic below {:.0}% of the link: {report}",
            min_share * 100.0
        );
        return;
    }
    assert!(
        echo_ms.len() >= MIN_SAMPLES,
        "too few echo samples: {report}"
    );
    assert!(
        p95 <= min_rtt_ms + ECHO_MARGIN_MS,
        "echo p95 above min_rtt + 50 ms: {report}"
    );
    assert!(
        share_alone >= min_share,
        "bulk without interactive traffic below {:.0}% of the link: {report}",
        min_share * 100.0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_yields_to_echo_on_a_deep_queue() {
    run(
        "deep queue (600 ms)",
        Duration::from_millis(600),
        true,
        Load::Tunnel,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_yields_to_echo_on_a_shallow_queue() {
    run(
        "shallow queue (20 ms)",
        Duration::from_millis(20),
        true,
        Load::Tunnel,
    )
    .await;
}

/// The same shallow queue with a `qsh cp` get as the bulk: `FILE_DATA` pays
/// the same budget as a tunnel splice, so the echo gate must hold for it too.
#[tokio::test(flavor = "multi_thread")]
async fn bulk_yields_to_echo_on_a_shallow_queue_under_file_copy() {
    run(
        "shallow queue (20 ms), qsh cp",
        Duration::from_millis(20),
        true,
        Load::FileCopy,
    )
    .await;
}

/// `[transport].adaptive = "off"` (decision 15): no budget, so the deep queue
/// is filled by the bulk and the echo pays for all of it.
#[tokio::test(flavor = "multi_thread")]
async fn bulk_does_not_yield_when_adaptive_is_off() {
    run(
        "deep queue (600 ms), adaptive off",
        Duration::from_millis(600),
        false,
        Load::Tunnel,
    )
    .await;
}
