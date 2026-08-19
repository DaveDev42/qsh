//! The recovery gate, driven through the product path (`PLAN.md` M2 Step 7
//! (a), `docs/ROADMAP.md` M2 수용 기준 4, `docs/design/testing.md` L4).
//!
//! Every other resume test in the tree builds its own re-dial by hand. This
//! one does not touch `recover` at all: it opens a session with `Ops`,
//! attaches with `Ops`, kills the path underneath, and then keeps using the
//! same [`SessionAttachStream`] — because the promise the product makes is
//! that a client *does not notice*.
//!
//! The criterion is narrow on purpose, because the loose version of it is
//! satisfiable by doing nothing (quinn's idle timeout is 45 s, so a client
//! that simply waits recovers "eventually"):
//!
//! - the client is never told the path died — no `close()`, no re-attach by
//!   the test, no second `Ops` call;
//! - the recovery record the driver emits is parsed, and its
//!   `time_to_recovery_ms` is cross-checked against the wall clock the test
//!   measured for itself — the record alone proves nothing, because
//!   `recover` caps its own attempt at the same bound, so every `resumed`
//!   record is inside it by construction. There must also be exactly one
//!   record, so a recovery that only worked on the third attempt fails;
//! - the wall clock is held to **detection + recovery**, both derived from
//!   the shipping config rather than written down here, so pushing the
//!   probe cadence or the strike count out fails this test instead of
//!   quietly quintupling the user-visible outage. (The clock in the record
//!   starts at *detection*; the wall clock is the only thing that bounds
//!   the detection half.);
//! - and the delivered `sequence` values are checked to tile the output
//!   stream exactly — every byte once, in order, across the seam. That is
//!   what "byte-identical to a reference stream" means when the cursor is a
//!   cumulative byte offset.
//!
//! Sessions are PTY-backed, so this file only exists on POSIX hosts.

#![cfg(unix)]

mod common;

use std::collections::HashSet;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::{HOST_ALIAS, Sandbox, ServeGuard};
use qsh_core::{Ops, Paths, RecoveryConfig, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{EnvVar, SessionAttachReq, SessionOpenReq};
use qsh_testkit::chaos::{ChaosPolicy, ChaosProxy};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Wall-clock bound for one recovery scenario end to end. Generous, because
/// everything inside is a real round trip against a real `qsh serve`; a hang
/// is a failure, not a wait.
const DEADLINE: Duration = Duration::from_secs(90);

/// The contract bound from `docs/design/testing.md` L4, restated here so a
/// change to it fails this test rather than passing quietly.
const REDIAL_DEADLINE_MS: u64 = 2_000;

/// quinn's idle timeout (`docs/design/protocol.md` §2). A recovery that
/// takes anywhere near this long recovered by waiting, which L4 defines as
/// a failure.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Room for everything the bounds below do not model: a real `qsh serve`
/// on a loaded CI box, the shell's own round trip, and the proxy in the
/// middle. Generous, but an order of magnitude short of the idle timeout —
/// which is the point, because "the idle timeout eventually fired" must
/// not be able to pass.
const SCHEDULING_SLACK: Duration = Duration::from_secs(3);

/// The longest the watchdog may take to call a silent path dead, derived
/// from the config the product actually ships rather than restated: a
/// strike per probe interval, and then the silence floor.
///
/// Derived rather than hard-coded so that loosening the detector — a
/// slower cadence, more strikes — fails this test, instead of passing it
/// while the outage the user sees grows.
fn detection_budget(cfg: &qsh_core::PathWatchConfig) -> Duration {
    cfg.probe_interval * cfg.strikes + cfg.min_dead_after
}

// ---------------------------------------------------------------------------
// recovery telemetry capture
// ---------------------------------------------------------------------------

/// Every `qsh::recovery` line this test binary produced, in order.
///
/// A process-wide sink because the records are emitted from runtime worker
/// threads the test never sees; each test filters by its own `session_ref`,
/// which is unique per session.
fn recovery_lines() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

/// Install the capturing subscriber once per test binary.
fn capture_recovery_records() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::registry()
            .with(CaptureLayer)
            .try_init()
            .ok();
    });
}

struct CaptureLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != qsh_core::telemetry::TARGET {
            return;
        }
        let mut line = String::new();
        event.record(&mut MessageOnly(&mut line));
        if !line.is_empty() {
            recovery_lines()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(line);
        }
    }
}

struct MessageOnly<'a>(&'a mut String);

impl tracing::field::Visit for MessageOnly<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }
}

/// One parsed recovery record.
#[derive(Debug, Clone)]
struct RecoveryRecord {
    recovery: String,
    time_to_recovery_ms: u64,
}

/// Every record emitted for `session_ref`, oldest first.
fn records_for(session_ref: &str) -> Vec<RecoveryRecord> {
    recovery_lines()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("a recovery line must be pure JSON ({err}): {line}"));
            (value["session_ref"].as_str() == Some(session_ref)).then(|| RecoveryRecord {
                recovery: value["recovery"].as_str().expect("recovery").to_string(),
                time_to_recovery_ms: value["time_to_recovery_ms"]
                    .as_u64()
                    .expect("time_to_recovery_ms"),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// harness: a real `qsh serve` behind a chaos proxy
// ---------------------------------------------------------------------------

/// A host, a client that pins it, and a chaos proxy the client dials
/// instead of the host — so the path between them can be destroyed while
/// both ends stay perfectly healthy.
struct ProxiedFleet {
    host: Sandbox,
    client: Sandbox,
    /// Held for the fleet's life: dropping it kills the host.
    _serve: ServeGuard,
    proxy: Arc<ChaosProxy>,
    /// Drives the proxy. Held for the fleet's life; dropping it stops the
    /// relay.
    runtime: tokio::runtime::Runtime,
}

impl ProxiedFleet {
    fn start(policy: ChaosPolicy) -> Self {
        let host = Sandbox::new();
        let client = Sandbox::new();
        let host_fingerprint = host.fingerprint();
        let client_fingerprint = client.fingerprint();
        host.trust_add(common::CLIENT_ALIAS, None, &client_fingerprint);
        let serve = ServeGuard::start(&host);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("proxy runtime");
        let server: SocketAddr = serve.addr().parse().expect("serve address");
        let proxy = Arc::new(
            runtime
                .block_on(ChaosProxy::start(server, policy))
                .expect("chaos proxy"),
        );
        // The client is pinned to the *proxy*: every packet it sends is one
        // the test can drop on the floor.
        client.trust_add(
            HOST_ALIAS,
            Some(&proxy.addr().to_string()),
            &host_fingerprint,
        );
        Self {
            host,
            client,
            _serve: serve,
            proxy,
            runtime,
        }
    }

    /// The one-line context every chaos assertion carries — it prints the
    /// seed (`docs/design/testing.md`, CI 규율).
    fn context(&self) -> String {
        self.proxy.context()
    }

    fn detail(&self) -> String {
        self.proxy.detail()
    }

    fn ops(&self, recovery: RecoveryConfig) -> Ops {
        Ops::new(Paths::new(
            self.client.config_dir().to_path_buf(),
            self.client.state_dir().to_path_buf(),
        ))
        .with_recovery(recovery)
    }

    /// How many `session.attach` decisions the host allowed. A resume is a
    /// second one, recorded by the host itself rather than inferred by the
    /// client.
    fn attach_allows(&self) -> usize {
        self.host
            .audit_records()
            .iter()
            .filter(|record| record["action"] == "session.attach" && record["decision"] == "allow")
            .count()
    }
}

// ---------------------------------------------------------------------------
// stream helpers
// ---------------------------------------------------------------------------

/// Everything an attach delivered, with the cumulative offsets it claimed.
#[derive(Default)]
struct Delivered {
    text: String,
    /// `(sequence_after, len)` for every output frame, in delivery order.
    frames: Vec<(u64, usize)>,
    gaps: Vec<(u64, u64)>,
}

impl Delivered {
    fn push(&mut self, sequence: u64, data: &[u8]) {
        self.text.push_str(&String::from_utf8_lossy(data));
        self.frames.push((sequence, data.len()));
    }

    /// Assert the frames tile the byte stream: each one starts exactly
    /// where the previous ended.
    ///
    /// This *is* the byte-identity check. The offsets are cumulative byte
    /// counts of the host's own stream, so a contiguous cover from the
    /// first frame to the last says the client saw the host's bytes once
    /// each, in order — with no gap at the seam a recovery leaves and no
    /// byte redelivered across it.
    fn assert_tiles_the_stream(&self, ctx: &str) {
        assert!(self.gaps.is_empty(), "unexpected replay gap(s) — {ctx}");
        let mut expected = self
            .frames
            .first()
            .map(|(seq, len)| seq - *len as u64)
            .unwrap_or(0);
        for (index, (sequence, len)) in self.frames.iter().enumerate() {
            let start = sequence - *len as u64;
            assert_eq!(
                start,
                expected,
                "frame {index} starts at {start} but the stream had reached {expected}: \
                 {} — {ctx}",
                if start > expected {
                    "bytes were lost"
                } else {
                    "bytes were redelivered"
                }
            );
            expected = *sequence;
        }
    }
}

/// Drain events until the accumulated output contains `needle`.
fn read_until(stream: &mut SessionAttachStream, seen: &mut Delivered, needle: &str, ctx: &str) {
    while let Some(event) = stream.next_event() {
        match event.unwrap_or_else(|err| panic!("attach stream failed: {err} — {ctx}")) {
            SessionEvent::Output {
                sequence, data_b64, ..
            } => {
                use base64::Engine as _;
                let data = base64::engine::general_purpose::STANDARD
                    .decode(data_b64.as_bytes())
                    .expect("session output is Base64");
                seen.push(sequence, &data);
                if seen.text.contains(needle) {
                    return;
                }
            }
            SessionEvent::Gap {
                requested_after,
                available_from,
                ..
            } => seen.gaps.push((requested_after, available_from)),
            SessionEvent::Exit { .. } | SessionEvent::Closed { .. } => panic!(
                "the session ended before {needle:?} arrived; saw {:?} — {ctx}",
                seen.text
            ),
            _ => {}
        }
    }
    panic!(
        "the attach stream ended before {needle:?} arrived; saw {:?} — {ctx}",
        seen.text
    );
}

/// Run `scenario` on a worker thread and fail — loudly — if it has not
/// finished within [`DEADLINE`]. The blocking `Ops` API has no timeout of
/// its own, so this is what turns a wedged attach into a failure instead of
/// a hung suite.
fn with_deadline<T: Send + 'static>(
    what: &'static str,
    scenario: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(scenario());
    });
    match rx.recv_timeout(DEADLINE) {
        Ok(value) => {
            worker.join().expect("scenario thread panicked");
            value
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => panic!("{what} produced no result"),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{what} did not finish within {DEADLINE:?}")
        }
    }
}

fn open_shell(ops: &Ops) -> String {
    ops.session_open(SessionOpenReq {
        host: HOST_ALIAS.to_string(),
        argv: vec!["sh".to_string()],
        env: vec![
            EnvVar {
                name: "LANG".into(),
                value: "C".into(),
            },
            EnvVar {
                name: "PS1".into(),
                value: String::new(),
            },
        ],
        term: Some("xterm-256color".into()),
        cols: Some(80),
        rows: Some(24),
        user: None,
    })
    .expect("session.open")
    .session_ref
}

fn attach(ops: &Ops, session_ref: &str) -> SessionAttachStream {
    ops.session_attach(SessionAttachReq {
        session_ref: session_ref.to_string(),
        no_steal: false,
    })
    .expect("session.attach")
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

/// **DoD 4, second half.** `sever()` — the path is gone for good — and the
/// attach the frontend is holding keeps working, because the driver noticed,
/// re-dialed and resumed underneath it.
#[test]
fn a_severed_path_is_detected_and_resumed_under_a_live_attach() {
    capture_recovery_records();
    let fleet = ProxiedFleet::start(ChaosPolicy::seeded(0x5E4E_57ED));
    let ctx = fleet.context();
    // Migration off. Not because it would be wrong, but because the chaos
    // proxy models a dead path by blacklisting the client's *source
    // address*, and a rebind escapes that by definition — the proxy cannot
    // express "a path no local socket can reach". Correctness comes from
    // resume alone, which is exactly the claim `protocol.md` §2 makes about
    // migration being only an optimization; the migration half is covered by
    // `a_repath_is_survived_by_the_live_attach` and by
    // `resume_chaos::rebinding_the_client_endpoint_keeps_the_connection`.
    let ops = fleet.ops(RecoveryConfig {
        migration: false,
        ..RecoveryConfig::default()
    });
    let session_ref = open_shell(&ops);
    let attaches_before = fleet.attach_allows();

    let (seen, elapsed, records) = {
        let session_ref = session_ref.clone();
        let ctx = ctx.clone();
        let severer = {
            // `sever` needs the fleet, which the scenario thread does not
            // own; hand it a closure over an `Arc` of the proxy instead.
            let proxy = fleet.proxy.clone();
            let handle = fleet.runtime.handle().clone();
            move || handle.block_on(proxy.sever())
        };
        with_deadline("severed-path recovery", move || {
            let mut stream = attach(&ops, &session_ref);
            let mut seen = Delivered::default();
            stream
                .write(b"printf 'BEFORE%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "BEFORE1", &ctx);

            // ---- the path dies here; nothing else is told ----
            let started = Instant::now();
            severer();
            // Typed into a session whose path is already dead: the bytes
            // are the client's responsibility now, and the resume owes them
            // to the shell exactly once.
            stream
                .write(b"printf 'AFTER%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "AFTER1", &ctx);
            let elapsed = started.elapsed();

            // A second command on the recovered connection: its answer is
            // what proves any duplicate of the first would already have
            // arrived, because the stream is ordered.
            stream
                .write(b"printf 'DONE%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "DONE1", &ctx);

            let records = records_for(&session_ref);
            stream.close();
            (seen, elapsed, records)
        })
    };

    // The recovery happened, it was a resume, and it fit the bound.
    assert_eq!(
        records.len(),
        1,
        "expected exactly one recovery record, got {records:?} — {}",
        fleet.detail()
    );
    assert_eq!(
        records[0].recovery,
        "resumed",
        "{records:?} — {}",
        fleet.detail()
    );
    assert!(
        records[0].time_to_recovery_ms <= REDIAL_DEADLINE_MS,
        "recovery took {} ms, over the {REDIAL_DEADLINE_MS} ms bound — {}",
        records[0].time_to_recovery_ms,
        fleet.detail()
    );
    // The line above is true by construction — `recover` caps its own
    // attempt at exactly that bound, so a `resumed` record cannot exceed
    // it. This is what makes it mean something: the driver's own clock has
    // to fit inside the clock the test kept independently, which starts
    // earlier (at the sever) and ends later (after the shell answered).
    assert!(
        u128::from(records[0].time_to_recovery_ms) <= elapsed.as_millis(),
        "the driver reported a {} ms recovery inside a {elapsed:?} window it is nested in — {}",
        records[0].time_to_recovery_ms,
        fleet.detail()
    );
    // The real end-to-end bound, and the only one that constrains the
    // *detection* half: noticing plus recovering plus a shell round trip.
    let budget = detection_budget(&RecoveryConfig::default().watch)
        + Duration::from_millis(REDIAL_DEADLINE_MS)
        + SCHEDULING_SLACK;
    assert!(
        elapsed < budget,
        "the path death took {elapsed:?} to turn back into a working shell, over the \
         {budget:?} detection+recovery budget — {}",
        fleet.detail()
    );
    // …and the same measurement said the other way, so the reason this
    // passes can never be "quinn's idle timeout fired and something
    // reconnected".
    assert!(
        elapsed < IDLE_TIMEOUT / 2,
        "the path death took {elapsed:?} to turn back into a working shell; \
         quinn's idle timeout is {IDLE_TIMEOUT:?}, so this recovered by waiting — {}",
        fleet.detail()
    );

    // The stream the frontend saw has no seam in it.
    seen.assert_tiles_the_stream(&fleet.detail());
    assert_eq!(
        seen.text.matches("AFTER1").count(),
        1,
        "the input typed into the dying path was applied {} times — {}\n{:?}",
        seen.text.matches("AFTER1").count(),
        fleet.detail(),
        seen.text
    );
    assert!(seen.text.contains("BEFORE1"), "{:?}", seen.text);

    // The host agrees it was a resume: a second authorized `session.attach`
    // on a session the client never re-opened.
    assert_eq!(
        fleet.attach_allows(),
        attaches_before + 2,
        "the host did not see the initial attach and its resume — {}",
        fleet.detail()
    );
    let stats = fleet.proxy.stats();
    assert_eq!(stats.severs, 1, "{}", fleet.detail());
    assert!(
        stats.is_balanced(),
        "the proxy's accounting identity broke — {}",
        fleet.detail()
    );
}

/// The other half of the recovery story: when the path merely *moves*, the
/// session survives it. Whether QUIC carried it (migration) or the driver
/// rebuilt it (resume) is recorded rather than demanded — the guarantee is
/// that the shell keeps working, and `protocol.md` §2 is explicit that
/// nothing may depend on migration succeeding.
#[test]
fn a_repath_is_survived_by_the_live_attach() {
    capture_recovery_records();
    let fleet = ProxiedFleet::start(ChaosPolicy::seeded(0x0009_EA74));
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig::default());
    let session_ref = open_shell(&ops);

    let (seen, records) = {
        let session_ref = session_ref.clone();
        let ctx = ctx.clone();
        let repather = {
            let proxy = fleet.proxy.clone();
            let handle = fleet.runtime.handle().clone();
            // `session.open` left its own (now idle) flow behind, so the
            // proxy has more than one and cannot guess which to move. The
            // attach's flow is the one that was not there a moment ago.
            let before: HashSet<SocketAddr> = handle
                .block_on(proxy.flows())
                .into_iter()
                .map(|(client, _)| client)
                .collect();
            move || {
                let fresh: Vec<SocketAddr> = handle
                    .block_on(proxy.flows())
                    .into_iter()
                    .map(|(client, _)| client)
                    .filter(|client| !before.contains(client))
                    .collect();
                let [client] = fresh.as_slice() else {
                    panic!("expected exactly one new flow for the attach, got {fresh:?}")
                };
                handle
                    .block_on(proxy.repath_client(*client))
                    .expect("repath")
            }
        };
        with_deadline("repath survival", move || {
            let mut stream = attach(&ops, &session_ref);
            let mut seen = Delivered::default();
            stream
                .write(b"printf 'BEFORE%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "BEFORE1", &ctx);

            // The host suddenly sees the same connection arriving from a
            // new peer address — a NAT rebind, or Wi-Fi→LTE.
            let moved = repather();
            stream
                .write(b"printf 'AFTER%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "AFTER1", &ctx);
            let records = records_for(&session_ref);
            stream.close();
            (seen, format!("{moved} {records:?}"))
        })
    };

    seen.assert_tiles_the_stream(&fleet.detail());
    assert_eq!(
        seen.text.matches("AFTER1").count(),
        1,
        "the command was applied more than once across the path change — {}",
        fleet.detail()
    );
    // Recorded, not asserted: which mechanism carried the session is
    // exactly the number the SC3 campaign is being built to measure.
    let mut stderr = std::io::stderr();
    let _ = writeln!(
        stderr,
        "repath survived via: {records} — {}",
        fleet.detail()
    );
    let stats = fleet.proxy.stats();
    assert_eq!(stats.repaths, 1, "{}", fleet.detail());
    assert!(stats.is_balanced(), "{}", fleet.detail());
}

/// Recovery is not something that happens to a session the user closed. A
/// detach ends the attach, and the connection it closes must not be
/// mistaken for a path that died.
#[test]
fn a_detach_is_not_recovered_from() {
    capture_recovery_records();
    let fleet = ProxiedFleet::start(ChaosPolicy::seeded(0x00DE_7AC4));
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig::default());
    let session_ref = open_shell(&ops);

    let records = {
        let session_ref = session_ref.clone();
        with_deadline("detach", move || {
            let mut stream = attach(&ops, &session_ref);
            let mut seen = Delivered::default();
            stream
                .write(b"printf 'HERE%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "HERE1", &ctx);
            let handle = stream.handle();
            handle.detach();
            // The event stream ends because the attach ended, not because
            // anything failed — and no recovery is attempted.
            while let Some(event) = stream.next_event() {
                if event.is_err() {
                    break;
                }
            }
            records_for(&session_ref)
        })
    };
    assert!(
        records.is_empty(),
        "a detach must not look like a dead path: {records:?} — {}",
        fleet.detail()
    );
}
