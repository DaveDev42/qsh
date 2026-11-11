//! L4 for the combined endpoint (ADR-0059 DoD 27.9, `docs/design/testing.md`
//! L4): one chaos proxy sits in front of the endpoint's one UDP port, so the
//! registration of a reverse target and the forward session of a client
//! cross the same path. An 8 s blackhole (longer than the registration's 5 s
//! detection ceiling, so the registration must re-form) takes both away at once, and the
//! test holds the endpoint to what each role owes after it:
//!
//! - the registration stands again inside the ADR-0041 budget (the reverse
//!   registration's detection ceiling plus the target's backoff plus the 2 s
//!   resume bound plus slack), shown by a real exec over the reverse route
//!   through the endpoint's localctl daemon and by the registry entry's
//!   `generation`, which only a new registration can raise;
//! - the forward session is the same session (one `session_ref`, one live
//!   session on the host's broker), its output tiles the stream with no gap
//!   and no redelivery, and the input typed before, during and after the
//!   blackhole reaches the session once, in order.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use qsh_core::acl::AllowAllPinned;
use qsh_core::config::{Config, ReverseConfig};
use qsh_core::quota::QuotaLimits;
use qsh_core::reverse::target::run_reverse_observed;
use qsh_core::{RecoveryConfig, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{EnvVar, SessionAttachReq, SessionCloseReq, SessionOpenReq};
use qsh_testkit::combined::CombinedHarness;
use qsh_testkit::loopback::make_identity;
use qsh_testkit::reverse::{loaded_identity, wait_for};
use qsh_testkit::{ChaosPolicy, ChaosProxy};
use qsh_transport::{Principal, StaticTrust};

use super::combined_accept::{client, pin, target_paths};
use super::jump_chain::{blocking, echo_argv, exec, stdout_of};

/// How long the proxy swallows every datagram. It has to outlast the
/// registration's detection ceiling below, or the registered connection could
/// ride the outage out (QUIC's own idle timeout is 45 s) and never re-form:
/// the test would then pass without the re-registration it exists to prove.
/// With 8 s the target's and the controller's path watches must both declare
/// the path dead before the proxy gives it back.
const BLACKHOLE: Duration = Duration::from_secs(8);

/// ADR-0041 decision 4: the registration's detection ceiling.
const REVERSE_DETECTION_CEILING: Duration = Duration::from_millis(5_000);

/// `docs/design/testing.md` L4: from the re-registration to a resumed
/// session.
const REDIAL_DEADLINE: Duration = Duration::from_millis(2_000);

/// Room for the proxy, the localctl relay, a QUIC handshake that had its
/// first flights swallowed, and a loaded CI machine.
const SLACK: Duration = Duration::from_secs(8);

const DEADLINE: Duration = Duration::from_secs(120);

fn fast_backoff() -> Config {
    Config {
        reverse: ReverseConfig {
            backoff_initial_ms: Some(5),
            backoff_max_ms: Some(20),
            backoff_jitter_pct: Some(0),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// What a client attach stream has delivered. A contiguous cover of
/// cumulative offsets from the first frame to the last means every byte of
/// the host's stream was seen exactly once, in order.
#[derive(Default)]
struct Delivered {
    text: String,
    frames: Vec<(u64, usize)>,
    gaps: Vec<(u64, u64)>,
}

impl Delivered {
    fn assert_tiles_the_stream(&self) {
        assert!(self.gaps.is_empty(), "replay gaps: {:?}", self.gaps);
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
                "frame {index} starts at {start} but the stream had reached {expected}: {}",
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

fn read_until(stream: &mut SessionAttachStream, seen: &mut Delivered, needle: &str) {
    while let Some(event) = stream.next_event() {
        match event.unwrap_or_else(|err| panic!("attach stream failed: {err}")) {
            SessionEvent::Output {
                sequence, data_b64, ..
            } => {
                let data = base64::engine::general_purpose::STANDARD
                    .decode(data_b64.as_bytes())
                    .expect("session output is Base64");
                seen.text.push_str(&String::from_utf8_lossy(&data));
                seen.frames.push((sequence, data.len()));
                if seen.text.contains(needle) {
                    return;
                }
            }
            SessionEvent::Gap {
                requested_after,
                available_from,
                ..
            } => seen.gaps.push((requested_after, available_from)),
            SessionEvent::Exit { .. } | SessionEvent::Closed { .. } => {
                panic!("the session ended before {needle:?}; saw {:?}", seen.text)
            }
            _ => {}
        }
    }
    panic!(
        "the attach stream ended before {needle:?}; saw {:?}",
        seen.text
    );
}

/// Read what the session child received until it has at least `want` bytes.
async fn read_input_until(
    pipe: &mut qsh_core::broker::PipeHandle,
    got: &mut Vec<u8>,
    needle: &str,
) {
    tokio::time::timeout(DEADLINE, async {
        while !String::from_utf8_lossy(got).contains(needle) {
            let chunk = pipe.read_input(4096).await.expect("read the child's input");
            assert!(!chunk.is_empty(), "the child's input closed early");
            got.extend_from_slice(&chunk);
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the input never reached the session; it has {:?}",
            String::from_utf8_lossy(got)
        )
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn combined_endpoint_recovers_both_roles_after_a_blackhole() {
    let c = client().await;
    let widget = make_identity();
    let dir = tempfile::tempdir().expect("tempdir");

    let trust = StaticTrust::empty()
        .with_pin(c.fp, Principal::Device("laptop".into()))
        .with_pin(widget.fingerprint, Principal::Device("widget".into()));
    let h = CombinedHarness::start(Arc::new(AllowAllPinned), trust, QuotaLimits::default()).await;
    let chaos = ChaosProxy::start(h.addr, ChaosPolicy::seeded(0x0C0B_14ED))
        .await
        .expect("bind the chaos proxy in front of the endpoint");
    let ctx = format!(
        "chaos seed={:#x} front={} endpoint={}",
        chaos.seed(),
        chaos.addr(),
        h.addr
    );

    // The client reaches the endpoint through the proxy.
    pin(&c.ops, "box", chaos.addr().to_string(), h.host.fingerprint).await;
    let ops = c.ops.clone().with_recovery(RecoveryConfig {
        // The path is gone, not moved: resume is the only way back.
        migration: false,
        // Enough attempts to outlast the blackhole: each redial is bounded
        // by REDIAL_DEADLINE, and one begun inside the outage carries the
        // QUIC handshake's retransmission backoff past the end of it. This
        // is a property of the forward route and the outage, not of the
        // combined endpoint: `status_line.rs` needs the same 10 against a
        // standalone `qsh serve` for its 6 s blackout. With the default 3
        // attempts this test fails ("not recovered within 2000 ms": all
        // three redials, 3 x REDIAL_DEADLINE, fall inside the 8 s outage);
        // the forward half of the endpoint is the standalone `Server`, so
        // nothing about it asks for more than a standalone serve does.
        attempts: 10,
        ..RecoveryConfig::default()
    });

    // The endpoint's localctl daemon, for the reverse route of `widget`.
    let localctl = {
        use qsh_core::localctl::daemon::{LocalctlDaemon, LocalctlListener};
        let bound = LocalctlListener::bind(&c.paths, std::process::id()).expect("bind localctl");
        let daemon = LocalctlDaemon::new(h.listen.clone());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = rx.await;
        }));
        (tx, task)
    };

    // The reverse target registers through the proxy too.
    let t_paths = target_paths(dir.path(), chaos.addr(), h.host.fingerprint);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let target_config = fast_backoff();
    let run_target = run_reverse_observed(
        &t_paths,
        &target_config,
        loaded_identity(&widget, "widget-device"),
        "ctl",
        Some("widget"),
        |_runtime| {},
        || {},
        async move {
            let _ = stop_rx.await;
        },
    );

    let test = async {
        wait_for(Duration::from_secs(30), || h.listen.control_hub("widget")).await;
        let baseline_generation = h
            .listen
            .registry()
            .get("widget")
            .expect("registered")
            .generation;

        // A forward session on the endpoint, attached, with output and input
        // already flowing.
        let (session_ref, mut stream, mut seen) = {
            let ops = ops.clone();
            blocking(move || {
                let session_ref = ops
                    .session_open(SessionOpenReq {
                        host: "box".into(),
                        argv: vec!["sh".into()],
                        env: vec![EnvVar {
                            name: "LANG".into(),
                            value: "C".into(),
                        }],
                        term: Some("xterm-256color".into()),
                        cols: Some(80),
                        rows: Some(24),
                        user: None,
                        shell_command: None,
                    })
                    .expect("session.open")
                    .session_ref;
                let stream = ops
                    .session_attach(
                        SessionAttachReq {
                            session_ref: session_ref.clone(),
                            no_steal: false,
                        },
                        &[],
                    )
                    .expect("session.attach");
                Ok::<_, qsh_core::OpError>((session_ref, stream, Delivered::default()))
            })
            .await
            .expect("open and attach")
        };
        let (_spec, mut pipe) = h.pipes.take_with_spec().expect("the session's child");
        let mut child_input: Vec<u8> = Vec::new();

        pipe.write_output(b"BEFORE\n").await.expect("child output");
        stream = {
            let mut seen_in = std::mem::take(&mut seen);
            let (stream, seen_out) = blocking(move || {
                read_until(&mut stream, &mut seen_in, "BEFORE");
                stream.write(b"input-1\n".to_vec()).expect("write input");
                Ok::<_, qsh_core::OpError>((stream, seen_in))
            })
            .await
            .expect("first round trip");
            seen = seen_out;
            stream
        };
        read_input_until(&mut pipe, &mut child_input, "input-1\n").await;

        // ---- the blackhole: both roles lose the path at once ----
        let started = Instant::now();
        chaos.blackhole(BLACKHOLE).await;

        // Produced and typed while the path is dead: the output must be
        // replayed and the input delivered once, on the far side.
        pipe.write_output(b"DURING\n").await.expect("child output");
        let forward = {
            let mut seen_in = std::mem::take(&mut seen);
            let mut stream_in = stream;
            blocking(move || {
                stream_in.write(b"input-2\n".to_vec()).expect("write input");
                read_until(&mut stream_in, &mut seen_in, "DURING");
                Ok::<_, qsh_core::OpError>((stream_in, seen_in, Instant::now()))
            })
        };
        let reverse = async {
            // The registration is back when an exec over the reverse route
            // runs on the target again.
            loop {
                if started.elapsed() > DEADLINE {
                    panic!("the registration never came back — {ctx}");
                }
                let attempt = tokio::time::timeout(
                    Duration::from_secs(5),
                    exec(&ops, "widget", echo_argv("alive-after")),
                )
                .await;
                if let Ok(Ok(out)) = attempt
                    && out.data.remote_exit_code == 0
                    && stdout_of(&out).contains("alive-after")
                {
                    return Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        let (forward, reverse_back) = tokio::join!(forward, reverse);
        let (stream_back, seen_back, forward_back) = forward.expect("the forward session resumed");
        stream = stream_back;
        seen = seen_back;

        // The input of the blackhole reached the child, and now the fence
        // after it: nothing is redelivered between them.
        let stream = {
            let stream_in = stream;
            blocking(move || {
                stream_in.write(b"fence\n".to_vec()).expect("write input");
                Ok::<_, qsh_core::OpError>(stream_in)
            })
            .await
            .expect("the fence")
        };
        read_input_until(&mut pipe, &mut child_input, "fence\n").await;
        assert_eq!(
            String::from_utf8_lossy(&child_input),
            "input-1\ninput-2\nfence\n",
            "input must arrive once and in order — {ctx}"
        );
        pipe.write_output(b"AFTER\n").await.expect("child output");
        let seen = {
            let mut seen_in = seen;
            let mut stream_in = stream;
            blocking(move || {
                read_until(&mut stream_in, &mut seen_in, "AFTER");
                stream_in.close();
                Ok::<_, qsh_core::OpError>(seen_in)
            })
            .await
            .expect("the output after the blackhole")
        };
        seen.assert_tiles_the_stream();
        assert_eq!(
            h.broker.live_counts().live,
            1,
            "the forward session is the same one, not a second one — {ctx}"
        );

        // The budgets. The proxy gave the path back after BLACKHOLE, so each
        // role owes its detection, its backoff and the resume bound.
        let backoff = Duration::from_millis(
            target_config
                .reverse
                .backoff_max_ms
                .expect("fast_backoff sets it"),
        );
        let reverse_budget =
            BLACKHOLE + REVERSE_DETECTION_CEILING + backoff + REDIAL_DEADLINE + SLACK;
        let reverse_took = reverse_back.duration_since(started);
        assert!(
            reverse_took < reverse_budget,
            "the registration took {reverse_took:?}, over {reverse_budget:?} — {}",
            chaos.detail()
        );
        let forward_took = forward_back.duration_since(started);
        let forward_budget = BLACKHOLE + REDIAL_DEADLINE + SLACK;
        assert!(
            forward_took < forward_budget,
            "the forward session took {forward_took:?}, over {forward_budget:?} — {}",
            chaos.detail()
        );
        // The registration re-formed: a connection that rode the outage out
        // would still hold the baseline generation.
        let final_generation = h
            .listen
            .registry()
            .get("widget")
            .expect("registered after the blackhole")
            .generation;
        assert!(
            final_generation > baseline_generation,
            "the registration was never replaced (generation {baseline_generation} -> \
             {final_generation}) — {ctx}"
        );
        eprintln!(
            "recovery: forward {forward_took:?}, reverse {reverse_took:?}, generation \
             {baseline_generation} -> {final_generation}"
        );

        let ops_close = ops.clone();
        let _ = blocking(move || {
            ops_close.session_close(SessionCloseReq {
                session_ref,
                signal: None,
            })
        })
        .await;
        let _ = stop_tx.send(());
    };

    let (target_result, ()) = tokio::join!(run_target, test);
    target_result.expect("the reverse target exits cleanly on shutdown");
    let (stop_localctl, task) = localctl;
    let _ = stop_localctl.send(());
    let _ = task.await;
    h.shutdown().await;
}
