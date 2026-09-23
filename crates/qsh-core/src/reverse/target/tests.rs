use super::*;

use crate::config::ReverseConfig;
use proptest::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn offered_name_precedence_flag_then_config_then_device_id() {
    let mut config = Config::default();
    assert_eq!(
        resolve_offered_name(None, &config, "device_abc"),
        "device_abc"
    );
    config.reverse.offered_name = Some("configured".into());
    assert_eq!(
        resolve_offered_name(None, &config, "device_abc"),
        "configured"
    );
    assert_eq!(
        resolve_offered_name(Some("flagged"), &config, "device_abc"),
        "flagged"
    );
}

// Regression for the adversarial review finding: `rand::rng()`
// (`ThreadRng`, `!Send`) held across every `.await` in the reconnect
// loop made `run_reverse_observed`'s (and therefore `run_reverse`'s)
// returned future `!Send`, so `tokio::spawn(run_reverse(..))` failed to
// compile while the symmetric `tokio::spawn(run_listen(..))` was fine.
// Nothing here actually runs `never_called` — the whole point is the
// compile-time check `assert_send` performs on the future value it's
// handed; a future `!Send` fails to *build*, not to pass an assertion.
#[cfg(unix)]
#[test]
fn run_reverse_future_is_send() {
    fn assert_send<T: Send>(_: T) {}
    fn never_called(paths: &Paths, config: &Config, identity: LoadedIdentity, controller: &str) {
        let fut = run_reverse_observed(
            paths,
            config,
            identity,
            controller,
            None,
            |_runtime| {},
            || {},
            std::future::pending::<()>(),
        );
        assert_send(fut);
    }
    let _ = never_called;
}

// `host_runtime` spawns the broker's TTL reaper (`tokio::spawn`), so
// this needs a runtime in context — same reason
// `serve::tests::host_runtime_wires_device_id_and_a_shared_audit_sink`
// is a `#[tokio::test]` rather than a plain `#[test]`.
#[tokio::test]
async fn reverse_hello_carries_only_offered_name_capabilities_empty() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path(), dir.path());
    let runtime = crate::serve::host_runtime(&paths, &Config::default(), "hermes");
    let hello = runtime.server.local_hello(Some(wire::ReverseRegistration {
        offered_name: "phone".into(),
        capabilities: Vec::new(),
    }));
    let reg = hello.reverse.expect("Hello.reverse is Some");
    assert_eq!(reg.offered_name, "phone");
    assert!(
        reg.capabilities.is_empty(),
        "empty means \"same as Hello.capabilities\" (v1.proto)"
    );
}

/// `dial_and_register`'s own doc comment reserves `resolve` for
/// [`crate::ops::resolve_one`]'s own literal DNS-resolver failure,
/// never for `hosts.toml`/`resolve_peer_address` failing to find an
/// address at all — this is the real end-to-end proof of that one
/// specific branch, driving `dial_and_register` itself (not just
/// `classify_dial_error`/`classify_hello_error`, which cannot see this
/// failure at all: it never reaches a dialer). `mac.example.invalid`
/// is RFC 2606's reserved, permanently-unresolvable TLD (the same
/// pattern `ops::tests::trust_accept_uses_the_normalized_address_for_the_dial_and_its_failure_message`
/// already relies on) — no network, no server, no dial timeout to
/// wait out. Not `#[cfg(unix)]`: `dial_and_register` itself is
/// `#[cfg(any(unix, test))]`, so this runs (and constructs
/// [`ReconnectCause::Resolve`]) on every CI target, including the
/// windows-latest test leg.
#[tokio::test]
async fn dial_and_register_maps_an_unresolvable_controller_to_resolve_cause() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    let mut trust = crate::trust::TrustStore::default();
    trust.add_peer(
        "widget",
        Some("mac.example.invalid:4433".to_string()),
        qsh_transport::Fingerprint::of_spki_der(&[]),
        "2026-01-01T00:00:00Z".to_string(),
    );
    trust.save(&paths.trust_file()).expect("save trust.toml");
    let trust = SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");

    let runtime = crate::serve::host_runtime(&paths, &Config::default(), "hermes");
    let local_hello = runtime.server.local_hello(Some(wire::ReverseRegistration {
        offered_name: "hermes".into(),
        capabilities: Vec::new(),
    }));

    let local = qsh_transport::LocalIdentity {
        cert_chain: Vec::new(),
        key_pkcs8_der: zeroize::Zeroizing::new(Vec::new()),
    };
    let dialer = Dialer::new(local, trust.clone() as Arc<dyn TrustEvaluator>);

    let (err, cause) =
        match dial_and_register(&dialer, &trust, &paths, "widget", &local_hello).await {
            Ok(_) => panic!("mac.example.invalid must never resolve"),
            Err(pair) => pair,
        };
    assert_eq!(
        cause,
        ReconnectCause::Resolve,
        "an unresolvable controller address must classify as `resolve`, not `local`"
    );
    assert_eq!(err.code, qsh_proto::ErrorCode::ConnectionFailed);
}

/// `docs/CLI.md` §6.13's Windows gate, mechanically: `run_reverse`
/// refuses on every non-unix target before it ever touches its
/// arguments (module docs on [`super::listen::windows_unsupported`]),
/// so the identity/paths/config below are throwaway. This is the
/// positive Windows-leg assertion `PLAN.md` Step 3 (d) owes ("Windows
/// leg의 nextest green … 나머지가 컴파일·통과") — a real `#[tokio::test]`
/// that runs and passes on the Windows CI leg, not just an absence of
/// a compile error there.
#[cfg(not(unix))]
#[tokio::test]
async fn run_reverse_is_unsupported_on_non_unix() {
    let identity = LoadedIdentity {
        identity: crate::identity::Identity {
            device_id: "device".into(),
            fingerprint: qsh_transport::Fingerprint::of_spki_der(&[]),
            key_store: qsh_proto::KeyStoreKind::File,
            created_at: "2026-01-01T00:00:00Z".into(),
            cert_der: Vec::new(),
            issued_by_ca: None,
        },
        local: qsh_transport::LocalIdentity {
            cert_chain: Vec::new(),
            key_pkcs8_der: zeroize::Zeroizing::new(Vec::new()),
        },
    };
    let paths = Paths::new("unused-config", "unused-state");
    let err = run_reverse(
        &paths,
        &Config::default(),
        identity,
        "controller",
        None,
        std::future::pending::<()>(),
    )
    .await
    .expect_err("non-unix must refuse to run");
    assert_eq!(err.code, qsh_proto::ErrorCode::Unsupported);
}

// ------------------------------------------------------------------
// Backoff (`docs/design/testing.md` L2 — deterministic, seeded RNG,
// no wall clock)
// ------------------------------------------------------------------

fn limits(initial_ms: u64, max_ms: u64, jitter_pct: u8) -> BackoffLimits {
    BackoffLimits {
        initial: Duration::from_millis(initial_ms),
        max: Duration::from_millis(max_ms),
        jitter_pct,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The un-jittered sequence never shrinks and never exceeds the
    /// cap — checked with `jitter_pct: 0` so the observed delay *is*
    /// the raw sequence, isolating this property from jitter's own
    /// (separately tested below).
    #[test]
    fn backoff_sequence_is_monotone_nondecreasing_until_the_cap(
        initial_ms in 1u64..=5_000,
        max_ms in 1u64..=120_000,
        seed in any::<u64>(),
    ) {
        prop_assume!(max_ms >= initial_ms);
        let limits = limits(initial_ms, max_ms, 0);
        let mut backoff = Backoff::new(limits, StdRng::seed_from_u64(seed));

        let first = backoff.next_delay();
        prop_assert_eq!(first, limits.initial);

        let mut prev = first;
        for _ in 0..24 {
            let next = backoff.next_delay();
            prop_assert!(next >= prev, "backoff must never shrink before a reset");
            prop_assert!(next <= limits.max, "backoff must never exceed the cap");
            prev = next;
        }
        // log2(120_000 / 1) < 17: 24 further doublings always
        // saturate at the cap for every (initial, max) in range.
        prop_assert_eq!(prev, limits.max, "cap must actually be reached, not just respected");
    }

    /// Every jittered delay falls within `±jitter_pct%` of the raw
    /// (pre-jitter) delay the same doubling-then-cap sequence would
    /// have produced.
    #[test]
    fn jitter_stays_within_the_declared_band(
        initial_ms in 1u64..=5_000,
        max_ms in 1u64..=120_000,
        jitter_pct in 0u8..100,
        seed in any::<u64>(),
    ) {
        prop_assume!(max_ms >= initial_ms);
        let limits = limits(initial_ms, max_ms, jitter_pct);
        let mut backoff = Backoff::new(limits, StdRng::seed_from_u64(seed));

        let mut raw = limits.initial;
        for i in 0..16 {
            if i > 0 {
                raw = raw.saturating_mul(2).min(limits.max);
            }
            let observed = backoff.next_delay();
            let raw_ms = raw.as_millis() as i64;
            let band = raw_ms * i64::from(jitter_pct) / 100;
            let lo = (raw_ms - band).max(0);
            let hi = raw_ms + band;
            let observed_ms = observed.as_millis() as i64;
            prop_assert!(
                observed_ms >= lo && observed_ms <= hi,
                "delay {observed_ms}ms out of band [{lo},{hi}] for raw {raw_ms}ms at {jitter_pct}%",
            );
        }
    }

    /// `jitter_stays_within_the_declared_band` above is containment-only:
    /// an implementation that applied zero jitter (or jitter only ever
    /// rounding down) would satisfy it trivially. Pin that jitter is
    /// actually applied and actually two-sided: at a fixed nonzero
    /// `jitter_pct`, repeated draws from distinct seeds must produce at
    /// least two distinct delays, with at least one strictly below the
    /// raw (pre-jitter) delay and at least one strictly above it.
    #[test]
    fn jitter_actually_varies_and_straddles_the_raw_delay(
        initial_ms in 200u64..=5_000,
        seed_base in any::<u64>(),
    ) {
        let jitter_pct = 20u8;
        let limits = limits(initial_ms, initial_ms, jitter_pct);
        let raw_ms = initial_ms as i64;

        let mut distinct = std::collections::HashSet::new();
        let mut saw_below = false;
        let mut saw_above = false;
        for offset in 0u64..64 {
            let mut backoff = Backoff::new(limits, StdRng::seed_from_u64(seed_base.wrapping_add(offset)));
            let observed_ms = backoff.next_delay().as_millis() as i64;
            distinct.insert(observed_ms);
            saw_below |= observed_ms < raw_ms;
            saw_above |= observed_ms > raw_ms;
        }
        prop_assert!(
            distinct.len() >= 2,
            "jitter_pct {jitter_pct}% must produce more than one distinct delay across seeds, got {distinct:?}",
        );
        prop_assert!(saw_below, "jitter must round down at least once across seeds, got {distinct:?}");
        prop_assert!(saw_above, "jitter must round up at least once across seeds, got {distinct:?}");
    }

    /// A reset collapses the sequence back to `initial`, regardless of
    /// how far it had already climbed.
    #[test]
    fn reset_returns_the_sequence_to_initial(
        initial_ms in 1u64..=5_000,
        max_ms in 1u64..=120_000,
        seed in any::<u64>(),
    ) {
        prop_assume!(max_ms >= initial_ms);
        let limits = limits(initial_ms, max_ms, 0);
        let mut backoff = Backoff::new(limits, StdRng::seed_from_u64(seed));

        prop_assert_eq!(backoff.next_delay(), limits.initial);
        let _ = backoff.next_delay();
        let _ = backoff.next_delay();
        backoff.reset();
        prop_assert_eq!(backoff.next_delay(), limits.initial);
    }
}

#[test]
fn a_jitter_of_exactly_zero_percent_is_deterministic() {
    // jitter_pct: 0 never calls into the rng at all — proven by
    // seeding with a value that would otherwise perturb the delay.
    let mut backoff = Backoff::new(limits(500, 2_000, 0), StdRng::seed_from_u64(1));
    assert_eq!(backoff.next_delay(), Duration::from_millis(500));
    assert_eq!(backoff.next_delay(), Duration::from_millis(1_000));
    assert_eq!(backoff.next_delay(), Duration::from_millis(2_000));
    assert_eq!(backoff.next_delay(), Duration::from_millis(2_000));
}

// ------------------------------------------------------------------
// wait_backoff (`docs/design/testing.md` L2 — `tokio::time::pause()`,
// no `sleep()`-based test synchronization)
// ------------------------------------------------------------------

/// `docs/design/protocol.md` §11-4 / `PLAN.md` Step 4 (d): "controller
/// 부재 상태에서 재접속 루프가 CPU를 태우지 않음(상한 도달 후 30 s
/// 간격)". Reaching the cap and then waiting is driven by a real
/// `tokio::time::sleep`, not a busy poll — proven by advancing a
/// *paused* clock and asserting the elapsed virtual time is exactly
/// the capped delay, never more (no extra spinning) and never less
/// (no shortcut).
#[tokio::test(start_paused = true)]
async fn after_reaching_the_cap_the_loop_waits_the_full_default_thirty_seconds() {
    // `jitter_pct: 0` isolates this from jitter's own (separately
    // tested) band — this test is about the *wait mechanism*, not
    // about how big the delay is.
    let cap = ReverseConfig::default().backoff().unwrap().max;
    assert_eq!(cap, Duration::from_millis(30_000), "the documented default");
    let mut backoff = Backoff::new(limits(500, 30_000, 0), StdRng::seed_from_u64(7));
    let mut delay = Duration::ZERO;
    for _ in 0..12 {
        delay = backoff.next_delay();
    }
    assert_eq!(delay, cap, "must have saturated at the cap by now");

    let shutdown = std::future::pending::<()>();
    tokio::pin!(shutdown);
    let start = tokio::time::Instant::now();
    let completed = wait_backoff(delay, &mut shutdown).await;
    assert!(completed, "the delay must elapse, not be short-circuited");
    assert_eq!(
        tokio::time::Instant::now() - start,
        Duration::from_millis(30_000),
        "must wait exactly the capped delay — no busy loop, no shortcut",
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_interrupts_a_backoff_wait_immediately() {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tx.send(()).unwrap();
    let shutdown = async move {
        let _ = rx.await;
    };
    tokio::pin!(shutdown);

    let start = tokio::time::Instant::now();
    let completed = wait_backoff(Duration::from_secs(30), &mut shutdown).await;
    assert!(!completed, "shutdown must win the race, not the sleep");
    assert_eq!(
        tokio::time::Instant::now() - start,
        Duration::ZERO,
        "must not wait any part of the delay once shutdown has already fired",
    );
}

// ------------------------------------------------------------------
// ReconnectEvent (`docs/CLI.md` §6.13 — one-line JSON, additive only)
// ------------------------------------------------------------------

#[test]
fn reconnect_event_json_line_has_the_documented_field_set() {
    let retry = ReconnectEvent {
        event: "retry",
        host: "personal-mac",
        fingerprint: None,
        delay_ms: Some(542),
        cause: Some("dial_timeout"),
        at: "2026-01-01T00:00:00Z".to_string(),
        since_registered_ms: None,
    };
    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&retry).unwrap()).unwrap();
    assert_eq!(parsed["event"], "retry");
    assert_eq!(parsed["host"], "personal-mac");
    // Issue #4 item 6: a `retry` never has a fingerprint yet (no TLS
    // handshake has started for that attempt) — the key is absent,
    // not the old `"-"` placeholder or a JSON `null`.
    assert!(parsed.get("fingerprint").is_none());
    assert_eq!(parsed["delay_ms"], 542);
    assert_eq!(parsed["cause"], "dial_timeout");
    assert_eq!(parsed["at"], "2026-01-01T00:00:00Z");
    assert!(parsed.get("since_registered_ms").is_none());

    let registered = ReconnectEvent {
        event: "registered",
        host: "personal-mac",
        fingerprint: Some("sha256:abc"),
        delay_ms: None,
        cause: None,
        at: "2026-01-01T00:00:01Z".to_string(),
        since_registered_ms: None,
    };
    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&registered).unwrap()).unwrap();
    assert_eq!(parsed["event"], "registered");
    assert_eq!(parsed["fingerprint"], "sha256:abc");
    assert!(
        parsed.get("delay_ms").is_none(),
        "delay_ms must be omitted, not null, when absent — additive-only field"
    );
    // `registered` is never an ended registration — no `cause`.
    assert!(parsed.get("cause").is_none());
    assert!(parsed.get("since_registered_ms").is_none());

    // `emit()`'s only production callers live inside `run_reverse_unix`,
    // which is `#[cfg(unix)]`. Under `cfg(test) && not(unix)` (the
    // windows-latest leg of `cargo clippy --workspace --all-targets`)
    // that leaves the method itself unreferenced unless a test calls it
    // too — call it here so it is exercised (and its output shape
    // covered) on every platform this module compiles under.
    retry.emit();
    registered.emit();
}

/// The `lost`/`retry` pair a connection death emits both carry
/// `since_registered_ms` and share `cause` — pins the JSON shape the
/// real emission site in `run_reverse_unix` relies on, independent of
/// driving a real connection death (the end-to-end proof lives in
/// `qsh-testkit`'s reverse chaos suite).
#[test]
fn reconnect_event_json_line_covers_the_lost_retry_pair_with_since_registered_ms() {
    let lost = ReconnectEvent {
        event: "lost",
        host: "personal-mac",
        fingerprint: Some("sha256:abc"),
        delay_ms: None,
        cause: Some("peer_closed"),
        at: "2026-01-01T00:00:02Z".to_string(),
        since_registered_ms: Some(4_200),
    };
    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&lost).unwrap()).unwrap();
    assert_eq!(parsed["event"], "lost");
    assert_eq!(parsed["cause"], "peer_closed");
    assert_eq!(parsed["since_registered_ms"], 4_200);

    let retry = ReconnectEvent {
        event: "retry",
        host: "personal-mac",
        fingerprint: None,
        delay_ms: Some(1_000),
        cause: Some("peer_closed"),
        at: "2026-01-01T00:00:02Z".to_string(),
        since_registered_ms: Some(4_200),
    };
    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&retry).unwrap()).unwrap();
    assert_eq!(parsed["cause"], "peer_closed");
    assert_eq!(parsed["since_registered_ms"], 4_200);
    assert!(parsed.get("fingerprint").is_none());

    lost.emit();
    retry.emit();
}

/// The `at` field every line carries parses as RFC 3339 — the exact
/// string `crate::config::now_rfc3339()` produces (`docs/CLI.md`
/// §2.3).
#[test]
fn reconnect_event_at_field_parses_as_rfc3339() {
    let at = crate::config::now_rfc3339();
    let retry = ReconnectEvent {
        event: "retry",
        host: "personal-mac",
        fingerprint: None,
        delay_ms: Some(10),
        cause: Some("local"),
        at: at.clone(),
        since_registered_ms: None,
    };
    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&retry).unwrap()).unwrap();
    let parsed_at = parsed["at"].as_str().expect("at must be a JSON string");
    time::OffsetDateTime::parse(parsed_at, &time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|err| panic!("`at` {parsed_at:?} must parse as RFC 3339: {err}"));
}

// ------------------------------------------------------------------
// cause classification (issue #4 item 6) — the
// real error types feeding `classify_dial_error`/`classify_hello_error`,
// where driving the real reconnect loop end to end for every variant
// is impractical (`qsh-testkit`'s reverse chaos suite covers the
// variants a real loop reaches: `resolve`, `refused`/`dial_timeout`,
// `tls_rejected`, `registration_denied`, `peer_closed`, `path_dead`,
// `local`).
// ------------------------------------------------------------------

#[test]
fn classify_dial_error_maps_the_documented_vocabulary() {
    use qsh_transport::DialError;

    assert_eq!(
        classify_dial_error(&DialError::Timeout(Duration::from_secs(10))),
        ReconnectCause::DialTimeout
    );
    // `RemoteRejected` — the peer rejected our certificate.
    assert_eq!(
        classify_dial_error(&DialError::RemoteRejected),
        ReconnectCause::TlsRejected
    );
    // `LocalRejected` — the wrong-pin case: **we** rejected the peer's
    // certificate (`DialError::LocalRejected`'s own doc). This is the
    // scenario issue #4 item 6 names first, and the match has no `_`
    // arm, so leaving it untested lets a mutation that reclassifies it
    // as `Refused` type-check silently.
    assert_eq!(
        classify_dial_error(&DialError::LocalRejected {
            reason: qsh_transport::tls::RejectReason::Untrusted,
            observed: None,
        }),
        ReconnectCause::TlsRejected
    );
    assert_eq!(
        classify_dial_error(&DialError::Refused),
        ReconnectCause::Refused
    );
    // `Connect` — the address/server name was unusable before any
    // packet went out; a transport-level refusal to even try, not a
    // TLS judgment.
    assert_eq!(
        classify_dial_error(&DialError::Connect(quinn::ConnectError::EndpointStopping)),
        ReconnectCause::Refused
    );
    // `Failed` mirrors `is_crypto_failure` exactly: a crypto-class
    // close code (0x100..=0x1ff, a TLS alert) is `tls_rejected`...
    assert_eq!(
        classify_dial_error(&DialError::Failed(
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::crypto(42),
                frame_type: None,
                reason: bytes::Bytes::new(),
            })
        )),
        ReconnectCause::TlsRejected
    );
    // ...and a non-crypto-class connection death is `refused`.
    assert_eq!(
        classify_dial_error(&DialError::Failed(quinn::ConnectionError::Reset)),
        ReconnectCause::Refused
    );
    // `Setup` — endpoint construction failed before any packet went
    // out at all; originates on this side.
    assert_eq!(
        classify_dial_error(&DialError::Setup(
            qsh_transport::endpoint::SetupError::Bind {
                addr: "127.0.0.1:0".parse().unwrap(),
                source: std::io::Error::other("bind failed"),
            }
        )),
        ReconnectCause::Local
    );
}

#[test]
fn classify_hello_error_maps_a_remote_rejection_to_registration_denied() {
    use crate::handshake::HelloError;
    use qsh_proto::ErrorCode;

    let err = HelloError::Remote {
        code: ErrorCode::PermissionDenied,
        message: "no acl row".to_string(),
        retryable: false,
    };
    assert_eq!(
        classify_hello_error(&err),
        ReconnectCause::RegistrationDenied
    );
}

#[test]
fn classify_target_connection_loss_maps_a_clean_end_of_stream_to_peer_closed() {
    // `serve_control`'s own loop ending on a clean end-of-stream — the
    // controller closed its send side.
    assert_eq!(
        classify_target_connection_loss(&Ok(Ok(()))),
        ReconnectCause::PeerClosed
    );
}

#[test]
fn classify_target_connection_loss_maps_a_connection_error_via_the_shared_judgment() {
    use crate::server::ConnError;

    // `ConnectionError::TimedOut` — quinn's own idle-timeout judgment
    // on an established connection — is `path_dead`, the same as a
    // real `PathWatch` death (`classify_connection_error`'s own doc).
    let timed_out: Result<Result<(), ConnError>, tokio::task::JoinError> = Ok(Err(
        ConnError::Connection(qsh_transport::ConnectionError::TimedOut),
    ));
    assert_eq!(
        classify_target_connection_loss(&timed_out),
        ReconnectCause::PathDead
    );

    // `ConnectionError::LocallyClosed` — this side closed the
    // connection itself — is `local`.
    let locally_closed: Result<Result<(), ConnError>, tokio::task::JoinError> = Ok(Err(
        ConnError::Connection(qsh_transport::ConnectionError::LocallyClosed),
    ));
    assert_eq!(
        classify_target_connection_loss(&locally_closed),
        ReconnectCause::Local
    );
}

#[tokio::test]
async fn classify_target_connection_loss_maps_a_task_panic_to_local() {
    // `serve_control`'s task itself failing (panic/abort) is a bug on
    // this side, never a peer/path judgment.
    let panicked = tokio::spawn(async { panic!("injected for this test") });
    let joined: Result<Result<(), crate::server::ConnError>, tokio::task::JoinError> =
        panicked.await.map(Ok);
    let join_err = match joined {
        Err(e) => Err(e),
        Ok(_) => panic!("the spawned task was expected to panic"),
    };
    assert_eq!(
        classify_target_connection_loss(&join_err),
        ReconnectCause::Local
    );
}
