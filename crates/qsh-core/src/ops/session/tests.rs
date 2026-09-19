use super::*;

#[test]
fn session_ref_round_trips_and_splits_at_the_last_slash() {
    let r = parse_session_ref("box/01K0ABC").unwrap();
    assert_eq!(r.host, "box");
    assert_eq!(r.session_id, "01K0ABC");
    assert_eq!(r.to_ref(), "box/01K0ABC");
    let r = parse_session_ref("team/box/01K0ABC").unwrap();
    assert_eq!(r.host, "team/box");
    assert_eq!(r.session_id, "01K0ABC");
}

#[test]
fn malformed_session_refs_are_invalid_argument() {
    for bad in ["", "box", "/01K0ABC", "box/", "box/has space", "box/a/b?"] {
        let err = parse_session_ref(bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad:?}");
    }
}

#[test]
fn exit_events_drop_the_code_when_signaled() {
    let signaled = event_json(
        "box/01K0",
        wire::SessionReadEvent::from_body(session_read_event::Body::Exit(wire::Exit {
            final_seq: 9,
            exit_code: -1,
            signal: Some("SIGKILL".into()),
        })),
    )
    .unwrap();
    assert!(matches!(
        signaled,
        SessionEvent::Exit {
            exit_code: None,
            sequence: 9,
            ..
        }
    ));
    let clean = event_json(
        "box/01K0",
        wire::SessionReadEvent::from_body(session_read_event::Body::Exit(wire::Exit {
            final_seq: 9,
            exit_code: 3,
            signal: None,
        })),
    )
    .unwrap();
    assert!(matches!(
        clean,
        SessionEvent::Exit {
            exit_code: Some(3),
            ..
        }
    ));
    // Unknown bodies are dropped, not an error.
    assert!(event_json("box/01K0", wire::SessionReadEvent { body: None }).is_none());
}

/// The renewal schedule with an injected clock: nothing here sleeps,
/// and nothing here depends on an event arriving — which is the whole
/// point, because the schedule replaces a renewal that only ran when
/// the host happened to send something.
#[test]
fn a_renewal_comes_due_on_the_clock_and_not_on_an_event() {
    let ttl = Duration::from_secs(24 * 60 * 60);
    let t0 = std::time::Instant::now();
    let mut schedule = RenewalSchedule::new(ttl, t0);

    // Half a window out, and the wait a silent attach is bounded by is
    // exactly that — not "forever, until the host speaks".
    assert_eq!(schedule.due_in(t0), ttl / 2);
    assert!(!schedule.take_if_due(t0));
    assert!(!schedule.take_if_due(t0 + ttl / 2 - Duration::from_secs(1)));

    // Due, claimed once, and re-armed for the next half-window.
    let due_at = t0 + ttl / 2;
    assert!(schedule.take_if_due(due_at));
    assert!(
        !schedule.take_if_due(due_at),
        "a claimed renewal must not fire again on the same instant"
    );
    assert_eq!(schedule.due_in(due_at), ttl / 2);
    assert_eq!(schedule.ttl(), ttl, "a renewal writes the host's window");

    // A wake-up long after the deadline claims exactly one renewal and
    // schedules the next from *now*, not from the missed deadline.
    let late = due_at + ttl * 3;
    assert!(schedule.take_if_due(late));
    assert_eq!(schedule.due_in(late), ttl / 2);
}

/// A degenerate window must not turn the event wait into a spin.
#[test]
fn a_zero_length_window_still_yields_a_nonzero_wait() {
    let now = std::time::Instant::now();
    let schedule = RenewalSchedule::new(Duration::ZERO, now);
    assert!(schedule.due_in(now) > Duration::ZERO);
}

/// The un-acked cap is a *contract* (`protocol.md` §10-5: "초과 시
/// 조용히 쌓지 않고 오류"), and the driver now surfaces it on the event
/// stream instead of logging it away. This pins the code the frontend
/// sees, because a `warn` and a `RESOURCE_EXHAUSTED` are the same
/// number of lines of source and very different products.
#[test]
fn a_full_un_acked_buffer_is_resource_exhausted_not_a_log_line() {
    let mut pending = PendingInput::new(0);
    pending
        .push(&vec![b'x'; crate::client::reconnect::UNACKED_INPUT_MAX])
        .expect("the cap itself fits");
    let err = pending
        .push(b"one byte too many")
        .expect_err("over the cap");
    assert!(matches!(err, ResumeError::UnackedInputOverflow { .. }));
    let mapped = map_resume_error(err);
    assert_eq!(mapped.code, ErrorCode::ResourceExhausted);
    // The message names the limit, so a user who pasted too much can
    // tell this from a host that ran out of memory.
    assert!(mapped.message.contains("un-acked"), "{:?}", mapped.message);
}

/// Migration is an answer to a *path* that died, never to a stream
/// that broke. The distinction is load-bearing: `probe_alive` asks the
/// connection, and a host that resets `SESSION_DATA` on a live
/// connection (`RESET_CODE_SESSION_CONFLICT`, `RESET_CODE_BAD_HEADER`)
/// still answers `Ping`. Classifying that as migratable returns
/// `Recovery::SameLeg` with the same broken reader, which the driver
/// re-reads with zero backoff — a hot loop that emits a `migrated`
/// record per turn and never tells the frontend anything.
#[test]
fn a_broken_stream_is_never_migratable_however_healthy_the_connection() {
    assert!(
        LegEnd::PathDead.leg_survived(),
        "a dead path leaves usable streams behind; that is what migration rescues"
    );
    assert!(
        !LegEnd::Broken(ClientError::Protocol("reset".into())).leg_survived(),
        "a broken data stream must be rebuilt, not migrated onto"
    );
    // The two endings that never reach recovery at all are still
    // classified conservatively, so a future caller cannot read a
    // survival out of them.
    assert!(!LegEnd::Ended.leg_survived());
    assert!(!LegEnd::Gone.leg_survived());
}

/// A detach that lands mid-recovery is the user's own doing, so it ends
/// the attach rather than producing an error the frontend has to
/// render — and it must not look like a failed recovery either.
#[test]
fn an_abandoned_recovery_is_not_a_wire_failure() {
    assert_eq!(
        map_resume_error(abandoned()).code,
        ErrorCode::ConnectionFailed
    );
}

/// The migration probe is worth one round trip, not a constant: on a
/// LAN a fixed 300 ms was 600 ms of a 2 s budget spent learning
/// nothing.
#[test]
fn the_migration_probe_scales_with_the_path() {
    assert_eq!(
        migration_probe_budget(Duration::from_micros(200)),
        MIGRATION_PROBE_MIN,
        "a fast path still gets a floor, for scheduling"
    );
    assert_eq!(
        migration_probe_budget(Duration::from_millis(100)),
        Duration::from_millis(200)
    );
    assert_eq!(
        migration_probe_budget(Duration::from_secs(5)),
        MIGRATION_PROBE_MAX,
        "and it is capped: the deadline it is spent from is 2 s"
    );
}

/// `Connected::peer_fingerprint` on the reverse leg must be exactly
/// the value that leg's own `LOCAL_CONTROL` handshake reported —
/// never re-derived from a QUIC connection this process does not
/// itself hold (ADR-0007's presentation condition, `PLAN.md` M3
/// Step 6). `dial_reverse` is what actually produces that value from
/// a live `LocalHelloAck` (exercised end-to-end by
/// `crate::client::link`'s and `crate::localctl::client`'s own
/// handshake tests); this pins the narrower claim that
/// `ConnectedLink::Reverse`'s carried value round-trips through
/// `peer_fingerprint()` unchanged, with no runtime/session needed to
/// observe it.
#[test]
fn connected_peer_fingerprint_on_the_reverse_leg_is_exactly_the_acks_value() {
    let connected = Connected {
        runtime: None,
        link: ConnectedLink::Reverse {
            peer_fingerprint: Some("sha256:deadbeefdeadbeefdeadbeefdeadbeef".to_string()),
            socket: std::path::PathBuf::from("/tmp/qsh-test.sock"),
            host: "box".to_string(),
        },
        session: None,
    };
    assert_eq!(
        connected.peer_fingerprint(),
        Some("sha256:deadbeefdeadbeefdeadbeefdeadbeef".to_string())
    );

    let no_fingerprint = Connected {
        runtime: None,
        link: ConnectedLink::Reverse {
            peer_fingerprint: None,
            socket: std::path::PathBuf::from("/tmp/qsh-test.sock"),
            host: "box".to_string(),
        },
        session: None,
    };
    assert_eq!(no_fingerprint.peer_fingerprint(), None);
}

#[test]
fn operation_commands_match_cli_md() {
    assert_eq!(SessionOpenOp::COMMAND, "session.open");
    assert_eq!(SessionGetOp::COMMAND, "session.get");
    assert_eq!(SessionListOp::COMMAND, "session.list");
    assert_eq!(SessionReadOp::COMMAND, "session.read");
    assert_eq!(SessionWriteOp::COMMAND, "session.write");
    assert_eq!(SessionResizeOp::COMMAND, "session.resize");
    assert_eq!(SessionCloseOp::COMMAND, "session.close");
}

/// `drive_attach`'s reverse gate with recovery turned **off**
/// (`RecoveryLink`'s own doc): a real reverse `Session`/`Attached`
/// pair whose `LOCAL_STREAM` data conduit breaks (not a clean close —
/// a mid-frame EOF, so `read_leg` reports [`LegEnd::Broken`]) must end
/// the attach with one typed [`OpError`] on the events channel and
/// *return*, never call [`recover_attach`], never hang. Before Step 8
/// this was true unconditionally — the reverse route had no
/// `Reconnect` at all — so this test used to leave
/// `ctx.recovery.enabled` at its default `true` on purpose (nothing
/// consumed it). Since Step 8 wired `RecoveryLink::Reverse` through
/// the same [`recover_attach`] the forward route uses (via
/// [`LocalReconnect`]), that default would now attempt a real
/// recovery instead of ending the attach immediately, so this test
/// sets `enabled: false` explicitly to keep testing exactly what its
/// name says: the immediate, no-recovery fail-closed path. The
/// recovery-**enabled** counterpart —
/// [`reverse_leg_link_death_with_recovery_exhausted_ends_the_attach_with_a_typed_error_never_a_panic_or_hang`]
/// — proves the same typed-error/never-hang property once a real
/// `LocalReconnect` attempt is in play and exhausts its budget.
#[cfg(unix)]
#[tokio::test]
async fn reverse_leg_link_death_with_recovery_disabled_ends_the_attach_with_a_typed_error_never_a_panic_or_hang()
 {
    use qsh_proto::local::{LocalHello, LocalHelloAck, LocalResponse, local_response};
    use tokio::net::UnixListener;

    use crate::localctl::frame::LocalConduit;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("drive-attach-reverse-death.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    let daemon = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut control = LocalConduit::new(stream);
        let _hello: LocalHello = control.recv().await.unwrap().unwrap();
        control
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:1111111111111111111111111111111111111111111"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();

        let (stream, _addr) = listener.accept().await.unwrap();
        let mut data = LocalConduit::new(stream);
        let _hello: LocalHello = data.recv().await.unwrap().unwrap();
        data.send(&LocalResponse {
            body: Some(local_response::Body::HelloAck(LocalHelloAck {
                host: "phone".to_string(),
                peer_fingerprint: "sha256:1111111111111111111111111111111111111111111".to_string(),
                generation: 1,
                capabilities: Vec::new(),
            })),
        })
        .await
        .unwrap();
        let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
        let (mut raw, _prefetched) = data.into_raw();
        // A declared frame length with no payload behind it at
        // all — a broken conduit, not a clean end: `DataRecvHalf`
        // reports this as `ConnectionFailed`, never `Ok(None)`.
        use tokio::io::AsyncWriteExt as _;
        raw.write_all(&[0, 0, 0, 50]).await.unwrap();
        drop(raw);
        // Keep the control conduit's peer alive for the rest of the
        // test — nothing on it is expected to arrive, but dropping it
        // early would end the control leg too and confound which leg
        // `drive_attach` actually reported the error for.
        std::future::pending::<()>().await
    });

    let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
        .await
        .unwrap();
    let mut session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        sock.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );
    let attached = session
        .open_attach_stream(wire::SessionAttached {
            ticket: vec![1],
            new_resume_token: Vec::new(),
            replay_from: 0,
            writer_lease: true,
            expires_at: String::new(),
            input_seq: 0,
        })
        .await
        .unwrap();

    let link = RecoveryLink::Reverse(ReverseKill::new(attached.kill.clone()));
    let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
    let (applied_input, _) = tokio::sync::watch::channel(0u64);
    let ctx = Arc::new(AttachContext {
        target: None,
        host: "phone".to_string(),
        session_id: "01REVERSEDEATH".to_string(),
        session_ref: "phone/01REVERSEDEATH".to_string(),
        paths,
        no_steal: false,
        link,
        window: Arc::new(std::sync::Mutex::new(None)),
        // Recovery off — this test proves the immediate fail-closed
        // path, not `LocalReconnect` (this fn's own doc).
        recovery: RecoveryConfig {
            enabled: false,
            ..RecoveryConfig::default()
        },
        finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        applied_input,
        reverse_route: None,
    });
    let (_commands_tx, commands_rx) = tokio::sync::mpsc::channel(4);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(4);

    tokio::time::timeout(
        Duration::from_secs(10),
        drive_attach(ctx, session, attached, commands_rx, events_tx),
    )
    .await
    .expect("drive_attach must return promptly on a broken reverse leg, not hang");

    let reported = events_rx
        .recv()
        .await
        .expect("drive_attach must report the broken leg on the events channel");
    assert!(
        reported.is_err(),
        "a broken reverse-leg link must be reported as an error, got {reported:?}"
    );

    daemon.abort();
}

/// `drive_attach`'s reverse gate with recovery turned **on** (Step 8):
/// the counterpart to
/// [`reverse_leg_link_death_with_recovery_disabled_ends_the_attach_with_a_typed_error_never_a_panic_or_hang`].
/// Same broken `LOCAL_STREAM` data conduit, but this time
/// `ctx.recovery.enabled` is `true`, so `drive_attach` now builds a
/// [`LocalReconnect`] and drives it through [`recover_attach`]. The
/// fake daemon in this test never accepts a third UDS connection (it
/// blocks in `std::future::pending()` after handing out the first
/// attach's control/data conduits), so the wait for a new-generation
/// registration never resolves — with `attempts: 1` this exhausts
/// [`recover_attach`]'s single attempt inside one [`REDIAL_DEADLINE`]
/// window (~2 s of real wall-clock time, the same bound the forward
/// route's own unit tests already accept — `docs/design/testing.md`'s
/// `sleep()`-free discipline binds the PR-gate chaos/acceptance
/// suites, not this crate's internal unit tests) and the attach still
/// ends with exactly one typed [`OpError`] on the events channel,
/// never a panic, never `recovery == "migrated"` (`RecoveryLink`'s own
/// doc — there is no `Link` on this route for `recover_attach` to
/// reach for), never a hang past the outer 10 s test timeout.
#[cfg(unix)]
#[tokio::test]
async fn reverse_leg_link_death_with_recovery_exhausted_ends_the_attach_with_a_typed_error_never_a_panic_or_hang()
 {
    use qsh_proto::local::{LocalHello, LocalHelloAck, LocalResponse, local_response};
    use tokio::net::UnixListener;

    use crate::localctl::frame::LocalConduit;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("drive-attach-reverse-recovery.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    let daemon = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut control = LocalConduit::new(stream);
        let _hello: LocalHello = control.recv().await.unwrap().unwrap();
        control
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:1111111111111111111111111111111111111111111"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();

        let (stream, _addr) = listener.accept().await.unwrap();
        let mut data = LocalConduit::new(stream);
        let _hello: LocalHello = data.recv().await.unwrap().unwrap();
        data.send(&LocalResponse {
            body: Some(local_response::Body::HelloAck(LocalHelloAck {
                host: "phone".to_string(),
                peer_fingerprint: "sha256:1111111111111111111111111111111111111111111".to_string(),
                generation: 1,
                capabilities: Vec::new(),
            })),
        })
        .await
        .unwrap();
        let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
        let (mut raw, _prefetched) = data.into_raw();
        use tokio::io::AsyncWriteExt as _;
        raw.write_all(&[0, 0, 0, 50]).await.unwrap();
        drop(raw);
        // No third accept, ever — a `LocalReconnect` wait against this
        // socket blocks until this test's own deadline cancels it.
        std::future::pending::<()>().await
    });

    let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
        .await
        .unwrap();
    let mut session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        sock.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );
    let attached = session
        .open_attach_stream(wire::SessionAttached {
            ticket: vec![1],
            new_resume_token: Vec::new(),
            replay_from: 0,
            writer_lease: true,
            expires_at: String::new(),
            input_seq: 0,
        })
        .await
        .unwrap();

    let link = RecoveryLink::Reverse(ReverseKill::new(attached.kill.clone()));
    let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
    let (applied_input, _) = tokio::sync::watch::channel(0u64);
    let ctx = Arc::new(AttachContext {
        target: None,
        host: "phone".to_string(),
        session_id: "01REVERSERECOVERY".to_string(),
        session_ref: "phone/01REVERSERECOVERY".to_string(),
        paths,
        no_steal: false,
        link,
        window: Arc::new(std::sync::Mutex::new(None)),
        // A single attempt is enough to prove "exhausted -> typed
        // error, never a hang" without the test paying for
        // `RecoveryConfig::default()`'s three attempts' worth of
        // `REDIAL_DEADLINE` windows.
        recovery: RecoveryConfig {
            enabled: true,
            attempts: 1,
            migration: false,
            registration_wait: Duration::from_millis(50),
            ..RecoveryConfig::default()
        },
        finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        applied_input,
        reverse_route: Some(ReverseRoute {
            host: "phone".to_string(),
            socket: sock.clone(),
            // Matches the ack's `generation: 1` above: `LocalReconnect`
            // must wait for something strictly greater, which this
            // fake daemon never produces.
            generation: std::sync::atomic::AtomicU64::new(1),
            registration_wait_ms: std::sync::atomic::AtomicU64::new(u64::MAX),
        }),
    });
    let (_commands_tx, commands_rx) = tokio::sync::mpsc::channel(4);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(4);

    tokio::time::timeout(
        Duration::from_secs(10),
        drive_attach(ctx, session, attached, commands_rx, events_tx),
    )
    .await
    .expect(
        "drive_attach must return once LocalReconnect exhausts its attempts, not hang \
         forever",
    );

    let reported = events_rx
        .recv()
        .await
        .expect("drive_attach must report the exhausted recovery on the events channel");
    assert!(
        reported.is_err(),
        "an exhausted reverse recovery must be reported as an error, got {reported:?}"
    );

    daemon.abort();
}

// ---- `Ops::resolve_user_hint` (`PLAN.md` M7 Step 3, `docs/CLI.md` §7)
// ----

fn user_hint_ops(dir: &std::path::Path) -> Ops {
    let paths = crate::config::Paths::new(dir.join("config"), dir.join("state"));
    Ops::new(paths)
}

fn write_hosts_toml(paths: &crate::config::Paths, body: &str) {
    std::fs::create_dir_all(&paths.config_dir).unwrap();
    std::fs::write(paths.hosts_file(), body).unwrap();
}

#[test]
fn explicit_user_hint_always_wins_over_hosts_toml() {
    let dir = tempfile::tempdir().unwrap();
    let ops = user_hint_ops(dir.path());
    write_hosts_toml(
        ops.paths(),
        "[[host]]\nname = \"mac\"\naddress = \"mac.example.com:4433\"\nuser = \"fromfile\"\n",
    );

    let user = ops
        .resolve_user_hint("mac", Some("explicit".to_string()))
        .unwrap();
    assert_eq!(user.as_deref(), Some("explicit"));
}

#[test]
fn hosts_toml_user_fills_in_when_no_explicit_hint_is_given() {
    let dir = tempfile::tempdir().unwrap();
    let ops = user_hint_ops(dir.path());
    write_hosts_toml(
        ops.paths(),
        "[[host]]\nname = \"mac\"\naddress = \"mac.example.com:4433\"\nuser = \"dave\"\n",
    );

    let user = ops.resolve_user_hint("mac", None).unwrap();
    assert_eq!(user.as_deref(), Some("dave"));
}

#[test]
fn no_hosts_toml_and_no_explicit_hint_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let ops = user_hint_ops(dir.path());
    let user = ops.resolve_user_hint("mac", None).unwrap();
    assert_eq!(user, None);
}

#[test]
fn a_hosts_toml_entry_with_no_user_set_is_none_not_an_empty_string() {
    let dir = tempfile::tempdir().unwrap();
    let ops = user_hint_ops(dir.path());
    write_hosts_toml(
        ops.paths(),
        "[[host]]\nname = \"mac\"\naddress = \"mac.example.com:4433\"\n",
    );

    let user = ops.resolve_user_hint("mac", None).unwrap();
    assert_eq!(user, None);
}

#[test]
fn a_different_hosts_toml_name_does_not_leak_its_user_hint() {
    let dir = tempfile::tempdir().unwrap();
    let ops = user_hint_ops(dir.path());
    write_hosts_toml(
        ops.paths(),
        "[[host]]\nname = \"phone\"\naddress = \"phone.example.com:4433\"\nuser = \"dave\"\n",
    );

    let user = ops.resolve_user_hint("mac", None).unwrap();
    assert_eq!(user, None);
}

#[test]
fn malformed_hosts_toml_surfaces_as_config_error_not_a_silent_none() {
    let dir = tempfile::tempdir().unwrap();
    let ops = user_hint_ops(dir.path());
    write_hosts_toml(ops.paths(), "[[host]]\nname = ");

    let err = ops.resolve_user_hint("mac", None).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
}

/// The re-dial cadence a recovering attach actually produces is a
/// property of [`RecoveryConfig::backoff`] alone, so it is checked as
/// arithmetic rather than by counting dials against a live host.
///
/// The bound it is checked against is the host's admission burst
/// limit for one source: `rate_exceeded` in
/// `crates/qsh-core/src/admission.rs` rejects when the estimate
/// exceeds `handshake_rate_per_source * EPOCH.as_secs()`, which for
/// the shipping defaults (10/s, `EPOCH` = 2 s) is 20 attempts per 2 s
/// window. Both values are restated here because `EPOCH` is private
/// to the `admission` module; the test fails loudly if the schedule
/// ever drifts toward that number rather than tracking it silently.
///
/// Attempts are modelled at the instant their backoff ends, i.e. an
/// attempt of zero duration. Real attempts take time and only spread
/// further apart, so the count computed here is an upper bound on the
/// density any real recovery loop can reach.
#[test]
fn the_recovery_backoff_schedule_stays_far_under_the_admission_burst_limit() {
    const HANDSHAKE_RATE_PER_SOURCE: u32 = 10;
    const EPOCH: Duration = Duration::from_secs(2);
    let burst_limit = HANDSHAKE_RATE_PER_SOURCE * EPOCH.as_secs() as u32;
    assert_eq!(burst_limit, 20, "admission burst limit for one source");

    // Every dial instant a loop of `attempts` attempts would produce,
    // sleeping `backoff(attempt)` before each one.
    let attempts = 64u32;
    let mut at = Vec::with_capacity(attempts as usize);
    let mut clock = Duration::ZERO;
    for attempt in 0..attempts {
        clock += RecoveryConfig::backoff(attempt);
        at.push(clock);
    }

    // Densest 2 s window: every window that starts at a dial covers
    // the maximum, because moving a window's start off a dial can
    // only drop that dial.
    let mut worst = 0usize;
    let mut worst_start = Duration::ZERO;
    for start in &at {
        let end = *start + EPOCH;
        let n = at.iter().filter(|t| **t >= *start && **t < end).count();
        if n > worst {
            worst = n;
            worst_start = *start;
        }
    }

    assert_eq!(
        worst, 4,
        "the 0/200 ms/800 ms schedule puts at most 4 dials in a 2 s window \
         (densest window starts at {worst_start:?}, dials at {at:?})"
    );
    assert!(
        (worst as u32) < burst_limit,
        "recovery cadence {worst} per 2 s must stay under the admission \
         burst limit {burst_limit}"
    );
}

// ---- `Ops::session_open_for_dynamic`'s capability gate (ADR-0020
// decisions 2–3): interactive `-D`'s ordering guarantee is that the gate
// runs *before* `SessionOpen` is ever sent, on both routes — mirrors
// `crate::ops::tunnel`'s own `tunnel_dynamic_*_without_dial_filter_
// capability_is_unsupported_and_binds_nothing` pair one level up the call
// chain. Unlike that pair (which never sends anything until a SOCKS client
// actually connects), `session_open_gated_with_connected` sends
// `SessionOpen` itself the moment the gate lets it through, so "no session
// was opened" cannot be inferred from the returned error alone: a
// mutation that moves the gate to *after* `conn.run(session_open(..))` can
// still surface the identical `Unsupported`/capability-message pair if
// nothing on the other end distinguishes "gate rejected first" from
// "request was sent and something else failed" — the two tests below give
// each fake peer/daemon a companion task that answers any `SessionOpen`
// that does reach it with a distinct, deliberately wrong error, so a
// skipped gate fails the exact-message assertion instead of coincidentally
// matching it (or hanging until nextest's own test-level timeout). ----

fn fake_session_open_msg() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: Vec::new(),
        env: std::collections::HashMap::new(),
        term: String::new(),
        cols: 0,
        rows: 0,
        user: None,
    }
}

#[test]
fn session_open_for_dynamic_without_dial_filter_capability_on_forward_route_opens_no_session() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
    let ops = Ops::new(paths);
    let runtime = ops.connect_runtime().unwrap();

    let (endpoint, client, server) =
        runtime.block_on(crate::tunnel::testutil::loopback_pair_with_client_endpoint());
    // Reports whether the peer's companion task below ever saw a frame on
    // this stream after setup — the actual property under test, checked
    // independently of `err`'s value below (see this module's own doc on
    // why the error alone cannot pin it).
    let (session_open_reached_tx, session_open_reached_rx) = std::sync::mpsc::channel::<bool>();
    let ctl = runtime.block_on(async {
        let (send, recv) = client.open_bi().await.unwrap();
        // Server-side companion of this same stream: if the capability
        // gate below is ever skipped, `session_open` reaches this task
        // instead of hanging forever, and the reply below is deliberately
        // *not* the capability-gate message, so a caller whose returned
        // `Result` does depend on the reply also fails on a normal value
        // diff instead of a 180s nextest timeout.
        tokio::spawn(async move {
            let Ok((peer_send, peer_recv)) = server.accept_bi().await else {
                let _ = session_open_reached_tx.send(false);
                return;
            };
            let mut peer_ctl = qsh_transport::FramedStream::control(peer_send, peer_recv);
            let request = peer_ctl.recv.recv::<wire::ControlMessage>().await;
            let reached = matches!(request, Ok(Some(_)));
            if let Ok(Some(msg)) = request {
                let _ = peer_ctl
                    .send
                    .send(&wire::ControlMessage::error(
                        msg.request_id,
                        wire::Error::from_code(
                            ErrorCode::Internal,
                            "test peer: SessionOpen must never reach the wire while \
                             dial-filter.v1 is missing",
                        ),
                    ))
                    .await;
            }
            let _ = session_open_reached_tx.send(reached);
        });
        qsh_transport::FramedStream::control(send, recv)
    });
    let hello = wire::Hello {
        versions: vec![1],
        device_name: "peer".to_string(),
        // Every other capability present, `dial-filter.v1` deliberately
        // missing — an old peer that predates ADR-0019.
        capabilities: vec![
            qsh_proto::wire::CAP_EXEC.to_string(),
            qsh_proto::wire::CAP_SESSION.to_string(),
        ],
        reverse: None,
    };
    let session = Session::from_control(client.clone(), ctl, hello);
    let conn = Connected::for_test_forward(runtime, endpoint, client, session);

    let err = ops
        .session_open_gated_with_connected(conn, fake_session_open_msg(), "box", true)
        .expect_err("session_open_for_dynamic must never open a session without dial-filter.v1");
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert_eq!(
        err.message,
        crate::ops::tunnel::DYNAMIC_FORWARD_CAPABILITY_UNSUPPORTED_MESSAGE
    );
    assert!(
        !recv_session_open_reached(&session_open_reached_rx),
        "SessionOpen must never reach the wire while the capability gate \
         could still reject the call"
    );
}

/// Wait for the fake peer/daemon's observation task to report whether it
/// ever saw a frame after its handshake ack. `conn.close()` inside
/// `session_open_gated_with_connected` always drops the connection/
/// conduit before that function returns to its caller, which is what
/// makes the companion task's read resolve — cleanly, to `Ok(None)`,
/// when nothing else was ever sent — so a report is always expected
/// within a couple of seconds on a correctly ordered gate. A report that
/// never arrives is itself worth failing loudly on rather than hanging
/// past nextest's own per-test timeout.
fn recv_session_open_reached(rx: &std::sync::mpsc::Receiver<bool>) -> bool {
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the fake peer/daemon's observation task did not report in time")
}

/// [`session_open_for_dynamic_without_dial_filter_capability_on_forward_route_opens_no_session`]'s
/// reverse-route twin (ADR-0020 decisions 2–3): a reverse route whose
/// `LOCAL_CONTROL` registration never negotiated `dial-filter.v1` also
/// opens no session — same fake-localctl-daemon seam
/// `crate::ops::tunnel`'s reverse capability test uses, plus the same
/// wrong-answer companion this module's own doc above explains.
#[cfg(unix)]
#[test]
fn session_open_for_dynamic_without_dial_filter_capability_on_reverse_route_opens_no_session() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
    let ops = Ops::new(paths);
    let runtime = ops.connect_runtime().unwrap();

    // Reports whether the fake daemon below ever saw a frame on this
    // conduit after its ack — the actual property under test, checked
    // independently of `err`'s value below (see this module's own doc,
    // above the forward-route twin, on why the error alone cannot pin
    // it).
    let (session_open_reached_tx, session_open_reached_rx) = std::sync::mpsc::channel::<bool>();
    let handshake = runtime.block_on(async {
        let (client_end, daemon_end) = tokio::net::UnixStream::pair().expect("socketpair");
        tokio::spawn(async move {
            let mut daemon = crate::localctl::frame::LocalConduit::new(daemon_end);
            let _hello: qsh_proto::local::LocalHello = daemon
                .recv()
                .await
                .expect("recv LocalHello")
                .expect("conduit open");
            let ack = qsh_proto::local::LocalResponse {
                body: Some(qsh_proto::local::local_response::Body::HelloAck(
                    qsh_proto::local::LocalHelloAck {
                        host: "target".to_string(),
                        peer_fingerprint: "sha256:deadbeef".to_string(),
                        generation: 1,
                        // `dial-filter.v1` deliberately missing — an old
                        // target, or a daemon still relaying its
                        // pre-upgrade registration. `CAP_SESSION` is
                        // present (unlike a bare "old target" would need)
                        // so that only the missing dial-filter capability
                        // stands between this ack and a real
                        // `session.open` attempt — the forward-route
                        // twin's own "every other capability present"
                        // isolation.
                        capabilities: vec![
                            qsh_proto::wire::CAP_EXEC.to_string(),
                            qsh_proto::wire::CAP_SESSION.to_string(),
                        ],
                    },
                )),
            };
            daemon.send(&ack).await.expect("send LocalHelloAck");
            // If the capability gate is skipped and `session.open`
            // genuinely reaches this conduit, answer with a
            // deliberately wrong error so a caller whose returned
            // `Result` does depend on the reply also fails on a normal
            // value diff instead of hanging until nextest's own
            // test-level timeout. `Ok(None)` — a clean EOF from
            // `conn.close()` — is the expected outcome when the gate
            // runs first, as it should: nothing else is ever sent on this
            // conduit, and the loop just ends.
            let request = daemon.recv::<qsh_proto::wire::ControlMessage>().await;
            let reached = matches!(request, Ok(Some(_)));
            if let Ok(Some(msg)) = request {
                let _ = daemon
                    .send(&qsh_proto::wire::ControlMessage::error(
                        msg.request_id,
                        qsh_proto::wire::Error::from_code(
                            ErrorCode::Internal,
                            "test daemon: SessionOpen must never reach the wire while \
                             dial-filter.v1 is missing",
                        ),
                    ))
                    .await;
            }
            let _ = session_open_reached_tx.send(reached);
        });
        crate::localctl::client::open_control_over(client_end, "target", 0, None)
            .await
            .expect("fake LOCAL_CONTROL handshake")
    });

    let session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        dir.path().join("fake.sock"),
        handshake.peer_fingerprint,
        handshake.generation,
    );
    let conn = Connected::for_test_reverse(
        runtime,
        session,
        dir.path().join("fake.sock"),
        "target".to_string(),
    );

    let err = ops
        .session_open_gated_with_connected(conn, fake_session_open_msg(), "target", true)
        .expect_err("session_open_for_dynamic must never open a session without dial-filter.v1");
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert_eq!(
        err.message,
        crate::ops::tunnel::DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE
    );
    assert!(
        !recv_session_open_reached(&session_open_reached_rx),
        "SessionOpen must never reach the wire while the capability gate \
         could still reject the call"
    );
}
