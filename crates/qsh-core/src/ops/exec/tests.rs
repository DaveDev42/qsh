use super::*;
use crate::ops::test_support::temp_ops;
use qsh_proto::{IdentityInitReq, KeyStoreMode, TrustAddReq};

/// M7 plan Step 7-2 (69dd788) carryover (ii): `exec_run` must dial on
/// `Ops`' shared [`crate::ops::Ops::connect_runtime`], not build a
/// fresh `Builder::new_multi_thread()` per call — modeled on
/// `ops/mod.rs`'s
/// `connect_runtime_is_the_same_instance_across_calls_and_clones`,
/// but pinned at `exec_run`'s own call site rather than at
/// `connect_runtime()` directly, since a regression here would look
/// identical from that test's point of view (both build *a* runtime,
/// just not the *same* one).
///
/// The dial itself is expected to fail — nothing listens on
/// `127.0.0.1:1` — the point is only that `exec_run` reaches into
/// `Ops::connect_runtime` on its way there, twice, and gets the same
/// `Arc` both times.
#[test]
fn exec_run_shares_the_connect_runtime_across_calls() {
    let (_dir, ops) = temp_ops();
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"exec-run-shared-runtime-peer");
    ops.trust_add(TrustAddReq {
        name: "peer".into(),
        address: Some("127.0.0.1:1".into()),
        fingerprint: Some(fingerprint.to_string()),
        cert_pem: None,
    })
    .unwrap();

    assert!(
        ops.connect_runtime.get().is_none(),
        "constructing Ops must not build the dial runtime eagerly"
    );

    let req = || ExecRunReq {
        host: "peer".into(),
        argv: vec!["true".into()],
        env: vec![],
        timeout_ms: Some(500),
    };
    let _ = ops.exec_run(req(), ExecStdin::Closed);
    let first = ops
        .connect_runtime
        .get()
        .cloned()
        .expect("exec_run must build (and reuse) Ops' shared connect_runtime");

    let _ = ops.exec_run(req(), ExecStdin::Closed);
    let second = ops
        .connect_runtime
        .get()
        .cloned()
        .expect("the shared runtime must still be installed after a second exec_run");

    assert!(
        Arc::ptr_eq(&first, &second),
        "exec_run must share one Runtime across calls, not build a second one"
    );
}

/// Issue #4 item 2, end to end: `exec_async` itself — not
/// `dial_first_reachable` driven directly (`ops::tests` already
/// covers that in isolation) — must try every resolved address, not
/// only the first. Drives `exec_async_resolving` (`exec_async`'s own
/// production body, with only the resolve step swapped for a
/// synthetic one, its `Resolver`-pattern seam) with two real,
/// unreachable loopback UDP ports — bind-then-drop, the same
/// technique `crates/qsh-cli/tests/reverse_unreachable_diagnostic.rs`
/// uses — so this is a real `Dialer::dial` attempt against each, not
/// a canned `DialError`. `with_timeout` keeps each attempt to well
/// under a second instead of the production 10s default. A mutation
/// that truncates the resolver's answer before the
/// `dial_first_reachable` call inside `exec_async_resolving` reds
/// this test: `attempted` would read 1 and the "(tried 2 addresses)"
/// suffix `map_dial_error` appends would be absent from the message.
#[tokio::test]
async fn exec_async_tries_every_resolved_address_not_only_the_first() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::ops::Paths::new(dir.path().join("config"), dir.path().join("state"));
    let trust = crate::trust::SharedTrustStore::open(paths.trust_file()).unwrap();

    // A real generated identity (not an empty `LocalIdentity`): the
    // dial below must actually reach `Dialer::dial`'s socket
    // bind/connect, not fail earlier at TLS config construction —
    // that would report `DialError::Setup`, which
    // `map_dial_error`'s own doc comment excludes from the "(tried N
    // addresses)" suffix this test asserts on.
    crate::identity::init(&paths, qsh_proto::KeyStoreMode::File).unwrap();
    let local = crate::identity::load(&paths).unwrap().unwrap().local;
    let dialer = Dialer::new(local, trust as Arc<dyn qsh_transport::TrustEvaluator>)
        .with_timeout(Duration::from_millis(300));

    // Two real, unreachable loopback UDP ports: bind each to claim a
    // real, otherwise unused port, then drop the socket immediately
    // so nothing ever answers there.
    let unreachable_addr = || {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a throwaway UDP port");
        socket.local_addr().expect("local addr")
    };
    let addrs = vec![unreachable_addr(), unreachable_addr()];

    struct StubResolver(Vec<std::net::SocketAddr>);
    impl crate::ops::AddressResolver for StubResolver {
        fn resolve_all<'a>(&'a self, _address: &'a str) -> crate::ops::ResolveFuture<'a> {
            let addrs = self.0.clone();
            Box::pin(async move { Ok(addrs) })
        }
    }

    let spec = ExecSpec {
        argv: vec!["true".into()],
        env: vec![],
        timeout: None,
    };

    let err = exec_async_resolving(
        &dialer,
        "does-not-matter:4433",
        "widget",
        "device",
        &spec,
        ExecStdin::Closed,
        None,
        &StubResolver(addrs),
    )
    .await
    .expect_err("two unreachable loopback ports must never dial successfully");

    assert!(
        err.message.contains("tried 2 addresses"),
        "message must name both attempts, not just the first (i.e. exec_async_resolving \
         must not have been reverted to trying only `addrs[0]`): {}",
        err.message
    );
}

/// `qsh exec` without `--timeout` has no deadline of its own, so before
/// [`crate::ops::RESOLVE_TIMEOUT`] a resolver that never answers (a VPN
/// swallowing DNS, issue #8) held it forever. It must now fail with
/// `CONNECTION_FAILED` after exactly that bound. Without the bound the
/// outer deadline below fires instead. Paused clock: the stub's future
/// is `pending`, so auto-advance reaches the first timer
/// deterministically.
#[tokio::test(start_paused = true)]
async fn exec_without_a_timeout_bounds_a_resolver_that_never_answers() {
    let local = qsh_transport::LocalIdentity {
        cert_chain: Vec::new(),
        key_pkcs8_der: zeroize::Zeroizing::new(Vec::new()),
    };
    let dialer = Dialer::new(local, Arc::new(qsh_transport::StaticTrust::empty()));

    struct SilentResolver;
    impl crate::ops::AddressResolver for SilentResolver {
        fn resolve_all<'a>(&'a self, _address: &'a str) -> crate::ops::ResolveFuture<'a> {
            Box::pin(std::future::pending())
        }
    }

    let spec = ExecSpec {
        argv: vec!["true".into()],
        env: vec![],
        timeout: None,
    };
    let started = tokio::time::Instant::now();
    let err = tokio::time::timeout(
        crate::ops::RESOLVE_TIMEOUT * 3,
        exec_async_resolving(
            &dialer,
            "controller.example:4433",
            "widget",
            "device",
            &spec,
            ExecStdin::Closed,
            None,
            &SilentResolver,
        ),
    )
    .await
    .expect("a resolver that never answers must not hold exec past RESOLVE_TIMEOUT")
    .expect_err("a resolver that never answers cannot yield a result");

    assert_eq!(started.elapsed(), crate::ops::RESOLVE_TIMEOUT);
    assert_eq!(err.code, ErrorCode::ConnectionFailed);
    assert_eq!(
        err.message,
        "failed to resolve controller.example:4433: timed out after 10s"
    );
}

#[test]
fn well_formed_unknown_codes_pass_through_malformed_ones_do_not() {
    let ok = map_client_error(ClientError::Remote {
        code: ErrorCode::Unknown("SOME_FUTURE_CODE".into()),
        message: "m".into(),
        retryable: true,
    });
    assert_eq!(ok.code, ErrorCode::Unknown("SOME_FUTURE_CODE".into()));
    assert!(ok.retryable);

    for raw in [
        "",
        "lowercase",
        "HAS SPACE",
        "ESC\u{1b}[31mRED",
        "한글",
        "9STARTS_WITH_DIGIT",
        &"X".repeat(65),
    ] {
        let bad = map_client_error(ClientError::Remote {
            code: ErrorCode::Unknown(raw.into()),
            message: "m".into(),
            retryable: false,
        });
        assert_eq!(bad.code, ErrorCode::RemoteError, "raw={raw:?}");
        assert_eq!(bad.details["raw_code"], raw);
    }
}

#[test]
fn timeout_error_is_retryable_and_carries_the_budget() {
    let err = timeout_error(Duration::from_millis(1500));
    assert_eq!(err.code, ErrorCode::Timeout);
    assert!(err.retryable);
    assert_eq!(err.details["timeout_ms"], 1500);
}

/// Issue #5's routing change (`resolve_exec_route`/
/// `resolve_host_route_with`) moved where `exec_run` learns a name has
/// no configuration at all, at the exact seam that decides it:
/// `exec_run` must answer `CONFIG_ERROR` before it ever routes, even
/// for a name that is configured nowhere at all — proving the order is
/// "identity, then routing" rather than "routing, then identity for
/// whichever branch happens to need it". A device that never ran `qsh
/// init` has no identity to build either the forward `PeerTarget` or
/// the reverse `LocalRoute` with, and the frozen `error.CONFIG_ERROR.json`
/// fixture (`qsh exec HOST_ALIAS`, `crates/qsh-cli/tests/fixtures.rs`)
/// and `exit_code_matrix.rs`'s "exec: no device identity" row both pin
/// this same order for a *configured* name; this pins it independently
/// for one that is not, so a regression that moved identity-loading
/// behind `resolve_host_route_with` (which would answer `HOST_NOT_FOUND`
/// for this name well before any identity check) cannot hide behind
/// "only the configured-name fixture is checked".
#[test]
fn exec_run_answers_config_error_before_routing_even_for_an_unconfigured_name() {
    let (_dir, ops) = temp_ops(); // never `identity_init`'d.
    let err = ops
        .exec_run(
            ExecRunReq {
                host: "nowhere-at-all".into(),
                argv: vec!["true".into()],
                env: vec![],
                timeout_ms: None,
            },
            ExecStdin::Closed,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError, "{err:?}");
}

/// `resolve_exec_route`'s "wholly unconfigured" branch must keep
/// `qsh exec`'s own frozen legacy wording
/// (`host::not_in_trust_store_host_not_found`, extracted verbatim from
/// the pre-issue-#5 `resolve_peer_address` this replaces) rather than
/// the longer, newer wording `Ops::resolve_host_route` gives every
/// other caller (`host::unconfigured_host_not_found`) — the
/// append-only `error.HOST_NOT_FOUND.json` fixture (`qsh exec nowhere`)
/// compares this message byte for byte.
#[test]
fn exec_host_not_found_keeps_the_frozen_text_for_a_wholly_unconfigured_name() {
    let (_dir, ops) = temp_ops();
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();
    let identity = ops.load_identity().unwrap().expect("just initialized");

    // `PeerRoute` (the `Ok` side) has no `Debug` impl, so this matches
    // by hand rather than `.unwrap_err()`.
    let err = match ops.resolve_exec_route("nowhere", identity) {
        Err(err) => err,
        Ok(_) => panic!("an unconfigured name must not route anywhere"),
    };
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(
        err.message,
        host::not_in_trust_store_host_not_found("nowhere").message,
        "exec's own frozen wording must be used, not resolve_host_route's newer one"
    );
}

/// The other exec-specific branch `resolve_exec_route` must get right:
/// a trust-store pin with no address and no reverse registration is
/// `pinned_without_address_host_not_found` — the truthful wording
/// issue #5 gives every caller of `Ops::resolve_host_route`'s shared
/// routing, replacing the pre-#5 `resolve_peer_address`'s false "is
/// not in the trust store" for this exact shape (the host *is* pinned;
/// see issue #5's reverse-only counterpart,
/// `exec_run_reaches_a_reverse_only_host_pinned_without_address` in
/// `crates/qsh-testkit/tests/reverse_exec.rs`).
#[test]
fn exec_host_not_found_names_a_pinned_host_without_address_truthfully() {
    let (_dir, ops) = temp_ops();
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();
    let identity = ops.load_identity().unwrap().expect("just initialized");
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"exec-pinned-no-address-peer");
    ops.trust_add(TrustAddReq {
        name: "phone".into(),
        address: None,
        fingerprint: Some(fingerprint.to_string()),
        cert_pem: None,
    })
    .unwrap();

    let err = match ops.resolve_exec_route("phone", identity) {
        Err(err) => err,
        Ok(_) => panic!("a pinned-but-addressless host must not route anywhere"),
    };
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(
        err.message,
        host::pinned_without_address_host_not_found("phone").message,
        "a pinned-but-addressless host must not be told it is unpinned"
    );
}

/// The `user@`-prefix branch, exercised through `exec_run`'s own
/// `resolve_exec_route` rather than the shared `host::resolve_route`
/// unit tests (`ops/host/tests.rs`) — this file's module doc in
/// `qsh-testkit/tests/reverse_exec.rs` used to claim this split was
/// unit tested against `Ops::resolve_exec_route` when no such test
/// existed. `"dave@phone"` with `phone` pinned must give the same
/// `user_prefix_not_accepted_host_not_found` wording every other
/// caller of `Ops::resolve_host_route`'s routing gets — that branch
/// is shared, unlike the "wholly unconfigured" wording above.
#[test]
fn exec_host_not_found_names_a_pinned_alias_behind_a_user_prefix() {
    let (_dir, ops) = temp_ops();
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();
    let identity = ops.load_identity().unwrap().expect("just initialized");
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"exec-user-prefix-peer");
    ops.trust_add(TrustAddReq {
        name: "phone".into(),
        address: None,
        fingerprint: Some(fingerprint.to_string()),
        cert_pem: None,
    })
    .unwrap();

    let err = match ops.resolve_exec_route("dave@phone", identity) {
        Err(err) => err,
        Ok(_) => panic!("a user@-prefixed positional must not route anywhere"),
    };
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(
        err.message,
        host::user_prefix_not_accepted_host_not_found("phone").message,
        "a configured alias behind a user@ prefix must name the prefix problem, not \
         pretend the alias itself is unconfigured"
    );
}

/// The `user@`-prefix branch's other side: `"dave@nowhere"` where
/// `nowhere` is configured nowhere at all still falls through to
/// exec's own frozen legacy text (same wording as the bare-alias case
/// above), because the prefix check only fires once `display_name` is
/// found in the trust store or `hosts.toml` (`host::resolve_route`'s
/// own doc) — an unconfigured name behind a prefix is exactly as
/// unconfigured as one without it.
#[test]
fn exec_host_not_found_keeps_the_frozen_text_for_a_user_prefixed_unconfigured_name() {
    let (_dir, ops) = temp_ops();
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();
    let identity = ops.load_identity().unwrap().expect("just initialized");

    let err = match ops.resolve_exec_route("dave@nowhere", identity) {
        Err(err) => err,
        Ok(_) => panic!("a user@-prefixed unconfigured name must not route anywhere"),
    };
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(
        err.message,
        host::not_in_trust_store_host_not_found("nowhere").message,
        "an unconfigured name behind a user@ prefix keeps exec's frozen bare-alias wording"
    );
}
