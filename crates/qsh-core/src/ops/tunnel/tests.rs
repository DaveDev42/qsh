use std::net::TcpListener;

use super::*;

fn req(mode: &str, bind: Option<&str>, listen_port: u32) -> TunnelOpenReq {
    TunnelOpenReq {
        host: "box".to_string(),
        mode: mode.to_string(),
        bind: bind.map(str::to_string),
        listen_port,
        forward_host: "db.internal".to_string(),
        forward_port: 5432,
        wait_ms: None,
        supervise_ms: None,
        accept_hold_ms: None,
    }
}

/// `--wait`'s bound (`docs/CLI.md` §6.9, issue #4 item 5a): `0..=600_000`
/// is accepted (mapped straight through as a millisecond budget),
/// anything above is `INVALID_ARGUMENT` before a connection is ever
/// attempted — same shape as [`port`]'s own `1..=65535` check just
/// above it in this file.
#[test]
fn wait_ms_is_bounded_0_to_600_000() {
    assert_eq!(wait_budget_ms(None).unwrap(), 0);
    assert_eq!(wait_budget_ms(Some(0)).unwrap(), 0);
    assert_eq!(
        wait_budget_ms(Some(WAIT_MS_MAX)).unwrap(),
        u64::from(WAIT_MS_MAX)
    );
    let err = wait_budget_ms(Some(WAIT_MS_MAX + 1)).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.message.contains("wait_ms"), "{}", err.message);
    assert_eq!(
        wait_budget_ms(Some(u32::MAX)).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

/// [`wait_budget_ms`]'s bound wired all the way through
/// [`Ops::tunnel_open`], not just the private helper the test above
/// pins in isolation (issue #4 item 5a review finding: nothing
/// previously called `tunnel_open` with an out-of-range `wait_ms`, so
/// a mutation that let it silently become `0` passed the whole
/// suite). `wait_budget_ms(req.wait_ms)?` runs before
/// `connect_keeping_target` ever dials anything, so this needs no daemon
/// or peer — a valid `listen_port` (`req`'s own default shape) keeps
/// `spec_from_request`'s own port check from firing first and masking
/// which check actually rejected the request.
#[test]
fn tunnel_open_rejects_an_out_of_range_wait_ms_before_ever_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
    let ops = Ops::new(paths);
    let over_budget = TunnelOpenReq {
        wait_ms: Some(WAIT_MS_MAX + 1),
        ..req("local", None, 8080)
    };
    let err = match ops.tunnel_open(over_budget) {
        Ok(_) => panic!("wait_ms above WAIT_MS_MAX must be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.message.contains("wait_ms"), "{}", err.message);
}

/// `[transport].keep_alive_ms` is read before `tunnel open`/`-D` dial
/// anything (ADR-0021 decision 1): an out-of-range value is `CONFIG_ERROR`,
/// not a clamp and not a `HOST_NOT_FOUND` from the unconfigured `box`.
#[test]
fn tunnel_open_and_dynamic_reject_an_out_of_range_keep_alive_before_ever_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
    std::fs::create_dir_all(&paths.config_dir).unwrap();
    std::fs::write(paths.config_file(), "[transport]\nkeep_alive_ms = 999\n").unwrap();
    let ops = Ops::new(paths);

    let err = match ops.tunnel_open(req("local", None, 8080)) {
        Ok(_) => panic!("keep_alive_ms = 999 must be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(!err.retryable);
    assert!(err.message.contains("keep_alive_ms"), "{}", err.message);

    let dynamic = TunnelDynamicReq {
        host: "box".to_string(),
        bind: None,
        listen_port: 1080,
        supervise_ms: None,
        accept_hold_ms: None,
    };
    let err = match ops.tunnel_dynamic(dynamic) {
        Ok(_) => panic!("keep_alive_ms = 999 must be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code, ErrorCode::ConfigError);
}

/// A `-R` request is refused as unimplemented, not as malformed, and
/// an unknown mode the other way round (`docs/CLI.md` §3.3).
#[test]
fn both_modes_parse_and_an_unknown_mode_is_invalid_argument() {
    assert_eq!(
        spec_from_request(&req("socks", None, 9000))
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    let spec = spec_from_request(&req("local", None, 8080)).unwrap();
    assert_eq!(spec.direction, ForwardDirection::Local);
    assert_eq!(spec.listen_port, 8080);
    assert_eq!((spec.host.as_str(), spec.host_port), ("db.internal", 5432));

    let spec = spec_from_request(&req("remote", None, 9000)).unwrap();
    assert_eq!(spec.direction, ForwardDirection::Remote);
    assert_eq!(spec.listen_port, 9000);
    assert_eq!((spec.host.as_str(), spec.host_port), ("db.internal", 5432));
}

/// A request that never went through the CLI parser still cannot
/// smuggle a port outside the grammar, or (in `"local"` mode) a
/// non-loopback bind past §4.1 #3. `"remote"` mode applies no such
/// pre-check (`spec_from_request`'s own doc) — a non-loopback `-R`
/// bind parses here and is caught on the peer instead.
#[test]
fn a_hand_built_request_is_still_held_to_the_grammar_and_the_local_loopback_rule() {
    for mode in ["local", "remote"] {
        for bad in [0, 65_536, u32::MAX] {
            assert_eq!(
                spec_from_request(&req(mode, None, bad)).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{mode} listen_port {bad}"
            );
        }
    }
    assert_eq!(
        spec_from_request(&req("local", Some("0.0.0.0"), 8080))
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(spec_from_request(&req("local", Some("127.0.0.9"), 8080)).is_ok());
    assert!(spec_from_request(&req("local", Some("::1"), 8080)).is_ok());
    // `"remote"` mode: a non-loopback bind is not rejected here — the
    // peer decides (`crate::server::Server::authorize_and_bind_remote_forward`).
    assert!(spec_from_request(&req("remote", Some("0.0.0.0"), 8080)).is_ok());
}

/// The frontend pre-flight: the grammar's code and the loopback
/// rule's code both come back as `INVALID_ARGUMENT`, with the
/// offending spec named, and nothing is created.
#[test]
fn the_preflight_reports_bad_specs_before_anything_binds() {
    let ok = parse_local_forwards(&["8080:localhost:3000".to_string()]).unwrap();
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].direction, ForwardDirection::Local);
    assert_eq!(ok[0].listen_port, 8080);

    for bad in [
        "not-a-spec",
        "0:localhost:3000",
        "70000:localhost:3000",
        "8080::3000",
        "203.0.113.5:8080:localhost:3000",
    ] {
        let err = parse_local_forwards(&[bad.to_string()]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad}");
        assert!(err.message.contains(bad), "{bad}: {}", err.message);
    }
}

/// An empty `-L` list is not an error — it is the ordinary
/// `qsh [user@]host` form with no forwards.
#[test]
fn no_specs_parse_to_no_forwards() {
    assert!(parse_local_forwards(&[]).unwrap().is_empty());
}

/// **Regression (adversarial-review finding).** `RemoteForwardOpened
/// .actual_port` is peer-supplied and not range-checked before this
/// point — a buggy or hostile target can send any `u32`. Before this
/// fix, `bind`'s port was clamped to `u16::MAX` on overflow while
/// `Tunnel.actual_port` kept the raw, un-clamped value, so the two
/// fields could name two different "actual" ports for the same
/// tunnel (`docs/CLI.md` §6.9's own stated invariant is that they
/// always agree). This asserts they still agree once clamped.
#[test]
fn remote_tunnel_dto_clamps_bind_and_actual_port_to_the_same_value() {
    let spec = ForwardSpec {
        direction: ForwardDirection::Remote,
        bind: None,
        listen_port: 9000,
        host: "db.internal".to_string(),
        host_port: 5432,
    };
    for out_of_range in [65_536u32, u32::MAX] {
        let opened = wire::RemoteForwardOpened {
            forward_id: "fwd-test".to_string(),
            actual_port: out_of_range,
        };
        let tunnel = remote_tunnel_dto(&spec, &opened, "box");
        assert_eq!(
            tunnel.actual_port,
            Some(u32::from(u16::MAX)),
            "actual_port must be clamped, not left raw, for {out_of_range}"
        );
        assert_eq!(
            tunnel.bind,
            wire::format_host_port("127.0.0.1", u16::MAX),
            "bind's port for {out_of_range}"
        );
    }

    // The ordinary in-range case is untouched: no spurious clamping.
    let opened = wire::RemoteForwardOpened {
        forward_id: "fwd-test".to_string(),
        actual_port: 9000,
    };
    let tunnel = remote_tunnel_dto(&spec, &opened, "box");
    assert_eq!(tunnel.actual_port, Some(9000));
    assert_eq!(tunnel.bind, wire::format_host_port("127.0.0.1", 9000));
}

/// ADR-0019 decision 3, no-fallback half: a peer that does not
/// advertise `dial-filter.v1` gets `UNSUPPORTED` and **nothing is
/// bound** — pinned by asking the OS for an ephemeral port
/// (`listen_port: 0`) and confirming `Ok` was never reached at all
/// (there is no handle to ask for its bound port; the only way to
/// observe "nothing bound" here is that this call never got that far).
///
/// Builds a real (but handshake-free) forward-route [`Connected`] via
/// [`Connected::for_test_forward`]: `Session::from_control` performs
/// no I/O, so a hand-built [`wire::Hello`] whose `capabilities` omits
/// [`wire::CAP_DIAL_FILTER_V1`] is enough to exercise the gate without
/// a real peer answering one.
#[test]
fn tunnel_dynamic_without_dial_filter_capability_is_unsupported_and_binds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
    let ops = Ops::new(paths);
    let runtime = ops.connect_runtime().unwrap();

    // `_server` is never touched again but must stay alive for the
    // test's whole duration: dropping the peer's own accepted
    // connection would tear down `client`'s side of the loopback pair
    // out from under it.
    let (endpoint, client, _server) =
        runtime.block_on(crate::tunnel::testutil::loopback_pair_with_client_endpoint());
    // The control stream `Session::from_control` stores — never read
    // in this test, since the capability check runs before any
    // request would ever go out on it.
    let ctl = runtime.block_on(async {
        let (send, recv) = client.open_bi().await.unwrap();
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
    let session = crate::client::Session::from_control(client.clone(), ctl, hello);
    let conn = Connected::for_test_forward(runtime, endpoint, client, session);

    let err = match Ops::tunnel_dynamic_with_connected(conn, None, 0, "box", None) {
        Err(err) => err,
        Ok(_) => panic!("-D must never bind without the peer's dial-filter.v1 capability"),
    };
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert_eq!(err.message, DYNAMIC_FORWARD_CAPABILITY_UNSUPPORTED_MESSAGE);
}

/// ADR-0019 decision 11 promises that a same-process `tunnel.close`
/// really tears a `-D` hold down — this
/// proves it through the same `register_hold` mechanism
/// `tunnel_dynamic_and_hold` itself calls (extracted as this test's
/// own doc explains), rather than through `tunnel_dynamic_and_hold`
/// end to end: that entry point additionally needs a real
/// `resolve_route`/`connect_target` dial, which — same reasoning as
/// `tunnel_dynamic_without_dial_filter_capability_is_unsupported_and_binds_nothing`
/// just above — is exactly what `Connected::for_test_forward` exists
/// to route around for this crate's own unit tests
/// (`crate::tunnel::testutil`'s own module doc: `qsh-testkit`, which
/// has the live-host harness, cannot be a dev-dependency here).
#[test]
fn tunnel_dynamic_and_hold_close_frees_the_socks_listener_port() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
    let ops = Ops::new(paths);
    let runtime = ops.connect_runtime().unwrap();

    let (endpoint, client, _server) =
        runtime.block_on(crate::tunnel::testutil::loopback_pair_with_client_endpoint());
    let ctl = runtime.block_on(async {
        let (send, recv) = client.open_bi().await.unwrap();
        qsh_transport::FramedStream::control(send, recv)
    });
    let hello = wire::Hello {
        versions: vec![1],
        device_name: "peer".to_string(),
        capabilities: vec![
            qsh_proto::wire::CAP_EXEC.to_string(),
            wire::CAP_DIAL_FILTER_V1.to_string(),
        ],
        reverse: None,
    };
    let session = crate::client::Session::from_control(client.clone(), ctl, hello);
    let conn = Connected::for_test_forward(runtime, endpoint, client, session);

    // Ephemeral port (`listen_port: 0`): the OS picks one, so a
    // successful re-bind after close is real proof the listener is
    // gone, not just that the request named a fixed, always-free port.
    let hold = Ops::tunnel_dynamic_with_connected(conn, None, 0, "box", None)
        .expect("a peer advertising dial-filter.v1 must be allowed to bind");
    let tunnel = hold.dynamic_tunnel().clone();
    let bound_port = u16::try_from(
        tunnel
            .actual_port
            .expect("a bound -D listener always reports actual_port"),
    )
    .expect("actual_port must fit a real TCP port");
    TcpListener::bind(("127.0.0.1", bound_port))
        .expect_err("the -D listener should still hold this port before close");

    ops.register_hold(hold, tunnel.tunnel_id.clone());

    let closed = ops
        .tunnel_close(TunnelCloseReq {
            tunnel_id: tunnel.tunnel_id.clone(),
        })
        .expect("tunnel.close never errors");
    assert!(
        closed.closed,
        "a same-process -D hold must report closed: true"
    );

    TcpListener::bind(("127.0.0.1", bound_port)).unwrap_or_else(|e| {
        panic!("port {bound_port} was not re-bindable after tunnel.close: {e}")
    });
}

mod require_dial_filter_capability_tests {
    use super::*;

    #[test]
    fn present_capability_is_ok() {
        let caps = vec![wire::CAP_DIAL_FILTER_V1.to_string(), "other.v1".to_string()];
        assert!(require_dial_filter_capability(&caps).is_ok());
    }

    #[test]
    fn missing_capability_is_the_forward_message() {
        let caps = vec!["other.v1".to_string()];
        let err = require_dial_filter_capability(&caps).expect_err("must refuse");
        assert_eq!(err.code, ErrorCode::Unsupported);
        assert_eq!(err.message, DYNAMIC_FORWARD_CAPABILITY_UNSUPPORTED_MESSAGE);
    }

    #[test]
    fn empty_capability_list_is_unsupported() {
        let err = require_dial_filter_capability(&[]).expect_err("must refuse");
        assert_eq!(err.code, ErrorCode::Unsupported);
    }
}

fn ops_in(dir: &std::path::Path) -> Ops {
    Ops::new(crate::config::Paths::new(
        dir.join("config"),
        dir.join("state"),
    ))
}

/// A `supervise_ms` outside `0..=86_400_000` is `INVALID_ARGUMENT`, and it
/// is decided before anything connects or binds: no host is configured in
/// this `Ops`, so any later step would have failed with `HOST_NOT_FOUND`.
#[test]
fn supervise_out_of_range_is_invalid_argument_before_any_listener_exists() {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());
    let too_long = TunnelOpenReq {
        supervise_ms: Some(SUPERVISE_MS_MAX + 1),
        ..req("local", None, 8080)
    };
    let err = ops.tunnel_open(too_long).err().expect("must be refused");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.message.contains("supervise_ms"), "{}", err.message);

    let dynamic = TunnelDynamicReq {
        host: "box".to_string(),
        bind: None,
        listen_port: 1080,
        supervise_ms: Some(SUPERVISE_MS_MAX + 1),
        accept_hold_ms: None,
    };
    let err = ops.tunnel_dynamic(dynamic).err().expect("must be refused");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.message.contains("supervise_ms"), "{}", err.message);
}

#[test]
fn tunnel_open_and_hold_with_supervise_is_invalid_argument_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());
    let err = ops
        .tunnel_open_and_hold(TunnelOpenReq {
            supervise_ms: Some(1_000),
            ..req("local", None, 8080)
        })
        .expect_err("must be refused");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    let err = ops
        .tunnel_dynamic_and_hold(TunnelDynamicReq {
            host: "box".to_string(),
            bind: None,
            listen_port: 1080,
            supervise_ms: Some(1_000),
            accept_hold_ms: None,
        })
        .expect_err("must be refused");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn accept_hold_without_supervise_or_above_two_thousand_or_on_remote_is_invalid_argument_before_bind()
 {
    let dir = tempfile::tempdir().unwrap();
    let ops = ops_in(dir.path());
    let cases = [
        // without supervise
        ("local", None, Some(500)),
        // above the bound
        ("local", Some(1_000), Some(ACCEPT_HOLD_MS_MAX + 1)),
        // on --remote
        ("remote", Some(1_000), Some(500)),
    ];
    for (mode, supervise_ms, accept_hold_ms) in cases {
        let err = ops
            .tunnel_open(TunnelOpenReq {
                supervise_ms,
                accept_hold_ms,
                ..req(mode, None, 8080)
            })
            .err()
            .expect("must be refused");
        assert_eq!(
            err.code,
            ErrorCode::InvalidArgument,
            "{mode} {supervise_ms:?} {accept_hold_ms:?}: {}",
            err.message
        );
        assert!(err.message.contains("accept_hold_ms"), "{}", err.message);
    }
    let err = ops
        .tunnel_dynamic(TunnelDynamicReq {
            host: "box".to_string(),
            bind: None,
            listen_port: 1080,
            supervise_ms: None,
            accept_hold_ms: Some(500),
        })
        .err()
        .expect("must be refused");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn supervise_zero_and_absent_serialize_byte_identically() {
    let absent = req("local", None, 8080);
    let json = serde_json::to_value(&absent).unwrap();
    assert!(json.get("supervise_ms").is_none(), "{json}");
    assert!(json.get("accept_hold_ms").is_none(), "{json}");
    // The CLI maps 0 to None, so "zero" and "absent" are the same value
    // and the same bytes; a nonzero value is a plain number, never null.
    let set = TunnelOpenReq {
        supervise_ms: Some(5_000),
        accept_hold_ms: Some(300),
        ..absent
    };
    let json = serde_json::to_value(&set).unwrap();
    assert_eq!(json["supervise_ms"], 5_000);
    assert_eq!(json["accept_hold_ms"], 300);
}
