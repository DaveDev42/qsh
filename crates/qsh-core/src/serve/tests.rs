use super::*;

#[test]
fn default_port_is_the_port_inside_default_bind() {
    assert_eq!(
        DEFAULT_PORT,
        DEFAULT_BIND.parse::<SocketAddr>().unwrap().port()
    );
}

#[test]
fn bind_precedence_flag_then_config_then_default() {
    let mut config = Config::default();
    assert_eq!(
        resolve_bind(None, &config).unwrap(),
        DEFAULT_BIND.parse::<SocketAddr>().unwrap()
    );
    config.serve.bind = Some("127.0.0.1:5000".into());
    assert_eq!(
        resolve_bind(None, &config).unwrap(),
        "127.0.0.1:5000".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        resolve_bind(Some("127.0.0.1:6000"), &config).unwrap(),
        "127.0.0.1:6000".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        resolve_bind(Some("localhost:7000"), &config)
            .unwrap()
            .port(),
        7000
    );
    let err = resolve_bind(Some("not an address"), &config).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn host_runtime_wires_device_id_and_a_shared_audit_sink() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path(), dir.path());
    let runtime = host_runtime(
        &paths,
        &Config::default(),
        "hermes",
        crate::trust::SharedTrustStore::open(paths.trust_file()).unwrap(),
    );
    assert_eq!(runtime.server.local_hello(None).device_name, "hermes");
    assert_eq!(runtime.audit.path(), paths.audit_log());
    assert_eq!(runtime.server.pending_tickets(), 0);
}

// `names_only_port`: unit coverage the two const-asserts
// above it never exercise on their own (a const-assert only proves
// the two production wordings pass; it says nothing about the
// function's behavior on inputs those wordings never contain).
#[test]
fn names_only_port_true_when_the_only_digit_run_is_the_port() {
    assert!(names_only_port("assuming port 4433: ...", 4433));
}

#[test]
fn names_only_port_false_when_a_second_number_appears() {
    assert!(!names_only_port(
        "assuming port 4433 after 80 retries",
        4433
    ));
}

#[test]
fn names_only_port_false_for_a_longer_run_sharing_a_prefix() {
    // `44330` contains `4433` as a prefix but is a different number.
    assert!(!names_only_port("bound to 44330", 4433));
}

#[test]
fn names_only_port_false_with_no_digits_at_all() {
    assert!(!names_only_port("no port named here", 4433));
}

#[test]
fn names_only_port_false_for_a_leading_zero_spelling() {
    // `04433` numerically equals 4433 but is not the same spelling —
    // a wording must name the port, not a zero-padded look-alike.
    assert!(!names_only_port("assuming port 04433", 4433));
}

#[test]
fn names_only_port_false_for_a_digit_run_long_enough_to_overflow_u32() {
    // Regression: this used to keep multiplying past `u16::MAX` and
    // panic with a `u32` overflow in a const context instead of
    // returning `false`.
    assert!(!names_only_port("after 99999999999999 bytes", 4433));
}

#[test]
fn names_only_port_true_for_the_two_production_wordings() {
    assert!(names_only_port(
        crate::trust::ADDRESS_PORT_ASSUMED_NOTICE,
        DEFAULT_PORT
    ));
    assert!(names_only_port(BIND_UNAVAILABLE_REMEDY, DEFAULT_PORT));
}

// `bind_setup_error`: only a genuine `SetupError::Bind`
// gets the shared-default-port remedy; a TLS/QUIC config failure
// (which a different `--bind` can never fix) gets the bare
// observation instead.
#[test]
fn bind_setup_error_attaches_the_remedy_only_to_an_actual_bind_failure() {
    let bind: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let bind_err = SetupError::Bind {
        addr: bind,
        source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "address in use"),
    };
    let op = bind_setup_error(&bind, bind_err);
    assert!(op.message.starts_with("cannot listen on 127.0.0.1:4433:"));
    assert!(
        op.message.contains(BIND_UNAVAILABLE_REMEDY),
        "an OS-level bind failure must carry the shared-default-port remedy: {}",
        op.message
    );
}

// `resolve_serve_mode` since ADR-0068: the outbound branch is retired, so
// every way into it is `UNSUPPORTED` with `details.reason = "reverse_retired"`,
// and only the inbound answer is left.

fn assert_retired(err: &OpError) {
    assert_eq!(err.code, ErrorCode::Unsupported, "{err:?}");
    assert!(!err.retryable);
    assert_eq!(err.details["reason"], "reverse_retired");
}

#[test]
fn resolve_serve_mode_to_is_unsupported_whatever_else_is_given() {
    let mut config = Config::default();
    assert_retired(&resolve_serve_mode(Some("box"), None, None, &config).unwrap_err());
    assert_retired(&resolve_serve_mode(Some("box"), Some("n"), None, &config).unwrap_err());
    assert_retired(
        &resolve_serve_mode(Some("box"), None, Some("127.0.0.1:0"), &config).unwrap_err(),
    );
    config.serve.to = Some("from-config".into());
    assert_retired(&resolve_serve_mode(Some("box"), None, None, &config).unwrap_err());
}

#[test]
fn resolve_serve_mode_name_is_unsupported() {
    let config = Config::default();
    assert_retired(&resolve_serve_mode(None, Some("laptop"), None, &config).unwrap_err());
}

#[test]
fn resolve_serve_mode_bind_without_to_is_inbound_via_resolve_bind() {
    let config = Config::default();
    let mode = resolve_serve_mode(None, None, Some("127.0.0.1:9000"), &config).unwrap();
    assert_eq!(mode, ServeMode::Inbound("127.0.0.1:9000".parse().unwrap()));
}

#[test]
fn resolve_serve_mode_refuses_a_config_that_still_dials_out_even_with_a_bind() {
    for (serve_to, controller) in [
        (Some("from-config"), None),
        (None, Some("legacy-controller")),
        (Some("a"), Some("a")),
        (Some("a"), Some("b")),
    ] {
        let mut config = Config::default();
        config.serve.to = serve_to.map(str::to_owned);
        config.reverse.controller = controller.map(str::to_owned);
        assert_retired(&resolve_serve_mode(None, None, None, &config).unwrap_err());
        assert_retired(
            &resolve_serve_mode(None, None, Some("127.0.0.1:9000"), &config).unwrap_err(),
        );
    }
}

#[test]
fn resolve_serve_mode_neither_given_and_neither_config_key_set_is_inbound() {
    let config = Config::default();
    let mode = resolve_serve_mode(None, None, None, &config).unwrap();
    assert_eq!(mode, ServeMode::Inbound(DEFAULT_BIND.parse().unwrap()));
}

// `config_serve_to_conflict` / `config_outbound_target` on their own,
// since `resolve_serve_mode`'s own tests above only exercise them
// through step 5.

#[test]
fn config_serve_to_conflict_is_none_when_only_one_key_is_set() {
    let mut config = Config::default();
    config.serve.to = Some("from-config".into());
    assert_eq!(config_serve_to_conflict(&config), None);

    let mut config = Config::default();
    config.reverse.controller = Some("legacy-controller".into());
    assert_eq!(config_serve_to_conflict(&config), None);
}

#[test]
fn config_serve_to_conflict_is_none_when_both_keys_agree() {
    let mut config = Config::default();
    config.serve.to = Some("same".into());
    config.reverse.controller = Some("same".into());
    assert_eq!(config_serve_to_conflict(&config), None);
    assert_eq!(
        config_outbound_target(&config).unwrap(),
        Some("same".to_string())
    );
}

#[test]
fn config_serve_to_conflict_is_some_when_both_keys_disagree() {
    let mut config = Config::default();
    config.serve.to = Some("from-config".into());
    config.reverse.controller = Some("also-from-config".into());
    assert_eq!(
        config_serve_to_conflict(&config),
        Some(("from-config", "also-from-config"))
    );
    let err = config_outbound_target(&config).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
}

#[test]
fn bind_setup_error_does_not_attach_the_remedy_to_a_tls_config_failure() {
    let bind: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let tls_err = SetupError::Tls(rustls::Error::General("bad certificate".into()));
    let op = bind_setup_error(&bind, tls_err);
    assert!(op.message.starts_with("cannot listen on 127.0.0.1:4433:"));
    assert!(
        !op.message.contains(BIND_UNAVAILABLE_REMEDY),
        "a TLS config failure must not suggest re-binding on a free port, which cannot \
         fix it: {}",
        op.message
    );
    assert_eq!(op.code, ErrorCode::ConfigError);
}
