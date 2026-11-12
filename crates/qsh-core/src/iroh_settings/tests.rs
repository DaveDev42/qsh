use super::*;
use crate::trust::iroh_pin::key_to_hex;
use qsh_transport::fingerprint_of_ed25519_key;

fn pin(routes: &[&str], relay: Option<&str>, key: Option<[u8; 32]>) -> TrustPeer {
    let any_key = key.unwrap_or([7; 32]);
    TrustPeer {
        name: "box".into(),
        fingerprint: fingerprint_of_ed25519_key(&any_key).to_string(),
        address: String::new(),
        added_at: "2026-11-13T00:00:00Z".into(),
        role: None,
        grants: None,
        paths: None,
        scope: None,
        source: None,
        remote_qsh: None,
        rendezvous: Vec::new(),
        jump: Vec::new(),
        routes: routes.iter().map(|r| (*r).to_string()).collect(),
        relay: relay.map(str::to_string),
        key: key.map(|k| key_to_hex(&k)),
    }
}

fn error_code(section: IrohSection) -> ErrorCode {
    section.settings().expect_err("must not validate").code
}

#[test]
fn an_empty_section_gives_the_documented_defaults() {
    let settings = IrohSection::default().settings().unwrap();
    assert!(!settings.enable);
    assert_eq!(settings.relay_url, DEFAULT_RELAY_URL);
    assert_eq!(settings.bind_port, 0);
    assert_eq!(settings.mode, IrohMode::Auto);
    assert_eq!(settings.proxy, IrohProxy::Env);
    assert_eq!(settings.head_start, Duration::from_millis(1000));
    assert_eq!(settings, IrohSettings::default());
}

#[test]
fn values_out_of_range_are_config_errors() {
    let bad_relay = IrohSection {
        relay_url: Some("http://relay.example".into()),
        ..IrohSection::default()
    };
    assert_eq!(error_code(bad_relay), ErrorCode::ConfigError);
    let bad_port = IrohSection {
        bind_port: Some(65_536),
        ..IrohSection::default()
    };
    assert_eq!(error_code(bad_port), ErrorCode::ConfigError);
    let bad_head = IrohSection {
        head_start_ms: Some(MAX_HEAD_START_MS + 1),
        ..IrohSection::default()
    };
    assert_eq!(error_code(bad_head), ErrorCode::ConfigError);
    let edges = IrohSection {
        bind_port: Some(65_535),
        head_start_ms: Some(MAX_HEAD_START_MS),
        relay_url: Some("https://relay.example:8443/".into()),
        ..IrohSection::default()
    };
    let settings = edges.settings().unwrap();
    assert_eq!(settings.bind_port, 65_535);
    assert_eq!(settings.head_start, Duration::from_secs(10));
}

#[test]
fn the_pins_relay_beats_the_device_relay_and_only_with_the_route_on() {
    let settings = IrohSection {
        relay_url: Some("https://device.example".into()),
        ..IrohSection::default()
    }
    .settings()
    .unwrap();
    let on = pin(&["iroh"], Some("https://pin.example"), Some([7; 32]));
    assert_eq!(settings.relay_for(&on), "https://pin.example");
    let no_relay = pin(&["iroh"], None, Some([7; 32]));
    assert_eq!(settings.relay_for(&no_relay), "https://device.example");
    let route_off = pin(&[], Some("https://pin.example"), Some([7; 32]));
    assert_eq!(settings.relay_for(&route_off), "https://device.example");
}

#[test]
fn a_target_needs_the_route_a_valid_key_and_a_device_with_the_mode_on() {
    let settings = IrohSettings::default();
    let ready = pin(&["iroh"], None, Some([7; 32]));
    let target = IrohTarget::for_pin(&settings, &ready).expect("a target");
    assert_eq!(target.peer.key, [7; 32]);
    assert!(target.uses_default_relay());
    assert_eq!(
        target.config.relay,
        IrohRelay::Url(DEFAULT_RELAY_URL.to_string())
    );
    assert!(target.config.proxy_from_env);
    assert!(matches!(target.config.relay_trust, IrohRelayTrust::System));

    assert!(IrohTarget::for_pin(&settings, &pin(&[], None, Some([7; 32]))).is_none());
    assert!(IrohTarget::for_pin(&settings, &pin(&["iroh"], None, None)).is_none());
    assert!(IrohTarget::for_pin(&settings, &pin(&["other"], None, Some([7; 32]))).is_none());
    assert!(IrohTarget::for_pin(&settings.clone().route_off(), &ready).is_none());
}

#[test]
fn proxy_off_and_a_fixed_port_reach_the_endpoint_config() {
    let settings = IrohSection {
        proxy: Some(IrohProxy::Off),
        bind_port: Some(4500),
        ..IrohSection::default()
    }
    .settings()
    .unwrap();
    assert!(
        !settings
            .client_config(&pin(&["iroh"], None, Some([7; 32])))
            .proxy_from_env
    );
    let server = settings.server_config();
    assert_eq!(server.bind.len(), 2);
    assert!(server.bind.iter().all(|a| a.port() == 4500));
    assert!(IrohSettings::default().server_config().bind.is_empty());
}

#[test]
fn a_relay_is_named_by_scheme_and_host_only() {
    assert_eq!(
        IrohSettings::relay_label("https://Relay.Example:8443/path?x=1"),
        "https://relay.example"
    );
    assert!(is_default_relay("https://aps1-1.relay.n0.iroh.link./"));
    assert!(!is_default_relay("https://other.example"));
}
