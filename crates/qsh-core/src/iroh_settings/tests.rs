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
    assert!(
        settings.enable,
        "ADR-0063: a daemon brings the endpoint up unless told not to"
    );
    assert_eq!(settings.relay_urls, DEFAULT_RELAY_URLS);
    assert_eq!(settings.relay_urls.len(), 4);
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
    assert_eq!(settings.relays_for(&on), ["https://pin.example"]);
    let no_relay = pin(&["iroh"], None, Some([7; 32]));
    assert_eq!(settings.relays_for(&no_relay), ["https://device.example"]);
    let route_off = pin(&[], Some("https://pin.example"), Some([7; 32]));
    assert_eq!(settings.relays_for(&route_off), ["https://device.example"]);
}

#[test]
fn a_target_needs_the_route_a_valid_key_and_a_device_with_the_mode_on() {
    let settings = IrohSettings::default();
    let ready = pin(&["iroh"], None, Some([7; 32]));
    let target = IrohTarget::for_pin(&settings, &ready).expect("a target");
    assert_eq!(target.peer.key, [7; 32]);
    assert!(target.uses_default_relay());
    // The default is every n0 relay, so one of them being down is survivable.
    assert_eq!(
        target.config.relay,
        IrohRelay::Urls(
            DEFAULT_RELAY_URLS
                .iter()
                .map(|u| (*u).to_string())
                .collect()
        )
    );
    assert_eq!(target.relay_urls, DEFAULT_RELAY_URLS);
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

fn section_of(toml_text: &str) -> IrohSection {
    toml::from_str(toml_text).expect("the section parses")
}

#[test]
fn relay_url_is_a_string_or_a_list_of_strings() {
    let one = section_of(r#"relay_url = "https://relay.example""#);
    assert_eq!(
        one.relay_url,
        Some(RelayUrlSetting::One("https://relay.example".into()))
    );
    let settings = one.settings().unwrap();
    assert_eq!(settings.relay_urls, ["https://relay.example"]);
    // A single URL is the old behavior: the endpoint's only relay.
    assert_eq!(
        settings
            .client_config(&pin(&["iroh"], None, Some([7; 32])))
            .relay,
        IrohRelay::Url("https://relay.example".into())
    );

    let many = section_of(r#"relay_url = ["https://a.example", "https://b.example:8443"]"#);
    let settings = many.settings().unwrap();
    assert_eq!(
        settings.relay_urls,
        ["https://a.example", "https://b.example:8443"]
    );
    assert_eq!(
        settings.server_config().relay,
        IrohRelay::Urls(vec![
            "https://a.example".into(),
            "https://b.example:8443".into()
        ])
    );
    assert!(
        !IrohTarget::for_pin(&settings, &pin(&["iroh"], None, Some([7; 32])))
            .unwrap()
            .uses_default_relay()
    );

    // Both forms survive a round trip through the config file's TOML.
    for section in [one, many] {
        let text = toml::to_string(&section).unwrap();
        assert_eq!(section_of(&text), section, "{text}");
    }
}

#[test]
fn a_bad_relay_list_is_a_config_error_and_a_duplicate_is_one_candidate() {
    let list = |urls: &[&str]| IrohSection {
        relay_url: Some(RelayUrlSetting::Many(
            urls.iter().map(|u| (*u).to_string()).collect(),
        )),
        ..IrohSection::default()
    };
    // Empty: the key's absence is how the defaults are asked for.
    assert_eq!(error_code(list(&[])), ErrorCode::ConfigError);
    // One bad element spoils the list.
    assert_eq!(
        error_code(list(&["https://ok.example", "http://not-https.example"])),
        ErrorCode::ConfigError
    );
    assert_eq!(
        error_code(list(&["https://ok.example", ""])),
        ErrorCode::ConfigError
    );
    // Over the cap.
    let many: Vec<String> = (0..=MAX_RELAY_URLS)
        .map(|i| format!("https://r{i}.example"))
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(error_code(list(&many)), ErrorCode::ConfigError);
    assert!(list(&many[..MAX_RELAY_URLS]).settings().is_ok());
    // The same relay spelled twice is one candidate, in first-seen order.
    let settings = list(&[
        "https://a.example",
        "https://b.example",
        "https://A.example/",
        "https://b.example.",
    ])
    .settings()
    .unwrap();
    assert_eq!(
        settings.relay_urls,
        ["https://a.example", "https://b.example"]
    );
}

#[test]
fn the_default_set_is_the_four_n0_relays_and_is_recognised_as_default() {
    assert_eq!(DEFAULT_RELAY_URLS.len(), 4);
    for host in ["aps1-1", "usw1-1", "use1-1", "euc1-1"] {
        let url = format!("https://{host}.relay.n0.iroh.link");
        assert!(DEFAULT_RELAY_URLS.contains(&url.as_str()), "{url}");
        assert!(is_default_relay(&url));
        assert!(is_default_relay(&format!("{url}./")));
    }
    assert!(!is_default_relay("https://relay.example"));
    // A pin's own relay is not the default set, even when it is an n0 relay
    // spelled out: the dial uses that one relay only.
    let settings = IrohSettings::default();
    let named = pin(
        &["iroh"],
        Some("https://aps1-1.relay.n0.iroh.link"),
        Some([7; 32]),
    );
    assert_eq!(
        settings.relays_for(&named),
        ["https://aps1-1.relay.n0.iroh.link"]
    );
}
