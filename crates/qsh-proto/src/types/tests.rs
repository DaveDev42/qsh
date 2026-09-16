use super::*;

#[test]
fn version_data_round_trips() {
    let data = VersionData {
        version: "0.1.0".to_string(),
        schemas: vec!["qsh.cli/v1".to_string(), "qsh.event/v1".to_string()],
        build: None,
    };
    let json = serde_json::to_string(&data).unwrap();
    let back: VersionData = serde_json::from_str(&json).unwrap();
    assert_eq!(back, data);
}

/// `docs/ROADMAP.md` M7 감사 개정 ③: `build` is additive, and its
/// absence must be an *omitted key* — not `"build": null` and not a
/// fabricated empty value — so older/newer readers of `qsh.cli/v1` see
/// no field at all rather than a value that looks meaningful.
#[test]
fn version_data_build_is_omitted_not_null_when_absent() {
    let data = VersionData {
        version: "0.1.0".to_string(),
        schemas: vec!["qsh.cli/v1".to_string()],
        build: None,
    };
    let json = serde_json::to_value(&data).unwrap();
    assert!(
        json.get("build").is_none(),
        "build must be an omitted key when None, not present with any value: {json}"
    );
}

/// The present case: `build.commit` round-trips as a plain string field,
/// additive alongside `version`/`schemas`.
#[test]
fn version_data_build_present_round_trips() {
    let data = VersionData {
        version: "0.1.0".to_string(),
        schemas: vec!["qsh.cli/v1".to_string()],
        build: Some(BuildInfo {
            commit: "deadbeef".to_string(),
        }),
    };
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(json["build"]["commit"], "deadbeef");
    let back: VersionData = serde_json::from_value(json).unwrap();
    assert_eq!(back, data);
}

#[test]
fn exec_run_data_matches_documented_shape() {
    let data = ExecRunData {
        stdout_b64: "RGFyd2luCg==".into(),
        stderr_b64: String::new(),
        remote_exit_code: 0,
        signal: None,
        duration_ms: 18,
    };
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "stdout_b64": "RGFyd2luCg==",
            "stderr_b64": "",
            "remote_exit_code": 0,
            "signal": null,
            "duration_ms": 18
        })
    );
}

#[test]
fn identity_init_data_matches_documented_shape() {
    let data = IdentityInitData {
        device_id: "device_01K0EXAMPLE".into(),
        fingerprint: "sha256:BASE64FINGERPRINT".into(),
        key_store: KeyStoreKind::Platform,
        config_dir: "/Users/dave/.config/qsh".into(),
        created: true,
    };
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(json["key_store"], "platform");
    assert_eq!(json["created"], true);
    assert_eq!(json["fingerprint"], "sha256:BASE64FINGERPRINT");
    let back: IdentityInitData = serde_json::from_value(json).unwrap();
    assert_eq!(back, data);
}

#[test]
fn key_store_mode_parses_lowercase_only() {
    assert_eq!("auto".parse::<KeyStoreMode>().unwrap(), KeyStoreMode::Auto);
    assert_eq!("file".parse::<KeyStoreMode>().unwrap(), KeyStoreMode::File);
    assert_eq!(
        "platform".parse::<KeyStoreMode>().unwrap(),
        KeyStoreMode::Platform
    );
    assert!("Keychain".parse::<KeyStoreMode>().is_err());
    assert_eq!(
        serde_json::to_string(&KeyStoreMode::Auto).unwrap(),
        "\"auto\""
    );
}

#[test]
fn trust_types_match_documented_shape() {
    let peer = TrustPeer {
        name: "personal-mac".into(),
        fingerprint: "sha256:BASE64FINGERPRINT".into(),
        address: "personal-mac.example.com:4433".into(),
        added_at: "2026-08-17T00:00:00Z".into(),
    };
    let add = TrustAddData {
        peer: peer.clone(),
        created: true,
        updated: None,
    };
    let json = serde_json::to_value(&add).unwrap();
    assert_eq!(json["peer"]["name"], "personal-mac");
    assert_eq!(json["peer"]["added_at"], "2026-08-17T00:00:00Z");
    assert_eq!(json["created"], true);
    // Additive (`docs/CLI.md` §10): a fresh pin has nothing to update,
    // and the key is omitted entirely rather than emitted `null` — an
    // envelope produced before M7 Step 2 is indistinguishable from one
    // where `updated` was simply never applicable.
    assert!(
        json.as_object().unwrap().get("updated").is_none(),
        "updated: None must be omitted, not null: {json}"
    );

    let moved = TrustAddData {
        peer: peer.clone(),
        created: false,
        updated: Some(true),
    };
    assert_eq!(serde_json::to_value(&moved).unwrap()["updated"], true);

    let list = TrustListData { peers: vec![peer] };
    assert_eq!(
        serde_json::to_value(&list).unwrap()["peers"][0]["name"],
        "personal-mac"
    );

    let rm = TrustRemoveData {
        name: "personal-mac".into(),
        removed: false,
    };
    assert_eq!(
        serde_json::to_value(&rm).unwrap(),
        serde_json::json!({"name": "personal-mac", "removed": false})
    );
}

#[test]
fn exec_run_req_omits_empty_optionals() {
    let req = ExecRunReq {
        host: "h".into(),
        argv: vec!["true".into()],
        env: vec![],
        timeout_ms: None,
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json, serde_json::json!({"host": "h", "argv": ["true"]}));
    let back: ExecRunReq = serde_json::from_value(json).unwrap();
    assert_eq!(back, req);
}

#[test]
fn contract_types_have_json_schemas() {
    // Smoke: schema generation must not panic for any contract type.
    let _ = schemars::schema_for!(VersionData);
    let _ = schemars::schema_for!(ExecRunReq);
    let _ = schemars::schema_for!(ExecRunData);
    let _ = schemars::schema_for!(IdentityInitData);
    let _ = schemars::schema_for!(TrustAddReq);
    let _ = schemars::schema_for!(TrustAddData);
    let _ = schemars::schema_for!(TrustListData);
    let _ = schemars::schema_for!(TrustRemoveData);
    let _ = schemars::schema_for!(Host);
    let _ = schemars::schema_for!(HostListReq);
    let _ = schemars::schema_for!(HostListData);
    let _ = schemars::schema_for!(HostGetReq);
    let _ = schemars::schema_for!(Tunnel);
    let _ = schemars::schema_for!(TunnelOpenReq);
    let _ = schemars::schema_for!(TunnelListReq);
    let _ = schemars::schema_for!(TunnelListData);
    let _ = schemars::schema_for!(TunnelCloseReq);
    let _ = schemars::schema_for!(TunnelCloseData);
    for schema in session_schemas() {
        // Every session contract type is an object schema with at least
        // one property (none of them is a bare alias or an empty struct).
        assert_eq!(schema["type"], "object", "{schema}");
        assert!(
            schema["properties"]
                .as_object()
                .is_some_and(|p| !p.is_empty()),
            "{schema}"
        );
    }
}

fn session_schemas() -> Vec<serde_json::Value> {
    vec![
        schemars::schema_for!(Session).to_value(),
        schemars::schema_for!(SessionListReq).to_value(),
        schemars::schema_for!(SessionListData).to_value(),
        schemars::schema_for!(UnreachableHost).to_value(),
        schemars::schema_for!(SessionGetReq).to_value(),
        schemars::schema_for!(SessionOpenReq).to_value(),
        schemars::schema_for!(SessionOpenData).to_value(),
        schemars::schema_for!(SessionAttachReq).to_value(),
        schemars::schema_for!(SessionReadReq).to_value(),
        schemars::schema_for!(SessionReadData).to_value(),
        schemars::schema_for!(SessionWriteReq).to_value(),
        schemars::schema_for!(SessionWriteData).to_value(),
        schemars::schema_for!(SessionResizeReq).to_value(),
        schemars::schema_for!(SessionResizeData).to_value(),
        schemars::schema_for!(SessionCloseReq).to_value(),
        schemars::schema_for!(SessionCloseData).to_value(),
    ]
}

/// ADR-0007: the resume token is never a property of any JSON contract
/// type (checked structurally on every `properties` map, at any depth).
#[test]
fn no_session_contract_type_exposes_resume_token() {
    fn property_names(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::Object(props)) = map.get("properties") {
                    out.extend(props.keys().cloned());
                }
                for child in map.values() {
                    property_names(child, out);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    property_names(child, out);
                }
            }
            _ => {}
        }
    }
    for schema in session_schemas() {
        let mut names = Vec::new();
        property_names(&schema, &mut names);
        assert!(!names.is_empty());
        for n in &names {
            let lower = n.to_ascii_lowercase();
            assert!(
                !lower.contains("token"),
                "credential-looking property {n:?} in a JSON contract schema"
            );
        }
    }
}

#[test]
fn session_matches_documented_shape() {
    let s = Session {
        session_ref: "personal-mac/01K0SESSION".into(),
        host: "personal-mac".into(),
        session_id: "01K0SESSION".into(),
        state: "running".into(),
        writer: Some("device:hermes".into()),
        created_at: "2026-08-17T00:00:00Z".into(),
        last_sequence: 42,
    };
    assert_eq!(
        serde_json::to_value(&s).unwrap(),
        serde_json::json!({
            "session_ref": "personal-mac/01K0SESSION",
            "host": "personal-mac",
            "session_id": "01K0SESSION",
            "state": "running",
            "writer": "device:hermes",
            "created_at": "2026-08-17T00:00:00Z",
            "last_sequence": 42
        })
    );
    // `writer` is nullable from day one (CLI.md §5).
    let json = serde_json::json!({
        "session_ref": "personal-mac/01K0SESSION",
        "host": "personal-mac",
        "session_id": "01K0SESSION",
        "state": "exited",
        "writer": null,
        "created_at": "2026-08-17T00:00:00Z",
        "last_sequence": 180
    });
    let back: Session = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back.writer, None);
    assert_eq!(serde_json::to_value(&back).unwrap(), json);
}

#[test]
fn session_open_data_matches_documented_shape() {
    let d = SessionOpenData {
        session_ref: "personal-mac/01K0SESSION".into(),
        initial_sequence: 0,
    };
    assert_eq!(
        serde_json::to_value(&d).unwrap(),
        serde_json::json!({
            "session_ref": "personal-mac/01K0SESSION",
            "initial_sequence": 0
        })
    );
}

#[test]
fn session_read_req_matches_long_poll_cursor_shape() {
    // The cursor-pull request shape a long-poll caller sends over
    // qsh.cli/v1's session.read: {session_ref, after_sequence, wait_ms,
    // limit_bytes}.
    let json = serde_json::json!({
        "session_ref": "personal-mac/01K0SESSION",
        "after_sequence": 42,
        "wait_ms": 30000,
        "limit_bytes": 65536
    });
    let req: SessionReadReq = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(req.after_sequence, 42);
    assert_eq!(req.wait_ms, Some(30000));
    assert_eq!(req.limit_bytes, Some(65536));
    assert_eq!(serde_json::to_value(&req).unwrap(), json);

    // Optionals default.
    let minimal: SessionReadReq =
        serde_json::from_value(serde_json::json!({"session_ref": "h/x"})).unwrap();
    assert_eq!(minimal.after_sequence, 0);
    assert_eq!(minimal.wait_ms, None);
    assert_eq!(minimal.limit_bytes, None);
    assert_eq!(minimal.ctl_after, None);

    // `ctl_after` is additive: absent from the §8.3 shape above, and
    // round-trips when a poller echoes the previous reply's cursor.
    let with_cursor: SessionReadReq = serde_json::from_value(serde_json::json!({
        "session_ref": "h/x",
        "after_sequence": 42,
        "ctl_after": 7
    }))
    .unwrap();
    assert_eq!(with_cursor.ctl_after, Some(7));
    assert_eq!(
        serde_json::to_value(&with_cursor).unwrap(),
        serde_json::json!({
            "session_ref": "h/x",
            "after_sequence": 42,
            "ctl_after": 7
        })
    );
}

#[test]
fn session_read_data_carries_events_in_order() {
    use crate::event::{EVENT_SCHEMA, SessionEvent};
    let d = SessionReadData {
        session_ref: "personal-mac/01K0SESSION".into(),
        next_after: 180,
        next_ctl_after: 3,
        events: vec![
            SessionEvent::Output {
                schema: EVENT_SCHEMA.into(),
                session_ref: "personal-mac/01K0SESSION".into(),
                sequence: 49,
                data_b64: "SGVsbG8NCg==".into(),
            },
            SessionEvent::Exit {
                schema: EVENT_SCHEMA.into(),
                session_ref: "personal-mac/01K0SESSION".into(),
                sequence: 49,
                exit_code: Some(0),
                signal: None,
            },
        ],
    };
    let json = serde_json::to_value(&d).unwrap();
    assert_eq!(json["events"][0]["type"], "session.output");
    assert_eq!(json["events"][1]["type"], "session.exit");
    let back: SessionReadData = serde_json::from_value(json).unwrap();
    assert_eq!(back, d);
}

#[test]
fn session_reqs_omit_empty_optionals() {
    let open = SessionOpenReq {
        host: "h".into(),
        argv: vec![],
        env: vec![],
        term: None,
        cols: None,
        rows: None,
        user: None,
    };
    assert_eq!(
        serde_json::to_value(&open).unwrap(),
        serde_json::json!({"host": "h"})
    );
    let attach = SessionAttachReq {
        session_ref: "h/x".into(),
        no_steal: false,
    };
    assert_eq!(
        serde_json::to_value(&attach).unwrap(),
        serde_json::json!({"session_ref": "h/x"})
    );
    let close = SessionCloseReq {
        session_ref: "h/x".into(),
        signal: None,
    };
    assert_eq!(
        serde_json::to_value(&close).unwrap(),
        serde_json::json!({"session_ref": "h/x"})
    );
    let list: SessionListReq = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(list.host, None);
}

#[test]
fn host_matches_documented_shape() {
    // CLI.md §5's device_id example is a peer SPKI fingerprint, not a
    // wire display name (docs/design/protocol.md §3) — never
    // "device_01K0EXAMPLE"-shaped (that vocabulary belongs to
    // IdentityInitData.device_id, a different field on a different
    // type).
    let h = Host {
        name: "personal-mac".into(),
        address: "personal-mac.example.com:4433".into(),
        connection_mode: "forward".into(),
        state: "unknown".into(),
        device_id: "sha256:BASE64FINGERPRINT".into(),
        source: None,
        user: None,
    };
    assert_eq!(
        serde_json::to_value(&h).unwrap(),
        serde_json::json!({
            "name": "personal-mac",
            "address": "personal-mac.example.com:4433",
            "connection_mode": "forward",
            "state": "unknown",
            "device_id": "sha256:BASE64FINGERPRINT"
        })
    );
    assert!(h.device_id.starts_with("sha256:"));
}

/// `PLAN.md` M7 Step 3: `source`/`user` are additive-optional —
/// `None` omits the key entirely (matches the pre-M7-Step-3 shape
/// above byte-for-byte), `Some` serializes it, matching
/// `docs/CLI.md` §10's additive-only evolution rule.
#[test]
fn host_source_and_user_are_additive_optional() {
    let h = Host {
        name: "personal-mac".into(),
        address: "personal-mac.example.com:4433".into(),
        connection_mode: "forward".into(),
        state: "unknown".into(),
        device_id: "sha256:BASE64FINGERPRINT".into(),
        source: Some("both".into()),
        user: Some("dave".into()),
    };
    assert_eq!(
        serde_json::to_value(&h).unwrap(),
        serde_json::json!({
            "name": "personal-mac",
            "address": "personal-mac.example.com:4433",
            "connection_mode": "forward",
            "state": "unknown",
            "device_id": "sha256:BASE64FINGERPRINT",
            "source": "both",
            "user": "dave"
        })
    );

    // Round-trips through a payload that predates these fields —
    // an old fixture/older peer's JSON deserializes with both `None`,
    // never a missing-field error.
    let old_shape = serde_json::json!({
        "name": "personal-mac",
        "address": "personal-mac.example.com:4433",
        "connection_mode": "forward",
        "state": "unknown",
        "device_id": "sha256:BASE64FINGERPRINT"
    });
    let parsed: Host = serde_json::from_value(old_shape).unwrap();
    assert_eq!(parsed.source, None);
    assert_eq!(parsed.user, None);
}

#[test]
fn host_list_req_is_empty_object() {
    assert_eq!(
        serde_json::to_value(HostListReq {}).unwrap(),
        serde_json::json!({})
    );
    let _: HostListReq = serde_json::from_value(serde_json::json!({})).unwrap();
}

#[test]
fn host_list_data_wraps_hosts_array() {
    let forward = Host {
        name: "personal-mac".into(),
        address: "personal-mac.example.com:4433".into(),
        connection_mode: "forward".into(),
        state: "unknown".into(),
        device_id: "sha256:AAAA".into(),
        source: None,
        user: None,
    };
    let reverse = Host {
        name: "laptop".into(),
        address: "203.0.113.5:51820".into(),
        connection_mode: "reverse".into(),
        state: "reachable".into(),
        device_id: "sha256:BBBB".into(),
        source: None,
        user: None,
    };
    let data = HostListData {
        hosts: vec![forward.clone(), reverse.clone()],
    };
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(json["hosts"][0]["connection_mode"], "forward");
    assert_eq!(json["hosts"][1]["connection_mode"], "reverse");
    let back: HostListData = serde_json::from_value(json).unwrap();
    assert_eq!(back, data);
}

#[test]
fn host_get_req_matches_documented_shape() {
    let req = HostGetReq {
        name: "personal-mac".into(),
    };
    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        serde_json::json!({"name": "personal-mac"})
    );
}

// ---- tunnel.* (M4) --------------------------------------------------

#[test]
fn tunnel_matches_documented_shape() {
    let t = Tunnel {
        tunnel_id: "tun_01K0EXAMPLE".into(),
        mode: "local".into(),
        bind: "127.0.0.1:8080".into(),
        forward_to: "localhost:3000".into(),
        actual_port: Some(8080),
        host: "personal-mac".into(),
    };
    assert_eq!(
        serde_json::to_value(&t).unwrap(),
        serde_json::json!({
            "tunnel_id": "tun_01K0EXAMPLE",
            "mode": "local",
            "bind": "127.0.0.1:8080",
            "forward_to": "localhost:3000",
            "actual_port": 8080,
            "host": "personal-mac"
        })
    );
    // `actual_port` is omitted, not null, when unset.
    let t = Tunnel {
        actual_port: None,
        ..t
    };
    let json = serde_json::to_value(&t).unwrap();
    assert!(json.get("actual_port").is_none());
    let back: Tunnel = serde_json::from_value(json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn tunnel_open_req_matches_documented_shape() {
    let req = TunnelOpenReq {
        host: "personal-mac".into(),
        mode: "remote".into(),
        bind: Some("0.0.0.0".into()),
        listen_port: 8080,
        forward_host: "localhost".into(),
        forward_port: 3000,
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["mode"], "remote");
    assert_eq!(json["bind"], "0.0.0.0");
    let back: TunnelOpenReq = serde_json::from_value(json).unwrap();
    assert_eq!(back, req);

    // `bind` omits when absent (`-L`/`-R` without an explicit bind).
    let req = TunnelOpenReq { bind: None, ..req };
    assert!(serde_json::to_value(&req).unwrap().get("bind").is_none());
}

#[test]
fn tunnel_open_data_is_a_tunnel() {
    // TunnelOpenData is a type alias, not a distinct struct — the data
    // payload of a successful `tunnel.open` is exactly a `Tunnel`
    // (`HostGetReq`/`SessionGetReq`'s "data payload is a `Host`/
    // `Session`" pattern).
    let data: TunnelOpenData = Tunnel {
        tunnel_id: "tun_01K0EXAMPLE".into(),
        mode: "local".into(),
        bind: "127.0.0.1:8080".into(),
        forward_to: "localhost:3000".into(),
        actual_port: None,
        host: "personal-mac".into(),
    };
    let _: Tunnel = data;
}

#[test]
fn tunnel_list_req_is_empty_object() {
    assert_eq!(
        serde_json::to_value(TunnelListReq {}).unwrap(),
        serde_json::json!({})
    );
    let _: TunnelListReq = serde_json::from_value(serde_json::json!({})).unwrap();
}

#[test]
fn tunnel_list_data_wraps_tunnels_array() {
    let local = Tunnel {
        tunnel_id: "tun_local".into(),
        mode: "local".into(),
        bind: "127.0.0.1:8080".into(),
        forward_to: "localhost:3000".into(),
        actual_port: Some(8080),
        host: "personal-mac".into(),
    };
    let remote = Tunnel {
        tunnel_id: "tun_remote".into(),
        mode: "remote".into(),
        bind: "127.0.0.1:9000".into(),
        forward_to: "localhost:22".into(),
        actual_port: Some(9000),
        host: "laptop".into(),
    };
    let data = TunnelListData {
        tunnels: vec![local.clone(), remote.clone()],
    };
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(json["tunnels"][0]["mode"], "local");
    assert_eq!(json["tunnels"][1]["mode"], "remote");
    let back: TunnelListData = serde_json::from_value(json).unwrap();
    assert_eq!(back, data);
}

#[test]
fn tunnel_close_req_and_data_match_documented_shape() {
    let req = TunnelCloseReq {
        tunnel_id: "tun_01K0EXAMPLE".into(),
    };
    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        serde_json::json!({"tunnel_id": "tun_01K0EXAMPLE"})
    );
    let data = TunnelCloseData {
        tunnel_id: "tun_01K0EXAMPLE".into(),
        closed: true,
    };
    assert_eq!(
        serde_json::to_value(&data).unwrap(),
        serde_json::json!({"tunnel_id": "tun_01K0EXAMPLE", "closed": true})
    );
}

/// `mode` is an open string, same discipline as `Host.connection_mode`
/// / `KeyStoreMode` — `"local"`/`"remote"` round-trip, and an unknown
/// value (e.g. a future SOCKS-adjacent mode) still deserializes rather
/// than hard-failing an older client reading a newer peer's JSON.
#[test]
fn tunnel_mode_is_an_open_string() {
    for mode in ["local", "remote", "future_mode"] {
        let json = serde_json::json!({
            "tunnel_id": "tun_x",
            "mode": mode,
            "bind": "127.0.0.1:1",
            "forward_to": "h:1",
            "host": "h"
        });
        let t: Tunnel = serde_json::from_value(json).unwrap();
        assert_eq!(t.mode, mode);
    }
}

// ---- acl.check (M5) --------------------------------------------------

#[test]
fn acl_check_req_omits_empty_optionals() {
    let req = AclCheckReq {
        principal: "user:dave".into(),
        action: "exec.run".into(),
        resource: None,
        auth_path: None,
        owner: None,
        owner_auth_path: None,
    };
    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        serde_json::json!({"principal": "user:dave", "action": "exec.run"})
    );
    let back: AclCheckReq = serde_json::from_value(serde_json::json!({
        "principal": "user:dave",
        "action": "exec.run"
    }))
    .unwrap();
    assert_eq!(back, req);

    // Every optional present round-trips too.
    let full = AclCheckReq {
        principal: "device:hermes".into(),
        action: "forward.local".into(),
        resource: Some("localhost:5432".into()),
        auth_path: Some("ca".into()),
        owner: Some("device:mac".into()),
        owner_auth_path: Some("pin".into()),
    };
    let json = serde_json::to_value(&full).unwrap();
    assert_eq!(json["resource"], "localhost:5432");
    assert_eq!(json["auth_path"], "ca");
    assert_eq!(json["owner"], "device:mac");
    assert_eq!(json["owner_auth_path"], "pin");
    let back: AclCheckReq = serde_json::from_value(json).unwrap();
    assert_eq!(back, full);
}

/// M5 Step 7's `--owner`/`--owner-auth-path` surface (`PLAN.md` M5
/// §4.2): additive on both `AclCheckReq` and `AclCheckData`, and
/// `owner_auth_path` omits (never `null`) whenever `owner` itself is
/// absent — the pairing is meaningless without an owner to pair with.
#[test]
fn acl_check_owner_fields_are_additive_and_round_trip() {
    let req = AclCheckReq {
        principal: "user:dave".into(),
        action: "session.control".into(),
        resource: Some("sess-1".into()),
        auth_path: None,
        owner: Some("user:dave".into()),
        owner_auth_path: None,
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["owner"], "user:dave");
    assert!(
        json.get("owner_auth_path").is_none(),
        "owner_auth_path omits when absent from the request, not null: {json}"
    );
    let back: AclCheckReq = serde_json::from_value(json).unwrap();
    assert_eq!(back, req);

    // An old client's JSON (no `owner`/`owner_auth_path` keys at all)
    // still deserializes — additive means a prior producer's output
    // stays valid input.
    let legacy: AclCheckReq = serde_json::from_value(serde_json::json!({
        "principal": "user:dave",
        "action": "exec.run"
    }))
    .unwrap();
    assert_eq!(legacy.owner, None);
    assert_eq!(legacy.owner_auth_path, None);

    let data = AclCheckData {
        principal: "user:dave".into(),
        action: "session.control".into(),
        resource: Some("sess-1".into()),
        auth_path: Some("pin".into()),
        decision: "allow".into(),
        rule: Some(0),
        policy: AclPolicyRef {
            path: "/x/acl.toml".into(),
            rules: 1,
            loaded: true,
        },
        owner: Some("user:dave".into()),
        owner_auth_path: Some("pin".into()),
    };
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(json["owner"], "user:dave");
    assert_eq!(json["owner_auth_path"], "pin");
    let back: AclCheckData = serde_json::from_value(json).unwrap();
    assert_eq!(back, data);

    // `owner: None` ⇒ `owner_auth_path` must also omit, never a
    // dangling default the caller never asked to evaluate.
    let unowned = AclCheckData {
        owner: None,
        owner_auth_path: None,
        ..data
    };
    let json = serde_json::to_value(&unowned).unwrap();
    assert!(json.get("owner").is_none());
    assert!(json.get("owner_auth_path").is_none());
}

#[test]
fn acl_check_data_matches_documented_shape() {
    let data = AclCheckData {
        principal: "user:dave".into(),
        action: "exec.run".into(),
        resource: Some("exec".into()),
        auth_path: Some("pin".into()),
        decision: "allow".into(),
        rule: Some(0),
        policy: AclPolicyRef {
            path: "/Users/dave/.config/qsh/acl.toml".into(),
            rules: 2,
            loaded: true,
        },
        owner: None,
        owner_auth_path: None,
    };
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "principal": "user:dave",
            "action": "exec.run",
            "resource": "exec",
            "auth_path": "pin",
            "decision": "allow",
            "rule": 0,
            "policy": {
                "path": "/Users/dave/.config/qsh/acl.toml",
                "rules": 2,
                "loaded": true
            }
        })
    );
    let back: AclCheckData = serde_json::from_value(json).unwrap();
    assert_eq!(back, data);

    // A deny with no loaded policy: `resource`/`auth_path`/`rule` all
    // omit when absent rather than serializing as `null`.
    let denied = AclCheckData {
        resource: None,
        auth_path: None,
        decision: "deny".into(),
        rule: None,
        policy: AclPolicyRef {
            path: "/Users/dave/.config/qsh/acl.toml".into(),
            rules: 0,
            loaded: false,
        },
        ..data
    };
    let json = serde_json::to_value(&denied).unwrap();
    assert!(json.get("resource").is_none());
    assert!(json.get("auth_path").is_none());
    assert!(json.get("rule").is_none());
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["policy"]["loaded"], false);
    let back: AclCheckData = serde_json::from_value(json).unwrap();
    assert_eq!(back, denied);
}

#[test]
fn acl_check_data_decision_is_an_open_string() {
    // Same open-string discipline as `Host.connection_mode`/`Tunnel.mode`
    // (`docs/CLI.md` §10) — an unrecognized value still round-trips
    // rather than hard-failing an older client reading a newer peer.
    for decision in ["allow", "deny", "future_decision"] {
        let json = serde_json::json!({
            "principal": "user:dave",
            "action": "exec.run",
            "decision": decision,
            "policy": {"path": "/x/acl.toml", "rules": 0, "loaded": false}
        });
        let d: AclCheckData = serde_json::from_value(json).unwrap();
        assert_eq!(d.decision, decision);
    }
}

#[test]
fn contract_types_have_json_schemas_for_acl_check() {
    // Smoke: schema generation must not panic for the M5 contract types.
    let _ = schemars::schema_for!(AclCheckReq);
    let _ = schemars::schema_for!(AclCheckData);
    let _ = schemars::schema_for!(AclPolicyRef);
}

#[test]
fn doctor_req_omits_host_when_absent_and_round_trips_when_present() {
    let bare = DoctorReq { host: None };
    let json = serde_json::to_value(&bare).unwrap();
    assert!(json.get("host").is_none());
    let back: DoctorReq = serde_json::from_value(json).unwrap();
    assert_eq!(back, bare);

    let with_host = DoctorReq {
        host: Some("web1".to_string()),
    };
    let json = serde_json::to_value(&with_host).unwrap();
    assert_eq!(json["host"], "web1");
    let back: DoctorReq = serde_json::from_value(json).unwrap();
    assert_eq!(back, with_host);
}

#[test]
fn doctor_req_defaults_host_when_omitted_by_an_older_client() {
    let json = serde_json::json!({});
    let req: DoctorReq = serde_json::from_value(json).unwrap();
    assert_eq!(req, DoctorReq { host: None });
}

#[test]
fn doctor_data_round_trips_with_findings_and_omits_remedy_when_absent() {
    let data = DoctorData {
        overall: "warn".to_string(),
        findings: vec![
            DoctorFinding {
                code: "keystore_unavailable".to_string(),
                status: "warn".to_string(),
                detail: "no platform keystore reachable".to_string(),
                remedy: Some("check keychain/secret-service access".to_string()),
            },
            DoctorFinding {
                code: "controller_unreachable".to_string(),
                status: "info".to_string(),
                detail: "no reverse.controller configured".to_string(),
                remedy: None,
            },
        ],
    };
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(json["overall"], "warn");
    assert!(json["findings"][0].get("remedy").is_some());
    assert!(json["findings"][1].get("remedy").is_none());
    let back: DoctorData = serde_json::from_value(json).unwrap();
    assert_eq!(back, data);
}

#[test]
fn doctor_data_empty_findings_is_overall_ok() {
    // `overall` is an open string at the wire level (same discipline as
    // `AclCheckData::decision`) — this only checks that the empty case
    // round-trips, not that `Ops::doctor` produces it (that belongs to
    // `qsh_core::ops::doctor`'s own tests).
    let data = DoctorData {
        overall: "ok".to_string(),
        findings: vec![],
    };
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(json["findings"], serde_json::json!([]));
    let back: DoctorData = serde_json::from_value(json).unwrap();
    assert_eq!(back, data);
}

#[test]
fn contract_types_have_json_schemas_for_doctor_run() {
    let _ = schemars::schema_for!(DoctorReq);
    let _ = schemars::schema_for!(DoctorData);
    let _ = schemars::schema_for!(DoctorFinding);
}
