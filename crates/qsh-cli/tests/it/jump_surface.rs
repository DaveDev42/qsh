//! The surface of `-J` (ADR-0056 decisions 20 to 22): which hop list a
//! command ends up with. The chain is never established here; a hop that is
//! not a pin ends the command at step one, and the step's name in the error
//! tells which list was chosen.

use crate::common::Sandbox;
use serde_json::Value;

const SAMPLE_FINGERPRINT: &str = "sha256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// A client whose pin `c` dials a closed loopback port and carries
/// `jump = ["pj"]`, where `pj` is not a pin.
fn client() -> Sandbox {
    let sandbox = Sandbox::initialized();
    std::fs::create_dir_all(sandbox.config_dir()).expect("create config dir");
    std::fs::write(
        sandbox.config_dir().join("trust.toml"),
        format!(
            "[[peer]]\n\
             name = \"c\"\n\
             fingerprint = \"{SAMPLE_FINGERPRINT}\"\n\
             address = \"127.0.0.1:1\"\n\
             added_at = \"2026-11-09T00:00:00Z\"\n\
             role = \"full\"\n\
             jump = [\"pj\"]\n"
        ),
    )
    .expect("write trust.toml");
    sandbox
}

/// The step the command failed at, `None` when it failed with no `jump`
/// detail (the chain was off and the direct dial failed).
fn failing_hop(value: &Value) -> Option<String> {
    assert_eq!(value["ok"], false, "{value}");
    value["error"]["details"]["jump"]["name"]
        .as_str()
        .map(str::to_string)
}

/// One row: argv after `qsh`, and the failing hop it must name.
struct Row {
    name: &'static str,
    args: &'static [&'static str],
    hop: Option<&'static str>,
}

/// `-J` / `--jump`, then `-o ProxyJump`, then the pin's `jump`, then the
/// ordinary route; `none` at any of the first two turns the chain off.
#[test]
fn jump_precedence_table() {
    let rows = [
        Row {
            name: "the pin's jump",
            args: &["exec", "c", "--json", "--", "true"],
            hop: Some("pj"),
        },
        Row {
            name: "--jump beats the pin",
            args: &["--jump", "a", "exec", "c", "--json", "--", "true"],
            hop: Some("a"),
        },
        Row {
            name: "exec -J beats the pin",
            args: &["exec", "c", "-J", "a", "--json", "--", "true"],
            hop: Some("a"),
        },
        Row {
            name: "-J lists several, the first is dialed first",
            args: &["exec", "c", "-J", "a,b", "--json", "--", "true"],
            hop: Some("a"),
        },
        Row {
            name: "root -o ProxyJump beats the pin",
            args: &["-o", "ProxyJump=b", "c", "--", "true"],
            hop: Some("b"),
        },
        Row {
            name: "root -J beats -o ProxyJump",
            args: &["-J", "a", "-o", "ProxyJump=b", "c", "--", "true"],
            hop: Some("a"),
        },
        Row {
            name: "cp -J beats the pin",
            args: &["cp", "-J", "a", "--json", "/dev/null", "c:/tmp/x"],
            hop: Some("a"),
        },
        Row {
            name: "--jump none turns the pin's jump off",
            args: &["--jump", "none", "exec", "c", "--json", "--", "true"],
            hop: None,
        },
        Row {
            name: "-o ProxyJump=none turns the pin's jump off",
            args: &["-o", "ProxyJump=none", "c", "--", "true"],
            hop: None,
        },
        Row {
            name: "-J none beats -o ProxyJump",
            args: &["-J", "none", "-o", "ProxyJump=b", "c", "--", "true"],
            hop: None,
        },
    ];
    let client = client();
    for row in rows {
        if row.args.contains(&"--json") {
            let (code, value) = client.json(row.args);
            assert_eq!(code, 255, "{}: {value}", row.name);
            assert_eq!(
                failing_hop(&value).as_deref(),
                row.hop,
                "{}: {value}",
                row.name
            );
        } else {
            // The root form has no JSON mode; the step shows in the text.
            let out = client.qsh(row.args);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(255), "{}: {stderr}", row.name);
            match row.hop {
                Some(hop) => assert!(
                    stderr.contains(&format!("({hop}):")),
                    "{}: {stderr}",
                    row.name
                ),
                None => assert!(!stderr.contains("jump "), "{}: {stderr}", row.name),
            }
        }
    }
}

/// A list `check_shape` refuses fails before any dial.
#[test]
fn a_bad_jump_list_is_invalid_argument() {
    let client = client();
    for list in ["a,a", "a,b,c,d,e", "c", "a,,b"] {
        let (code, value) = client.json(&["exec", "c", "-J", list, "--json", "--", "true"]);
        assert_eq!(code, 255, "{list}: {value}");
        assert_eq!(
            value["error"]["code"], "INVALID_ARGUMENT",
            "{list}: {value}"
        );
    }
}

/// `-W` stays unsupported.
#[test]
fn stdio_forwarding_is_still_unsupported() {
    let client = client();
    let (code, value) = client.json(&["-W", "c:22", "--json", "c"]);
    assert_ne!(code, 0, "{value}");
}

/// A pin whose saved chain names a pin that is gone gets `jump_hop_missing`
/// from `doctor` (ADR-0056 decision 22).
#[test]
fn doctor_reports_a_missing_hop() {
    let client = client();
    let (_, value) = client.json(&["doctor", "c", "--json"]);
    let findings = value["data"]["findings"].as_array().expect("findings");
    let hit = findings
        .iter()
        .find(|f| f["code"] == "jump_hop_missing")
        .unwrap_or_else(|| panic!("no jump_hop_missing in {value}"));
    assert_eq!(hit["status"], "warn", "{hit}");
}
