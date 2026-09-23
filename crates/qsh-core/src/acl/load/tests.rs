use qsh_transport::{AuthPath, Principal};

use super::*;
use crate::acl::{Decision, ResourceRef};

fn paths_with(dir: &std::path::Path) -> Paths {
    Paths::new(dir, dir)
}

fn write_acl(dir: &std::path::Path, text: &str) {
    std::fs::write(dir.join("acl.toml"), text).unwrap();
}

#[test]
fn absent_file_is_missing_with_effective_deny_all() {
    let dir = tempfile::tempdir().unwrap();
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(matches!(load, PolicyLoad::Missing));
    assert!(load.as_loaded().is_none());
}

#[test]
fn broken_toml_is_invalid_config_error() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(dir.path(), "this is not [ valid toml");
    let load = PolicySource::load(&paths_with(dir.path()));
    match load {
        PolicyLoad::Invalid(err) => assert_eq!(err.code, ErrorCode::ConfigError),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn unknown_action_pattern_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"bogus.action\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    match load {
        PolicyLoad::Invalid(err) => assert_eq!(err.code, ErrorCode::ConfigError),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn dot_boundary_is_required_session_star_without_dot_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"session*\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(
        matches!(load, PolicyLoad::Invalid(_)),
        "\"session*\" has no dot boundary and must not parse as a wildcard"
    );
}

#[test]
fn unknown_keys_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "future_top_level_key = 1\n\n[[acl]]\nprincipal = \"user:dave\"\nallow = [\"exec.run\"]\nfuture_row_key = \"x\"\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    let policy = load
        .as_loaded()
        .expect("unknown keys must not fail the load");
    assert_eq!(policy.rules.len(), 1);
}

#[test]
fn empty_acl_array_loads_with_all_deny() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(dir.path(), "# no rules yet\n");
    let load = PolicySource::load(&paths_with(dir.path()));
    let policy = load.as_loaded().expect("an existing, empty file loads");
    assert!(policy.rules.is_empty());
    let verdict = policy.decide(
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
        Action::ExecRun,
        ResourceRef::unowned("exec"),
    );
    assert_eq!(verdict.decision, Decision::Deny);
    assert_eq!(verdict.rule, None);
}

#[test]
fn explicit_acl_array_key_but_zero_entries_also_loads_with_all_deny() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(dir.path(), "acl = []\n");
    let load = PolicySource::load(&paths_with(dir.path()));
    let policy = load.as_loaded().expect("loads");
    assert!(policy.rules.is_empty());
}

#[test]
fn a_rule_naming_an_always_denied_action_exactly_still_loads() {
    // PLAN.md M5 Step 2 (a): not a CONFIG_ERROR — `forward.socks` is a
    // real action name, just one no policy can ever grant. The
    // operator warning is emitted via `tracing`, not asserted here
    // (no subscriber is installed in this unit test).
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"forward.socks\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    let policy = load
        .as_loaded()
        .expect("a real action name is not a grammar error");
    assert_eq!(policy.rules.len(), 1);
    // And it still can never be granted (the always-deny gate runs
    // ahead of rule matching in `Policy::decide`).
    let verdict = policy.decide(
        &Principal::User("dave".into()),
        AuthPath::Pin,
        Action::ForwardSocks,
        ResourceRef::unowned("x"),
    );
    assert_eq!(verdict.decision, Decision::Deny);
    assert_eq!(verdict.rule, None);
}

#[test]
fn auth_path_and_scope_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nauth_path = \"ca\"\nscope = \"any\"\nallow = [\"session.open\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    let policy = load.as_loaded().unwrap();
    assert_eq!(policy.rules[0].auth_path, AuthPath::Ca);
    assert_eq!(policy.rules[0].scope, crate::acl::Scope::Any);
}

#[test]
fn auth_path_defaults_to_pin_when_omitted() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"session.open\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    let policy = load.as_loaded().unwrap();
    assert_eq!(policy.rules[0].auth_path, AuthPath::Pin);
}

#[test]
fn scope_defaults_to_owned_when_omitted() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"session.open\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    let policy = load.as_loaded().unwrap();
    assert_eq!(policy.rules[0].scope, crate::acl::Scope::Owned);
}

#[test]
fn unknown_auth_path_value_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nauth_path = \"bogus\"\nallow = [\"exec.run\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(matches!(load, PolicyLoad::Invalid(_)));
}

#[test]
fn unknown_scope_value_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nscope = \"bogus\"\nallow = [\"exec.run\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(matches!(load, PolicyLoad::Invalid(_)));
}

#[test]
fn empty_principal_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"\"\nallow = [\"exec.run\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(matches!(load, PolicyLoad::Invalid(_)));
}

#[test]
fn empty_allow_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nallow = []\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(matches!(load, PolicyLoad::Invalid(_)));
}

#[test]
fn rule_count_over_the_cap_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let mut text = String::new();
    for i in 0..=caps::MAX_RULES {
        text.push_str(&format!(
            "[[acl]]\nprincipal = \"user:u{i}\"\nallow = [\"exec.run\"]\n"
        ));
    }
    write_acl(dir.path(), &text);
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(matches!(load, PolicyLoad::Invalid(_)));
}

#[test]
fn patterns_per_rule_over_the_cap_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let patterns: Vec<String> = (0..=caps::MAX_PATTERNS_PER_RULE)
        .map(|_| "\"exec.run\"".to_string())
        .collect();
    let text = format!(
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [{}]\n",
        patterns.join(", ")
    );
    write_acl(dir.path(), &text);
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(matches!(load, PolicyLoad::Invalid(_)));
}

#[test]
fn file_over_the_byte_cap_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    // Pad with a TOML comment line well past the byte cap; the file
    // is rejected on size before parsing ever looks at content.
    let mut text = String::new();
    while (text.len() as u64) <= caps::MAX_FILE_BYTES {
        text.push_str("# padding padding padding padding padding padding\n");
    }
    write_acl(dir.path(), &text);
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(matches!(load, PolicyLoad::Invalid(_)));
}

#[test]
fn file_at_exactly_the_byte_cap_loads() {
    // F2 boundary companion to `file_over_the_byte_cap_is_invalid`: a
    // file whose size is exactly `MAX_FILE_BYTES` must still load —
    // the bounded-read rewrite must not have shifted the boundary by
    // one in either direction.
    let dir = tempfile::tempdir().unwrap();
    let mut text = String::from("#");
    while (text.len() as u64) < caps::MAX_FILE_BYTES - 1 {
        text.push('x');
    }
    text.push('\n');
    assert_eq!(text.len() as u64, caps::MAX_FILE_BYTES);
    write_acl(dir.path(), &text);
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(
        matches!(load, PolicyLoad::Loaded(_)),
        "a file of exactly MAX_FILE_BYTES must load, got {}",
        kind(&load)
    );
}

/// F2 (M5 Step 2 adversarial review): the byte cap used to be
/// enforced against `fs::metadata().len()` alone, then the file was
/// read with an unbounded `read_to_string` — a path whose `stat` size
/// doesn't predict its read size (a FIFO, a device node) defeated the
/// cap entirely. A symlink to `/dev/zero` reproduces exactly that:
/// `stat` reports 0 bytes, but reading never ends on its own. If the
/// fix regressed to the old stat-only gate, this test would hang
/// forever reading zeroes instead of returning `Invalid` — the
/// `recv_timeout` turns that into a fast, deterministic test failure
/// instead of an actual hang.
#[test]
#[cfg(unix)]
fn byte_cap_bounds_the_read_not_just_the_stat() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("/dev/zero", dir.path().join("acl.toml")).unwrap();
    let paths = paths_with(dir.path());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(PolicySource::load(&paths));
    });
    let load = rx.recv_timeout(std::time::Duration::from_secs(10)).expect(
        "PolicySource::load must return promptly instead of reading /dev/zero \
             unboundedly",
    );
    assert!(
        matches!(load, PolicyLoad::Invalid(_)),
        "over-cap content behind a stat-lying path must be Invalid, got {}",
        kind(&load)
    );
}

#[test]
fn principal_over_the_length_cap_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let long = "a".repeat(caps::MAX_PRINCIPAL_LEN + 1);
    let text = format!("[[acl]]\nprincipal = \"user:{long}\"\nallow = [\"exec.run\"]\n");
    write_acl(dir.path(), &text);
    let load = PolicySource::load(&paths_with(dir.path()));
    assert!(matches!(load, PolicyLoad::Invalid(_)));
}

// ---------------------------------------------------------------
// F6(b): the three principal shapes `docs/CLI.md` §6.15 mandates.
// ---------------------------------------------------------------

#[test]
fn each_valid_principal_shape_loads() {
    for principal in [
        "user:dave",
        "device:laptop",
        "fp:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let text = format!("[[acl]]\nprincipal = \"{principal}\"\nallow = [\"exec.run\"]\n");
        write_acl(dir.path(), &text);
        let load = PolicySource::load(&paths_with(dir.path()));
        assert!(
            matches!(load, PolicyLoad::Loaded(_)),
            "{principal:?} is a valid shape and must load, got {}",
            kind(&load)
        );
    }
}

#[test]
fn nonsense_principal_shapes_are_now_invalid() {
    // F6(b) REVERSES the pre-fix behavior (any string loaded
    // silently, "l6_loader_accepts_arbitrary_nonsense_principals_
    // silently"-class): a principal that can never match any real
    // `Principal::to_string()` output is now a load-time
    // `CONFIG_ERROR`, not a permanently-inert rule.
    for principal in ["hello world", "*", "dave", "USER:dave", "user:", "fp:"] {
        let dir = tempfile::tempdir().unwrap();
        let text = format!("[[acl]]\nprincipal = \"{principal}\"\nallow = [\"exec.run\"]\n");
        write_acl(dir.path(), &text);
        let load = PolicySource::load(&paths_with(dir.path()));
        assert!(
            matches!(load, PolicyLoad::Invalid(_)),
            "{principal:?} has no valid principal shape and must be Invalid, got {}",
            kind(&load)
        );
    }
}

// ---------------------------------------------------------------
// F1: the Invalid message must never dump acl.toml source content,
// and must always be a single line.
// ---------------------------------------------------------------

fn invalid_message(dir: &std::path::Path) -> String {
    match PolicySource::load(&paths_with(dir)) {
        PolicyLoad::Invalid(err) => err.message,
        other => panic!("expected Invalid, got {}", kind(&other)),
    }
}

fn kind(load: &PolicyLoad) -> &'static str {
    match load {
        PolicyLoad::Loaded(_) => "Loaded",
        PolicyLoad::Missing => "Missing",
        PolicyLoad::Invalid(_) => "Invalid",
    }
}

#[test]
fn invalid_message_does_not_echo_acl_toml_source_content() {
    let dir = tempfile::tempdir().unwrap();
    // The syntax error sits on the same line as the sentinel, so the
    // old `toml::de::Error::to_string()`-verbatim message rendered
    // this exact line, principal included.
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"fp:sha256:SUPERSECRETPINVALUE\nallow = [\"exec.run\"]\n",
    );
    let msg = invalid_message(dir.path());
    assert!(
        !msg.contains("SUPERSECRETPINVALUE"),
        "CONFIG_ERROR message echoes acl.toml source content: {msg:?}"
    );
    assert!(
        !msg.contains('\n'),
        "CONFIG_ERROR message must be single-line: {msg:?}"
    );
}

#[test]
fn invalid_messages_are_always_single_line() {
    // A sweep across every distinct way `parse`/`parse_rule` can
    // fail, including the three grammar-token echoes that F1
    // deliberately keeps (unknown action pattern/auth_path/scope) —
    // those echo a bounded, single-line-escaped grammar token, never
    // raw multi-line acl.toml source.
    let bad_files = [
        "this is not [ valid toml",
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"bogus.action\"]\n",
        "[[acl]]\nprincipal = \"user:dave\"\nauth_path = \"bogus\"\nallow = [\"exec.run\"]\n",
        "[[acl]]\nprincipal = \"user:dave\"\nscope = \"bogus\"\nallow = [\"exec.run\"]\n",
        "[[acl]]\nprincipal = \"\"\nallow = [\"exec.run\"]\n",
        "[[acl]]\nprincipal = \"nonsense\"\nallow = [\"exec.run\"]\n",
        "[[acl]]\nprincipal = \"user:dave\"\nallow = []\n",
    ];
    for text in bad_files {
        let dir = tempfile::tempdir().unwrap();
        write_acl(dir.path(), text);
        let msg = invalid_message(dir.path());
        assert!(
            !msg.contains('\n'),
            "Invalid message for {text:?} is not single-line: {msg:?}"
        );
    }
}

// ---------------------------------------------------------------
// F9: pin that the two `tracing::warn!` diagnostics (always-denied
// named action, F1 comment above `parse_rule`; zero rules loaded,
// F7) actually fire, on the right target, with structural fields
// only — not just that the code compiles a warn! call nobody ever
// observes firing. A minimal hand-rolled `Subscriber` is enough
// (`tracing`, unlike `tracing-subscriber`, is already an ordinary
// dependency of this crate); no new dev-dependency is pulled in.
// ---------------------------------------------------------------
mod capture {
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};

    #[derive(Default)]
    pub(super) struct Sink {
        pub(super) events: Mutex<Vec<(String, String)>>, // (target, rendered fields)
    }

    struct Rec(String);
    impl Visit for Rec {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{}={:?} ", field.name(), value));
        }
    }

    pub(super) struct Sub(pub(super) Arc<Sink>);
    impl tracing::Subscriber for Sub {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::Id, _: &tracing::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut rec = Rec(String::new());
            event.record(&mut rec);
            self.0
                .events
                .lock()
                .unwrap()
                .push((event.metadata().target().to_string(), rec.0));
        }
        fn enter(&self, _: &tracing::Id) {}
        fn exit(&self, _: &tracing::Id) {}
    }
}

fn capture_qsh_acl_events(text: &str) -> (PolicyLoad, Vec<(String, String)>) {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    write_acl(dir.path(), text);
    let sink = Arc::new(capture::Sink::default());
    let sub = capture::Sub(sink.clone());
    let load =
        tracing::subscriber::with_default(sub, || PolicySource::load(&paths_with(dir.path())));
    let events = sink
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|(target, _)| target == "qsh::acl")
        .cloned()
        .collect();
    (load, events)
}

#[test]
fn always_denied_named_action_warns_with_structural_fields_only() {
    let (load, events) = capture_qsh_acl_events(
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"forward.socks\", \"file.read\"]\n",
    );
    assert!(matches!(load, PolicyLoad::Loaded(_)));
    assert_eq!(
        events.len(),
        2,
        "one warning per exactly-named always-denied action, got {events:?}"
    );
    for (_, fields) in &events {
        assert!(fields.contains("rule="), "{fields}");
        assert!(fields.contains("action="), "{fields}");
        // Structural only — never the operator's own text.
        assert!(!fields.contains("user:dave"), "{fields}");
    }
}

#[test]
fn wildcard_covering_an_always_denied_action_emits_no_warning() {
    let (load, events) = capture_qsh_acl_events(
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"forward.*\", \"file.*\"]\n",
    );
    assert!(matches!(load, PolicyLoad::Loaded(_)));
    assert!(
        events.is_empty(),
        "only exact always-denied action names warn, not the wildcards that cover them: {events:?}"
    );
}

#[test]
fn zero_rules_loaded_warns() {
    for text in [
        "# no rules yet\n",
        "acl = []\n",
        "[[acls]]\nprincipal = \"user:dave\"\nallow = [\"exec.run\"]\n",
    ] {
        let (load, events) = capture_qsh_acl_events(text);
        let policy = load.as_loaded().expect("must still load");
        assert!(policy.rules.is_empty());
        assert_eq!(events.len(), 1, "{text:?} -> {events:?}");
        // No content beyond the fixed message — F7's warning carries
        // no operator-supplied text at all.
        assert!(!events[0].1.contains("dave"), "{events:?}");
    }
}

#[test]
fn nonzero_rules_loaded_does_not_warn_about_zero_rules() {
    let (load, events) =
        capture_qsh_acl_events("[[acl]]\nprincipal = \"user:dave\"\nallow = [\"exec.run\"]\n");
    assert!(matches!(load, PolicyLoad::Loaded(_)));
    assert!(events.is_empty(), "{events:?}");
}

// ---------------------------------------------------------------
// M5 Step 6 owed test (6): the group-/world-writable warning
// (`warn_if_group_or_world_writable`) — non-fatal, fires once, never
// on an owner-only file. Unix-only: the check itself is `#[cfg(unix)]`.
// ---------------------------------------------------------------

#[test]
#[cfg(unix)]
fn world_writable_acl_toml_loads_but_warns_once() {
    // F7 (`PLAN.md` M5 Step 6 PR 6a adversarial ④): table-driven over
    // the mode matrix so the group-writable bit *alone* is pinned, not
    // just the world-writable case — a mutation narrowing the mask
    // from `& 0o022` to `& 0o002` (other-write only) would still catch
    // 0o666/0o602 (both other-writable) but must be caught here by
    // 0o660 (group-writable, NOT other-writable), which the narrowed
    // mask would wrongly wave through as silent.
    use std::os::unix::fs::PermissionsExt;
    let cases: &[(u32, bool)] = &[
        (0o666, true),  // group- and world-writable
        (0o660, true),  // group-writable only
        (0o602, true),  // world-writable only
        (0o600, false), // owner-only: no warning
    ];
    for &(mode, should_warn) in cases {
        let dir = tempfile::tempdir().unwrap();
        write_acl(
            dir.path(),
            "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"exec.run\"]\n",
        );
        std::fs::set_permissions(
            dir.path().join("acl.toml"),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        let sink = std::sync::Arc::new(capture::Sink::default());
        let sub = capture::Sub(sink.clone());
        let load =
            tracing::subscriber::with_default(sub, || PolicySource::load(&paths_with(dir.path())));
        assert!(
            load.as_loaded().is_some(),
            "{mode:03o}: a group-/world-writable file still loads — warning, not a deny"
        );
        let events: Vec<_> = sink
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(target, _)| target == "qsh::acl")
            .cloned()
            .collect();
        if should_warn {
            assert_eq!(
                events.len(),
                1,
                "{mode:03o}: exactly one warning, got {events:?}"
            );
            assert!(events[0].1.contains("mode="), "{mode:03o}: {events:?}");
            assert!(events[0].1.contains("path="), "{mode:03o}: {events:?}");
        } else {
            assert!(
                events.is_empty(),
                "{mode:03o}: must stay silent, got {events:?}"
            );
        }
    }
}

#[test]
#[cfg(unix)]
fn owner_only_acl_toml_does_not_warn() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"exec.run\"]\n",
    );
    std::fs::set_permissions(
        dir.path().join("acl.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let sink = std::sync::Arc::new(capture::Sink::default());
    let sub = capture::Sub(sink.clone());
    let load =
        tracing::subscriber::with_default(sub, || PolicySource::load(&paths_with(dir.path())));
    assert!(load.as_loaded().is_some());
    let events: Vec<_> = sink
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|(target, _)| target == "qsh::acl")
        .cloned()
        .collect();
    assert!(events.is_empty(), "0600 must stay silent: {events:?}");
}

// ---------------------------------------------------------------
// `load_or_deny` / `StartupDiagnostic` — the production wiring itself.
// ---------------------------------------------------------------

#[test]
fn load_or_deny_on_missing_file_denies_and_names_the_missing_code() {
    let dir = tempfile::tempdir().unwrap();
    let (authorizer, diag) = load_or_deny(&paths_with(dir.path()), Role::Serve);
    let verdict = authorizer.check(
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
        Action::ExecRun,
        ResourceRef::unowned("exec"),
    );
    assert_eq!(verdict.decision, Decision::Deny);
    let diag = diag.expect("a missing acl.toml must produce a diagnostic");
    assert_eq!(diag.code, ACL_POLICY_MISSING_CODE);
    assert_eq!(diag.path, paths_with(dir.path()).acl_file());
    assert!(diag.detail.is_none());
    let rendered = diag.render();
    assert!(rendered.contains(ACL_POLICY_MISSING_CODE));
    assert!(rendered.contains(ErrorCode::ConfigError.as_str()));
    assert!(rendered.contains("[[acl]]"));
    // The other half of the F4 L6 gate (`acl_docs.rs` pins the docs to
    // these consts): pin `render()` itself to them too, so the banner
    // cannot silently stop emitting a fragment the docs still quote
    // verbatim as its wording.
    for fragment in [
        ACL_STARTUP_HEADLINE,
        ACL_STARTUP_DENIED_CLAUSE,
        ACL_STARTUP_NO_AUTOGEN,
        ACL_STARTUP_CHECK_HINT,
    ] {
        assert!(
            rendered.contains(fragment),
            "render() must emit {fragment:?} (docs quote it as the banner's wording)"
        );
    }
}

#[test]
fn load_or_deny_on_invalid_file_denies_and_carries_a_content_free_detail() {
    // F3 (`PLAN.md` M5 Step 6 PR 6a adversarial ①): table-driven over
    // every distinct way `PolicySource::load_path` can produce
    // `PolicyLoad::Invalid`, not just the TOML-syntax shape this test
    // used to cover alone. `SENTINEL` sits inside a full raw source
    // line of the file for every shape, so "the raw line never
    // survives into `render()`" is actually exercised per-shape
    // instead of assumed to generalize from one.
    const SENTINEL: &str = "SUPERSECRETPINVALUE0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    struct Case {
        name: &'static str,
        text: String,
        /// The exact raw source line (no trailing `\n`) the sentinel
        /// sits on — must never appear anywhere in `detail`/`render()`,
        /// for every shape without exception.
        raw_line: String,
        /// `Some(token)` for the three Step 2 grammar-token carve-outs
        /// (this file's F1 doc comment, `parse_rule`'s three
        /// `unknown ... {other:?}`/`{pattern:?}` arms): `detail` DOES
        /// echo `token` verbatim, but bounded (<=128 bytes) and
        /// single-line. `None` for every other shape, where nothing
        /// from the file survives into `detail` at all.
        grammar_token: Option<String>,
    }

    let over_length_pattern = SENTINEL.repeat(3);
    assert!(
        over_length_pattern.len() > caps::MAX_PATTERN_LEN,
        "test setup: the over-length pattern must actually exceed the cap"
    );
    let unknown_action = format!("{SENTINEL}.bogus");

    let cases = [
        Case {
            name: "toml syntax error",
            text: format!("[[acl]]\nprincipal = \"fp:sha256:{SENTINEL}\nallow = [\"exec.run\"]\n"),
            raw_line: format!("principal = \"fp:sha256:{SENTINEL}"),
            grammar_token: None,
        },
        Case {
            name: "unknown action pattern",
            text: format!("[[acl]]\nprincipal = \"user:dave\"\nallow = [\"{unknown_action}\"]\n"),
            raw_line: format!("allow = [\"{unknown_action}\"]"),
            grammar_token: Some(unknown_action.clone()),
        },
        Case {
            name: "unknown auth_path",
            text: format!(
                "[[acl]]\nprincipal = \"user:dave\"\nauth_path = \"{SENTINEL}\"\n\
                 allow = [\"exec.run\"]\n"
            ),
            raw_line: format!("auth_path = \"{SENTINEL}\""),
            grammar_token: Some(SENTINEL.to_string()),
        },
        Case {
            name: "unknown scope",
            text: format!(
                "[[acl]]\nprincipal = \"user:dave\"\nscope = \"{SENTINEL}\"\n\
                 allow = [\"exec.run\"]\n"
            ),
            raw_line: format!("scope = \"{SENTINEL}\""),
            grammar_token: Some(SENTINEL.to_string()),
        },
        Case {
            name: "over-length action pattern",
            text: format!(
                "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"{over_length_pattern}\"]\n"
            ),
            raw_line: format!("allow = [\"{over_length_pattern}\"]"),
            grammar_token: None,
        },
        Case {
            name: "serde type error",
            text: format!(
                "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"exec.run\"]\n\
                 # {SENTINEL}\nauth_path = 12345\n"
            ),
            raw_line: format!("# {SENTINEL}"),
            grammar_token: None,
        },
        Case {
            name: "missing field",
            text: format!("[[acl]]\nprincipal = \"user:{SENTINEL}\"\n"),
            raw_line: format!("principal = \"user:{SENTINEL}\""),
            grammar_token: None,
        },
    ];

    for case in cases {
        let dir = tempfile::tempdir().unwrap();
        write_acl(dir.path(), &case.text);
        let (authorizer, diag) = load_or_deny(&paths_with(dir.path()), Role::Serve);
        let verdict = authorizer.check(
            &Principal::Device("laptop".into()),
            AuthPath::Pin,
            Action::ExecRun,
            ResourceRef::unowned("exec"),
        );
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "{}: an invalid acl.toml must deny",
            case.name
        );
        let diag = diag.unwrap_or_else(|| {
            panic!(
                "{}: an invalid acl.toml must produce a diagnostic",
                case.name
            )
        });
        assert_eq!(diag.code, ACL_POLICY_INVALID_CODE, "{}", case.name);
        let detail = diag
            .detail
            .as_ref()
            .unwrap_or_else(|| panic!("{}: Invalid always carries a detail", case.name));
        let rendered = diag.render();

        assert!(
            !detail.contains(&case.raw_line) && !rendered.contains(&case.raw_line),
            "{}: raw acl.toml source line leaked into the diagnostic: {detail:?}",
            case.name
        );

        match &case.grammar_token {
            None => {
                assert!(
                    !detail.contains(SENTINEL) && !rendered.contains(SENTINEL),
                    "{}: diagnostic must be content-free, got detail={detail:?}",
                    case.name
                );
            }
            Some(token) => {
                assert!(
                    detail.contains(token.as_str()),
                    "{}: the documented grammar-token carve-out must still echo the \
                     token, got detail={detail:?}",
                    case.name
                );
                assert!(
                    token.len() <= caps::MAX_PATTERN_LEN,
                    "{}: test setup: grammar token must fit the documented <=128-byte \
                     bound",
                    case.name
                );
                assert!(
                    !detail.contains('\n'),
                    "{}: the grammar-token carve-out must stay single-line: {detail:?}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn load_or_deny_on_loaded_policy_has_no_diagnostic_and_evaluates_rules() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"device:laptop\"\nallow = [\"exec.run\"]\n",
    );
    let (authorizer, diag) = load_or_deny(&paths_with(dir.path()), Role::Serve);
    assert!(diag.is_none());
    let verdict = authorizer.check(
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
        Action::ExecRun,
        ResourceRef::unowned("exec"),
    );
    assert_eq!(verdict.decision, Decision::Allow);
    let verdict = authorizer.check(
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
        Action::SessionOpen,
        ResourceRef::unowned("s1"),
    );
    assert_eq!(verdict.decision, Decision::Deny);
}

// ---------------------------------------------------------------
// M5 Step 6 owed test (4): the CA-path round trip through the real
// `load_or_deny` pipeline — a rule with no `auth_path` (defaults to
// `pin`) never grants a CA-authenticated peer anything, and an
// explicit `auth_path = "ca"` rule does. No CA issuance harness exists
// at the real-binary level yet (private CA is M6 scope,
// `crate::trust`'s own module doc), so this exercises the same
// `AuthPath` distinction `crates/qsh-cli/tests/acl_enforcement.rs`'s
// owed tests (1)/(2)/(3)/(5) exercise for the pin path, through the
// one function production actually calls (`load_or_deny`), not just
// `Policy::decide` against a hand-built `Policy` (`policy.rs`'s own
// `auth_path`-sensitive tests already cover that half in isolation).
// ---------------------------------------------------------------

#[test]
fn load_or_deny_ca_path_round_trip_default_denies_explicit_ca_allows() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"user:dave\"\nallow = [\"exec.run\"]\n\n\
         [[acl]]\nprincipal = \"user:carol\"\nauth_path = \"ca\"\nallow = [\"exec.run\"]\n",
    );
    let (authorizer, diag) = load_or_deny(&paths_with(dir.path()), Role::Serve);
    assert!(diag.is_none());

    // `dave`'s rule has no `auth_path` — defaults to `pin` (F6(b)'s own
    // discipline) — so a CA-authenticated `dave` is denied even though
    // the principal string matches a real rule.
    let verdict = authorizer.check(
        &Principal::User("dave".into()),
        AuthPath::Ca,
        Action::ExecRun,
        ResourceRef::unowned("exec"),
    );
    assert_eq!(verdict.decision, Decision::Deny, "no implicit CA grant");
    // The same principal, pinned, is allowed — the rule it omitted
    // `auth_path` for.
    let verdict = authorizer.check(
        &Principal::User("dave".into()),
        AuthPath::Pin,
        Action::ExecRun,
        ResourceRef::unowned("exec"),
    );
    assert_eq!(verdict.decision, Decision::Allow);

    // `carol`'s rule explicitly names `auth_path = "ca"`: a
    // CA-authenticated `carol` is allowed, but a *pinned* `carol` is
    // not — the rule never claimed to cover that path.
    let verdict = authorizer.check(
        &Principal::User("carol".into()),
        AuthPath::Ca,
        Action::ExecRun,
        ResourceRef::unowned("exec"),
    );
    assert_eq!(verdict.decision, Decision::Allow);
    let verdict = authorizer.check(
        &Principal::User("carol".into()),
        AuthPath::Pin,
        Action::ExecRun,
        ResourceRef::unowned("exec"),
    );
    assert_eq!(verdict.decision, Decision::Deny, "the rule never named pin");
}

#[test]
fn minimal_policy_example_fills_in_actual_pinned_peer_names() {
    let dir = tempfile::tempdir().unwrap();
    let mut trust = crate::trust::TrustStore::default();
    trust.add_peer(
        "laptop",
        None,
        qsh_transport::Fingerprint::of_spki_der(b"k"),
        "2026-01-01T00:00:00Z".to_string(),
    );
    trust.save(&dir.path().join("trust.toml")).unwrap();
    let example = minimal_policy_example(&paths_with(dir.path()), Role::Serve);
    assert!(example.contains("device:laptop"), "{example:?}");
}

#[test]
fn policy_example_rows_is_the_generic_placeholder_row_when_names_is_empty() {
    let example = policy_example_rows(&[], Role::Serve);
    assert_eq!(
        example,
        "[[acl]]\nprincipal = \"device:<name>\"\nallow = [\"exec.run\", \"session.open\", \"session.list\", \"session.attach\", \"session.control\"]\n"
    );
}

#[test]
fn policy_example_rows_emits_one_row_per_name_and_is_role_aware() {
    let example = policy_example_rows(&["laptop", "phone"], Role::Serve);
    assert!(example.contains("device:laptop"), "{example:?}");
    assert!(example.contains("device:phone"), "{example:?}");
    assert_eq!(
        example.matches("[[acl]]").count(),
        2,
        "one row per name: {example:?}"
    );
    assert!(example.contains("exec.run"), "{example:?}");
    assert!(!example.contains("host.reverse"), "{example:?}");

    let listen_example = policy_example_rows(&["laptop"], Role::Listen);
    assert!(
        listen_example.contains("host.reverse"),
        "{listen_example:?}"
    );
    assert!(!listen_example.contains("exec.run"), "{listen_example:?}");
}

#[test]
fn ca_policy_example_row_names_no_specific_peer_and_sets_auth_path_ca() {
    let example = ca_policy_example_row(Role::Serve);
    assert!(example.contains("[[acl]]"), "{example:?}");
    assert!(example.contains("device:<id>"), "{example:?}");
    assert!(example.contains("auth_path = \"ca\""), "{example:?}");
    assert!(example.contains("exec.run"), "{example:?}");

    let listen_example = ca_policy_example_row(Role::Listen);
    assert!(
        listen_example.contains("host.reverse"),
        "{listen_example:?}"
    );
    assert!(!listen_example.contains("exec.run"), "{listen_example:?}");
}

// `PinnedPrincipalIndex` (ADR-0017 결정 2 `:21`'s matching
// rule reused verbatim): the pairing-pin notice's "does an `[[acl]]` row
// already name this principal" answer. Previously untested — a mutation
// that deleted the `auth_path == AuthPath::Pin` filter left the whole
// `acl::` suite green.
#[test]
fn pinned_principal_index_counts_only_pin_auth_path_rows() {
    let dir = tempfile::tempdir().unwrap();
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"device:a\"\nauth_path = \"pin\"\nallow = [\"session.open\"]\n\n\
         [[acl]]\nprincipal = \"device:b\"\nauth_path = \"ca\"\nallow = [\"session.open\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    let policy = load.as_loaded().expect("valid acl.toml must load");
    let index = PinnedPrincipalIndex::from_policy(policy);
    assert!(
        index.names_device("a"),
        "a pin-path row for device:a must be counted"
    );
    assert!(
        !index.names_device("b"),
        "a ca-path row for device:b must not be counted as a pin-path row"
    );
}

#[test]
fn pinned_principal_index_counts_the_omitted_default_auth_path() {
    let dir = tempfile::tempdir().unwrap();
    // `auth_path` omitted entirely — defaults to `pin`
    // (`auth_path_defaults_to_pin_when_omitted`, above).
    write_acl(
        dir.path(),
        "[[acl]]\nprincipal = \"device:a\"\nallow = [\"session.open\"]\n",
    );
    let load = PolicySource::load(&paths_with(dir.path()));
    let policy = load.as_loaded().expect("valid acl.toml must load");
    let index = PinnedPrincipalIndex::from_policy(policy);
    assert!(
        index.names_device("a"),
        "an omitted auth_path defaults to pin and must be counted"
    );
}

#[test]
fn pinned_principal_index_empty_names_no_device() {
    assert!(!PinnedPrincipalIndex::empty().names_device("anything"));
}

#[test]
fn load_or_deny_with_index_returns_the_empty_index_on_a_missing_or_invalid_policy() {
    // `DenyAll` is what is actually enforced in both cases, so no row —
    // pin-path or otherwise — is enforcing anything.
    let dir = tempfile::tempdir().unwrap();
    let (_authorizer, diagnostic, index) =
        load_or_deny_with_index(&paths_with(dir.path()), Role::Serve);
    assert!(diagnostic.is_some(), "a missing acl.toml must diagnose");
    assert!(!index.names_device("anything"));

    write_acl(dir.path(), "this is not [ valid toml");
    let (_authorizer, diagnostic, index) =
        load_or_deny_with_index(&paths_with(dir.path()), Role::Serve);
    assert!(
        diagnostic.is_some(),
        "an unparseable acl.toml must diagnose"
    );
    assert!(!index.names_device("anything"));
}
