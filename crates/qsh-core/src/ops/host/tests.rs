use super::*;

fn sample_local(name: &str, state: &str, fingerprint: &str) -> LocalHost {
    LocalHost {
        name: name.to_string(),
        address: "203.0.113.5:51820".to_string(),
        state: state.to_string(),
        fingerprint: fingerprint.to_string(),
        capabilities: vec!["pty".to_string()],
        generation: 1,
        registered_at: "2026-08-22T00:00:00Z".to_string(),
    }
}

fn reverse_entry(pid: u32, name: &str, state: &str, fingerprint: &str) -> ReverseHostEntry {
    ReverseHostEntry {
        pid,
        socket: PathBuf::from(format!("/run/qsh/{pid}.sock")),
        local: sample_local(name, state, fingerprint),
    }
}

fn forward_store(name: &str, address: &str, fingerprint: &str) -> TrustStore {
    let mut store = TrustStore::default();
    store.add_peer(
        name,
        Some(address.to_string()),
        fingerprint.parse().expect("fingerprint"),
        "2026-01-01T00:00:00Z".to_string(),
    );
    store
}

/// The pre-M7-Step-3 shape every test in this module that isn't
/// specifically about `hosts.toml` layering keeps using — an absent
/// directory, so `source`/`user` stay `None` throughout
/// (`resolve_forward`'s own doc).
fn no_hosts() -> HostsFile {
    HostsFile::default()
}

fn hosts_with(entries: &[(&str, &str, Option<&str>)]) -> HostsFile {
    let toml = entries
        .iter()
        .map(|(name, address, user)| match user {
            Some(user) => {
                format!("[[host]]\nname = \"{name}\"\naddress = \"{address}\"\nuser = \"{user}\"\n")
            }
            None => format!("[[host]]\nname = \"{name}\"\naddress = \"{address}\"\n"),
        })
        .collect::<Vec<_>>()
        .join("\n");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hosts.toml");
    std::fs::write(&path, toml).expect("write hosts.toml");
    // `HostsFile::load` reads and fully owns its result before `dir`
    // goes out of scope at the end of this function — nothing in the
    // returned value references the directory afterward.
    HostsFile::load(&path).expect("parses")
}

const FP_A: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
// Not "BBBB…B": an all-`B` run of 43 base64 chars has non-zero trailing
// bits in its last symbol, which `Fingerprint::from_str`'s canonical
// decoder rejects (`FingerprintParseError`) — this is the base64
// encoding of 32 `0xBB` bytes, which round-trips cleanly through
// `.parse()` at line ~502 below (caught by gate run: nextest failure
// pre-existing in this diff, not a change in behavior).
const FP_B: &str = "sha256:u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=";

// ---- merge table (`PLAN.md` M3 Step 5 (c)) ----

#[test]
fn merge_forward_only() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let hosts = merge_hosts(forward_hosts(&store, &no_hosts()), &[], &no_hosts());
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].connection_mode, "forward");
    assert_eq!(hosts[0].state, "unknown");
}

#[test]
fn merge_reverse_only() {
    let reverse = vec![reverse_entry(100, "phone", "reachable", FP_A)];
    let hosts = merge_hosts(Vec::new(), &reverse, &no_hosts());
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].connection_mode, "reverse");
    assert_eq!(hosts[0].state, "reachable");
}

#[test]
fn merge_same_name_both_sources_yields_two_entries() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let reverse = vec![reverse_entry(100, "mac", "reachable", FP_B)];
    let hosts = merge_hosts(forward_hosts(&store, &no_hosts()), &reverse, &no_hosts());
    assert_eq!(hosts.len(), 2, "same name in both sources must not merge");
    let modes: std::collections::BTreeSet<&str> =
        hosts.iter().map(|h| h.connection_mode.as_str()).collect();
    assert_eq!(
        modes,
        std::collections::BTreeSet::from(["forward", "reverse"])
    );
}

#[test]
fn merge_includes_stale_reverse_entries() {
    let reverse = vec![reverse_entry(100, "old-laptop", "stale", FP_A)];
    let hosts = merge_hosts(Vec::new(), &reverse, &no_hosts());
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].state, "stale");
}

#[test]
fn merge_with_no_daemons_is_forward_only_not_an_error() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let hosts = merge_hosts(forward_hosts(&store, &no_hosts()), &[], &no_hosts());
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].connection_mode, "forward");
}

#[test]
fn merge_carries_the_hosts_toml_user_hint_onto_a_reverse_entry() {
    // P3-5 (`PLAN.md` Step 3 (a)-추기 ④): `Ops::session_open`'s
    // `resolve_user_hint` fills the default purely from the host
    // *name*, before routing ever decides forward vs. reverse — so a
    // reverse-routed name's listed `Host.user` must match, not show
    // `None` while the hint is genuinely applied.
    let reverse = vec![reverse_entry(100, "phone", "reachable", FP_A)];
    let hosts = hosts_with(&[("phone", "unused.example.com:1", Some("dave"))]);
    let listed = merge_hosts(Vec::new(), &reverse, &hosts);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].user.as_deref(), Some("dave"));
    assert_eq!(
        listed[0].source, None,
        "source stays a pure address concept — never set for a reverse entry"
    );
}

#[test]
fn forward_hosts_skips_pins_with_no_address() {
    let mut store = TrustStore::default();
    store.add_peer(
        "addressless",
        None,
        FP_A.parse().expect("fingerprint"),
        "2026-01-01T00:00:00Z".to_string(),
    );
    assert!(forward_hosts(&store, &no_hosts()).is_empty());
}

#[test]
fn forward_hosts_and_resolve_route_agree_on_routability() {
    // Pins a `forward_hosts` (listing) and `resolve_route` (routing)
    // must agree on: one with an address, one without. If the two ever
    // re-diverge (adversarial review finding: they used to be two
    // hand-written copies of the same filter), this catches it as a
    // mismatch rather than as two independently-passing but
    // inconsistent test suites.
    let mut store = TrustStore::default();
    store.add_peer(
        "routable",
        Some("routable.example.com:4433".to_string()),
        FP_A.parse().expect("fingerprint"),
        "2026-01-01T00:00:00Z".to_string(),
    );
    store.add_peer(
        "addressless",
        None,
        FP_B.parse().expect("fingerprint"),
        "2026-01-01T00:00:00Z".to_string(),
    );

    let listed: std::collections::BTreeSet<String> = forward_hosts(&store, &no_hosts())
        .into_iter()
        .map(|host| host.name)
        .collect();
    assert_eq!(
        listed,
        std::collections::BTreeSet::from(["routable".to_string()])
    );

    assert!(resolve_route(&[], &store, &no_hosts(), "routable").is_ok());
    let err = resolve_route(&[], &store, &no_hosts(), "addressless").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
}

// ---- hosts.toml priority/merge (`PLAN.md` M7 Step 3, §4.1 #4) ----
//
// `resolve_forward` (via `forward_hosts`/`resolve_route`, its only two
// callers) is the single place this decision is made; these tests pin
// every combination the design draft calls out by name: hosts.toml
// absent, hosts.toml naming a host trust doesn't, trust naming a host
// hosts.toml doesn't, and both naming the same host with different
// addresses (hosts.toml's address must win, trust's fingerprint must
// still be the one reported).

#[test]
fn absent_hosts_toml_is_byte_identical_to_pre_m7_step_3_forward_hosts() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let hosts = forward_hosts(&store, &no_hosts());
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].address, "mac.example.com:4433");
    assert_eq!(hosts[0].device_id, FP_A);
    assert_eq!(
        hosts[0].source, None,
        "no hosts.toml entries anywhere -> source stays unset, not Some(\"trust\")"
    );
    assert_eq!(hosts[0].user, None);
}

#[test]
fn hosts_toml_only_name_is_forward_routable_with_no_fingerprint() {
    // A name hosts.toml knows and trust.toml has never heard of: still
    // listed/routable (an address, no identity) — trust alone remains
    // the authority on *who* answers at that address when actually
    // dialed (this module's own `HostRoute::Forward::fingerprint` doc).
    let store = TrustStore::default();
    let hosts = hosts_with(&[("headless", "headless.example.com:4433", None)]);

    let listed = forward_hosts(&store, &hosts);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, "headless.example.com:4433");
    assert_eq!(
        listed[0].device_id, "",
        "no trust peer -> empty fingerprint"
    );
    assert_eq!(listed[0].source.as_deref(), Some("hosts"));

    let route = resolve_route(&[], &store, &hosts, "headless").unwrap();
    assert_eq!(
        route,
        HostRoute::Forward {
            address: "headless.example.com:4433".to_string(),
            fingerprint: String::new(),
            source: Some("hosts".to_string()),
            user: None,
        }
    );
}

#[test]
fn trust_only_name_reports_source_trust_once_hosts_toml_exists_at_all() {
    // hosts.toml has *some* entries (for an unrelated name), so
    // `source` starts appearing at all — a name only trust.toml knows
    // must then report `"trust"`, not silently omit the field the way
    // `absent_hosts_toml_is_byte_identical_to_pre_m7_step_3_forward_hosts`
    // pins for the *no hosts.toml entries anywhere* case.
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let hosts = hosts_with(&[("phone", "phone.example.com:4433", None)]);

    let listed = forward_hosts(&store, &hosts);
    let mac = listed.iter().find(|h| h.name == "mac").unwrap();
    assert_eq!(mac.address, "mac.example.com:4433");
    assert_eq!(mac.source.as_deref(), Some("trust"));
    assert_eq!(mac.user, None);
}

#[test]
fn hosts_toml_address_wins_over_trust_toml_address_for_the_same_name() {
    // The one decision `PLAN.md` M7 §4.1 #4 names explicitly:
    // hosts.toml's address wins; trust.toml's fingerprint is still the
    // one reported (hosts.toml never supplies identity). The two
    // addresses disagree here, so under the redefined `source`
    // (`PLAN.md` Step 3 (a)-추기 ②: which side's *address* won, not
    // which sides merely *name* the host) this is exactly the
    // silent-redirect-to-a-different-pinned-peer shape `source` exists
    // to surface -> `"hosts"`, not `"both"`.
    let store = forward_store("mac", "stale-trust-address.example.com:4433", FP_A);
    let hosts = hosts_with(&[("mac", "fresh-hosts-address.example.com:4433", None)]);

    let listed = forward_hosts(&store, &hosts);
    assert_eq!(
        listed.len(),
        1,
        "same name in both -> one merged entry, not two"
    );
    assert_eq!(listed[0].address, "fresh-hosts-address.example.com:4433");
    assert_eq!(
        listed[0].device_id, FP_A,
        "identity still comes from trust.toml alone"
    );
    assert_eq!(
        listed[0].source.as_deref(),
        Some("hosts"),
        "addresses disagree -> hosts.toml's address won, not a same-address agreement"
    );

    let route = resolve_route(&[], &store, &hosts, "mac").unwrap();
    assert_eq!(
        route,
        HostRoute::Forward {
            address: "fresh-hosts-address.example.com:4433".to_string(),
            fingerprint: FP_A.to_string(),
            source: Some("hosts".to_string()),
            user: None,
        }
    );
}

#[test]
fn hosts_toml_and_trust_toml_agreeing_on_the_same_address_report_source_both() {
    // `"both"` is reserved for the case the two sides actually agree —
    // distinct from `hosts_toml_address_wins_over_trust_toml_address_for_the_same_name`
    // above, where they disagree and hosts.toml's address wins alone.
    let store = forward_store("mac", "shared-address.example.com:4433", FP_A);
    let hosts = hosts_with(&[("mac", "shared-address.example.com:4433", None)]);

    let listed = forward_hosts(&store, &hosts);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, "shared-address.example.com:4433");
    assert_eq!(listed[0].device_id, FP_A);
    assert_eq!(
        listed[0].source.as_deref(),
        Some("both"),
        "same address on both sides -> \"both\", not just \"hosts\""
    );

    let route = resolve_route(&[], &store, &hosts, "mac").unwrap();
    assert_eq!(
        route,
        HostRoute::Forward {
            address: "shared-address.example.com:4433".to_string(),
            fingerprint: FP_A.to_string(),
            source: Some("both".to_string()),
            user: None,
        }
    );
}

#[test]
fn hosts_toml_user_hint_is_carried_through_forward_hosts_and_resolve_route() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let hosts = hosts_with(&[("mac", "mac.example.com:4433", Some("dave"))]);

    let listed = forward_hosts(&store, &hosts);
    assert_eq!(listed[0].user.as_deref(), Some("dave"));

    let route = resolve_route(&[], &store, &hosts, "mac").unwrap();
    match route {
        HostRoute::Forward { user, .. } => assert_eq!(user.as_deref(), Some("dave")),
        other => panic!("expected a forward route, got {other:?}"),
    }
}

#[test]
fn a_hosts_toml_entry_with_an_empty_address_falls_back_to_the_trust_pin() {
    // `crate::hosts::HostEntry::address`'s own doc: an explicit empty
    // string still parses but is "no route from hosts.toml for this
    // name" — must fall through to trust.toml's address exactly like a
    // client-only trust pin's own empty address does.
    let store = forward_store("mac", "trust-address.example.com:4433", FP_A);
    let hosts = hosts_with(&[("mac", "", Some("dave"))]);

    let listed = forward_hosts(&store, &hosts);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, "trust-address.example.com:4433");
    assert_eq!(
        listed[0].source.as_deref(),
        Some("trust"),
        "hosts.toml's address is empty (no route) -> trust.toml's address is the one \
         that actually won, so `source` reports \"trust\" (which side's *address* won), \
         not \"both\" merely because hosts.toml also names this host"
    );
    assert_eq!(
        listed[0].user.as_deref(),
        Some("dave"),
        "the user hint isn't gated on the address actually winning"
    );
}

#[test]
fn hosts_toml_never_makes_an_addressless_client_only_pin_forward_routable_on_its_own_error() {
    // Sanity check on the "trust remains the sole arbiter of identity"
    // rule from the other direction: a hosts.toml-only name with an
    // address is routable (proven above) purely as an address, with no
    // fingerprint — dialing it still fails closed at the TLS layer
    // (`TrustEvaluator::lookup_pin` is fingerprint-keyed, not
    // name-scoped) if no trust peer anywhere shares that fingerprint.
    // This module has no dial step to assert that with directly; the
    // fingerprint being empty here is the on-paper proof of it.
    let store = TrustStore::default();
    let hosts = hosts_with(&[("ghost", "ghost.example.com:4433", None)]);
    let route = resolve_route(&[], &store, &hosts, "ghost").unwrap();
    match route {
        HostRoute::Forward { fingerprint, .. } => assert_eq!(fingerprint, ""),
        other => panic!("expected a forward route, got {other:?}"),
    }
}

// ---- routing table (`PLAN.md` M3 Step 5 (c)) ----
//
// These call `resolve_route` (the pure function `Ops::resolve_host_route`
// itself delegates to) directly against hand-built sources — the
// injectable seam the module docs promise, no real socket or on-disk
// trust file involved.

#[test]
fn routing_prefers_live_reverse_over_forward_pin() {
    let store = forward_store("mac", "stale-estimate.example.com:4433", FP_A);
    let reverse = vec![reverse_entry(100, "mac", "reachable", FP_B)];
    let route = resolve_route(&reverse, &store, &no_hosts(), "mac").unwrap();
    assert_eq!(
        route,
        HostRoute::Reverse {
            pid: 100,
            socket: PathBuf::from("/run/qsh/100.sock"),
            address: "203.0.113.5:51820".to_string(),
            fingerprint: FP_B.to_string(),
            generation: 1,
            user: None,
        }
    );
}

#[test]
fn routing_falls_back_to_forward_pin_when_no_live_reverse_entry() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    // Only a stale reverse entry — not live, must not win.
    let reverse = vec![reverse_entry(100, "mac", "stale", FP_B)];
    let route = resolve_route(&reverse, &store, &no_hosts(), "mac").unwrap();
    assert_eq!(
        route,
        HostRoute::Forward {
            address: "mac.example.com:4433".to_string(),
            fingerprint: FP_A.to_string(),
            source: None,
            user: None,
        }
    );
}

#[test]
fn routing_on_an_empty_or_whitespace_name_is_invalid_argument_not_host_not_found() {
    // An empty name is an argument defect (`ErrorCode::InvalidArgument`),
    // never `HOST_NOT_FOUND` — falling through to `HOST_NOT_FOUND`
    // would interpolate the empty name into that error's remediation
    // message and produce a malformed `qsh trust add` suggestion
    // (adversarial review finding).
    let store = TrustStore::default();
    for name in ["", "   ", "\t"] {
        let err = resolve_route(&[], &store, &no_hosts(), name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "name {name:?}");
    }
}

#[test]
fn routing_unregistered_and_unpinned_is_host_not_found() {
    let store = TrustStore::default();
    let err = resolve_route(&[], &store, &no_hosts(), "nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
}

#[test]
fn host_not_found_message_never_leaks_a_user_at_prefix() {
    // `qsh host get <name>` (`docs/CLI.md` §6.1) takes a raw
    // positional — unlike the bare `qsh [user@]host` form, it does not
    // run `parse_target`'s `user@` split first, so a `user@host` typo
    // can reach `resolve_route` unstripped (`PLAN.md` §3 Step 6, M7
    // carry-over v). The message must not echo the `@` back, and the
    // suggested `qsh trust add <name> --address ...` remedy must name
    // something `qsh trust add` itself would actually accept —
    // `qsh_proto::wire::valid_host_name`'s `[A-Za-z0-9._-]`, `1..=64`
    // rule, which rejects `@` outright.
    let store = TrustStore::default();
    let err = resolve_route(&[], &store, &no_hosts(), "dave@nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        !err.message.contains('@'),
        "message leaked the user@ hint: {:?}",
        err.message
    );
    assert!(
        err.message.contains("qsh trust add nowhere --address"),
        "remedy did not name the bare alias: {:?}",
        err.message
    );
    assert!(
        qsh_proto::wire::valid_host_name("nowhere"),
        "the suggested alias itself must satisfy `qsh trust add`'s own name rule",
    );
}

#[test]
fn an_at_prefix_with_no_alias_left_is_invalid_argument_not_host_not_found() {
    // `"dave@"`/`"@"`/`"dave@ "` strip down to an empty (or
    // whitespace-only) alias — falling through to `HOST_NOT_FOUND`
    // would produce `qsh trust add  --address ...` (two spaces, no
    // name: un-runnable). This must land on the exact same
    // `InvalidArgument`/message the empty-name guard above uses, not a
    // new one (`PLAN.md` §3 Step 6, lens-2 finding).
    let store = TrustStore::default();
    for name in ["dave@", "@", "dave@ "] {
        let err = resolve_route(&[], &store, &no_hosts(), name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "name {name:?}");
        assert_eq!(
            err.message, "host name must not be empty",
            "name {name:?} did not share the empty-name guard's message"
        );
        assert!(
            !err.message.contains("HOST_NOT_FOUND") && !err.message.contains("trust add"),
            "name {name:?} leaked into a HOST_NOT_FOUND-shaped remedy: {:?}",
            err.message
        );
    }
}

#[test]
fn routing_trims_a_stray_space_left_by_an_at_split_and_still_finds_host_not_found() {
    // `PLAN.md` §3 Step 7, Q10: `"dave@ nowhere"` splits on the last
    // `@` to `" nowhere"` — the leading space must be trimmed before
    // the `HOST_NOT_FOUND` remedy names the alias, so the suggested
    // `qsh trust add` command is runnable and the message matches the
    // `@`-free case exactly.
    let store = TrustStore::default();
    let err = resolve_route(&[], &store, &no_hosts(), "dave@ nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        err.message.contains("qsh trust add nowhere --address"),
        "remedy did not name the trimmed bare alias: {:?}",
        err.message
    );
}

#[test]
fn routing_trims_a_bare_name_with_no_at_sign_the_same_way() {
    // Same trim, no `@` involved at all: a bare name surrounded by
    // whitespace must resolve exactly like its trimmed form, not
    // surface the untrimmed (and therefore not `valid_host_name`)
    // string in the remedy.
    let store = TrustStore::default();
    let err = resolve_route(&[], &store, &no_hosts(), " nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        err.message.contains("qsh trust add nowhere --address"),
        "remedy did not name the trimmed bare alias: {:?}",
        err.message
    );
}

#[test]
fn routing_an_internal_space_left_after_stripping_is_invalid_argument_not_host_not_found() {
    // `PLAN.md` §3 Step 7, Q10: `"dave@no where"` strips to `"no
    // where"` — non-empty, but not a legal `valid_host_name` alias (an
    // internal space). Falling through to `HOST_NOT_FOUND` would
    // suggest an un-runnable `qsh trust add "no where" --address ...`;
    // this must be a distinct `INVALID_ARGUMENT`, not the empty-name
    // wording either.
    let store = TrustStore::default();
    let err = resolve_route(&[], &store, &no_hosts(), "dave@no where").unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert_eq!(
        err.message,
        "host name \"no where\" is not a valid host alias"
    );
    assert_ne!(
        err.message, "host name must not be empty",
        "a non-empty invalid alias must not share the empty-name wording"
    );
}

#[test]
fn routing_two_live_daemons_is_invalid_argument_with_pids() {
    let store = TrustStore::default();
    let reverse = vec![
        reverse_entry(200, "mac", "reachable", FP_A),
        reverse_entry(100, "mac", "reachable", FP_B),
    ];
    let err = resolve_route(&reverse, &store, &no_hosts(), "mac").unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert_eq!(err.details["pids"], serde_json::json!([100, 200]));
}

#[test]
fn routing_ignores_a_stale_duplicate_and_uses_the_live_one() {
    let store = TrustStore::default();
    let reverse = vec![
        reverse_entry(200, "mac", "stale", FP_A),
        reverse_entry(100, "mac", "reachable", FP_B),
    ];
    let route = resolve_route(&reverse, &store, &no_hosts(), "mac").unwrap();
    assert_eq!(
        route,
        HostRoute::Reverse {
            pid: 100,
            socket: PathBuf::from("/run/qsh/100.sock"),
            address: "203.0.113.5:51820".to_string(),
            fingerprint: FP_B.to_string(),
            generation: 1,
            user: None,
        }
    );
}

#[test]
fn host_route_into_host_matches_the_json_contract_vocabulary() {
    let forward = HostRoute::Forward {
        address: "mac.example.com:4433".to_string(),
        fingerprint: FP_A.to_string(),
        source: Some("both".to_string()),
        user: Some("dave".to_string()),
    }
    .into_host("mac");
    assert_eq!(forward.connection_mode, "forward");
    assert_eq!(forward.state, "unknown");
    assert_eq!(forward.source.as_deref(), Some("both"));
    assert_eq!(forward.user.as_deref(), Some("dave"));

    // `user: Some(...)` here too (unlike `source`, which a reverse
    // route always omits) — P3-5, `into_host`'s Reverse arm must carry
    // the hint through rather than hard-coding `None`.
    let reverse = HostRoute::Reverse {
        pid: 100,
        socket: PathBuf::from("/run/qsh/100.sock"),
        address: "203.0.113.5:51820".to_string(),
        fingerprint: FP_B.to_string(),
        generation: 3,
        user: Some("dave".to_string()),
    }
    .into_host("phone");
    assert_eq!(reverse.connection_mode, "reverse");
    assert_eq!(reverse.state, "reachable");
    assert_eq!(
        reverse.source, None,
        "a reverse route is never hosts.toml-sourced"
    );
    assert_eq!(
        reverse.user.as_deref(),
        Some("dave"),
        "user is not tied to source — it must still come through"
    );
}

// ---- `resolve_host_route_async` (`PLAN.md` M3 Step 6's async seam) ----
//
// `#[cfg(unix)]`: localctl (UDS, `tokio::net::UnixListener`) is
// unix-only, same gate as `crate::localctl` itself (`lib.rs`) —
// Windows leg trap (b), an ungated `#[cfg(test)]` item under
// `--all-targets` breaks the Windows leg exactly like ungated
// production code would.
//
// These drive the seam `Ops::connect`/`connect_target` (`crate::ops::
// session`) actually use, straight from a `#[tokio::test]` worker
// thread with **no** `spawn_blocking` bridge — proving it is genuinely
// safe to `.await` from inside a runtime that already exists, which is
// exactly the hazard the sync `resolve_host_route`'s own doc comment
// flags. Where a live registration matters, a hand-rolled `LOCAL_ADMIN`
// fake daemon (mirroring `localctl::client`'s own test idiom) stands in
// for a real `qsh listen` process — no `qsh-testkit`/`ReverseHarness`
// here, since `qsh-core` deliberately does not dev-depend on it.
#[cfg(unix)]
mod reverse_route_async_tests {
    use super::*;
    use tokio::net::UnixListener;

    use crate::config::Paths;

    /// Bind a one-shot fake `LOCAL_ADMIN` daemon at `<pid>.sock` under
    /// `runtime_dir`, answering exactly one `LocalHostList` with `hosts`.
    fn spawn_fake_admin_daemon(
        runtime_dir: &std::path::Path,
        pid: u32,
        hosts: Vec<LocalHost>,
    ) -> tokio::task::JoinHandle<()> {
        std::fs::create_dir_all(runtime_dir).unwrap();
        let sock = runtime_dir.join(format!("{pid}.sock"));
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = crate::localctl::frame::LocalConduit::new(stream);
            let _hello: qsh_proto::local::LocalHello = conduit.recv().await.unwrap().unwrap();
            let _req: qsh_proto::local::LocalHostList = conduit.recv().await.unwrap().unwrap();
            conduit
                .send(&qsh_proto::local::LocalResponse {
                    body: Some(qsh_proto::local::local_response::Body::HostListResult(
                        qsh_proto::local::LocalHostListResult { hosts },
                    )),
                })
                .await
                .unwrap();
        })
    }

    fn ops_at(runtime_dir: &std::path::Path, trust: &TrustStore) -> Ops {
        let paths = Paths::new(runtime_dir.join("config"), runtime_dir.join("state"))
            .with_runtime_dir(runtime_dir.join("run"));
        trust.save(&paths.trust_file()).unwrap();
        Ops::new(paths)
    }

    #[tokio::test]
    async fn resolve_host_route_async_is_host_not_found_with_no_pin_and_no_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let ops = ops_at(dir.path(), &TrustStore::default());

        let err = ops.resolve_host_route_async("nowhere").await.unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
    }

    #[tokio::test]
    async fn resolve_host_route_async_returns_the_forward_pin_when_nothing_is_live() {
        let dir = tempfile::tempdir().unwrap();
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let ops = ops_at(dir.path(), &store);

        let route = ops.resolve_host_route_async("mac").await.unwrap();
        assert!(matches!(route, HostRoute::Forward { .. }), "{route:?}");
    }

    #[tokio::test]
    async fn resolve_host_route_async_prefers_a_live_reverse_daemon_over_a_forward_pin() {
        let dir = tempfile::tempdir().unwrap();
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let ops = ops_at(dir.path(), &store);
        let daemon = spawn_fake_admin_daemon(
            &ops.paths().runtime_dir(),
            100,
            vec![sample_local("mac", "reachable", FP_B)],
        );

        let route = ops.resolve_host_route_async("mac").await.unwrap();
        match route {
            HostRoute::Reverse {
                pid, fingerprint, ..
            } => {
                assert_eq!(pid, 100);
                assert_eq!(fingerprint, FP_B);
            }
            other => panic!("expected a live reverse route, got {other:?}"),
        }
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn resolve_host_route_async_is_invalid_argument_when_two_daemons_both_hold_it_live() {
        let dir = tempfile::tempdir().unwrap();
        let ops = ops_at(dir.path(), &TrustStore::default());
        let a = spawn_fake_admin_daemon(
            &ops.paths().runtime_dir(),
            100,
            vec![sample_local("dup", "reachable", FP_A)],
        );
        let b = spawn_fake_admin_daemon(
            &ops.paths().runtime_dir(),
            101,
            vec![sample_local("dup", "reachable", FP_B)],
        );

        let err = ops.resolve_host_route_async("dup").await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        a.await.unwrap();
        b.await.unwrap();
    }
} // mod reverse_route_async_tests
