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
        lost_at: None,
    }
}

/// Fixed test defaults for [`resolve_route`]'s injected `now`/
/// `retry_after_ms` (`docs/design/testing.md` L2) — every pre-existing
/// test in this module predates the stale branch and does not exercise
/// it, so a deterministic constant keeps them behavior-neutral while
/// still letting the new stale-branch tests below pass their own values
/// straight to [`resolve_route`] when they need to control the clock.
const TEST_NOW: std::time::SystemTime = std::time::UNIX_EPOCH;
const TEST_RETRY_AFTER_MS: u64 = 30_000;

fn resolve(
    reverse: &[ReverseHostEntry],
    store: &TrustStore,
    hosts: &HostsFile,
    name: &str,
) -> Result<HostRoute, OpError> {
    resolve_route(
        reverse,
        store,
        hosts,
        name,
        TEST_NOW,
        TEST_RETRY_AFTER_MS,
        unconfigured_host_not_found,
    )
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

    assert!(resolve(&[], &store, &no_hosts(), "routable").is_ok());
    let err = resolve(&[], &store, &no_hosts(), "addressless").unwrap_err();
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

    let route = resolve(&[], &store, &hosts, "headless").unwrap();
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

    let route = resolve(&[], &store, &hosts, "mac").unwrap();
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

    let route = resolve(&[], &store, &hosts, "mac").unwrap();
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

/// ADR-0014 결정 4: a port-less trust pin and a `hosts.toml` address
/// carrying the default port name the same address once normalized —
/// `source` must be `"both"`, not `"hosts"` (a false redirect signal).
#[test]
fn a_port_less_trust_pin_and_a_hosts_toml_address_with_the_port_report_source_both() {
    let store = forward_store("mac", "mac.example", FP_A);
    let hosts = hosts_with(&[("mac", "mac.example:4433", None)]);

    let listed = forward_hosts(&store, &hosts);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, "mac.example:4433");
    assert_eq!(
        listed[0].source.as_deref(),
        Some("both"),
        "same address, port-spelling only difference -> \"both\""
    );

    let route = resolve(&[], &store, &hosts, "mac").unwrap();
    assert_eq!(
        route,
        HostRoute::Forward {
            address: "mac.example:4433".to_string(),
            fingerprint: FP_A.to_string(),
            source: Some("both".to_string()),
            user: None,
        }
    );
}

#[test]
fn a_port_less_hosts_toml_address_resolves_with_the_default_port() {
    let hosts = hosts_with(&[("mac", "mac", None)]);
    let store = TrustStore::default();

    let listed = forward_hosts(&store, &hosts);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, "mac:4433");
    assert_eq!(listed[0].source.as_deref(), Some("hosts"));
}

/// ADR-0014 결정 4: a *live* reverse registration's address is an
/// observed value from an active daemon, never a hand-written file —
/// it must never be run through the peer-address normalizer.
#[test]
fn a_live_reverse_registration_address_is_never_normalized() {
    let mut entry = reverse_entry(100, "mac", "reachable", FP_B);
    entry.local.address = "203.0.113.5".to_string();
    let hosts = no_hosts();

    let reverse = vec![entry.clone()];
    let route = resolve(&reverse, &TrustStore::default(), &hosts, "mac").unwrap();
    assert_eq!(
        route,
        HostRoute::Reverse {
            pid: 100,
            socket: entry.socket.clone(),
            address: "203.0.113.5".to_string(),
            fingerprint: FP_B.to_string(),
            generation: 1,
            user: None,
        }
    );

    let merged = merge_hosts(Vec::new(), &reverse, &hosts);
    assert_eq!(merged[0].address, "203.0.113.5");
}

/// `PLAN.md` M9 §6 행 i: surrounding whitespace in a lookup key is
/// trimmed and still finds the pin; a `user@` hint is a different kind
/// of prefix and must keep failing closed.
#[test]
fn a_lookup_key_with_surrounding_whitespace_finds_the_pin_but_a_user_at_prefix_still_does_not() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let hosts = no_hosts();

    let route = resolve(&[], &store, &hosts, " mac ").unwrap();
    assert_eq!(
        route,
        HostRoute::Forward {
            address: "mac.example.com:4433".to_string(),
            fingerprint: FP_A.to_string(),
            source: None,
            user: None,
        }
    );

    let err = resolve(&[], &store, &hosts, "dave@mac").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        err.message.contains("qsh trust add mac --address"),
        "remedy did not name the bare alias: {:?}",
        err.message
    );
}

#[test]
fn hosts_toml_user_hint_is_carried_through_forward_hosts_and_route() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let hosts = hosts_with(&[("mac", "mac.example.com:4433", Some("dave"))]);

    let listed = forward_hosts(&store, &hosts);
    assert_eq!(listed[0].user.as_deref(), Some("dave"));

    let route = resolve(&[], &store, &hosts, "mac").unwrap();
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
    let route = resolve(&[], &store, &hosts, "ghost").unwrap();
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
    let route = resolve(&reverse, &store, &no_hosts(), "mac").unwrap();
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
    let route = resolve(&reverse, &store, &no_hosts(), "mac").unwrap();
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
        let err = resolve(&[], &store, &no_hosts(), name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "name {name:?}");
    }
}

#[test]
fn routing_unregistered_and_unpinned_is_host_not_found() {
    let store = TrustStore::default();
    let err = resolve(&[], &store, &no_hosts(), "nowhere").unwrap_err();
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
    let err = resolve(&[], &store, &no_hosts(), "dave@nowhere").unwrap_err();
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
        let err = resolve(&[], &store, &no_hosts(), name).unwrap_err();
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
    let err = resolve(&[], &store, &no_hosts(), "dave@ nowhere").unwrap_err();
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
    let err = resolve(&[], &store, &no_hosts(), " nowhere").unwrap_err();
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
    let err = resolve(&[], &store, &no_hosts(), "dave@no where").unwrap_err();
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
    let err = resolve(&reverse, &store, &no_hosts(), "mac").unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert_eq!(err.details["pids"], serde_json::json!([100, 200]));
}

/// Issue #5's own inherited-behavior claim, pinned at the seam that
/// actually decides it: the two-live-daemon conflict is the "many" branch
/// of `resolve_route`'s live match, which returns before ever consulting
/// `unconfigured` (`resolve_route`'s own doc on that parameter) — so
/// `qsh exec`'s routing (`Ops::resolve_host_route_with`, which passes
/// `not_in_trust_store_host_not_found` instead of
/// `unconfigured_host_not_found`) must get the identical
/// `InvalidArgument`/`pids` result `host.get`/attach do
/// (`routing_two_live_daemons_is_invalid_argument_with_pids` above), not a
/// different one. A regression that made the "many" branch consult
/// `unconfigured` at all — or made it depend in any way on which
/// constructor was passed — would change this result; today's code
/// cannot, which is exactly what this pins.
#[test]
fn routing_two_live_daemons_is_invalid_argument_regardless_of_the_unconfigured_constructor() {
    let store = TrustStore::default();
    let reverse = vec![
        reverse_entry(200, "mac", "reachable", FP_A),
        reverse_entry(100, "mac", "reachable", FP_B),
    ];
    let err = resolve_route(
        &reverse,
        &store,
        &no_hosts(),
        "mac",
        TEST_NOW,
        TEST_RETRY_AFTER_MS,
        not_in_trust_store_host_not_found,
    )
    .unwrap_err();
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
    let route = resolve(&reverse, &store, &no_hosts(), "mac").unwrap();
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

// ---- stale-registration retryable `HOST_NOT_FOUND` (issue #4 items 4/3a) ----

/// A `sample_local`-shaped stale entry carrying `lost_at`, for the tests
/// below that need to control it directly rather than through
/// `reverse_entry`'s `None` default.
fn stale_reverse_entry(pid: u32, name: &str, fingerprint: &str, lost_at: &str) -> ReverseHostEntry {
    let mut entry = reverse_entry(pid, name, "stale", fingerprint);
    entry.local.lost_at = Some(lost_at.to_string());
    entry
}

#[test]
fn three_way_table_never_registered_vs_stale_vs_swept() {
    let store = TrustStore::default();

    // (a) never registered at all — today's non-retryable HOST_NOT_FOUND,
    // unchanged text and `details`.
    let never = resolve(&[], &store, &no_hosts(), "nowhere").unwrap_err();
    assert_eq!(never.code, ErrorCode::HostNotFound);
    assert!(!never.retryable, "never-registered stays non-retryable");
    assert!(
        never.details.get("reason").is_none(),
        "never-registered must not carry the stale reason: {:?}",
        never.details
    );

    // (b) stale within `stale_retention` — the daemon still lists it
    // (`sweep_expired` has not dropped it), so this is the new retryable
    // branch.
    let reverse = vec![stale_reverse_entry(
        100,
        "phone",
        FP_A,
        "2026-01-01T00:00:00Z",
    )];
    let stale = resolve(&reverse, &store, &no_hosts(), "phone").unwrap_err();
    assert_eq!(stale.code, ErrorCode::HostNotFound);
    assert!(
        stale.retryable,
        "a stale-but-listed entry must be retryable"
    );
    assert_eq!(
        stale.details["reason"],
        serde_json::json!(STALE_REGISTRATION_REASON)
    );

    // (c) stale then swept — `sweep_expired` has already dropped the
    // entry, so the daemon's list no longer carries it at all: from
    // `resolve_route`'s point of view this is indistinguishable from (a),
    // by construction (an empty `reverse` slice), and must answer
    // identically.
    let swept = resolve(&[], &store, &no_hosts(), "phone").unwrap_err();
    assert_eq!(swept.code, ErrorCode::HostNotFound);
    assert!(
        !swept.retryable,
        "a swept entry is exactly the unknown case"
    );
    assert!(swept.details.get("reason").is_none());
}

/// A registry entry whose `state` is neither `"reachable"` nor `"stale"`
/// (an open string, `docs/CLI.md` §5/§10 — not reachable through
/// `EntryState`'s current two variants, but the wire-level `state` field
/// itself carries no such guarantee) must not be picked up by the stale
/// branch: it is neither live nor documented-stale, so it reads exactly
/// like a never-registered name. Pins the explicit `state == "stale"`
/// match against `!is_live(entry)`'s looser "anything not reachable".
#[test]
fn stale_route_does_not_treat_an_undocumented_third_state_as_stale() {
    let store = TrustStore::default();
    let mut reverse = vec![stale_reverse_entry(
        100,
        "phone",
        FP_A,
        "2026-01-01T00:00:00Z",
    )];
    reverse[0].local.state = "unknown".to_string();
    let err = resolve(&reverse, &store, &no_hosts(), "phone").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        !err.retryable,
        "an undocumented state must not be treated as retryable-stale"
    );
    assert!(err.details.get("reason").is_none());
}

#[test]
fn stale_route_reports_lost_ago_ms_from_the_supplied_now() {
    let store = TrustStore::default();
    let reverse = vec![stale_reverse_entry(
        100,
        "phone",
        FP_A,
        "2026-01-01T00:00:00Z",
    )];
    let now = parse_rfc3339("2026-01-01T00:00:07Z").expect("parses");
    let err = resolve_route(
        &reverse,
        &store,
        &no_hosts(),
        "phone",
        now,
        30_000,
        unconfigured_host_not_found,
    )
    .unwrap_err();
    assert_eq!(err.details["lost_ago_ms"], serde_json::json!(7_000));
}

#[test]
fn stale_route_defaults_lost_ago_ms_to_zero_when_lost_at_is_missing_or_malformed() {
    let store = TrustStore::default();
    for lost_at in ["not-a-timestamp", ""] {
        let reverse = vec![stale_reverse_entry(100, "phone", FP_A, lost_at)];
        let err = resolve(&reverse, &store, &no_hosts(), "phone").unwrap_err();
        assert_eq!(
            err.details["lost_ago_ms"],
            serde_json::json!(0),
            "lost_at {lost_at:?} must default rather than panic or fail closed"
        );
    }

    // `lost_at` entirely absent (`None`, e.g. `reverse_entry`'s own
    // default) behaves the same as malformed.
    let reverse = vec![reverse_entry(100, "phone", "stale", FP_A)];
    let err = resolve(&reverse, &store, &no_hosts(), "phone").unwrap_err();
    assert_eq!(err.details["lost_ago_ms"], serde_json::json!(0));
}

/// Two daemons on this machine each holding a stale entry under the same
/// name (the live branch's ambiguity, but for the stale branch instead)
/// must resolve deterministically rather than through
/// `Self::reverse_host_entries`'s unpinned discovery order — the smallest
/// `pid` wins, regardless of the order the two entries appear in
/// `reverse`.
#[test]
fn stale_route_picks_the_smallest_pid_deterministically_when_two_daemons_both_hold_it_stale() {
    let store = TrustStore::default();
    let reverse = vec![
        stale_reverse_entry(200, "phone", FP_A, "2026-01-01T00:00:10Z"),
        stale_reverse_entry(100, "phone", FP_B, "2026-01-01T00:00:00Z"),
    ];
    let now = parse_rfc3339("2026-01-01T00:00:20Z").expect("parses");
    let err = resolve_route(
        &reverse,
        &store,
        &no_hosts(),
        "phone",
        now,
        30_000,
        unconfigured_host_not_found,
    )
    .unwrap_err();
    assert_eq!(
        err.details["lost_ago_ms"],
        serde_json::json!(20_000),
        "must report the pid-100 entry's lost_at, not pid-200's: {:?}",
        err.details
    );

    // Order-independence: reversing the input slice must not change which
    // entry wins.
    let reversed = vec![
        stale_reverse_entry(100, "phone", FP_B, "2026-01-01T00:00:00Z"),
        stale_reverse_entry(200, "phone", FP_A, "2026-01-01T00:00:10Z"),
    ];
    let err2 = resolve_route(
        &reversed,
        &store,
        &no_hosts(),
        "phone",
        now,
        30_000,
        unconfigured_host_not_found,
    )
    .unwrap_err();
    assert_eq!(err2.details["lost_ago_ms"], serde_json::json!(20_000));
}

#[test]
fn stale_route_propagates_the_caller_supplied_retry_after_ms() {
    let store = TrustStore::default();
    let reverse = vec![stale_reverse_entry(
        100,
        "phone",
        FP_A,
        "2026-01-01T00:00:00Z",
    )];
    let err = resolve_route(
        &reverse,
        &store,
        &no_hosts(),
        "phone",
        TEST_NOW,
        12_345,
        unconfigured_host_not_found,
    )
    .unwrap_err();
    assert_eq!(err.details["retry_after_ms"], serde_json::json!(12_345));
}

#[test]
fn stale_route_trims_surrounding_whitespace_the_same_way_live_routing_does() {
    // `lookup_name` trims before the key lookup (see its own doc) and
    // `hint_alias` trims again for the display name — both must agree, or
    // a stray space finds the stale entry by key but then fails to
    // interpolate a clean alias into the message (or the reverse: finds
    // no entry at all because only one of the two trims ran).
    let store = TrustStore::default();
    let reverse = vec![stale_reverse_entry(
        100,
        "phone",
        FP_A,
        "2026-01-01T00:00:00Z",
    )];
    let err = resolve(&reverse, &store, &no_hosts(), " phone ").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        err.retryable,
        "the trimmed key must still find the stale entry"
    );
    assert_eq!(
        err.details["reason"],
        serde_json::json!(STALE_REGISTRATION_REASON)
    );
    assert!(
        err.message.contains("\"phone\""),
        "message must interpolate the trimmed alias, not the raw padded name: {:?}",
        err.message
    );
}

#[test]
fn stale_route_never_matches_a_user_at_prefixed_query_key() {
    // The lookup *key* is only ever whitespace-trimmed, never
    // `user@`-stripped (`lookup_name`'s own doc: stripping the hint for
    // the key, not just the display name, would let `qsh exec dave@mac`
    // silently resolve to `mac` and run as the wrong account). So a
    // `user@`-prefixed query against a name that is genuinely stale must
    // still miss the stale branch (key `"dave@phone"` != `"phone"`) and
    // fall through to the ordinary non-retryable `HOST_NOT_FOUND`, not a
    // retryable one — the stale branch does not get a wider match rule
    // than the live branch it mirrors.
    let store = TrustStore::default();
    let reverse = vec![stale_reverse_entry(
        100,
        "phone",
        FP_A,
        "2026-01-01T00:00:00Z",
    )];
    let err = resolve(&reverse, &store, &no_hosts(), "dave@phone").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        !err.retryable,
        "a user@-prefixed query must not match the stale entry by key"
    );
    assert!(err.details.get("reason").is_none());
    assert!(
        !err.message.contains('@'),
        "message leaked the user@ hint: {:?}",
        err.message
    );
}

// ---------------------------------------------------------------------
// issue #3 item b2 (PR-D): the single OR-ed `HOST_NOT_FOUND` fallback
// splits into three branches. Branch (ii) is PR-C's retryable stale
// branch above (`three_way_table_never_registered_vs_stale_vs_swept`'s
// row (b)); these tests cover (i)/(iii) and the mutation check across
// all three.
// ---------------------------------------------------------------------

/// Branch (i): a name unknown to trust.toml, hosts.toml, and the
/// registry alike. `routing_unregistered_and_unpinned_is_host_not_found`
/// (above) already pins the code; this test pins the wording and its
/// remedy shape (observation "not configured on this machine", next
/// command `qsh trust add`/`qsh reverse`).
#[test]
fn unconfigured_name_gets_the_not_configured_wording() {
    let store = TrustStore::default();
    let err = resolve(&[], &store, &no_hosts(), "nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(!err.retryable);
    assert_eq!(err, unconfigured_host_not_found("nowhere"));
    assert!(err.message.contains("is not configured on this machine"));
    assert!(err.message.contains("qsh trust add nowhere --address"));
    assert!(err.message.contains("qsh reverse <controller>"));
}

/// Branch (iii): a trust-store pin with no address
/// (`store.add_peer(name, None, ...)`, `docs/CLI.md` §6.1's client-only
/// pin) and no reverse registration at all. Must land on the distinct
/// "configured but no address" wording, not branch (i)'s.
#[test]
fn pinned_without_address_and_no_registration_gets_the_pinned_wording() {
    let mut store = TrustStore::default();
    store.add_peer(
        "phone",
        None,
        FP_A.parse().expect("fingerprint"),
        "2026-01-01T00:00:00Z".to_string(),
    );
    let err = resolve(&[], &store, &no_hosts(), "phone").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(!err.retryable);
    assert_eq!(err, pinned_without_address_host_not_found("phone"));
    assert!(
        err.message
            .contains("is configured on this machine but has no address")
    );
    assert!(err.message.contains("qsh trust add phone --address"));
    assert!(err.message.contains("qsh reverse <controller>"));
    assert_ne!(
        err.message,
        unconfigured_host_not_found("phone").message,
        "a pinned-without-address name must not get branch (i)'s wording"
    );
}

/// The same "configured but no address" branch, reached from
/// `hosts.toml` instead of `trust.toml`: an explicit `address = ""`
/// entry parses (`crate::hosts::HostEntry::address`'s doc) but is not
/// routable, and no trust pin exists at all for the name. This is the
/// one `hosts.toml` shape [`resolve_forward`] does not already turn into
/// a route, so it must not be reported as "not configured" either — the
/// operator did configure it, just with nothing usable. The wording says
/// "configured", not "pinned": `docs/CLI.md` §6.1 is explicit that
/// `hosts.toml` never participates in identity, so this source must not
/// be described with trust-store vocabulary.
#[test]
fn hosts_toml_entry_with_an_empty_address_and_no_trust_pin_gets_the_pinned_wording_too() {
    let store = TrustStore::default();
    let hosts = hosts_with(&[("phone", "", None)]);
    let err = resolve(&[], &store, &hosts, "phone").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(err, pinned_without_address_host_not_found("phone"));
}

/// issue #3 item b2 fix-up: a `user@`-prefixed query against a name that
/// IS pinned (with a routable address, even) must not land on either
/// enumerated branch — both would assert something false about the
/// pinned alias. Regression test for the routing key (`key`, still
/// carrying the `user@` hint) and the message subject (`display_name`,
/// hint-stripped) disagreeing on what "known" means.
#[test]
fn a_user_at_prefixed_query_against_a_fully_routable_pin_does_not_claim_it_is_unpinned() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let err = resolve(&[], &store, &no_hosts(), "dave@mac").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(!err.retryable);
    assert!(
        !err.message.contains("is not configured on this machine"),
        "mac has a forward pin; branch (i)'s wording is false here: {:?}",
        err.message
    );
    assert!(
        !err.message.contains("no trust-store pin"),
        "mac has a trust-store pin: {:?}",
        err.message
    );
    assert!(
        !err.message
            .contains("is configured on this machine but has no address"),
        "mac has an address; branch (iii)'s wording is false here: {:?}",
        err.message
    );
    assert!(
        !err.message.contains('@'),
        "message leaked the user@ hint: {:?}",
        err.message
    );
    assert!(err.message.contains("qsh trust add mac --address"));
}

/// The same fix-up, for an addressless pin — the finding's own repro
/// shape (`qsh trust add phone --fingerprint ...` with no `--address`,
/// then `qsh host get 'dave@phone'`). The message must not claim "no
/// trust-store pin" for a name that has one.
#[test]
fn a_user_at_prefixed_query_against_an_addressless_pin_does_not_claim_no_pin() {
    let mut store = TrustStore::default();
    store.add_peer(
        "phone",
        None,
        FP_A.parse().expect("fingerprint"),
        "2026-01-01T00:00:00Z".to_string(),
    );
    let err = resolve(&[], &store, &no_hosts(), "dave@phone").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(!err.retryable);
    assert!(
        !err.message.contains("no trust-store pin"),
        "phone has a trust-store pin: {:?}",
        err.message
    );
    assert!(!err.message.contains('@'));
}

/// Mutation check (`docs/design/testing.md`'s discipline): collapsing
/// any two of the three `HOST_NOT_FOUND` branches into one wording would
/// red exactly one of the three `*_message` assertions below, at the
/// wording-constant level.
///
/// Mapping — the test that goes red if a branch is collapsed into
/// another:
/// - (i)=(ii): `unconfigured_vs_stale_message` below guards the two
///   wording constants directly; it cannot see a *routing-level*
///   collapse (e.g. the stale arm in `resolve_route` returning
///   `unconfigured_host_not_found` instead of `stale_host_not_found`),
///   since it calls both constructors rather than going through
///   `resolve`. `three_way_table_never_registered_vs_stale_vs_swept`'s
///   `code`/`retryable`/`details.reason` assertions and the byte-pinned
///   `error.HOST_NOT_FOUND.reverse_stale.json` golden are what guard that
///   arm at the routing level.
/// - (i)=(iii): `unconfigured_vs_pinned_message` below (and
///   `pinned_without_address_and_no_registration_gets_the_pinned_wording`'s
///   `assert_ne!` above) — this pair is reachable through `resolve(...)`
///   directly, so both the constructor-level and routing-level checks
///   exist for it.
/// - (ii)=(iii): `stale_vs_pinned_message` below guards the wording
///   constants only, for the same reason as (i)=(ii);
///   `stale_route_never_matches_a_user_at_prefixed_query_key` and the
///   `error.HOST_NOT_FOUND.reverse_stale.json`/`pinned_no_address.json`
///   goldens are the routing-level guard for that arm.
#[test]
fn unconfigured_vs_stale_message() {
    let unconfigured = unconfigured_host_not_found("phone").message;
    let stale = stale_host_not_found("phone", None, TEST_NOW, TEST_RETRY_AFTER_MS).message;
    assert_ne!(unconfigured, stale);
}

#[test]
fn unconfigured_vs_pinned_message() {
    let unconfigured = unconfigured_host_not_found("phone").message;
    let pinned = pinned_without_address_host_not_found("phone").message;
    assert_ne!(unconfigured, pinned);
}

#[test]
fn stale_vs_pinned_message() {
    let stale = stale_host_not_found("phone", None, TEST_NOW, TEST_RETRY_AFTER_MS).message;
    let pinned = pinned_without_address_host_not_found("phone").message;
    assert_ne!(stale, pinned);
}

/// No branch's remedy leaks an unescaped `@` or interpolates anything
/// but the already-validated (`hint_alias`) bare alias — the same
/// discipline `host_not_found_message_never_leaks_a_user_at_prefix`
/// pins for branch (i)/(iii)'s shared pre-split ancestor, restated here
/// against all three constructors directly so a future fourth branch is
/// caught by the same loop.
#[test]
fn no_host_not_found_branch_leaks_an_at_sign() {
    let messages = [
        unconfigured_host_not_found("we-re-a-name").message,
        pinned_without_address_host_not_found("we-re-a-name").message,
        stale_host_not_found("we-re-a-name", None, TEST_NOW, TEST_RETRY_AFTER_MS).message,
    ];
    for message in messages {
        assert!(!message.contains('@'), "leaked an @: {message:?}");
    }
}

/// Builds a [`ReverseHostEntry`] straight from a live registry's
/// [`crate::reverse::registry::ReverseEntry`], mapping `state`/`lost_at`
/// the exact same way `crate::localctl::daemon::to_local_host` does (that
/// function is private to its module, so this test-only mirror is the one
/// way this file — the routing table's own test suite — can drive
/// `resolve_route` off a *real*, clock-driven [`Registry`] rather than a
/// hand-typed [`LocalHost`], without reaching into `daemon.rs`'s privates).
fn from_registry_entry(
    pid: u32,
    entry: crate::reverse::registry::ReverseEntry,
) -> ReverseHostEntry {
    use crate::reverse::registry::EntryState;
    ReverseHostEntry {
        pid,
        socket: PathBuf::from(format!("/run/qsh/{pid}.sock")),
        local: LocalHost {
            name: entry.name,
            address: entry.address.to_string(),
            state: match entry.state {
                EntryState::Live => "reachable".to_string(),
                EntryState::Stale => "stale".to_string(),
            },
            fingerprint: entry.fingerprint,
            capabilities: entry.capabilities,
            generation: entry.generation,
            registered_at: entry.registered_at,
            lost_at: entry.lost_at,
        },
    }
}

#[test]
fn crossing_stale_retention_sweeps_the_entry_and_the_route_answer_flips_back_to_non_retryable() {
    // End-to-end across the real layer this module's other tests stub
    // out: a `TestClock`-driven `Registry` (`docs/design/testing.md` L2)
    // registers, loses the connection (`mark_stale`), and is queried
    // through `resolve_route` while still inside `stale_retention` (must
    // be the new retryable branch) and again after `sweep_expired` has
    // actually dropped it past that retention (must fall back to the
    // ordinary non-retryable `HOST_NOT_FOUND` — `three_way_table_…`'s (c)
    // row, proven here against the real sweep instead of a synthetic
    // empty slice).
    use crate::broker::TestClock;
    use crate::reverse::registry::{AdmittedEntry, Registry};
    use std::sync::Arc;
    use std::time::Duration;

    let clock = TestClock::new();
    let registry = Registry::new(Arc::new(clock.clone()), false);
    let store = TrustStore::default();
    let retention = Duration::from_secs(120);

    let admitted = registry
        .admit(
            "phone".to_string(),
            AdmittedEntry {
                fingerprint: FP_A,
                principal: "device:phone",
                address: "203.0.113.9:9".parse().unwrap(),
                capabilities: vec!["pty".to_string()],
            },
        )
        .expect("first registration admits");

    registry
        .mark_stale("phone", admitted.entry.generation)
        .expect("live entry transitions to stale");

    // Still inside `stale_retention`: the daemon's own list still holds
    // it (nothing has swept it yet), so this is the retryable branch.
    let still_listed = registry.get("phone").expect("not yet swept");
    let reverse = vec![from_registry_entry(100, still_listed)];
    let within = resolve(&reverse, &store, &no_hosts(), "phone").unwrap_err();
    assert!(
        within.retryable,
        "a stale entry still inside stale_retention must be retryable"
    );
    assert_eq!(
        within.details["reason"],
        serde_json::json!(STALE_REGISTRATION_REASON)
    );

    // Cross the retention boundary and sweep — the entry is now actually
    // gone from the table, exactly as it would be from the daemon's next
    // `LocalHostList` answer.
    clock.advance(retention + Duration::from_secs(1));
    let removed = registry.sweep_expired(retention);
    assert_eq!(removed.len(), 1, "the stale entry must be swept");
    assert!(registry.get("phone").is_none());

    let after_sweep = resolve(&[], &store, &no_hosts(), "phone").unwrap_err();
    assert!(
        !after_sweep.retryable,
        "once swept, the name must answer exactly like it was never registered"
    );
    assert!(after_sweep.details.get("reason").is_none());
}

#[test]
fn stale_route_loses_to_a_forward_pin_when_one_exists() {
    // A stale reverse entry is not live, so it never outranks a forward
    // pin — same priority the non-retryable "falls back to forward"
    // test above already pins, restated here with the retryable branch
    // in the mix to prove the new check does not jump the queue.
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let reverse = vec![stale_reverse_entry(
        100,
        "mac",
        FP_B,
        "2026-01-01T00:00:00Z",
    )];
    let route = resolve(&reverse, &store, &no_hosts(), "mac").unwrap();
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

// ---- `host_pinned_without_address` (ROADMAP M9 (h)) ----

/// A trust-store pin with **no** address — [`forward_store`]'s twin, minus
/// the `--address` a real `qsh trust add --fingerprint`-only pin also
/// omits (`crate::doctor::HOST_PINNED_WITHOUT_ADDRESS`'s own remedy: this
/// is a normal pure-reverse-target pinning shape, not a malformed one).
fn pinless_store(name: &str, fingerprint: &str) -> TrustStore {
    let mut store = TrustStore::default();
    store.add_peer(
        name,
        None,
        fingerprint.parse().expect("fingerprint"),
        "2026-01-01T00:00:00Z".to_string(),
    );
    store
}

#[test]
fn host_pinned_without_address_fires_for_an_addressless_pin_with_no_reverse_entry_at_all() {
    let store = pinless_store("mac", FP_A);
    let names = host_pinned_without_address(&[], &store, &no_hosts());
    assert_eq!(names, vec!["mac".to_string()]);
}

/// "live **or stale**" — a live registration suppresses the finding
/// (`crate::doctor::HOST_PINNED_WITHOUT_ADDRESS`'s own doc).
#[test]
fn host_pinned_without_address_is_suppressed_by_a_live_reverse_entry() {
    let store = pinless_store("mac", FP_A);
    let reverse = [reverse_entry(1, "mac", "reachable", FP_A)];
    assert!(host_pinned_without_address(&reverse, &store, &no_hosts()).is_empty());
}

/// The other half of that rule — a merely *stale* registration (not evicted
/// yet) still proves this device has heard from the name before, so it
/// suppresses the finding exactly like a live one: this is the one place
/// [`host_pinned_without_address`] deliberately does **not** reuse
/// [`is_live`]'s live-only filter.
#[test]
fn host_pinned_without_address_is_suppressed_by_a_stale_reverse_entry_too() {
    let store = pinless_store("mac", FP_A);
    let reverse = [reverse_entry(1, "mac", "stale", FP_A)];
    assert!(host_pinned_without_address(&reverse, &store, &no_hosts()).is_empty());
}

#[test]
fn host_pinned_without_address_is_silent_when_the_trust_pin_has_an_address() {
    let store = forward_store("mac", "mac.example:4433", FP_A);
    assert!(host_pinned_without_address(&[], &store, &no_hosts()).is_empty());
}

#[test]
fn host_pinned_without_address_is_silent_when_hosts_toml_supplies_the_address() {
    let store = pinless_store("mac", FP_A);
    let hosts = hosts_with(&[("mac", "mac.example:4433", None)]);
    assert!(host_pinned_without_address(&[], &store, &hosts).is_empty());
}

/// A reverse entry for an unrelated name must not suppress this one —
/// the suppression is keyed by name, not by "some reverse entry exists
/// somewhere".
#[test]
fn host_pinned_without_address_ignores_a_reverse_entry_for_a_different_name() {
    let store = pinless_store("mac", FP_A);
    let reverse = [reverse_entry(1, "phone", "reachable", FP_B)];
    assert_eq!(
        host_pinned_without_address(&reverse, &store, &no_hosts()),
        vec!["mac".to_string()]
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

    /// Issue #4 items 4/3a: `retry_after_ms` on the stale branch is this
    /// controller's own effective `[reverse].backoff_max_ms`
    /// ([`Ops::stale_retry_after_ms`]), not the compiled-in default — a
    /// mutation that deletes the `config()`/`backoff()` read entirely and
    /// hardcodes the default would still pass every other test in this
    /// file (they all resolve against an absent `config.toml`, where the
    /// default and the read happen to agree). This pins the read itself
    /// by making the configured value disagree with the default.
    #[tokio::test]
    async fn resolve_host_route_async_uses_the_configured_reverse_backoff_max_as_the_retry_hint() {
        let dir = tempfile::tempdir().unwrap();
        let ops = ops_at(dir.path(), &TrustStore::default());
        std::fs::write(
            ops.paths().config_file(),
            "[reverse]\nbackoff_max_ms = 7000\n",
        )
        .unwrap();
        let mut stale = sample_local("phone", "stale", FP_A);
        stale.lost_at = Some("2026-01-01T00:00:00Z".to_string());
        let daemon = spawn_fake_admin_daemon(&ops.paths().runtime_dir(), 100, vec![stale]);

        let err = ops.resolve_host_route_async("phone").await.unwrap_err();
        assert_eq!(err.details["retry_after_ms"], serde_json::json!(7_000));
        daemon.await.unwrap();
    }

    /// The fail-open half of the same rule: a `[reverse]` section that
    /// fails `ReverseConfig::backoff`'s own validation (here,
    /// `backoff_max_ms` below the defaulted `backoff_initial_ms`) must not
    /// fail the route lookup — `Ops::stale_retry_after_ms` falls back to
    /// `ReverseConfig::DEFAULT_BACKOFF_MAX_MS` rather than propagating the
    /// error (`Ops::stale_retry_after_ms`'s own doc: a bad *local* config
    /// must not turn a display-only hint into a routing outage). Note
    /// this is still valid TOML, so `Config::load` itself succeeds; only
    /// the semantic `backoff()` validation fails.
    #[tokio::test]
    async fn resolve_host_route_async_falls_back_to_the_default_retry_hint_when_reverse_config_fails_validation()
     {
        let dir = tempfile::tempdir().unwrap();
        let ops = ops_at(dir.path(), &TrustStore::default());
        std::fs::write(ops.paths().config_file(), "[reverse]\nbackoff_max_ms = 0\n").unwrap();
        let mut stale = sample_local("phone", "stale", FP_A);
        stale.lost_at = Some("2026-01-01T00:00:00Z".to_string());
        let daemon = spawn_fake_admin_daemon(&ops.paths().runtime_dir(), 100, vec![stale]);

        let err = ops.resolve_host_route_async("phone").await.unwrap_err();
        assert_eq!(
            err.details["retry_after_ms"],
            serde_json::json!(crate::config::ReverseConfig::DEFAULT_BACKOFF_MAX_MS)
        );
        daemon.await.unwrap();
    }
} // mod reverse_route_async_tests
