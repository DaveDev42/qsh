use super::*;

fn resolve(store: &TrustStore, hosts: &HostsFile, name: &str) -> Result<HostRoute, OpError> {
    resolve_route(store, hosts, name, unconfigured_host_not_found)
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

// ---- merge table (M3 plan Step 5 (c) (2473c88)) ----

#[test]
fn merge_forward_only() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let hosts = forward_hosts(&store, &no_hosts());
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].connection_mode, "forward");
    assert_eq!(hosts[0].state, "unknown");
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

    assert!(resolve(&store, &no_hosts(), "routable").is_ok());
    let err = resolve(&store, &no_hosts(), "addressless").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
}

// ---- hosts.toml priority/merge (M7 plan Step 3 (69dd788), §4.1 #4) ----
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

    let route = resolve(&store, &hosts, "headless").unwrap();
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
    // The one decision M7 plan §4.1 #4 (69dd788) names explicitly:
    // hosts.toml's address wins; trust.toml's fingerprint is still the
    // one reported (hosts.toml never supplies identity). The two
    // addresses disagree here, so under the redefined `source`
    // (M9 plan Step 3 (a)-추기 ② (b9a621b): which side's *address* won, not
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

    let route = resolve(&store, &hosts, "mac").unwrap();
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

    let route = resolve(&store, &hosts, "mac").unwrap();
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

    let route = resolve(&store, &hosts, "mac").unwrap();
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

/// M9 plan §6 (b9a621b) 행 i: surrounding whitespace in a lookup key is
/// trimmed and still finds the pin; a `user@` hint is a different kind
/// of prefix and must keep failing closed.
#[test]
fn a_lookup_key_with_surrounding_whitespace_finds_the_pin_but_a_user_at_prefix_still_does_not() {
    let store = forward_store("mac", "mac.example.com:4433", FP_A);
    let hosts = no_hosts();

    let route = resolve(&store, &hosts, " mac ").unwrap();
    assert_eq!(
        route,
        HostRoute::Forward {
            address: "mac.example.com:4433".to_string(),
            fingerprint: FP_A.to_string(),
            source: None,
            user: None,
        }
    );

    let err = resolve(&store, &hosts, "dave@mac").unwrap_err();
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

    let route = resolve(&store, &hosts, "mac").unwrap();
    match route {
        HostRoute::Forward { user, .. } => assert_eq!(user.as_deref(), Some("dave")),
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
    let route = resolve(&store, &hosts, "ghost").unwrap();
    match route {
        HostRoute::Forward { fingerprint, .. } => assert_eq!(fingerprint, ""),
    }
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
        let err = resolve(&store, &no_hosts(), name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "name {name:?}");
    }
}

#[test]
fn routing_unregistered_and_unpinned_is_host_not_found() {
    let store = TrustStore::default();
    let err = resolve(&store, &no_hosts(), "nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
}

#[test]
fn host_not_found_message_never_leaks_a_user_at_prefix() {
    // `qsh host get <name>` (`docs/CLI.md` §6.1) takes a raw
    // positional — unlike the bare `qsh [user@]host` form, it does not
    // run `parse_target`'s `user@` split first, so a `user@host` typo
    // can reach `resolve_route` unstripped (M8 plan Step 6 (52639fc), M7
    // carry-over v). The message must not echo the `@` back, and the
    // suggested `qsh trust add <name> --address ...` remedy must name
    // something `qsh trust add` itself would actually accept —
    // `qsh_proto::wire::valid_host_name`'s `[A-Za-z0-9._-]`, `1..=64`
    // rule, which rejects `@` outright.
    let store = TrustStore::default();
    let err = resolve(&store, &no_hosts(), "dave@nowhere").unwrap_err();
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
    // new one (M8 plan Step 6 (52639fc), lens-2 finding).
    let store = TrustStore::default();
    for name in ["dave@", "@", "dave@ "] {
        let err = resolve(&store, &no_hosts(), name).unwrap_err();
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
    // M8 plan Step 7 (52639fc), Q10: `"dave@ nowhere"` splits on the last
    // `@` to `" nowhere"` — the leading space must be trimmed before
    // the `HOST_NOT_FOUND` remedy names the alias, so the suggested
    // `qsh trust add` command is runnable and the message matches the
    // `@`-free case exactly.
    let store = TrustStore::default();
    let err = resolve(&store, &no_hosts(), "dave@ nowhere").unwrap_err();
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
    let err = resolve(&store, &no_hosts(), " nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        err.message.contains("qsh trust add nowhere --address"),
        "remedy did not name the trimmed bare alias: {:?}",
        err.message
    );
}

#[test]
fn routing_an_internal_space_left_after_stripping_is_invalid_argument_not_host_not_found() {
    // M8 plan Step 7 (52639fc), Q10: `"dave@no where"` strips to `"no
    // where"` — non-empty, but not a legal `valid_host_name` alias (an
    // internal space). Falling through to `HOST_NOT_FOUND` would
    // suggest an un-runnable `qsh trust add "no where" --address ...`;
    // this must be a distinct `INVALID_ARGUMENT`, not the empty-name
    // wording either.
    let store = TrustStore::default();
    let err = resolve(&store, &no_hosts(), "dave@no where").unwrap_err();
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
}

// ---------------------------------------------------------------------
// issue #3 item b2 (PR-D): the single OR-ed `HOST_NOT_FOUND` fallback
// splits into three branches. Branch (ii) is PR-C's retryable stale
// branch, retired with the registry (ADR-0068); these tests cover (i)/(iii)
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
    let err = resolve(&store, &no_hosts(), "nowhere").unwrap_err();
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
    let err = resolve(&store, &no_hosts(), "phone").unwrap_err();
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
    let err = resolve(&store, &hosts, "phone").unwrap_err();
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
    let err = resolve(&store, &no_hosts(), "dave@mac").unwrap_err();
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
    let err = resolve(&store, &no_hosts(), "dave@phone").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(!err.retryable);
    assert!(
        !err.message.contains("no trust-store pin"),
        "phone has a trust-store pin: {:?}",
        err.message
    );
    assert!(!err.message.contains('@'));
}

#[test]
fn unconfigured_vs_pinned_message() {
    let unconfigured = unconfigured_host_not_found("phone").message;
    let pinned = pinned_without_address_host_not_found("phone").message;
    assert_ne!(unconfigured, pinned);
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
    ];
    for message in messages {
        assert!(!message.contains('@'), "leaked an @: {message:?}");
    }
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
fn host_pinned_without_address_fires_for_an_addressless_pin() {
    let store = pinless_store("mac", FP_A);
    let names = host_pinned_without_address(&store, &no_hosts());
    assert_eq!(names, vec!["mac".to_string()]);
}

#[test]
fn host_pinned_without_address_is_silent_when_the_trust_pin_has_an_address() {
    let store = forward_store("mac", "mac.example:4433", FP_A);
    assert!(host_pinned_without_address(&store, &no_hosts()).is_empty());
}

#[test]
fn host_pinned_without_address_is_silent_when_hosts_toml_supplies_the_address() {
    let store = pinless_store("mac", FP_A);
    let hosts = hosts_with(&[("mac", "mac.example:4433", None)]);
    assert!(host_pinned_without_address(&store, &hosts).is_empty());
}

// ---- the automatic bootstrap's "wholly unconfigured" probe (ADR-0044 decision 2) ----

fn probe_fires(store: &TrustStore, hosts: &HostsFile, name: &str) -> bool {
    matches!(
        resolve_route(store, hosts, name, unconfigured_probe),
        Err(err) if err.message == UNCONFIGURED_PROBE
    )
}

/// Only the first `HOST_NOT_FOUND` branch of `docs/CLI.md` §6.1 starts the
/// bootstrap: a pin with or without
/// an address, and a `hosts.toml` entry each count as "qsh already knows this
/// name".
#[test]
fn the_unconfigured_probe_fires_only_when_nothing_mentions_the_name() {
    let empty_store = TrustStore::default();
    let empty_hosts = HostsFile::default();
    assert!(probe_fires(&empty_store, &empty_hosts, "box"));
    assert!(!probe_fires(&empty_store, &empty_hosts, "  "));

    let pinned = forward_store("box", "203.0.113.5:4433", FP_A);
    assert!(!probe_fires(&pinned, &empty_hosts, "box"));
    // A `user@` hint on a configured alias is its own branch.
    assert!(!probe_fires(&pinned, &empty_hosts, "dave@box"));
    let book = hosts_with(&[("book", "203.0.113.6:4433", None), ("blank", "", None)]);
    assert!(!probe_fires(&empty_store, &book, "book"));
    assert!(!probe_fires(&empty_store, &book, "blank"));
    let mut inbound = TrustStore::default();
    inbound.add_peer(
        "box",
        None,
        FP_A.parse().unwrap(),
        "2026-01-01T00:00:00Z".into(),
    );
    assert!(!probe_fires(&inbound, &empty_hosts, "box"));
}
