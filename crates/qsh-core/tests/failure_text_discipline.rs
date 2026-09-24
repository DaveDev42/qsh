//! The "observation, impact, next command" discipline for the repo's
//! failure wordings (`docs/ROADMAP.md:123`'s eight-topic list; ADR-0017
//! 결정 4's exemption axes; ADR-0014 결정 5/9's port/bind wordings).
//!
//! Scope: **T1-T7, seven topics**, plus a separate `HOST_NOT_FOUND(i)`/
//! `HOST_NOT_FOUND(iii)` table (issue #3 item b2, PR-D) below the T1-T7
//! section — kept out of `three_part_rows` so that table's own exact
//! row-count assertion stays a statement about T1-T7 specifically. T7 is
//! the `qsh trust invite`
//! candidate-address enumeration: its zero-candidate wording
//! (`qsh_core::trust::invite_address::INVITE_ADDRESS_NONE`) is the
//! three-part one, while the populated-case heading
//! (`INVITE_ADDRESS_HEADING`) is a heading rather than a failure and
//! carries no remedy — it is covered by the §6.11 verbatim test alone.
//!
//! Two frames, both copied from `acl_docs.rs`/`schema_commands_registry.rs`
//! rather than invented fresh:
//!
//! - [`heading_section_slice`] — `acl_docs.rs`'s own helper (integration
//!   test binaries cannot share code across files without a `#[path]`
//!   module, so this is a byte-for-byte copy, not a reimplementation). A
//!   whole-file `.contains` would still pass if a constant only showed up
//!   somewhere unrelated while the section that is actually supposed to
//!   quote it drifted (F5, recorded in `acl_docs.rs`'s own module doc) —
//!   every verbatim check below is section-scoped for exactly that reason.
//! - The exclusion-list shape from `schema_commands_registry.rs`'s
//!   `EXCLUDED`/bidirectional gate: an exclusion is a documented decision
//!   with a reason, not a silent gap, and the two directions (is every
//!   documented axis real? is every real axis documented?) are both
//!   checked.
//!
//! Every assertion below is against a real constant or a real function
//! call imported from `qsh_core` — never a copy of the wording inlined in
//! this file. Where a wording's observation/impact/next-command slot is
//! not itself a named `pub` constant (T2's `{bind}: {err}` prefix, T3's
//! assembled `qsh acl check ...` command line), the test calls the real
//! production function (`bind_unavailable`, `pairing_pin_notice`) instead
//! of inlining a copy of that format string.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;

use qsh_core::acl::PERMISSION_DENIED_MESSAGE;
use qsh_core::ops::host::{pinned_without_address_host_not_found, unconfigured_host_not_found};
use qsh_core::ops::tunnel::DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE;
use qsh_core::pairing::{
    PAIRING_ACL_ROW_ABSENT, PAIRING_ACL_ROW_PRESENT, PAIRING_INVITE_REPLAY_NOTICE,
    PAIRING_PINNED_SELF_ASSERTED, PairingError, pairing_pin_notice,
};
use qsh_core::serve::{BIND_UNAVAILABLE_REMEDY, bind_unavailable};
use qsh_core::trust::ADDRESS_PORT_ASSUMED_NOTICE;
use qsh_core::trust::invite_address::{INVITE_ADDRESS_HEADING, INVITE_ADDRESS_NONE};
use qsh_core::tunnel::REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE;

#[path = "support/docs.rs"]
mod docs;
use docs::read_doc;

/// Slice `doc` from `heading` (matched verbatim) up to, but not including,
/// the next line starting with `#` at any level. Copied from
/// `acl_docs.rs`'s `heading_section_slice` — same behavior, same doc, same
/// F5 rationale; see that file for the full writeup.
fn heading_section_slice<'a>(doc: &'a str, heading: &str) -> &'a str {
    let start = doc
        .find(heading)
        .unwrap_or_else(|| panic!("doc must have a {heading:?} heading"));
    let rest = &doc[start..];
    let end = rest[heading.len()..]
        .find("\n#")
        .map(|i| i + heading.len())
        .unwrap_or(rest.len());
    &rest[..end]
}

// ---------------------------------------------------------------------
// 6.1 Verbatim doc-quoting tests, rows 1-6 (rows 7-10 live in
// tunnel_docs.rs); T7's own verbatim test is F23, below the three-part
// table.
// ---------------------------------------------------------------------

#[test]
fn cli_md_section_6_11_quotes_the_address_port_assumed_notice_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 6.11 Identity와 trust");
    assert!(
        section.contains(ADDRESS_PORT_ASSUMED_NOTICE),
        "docs/CLI.md §6.11 itself (not merely somewhere in the file) must quote \
         ADDRESS_PORT_ASSUMED_NOTICE verbatim"
    );
}

#[test]
fn cli_md_section_6_13_quotes_the_bind_unavailable_remedy_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(
        &cli_md,
        "### 6.13 장기 실행 모드: `qsh listen` / `qsh serve --to`",
    );
    assert!(
        section.contains(BIND_UNAVAILABLE_REMEDY),
        "docs/CLI.md §6.13 itself must quote BIND_UNAVAILABLE_REMEDY verbatim (ADR-0014 결정 9)"
    );
}

#[test]
fn readme_known_limitations_quotes_the_bind_unavailable_remedy_verbatim() {
    let readme = read_doc("README.md");
    let section = heading_section_slice(&readme, "## Known limitations");
    assert!(
        section.contains(BIND_UNAVAILABLE_REMEDY),
        "README.md's Known limitations section itself must quote BIND_UNAVAILABLE_REMEDY \
         verbatim (ADR-0014 결정 9)"
    );
}

#[test]
fn cli_md_section_6_11_quotes_the_pairing_pin_notice_constants_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 6.11 Identity와 trust");
    for fragment in [
        PAIRING_PINNED_SELF_ASSERTED,
        PAIRING_ACL_ROW_ABSENT,
        PAIRING_ACL_ROW_PRESENT,
    ] {
        assert!(
            section.contains(fragment),
            "docs/CLI.md §6.11 must quote {fragment:?} verbatim"
        );
    }
}

#[test]
fn cli_md_section_6_13_quotes_the_pairing_pin_notice_constants_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(
        &cli_md,
        "### 6.13 장기 실행 모드: `qsh listen` / `qsh serve --to`",
    );
    for fragment in [
        PAIRING_PINNED_SELF_ASSERTED,
        PAIRING_ACL_ROW_ABSENT,
        PAIRING_ACL_ROW_PRESENT,
    ] {
        assert!(
            section.contains(fragment),
            "docs/CLI.md §6.13 must quote {fragment:?} verbatim (ADR-0017 결과 role-example row)"
        );
    }
}

#[test]
fn cli_md_section_6_11_quotes_the_pairing_invite_replay_notice_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 6.11 Identity와 trust");
    assert!(
        section.contains(PAIRING_INVITE_REPLAY_NOTICE),
        "docs/CLI.md §6.11 itself must quote PAIRING_INVITE_REPLAY_NOTICE verbatim"
    );
}

/// T7's own verbatim check: `docs/CLI.md` §6.11 itself must quote both
/// `INVITE_ADDRESS_*` constants, not merely somewhere in the file
/// (§6.1's F5 rationale — the same reason every other row here is
/// section-scoped).
#[test]
fn cli_md_section_6_11_quotes_the_invite_address_wordings_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 6.11 Identity와 trust");
    for wording in [INVITE_ADDRESS_HEADING, INVITE_ADDRESS_NONE] {
        assert!(
            section.contains(wording),
            "docs/CLI.md §6.11 itself must quote {wording:?} verbatim"
        );
    }
}

// ---------------------------------------------------------------------
// 6.2 Three-part structure test: (label, observation, impact,
// next-command) for T1-T6. Not a wording-plagiarism check — a structural
// one (PLAN (c)): each slot must be non-empty and must actually occur
// inside the real wording that produces it.
// ---------------------------------------------------------------------

/// One (haystack, slice) pair: `slice` must be a non-empty substring of
/// `haystack`, and `haystack` must itself be real `qsh_core` output (a
/// constant's bytes, or a real function's return value) — never a literal
/// copied into this test file.
struct ThreePartSlot {
    haystack: String,
    slice: &'static str,
}

impl ThreePartSlot {
    fn new(haystack: impl Into<String>, slice: &'static str) -> Self {
        Self {
            haystack: haystack.into(),
            slice,
        }
    }

    fn assert_holds(&self, label: &str, part: &str) {
        assert!(
            !self.slice.is_empty(),
            "{label}'s {part} slice must not be empty"
        );
        assert!(
            self.haystack.contains(self.slice),
            "{label}'s {part} slice {:?} must occur inside its real wording {:?}",
            self.slice,
            self.haystack
        );
    }
}

struct ThreePartRow {
    label: &'static str,
    observation: ThreePartSlot,
    impact: ThreePartSlot,
    next_command: ThreePartSlot,
}

/// Builds the six-row table. T2's observation and T3's next-command are
/// not bare constants — they are assembled at the call site — so this
/// calls the real production functions (`bind_unavailable`,
/// `pairing_pin_notice`) with fixed, deterministic inputs rather than
/// inlining a copy of their format strings.
fn three_part_rows() -> Vec<ThreePartRow> {
    let bind: SocketAddr = "127.0.0.1:4433".parse().expect("valid socket addr literal");
    let err = io::Error::new(
        io::ErrorKind::AddrInUse,
        "Address already in use (os error 48)",
    );
    let bind_message = bind_unavailable(&bind, &err).message;

    let pairing_notice_row_absent = pairing_pin_notice("probe-device", false);
    let pairing_notice_row_present = pairing_pin_notice("probe-device", true);

    vec![
        ThreePartRow {
            label: "T1",
            observation: ThreePartSlot::new(
                ADDRESS_PORT_ASSUMED_NOTICE,
                "assuming port 4433: the peer address names no port",
            ),
            impact: ThreePartSlot::new(
                ADDRESS_PORT_ASSUMED_NOTICE,
                "so this command uses port 4433 everywhere that address goes",
            ),
            next_command: ThreePartSlot::new(
                ADDRESS_PORT_ASSUMED_NOTICE,
                "Re-run with an explicit `host:port` to use a different port.",
            ),
        },
        ThreePartRow {
            label: "T2",
            // `cannot listen on {bind}: {err}` is assembled inside
            // `bind_unavailable`, not a named constant — call the real
            // function instead of inlining a copy of its format string.
            observation: ThreePartSlot::new(bind_message, "cannot listen on"),
            impact: ThreePartSlot::new(BIND_UNAVAILABLE_REMEDY, "Nothing is being served."),
            next_command: ThreePartSlot::new(
                BIND_UNAVAILABLE_REMEDY,
                "Re-run with `--bind <ip:port>` on a free port.",
            ),
        },
        ThreePartRow {
            label: "T3",
            observation: ThreePartSlot::new(
                PAIRING_PINNED_SELF_ASSERTED,
                "pinned a new peer under the name it asked for itself:",
            ),
            impact: ThreePartSlot::new(
                PAIRING_ACL_ROW_ABSENT,
                "it can authenticate but every action is still denied",
            ),
            // `qsh acl check --principal device:<name> --action
            // session.open` is assembled by `pairing_pin_notice`, not a
            // bare constant — call the real function with a fixed probe
            // name so the command line is deterministic.
            next_command: ThreePartSlot::new(
                pairing_notice_row_absent,
                "qsh acl check --principal 'device:probe-device' --action session.open",
            ),
        },
        ThreePartRow {
            label: "T3-present",
            observation: ThreePartSlot::new(
                PAIRING_PINNED_SELF_ASSERTED,
                "pinned a new peer under the name it asked for itself:",
            ),
            impact: ThreePartSlot::new(
                PAIRING_ACL_ROW_PRESENT,
                "it inherits that row's grants exactly as written",
            ),
            // Same assembled-command shape as the T3 (absent) row above,
            // but with `acl_row_present: true`. T3's impact slot covers
            // both branches' impact clauses, and this row
            // is what stops `PAIRING_ACL_ROW_PRESENT`'s impact clause
            // from being droppable while the gate stays green (a
            // mutation that replaced it with a bare "A row exists:" was
            // caught only by an integration test's substring check
            // before this row existed).
            next_command: ThreePartSlot::new(
                pairing_notice_row_present,
                "qsh acl check --principal 'device:probe-device' --action session.open",
            ),
        },
        ThreePartRow {
            label: "T4",
            observation: ThreePartSlot::new(
                PAIRING_INVITE_REPLAY_NOTICE,
                "an invite code was presented again after it had already been redeemed.",
            ),
            impact: ThreePartSlot::new(
                PAIRING_INVITE_REPLAY_NOTICE,
                "Nothing was pinned and the peer got SESSION_CONFLICT",
            ),
            next_command: ThreePartSlot::new(
                PAIRING_INVITE_REPLAY_NOTICE,
                "Mint a fresh one with `qsh trust invite`",
            ),
        },
        ThreePartRow {
            label: "T5",
            observation: ThreePartSlot::new(
                REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE,
                "this bind could not be confirmed as a loopback address",
            ),
            impact: ThreePartSlot::new(
                REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE,
                "nothing was opened on the host",
            ),
            next_command: ThreePartSlot::new(
                REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE,
                "Re-run `-R` with a loopback bind",
            ),
        },
        ThreePartRow {
            label: "T7",
            observation: ThreePartSlot::new(
                INVITE_ADDRESS_NONE,
                "the kernel named no source address, or only ones this line can't offer \
                 (loopback, unspecified, or an unprintable link-local)",
            ),
            impact: ThreePartSlot::new(
                INVITE_ADDRESS_NONE,
                "Invite still valid; fill `<address>` by hand.",
            ),
            next_command: ThreePartSlot::new(
                INVITE_ADDRESS_NONE,
                "Check routing with `ip route`/`route -n`",
            ),
        },
        ThreePartRow {
            label: "T6",
            // T6 is `-D`'s reverse-route capability refusal (ADR-0019
            // decision 3, ADR-0020 decision 2): ADR-0020 lifted the
            // forward-only restriction this row used to pin, so the
            // reverse-route-specific wording is now the *capability* gate
            // instead — the same one every route hits, just naming the two
            // reverse-specific causes a missing `dial-filter.v1` there can
            // have. The new wording packs all three parts into the one
            // envelope `message`, same as before. The sibling
            // `DYNAMIC_FORWARD_CAPABILITY_UNSUPPORTED_MESSAGE` refusal (the
            // forward-route twin) follows the identical
            // observation/impact/next-command shape but is not its own row
            // here — this table pins one example of each of the seven
            // topics, not every wording `qsh-core` produces.
            observation: ThreePartSlot::new(
                DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE,
                "and this reverse route does not have it: either the target's qsh predates \
                 dial-filter.v1, or this machine's `qsh listen` daemon started before this \
                 machine's own qsh was last upgraded",
            ),
            impact: ThreePartSlot::new(
                DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE,
                "nothing was bound",
            ),
            next_command: ThreePartSlot::new(
                DYNAMIC_FORWARD_REVERSE_CAPABILITY_UNSUPPORTED_MESSAGE,
                "Upgrade qsh on the target, then restart `qsh listen` on this machine and retry.",
            ),
        },
    ]
}

#[test]
fn each_failure_wording_has_observation_impact_and_next_command() {
    // Eight rows for seven topics: T3 gets two (absent/present `[[acl]]`
    // row branches).
    let rows = three_part_rows();
    assert_eq!(
        rows.len(),
        8,
        "this table covers T1-T7 (T3 split into its absent/present rows)"
    );
    for row in &rows {
        row.observation.assert_holds(row.label, "observation");
        row.impact.assert_holds(row.label, "impact");
        row.next_command.assert_holds(row.label, "next-command");
    }
}

#[test]
fn t1_observation_slice_guards_the_assuming_port_substring() {
    let rows = three_part_rows();
    let t1 = rows
        .iter()
        .find(|row| row.label == "T1")
        .expect("T1 row must exist");
    assert!(
        t1.observation.slice.contains("assuming port 4433"),
        "T1's observation slice must be the clause containing \"assuming port 4433\" — \
         `qsh-cli/tests/init_trust.rs` and `trust_pairing_live.rs` both count occurrences of \
         that exact substring in stderr, so this table doubles as a guard for it"
    );
}

// ---------------------------------------------------------------------
// 6.3 Exception-list tests, over the two tables written out just below.
// ---------------------------------------------------------------------

/// Axes deliberately excluded from the observation/impact/next-command
/// discipline, each with a reason — same shape as
/// `schema_commands_registry.rs`'s `EXCLUDED` and `qsh-cli/tests/
/// fixtures.rs`'s `DEFERRED`: an exclusion is a documented decision, not a
/// silent gap.
const EXCLUDED: &[(&str, &str)] = &[
    (
        "원격으로 나가는 페어링 실패 문면",
        "ADR-0017 결정 4 (`docs/adr/0017-acl-toml-not-written.md:38`): \
         `PairingError::as_wire_error`(`crates/qsh-core/src/pairing.rs:176-187`) \
         의 매핑 — `NoMatch → AUTH_FAILED`, `Expired → TRUST_REQUIRED`, \
         `AlreadyConsumed`·`PinCollision → SESSION_CONFLICT` — 과 \
         `PERMISSION_DENIED_MESSAGE`(`crates/qsh-core/src/acl/mod.rs:270`) \
         의 균일 문면에는 원인을 앞세우는 처방을 얹지 않는다. 처방은 \
         관측한 host 의 상태를 담게 되고, 그것을 원격 응답에 실으면 \
         인가 실패가 host 내부 상태의 오라클이 된다. 이 축을 원격 응답에서 \
         합치거나 구분해 노출하는 안은 그 ADR이 범위 밖으로 명시했다. \
         대신 같은 사실을 host 로컬 채널로 낸다 — 결정 2 의 doctor 진단과 \
         결정 3 의 페어링 고지, 그리고 이 스텝의 \
         `PAIRING_INVITE_REPLAY_NOTICE`. 균일성 게이트는 \
         `crates/qsh-testkit/tests/acl_uniformity.rs` 가 지킨다",
    ),
    (
        "콘솔/tracing 구조화 진단",
        "ADR-0017 결정 4 (같은 줄), `docs/CLI.md` §6.13: tracing stderr 는 \
         구조화 이벤트 스트림이고 운영자에게 처방을 건네는 표면이 아니다. \
         `Server::serve_pairing_connection`의 `Err` 분기가 내는 \
         `tracing::warn!(%err, \"pairing exchange \
         failed\")` 는 `PairingError` variant 전부를 같은 문장으로 \
         감싸므로 종류별 처방을 담을 자리 자체가 없고, 담으려면 variant 마다 \
         래퍼를 쪼개야 한다. 이 스텝은 그 줄을 건드리지 않고 별개 stderr \
         고지를 더한다",
    ),
];

/// A different shape of exclusion: not "no remedy belongs here" (ADR
/// territory, `EXCLUDED` above) but "the remedy exists, a repo rule just
/// keeps it out of this particular channel".
///
/// Empty since ADR-0019: `-D`'s P0 stub refusal used to be the one entry
/// here (its unconditional-refusal message constant was frozen by the
/// append-only `error.UNSUPPORTED.json` fixture, so its impact/next-command
/// had to live on a channel no fixture pinned). `-D`'s real refusals
/// (T6, above) pack all three parts into the envelope `message` itself
/// from the start, so there is nothing left to constrain — this stays
/// declared, empty, as the seam the next such wording would register in.
const CHANNEL_CONSTRAINED: &[(&str, &str)] = &[];

/// Test one of the two: every exclusion has a non-empty reason, the
/// two lists never overlap, and ADR-0017 결정 4's two exempt axes are
/// present by name — modeled on `schema_commands_registry.rs`'s
/// bidirectional gate (`every_implemented_operation_has_a_schema_or_a_
/// documented_exclusion`).
#[test]
fn excluded_and_channel_constrained_entries_are_documented_and_disjoint() {
    for (label, reason) in EXCLUDED.iter().chain(CHANNEL_CONSTRAINED.iter()) {
        assert!(
            !label.is_empty(),
            "an exclusion's axis label must not be empty"
        );
        assert!(
            !reason.is_empty(),
            "{label}'s exclusion reason must not be empty — an exclusion is a documented \
             decision, not a silent gap"
        );
    }

    let excluded_labels: HashSet<&str> = EXCLUDED.iter().map(|(label, _)| *label).collect();
    let channel_constrained_labels: HashSet<&str> = CHANNEL_CONSTRAINED
        .iter()
        .map(|(label, _)| *label)
        .collect();
    let overlap: Vec<&&str> = excluded_labels
        .intersection(&channel_constrained_labels)
        .collect();
    assert!(
        overlap.is_empty(),
        "an axis cannot be both an ADR-0017 결정 4 exemption (EXCLUDED) and a repo-rule \
         channel constraint (CHANNEL_CONSTRAINED) at once: {overlap:?}"
    );

    for axis in [
        "원격으로 나가는 페어링 실패 문면",
        "콘솔/tracing 구조화 진단",
    ] {
        assert!(
            excluded_labels.contains(axis),
            "ADR-0017 결정 4 exempts exactly two axes by name; {axis:?} must be one of them"
        );
    }
}

/// Test two, the reverse direction: `PERMISSION_DENIED_
/// MESSAGE` and `PairingError::AlreadyConsumed`'s wire text must NOT show
/// up as a slot's source wording in the §6.2 three-part table — that is
/// what stops someone later three-parting them and breaking
/// `acl_uniformity.rs`'s exhaustive uniform-denial assertion.
#[test]
fn exempted_uniform_messages_never_become_a_three_part_slot() {
    let denied = PERMISSION_DENIED_MESSAGE;
    let replay_wire = PairingError::AlreadyConsumed.to_string();

    // Chains in `host_not_found_rows()` (issue #3 item b2, PR-D) so a
    // table added after `three_part_rows()` still inherits the ADR-0017
    // 결정 4 uniformity guard rather than sitting outside it silently.
    for row in three_part_rows().into_iter().chain(host_not_found_rows()) {
        for (part, slot) in [
            ("observation", &row.observation),
            ("impact", &row.impact),
            ("next-command", &row.next_command),
        ] {
            assert!(
                slot.haystack != denied,
                "{}'s {part} must not become PERMISSION_DENIED_MESSAGE — that message is \
                 ADR-0017 결정 4's uniform-denial exemption (EXCLUDED above), and \
                 acl_uniformity.rs asserts it stays undifferentiated",
                row.label
            );
            assert!(
                slot.haystack != replay_wire,
                "{}'s {part} must not become PairingError::AlreadyConsumed's wire text — that \
                 Display is the remote SESSION_CONFLICT mapping ADR-0017 결정 4 exempts \
                 (EXCLUDED above), not a three-part host notice",
                row.label
            );
        }
    }
}

// ---------------------------------------------------------------------
// issue #3 item b2 (PR-D): `resolve_route`'s (`crates/qsh-core/src/ops/
// host.rs`) `HOST_NOT_FOUND` fallback split into three branches. A
// dedicated table, kept separate from `three_part_rows`' T1-T7 (whose own
// `each_failure_wording_has_observation_impact_and_next_command` asserts
// an exact row count for that fixed set) rather than folded into it.
//
// Branch (ii) — a stale-but-listed registry entry — is PR-C's
// `stale_host_not_found`, unchanged by this split and not a `pub`
// function (`error.HOST_NOT_FOUND.reverse_stale.json` pins its wording;
// `crates/qsh-core/src/ops/host/tests.rs`'s `unconfigured_vs_stale_
// message`/`stale_vs_pinned_message` prove it stays distinct from the two
// branches below). Only (i)/(iii) are `pub` and verbatim-tested here.
// ---------------------------------------------------------------------

fn host_not_found_rows() -> Vec<ThreePartRow> {
    let unconfigured = unconfigured_host_not_found("nowhere").message;
    let pinned = pinned_without_address_host_not_found("phone").message;

    vec![
        ThreePartRow {
            label: "HOST_NOT_FOUND(i)",
            observation: ThreePartSlot::new(
                unconfigured.clone(),
                "is not configured on this machine: no trust-store pin, no hosts.toml entry, \
                 and no reverse registration naming it",
            ),
            impact: ThreePartSlot::new(unconfigured.clone(), "nothing will be dialed"),
            next_command: ThreePartSlot::new(
                unconfigured,
                "Pin it with `qsh trust add nowhere --address <host:port> --fingerprint \
                 sha256:...`, or register it by running `qsh reverse <controller>` on that host",
            ),
        },
        ThreePartRow {
            label: "HOST_NOT_FOUND(iii)",
            observation: ThreePartSlot::new(
                pinned.clone(),
                "is configured on this machine but has no address for it and no reverse \
                 registration is currently held",
            ),
            impact: ThreePartSlot::new(pinned.clone(), "nothing will be dialed"),
            next_command: ThreePartSlot::new(
                pinned,
                "Add one with `qsh trust add phone --address <host:port> --fingerprint \
                 sha256:...`, or run `qsh reverse <controller>` on that host to register it here",
            ),
        },
    ]
}

#[test]
fn host_not_found_split_has_observation_impact_and_next_command() {
    let rows = host_not_found_rows();
    assert_eq!(
        rows.len(),
        2,
        "branches (i) and (iii); (ii) is PR-C's own row, tested elsewhere"
    );
    for row in &rows {
        row.observation.assert_holds(row.label, "observation");
        row.impact.assert_holds(row.label, "impact");
        row.next_command.assert_holds(row.label, "next-command");
    }
}

/// Mutation check: collapsing branch (i) into (iii) (or the reverse)
/// would red this. The third leg of the pairwise check — (i)/(ii) and
/// (ii)/(iii) — cannot be written here since `stale_host_not_found` is
/// not `pub`; `crates/qsh-core/src/ops/host/tests.rs`'s
/// `unconfigured_vs_stale_message` and `stale_vs_pinned_message` are
/// those two legs, run from inside the crate where that function is
/// visible.
#[test]
fn host_not_found_branches_i_and_iii_do_not_collapse() {
    assert_ne!(
        unconfigured_host_not_found("phone").message,
        pinned_without_address_host_not_found("phone").message
    );
}

/// Neither branch's remedy leaks an `@` — both interpolate only the
/// already-`hint_alias`-validated bare alias, never a raw `user@host`
/// query.
#[test]
fn host_not_found_i_and_iii_never_leak_an_at_sign() {
    for message in [
        unconfigured_host_not_found("dave").message,
        pinned_without_address_host_not_found("dave").message,
    ] {
        assert!(!message.contains('@'), "leaked an @: {message:?}");
    }
}
