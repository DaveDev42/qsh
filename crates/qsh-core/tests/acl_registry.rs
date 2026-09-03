//! `PLAN.md` M5 Step 8 (SC6, DoD 2) — the three-layer enumeration owed on
//! top of `crates/qsh-core/src/acl/registry.rs`'s `OP_REGISTRY`:
//!
//! 1. **L6 contract cross-check** ([`section_2_5::registry_matches_cli_md_section_2_5_bidirectionally`]):
//!    `OP_REGISTRY`'s (op, action) pairs equal `docs/CLI.md` §2.5's
//!    mapping table, in both directions — a row in one side missing from
//!    the other fails, the `acl_docs.rs`/`tunnel_docs.rs` precedent
//!    pattern.
//! 2. **Authorization-surface cross-check** ([`dispatch_surface`]): every
//!    `qsh_proto::wire::control_message::Body` variant either needs
//!    authorization (and has an `OP_REGISTRY` row) or is on the short,
//!    explicit no-authorization-needed list — an exhaustive match with no
//!    wildcard arm, so a new wire variant fails this file's *compilation*
//!    until it is classified (`crates/qsh-core/src/acl/registry.rs`'s own
//!    `classify_control_message_body` precedent, `crates/qsh-cli/tests/
//!    acl_check_equivalence.rs`'s 16-variant exhaustive match).
//! 3. **DoD 2 — audit completeness** ([`dod2_audit`]): every `OP_REGISTRY`
//!    row actually driven once under an allow policy and once under a
//!    deny policy, asserting `MemoryAuditSink` gets exactly one new record
//!    with that row's `action` and the expected `decision`. Ten of the
//!    thirteen rows need nothing more than a bare `Server::dispatch` call
//!    (`DISPATCH_DRIVABLE_OPS`) — this file drives those, extending
//!    `crates/qsh-core/src/server/mod.rs`'s own
//!    `every_session_op_passes_the_choke_point_with_the_mapped_action`
//!    precedent to an external integration test. The remaining three
//!    (`forward.local`, `forward.remote`, `host.reverse`) each need a real
//!    QUIC connection or a real reverse registration to ever reach their
//!    choke point — `Server::authorize_and_dial_tunnel`/
//!    `authorize_and_bind_remote_forward`/`handle_rfwd_open` are
//!    `pub(crate)`, and `reverse::admit::admit`'s registry needs a real
//!    `Listen` controller — so `crates/qsh-testkit/tests/
//!    acl_registry_audit.rs` drives those instead, over
//!    `qsh_testkit::tunnel::TunnelHarness`/`reverse::ReverseHarness`.
//!    [`single_source::every_op_registry_row_is_driven_somewhere`] is the
//!    guard that keeps `OP_REGISTRY` as the *one* enumeration both files
//!    consume — a 14th row added to the registry with neither file taught
//!    to drive it fails there, not silently.
//!
//! **A named limit (F3, P2-2, M5 Step 8 adversarial review):** layer 3's
//! `action` assertion checks that a driven op's audit record carries the
//! `action` `OP_REGISTRY` itself declares for that row — it proves the
//! table and the dispatch path agree with each other, not that either one
//! is the *right* action for that op. That correctness claim is carried
//! elsewhere in the chain: layer 1 ties `OP_REGISTRY` to `docs/CLI.md`
//! §2.5's own committed mapping, and `crates/qsh-core/src/acl/registry.rs`'s
//! `DENY_SEAMS` cross-check ties the same table to the uniform-refusal
//! seam list Step 4 built independently. A wrong action would have to
//! survive all three at once to go unnoticed.

use std::collections::HashSet;
use std::path::PathBuf;

use qsh_core::acl::{Action, AllowAllPinned, DenyAll, OP_REGISTRY};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn read_doc(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// Same trick `crates/qsh-core/tests/acl_docs.rs` uses: slice `doc` from
/// `heading` (matched verbatim) up to, but not including, the next line
/// starting with `#` at any level — so a check is scoped to the one
/// section it claims to quote, not merely somewhere in the file.
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

/// Every backtick-quoted inline-code span in `cell`, in order.
fn backtick_tokens(cell: &str) -> Vec<&str> {
    cell.split('`').skip(1).step_by(2).collect()
}

// ---------------------------------------------------------------------
// Layer 1 — `docs/CLI.md` §2.5 cross-check.
// ---------------------------------------------------------------------
mod section_2_5 {
    use super::*;

    /// `docs/CLI.md` §2.5's operation→ACL action table, as
    /// `(left_cell, right_cell)` raw text per data row — header and
    /// separator rows dropped.
    fn rows(cli_md: &str) -> Vec<(String, String)> {
        let section = heading_section_slice(cli_md, "### 2.5 Operation과 ACL action 매핑");
        section
            .lines()
            .filter(|line| line.trim_start().starts_with('|'))
            .skip(2) // header + `|---|---|` separator
            .map(|line| {
                let body = line.trim().trim_matches('|');
                let mut cells = body.splitn(2, '|');
                let left = cells.next().unwrap_or_default().trim().to_string();
                let right = cells.next().unwrap_or_default().trim().to_string();
                (left, right)
            })
            .collect()
    }

    /// The bidirectional L6 gate: `OP_REGISTRY`'s (op, action) pairs equal
    /// exactly what `docs/CLI.md` §2.5 documents — a row present on either
    /// side and missing on the other fails. The table's nine data rows are
    /// walked by fixed index (asserted below) rather than generically
    /// classified: three of them (tunnel.open's two annotated forms, and
    /// the "인가 불요"/tunnel.close-tunnel.list rows) don't reduce to a
    /// single clean `(op, action)` pair by regex alone, so each gets its
    /// own explicit, documented handling instead of a parser fragile
    /// enough to silently mis-read one of them.
    #[test]
    fn registry_matches_cli_md_section_2_5_bidirectionally() {
        let cli_md = read_doc("docs/CLI.md");
        let section = heading_section_slice(&cli_md, "### 2.5 Operation과 ACL action 매핑");
        let rows = rows(&cli_md);
        assert_eq!(
            rows.len(),
            9,
            "docs/CLI.md §2.5's table row count drifted from this test's row-by-row \
             expectations — update them alongside whatever row was added, removed or \
             reordered: {rows:?}"
        );

        let mut expected: HashSet<(String, String)> = HashSet::new();

        // Rows 0–4: a single left-cell op (or several) mapping to a single
        // right-cell action, no annotation.
        // 0: `session.open` -> `session.open`
        // 1: `session.list`, `session.get` -> `session.list`
        // 2: `session.read`, `session.attach` -> `session.attach`
        // 3: `session.write`, `session.resize`, `session.close` -> `session.control`
        // 4: `exec.run` -> `exec.run`
        for (i, (left, right)) in rows.iter().enumerate().take(5) {
            let action_tokens = backtick_tokens(right);
            assert_eq!(
                action_tokens.len(),
                1,
                "§2.5 row {i}'s action cell must be exactly one backtick action: {right:?}"
            );
            for op in backtick_tokens(left) {
                expected.insert((op.to_string(), action_tokens[0].to_string()));
            }
        }

        // Row 5: `tunnel.open` (local forward) -> `forward.local`. Not
        // literally the op name `tunnel.open` on the OP_REGISTRY side —
        // `forward.local` is the seam's own name (`OpSpec`'s own doc),
        // matching `DENY_SEAMS` and this annotation's own right-hand
        // action.
        let (left5, right5) = &rows[5];
        assert!(
            left5.contains("local forward"),
            "row 5 must be tunnel.open's local-forward annotation: {left5:?}"
        );
        assert_eq!(backtick_tokens(right5), ["forward.local"]);
        expected.insert(("forward.local".to_string(), "forward.local".to_string()));

        // Row 6: `tunnel.open` (remote forward) -> `forward.remote`.
        let (left6, right6) = &rows[6];
        assert!(
            left6.contains("remote forward"),
            "row 6 must be tunnel.open's remote-forward annotation: {left6:?}"
        );
        assert_eq!(backtick_tokens(right6), ["forward.remote"]);
        expected.insert(("forward.remote".to_string(), "forward.remote".to_string()));

        // Row 7: `tunnel.close`, `tunnel.list` — no single-action pair of
        // its own (the cell is prose, not one backtick action): `-L`'s
        // tunnel.close has no host-side ACL check at all, and `-R`'s is
        // the forward.remote.close consequence this row's own prose
        // cross-references (§6.9). Assert the cross-reference still lives
        // rather than silently trusting it, then add that row by hand.
        let (left7, right7) = &rows[7];
        assert!(
            left7.contains("tunnel.close") && left7.contains("tunnel.list"),
            "row 7 must be the tunnel.close/tunnel.list row: {left7:?}"
        );
        assert!(
            right7.contains("forward.remote")
                && right7.contains("M5 Step 5")
                && right7.contains("6.9"),
            "row 7 must still cross-reference the forward.remote.close host-side check \
             (M5 Step 5, §6.9): {right7:?}"
        );
        expected.insert((
            "forward.remote.close".to_string(),
            "forward.remote".to_string(),
        ));

        // Row 8: host.list, host.get, identity.init, trust.*, doctor.run,
        // acl.check, schema.get, capabilities.get, version.get — 인가
        // 불요. Contributes no OP_REGISTRY pair; verified as an exclusion
        // list below instead.
        let (left8, right8) = &rows[8];
        assert!(
            right8.contains("인가 불요"),
            "row 8 must be the no-authorization-needed row: {right8:?}"
        );
        let no_authz_ops = backtick_tokens(left8);
        assert!(no_authz_ops.contains(&"host.list"));

        // `host.reverse` is not a table row at all (§2.5's own prose: a
        // connection-time check, not an operation) — it lives in the
        // paragraph right after the table. F4 (M5 Step 8 adversarial
        // review): scoped to `section` (§2.5 alone, via
        // `heading_section_slice`) rather than searched across the whole
        // document — a paragraph with this opening sentence anywhere else
        // in a growing, Korean-language doc must not satisfy this check,
        // and slicing a fixed byte count from a `find` offset in a
        // non-ASCII document risks landing mid-character. `.contains()`
        // on the already-bounded section has neither problem.
        let paragraph_start = section
            .find("역방향 host 등록은 operation이 아니라")
            .expect("§2.5 must still carry the host.reverse registration paragraph");
        assert!(
            section[paragraph_start..].contains("host.reverse"),
            "the host.reverse registration paragraph must still name host.reverse"
        );
        expected.insert(("host.reverse".to_string(), "host.reverse".to_string()));

        let registry: HashSet<(String, String)> = OP_REGISTRY
            .iter()
            .map(|spec| {
                (
                    spec.op.as_str().to_string(),
                    spec.action.as_str().to_string(),
                )
            })
            .collect();
        assert_eq!(
            registry, expected,
            "OP_REGISTRY and docs/CLI.md §2.5 have drifted apart — a row in one and not \
             the other means the doc and the code disagree about what a peer is \
             authorized against"
        );

        // Bidirectional exclusion: every op §2.5 says needs no
        // authorization must have NO OP_REGISTRY row. `trust.*` in the
        // doc's prose stands for the three real docs/CLI.md §2.4
        // operations it is short for.
        let mut excluded: Vec<String> = no_authz_ops.iter().map(|s| s.to_string()).collect();
        if let Some(pos) = excluded.iter().position(|o| o == "trust.*") {
            excluded.remove(pos);
            excluded.extend(["trust.add", "trust.list", "trust.remove"].map(String::from));
        }
        // The CLI-level tunnel.open/tunnel.close/tunnel.list op names
        // themselves must also have no row of their own — their ACL is
        // carried by forward.local/forward.remote/forward.remote.close
        // instead (row 5/6/7's own handling above).
        excluded.extend(["tunnel.open", "tunnel.close", "tunnel.list"].map(String::from));
        for op in &excluded {
            assert!(
                !registry.iter().any(|(o, _)| o == op),
                "{op} is documented (§2.5) as needing no authorization of its own, but has \
                 an OP_REGISTRY row"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Layer 2 — dispatch's `control_message::Body` variant enumeration.
// ---------------------------------------------------------------------
mod dispatch_surface {
    use super::*;
    use qsh_proto::wire::control_message::Body;
    use qsh_proto::wire::{
        ExecStart, Hello, PairingAccepted, PairingProof, Ping, Pong, RemoteForwardClose,
        RemoteForwardOpen, Response, SessionAttach, SessionClose, SessionEvent, SessionGet,
        SessionList, SessionOpen, SessionRead, SessionResize, SessionWrite,
    };

    enum Classification {
        /// This variant is the wire shape of the named `OP_REGISTRY` op.
        NeedsOp(&'static str),
        /// This variant never reaches an ACL choke point, for the given
        /// one-line reason.
        NoAuthorizationSurface(&'static str),
    }

    /// Exhaustive, **no wildcard arm**: a new `Body` variant fails this
    /// function's — and so this whole test binary's — compilation until
    /// it is classified here (`crates/qsh-core/src/acl/registry.rs`'s own
    /// `classify_control_message_body`, `crates/qsh-cli/tests/
    /// acl_check_equivalence.rs`'s 16-variant precedent).
    fn classify(body: &Body) -> Classification {
        match body {
            Body::Hello(_) => Classification::NoAuthorizationSurface(
                "handshake-only: a Hello after the handshake is answered INVALID_ARGUMENT \
                 before any ACL check",
            ),
            Body::Response(_) => Classification::NoAuthorizationSurface(
                "a reply, never a request a peer sends to be authorized",
            ),
            Body::SessionOpen(_) => Classification::NeedsOp("session.open"),
            Body::SessionAttach(_) => Classification::NeedsOp("session.attach"),
            Body::SessionList(_) => Classification::NeedsOp("session.list"),
            Body::SessionGet(_) => Classification::NeedsOp("session.get"),
            Body::SessionResize(_) => Classification::NeedsOp("session.resize"),
            Body::SessionClose(_) => Classification::NeedsOp("session.close"),
            Body::SessionRead(_) => Classification::NeedsOp("session.read"),
            Body::SessionWrite(_) => Classification::NeedsOp("session.write"),
            Body::ExecStart(_) => Classification::NeedsOp("exec.run"),
            Body::RfwdOpen(_) => Classification::NeedsOp("forward.remote"),
            Body::RfwdClose(_) => Classification::NeedsOp("forward.remote.close"),
            Body::Ping(_) => Classification::NoAuthorizationSurface(
                "keepalive, answered unconditionally with no ACL check",
            ),
            Body::Pong(_) => {
                Classification::NoAuthorizationSurface("unsolicited reply, dropped unconditionally")
            }
            Body::SessionEvent(_) => Classification::NoAuthorizationSurface(
                "host-to-client only; an inbound one is dropped, never authorized",
            ),
            Body::PairingProof(_) => Classification::NoAuthorizationSurface(
                "pairing-only (ADR-0002): reaches a connection whose principal is \
                 Principal::Pairing, routed to a dedicated pairing responder before \
                 dispatch/ACL ever run",
            ),
            Body::PairingAccepted(_) => Classification::NoAuthorizationSurface(
                "a reply, produced only by the pairing responder itself; never a request \
                 a peer sends to be authorized",
            ),
        }
    }

    fn all_body_samples() -> Vec<Body> {
        vec![
            Body::Hello(Hello::default()),
            Body::Response(Response::default()),
            Body::SessionOpen(SessionOpen::default()),
            Body::SessionAttach(SessionAttach::default()),
            Body::SessionList(SessionList::default()),
            Body::SessionGet(SessionGet::default()),
            Body::SessionResize(SessionResize::default()),
            Body::SessionClose(SessionClose::default()),
            Body::SessionRead(SessionRead::default()),
            Body::SessionWrite(SessionWrite::default()),
            Body::ExecStart(ExecStart::default()),
            Body::RfwdOpen(RemoteForwardOpen::default()),
            Body::RfwdClose(RemoteForwardClose::default()),
            Body::Ping(Ping::default()),
            Body::Pong(Pong::default()),
            Body::SessionEvent(SessionEvent::default()),
            Body::PairingProof(PairingProof::default()),
            Body::PairingAccepted(PairingAccepted::default()),
        ]
    }

    /// The explicit no-authorization-needed list, restated as a value so a
    /// change to it shows up in a diff — not merely the classifier's own
    /// (already exhaustive) match arms. The brief's own illustrative list
    /// (`Ping`/`Hello`/`SessionEvent`) undercounts: `Response` and `Pong`
    /// are equally never-authorized wire shapes (a reply and an
    /// unsolicited keepalive echo, never a peer request), and M7 Step 4
    /// added two more (`PairingProof`/`PairingAccepted`, ADR-0002) — so the
    /// real, code-verified list is seven variants, not three.
    const NO_AUTHORIZATION_NEEDED_REASON_COUNT: usize = 7;

    #[test]
    fn every_control_message_body_variant_needs_authorization_or_is_explicitly_exempt() {
        let samples = all_body_samples();
        assert_eq!(samples.len(), 18, "Body sample count drifted");

        let mut needs_op: HashSet<&'static str> = HashSet::new();
        let mut no_auth_count = 0usize;
        for body in &samples {
            match classify(body) {
                Classification::NeedsOp(op) => {
                    assert!(
                        needs_op.insert(op),
                        "two Body variants both classified as needing {op:?} — the mapping \
                         must be one-to-one"
                    );
                }
                Classification::NoAuthorizationSurface(reason) => {
                    assert!(!reason.is_empty());
                    no_auth_count += 1;
                }
            }
        }
        assert_eq!(
            no_auth_count, NO_AUTHORIZATION_NEEDED_REASON_COUNT,
            "the no-authorization-needed variant count drifted"
        );

        // Every op the classifier names must be a real OP_REGISTRY row.
        for op in &needs_op {
            assert!(
                OP_REGISTRY.iter().any(|spec| spec.op.as_str() == *op),
                "classify() mapped a Body variant to {op:?}, which is not an OP_REGISTRY row"
            );
        }

        // Every OP_REGISTRY row reachable over the wire (i.e. every row
        // except forward.local's inline gate and host.reverse's
        // connection-time check, neither of which is a Body variant) must
        // be reached by exactly one variant.
        let wire_reachable: HashSet<&'static str> = OP_REGISTRY
            .iter()
            .map(|spec| spec.op.as_str())
            .filter(|op| !matches!(*op, "forward.local" | "host.reverse"))
            .collect();
        assert_eq!(
            needs_op, wire_reachable,
            "every wire-reachable OP_REGISTRY row must be classified as needing exactly one \
             Body variant, and every variant classified as needing authorization must name a \
             real, wire-reachable row"
        );
    }
}

// ---------------------------------------------------------------------
// Layer 3 — DoD 2 audit completeness, the subset drivable via a bare
// `Server::dispatch` call with no live QUIC connection at all.
// ---------------------------------------------------------------------
mod dod2_audit {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use qsh_core::acl::{ActionPattern, Authorizer, OpSpec, Policy, ResourceKind, Rule, Scope};
    use qsh_core::audit::MemoryAuditSink;
    use qsh_core::broker::{
        Broker, BrokerConfig, PeerFingerprint, PipeFactory, SessionBackend, SessionId, SessionSpec,
        TestClock,
    };
    use qsh_core::server::{ConnCtx, SESSION_RESOURCE, Server};
    use qsh_proto::ErrorCode;
    use qsh_proto::wire::{self, ControlMessage, control_message, response};
    use qsh_transport::{AuthPath, Principal};

    /// The ten `OP_REGISTRY` rows this file drives — every op whose wire
    /// handler needs nothing beyond `Server::dispatch` (module doc). The
    /// remaining three live in `crates/qsh-testkit/tests/
    /// acl_registry_audit.rs`; `single_source` below is what keeps this
    /// split honest.
    pub(super) const DISPATCH_DRIVABLE_OPS: &[&str] = &[
        "session.open",
        "session.list",
        "session.get",
        "session.read",
        "session.attach",
        "session.write",
        "session.resize",
        "session.close",
        "exec.run",
        "forward.remote.close",
    ];

    fn ctx(principal: Principal) -> ConnCtx {
        ConnCtx {
            principal,
            auth_path: AuthPath::Pin,
            peer_fingerprint: Some(PeerFingerprint::new([7u8; 32])),
            peer_addr: "127.0.0.1:5000".parse().unwrap(),
            conn_id: 42,
            capabilities: vec!["exec".to_string(), "session".to_string()],
            is_reverse_registration: false,
        }
    }

    struct Rig {
        server: Arc<Server>,
        audit: Arc<MemoryAuditSink>,
        broker: Arc<Broker>,
    }

    fn rig(authorizer: Arc<dyn Authorizer>) -> Rig {
        let broker = Broker::new(
            Arc::new(TestClock::new()),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace: Duration::from_millis(100),
                quota_limits: qsh_core::quota::QuotaLimits::default(),
            },
            Arc::new(PipeFactory::new(64 * 1024)),
        );
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(authorizer, audit.clone(), broker.clone(), "host");
        Rig {
            server,
            audit,
            broker,
        }
    }

    fn error_code(msg: &ControlMessage) -> Option<ErrorCode> {
        match &msg.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => Some(e.error_code()),
            _ => None,
        }
    }

    /// F2 (P2-1, M5 Step 8 adversarial review) — `OpSpec::resource_kind`
    /// was dead data: nothing read it, so a mutation swapping one row's
    /// declared kind for another survived every existing test. This
    /// derives, from `kind` alone (never from what the caller happened to
    /// pass in), the one shape fact that actually discriminates the kinds
    /// [`DISPATCH_DRIVABLE_OPS`] can produce — `ResourceKind::Exec` is the
    /// literal sentinel `"exec"` and nothing else is, `ResourceKind::
    /// Session`'s two sentinel ops (`session.open`/`session.list`) are the
    /// literal [`SESSION_RESOURCE`] and nothing else is — and checks the
    /// real, observed `resource` against it. A row whose `resource_kind`
    /// no longer matches what its handler actually passes `ResourceRef`
    /// fails here. What this does **not** discriminate: `ResourceKind::
    /// Session` (non-sentinel ops) from `ResourceKind::ForwardBinding` —
    /// both are opaque host-minted ids with no shape in common with
    /// `"exec"`/`"session"`, so a mutation swapping only between those two
    /// kinds on a row this file drives would not be caught here (F2's own
    /// report names this residual gap explicitly).
    fn assert_resource_matches_declared_kind(spec: &OpSpec, resource: &str) {
        let is_exec_sentinel = resource == "exec";
        let is_session_sentinel = resource == SESSION_RESOURCE;
        let ok = match spec.resource_kind {
            ResourceKind::Exec => is_exec_sentinel,
            ResourceKind::Session
                if matches!(spec.op.as_str(), "session.open" | "session.list") =>
            {
                is_session_sentinel
            }
            ResourceKind::Session
            | ResourceKind::ForwardBinding
            | ResourceKind::ForwardDestination
            | ResourceKind::ReverseHost => !is_exec_sentinel && !is_session_sentinel,
        };
        assert!(
            ok,
            "{}'s declared resource_kind ({:?}) does not match its observed audit resource \
             {resource:?}",
            spec.op.as_str(),
            spec.resource_kind
        );
    }

    /// Dispatch one request for `op` and assert exactly one new audit
    /// record landed with `op`'s registered `action`/`expected_decision`,
    /// that the reply carries `expected_error` (`None` for an ordinary
    /// success reply), and — F2 above — that the record's `resource`
    /// matches `op`'s declared `resource_kind`. Looking `op` up here
    /// (rather than each call site passing `action_of(op)` directly, as
    /// before F2) is what makes every one of this file's ~20 drive sites
    /// exercise `resource_kind` for free.
    async fn drive(
        rig: &Rig,
        ctx: &ConnCtx,
        request_id: u64,
        body: control_message::Body,
        op: &str,
        expected_decision: &str,
        expected_error: Option<ErrorCode>,
    ) -> ControlMessage {
        let spec = OP_REGISTRY
            .iter()
            .find(|s| s.op.as_str() == op)
            .unwrap_or_else(|| panic!("{op:?} is not an OP_REGISTRY row"));
        let expected_action = spec.action;
        let before = rig.audit.records().len();
        let reply = rig
            .server
            .dispatch(ctx, &ControlMessage::new(request_id, body))
            .await
            .expect("dispatch always replies to a control-stream request");
        assert_eq!(
            error_code(&reply),
            expected_error,
            "{expected_action:?}, request {request_id}: {reply:?}"
        );
        let after = rig.audit.records();
        assert_eq!(
            after.len(),
            before + 1,
            "expected exactly one new audit record for {expected_action:?}, request {request_id}: \
             {after:?}"
        );
        let rec = after.last().unwrap();
        assert_eq!(rec.action, expected_action.as_str());
        assert_eq!(rec.decision, expected_decision, "{expected_action:?}");
        assert_resource_matches_declared_kind(spec, &rec.resource);
        reply
    }

    /// The allow leg: every `DISPATCH_DRIVABLE_OPS` row, driven once
    /// against one live session, under `AllowAllPinned`.
    #[tokio::test]
    async fn dispatch_drivable_ops_are_audited_allow() {
        let rig = rig(Arc::new(AllowAllPinned));
        let ctx = ctx(Principal::Device("laptop".into()));

        let opened = drive(
            &rig,
            &ctx,
            1,
            control_message::Body::SessionOpen(wire::SessionOpen {
                argv: vec!["sh".into()],
                cols: 80,
                rows: 24,
                ..Default::default()
            }),
            "session.open",
            "allow",
            None,
        )
        .await;
        let opened = match opened.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::SessionOpened(o)),
            })) => o,
            other => panic!("expected SessionOpened, got {other:?}"),
        };
        let id = opened.session_id.clone();

        drive(
            &rig,
            &ctx,
            2,
            control_message::Body::SessionList(wire::SessionList {}),
            "session.list",
            "allow",
            None,
        )
        .await;

        drive(
            &rig,
            &ctx,
            3,
            control_message::Body::SessionGet(wire::SessionGet {
                session_id: id.clone(),
            }),
            "session.get",
            "allow",
            None,
        )
        .await;

        drive(
            &rig,
            &ctx,
            4,
            control_message::Body::SessionRead(wire::SessionRead {
                session_id: id.clone(),
                ..Default::default()
            }),
            "session.read",
            "allow",
            None,
        )
        .await;

        drive(
            &rig,
            &ctx,
            5,
            control_message::Body::SessionAttach(wire::SessionAttach {
                session_id: id.clone(),
                resume_token: opened.resume_token.clone(),
                mode: wire::AttachMode::Rw as i32,
                ..Default::default()
            }),
            "session.attach",
            "allow",
            None,
        )
        .await;

        drive(
            &rig,
            &ctx,
            6,
            control_message::Body::SessionWrite(wire::SessionWrite {
                session_id: id.clone(),
                data: b"x".to_vec(),
            }),
            "session.write",
            "allow",
            None,
        )
        .await;

        drive(
            &rig,
            &ctx,
            7,
            control_message::Body::SessionResize(wire::SessionResize {
                session_id: id.clone(),
                cols: 80,
                rows: 24,
            }),
            "session.resize",
            "allow",
            None,
        )
        .await;

        drive(
            &rig,
            &ctx,
            8,
            control_message::Body::ExecStart(wire::ExecStart {
                argv: vec!["true".into()],
                env: Default::default(),
                timeout_ms: 0,
            }),
            "exec.run",
            "allow",
            None,
        )
        .await;

        // Well-formed but nonexistent forward_id: `owner: None` never
        // filters an ACL decision (`ResourceRef`'s own doc), so this still
        // reaches the choke point as an allow before "nothing to close"
        // answers `INVALID_ARGUMENT` — the audit decision, not the reply,
        // is what this row's DoD 2 obligation is about.
        drive(
            &rig,
            &ctx,
            9,
            control_message::Body::RfwdClose(wire::RemoteForwardClose {
                forward_id: "01FAKEFORWARDID0000000000".to_string(),
            }),
            "forward.remote.close",
            "allow",
            Some(ErrorCode::InvalidArgument),
        )
        .await;

        // Close last: it ends the session the rest of this test used.
        drive(
            &rig,
            &ctx,
            10,
            control_message::Body::SessionClose(wire::SessionClose {
                session_id: id.clone(),
                signal: None,
            }),
            "session.close",
            "allow",
            None,
        )
        .await;
    }

    /// The deny leg: every `DISPATCH_DRIVABLE_OPS` row, driven once under
    /// `DenyAll` — no live session needed for most rows (`DenyAll` denies
    /// before any existence lookup), except `session.attach`, whose
    /// credential check runs *before* the ACL choke point and so needs a
    /// real resume token minted directly at the broker layer, bypassing
    /// the (ACL-gated, and therefore itself denied under `DenyAll`)
    /// `session.open` handler entirely — the same bypass
    /// `crates/qsh-testkit/tests/acl_uniformity.rs`'s
    /// `drive_session_attach` uses.
    #[tokio::test]
    async fn dispatch_drivable_ops_are_audited_deny() {
        const FAKE_SESSION_ID: &str = "01K0FAKESESSION0000000000";

        let rig = rig(Arc::new(DenyAll));
        let ctx = ctx(Principal::Device("intruder".into()));

        drive(
            &rig,
            &ctx,
            1,
            control_message::Body::SessionOpen(wire::SessionOpen {
                argv: vec!["sh".into()],
                cols: 80,
                rows: 24,
                ..Default::default()
            }),
            "session.open",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;

        drive(
            &rig,
            &ctx,
            2,
            control_message::Body::SessionList(wire::SessionList {}),
            "session.list",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;

        drive(
            &rig,
            &ctx,
            3,
            control_message::Body::SessionGet(wire::SessionGet {
                session_id: FAKE_SESSION_ID.into(),
            }),
            "session.get",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;

        drive(
            &rig,
            &ctx,
            4,
            control_message::Body::SessionRead(wire::SessionRead {
                session_id: FAKE_SESSION_ID.into(),
                ..Default::default()
            }),
            "session.read",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;

        // `session.attach`'s own bypass: plant a session and mint a valid
        // resume credential directly at the broker, so the pre-ACL
        // credential check passes and the request reaches the real
        // `Action::SessionAttach` deny.
        let handle = rig
            .broker
            .open(&SessionSpec {
                argv: vec!["sh".into()],
                env: vec![],
                term: None,
                cols: 80,
                rows: 24,
                user: None,
            })
            .expect("plant a session directly at the broker");
        let id = SessionId(handle.id().to_string());
        let peer = PeerFingerprint::new([7u8; 32]);
        let token = SessionBackend::issue_resume(&*rig.broker, &id, peer);
        drive(
            &rig,
            &ctx,
            5,
            control_message::Body::SessionAttach(wire::SessionAttach {
                session_id: id.0.clone(),
                resume_token: token.expose().to_vec(),
                mode: wire::AttachMode::Rw as i32,
                ..Default::default()
            }),
            "session.attach",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;

        drive(
            &rig,
            &ctx,
            6,
            control_message::Body::SessionWrite(wire::SessionWrite {
                session_id: FAKE_SESSION_ID.into(),
                data: b"x".to_vec(),
            }),
            "session.write",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;

        drive(
            &rig,
            &ctx,
            7,
            control_message::Body::SessionResize(wire::SessionResize {
                session_id: FAKE_SESSION_ID.into(),
                cols: 80,
                rows: 24,
            }),
            "session.resize",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;

        drive(
            &rig,
            &ctx,
            8,
            control_message::Body::ExecStart(wire::ExecStart {
                argv: vec!["true".into()],
                env: Default::default(),
                timeout_ms: 0,
            }),
            "exec.run",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;

        drive(
            &rig,
            &ctx,
            9,
            control_message::Body::RfwdClose(wire::RemoteForwardClose {
                forward_id: "01FAKEFORWARDID0000000000".to_string(),
            }),
            "forward.remote.close",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;

        drive(
            &rig,
            &ctx,
            10,
            control_message::Body::SessionClose(wire::SessionClose {
                session_id: FAKE_SESSION_ID.into(),
                signal: None,
            }),
            "session.close",
            "deny",
            Some(ErrorCode::PermissionDenied),
        )
        .await;
    }

    /// F2 (P2-1, M5 Step 8 adversarial review) — the other dead-data half:
    /// `OpSpec::owned` was never checked against what a handler actually
    /// does. This drives the two `owned: true` rows this file can reach
    /// via a bare `Server::dispatch` call (`session.write`/`session.
    /// resize` — `Server::authorize_session_control` folds the opener's
    /// identity into `ResourceRef::owner`) and the one `owned: false`
    /// exception sharing their `Action::SessionControl`
    /// (`session.close` — `Server::handle_session_close` deliberately
    /// calls the *unowned* `Self::authorize`, not `authorize_session_
    /// control`, per its own doc comment) from a principal that is not
    /// the session's opener, under a real `Policy` with the default
    /// `scope = "owned"` — not `AllowAllPinned`, whose ownership check is
    /// hardcoded independently of any policy `scope`. The expected
    /// decision for each op is computed *from* `OP_REGISTRY`'s own
    /// `owned` field rather than hardcoded, so a mutation that flips a
    /// row's declared `owned` without changing the handler's real
    /// behavior fails here: it predicts the opposite of what actually
    /// happens. `forward.remote.close` (the third `owned: true` row)
    /// needs a real registered forward on a live QUIC connection to test
    /// the same way — `crates/qsh-testkit/tests/acl_registry_audit.rs`'s
    /// `forward_remote_close_owned_flag_matches_the_observed_ownership_gate`
    /// covers it.
    #[tokio::test]
    async fn owned_flag_matches_the_observed_ownership_gate_for_dispatch_drivable_rows() {
        fn spec_of(op: &str) -> &'static OpSpec {
            OP_REGISTRY
                .iter()
                .find(|s| s.op.as_str() == op)
                .unwrap_or_else(|| panic!("{op} must be an OP_REGISTRY row"))
        }
        fn expect(spec: &OpSpec) -> (&'static str, Option<ErrorCode>) {
            if spec.owned {
                ("deny", Some(ErrorCode::PermissionDenied))
            } else {
                ("allow", None)
            }
        }

        let policy = Policy {
            rules: vec![
                Rule {
                    principal: Principal::Device("owner".into()).to_string(),
                    auth_path: AuthPath::Pin,
                    allow: vec![
                        ActionPattern::Exact(Action::SessionOpen),
                        ActionPattern::Exact(Action::SessionControl),
                    ],
                    scope: Scope::Owned,
                },
                Rule {
                    principal: Principal::Device("intruder".into()).to_string(),
                    auth_path: AuthPath::Pin,
                    allow: vec![ActionPattern::Exact(Action::SessionControl)],
                    scope: Scope::Owned,
                },
            ],
        };
        let rig = rig(Arc::new(policy));
        let owner_ctx = ctx(Principal::Device("owner".into()));
        let intruder_ctx = ctx(Principal::Device("intruder".into()));

        let opened = drive(
            &rig,
            &owner_ctx,
            1,
            control_message::Body::SessionOpen(wire::SessionOpen {
                argv: vec!["sh".into()],
                cols: 80,
                rows: 24,
                ..Default::default()
            }),
            "session.open",
            "allow",
            None,
        )
        .await;
        let id = match opened.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::SessionOpened(o)),
            })) => o.session_id,
            other => panic!("expected SessionOpened, got {other:?}"),
        };

        let (write_decision, write_error) = expect(spec_of("session.write"));
        drive(
            &rig,
            &intruder_ctx,
            2,
            control_message::Body::SessionWrite(wire::SessionWrite {
                session_id: id.clone(),
                data: b"x".to_vec(),
            }),
            "session.write",
            write_decision,
            write_error,
        )
        .await;

        let (resize_decision, resize_error) = expect(spec_of("session.resize"));
        drive(
            &rig,
            &intruder_ctx,
            3,
            control_message::Body::SessionResize(wire::SessionResize {
                session_id: id.clone(),
                cols: 80,
                rows: 24,
            }),
            "session.resize",
            resize_decision,
            resize_error,
        )
        .await;

        // The documented exception: not narrowed by ownership, so the
        // non-owner `intruder` succeeds and ends the session here.
        let (close_decision, close_error) = expect(spec_of("session.close"));
        drive(
            &rig,
            &intruder_ctx,
            4,
            control_message::Body::SessionClose(wire::SessionClose {
                session_id: id.clone(),
                signal: None,
            }),
            "session.close",
            close_decision,
            close_error,
        )
        .await;
    }

    #[test]
    fn dispatch_drivable_ops_matches_its_own_declared_count() {
        assert_eq!(DISPATCH_DRIVABLE_OPS.len(), 10);
        for op in DISPATCH_DRIVABLE_OPS {
            assert!(
                OP_REGISTRY.iter().any(|spec| spec.op.as_str() == *op),
                "{op} is in DISPATCH_DRIVABLE_OPS but not in OP_REGISTRY"
            );
        }
    }
}
// ---------------------------------------------------------------------
// Single-source-of-truth guard: OP_REGISTRY is enumerated exactly once
// across this file and qsh-testkit's acl_registry_audit.rs.
// ---------------------------------------------------------------------
mod single_source {
    use super::*;

    /// The three rows this file cannot drive via a bare `Server::dispatch`
    /// call (module doc) — `crates/qsh-testkit/tests/
    /// acl_registry_audit.rs` drives these instead. Restated here (not
    /// merely trusted) so this test fails the moment `OP_REGISTRY` grows a
    /// row neither this list nor `dod2_audit::DISPATCH_DRIVABLE_OPS` names.
    const TESTKIT_ONLY_OPS: &[&str] = &["forward.local", "forward.remote", "host.reverse"];

    #[test]
    fn every_op_registry_row_is_driven_somewhere() {
        let mut all: HashSet<&str> = dod2_audit::DISPATCH_DRIVABLE_OPS.iter().copied().collect();
        all.extend(TESTKIT_ONLY_OPS.iter().copied());
        let registry: HashSet<&str> = OP_REGISTRY.iter().map(|spec| spec.op.as_str()).collect();
        assert_eq!(
            all, registry,
            "OP_REGISTRY has a row neither this file's DISPATCH_DRIVABLE_OPS nor \
             TESTKIT_ONLY_OPS knows how to drive for DoD 2 (or one of those lists names a \
             row that no longer exists) — teach one of the two files, or move the row \
             between them"
        );
    }
}

// ---------------------------------------------------------------------
// F5 (P2-5 + P2-6, M5 Step 8 adversarial review): the stream axis and the
// literal-bypass have no enumeration anchor the way the Body-variant axis
// does (`dispatch_surface`'s exhaustive, no-wildcard match) — a source
// scan is the only thing that can pin them, since there is no exhaustive
// Rust match over "every call to a private method" or "every Action::
// literal in a file" to lean on.
// ---------------------------------------------------------------------
mod source_scan {
    use super::*;

    /// `crates/qsh-core/src/server/mod.rs`, production code only: a
    /// prefix slice on the file's sole `"\n#[cfg(test)]\nmod tests {"`
    /// marker (this crate's clippy/fmt discipline keeps exactly one such
    /// block per file), not a parser. Deliberately simple over clever: a
    /// `#[cfg(test)]` call site or `Action::` literal inside the test
    /// module must never count toward either pin below, and a byte-offset
    /// slice on a literal, verbatim string is the cheapest way to
    /// guarantee that.
    fn server_mod_production_source() -> String {
        // CRLF-normalized: the Windows CI runner checks sources out with
        // `\r\n` endings, which would keep the `\n`-joined marker below
        // from ever matching (and panic this scan on every Windows run).
        let full = read_doc("crates/qsh-core/src/server/mod.rs").replace("\r\n", "\n");
        let marker = "\n#[cfg(test)]\nmod tests {";
        let end = full.find(marker).unwrap_or_else(|| {
            panic!("server/mod.rs must still have a #[cfg(test)] mod tests block")
        });
        full[..end].to_string()
    }

    /// Every line of `source`, blanking any line that is itself a comment
    /// (`//`, `///`, or `//!`, after leading whitespace) — so a doc
    /// comment that merely *mentions* `authorize_stream(` or `Action::`
    /// in prose (this file's own module docs do, constantly) never counts
    /// as a real call site or literal.
    fn non_comment_lines(source: &str) -> Vec<&str> {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect()
    }

    /// P2-5: `docs/design/architecture.md` §6 and `crates/qsh-core/src/
    /// acl/registry.rs`'s own `SeamKind` doc both *say*
    /// `Server::authorize_stream` has exactly two production callers
    /// (`forward.local`'s inline `TCP_CONNECT` gate,
    /// `session.attach@data-stream`'s reattach gate) — nothing enumerated
    /// them. This counts real call sites (`.authorize_stream(`, which
    /// excludes the method's own `fn authorize_stream(` definition line —
    /// a method call is always written `receiver.method(`, a definition
    /// never is) in the non-test region, and pins both the count and
    /// which two seams they are by the literal each call site's `action`
    /// argument carries.
    #[test]
    fn authorize_stream_has_exactly_two_production_call_sites() {
        let source = server_mod_production_source();
        let call_sites: Vec<&str> = non_comment_lines(&source)
            .into_iter()
            .filter(|line| line.contains(".authorize_stream("))
            .collect();
        assert_eq!(
            call_sites.len(),
            2,
            "authorize_stream must have exactly two production call sites \
             (forward.local's inline TCP_CONNECT gate, session.attach@data-stream's \
             reattach gate) — a third call site means a new inline stream-authorization \
             gate was added with no DENY_SEAMS row to match it: {call_sites:?}"
        );
        assert!(
            call_sites
                .iter()
                .any(|line| line.contains("Op::ForwardLocal.action()")),
            "one authorize_stream call site must be forward.local's, by name: {call_sites:?}"
        );
        assert!(
            call_sites
                .iter()
                .any(|line| line.contains("Action::SessionAttach")),
            "the other authorize_stream call site must be session.attach@data-stream's \
             documented Action::SessionAttach literal: {call_sites:?}"
        );
    }

    /// P2-6: every dispatch handler is supposed to get its `Action` from
    /// `crate::acl::Op::X.action()`, not a hardcoded `Action::` variant —
    /// that is what keeps a handler and `OP_REGISTRY` from silently
    /// drifting apart (`OpSpec`'s own doc, `Op::action`'s own doc: "the
    /// sole replacement for the deleted `action_of`... every production
    /// call site now writes `Op::X.action()`"). The one documented
    /// exception is `session.attach@data-stream`, which has no
    /// `OP_REGISTRY` row of its own to look up (same doc). This counts
    /// real `Action::` variant literals in the non-test region and pins
    /// that count to exactly one, at that one documented call site — a
    /// handler that starts hardcoding `Action::Whatever` instead of
    /// calling `Op::X.action()` fails here, not silently.
    #[test]
    fn action_variant_literals_are_pinned_to_the_one_documented_exception() {
        let source = server_mod_production_source();
        let literal_lines: Vec<&str> = non_comment_lines(&source)
            .into_iter()
            .filter(|line| line.contains("Action::"))
            .collect();
        assert_eq!(
            literal_lines.len(),
            1,
            "server/mod.rs's production code must have exactly one Action:: variant \
             literal — every other handler must route through crate::acl::Op::X.action() \
             instead of naming an Action variant directly: {literal_lines:?}"
        );
        assert!(
            literal_lines[0].contains("Action::SessionAttach")
                && literal_lines[0].contains("authorize_stream"),
            "the one Action:: literal must be session.attach@data-stream's documented \
             authorize_stream(&ctx, Action::SessionAttach, ...) call: {literal_lines:?}"
        );
    }
}
