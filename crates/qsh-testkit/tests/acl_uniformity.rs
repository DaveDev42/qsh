//! L3 — `PLAN.md` M5 Step 4 DoD 4: every seam in
//! [`qsh_core::acl::DENY_SEAMS`] denies a remote peer uniformly, under a
//! real `DenyAll` host (never `AllowAllPinned` — production policy is
//! untouched by this file). "Uniformly" means two things, load-bearing
//! both (F2, M5 Step 4 adversarial review):
//!
//! - The wire-visible refusal is right for the row's [`SeamKind`]: the
//!   exact same [`qsh_core::acl::PERMISSION_DENIED_MESSAGE`], byte for
//!   byte, for the three message-carrying kinds
//!   ([`SeamKind::ControlStreamOp`]/[`SeamKind::TunnelInline`]/
//!   [`SeamKind::ReverseRegistration`]); the correct QUIC reset code
//!   (`RESET_CODE_FORBIDDEN`) for the message-less
//!   [`SeamKind::StreamReset`] kind, which has no envelope to carry text
//!   in at all.
//! - The audit sink recorded a **deny under the row's own [`Action`]**,
//!   not merely *some* deny — [`assert_new_audit_deny_for_seam`] checks
//!   this after every single seam drive below, which is what makes a
//!   row's `action` field load-bearing instead of decorative: a row
//!   mislabeled with the wrong `Action` fails here even though the wire
//!   refusal itself still looks perfect.
//!
//! **Why its own file, not folded into `session_loopback.rs` or
//! `tunnel_loopback.rs`/`reverse_loopback.rs`.** `DENY_SEAMS` spans four
//! unrelated wire shapes — ordinary control-stream ops
//! ([`qsh_testkit::loopback::LoopbackHarness`]), the `forward.local`
//! inline `TCP_CONNECT` gate ([`qsh_testkit::tunnel::TunnelHarness`]),
//! the `host.reverse` connection-time registration
//! ([`qsh_testkit::reverse::ReverseHarness`]), and the `SessionData`
//! reattach inline gate (also [`qsh_testkit::loopback::LoopbackHarness`],
//! but under a bespoke policy — see [`OpenOnlyDenyAttach`]'s doc) — so no
//! single existing per-op-family suite is the natural home for a test
//! whose entire point is to walk *all four* against *one* registry. This
//! mirrors why `acl_docs.rs`/`tunnel_docs.rs` are their own files rather
//! than folded into whatever suite happens to exercise the wording they
//! pin: the property under test (uniformity/anti-drift) is orthogonal to
//! any one op family.
//!
//! **What "exhaustive" means here, concretely.** [`drive_control_stream_op`]
//! matches on the registry row's `name` with a panicking default arm, so
//! a `ControlStreamOp` row added to the registry with no case here fails
//! this test immediately (not silently skipped). Every non-`ControlStreamOp`
//! block below looks its own row up in [`DENY_SEAMS`] by name and asserts
//! its `kind` is the one that block knows how to drive (F2) — a row whose
//! `kind` no longer matches what its block expects fails there instead of
//! silently driving the wrong wire shape. The single test function below
//! additionally asserts the *set* of row names it actually drove, across
//! every driver, equals `DENY_SEAMS`'s full name set exactly — so a new
//! row of *any* kind that this file's blocks don't reach also fails
//! loudly, not silently. The exemption list this file owes PLAN.md's DoD
//! 4 is empty: every row in the registry is genuinely driven to a real
//! deny from testkit, including `session.attach` (see
//! [`drive_session_attach`]'s doc for how a `DenyAll` host — which also
//! denies `session.open` — still gets one to attach to) and
//! `session.attach@data-stream` (see [`OpenOnlyDenyAttach`]'s doc for why
//! that row cannot be driven under a literal `DenyAll` at all).

use std::collections::BTreeSet;
use std::sync::Arc;

use qsh_core::acl::{
    Action, Authorizer, DENY_SEAMS, Decision, DenyAll, DenySeam, PERMISSION_DENIED_MESSAGE,
    ResourceRef, SeamKind, Verdict,
};
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{PeerFingerprint, SessionBackend, SessionId, SessionSpec};
use qsh_core::client::{ClientError, Session};
use qsh_core::exec::ExecSpec;
use qsh_core::handshake::HelloError;
use qsh_core::server::RESET_CODE_FORBIDDEN;
use qsh_proto::ErrorCode;
use qsh_proto::wire;
use qsh_testkit::loopback::{LoopbackHarness, TestIdentity, make_identity};
use qsh_testkit::reverse::ReverseHarness;
use qsh_testkit::tunnel::TunnelHarness;
use qsh_transport::{AuthPath, Dialed, FramedStream, Principal, StaticTrust};

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// A session id that need not name a real session: under `DenyAll` the
/// choke point denies before any resource lookup, so every `session.*`
/// op below except `session.attach` (which is gated by credential
/// verification *before* the choke point, see [`drive_session_attach`])
/// can use one fixed placeholder, the same way
/// `session_loopback.rs`'s own `denied_peer_cannot_learn_whether_a_session_exists`
/// drives both a real and a fake id through the identical deny.
const FAKE_SESSION_ID: &str = "01K0FAKESESSION0000000000";

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        env: Default::default(),
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// Every `SeamKind::ControlStreamOp` row except `session.attach`, driven
/// against one shared session — an exhaustive match on the row's `name`;
/// an unrecognized name panics rather than being silently skipped, which
/// is what makes this the thing that fails when a new remote-facing
/// control-stream op is added to [`DENY_SEAMS`] with nobody having taught
/// this file how to drive it.
async fn drive_control_stream_op(s: &mut Session, name: &str) -> Result<(), ClientError> {
    match name {
        "exec.run" => s
            .exec_start(&ExecSpec {
                argv: vec!["true".into()],
                env: vec![],
                timeout: None,
            })
            .await
            .map(|_| ()),
        "session.open" => s.session_open(open_req()).await.map(|_| ()),
        "session.list" => s.session_list().await.map(|_| ()),
        "session.get" => s.session_get(FAKE_SESSION_ID).await.map(|_| ()),
        "session.read" => s
            .session_read(wire::SessionRead {
                session_id: FAKE_SESSION_ID.into(),
                ..Default::default()
            })
            .await
            .map(|_| ()),
        "session.write" => s
            .session_write(FAKE_SESSION_ID, b"x".to_vec())
            .await
            .map(|_| ()),
        "session.resize" => s.session_resize(FAKE_SESSION_ID, 80, 24).await.map(|_| ()),
        "session.close" => s.session_close(FAKE_SESSION_ID, None).await.map(|_| ()),
        "forward.remote" => s
            .rfwd_open(wire::RemoteForwardOpen {
                bind_host: String::new(),
                bind_port: 0,
                forward_host: "127.0.0.1".to_string(),
                forward_port: 9,
                claim_token: Vec::new(),
            })
            .await
            .map(|_| ()),
        // A well-formed but nonexistent `forward_id` — under `DenyAll` the
        // ACL gate (`Server::authorize_owned`, `PLAN.md` M5 Step 5) always
        // runs first, so this still hits `PERMISSION_DENIED`, never
        // `INVALID_ARGUMENT`'s existence tell (`Server::handle_rfwd_close`'s
        // own doc: unknown-id resources are `owner: None`, never filtered
        // by scope, so a `DenyAll`/`Policy` verdict for one is identical to
        // a real forward's).
        "forward.remote.close" => {
            s.rfwd_close(wire::RemoteForwardClose {
                forward_id: "01FAKEFORWARDID0000000000".to_string(),
            })
            .await
        }
        other => panic!(
            "drive_control_stream_op: DENY_SEAMS has a ControlStreamOp row {other:?} with no \
             driver in this match — teach acl_uniformity.rs how to drive it"
        ),
    }
}

/// `session.attach`'s own driver: unlike every other row, the wire
/// handler verifies the resume credential **before** the ACL choke point
/// (`Server::handle_session_attach`), so a bare `DenyAll` host — which
/// also denies `session.open` — has no ordinary way to mint one. This
/// plants a session and mints a valid credential directly at the broker
/// layer ([`SessionBackend::issue_resume`]), bypassing the ACL-gated wire
/// `SessionOpen` handler entirely (the same broker-direct pattern
/// `session_loopback.rs`'s own `denied_peer_cannot_learn_whether_a_session_exists`
/// uses to plant a session under `DenyAll`), so the credential check
/// passes and the request reaches `Action::SessionAttach`'s real deny —
/// this is why `session.attach` needs no exemption.
async fn drive_session_attach(h: &LoopbackHarness) -> Result<(), ClientError> {
    let handle = h
        .broker
        .open(&SessionSpec {
            argv: vec!["sh".into()],
            env: vec![],
            term: None,
            cols: 80,
            rows: 24,
            user: None,
        })
        .expect("plant a session directly at the broker (bypasses the ACL-gated session.open)");
    let id = SessionId(handle.id().to_string());
    let peer = PeerFingerprint::new(*h.client.fingerprint.as_bytes());
    let token = SessionBackend::issue_resume(&*h.broker, &id, peer);

    let (conn, mut ctl): (_, FramedStream) = h.raw_session().await;
    ctl.send
        .send(&wire::ControlMessage::new(
            1,
            wire::control_message::Body::SessionAttach(wire::SessionAttach {
                session_id: id.0.clone(),
                resume_token: token.expose().to_vec(),
                mode: wire::AttachMode::Rw as i32,
                ..Default::default()
            }),
        ))
        .await
        .expect("send SessionAttach");
    let reply = ctl
        .recv
        .recv::<wire::ControlMessage>()
        .await
        .expect("recv")
        .expect("conduit stayed open for the reply");
    let result = match reply.body {
        Some(wire::control_message::Body::Response(wire::Response {
            body: Some(wire::response::Body::Error(e)),
        })) => Err(ClientError::Remote {
            code: e.error_code(),
            message: e.message,
            retryable: e.retryable,
        }),
        Some(wire::control_message::Body::Response(wire::Response { body: None })) => Ok(()),
        other => panic!("unexpected reply to a raw SessionAttach: {other:?}"),
    };
    conn.close(0, b"done");
    result
}

fn assert_denied(result: Result<(), ClientError>, seam: &str) {
    match result {
        Err(ClientError::Remote { code, message, .. }) => {
            assert_eq!(code, ErrorCode::PermissionDenied, "{seam}");
            assert_eq!(
                message, PERMISSION_DENIED_MESSAGE,
                "{seam}: message must be the uniform PERMISSION_DENIED_MESSAGE, byte for byte"
            );
        }
        other => panic!("{seam}: expected a remote PERMISSION_DENIED, got {other:?}"),
    }
}

/// F2 (M5 Step 4 adversarial review): assert driving `seam` appended at
/// least one **new** audit record — `records()[before..]` — that is a
/// deny recorded under `seam.action`, not merely some deny somewhere.
/// This is what makes [`DenySeam::action`] load-bearing: the production
/// wire handler that answers a given op hardcodes its own `Action` and
/// never consults the registry, so a row mislabeled with the wrong
/// `Action` would otherwise go unnoticed as long as *some* deny got
/// recorded — this check catches exactly that mislabeling.
fn assert_new_audit_deny_for_seam(audit: &MemoryAuditSink, before: usize, seam: &DenySeam) {
    let records = audit.records();
    let new_records = &records[before..];
    assert!(
        new_records
            .iter()
            .any(|r| r.action == seam.action.as_str() && r.decision == "deny"),
        "{}: expected a new audit deny record with action {:?}, got {:?}",
        seam.name,
        seam.action.as_str(),
        new_records
    );
}

/// [`Result::expect_err`] needs `T: Debug`, and a successful `Hello.reverse`
/// exchange's success type (`(Dialed, FramedStream, Hello)`) is not
/// (`FramedStream` owns live QUIC stream halves) — the same shape check
/// `reverse_loopback.rs`'s own `expect_hello_err` provides, duplicated here
/// rather than shared (each test binary is its own crate; there is no
/// shared support module for these small per-file wire helpers to live
/// in — same division `reverse_tunnel.rs`'s own `connect_control` doc
/// notes).
fn expect_hello_err(
    result: Result<(Dialed, FramedStream, wire::Hello), HelloError>,
    msg: &str,
) -> HelloError {
    match result {
        Ok(_) => panic!("{msg}"),
        Err(err) => err,
    }
}

fn remote(err: HelloError) -> (ErrorCode, String, bool) {
    match err {
        HelloError::Remote {
            code,
            message,
            retryable,
        } => (code, message, retryable),
        other => panic!("expected a remote error frame, got {other:?}"),
    }
}

/// [`SeamKind::StreamReset`]'s driver needs a policy shape a blanket
/// [`DenyAll`] cannot provide, and this is deliberate, not a shortcut
/// (F3, M5 Step 4 adversarial review). The `SessionData` reattach inline
/// gate (`server/mod.rs`'s `handle_data_stream`, the `SessionData` ticket
/// branch) only runs its `Action::SessionAttach` check on a ticket minted
/// with `attach_authorized: false` — and the *only* place that ever mints
/// one is a **successful** `session.open` (`Server::handle_session_open`).
/// `Server::issue_ticket` is a private method with no test-facing
/// "plant a raw ticket" equivalent of `SessionBackend::issue_resume` (the
/// production API [`drive_session_attach`] above legitimately reuses to
/// bypass `session.open`'s own gate for `session.attach`'s row) — there is
/// no ticket-planting production API to bypass this gate with. Under a
/// real `DenyAll` host, `session.open` itself is always denied, so no
/// `attach_authorized: false` ticket can ever come to exist to redeem: the
/// seam would not merely be undriven, it would be *unreachable*, no matter
/// what this file did.
///
/// So this authorizer is the narrowest policy that still isolates the seam
/// for a real, wire-driven deny — `session.open` allowed (so a real ticket
/// exists), everything else (including `session.attach`, and every other
/// action) denied exactly like `DenyAll` would deny it if `session.open`
/// were reachable at all. Driving the seam this way is arguably stronger
/// evidence than a broker-planting bypass would have been: both the
/// `session.open` allow and the reattach's `session.attach` deny are real
/// ACL decisions made by the production choke points, not stand-ins.
struct OpenOnlyDenyAttach;

impl Authorizer for OpenOnlyDenyAttach {
    fn check(
        &self,
        _principal: &Principal,
        _auth_path: AuthPath,
        action: Action,
        _resource: ResourceRef<'_>,
    ) -> Verdict {
        let decision = if action == Action::SessionOpen {
            Decision::Allow
        } else {
            Decision::Deny
        };
        Verdict {
            decision,
            rule: None,
        }
    }
}

/// The exhaustive DoD 4 sweep: every row in [`DENY_SEAMS`], driven by
/// whichever driver its [`SeamKind`] calls for, denied with the
/// wire-shape-appropriate refusal and a matching audit record (module
/// doc) — and a final coverage assertion that the set of rows actually
/// driven equals the registry exactly (`PLAN.md` M5 Step 4 DoD 4's "add a
/// remote-facing deny seam without a registry row is a defect" made
/// concrete for the reverse direction too: add a row nobody drives, and
/// this test fails).
#[tokio::test(flavor = "multi_thread")]
async fn every_deny_seam_in_the_registry_denies_with_the_uniform_message() {
    let mut driven: BTreeSet<&'static str> = BTreeSet::new();

    // (a) SeamKind::ControlStreamOp, except session.attach.
    {
        let h = LoopbackHarness::start_with(Arc::new(DenyAll)).await;
        let mut s = h.session().await;
        for seam in DENY_SEAMS
            .iter()
            .filter(|seam| seam.kind == SeamKind::ControlStreamOp && seam.name != "session.attach")
        {
            let before = h.audit.records().len();
            let result = drive_control_stream_op(&mut s, seam.name).await;
            assert_denied(result, seam.name);
            assert_new_audit_deny_for_seam(&h.audit, before, seam);
            assert!(
                driven.insert(seam.name),
                "DENY_SEAMS has a duplicate row name {:?}",
                seam.name
            );
        }
        s.close();
        h.shutdown().await;
    }

    // (b) session.attach — its own harness instance: it plants a session
    // directly at the broker, which a shared session/harness above must
    // not be contaminated by.
    {
        let h = LoopbackHarness::start_with(Arc::new(DenyAll)).await;
        let seam = DENY_SEAMS
            .iter()
            .find(|s| s.name == "session.attach")
            .expect("DENY_SEAMS must have a session.attach row");
        let before = h.audit.records().len();
        let result = drive_session_attach(&h).await;
        assert_denied(result, "session.attach");
        assert_new_audit_deny_for_seam(&h.audit, before, seam);
        assert!(
            driven.insert("session.attach"),
            "duplicate session.attach drive"
        );
        h.shutdown().await;
    }

    // (c) SeamKind::TunnelInline: forward.local's inline TCP_CONNECT gate.
    {
        let seam = DENY_SEAMS
            .iter()
            .find(|s| s.name == "forward.local")
            .expect("DENY_SEAMS must have a forward.local row");
        assert_eq!(
            seam.kind,
            SeamKind::TunnelInline,
            "forward.local: this block only knows how to drive a TunnelInline seam — a \
             different SeamKind here means the registry row and this driver have drifted apart"
        );
        let h = TunnelHarness::start_with(Arc::new(DenyAll)).await;
        let before = h.audit().records().len();
        let result = h.tcp_connect("127.0.0.1", 9).await;
        assert!(!result.ok, "forward.local: ConnectResult.ok must be false");
        assert_eq!(
            result.code,
            ErrorCode::PermissionDenied.as_str(),
            "forward.local"
        );
        assert_eq!(
            result.message, PERMISSION_DENIED_MESSAGE,
            "forward.local: message must be the uniform PERMISSION_DENIED_MESSAGE, byte for byte"
        );
        assert_new_audit_deny_for_seam(h.audit(), before, seam);
        assert!(driven.insert(seam.name), "duplicate forward.local drive");
        h.shutdown().await;
    }

    // (d) SeamKind::ReverseRegistration: host.reverse's connection-time
    // registration check.
    {
        let seam = DENY_SEAMS
            .iter()
            .find(|s| s.name == "host.reverse")
            .expect("DENY_SEAMS must have a host.reverse row");
        assert_eq!(
            seam.kind,
            SeamKind::ReverseRegistration,
            "host.reverse: this block only knows how to drive a ReverseRegistration seam — a \
             different SeamKind here means the registry row and this driver have drifted apart"
        );
        let target = make_identity();
        let harness =
            ReverseHarness::start_with(Arc::new(DenyAll), false, pin(&target, "widget")).await;
        let before = harness.audit.records().len();
        let err = expect_hello_err(
            harness.register(&target, "widget").await,
            "DenyAll must deny host.reverse",
        );
        let (code, message, _retryable) = remote(err);
        assert_eq!(code, ErrorCode::PermissionDenied, "host.reverse");
        assert_eq!(
            message, PERMISSION_DENIED_MESSAGE,
            "host.reverse: message must be the uniform PERMISSION_DENIED_MESSAGE, byte for byte"
        );
        assert_new_audit_deny_for_seam(&harness.audit, before, seam);
        assert!(driven.insert(seam.name), "duplicate host.reverse drive");
        harness.shutdown().await;
    }

    // (e) SeamKind::StreamReset: the SessionData reattach inline gate.
    // Needs OpenOnlyDenyAttach, not DenyAll — see that struct's doc for
    // why a literal DenyAll can never make this seam reachable at all.
    {
        let seam = DENY_SEAMS
            .iter()
            .find(|s| s.name == "session.attach@data-stream")
            .expect("DENY_SEAMS must have the session.attach@data-stream row");
        assert_eq!(
            seam.kind,
            SeamKind::StreamReset,
            "session.attach@data-stream: this block only knows how to drive a StreamReset \
             seam — a different SeamKind here means the registry row and this driver have \
             drifted apart"
        );
        let h = LoopbackHarness::start_with(Arc::new(OpenOnlyDenyAttach)).await;
        let mut s = h.session().await;
        let opened = s
            .session_open(open_req())
            .await
            .expect("OpenOnlyDenyAttach allows session.open — only session.attach is denied");
        let before = h.audit.records().len();
        let (send, recv) = s
            .connection()
            .open_bi()
            .await
            .expect("open a SessionData stream");
        let mut data = FramedStream::data(send, recv);
        data.send
            .send(&wire::StreamHeader::session_data(opened.ticket.clone()))
            .await
            .expect("send StreamHeader");
        match data.recv.recv::<wire::SessionFrame>().await {
            Err(qsh_transport::StreamError::Read(qsh_transport::ReadError::Reset(code))) => {
                assert_eq!(
                    code.into_inner(),
                    u64::from(RESET_CODE_FORBIDDEN),
                    "session.attach@data-stream: wrong QUIC reset code"
                );
            }
            other => panic!(
                "session.attach@data-stream: expected the host to reset the stream with \
                 RESET_CODE_FORBIDDEN (no message — this seam is message-less by wire \
                 shape), got {other:?}"
            ),
        }
        assert_new_audit_deny_for_seam(&h.audit, before, seam);
        assert!(
            driven.insert(seam.name),
            "duplicate session.attach@data-stream drive"
        );
        s.close();
        h.shutdown().await;
    }

    // Coverage: the set of rows this test actually drove must equal
    // DENY_SEAMS exactly — no row left undriven, nothing driven that
    // is not (any longer) a registry row. This is the "exemption list is
    // empty" property PLAN.md M5 Step 4 DoD 4 asks for: there is no
    // separate documented-exemption branch anywhere in this file because
    // every row really is driven.
    let registry_names: BTreeSet<&'static str> = DENY_SEAMS.iter().map(|seam| seam.name).collect();
    assert_eq!(
        driven, registry_names,
        "every DENY_SEAMS row must be driven by exactly one driver in this test — a \
         mismatch means either a registry row was added with no driver wired up here, \
         or a driver here no longer corresponds to a registry row"
    );
}
