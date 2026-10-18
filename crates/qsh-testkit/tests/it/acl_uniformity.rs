//! L3 — M5 plan Step 4 (2473c88) DoD 4: every seam in
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
//! loudly, not silently. The exemption list this file owes DoD 4 of
//! The M5 plan (2473c88) is empty: every row in the registry is genuinely driven to a real
//! deny from testkit, including `session.attach` (see
//! [`drive_session_attach`]'s doc for how a `DenyAll` host — which also
//! denies `session.open` — still gets one to attach to) and
//! `session.attach@data-stream` (see [`OpenOnlyDenyAttach`]'s doc for why
//! that row cannot be driven under a literal `DenyAll` at all).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use qsh_core::acl::{
    Action, Authorizer, DENY_SEAMS, Decision, DenyAll, DenySeam, PERMISSION_DENIED_MESSAGE,
    Requester, ResourceRef, SeamKind, Verdict,
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
use qsh_transport::{Dialed, FramedStream, Principal, StaticTrust};

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
        // ACL gate (`Server::authorize_owned`, M5 plan Step 5 (2473c88)) always
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
        // The four remote file ops (ADR-0029): `Session` has no typed helper
        // for them yet, so they go out as raw control messages.
        "file.read" => {
            drive_file_op(
                s,
                wire::control_message::Body::FileReadOpen(wire::FileReadOpen {
                    path: FILE_PROBE_PATH.into(),
                    user: String::new(),
                }),
            )
            .await
        }
        "file.write" => {
            drive_file_op(
                s,
                wire::control_message::Body::FileWriteOpen(wire::FileWriteOpen {
                    path: FILE_PROBE_PATH.into(),
                    size: 1,
                    mode: 0o600,
                    ..Default::default()
                }),
            )
            .await
        }
        "file.list" => {
            drive_file_op(
                s,
                wire::control_message::Body::FileListOpen(wire::FileListOpen {
                    path: FILE_PROBE_PATH.into(),
                    ..Default::default()
                }),
            )
            .await
        }
        "file.mkdir" => {
            drive_file_op(
                s,
                wire::control_message::Body::FileMkdirOpen(wire::FileMkdirOpen {
                    path: FILE_PROBE_PATH.into(),
                    mode: 0o700,
                    ..Default::default()
                }),
            )
            .await
        }
        other => panic!(
            "drive_control_stream_op: DENY_SEAMS has a ControlStreamOp row {other:?} with no \
             driver in this match — teach acl_uniformity.rs how to drive it"
        ),
    }
}

/// An absolute path every host accepts at the shape check, so a file op
/// reaches the ACL choke point and is denied there, not rejected earlier.
#[cfg(unix)]
const FILE_PROBE_PATH: &str = "/srv/qsh-uniformity-probe/x";
#[cfg(windows)]
const FILE_PROBE_PATH: &str = "C:/srv/qsh-uniformity-probe/x";

/// Send one raw file-op request on `s`'s control stream and map the reply
/// the way the typed helpers do: an `Error` response is `ClientError::Remote`,
/// anything else is success.
async fn drive_file_op(
    s: &mut Session,
    body: wire::control_message::Body,
) -> Result<(), ClientError> {
    const REQUEST_ID: u64 = 9_000;
    s.send_control_message(&wire::ControlMessage::new(REQUEST_ID, body))
        .await?;
    loop {
        let msg = s
            .next_control_message()
            .await?
            .expect("the control stream stays open for the reply");
        if msg.request_id != REQUEST_ID {
            continue;
        }
        return match msg.body {
            Some(wire::control_message::Body::Response(wire::Response {
                body: Some(wire::response::Body::Error(e)),
            })) => Err(ClientError::Remote {
                code: e.error_code(),
                message: e.message,
                retryable: e.retryable,
            }),
            Some(wire::control_message::Body::Response(_)) => Ok(()),
            other => panic!("unexpected reply to a raw file op: {other:?}"),
        };
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
        _requester: &Requester<'_>,
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
            role: None,
        }
    }
}

/// A recording wrapper around a real deny authorizer
/// (M15 plan Step 3 (1a4af3b)): delegates every decision unchanged and notes which
/// `(action, connection fingerprint)` pairs it was asked about, so the sweep
/// can assert that each seam hands the authorizer the connection's own
/// fingerprint (ADR-0045 결정 6: the role stage compares it with the
/// current pin).
struct FingerprintProbe {
    seen: Mutex<Vec<(Action, Option<PeerFingerprint>)>>,
}

impl FingerprintProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
        })
    }

    /// An authorizer that records, then delegates to `inner`.
    fn wrapping(self: &Arc<Self>, inner: Arc<dyn Authorizer>) -> Arc<dyn Authorizer> {
        Arc::new(RecordingAuthorizer {
            inner,
            probe: Arc::clone(self),
        })
    }

    fn mark(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// Since `mark`, the authorizer was asked about `seam.action` with
    /// exactly `expected` as the connection fingerprint, and never with a
    /// different or absent one.
    fn assert_seam_saw(&self, mark: usize, seam: &DenySeam, expected: PeerFingerprint) {
        let seen = self.seen.lock().unwrap();
        let for_action: Vec<_> = seen[mark..]
            .iter()
            .filter(|(action, _)| *action == seam.action)
            .collect();
        assert!(
            !for_action.is_empty(),
            "{}: the authorizer was never asked about {:?}",
            seam.name,
            seam.action.as_str()
        );
        for (_, fingerprint) in for_action {
            assert_eq!(
                *fingerprint,
                Some(expected),
                "{}: the authorizer must receive the connection's own verified fingerprint",
                seam.name
            );
        }
    }
}

struct RecordingAuthorizer {
    inner: Arc<dyn Authorizer>,
    probe: Arc<FingerprintProbe>,
}

impl Authorizer for RecordingAuthorizer {
    fn check(
        &self,
        requester: &Requester<'_>,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> Verdict {
        self.probe
            .seen
            .lock()
            .unwrap()
            .push((action, requester.fingerprint));
        self.inner.check(requester, action, resource)
    }
}

/// The exhaustive DoD 4 sweep: every row in [`DENY_SEAMS`], driven by
/// whichever driver its [`SeamKind`] calls for, denied with the
/// wire-shape-appropriate refusal and a matching audit record (module
/// doc) — and a final coverage assertion that the set of rows actually
/// driven equals the registry exactly (M5 plan Step 4 (2473c88) DoD 4's "add a
/// remote-facing deny seam without a registry row is a defect" made
/// concrete for the reverse direction too: add a row nobody drives, and
/// this test fails).
#[tokio::test(flavor = "multi_thread")]
async fn every_deny_seam_in_the_registry_denies_with_the_uniform_message() {
    sweep(None).await;
}

/// M15 plan Step 3 (1a4af3b): every [`DENY_SEAMS`] row hands the authorizer the
/// verified fingerprint of the connection it arrived on. Same sweep as the
/// uniformity test above, with each host's authorizer wrapped in a
/// [`FingerprintProbe`]; after every seam is driven the probe must have
/// seen that seam's action with the driving identity's own fingerprint
/// (ADR-0045 결정 6, "호출 지점이 모두 `ConnCtx`에서 그 값을 넘긴다").
#[tokio::test(flavor = "multi_thread")]
async fn authorizer_receives_the_connection_fingerprint_at_every_call_site() {
    let probe = FingerprintProbe::new();
    sweep(Some(&probe)).await;
}

fn peer(fingerprint: &qsh_transport::Fingerprint) -> PeerFingerprint {
    PeerFingerprint::new(*fingerprint.as_bytes())
}

fn probe_mark(probe: Option<&Arc<FingerprintProbe>>) -> usize {
    probe.map_or(0, |p| p.mark())
}

fn probe_assert(
    probe: Option<&Arc<FingerprintProbe>>,
    mark: usize,
    seam: &DenySeam,
    fingerprint: &qsh_transport::Fingerprint,
) {
    if let Some(p) = probe {
        p.assert_seam_saw(mark, seam, peer(fingerprint));
    }
}

async fn sweep(probe: Option<&Arc<FingerprintProbe>>) {
    let wrap = |inner: Arc<dyn Authorizer>| match probe {
        Some(p) => p.wrapping(inner),
        None => inner,
    };
    let mut driven: BTreeSet<&'static str> = BTreeSet::new();

    // (a) SeamKind::ControlStreamOp, except session.attach.
    {
        let h = LoopbackHarness::start_with(wrap(Arc::new(DenyAll))).await;
        let mut s = h.session().await;
        for seam in DENY_SEAMS
            .iter()
            .filter(|seam| seam.kind == SeamKind::ControlStreamOp && seam.name != "session.attach")
        {
            let before = h.audit.records().len();
            let mark = probe_mark(probe);
            let result = drive_control_stream_op(&mut s, seam.name).await;
            assert_denied(result, seam.name);
            assert_new_audit_deny_for_seam(&h.audit, before, seam);
            probe_assert(probe, mark, seam, &h.client.fingerprint);
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
        let h = LoopbackHarness::start_with(wrap(Arc::new(DenyAll))).await;
        let seam = DENY_SEAMS
            .iter()
            .find(|s| s.name == "session.attach")
            .expect("DENY_SEAMS must have a session.attach row");
        let before = h.audit.records().len();
        let mark = probe_mark(probe);
        let result = drive_session_attach(&h).await;
        assert_denied(result, "session.attach");
        assert_new_audit_deny_for_seam(&h.audit, before, seam);
        probe_assert(probe, mark, seam, &h.client.fingerprint);
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
        let h = TunnelHarness::start_with(wrap(Arc::new(DenyAll))).await;
        let before = h.audit().records().len();
        let mark = probe_mark(probe);
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
        probe_assert(probe, mark, seam, &h.host.client.fingerprint);
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
            ReverseHarness::start_with(wrap(Arc::new(DenyAll)), false, pin(&target, "widget"))
                .await;
        let before = harness.audit.records().len();
        let mark = probe_mark(probe);
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
        probe_assert(probe, mark, seam, &target.fingerprint);
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
        let h = LoopbackHarness::start_with(wrap(Arc::new(OpenOnlyDenyAttach))).await;
        let mut s = h.session().await;
        let opened = s
            .session_open(open_req())
            .await
            .expect("OpenOnlyDenyAttach allows session.open — only session.attach is denied");
        let before = h.audit.records().len();
        let mark = probe_mark(probe);
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
        probe_assert(probe, mark, seam, &h.client.fingerprint);
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
    // empty" property M5 plan Step 4 (2473c88) DoD 4 asks for: there is no
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

// --- M15 plan Step 4 (1a4af3b): the role stage denies exactly like the rest ---------

/// A sandbox `trust.toml` pinning `fingerprint` as `name` with an optional
/// role, plus the production authorizer over it (`load_or_deny`; no
/// `acl.toml`, so the role is the only grant).
struct RoleSandbox {
    _dir: tempfile::TempDir,
    paths: qsh_core::config::Paths,
    trust: Arc<qsh_core::trust::SharedTrustStore>,
}

fn pin_block(name: &str, fingerprint: &qsh_transport::Fingerprint, role: Option<&str>) -> String {
    let role = role.map_or(String::new(), |r| format!("role = \"{r}\"\n"));
    format!(
        "[[peer]]\nname = \"{name}\"\nfingerprint = \"{fingerprint}\"\naddress = \"\"\n\
         added_at = \"2026-10-14T00:00:00Z\"\n{role}\n"
    )
}

impl RoleSandbox {
    fn new(name: &str, fingerprint: &qsh_transport::Fingerprint, role: Option<&str>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths =
            qsh_core::config::Paths::new(dir.path().join("config"), dir.path().join("state"));
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        std::fs::write(paths.trust_file(), pin_block(name, fingerprint, role))
            .expect("write trust.toml");
        let trust =
            qsh_core::trust::SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");
        Self {
            _dir: dir,
            paths,
            trust,
        }
    }

    fn authorizer(&self, role: qsh_core::acl::Role) -> Arc<dyn Authorizer> {
        qsh_core::acl::load_or_deny(&self.paths, role, Arc::clone(&self.trust)).0
    }

    fn break_trust_toml(&self) {
        std::fs::write(self.paths.trust_file(), "[[peer]]\nname = ").expect("break trust.toml");
    }
}

/// Drive every `ControlStreamOp` row (except those in `skip`) and require the
/// uniform refusal plus a deny audit record under the row's own action.
/// `session.attach` is driven through its dedicated path unless skipped.
async fn assert_control_rows_denied(h: &LoopbackHarness, skip: &[&str], situation: &str) {
    let mut s = h.session().await;
    for seam in DENY_SEAMS.iter().filter(|seam| {
        seam.kind == SeamKind::ControlStreamOp
            && seam.name != "session.attach"
            && !skip.contains(&seam.name)
    }) {
        let before = h.audit.records().len();
        let result = drive_control_stream_op(&mut s, seam.name).await;
        assert_denied(result, &format!("{situation}: {}", seam.name));
        assert_new_audit_deny_for_seam(&h.audit, before, seam);
    }
    s.close();
    if !skip.contains(&"session.attach") {
        assert_denied(
            drive_session_attach(h).await,
            &format!("{situation}: session.attach"),
        );
    }
}

/// A peer with no role, a peer whose role does not cover the action, and a
/// peer whose role was suspended by a broken `trust.toml` reload are all
/// refused with the byte-identical `PERMISSION_DENIED_MESSAGE` and an audit
/// deny under the row's own action. Nothing on the wire tells them apart
/// (ADR-0045 결정 16, "거부는 균일").
#[tokio::test(flavor = "multi_thread")]
async fn role_absent_out_of_scope_and_reload_failure_denials_are_uniform() {
    use qsh_core::acl::Role;

    // (a) no role: the pin has no `role` key.
    {
        let client = make_identity();
        let sandbox = RoleSandbox::new("laptop", &client.fingerprint, None);
        let h = LoopbackHarness::start_custom(
            sandbox.authorizer(Role::Serve),
            client.clone(),
            pin(&client, "laptop"),
        )
        .await;
        assert_control_rows_denied(&h, &[], "no role").await;
        h.shutdown().await;

        let t = TunnelHarness::start_custom(
            sandbox.authorizer(Role::Serve),
            client.clone(),
            pin(&client, "laptop"),
        )
        .await;
        let result = t.tcp_connect("127.0.0.1", 9).await;
        assert!(!result.ok);
        assert_eq!(
            result.message, PERMISSION_DENIED_MESSAGE,
            "no role: forward.local"
        );
        t.shutdown().await;

        let target = make_identity();
        let sandbox = RoleSandbox::new("widget", &target.fingerprint, None);
        let harness = ReverseHarness::start_with(
            sandbox.authorizer(Role::Listen),
            false,
            pin(&target, "widget"),
        )
        .await;
        let (code, message, _) = remote(expect_hello_err(
            harness.register(&target, "widget").await,
            "no role must deny host.reverse",
        ));
        assert_eq!(code, ErrorCode::PermissionDenied);
        assert_eq!(message, PERMISSION_DENIED_MESSAGE, "no role: host.reverse");
        harness.shutdown().await;
    }

    // (b) out of scope: `read-only` covers the session reads, nothing else.
    {
        let client = make_identity();
        let sandbox = RoleSandbox::new("laptop", &client.fingerprint, Some("read-only"));
        let h = LoopbackHarness::start_custom(
            sandbox.authorizer(Role::Serve),
            client.clone(),
            pin(&client, "laptop"),
        )
        .await;
        // `session.list` (and its `session.get`), `session.read` and
        // `session.attach` are what the role grants; the rest is refused.
        assert_control_rows_denied(
            &h,
            &[
                "session.list",
                "session.get",
                "session.read",
                "session.attach",
            ],
            "out of scope",
        )
        .await;
        h.shutdown().await;

        let t = TunnelHarness::start_custom(
            sandbox.authorizer(Role::Serve),
            client.clone(),
            pin(&client, "laptop"),
        )
        .await;
        let result = t.tcp_connect("127.0.0.1", 9).await;
        assert!(!result.ok);
        assert_eq!(
            result.message, PERMISSION_DENIED_MESSAGE,
            "out of scope: forward.local"
        );
        t.shutdown().await;
    }

    // (c) reload failure: `full` worked until `trust.toml` stopped parsing.
    {
        let client = make_identity();
        let sandbox = RoleSandbox::new("laptop", &client.fingerprint, Some("full"));
        let h = LoopbackHarness::start_custom(
            sandbox.authorizer(Role::Serve),
            client.clone(),
            pin(&client, "laptop"),
        )
        .await;
        let mut s = h.session().await;
        s.session_list()
            .await
            .expect("the role is in effect before the edit");
        s.close();
        sandbox.break_trust_toml();
        assert_control_rows_denied(&h, &[], "reload failure").await;
        h.shutdown().await;

        let t = TunnelHarness::start_custom(
            sandbox.authorizer(Role::Serve),
            client.clone(),
            pin(&client, "laptop"),
        )
        .await;
        let result = t.tcp_connect("127.0.0.1", 9).await;
        assert!(!result.ok);
        assert_eq!(
            result.message, PERMISSION_DENIED_MESSAGE,
            "reload failure: forward.local"
        );
        t.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// The file ops' policy outcomes are one denial (ADR-0029 decision 17).
// ---------------------------------------------------------------------------

/// The four file requests for `path`, as `(seam name, body)`.
#[cfg(unix)]
fn file_bodies(path: &str) -> [(&'static str, wire::control_message::Body); 4] {
    use wire::control_message::Body;
    [
        (
            "file.read",
            Body::FileReadOpen(wire::FileReadOpen {
                path: path.into(),
                user: String::new(),
            }),
        ),
        (
            "file.write",
            Body::FileWriteOpen(wire::FileWriteOpen {
                path: path.into(),
                size: 1,
                mode: 0o600,
                overwrite: true,
                ..Default::default()
            }),
        ),
        (
            "file.list",
            Body::FileListOpen(wire::FileListOpen {
                path: path.into(),
                ..Default::default()
            }),
        ),
        (
            "file.mkdir",
            Body::FileMkdirOpen(wire::FileMkdirOpen {
                path: path.into(),
                mode: 0o700,
                ..Default::default()
            }),
        ),
    ]
}

/// A normalizer that folds `.` and `..` lexically and follows no symlink:
/// the stand-in for "the path looked fine when it was normalized" that the
/// opened-handle recheck exists for.
#[cfg(unix)]
struct LexicalNormalizer;

#[cfg(unix)]
impl qsh_core::file::guard::Normalizer for LexicalNormalizer {
    fn normalize(
        &self,
        absolute: &std::path::Path,
    ) -> Result<std::path::PathBuf, qsh_core::file::guard::NormalizeError> {
        let mut out = std::path::PathBuf::new();
        for component in absolute.components() {
            match component {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::CurDir => {}
                other => out.push(other.as_os_str()),
            }
        }
        Ok(out)
    }
}

/// Start a host that grants `laptop` the file actions with `paths`, wired to
/// a state tree under `root`, and drive every path in `paths_to_try` through
/// all four file seams. Returns each reply's `(code, message)`.
#[cfg(unix)]
async fn file_denials(
    root: &std::path::Path,
    grant_paths: Option<Vec<String>>,
    lexical: bool,
    paths_to_try: &[String],
) -> Vec<(ErrorCode, String)> {
    use qsh_core::acl::{ActionPattern, Policy, Rule, Scope};
    use qsh_testkit::pair::HostedPair;

    let policy = Policy {
        rules: vec![Rule {
            principal: Principal::Device("laptop".into()).to_string(),
            auth_path: qsh_transport::AuthPath::Pin,
            allow: vec![
                ActionPattern::Exact(Action::FileRead),
                ActionPattern::Exact(Action::FileWrite),
            ],
            scope: Scope::Any,
            paths: grant_paths,
        }],
    };
    let h = LoopbackHarness::start_with(Arc::new(policy)).await;
    let paths = qsh_core::config::Paths::new(root.join("host/config"), root.join("host/state"))
        .with_runtime_dir(root.join("host/run"));
    h.server()
        .set_file_host(paths, qsh_core::config::AuditConfig::default());
    if lexical {
        h.server().set_path_normalizer(
            Arc::new(LexicalNormalizer) as Arc<dyn qsh_core::file::guard::Normalizer>
        );
    }
    let mut s = h.session().await;
    let mut out = Vec::new();
    for path in paths_to_try {
        for (seam, body) in file_bodies(path) {
            match drive_file_op(&mut s, body).await {
                Err(ClientError::Remote { code, message, .. }) => out.push((code, message)),
                other => panic!("{seam} {path}: expected a remote refusal, got {other:?}"),
            }
        }
    }
    h.shutdown().await;
    out
}

/// A request outside `paths`, a row without `paths`, a path that cannot be
/// normalized, a state path, and a symlink swapped in under a lexically
/// fine path (the recheck) all answer the same `PERMISSION_DENIED` with the
/// same message, on each of the four file seams: nothing in the reply says
/// which check refused (ADR-0029 decision 17).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn file_policy_outcomes_all_answer_the_same_denial() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = std::fs::canonicalize(dir.path()).expect("canonical tempdir");
    for sub in [
        "share",
        "outside/sub",
        "host/config",
        "host/state",
        "host/run",
    ] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    std::fs::write(root.join("share/a.txt"), b"a").unwrap();
    std::fs::write(root.join("outside/secret.txt"), b"s").unwrap();
    std::fs::write(root.join("outside/sub/new.txt"), b"n").unwrap();
    std::fs::write(root.join("host/config/trust.toml"), b"t").unwrap();
    std::os::unix::fs::symlink(root.join("outside"), root.join("share/swap")).unwrap();
    let share = root.join("share").display().to_string();
    let p = |rel: &str| format!("{}/{rel}", root.display());

    let mut replies: Vec<(&str, Vec<(ErrorCode, String)>)> = Vec::new();
    // Outside `paths`, and a path whose normalization fails (a file used as
    // a directory).
    replies.push((
        "outside paths / normalization failure",
        file_denials(
            &root,
            Some(vec![share.clone()]),
            false,
            &[p("outside/secret.txt"), p("share/a.txt/x")],
        )
        .await,
    ));
    // A row without `paths`.
    replies.push((
        "row without paths",
        file_denials(&root, None, false, &[p("share/a.txt")]).await,
    ));
    // The broadest grant, aimed at the state tree.
    replies.push((
        "state path",
        file_denials(
            &root,
            Some(vec!["/".to_string()]),
            false,
            &[p("host/config/trust.toml"), p("host/state")],
        )
        .await,
    ));
    // A symlink the normalizer did not see: only the recheck catches it.
    replies.push((
        "recheck mismatch",
        file_denials(
            &root,
            Some(vec![share]),
            true,
            &[p("share/swap/sub/new.txt")],
        )
        .await,
    ));

    for (situation, list) in &replies {
        assert!(!list.is_empty(), "{situation}");
        for (code, message) in list {
            assert_eq!(*code, ErrorCode::PermissionDenied, "{situation}");
            assert_eq!(message, PERMISSION_DENIED_MESSAGE, "{situation}");
        }
    }
    let total: usize = replies.iter().map(|(_, l)| l.len()).sum();
    assert_eq!(total, 4 * 6, "four seams over six requests");
}
