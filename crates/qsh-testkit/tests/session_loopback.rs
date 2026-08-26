//! L3 loopback end-to-end for the `session.*` value ops (PLAN M2 Step 3):
//! pinned mTLS handshake → `Hello` → `SessionOpen` → ACL + audit → broker
//! session + `SESSION_DATA` ticket → write / read (`--after`, `--wait`) /
//! resize / get / list / close, all over a real QUIC connection against a
//! pipe-backed session (`docs/design/testing.md` §3). Zero PTY code.
//!
//! Every scenario below is a generic `async fn<P: HostedPair>(h: P)` run
//! twice — once against [`LoopbackHarness`] (forward: the client dials the
//! host) and once against [`ReversePairHarness`] (reverse: the target
//! dials the controller, and *it* is the host; the controller drives ops
//! as the client-role peer) — with the identical body and identical
//! assertions in both. That is the mechanical proof of role-axis
//! independence `PLAN.md` M3 Step 3 PR 3b owes: the `session.*` `Ops` code
//! never learns which side dialed.

use std::sync::Arc;

use qsh_core::acl::{Action, AllowAllPinned, DenyAll};
use qsh_core::client::{ClientError, Session};
use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, StreamHeader, session_read_event};
use qsh_testkit::HostedPair;
use qsh_testkit::loopback::{LoopbackHarness, TestIdentity, make_identity};
use qsh_testkit::reverse::ReversePairHarness;
use qsh_transport::{Dialer, FramedStream, Principal, StaticTrust};

fn open_req(argv: &[&str]) -> wire::SessionOpen {
    wire::SessionOpen {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: [("QSH_TEST".to_string(), "1".to_string())]
            .into_iter()
            .collect(),
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

fn remote_code(err: ClientError) -> ErrorCode {
    match err {
        ClientError::Remote { code, .. } => code,
        other => panic!("expected a remote error, got {other:?}"),
    }
}

/// Every session op body, addressed at `id`, for the choke-point sweeps.
async fn each_op(s: &mut Session, id: &str) -> Vec<(&'static str, Result<(), ClientError>)> {
    let mut out = Vec::new();
    out.push(("open", s.session_open(open_req(&["sh"])).await.map(|_| ())));
    out.push(("list", s.session_list().await.map(|_| ())));
    out.push(("get", s.session_get(id).await.map(|_| ())));
    out.push((
        "read",
        s.session_read(wire::SessionRead {
            session_id: id.into(),
            ..Default::default()
        })
        .await
        .map(|_| ()),
    ));
    out.push((
        "write",
        s.session_write(id, b"x".to_vec()).await.map(|_| ()),
    ));
    out.push(("resize", s.session_resize(id, 80, 24).await.map(|_| ())));
    out.push(("close", s.session_close(id, None).await.map(|_| ())));
    out
}

async fn session_full_path_open_write_read_resize_get_list_close<P: HostedPair>(h: P) {
    let mut s = h.session().await;

    // open → session + ticket; the pipe side is the "child".
    let opened = s.session_open(open_req(&["sh", "-l"])).await.unwrap();
    assert!(!opened.session_id.is_empty());
    assert_eq!(opened.initial_seq, 0);
    assert_eq!(
        opened.resume_token.len(),
        32,
        "session.open must issue a resume credential (protocol.md §10)"
    );
    assert_eq!(opened.ticket.len(), 16);
    assert!(!opened.expires_at.is_empty());
    let id = opened.session_id.clone();
    let (spec, mut pipe) = h
        .pipes()
        .take_with_spec()
        .expect("pipe handle for the session");
    // PLAN Step 3 (d): what follows `--` reaches the source verbatim, with
    // no shell re-interpretation anywhere on the path (CLI → SessionOpen →
    // wire → SessionSpec), and the rest of the spec survives with it.
    assert_eq!(spec.argv, vec!["sh".to_string(), "-l".to_string()]);
    assert_eq!(spec.term.as_deref(), Some("xterm-256color"));
    assert_eq!((spec.cols, spec.rows), (80, 24));
    assert_eq!(
        spec.env,
        vec![("QSH_TEST".to_string(), "1".to_string())],
        "extra env is layered through unchanged"
    );
    assert_eq!(spec.user, None, "no user@ hint was sent");
    assert_eq!(h.broker().session_count(), 1);
    assert_eq!(h.server().pending_tickets(), 1);

    // The child produces output; a long-poll read from 0 returns it.
    pipe.write_output(b"$ ").await.unwrap();
    let read = s
        .session_read(wire::SessionRead {
            session_id: id.clone(),
            after: 0,
            max_bytes: 0,
            wait_ms: 30_000,
            ctl_after: 0,
        })
        .await
        .unwrap();
    assert_eq!(read.next_after, 2, "the reply carries the resume cursor");
    let mut bytes = Vec::new();
    let mut seq = 0;
    for e in &read.events {
        if let Some(session_read_event::Body::Output(o)) = &e.body {
            bytes.extend_from_slice(&o.data);
            seq = o.sequence;
        }
    }
    assert_eq!(bytes, b"$ ");
    assert_eq!(seq, 2);

    // write → the child sees the input.
    let n = s.session_write(&id, b"echo hi\n".to_vec()).await.unwrap();
    assert_eq!(n, 8);
    assert_eq!(pipe.read_input(64).await.unwrap(), b"echo hi\n");

    // --after past everything, no wait: no output, no error.
    let read = s
        .session_read(wire::SessionRead {
            session_id: id.clone(),
            after: 2,
            max_bytes: 0,
            wait_ms: 0,
            ctl_after: 0,
        })
        .await
        .unwrap();
    assert!(
        read.events
            .iter()
            .all(|e| !matches!(e.body, Some(session_read_event::Body::Output(_))))
    );
    // The write took the writer lease, so a control entry sits at exactly
    // offset 2. A stateless re-read is handed it again; echoing the
    // returned control cursor back makes the same read empty — the
    // property a `--wait` poll loop depends on (protocol.md §9).
    assert!(!read.events.is_empty(), "writer_changed at offset 2");
    let again = s
        .session_read(wire::SessionRead {
            session_id: id.clone(),
            after: read.next_after,
            max_bytes: 0,
            wait_ms: 0,
            ctl_after: read.next_ctl_after,
        })
        .await
        .unwrap();
    assert!(again.events.is_empty(), "{:?}", again.events);
    assert_eq!(again.next_ctl_after, read.next_ctl_after);

    // --after beyond the end is INVALID_ARGUMENT, not NOT_FOUND.
    let err = s
        .session_read(wire::SessionRead {
            session_id: id.clone(),
            after: 99,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::InvalidArgument);

    // resize reaches the child; get/list reflect the state.
    assert_eq!(s.session_resize(&id, 132, 43).await.unwrap(), (132, 43));
    assert_eq!(pipe.resizes(), vec![(132, 43)]);
    let info = s.session_get(&id).await.unwrap();
    assert_eq!(info.session_id, id);
    assert_eq!(info.state, "running");
    assert_eq!(info.writer.as_deref(), Some("device:laptop"));
    assert_eq!(info.last_sequence, 2);
    let list = s.session_list().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].session_id, id);

    // close: HUP reaches the child, the session is gone, final_seq = 2.
    let final_seq = s.session_close(&id, Some("TERM".into())).await.unwrap();
    assert_eq!(final_seq, 2);
    assert_eq!(pipe.signals(), vec![qsh_core::broker::Signal::Term]);
    assert_eq!(h.broker().session_count(), 0);
    let err = s.session_get(&id).await.unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::SessionNotFound);
    // …but a late reader still drains exit + closed.
    let late = s
        .session_read(wire::SessionRead {
            session_id: id.clone(),
            after: 2,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(late.events.iter().any(|e| matches!(
        &e.body,
        Some(session_read_event::Body::Exit(x)) if x.signal.as_deref() == Some("SIGTERM")
    )));
    assert!(matches!(
        late.events.last().map(|e| &e.body),
        Some(Some(session_read_event::Body::Closed(c))) if c.reason == "closed"
    ));

    // The unredeemed session ticket is still outstanding until the
    // connection goes away; the audit log has one structural line per op.
    assert_eq!(h.server().pending_tickets(), 1);
    let recs = h.audit().records();
    let actions: Vec<&str> = recs.iter().map(|r| r.action.as_str()).collect();
    assert_eq!(
        actions,
        vec![
            Action::SessionOpen.as_str(),    // open
            Action::SessionAttach.as_str(),  // read
            Action::SessionControl.as_str(), // write
            Action::SessionAttach.as_str(),  // read
            Action::SessionAttach.as_str(),  // read (same cursor, echoed)
            Action::SessionAttach.as_str(),  // read (beyond end)
            Action::SessionControl.as_str(), // resize
            Action::SessionList.as_str(),    // get
            Action::SessionList.as_str(),    // list
            Action::SessionControl.as_str(), // close
            Action::SessionList.as_str(),    // get (not found)
            Action::SessionAttach.as_str(),  // read (late)
        ]
    );
    assert!(recs.iter().all(|r| r.decision == "allow"));
    assert!(recs.iter().all(|r| r.principal == "device:laptop"));
    assert!(
        recs.iter()
            .skip(1)
            .all(|r| r.resource == id || r.resource == "session")
    );
    // Structural only: no payload ever reaches the audit log.
    let dump = format!("{recs:?}");
    assert!(!dump.contains("echo hi"));

    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_full_path_open_write_read_resize_get_list_close_forward() {
    session_full_path_open_write_read_resize_get_list_close(LoopbackHarness::start().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_full_path_open_write_read_resize_get_list_close_reverse() {
    session_full_path_open_write_read_resize_get_list_close(ReversePairHarness::start().await)
        .await;
}

async fn sessions_survive_the_connection_and_leases_are_released<P: HostedPair>(h: P) {
    let mut s = h.session().await;
    let opened = s.session_open(open_req(&["sh"])).await.unwrap();
    let id = opened.session_id.clone();
    let _pipe = h.pipes().take().unwrap();
    s.session_write(&id, b"a".to_vec()).await.unwrap();
    assert_eq!(
        s.session_get(&id).await.unwrap().writer.as_deref(),
        Some("device:laptop")
    );
    s.close();

    // A fresh connection sees the same session, writer released, ticket
    // of the old connection purged.
    let mut s2 = h.session().await;
    let info = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let info = s2.session_get(&id).await.unwrap();
            if info.writer.is_none() {
                return info;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lease released after the connection went away");
    assert_eq!(info.state, "running");
    assert_eq!(h.broker().session_count(), 1);
    s2.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_survive_the_connection_and_leases_are_released_forward() {
    sessions_survive_the_connection_and_leases_are_released(LoopbackHarness::start().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_survive_the_connection_and_leases_are_released_reverse() {
    sessions_survive_the_connection_and_leases_are_released(ReversePairHarness::start().await)
        .await;
}

/// The redeemable-once `SESSION_DATA` ticket: valid → the host consumes it
/// and runs the pump (the stream delivers real output); bogus → reset with
/// the bad-header code, nothing touched.
async fn session_data_ticket_is_consumed_exactly_once<P: HostedPair>(h: P) {
    let mut s = h.session().await;
    let opened = s.session_open(open_req(&["sh"])).await.unwrap();
    let mut pipe = h.pipes().take().unwrap();
    assert_eq!(h.server().pending_tickets(), 1);

    let (send, recv) = s.connection().open_bi().await.unwrap();
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&StreamHeader::session_data(opened.ticket.clone()))
        .await
        .unwrap();
    pipe.write_output(b"live").await.unwrap();
    let frame = data
        .recv
        .recv::<wire::SessionFrame>()
        .await
        .unwrap()
        .expect("the pump answers a redeemed ticket");
    assert_eq!(
        frame.body,
        Some(wire::session_frame::Body::Output(wire::Output {
            sequence: 4,
            data: b"live".to_vec(),
        }))
    );
    assert_eq!(h.server().pending_tickets(), 0, "ticket consumed");

    // Replaying the same ticket, or presenting it on an EXEC_DATA header,
    // is refused.
    for header in [
        StreamHeader::session_data(opened.ticket.clone()),
        StreamHeader::exec_data(opened.ticket.clone()),
    ] {
        let (send, recv) = s.connection().open_bi().await.unwrap();
        let mut data = FramedStream::data(send, recv);
        data.send.send(&header).await.unwrap();
        assert!(data.recv.recv::<wire::SessionFrame>().await.is_err());
    }
    // Opening the data stream *is* an attach, and `session.open` only
    // authorized opening — so redeeming its ticket runs (and audits) the
    // `session.attach` decision too. Two decisions, no more: the two
    // refused replays above are ticket failures, not ACL decisions.
    let actions: Vec<String> = h
        .audit()
        .records()
        .iter()
        .map(|r| r.action.clone())
        .collect();
    assert_eq!(actions, ["session.open", "session.attach"], "{actions:?}");
    assert_eq!(h.broker().session_count(), 1);
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_data_ticket_is_consumed_exactly_once_forward() {
    session_data_ticket_is_consumed_exactly_once(LoopbackHarness::start().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_data_ticket_is_consumed_exactly_once_reverse() {
    session_data_ticket_is_consumed_exactly_once(ReversePairHarness::start().await).await;
}

/// Under `DenyAll` every session op is `PERMISSION_DENIED`, nothing is
/// created (no session, no ticket, no pipe), and — the non-distinguishing
/// property — an unauthorized peer gets the *same* answer for a real and a
/// fabricated session id, so it cannot learn whether a session exists.
async fn denied_peer_cannot_learn_whether_a_session_exists<P: HostedPair>(h: P) {
    // Plant a real session behind the deny-all host through the broker.
    let real = h
        .broker()
        .open(&qsh_core::broker::SessionSpec {
            argv: vec!["sh".into()],
            env: vec![],
            term: None,
            cols: 80,
            rows: 24,
            user: None,
        })
        .unwrap()
        .id()
        .to_string();
    let _pipe = h.pipes().take().unwrap();
    let mut s = h.session().await;

    let mut answers: Vec<Vec<(&str, ErrorCode)>> = Vec::new();
    for id in [real.as_str(), "01K0NOSUCHSESSION"] {
        let results = each_op(&mut s, id).await;
        answers.push(
            results
                .into_iter()
                .map(|(name, r)| (name, remote_code(r.unwrap_err())))
                .collect(),
        );
    }
    assert!(
        answers[0]
            .iter()
            .all(|(_, code)| *code == ErrorCode::PermissionDenied)
    );
    assert_eq!(
        answers[0], answers[1],
        "existence must not be distinguishable"
    );
    assert_eq!(h.broker().session_count(), 1, "nothing created");
    assert_eq!(h.pipes().pending(), 0);
    assert_eq!(h.server().pending_tickets(), 0);
    let recs = h.audit().records();
    assert_eq!(recs.len(), 14, "one structural line per op");
    assert!(recs.iter().all(|r| r.decision == "deny"));
    let dump = format!("{recs:?}");
    assert!(!dump.contains("sh\""), "no argv in the audit log");
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_peer_cannot_learn_whether_a_session_exists_forward() {
    denied_peer_cannot_learn_whether_a_session_exists(
        LoopbackHarness::start_with(Arc::new(DenyAll)).await,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_peer_cannot_learn_whether_a_session_exists_reverse() {
    denied_peer_cannot_learn_whether_a_session_exists(
        ReversePairHarness::start_with(Arc::new(DenyAll)).await,
    )
    .await;
}

/// `session.attach` for an unknown id is the same non-distinguishing
/// `AUTH_FAILED` a wrong credential gets (protocol.md §10-2) — decided
/// after mode validation, audited as a deny, with nothing created. The
/// unknown id never reaches the broker, so existence is not disclosed.
///
/// Drives the raw control stream (via [`HostedPair::raw_session`]) so the
/// wire shape itself is under test, not the typed client wrapper — the
/// `Hello` exchange to get there is `qsh_core::handshake::initiate`/
/// `respond` (product code) rather than a hand-rolled frame, which is what
/// makes this parametrizable: in reverse, only the *host* side (`qsh
/// listen`'s equivalent) accepts, and it never opens the raw stream itself.
async fn attach_to_an_unknown_session_creates_nothing<P: HostedPair>(h: P) {
    let (conn, mut ctl) = h.raw_session().await;
    ctl.send
        .send(&wire::ControlMessage::new(
            1,
            wire::control_message::Body::SessionAttach(wire::SessionAttach {
                session_id: "01K0NOSUCHSESSION".into(),
                // A well-formed credential for a session that does not
                // exist: the answer must not differ from the one a real id
                // with a stale token gets.
                resume_token: vec![7u8; 32],
                mode: wire::AttachMode::Rw as i32,
                ..Default::default()
            }),
        ))
        .await
        .unwrap();
    let reply = ctl
        .recv
        .recv::<wire::ControlMessage>()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.request_id, 1);
    match reply.body {
        Some(wire::control_message::Body::Response(wire::Response {
            body: Some(wire::response::Body::Error(e)),
        })) => assert_eq!(e.error_code(), ErrorCode::AuthFailed),
        other => panic!("expected AUTH_FAILED, got {other:?}"),
    }
    // The refusal is audited structurally, and nothing was created.
    let recs = h.audit().records();
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0].action, "session.attach");
    assert_eq!(recs[0].resource, "01K0NOSUCHSESSION");
    assert_eq!(recs[0].decision, "deny");
    assert_eq!(h.server().pending_tickets(), 0);
    assert_eq!(h.broker().session_count(), 0);
    conn.close(0, b"done");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_to_an_unknown_session_creates_nothing_forward() {
    attach_to_an_unknown_session_creates_nothing(LoopbackHarness::start().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_to_an_unknown_session_creates_nothing_reverse() {
    attach_to_an_unknown_session_creates_nothing(ReversePairHarness::start().await).await;
}

// ==========================================================================
// Session ownership (`PLAN.md` Step 3.5 PR②, PRD §6, audit A2 P0):
// `session.write`/`session.resize` bind to the session's opener.
// Forward-only, same reason `resume_loopback.rs`'s multi-principal section
// gives — a reverse target has exactly one peer, ever, so there is no
// second, distinct principal to test ownership against.
// ==========================================================================

/// A second pinned device: its own dialer, its own connection, its own
/// principal. Mirrors `resume_loopback.rs`'s `other_device` (private to
/// each file — the pattern, not the function, is what's shared).
async fn other_device(h: &LoopbackHarness, identity: &TestIdentity) -> Session {
    let client_trust = StaticTrust::empty().with_pin(
        h.server_identity.fingerprint,
        Principal::Device("box".into()),
    );
    let dialer = Dialer::new(identity.local.clone(), Arc::new(client_trust));
    let dialed = dialer
        .dial(h.addr, "127.0.0.1")
        .await
        .expect("the second device is pinned");
    Session::negotiate(dialed.connection, "desktop")
        .await
        .expect("negotiate")
}

/// `session.write`/`session.resize` are refused to every principal but the
/// session's opener, with the **identical** `PERMISSION_DENIED` an ACL
/// policy deny for `session.control` would produce — a peer must not be
/// able to tell "this session exists but is someone else's" from "the
/// policy forbids this" — and each refusal is audited as a
/// `session.control` deny. The opener itself is unaffected.
#[tokio::test(flavor = "multi_thread")]
async fn session_control_binds_write_and_resize_to_the_opener() {
    let owner = make_identity();
    let other = make_identity();
    let server_trust = StaticTrust::empty()
        .with_pin(owner.fingerprint, Principal::Device("laptop".into()))
        .with_pin(other.fingerprint, Principal::Device("desktop".into()));
    let h = LoopbackHarness::start_custom(Arc::new(AllowAllPinned), owner, server_trust).await;

    let mut s = h.session().await;
    let opened = s.session_open(open_req(&["sh"])).await.unwrap();
    let id = opened.session_id.clone();
    let _pipe = h.pipes().take().expect("pipe handle for the session");

    let mut desktop = other_device(&h, &other).await;

    for (name, result) in [
        (
            "write",
            desktop.session_write(&id, b"x".to_vec()).await.map(|_| ()),
        ),
        (
            "resize",
            desktop.session_resize(&id, 80, 24).await.map(|_| ()),
        ),
    ] {
        match result {
            Err(ClientError::Remote { code, message, .. }) => {
                assert_eq!(code, ErrorCode::PermissionDenied, "{name}");
                assert_eq!(
                    message, "peer is not allowed to session.control on this host",
                    "{name}: message must match an ACL policy deny byte-for-byte"
                );
            }
            other => panic!("{name}: expected PERMISSION_DENIED, got {other:?}"),
        }
    }

    // Both refusals are audited structurally as `session.control` denies
    // against the foreign principal — exactly one record per op
    // (`Server::authorize_session_control` folds the ACL check and the
    // ownership check into a single terminal decision, so a foreign
    // principal's refusal never also shows up as an `allow`).
    let recs = h.audit().records();
    let desktop_recs: Vec<_> = recs
        .iter()
        .filter(|r| r.principal == "device:desktop")
        .collect();
    assert_eq!(desktop_recs.len(), 2, "{recs:?}");
    assert!(desktop_recs.iter().all(|r| r.decision == "deny"));
    assert!(
        desktop_recs
            .iter()
            .all(|r| r.action == Action::SessionControl.as_str())
    );
    assert!(desktop_recs.iter().all(|r| r.resource == id));

    // The owner's own write/resize are unaffected.
    assert_eq!(s.session_write(&id, b"y".to_vec()).await.unwrap(), 1);
    assert_eq!(s.session_resize(&id, 100, 30).await.unwrap(), (100, 30));

    desktop.close();
    s.close();
    h.shutdown().await;
}

/// Not a real posture — `AllowAllPinned` denies every CA-authenticated
/// peer for good (`acl/mod.rs` doc) — but exactly what `require_opener`'s
/// own doc says the ownership binding must survive: a future M5 policy
/// that admits a CA-authenticated peer for `session.control` too.
struct AllowAllAnyAuthPath;

impl qsh_core::acl::Authorizer for AllowAllAnyAuthPath {
    fn check(
        &self,
        _principal: &Principal,
        _auth_path: qsh_transport::AuthPath,
        _action: Action,
        _resource: &str,
    ) -> qsh_core::acl::Verdict {
        qsh_core::acl::Verdict {
            decision: qsh_core::acl::Decision::Allow,
            rule: None,
        }
    }
}

/// A CA-issued leaf asserting the pinned opener's own principal
/// (`qsh://device/laptop`, same as the pin) must still be refused
/// ownership: `Principal`'s `Display` alone cannot tell a pin from a CA
/// leaf (`qsh-transport::tls::AuthPath`'s doc), so the binding has to key
/// on `(principal, auth_path)`, not `principal.to_string()` alone
/// (`PLAN.md` Step 3.5 PR② review). Forward-only for the same reason the
/// two-principal ownership tests above are: this is about the ownership
/// gate, not role symmetry.
#[tokio::test(flavor = "multi_thread")]
async fn ca_leaf_asserting_the_opener_principal_is_still_denied_ownership() {
    let owner = make_identity();
    let ca = qsh_testkit::loopback::make_ca();
    let spoofer_identity = ca.issue("qsh://device/laptop");
    let server_trust = StaticTrust::empty()
        .with_pin(owner.fingerprint, Principal::Device("laptop".into()))
        .with_ca(ca.root_der.clone());
    let h = LoopbackHarness::start_custom(Arc::new(AllowAllAnyAuthPath), owner, server_trust).await;

    let mut s = h.session().await;
    let opened = s.session_open(open_req(&["sh"])).await.unwrap();
    let id = opened.session_id.clone();
    let _pipe = h.pipes().take().expect("pipe handle for the session");

    let client_trust = StaticTrust::empty().with_pin(
        h.server_identity.fingerprint,
        Principal::Device("box".into()),
    );
    let dialer = Dialer::new(spoofer_identity.local.clone(), Arc::new(client_trust));
    let dialed = dialer
        .dial(h.addr, "127.0.0.1")
        .await
        .expect("the host's CA root trusts this leaf");
    // `Connection::principal()` is the *peer's* authenticated principal —
    // on the dialer side that is the host's ("box"), not what the host
    // assigned this leaf. The audit assertion below is what actually
    // proves the host classified this CA leaf as `device:laptop`, same as
    // the pin.
    let mut spoofer = Session::negotiate(dialed.connection, "desktop")
        .await
        .expect("negotiate");

    let err = spoofer
        .session_write(&id, b"pwned".to_vec())
        .await
        .unwrap_err();
    match err {
        ClientError::Remote { code, message, .. } => {
            assert_eq!(code, ErrorCode::PermissionDenied);
            assert_eq!(
                message, "peer is not allowed to session.control on this host",
                "byte-identical to a policy deny — no ownership oracle"
            );
        }
        other => panic!("expected remote PERMISSION_DENIED, got {other:?}"),
    }
    let recs = h.audit().records();
    assert!(
        recs.iter()
            .any(|r| r.principal == "device:laptop" && r.decision == "deny")
    );

    // The genuine (pinned) opener is unaffected.
    assert_eq!(s.session_write(&id, b"y".to_vec()).await.unwrap(), 1);

    spoofer.close();
    s.close();
    h.shutdown().await;
}

/// PRD §6's boundary, pinned so a future change cannot silently widen the
/// ownership binding: unlike `write`/`resize` above, `session.get`/`read`/
/// `close` stay cross-device, decided by ACL alone — a non-owner succeeds
/// exactly as it did before session ownership existed.
#[tokio::test(flavor = "multi_thread")]
async fn session_control_binding_does_not_reach_get_read_or_close() {
    let owner = make_identity();
    let other = make_identity();
    let server_trust = StaticTrust::empty()
        .with_pin(owner.fingerprint, Principal::Device("laptop".into()))
        .with_pin(other.fingerprint, Principal::Device("desktop".into()));
    let h = LoopbackHarness::start_custom(Arc::new(AllowAllPinned), owner, server_trust).await;

    let mut s = h.session().await;
    let opened = s.session_open(open_req(&["sh"])).await.unwrap();
    let id = opened.session_id.clone();
    let mut pipe = h.pipes().take().expect("pipe handle for the session");

    let mut desktop = other_device(&h, &other).await;

    let info = desktop
        .session_get(&id)
        .await
        .expect("session.get stays cross-device (PRD §6)");
    assert_eq!(info.session_id, id);

    pipe.write_output(b"hi").await.unwrap();
    let read = desktop
        .session_read(wire::SessionRead {
            session_id: id.clone(),
            after: 0,
            wait_ms: 5_000,
            ..Default::default()
        })
        .await
        .expect("session.read stays cross-device (PRD §6)");
    assert!(!read.events.is_empty());

    desktop
        .session_close(&id, None)
        .await
        .expect("session.close stays cross-device (PRD §6)");

    desktop.close();
    s.close();
    h.shutdown().await;
}
