//! L3 acceptance for the combined endpoint's role matrix (ADR-0059 DoD
//! 27.5): one endpoint, one `trust.toml`, one authorizer built the way
//! production builds it ([`qsh_core::acl::load_or_deny`] over a hand-written
//! `trust.toml` and no `acl.toml`), and every pin role driven through all
//! three branches of the endpoint: the registration (`host.reverse`), the
//! punching connection (`host.punch`) and the six control-stream forward
//! actions.
//!
//! The expectations are this file's own literal copy of ADR-0045 결정 2's
//! table (and its `host.punch` revision), not a call into the code under
//! test. A denial must be the uniform `PERMISSION_DENIED`, must be audited,
//! and must leave no resource behind: no registry entry, no session, no
//! punching connection. No audit record may carry a payload.

use qsh_core::acl::{PERMISSION_DENIED_MESSAGE, Role, load_or_deny};
use qsh_core::client::{ClientError, Session};
use qsh_core::config::Paths;
use qsh_core::handshake::HelloError;
use qsh_core::trust::SharedTrustStore;
use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, control_message};
use qsh_testkit::combined::CombinedHarness;
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{wait_for, wait_for_audit_records};
use std::collections::BTreeMap;

use super::combined::{Reply, TIMEOUT, ask, classify, limits, open_req, pins, punch_request};

/// A string no record may ever hold: it rides in the argv of the exec the
/// matrix sends.
const MARKER: &str = "payload-marker-1f3a";

const FAKE_ID: &str = "01K0FAKESESSION0000000000";

/// One pin of the matrix. `role` is the `role` key in `trust.toml` (none for
/// a pin written before ADR-0045, which is judged as `none`).
struct Peer {
    name: &'static str,
    role: Option<&'static str>,
    id: TestIdentity,
}

fn peers() -> Vec<Peer> {
    [
        ("m-full", Some("full")),
        ("m-exec", Some("exec")),
        ("m-tunnel", Some("tunnel")),
        ("m-readonly", Some("read-only")),
        ("m-reverse", Some("reverse")),
        ("m-none", Some("none")),
        ("m-roleless", None),
    ]
    .into_iter()
    .map(|(name, role)| Peer {
        name,
        role,
        id: make_identity(),
    })
    .collect()
}

impl Peer {
    /// The role the evaluator judges this pin by.
    fn effective(&self) -> &'static str {
        self.role.unwrap_or("none")
    }
}

/// ADR-0045 결정 2 and ADR-0054 결정 6: which of the two connection-level
/// actions a role may use.
fn registration_allowed(role: &str) -> bool {
    matches!(role, "full" | "reverse")
}

fn punch_allowed(role: &str) -> bool {
    role != "none"
}

/// The six forward actions each role may use.
fn forward_allowed(role: &str) -> &'static [&'static str] {
    match role {
        "full" => &[
            "exec.run",
            "session.open",
            "session.list",
            "session.attach",
            "session.control",
            "forward.remote",
        ],
        "exec" => &[
            "exec.run",
            "session.open",
            "session.list",
            "session.attach",
            "session.control",
        ],
        "tunnel" => &["forward.remote"],
        "read-only" => &["session.list", "session.attach"],
        "reverse" | "none" => &[],
        other => panic!("unknown role {other}"),
    }
}

const FORWARD_ACTIONS: [&str; 6] = [
    "exec.run",
    "session.open",
    "session.list",
    "session.attach",
    "session.control",
    "forward.remote",
];

/// Whether the host authorized the request: success is an allow, the uniform
/// `PERMISSION_DENIED` is a denial, and anything else (bar the listed codes
/// only the handler past the gate can produce) fails the test.
fn authorized<T>(result: Result<T, ClientError>, post_authz: &[ErrorCode]) -> bool {
    match result {
        Ok(_) => true,
        Err(ClientError::Remote {
            code: ErrorCode::PermissionDenied,
            message,
            ..
        }) => {
            assert_eq!(message, PERMISSION_DENIED_MESSAGE, "uniform denial");
            false
        }
        Err(ClientError::Remote { code, .. }) if post_authz.contains(&code) => true,
        Err(other) => panic!("neither an allow nor a uniform denial: {other:?}"),
    }
}

async fn probe_forward(s: &mut Session) -> BTreeMap<&'static str, bool> {
    let mut out = BTreeMap::new();
    out.insert(
        "exec.run",
        authorized(
            s.exec_start(&qsh_core::exec::ExecSpec {
                argv: vec!["true".into(), MARKER.into()],
                env: vec![],
                timeout: None,
                shell: None,
                agent_sock: None,
            })
            .await,
            &[],
        ),
    );
    out.insert(
        "session.open",
        authorized(s.session_open(open_req()).await, &[]),
    );
    out.insert("session.list", authorized(s.session_list().await, &[]));
    out.insert(
        "session.attach",
        authorized(
            s.session_read(wire::SessionRead {
                session_id: FAKE_ID.into(),
                ..Default::default()
            })
            .await,
            &[ErrorCode::SessionNotFound],
        ),
    );
    out.insert(
        "session.control",
        authorized(
            s.session_resize(FAKE_ID, 80, 24).await,
            &[ErrorCode::SessionNotFound],
        ),
    );
    out.insert(
        "forward.remote",
        authorized(
            s.rfwd_open(wire::RemoteForwardOpen {
                bind_host: String::new(),
                bind_port: 0,
                forward_host: "127.0.0.1".to_string(),
                forward_port: 9,
                claim_token: Vec::new(),
            })
            .await,
            &[],
        ),
    );
    out
}

/// A `trust.toml` pinning every peer of the matrix under its role.
fn trust_text(peers: &[Peer]) -> String {
    let mut text = String::new();
    for p in peers {
        let role = p
            .role
            .map_or(String::new(), |r| format!("role = \"{r}\"\n"));
        text.push_str(&format!(
            "[[peer]]\nname = \"{}\"\nfingerprint = \"{}\"\naddress = \"\"\n\
             added_at = \"2026-11-11T00:00:00Z\"\n{role}\n",
            p.name, p.id.fingerprint
        ));
    }
    text
}

/// The decision a record of `action` for `peer` must carry.
fn expect_allow(peer: &Peer, action: &str) -> bool {
    let role = peer.effective();
    match action {
        "host.reverse" => registration_allowed(role),
        "host.punch" => punch_allowed(role),
        other => forward_allowed(role).contains(&other),
    }
}

/// Every role of the matrix through the registration, the punch and the
/// forward branch of one combined endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn combined_role_matrix() {
    let peers = peers();
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    std::fs::create_dir_all(&paths.config_dir).expect("config dir");
    std::fs::write(paths.trust_file(), trust_text(&peers)).expect("write trust.toml");
    let store = SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");
    let (authorizer, _diagnostic) = load_or_deny(&paths, Role::Serve, store);

    let pin_list: Vec<(&TestIdentity, &str)> = peers.iter().map(|p| (&p.id, p.name)).collect();
    let h = CombinedHarness::start(authorizer, pins(&pin_list), limits(512, 32)).await;
    h.listen.set_punch_enabled(true);

    // Every peer's connections stay open to the end, so a resource a denial
    // wrongly created could not be reaped before the asserts below.
    let mut held: Vec<Box<dyn std::any::Any + Send>> = Vec::new();

    // --- branch 1: the registration -------------------------------------
    for p in &peers {
        let role = p.effective();
        match h.register(&p.id, p.name).await {
            Ok((dialed, ctl, _hello)) => {
                assert!(
                    registration_allowed(role),
                    "{}: the role {role} must not register",
                    p.name
                );
                held.push(Box::new((dialed, ctl)));
            }
            Err(HelloError::Remote { code, message, .. }) => {
                assert!(
                    !registration_allowed(role),
                    "{}: the role {role} must register, got {code:?}",
                    p.name
                );
                assert_eq!(code, ErrorCode::PermissionDenied, "{}", p.name);
                assert_eq!(message, PERMISSION_DENIED_MESSAGE, "{}", p.name);
            }
            Err(other) => panic!("{}: neither an allow nor a denial: {other:?}", p.name),
        }
    }
    let registered: Vec<String> = h
        .listen
        .registry()
        .snapshot()
        .into_iter()
        .map(|e| e.name)
        .collect();
    let mut expected_registered: Vec<String> = peers
        .iter()
        .filter(|p| registration_allowed(p.effective()))
        .map(|p| p.name.to_string())
        .collect();
    expected_registered.sort();
    assert_eq!(
        registered, expected_registered,
        "only the roles that may register hold an entry"
    );

    // --- branch 2: the punching connection --------------------------------
    let mut punching = 0usize;
    for p in &peers {
        let role = p.effective();
        let (dialed, mut ctl, _) = h
            .forward(&p.id)
            .await
            .unwrap_or_else(|err| panic!("{}: forward hello: {err:?}", p.name));
        let msg = ask(
            &mut ctl,
            2,
            control_message::Body::PunchRequest(punch_request()),
        )
        .await;
        let reply = classify(msg);
        if punch_allowed(role) {
            assert_eq!(
                reply,
                Reply::PunchRefusal(wire::PunchRefusal::TargetNotRegistered as i32),
                "{}: the rendezvous answers",
                p.name
            );
            punching += 1;
            held.push(Box::new((dialed, ctl)));
        } else {
            assert_eq!(
                reply,
                Reply::Error("PERMISSION_DENIED".into()),
                "{}: the role {role} must not punch",
                p.name
            );
        }
    }
    // A denied punch connection is counted until the host has closed it, so
    // the count settles on the allowed ones.
    wait_for(TIMEOUT, || {
        (h.listen.punch_connections() == punching).then_some(())
    })
    .await;

    // --- branch 3: the forward actions ------------------------------------
    let mut sessions_expected = 0usize;
    for p in &peers {
        let role = p.effective();
        let (dialed, ctl, hello) = h
            .forward(&p.id)
            .await
            .unwrap_or_else(|err| panic!("{}: forward hello: {err:?}", p.name));
        let mut session = Session::from_control(dialed.connection.clone(), ctl, hello);
        let got = probe_forward(&mut session).await;
        let want: BTreeMap<&'static str, bool> = FORWARD_ACTIONS
            .into_iter()
            .map(|a| (a, forward_allowed(role).contains(&a)))
            .collect();
        assert_eq!(got, want, "{} ({role})", p.name);
        if want["session.open"] {
            sessions_expected += 1;
        }
        // Keep the connection (and its remote-forward listener) alive.
        held.push(Box::new((dialed, session)));
    }

    // --- no resource for a denial -----------------------------------------
    assert_eq!(
        h.broker.live_counts().live,
        sessions_expected,
        "only an allowed session.open created a session"
    );
    assert_eq!(
        h.listen.registry().snapshot().len(),
        expected_registered.len()
    );

    // --- the audit trail ----------------------------------------------------
    let per_peer = 2 + FORWARD_ACTIONS.len();
    let records = wait_for_audit_records(&h.audit, per_peer * peers.len(), TIMEOUT).await;
    for p in &peers {
        let principal = format!("device:{}", p.name);
        for action in ["host.reverse", "host.punch"]
            .into_iter()
            .chain(FORWARD_ACTIONS)
        {
            let mine: Vec<_> = records
                .iter()
                .filter(|r| r.principal == principal && r.action == action)
                .collect();
            assert_eq!(mine.len(), 1, "{}: one {action} record: {mine:?}", p.name);
            let want = if expect_allow(p, action) {
                "allow"
            } else {
                "deny"
            };
            assert_eq!(mine[0].decision, want, "{}: {action}", p.name);
            if want == "allow" {
                assert_eq!(
                    mine[0].role.as_deref(),
                    p.role,
                    "{}: {action}: an allow rests on the pin's role",
                    p.name
                );
                assert_eq!(mine[0].rule, None, "{}: {action}", p.name);
            }
        }
    }
    for r in &records {
        let line = serde_json::to_string(r).expect("serialize a record");
        assert!(!line.contains(MARKER), "a record holds a payload: {line}");
    }

    drop(held);
    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// The rest of the vocabulary: file.*, forward.local, forward.jump,
// forward.agent and the always-deny forward.socks gate.
// ---------------------------------------------------------------------------

/// What each role may do among the actions `combined_role_matrix` leaves out.
/// This is again a literal copy of ADR-0045 결정 2 and ADR-0056 결정 18, not a
/// call into the code under test. `file.*` is `full` only, and in this
/// harness (no `[[acl]]` row with a `paths` list) the file ops still answer
/// the uniform denial for `full` too, after the action itself is allowed:
/// the path scope (ADR-0029) is a second gate. So the reply is a denial for
/// every role and the audit shows `allow` for `full` and `deny` for the rest.
fn extra_allowed(role: &str, op: &str) -> bool {
    matches!(
        (role, op),
        ("full", "forward.local" | "forward.jump" | "forward.agent")
            | ("tunnel", "forward.local" | "forward.jump")
            | ("exec", "forward.agent")
    )
}

/// One raw file-op request on the control stream; `true` unless the reply is
/// the uniform denial.
async fn file_op_denied(s: &mut Session, body: control_message::Body) -> bool {
    const REQUEST_ID: u64 = 9_000;
    s.send_control_message(&wire::ControlMessage::new(REQUEST_ID, body))
        .await
        .expect("send the file op");
    loop {
        let msg = s
            .next_control_message()
            .await
            .expect("read the reply")
            .expect("the control stream stays open for the reply");
        if msg.request_id != REQUEST_ID {
            continue;
        }
        return match msg.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(wire::response::Body::Error(e)),
            })) if e.error_code() == ErrorCode::PermissionDenied => {
                assert_eq!(e.message, PERMISSION_DENIED_MESSAGE, "uniform denial");
                true
            }
            _ => false,
        };
    }
}

/// Open a stream with `header` on `conn` and read the `ConnectResult`.
async fn stream_result(
    conn: &qsh_transport::Connection,
    header: wire::StreamHeader,
) -> wire::ConnectResult {
    let (send, recv) = conn.open_bi().await.expect("open a stream");
    let mut send = qsh_transport::FramedSend::data(send);
    send.send(&header).await.expect("send the header");
    let mut recv = qsh_transport::FramedRecv::data(recv);
    let result = recv
        .recv()
        .await
        .expect("read the ConnectResult")
        .expect("a ConnectResult comes back");
    // Keep the stream alive until the result is read, then let it go.
    drop((send, recv));
    result
}

/// ADR-0059 DoD 27.5, the part the six-action matrix leaves out: the four
/// file ops, the `-L` inline gate, the `JUMP` inline gate, the agent grant
/// and the always-deny `forward.socks` gate, for every role. Every denial is
/// the uniform message and leaves no resource: a role that is denied `-L`
/// opens no TCP connection, a role that is denied `forward.jump` opens no UDP
/// socket (the stream answers `ok` only for an allowed role), and a role that is denied the
/// exec that carries an agent request gets no `forward.agent` record at all.
#[tokio::test(flavor = "multi_thread")]
async fn combined_role_matrix_covers_files_streams_agent_and_socks() {
    use qsh_core::acl::{Action, Requester, ResourceRef};
    use qsh_transport::{AuthPath, Principal};

    let peers = peers();
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    std::fs::create_dir_all(&paths.config_dir).expect("config dir");
    std::fs::write(paths.trust_file(), trust_text(&peers)).expect("write trust.toml");
    let store = SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");
    let (authorizer, _diagnostic) = load_or_deny(&paths, Role::Serve, store);

    let pin_list: Vec<(&TestIdentity, &str)> = peers.iter().map(|p| (&p.id, p.name)).collect();
    let h = CombinedHarness::start(authorizer.clone(), pins(&pin_list), limits(512, 32)).await;

    // A TCP target for `-L`: an allowed role connects to it, a denied role
    // must not.
    let target = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the -L target");
    let target_port = target.local_addr().expect("addr").port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let accepted = accepted.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = target.accept().await {
                accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(sock);
            }
        });
    }

    let mut held: Vec<Box<dyn std::any::Any + Send>> = Vec::new();
    let mut want_local = 0usize;
    for p in &peers {
        let role = p.effective();
        let (dialed, ctl, hello) = h
            .forward(&p.id)
            .await
            .unwrap_or_else(|err| panic!("{}: forward hello: {err:?}", p.name));
        let mut s = Session::from_control(dialed.connection.clone(), ctl, hello);

        // file.* : denied for the reverse role, as for every role without a
        // `paths` row.
        let probe = "/srv/qsh-combined-probe/x";
        for (name, body) in [
            (
                "file.read",
                control_message::Body::FileReadOpen(wire::FileReadOpen {
                    path: probe.into(),
                    user: String::new(),
                }),
            ),
            (
                "file.write",
                control_message::Body::FileWriteOpen(wire::FileWriteOpen {
                    path: probe.into(),
                    size: 1,
                    mode: 0o600,
                    ..Default::default()
                }),
            ),
            (
                "file.list",
                control_message::Body::FileListOpen(wire::FileListOpen {
                    path: probe.into(),
                    ..Default::default()
                }),
            ),
            (
                "file.mkdir",
                control_message::Body::FileMkdirOpen(wire::FileMkdirOpen {
                    path: probe.into(),
                    mode: 0o700,
                    ..Default::default()
                }),
            ),
        ] {
            assert!(
                file_op_denied(&mut s, body).await,
                "{} ({role}): {name} must be the uniform PERMISSION_DENIED",
                p.name
            );
        }

        // forward.local: the inline TCP_CONNECT gate.
        let local = stream_result(
            &dialed.connection,
            wire::StreamHeader {
                kind: wire::StreamKind::TcpConnect as i32,
                ticket: Vec::new(),
                host: "127.0.0.1".into(),
                port: u32::from(target_port),
                deny_host_local: false,
            },
        )
        .await;
        let allowed = extra_allowed(role, "forward.local");
        assert_eq!(local.ok, allowed, "{} ({role}): forward.local", p.name);
        if allowed {
            want_local += 1;
        } else {
            assert_eq!(
                local.code,
                ErrorCode::PermissionDenied.as_str(),
                "{}",
                p.name
            );
            assert_eq!(local.message, PERMISSION_DENIED_MESSAGE, "{}", p.name);
        }

        // forward.jump: the inline JUMP gate. 192.0.2.1 is TEST-NET-1, not
        // host-local, so an allowed role gets `ok` and a UDP socket.
        let jump = stream_result(
            &dialed.connection,
            wire::StreamHeader::jump([3u8; 16], "192.0.2.1".into(), 4433),
        )
        .await;
        let allowed = extra_allowed(role, "forward.jump");
        assert_eq!(jump.ok, allowed, "{} ({role}): forward.jump", p.name);
        if !allowed {
            assert_eq!(
                jump.code,
                ErrorCode::PermissionDenied.as_str(),
                "{}",
                p.name
            );
            assert_eq!(jump.message, PERMISSION_DENIED_MESSAGE, "{}", p.name);
        }

        // forward.agent: decided only for an exec that is itself allowed.
        // The roles that cannot exec are denied the exec uniformly and no
        // agent record exists for them (asserted below).
        let started = s
            .exec_start_with_agent(
                &qsh_core::exec::ExecSpec {
                    argv: vec!["true".into()],
                    env: vec![],
                    timeout: None,
                    shell: None,
                    agent_sock: None,
                },
                vec![5u8; 16],
            )
            .await;
        let may_exec = forward_allowed(role).contains(&"exec.run");
        assert_eq!(
            authorized(started, &[]),
            may_exec,
            "{} ({role}): the exec that carries the agent request",
            p.name
        );

        // forward.socks: the always-deny gate runs before the role, so no
        // pin gets it. `-D` is authorized per connection as forward.local.
        let principal = Principal::Device(p.name.to_string());
        let verdict = authorizer.check(
            &Requester::new(&principal, AuthPath::Pin, None),
            Action::ForwardSocks,
            ResourceRef::unowned("socks"),
        );
        assert!(!verdict.is_allow(), "{} ({role}): forward.socks", p.name);

        held.push(Box::new((dialed, s)));
    }

    // The TCP connections an allowed role made, and no others.
    wait_for(TIMEOUT, || {
        (accepted.load(std::sync::atomic::Ordering::SeqCst) == want_local).then_some(())
    })
    .await;

    // The audit trail: one record per decision, a denial for every role
    // that lacks the action, no payload anywhere.
    let records = h.audit.records();
    for p in &peers {
        let principal = format!("device:{}", p.name);
        let role = p.effective();
        let mine = |action: &str| -> Vec<_> {
            records
                .iter()
                .filter(|r| r.principal == principal && r.action == action)
                .collect()
        };
        for action in ["file.read", "file.write"] {
            // `full` is allowed the action (the path scope then denies, with
            // a second record of its own); every other role is denied.
            let rows = mine(action);
            if role == "full" {
                assert!(
                    rows.iter()
                        .any(|r| r.decision == "allow" && r.role.as_deref() == Some("full")),
                    "{} ({role}): {action} is allowed by the role: {rows:?}",
                    p.name
                );
            } else {
                assert!(
                    rows.iter().all(|r| r.decision == "deny"),
                    "{} ({role}): {action} is denied: {rows:?}",
                    p.name
                );
            }
            assert!(!mine(action).is_empty(), "{}: {action} is audited", p.name);
        }
        for action in ["forward.local", "forward.jump"] {
            let rows = mine(action);
            assert_eq!(rows.len(), 1, "{}: one {action} record", p.name);
            let want = if extra_allowed(role, action) {
                "allow"
            } else {
                "deny"
            };
            assert_eq!(rows[0].decision, want, "{}: {action}", p.name);
        }
        let agent = mine("forward.agent");
        if forward_allowed(role).contains(&"exec.run") {
            assert_eq!(agent.len(), 1, "{}: the agent request is decided", p.name);
            let want = if extra_allowed(role, "forward.agent") {
                "allow"
            } else {
                "deny"
            };
            assert_eq!(agent[0].decision, want, "{}: forward.agent", p.name);
        } else {
            assert!(
                agent.is_empty(),
                "{} ({role}): a refused exec decides no agent grant: {agent:?}",
                p.name
            );
        }
        assert!(
            mine("forward.socks").is_empty(),
            "{}: the socks gate never reaches the wire",
            p.name
        );
    }
    drop(held);
    h.shutdown().await;
}
