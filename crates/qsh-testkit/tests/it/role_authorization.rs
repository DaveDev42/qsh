//! M15 plan Step 4 (1a4af3b): the role stage of the evaluator (ADR-0045 결정 1·4·6·7·16)
//! driven end to end through the production wiring.
//!
//! Every host here gets its authorizer from [`qsh_core::acl::load_or_deny`]
//! over a sandbox whose `trust.toml` (and, per scenario, `acl.toml`) is
//! written by hand, so the whole chain under test is the real one:
//! `SharedTrustStore::resolve_role` -> `RoleResolvingAuthorizer` ->
//! `Policy::check_with_role` -> the wire handler's refusal and audit record.
//! The commands that write `role` keys arrive in Step 5; this file builds the
//! files itself.
//!
//! **Routes.** A control-stream scenario is generic over [`Route`] and runs
//! on the forward route (`qsh serve`, [`LoopbackHarness`]) and the reverse
//! route (`qsh serve --to`, [`ReversePairHarness`]) with the same body. The
//! `host.reverse` row has its own route (`qsh listen`,
//! [`ReverseHarness`]); the inline `forward.local` gate its own harness
//! ([`TunnelHarness`]).
//!
//! The two scenarios that need something the generic [`Route`] does not
//! offer (a CA-issued leaf; a second distinct principal on one host) are
//! written out per route with `_forward` / `_reverse` suffixes. On the reverse
//! route they use [`ReversePairHarness::start_custom_trusting`] (a CA-issued
//! controller) and [`ReversePairHarness::session_from_second_controller`] (a
//! second controller the target dials). Every scenario therefore runs on both
//! routes.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use qsh_core::acl::{
    Action, Authorizer, Decision, PERMISSION_DENIED_MESSAGE, Requester, ResourceRef, Role,
    load_or_deny,
};
use qsh_core::broker::{PeerFingerprint, SessionSpec};
use qsh_core::client::{ClientError, Session};
use qsh_core::config::Paths;
use qsh_core::exec::ExecSpec;
use qsh_core::handshake::HelloError;
use qsh_core::trust::SharedTrustStore;
use qsh_core::tunnel::RemoteForwardAcceptor;
use qsh_proto::ErrorCode;
use qsh_proto::wire;
use qsh_testkit::loopback::{LoopbackHarness, TestIdentity, make_ca, make_identity};
use qsh_testkit::pair::HostedPair;
use qsh_testkit::reverse::{ReverseHarness, ReversePairHarness};
use qsh_testkit::tunnel::{EchoServer, TunnelHarness};
use qsh_transport::{AuthPath, Dialer, Principal, StaticTrust};

/// How the sandbox's `acl.toml` is left (ADR-0045 결정 6's three states).
enum AclFile {
    /// No file: no rows, roles still work.
    Missing,
    /// A usable file with these rows.
    Rows(&'static str),
    /// A file that does not parse: everything is denied, roles included.
    Garbage,
}

/// A sandbox config dir plus the authorizer production would build over it.
struct Env {
    _dir: tempfile::TempDir,
    paths: Paths,
    trust: Arc<SharedTrustStore>,
    client: TestIdentity,
}

fn peer_block(name: &str, fingerprint: &qsh_transport::Fingerprint, role: Option<&str>) -> String {
    let role = role.map_or(String::new(), |r| format!("role = \"{r}\"\n"));
    format!(
        "[[peer]]\nname = \"{name}\"\nfingerprint = \"{fingerprint}\"\naddress = \"\"\n\
         added_at = \"2026-10-14T00:00:00Z\"\n{role}\n"
    )
}

impl Env {
    /// A sandbox whose `trust.toml` pins the harness client as `laptop`
    /// carrying `role` (no `role` key when `None`).
    fn new(role: Option<&str>, acl: AclFile) -> Self {
        let client = make_identity();
        let text = peer_block("laptop", &client.fingerprint, role);
        Self::with_trust_text(client, &text, acl)
    }

    fn with_trust_text(client: TestIdentity, trust_text: &str, acl: AclFile) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        std::fs::write(paths.trust_file(), trust_text).expect("write trust.toml");
        match acl {
            AclFile::Missing => {}
            AclFile::Rows(text) => write_private(&paths.acl_file(), text),
            AclFile::Garbage => write_private(&paths.acl_file(), "[[acl]\nthis is not toml"),
        }
        let trust = SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");
        Self {
            _dir: dir,
            paths,
            trust,
            client,
        }
    }

    /// Replace `trust.toml` on disk; the next decision sees it.
    fn rewrite_trust(&self, text: &str) {
        std::fs::write(self.paths.trust_file(), text).expect("rewrite trust.toml");
    }

    fn authorizer(&self, role: Role) -> Arc<dyn Authorizer> {
        let (authorizer, _diagnostic) = load_or_deny(&self.paths, role, Arc::clone(&self.trust));
        authorizer
    }

    /// The host-side pin for the harness client.
    fn host_trust(&self) -> StaticTrust {
        StaticTrust::empty().with_pin(
            self.client.fingerprint,
            Principal::Device("laptop".to_string()),
        )
    }
}

fn write_private(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).expect("write acl.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod acl.toml");
    }
}

/// A route a control-stream scenario can run on.
trait Route: HostedPair {
    fn start(env: &Env) -> impl Future<Output = Self>;
}

impl Route for LoopbackHarness {
    async fn start(env: &Env) -> Self {
        LoopbackHarness::start_custom(
            env.authorizer(Role::Serve),
            env.client.clone(),
            env.host_trust(),
        )
        .await
    }
}

impl Route for ReversePairHarness {
    async fn start(env: &Env) -> Self {
        ReversePairHarness::start_custom(env.authorizer(Role::Serve), env.client.clone()).await
    }
}

/// Run `$scenario::<Route>()` on both routes as two tests.
macro_rules! both_routes {
    ($scenario:ident => $forward:ident, $reverse:ident) => {
        #[tokio::test(flavor = "multi_thread")]
        async fn $forward() {
            $scenario::<LoopbackHarness>().await;
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn $reverse() {
            $scenario::<ReversePairHarness>().await;
        }
    };
}

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

/// Whether the host authorized the request. A refusal must be the uniform
/// `PERMISSION_DENIED`. Success means allowed. Any other error is a test
/// failure (a transport error or malformed reply must not read as "allowed"),
/// so a call site whose allowed outcome is a business error after the ACL
/// gate (a fake target that does not exist) names that code with
/// [`authorized_or`].
fn authorized<T>(result: Result<T, ClientError>) -> bool {
    authorized_or(result, &[])
}

/// [`authorized`] that also accepts a `Remote` error carrying one of
/// `post_authz`: a code the handler can only produce *after* the ACL gate
/// passed, because the request names a resource that does not exist. Every
/// code listed is therefore evidence of an allow, never of a denial.
fn authorized_or<T>(result: Result<T, ClientError>, post_authz: &[ErrorCode]) -> bool {
    match result {
        Ok(_) => true,
        Err(ClientError::Remote {
            code: ErrorCode::PermissionDenied,
            message,
            ..
        }) => {
            assert_eq!(
                message, PERMISSION_DENIED_MESSAGE,
                "a denial must carry the uniform message"
            );
            false
        }
        Err(ClientError::Remote { code, .. }) if post_authz.contains(&code) => true,
        Err(other) => panic!("neither an allow nor a uniform denial: {other:?}"),
    }
}

const FAKE_ID: &str = "01K0FAKESESSION0000000000";

/// The six control-stream actions, each driven by the wire call that maps to
/// it. Returns `action name -> authorized`.
async fn probe_control_stream(s: &mut Session) -> BTreeMap<&'static str, bool> {
    let mut out = BTreeMap::new();
    out.insert(
        "exec.run",
        authorized(
            s.exec_start(&ExecSpec {
                argv: vec!["true".into()],
                env: vec![],
                timeout: None,
            })
            .await,
        ),
    );
    out.insert("session.open", authorized(s.session_open(open_req()).await));
    out.insert("session.list", authorized(s.session_list().await));
    out.insert(
        "session.attach",
        // `FAKE_ID` names no session, so an allowed attach ends in
        // SESSION_NOT_FOUND: the lookup runs after the ACL gate.
        authorized_or(
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
        // Same as attach: an allowed resize of the fake id is not-found.
        authorized_or(
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
        ),
    );
    out
}

/// ADR-0045 결정 2's table as the test's own literal copy: which of the six
/// probed actions each role may use.
fn expected_control_stream(role: &str) -> BTreeMap<&'static str, bool> {
    let allowed: &[&str] = match role {
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
    };
    [
        "exec.run",
        "session.open",
        "session.list",
        "session.attach",
        "session.control",
        "forward.remote",
    ]
    .into_iter()
    .map(|name| (name, allowed.contains(&name)))
    .collect()
}

const ROLES: [&str; 6] = ["full", "exec", "tunnel", "read-only", "reverse", "none"];

fn requester_for(env: &Env) -> (Principal, Option<PeerFingerprint>) {
    (
        Principal::Device("laptop".to_string()),
        Some(PeerFingerprint::new(*env.client.fingerprint.as_bytes())),
    )
}

// --- legacy pin ---------------------------------------------------------

async fn legacy_pin_scenario<R: Route>() {
    // A pin with no `role` key is judged as `none`: only `[[acl]]` rows can
    // authorize it.
    let env = Env::new(
        None,
        AclFile::Rows("[[acl]]\nprincipal = \"device:laptop\"\nallow = [\"session.list\"]\n"),
    );
    let h = R::start(&env).await;
    let mut s = h.session().await;
    let got = probe_control_stream(&mut s).await;
    let mut expected = expected_control_stream("none");
    expected.insert("session.list", true);
    assert_eq!(got, expected);

    // The allow came from row 0; no role is named.
    let records = h.audit().records();
    let allow = records
        .iter()
        .find(|r| r.action == "session.list" && r.decision == "allow")
        .expect("session.list allow record");
    assert_eq!(allow.rule, Some(0));
    assert_eq!(allow.role, None);
    s.close();
    h.shutdown().await;
}

both_routes!(legacy_pin_scenario =>
    legacy_pin_without_role_is_authorized_by_acl_rows_only_forward,
    legacy_pin_without_role_is_authorized_by_acl_rows_only_reverse);

// --- the table, all six roles, no acl.toml -----------------------------

async fn role_table_scenario<R: Route>() {
    for role in ROLES {
        let env = Env::new(Some(role), AclFile::Missing);
        let h = R::start(&env).await;
        let mut s = h.session().await;
        let got = probe_control_stream(&mut s).await;
        assert_eq!(got, expected_control_stream(role), "role {role}");
        s.close();
        h.shutdown().await;
    }
}

both_routes!(role_table_scenario =>
    role_full_without_acl_toml_allows_every_action_but_forward_socks_forward,
    role_full_without_acl_toml_allows_every_action_but_forward_socks_reverse);

/// The actions with no control-stream wire call in this build. They are not
/// drivable, so the authorizer is asked directly: `forward.socks` is behind
/// the always-deny gate for every role; `file.read` and `file.write` are
/// `full`'s alone since the always-deny gate stopped covering them
/// (ADR-0029 decision 3), and a role's file grant ignores the request path (ADR-0045
/// 결정 5). The file ops themselves are driven in `file_host.rs`.
#[test]
fn role_full_without_acl_toml_allows_every_action_but_forward_socks_undrivable_actions() {
    for role in ROLES {
        let env = Env::new(Some(role), AclFile::Missing);
        let authorizer = env.authorizer(Role::Serve);
        let (principal, fingerprint) = requester_for(&env);
        let requester = Requester::new(&principal, AuthPath::Pin, fingerprint);
        let verdict = authorizer.check(&requester, Action::ForwardSocks, ResourceRef::unowned("x"));
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "role {role} must not reach forward.socks"
        );
        for action in [Action::FileRead, Action::FileWrite] {
            let verdict = authorizer.check(&requester, action, ResourceRef::unowned("x"));
            let want = if role == "full" {
                Decision::Allow
            } else {
                Decision::Deny
            };
            assert_eq!(verdict.decision, want, "role {role} and {action}");
        }
    }
}

/// The inline `forward.local` gate and the `host.reverse` registration take
/// their own routes through the same table.
#[tokio::test(flavor = "multi_thread")]
async fn role_full_without_acl_toml_allows_every_action_but_forward_socks_inline_and_registration()
{
    for role in ROLES {
        let want_forward_local = matches!(role, "full" | "tunnel");
        let want_host_reverse = matches!(role, "full" | "reverse");

        let env = Env::new(Some(role), AclFile::Missing);
        let h = TunnelHarness::start_custom(
            env.authorizer(Role::Serve),
            env.client.clone(),
            env.host_trust(),
        )
        .await;
        let result = h.tcp_connect("127.0.0.1", h.echo.port()).await;
        assert_eq!(
            result.ok, want_forward_local,
            "forward.local under role {role}"
        );
        if !result.ok {
            assert_eq!(result.code, ErrorCode::PermissionDenied.as_str());
            assert_eq!(result.message, PERMISSION_DENIED_MESSAGE);
        }
        h.shutdown().await;

        let target = make_identity();
        let env = Env::with_trust_text(
            make_identity(),
            &peer_block("widget", &target.fingerprint, Some(role)),
            AclFile::Missing,
        );
        let pin = StaticTrust::empty()
            .with_pin(target.fingerprint, Principal::Device("widget".to_string()));
        let harness = ReverseHarness::start_with(env.authorizer(Role::Listen), false, pin).await;
        match harness.register(&target, "widget").await {
            Ok(_) => assert!(
                want_host_reverse,
                "host.reverse must be denied under {role}"
            ),
            Err(HelloError::Remote { code, message, .. }) => {
                assert!(
                    !want_host_reverse,
                    "host.reverse must be allowed under {role}"
                );
                assert_eq!(code, ErrorCode::PermissionDenied);
                assert_eq!(message, PERMISSION_DENIED_MESSAGE);
            }
            Err(other) => panic!("unexpected registration failure under {role}: {other:?}"),
        }
        harness.shutdown().await;
    }
}

// --- the three acl.toml states -----------------------------------------

async fn invalid_acl_scenario<R: Route>() {
    // `full` would allow everything; the unparseable `acl.toml` takes the
    // role grant away with the rows.
    let env = Env::new(Some("full"), AclFile::Garbage);
    let h = R::start(&env).await;
    let mut s = h.session().await;
    let got = probe_control_stream(&mut s).await;
    assert_eq!(got, expected_control_stream("none"));
    s.close();
    h.shutdown().await;
}

both_routes!(invalid_acl_scenario =>
    invalid_acl_toml_denies_role_grants_too_forward,
    invalid_acl_toml_denies_role_grants_too_reverse);

#[tokio::test(flavor = "multi_thread")]
async fn invalid_acl_toml_denies_role_grants_too_inline_and_registration() {
    let env = Env::new(Some("full"), AclFile::Garbage);
    let h = TunnelHarness::start_custom(
        env.authorizer(Role::Serve),
        env.client.clone(),
        env.host_trust(),
    )
    .await;
    let result = h.tcp_connect("127.0.0.1", h.echo.port()).await;
    assert!(!result.ok, "forward.local must be denied");
    assert_eq!(result.message, PERMISSION_DENIED_MESSAGE);
    h.shutdown().await;

    let target = make_identity();
    let env = Env::with_trust_text(
        make_identity(),
        &peer_block("widget", &target.fingerprint, Some("full")),
        AclFile::Garbage,
    );
    let pin =
        StaticTrust::empty().with_pin(target.fingerprint, Principal::Device("widget".to_string()));
    let harness = ReverseHarness::start_with(env.authorizer(Role::Listen), false, pin).await;
    match harness.register(&target, "widget").await {
        Ok(_) => panic!("host.reverse must be denied"),
        Err(HelloError::Remote { code, message, .. }) => {
            assert_eq!(code, ErrorCode::PermissionDenied);
            assert_eq!(message, PERMISSION_DENIED_MESSAGE);
        }
        Err(other) => panic!("unexpected registration failure: {other:?}"),
    }
    harness.shutdown().await;
}

// --- fingerprint binding ------------------------------------------------

async fn fingerprint_binding_scenario<R: Route>() {
    // The host authenticates the client as `device:laptop` (its own pin), but
    // `trust.toml` names a *different* fingerprint under that name: the name
    // alone grants nothing.
    let client = make_identity();
    let stranger = make_identity();
    let env = Env::with_trust_text(
        client.clone(),
        &peer_block("laptop", &stranger.fingerprint, Some("full")),
        AclFile::Missing,
    );
    let h = R::start(&env).await;
    let mut s = h.session().await;
    assert!(
        !authorized(s.session_list().await),
        "name without fingerprint"
    );

    // The pin is brought in line with the connection: the next request on the
    // same connection is allowed.
    env.rewrite_trust(&peer_block("laptop", &client.fingerprint, Some("full")));
    assert!(authorized(s.session_list().await), "matching fingerprint");

    // And re-pinning the name under another key ends it again.
    env.rewrite_trust(&peer_block("laptop", &stranger.fingerprint, Some("full")));
    assert!(!authorized(s.session_list().await), "re-pinned name");
    s.close();
    h.shutdown().await;
}

both_routes!(fingerprint_binding_scenario =>
    role_requires_the_connection_fingerprint_to_match_the_current_pin_forward,
    role_requires_the_connection_fingerprint_to_match_the_current_pin_reverse);

/// Forward route: a CA leaf that names the pinned device (`qsh://device/laptop`) is
/// classified as `device:laptop` over `AuthPath::Ca`; the pin's role must not
/// reach it, while the genuinely pinned key on the same host keeps its role.
#[tokio::test(flavor = "multi_thread")]
async fn role_grant_does_not_reach_a_ca_leaf_naming_a_pinned_device_forward() {
    let env = Env::new(Some("full"), AclFile::Missing);
    let ca = make_ca();
    let leaf = ca.issue("qsh://device/laptop");
    let server_trust = env.host_trust().with_ca(ca.root_der.clone());
    let h = LoopbackHarness::start_custom(
        env.authorizer(Role::Serve),
        env.client.clone(),
        server_trust,
    )
    .await;

    let client_trust = StaticTrust::empty().with_pin(
        h.server_identity.fingerprint,
        Principal::Device("box".into()),
    );
    let dialer = Dialer::new(leaf.local.clone(), Arc::new(client_trust));
    let dialed = dialer
        .dial(h.addr, "127.0.0.1")
        .await
        .expect("the host's CA root trusts this leaf");
    let mut via_ca = Session::negotiate(dialed.connection, "desktop")
        .await
        .expect("negotiate");
    assert!(
        !authorized(via_ca.session_list().await),
        "a CA leaf must not inherit the pin's role"
    );
    let records = h.audit().records();
    assert!(
        records
            .iter()
            .any(|r| r.principal == "device:laptop" && r.auth_path == "ca" && r.decision == "deny"),
        "{records:?}"
    );

    let mut pinned = h.session().await;
    assert!(
        authorized(pinned.session_list().await),
        "the pinned key keeps its role"
    );
    via_ca.close();
    pinned.close();
    h.shutdown().await;
}

/// Reverse-route twin of the CA-leaf scenario: the *controller* presents the
/// CA leaf naming `device:laptop`, the target (host role) authenticates it by
/// CA only, and the pin's role must not reach it. A second pair whose
/// controller is the genuinely pinned key keeps its role.
#[tokio::test(flavor = "multi_thread")]
async fn role_grant_does_not_reach_a_ca_leaf_naming_a_pinned_device_reverse() {
    let env = Env::new(Some("full"), AclFile::Missing);
    let ca = make_ca();
    let leaf = ca.issue("qsh://device/laptop");
    let ca_only = StaticTrust::empty().with_ca(ca.root_der.clone());
    let h =
        ReversePairHarness::start_custom_trusting(env.authorizer(Role::Serve), leaf, ca_only).await;
    let mut via_ca = h.session().await;
    assert!(
        !authorized(via_ca.session_list().await),
        "a CA leaf must not inherit the pin's role"
    );
    let records = h.audit().records();
    assert!(
        records
            .iter()
            .any(|r| r.principal == "device:laptop" && r.auth_path == "ca" && r.decision == "deny"),
        "{records:?}"
    );
    via_ca.close();
    h.shutdown().await;

    let pinned_pair =
        ReversePairHarness::start_custom(env.authorizer(Role::Serve), env.client.clone()).await;
    let mut pinned = pinned_pair.session().await;
    assert!(
        authorized(pinned.session_list().await),
        "the pinned key keeps its role"
    );
    pinned.close();
    pinned_pair.shutdown().await;
}

// --- trust.toml changes while connected ---------------------------------

async fn trust_remove_scenario<R: Route>() {
    let env = Env::new(Some("full"), AclFile::Missing);
    let h = R::start(&env).await;
    let mut s = h.session().await;
    assert!(authorized(s.session_list().await), "role in effect");

    // `trust remove` rewrites trust.toml without the pin. The connection
    // stays up (the handshake already happened) but the very next request
    // finds no role.
    env.rewrite_trust("");
    assert!(
        !authorized(s.session_list().await),
        "a removed pin ends its role grants on the next request"
    );
    s.close();
    h.shutdown().await;
}

both_routes!(trust_remove_scenario =>
    trust_remove_ends_role_grants_on_the_next_request_forward,
    trust_remove_ends_role_grants_on_the_next_request_reverse);

async fn reload_failure_scenario<R: Route>() {
    let env = Env::new(Some("full"), AclFile::Missing);
    let good = std::fs::read_to_string(env.paths.trust_file()).unwrap();
    let h = R::start(&env).await;
    let mut s = h.session().await;
    assert!(authorized(s.session_list().await), "role in effect");

    // A hand edit that no longer parses: the snapshot keeps authenticating
    // the pin, but the role grant stops.
    env.rewrite_trust("[[peer]]\nname = ");
    assert!(
        !authorized(s.session_list().await),
        "a failed reload suspends role grants"
    );
    assert!(env.trust.roles_suspended());
    assert_eq!(
        qsh_transport::TrustEvaluator::lookup_pin(&*env.trust, &env.client.fingerprint),
        Some(Principal::Device("laptop".to_string())),
        "pin authentication still uses the last good snapshot"
    );

    // Putting the file right again restores the role.
    env.rewrite_trust(&good);
    assert!(authorized(s.session_list().await), "role restored");
    assert!(!env.trust.roles_suspended());
    s.close();
    h.shutdown().await;
}

both_routes!(reload_failure_scenario =>
    trust_store_reload_failure_suspends_role_grants_forward,
    trust_store_reload_failure_suspends_role_grants_reverse);

// --- audit ----------------------------------------------------------------

async fn role_audit_scenario<R: Route>() {
    let env = Env::new(
        Some("exec"),
        AclFile::Rows("[[acl]]\nprincipal = \"device:other\"\nallow = [\"session.list\"]\n"),
    );
    let h = R::start(&env).await;
    let mut s = h.session().await;
    assert!(authorized(s.session_list().await));
    assert!(!authorized(
        s.rfwd_close(wire::RemoteForwardClose {
            forward_id: "01FAKEFORWARDID0000000000".to_string(),
        })
        .await
    ));

    let records = h.audit().records();
    let allow = records
        .iter()
        .find(|r| r.action == "session.list" && r.decision == "allow")
        .expect("allow record");
    assert_eq!(allow.role.as_deref(), Some("exec"));
    assert_eq!(allow.rule, None, "a role grant names no rule");
    assert_eq!(allow.principal, "device:laptop");

    let deny = records
        .iter()
        .find(|r| r.action == "forward.remote" && r.decision == "deny")
        .expect("deny record");
    assert_eq!(deny.role, None, "a denial names no role");
    assert_eq!(deny.rule, None);

    // On the JSONL line the key is present on the role record and absent
    // elsewhere (additive: a record without a role is byte-identical to
    // what it was before).
    let allow_line = serde_json::to_string(allow).unwrap();
    assert!(allow_line.contains("\"role\":\"exec\""), "{allow_line}");
    let deny_line = serde_json::to_string(deny).unwrap();
    assert!(!deny_line.contains("\"role\""), "{deny_line}");
    s.close();
    h.shutdown().await;
}

both_routes!(role_audit_scenario =>
    role_grant_audit_record_names_the_role_and_no_rule_forward,
    role_grant_audit_record_names_the_role_and_no_rule_reverse);

// --- scope ---------------------------------------------------------------

/// `read-only` may attach to a session (read its output) but may not write
/// to it. The session is planted at the broker so the test needs no second
/// principal and runs on both routes.
async fn read_only_scenario<R: Route>() {
    let env = Env::new(Some("read-only"), AclFile::Missing);
    let h = R::start(&env).await;
    let handle = h
        .broker()
        .open(&SessionSpec {
            argv: vec!["sh".into()],
            env: vec![],
            term: None,
            cols: 80,
            rows: 24,
            user: None,
        })
        .expect("plant a session at the broker");
    let id = handle.id().to_string();
    let _pipe = h.pipes().take().expect("pipe handle for the session");

    let mut s = h.session().await;
    s.session_read(wire::SessionRead {
        session_id: id.clone(),
        ..Default::default()
    })
    .await
    .expect("read-only may attach and read");
    assert!(authorized(s.session_list().await));
    match s.session_write(&id, b"x".to_vec()).await {
        Err(ClientError::Remote { code, message, .. }) => {
            assert_eq!(code, ErrorCode::PermissionDenied);
            assert_eq!(message, PERMISSION_DENIED_MESSAGE);
        }
        other => panic!("read-only must not write, got {other:?}"),
    }
    s.close();
    h.shutdown().await;
}

both_routes!(read_only_scenario =>
    role_read_only_can_attach_but_not_write_forward,
    role_read_only_can_attach_but_not_write_reverse);

/// `tunnel` is the one owned role: it may open and close its own `-R`
/// forward, never close another principal's. Forward route here (two devices
/// dial one host); the `_reverse` twin below has two controllers the target
/// dials.
#[tokio::test(flavor = "multi_thread")]
async fn role_tunnel_cannot_close_another_principals_remote_forward_forward() {
    let owner = make_identity();
    let other = make_identity();
    let text = format!(
        "{}{}",
        peer_block("laptop", &owner.fingerprint, Some("tunnel")),
        peer_block("desktop", &other.fingerprint, Some("tunnel"))
    );
    let env = Env::with_trust_text(owner.clone(), &text, AclFile::Missing);
    let server_trust = env
        .host_trust()
        .with_pin(other.fingerprint, Principal::Device("desktop".to_string()));
    let h = TunnelHarness::start_custom(env.authorizer(Role::Serve), owner, server_trust).await;
    let forward = h.remote_forward("127.0.0.1", h.echo.port()).await;
    let addr = forward.host_addr();
    let forward_id = forward.forward_id().to_string();

    let client_trust = StaticTrust::empty().with_pin(
        h.host.server_identity.fingerprint,
        Principal::Device("box".into()),
    );
    let dialer = Dialer::new(other.local.clone(), Arc::new(client_trust));
    let dialed = dialer.dial(h.host.addr, "127.0.0.1").await.expect("dial");
    let mut desktop = Session::negotiate(dialed.connection, "desktop")
        .await
        .expect("negotiate");

    // The role grants `forward.remote`, but its owner axis stops the close
    // of a forward `laptop` opened.
    match desktop
        .rfwd_close(wire::RemoteForwardClose {
            forward_id: forward_id.clone(),
        })
        .await
    {
        Err(ClientError::Remote { code, message, .. }) => {
            assert_eq!(code, ErrorCode::PermissionDenied);
            assert_eq!(message, PERMISSION_DENIED_MESSAGE);
        }
        other => panic!("a tunnel peer must not close another's forward, got {other:?}"),
    }
    assert_eq!(
        TunnelHarness::round_trip(addr, b"still alive".to_vec())
            .await
            .expect("round trip"),
        b"still alive",
        "the forward survives the refused close"
    );
    let records = h.audit().records();
    assert!(
        records.iter().any(|r| r.principal == "device:desktop"
            && r.action == "forward.remote"
            && r.decision == "deny"
            && r.resource == forward_id),
        "{records:?}"
    );

    // Its own forward, the other peer can open and close freely.
    let own = desktop
        .rfwd_open(wire::RemoteForwardOpen {
            bind_host: String::new(),
            bind_port: 0,
            forward_host: "127.0.0.1".to_string(),
            forward_port: u32::from(h.echo.port()),
            claim_token: Vec::new(),
        })
        .await
        .expect("a tunnel peer may open a forward");
    desktop
        .rfwd_close(wire::RemoteForwardClose {
            forward_id: own.forward_id,
        })
        .await
        .expect("and close its own");

    desktop.close();
    forward.close().await;
    h.shutdown().await;
}

/// Reverse route: `laptop` (the harness controller) opens a `-R` forward on the
/// target; a second controller `desktop`, also dialed by the target and served
/// by the same host, holds `tunnel` too but must not close `laptop`'s forward.
#[tokio::test(flavor = "multi_thread")]
async fn role_tunnel_cannot_close_another_principals_remote_forward_reverse() {
    let owner = make_identity();
    let other = make_identity();
    let text = format!(
        "{}{}",
        peer_block("laptop", &owner.fingerprint, Some("tunnel")),
        peer_block("desktop", &other.fingerprint, Some("tunnel"))
    );
    let env = Env::with_trust_text(owner.clone(), &text, AclFile::Missing);
    let h = ReversePairHarness::start_custom(env.authorizer(Role::Serve), owner).await;
    let echo = EchoServer::start().await.expect("echo server");

    let mut laptop = h.session().await;
    let acceptor = RemoteForwardAcceptor::spawn(laptop.connection().clone()).await;
    let opened = laptop
        .rfwd_open(wire::RemoteForwardOpen {
            bind_host: String::new(),
            bind_port: 0,
            forward_host: "127.0.0.1".to_string(),
            forward_port: u32::from(echo.port()),
            claim_token: Vec::new(),
        })
        .await
        .expect("a tunnel peer may open a forward");
    let forward_id = opened.forward_id.clone();
    acceptor.register(forward_id.clone(), "127.0.0.1".to_string(), echo.port());
    let addr = SocketAddr::from((
        [127, 0, 0, 1],
        u16::try_from(opened.actual_port).expect("port fits u16"),
    ));

    let mut desktop = h.session_from_second_controller(&other, "desktop").await;
    match desktop
        .rfwd_close(wire::RemoteForwardClose {
            forward_id: forward_id.clone(),
        })
        .await
    {
        Err(ClientError::Remote { code, message, .. }) => {
            assert_eq!(code, ErrorCode::PermissionDenied);
            assert_eq!(message, PERMISSION_DENIED_MESSAGE);
        }
        other => panic!("a tunnel peer must not close another's forward, got {other:?}"),
    }
    assert_eq!(
        TunnelHarness::round_trip(addr, b"still alive".to_vec())
            .await
            .expect("round trip"),
        b"still alive",
        "the forward survives the refused close"
    );
    let records = h.audit().records();
    assert!(
        records.iter().any(|r| r.principal == "device:desktop"
            && r.action == "forward.remote"
            && r.decision == "deny"
            && r.resource == forward_id),
        "{records:?}"
    );

    // Its own forward, the other peer can open and close freely.
    let own = desktop
        .rfwd_open(wire::RemoteForwardOpen {
            bind_host: String::new(),
            bind_port: 0,
            forward_host: "127.0.0.1".to_string(),
            forward_port: u32::from(echo.port()),
            claim_token: Vec::new(),
        })
        .await
        .expect("a tunnel peer may open a forward");
    desktop
        .rfwd_close(wire::RemoteForwardClose {
            forward_id: own.forward_id,
        })
        .await
        .expect("and close its own");

    desktop.close();
    acceptor.unregister(&forward_id);
    laptop
        .rfwd_close(wire::RemoteForwardClose { forward_id })
        .await
        .expect("the owner closes its own");
    laptop.close();
    h.shutdown().await;
}
