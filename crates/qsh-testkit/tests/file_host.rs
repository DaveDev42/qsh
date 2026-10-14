//! The host control plane of the remote file ops
//! (ADR-0029 decisions 3, 4-6, 5, 6-4 to 6-6, 8, 9, 12 and 20; ADR-0045
//! decision 18), driven end to end by a raw wire requester. There is no
//! client in this step, so each request is a hand-built `ControlMessage`
//! sent on a real connection, and the reply is read back the same way. Data
//! never flows: a `file.read`/`file.write` ticket is only ever issued, then
//! dropped or left to expire (the `FILE_DATA` stream lands in Step 13).
//!
//! Every host here gets its authorizer from [`qsh_core::acl::load_or_deny`]
//! over a sandbox whose `trust.toml` and `acl.toml` are written by hand, so
//! the chain under test is the production one: trust role -> evaluator ->
//! state-path check -> open and recheck. Each scenario is generic over
//! [`Route`] and runs on the forward route (`qsh serve`,
//! [`LoopbackHarness`]) and the reverse route (`qsh serve --to`,
//! [`ReversePairHarness`]) with the same body.
//!
//! The sandbox keeps the served data (`share/`, `outside/`) and qsh's own
//! state (`host/config`, `host/state`, `host/run`) side by side, so a path
//! that escapes `share/` and a path that lands in the state tree are both a
//! few components away. Snapshots compare whole trees byte for byte.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::future::Future;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::{Authorizer, PERMISSION_DENIED_MESSAGE, Role, load_or_deny};
use qsh_core::audit::AuditRecord;
use qsh_core::client::Session;
use qsh_core::config::{AuditConfig, Paths};
use qsh_core::file::guard::{CountingNormalizer, FsNormalizer, NormalizeError, Normalizer};
use qsh_core::server::Server;
use qsh_core::trust::SharedTrustStore;
use qsh_proto::ErrorCode;
use qsh_proto::wire::{
    self, ControlMessage, FILE_LIST_DIR_MAX, FILE_LIST_PAGE_MAX, control_message, response,
};
use qsh_testkit::loopback::{LoopbackHarness, TestIdentity, make_identity};
use qsh_testkit::pair::HostedPair;
use qsh_testkit::reverse::{ReversePairHarness, wait_for};
use qsh_transport::{Principal, StaticTrust};

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

/// Resolves a path without touching the filesystem: `.` and `..` folded
/// lexically, symlinks left alone. Stands in for a normalizer that was
/// correct a moment ago, so a symlink swapped in afterwards is only caught by
/// the opened-handle recheck (ADR-0029 decision 6-4).
struct Switch {
    lexical: bool,
}

impl Normalizer for Switch {
    fn normalize(&self, absolute: &Path) -> Result<PathBuf, NormalizeError> {
        if !self.lexical {
            return FsNormalizer.normalize(absolute);
        }
        let mut out = PathBuf::new();
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

struct Env {
    _dir: tempfile::TempDir,
    /// The served data. Always exists.
    share: PathBuf,
    /// A sibling of `share` the ACL never covers.
    outside: PathBuf,
    /// The root of qsh's own state tree (`host/`).
    host: PathBuf,
    paths: Paths,
    audit_cfg: AuditConfig,
    trust: Arc<SharedTrustStore>,
    client: TestIdentity,
    normalizer: Arc<CountingNormalizer<Switch>>,
}

fn write_private(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, bytes).expect("write file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

impl Env {
    /// A sandbox whose `trust.toml` pins the harness client as `laptop`
    /// carrying `role` (no `role` key when `None`), with no `acl.toml`.
    fn new(role: Option<&str>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canonical tempdir");
        let share = root.join("share");
        let outside = root.join("outside");
        let host = root.join("host");
        for d in [
            &share,
            &outside,
            &host.join("config/identity"),
            &host.join("state"),
            &host.join("run"),
        ] {
            std::fs::create_dir_all(d).expect("create dir");
        }
        std::fs::write(share.join("a.txt"), b"alpha\n").unwrap();
        std::fs::write(outside.join("secret.txt"), b"TOPSECRET").unwrap();

        let paths =
            Paths::new(host.join("config"), host.join("state")).with_runtime_dir(host.join("run"));
        let client = make_identity();
        let role_line = role.map_or(String::new(), |r| format!("role = \"{r}\"\n"));
        let trust_text = format!(
            "[[peer]]\nname = \"laptop\"\nfingerprint = \"{}\"\naddress = \"\"\n\
             added_at = \"2026-10-14T00:00:00Z\"\n{role_line}\n",
            client.fingerprint
        );
        std::fs::write(paths.trust_file(), trust_text).expect("write trust.toml");
        let trust = SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");
        Self {
            _dir: dir,
            share,
            outside,
            host,
            paths,
            audit_cfg: AuditConfig::default(),
            trust,
            client,
            normalizer: Arc::new(CountingNormalizer::new(Switch { lexical: false })),
        }
    }

    /// Use the lexical normalizer (see [`Switch`]).
    fn lexical(mut self) -> Self {
        self.normalizer = Arc::new(CountingNormalizer::new(Switch { lexical: true }));
        self
    }

    /// Write `acl.toml`: one row for the harness client allowing `allow`,
    /// with `paths` when given.
    fn acl_rows(self, allow: &[&str], paths: Option<&[&Path]>) -> Self {
        let allow = allow
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut text = format!("[[acl]]\nprincipal = \"device:laptop\"\nallow = [{allow}]\n");
        if let Some(paths) = paths {
            let list = paths
                .iter()
                .map(|p| format!("\"{}\"", p.display()))
                .collect::<Vec<_>>()
                .join(", ");
            text.push_str(&format!("paths = [{list}]\n"));
        }
        write_private(&self.paths.acl_file(), text.as_bytes());
        self
    }

    /// An `acl.toml` that does not mention the harness client at all.
    fn acl_for_someone_else(self) -> Self {
        write_private(
            &self.paths.acl_file(),
            b"[[acl]]\nprincipal = \"device:somebody-else\"\nallow = [\"exec.run\"]\n",
        );
        self
    }

    /// Put bytes in the state files ADR-0029 decision 5 protects, those the
    /// sandbox does not already hold. The returned list is what the tests
    /// aim at: `acl.toml` (when present), `trust.toml`, `invites.toml`, the
    /// identity key and the audit file.
    fn seed_state(&self) -> Vec<PathBuf> {
        let invites = self.paths.invites_file();
        let key = self.paths.identity_dir().join("device.key");
        let audit = self.paths.audit_log();
        write_private(&invites, b"# invites\n");
        write_private(&key, b"-----KEY-----\n");
        write_private(&audit, b"{\"audit\":1}\n");
        let mut targets = vec![self.paths.trust_file(), invites, key, audit];
        if self.paths.acl_file().exists() {
            targets.insert(0, self.paths.acl_file());
        }
        targets
    }

    fn authorizer(&self) -> Arc<dyn Authorizer> {
        let (authorizer, _diagnostic) =
            load_or_deny(&self.paths, Role::Serve, Arc::clone(&self.trust));
        authorizer
    }

    fn host_trust(&self) -> StaticTrust {
        StaticTrust::empty().with_pin(
            self.client.fingerprint,
            Principal::Device("laptop".to_string()),
        )
    }

    /// Tell a started host where its state tree is and which normalizer to
    /// use (production does the same in `serve::host_runtime`).
    fn wire(&self, server: &Server) {
        server.set_path_normalizer(self.normalizer.clone() as Arc<dyn Normalizer>);
        server.set_file_host(self.paths.clone(), self.audit_cfg.clone());
    }

    fn share_path(&self, rel: &str) -> String {
        format!("{}/{rel}", self.share.display())
    }

    fn normalizer_calls(&self) -> usize {
        self.normalizer.calls()
    }
}

trait Route: HostedPair {
    fn start(env: &Env) -> impl Future<Output = Self>;
}

impl Route for LoopbackHarness {
    async fn start(env: &Env) -> Self {
        let h =
            LoopbackHarness::start_custom(env.authorizer(), env.client.clone(), env.host_trust())
                .await;
        env.wire(h.server());
        h
    }
}

impl Route for ReversePairHarness {
    async fn start(env: &Env) -> Self {
        let h = ReversePairHarness::start_custom(env.authorizer(), env.client.clone()).await;
        env.wire(h.server());
        h
    }
}

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

// ---------------------------------------------------------------------------
// Trees
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Node {
    Dir,
    Link(PathBuf),
    File(Vec<u8>),
}

/// Every entry under `root` (not following symlinks), with bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Node> {
    fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Node>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).expect("lstat");
            if meta.file_type().is_symlink() {
                out.insert(path.clone(), Node::Link(std::fs::read_link(&path).unwrap()));
            } else if meta.is_dir() {
                out.insert(path.clone(), Node::Dir);
                walk(&path, out);
            } else {
                out.insert(path.clone(), Node::File(std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, &mut out);
    out
}

// ---------------------------------------------------------------------------
// The raw requester
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Reply {
    /// `PERMISSION_DENIED` carrying exactly [`PERMISSION_DENIED_MESSAGE`].
    Denied,
    Err(ErrorCode, String),
    Read(wire::FileReadOpened),
    Write(wire::FileWriteOpened),
    List(wire::FileListed),
    Mkdir(wire::FileMkdirDone),
}

impl Reply {
    fn is_denied(&self) -> bool {
        matches!(self, Reply::Denied)
    }

    fn code(&self) -> Option<ErrorCode> {
        match self {
            Reply::Denied => Some(ErrorCode::PermissionDenied),
            Reply::Err(code, message) => {
                assert!(!message.is_empty(), "an error says what went wrong");
                Some(code.clone())
            }
            _ => None,
        }
    }

    fn read(self) -> wire::FileReadOpened {
        match self {
            Reply::Read(r) => r,
            other => panic!("expected FileReadOpened, got {other:?}"),
        }
    }

    fn write(self) -> wire::FileWriteOpened {
        match self {
            Reply::Write(r) => r,
            other => panic!("expected FileWriteOpened, got {other:?}"),
        }
    }

    fn list(self) -> wire::FileListed {
        match self {
            Reply::List(r) => r,
            other => panic!("expected FileListed, got {other:?}"),
        }
    }

    fn mkdir(self) -> wire::FileMkdirDone {
        match self {
            Reply::Mkdir(r) => r,
            other => panic!("expected FileMkdirDone, got {other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Read,
    Write,
    List,
    Mkdir,
}

const ALL_OPS: [Op; 4] = [Op::Read, Op::Write, Op::List, Op::Mkdir];

impl Op {
    /// The audit action of the op (ADR-0029 decision 3).
    fn action(self) -> &'static str {
        match self {
            Op::Read | Op::List => "file.read",
            Op::Write | Op::Mkdir => "file.write",
        }
    }
}

struct Conn {
    s: Session,
    id: u64,
}

impl Conn {
    async fn open<R: HostedPair>(h: &R) -> Self {
        Self {
            s: h.session().await,
            id: 0,
        }
    }

    async fn send(&mut self, body: control_message::Body) -> Reply {
        self.id += 1;
        let id = self.id;
        self.s
            .send_control_message(&ControlMessage::new(id, body))
            .await
            .expect("send file request");
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(20), self.s.next_control_message())
                .await
                .expect("the host answers in time")
                .expect("control stream is readable")
                .expect("control stream is open");
            let Some(control_message::Body::Response(wire::Response { body: Some(body) })) =
                msg.body
            else {
                continue;
            };
            assert_eq!(msg.request_id, id, "reply correlates with its request");
            return match body {
                response::Body::Error(e) => {
                    let code = e.error_code();
                    if code == ErrorCode::PermissionDenied {
                        assert_eq!(
                            e.message, PERMISSION_DENIED_MESSAGE,
                            "a denial carries the uniform message"
                        );
                        Reply::Denied
                    } else {
                        Reply::Err(code, e.message)
                    }
                }
                response::Body::FileReadOpened(r) => Reply::Read(r),
                response::Body::FileWriteOpened(r) => Reply::Write(r),
                response::Body::FileListed(r) => Reply::List(r),
                response::Body::FileMkdirDone(r) => Reply::Mkdir(r),
                other => panic!("unexpected reply body {other:?}"),
            };
        }
    }

    async fn read(&mut self, path: &str) -> Reply {
        self.read_as(path, "").await
    }

    async fn read_as(&mut self, path: &str, user: &str) -> Reply {
        self.send(control_message::Body::FileReadOpen(wire::FileReadOpen {
            path: path.into(),
            user: user.into(),
        }))
        .await
    }

    async fn write(&mut self, path: &str, overwrite: bool, name_if_dir: &str) -> Reply {
        self.send(control_message::Body::FileWriteOpen(wire::FileWriteOpen {
            path: path.into(),
            size: 5,
            mode: 0o644,
            overwrite,
            name_if_dir: name_if_dir.into(),
            ..Default::default()
        }))
        .await
    }

    async fn list(&mut self, path: &str, after: &str) -> Reply {
        self.send(control_message::Body::FileListOpen(wire::FileListOpen {
            path: path.into(),
            after: after.into(),
            ..Default::default()
        }))
        .await
    }

    async fn mkdir(&mut self, path: &str, name_if_dir: &str) -> Reply {
        self.send(control_message::Body::FileMkdirOpen(wire::FileMkdirOpen {
            path: path.into(),
            mode: 0o755,
            name_if_dir: name_if_dir.into(),
            ..Default::default()
        }))
        .await
    }

    /// The op, in its most destructive shape (`overwrite = true`, no
    /// `name_if_dir`).
    async fn op(&mut self, op: Op, path: &str) -> Reply {
        match op {
            Op::Read => self.read(path).await,
            Op::Write => self.write(path, true, "").await,
            Op::List => self.list(path, "").await,
            Op::Mkdir => self.mkdir(path, "").await,
        }
    }
}

fn file_records<R: HostedPair>(h: &R) -> Vec<AuditRecord> {
    h.audit()
        .records()
        .into_iter()
        .filter(|r| r.action.starts_with("file."))
        .collect()
}

/// Every op on every path is the uniform denial, leaves exactly the audit
/// lines `lines` says, and mints no ticket. `lines` is 1 for a refusal by
/// the ACL itself and 2 when the ACL allowed and a later stage refused.
async fn assert_denied_everywhere<R: HostedPair>(
    h: &R,
    conn: &mut Conn,
    targets: &[String],
    lines: usize,
) {
    let tickets_before = h.server().pending_tickets();
    for target in targets {
        for op in ALL_OPS {
            h.audit().clear();
            let reply = conn.op(op, target).await;
            assert!(reply.is_denied(), "{op:?} {target}: {reply:?}");
            let records = file_records(h);
            assert_eq!(records.len(), lines, "{op:?} {target}: {records:?}");
            let last = records.last().unwrap();
            assert_eq!(last.decision, "deny", "{op:?} {target}");
            assert_eq!(last.action, op.action(), "{op:?} {target}");
            assert_eq!(last.resource, *target, "{op:?} {target}");
            if lines == 2 {
                assert_eq!(records[0].decision, "allow", "{op:?} {target}");
                assert_eq!(last.rule, None, "{op:?} {target}");
                assert_eq!(last.role, None, "{op:?} {target}");
            }
        }
    }
    assert_eq!(h.server().pending_tickets(), tickets_before);
}

fn s(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_string()
}

// ---------------------------------------------------------------------------
// ACL: no ground, no touch
// ---------------------------------------------------------------------------

async fn ops_denied_without_a_grant<R: Route>() {
    let cases: Vec<Env> = vec![
        // No role, no acl.toml.
        Env::new(None),
        // A role that grants no file access.
        Env::new(Some("exec")),
        // A row that names another action only.
        Env::new(None).acl_rows(&["exec.run"], None),
    ];
    for env in cases {
        let h = R::start(&env).await;
        let mut conn = Conn::open(&h).await;
        let before = snapshot(&env.share);
        let target = env.share_path("a.txt");
        assert_denied_everywhere(&h, &mut conn, &[target], 1).await;
        assert_eq!(snapshot(&env.share), before);
        assert_eq!(env.normalizer_calls(), 0, "no ground, no path lookup");
        h.shutdown().await;
    }
}
both_routes!(ops_denied_without_a_grant =>
    file_ops_are_denied_without_a_matching_rule_or_role_forward,
    file_ops_are_denied_without_a_matching_rule_or_role_reverse);

async fn rule_without_paths<R: Route>() {
    // A row that names `file.*` but has no `paths` grants nothing, and the
    // loader still accepts the file (it only warns).
    let env = Env::new(None).acl_rows(&["file.*", "exec.run"], None);
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let before = snapshot(&env.share);
    assert_denied_everywhere(&h, &mut conn, &[env.share_path("a.txt")], 1).await;
    assert_eq!(snapshot(&env.share), before);
    assert_eq!(env.normalizer_calls(), 0);
    h.shutdown().await;
}
both_routes!(rule_without_paths =>
    file_rule_without_paths_grants_no_file_access_forward,
    file_rule_without_paths_grants_no_file_access_reverse);

async fn no_grant_no_normalize<R: Route>() {
    let env = Env::new(None).acl_rows(&["exec.run"], None);
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    // A path that cannot exist, so a lookup would be observable only
    // through the counter.
    let target = "/qsh-no-such-root/dir/../file".to_string();
    assert_denied_everywhere(&h, &mut conn, &[target], 1).await;
    assert_eq!(env.normalizer_calls(), 0);
    h.shutdown().await;

    // The counter is live: a request that does have ground is normalized.
    let env = Env::new(Some("full"));
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let reply = conn.read(&env.share_path("a.txt")).await;
    reply.read();
    assert!(env.normalizer_calls() > 0);
    h.shutdown().await;
}
both_routes!(no_grant_no_normalize =>
    file_request_without_a_file_grant_touches_no_filesystem_forward,
    file_request_without_a_file_grant_touches_no_filesystem_reverse);

// ---------------------------------------------------------------------------
// State paths
// ---------------------------------------------------------------------------

/// The state-path targets of the role `full` tests: the five files, a
/// symlink from the data area to one of them, a `..` escape, and a name that
/// does not exist yet below the config directory.
fn state_targets(env: &Env, files: &[PathBuf]) -> Vec<String> {
    let mut out: Vec<String> = files.iter().map(|p| s(p)).collect();
    let link = env.share.join("link-to-trust");
    std::os::unix::fs::symlink(env.paths.trust_file(), &link).unwrap();
    out.push(s(&link));
    out.push(env.share_path("../host/config/trust.toml"));
    out.push(env.share_path("sub/../../host/state/audit.log"));
    out.push(s(&env.paths.config_dir.join("not-yet.toml")));
    out
}

async fn full_role_allows_any_path_but_not_state<R: Route>() {
    let env = Env::new(Some("full")).acl_for_someone_else();
    let files = env.seed_state();
    let targets = state_targets(&env, &files);
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;

    // `full` reaches ordinary paths, whatever `paths` says (there is none).
    h.audit().clear();
    let read = conn.read(&env.share_path("a.txt")).await.read();
    assert_eq!(read.size, 6);
    assert!(!read.ticket.is_empty());
    let created = conn.mkdir(&env.share_path("made"), "").await.mkdir();
    assert!(created.created);
    conn.list(&env.share_path(""), "").await.list();
    let outside = conn.read(&s(&env.outside.join("secret.txt"))).await.read();
    assert_eq!(outside.size, 9);
    let records = file_records(&h);
    assert_eq!(records.len(), 4, "{records:?}");
    for record in &records {
        assert_eq!(record.decision, "allow");
        assert_eq!(record.rule, None);
        assert_eq!(record.role.as_deref(), Some("full"));
    }
    let tickets = h.server().pending_tickets();

    // And is stopped at the state tree, on all four ops.
    let before = snapshot(&env.host);
    assert_denied_everywhere(&h, &mut conn, &targets, 2).await;
    assert_eq!(
        snapshot(&env.host),
        before,
        "state tree bytes are unchanged"
    );
    assert_eq!(h.server().pending_tickets(), tickets);
    h.shutdown().await;
}
both_routes!(full_role_allows_any_path_but_not_state =>
    role_full_file_ops_allow_any_path_but_still_deny_state_paths_forward,
    role_full_file_ops_allow_any_path_but_still_deny_state_paths_reverse);

async fn full_role_cannot_touch_trust_state<R: Route>() {
    // No acl.toml: asking to create one is as refused as overwriting one.
    let env = Env::new(Some("full"));
    let files = env.seed_state();
    assert!(!env.paths.acl_file().exists());
    let before = snapshot(&env.host);
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let mut targets: Vec<String> = files.iter().map(|p| s(p)).collect();
    targets.push(s(&env.paths.acl_file()));
    assert_denied_everywhere(&h, &mut conn, &targets, 2).await;
    assert_eq!(snapshot(&env.host), before);
    assert!(!env.paths.acl_file().exists(), "no acl.toml was created");
    h.shutdown().await;
}
both_routes!(full_role_cannot_touch_trust_state =>
    role_full_file_ops_still_deny_state_paths_forward,
    role_full_file_ops_still_deny_state_paths_reverse);

async fn root_paths_write_to_state<R: Route>() {
    let env = Env::new(None).acl_rows(&["file.*"], Some(&[Path::new("/")]));
    let files = env.seed_state();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    // Positive control: the grant reaches the data area.
    conn.write(&env.share_path("new.txt"), false, "")
        .await
        .write();

    let before = snapshot(&env.host);
    let mut targets: Vec<String> = files.iter().map(|p| s(p)).collect();
    targets.push(s(&env.paths.state_dir.join("fresh.txt")));
    for target in &targets {
        for overwrite in [true, false] {
            let reply = conn.write(target, overwrite, "").await;
            assert!(reply.is_denied(), "{target}: {reply:?}");
        }
        let reply = conn.mkdir(target, "").await;
        assert!(reply.is_denied(), "{target}: {reply:?}");
    }
    // Into the state directories under a name.
    for dir in [&env.paths.config_dir, &env.paths.state_dir] {
        let reply = conn.write(&s(dir), true, "acl.toml").await;
        assert!(reply.is_denied(), "{dir:?}: {reply:?}");
    }
    assert_eq!(snapshot(&env.host), before);
    h.shutdown().await;
}
both_routes!(root_paths_write_to_state =>
    file_write_to_state_paths_is_denied_even_with_root_paths_forward,
    file_write_to_state_paths_is_denied_even_with_root_paths_reverse);

async fn root_paths_read_state<R: Route>() {
    let env = Env::new(None).acl_rows(&["file.*"], Some(&[Path::new("/")]));
    let files = env.seed_state();
    // A rotated audit slot is part of the audit family.
    let rotated = env.paths.state_dir.join("audit.log.3");
    write_private(&rotated, b"{\"old\":1}\n");
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    conn.read(&env.share_path("a.txt")).await.read();

    // Hard links into the data area: the name is innocent, the inode is not.
    let mut targets: Vec<String> = Vec::new();
    for (i, file) in files.iter().chain([&rotated]).enumerate() {
        let link = env.share.join(format!("hard-{i}"));
        std::fs::hard_link(file, &link).expect("hard link");
        targets.push(s(&link));
        targets.push(s(file));
    }
    let tickets = h.server().pending_tickets();
    for target in &targets {
        let reply = conn.read(target).await;
        assert!(reply.is_denied(), "{target}: {reply:?}");
    }
    assert_eq!(h.server().pending_tickets(), tickets);
    h.shutdown().await;
}
both_routes!(root_paths_read_state =>
    file_read_of_state_paths_is_denied_even_with_root_paths_forward,
    file_read_of_state_paths_is_denied_even_with_root_paths_reverse);

async fn list_and_mkdir_in_state_dirs<R: Route>() {
    let env = Env::new(Some("full"));
    env.seed_state();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let before = snapshot(&env.host);
    let dirs = [
        s(&env.paths.config_dir),
        s(&env.paths.state_dir),
        s(&env.paths.runtime_dir()),
        s(&env.paths.identity_dir()),
    ];
    for dir in &dirs {
        let reply = conn.list(dir, "").await;
        assert!(reply.is_denied(), "list {dir}: {reply:?}");
        // The directory itself (it exists) and a new name inside it.
        let reply = conn.mkdir(dir, "").await;
        assert!(reply.is_denied(), "mkdir {dir}: {reply:?}");
        let reply = conn.mkdir(&format!("{dir}/evil"), "").await;
        assert!(reply.is_denied(), "mkdir {dir}/evil: {reply:?}");
        let reply = conn.mkdir(dir, "evil").await;
        assert!(reply.is_denied(), "mkdir {dir} + name: {reply:?}");
    }
    assert_eq!(snapshot(&env.host), before);
    h.shutdown().await;
}
both_routes!(list_and_mkdir_in_state_dirs =>
    file_list_and_mkdir_in_state_dirs_are_denied_forward,
    file_list_and_mkdir_in_state_dirs_are_denied_reverse);

async fn custom_audit_path_is_protected<R: Route>() {
    // An `[audit] path` outside the state directory is protected too, with
    // its rotated slots.
    let mut env = Env::new(Some("full"));
    let audit = env.share.join("custom-audit.log");
    env.audit_cfg.path = Some(s(&audit));
    write_private(&audit, b"{\"a\":1}\n");
    write_private(&env.share.join("custom-audit.log.2"), b"{\"b\":1}\n");
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let before = snapshot(&env.share);
    let targets = vec![
        s(&audit),
        env.share_path("custom-audit.log.2"),
        env.share_path("custom-audit.log.9"),
    ];
    assert_denied_everywhere(&h, &mut conn, &targets, 2).await;
    assert_eq!(snapshot(&env.share), before);
    // Next to it, an ordinary name is not protected.
    conn.read(&env.share_path("a.txt")).await.read();
    h.shutdown().await;
}
both_routes!(custom_audit_path_is_protected =>
    file_ops_protect_a_custom_audit_path_and_its_rotated_slots_forward,
    file_ops_protect_a_custom_audit_path_and_its_rotated_slots_reverse);

// ---------------------------------------------------------------------------
// `paths`
// ---------------------------------------------------------------------------

async fn symlink_out_of_paths<R: Route>() {
    let env_probe = Env::new(None);
    let share = env_probe.share.clone();
    let env = env_probe.acl_rows(&["file.*"], Some(&[share.as_path()]));
    std::os::unix::fs::symlink(env.outside.join("secret.txt"), env.share.join("out")).unwrap();
    std::os::unix::fs::symlink(&env.outside, env.share.join("outdir")).unwrap();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    conn.read(&env.share_path("a.txt")).await.read();

    let before = snapshot(&env.outside);
    let targets = vec![
        env.share_path("out"),
        env.share_path("outdir/secret.txt"),
        env.share_path("outdir"),
        env.share_path("outdir/new.txt"),
    ];
    assert_denied_everywhere(&h, &mut conn, &targets, 1).await;
    assert_eq!(snapshot(&env.outside), before);
    h.shutdown().await;
}
both_routes!(symlink_out_of_paths =>
    file_read_through_a_symlink_out_of_paths_is_denied_forward,
    file_read_through_a_symlink_out_of_paths_is_denied_reverse);

async fn dotdot_out_of_paths<R: Route>() {
    let probe = Env::new(None);
    let share = probe.share.clone();
    let env = probe.acl_rows(&["file.*"], Some(&[share.as_path()]));
    std::fs::create_dir(env.share.join("sub")).unwrap();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    // `..` that stays inside resolves and is allowed.
    conn.read(&env.share_path("sub/../a.txt")).await.read();

    let before = snapshot(&env.outside);
    let targets = vec![
        env.share_path("../outside/secret.txt"),
        env.share_path("sub/../../outside/secret.txt"),
        env.share_path("../outside"),
        env.share_path("../outside/new.txt"),
    ];
    assert_denied_everywhere(&h, &mut conn, &targets, 1).await;
    assert_eq!(snapshot(&env.outside), before);
    h.shutdown().await;
}
both_routes!(dotdot_out_of_paths =>
    file_dotdot_escape_out_of_paths_is_denied_forward,
    file_dotdot_escape_out_of_paths_is_denied_reverse);

async fn recheck_the_opened_handle<R: Route>() {
    // The normalizer here is lexical, so it does not see the symlink at
    // `share/swap`: the ACL and the state-path stage both pass on a path that
    // looks inside `share`. What the open reaches is `outside/sub`, which the
    // recheck of the opened handle catches, one audit line after the
    // ACL's own.
    let probe = Env::new(None);
    let share = probe.share.clone();
    let env = probe
        .lexical()
        .acl_rows(&["file.*"], Some(&[share.as_path()]));
    std::fs::create_dir(env.outside.join("sub")).unwrap();
    std::fs::write(env.outside.join("sub/secret.txt"), b"TOPSECRET").unwrap();
    std::os::unix::fs::symlink(&env.outside, env.share.join("swap")).unwrap();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    conn.read(&env.share_path("a.txt")).await.read();

    let before = snapshot(&env.outside);
    let tickets = h.server().pending_tickets();
    for (op, rel) in [
        (Op::Read, "swap/sub/secret.txt"),
        (Op::Write, "swap/sub/new.txt"),
        (Op::Write, "swap/sub/secret.txt"),
        (Op::Mkdir, "swap/sub/newdir"),
    ] {
        let target = env.share_path(rel);
        h.audit().clear();
        let reply = conn.op(op, &target).await;
        assert!(reply.is_denied(), "{op:?} {rel}: {reply:?}");
        let records = file_records(&h);
        assert_eq!(records.len(), 2, "{op:?} {rel}: {records:?}");
        assert_eq!(records[0].decision, "allow");
        assert_eq!(records[1].decision, "deny");
        assert_eq!(records[1].rule, None);
        assert_eq!(records[1].role, None);
    }
    assert_eq!(h.server().pending_tickets(), tickets);
    assert_eq!(snapshot(&env.outside), before);
    h.shutdown().await;
}
both_routes!(recheck_the_opened_handle =>
    file_paths_recheck_the_opened_handle_forward,
    file_paths_recheck_the_opened_handle_reverse);

// ---------------------------------------------------------------------------
// Nothing is created before authorization, nothing is left by an
// unredeemed ticket
// ---------------------------------------------------------------------------

async fn denied_write_leaves_nothing<R: Route>() {
    let probe = Env::new(None);
    let allowed = probe.share.join("allowed");
    std::fs::create_dir(&allowed).unwrap();
    let env = probe.acl_rows(&["file.*"], Some(&[allowed.as_path()]));
    let denied = env.share.join("denied");
    std::fs::create_dir(&denied).unwrap();
    std::fs::write(denied.join("existing.txt"), b"keep these bytes").unwrap();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;

    let before = snapshot(&env.share);
    let denied_s = s(&denied);
    for reply in [
        conn.write(&format!("{denied_s}/new.txt"), true, "").await,
        conn.write(&format!("{denied_s}/new.txt"), false, "").await,
        conn.write(&format!("{denied_s}/existing.txt"), true, "")
            .await,
        conn.write(&denied_s, true, "named.txt").await,
        conn.mkdir(&format!("{denied_s}/sub"), "").await,
        conn.mkdir(&denied_s, "sub").await,
    ] {
        assert!(reply.is_denied(), "{reply:?}");
    }
    assert_eq!(snapshot(&env.share), before, "no file, no temp, same bytes");
    assert_eq!(h.server().pending_tickets(), 0);
    h.shutdown().await;
}
both_routes!(denied_write_leaves_nothing =>
    denied_file_write_leaves_no_file_or_temp_behind_forward,
    denied_file_write_leaves_no_file_or_temp_behind_reverse);

async fn unredeemed_ticket_leaves_nothing<R: Route>() {
    let env = Env::new(Some("full"));
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let before = snapshot(&env.share);

    // A write that would create, and one that would replace.
    let created = conn
        .write(&env.share_path("up.txt"), false, "")
        .await
        .write();
    assert!(!created.ticket.is_empty());
    assert!(!created.into_dir);
    conn.write(&env.share_path("a.txt"), true, "").await.write();
    conn.read(&env.share_path("a.txt")).await.read();
    assert_eq!(h.server().pending_tickets(), 3);
    assert_eq!(
        snapshot(&env.share),
        before,
        "the open step creates no file and no temp file, and replaces nothing"
    );

    // The connection goes away without redeeming anything.
    drop(conn);
    wait_for(Duration::from_secs(20), || {
        (h.server().pending_tickets() == 0).then_some(())
    })
    .await;
    assert_eq!(snapshot(&env.share), before);
    h.shutdown().await;
}
both_routes!(unredeemed_ticket_leaves_nothing =>
    unredeemed_file_write_ticket_leaves_nothing_behind_forward,
    unredeemed_file_write_ticket_leaves_nothing_behind_reverse);

// ---------------------------------------------------------------------------
// file.list
// ---------------------------------------------------------------------------

async fn list_pages<R: Route>() {
    let env = Env::new(Some("full"));
    let dir = env.share.join("many");
    std::fs::create_dir(&dir).unwrap();
    let mut expected: Vec<String> = (0..1100).map(|i| format!("f{i:04}")).collect();
    expected.extend(["B".to_string(), "Z".to_string(), "a".to_string()]);
    for name in &expected {
        std::fs::write(dir.join(name), b"").unwrap();
    }
    // One name that is not UTF-8 cannot be listed, only counted.
    std::fs::write(dir.join(std::ffi::OsStr::from_bytes(b"bad-\xff-name")), b"").unwrap();
    expected.sort();

    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let dir_s = s(&dir);
    let mut got: Vec<String> = Vec::new();
    let mut after = String::new();
    let mut pages = 0;
    loop {
        let page = conn.list(&dir_s, &after).await.list();
        pages += 1;
        assert_eq!(page.kind, wire::FileKind::Dir as i32);
        assert_eq!(page.unlistable, 1);
        assert!(page.entries.len() <= FILE_LIST_PAGE_MAX);
        if page.more {
            assert_eq!(page.entries.len(), FILE_LIST_PAGE_MAX);
        }
        got.extend(page.entries.iter().map(|e| e.name.clone()));
        if !page.more {
            break;
        }
        after = page.entries.last().expect("a full page").name.clone();
    }
    assert_eq!(pages, 3);
    assert_eq!(got, expected, "byte order, no gap, no repeat");
    assert_eq!(&got[..3], ["B", "Z", "a"], "byte order puts capitals first");

    // A cursor past the end is an empty last page.
    let tail = conn.list(&dir_s, "zzzz").await.list();
    assert!(tail.entries.is_empty());
    assert!(!tail.more);
    h.shutdown().await;
}
both_routes!(list_pages =>
    file_list_pages_are_sorted_and_resumable_by_cursor_forward,
    file_list_pages_are_sorted_and_resumable_by_cursor_reverse);

async fn list_entry_cap<R: Route>() {
    let env = Env::new(Some("full"));
    let dir = env.share.join("huge");
    std::fs::create_dir(&dir).unwrap();
    for i in 0..=FILE_LIST_DIR_MAX {
        std::fs::File::create(dir.join(format!("{i:06}"))).unwrap();
    }
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let reply = conn.list(&s(&dir), "").await;
    assert_eq!(
        reply.code(),
        Some(ErrorCode::ResourceExhausted),
        "{reply:?}"
    );
    // Removing one entry brings it back under the cap.
    std::fs::remove_file(dir.join("000000")).unwrap();
    let page = conn.list(&s(&dir), "").await.list();
    assert_eq!(page.entries.len(), FILE_LIST_PAGE_MAX);
    assert!(page.more);
    h.shutdown().await;
}
both_routes!(list_entry_cap =>
    file_list_rejects_directories_over_the_entry_cap_forward,
    file_list_rejects_directories_over_the_entry_cap_reverse);

// ---------------------------------------------------------------------------
// Object facts and caller mistakes (only reachable past the ACL)
// ---------------------------------------------------------------------------

async fn replies_for_allowed_requests<R: Route>() {
    let env = Env::new(Some("full"));
    let dir = env.share.join("d");
    std::fs::create_dir(&dir).unwrap();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let a = env.share_path("a.txt");

    let read = conn.read(&a).await.read();
    assert_eq!(read.size, 6);
    assert_ne!(read.mode & 0o777, 0);
    assert!(read.mtime > 0);

    for reply in [
        conn.read(&s(&dir)).await,
        conn.read(&env.share_path("missing.txt")).await,
        conn.read(&format!("{a}/")).await,
        conn.list(&env.share_path("missing"), "").await,
        conn.list(&format!("{a}/"), "").await,
        conn.mkdir(&a, "").await,
        conn.write(&a, false, "").await,
        conn.write(&s(&dir), true, "").await,
        conn.write(&format!("{a}/"), true, "").await,
        conn.write(&env.share_path("no-such-dir/x.txt"), true, "")
            .await,
    ] {
        assert_eq!(reply.code(), Some(ErrorCode::InvalidArgument), "{reply:?}");
    }

    // A file listed is its own facts and no entries.
    let listed = conn.list(&a, "").await.list();
    assert_eq!(listed.kind, wire::FileKind::File as i32);
    assert_eq!(listed.size, 6);
    assert!(listed.entries.is_empty());

    // `name_if_dir` resolves against an existing directory.
    let into = conn.write(&s(&dir), false, "x.txt").await.write();
    assert!(into.into_dir);
    let plain = conn
        .write(&format!("{}/y.txt", s(&dir)), false, "x.txt")
        .await
        .write();
    assert!(!plain.into_dir);

    // mkdir is idempotent on a directory and says whether it created.
    let first = conn.mkdir(&env.share_path("m"), "").await.mkdir();
    assert!(first.created && !first.into_dir);
    let second = conn.mkdir(&env.share_path("m"), "").await.mkdir();
    assert!(!second.created);
    let nested = conn.mkdir(&env.share_path("m"), "inner").await.mkdir();
    assert!(nested.created && nested.into_dir);
    assert!(env.share.join("m/inner").is_dir());
    h.shutdown().await;
}
both_routes!(replies_for_allowed_requests =>
    file_ops_answer_allowed_requests_with_the_object_facts_forward,
    file_ops_answer_allowed_requests_with_the_object_facts_reverse);

async fn user_hint<R: Route>() {
    // With a grant, a `user@` that is not the serve account is UNSUPPORTED.
    let env = Env::new(Some("full"));
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    h.audit().clear();
    let reply = conn
        .read_as(&env.share_path("a.txt"), "qsh-no-such-account")
        .await;
    assert_eq!(reply.code(), Some(ErrorCode::Unsupported), "{reply:?}");
    let records = file_records(&h);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].decision, "allow");
    assert_eq!(h.server().pending_tickets(), 0);
    h.shutdown().await;

    // Without one, the same request is the uniform denial: the serve
    // account's name is never a reply to an unauthorized peer.
    let env = Env::new(None);
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let reply = conn
        .read_as(&env.share_path("a.txt"), "qsh-no-such-account")
        .await;
    assert!(reply.is_denied(), "{reply:?}");
    h.shutdown().await;
}
both_routes!(user_hint =>
    file_user_hint_is_unsupported_only_after_an_allow_forward,
    file_user_hint_is_unsupported_only_after_an_allow_reverse);

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

async fn audit_has_path_but_no_payload<R: Route>() {
    let env = Env::new(Some("full"));
    write_private(&env.share.join("payload.txt"), b"SENTINEL-FILE-CONTENT");
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    h.audit().clear();
    // The path as sent, `..` and all, is the resource; the canonical form
    // and the bytes behind it are not.
    let sent = env.share_path("sub/../payload.txt");
    conn.read(&sent).await.read();
    conn.write(&env.share_path("sentinel-name.txt"), true, "")
        .await
        .write();
    let records = file_records(&h);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].resource, sent);
    assert_eq!(records[0].action, "file.read");
    assert_eq!(records[1].action, "file.write");

    let nine = [
        "ts",
        "request_id",
        "principal",
        "action",
        "resource",
        "decision",
        "rule",
        "auth_path",
        "peer_addr",
    ];
    for record in &records {
        let value = serde_json::to_value(record).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for key in nine {
            assert!(keys.contains(&key), "{key} missing in {value}");
        }
        for key in &keys {
            assert!(
                nine.contains(key) || *key == "role",
                "{key} is not a structural audit field: {value}"
            );
        }
        let text = value.to_string();
        assert!(!text.contains("SENTINEL-FILE-CONTENT"), "{text}");
        assert!(!text.contains("TOPSECRET"), "{text}");
    }
    h.shutdown().await;
}
both_routes!(audit_has_path_but_no_payload =>
    file_audit_record_carries_path_but_no_payload_forward,
    file_audit_record_carries_path_but_no_payload_reverse);

// ---------------------------------------------------------------------------
// `acl check --path` and enforcement agree
// ---------------------------------------------------------------------------

/// The local query (`Ops::acl_check`, what `qsh acl check --path` calls),
/// `acl show` (`Ops::acl_show`) and the running host answer the same for
/// paths the state check does not cover (the query does not run it, CLI.md
/// section 6.15): the allowed file ops get past the ACL, the refused ones are
/// the uniform denial, and `acl show` lists the action exactly when the
/// principal has a ground for it (a row with `paths`, or the role). The
/// argument-contract rows (`--path` missing, `--path` on a non-file action)
/// are `INVALID_ARGUMENT` for the query; the host side of the first is an
/// empty path, which the shape check refuses before any ACL work.
async fn acl_check_agrees_with_enforcement<R: Route>() {
    use qsh_core::ops::Ops;
    use qsh_proto::types::{AclCheckReq, AclShowReq};

    struct Situation {
        env: Env,
        /// Whether `acl show` lists the file actions for the principal.
        shown: bool,
        /// `(path, expected decision)`.
        rows: Vec<(String, bool)>,
    }

    // paths = [share]
    let probe = Env::new(None);
    let share = probe.share.clone();
    let env = probe.acl_rows(&["file.*"], Some(&[share.as_path()]));
    std::os::unix::fs::symlink(env.outside.join("secret.txt"), env.share.join("out")).unwrap();
    std::fs::create_dir(env.share.join("sub")).unwrap();
    let rows = vec![
        (env.share_path("a.txt"), true),
        (env.share_path("sub/../a.txt"), true),
        (env.share_path("new.txt"), true),
        (env.share_path("sub/deeper/new.txt"), true),
        (s(&env.outside.join("secret.txt")), false),
        (env.share_path("out"), false),
        (env.share_path("../outside/secret.txt"), false),
        (s(&share.parent().unwrap().join("share-sibling")), false),
    ];
    let inside = Situation {
        env,
        shown: true,
        rows,
    };

    // A row with no `paths`.
    let env = Env::new(None).acl_rows(&["file.*"], None);
    let rows = vec![(env.share_path("a.txt"), false)];
    let nopaths = Situation {
        env,
        shown: false,
        rows,
    };

    // Role `full` reaches every path.
    let env = Env::new(Some("full"));
    let rows = vec![
        (env.share_path("a.txt"), true),
        (s(&env.outside.join("secret.txt")), true),
    ];
    let full = Situation {
        env,
        shown: true,
        rows,
    };

    for Situation { env, shown, rows } in [inside, nopaths, full] {
        let h = R::start(&env).await;
        let mut conn = Conn::open(&h).await;
        let ops = Ops::new(env.paths.clone());

        let show = ops
            .acl_show(AclShowReq {
                principal: "device:laptop".into(),
                auth_path: None,
            })
            .expect("acl show answers");
        for action in ["file.read", "file.write"] {
            assert_eq!(
                show.effective_actions.iter().any(|a| a == action),
                shown,
                "acl show {action}: {:?}",
                show.effective_actions
            );
        }

        // `--path` missing: the query refuses, and so does the shape check
        // on the host (no ACL work, no ticket).
        for action in ["file.read", "file.write"] {
            let err = ops
                .acl_check(AclCheckReq {
                    principal: "device:laptop".into(),
                    action: action.into(),
                    resource: None,
                    auth_path: None,
                    owner: None,
                    owner_auth_path: None,
                    path: None,
                })
                .expect_err("a file action needs --path");
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{action}");
        }
        for op in ALL_OPS {
            let reply = conn.op(op, "").await;
            assert_eq!(reply.code(), Some(ErrorCode::InvalidArgument), "{op:?}");
        }
        // `--path` on a non-file action: refused by the query; the wire has
        // no such request, so there is no host side to compare.
        let err = ops
            .acl_check(AclCheckReq {
                principal: "device:laptop".into(),
                action: "exec.run".into(),
                resource: None,
                auth_path: None,
                owner: None,
                owner_auth_path: None,
                path: Some(env.share_path("a.txt")),
            })
            .expect_err("--path is for file actions only");
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        for (path, expected) in rows {
            for (action, op) in [("file.read", Op::Read), ("file.write", Op::Write)] {
                let data = ops
                    .acl_check(AclCheckReq {
                        principal: "device:laptop".into(),
                        action: action.into(),
                        resource: None,
                        auth_path: None,
                        owner: None,
                        owner_auth_path: None,
                        path: Some(path.clone()),
                    })
                    .expect("acl check answers");
                let checked = data.decision == "allow";
                let enforced = !conn.op(op, &path).await.is_denied();
                assert_eq!(checked, expected, "acl check {action} {path}");
                assert_eq!(enforced, expected, "enforcement {action} {path}");
            }
        }
        h.shutdown().await;
    }
}
both_routes!(acl_check_agrees_with_enforcement =>
    acl_check_path_agrees_with_enforcement_forward,
    acl_check_path_agrees_with_enforcement_reverse);
