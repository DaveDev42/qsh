//! The host side of the remote file ops: the control plane (ADR-0029
//! decisions 3, 4-6, 5, 6-4 to 6-6, 8, 9, 12 and 20; ADR-0045 decision 18)
//! and the `FILE_DATA` data plane (decisions 7, 9, 10, 11, 13 and 15),
//! driven end to end by a raw wire requester. There is no client in this
//! file, so each request is a hand-built `ControlMessage` sent on a real
//! connection, the reply is read back the same way, and a `FILE_DATA` stream
//! is a bare framed bidi stream opened with the ticket the reply carried.
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

use std::collections::BTreeMap;
use std::future::Future;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::{Authorizer, PERMISSION_DENIED_MESSAGE, Role, load_or_deny};
use qsh_core::audit::AuditRecord;
use qsh_core::client::Session;
use qsh_core::config::{AuditConfig, Paths};
use qsh_core::file::guard::{CountingNormalizer, FsNormalizer, NormalizeError, Normalizer};
use qsh_core::file::host::{FreeSpace, WriteGate};
use qsh_core::server::Server;
use qsh_core::trust::SharedTrustStore;
use qsh_proto::ErrorCode;
use qsh_proto::wire::{
    self, ControlMessage, FILE_CHUNK_MAX, FILE_LIST_DIR_MAX, FILE_LIST_PAGE_MAX,
    FILE_WRITE_FREE_RESERVE, FileFrame, FileWriteResult, StreamHeader, control_message, file_frame,
    response,
};
use qsh_testkit::loopback::{LoopbackHarness, TestIdentity, make_identity};
use qsh_testkit::pair::HostedPair;
use qsh_testkit::reverse::{ReversePairHarness, wait_for};
use qsh_transport::{FramedStream, Principal, ReadError, StaticTrust, StreamError};

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
    /// An injected free-space probe (production uses `fstatvfs`).
    free_space: Option<Arc<dyn FreeSpace>>,
    /// An injected hold on the disk writer (production has none).
    write_gate: Option<Arc<dyn WriteGate>>,
}

fn write_private(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, bytes).expect("write file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

/// The directory as the host spells it: canonical, and on Windows without
/// the `\\?\` prefix the system puts on a final path (the host answers
/// with drive paths only).
fn canonical(path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(path).expect("canonical path");
    match canonical.to_str().and_then(|p| p.strip_prefix(r"\\?\")) {
        Some(plain) => PathBuf::from(plain),
        None => canonical,
    }
}

/// How a path is written in `acl.toml`: Windows entries use `C:/...`
/// (ADR-0029 decision 23), and a backslash would be a TOML escape.
fn acl_text(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

/// A path that cannot exist, in the host's own syntax.
#[cfg(unix)]
const NOWHERE: &str = "/qsh-no-such-root/dir/../file";
#[cfg(windows)]
const NOWHERE: &str = "C:/qsh-no-such-root/dir/../file";

/// The root of the volume the sandbox lives on, as an `acl.toml` `paths`
/// entry that covers everything the tests touch.
fn fs_root() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/")
    }
    #[cfg(windows)]
    {
        let temp = canonical(&std::env::temp_dir());
        let drive = temp.to_str().expect("utf-8 temp dir")[..2].to_string();
        PathBuf::from(format!("{drive}/"))
    }
}

/// A directory link: a symlink on unix, a junction on Windows (`mklink /J`
/// needs no privilege).
fn dir_link(link: &Path, target: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).expect("symlink");
    #[cfg(windows)]
    {
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link.to_str().unwrap().replace('/', "\\"))
            .arg(target.to_str().unwrap().replace('/', "\\"))
            .output()
            .expect("run cmd");
        assert!(
            made.status.success(),
            "mklink /J: {}",
            String::from_utf8_lossy(&made.stdout)
        );
    }
}

/// A file symlink. `false` when this account may not create one (Windows
/// without the privilege), in which case the scenario skips that part.
fn file_link(link: &Path, target: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).expect("symlink");
        true
    }
    #[cfg(windows)]
    {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(1314) => false,
            Err(e) => panic!("symlink_file: {e}"),
        }
    }
}

impl Env {
    /// A sandbox whose `trust.toml` pins the harness client as `laptop`
    /// carrying `role` (no `role` key when `None`), with no `acl.toml`.
    fn new(role: Option<&str>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = canonical(dir.path());
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
            free_space: None,
            write_gate: None,
        }
    }

    /// Make every `file.write` see `probe` as the free-space reading.
    fn with_free_space(mut self, probe: Arc<dyn FreeSpace>) -> Self {
        self.free_space = Some(probe);
        self
    }

    /// Hold every disk write behind `gate`.
    fn with_write_gate(mut self, gate: Arc<dyn WriteGate>) -> Self {
        self.write_gate = Some(gate);
        self
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
                .map(|p| format!("\"{}\"", acl_text(p)))
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
        if let Some(probe) = &self.free_space {
            server.set_free_space(Arc::clone(probe));
        }
        if let Some(gate) = &self.write_gate {
            server.set_file_write_gate(Arc::clone(gate));
        }
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
    let target = NOWHERE.to_string();
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
    #[cfg(unix)]
    {
        let link = env.share.join("link-to-trust");
        file_link(&link, &env.paths.trust_file());
        out.push(s(&link));
    }
    // A directory link into the config directory reaches the same files.
    let dir = env.share.join("link-to-config");
    dir_link(&dir, &env.paths.config_dir);
    out.push(s(&dir.join("trust.toml")));
    out.push(s(&dir.join("not-yet.toml")));
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
    let env = Env::new(None).acl_rows(&["file.*"], Some(&[fs_root().as_path()]));
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
    let env = Env::new(None).acl_rows(&["file.*"], Some(&[fs_root().as_path()]));
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
    // Windows may not create a file symlink without a privilege; the
    // directory link (a junction there) is always made.
    let file_made = file_link(&env.share.join("out"), &env.outside.join("secret.txt"));
    dir_link(&env.share.join("outdir"), &env.outside);
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    conn.read(&env.share_path("a.txt")).await.read();

    let before = snapshot(&env.outside);
    let mut targets = vec![
        env.share_path("outdir/secret.txt"),
        env.share_path("outdir"),
        env.share_path("outdir/new.txt"),
    ];
    if file_made {
        targets.push(env.share_path("out"));
    }
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
    dir_link(&env.share.join("swap"), &env.outside);
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
    // No two names differ only by case: APFS (macOS) folds case.
    expected.extend(["B".to_string(), "Z".to_string(), "a".to_string()]);
    for name in &expected {
        std::fs::write(dir.join(name), b"").unwrap();
    }
    // One name that is not UTF-8 cannot be listed, only counted. APFS
    // (macOS) refuses to create such a name at all, so there it counts zero.
    #[cfg(unix)]
    let unlistable =
        match std::fs::write(dir.join(std::ffi::OsStr::from_bytes(b"bad-\xff-name")), b"") {
            Ok(()) => 1,
            // EILSEQ in macOS <sys/errno.h>.
            Err(e) if cfg!(target_os = "macos") && e.raw_os_error() == Some(92) => 0,
            Err(e) => panic!("create non-UTF-8 name: {e}"),
        };
    // NTFS stores names as UTF-16 and a lone surrogate cannot be created
    // through a UTF-8 API, so nothing is unlistable here.
    #[cfg(windows)]
    let unlistable = 0;
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
        assert_eq!(page.unlistable, unlistable);
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

    // A trailing `/` says the destination is a directory. With a
    // `name_if_dir` that is a claim about a directory that must already be
    // there, so a missing one is refused and nothing is made (several
    // sources copied to one destination, `qsh cp`).
    let missing = format!("{}/", env.share_path("not-there"));
    let reply = conn.mkdir(&missing, "inner").await;
    assert_eq!(reply.code(), Some(ErrorCode::InvalidArgument), "{reply:?}");
    assert!(!env.share.join("not-there").exists());
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
    // Content bytes really flow over `FILE_DATA` in both directions, so the
    // absence below is a property of the audit record, not of a transfer that
    // never happened.
    let (downloaded, end) = conn.get(&sent).await;
    assert_eq!(downloaded, b"SENTINEL-FILE-CONTENT");
    assert_eq!(end.size, downloaded.len() as u64);
    let uploaded = b"SENTINEL-UPLOAD-CONTENT".to_vec();
    let result = conn
        .put(
            &env.share_path("sentinel-name.txt"),
            &Put::new(uploaded.len()),
            &uploaded,
        )
        .await;
    assert!(result.ok, "{result:?}");
    assert_eq!(
        std::fs::read(env.share.join("sentinel-name.txt")).unwrap(),
        uploaded
    );

    // The data plane adds no line: two control requests, two lines.
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
    // Every record the host wrote, not only the file ones.
    let everything = h.audit().records();
    assert!(everything.len() >= records.len());
    for record in &everything {
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
        for needle in [
            "SENTINEL-FILE-CONTENT",
            "SENTINEL-UPLOAD-CONTENT",
            "TOPSECRET",
        ] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
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
    let file_made = file_link(&env.share.join("out"), &env.outside.join("secret.txt"));
    std::fs::create_dir(env.share.join("sub")).unwrap();
    let mut rows = vec![
        (env.share_path("a.txt"), true),
        (env.share_path("sub/../a.txt"), true),
        (env.share_path("new.txt"), true),
        (env.share_path("sub/deeper/new.txt"), true),
        (s(&env.outside.join("secret.txt")), false),
        (env.share_path("../outside/secret.txt"), false),
        (s(&share.parent().unwrap().join("share-sibling")), false),
    ];
    if file_made {
        rows.push((env.share_path("out"), false));
    }
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

// ---------------------------------------------------------------------------
// FILE_DATA: the data plane
// ---------------------------------------------------------------------------

/// Bound on every "the host answers" wait of the data plane.
const STEP: Duration = Duration::from_secs(20);

fn digest(bytes: &[u8]) -> Vec<u8> {
    blake3::hash(bytes).as_bytes().to_vec()
}

/// Deterministic content that does not repeat at the chunk size, so a
/// dropped, duplicated or reordered chunk changes the bytes.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (i.wrapping_mul(131)
                .wrapping_add(i >> 8)
                .wrapping_add(usize::from(seed))
                % 251) as u8
        })
        .collect()
}

/// The temp files (`.<name>.qsh-<16 hex>.part`) directly inside `dir`.
fn temps(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read_dir")
        .filter_map(|entry| {
            let name = entry.expect("entry").file_name().into_string().ok()?;
            (name.starts_with('.') && name.contains(".qsh-") && name.ends_with(".part"))
                .then_some(name)
        })
        .collect()
}

async fn wait_no_temps(dir: &Path) {
    let dir = dir.to_path_buf();
    wait_for(STEP, || temps(&dir).is_empty().then_some(())).await;
}

/// The shape of a `file.write` request.
#[derive(Clone)]
struct Put {
    size: u64,
    mode: u32,
    overwrite: bool,
    preserve: bool,
    mtime: i64,
    name_if_dir: String,
}

impl Put {
    fn new(size: usize) -> Self {
        Self {
            size: size as u64,
            mode: 0o644,
            overwrite: true,
            preserve: false,
            mtime: 0,
            name_if_dir: String::new(),
        }
    }

    fn no_clobber(mut self) -> Self {
        self.overwrite = false;
        self
    }

    fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    fn preserving(mut self, mtime: i64) -> Self {
        self.preserve = true;
        self.mtime = mtime;
        self
    }

    fn into_dir(mut self, name: &str) -> Self {
        self.name_if_dir = name.into();
        self
    }
}

impl Conn {
    async fn write_with(&mut self, path: &str, put: &Put) -> Reply {
        self.send(control_message::Body::FileWriteOpen(wire::FileWriteOpen {
            path: path.into(),
            size: put.size,
            mode: put.mode,
            overwrite: put.overwrite,
            name_if_dir: put.name_if_dir.clone(),
            preserve: put.preserve,
            mtime: put.mtime,
            ..Default::default()
        }))
        .await
    }

    /// A `FILE_DATA` stream redeeming `ticket`.
    async fn data(&self, ticket: Vec<u8>) -> FramedStream {
        let (send, recv) = self
            .s
            .connection()
            .open_bi()
            .await
            .expect("open a data stream");
        let mut data = FramedStream::data(send, recv);
        data.send
            .send(&StreamHeader::file_data(ticket))
            .await
            .expect("send the FILE_DATA header");
        data
    }

    /// Open a write and start its data stream, sending nothing yet.
    async fn begin_put(&mut self, path: &str, put: &Put) -> FramedStream {
        let opened = self.write_with(path, put).await.write();
        self.data(opened.ticket).await
    }

    /// A whole, well-formed upload: open, every chunk, `end`, finish, and the
    /// host's `result`.
    async fn put(&mut self, path: &str, put: &Put, bytes: &[u8]) -> FileWriteResult {
        let mut data = self.begin_put(path, put).await;
        send_data(&mut data, bytes).await;
        send_end(&mut data, bytes.len() as u64, digest(bytes)).await;
        data.send.finish().expect("finish the upload");
        result_of(&mut data).await
    }

    /// A whole download: every `data` chunk (each within the cap) and the
    /// `end` frame, after which the stream must finish cleanly.
    async fn get(&mut self, path: &str) -> (Vec<u8>, wire::FileEnd) {
        let opened = self.read(path).await.read();
        let mut data = self.data(opened.ticket).await;
        data.send.finish().expect("a read requester sends nothing");
        let mut bytes = Vec::new();
        let end = loop {
            let frame = next_frame(&mut data)
                .await
                .expect("a readable stream")
                .expect("the host ends with an `end` frame, not a bare finish");
            match frame.body {
                Some(file_frame::Body::Data(chunk)) => {
                    assert!(chunk.len() <= FILE_CHUNK_MAX, "chunk over the cap");
                    assert!(!chunk.is_empty(), "no empty chunks");
                    bytes.extend_from_slice(&chunk);
                }
                Some(file_frame::Body::End(end)) => break end,
                other => panic!("unexpected frame on a read stream: {other:?}"),
            }
        };
        let after = next_frame(&mut data).await.expect("a clean finish");
        assert!(after.is_none(), "nothing follows `end`: {after:?}");
        (bytes, end)
    }
}

async fn send_data(data: &mut FramedStream, bytes: &[u8]) {
    for chunk in bytes.chunks(FILE_CHUNK_MAX) {
        data.send
            .send(&FileFrame::data(chunk.to_vec()))
            .await
            .expect("send a chunk");
    }
}

async fn send_end(data: &mut FramedStream, size: u64, hash: Vec<u8>) {
    data.send
        .send(&FileFrame::end(size, hash))
        .await
        .expect("send `end`");
}

async fn next_frame(data: &mut FramedStream) -> Result<Option<FileFrame>, StreamError> {
    tokio::time::timeout(STEP, data.recv.recv::<FileFrame>())
        .await
        .expect("the host answers in time")
}

async fn result_of(data: &mut FramedStream) -> FileWriteResult {
    match next_frame(data).await {
        Ok(Some(FileFrame {
            body: Some(file_frame::Body::Result(result)),
        })) => result,
        other => panic!("expected the host's `result` frame, got {other:?}"),
    }
}

/// The reset code the host ended the stream with, past any frames already in
/// flight.
async fn reset_code_of(data: &mut FramedStream) -> u64 {
    let end = tokio::time::timeout(STEP, async {
        loop {
            match data.recv.recv::<FileFrame>().await {
                Ok(Some(_)) => continue,
                other => break other,
            }
        }
    })
    .await
    .expect("the host ends the stream in time");
    match end {
        Err(StreamError::Read(ReadError::Reset(code))) => code.into_inner(),
        other => panic!("expected a reset, got {other:?}"),
    }
}

const RESET_BAD_HEADER: u64 = 0x2001;
const RESET_TUNNEL_STALLED: u64 = 0x200E;

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

#[cfg(unix)]
fn ino_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("stat").ino()
}

// ---- capability --------------------------------------------------------

async fn file_capability<R: Route>() {
    let env = Env::new(Some("full"));
    let h = R::start(&env).await;
    let session = h.session().await;
    assert!(
        session.capabilities.iter().any(|c| c == "file.v1"),
        "a host advertises file.v1: {:?}",
        session.capabilities
    );
    session.close();
    h.shutdown().await;
}
both_routes!(file_capability =>
    file_v1_is_negotiated_by_a_host_forward,
    file_v1_is_negotiated_by_a_host_reverse);

// ---- file.read ---------------------------------------------------------

async fn read_streams<R: Route>() {
    let env = Env::new(Some("full"));
    // Empty, one byte, exactly one chunk, a chunk and a bit, and a size that
    // takes the send-depth yield several times over.
    let sizes = [
        0usize,
        1,
        FILE_CHUNK_MAX,
        FILE_CHUNK_MAX + 1,
        2 * 1024 * 1024 + 17,
    ];
    for (i, size) in sizes.iter().enumerate() {
        std::fs::write(env.share.join(format!("r{i}.bin")), pattern(*size, i as u8)).unwrap();
    }
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    h.audit().clear();
    for (i, size) in sizes.iter().enumerate() {
        let expected = pattern(*size, i as u8);
        let (bytes, end) = conn.get(&env.share_path(&format!("r{i}.bin"))).await;
        assert_eq!(bytes, expected, "size {size}");
        assert_eq!(end.size, *size as u64, "size {size}");
        assert_eq!(end.blake3, digest(&expected), "size {size}");
    }
    // The data plane writes no audit line of its own: the control request
    // was the decision, and each of the five is one `file.read` line.
    assert_eq!(file_records(&h).len(), sizes.len());
    assert_eq!(h.server().pending_tickets(), 0);
    h.shutdown().await;
}
both_routes!(read_streams =>
    file_read_streams_chunks_and_a_matching_end_forward,
    file_read_streams_chunks_and_a_matching_end_reverse);

async fn ticket_is_single_use<R: Route>() {
    let env = Env::new(Some("full"));
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let opened = conn.read(&env.share_path("a.txt")).await.read();
    let mut first = conn.data(opened.ticket.clone()).await;
    let frame = next_frame(&mut first).await.unwrap().unwrap();
    assert!(matches!(frame.body, Some(file_frame::Body::Data(_))));
    // The ticket was removed at the first redemption.
    let mut second = conn.data(opened.ticket).await;
    assert_eq!(reset_code_of(&mut second).await, RESET_BAD_HEADER);
    h.shutdown().await;
}
both_routes!(ticket_is_single_use =>
    file_data_ticket_is_single_use_forward,
    file_data_ticket_is_single_use_reverse);

// ---- file.write: replacement ------------------------------------------

async fn write_overwrites<R: Route>() {
    let env = Env::new(Some("full"));
    let old = b"old content that must stay whole until the new one is complete";
    std::fs::write(env.share.join("a.txt"), old).unwrap();
    // A second name for the same inode: replacement puts a new inode in the
    // name, it does not rewrite the old one (ADR-0029 decision 7).
    std::fs::hard_link(env.share.join("a.txt"), env.share.join("a.link")).unwrap();
    #[cfg(unix)]
    let old_ino = ino_of(&env.share.join("a.txt"));
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    #[cfg(unix)]
    let umask = qsh_core::file::host::process_umask();

    // Half-way through, the destination is still the old file whole, and the
    // new bytes are going to a temp file nobody can reach by the final name.
    let bytes = pattern(300 * 1024, 7);
    let mut data = conn
        .begin_put(&env.share_path("a.txt"), &Put::new(bytes.len()))
        .await;
    send_data(&mut data, &bytes[..FILE_CHUNK_MAX * 3]).await;
    let share = env.share.clone();
    let names = wait_for(STEP, || {
        let names = temps(&share);
        (!names.is_empty()).then_some(names)
    })
    .await;
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(names[0].starts_with(".a.txt.qsh-"), "{names:?}");
    assert_eq!(names[0].len(), ".a.txt.qsh-".len() + 16 + ".part".len());
    #[cfg(unix)]
    assert_eq!(mode_of(&env.share.join(&names[0])), 0o600);
    assert_eq!(std::fs::read(env.share.join("a.txt")).unwrap(), old);

    send_data(&mut data, &bytes[FILE_CHUNK_MAX * 3..]).await;
    send_end(&mut data, bytes.len() as u64, digest(&bytes)).await;
    data.send.finish().unwrap();
    let result = result_of(&mut data).await;
    assert!(result.ok, "{result:?}");
    assert!(result.overwritten, "{result:?}");
    assert_eq!(std::fs::read(env.share.join("a.txt")).unwrap(), bytes);
    #[cfg(unix)]
    assert_ne!(ino_of(&env.share.join("a.txt")), old_ino);
    assert_eq!(std::fs::read(env.share.join("a.link")).unwrap(), old);
    #[cfg(unix)]
    assert_eq!(mode_of(&env.share.join("a.txt")), 0o644 & !umask);
    assert!(temps(&env.share).is_empty());

    // A new name: created, not overwritten.
    let fresh = pattern(10, 1);
    let result = conn
        .put(&env.share_path("new.txt"), &Put::new(fresh.len()), &fresh)
        .await;
    assert!(result.ok && !result.overwritten, "{result:?}");
    assert_eq!(std::fs::read(env.share.join("new.txt")).unwrap(), fresh);

    // `-p`: the mode exactly, and the modification time.
    let result = conn
        .put(
            &env.share_path("kept.txt"),
            &Put::new(fresh.len()).mode(0o751).preserving(1_000_000_000),
            &fresh,
        )
        .await;
    assert!(result.ok, "{result:?}");
    let kept = env.share.join("kept.txt");
    #[cfg(unix)]
    assert_eq!(mode_of(&kept), 0o751);
    let mtime = std::fs::metadata(&kept).unwrap().modified().unwrap();
    assert_eq!(
        mtime,
        std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    );

    // Into an existing directory under the sent name.
    let result = {
        let opened = conn
            .write_with(
                &env.share_path(""),
                &Put::new(fresh.len()).into_dir("into.txt"),
            )
            .await
            .write();
        assert!(opened.into_dir);
        let mut data = conn.data(opened.ticket).await;
        send_data(&mut data, &fresh).await;
        send_end(&mut data, fresh.len() as u64, digest(&fresh)).await;
        data.send.finish().unwrap();
        result_of(&mut data).await
    };
    assert!(result.ok, "{result:?}");
    assert_eq!(std::fs::read(env.share.join("into.txt")).unwrap(), fresh);

    // A transfer slot is free again the moment the result is visible: many
    // more sequential transfers than the per-principal limit (4) all open.
    for i in 0..8u8 {
        let body = pattern(1000, i);
        let result = conn
            .put(&env.share_path("loop.txt"), &Put::new(body.len()), &body)
            .await;
        assert!(result.ok, "round {i}: {result:?}");
        let (back, end) = conn.get(&env.share_path("loop.txt")).await;
        assert_eq!(back, body);
        assert_eq!(end.blake3, digest(&body));
    }
    assert!(temps(&env.share).is_empty());
    assert_eq!(h.server().pending_tickets(), 0);
    h.shutdown().await;
}
both_routes!(write_overwrites =>
    file_write_overwrites_atomically_by_default_forward,
    file_write_overwrites_atomically_by_default_reverse);

async fn write_no_clobber<R: Route>() {
    let env = Env::new(Some("full"));
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;

    // Already there at the open step: refused before any ticket.
    let before = snapshot(&env.share);
    let reply = conn
        .write_with(&env.share_path("a.txt"), &Put::new(5).no_clobber())
        .await;
    assert_eq!(reply.code(), Some(ErrorCode::InvalidArgument), "{reply:?}");
    assert_eq!(snapshot(&env.share), before);
    assert_eq!(h.server().pending_tickets(), 0);

    // Absent: created through a link, and no temp is left.
    let body = pattern(5000, 3);
    let result = conn
        .put(
            &env.share_path("fresh.txt"),
            &Put::new(body.len()).no_clobber(),
            &body,
        )
        .await;
    assert!(result.ok && !result.overwritten, "{result:?}");
    assert_eq!(std::fs::read(env.share.join("fresh.txt")).unwrap(), body);
    assert!(temps(&env.share).is_empty());

    // The race: absent when the ticket is issued, present when the data is
    // done. The winner's bytes stay, the result says why, nothing is left.
    let mut data = conn
        .begin_put(
            &env.share_path("race.txt"),
            &Put::new(body.len()).no_clobber(),
        )
        .await;
    std::fs::write(env.share.join("race.txt"), b"WINNER").unwrap();
    send_data(&mut data, &body).await;
    send_end(&mut data, body.len() as u64, digest(&body)).await;
    data.send.finish().unwrap();
    let result = result_of(&mut data).await;
    assert!(!result.ok, "{result:?}");
    assert_eq!(result.code, "INVALID_ARGUMENT");
    assert!(!result.overwritten);
    assert_eq!(
        std::fs::read(env.share.join("race.txt")).unwrap(),
        b"WINNER"
    );
    assert!(temps(&env.share).is_empty());
    assert_eq!(h.server().pending_tickets(), 0);
    h.shutdown().await;
}
both_routes!(write_no_clobber =>
    file_write_no_clobber_never_replaces_an_existing_file_forward,
    file_write_no_clobber_never_replaces_an_existing_file_reverse);

// ---- file.write: interruption -------------------------------------------

async fn interrupted_by_connection_loss<R: Route>() {
    let env = Env::new(Some("full"));
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let before = snapshot(&env.share);
    let bytes = pattern(200 * 1024, 5);
    let mut data = conn
        .begin_put(&env.share_path("a.txt"), &Put::new(bytes.len()))
        .await;
    send_data(&mut data, &bytes[..FILE_CHUNK_MAX * 2]).await;
    let share = env.share.clone();
    wait_for(STEP, || (!temps(&share).is_empty()).then_some(())).await;
    conn.s.connection().close(0, b"gone");
    wait_no_temps(&env.share).await;
    assert_eq!(snapshot(&env.share), before, "the destination is untouched");
    h.shutdown().await;
}
both_routes!(interrupted_by_connection_loss =>
    interrupted_file_write_removes_its_temp_file_on_connection_loss_forward,
    interrupted_file_write_removes_its_temp_file_on_connection_loss_reverse);

async fn interrupted_by_cancel<R: Route>() {
    let env = Env::new(Some("full"));
    std::fs::write(env.share.join("a.txt"), b"old").unwrap();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let before = snapshot(&env.share);
    let bytes = pattern(200 * 1024, 5);
    let mut data = conn
        .begin_put(&env.share_path("a.txt"), &Put::new(bytes.len()))
        .await;
    send_data(&mut data, &bytes[..FILE_CHUNK_MAX * 2]).await;
    let share = env.share.clone();
    wait_for(STEP, || (!temps(&share).is_empty()).then_some(())).await;
    // Ctrl-C of a client: the stream is reset, the connection stays.
    data.send.reset(0x2007);
    wait_no_temps(&env.share).await;
    assert_eq!(snapshot(&env.share), before);
    assert_eq!(h.server().pending_tickets(), 0);
    // The connection is still good for the next transfer.
    let result = conn
        .put(&env.share_path("a.txt"), &Put::new(bytes.len()), &bytes)
        .await;
    assert!(result.ok, "{result:?}");
    h.shutdown().await;
}
both_routes!(interrupted_by_cancel =>
    interrupted_file_write_removes_its_temp_file_on_cancel_forward,
    interrupted_file_write_removes_its_temp_file_on_cancel_reverse);

/// A disk writer that waits until it is released, so a transfer's local
/// write can be held still on demand (the ADR-0037 stall).
struct Hold {
    open: std::sync::Mutex<bool>,
    cv: std::sync::Condvar,
}

impl Hold {
    fn closed() -> Arc<Self> {
        Arc::new(Self {
            open: std::sync::Mutex::new(false),
            cv: std::sync::Condvar::new(),
        })
    }

    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }
}

impl WriteGate for Hold {
    fn before_write(&self, _written: u64) {
        let guard = self.open.lock().unwrap();
        // Bounded, so a failed test cannot park a blocking thread forever.
        let _ = self
            .cv
            .wait_timeout_while(guard, Duration::from_secs(60), |open| !*open)
            .unwrap();
    }
}

async fn interrupted_by_the_stall_ledger<R: Route>() {
    let hold = Hold::closed();
    let env = Env::new(Some("full")).with_write_gate(hold.clone() as Arc<dyn WriteGate>);
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;

    // Four uploads whose disk writes are held: more than
    // `MAX_STALLED_STREAMS_PER_CONNECTION` (3) stalled at once, so the
    // ledger stops the oldest (ADR-0037 decision 3).
    let size = 1024 * 1024;
    let mut streams = Vec::new();
    let mut bodies = Vec::new();
    for i in 0..4u8 {
        let body = pattern(size, i);
        let mut data = conn
            .begin_put(&env.share_path(&format!("s{i}.bin")), &Put::new(size))
            .await;
        send_data(&mut data, &body).await;
        send_end(&mut data, size as u64, digest(&body)).await;
        data.send.finish().unwrap();
        streams.push(data);
        bodies.push(body);
    }

    // Exactly one of them ends with the ledger's reset code, and its temp
    // file goes while the other three are still held.
    let (stopped, mut rest) = {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut handles = Vec::new();
        for (i, mut data) in streams.into_iter().enumerate() {
            let tx = tx.clone();
            handles.push(tokio::spawn(async move {
                let end = match data.recv.recv::<FileFrame>().await {
                    Ok(Some(frame)) => Ok(frame),
                    Ok(None) => Err(None),
                    Err(StreamError::Read(ReadError::Reset(code))) => Err(Some(code.into_inner())),
                    Err(other) => panic!("stream {i}: {other:?}"),
                };
                let _ = tx.send((i, end));
            }));
        }
        drop(tx);
        let first = tokio::time::timeout(STEP, rx.recv())
            .await
            .expect("the ledger stops a stalled upload in time")
            .expect("a stream reports");
        (first, (rx, handles))
    };
    let (stopped_index, outcome) = stopped;
    assert_eq!(
        outcome.map(|_| ()).unwrap_err(),
        Some(RESET_TUNNEL_STALLED),
        "stream {stopped_index} is stopped with the ledger's code"
    );
    let share = env.share.clone();
    wait_for(STEP, || (temps(&share).len() == 3).then_some(())).await;
    assert!(
        !env.share.join(format!("s{stopped_index}.bin")).exists(),
        "a stopped upload leaves no file"
    );

    // Release the disk: the three that were not stopped finish normally.
    hold.release();
    let mut ok = 0;
    while let Some((i, outcome)) = tokio::time::timeout(STEP, rest.0.recv())
        .await
        .expect("the remaining uploads answer")
    {
        let frame = outcome.unwrap_or_else(|code| panic!("stream {i} ended with {code:?}"));
        match frame.body {
            Some(file_frame::Body::Result(result)) => {
                assert!(result.ok, "stream {i}: {result:?}");
                assert_eq!(
                    std::fs::read(env.share.join(format!("s{i}.bin"))).unwrap(),
                    bodies[i]
                );
                ok += 1;
            }
            other => panic!("stream {i}: {other:?}"),
        }
    }
    assert_eq!(ok, 3);
    wait_no_temps(&env.share).await;
    assert_eq!(h.server().pending_tickets(), 0);
    h.shutdown().await;
}
both_routes!(interrupted_by_the_stall_ledger =>
    interrupted_file_write_removes_its_temp_file_on_a_ledger_stop_forward,
    interrupted_file_write_removes_its_temp_file_on_a_ledger_stop_reverse);

// ---- file.write: integrity and violations --------------------------------

async fn write_mismatch<R: Route>() {
    let env = Env::new(Some("full"));
    std::fs::write(env.share.join("a.txt"), b"old").unwrap();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let before = snapshot(&env.share);
    let body = pattern(70_000, 9);
    let wrong = pattern(70_000, 10);

    // (announced size, bytes sent, `end.size`, `end.blake3`)
    type Case<'a> = (&'a str, usize, &'a [u8], u64, Vec<u8>);
    let cases: [Case<'_>; 5] = [
        (
            "hash differs",
            body.len(),
            &body,
            body.len() as u64,
            digest(&wrong),
        ),
        (
            "end size short",
            body.len(),
            &body,
            body.len() as u64 - 1,
            digest(&body),
        ),
        (
            "fewer bytes than announced",
            body.len() + 1,
            &body,
            body.len() as u64,
            digest(&body),
        ),
        (
            "short hash",
            body.len(),
            &body,
            body.len() as u64,
            vec![0u8; 3],
        ),
        ("no hash", body.len(), &body, body.len() as u64, Vec::new()),
    ];
    for (name, announced, sent, end_size, end_hash) in cases {
        let mut data = conn
            .begin_put(&env.share_path("a.txt"), &Put::new(announced))
            .await;
        send_data(&mut data, sent).await;
        send_end(&mut data, end_size, end_hash).await;
        data.send.finish().unwrap();
        let result = result_of(&mut data).await;
        assert!(!result.ok, "{name}: {result:?}");
        assert_eq!(result.code, "INVALID_ARGUMENT", "{name}");
        assert!(!result.overwritten, "{name}");
        wait_no_temps(&env.share).await;
        assert_eq!(snapshot(&env.share), before, "{name}: nothing was renamed");
    }
    assert_eq!(h.server().pending_tickets(), 0);
    h.shutdown().await;
}
both_routes!(write_mismatch =>
    file_write_size_or_hash_mismatch_renames_nothing_forward,
    file_write_size_or_hash_mismatch_renames_nothing_reverse);

async fn write_violations<R: Route>() {
    let env = Env::new(Some("full"));
    std::fs::write(env.share.join("a.txt"), b"old").unwrap();
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let before = snapshot(&env.share);
    let body = pattern(70_000, 9);

    // More bytes than `FileWriteOpen.size`: cut on the spot.
    let mut data = conn
        .begin_put(&env.share_path("a.txt"), &Put::new(body.len() - 1))
        .await;
    send_data(&mut data, &body).await;
    assert_eq!(
        reset_code_of(&mut data).await,
        RESET_BAD_HEADER,
        "excess bytes"
    );
    wait_no_temps(&env.share).await;
    assert_eq!(snapshot(&env.share), before);

    // A chunk over `FILE_CHUNK_MAX` (within the 64 KiB frame cap, so it
    // reaches the host's check).
    let mut data = conn
        .begin_put(&env.share_path("a.txt"), &Put::new(FILE_CHUNK_MAX * 2))
        .await;
    data.send
        .send(&FileFrame::data(vec![1u8; FILE_CHUNK_MAX + 1]))
        .await
        .unwrap();
    assert_eq!(
        reset_code_of(&mut data).await,
        RESET_BAD_HEADER,
        "over-cap chunk"
    );

    // A frame after `end`.
    let mut data = conn.begin_put(&env.share_path("a.txt"), &Put::new(4)).await;
    send_data(&mut data, b"abcd").await;
    send_end(&mut data, 4, digest(b"abcd")).await;
    data.send
        .send(&FileFrame::data(b"more".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        reset_code_of(&mut data).await,
        RESET_BAD_HEADER,
        "data after end"
    );

    // A second `end`.
    let mut data = conn.begin_put(&env.share_path("a.txt"), &Put::new(4)).await;
    send_data(&mut data, b"abcd").await;
    send_end(&mut data, 4, digest(b"abcd")).await;
    send_end(&mut data, 4, digest(b"abcd")).await;
    assert_eq!(
        reset_code_of(&mut data).await,
        RESET_BAD_HEADER,
        "end after end"
    );

    // A `result` frame sent by the requester.
    let mut data = conn.begin_put(&env.share_path("a.txt"), &Put::new(4)).await;
    data.send
        .send(&FileFrame::result(true, "", "", false))
        .await
        .unwrap();
    assert_eq!(
        reset_code_of(&mut data).await,
        RESET_BAD_HEADER,
        "requester result"
    );

    // Finishing without any `end`.
    let mut data = conn.begin_put(&env.share_path("a.txt"), &Put::new(4)).await;
    send_data(&mut data, b"abcd").await;
    data.send.finish().unwrap();
    assert_eq!(reset_code_of(&mut data).await, RESET_BAD_HEADER, "no end");

    wait_no_temps(&env.share).await;
    assert_eq!(snapshot(&env.share), before, "nothing was renamed");
    assert_eq!(h.server().pending_tickets(), 0);
    h.shutdown().await;
}
both_routes!(write_violations =>
    file_write_protocol_violations_reset_the_stream_and_rename_nothing_forward,
    file_write_protocol_violations_reset_the_stream_and_rename_nothing_reverse);

// ---- file.write: free space ----------------------------------------------

struct Free(u64);

impl FreeSpace for Free {
    fn available_bytes(&self, _dir: &std::fs::File) -> std::io::Result<u64> {
        Ok(self.0)
    }
}

async fn write_free_space<R: Route>() {
    // The reading is the reserve plus 99 bytes: a 99-byte file fits exactly, a
    // 100-byte one does not (ADR-0029 decision 13).
    let env = Env::new(Some("full"))
        .with_free_space(Arc::new(Free(FILE_WRITE_FREE_RESERVE + 99)) as Arc<dyn FreeSpace>);
    let h = R::start(&env).await;
    let mut conn = Conn::open(&h).await;
    let before = snapshot(&env.share);

    let refused = conn
        .write_with(&env.share_path("big.bin"), &Put::new(100))
        .await;
    assert_eq!(
        refused.code(),
        Some(ErrorCode::ResourceExhausted),
        "{refused:?}"
    );
    assert_eq!(h.server().pending_tickets(), 0, "no ticket for a refusal");
    assert_eq!(snapshot(&env.share), before, "no temp, no file");

    let body = pattern(99, 2);
    let result = conn
        .put(&env.share_path("fits.bin"), &Put::new(99), &body)
        .await;
    assert!(result.ok, "{result:?}");
    assert_eq!(std::fs::read(env.share.join("fits.bin")).unwrap(), body);

    // The refusal is the same for an overwrite and for a write into a dir.
    for put in [Put::new(100), Put::new(100).into_dir("x.bin")] {
        let path = if put.name_if_dir.is_empty() {
            env.share_path("fits.bin")
        } else {
            env.share_path("")
        };
        let refused = conn.write_with(&path, &put).await;
        assert_eq!(refused.code(), Some(ErrorCode::ResourceExhausted));
    }
    h.shutdown().await;
}
both_routes!(write_free_space =>
    file_write_refused_below_the_free_space_reserve_forward,
    file_write_refused_below_the_free_space_reserve_reverse);

// ---------------------------------------------------------------------------
// Windows host (ADR-0035 decision 26): what differs from the unix scenarios
// above, which otherwise run unchanged on a Windows host.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod windows_host {
    use super::*;

    /// `(ACE count, inherited ACE count)` of `path` as `icacls` prints it.
    fn aces(path: &Path) -> (usize, usize) {
        let out = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .expect("run icacls");
        assert!(out.status.success(), "icacls: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = text.lines().filter(|l| l.contains(":(")).collect();
        (
            lines.len(),
            lines.iter().filter(|l| l.contains("(I)")).count(),
        )
    }

    fn read_only(path: &Path) -> bool {
        std::fs::metadata(path).unwrap().permissions().readonly()
    }

    async fn temp_file_is_owner_only_until_rename<R: Route>() {
        let env = Env::new(Some("full"));
        let h = R::start(&env).await;
        let mut conn = Conn::open(&h).await;
        let bytes = pattern(300 * 1024, 3);
        let mut data = conn
            .begin_put(&env.share_path("held.bin"), &Put::new(bytes.len()))
            .await;
        send_data(&mut data, &bytes[..FILE_CHUNK_MAX * 3]).await;
        let share = env.share.clone();
        let names = wait_for(STEP, || {
            let names = temps(&share);
            (!names.is_empty()).then_some(names)
        })
        .await;
        assert_eq!(names.len(), 1, "{names:?}");
        // While the bytes arrive: exactly one ACE, not inherited.
        let (all, inherited) = aces(&env.share.join(&names[0]));
        assert_eq!((all, inherited), (1, 0), "{names:?}");

        send_data(&mut data, &bytes[FILE_CHUNK_MAX * 3..]).await;
        send_end(&mut data, bytes.len() as u64, digest(&bytes)).await;
        data.send.finish().unwrap();
        let result = result_of(&mut data).await;
        assert!(result.ok, "{result:?}");
        assert!(temps(&env.share).is_empty());
        // The finished file carries what its directory hands down.
        let (all, inherited) = aces(&env.share.join("held.bin"));
        assert!(
            all >= 1 && inherited == all,
            "{all} ACEs, {inherited} inherited"
        );
        h.shutdown().await;
    }
    both_routes!(temp_file_is_owner_only_until_rename =>
        windows_put_temp_file_is_owner_only_until_rename_then_inherits_forward,
        windows_put_temp_file_is_owner_only_until_rename_then_inherits_reverse);

    async fn read_only_attribute<R: Route>() {
        let env = Env::new(Some("full"));
        let h = R::start(&env).await;
        let mut conn = Conn::open(&h).await;
        let body = pattern(64, 5);
        for (mode, expect) in [(0o644, false), (0o755, false), (0o444, true), (0o400, true)] {
            let path = env.share.join(format!("m{mode:03o}.bin"));
            let result = conn
                .put(&s(&path), &Put::new(body.len()).mode(mode), &body)
                .await;
            assert!(result.ok, "{mode:03o}: {result:?}");
            assert_eq!(read_only(&path), expect, "mode {mode:03o}");
        }
        // A read-only file is replaced as a unix rename replaces it.
        let path = env.share.join("m444.bin");
        let result = conn
            .put(&s(&path), &Put::new(body.len()).mode(0o644), &body)
            .await;
        assert!(result.ok && result.overwritten, "{result:?}");
        assert!(!read_only(&path));
        h.shutdown().await;
    }
    both_routes!(read_only_attribute =>
        windows_put_sets_read_only_only_when_owner_write_is_clear_forward,
        windows_put_sets_read_only_only_when_owner_write_is_clear_reverse);

    async fn mode_bits_are_synthesized<R: Route>() {
        let env = Env::new(Some("full"));
        let ro = env.share.join("ro.txt");
        std::fs::write(&ro, b"x").unwrap();
        let mut perms = std::fs::metadata(&ro).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&ro, perms).unwrap();
        std::fs::create_dir(env.share.join("d")).unwrap();
        let h = R::start(&env).await;
        let mut conn = Conn::open(&h).await;
        assert_eq!(conn.read(&env.share_path("a.txt")).await.read().mode, 0o644);
        assert_eq!(conn.read(&s(&ro)).await.read().mode, 0o444);
        let listed = conn.list(&env.share_path(""), "").await.list();
        let mode_of = |name: &str| {
            listed
                .entries
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("{name} is listed"))
                .mode
        };
        assert_eq!(mode_of("a.txt"), 0o644);
        assert_eq!(mode_of("ro.txt"), 0o444);
        assert_eq!(mode_of("d"), 0o755);
        h.shutdown().await;
        let mut perms = std::fs::metadata(&ro).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&ro, perms).unwrap();
    }
    both_routes!(mode_bits_are_synthesized =>
        windows_get_synthesizes_mode_bits_forward,
        windows_get_synthesizes_mode_bits_reverse);

    async fn put_preserves_mtime<R: Route>() {
        let env = Env::new(Some("full"));
        let h = R::start(&env).await;
        let mut conn = Conn::open(&h).await;
        let body = pattern(10, 2);
        let result = conn
            .put(
                &env.share_path("kept.txt"),
                &Put::new(body.len()).preserving(1_000_000_000),
                &body,
            )
            .await;
        assert!(result.ok, "{result:?}");
        let mtime = std::fs::metadata(env.share.join("kept.txt"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            mtime,
            std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
        );
        // Without `-p` the time is the transfer's, not the sender's.
        let result = conn
            .put(&env.share_path("fresh.txt"), &Put::new(body.len()), &body)
            .await;
        assert!(result.ok, "{result:?}");
        let mtime = std::fs::metadata(env.share.join("fresh.txt"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(mtime > std::time::UNIX_EPOCH + Duration::from_secs(1_500_000_000));
        h.shutdown().await;
    }
    both_routes!(put_preserves_mtime =>
        windows_put_preserves_mtime_with_p_forward,
        windows_put_preserves_mtime_with_p_reverse);

    async fn real_free_space_probe_admits_a_small_write<R: Route>() {
        // No injected probe: the production `GetDiskFreeSpaceExW` reading is
        // used, and a small file fits on any disk a test can run on.
        let env = Env::new(Some("full"));
        let h = R::start(&env).await;
        let mut conn = Conn::open(&h).await;
        let body = pattern(1000, 4);
        let result = conn
            .put(&env.share_path("small.bin"), &Put::new(body.len()), &body)
            .await;
        assert!(result.ok, "{result:?}");
        // And one that cannot fit anywhere is refused before any ticket.
        let refused = conn
            .write_with(&env.share_path("huge.bin"), &Put::new(usize::MAX >> 1))
            .await;
        assert_eq!(
            refused.code(),
            Some(ErrorCode::ResourceExhausted),
            "{refused:?}"
        );
        assert!(!env.share.join("huge.bin").exists());
        h.shutdown().await;
    }
    // The injected-probe refusal below the reserve is the shared
    // `write_free_space` scenario; it is named here too so the Windows leg
    // lists it beside the real-probe test.
    both_routes!(write_free_space =>
        windows_put_refuses_when_free_space_is_short_forward,
        windows_put_refuses_when_free_space_is_short_reverse);

    both_routes!(real_free_space_probe_admits_a_small_write =>
        windows_put_uses_the_disk_free_space_probe_forward,
        windows_put_uses_the_disk_free_space_probe_reverse);

    async fn unc_and_device_paths_are_malformed_before_the_acl<R: Route>() {
        // `full` would allow anything; the shape check comes first, so the
        // answer is INVALID_ARGUMENT, not the uniform denial, and nothing is
        // audited.
        let env = Env::new(Some("full"));
        let h = R::start(&env).await;
        let mut conn = Conn::open(&h).await;
        h.audit().clear();
        for target in [
            r"\\server\share\x",
            "//server/share/x",
            r"\\?\C:\Windows",
            r"\\.\pipe\qsh",
        ] {
            for op in ALL_OPS {
                let reply = conn.op(op, target).await;
                assert_eq!(
                    reply.code(),
                    Some(ErrorCode::InvalidArgument),
                    "{op:?} {target}: {reply:?}"
                );
            }
        }
        assert!(file_records(&h).is_empty(), "{:?}", file_records(&h));
        assert_eq!(h.server().pending_tickets(), 0);
        // A drive-relative or rootless path is malformed too.
        for target in [r"\x", "C:x", "/x"] {
            let reply = conn.read(target).await;
            assert_eq!(reply.code(), Some(ErrorCode::InvalidArgument), "{target}");
        }
        h.shutdown().await;
    }
    both_routes!(unc_and_device_paths_are_malformed_before_the_acl =>
        windows_remote_path_unc_is_invalid_argument_with_no_audit_line_forward,
        windows_remote_path_unc_is_invalid_argument_with_no_audit_line_reverse);

    async fn case_variants_and_streams_of_state_paths<R: Route>() {
        // The volume ignores case: a differently cased spelling of a state
        // file is the same file. An alternate data stream of one is
        // malformed. Neither reaches the file.
        let env = Env::new(None).acl_rows(&["file.*"], Some(&[fs_root().as_path()]));
        let files = env.seed_state();
        let h = R::start(&env).await;
        let mut conn = Conn::open(&h).await;
        let before = snapshot(&env.host);
        for file in &files {
            let upper = s(file).to_uppercase();
            let reply = conn.read(&upper).await;
            assert!(reply.is_denied(), "{upper}: {reply:?}");
            let reply = conn.write(&upper, true, "").await;
            assert!(reply.is_denied(), "{upper}: {reply:?}");
            let stream = format!("{}:evil", s(file));
            let reply = conn.read(&stream).await;
            assert_eq!(reply.code(), Some(ErrorCode::InvalidArgument), "{stream}");
        }
        assert_eq!(snapshot(&env.host), before);
        h.shutdown().await;
    }
    both_routes!(case_variants_and_streams_of_state_paths =>
        windows_state_paths_fold_case_and_refuse_streams_forward,
        windows_state_paths_fold_case_and_refuse_streams_reverse);
}
