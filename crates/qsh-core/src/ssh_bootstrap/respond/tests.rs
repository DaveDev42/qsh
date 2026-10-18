use std::fs::{File, OpenOptions, TryLockError};
use std::path::PathBuf;
use std::sync::Mutex;

use qsh_proto::IdentityInitReq;
use qsh_proto::KeyStoreMode;
use qsh_proto::ssh_bootstrap::{BootstrapReader, Commit};

use super::*;
use crate::audit::{AuditError, FailingAuditSink, MemoryAuditSink};
use crate::ops::test_support::temp_ops;

/// A well-formed fingerprint made of one repeated byte.
fn fp(byte: u8) -> String {
    use base64::Engine as _;
    format!(
        "sha256:{}",
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    )
}

/// A temp config tree, optionally holding an identity.
fn tree(initialized: bool) -> (tempfile::TempDir, Ops) {
    let (dir, ops) = temp_ops();
    if initialized {
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
            import_ssh_key: None,
        })
        .unwrap();
    }
    (dir, ops)
}

fn responder(ops: &Ops, audit: Arc<dyn AuditSink>) -> Responder {
    Responder::new(ops.paths().clone(), Config::default(), audit)
}

fn commit(name: &str, fingerprint: &str, role: &str, address: Option<&str>) -> Commit {
    Commit {
        version: 1,
        fingerprint: fingerprint.into(),
        name: name.into(),
        role: role.into(),
        address: address.map(str::to_string),
    }
}

fn commit_bytes(commit: Commit) -> Vec<u8> {
    BootstrapLine::Commit(commit)
        .encode_line()
        .unwrap()
        .into_bytes()
}

/// Run one conversation that sends `input` and then closes its end.
async fn converse(responder: &Responder, input: &[u8]) -> (RespondEnd, Vec<BootstrapLine>) {
    let mut out = Vec::new();
    let end = responder.run(input, &mut out).await.unwrap();
    (end, BootstrapReader::new().push(&out).unwrap())
}

fn result_of(lines: &[BootstrapLine]) -> &BootstrapResult {
    match lines {
        [BootstrapLine::Hello(_), BootstrapLine::Result(result)] => result,
        other => panic!("expected hello and result, got {other:?}"),
    }
}

fn trust_bytes(ops: &Ops) -> Vec<u8> {
    std::fs::read(ops.paths().trust_file()).unwrap_or_default()
}

fn pin(ops: &Ops, name: &str, fingerprint: &str, role: Option<&str>) {
    let path = ops.paths().trust_file();
    let _lock = TrustStore::lock(&path).unwrap();
    let mut store = TrustStore::load(&path).unwrap();
    let fingerprint: Fingerprint = fingerprint.parse().unwrap();
    match role {
        Some(role) => store.add_peer_with_role(
            name,
            None,
            fingerprint,
            now_rfc3339(),
            role.parse().unwrap(),
        ),
        None => store.add_peer(name, None, fingerprint, now_rfc3339()),
    };
    store.save(&path).unwrap();
}

#[tokio::test]
async fn ssh_respond_reports_not_initialized_without_writing() {
    let (_dir, ops) = tree(false);
    let audit = Arc::new(MemoryAuditSink::new());
    let responder = responder(&ops, audit.clone());
    // Even a commit that is already waiting on stdin is never read.
    let input = commit_bytes(commit("laptop", &fp(0xB1), "full", None));
    let mut out = Vec::new();
    let end = responder.run(&input[..], &mut out).await.unwrap();
    assert_eq!(end, RespondEnd::NotInitialized);
    let lines = BootstrapReader::new().push(&out).unwrap();
    let [BootstrapLine::Hello(hello)] = lines.as_slice() else {
        panic!("expected exactly a hello, got {lines:?}");
    };
    assert_eq!(hello.status, HelloStatus::NotInitialized);
    assert_eq!(hello.fingerprint, None);
    assert_eq!(hello.serve_listening, None);
    assert_eq!(hello.versions, BOOTSTRAP_VERSIONS);
    // No identity was made, no trust file was made, nothing was audited.
    assert!(!ops.paths().identity_dir().join("device.pem").exists());
    assert!(!ops.paths().trust_file().exists());
    assert!(audit.records().is_empty());
}

#[tokio::test]
async fn ssh_respond_hello_names_the_identity_and_the_serve_bind() {
    let (_dir, ops) = tree(true);
    let fingerprint = crate::identity::read_identity(ops.paths())
        .unwrap()
        .unwrap()
        .fingerprint
        .to_string();
    let responder = responder(&ops, Arc::new(MemoryAuditSink::new()));
    let (end, lines) = converse(&responder, b"").await;
    assert_eq!(end, RespondEnd::ClientClosed);
    let [BootstrapLine::Hello(hello)] = lines.as_slice() else {
        panic!("expected exactly a hello, got {lines:?}");
    };
    assert_eq!(hello.status, HelloStatus::Ready);
    assert_eq!(hello.fingerprint.as_deref(), Some(fingerprint.as_str()));
    assert_eq!(hello.serve_bind.as_deref(), Some("[::]:4433"));
    assert_eq!(hello.qsh_version, env!("CARGO_PKG_VERSION"));
    // A client that closes its end without a commit leaves no trust file.
    assert!(!ops.paths().trust_file().exists());
}

#[tokio::test]
async fn ssh_respond_writes_an_inbound_only_pin_with_the_committed_role() {
    let (_dir, ops) = tree(true);
    let audit = Arc::new(MemoryAuditSink::new());
    let responder = responder(&ops, audit.clone());
    let input = commit_bytes(commit("laptop", &fp(0xB1), "exec", None));
    let (end, lines) = converse(&responder, &input).await;
    assert_eq!(end, RespondEnd::Answered(ResultStatus::Pinned));
    let result = result_of(&lines);
    assert_eq!(result.name, "laptop");
    assert_eq!(result.role.as_deref(), Some("exec"));
    assert!(result.created);

    let store = TrustStore::load(&ops.paths().trust_file()).unwrap();
    let peer = store.find("laptop").unwrap();
    assert_eq!(peer.fingerprint, fp(0xB1));
    assert_eq!(
        peer.address, "",
        "no address in the commit, no address in the pin"
    );
    assert_eq!(peer.role.as_deref(), Some("exec"));
    assert_eq!(audit.records().len(), 1);
}

#[tokio::test]
async fn ssh_respond_a_commit_address_makes_an_addressed_pin() {
    let (_dir, ops) = tree(true);
    let responder = responder(&ops, Arc::new(MemoryAuditSink::new()));
    let input = commit_bytes(commit("ctl", &fp(0xB1), "full", Some("ctl.example:4500")));
    let (_end, lines) = converse(&responder, &input).await;
    assert_eq!(result_of(&lines).status, ResultStatus::Pinned);
    let store = TrustStore::load(&ops.paths().trust_file()).unwrap();
    assert_eq!(store.find("ctl").unwrap().address, "ctl.example:4500");
}

#[tokio::test]
async fn ssh_respond_a_crlf_commit_is_accepted() {
    // A Windows remote may hand the line over with its CR still attached.
    let (_dir, ops) = tree(true);
    let responder = responder(&ops, Arc::new(MemoryAuditSink::new()));
    let mut input = commit_bytes(commit("laptop", &fp(0xB1), "full", None));
    input.pop();
    input.extend_from_slice(b"\r\n");
    let (_end, lines) = converse(&responder, &input).await;
    assert_eq!(result_of(&lines).status, ResultStatus::Pinned);
}

/// A `trust.toml` the responder starts is as private as one `qsh trust add`
/// starts (ADR-0035 decision 9): a protected DACL granting only the account
/// the responder runs as, on the file and on its directory. The Unix twin is
/// `responder_trust_toml_is_owner_only_on_unix`.
#[cfg(windows)]
#[tokio::test]
async fn responder_trust_toml_has_an_owner_only_dacl_on_windows() {
    use crate::fsutil::dacl::ObjectKind;
    use crate::fsutil::dacl::testing::assert_owner_only;

    let (_dir, ops) = tree(true);
    let responder = responder(&ops, Arc::new(MemoryAuditSink::new()));
    let input = commit_bytes(commit("laptop", &fp(0xB1), "full", None));
    let (_end, lines) = converse(&responder, &input).await;
    assert_eq!(result_of(&lines).status, ResultStatus::Pinned);

    let trust = ops.paths().trust_file();
    assert_owner_only(&trust, ObjectKind::File);
    assert_owner_only(trust.parent().unwrap(), ObjectKind::Dir);
}

/// The Unix twin of `responder_trust_toml_has_an_owner_only_dacl_on_windows`:
/// mode 0600 on the file in a 0700 directory.
#[cfg(unix)]
#[tokio::test]
async fn responder_trust_toml_is_owner_only_on_unix() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_dir, ops) = tree(true);
    let responder = responder(&ops, Arc::new(MemoryAuditSink::new()));
    let input = commit_bytes(commit("laptop", &fp(0xB1), "full", None));
    let (_end, lines) = converse(&responder, &input).await;
    assert_eq!(result_of(&lines).status, ResultStatus::Pinned);

    let trust = ops.paths().trust_file();
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&trust), 0o600);
    assert_eq!(mode(trust.parent().unwrap()), 0o700);
}

#[tokio::test]
async fn ssh_respond_returns_exists_and_keeps_the_role_for_a_known_fingerprint() {
    let (_dir, ops) = tree(true);
    // Pinned under another name, with no role key at all (a legacy pin).
    pin(&ops, "old-name", &fp(0xB1), None);
    let before = trust_bytes(&ops);
    let audit = Arc::new(MemoryAuditSink::new());
    let responder = responder(&ops, audit.clone());
    let input = commit_bytes(commit("laptop", &fp(0xB1), "full", None));
    let (end, lines) = converse(&responder, &input).await;
    assert_eq!(end, RespondEnd::Answered(ResultStatus::Exists));
    let result = result_of(&lines);
    assert_eq!(result.name, "old-name");
    assert_eq!(result.role, None, "the legacy pin keeps having no role");
    assert!(!result.created);
    assert_eq!(trust_bytes(&ops), before);
    assert!(audit.records().is_empty());

    // An existing pin with an explicit role reports it unchanged.
    pin(&ops, "ci", &fp(0xC2), Some("read-only"));
    let before = trust_bytes(&ops);
    let input = commit_bytes(commit("laptop", &fp(0xC2), "full", None));
    let (_end, lines) = converse(&responder, &input).await;
    let result = result_of(&lines);
    assert_eq!(result.status, ResultStatus::Exists);
    assert_eq!(result.name, "ci");
    assert_eq!(result.role.as_deref(), Some("read-only"));
    assert_eq!(trust_bytes(&ops), before);
}

#[tokio::test]
async fn ssh_respond_a_reverse_commit_updates_only_the_address_of_a_known_pin() {
    let (_dir, ops) = tree(true);
    // Known under another name, with a role that must stay as it is, and an
    // address that is not the one the commit names.
    {
        let path = ops.paths().trust_file();
        let _lock = TrustStore::lock(&path).unwrap();
        let mut store = TrustStore::load(&path).unwrap();
        store.add_peer_with_role(
            "ctl",
            Some("old.example:4433".into()),
            fp(0xB1).parse().unwrap(),
            now_rfc3339(),
            TrustRole::ReadOnly,
        );
        store.save(&path).unwrap();
    }
    let audit = Arc::new(MemoryAuditSink::new());
    let responder = responder(&ops, audit.clone());
    let input = commit_bytes(commit("hub", &fp(0xB1), "full", Some("new.example:4500")));
    let (end, lines) = converse(&responder, &input).await;
    assert_eq!(end, RespondEnd::Answered(ResultStatus::Exists));
    let result = result_of(&lines);
    assert_eq!(result.name, "ctl");
    assert_eq!(result.role.as_deref(), Some("read-only"), "role unchanged");
    assert!(!result.created);
    let store = TrustStore::load(&ops.paths().trust_file()).unwrap();
    assert_eq!(store.peers().len(), 1, "no second pin");
    let held = store.find("ctl").unwrap();
    assert_eq!(held.address, "new.example:4500");
    assert_eq!(held.role.as_deref(), Some("read-only"));
    // `trust add` leaves no record for an address refresh, and neither does
    // this (the pin's grants did not change).
    assert!(audit.records().is_empty());

    // The same address again changes nothing on disk.
    let before = trust_bytes(&ops);
    let (_end, lines) = converse(&responder, &input).await;
    assert_eq!(result_of(&lines).status, ResultStatus::Exists);
    assert_eq!(trust_bytes(&ops), before);

    // An inbound-only pin (no address) gains the address and keeps its role.
    let (_dir, ops) = tree(true);
    pin(&ops, "ctl", &fp(0xB2), Some("full"));
    let responder = self::responder(&ops, Arc::new(MemoryAuditSink::new()));
    let input = commit_bytes(commit("hub", &fp(0xB2), "exec", Some("hub.example:4433")));
    let (_end, lines) = converse(&responder, &input).await;
    assert_eq!(result_of(&lines).role.as_deref(), Some("full"));
    let store = TrustStore::load(&ops.paths().trust_file()).unwrap();
    assert_eq!(store.find("ctl").unwrap().address, "hub.example:4433");
}

#[tokio::test]
async fn ssh_respond_a_forward_commit_never_touches_the_address_of_a_known_pin() {
    let (_dir, ops) = tree(true);
    {
        let path = ops.paths().trust_file();
        let _lock = TrustStore::lock(&path).unwrap();
        let mut store = TrustStore::load(&path).unwrap();
        store.add_peer_with_role(
            "ctl",
            Some("old.example:4433".into()),
            fp(0xB1).parse().unwrap(),
            now_rfc3339(),
            TrustRole::Full,
        );
        store.save(&path).unwrap();
    }
    let before = trust_bytes(&ops);
    let responder = responder(&ops, Arc::new(MemoryAuditSink::new()));
    let input = commit_bytes(commit("hub", &fp(0xB1), "full", None));
    let (_end, lines) = converse(&responder, &input).await;
    assert_eq!(result_of(&lines).status, ResultStatus::Exists);
    assert_eq!(trust_bytes(&ops), before);
}

#[tokio::test]
async fn ssh_respond_returns_conflict_for_the_same_name_with_another_fingerprint() {
    let (_dir, ops) = tree(true);
    pin(&ops, "laptop", &fp(0xC2), Some("full"));
    let before = trust_bytes(&ops);
    let audit = Arc::new(MemoryAuditSink::new());
    let responder = responder(&ops, audit.clone());
    let input = commit_bytes(commit("laptop", &fp(0xB1), "full", None));
    let (end, lines) = converse(&responder, &input).await;
    assert_eq!(end, RespondEnd::Answered(ResultStatus::Conflict));
    let result = result_of(&lines);
    assert_eq!(result.code, Some(ErrorCode::SessionConflict));
    assert!(!result.created);
    assert_eq!(
        trust_bytes(&ops),
        before,
        "trust.toml is byte-identical after a conflict"
    );
    assert!(audit.records().is_empty());
}

#[tokio::test(start_paused = true)]
async fn ssh_respond_writes_nothing_when_commit_times_out() {
    let (_dir, ops) = tree(true);
    let audit = Arc::new(MemoryAuditSink::new());
    let responder = responder(&ops, audit.clone());
    // The client keeps its end open and never sends a line. Time is
    // paused: the runtime jumps to the deadline once everything is idle.
    let (_client, server_input) = tokio::io::duplex(1024);
    let mut out = Vec::new();
    let started = tokio::time::Instant::now();
    let end = responder.run(server_input, &mut out).await.unwrap();
    assert_eq!(end, RespondEnd::CommitTimedOut);
    assert_eq!(started.elapsed(), MESSAGE_TIMEOUT);
    assert_eq!(MESSAGE_TIMEOUT, Duration::from_secs(30));
    // Only the hello was written.
    let lines = BootstrapReader::new().push(&out).unwrap();
    assert!(matches!(lines.as_slice(), [BootstrapLine::Hello(_)]));
    assert!(!ops.paths().trust_file().exists());
    assert!(audit.records().is_empty());
}

#[tokio::test(start_paused = true)]
async fn ssh_respond_a_partial_commit_line_does_not_extend_the_deadline() {
    let (_dir, ops) = tree(true);
    let responder = responder(&ops, Arc::new(MemoryAuditSink::new()))
        .with_commit_timeout(Duration::from_secs(5));
    let (mut client, server_input) = tokio::io::duplex(1024);
    client
        .write_all(b"qsh-bootstrap {\"type\":\"commit\"")
        .await
        .unwrap();
    let mut out = Vec::new();
    let end = responder.run(server_input, &mut out).await.unwrap();
    assert_eq!(end, RespondEnd::CommitTimedOut);
    assert!(!ops.paths().trust_file().exists());
}

#[tokio::test]
async fn ssh_respond_refuses_to_pin_when_audit_is_unwritable() {
    let (_dir, ops) = tree(true);
    let audit = Arc::new(FailingAuditSink::new());
    audit.fail();
    let responder = responder(&ops, audit.clone());
    let input = commit_bytes(commit("laptop", &fp(0xB1), "full", None));
    let (end, lines) = converse(&responder, &input).await;
    assert_eq!(end, RespondEnd::Answered(ResultStatus::Error));
    let result = result_of(&lines);
    assert_eq!(result.code, Some(ErrorCode::Internal));
    assert!(!result.created);
    assert!(
        !ops.paths().trust_file().exists(),
        "no audit record, no pin"
    );
    assert!(audit.records().is_empty());

    // Once the audit works again the same commit goes through.
    audit.clear();
    let (_end, lines) = converse(&responder, &input).await;
    assert_eq!(result_of(&lines).status, ResultStatus::Pinned);
    assert_eq!(audit.records().len(), 1);
}

#[tokio::test]
async fn ssh_respond_audit_record_has_only_structural_fields() {
    let (_dir, ops) = tree(true);
    let audit = Arc::new(MemoryAuditSink::new());
    let responder = responder(&ops, audit.clone());
    let input = commit_bytes(commit("laptop", &fp(0xB1), "tunnel", None));
    converse(&responder, &input).await;
    let records = audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, AUDIT_ACTION);
    assert_eq!(records[0].action, "pair.ssh_respond");
    assert_eq!(records[0].principal, "device:laptop");
    assert_eq!(records[0].resource, "laptop");
    assert_eq!(records[0].role.as_deref(), Some("tunnel"));
    assert_eq!(records[0].auth_path, "local");
    let value = serde_json::to_value(&records[0]).unwrap();
    let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    // The nine structural keys every record carries plus `role` (ADR-0045
    // decision 16); no field can hold the commit's text, an argv or a key.
    assert_eq!(
        keys,
        [
            "action",
            "auth_path",
            "decision",
            "peer_addr",
            "principal",
            "request_id",
            "resource",
            "role",
            "rule",
            "ts"
        ]
    );
}

/// An audit sink that checks the state of `trust.toml` and its lock at the
/// moment the record is written.
struct OrderProbe {
    trust: PathBuf,
    before: Vec<u8>,
    calls: Mutex<u32>,
}

impl AuditSink for OrderProbe {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        *self.calls.lock().unwrap() += 1;
        // Lock: another handle on the lock file cannot take it now.
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(crate::config::lock_path_for(&self.trust))
            .unwrap();
        assert!(
            matches!(lock.try_lock(), Err(TryLockError::WouldBlock)),
            "the audit record is written while the trust lock is held"
        );
        // Save comes after the audit: the file on disk is still the old one.
        assert_eq!(std::fs::read(&self.trust).unwrap_or_default(), self.before);
        Ok(())
    }
}

#[tokio::test]
async fn ssh_respond_writes_in_the_order_lock_load_mutate_audit_save() {
    let (_dir, ops) = tree(true);
    pin(&ops, "other", &fp(0xC2), Some("full"));
    let trust = ops.paths().trust_file();
    let probe = Arc::new(OrderProbe {
        before: std::fs::read(&trust).unwrap(),
        trust: trust.clone(),
        calls: Mutex::new(0),
    });
    let responder = responder(&ops, probe.clone());
    let input = commit_bytes(commit("laptop", &fp(0xB1), "full", None));
    let (_end, lines) = converse(&responder, &input).await;
    assert_eq!(result_of(&lines).status, ResultStatus::Pinned);
    assert_eq!(*probe.calls.lock().unwrap(), 1);
    // Load happened inside the lock: the pin made before the call survives.
    let store = TrustStore::load(&trust).unwrap();
    assert!(store.find("other").is_some());
    assert!(store.find("laptop").is_some());
    // The lock is free again once the conversation is over.
    let lock = File::open(crate::config::lock_path_for(&trust)).unwrap();
    assert!(lock.try_lock().is_ok());
}

#[tokio::test]
async fn ssh_respond_rejects_a_bad_commit_without_writing() {
    let (_dir, ops) = tree(true);
    let audit = Arc::new(MemoryAuditSink::new());
    let responder = responder(&ops, audit.clone());
    let too_long = format!("qsh-bootstrap {}\n", "x".repeat(BOOTSTRAP_LINE_MAX)).into_bytes();
    let hello_instead = BootstrapLine::Hello(Hello {
        versions: vec![1],
        qsh_version: "0".into(),
        status: HelloStatus::Ready,
        fingerprint: None,
        serve_bind: None,
        serve_listening: None,
    })
    .encode_line()
    .unwrap()
    .into_bytes();
    let mut wrong_version = commit("laptop", &fp(0xB1), "full", None);
    wrong_version.version = 9;
    let cases: Vec<(&str, Vec<u8>, ErrorCode)> = vec![
        (
            "not a line",
            b"hello there\n".to_vec(),
            ErrorCode::InvalidArgument,
        ),
        ("too long", too_long, ErrorCode::InvalidArgument),
        ("wrong message", hello_instead, ErrorCode::InvalidArgument),
        (
            "version",
            commit_bytes(wrong_version),
            ErrorCode::Unsupported,
        ),
        (
            "fingerprint",
            commit_bytes(commit("laptop", "sha256:short", "full", None)),
            ErrorCode::InvalidArgument,
        ),
        (
            "role",
            commit_bytes(commit("laptop", &fp(0xB1), "root", None)),
            ErrorCode::InvalidArgument,
        ),
        (
            "name",
            commit_bytes(commit("a/b", &fp(0xB1), "full", None)),
            ErrorCode::InvalidArgument,
        ),
        (
            "empty address",
            commit_bytes(commit("laptop", &fp(0xB1), "full", Some(""))),
            ErrorCode::InvalidArgument,
        ),
    ];
    for (label, input, code) in cases {
        let (end, lines) = converse(&responder, &input).await;
        assert_eq!(end, RespondEnd::Answered(ResultStatus::Error), "{label}");
        let result = result_of(&lines);
        assert_eq!(result.code, Some(code.clone()), "{label}");
        assert!(!result.created, "{label}");
        assert!(!ops.paths().trust_file().exists(), "{label}");
    }
    assert!(audit.records().is_empty());
}

#[tokio::test]
async fn ssh_respond_a_bad_commit_is_not_echoed_back() {
    let (_dir, ops) = tree(true);
    let responder = responder(&ops, Arc::new(MemoryAuditSink::new()));
    let input = commit_bytes(commit(
        "secret-name/x",
        "sha256:SecretFingerprint",
        "SecretRole",
        None,
    ));
    let mut out = Vec::new();
    responder.run(&input[..], &mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(!text.contains("SecretFingerprint"), "{text}");
    assert!(!text.contains("SecretRole"), "{text}");
    assert!(!text.contains("secret-name"), "{text}");
}

// ---------------------------------------------------------------------
// The UDP bind probe (ADR-0044 decision 10)
// ---------------------------------------------------------------------

#[test]
fn bind_probe_reports_a_taken_port_as_listening_and_a_free_one_as_not() {
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap();
    assert_eq!(probe_udp_bind(addr), Some(true));
    drop(taken);
    assert_eq!(probe_udp_bind(addr), Some(false));
}

#[test]
fn bind_probe_does_not_keep_the_port() {
    let free = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    assert_eq!(probe_udp_bind(addr), Some(false));
    // A second probe and a real bind both still succeed.
    assert_eq!(probe_udp_bind(addr), Some(false));
    std::net::UdpSocket::bind(addr).unwrap();
}

#[test]
fn bind_probe_sees_a_port_shared_with_reuse_address() {
    // A listener that opened the port with SO_REUSEADDR must still make the
    // probe answer "listening". The probe does not set SO_REUSEADDR itself,
    // so its plain bind already conflicts; the Windows probe's
    // SO_EXCLUSIVEADDRUSE (ADR-0044 decision 10) is defensive on top of that
    // and this test does not depend on it.
    let first = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    first.set_reuse_address(true).unwrap();
    first
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    let addr = first.local_addr().unwrap().as_socket().unwrap();
    assert_eq!(probe_udp_bind(addr), Some(true));
}

#[test]
fn serve_listening_is_unknown_for_a_spec_that_does_not_resolve() {
    assert_eq!(serve_listening("not an address"), None);
    assert_eq!(serve_listening(""), None);
}

#[test]
fn serve_listening_resolves_the_configured_spec() {
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let spec = taken.local_addr().unwrap().to_string();
    assert_eq!(serve_listening(&spec), Some(true));
}
