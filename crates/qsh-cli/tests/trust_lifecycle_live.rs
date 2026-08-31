//! `trust remove`/`trust add` live semantics against a **running** `qsh
//! serve` daemon, driven through the product path (`PLAN.md` M7 Step 2,
//! `docs/ROADMAP.md` M7 DoD 4).
//!
//! `SharedTrustStore` (`crates/qsh-core/src/trust/mod.rs`) re-reads
//! `trust.toml` on every `TrustEvaluator` lookup and reloads on any content
//! change (byte comparison is the sole arbiter — not mtime), and the
//! host's `QshPeerVerifier` calls that lookup synchronously on every TLS
//! handshake (`crates/qsh-transport/src/tls.rs`) — so a running daemon
//! picks up a `trust remove`/`trust add` without a restart, *for new
//! handshakes*. This file is the real-QUIC proof of that (E1,
//! `PLAN.md` M7 Step 2 §A) plus the two behaviors decision A commits to:
//!
//! - an **established** connection survives a `trust remove` of its own
//!   principal — the same PTY-backed attach keeps writing and reading;
//! - the **next** handshake against the same running `qsh serve` (no
//!   restart) is rejected.
//!
//! It also carries the real-QUIC reproduction of decision B's `trust add`
//! address-update path: the M6 mobility-campaign backlog item where a
//! host's `qsh serve` rebinds to a new address under the same identity.
//!
//! Sessions are PTY-backed, so this file only exists on POSIX hosts
//! (mirrors `attach_recovery.rs`'s own gate and reasoning).

#![cfg(unix)]

mod common;

use base64::Engine as _;
use common::{CLIENT_ALIAS, HOST_ALIAS, Sandbox, ServeGuard};
use qsh_core::{ExecStdin, Ops, Paths, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{EnvVar, ErrorCode, ExecRunReq, SessionAttachReq, SessionOpenReq};

/// Bring up a host (`qsh serve`) that pins `client`, and a client sandbox
/// pinned back to it. Returns `(host, client, serve, host_fingerprint)`.
fn start(client: &Sandbox) -> (Sandbox, ServeGuard, String) {
    let host = Sandbox::new();
    let host_fingerprint = host.fingerprint();
    let client_fingerprint = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fingerprint);
    let serve = ServeGuard::start(&host);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fingerprint);
    (host, serve, host_fingerprint)
}

fn client_ops(client: &Sandbox) -> Ops {
    Ops::new(Paths::new(
        client.config_dir().to_path_buf(),
        client.state_dir().to_path_buf(),
    ))
}

fn open_shell(ops: &Ops) -> String {
    ops.session_open(SessionOpenReq {
        host: HOST_ALIAS.to_string(),
        argv: vec!["sh".to_string()],
        env: vec![
            EnvVar {
                name: "LANG".into(),
                value: "C".into(),
            },
            EnvVar {
                name: "PS1".into(),
                value: String::new(),
            },
        ],
        term: Some("xterm-256color".into()),
        cols: Some(80),
        rows: Some(24),
        user: None,
    })
    .expect("session.open")
    .session_ref
}

fn attach(ops: &Ops, session_ref: &str) -> SessionAttachStream {
    ops.session_attach(
        SessionAttachReq {
            session_ref: session_ref.to_string(),
            no_steal: false,
        },
        &[],
    )
    .expect("session.attach")
}

/// Drain events until the accumulated output contains `needle`, panicking
/// (with everything seen so far) if the stream ends first.
fn read_until(stream: &mut SessionAttachStream, needle: &str) -> String {
    let mut seen = String::new();
    while let Some(event) = stream.next_event() {
        match event.unwrap_or_else(|err| panic!("attach stream failed: {err}")) {
            SessionEvent::Output { data_b64, .. } => {
                let data = base64::engine::general_purpose::STANDARD
                    .decode(data_b64.as_bytes())
                    .expect("session output is Base64");
                seen.push_str(&String::from_utf8_lossy(&data));
                if seen.contains(needle) {
                    return seen;
                }
            }
            SessionEvent::Exit { .. } | SessionEvent::Closed { .. } => {
                panic!("session ended before {needle:?} arrived; saw {seen:?}")
            }
            _ => {}
        }
    }
    panic!("attach stream ended before {needle:?} arrived; saw {seen:?}");
}

/// **E1 (i) / DoD 4 first half.** `trust remove` on a *running* `qsh
/// serve` (no restart) does not touch a connection that is already
/// established: the client keeps writing to, and reading from, the same
/// live PTY session after the host un-pins it.
#[test]
fn an_established_connection_survives_the_hosts_trust_remove() {
    let client = Sandbox::new();
    let (host, _serve, _host_fp) = start(&client);
    let ops = client_ops(&client);

    let session_ref = open_shell(&ops);
    let mut stream = attach(&ops, &session_ref);
    stream
        .write(b"printf 'BEFORE%s\\n' 1\n".to_vec())
        .expect("write before remove");
    read_until(&mut stream, "BEFORE1");

    let (code, removed) = host.json(&["trust", "remove", CLIENT_ALIAS, "--json"]);
    assert_eq!(code, 0, "{removed}");
    assert_eq!(removed["data"]["removed"], true, "{removed}");

    // The already-established connection must not notice: same stream,
    // same principal, no re-handshake.
    stream
        .write(b"printf 'AFTER%s\\n' 1\n".to_vec())
        .expect("write after remove");
    read_until(&mut stream, "AFTER1");

    stream.close();
}

/// **E1 (ii) / DoD 4 second half.** `trust remove` on a *running* `qsh
/// serve` (no restart) rejects the very next handshake from the removed
/// principal — `SharedTrustStore` reloads `trust.toml` on the verifier's
/// next lookup, so the host does not need to be restarted for this to take
/// effect (README "Known limitations", `docs/CLI.md` §6.11).
#[test]
fn trust_remove_on_a_running_daemon_rejects_the_next_handshake_without_a_restart() {
    let client = Sandbox::new();
    let (host, _serve, _host_fp) = start(&client);
    let ops = client_ops(&client);

    // Sanity: a fresh handshake succeeds before removal.
    ops.exec_run(
        ExecRunReq {
            host: HOST_ALIAS.to_string(),
            argv: vec!["true".to_string()],
            env: vec![],
            timeout_ms: Some(10_000),
        },
        ExecStdin::Closed,
    )
    .expect("exec.run must succeed before trust remove");

    let (code, removed) = host.json(&["trust", "remove", CLIENT_ALIAS, "--json"]);
    assert_eq!(code, 0, "{removed}");
    assert_eq!(removed["data"]["removed"], true, "{removed}");

    // Same running `qsh serve` process (never restarted): the next fresh
    // dial must be rejected as untrusted.
    let err = ops
        .exec_run(
            ExecRunReq {
                host: HOST_ALIAS.to_string(),
                argv: vec!["true".to_string()],
                env: vec![],
                timeout_ms: Some(10_000),
            },
            ExecStdin::Closed,
        )
        .expect_err("a removed peer's next handshake must be rejected");
    assert_eq!(
        err.code,
        ErrorCode::AuthFailed,
        "unexpected error for a post-removal handshake: {err:?}"
    );
}

/// **`PLAN.md` M7 Step 2 P2-2, real-QUIC regression.** Same scenario as
/// [`trust_remove_on_a_running_daemon_rejects_the_next_handshake_without_a_restart`],
/// except the host's `trust.toml` is pinned back to its pre-removal mtime
/// right after the CLI rewrites it — simulating a coarse-granularity
/// filesystem (HFS+, exFAT/FAT, some SMB/NFS mounts; 1-2s resolution) where
/// the removal's rewrite lands in the same tick as the file the running
/// `SharedTrustStore` already has cached. An mtime-only invalidator would
/// miss this and let the removed peer's next handshake through; the
/// content-based `refresh` (`crates/qsh-core/src/trust/mod.rs`) must not.
#[test]
fn trust_remove_on_a_running_daemon_rejects_the_next_handshake_even_with_the_file_mtime_pinned() {
    let client = Sandbox::new();
    let (host, _serve, _host_fp) = start(&client);
    let ops = client_ops(&client);

    // The mtime the host's running `SharedTrustStore` cached at startup —
    // the value a same-tick removal would collide on on a coarse
    // filesystem.
    let trust_path = host.config_dir().join("trust.toml");
    let pinned_mtime = std::fs::metadata(&trust_path)
        .expect("host trust.toml must exist")
        .modified()
        .expect("mtime");

    // Sanity: a fresh handshake succeeds before removal.
    ops.exec_run(
        ExecRunReq {
            host: HOST_ALIAS.to_string(),
            argv: vec!["true".to_string()],
            env: vec![],
            timeout_ms: Some(10_000),
        },
        ExecStdin::Closed,
    )
    .expect("exec.run must succeed before trust remove");

    let (code, removed) = host.json(&["trust", "remove", CLIENT_ALIAS, "--json"]);
    assert_eq!(code, 0, "{removed}");
    assert_eq!(removed["data"]["removed"], true, "{removed}");

    // `trust remove` rewrote the file atomically (temp+fsync+rename), so
    // its mtime is naturally "now" on a fine-grained filesystem. Pin it
    // back to the pre-removal value to reproduce the same-tick collision
    // deterministically, without depending on the test host's actual
    // filesystem timestamp resolution or any sleep.
    let file = std::fs::File::options()
        .write(true)
        .open(&trust_path)
        .expect("reopen host trust.toml after removal");
    file.set_times(std::fs::FileTimes::new().set_modified(pinned_mtime))
        .expect("pin trust.toml's mtime back to its pre-removal value");
    assert_eq!(
        std::fs::metadata(&trust_path).unwrap().modified().unwrap(),
        pinned_mtime,
        "test setup: the mtime must be pinned back to its pre-removal value"
    );

    // Same running `qsh serve` process (never restarted), mtime unchanged
    // from what its cache already has, content changed under it: the next
    // fresh dial must still be rejected as untrusted.
    let err = ops
        .exec_run(
            ExecRunReq {
                host: HOST_ALIAS.to_string(),
                argv: vec!["true".to_string()],
                env: vec![],
                timeout_ms: Some(10_000),
            },
            ExecStdin::Closed,
        )
        .expect_err("a removed peer's next handshake must be rejected even with the mtime pinned");
    assert_eq!(
        err.code,
        ErrorCode::AuthFailed,
        "unexpected error for a post-removal handshake with the mtime pinned: {err:?}"
    );
}

/// **Decision B / M6 mobility-campaign reproduction.** The host's identity
/// (and therefore fingerprint) survives a `qsh serve` restart on a new
/// port — the M2 mobility scenario this crate's `docs/campaigns/
/// m2-mobility.md` exercises manually. `trust add` re-run with the *same*
/// name and fingerprint but a *new* `--address` must update the pin in
/// place (`data.updated == true`, `data.created == false`,
/// `docs/CLI.md` §6.11) so a live client can follow the host to its new
/// address without a `trust remove` first.
#[test]
fn trust_add_rebinds_a_known_identity_to_the_hosts_new_address() {
    let client = Sandbox::new();
    let host = Sandbox::new();
    let host_fingerprint = host.fingerprint();
    let client_fingerprint = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fingerprint);

    let serve1 = ServeGuard::start(&host);
    let addr1 = serve1.addr().to_string();
    client.trust_add(HOST_ALIAS, Some(&addr1), &host_fingerprint);
    let ops = client_ops(&client);

    ops.exec_run(
        ExecRunReq {
            host: HOST_ALIAS.to_string(),
            argv: vec!["true".to_string()],
            env: vec![],
            timeout_ms: Some(10_000),
        },
        ExecStdin::Closed,
    )
    .expect("exec.run must succeed at the first address");

    // The host's `qsh serve` goes away and comes back on a different
    // ephemeral port, same on-disk identity — an address change with no
    // fingerprint change, exactly what decision B's update path is for.
    drop(serve1);
    let serve2 = ServeGuard::start(&host);
    let addr2 = serve2.addr().to_string();
    assert_ne!(
        addr1, addr2,
        "test needs the OS to hand back a different ephemeral port"
    );

    let (code, added) = client.json(&[
        "trust",
        "add",
        HOST_ALIAS,
        "--address",
        &addr2,
        "--fingerprint",
        &host_fingerprint,
        "--json",
    ]);
    assert_eq!(code, 0, "{added}");
    assert_eq!(added["data"]["created"], false, "{added}");
    assert_eq!(added["data"]["updated"], true, "{added}");
    assert_eq!(added["data"]["peer"]["address"], addr2, "{added}");

    // A dial against the same alias now reaches the host at its new
    // address with no other trust-store change (no remove, no re-init).
    ops.exec_run(
        ExecRunReq {
            host: HOST_ALIAS.to_string(),
            argv: vec!["true".to_string()],
            env: vec![],
            timeout_ms: Some(10_000),
        },
        ExecStdin::Closed,
    )
    .expect("exec.run must succeed at the rebound address");
}
