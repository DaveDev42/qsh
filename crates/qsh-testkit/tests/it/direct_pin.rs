//! A direct dial to a named pin reaches that pin and nobody else
//! (ADR-0060, threat model A25).
//!
//! The scenario of the defect, with two real hosts on loopback: the client
//! pins host B under `other`, and pins `mm` to host A's key but at B's
//! address. B is a pinned peer of the client, so a verifier that asks only
//! "is this key pinned anywhere" took B for `mm` and ran the command there.
//! Every command below must end `AUTH_FAILED` with nothing done on B, while
//! a correct pin, a hosts.toml name reached through the CA, and a name
//! pinned to the CA-issued leaf's own key still connect.

use std::sync::Arc;

use qsh_core::acl::AllowAllPinned;
use qsh_core::{CancelToken, ExecStdin, OpError, Ops, SilentObserver};
use qsh_proto::{
    CapabilitiesReq, ErrorCode, ExecRunReq, FileCopyReq, SessionOpenReq, TrustAddCaReq,
    TunnelOpenReq,
};
use qsh_testkit::loopback::{LoopbackHarness, make_ca, make_identity};
use qsh_transport::{Principal, StaticTrust};

use super::jump_chain::{Net, blocking, loopback_options};

/// Hosts `a` and `b` that pin the client, and a client that pins `good` (A at
/// A's address), `other` (B at B's address) and `mm` (A's key at B's
/// address).
async fn rig() -> Net {
    let net = Net::start_unpinned(&["a", "b"], |_| "*", loopback_options()).await;
    let (a, b) = (net.host("a"), net.host("b"));
    let (a_addr, a_fp) = (a.h.addr.to_string(), a.h.server_identity.fingerprint);
    let (b_addr, b_fp) = (b.h.addr.to_string(), b.h.server_identity.fingerprint);
    net.pin("good", Some(a_addr), a_fp).await;
    net.pin("other", Some(b_addr.clone()), b_fp).await;
    net.pin("mm", Some(b_addr), a_fp).await;
    net
}

fn echo_argv() -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["sh".into(), "-c".into(), "echo reached".into()]
    }
    #[cfg(windows)]
    {
        vec!["cmd".into(), "/c".into(), "echo reached".into()]
    }
}

async fn exec(ops: &Ops, host: &str) -> Result<qsh_core::ExecRunOutput, OpError> {
    let ops = ops.clone();
    let req = ExecRunReq {
        host: host.into(),
        argv: echo_argv(),
        env: vec![],
        timeout_ms: Some(30_000),
    };
    blocking(move || ops.exec_run(req, ExecStdin::Closed)).await
}

fn session_req(host: &str) -> SessionOpenReq {
    SessionOpenReq {
        host: host.into(),
        argv: vec!["sh".into()],
        env: vec![],
        term: Some("xterm-256color".into()),
        cols: Some(80),
        rows: Some(24),
        user: None,
        shell_command: None,
    }
}

/// The error a dial to the wrong host ends in: the coarse `untrusted`
/// category of every rejected server certificate, not a new code.
fn assert_wrong_host(err: &OpError) {
    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert!(!err.retryable, "{err:?}");
    assert_eq!(err.details["category"], "untrusted", "{err:?}");
}

/// Nothing was admitted on `host`: no `allow` record of any kind, no
/// session, whatever its audit holds from the handshakes that were refused.
fn untouched(host: &super::jump_chain::Host) {
    let allowed: Vec<_> = host
        .h
        .audit
        .records()
        .into_iter()
        .filter(|r| r.decision == "allow")
        .collect();
    assert!(allowed.is_empty(), "{} allowed: {allowed:?}", host.name);
    assert_eq!(
        host.h.broker.session_count(),
        0,
        "{} has a session",
        host.name
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_name_pinned_to_one_host_never_reaches_another_pinned_host() {
    let net = rig().await;

    // exec
    let err = exec(&net.ops, "mm")
        .await
        .expect_err("B answered for A's pin");
    assert_wrong_host(&err);

    // a PTY session
    let ops = net.ops.clone();
    let err = blocking(move || ops.session_open(session_req("mm")))
        .await
        .expect_err("session.open reached B");
    assert_wrong_host(&err);

    // capabilities
    let ops = net.ops.clone();
    let err = blocking(move || {
        ops.capabilities(CapabilitiesReq {
            host: Some("mm".into()),
        })
    })
    .await
    .expect_err("capabilities answered by B");
    assert_wrong_host(&err);

    // a -L tunnel
    let ops = net.ops.clone();
    let err = blocking(move || {
        ops.tunnel_open(TunnelOpenReq {
            host: "mm".into(),
            mode: "local".into(),
            bind: None,
            listen_port: u32::from(qsh_testkit::net_probe::free_port()),
            forward_host: "127.0.0.1".into(),
            forward_port: 9,
            wait_ms: None,
            supervise_ms: None,
            accept_hold_ms: None,
        })
        .map(|hold| hold.close())
    })
    .await
    .expect_err("tunnel.open reached B");
    assert_wrong_host(&err);

    // qsh cp, both directions
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.bin");
    let landed = dir.path().join("landed.bin");
    std::fs::write(&source, b"payload").expect("write the source");
    let ops = net.ops.clone();
    let req = FileCopyReq {
        sources: vec![source.to_string_lossy().into_owned()],
        destination: format!("[mm]:{}", landed.display()),
        recursive: false,
        preserve: false,
        no_clobber: false,
    };
    let err = blocking(move || ops.file_copy(req, Arc::new(SilentObserver), &CancelToken::new()))
        .await
        .expect_err("cp reached B");
    assert_wrong_host(&err.error);
    assert!(!landed.exists(), "cp wrote a file on B's behalf");
    let ops = net.ops.clone();
    let pulled = dir.path().join("pulled.bin");
    let req = FileCopyReq {
        sources: vec![format!("[mm]:{}", source.display())],
        destination: pulled.to_string_lossy().into_owned(),
        recursive: false,
        preserve: false,
        no_clobber: false,
    };
    let err = blocking(move || ops.file_copy(req, Arc::new(SilentObserver), &CancelToken::new()))
        .await
        .expect_err("cp pull reached B");
    assert_wrong_host(&err.error);
    assert!(!pulled.exists(), "cp pulled a file from B");

    // Neither host did anything: B was never admitted, and A was never dialed.
    untouched(net.host("b"));
    untouched(net.host("a"));
    net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_correct_pin_still_connects_and_the_refused_host_would_have_served() {
    let net = rig().await;
    let out = exec(&net.ops, "good").await.expect("A under its own pin");
    assert_eq!(out.data.remote_exit_code, 0);
    // B answers under B's own name, which shows the refusal above came from
    // the pin and not from B refusing the client.
    let out = exec(&net.ops, "other").await.expect("B under its own pin");
    assert_eq!(out.data.remote_exit_code, 0);
    let ops = net.ops.clone();
    let caps = blocking(move || {
        ops.capabilities(CapabilitiesReq {
            host: Some("good".into()),
        })
    })
    .await
    .expect("capabilities under a correct pin");
    assert!(!caps.capabilities.is_empty());
    net.shutdown().await;
}

fn pem_of(der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("ascii"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_name_without_a_pin_is_reached_through_the_ca_and_not_through_a_pin() {
    let net = rig().await;
    // A host whose leaf the private CA issued, and a client that trusts the
    // CA. The names below come from hosts.toml and have no pin.
    let ca = make_ca();
    let leaf = ca.issue("qsh://device/cahost");
    let leaf_fp = leaf.fingerprint;
    let trust = StaticTrust::empty().with_pin(net.fp, Principal::Device("laptop".into()));
    let ca_host = LoopbackHarness::start_with_server_identity(
        Arc::new(AllowAllPinned),
        make_identity(),
        trust,
        leaf,
    )
    .await;
    let ops = net.ops.clone();
    let root_pem = pem_of(ca.root_der.as_ref());
    blocking(move || {
        ops.trust_add_ca(TrustAddCaReq {
            name: "root".into(),
            cert_pem: root_pem,
        })
    })
    .await
    .expect("trust.add_ca");
    let hosts = format!(
        "[[host]]\nname = \"cahost\"\naddress = \"{}\"\n\n\
         [[host]]\nname = \"stranger\"\naddress = \"{}\"\n",
        ca_host.addr,
        net.host("b").h.addr
    );
    std::fs::write(net.ops.paths().hosts_file(), hosts).expect("write hosts.toml");

    // The CA-issued host answers a name with no pin.
    let out = exec(&net.ops, "cahost").await.expect("through the CA");
    assert_eq!(out.data.remote_exit_code, 0);
    // A host that is pinned (as `other`) but not CA-issued does not answer a
    // name with no pin: the pin belongs to another name.
    let err = exec(&net.ops, "stranger")
        .await
        .expect_err("a pin of another name does not admit an unpinned name");
    assert_wrong_host(&err);
    untouched(net.host("b"));

    // The same CA-issued leaf pinned by its own key also connects: a pin is
    // exactly that key, wherever the chain behind it comes from.
    net.pin("cahost-pinned", Some(ca_host.addr.to_string()), leaf_fp)
        .await;
    let out = exec(&net.ops, "cahost-pinned").await.expect("pinned leaf");
    assert_eq!(out.data.remote_exit_code, 0);

    ca_host.shutdown().await;
    net.shutdown().await;
}
