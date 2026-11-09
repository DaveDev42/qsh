//! L3 loopback for the client side of a jump chain (ADR-0056 decisions 4 to
//! 6 and 10 to 13; DoD 25.1, 25.2, 25.4 (client half), 25.5, 25.6 and 25.11).
//!
//! Every party is real and talks over real loopback UDP:
//!
//! ```text
//!   client (Ops, or dial_chain) ==QUIC== J1 --UDP-- J2 --UDP-- ... --UDP-- T
//! ```
//!
//! Two rigs:
//!
//! - [`Net`] drives the product `Ops` with `with_jump`, so a PTY session, an
//!   exec, a `-L` tunnel and a `qsh cp` run on the end connection of a chain
//!   exactly as they would on a direct one.
//! - [`Direct`] calls `dial_chain` itself, with a hand-made plan and the
//!   trust it wants, to look at the chain: which carrier a channel took,
//!   which step failed and how fast.
//!
//! Every peer of a chain is a [`LoopbackHarness`]. The intermediate ones
//! turn their host-local filter off with the same test hook that shortens
//! their timers, since every target here is on loopback.

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qsh_core::acl::{AllowAllPinned, Authorizer, Role, load_or_deny};
use qsh_core::client::Session;
use qsh_core::config::Paths;
use qsh_core::jump::carrier::{Carrier, choose_carrier};
use qsh_core::jump::chain::{budget, datagram_packet_limit};
use qsh_core::jump::{
    ChainConn, HopPin, JumpFailure, JumpOptions, JumpPlan, MAX_JUMP_HOPS, Stage, dial_chain,
};
use qsh_core::trust::SharedTrustStore;
use qsh_core::{CancelToken, ExecStdin, Fingerprint, OpError, Ops, SilentObserver};
use qsh_proto::wire::{CAP_DATAGRAM_V1, CAP_JUMP_V1};
use qsh_proto::{
    ErrorCode, ExecRunReq, FileCopyReq, IdentityInitReq, KeyStoreMode, SessionOpenReq,
    SessionReadReq, SessionWriteReq, TrustAddReq, TunnelOpenReq,
};
use qsh_testkit::loopback::{LoopbackHarness, TestIdentity, make_identity};
use qsh_testkit::net_probe::free_port;
use qsh_testkit::tunnel::EchoServer;
use qsh_transport::{Dialer, Principal, StaticTrust};
use serde_json::json;
use tokio::net::UdpSocket;

const LIMIT: Duration = Duration::from_secs(60);

pub(super) async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    blocking_named("a blocking step", f).await
}

/// `blocking` that names the step, so a hang says which one.
pub(super) async fn blocking_named<T: Send + 'static>(
    step: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    eprintln!("step: {step}");
    match tokio::time::timeout(LIMIT, tokio::task::spawn_blocking(f)).await {
        Ok(joined) => joined.expect("blocking task"),
        Err(_) => panic!("{step} did not finish within {LIMIT:?}"),
    }
}

pub(super) fn loopback_options() -> JumpOptions {
    JumpOptions {
        allow_host_local: true,
        ..JumpOptions::default()
    }
}

/// `trust.toml` pinning the client as `laptop` with `role`, and the host's
/// production authorizer built over it.
struct Roles {
    _dir: tempfile::TempDir,
    paths: Paths,
    authorizer: Arc<dyn Authorizer>,
}

fn roles(client: Fingerprint, role: &str) -> Roles {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    std::fs::create_dir_all(&paths.config_dir).expect("config dir");
    if role == "*" {
        return Roles {
            _dir: dir,
            paths,
            authorizer: Arc::new(AllowAllPinned),
        };
    }
    std::fs::write(
        paths.trust_file(),
        format!(
            "[[peer]]\nname = \"laptop\"\nfingerprint = \"{client}\"\naddress = \"\"\n\
             added_at = \"2026-11-09T00:00:00Z\"\nrole = \"{role}\"\n"
        ),
    )
    .expect("write trust.toml");
    let trust = SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");
    let (authorizer, _diagnostic) = load_or_deny(&paths, Role::Serve, trust);
    Roles {
        _dir: dir,
        paths,
        authorizer,
    }
}

// ----------------------------------------------------------------------
// the hosts
// ----------------------------------------------------------------------

pub(super) struct Host {
    pub(super) name: String,
    pub(super) h: LoopbackHarness,
    _roles: Roles,
}

impl Host {
    pub(super) fn pin(&self) -> HopPin {
        HopPin {
            name: self.name.clone(),
            address: self.h.addr.to_string(),
            fingerprint: self.h.server_identity.fingerprint,
        }
    }
}

/// One host per name, each pinning `client` as `laptop` with `role_of(name)`.
pub(super) async fn start_hosts(
    names: &[&str],
    client: Fingerprint,
    role_of: impl Fn(&str) -> &'static str,
    options: JumpOptions,
) -> Vec<Host> {
    let mut hosts = Vec::new();
    for name in names {
        let roles = roles(client, role_of(name));
        let trust = StaticTrust::empty().with_pin(client, Principal::Device("laptop".into()));
        let h =
            LoopbackHarness::start_custom(Arc::clone(&roles.authorizer), make_identity(), trust)
                .await;
        h.server.set_jump_options(options);
        // The file ops refuse everything until the host knows which paths
        // are its own.
        h.server.set_file_host(
            roles.paths.clone(),
            qsh_core::config::AuditConfig::default(),
        );
        hosts.push(Host {
            name: (*name).to_string(),
            h,
            _roles: roles,
        });
    }
    hosts
}

pub(super) async fn shutdown(hosts: Vec<Host>) {
    // Each host waits out its own drain grace; wait for them together.
    let mut set = tokio::task::JoinSet::new();
    for host in hosts {
        set.spawn(host.h.shutdown());
    }
    while set.join_next().await.is_some() {}
}

// ----------------------------------------------------------------------
// rig 1: the product Ops
// ----------------------------------------------------------------------

pub(super) struct Net {
    _dir: tempfile::TempDir,
    pub(super) ops: Ops,
    /// The client's fingerprint, which the hosts pin.
    pub(super) fp: Fingerprint,
    pub(super) hosts: Vec<Host>,
}

impl Net {
    /// A client `Ops` that pins every host in `names` (the last is the
    /// target) and hosts that pin the client with `full`.
    pub(super) async fn start(names: &[&str]) -> Self {
        Self::start_with(names, |_| "*", loopback_options()).await
    }

    async fn start_with(
        names: &[&str],
        role_of: impl Fn(&str) -> &'static str,
        options: JumpOptions,
    ) -> Self {
        let net = Self::start_unpinned(names, role_of, options).await;
        for host in &net.hosts {
            net.pin(
                &host.name,
                Some(host.h.addr.to_string()),
                host.h.server_identity.fingerprint,
            )
            .await;
        }
        net
    }

    /// [`Self::start_with`] without the client's pins, for a test that pins
    /// some hosts at an address of its own (a chaos proxy in front).
    pub(super) async fn start_unpinned(
        names: &[&str],
        role_of: impl Fn(&str) -> &'static str,
        options: JumpOptions,
    ) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(
            dir.path().join("client/config"),
            dir.path().join("client/state"),
        );
        let ops = Ops::new(paths);
        let init = blocking({
            let ops = ops.clone();
            move || {
                ops.identity_init(IdentityInitReq {
                    key_store: Some(KeyStoreMode::File),
                    ..Default::default()
                })
            }
        })
        .await
        .expect("identity.init");
        let fp: Fingerprint = init.fingerprint.parse().expect("fingerprint");
        let hosts = start_hosts(names, fp, role_of, options).await;
        Self {
            _dir: dir,
            ops,
            fp,
            hosts,
        }
    }

    pub(super) async fn pin(&self, name: &str, address: Option<String>, fingerprint: Fingerprint) {
        let ops = self.ops.clone();
        let name = name.to_string();
        blocking(move || {
            ops.trust_add(TrustAddReq {
                name,
                address,
                fingerprint: Some(fingerprint.to_string()),
                cert_pem: None,
                role: None,
            })
        })
        .await
        .expect("trust.add");
    }

    pub(super) fn host(&self, name: &str) -> &Host {
        self.hosts
            .iter()
            .find(|h| h.name == name)
            .expect("a host of the net")
    }

    /// The client reaching everything through `hops`.
    pub(super) fn via(&self, hops: &[&str]) -> Ops {
        self.ops
            .clone()
            .with_jump(hops.iter().map(|h| (*h).to_string()).collect())
    }

    pub(super) async fn shutdown(self) {
        shutdown(self.hosts).await;
    }
}

fn echo_argv(text: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["sh".into(), "-c".into(), format!("echo {text}")]
    }
    #[cfg(windows)]
    {
        vec!["cmd".into(), "/c".into(), format!("echo {text}")]
    }
}

async fn exec(
    ops: &Ops,
    host: &str,
    argv: Vec<String>,
) -> Result<qsh_core::ExecRunOutput, OpError> {
    let ops = ops.clone();
    let req = ExecRunReq {
        host: host.into(),
        argv,
        env: vec![],
        timeout_ms: Some(30_000),
    };
    blocking(move || ops.exec_run(req, ExecStdin::Closed)).await
}

fn stdout_of(out: &qsh_core::ExecRunOutput) -> String {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(out.data.stdout_b64.as_bytes())
        .expect("stdout is Base64");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// One round trip through a `-L` listener: write `payload`, half-close, read
/// the echo to the end.
fn echo_through(listen_port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], listen_port)),
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = stream.try_clone()?;
    let data = payload.to_vec();
    let writing = std::thread::spawn(move || {
        writer.write_all(&data)?;
        writer.shutdown(Shutdown::Write)
    });
    let mut got = Vec::new();
    stream.read_to_end(&mut got)?;
    writing.join().expect("writer thread")?;
    Ok(got)
}

/// The features of DoD 25.1 and 25.2 on the end connection of `ops`: an
/// exec, a PTY session (the host's side is the test's pipe), a `-L` tunnel
/// to an echo server and a `qsh cp`. Returns after each has finished.
async fn every_feature(net: &Net, ops: &Ops, target: &str, tag: &str) {
    // exec
    let said = format!("exec-{tag}");
    let out = exec(ops, target, echo_argv(&said))
        .await
        .expect("exec through the chain");
    assert_eq!(out.data.remote_exit_code, 0);
    assert!(stdout_of(&out).contains(&said), "{:?}", stdout_of(&out));

    // a PTY session: the output the host's side produces reaches the
    // client, and the input the client writes reaches the host's side.
    let opened = {
        let ops = ops.clone();
        let host = target.to_string();
        blocking_named("session.open", move || {
            ops.session_open(SessionOpenReq {
                host,
                argv: vec!["sh".into()],
                env: vec![],
                term: Some("xterm-256color".into()),
                cols: Some(80),
                rows: Some(24),
                user: None,
                shell_command: None,
            })
        })
        .await
        .expect("session.open through the chain")
    };
    let mut pipe = net
        .host(target)
        .h
        .pipes
        .take()
        .expect("the host's side of the session");
    let hello = format!("hello-{tag}");
    pipe.write_output(hello.as_bytes()).await.expect("output");
    let read = {
        let ops = ops.clone();
        let session_ref = opened.session_ref.clone();
        blocking_named("session.read", move || {
            ops.session_read(SessionReadReq {
                session_ref,
                after_sequence: 0,
                wait_ms: Some(10_000),
                limit_bytes: None,
                ctl_after: None,
            })
        })
        .await
        .expect("session.read through the chain")
    };
    assert_eq!(String::from_utf8_lossy(&read.output), hello);
    {
        use base64::Engine as _;
        let ops = ops.clone();
        let session_ref = opened.session_ref.clone();
        let data = format!("typed-{tag}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());
        blocking_named("session.write", move || {
            ops.session_write(SessionWriteReq {
                session_ref,
                data_b64: b64,
            })
        })
        .await
        .expect("session.write through the chain");
        let got = pipe.read_input(64).await.expect("input");
        assert_eq!(got, data.as_bytes());
    }

    // -L to an echo server on the target's machine
    let echo = EchoServer::start().await.expect("echo server");
    let echo_port = echo.port();
    let listen_port = free_port();
    let payload: Vec<u8> = (0..192 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let got = {
        let ops = ops.clone();
        let host = target.to_string();
        blocking_named("-L tunnel and echo", move || {
            let hold = ops
                .tunnel_open(TunnelOpenReq {
                    host,
                    mode: "local".into(),
                    bind: None,
                    listen_port: u32::from(listen_port),
                    forward_host: "127.0.0.1".into(),
                    forward_port: u32::from(echo_port),
                    wait_ms: None,
                    supervise_ms: None,
                    accept_hold_ms: None,
                })
                .expect("open the -L tunnel through the chain");
            let got = echo_through(listen_port, &payload).expect("a round trip through -L");
            hold.close();
            got
        })
        .await
    };
    assert_eq!(got.len(), expected.len(), "truncated or padded");
    assert!(got == expected, "the echo came back different");

    // qsh cp
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.bin");
    let dest = dir.path().join("dest.bin");
    let bytes: Vec<u8> = (0..300 * 1024).map(|i| (i % 253) as u8).collect();
    std::fs::write(&source, &bytes).expect("write the source");
    let req = FileCopyReq {
        sources: vec![source.to_string_lossy().into_owned()],
        destination: format!("[{target}]:{}", dest.display()),
        recursive: false,
        preserve: false,
        no_clobber: false,
    };
    let data = {
        let ops = ops.clone();
        blocking_named("cp", move || {
            ops.file_copy(req, Arc::new(SilentObserver), &CancelToken::new())
        })
        .await
    }
    .unwrap_or_else(|err| panic!("cp through the chain: {err:?}"));
    assert_eq!(data.files, 1, "{data:?}");
    assert!(
        std::fs::read(&dest).expect("the copy") == bytes,
        "the copy differs from the source"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_one_hop_runs_every_feature() {
    let net = Net::start(&["j", "t"]).await;
    let ops = net.via(&["j"]);
    every_feature(&net, &ops, "t", "one").await;
    // J carried it, and the target saw the client, not J.
    let stats = net.host("j").h.server.jump_stats();
    assert!(stats.opened.load(std::sync::atomic::Ordering::Relaxed) >= 4);
    assert!(
        stats
            .to_target_packets
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
    let t_audit = net.host("t").h.audit.records();
    assert!(
        t_audit.iter().any(|r| r.principal.contains("laptop")),
        "the target audits the client's principal"
    );
    assert!(
        net.host("j")
            .h
            .audit
            .records()
            .iter()
            .any(|r| r.action == "forward.jump"),
        "the hop audits the jump"
    );
    net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_two_hops_runs_session_exec_and_cp() {
    let net = Net::start(&["a", "b", "t"]).await;
    let ops = net.via(&["a", "b"]);
    every_feature(&net, &ops, "t", "two").await;
    let a = net.host("a").h.server.jump_stats();
    let b = net.host("b").h.server.jump_stats();
    assert!(a.opened.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    assert!(b.opened.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    net.shutdown().await;
}

// ----------------------------------------------------------------------
// validation: no dial
// ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_chain_is_invalid_argument_and_dials_nothing() {
    let net = Net::start(&["a", "b", "c", "d", "e", "t"]).await;
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("five hops", vec!["a", "b", "c", "d", "e"]),
        ("the same pin twice", vec!["a", "b", "a"]),
        ("the target among the hops", vec!["a", "t"]),
    ];
    for (what, hops) in cases {
        let started = Instant::now();
        let err = exec(&net.via(&hops), "t", echo_argv("x"))
            .await
            .expect_err(what);
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{what}: {err:?}");
        assert!(started.elapsed() < Duration::from_secs(2), "{what}");
    }
    for host in &net.hosts {
        let stats = host.h.server.jump_stats();
        assert_eq!(
            stats.opened.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "{} opened a channel",
            host.name
        );
        assert!(
            host.h.audit.records().is_empty(),
            "{} saw a request",
            host.name
        );
    }
    // The same fingerprint under two names is the same peer.
    let fp = net.host("a").h.server_identity.fingerprint;
    net.pin("a2", Some(net.host("a").h.addr.to_string()), fp)
        .await;
    let err = exec(&net.via(&["a", "a2"]), "t", echo_argv("x"))
        .await
        .expect_err("one peer under two names");
    assert_eq!(err.code, ErrorCode::InvalidArgument, "{err:?}");
    net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hop_without_a_pin_or_an_address_is_host_not_found_naming_it() {
    let net = Net::start(&["a", "t"]).await;
    // No pin.
    let err = exec(&net.via(&["a", "nobody"]), "t", echo_argv("x"))
        .await
        .expect_err("no such pin");
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(
        err.details["jump"],
        json!({"hop": 2, "hops": 3, "name": "nobody", "stage": "address"})
    );
    assert!(
        err.message.starts_with("jump 2/3 (nobody): "),
        "{}",
        err.message
    );
    // A pin with no address.
    net.pin("quiet", None, make_identity().fingerprint).await;
    let err = exec(&net.via(&["quiet"]), "t", echo_argv("x"))
        .await
        .expect_err("no address");
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(
        err.details["jump"],
        json!({"hop": 1, "hops": 2, "name": "quiet", "stage": "address"})
    );
    assert_eq!(
        net.host("a")
            .h
            .server
            .jump_stats()
            .opened
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    net.shutdown().await;
}

// ----------------------------------------------------------------------
// pins
// ----------------------------------------------------------------------

fn nothing_ran_on(host: &Host) {
    let ran: Vec<_> = host
        .h
        .audit
        .records()
        .into_iter()
        .filter(|r| r.action.starts_with("exec") || r.action.starts_with("session"))
        .collect();
    assert!(ran.is_empty(), "{} ran something: {ran:?}", host.name);
    assert_eq!(
        host.h.broker.session_count(),
        0,
        "{} has a session",
        host.name
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_pin_mismatch_at_a_hop_and_at_the_end() {
    // The end: T's pin holds another fingerprint.
    let net = Net::start(&["j", "t"]).await;
    net.pin(
        "t-wrong",
        Some(net.host("t").h.addr.to_string()),
        make_identity().fingerprint,
    )
    .await;
    let err = exec(&net.via(&["j"]), "t-wrong", echo_argv("x"))
        .await
        .expect_err("the end presents another certificate");
    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert_eq!(
        err.details["jump"],
        json!({"hop": 2, "hops": 2, "name": "t-wrong", "stage": "auth"})
    );
    nothing_ran_on(net.host("t"));
    net.shutdown().await;

    // The second hop: b's pin holds another fingerprint.
    let net = Net::start(&["a", "b", "t"]).await;
    net.pin(
        "b-wrong",
        Some(net.host("b").h.addr.to_string()),
        make_identity().fingerprint,
    )
    .await;
    let err = exec(&net.via(&["a", "b-wrong"]), "t", echo_argv("x"))
        .await
        .expect_err("the second hop presents another certificate");
    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert_eq!(
        err.details["jump"],
        json!({"hop": 2, "hops": 3, "name": "b-wrong", "stage": "auth"})
    );
    assert!(
        err.message.starts_with("jump 2/3 (b-wrong): "),
        "{}",
        err.message
    );
    nothing_ran_on(net.host("t"));
    net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_pin_mismatch_at_the_first_hop() {
    // The first hop's certificate is not pinned under that name. Variant 1:
    // not pinned at all, so the ordinary check refuses it. Variant 2: pinned
    // under another name, which the ordinary check would accept, so the
    // chain's own exact check is what refuses it.
    let net = Net::start(&["j", "t"]).await;
    net.pin(
        "j-wrong",
        Some(net.host("j").h.addr.to_string()),
        make_identity().fingerprint,
    )
    .await;
    // `j-wrong` replaces nothing: `j` still pins J's real certificate, so
    // the ordinary check passes for J's address. The exact check is what
    // sees that the peer is not `j-wrong`.
    let err = exec(&net.via(&["j-wrong"]), "t", echo_argv("x"))
        .await
        .expect_err("the first hop is not the pin");
    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert_eq!(
        err.details["jump"],
        json!({"hop": 1, "hops": 2, "name": "j-wrong", "stage": "auth"})
    );
    nothing_ran_on(net.host("t"));
    net.shutdown().await;

    // Variant 1: a peer nobody pinned. The ordinary check refuses it.
    let net = Net::start(&["t"]).await;
    let stranger = start_hosts(&["j"], net.fp, |_| "*", loopback_options()).await;
    net.pin(
        "j",
        Some(stranger[0].h.addr.to_string()),
        make_identity().fingerprint,
    )
    .await;
    let err = exec(&net.via(&["j"]), "t", echo_argv("x"))
        .await
        .expect_err("the first hop is nobody's pin");
    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert_eq!(
        err.details["jump"],
        json!({"hop": 1, "hops": 2, "name": "j", "stage": "auth"})
    );
    nothing_ran_on(net.host("t"));
    shutdown(stranger).await;
    net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_jump_redirect_to_another_pinned_peer_fails_with_auth_failed() {
    // b's pin has b's fingerprint, but the address J2 resolves leads to
    // another pinned peer, t: what a middle peer that redirects looks like.
    let net = Net::start(&["a", "b", "t"]).await;
    net.pin(
        "b-redirected",
        Some(net.host("t").h.addr.to_string()),
        net.host("b").h.server_identity.fingerprint,
    )
    .await;
    let err = exec(&net.via(&["a", "b-redirected"]), "t", echo_argv("x"))
        .await
        .expect_err("the redirected hop presents t's certificate");
    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert_eq!(
        err.details["jump"],
        json!({"hop": 2, "hops": 3, "name": "b-redirected", "stage": "auth"})
    );
    nothing_ran_on(net.host("t"));
    net.shutdown().await;
}

// ----------------------------------------------------------------------
// rig 2: dial_chain by hand
// ----------------------------------------------------------------------

pub(super) struct Direct {
    client: TestIdentity,
    hosts: Vec<Host>,
}

impl Direct {
    pub(super) async fn start(names: &[&str]) -> Self {
        Self::start_with(names, |_| "*", loopback_options()).await
    }

    async fn start_with(
        names: &[&str],
        role_of: impl Fn(&str) -> &'static str,
        options: JumpOptions,
    ) -> Self {
        let client = make_identity();
        let hosts = start_hosts(names, client.fingerprint, role_of, options).await;
        Self { client, hosts }
    }

    pub(super) fn host(&self, name: &str) -> &Host {
        self.hosts.iter().find(|h| h.name == name).expect("a host")
    }

    pub(super) fn plan(&self, order: &[&str]) -> JumpPlan {
        let (end, hops) = order.split_last().expect("an end");
        JumpPlan::new(
            hops.iter().map(|n| self.host(n).pin()).collect(),
            self.host(end).pin(),
            None,
            "laptop".into(),
        )
        .expect("a valid plan")
    }

    /// Dials the plan: the first hop with the ordinary trust of every host,
    /// the rest with the chain's exact pins.
    pub(super) async fn dial(
        &self,
        plan: &JumpPlan,
        within: Duration,
    ) -> Result<ChainConn, OpError> {
        let mut trust = StaticTrust::empty();
        for host in &self.hosts {
            trust = trust.with_pin(
                host.h.server_identity.fingerprint,
                Principal::Device(host.name.clone()),
            );
        }
        let dialer = Dialer::new(self.client.local.clone(), Arc::new(trust)).with_timeout(within);
        let first = plan.step(0);
        let dialed = dialer
            .dial(first.address.parse().expect("an address"), "qsh")
            .await
            .expect("the first hop");
        dial_chain(
            plan,
            &dialer,
            (dialed.connection, dialed.endpoint),
            tokio::time::Instant::now() + within,
        )
        .await
    }

    pub(super) async fn shutdown(self) {
        shutdown(self.hosts).await;
    }
}

pub(super) async fn close(chain: ChainConn) {
    chain.connection.close(0, b"done");
    chain
        .endpoint
        .wait_idle_for(Duration::from_millis(500))
        .await;
}

fn failure_json(op: &OpError) -> serde_json::Value {
    op.details["jump"].clone()
}

// ----------------------------------------------------------------------
// carriers
// ----------------------------------------------------------------------

#[test]
fn jump_carrier_selection_table() {
    // The static rule (ADR-0056 decision 4): both sides advertise
    // `datagram.v1` and the room holds a minimum packet plus the 17-byte
    // header, 1217.
    let table = [
        (true, Some(1217), Carrier::Datagram),
        (true, Some(1216), Carrier::Stream),
        (true, Some(1414), Carrier::Datagram),
        // Right after a handshake the room is 1200 - 38.
        (true, Some(1162), Carrier::Stream),
        (false, Some(1414), Carrier::Stream),
        (true, None, Carrier::Stream),
        (false, None, Carrier::Stream),
    ];
    for (both, room, want) in table {
        assert_eq!(choose_carrier(both, room), want, "{both} {room:?}");
    }
}

#[test]
fn jump_mtu_budget_table() {
    // ADR-0057: 17 + 38 = 55 bytes a layer.
    assert_eq!(qsh_core::jump::chain::LAYER_COST, 55);
    assert_eq!(datagram_packet_limit(1414), 1397);
    // A 1500 link (outer UDP payload 1472, PLPMTUD stops at 1452): four
    // hops, all datagram.
    let rows = budget(1472, MAX_JUMP_HOPS);
    let limits: Vec<usize> = rows.iter().map(|(_, l)| *l).collect();
    assert_eq!(limits, vec![1397, 1342, 1287, 1232]);
    assert!(rows.iter().all(|(c, _)| *c == Carrier::Datagram));
    // The fifth layer would be 1232 - 55 = 1177, under the 1200 floor, and
    // its room (1194) is under the 1217 threshold: the chain stops at four
    // hops.
    assert_eq!(1232 - qsh_core::jump::chain::LAYER_COST, 1177);
    assert_eq!(budget(1472, 5)[4].0, Carrier::Stream);
    // 1280 links: the room is 1252 - 38 = 1214 (IPv4) and 1232 - 38 = 1194
    // (IPv6 minimum MTU), under 1217, so the first hop is the stream.
    assert_eq!(budget(1252, 1)[0].0, Carrier::Stream);
    assert_eq!(budget(1232, 1)[0].0, Carrier::Stream);
}

/// Drives light traffic on `session` until `done` or `within` passes.
async fn drive_until(
    session: &mut Session,
    within: Duration,
    mut done: impl FnMut() -> bool,
) -> bool {
    let end = Instant::now() + within;
    while Instant::now() < end {
        if done() {
            return true;
        }
        let _ = session.session_list().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    done()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_carrier_follows_the_outer_room_and_datagram_v1() {
    use std::sync::atomic::Ordering::Relaxed;
    // Both sides advertise datagram.v1: once the outer connection's room
    // grows past 1217 the channel moves to datagrams.
    let d = Direct::start(&["j", "t"]).await;
    let plan = d.plan(&["j", "t"]);
    let chain = d.dial(&plan, Duration::from_secs(10)).await.expect("chain");
    let mut session = Session::negotiate(chain.connection.clone(), "laptop")
        .await
        .expect("hello with the end");
    let info = Arc::clone(&chain.info.channels[0]);
    let moved = drive_until(&mut session, Duration::from_secs(15), || {
        info.datagrams_out.load(Relaxed) > 0 && info.carrier() == Carrier::Datagram
    })
    .await;
    assert!(moved, "never used a datagram: {info:?}");
    assert!(info.packet_limit() <= 1397 && info.packet_limit() >= 1200);
    drop(session);
    close(chain).await;
    d.shutdown().await;

    // J without datagram.v1: the stream carries everything and no datagram
    // is ever sent.
    let d = Direct::start(&["j", "t"]).await;
    d.host("j").h.server.hide_capabilities(&[CAP_DATAGRAM_V1]);
    let plan = d.plan(&["j", "t"]);
    let chain = d.dial(&plan, Duration::from_secs(10)).await.expect("chain");
    let mut session = Session::negotiate(chain.connection.clone(), "laptop")
        .await
        .expect("hello with the end");
    let info = Arc::clone(&chain.info.channels[0]);
    let used = drive_until(&mut session, Duration::from_secs(10), || {
        info.stream_out.load(Relaxed) > 5
    })
    .await;
    assert!(used, "nothing went out: {info:?}");
    assert_eq!(info.datagrams_out.load(Relaxed), 0);
    assert_eq!(info.carrier(), Carrier::Stream);
    drop(session);
    close(chain).await;
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_mtu_budget_on_a_four_hop_chain() {
    use std::sync::atomic::Ordering::Relaxed;
    // Loopback lets every outer connection discover 1452, so each layer
    // costs 55 more bytes than the one it rides on. Discovery stops within
    // a probe step (20 bytes) of the limit, so each layer may sit that much
    // under the table.
    let d = Direct::start(&["h1", "h2", "h3", "h4", "t"]).await;
    let plan = d.plan(&["h1", "h2", "h3", "h4", "t"]);
    let chain = d.dial(&plan, Duration::from_secs(20)).await.expect("chain");
    let mut session = Session::negotiate(chain.connection.clone(), "laptop")
        .await
        .expect("hello with the end");
    let table = [1397usize, 1342, 1287, 1232];
    let infos = chain.info.channels.clone();
    assert_eq!(infos.len(), 4);
    let settled = drive_until(&mut session, Duration::from_secs(40), || {
        infos
            .iter()
            .zip(table)
            .enumerate()
            .all(|(k, (info, want))| {
                let got = info.packet_limit();
                info.carrier() == Carrier::Datagram && got <= want && got + 20 * (k + 1) >= want
            })
    })
    .await;
    let seen: Vec<(usize, Carrier, u64)> = infos
        .iter()
        .map(|i| (i.packet_limit(), i.carrier(), i.datagrams_out.load(Relaxed)))
        .collect();
    assert!(settled, "the limits never reached the table: {seen:?}");
    drop(session);
    close(chain).await;
    d.shutdown().await;
}

// ----------------------------------------------------------------------
// the failure report
// ----------------------------------------------------------------------

fn expect_failure(
    err: &OpError,
    hop: usize,
    hops: usize,
    name: &str,
    stage: Stage,
    code: ErrorCode,
) {
    assert_eq!(err.code, code, "expected stage {}: {err:?}", stage.as_str());
    assert_eq!(
        failure_json(err),
        json!({"hop": hop, "hops": hops, "name": name, "stage": stage.as_str()}),
        "{err:?}"
    );
    let prefix = JumpFailure {
        hop,
        hops,
        name: name.into(),
        stage,
    }
    .prefix();
    assert!(err.message.starts_with(&prefix), "{}", err.message);
}

/// A UDP port nothing listens on.
fn closed_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket.local_addr().expect("addr").port()
}

fn pin_at(name: &str, port: u16, fingerprint: Fingerprint) -> HopPin {
    HopPin {
        name: name.into(),
        address: format!("127.0.0.1:{port}"),
        fingerprint,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_failure_stage_table() {
    // address: `a_hop_without_a_pin_or_an_address_is_host_not_found_naming_it`.
    // dial: `jump_failure_dial_stage_keeps_the_routes_code`.

    // unsupported: the previous hop does not advertise jump.v1; no JUMP
    // stream is opened.
    let unsupported_0 = async {
        let d = Direct::start(&["j", "t"]).await;
        d.host("j").h.server.hide_capabilities(&[CAP_JUMP_V1]);
        let err = d
            .dial(&d.plan(&["j", "t"]), Duration::from_secs(5))
            .await
            .expect_err("no jump.v1");
        expect_failure(&err, 2, 2, "t", Stage::Unsupported, ErrorCode::Unsupported);
        let stats = d.host("j").h.server.jump_stats();
        assert_eq!(stats.opened.load(std::sync::atomic::Ordering::Relaxed), 0);
        nothing_ran_on(d.host("t"));
        d.shutdown().await;
    };

    // denied: a role without forward.jump.
    let denied_1 = async {
        let d = Direct::start_with(
            &["j", "t"],
            |name| if name == "j" { "exec" } else { "*" },
            loopback_options(),
        )
        .await;
        let err = d
            .dial(&d.plan(&["j", "t"]), Duration::from_secs(5))
            .await
            .expect_err("denied");
        expect_failure(&err, 2, 2, "t", Stage::Denied, ErrorCode::PermissionDenied);
        d.shutdown().await;
    };

    // denied: a host-local target is refused whatever the role.
    let denied_2 = async {
        let d = Direct::start_with(&["j", "t"], |_| "*", JumpOptions::default()).await;
        let err = d
            .dial(&d.plan(&["j", "t"]), Duration::from_secs(5))
            .await
            .expect_err("host-local");
        expect_failure(&err, 2, 2, "t", Stage::Denied, ErrorCode::PermissionDenied);
        d.shutdown().await;
    };

    // limit: the previous hop is at its channel cap.
    let limit_3 = async {
        let d = Direct::start_with(
            &["j", "t"],
            |_| "*",
            JumpOptions {
                max_channels_per_conn: 0,
                ..loopback_options()
            },
        )
        .await;
        let err = d
            .dial(&d.plan(&["j", "t"]), Duration::from_secs(5))
            .await
            .expect_err("limit");
        expect_failure(&err, 2, 2, "t", Stage::Limit, ErrorCode::ResourceExhausted);
        d.shutdown().await;
    };

    // resolve: the previous hop cannot resolve the name.
    let resolve_4 = async {
        let d = Direct::start_with(
            &["j", "t"],
            |_| "*",
            JumpOptions {
                resolve_timeout: Duration::from_secs(3),
                ..loopback_options()
            },
        )
        .await;
        let mut plan = d.plan(&["j", "t"]);
        plan.end.address = "no-such-host.invalid:4433".into();
        let err = d
            .dial(&plan, Duration::from_secs(8))
            .await
            .expect_err("resolve");
        expect_failure(&err, 2, 2, "t", Stage::Resolve, ErrorCode::ConnectionFailed);
        d.shutdown().await;
    };

    // unreachable: the target's port refuses.
    let unreachable_5 = async {
        let d = Direct::start(&["j", "t"]).await;
        let mut plan = d.plan(&["j", "t"]);
        plan.end = pin_at(
            "t",
            closed_udp_port(),
            d.host("t").h.server_identity.fingerprint,
        );
        let err = d
            .dial(&plan, Duration::from_secs(8))
            .await
            .expect_err("unreachable");
        expect_failure(
            &err,
            2,
            2,
            "t",
            Stage::Unreachable,
            ErrorCode::ConnectionFailed,
        );
        d.shutdown().await;
    };

    // handshake: the packets pass but nobody answers in time.
    let handshake_6 = async {
        let d = Direct::start_with(
            &["j", "t"],
            |_| "*",
            JumpOptions {
                gate_timeout: Duration::from_secs(60),
                ..loopback_options()
            },
        )
        .await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let mut plan = d.plan(&["j", "t"]);
        plan.end = pin_at(
            "t",
            silent.local_addr().expect("addr").port(),
            d.host("t").h.server_identity.fingerprint,
        );
        let err = d
            .dial(&plan, Duration::from_millis(1500))
            .await
            .expect_err("handshake");
        expect_failure(&err, 2, 2, "t", Stage::Handshake, ErrorCode::Timeout);
        d.shutdown().await;
    };

    // auth: the second hop of three presents another certificate.
    let auth_7 = async {
        let d = Direct::start(&["a", "b", "t"]).await;
        let mut plan = d.plan(&["a", "b", "t"]);
        plan.hops[1].fingerprint = make_identity().fingerprint;
        let err = d
            .dial(&plan, Duration::from_secs(8))
            .await
            .expect_err("auth");
        expect_failure(&err, 2, 3, "b", Stage::Auth, ErrorCode::AuthFailed);
        nothing_ran_on(d.host("t"));
        d.shutdown().await;
    };

    // The cases share nothing; each pays the host's drain grace on its own
    // shutdown, so they run side by side.
    tokio::join!(
        unsupported_0,
        denied_1,
        denied_2,
        limit_3,
        resolve_4,
        unreachable_5,
        handshake_6,
        auth_7
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_failure_dial_stage_keeps_the_routes_code() {
    let net = Net::start(&["t"]).await;
    net.pin(
        "ghost",
        Some(format!("127.0.0.1:{}", closed_udp_port())),
        make_identity().fingerprint,
    )
    .await;
    qsh_transport::set_default_dial_timeout(Duration::from_millis(1500));
    let err = exec(&net.via(&["ghost"]), "t", echo_argv("x"))
        .await
        .expect_err("nobody answers");
    assert_eq!(failure_json(&err)["stage"], "dial", "{err:?}");
    assert_eq!(failure_json(&err)["hop"], 1);
    assert_eq!(failure_json(&err)["hops"], 2);
    assert_eq!(failure_json(&err)["name"], "ghost");
    assert!(
        matches!(err.code, ErrorCode::ConnectionFailed | ErrorCode::Timeout),
        "{err:?}"
    );
    assert!(
        err.message.starts_with("jump 1/2 (ghost): "),
        "{}",
        err.message
    );
    net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_target_refusal_is_reported_fast() {
    let d = Direct::start(&["j", "t"]).await;
    let mut plan = d.plan(&["j", "t"]);
    plan.end = pin_at(
        "t",
        closed_udp_port(),
        d.host("t").h.server_identity.fingerprint,
    );
    // The handshake time is long: the report must not wait for it.
    let started = Instant::now();
    let err = d
        .dial(&plan, Duration::from_secs(20))
        .await
        .expect_err("the target refuses");
    let took = started.elapsed();
    expect_failure(
        &err,
        2,
        2,
        "t",
        Stage::Unreachable,
        ErrorCode::ConnectionFailed,
    );
    assert!(took < Duration::from_secs(1), "took {took:?}");
    d.shutdown().await;
}

// ----------------------------------------------------------------------
// J sees no plaintext
// ----------------------------------------------------------------------

/// A UDP relay standing where the target is: it forwards between J and the
/// real target and keeps every byte it carries, in both directions. That is
/// everything J's socket sends and receives.
struct Tap {
    port: u16,
    seen: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Tap {
    async fn start(target: SocketAddr) -> Self {
        let near = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let far = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        far.connect(target).await.expect("connect");
        let port = near.local_addr().expect("addr").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let task = {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut j: Option<SocketAddr> = None;
                let mut a = vec![0u8; 4096];
                let mut b = vec![0u8; 4096];
                loop {
                    tokio::select! {
                        got = near.recv_from(&mut a) => {
                            let Ok((n, from)) = got else { return };
                            j = Some(from);
                            seen.lock().unwrap().extend_from_slice(&a[..n]);
                            let _ = far.send(&a[..n]).await;
                        }
                        got = far.recv(&mut b) => {
                            let Ok(n) = got else { continue };
                            seen.lock().unwrap().extend_from_slice(&b[..n]);
                            if let Some(j) = j {
                                let _ = near.send_to(&b[..n], j).await;
                            }
                        }
                    }
                }
            })
        };
        Self { port, seen, task }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_jump_never_sees_inner_plaintext() {
    let net = Net::start(&["j", "t"]).await;
    let t = net.host("t");
    let tap = Tap::start(t.h.host_addr).await;
    // The client reaches T through J at the tap's address.
    net.pin(
        "t-tapped",
        Some(format!("127.0.0.1:{}", tap.port)),
        t.h.server_identity.fingerprint,
    )
    .await;
    let ops = net.via(&["j"]);

    const ARGV: &str = "ARGV-5c0ffee1a2b3c4d5e6f7";
    const OUT: &str = "SESSION-OUT-9a8b7c6d5e4f3a2b";
    const IN: &str = "SESSION-IN-0f1e2d3c4b5a6978";
    const FILE: &str = "FILE-BODY-1122334455667788";
    const TUNNEL: &str = "TUNNEL-BODY-99aabbccddeeff00";

    let out = exec(&ops, "t-tapped", echo_argv(ARGV)).await.expect("exec");
    assert!(stdout_of(&out).contains(ARGV));

    let opened = {
        let ops = ops.clone();
        blocking(move || {
            ops.session_open(SessionOpenReq {
                host: "t-tapped".into(),
                argv: vec!["sh".into()],
                env: vec![],
                term: None,
                cols: Some(80),
                rows: Some(24),
                user: None,
                shell_command: None,
            })
        })
        .await
        .expect("session.open")
    };
    let mut pipe = t.h.pipes.take().expect("pipe");
    pipe.write_output(OUT.as_bytes()).await.expect("output");
    let read = {
        let ops = ops.clone();
        let session_ref = opened.session_ref.clone();
        blocking(move || {
            ops.session_read(SessionReadReq {
                session_ref,
                after_sequence: 0,
                wait_ms: Some(10_000),
                limit_bytes: None,
                ctl_after: None,
            })
        })
        .await
        .expect("session.read")
    };
    assert_eq!(String::from_utf8_lossy(&read.output), OUT);
    {
        use base64::Engine as _;
        let ops = ops.clone();
        let session_ref = opened.session_ref.clone();
        let b64 = base64::engine::general_purpose::STANDARD.encode(IN.as_bytes());
        blocking(move || {
            ops.session_write(SessionWriteReq {
                session_ref,
                data_b64: b64,
            })
        })
        .await
        .expect("session.write");
        assert_eq!(pipe.read_input(64).await.expect("input"), IN.as_bytes());
    }

    let echo = EchoServer::start().await.expect("echo");
    let echo_port = echo.port();
    let listen_port = free_port();
    let body = TUNNEL.repeat(2000).into_bytes();
    let expected = body.clone();
    let got = {
        let ops = ops.clone();
        blocking(move || {
            let hold = ops
                .tunnel_open(TunnelOpenReq {
                    host: "t-tapped".into(),
                    mode: "local".into(),
                    bind: None,
                    listen_port: u32::from(listen_port),
                    forward_host: "127.0.0.1".into(),
                    forward_port: u32::from(echo_port),
                    wait_ms: None,
                    supervise_ms: None,
                    accept_hold_ms: None,
                })
                .expect("-L");
            let got = echo_through(listen_port, &body).expect("round trip");
            hold.close();
            got
        })
        .await
    };
    assert!(got == expected);

    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("s.bin");
    let dest = dir.path().join("d.bin");
    std::fs::write(&source, FILE.repeat(4000)).expect("source");
    let req = FileCopyReq {
        sources: vec![source.to_string_lossy().into_owned()],
        destination: format!("[t-tapped]:{}", dest.display()),
        recursive: false,
        preserve: false,
        no_clobber: false,
    };
    {
        let ops = ops.clone();
        blocking(move || ops.file_copy(req, Arc::new(SilentObserver), &CancelToken::new())).await
    }
    .expect("cp");
    assert_eq!(std::fs::read(&dest).expect("copy").len(), FILE.len() * 4000);

    // Everything J's socket carried.
    let seen = tap.seen.lock().unwrap().clone();
    assert!(
        seen.len() > 200_000,
        "the tap saw only {} bytes",
        seen.len()
    );
    let has = |needle: &[u8]| seen.windows(needle.len()).any(|w| w == needle);
    for marker in [ARGV, OUT, IN, FILE, TUNNEL] {
        assert!(!has(marker.as_bytes()), "{marker} crossed J in the clear");
    }
    assert!(
        !has(&t.h.server_identity.cert_der),
        "the target's certificate crossed J in the clear"
    );
    tap.task.abort();
    net.shutdown().await;
}

// ----------------------------------------------------------------------
// a plan checked by itself
// ----------------------------------------------------------------------

#[test]
fn a_plan_refuses_the_shapes_decision_11_names() {
    let pin = |name: &str| HopPin {
        name: name.into(),
        address: "127.0.0.1:1".into(),
        fingerprint: make_identity().fingerprint,
    };
    let plan = |hops: Vec<HopPin>, end: HopPin| JumpPlan::new(hops, end, None, "d".into());
    assert!(plan(vec![pin("a")], pin("t")).is_ok());
    let four: Vec<HopPin> = ["a", "b", "c", "d"].map(pin).into();
    assert!(plan(four.clone(), pin("t")).is_ok());
    let mut five = four.clone();
    five.push(pin("e"));
    assert_eq!(
        plan(five, pin("t")).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        plan(vec![], pin("t")).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        plan(vec![pin("a"), pin("a")], pin("t")).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        plan(vec![pin("a"), pin("t")], pin("t")).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    // The same fingerprint under another name is the same peer.
    let a = pin("a");
    let mut a2 = a.clone();
    a2.name = "a2".into();
    assert_eq!(
        plan(vec![a, a2], pin("t")).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}
