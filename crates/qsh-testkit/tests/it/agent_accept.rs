//! M25 acceptance on every OS (ADR-0055 DoD 23.2, 23.8 and 23.9): real
//! OpenSSH tools in front of a real client `Ops` and a real host on loopback.
//!
//! - `ssh_add_and_ssh_keygen_sign_through_a_forwarded_real_agent`: a `-A`
//!   exec whose program is the system `ssh-add` or `ssh-keygen` lists and
//!   signs through the host's agent socket (unix) or pipe (Windows), while
//!   every state-changing request stops at the client.
//! - `windows_host_pipe_serves_win32_openssh_ssh_add`: Win32-OpenSSH's own
//!   `ssh-add -l` reads the host pipe.
//! - `a_host_without_agent_v1_gets_no_agent_field`: an old host gets no
//!   `agent_channel` and the result says `"unsupported"`.
//!
//! The real-agent tests never touch the process `SSH_AUTH_SOCK`. On unix they
//! start a private `ssh-agent -a <tmp>`. On Windows `ssh-agent.exe` ignores
//! `-a` and serves only `\\.\pipe\openssh-ssh-agent`, so they use the
//! `ssh-agent` service the CI runner starts; a developer machine where the
//! service is off skips. A missing tool skips with a message unless
//! `QSH_REQUIRE_SSH_AGENT=1`, which CI sets and which turns a skip into a
//! failure. Nothing here prints a key, a signature or an agent message.
//!
//! The two Windows-service tests share one agent per machine, so nextest runs
//! them one at a time (`shared-ssh-agent` in `.config/nextest.toml`): the
//! service has no per-test isolation, and a key another test adds mid-run
//! would show up in this file's before/after list comparison.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_core::acl::{Authorizer, Role, load_or_deny};
use qsh_core::agent::{AgentEndpoint, ClientAgent};
use qsh_core::config::Paths;
use qsh_core::trust::SharedTrustStore;
use qsh_core::{ExecRunOutput, ExecStdin, Fingerprint, Ops};
use qsh_proto::wire;
use qsh_proto::{ExecRunReq, IdentityInitReq, KeyStoreMode, SessionOpenReq, TrustAddReq};
use qsh_testkit::fake_agent::{FakeAgent, FakeIdentity};
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_transport::{Principal, StaticTrust};

fn required() -> bool {
    std::env::var("QSH_REQUIRE_SSH_AGENT").is_ok_and(|v| v == "1")
}

/// Report that a test cannot run here. Skips (returns `None` to the caller)
/// unless CI demanded the real agent, in which case it fails.
fn cannot_run(reason: &str) {
    assert!(
        !required(),
        "QSH_REQUIRE_SSH_AGENT=1 but the real-agent test cannot run: {reason}"
    );
    eprintln!("skipping: {reason}");
}

fn have_tool(tool: &str) -> bool {
    Command::new(tool)
        .arg("-?")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("blocking task")
}

// ---- a real client Ops and a real host ------------------------------------

struct Rig {
    _dir: tempfile::TempDir,
    ops: Ops,
    h: LoopbackHarness,
    runtime: PathBuf,
}

impl Rig {
    /// A client whose identity the host pins with role `full`, and a host
    /// whose agent runtime directory is private to the test.
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(
            dir.path().join("client/config"),
            dir.path().join("client/state"),
        )
        .with_runtime_dir(dir.path().join("client/run"));
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

        let host_paths = Paths::new(
            dir.path().join("host/config"),
            dir.path().join("host/state"),
        );
        std::fs::create_dir_all(&host_paths.config_dir).expect("host config dir");
        std::fs::write(
            host_paths.trust_file(),
            format!(
                "[[peer]]\nname = \"laptop\"\nfingerprint = \"{fp}\"\naddress = \"\"\n\
                 added_at = \"2026-11-09T00:00:00Z\"\nrole = \"full\"\n"
            ),
        )
        .expect("write trust.toml");
        let trust = SharedTrustStore::open(host_paths.trust_file()).expect("open trust.toml");
        let (authorizer, _diag): (Arc<dyn Authorizer>, _) =
            load_or_deny(&host_paths, Role::Serve, trust);
        let host_trust = StaticTrust::empty().with_pin(fp, Principal::Device("laptop".into()));
        let h = LoopbackHarness::start_custom(authorizer, make_identity(), host_trust).await;
        let runtime = dir.path().join("host/run");
        h.server.set_agent_runtime_dir(runtime.clone());

        let address = h.addr.to_string();
        let host_fp = h.server_identity.fingerprint.to_string();
        blocking({
            let ops = ops.clone();
            move || {
                ops.trust_add(TrustAddReq {
                    name: "box".into(),
                    address: Some(address),
                    fingerprint: Some(host_fp),
                    cert_pem: None,
                    role: None,
                })
            }
        })
        .await
        .expect("trust.add");
        Self {
            _dir: dir,
            ops,
            h,
            runtime,
        }
    }

    /// The client with forwarding on, pointed at `agent`.
    fn with_agent(&self, agent: Arc<ClientAgent>) -> Ops {
        self.ops.clone().with_client_agent(agent)
    }
}

/// Run `argv` on the host as an exec of `ops`.
async fn remote(ops: &Ops, argv: &[&str]) -> ExecRunOutput {
    let ops = ops.clone();
    let req = ExecRunReq {
        host: "box".into(),
        argv: argv.iter().map(|a| (*a).to_string()).collect(),
        env: vec![],
        timeout_ms: Some(60_000),
    };
    blocking(move || ops.exec_run(req, ExecStdin::Closed))
        .await
        .expect("exec.run")
}

fn exit_code(out: &ExecRunOutput) -> i32 {
    out.data.remote_exit_code
}

// ---- the real agent -----------------------------------------------------------

/// A local ssh-agent holding one throwaway Ed25519 key. On unix it is a
/// private process on a socket in a temp directory; on Windows it is the
/// runner's `ssh-agent` service.
struct RealAgent {
    dir: tempfile::TempDir,
    #[cfg(unix)]
    sock: PathBuf,
    #[cfg(unix)]
    child: std::process::Child,
}

impl RealAgent {
    fn key(&self) -> PathBuf {
        self.dir.path().join("id")
    }

    fn pubkey(&self) -> PathBuf {
        self.dir.path().join("id.pub")
    }

    /// A tool run against this agent, never the caller's.
    fn local(&self, tool: &str, args: &[&str]) -> Output {
        let mut cmd = Command::new(tool);
        cmd.args(args)
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null());
        #[cfg(unix)]
        cmd.env("SSH_AUTH_SOCK", &self.sock);
        cmd.output().unwrap_or_else(|e| panic!("run {tool}: {e}"))
    }

    /// The client side of forwarding, aimed at this agent and nothing else.
    fn client_agent(&self) -> Arc<ClientAgent> {
        #[cfg(unix)]
        let endpoint = AgentEndpoint::resolve(self.sock.to_str(), &|_| None);
        // Windows: no value means Win32-OpenSSH's default pipe.
        #[cfg(windows)]
        let endpoint = AgentEndpoint::resolve(None, &|_| None);
        ClientAgent::new(endpoint)
    }

    /// The `SHA256:...` fingerprint of the key.
    fn fingerprint(&self) -> String {
        let pubkey = self.pubkey();
        let out = self.local("ssh-keygen", &["-l", "-f", &pubkey.to_string_lossy()]);
        assert!(out.status.success(), "ssh-keygen -l failed");
        let text = String::from_utf8_lossy(&out.stdout);
        text.split_whitespace()
            .find(|w| w.starts_with("SHA256:"))
            .expect("a SHA256 fingerprint")
            .to_string()
    }

    /// `ssh-add -L` of the local agent, for before/after comparison.
    fn listing(&self) -> String {
        let out = self.local("ssh-add", &["-L"]);
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Bring the agent up with a fresh key, or report why not (and skip, or
    /// fail under `QSH_REQUIRE_SSH_AGENT=1`).
    async fn start() -> Option<Self> {
        for tool in ["ssh-add", "ssh-keygen"] {
            if !have_tool(tool) {
                cannot_run(&format!("`{tool}` is not installed"));
                return None;
            }
        }
        #[cfg(unix)]
        if !have_tool("ssh-agent") {
            cannot_run("`ssh-agent` is not installed");
            return None;
        }
        let dir = tempfile::Builder::new()
            .prefix("qsh-ra")
            .tempdir()
            .expect("tempdir");

        #[cfg(unix)]
        let (sock, child) = {
            let sock = dir.path().join("a");
            let child = Command::new("ssh-agent")
                .args(["-D", "-a"])
                .arg(&sock)
                .env_remove("SSH_AUTH_SOCK")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("start a private ssh-agent");
            (sock, child)
        };
        let agent = Self {
            dir,
            #[cfg(unix)]
            sock,
            #[cfg(unix)]
            child,
        };

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // `ssh-add -l` exits 1 for an empty agent and 2 when it cannot
            // reach one.
            let code = agent.local("ssh-add", &["-l"]).status.code();
            if matches!(code, Some(0 | 1)) {
                break;
            }
            if Instant::now() >= deadline {
                cannot_run("no ssh-agent answers (on Windows: start the `ssh-agent` service)");
                return None;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let key = agent.key();
        let made = agent.local(
            "ssh-keygen",
            &[
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "qsh-test-key",
                "-f",
                &key.to_string_lossy(),
            ],
        );
        assert!(made.status.success(), "ssh-keygen could not make a key");
        let added = agent.local("ssh-add", &[&key.to_string_lossy()]);
        assert!(added.status.success(), "ssh-add could not add the key");
        Some(agent)
    }
}

impl Drop for RealAgent {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        // The Windows service outlives the test; take the throwaway key out.
        #[cfg(windows)]
        {
            let _ = self.local("ssh-add", &["-d", &self.key().to_string_lossy()]);
        }
    }
}

// ---- DoD 23.2 ----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn ssh_add_and_ssh_keygen_sign_through_a_forwarded_real_agent() {
    let Some(agent) = RealAgent::start().await else {
        return;
    };
    let rig = Rig::start().await;
    let ops = rig.with_agent(agent.client_agent());
    let fingerprint = agent.fingerprint();
    let before = agent.listing();
    assert!(!before.is_empty(), "the local agent holds the key");

    // Listing works and shows the key.
    let listed = remote(&ops, &["ssh-add", "-l"]).await;
    assert_eq!(exit_code(&listed), 0, "remote ssh-add -l");
    assert_eq!(listed.data.agent.as_deref(), Some("forwarded"));
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains(&fingerprint),
        "remote ssh-add -l lists the key"
    );

    // Signing works: the key file named is the public half, so the private
    // half is reachable only through the agent. The signature then verifies.
    let data = agent.dir.path().join("data.txt");
    std::fs::write(&data, b"qsh agent acceptance").expect("write data");
    let pubkey = agent.pubkey();
    let signed = remote(
        &ops,
        &[
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            &pubkey.to_string_lossy(),
            "-n",
            "file",
            &data.to_string_lossy(),
        ],
    )
    .await;
    assert_eq!(exit_code(&signed), 0, "remote ssh-keygen -Y sign");
    let sig = agent.dir.path().join("data.txt.sig");
    let verified = Command::new("ssh-keygen")
        .args(["-Y", "check-novalidate", "-n", "file", "-s"])
        .arg(&sig)
        .stdin(std::fs::File::open(&data).expect("open data"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run ssh-keygen");
    assert!(verified.success(), "the signature verifies");

    // Every state-changing request stops at the client.
    let other = agent.dir.path().join("other");
    let made = agent.local(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            &other.to_string_lossy(),
        ],
    );
    assert!(made.status.success(), "second key");
    let remove_all = remote(&ops, &["ssh-add", "-D"]).await;
    assert_ne!(exit_code(&remove_all), 0, "remote ssh-add -D must fail");
    let add = remote(&ops, &["ssh-add", &other.to_string_lossy()]).await;
    assert_ne!(exit_code(&add), 0, "remote ssh-add <key> must fail");
    let remove_one = remote(&ops, &["ssh-add", "-d", &pubkey.to_string_lossy()]).await;
    assert_ne!(exit_code(&remove_one), 0, "remote ssh-add -d must fail");

    assert_eq!(agent.listing(), before, "the local key list is unchanged");
    // And the key still signs from the local side.
    assert!(
        agent.local("ssh-add", &["-l"]).status.success(),
        "the local agent still lists its key"
    );
    rig.h.shutdown().await;
}

// ---- DoD 23.9 ----------------------------------------------------------------

/// Win32-OpenSSH's `ssh-add -l`, run on the host side of a `-A` exec, reads
/// the key through the host's own named pipe. Runs only where the
/// `ssh-agent` service is on (the CI runner); elsewhere it skips, and
/// `QSH_REQUIRE_SSH_AGENT=1` turns the skip into a failure.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_pipe_serves_win32_openssh_ssh_add() {
    let Some(agent) = RealAgent::start().await else {
        return;
    };
    let rig = Rig::start().await;
    let ops = rig.with_agent(agent.client_agent());
    let listed = remote(&ops, &["ssh-add", "-l"]).await;
    assert_eq!(exit_code(&listed), 0, "ssh-add -l through the host pipe");
    assert_eq!(listed.data.agent.as_deref(), Some("forwarded"));
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains(&agent.fingerprint()),
        "ssh-add -l through the host pipe lists the key"
    );
    rig.h.shutdown().await;
}

// ---- DoD 23.8 ----------------------------------------------------------------

/// A host that did not advertise `agent.v1` is never sent `agent_channel`:
/// it creates no socket and writes no `forward.agent` record, the session and
/// the exec still open, and both results say `"unsupported"`.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_without_agent_v1_gets_no_agent_field() {
    let rig = Rig::start().await;
    rig.h.server.hide_capabilities(&[wire::CAP_AGENT_V1]);
    let fake = FakeAgent::start(vec![FakeIdentity::new(b"old-host-key".to_vec(), "k")])
        .await
        .expect("fake agent");
    let agent = ClientAgent::new(AgentEndpoint::resolve(Some(fake.endpoint()), &|_| None));
    let ops = rig.with_agent(agent);

    let opened = blocking({
        let ops = ops.clone();
        move || {
            ops.session_open(SessionOpenReq {
                host: "box".into(),
                argv: vec![],
                env: vec![],
                term: Some("xterm-256color".into()),
                cols: Some(80),
                rows: Some(24),
                user: None,
                shell_command: None,
            })
        }
    })
    .await
    .expect("session.open still opens");
    assert_eq!(opened.agent.as_deref(), Some("unsupported"));

    let argv: &[&str] = if cfg!(windows) {
        &["cmd", "/c", "exit", "0"]
    } else {
        &["true"]
    };
    let ran = remote(&ops, argv).await;
    assert_eq!(exit_code(&ran), 0);
    assert_eq!(ran.data.agent.as_deref(), Some("unsupported"));

    assert!(
        rig.h
            .audit
            .records()
            .iter()
            .all(|r| r.action != "forward.agent"),
        "the host never saw an agent request"
    );
    assert!(
        !agent_dir_has_entries(&rig.runtime),
        "no socket was created on the old host"
    );
    assert_eq!(fake.connections(), 0, "the local agent was never dialed");
    rig.h.shutdown().await;
}

fn agent_dir_has_entries(runtime: &Path) -> bool {
    std::fs::read_dir(runtime.join("agent"))
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}
