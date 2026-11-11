//! **L5 real-process** acceptance of the combined endpoint's two roles at
//! once (ADR-0059 DoD 27.3): the shipped `qsh` binary, a loopback UDP port,
//! temp configs, no allow-all `acl.toml` (the policy is the pins' roles).
//!
//! One `qsh listen --serve` (the "hub") has a `qsh serve --to` target
//! registered. While it does, a second machine, on the hub's one port, runs
//! exec, a `-t` command, an interactive PTY session, `-L`, `-R`, `-D`,
//! `qsh cp` both ways (bytes compared) and `-A`; at the same time the hub's
//! own account reaches the target over the reverse route through its local
//! control daemon (exec, an interactive session, `qsh cp` both ways).
//!
//! **`-J` is not here.** A jump hop refuses a host-local destination (ADR-0056
//! decision 8), and every second `qsh serve` a single-machine test can start
//! is host-local to the hub, so the hop can only be exercised with the
//! in-process hook that lets it dial a loopback target
//! (`Server::set_jump_options`). It stays in
//! `qsh-testkit`'s `combined_endpoint_serves_registration_and_forward_at_once`.
//!
//! On Windows the same test name runs a reduced list: the hub hosts a ConPTY
//! session and serves its named-pipe local control daemon in the one process
//! (DoD 27.13). The unix list needs `sh`, a unix socket agent and the pty
//! helper, none of which the Windows rig has.

use crate::common;

use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use common::{HOST_ALIAS, ListenGuard, ReverseGuard, Sandbox, hosts_array, poll_until};
use serde_json::Value;

/// The key that turns a listen into the combined endpoint.
const COMBINED: &str = "[listen]\nserve = true\n";

/// A repeatable, non-periodic body for the copies.
fn file_body(seed: u8) -> Vec<u8> {
    (0..512 * 1024u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8 ^ seed)
        .collect()
}

fn same_bytes(a: &Path, b: &Path) -> bool {
    blake3::hash(&std::fs::read(a).expect("read a"))
        == blake3::hash(&std::fs::read(b).expect("read b"))
}

struct Rig {
    /// The hub: `qsh listen --serve`.
    hub: Sandbox,
    /// The reverse target.
    target: Sandbox,
    /// The second machine, a plain forward client.
    client: Sandbox,
    listen: ListenGuard,
    reverse: ReverseGuard,
    work: tempfile::TempDir,
}

impl Rig {
    fn start() -> Self {
        let hub = Sandbox::initialized();
        std::fs::write(hub.config_dir().join("config.toml"), COMBINED).unwrap();
        let target = Sandbox::initialized();
        let client = Sandbox::initialized();
        let (hub_fp, target_fp, client_fp) = (
            hub.fingerprint(),
            target.fingerprint(),
            client.fingerprint(),
        );
        // The roles are the whole policy: the target may register and nothing
        // else on the hub; the client has the full forward role.
        hub.trust_add_with_role("widget", None, &target_fp, "reverse");
        hub.trust_add_with_role("laptop", None, &client_fp, "full");
        let listen = ListenGuard::start_without_policy(&hub, "127.0.0.1:0");
        let addr = listen.addr().to_string();
        client.trust_add(HOST_ALIAS, Some(&addr), &hub_fp);
        // The hub is the target's controller and the client of its reverse
        // route, so the target pins it with the role that runs commands.
        target.trust_add_with_role("ctl", Some(&addr), &hub_fp, "full");
        let reverse = ReverseGuard::start_without_policy(&target, &["serve", "--to", "ctl"]);
        poll_until(
            "the target's registration on the combined hub",
            Duration::from_secs(20),
            || {
                hosts_array(&hub)
                    .iter()
                    .any(|h| {
                        h["name"] == "widget"
                            && h["connection_mode"] == "reverse"
                            && h["state"] == "reachable"
                    })
                    .then_some(())
            },
        );
        Self {
            hub,
            target,
            client,
            listen,
            reverse,
            work: tempfile::tempdir().expect("work dir"),
        }
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.work.path().join(name)
    }
}

fn stdout_of(value: &Value) -> String {
    let b64 = value["data"]["stdout_b64"].as_str().expect("stdout_b64");
    String::from_utf8_lossy(
        &base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("base64"),
    )
    .into_owned()
}

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::tunnel_e2e::{
        PtyClient, TunnelGuard, forward_audit, payload, round_trip, start_echo,
    };

    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;

    use common::{DynamicTunnelGuard, exit_code};
    use qsh_testkit::fake_agent::{FakeAgent, FakeIdentity};
    use qsh_testkit::net_probe::{Gap, LanEcho, free_port, require_non_loopback_v4_route};

    /// The marker the reverse side's exec prints; it must reach no audit record.
    const REVERSE_MARKER: &str = "reverse-exec-marker-7c1e";
    const FORWARD_MARKER: &str = "forward-exec-marker-4b9d";

    /// The fields an audit record may carry (`docs/design/architecture.md` §6):
    /// structure only, no payload field.
    const RECORD_KEYS: &[&str] = &[
        "ts",
        "request_id",
        "principal",
        "auth_path",
        "action",
        "resource",
        "decision",
        "rule",
        "peer_addr",
        "count",
        "role",
        "grant",
    ];

    /// Everything the second machine does against the hub's forward side.
    fn forward_battery(rig: &Rig) {
        let client = &rig.client;

        // exec
        let (code, out) = client.json(&[
            "exec",
            HOST_ALIAS,
            "--json",
            "--",
            "sh",
            "-c",
            &format!("echo {FORWARD_MARKER}; exit 3"),
        ]);
        assert_eq!(code, 3, "{out}");
        assert!(stdout_of(&out).contains(FORWARD_MARKER), "{out}");

        // `-t` with a command
        let mut t = PtyClient::spawn(client, &["-t", HOST_ALIAS, "echo", "tcmd-ran-ok"]);
        t.expect("tcmd-ran-ok");
        t.wait_end();

        // an interactive PTY session
        let mut shell = PtyClient::spawn(client, &[HOST_ALIAS]);
        shell.shell_round_trip("hub-pty");
        shell.type_("exit\r");
        shell.wait_end();

        // -L
        let echo = start_echo();
        let lport = free_port();
        let spec = format!("{lport}:127.0.0.1:{}", echo.port());
        let (mut local, envelope) = TunnelGuard::start(client, &spec);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let sent = payload();
        assert!(round_trip(lport, sent.clone()).expect("-L round trip") == sent);
        assert!(local.is_running());
        assert!(local.finish().is_empty());

        // -R
        let rport = free_port();
        let spec = format!("{rport}:127.0.0.1:{}", echo.port());
        let (mut remote, envelope) = TunnelGuard::start_mode(client, "--remote", &spec);
        assert_eq!(envelope["ok"], true, "{envelope}");
        assert!(round_trip(rport, sent.clone()).expect("-R round trip") == sent);
        assert!(remote.is_running());
        assert!(remote.finish().is_empty());

        // cp, both ways, bytes compared
        let up_src = rig.path("up-src");
        let up_dst = rig.path("up-dst");
        let down_dst = rig.path("down-dst");
        std::fs::write(&up_src, file_body(1)).unwrap();
        let out = client.qsh(&[
            "cp",
            &up_src.display().to_string(),
            &format!("{HOST_ALIAS}:{}", up_dst.display()),
        ]);
        assert_eq!(
            exit_code(&out),
            0,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(same_bytes(&up_src, &up_dst), "upload changed the bytes");
        let out = client.qsh(&[
            "cp",
            &format!("{HOST_ALIAS}:{}", up_dst.display()),
            &down_dst.display().to_string(),
        ]);
        assert_eq!(
            exit_code(&out),
            0,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(same_bytes(&up_src, &down_dst), "download changed the bytes");

        // -A: a command on the hub talks to the forwarded agent, which is the
        // fake agent on this side.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let agent = runtime
            .block_on(FakeAgent::start(vec![FakeIdentity::new(
                b"combined-key".to_vec(),
                "k",
            )]))
            .unwrap();
        let probe = qsh_testkit::agent_probe::bin();
        // 11 is SSH2_AGENTC_REQUEST_IDENTITIES.
        let out = client
            .command(&["-A", HOST_ALIAS, &probe.display().to_string(), "call", "11"])
            .env("SSH_AUTH_SOCK", agent.endpoint())
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run qsh -A");
        assert_eq!(
            exit_code(&out),
            0,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(agent.connections() >= 1, "the forwarded agent was reached");
        assert!(
            agent.received_kinds().contains(&11),
            "{:?}",
            agent.received_kinds()
        );
        drop(runtime);

        // -D: a SOCKS5 CONNECT to an off-loopback echo (the host-local filter
        // refuses loopback), when this machine has such an address.
        let dport = free_port();
        let (mut dynamic, envelope) = DynamicTunnelGuard::start(client, &dport.to_string());
        let bind = envelope["data"]["bind"].as_str().expect("bind").to_string();
        let mut socket = TcpStream::connect(&bind).expect("connect to the -D listener");
        socket
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        socket.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut greeting = [0u8; 2];
        socket.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x00]);
        match require_non_loopback_v4_route("no non-loopback IPv4 route on this host") {
            Gap::Ready(ip) => {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                let lan = runtime.block_on(LanEcho::start(ip)).expect("LAN echo");
                let std::net::SocketAddr::V4(lan_addr) = lan.addr() else {
                    panic!("an IPv4 echo")
                };
                let mut request = vec![0x05, 0x01, 0x00, 0x01];
                request.extend_from_slice(&lan_addr.ip().octets());
                request.extend_from_slice(&lan_addr.port().to_be_bytes());
                socket.write_all(&request).unwrap();
                let mut rep = [0u8; 10];
                socket.read_exact(&mut rep).unwrap();
                assert_eq!(
                    rep[1], 0x00,
                    "CONNECT through -D on the combined hub: {rep:?}"
                );
                socket.write_all(b"dynamic-through-hub").unwrap();
                let mut back = [0u8; 19];
                socket.read_exact(&mut back).unwrap();
                assert_eq!(&back, b"dynamic-through-hub");
                drop(socket);
                // The decision is on the hub's one audit file, with the
                // destination as the resource.
                let resource = format!("{}:{}", lan_addr.ip(), lan_addr.port());
                let records = forward_audit(&rig.hub, "forward.local", &resource, 1);
                assert_eq!(records[0]["decision"], "allow");
                assert_eq!(records[0]["principal"], "device:laptop");
            }
            Gap::Skip(reason) => {
                eprintln!("-D CONNECT leg skipped: {reason}");
                drop(socket);
            }
            Gap::Fail(reason) => panic!("-D CONNECT leg: {reason}"),
        }
        assert!(dynamic.is_running());
        assert!(dynamic.finish().is_empty());

        // The -L and -R decisions, one each.
        forward_audit(
            &rig.hub,
            "forward.local",
            &format!("127.0.0.1:{}", echo.port()),
            1,
        );
        forward_audit(&rig.hub, "forward.remote", &format!("127.0.0.1:{rport}"), 1);
    }

    /// What the hub's own account does over the reverse route (its localctl
    /// daemon), at the same time.
    fn reverse_battery(rig: &Rig) {
        let hub = &rig.hub;
        let (code, out) = hub.json(&[
            "exec",
            "widget",
            "--json",
            "--",
            "sh",
            "-c",
            &format!("echo {REVERSE_MARKER}"),
        ]);
        assert_eq!(code, 0, "{out}");
        assert!(stdout_of(&out).contains(REVERSE_MARKER), "{out}");

        let mut shell = PtyClient::spawn(hub, &["widget"]);
        shell.shell_round_trip("rev-pty");
        shell.type_("exit\r");
        shell.wait_end();

        let src = rig.path("rev-src");
        let on_target = rig.path("rev-target");
        let back = rig.path("rev-back");
        std::fs::write(&src, file_body(2)).unwrap();
        let out = hub.qsh(&[
            "cp",
            &src.display().to_string(),
            &format!("widget:{}", on_target.display()),
        ]);
        assert_eq!(
            exit_code(&out),
            0,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(same_bytes(&src, &on_target));
        let out = hub.qsh(&[
            "cp",
            &format!("widget:{}", on_target.display()),
            &back.display().to_string(),
        ]);
        assert_eq!(
            exit_code(&out),
            0,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(same_bytes(&src, &back));
    }

    /// DoD 27.3 on the real binary. See the module docs for what is in it and
    /// why `-J` is not.
    #[test]
    fn combined_endpoint_serves_registration_and_forward_at_once() {
        {
            let rig = Rig::start();
            let registered_before = rig
                .reverse
                .stderr_snapshot()
                .iter()
                .filter(|l| l.contains("\"event\":\"registered\""))
                .count();

            std::thread::scope(|scope| {
                let forward = scope.spawn(|| forward_battery(&rig));
                let reverse = scope.spawn(|| reverse_battery(&rig));
                forward.join().expect("the forward battery");
                reverse.join().expect("the reverse battery");
            });

            // The registration lived through all of it: still reachable, never
            // lost, never registered a second time.
            assert!(
                hosts_array(&rig.hub)
                    .iter()
                    .any(|h| h["name"] == "widget" && h["state"] == "reachable"),
                "the target is still registered"
            );
            let lines = rig.reverse.stderr_snapshot();
            assert!(
                lines.iter().all(|l| !l.contains("\"event\":\"lost\"")),
                "the registration was lost: {lines:?}"
            );
            let registered_after = lines
                .iter()
                .filter(|l| l.contains("\"event\":\"registered\""))
                .count();
            assert_eq!(registered_before, registered_after, "{lines:?}");

            // One audit sink holds both roles' records, structure only.
            let records = poll_until("the hub's audit trail", Duration::from_secs(20), || {
                let records = rig.hub.audit_records_tolerant();
                let has = |principal: &str, action: &str| {
                    records.iter().any(|r| {
                        r["principal"] == principal
                            && r["action"] == action
                            && r["decision"] == "allow"
                    })
                };
                (has("device:widget", "host.reverse")
                    && has("device:laptop", "exec.run")
                    && has("device:laptop", "session.open")
                    && has("device:laptop", "forward.local")
                    && has("device:laptop", "forward.remote")
                    && has("device:laptop", "forward.agent")
                    && has("device:laptop", "file.read")
                    && has("device:laptop", "file.write"))
                .then_some(records)
            });
            for record in &records {
                let object = record.as_object().expect("a record is an object");
                for key in object.keys() {
                    assert!(RECORD_KEYS.contains(&key.as_str()), "{key} in {record}");
                }
                let line = record.to_string();
                assert!(
                    !line.contains(FORWARD_MARKER) && !line.contains(REVERSE_MARKER),
                    "a payload reached the audit: {line}"
                );
            }
            // The target never got a forward action from the registration role:
            // the only records for it that came over the wire are the
            // registration decisions (`local` ones are `trust add` itself).
            assert!(
                records
                    .iter()
                    .filter(|r| r["principal"] == "device:widget" && r["auth_path"] != "local")
                    .all(|r| r["action"] == "host.reverse"),
                "{records:#?}"
            );
            let _ = (&rig.target, &rig.listen);
        }
    }
}

/// The same DoD 27.3 on Windows, where the hub hosts a ConPTY session and
/// serves the named-pipe local control daemon in one process (DoD 27.13).
/// The second machine opens an interactive session (ConPTY) and runs an
/// exec on the hub while the hub's own account does the same over the
/// reverse route to the target, through the named pipe; `-L`, `-R`, `cp`
/// and the rest of the forward list are the same code on every OS and are
/// covered by the unix half and the in-process tests.
#[cfg(windows)]
mod windows {
    use super::*;
    use crate::tunnel_e2e::PtyClient;
    use common::exit_code;

    fn exec_echo(sandbox: &Sandbox, host: &str, marker: &str) {
        let (code, out) =
            sandbox.json(&["exec", host, "--json", "--", "cmd", "/c", "echo", marker]);
        assert_eq!(code, 0, "{out}");
        assert!(stdout_of(&out).contains(marker), "{out}");
    }

    #[test]
    fn combined_endpoint_serves_registration_and_forward_at_once() {
        let rig = Rig::start();
        std::thread::scope(|scope| {
            let forward = scope.spawn(|| {
                exec_echo(&rig.client, HOST_ALIAS, "forward-exec-marker");
                let mut shell = PtyClient::spawn(&rig.client, &[HOST_ALIAS]);
                shell.shell_round_trip("hub-conpty");
                shell.type_("exit\r");
                shell.wait_end();
                let src = rig.path("win-src");
                let dst = rig.path("win-dst");
                std::fs::write(&src, file_body(3)).unwrap();
                let out = rig.client.qsh(&[
                    "cp",
                    &src.display().to_string(),
                    &format!("{HOST_ALIAS}:{}", dst.display()),
                ]);
                assert_eq!(
                    exit_code(&out),
                    0,
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(same_bytes(&src, &dst));
            });
            let reverse = scope.spawn(|| {
                exec_echo(&rig.hub, "widget", "reverse-exec-marker");
                let mut shell = PtyClient::spawn(&rig.hub, &["widget"]);
                shell.shell_round_trip("rev-conpty");
                shell.type_("exit\r");
                shell.wait_end();
            });
            forward.join().expect("the forward half");
            reverse.join().expect("the reverse half");
        });
        assert!(
            hosts_array(&rig.hub)
                .iter()
                .any(|h| h["name"] == "widget" && h["state"] == "reachable"),
            "the target is still registered"
        );
        let lines = rig.reverse.stderr_snapshot();
        assert!(
            lines.iter().all(|l| !l.contains("\"event\":\"lost\"")),
            "{lines:?}"
        );
        let _ = (&rig.target, &rig.listen);
    }
}
