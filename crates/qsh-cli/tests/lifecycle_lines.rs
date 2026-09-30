//! `qsh::lifecycle`: the one-line JSON records beside the human lifecycle
//! lines (ADR-0023 decision 21, `docs/CLI.md` §6.12-§6.14).
//!
//! Real `qsh serve`, `qsh listen`, `qsh serve --to` and `qsh tunnel open`
//! children, read from their stderr. The human lines keep their bytes; the
//! JSON lines add a timestamp and a process kind and never an address.

#![cfg(unix)]

mod common;

use std::io::{BufRead as _, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::{Fleet, HOST_ALIAS, ListenGuard, Sandbox, ServeGuard, poll_until};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;

const WAIT: Duration = Duration::from_secs(60);

/// The keys a lifecycle line may carry (ADR-0023 decision 21). Anything
/// else is a field the contract has not agreed to, an address above all.
const ALLOWED_KEYS: &[&str] = &[
    "lifecycle",
    "at",
    "process",
    "tunnel_id",
    "mode",
    "supervise",
    "code",
    "cause",
];

/// The `cause` words a lost connection can carry (`docs/CLI.md` §6.13).
const CAUSES: &[&str] = &["idle_timeout", "path_dead", "peer_closed", "local"];

fn lifecycle_lines(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .filter(|line| line.starts_with("{\"lifecycle\""))
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
        .collect()
}

fn position(lines: &[String], pred: impl Fn(&str) -> bool) -> usize {
    lines
        .iter()
        .position(|line| pred(line))
        .unwrap_or_else(|| panic!("no such line in {lines:?}"))
}

/// Every line has the agreed keys only, a plausible `at`, and none of the
/// forbidden `needles` (addresses and ports).
fn check_shape(lines: &[String], needles: &[&str]) {
    for line in lines.iter().filter(|l| l.starts_with("{\"lifecycle\"")) {
        let value: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"));
        let object = value.as_object().expect("a JSON object");
        for key in object.keys() {
            assert!(
                ALLOWED_KEYS.contains(&key.as_str()),
                "unexpected `{key}`: {line}"
            );
        }
        let at = value["at"].as_str().expect("`at` is a string");
        let bytes = at.as_bytes();
        assert!(
            at.len() == 20 && at.ends_with('Z') && bytes[4] == b'-' && bytes[10] == b'T',
            "`at` is RFC 3339 to the second: {at}"
        );
        for needle in needles {
            assert!(!line.contains(needle), "`{needle}` leaked into: {line}");
        }
    }
}

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a free port");
    listener.local_addr().expect("picked port").port()
}

fn collect<R: std::io::Read + Send + 'static>(
    reader: R,
    sink: Arc<Mutex<Vec<String>>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            sink.lock().unwrap_or_else(|e| e.into_inner()).push(line);
        }
    })
}

fn wait_exit(child: &mut Child, readers: &mut Vec<JoinHandle<()>>, what: &str) -> i32 {
    let until = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            for reader in readers.drain(..) {
                let _ = reader.join();
            }
            return status.code().expect("qsh died of a signal");
        }
        assert!(Instant::now() < until, "{what} never exited");
        thread::sleep(Duration::from_millis(20));
    }
}

/// A `qsh tunnel open --local` child (no `--supervise`) with both streams
/// collected.
struct Holder {
    child: Child,
    port: u16,
    stdout: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<Vec<String>>>,
    readers: Vec<JoinHandle<()>>,
}

impl Holder {
    fn start(fleet: &Fleet, extra: &[&str]) -> Self {
        let port = free_tcp_port();
        let spec = format!("{port}:127.0.0.1:9");
        let mut args = vec![
            "tunnel",
            "open",
            HOST_ALIAS,
            "--local",
            spec.as_str(),
            "--json",
        ];
        args.extend_from_slice(extra);
        let mut child = fleet
            .client
            .command(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qsh tunnel open");
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let readers = vec![
            collect(
                child.stdout.take().expect("stdout pipe"),
                Arc::clone(&stdout),
            ),
            collect(
                child.stderr.take().expect("stderr pipe"),
                Arc::clone(&stderr),
            ),
        ];
        let holder = Self {
            child,
            port,
            stdout,
            stderr,
            readers,
        };
        // The "holding" line is written after the envelope, and after the
        // `tunnel_opened` record when it is on.
        poll_until("the holding line", Duration::from_secs(30), || {
            holder
                .stderr_lines()
                .iter()
                .any(|l| l.starts_with("qsh tunnel open: holding"))
                .then_some(())
        });
        holder
    }

    fn stdout_lines(&self) -> Vec<String> {
        self.stdout
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn stderr_lines(&self) -> Vec<String> {
        self.stderr
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn wait_exit(&mut self) -> i32 {
        wait_exit(&mut self.child, &mut self.readers, "qsh tunnel open")
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// End the host politely (SIGTERM closes its connections with a close
/// frame) and wait for it to be gone.
fn stop_host(fleet: &mut Fleet) {
    fleet.serve.signal(Signal::SIGTERM);
    fleet
        .serve
        .wait_timeout(Duration::from_secs(20))
        .expect("the host exits on SIGTERM");
}

#[test]
fn serve_and_listen_listening_lines_are_byte_identical_and_a_lifecycle_line_carries_at() {
    let host = Sandbox::initialized();
    let serve = ServeGuard::start(&host);
    let controller = Sandbox::initialized();
    let listen = ListenGuard::start(&controller);

    let serve_addr = serve.addr().to_string();
    let human = format!("qsh serve: listening on {serve_addr}");
    let serve_lines = poll_until("serve's lifecycle line", Duration::from_secs(20), || {
        let lines = serve.stderr_snapshot();
        lines
            .iter()
            .any(|l| l.starts_with("{\"lifecycle\":\"listening\""))
            .then_some(lines)
    });
    assert!(
        serve_lines.contains(&human),
        "the human line is unchanged: {serve_lines:?}"
    );
    let listening = position(&serve_lines, |l| {
        l.starts_with("{\"lifecycle\":\"listening\"")
    });
    assert!(
        position(&serve_lines, |l| l == human) < listening,
        "the human line comes first: {serve_lines:?}"
    );
    let parsed = lifecycle_lines(&serve_lines);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["process"], "serve");
    let port = serve_addr.rsplit(':').next().expect("a port");
    check_shape(&serve_lines, &[serve_addr.as_str(), port]);

    let listen_addr = listen.addr().to_string();
    let human = format!("qsh listen: listening on {listen_addr}");
    let listen_lines = poll_until("listen's lifecycle line", Duration::from_secs(20), || {
        let lines = listen.stderr_lines();
        lines
            .iter()
            .any(|l| l.starts_with("{\"lifecycle\":\"listening\""))
            .then_some(lines)
    });
    assert!(
        listen_lines.contains(&human),
        "the human line is unchanged: {listen_lines:?}"
    );
    assert!(
        position(&listen_lines, |l| l == human)
            < position(&listen_lines, |l| l
                .starts_with("{\"lifecycle\":\"listening\"")),
        "the human line comes first: {listen_lines:?}"
    );
    let parsed = lifecycle_lines(&listen_lines);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["process"], "listen");
    let port = listen_addr.rsplit(':').next().expect("a port");
    check_shape(&listen_lines, &[listen_addr.as_str(), port]);
}

#[test]
fn a_default_mode_tunnel_end_emits_a_lifecycle_line_with_code_and_no_address() {
    let mut fleet = Fleet::start();
    let mut holder = Holder::start(&fleet, &[]);
    let envelope: Value =
        serde_json::from_str(&holder.stdout_lines()[0]).expect("the envelope is one JSON line");
    let tunnel_id = envelope["data"]["tunnel_id"]
        .as_str()
        .expect("tunnel_id")
        .to_string();

    stop_host(&mut fleet);
    assert_eq!(
        holder.wait_exit(),
        255,
        "an unsupervised tunnel dies with its connection"
    );

    let lines = holder.stderr_lines();
    let opened = position(&lines, |l| {
        l.starts_with("{\"lifecycle\":\"tunnel_opened\"")
    });
    let holding = position(&lines, |l| l.starts_with("qsh tunnel open: holding"));
    let ended = position(&lines, |l| l.starts_with("{\"lifecycle\":\"tunnel_ended\""));
    let human = position(&lines, |l| {
        l.contains("the connection carrying this tunnel closed:")
    });
    assert!(opened < holding && holding < ended, "{lines:?}");
    assert!(
        human > holding,
        "the human end line is still there: {lines:?}"
    );

    let parsed = lifecycle_lines(&lines);
    assert_eq!(parsed.len(), 2, "{lines:?}");
    assert_eq!(parsed[0]["tunnel_id"], tunnel_id.as_str());
    assert_eq!(parsed[0]["mode"], "local");
    assert_eq!(parsed[0]["supervise"], false);
    assert_eq!(parsed[0]["process"], "tunnel");
    assert_eq!(parsed[1]["code"], "CONNECTION_FAILED");
    assert_eq!(parsed[1]["tunnel_id"], tunnel_id.as_str());
    assert_eq!(parsed[1]["supervise"], false);
    let cause = parsed[1]["cause"]
        .as_str()
        .expect("a forward tunnel knows its cause");
    assert!(CAUSES.contains(&cause), "{cause}");

    let host_addr = fleet.addr().to_string();
    let host_port = host_addr.rsplit(':').next().expect("a port").to_string();
    let bind_port = holder.port.to_string();
    check_shape(
        &lines,
        &[
            host_addr.as_str(),
            host_port.as_str(),
            bind_port.as_str(),
            "127.0.0.1",
        ],
    );
    // stdout stays the one envelope.
    assert_eq!(holder.stdout_lines().len(), 1);
}

#[test]
fn quiet_suppresses_lifecycle_lines() {
    let mut fleet = Fleet::start_with(&["-q"]);
    let mut holder = Holder::start(&fleet, &["-q"]);
    stop_host(&mut fleet);
    assert_eq!(holder.wait_exit(), 255);
    let holder_lines = holder.stderr_lines();
    assert!(
        holder_lines
            .iter()
            .any(|l| l.starts_with("qsh tunnel open: holding")),
        "the human lines are not diagnostics: {holder_lines:?}"
    );
    assert!(
        lifecycle_lines(&holder_lines).is_empty(),
        "{holder_lines:?}"
    );

    let serve = fleet.serve.captured();
    assert!(
        serve
            .stderr
            .iter()
            .any(|l| l.starts_with("qsh serve: listening on ")),
        "{:?}",
        serve.stderr
    );
    assert!(
        lifecycle_lines(&serve.stderr).is_empty(),
        "{:?}",
        serve.stderr
    );
}

#[test]
fn serve_to_emits_listening_and_shutting_down_lifecycle_lines() {
    let sandbox = Sandbox::initialized();
    // A controller nothing answers at: the target's runtime still comes up,
    // which is all `listening` promises for a target.
    let port = {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a throwaway UDP port");
        socket.local_addr().expect("local addr").port()
    };
    let fingerprint = sandbox.fingerprint();
    sandbox.trust_add("nowhere", Some(&format!("127.0.0.1:{port}")), &fingerprint);

    let mut child = sandbox
        .command(&["serve", "--to", "nowhere"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qsh serve --to");
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let mut readers = vec![
        collect(
            child.stdout.take().expect("stdout pipe"),
            Arc::clone(&stdout),
        ),
        collect(
            child.stderr.take().expect("stderr pipe"),
            Arc::clone(&stderr),
        ),
    ];
    let snapshot = || stderr.lock().unwrap_or_else(|e| e.into_inner()).clone();
    poll_until("the listening record", Duration::from_secs(30), || {
        snapshot()
            .iter()
            .any(|l| l.starts_with("{\"lifecycle\":\"listening\""))
            .then_some(())
    });
    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
    let code = wait_exit(&mut child, &mut readers, "qsh serve --to");
    assert_eq!(code, 0);

    let lines = snapshot();
    let parsed = lifecycle_lines(&lines);
    assert_eq!(parsed.len(), 2, "{lines:?}");
    assert_eq!(parsed[0]["lifecycle"], "listening");
    assert_eq!(parsed[1]["lifecycle"], "shutting_down");
    assert!(parsed.iter().all(|line| line["process"] == "serve_to"));
    assert!(
        position(&lines, |l| l.starts_with("qsh ")
            && l.ends_with(": shutting down"))
            < position(&lines, |l| l
                .starts_with("{\"lifecycle\":\"shutting_down\"")),
        "the human line comes first: {lines:?}"
    );
    check_shape(&lines, &[port.to_string().as_str(), "127.0.0.1"]);
    assert!(stdout.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
}
