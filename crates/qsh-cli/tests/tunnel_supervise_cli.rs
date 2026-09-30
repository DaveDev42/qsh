//! The shipped `qsh tunnel open --supervise` binary: exit codes, stdout
//! purity and the one-line diagnostics on stderr (ADR-0023 decisions 11 and
//! 12, `docs/CLI.md` §6.14).
//!
//! The host is a real `qsh serve` that a test kills with SIGKILL and, where
//! the scenario needs the peer back, starts again on the address it had.

#![cfg(unix)]

mod common;

use std::io::{BufRead as _, BufReader};
use std::net::TcpListener;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::{Fleet, HOST_ALIAS, ServeGuard, poll_until};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;

const WAIT: Duration = Duration::from_secs(90);

/// The keys a supervise line may carry (ADR-0023 decision 12). Anything else
/// is a new field the contract has not agreed to.
const ALLOWED_KEYS: &[&str] = &[
    "supervise",
    "at",
    "tunnel_id",
    "mode",
    "route",
    "cause",
    "attempt",
    "code",
    "outage_ms",
    "slept_ms",
];

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a free port");
    listener.local_addr().expect("picked port").port()
}

/// A running `qsh tunnel open --local … --supervise` child with both output
/// streams collected line by line.
struct Holder {
    child: Child,
    port: u16,
    stdout: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<Vec<String>>>,
    readers: Vec<JoinHandle<()>>,
}

impl Holder {
    fn start(fleet: &Fleet, supervise_ms: u32, extra: &[&str]) -> Self {
        let port = free_port();
        // The forward destination is never dialed: no test here connects a
        // local client, and a supervised tunnel does not check it.
        let spec = format!("{port}:127.0.0.1:9");
        let budget = supervise_ms.to_string();
        let mut args = vec![
            "tunnel",
            "open",
            HOST_ALIAS,
            "--local",
            spec.as_str(),
            "--supervise",
            budget.as_str(),
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
        let pipe_out = child.stdout.take().expect("stdout pipe");
        let pipe_err = child.stderr.take().expect("stderr pipe");
        let readers = vec![
            collect(BufReader::new(pipe_out), Arc::clone(&stdout)),
            collect(BufReader::new(pipe_err), Arc::clone(&stderr)),
        ];
        let holder = Self {
            child,
            port,
            stdout,
            stderr,
            readers,
        };
        poll_until("the tunnel envelope", Duration::from_secs(30), || {
            (!holder.stdout_lines().is_empty()).then_some(())
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

    /// The parsed supervise diagnostics on stderr, in order.
    fn supervise_lines(&self) -> Vec<Value> {
        supervise_lines(&self.stderr_lines())
    }

    fn wait_for(&self, kind: &str, count: usize) {
        poll_until(&format!("{count} `{kind}` line(s)"), WAIT, || {
            let seen = self
                .supervise_lines()
                .iter()
                .filter(|line| line["supervise"] == kind)
                .count();
            (seen >= count).then_some(())
        });
    }

    fn signal(&self, signal: Signal) {
        let _ = kill(Pid::from_raw(self.child.id() as i32), signal);
    }

    /// Wait for the child to exit on its own and return its exit code.
    fn wait_exit(&mut self) -> i32 {
        let until = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                for reader in self.readers.drain(..) {
                    let _ = reader.join();
                }
                return status.code().expect("qsh died of a signal");
            }
            assert!(Instant::now() < until, "qsh tunnel open never exited");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn collect<R: std::io::Read + Send + 'static>(
    reader: BufReader<R>,
    sink: Arc<Mutex<Vec<String>>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        for line in reader.lines().map_while(Result::ok) {
            sink.lock().unwrap_or_else(|e| e.into_inner()).push(line);
        }
    })
}

fn supervise_lines(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .filter(|line| line.starts_with("{\"supervise\""))
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
        .collect()
}

/// SIGKILL the running host and wait until it is gone.
fn kill_host(fleet: &mut Fleet) -> String {
    let addr = fleet.serve.addr().to_string();
    fleet.serve.signal(Signal::SIGKILL);
    fleet
        .serve
        .wait_timeout(Duration::from_secs(10))
        .expect("the killed serve exits");
    addr
}

/// Kill the host, let a `--supervise 2500` tunnel run out of budget, and
/// hand back its exit code and stderr.
fn run_out_of_budget(extra: &[&str]) -> (i32, Vec<String>, Vec<String>) {
    let mut fleet = Fleet::start_steady();
    let mut holder = Holder::start(&fleet, 2_500, extra);
    kill_host(&mut fleet);
    let code = holder.wait_exit();
    (code, holder.stderr_lines(), holder.stdout_lines())
}

#[test]
fn supervised_sigterm_during_an_outage_releases_the_listener_and_exits_zero() {
    let mut fleet = Fleet::start_steady();
    let mut holder = Holder::start(&fleet, 120_000, &[]);
    kill_host(&mut fleet);
    holder.wait_for("lost", 1);

    holder.signal(Signal::SIGTERM);
    assert_eq!(holder.wait_exit(), 0, "stderr: {:?}", holder.stderr_lines());
    // The listener went with the process.
    TcpListener::bind(("127.0.0.1", holder.port)).expect("the port is free after SIGTERM");
    assert!(
        holder
            .supervise_lines()
            .iter()
            .all(|line| line["supervise"] != "gave_up"),
        "a deliberate stop is not a give-up"
    );
}

#[test]
fn supervised_budget_exhaustion_emits_gave_up_then_the_error_then_exit_255() {
    let (code, stderr, _stdout) = run_out_of_budget(&[]);
    assert_eq!(code, 255, "stderr: {stderr:?}");
    let position = |pred: &dyn Fn(&str) -> bool| stderr.iter().position(|line| pred(line));
    let lost = position(&|l| l.starts_with("{\"supervise\":\"lost\"")).expect("a lost line");
    let gave_up =
        position(&|l| l.starts_with("{\"supervise\":\"gave_up\"")).expect("a gave_up line");
    assert!(lost < gave_up, "{stderr:?}");
    let error = stderr
        .iter()
        .rposition(|line| !line.starts_with("{\"supervise\""))
        .expect("the error text");
    assert!(
        error > gave_up,
        "the error must follow the gave_up line: {stderr:?}"
    );
}

#[test]
fn supervised_stdout_stays_one_envelope_across_two_reestablishments() {
    let mut fleet = Fleet::start_steady();
    let holder = Holder::start(&fleet, 120_000, &[]);
    for round in 1..=2 {
        let addr = kill_host(&mut fleet);
        holder.wait_for("lost", round);
        fleet.serve = ServeGuard::start_at(&fleet.host, &addr);
        holder.wait_for("reestablished", round);
    }
    let stdout = holder.stdout_lines();
    assert_eq!(stdout.len(), 1, "stdout: {stdout:?}");
    let envelope: Value = serde_json::from_str(&stdout[0]).expect("the envelope is JSON");
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["schema"], "qsh.cli/v1");
    // Both restarts were the same tunnel.
    let lines = holder.supervise_lines();
    let id = envelope["data"]["tunnel_id"].clone();
    assert!(
        lines.iter().all(|line| line["tunnel_id"] == id),
        "{lines:?}"
    );
}

#[test]
fn supervise_lost_and_gave_up_lines_are_visible_at_default_verbosity_and_silent_under_quiet() {
    let (code, stderr, _) = run_out_of_budget(&[]);
    assert_eq!(code, 255);
    let kinds: Vec<String> = supervise_lines(&stderr)
        .iter()
        .map(|line| line["supervise"].as_str().unwrap().to_string())
        .collect();
    assert!(kinds.contains(&"lost".to_string()), "{stderr:?}");
    assert!(kinds.contains(&"gave_up".to_string()), "{stderr:?}");

    let (code, stderr, stdout) = run_out_of_budget(&["--quiet"]);
    assert_eq!(code, 255, "--quiet keeps the exit code");
    assert!(
        supervise_lines(&stderr).is_empty(),
        "--quiet must silence the supervise lines: {stderr:?}"
    );
    assert!(
        stdout.len() <= 1,
        "--quiet must not add stdout lines: {stdout:?}"
    );
}

#[test]
fn supervise_lines_never_carry_an_address_or_token_field() {
    let (_, stderr, _) = run_out_of_budget(&[]);
    let lines = supervise_lines(&stderr);
    assert!(!lines.is_empty(), "{stderr:?}");
    for line in lines {
        for (key, value) in line.as_object().expect("a JSON object") {
            assert!(
                ALLOWED_KEYS.contains(&key.as_str()),
                "unexpected supervise field {key:?} in {line}"
            );
            if let Some(text) = value.as_str() {
                assert!(
                    !text.contains("127.0.0.1") && !text.contains("::1") && !text.contains("token"),
                    "an address or token leaked into {key}: {line}"
                );
            }
        }
    }
}
