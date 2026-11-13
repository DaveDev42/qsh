//! `qsh serve --on-demand` (ADR-0051 decision 2): the idle exit, the
//! `serve.json` runtime record, the port fallback and the detached spawn.
//!
//! No test binds a fixed port: every bind is `127.0.0.1:0`, or a port the
//! test just found free, and the fallback range is injected.

use std::net::{SocketAddr, UdpSocket};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qsh_core::Paths;
#[cfg(unix)]
use qsh_core::broker::{CloseReason, SessionSpec};
use qsh_core::config::Config;
use qsh_core::identity;
use qsh_core::serve::record::{self, ServeRecord, ServeRecordMode};
use qsh_core::serve::{OnDemandOptions, run_serve_with};
use qsh_core::server::Server;
use qsh_proto::{ErrorCode, KeyStoreMode};

const LOOPBACK0: &str = "127.0.0.1:0";

struct Rig {
    _dir: tempfile::TempDir,
    paths: Paths,
    config: Config,
}

fn rig(idle_ms: u64) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    identity::init(&paths, KeyStoreMode::File).unwrap();
    let mut config = Config::default();
    config.serve.on_demand_idle_ms = Some(idle_ms);
    // A serve that is not on demand brings its iroh endpoint up unless told
    // not to (ADR-0063) and asks the router for a port mapping (ADR-0064);
    // these tests must reach neither a public relay nor the LAN gateway.
    config.iroh.enable = Some(false);
    Rig {
        _dir: dir,
        paths,
        config,
    }
}

/// A one-port range on a UDP port nothing holds right now.
fn one_free_port() -> RangeInclusive<u16> {
    let port = free_port();
    port..=port
}

/// A UDP port nothing holds right now.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn options(config: &Config, ports: RangeInclusive<u16>) -> OnDemandOptions {
    OnDemandOptions {
        fallback_ports: ports,
        ..OnDemandOptions::from_config(config).unwrap()
    }
}

/// What a running serve published, plus the join handle of the task that
/// runs it.
struct Running {
    task: tokio::task::JoinHandle<Result<(), qsh_core::ops::OpError>>,
    bound: SocketAddr,
    // Read only by the unix session test (a PTY session needs unix here).
    #[cfg_attr(not(unix), allow(dead_code))]
    server: Arc<Server>,
    record_at_bind: Option<ServeRecord>,
}

async fn start(
    rig: &Rig,
    bind: &str,
    on_demand: Option<OnDemandOptions>,
) -> Result<Running, qsh_core::ops::OpError> {
    let identity = identity::load(&rig.paths).unwrap().unwrap();
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    let server_slot: Arc<Mutex<Option<Arc<Server>>>> = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&server_slot);
    let paths = rig.paths.clone();
    let config = rig.config.clone();
    let bind: SocketAddr = bind.parse().unwrap();
    let record_paths = rig.paths.clone();
    let task = tokio::spawn(async move {
        run_serve_with(
            &paths,
            &config,
            identity,
            bind,
            on_demand,
            move |addr| {
                let _ = bound_tx.send((addr, record::read(&record_paths)));
            },
            move |runtime| {
                *slot.lock().unwrap() = Some(Arc::clone(&runtime.server));
            },
            |_| {},
            std::future::pending(),
        )
        .await
    });
    match tokio::time::timeout(Duration::from_secs(10), bound_rx).await {
        Ok(Ok((bound, record_at_bind))) => Ok(Running {
            task,
            bound,
            server: server_slot.lock().unwrap().clone().unwrap(),
            record_at_bind,
        }),
        _ => Err(task
            .await
            .unwrap()
            .expect_err("serve ended without binding")),
    }
}

async fn finished_within(running: &mut Running, limit: Duration) -> bool {
    tokio::time::timeout(limit, &mut running.task).await.is_ok()
}

#[test]
fn on_demand_idle_is_validated_like_the_other_durations() {
    let mut config = Config::default();
    assert_eq!(
        config.serve.on_demand_idle().unwrap(),
        Duration::from_secs(600)
    );
    config.serve.on_demand_idle_ms = Some(0);
    assert_eq!(
        config.serve.on_demand_idle().unwrap_err().code,
        ErrorCode::ConfigError
    );
    config.serve.on_demand_idle_ms = Some(24 * 60 * 60 * 1000 + 1);
    assert_eq!(
        config.serve.on_demand_idle().unwrap_err().code,
        ErrorCode::ConfigError
    );
    config.serve.on_demand_idle_ms = Some(1);
    assert!(config.serve.on_demand_idle().is_ok());
}

#[tokio::test]
async fn a_serve_nobody_connects_to_drains_after_the_idle_limit_and_removes_its_record() {
    let rig = rig(300);
    let started = Instant::now();
    let mut running = start(&rig, LOOPBACK0, Some(options(&rig.config, one_free_port())))
        .await
        .unwrap();

    let record = running
        .record_at_bind
        .clone()
        .expect("serve.json exists when the address is announced");
    assert_eq!(record.pid, std::process::id());
    assert_eq!(record.mode, ServeRecordMode::OnDemand);
    assert_eq!(record.socket_addr(), Some(running.bound));
    assert_eq!(
        record::live_serve(&rig.paths).map(|r| r.pid),
        Some(std::process::id())
    );

    assert!(finished_within(&mut running, Duration::from_secs(10)).await);
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(
        record::read(&rig.paths).is_none(),
        "a clean exit removes serve.json"
    );
}

#[tokio::test]
async fn a_serve_that_is_not_on_demand_never_exits_on_idle_but_still_publishes_a_record() {
    let mut rig = rig(100);
    // Even a configured idle limit does nothing without `--on-demand`.
    rig.config.serve.on_demand_idle_ms = Some(100);
    let mut running = start(&rig, LOOPBACK0, None).await.unwrap();
    assert_eq!(
        running.record_at_bind.as_ref().map(|r| r.mode),
        Some(ServeRecordMode::Persistent)
    );
    assert!(!finished_within(&mut running, Duration::from_millis(800)).await);
    running.task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn a_detached_session_keeps_the_serve_alive_until_the_idle_limit_after_the_last_one_closes() {
    let rig = rig(400);
    let mut running = start(&rig, LOOPBACK0, Some(options(&rig.config, one_free_port())))
        .await
        .unwrap();

    let spec = SessionSpec {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        ..Default::default()
    };
    let backend = Arc::clone(running.server.sessions());
    let id = backend.open(&spec, "test-opener").unwrap();
    assert_eq!(running.server.activity().sessions, 1);

    // Several idle limits pass; the detached session is what keeps it up.
    assert!(!finished_within(&mut running, Duration::from_millis(1500)).await);
    assert!(record::live_serve(&rig.paths).is_some());

    backend.close(&id, CloseReason::Closed, None).await.unwrap();
    let closed_at = Instant::now();
    assert!(finished_within(&mut running, Duration::from_secs(10)).await);
    assert!(
        closed_at.elapsed() >= Duration::from_millis(300),
        "the idle clock restarts when the last session closes"
    );
    assert!(record::read(&rig.paths).is_none());
}

#[tokio::test]
async fn a_taken_port_falls_back_to_the_injected_range_and_the_record_names_the_real_port() {
    let rig = rig(5_000);
    let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let taken = holder.local_addr().unwrap().port();
    let wanted = free_port();
    let range = wanted..=wanted;

    let running = start(
        &rig,
        &format!("127.0.0.1:{taken}"),
        Some(options(&rig.config, range)),
    )
    .await
    .unwrap();
    assert_eq!(running.bound.port(), wanted);
    assert_eq!(
        running.record_at_bind.unwrap().socket_addr(),
        Some(running.bound)
    );
    running.task.abort();
}

#[tokio::test]
async fn without_on_demand_a_taken_port_stays_an_error() {
    let rig = rig(5_000);
    let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let taken = holder.local_addr().unwrap().port();
    let err = start(&rig, &format!("127.0.0.1:{taken}"), None)
        .await
        .err()
        .expect("bind must fail");
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(err.message.contains("cannot listen on"));
    assert!(record::read(&rig.paths).is_none());
}

#[tokio::test]
async fn a_live_serve_of_this_user_blocks_the_fallback() {
    let rig = rig(5_000);
    let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let taken = holder.local_addr().unwrap().port();
    // serve.json names a live process (this test), so the taken port is that
    // serve's, not somebody else's.
    record::write(
        &rig.paths,
        &ServeRecord::for_current_process(holder.local_addr().unwrap(), ServeRecordMode::OnDemand),
    )
    .unwrap();
    let err = start(
        &rig,
        &format!("127.0.0.1:{taken}"),
        Some(options(&rig.config, one_free_port())),
    )
    .await
    .err()
    .expect("bind must fail");
    assert_eq!(err.code, ErrorCode::ConfigError);
    // The live serve's record is not touched by the one that failed.
    assert!(record::read(&rig.paths).is_some());
}

#[cfg(unix)]
fn dead_pid() -> u32 {
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    pid
}

#[cfg(unix)]
#[test]
fn a_record_with_a_dead_pid_is_absent() {
    let rig = rig(1_000);
    let stale = ServeRecord {
        pid: dead_pid(),
        addr: "[::]:4433".into(),
        mode: ServeRecordMode::OnDemand,
        started_at: "2026-11-05T00:00:00Z".into(),
        iroh: None,
    };
    record::write(&rig.paths, &stale).unwrap();
    assert_eq!(record::read(&rig.paths), Some(stale.clone()));
    assert_eq!(record::live_serve(&rig.paths), None);

    // A live pid with the same record is found.
    let live = ServeRecord {
        pid: std::process::id(),
        ..stale
    };
    record::write(&rig.paths, &live).unwrap();
    assert_eq!(record::live_serve(&rig.paths), Some(live));
}

#[cfg(unix)]
#[test]
fn serve_json_is_owner_only_and_removal_only_takes_the_owners_record() {
    use std::os::unix::fs::PermissionsExt as _;
    let rig = rig(1_000);
    let mine = ServeRecord::for_current_process(
        "127.0.0.1:60001".parse().unwrap(),
        ServeRecordMode::OnDemand,
    );
    record::write(&rig.paths, &mine).unwrap();
    let mode = std::fs::metadata(rig.paths.serve_record_file())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    record::remove_if_owned_by(&rig.paths, std::process::id() + 1);
    assert!(record::read(&rig.paths).is_some());
    record::remove_if_owned_by(&rig.paths, std::process::id());
    assert!(record::read(&rig.paths).is_none());
}

/// A stand-in for `qsh serve --on-demand`: a script that counts its starts
/// and publishes a record naming its own pid, then stays up.
#[cfg(unix)]
fn fake_serve_program(dir: &std::path::Path, paths: &Paths) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let program = dir.join("fake-qsh");
    let counter = dir.join("starts");
    let script = format!(
        "#!/bin/sh\n\
         [ \"$1 $2\" = \"serve --on-demand\" ] || exit 2\n\
         echo started >> '{counter}'\n\
         printf '{{\"pid\":%s,\"addr\":\"127.0.0.1:60001\",\"mode\":\"on_demand\",\"started_at\":\"2026-11-05T00:00:00Z\"}}' $$ > '{record}'\n\
         exec sleep 30\n",
        counter = counter.display(),
        record = paths.serve_record_file().display(),
    );
    std::fs::write(&program, script).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    program
}

#[cfg(unix)]
#[test]
fn a_second_ensure_reuses_the_live_serve_instead_of_spawning_another() {
    let rig = rig(1_000);
    let program = fake_serve_program(rig._dir.path(), &rig.paths);
    std::fs::create_dir_all(&rig.paths.state_dir).unwrap();

    let first = qsh_core::serve::detach::ensure_on_demand_serve(
        &rig.paths,
        &program,
        Duration::from_secs(10),
    )
    .unwrap();
    assert!(first.spawned);
    assert!(!first.breakaway_refused);
    assert_eq!(first.record.addr, "127.0.0.1:60001");

    let second = qsh_core::serve::detach::ensure_on_demand_serve(
        &rig.paths,
        &program,
        Duration::from_secs(10),
    )
    .unwrap();
    assert!(!second.spawned);
    assert_eq!(second.record.pid, first.record.pid);

    let starts = std::fs::read_to_string(rig._dir.path().join("starts")).unwrap();
    assert_eq!(starts.lines().count(), 1);

    // SAFETY: the pid is the fake serve this test started.
    unsafe { libc::kill(first.record.pid as libc::pid_t, libc::SIGKILL) };
}

#[cfg(unix)]
#[test]
fn ensure_ignores_a_stale_record_and_times_out_when_the_serve_never_comes_up() {
    let rig = rig(1_000);
    let stale = ServeRecord {
        pid: dead_pid(),
        addr: "[::]:4433".into(),
        mode: ServeRecordMode::OnDemand,
        started_at: "2026-11-05T00:00:00Z".into(),
        iroh: None,
    };
    record::write(&rig.paths, &stale).unwrap();
    // `true` accepts the arguments, publishes nothing and exits.
    let err = qsh_core::serve::detach::ensure_on_demand_serve(
        &rig.paths,
        std::path::Path::new("/bin/true"),
        Duration::from_millis(400),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout);
}

/// The child must outlive the process that started it. The test forks; the
/// forked process starts a detached `sh` and exits at once, and the `sh`
/// still writes its marker afterwards.
#[cfg(unix)]
#[test]
fn a_detached_child_survives_its_parent_exiting() {
    use std::ffi::OsStr;
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    let script = format!("sleep 1; echo survived > '{}'", marker.display());

    // SAFETY: the forked child only runs `spawn_detached` and `_exit`.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let ok = qsh_core::serve::detach::spawn_detached(
            std::path::Path::new("/bin/sh"),
            &[OsStr::new("-c"), OsStr::new(&script)],
        )
        .is_ok();
        // SAFETY: leaves the forked copy without running destructors or the
        // test harness' exit path.
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status = 0;
    // SAFETY: `pid` is this test's own child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    assert!(!marker.exists(), "the child is still sleeping");

    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "survived");
}

#[cfg(target_os = "linux")]
#[test]
fn a_detached_child_has_its_own_session_and_null_stdio() {
    use std::ffi::OsStr;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    // `ps` prints the session id; `-p $$` is the sh itself.
    let script = format!(
        "echo \"$(ps -o sid= -p $$ | tr -d ' ') $$\" > '{out}'; [ ! -t 0 ] && echo notty >> '{out}'",
        out = out.display()
    );
    let spawn = qsh_core::serve::detach::spawn_detached(
        std::path::Path::new("/bin/sh"),
        &[OsStr::new("-c"), OsStr::new(&script)],
    )
    .unwrap();
    assert!(!spawn.breakaway_refused);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !out.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(200));
    let text = std::fs::read_to_string(&out).unwrap();
    let mut lines = text.lines();
    let first: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
    // A session of its own (the intermediate process led it and is gone, so
    // the serve is not a leader and cannot take a terminal back).
    // SAFETY: `getsid(0)` reads this process's session id.
    let ours = unsafe { libc::getsid(0) };
    assert_ne!(first[0], ours.to_string());
    assert_ne!(first[0], first[1]);
    assert_eq!(lines.next(), Some("notty"));
}

#[cfg(windows)]
#[test]
fn a_detached_windows_child_starts() {
    use std::ffi::OsStr;
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker.txt");
    let comspec =
        std::env::var_os("COMSPEC").unwrap_or_else(|| "C:\\Windows\\System32\\cmd.exe".into());
    // No inner quotes: the Windows command-line builder escapes `"` as `\"`,
    // which `cmd /c` does not understand. Temp paths have no spaces.
    let command = format!("echo ok>{}", marker.display());
    let spawn = qsh_core::serve::detach::spawn_detached(
        std::path::Path::new(&comspec),
        &[OsStr::new("/c"), OsStr::new(&command)],
    )
    .unwrap();
    // Under a CI runner that is not in a restrictive job the flag is accepted;
    // either way the child must start.
    let _ = spawn.breakaway_refused;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(marker.exists());
}
