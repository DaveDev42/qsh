//! L5 for host-side `exec` on Windows (`docs/design/testing.md`): the
//! Windows counterparts of the unix `exec_loopback` cases that need a real
//! process tree or a real environment, driven through [`spawn_child`], the
//! same entry `run_exec` uses, with `cmd.exe` and the programs that ship with
//! Windows.
//!
//! No fixed sleeps. A test that needs a process to be running waits for the
//! output that process printed itself; the only bounds are hard timeouts that
//! elapse only when the backend is broken.

use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::OwnedHandle;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows_sys::Win32::System::Environment::SetEnvironmentVariableW;

use super::*;
use crate::exec::ChildOutput;
use crate::winproc::testing::{assert_all_ended, job_pids, open_members};

/// Hard bound: only elapses when exec is broken.
const HARD_TIMEOUT: Duration = Duration::from_secs(60);

/// A long-running two-deep tree whose output the test can wait for: `cmd`
/// runs `ping`, whose first reply line carries `127.0.0.1:` in every locale.
const LONG_TREE: [&str; 5] = ["cmd", "/c", "ping", "-n", "120"];
const PING_REPLY: &str = "127.0.0.1:";

async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(HARD_TIMEOUT, fut)
        .await
        .expect("timed out: exec stalled")
}

fn spec(argv: &[&str], env: &[(&str, &str)]) -> ExecSpec {
    ExecSpec {
        argv: argv.iter().map(|a| (*a).to_string()).collect(),
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        timeout: None,
    }
}

fn start(argv: &[&str], env: &[(&str, &str)]) -> Spawned {
    let spec = spec(argv, env);
    spawn_child(&spec.argv[0], &spec.argv[1..], &spec)
        .unwrap_or_else(|f| panic!("spawn failed ({}): {}", f.code, f.message))
}

/// What a finished command wrote and how it ended.
struct Ran {
    stdout: String,
    stderr: String,
    exit: i32,
}

/// Run `argv` to its end, with `input` on its standard input (closed after).
async fn run(argv: &[&str], env: &[(&str, &str)], input: &[u8]) -> Ran {
    let Spawned {
        mut child,
        stdin,
        stdout,
        stderr,
    } = start(argv, env);
    let mut stdin = stdin.expect("stdin pipe");
    let (mut stdout, mut stderr) = (stdout.expect("stdout pipe"), stderr.expect("stderr pipe"));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let feed = async {
        stdin.write_all(input).await.unwrap();
        drop(stdin);
    };
    let (_, out_read, err_read) = within(async {
        tokio::join!(
            feed,
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err)
        )
    })
    .await;
    out_read.unwrap();
    err_read.unwrap();
    let (exit, signal) = within(child.wait()).await.unwrap();
    assert_eq!(signal, None);
    Ran {
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
        exit,
    }
}

/// Set a variable in this process the way a hostile serve environment would
/// carry one. `std::env::set_var` is `unsafe` because the C runtime's
/// environment is not synchronised; `SetEnvironmentVariableW` is.
fn set_process_variable(name: &str, value: &str) {
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let ok = unsafe { SetEnvironmentVariableW(wide(name).as_ptr(), wide(value).as_ptr()) };
    assert_ne!(ok, 0, "SetEnvironmentVariableW failed");
}

/// The text after `prefix` on the first output line that starts with it.
fn line_value(out: &str, prefix: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.strip_prefix(prefix))
        .map(|v| v.trim_end().to_string())
}

fn user_value(user_env: &[(String, String)], key: &str) -> String {
    env_policy::windows_lookup(user_env, key)
        .unwrap_or_else(|| panic!("the user environment has no {key}"))
        .to_string()
}

/// Read `out` until `needle` has appeared in what it said.
async fn read_until(out: &mut ChildOutput, needle: &str) -> String {
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    while !String::from_utf8_lossy(&seen).contains(needle) {
        let n = within(out.read(&mut chunk)).await.unwrap();
        assert_ne!(n, 0, "the output ended before {needle:?}");
        seen.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&seen).into_owned()
}

// --------------------------------------------------------------------------
// The pipes
// --------------------------------------------------------------------------

/// Standard output and error arrive separately, and the exit code is the
/// program's.
#[tokio::test]
async fn exec_streams_and_exit_code_come_back_separately() {
    let ran = run(&["cmd", "/c", "echo out& echo err>&2& exit 7"], &[], b"").await;
    assert_eq!(ran.stdout, "out\r\n");
    assert_eq!(ran.stderr, "err\r\n");
    assert_eq!(ran.exit, 7);
}

/// What the host feeds the child's standard input reaches it, and closing it
/// is the end of input (`sort` prints only once it has seen the end).
#[tokio::test]
async fn exec_stdin_reaches_the_child_and_closing_it_ends_the_input() {
    let ran = run(&["sort"], &[], b"pear\r\napple\r\n").await;
    assert_eq!(ran.stdout, "apple\r\npear\r\n");
    assert_eq!(ran.exit, 0);
}

/// The 32-bit exit status is reported as a signed number, as
/// `ExitStatus::code()` does.
#[tokio::test]
async fn exec_exit_code_is_the_signed_bit_pattern() {
    let ran = run(&["cmd", "/c", "exit -1"], &[], b"").await;
    assert_eq!(ran.exit, -1);
}

/// Output at least a few pipe buffers long arrives whole and in order,
/// before the end of the stream.
#[tokio::test]
async fn exec_one_mib_of_output_arrives_whole() {
    let ran = run(
        &[
            "cmd",
            "/c",
            "for /l %i in (1,1,20000) do @echo 0123456789012345678901234567890123456789012345",
        ],
        &[],
        b"",
    )
    .await;
    assert_eq!(ran.stdout.lines().count(), 20_000);
    assert!(ran.stdout.len() > 900_000, "{}", ran.stdout.len());
    assert_eq!(ran.exit, 0);
}

// --------------------------------------------------------------------------
// The tree
// --------------------------------------------------------------------------

/// A timeout or a gone peer ends the whole tree, not just the program
/// `argv[0]` named: `cmd` and the `ping` it started are both in the job and
/// both end with `TerminateJobObject`. The unix counterpart is the process
/// group kill.
#[tokio::test]
async fn exec_timeout_kills_the_whole_tree_on_windows() {
    let mut argv = LONG_TREE.to_vec();
    argv.push("127.0.0.1");
    let Spawned {
        mut child,
        stdout,
        stderr,
        ..
    } = start(&argv, &[]);
    let (mut stdout, _stderr) = (stdout.unwrap(), stderr.unwrap());
    // `ping` printed its first reply: it is running, and it is `cmd`'s child.
    read_until(&mut stdout, PING_REPLY).await;
    let pids = job_pids(child.job());
    assert!(pids.len() >= 2, "cmd and ping are in the job: {pids:?}");
    let members = open_members(&pids);

    child.kill_tree();

    assert_all_ended(&members, &pids, "TerminateJobObject");
    // The status is the code the job was ended with, and there is no signal.
    let (exit, signal) = within(child.wait()).await.unwrap();
    assert_eq!((exit, signal), (KILLED_EXIT_CODE as i32, None));
    // Every holder of the output pipe is gone, so the stream ends.
    let mut rest = Vec::new();
    within(stdout.read_to_end(&mut rest)).await.unwrap();
}

/// Dropping the child (a failed pump, a cancelled exec) closes the job and so
/// ends the tree too.
#[tokio::test]
async fn exec_dropping_the_child_ends_the_tree() {
    let mut argv = LONG_TREE.to_vec();
    argv.push("127.0.0.1");
    let Spawned {
        child,
        stdout,
        stderr,
        ..
    } = start(&argv, &[]);
    let (mut stdout, _stderr) = (stdout.unwrap(), stderr.unwrap());
    read_until(&mut stdout, PING_REPLY).await;
    let pids = job_pids(child.job());
    assert!(pids.len() >= 2, "{pids:?}");
    let members = open_members(&pids);

    drop(child);

    assert_all_ended(&members, &pids, "dropping the child");
}

/// Exactly the three pipes are inherited, not every inheritable handle this
/// process has: a file this process holds open (inheritable, and without
/// delete sharing) can be deleted once this process closes it, although the
/// child is still running. Had the child inherited the handle, the delete
/// would fail with a sharing violation for as long as the child lives.
#[tokio::test]
async fn exec_child_inherits_only_its_three_pipe_handles() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("held.txt");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)
        .unwrap();
    let held = OwnedHandle::from(file);
    crate::winproc::pipe::set_inheritable(held.as_raw_handle(), true).unwrap();

    let mut argv = LONG_TREE.to_vec();
    argv.push("127.0.0.1");
    let Spawned {
        child,
        stdout,
        stderr,
        ..
    } = start(&argv, &[]);
    let (mut stdout, _stderr) = (stdout.unwrap(), stderr.unwrap());
    read_until(&mut stdout, PING_REPLY).await;

    drop(held);
    std::fs::remove_file(&path).expect("a handle of this process was inherited by the exec child");
    drop(child);
}

/// The child's pipe ends are inheritable only inside `spawn_in_job`, which
/// holds the process-wide spawn lock: once it returns, a started child or a
/// failed start alike, a `Command` spawned by anyone else cannot inherit them.
#[tokio::test]
async fn the_pipe_ends_are_inheritable_only_inside_spawn_in_job() {
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};

    use crate::winproc::pipe::host_pipe;
    use crate::winproc::{JobObject, ProcessSpec, StdioHandles, spawn_in_job};

    fn inheritable(handle: &OwnedHandle) -> bool {
        let mut flags = 0u32;
        // SAFETY: a live handle and a writable out parameter.
        let ok = unsafe { GetHandleInformation(handle.as_raw_handle(), &mut flags) };
        assert_ne!(ok, 0, "GetHandleInformation failed");
        flags & HANDLE_FLAG_INHERIT != 0
    }

    let launch = plan(
        &argv(&["cmd", "/c", "exit 0"]),
        &[],
        &winproc::user_environment().unwrap(),
        &winproc::windows_directory().unwrap(),
        &std::env::current_dir().unwrap(),
    )
    .unwrap();
    let missing = std::path::Path::new(
        r"C:\qsh-no-such-dir
o-such-program.exe",
    );
    for application in [launch.application.as_path(), missing] {
        let (stdin, stdout, stderr) = (
            host_pipe(false).unwrap(),
            host_pipe(true).unwrap(),
            host_pipe(true).unwrap(),
        );
        let job = JobObject::new_kill_on_close().unwrap();
        let started = spawn_in_job(
            &job,
            &ProcessSpec {
                application: Some(application.as_os_str()),
                command_line: &launch.command_line,
                creation_flags: CREATE_NO_WINDOW,
                pseudo_console: None,
                environment: Some(&launch.environment),
                current_dir: None,
                stdio: Some(StdioHandles {
                    stdin: stdin.child.as_raw_handle(),
                    stdout: stdout.child.as_raw_handle(),
                    stderr: stderr.child.as_raw_handle(),
                }),
            },
        );
        assert_eq!(
            started.is_ok(),
            application == launch.application,
            "{application:?}: {started:?}"
        );
        for (name, end) in [
            ("stdin", &stdin.child),
            ("stdout", &stdout.child),
            ("stderr", &stderr.child),
        ] {
            assert!(
                !inheritable(end),
                "{name} stayed inheritable after spawn_in_job ({application:?})"
            );
        }
    }
}

// --------------------------------------------------------------------------
// The environment
// --------------------------------------------------------------------------

/// The child's environment is the user's environment block plus the caller's
/// `env`; what is only in the `qsh serve` process (here a variable no logon
/// defines) does not reach it, there is no `TERM`, and the identity variables
/// are the account's.
#[tokio::test]
async fn exec_child_environment_is_the_user_block_not_ours_on_windows() {
    const LEAK: &str = "QSH_EXEC_TEST_LEAK";
    set_process_variable(LEAK, "from-the-serve-process");
    assert!(std::env::var_os(LEAK).is_some());
    let user_env = winproc::user_environment().unwrap();
    assert!(
        env_policy::windows_lookup(&user_env, LEAK).is_none(),
        "the user block must not carry the serve process's variables"
    );

    let script = format!(
        "echo T=%TERM%& echo U=%USERNAME%& echo P=%USERPROFILE%& echo X=%QSH_EXTRA%& \
         echo L=%{LEAK}%& echo R=%SystemRoot%"
    );
    let ran = run(&["cmd", "/c", &script], &[("QSH_EXTRA", "extra")], b"").await;
    let out = &ran.stdout;

    // `cmd` leaves a reference to an undefined variable as written.
    assert_eq!(
        line_value(out, "T=").as_deref(),
        Some("%TERM%"),
        "a scripted command has no terminal: {out}"
    );
    assert_eq!(line_value(out, "X=").as_deref(), Some("extra"), "{out}");
    assert_eq!(
        line_value(out, "L=").as_deref(),
        Some(format!("%{LEAK}%").as_str()),
        "the serve process's variable reached the child: {out}"
    );
    for (prefix, key) in [
        ("P=", "USERPROFILE"),
        ("U=", "USERNAME"),
        ("R=", "SystemRoot"),
    ] {
        let want = user_value(&user_env, key);
        assert_eq!(
            line_value(out, prefix).as_deref(),
            Some(want.as_str()),
            "{key}: {out}"
        );
    }
}

/// The serve process's locale and time zone do not reach the child, as on
/// unix (`exec.run` gives a scripted command a deterministic environment). A
/// `LANG`, `LANGUAGE`, `LC_*` or `TZ` the caller sends does.
#[tokio::test]
async fn exec_locale_and_time_zone_do_not_pass_through_from_the_serve_process() {
    let user_env = winproc::user_environment().unwrap();
    for key in ["LANG", "LANGUAGE", "LC_QSHTEST", "TZ"] {
        assert!(
            env_policy::windows_lookup(&user_env, key).is_none(),
            "the account's block defines {key}, so this test cannot tell"
        );
    }
    set_process_variable("LANG", "qsh-serve");
    set_process_variable("LANGUAGE", "qsh-serve");
    set_process_variable("LC_QSHTEST", "qsh-serve");
    set_process_variable("TZ", "qsh-serve");
    let script = "echo A=%LANG%& echo B=%LANGUAGE%& echo C=%LC_QSHTEST%& echo D=%TZ%";
    let ran = run(&["cmd", "/c", script], &[], b"").await;
    // `cmd` leaves a reference to an undefined variable as written.
    for (prefix, key) in [
        ("A=", "LANG"),
        ("B=", "LANGUAGE"),
        ("C=", "LC_QSHTEST"),
        ("D=", "TZ"),
    ] {
        assert_eq!(
            line_value(&ran.stdout, prefix).as_deref(),
            Some(format!("%{key}%").as_str()),
            "the serve process's {key} reached the child: {}",
            ran.stdout
        );
    }

    let ran = run(
        &["cmd", "/c", "echo A=%LANG%& echo D=%TZ%"],
        &[("LANG", "ko_KR"), ("TZ", "UTC")],
        b"",
    )
    .await;
    assert_eq!(line_value(&ran.stdout, "A=").as_deref(), Some("ko_KR"));
    assert_eq!(line_value(&ran.stdout, "D=").as_deref(), Some("UTC"));
}

/// The caller's `env` cannot change a pinned key, whatever the case of its
/// name, and an entry that cannot be an environment entry is dropped.
#[tokio::test]
async fn exec_pinned_keys_cannot_be_overridden_on_windows() {
    let user_env = winproc::user_environment().unwrap();
    let ran = run(
        &[
            "cmd",
            "/c",
            "echo B=%USERPROFILE%& echo D=%COMSPEC%& echo E=%SystemRoot%& echo F=%USERNAME%& \
             echo G=%HOME%& echo H=%QSH_FREE%& echo I=%USERDOMAIN%& echo S=%QSH_SIGNAL_EVENT_USR1%",
        ],
        &[
            ("path", r"C:\evil"),
            ("UserProfile", r"C:\evil"),
            ("comspec", r"C:\evil\cmd.exe"),
            ("SYSTEMROOT", r"C:\evil"),
            ("username", "mallory"),
            ("Home", r"C:\evil"),
            ("userdomain", "EVIL"),
            ("QSH_SIGNAL_EVENT_USR1", "Local\\evil"),
            ("QSH_FREE", "free"),
            ("PATH=C:\\evil2", ""),
        ],
        b"",
    )
    .await;
    let out = &ran.stdout;
    assert_eq!(ran.exit, 0, "{out}");
    for (prefix, key) in [
        ("B=", "USERPROFILE"),
        ("D=", "COMSPEC"),
        ("E=", "SystemRoot"),
        ("F=", "USERNAME"),
        ("I=", "USERDOMAIN"),
    ] {
        let want = user_value(&user_env, key);
        assert_eq!(
            line_value(out, prefix).as_deref(),
            Some(want.as_str()),
            "{key} was changed by the caller: {out}"
        );
    }
    // A pinned key the account's block does not define is absent, and the
    // caller cannot add it.
    let home = env_policy::windows_lookup(&user_env, "HOME").unwrap_or("%HOME%");
    assert_eq!(line_value(out, "G=").as_deref(), Some(home), "{out}");
    // The session-event names are session variables; exec has no such events
    // and the caller cannot invent them.
    assert_eq!(
        line_value(out, "S=").as_deref(),
        Some("%QSH_SIGNAL_EVENT_USR1%"),
        "{out}"
    );
    assert_eq!(line_value(out, "H=").as_deref(), Some("free"), "{out}");
    assert!(!out.contains("evil"), "{out}");
}

/// A path the caller sends cannot redirect which program `argv[0]` names: the
/// lookup uses the account's `PATH`, so a `path` entry in the caller's `env`
/// does not decide it, and this still finds `cmd`.
#[tokio::test]
async fn exec_program_lookup_ignores_a_path_override() {
    let ran = run(&["cmd", "/c", "echo ran"], &[("Path", r"C:\evil")], b"").await;
    assert_eq!(ran.stdout, "ran\r\n");
}

// --------------------------------------------------------------------------
// Planning (no process)
// --------------------------------------------------------------------------

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|a| (*a).to_string()).collect()
}

/// The entries of an environment block, in order.
fn block_entries(block: &[u16]) -> Vec<String> {
    block
        .split(|&u| u == 0)
        .filter(|entry| !entry.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

#[test]
fn the_plan_layers_user_block_and_caller_env_with_pinned_keys_last() {
    let user_env = pairs(&[
        ("Path", r"C:\Windows\System32"),
        ("USERPROFILE", r"C:\Users\dave"),
        ("TEMP", r"C:\Temp"),
        ("ComSpec", r"C:\Windows\System32\cmd.exe"),
    ]);
    let client = pairs(&[
        ("path", r"C:\evil"),
        ("temp", r"D:\Scratch"),
        ("TZ", "UTC"),
        ("QSH_OWN", "1"),
        ("BAD=KEY", "x"),
    ]);
    let cwd = tempfile::tempdir().unwrap();
    let launch = plan(
        &argv(&["cmd.exe", "/c", "echo x"]),
        &client,
        &user_env,
        r"C:\Windows",
        cwd.path(),
    )
    .unwrap();
    let entries = block_entries(&launch.environment);

    // One entry per name, sorted like Windows lists a block; the user's
    // pinned spellings win, the caller's other entries replace the block's.
    assert_eq!(
        entries,
        [
            r"ComSpec=C:\Windows\System32\cmd.exe",
            r"Path=C:\Windows\System32",
            "QSH_OWN=1",
            r"temp=D:\Scratch",
            "TZ=UTC",
            r"USERPROFILE=C:\Users\dave",
        ]
    );
    assert_eq!(
        launch.command_line.to_string_lossy(),
        r#"cmd.exe /c "echo x""#
    );
}

#[test]
fn the_plan_finds_the_program_on_the_account_path_and_not_in_the_host_directory() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    std::fs::write(cwd.path().join("tool.exe"), b"").unwrap();
    std::fs::write(cwd.path().join("evil.exe"), b"").unwrap();
    std::fs::write(bin.path().join("tool.exe"), b"").unwrap();
    let path = std::env::join_paths([bin.path()]).unwrap();
    let user_env = pairs(&[("Path", path.to_str().unwrap())]);
    let plan_for = |name: &str, client: &[(String, String)]| {
        plan(&argv(&[name]), client, &user_env, r"C:\Windows", cwd.path())
    };

    assert_eq!(
        plan_for("tool", &[]).unwrap().application,
        bin.path().join("tool.exe")
    );
    // The caller's `PATH` does not decide it either.
    let evil = pairs(&[("PATH", cwd.path().to_str().unwrap())]);
    assert_eq!(
        plan_for("tool", &evil).unwrap().application,
        bin.path().join("tool.exe")
    );
    // A file in the host's working directory, or on the serve process's
    // `PATH`, is not found by its bare name.
    assert_eq!(
        plan_for("evil", &evil).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn the_plan_refuses_an_empty_argv_and_a_nul_before_creating_anything() {
    let plan_for = |items: &[&str]| {
        plan(
            &argv(items),
            &[],
            &pairs(&[("Path", r"C:\Windows\System32")]),
            r"C:\Windows",
            Path::new(r"C:\"),
        )
    };
    assert_eq!(
        plan_for(&[]).err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert_eq!(
        plan_for(&["cmd", "/c", "echo a\0b"])
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
}

/// A program that does not exist ends in-band with the shell's 127, like
/// the unix `Command::spawn` `NotFound`.
#[test]
fn a_missing_program_is_a_not_found_failure_with_exit_127() {
    let spec = spec(&["qsh-no-such-program-anywhere"], &[]);
    let failure = match spawn_child(&spec.argv[0], &spec.argv[1..], &spec) {
        Ok(_) => panic!("the program must not exist"),
        Err(failure) => failure,
    };
    assert_eq!(failure.code, 127);
    assert!(failure.message.contains("cannot execute"), "{failure:?}");
}
