//! `qsh service run <mode>`: the hidden entry the Windows Task Scheduler task
//! calls (ADR-0035 decision 27), run as a real process on every platform. It
//! detaches from the console, points stdout and stderr at
//! `<state_dir>/log/<mode>.out.log` and `.err.log`, then runs the same entry
//! as the foreground `qsh serve` and `qsh listen`.

use crate::common;

use std::io::Read as _;
use std::process::{Child, Stdio};
use std::time::Duration;

use common::{Sandbox, own_process_group, poll_until, stop_gracefully};

const WAIT: Duration = Duration::from_secs(60);

/// A `qsh service run <mode>` child with both pipes held, killed on drop.
struct RunChild {
    child: Option<Child>,
}

impl RunChild {
    fn spawn(sandbox: &Sandbox, args: &[&str]) -> Self {
        let mut command = sandbox.command(args);
        let child = own_process_group(&mut command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qsh service run");
        Self { child: Some(child) }
    }

    /// Stops the child and returns what reached its own stdout and stderr
    /// pipes, which `service run` has replaced with the logs.
    fn stop(mut self) -> (Vec<u8>, Vec<u8>) {
        let mut child = self.child.take().unwrap();
        if cfg!(unix) {
            stop_gracefully(&mut child);
        } else {
            // The task has no console to receive a stop event on once it has
            // detached from it; the scheduler ends it the same way.
            let _ = child.kill();
        }
        let _ = child.wait();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
        child.stderr.take().unwrap().read_to_end(&mut err).unwrap();
        (out, err)
    }
}

impl Drop for RunChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn log_text(sandbox: &Sandbox, name: &str) -> Option<String> {
    std::fs::read_to_string(sandbox.state_dir().join("log").join(name)).ok()
}

fn banner_count(text: &str, banner: &str) -> usize {
    text.matches(banner).count()
}

/// A sandbox whose config binds `mode` to an ephemeral loopback port.
fn bound_sandbox(mode: &str) -> Sandbox {
    let sandbox = Sandbox::initialized();
    let table = if mode == "listen" { "listen" } else { "serve" };
    std::fs::write(
        sandbox.config_dir().join("config.toml"),
        format!("[{table}]\nbind = \"127.0.0.1:0\"\n"),
    )
    .unwrap();
    sandbox
}

#[test]
fn service_run_redirects_stdout_and_stderr_to_the_mode_logs() {
    for (mode, banner) in [
        ("serve", "qsh serve: listening on "),
        ("listen", "qsh listen: listening on "),
    ] {
        let sandbox = bound_sandbox(mode);
        let err_name = format!("{mode}.err.log");
        let out_name = format!("{mode}.out.log");

        // Two runs: the logs are appended to, never truncated.
        for run in 1..=2 {
            let child = RunChild::spawn(&sandbox, &["service", "run", mode]);
            poll_until(&format!("{mode} run {run} banner"), WAIT, || {
                let text = log_text(&sandbox, &err_name)?;
                (banner_count(&text, banner) == run).then_some(())
            });
            let (piped_out, piped_err) = child.stop();
            assert!(
                piped_out.is_empty(),
                "{mode}: stdout reached the original pipe: {}",
                String::from_utf8_lossy(&piped_out)
            );
            assert!(
                piped_err.is_empty(),
                "{mode}: stderr reached the original pipe: {}",
                String::from_utf8_lossy(&piped_err)
            );
        }

        let err_log = log_text(&sandbox, &err_name).unwrap();
        assert_eq!(banner_count(&err_log, banner), 2, "{mode}: {err_log}");
        // Machine-readable stdout stays empty in a long-running mode.
        assert_eq!(log_text(&sandbox, &out_name).as_deref(), Some(""), "{mode}");
    }
}

/// The log directory and both log files are the account's alone: mode
/// `0700` and `0600` on unix, a single non-inherited entry for the account
/// on Windows (ADR-0035 decision 6).
#[test]
fn service_run_log_files_have_an_owner_only_mode() {
    let sandbox = bound_sandbox("serve");
    let child = RunChild::spawn(&sandbox, &["service", "run", "serve"]);
    poll_until("serve banner", WAIT, || {
        log_text(&sandbox, "serve.err.log")?
            .contains("listening on")
            .then_some(())
    });
    let _ = child.stop();
    let dir = sandbox.state_dir().join("log");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["serve.out.log", "serve.err.log"] {
            assert_eq!(
                std::fs::metadata(dir.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "{name}"
            );
        }
    }
    #[cfg(windows)]
    {
        crate::release_smoke::assert_account_only(&dir);
        for name in ["serve.out.log", "serve.err.log"] {
            crate::release_smoke::assert_account_only(&dir.join(name));
        }
    }
}

#[test]
fn service_run_reports_a_log_it_cannot_open_on_the_original_stderr() {
    let sandbox = bound_sandbox("serve");
    // A file where the log directory belongs: nothing can be redirected.
    std::fs::write(sandbox.state_dir().join("log"), b"in the way").unwrap();
    let output = sandbox.qsh(&["service", "run", "serve"]);
    assert_eq!(common::exit_code(&output), 255);
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("log"), "{stderr}");
}

#[test]
fn service_run_takes_a_closed_mode_set_and_a_controller_for_reverse_only() {
    let sandbox = Sandbox::initialized();
    for args in [
        &["service", "run"][..],
        &["service", "run", "bogus"],
        &["service", "run", "reverse"],
        &["service", "run", "serve", "ctrl"],
    ] {
        let output = sandbox.qsh(args);
        assert_eq!(common::exit_code(&output), 2, "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    // No log was opened for any of them.
    assert!(!sandbox.state_dir().join("log").exists());
}
