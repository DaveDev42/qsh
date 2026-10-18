//! The unix half of host-side `exec.run`: a child in its own process group,
//! with the environment pinned from the password database
//! (`pty::pinned_identity_env`).

use std::process::Stdio;

use tokio::process::Command;

use super::{ExecSpec, SpawnFailure, Spawned, exit_status_parts, spawn_failure_code};

/// The spawned child. Dropping it kills the child (`kill_on_drop`).
pub(super) struct ExecChild(tokio::process::Child);

impl ExecChild {
    /// Kill the child and everything in its process group.
    pub(super) fn kill_tree(&mut self) {
        kill_group(&self.0);
        let _ = self.0.start_kill();
    }

    /// Wait for the child to end and report `(exit_code, signal)`. Safe to
    /// cancel and to call again: tokio caches the status.
    pub(super) async fn wait(&mut self) -> std::io::Result<(i32, Option<String>)> {
        self.0.wait().await.map(|status| exit_status_parts(&status))
    }
}

/// Start `program` with `args`; `spec` carries the caller's `env`.
pub(super) fn spawn_child(
    program: &str,
    args: &[String],
    spec: &ExecSpec,
) -> Result<Spawned, SpawnFailure> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Own process group so a timeout kill reaches the whole tree.
    cmd.process_group(0);

    // Environment hygiene (`docs/CLI.md`: `exec.run` does not implicitly
    // inherit the `qsh serve` process environment, and `HOME`/`USER`/
    // `LOGNAME`/`SHELL`/`PATH` are host-pinned on every path — the *values*
    // mirror `pty::posix::pinned_identity_env`, not its `build_env`'s
    // broader `TERM`/`LANG`/`LC_*` passthrough, which this path skips on
    // purpose, module docs in `exec/mod.rs`).
    let pinned = crate::pty::pinned_identity_env().map_err(|err| SpawnFailure {
        code: 126,
        message: format!("qsh: cannot resolve host account: {err}\n"),
    })?;
    cmd.env_clear();
    for (k, v) in &spec.env {
        // Same entry-shape filter as `pty::posix::build_env`: an `=` in
        // the key is not rejected by `Command::env` — it is emitted
        // verbatim into envp as a second `PATH=`/`HOME=`/... entry,
        // which a shell child resolves as an *override* of the pinned
        // one below (later envp entry wins). Filtering by exact key
        // name alone (`PINNED_ENV.contains`) does not catch that; the
        // key has to be valid first.
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            continue; // not a valid environment entry; drop silently
        }
        if crate::pty::PINNED_ENV.contains(&k.as_str()) {
            continue; // the caller cannot override a host-pinned key
        }
        cmd.env(k, v);
    }
    cmd.envs(pinned);

    let mut child = cmd.spawn().map_err(|err| SpawnFailure {
        code: spawn_failure_code(&err),
        message: format!("qsh: cannot execute {program:?}: {err}\n"),
    })?;
    let stdin = child.stdin.take().map(|s| Box::new(s) as _);
    let stdout = child.stdout.take().map(|s| Box::new(s) as _);
    let stderr = child.stderr.take().map(|s| Box::new(s) as _);
    Ok(Spawned {
        child: ExecChild(child),
        stdin,
        stdout,
        stderr,
    })
}

fn kill_group(child: &tokio::process::Child) {
    if let Some(pid) = child.id() {
        // SAFETY: killpg is async-signal-safe and only takes plain integers;
        // the pgid equals the child's pid because we spawned it with
        // `process_group(0)`.
        unsafe {
            libc::killpg(pid as libc::pid_t, libc::SIGKILL);
        }
    }
}
