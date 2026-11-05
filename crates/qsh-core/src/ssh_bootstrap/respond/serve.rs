//! The responder's answer to `commit.ensure_serve` (ADR-0051 decisions 1, 2
//! and 4): find or start the on-demand serve of this account and say where it
//! listens and whether it will outlive the ssh session that asked for it.

use std::path::Path;
use std::time::Duration;

use crate::config::Paths;
use crate::ops::OpError;
use crate::serve::detach::ensure_on_demand_serve;
use crate::serve::record::ServeRecordMode;

/// What the responder reports in the `result` after `ensure_serve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServeAnswer {
    /// The address in the serve's `serve.json` (`result.serve_bind`).
    pub bind: String,
    /// This call started the serve (`result.serve_started`).
    pub started: bool,
    /// The serve ends with the ssh session (`result.serve_session_scoped`).
    pub session_scoped: bool,
}

/// Find or start the serve (blocking: it polls `serve.json`; run it from a
/// blocking context).
///
/// `session_scoped` is only ever `true` for an on-demand serve. A serve that
/// a service manager runs (`persistent`) does not depend on the ssh session.
/// For an on-demand one, Windows says so when the Job Object refused
/// breakaway, which is known only for the serve this call started, and Linux
/// when logind would kill the account's processes at logout.
pub(super) fn ensure(
    paths: &Paths,
    program: &Path,
    timeout: Duration,
) -> Result<ServeAnswer, OpError> {
    let serve = ensure_on_demand_serve(paths, program, timeout)?;
    let on_demand = serve.record.mode == ServeRecordMode::OnDemand;
    let session_scoped = on_demand && (serve.breakaway_refused || logind_kills_user_processes());
    Ok(ServeAnswer {
        bind: serve.record.addr,
        started: serve.spawned,
        session_scoped,
    })
}

/// What `loginctl show-user` and `logind.conf` say about this account.
/// Only Linux asks; the parser is plain text handling and every platform
/// tests it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct LogindFacts {
    /// `KillUserProcesses=yes`, when the output says so at all.
    pub kill_user_processes: Option<bool>,
    /// `Linger=yes`, when the output says so at all.
    pub linger: Option<bool>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl LogindFacts {
    /// logind ends this account's processes when its last session closes:
    /// kills are on and linger is off. A missing linger line counts as off
    /// (an account that never ran `enable-linger` has none).
    pub(super) fn kills_at_logout(self) -> bool {
        self.kill_user_processes == Some(true) && self.linger != Some(true)
    }
}

/// Read `Key=value` lines of `loginctl show-user -p KillUserProcesses -p
/// Linger` (and the same keys of `logind.conf`). The first value of a key
/// wins for `show-user`, which prints each property once. `KillProcesses` is
/// the name some systemd versions print for the same property.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn parse_logind(text: &str) -> LogindFacts {
    let mut facts = LogindFacts::default();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = match value.trim().to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" | "on" => true,
            "no" | "false" | "0" | "off" => false,
            _ => continue,
        };
        match key.trim() {
            "KillUserProcesses" | "KillProcesses" if facts.kill_user_processes.is_none() => {
                facts.kill_user_processes = Some(value);
            }
            "Linger" if facts.linger.is_none() => facts.linger = Some(value),
            _ => {}
        }
    }
    facts
}

/// Linux: logind `KillUserProcesses=yes` with linger off. Anything that goes
/// wrong (no `loginctl`, no logind, a timeout) is `false`: the warning this
/// feeds is advice, and a missing tool must not produce a wrong one.
#[cfg(target_os = "linux")]
fn logind_kills_user_processes() -> bool {
    let Some(output) = run_loginctl() else {
        return false;
    };
    let mut facts = parse_logind(&output);
    if facts.kill_user_processes.is_none() {
        // `show-user` does not print the setting on every systemd; it is a
        // `logind.conf` option, so read it from there.
        facts.kill_user_processes = parse_logind_conf(&logind_conf_text());
    }
    facts.kills_at_logout()
}

#[cfg(not(target_os = "linux"))]
fn logind_kills_user_processes() -> bool {
    false
}

/// The last `KillUserProcesses=` assignment of `logind.conf` text.
#[cfg(target_os = "linux")]
fn parse_logind_conf(text: &str) -> Option<bool> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(value) = parse_logind(line).kill_user_processes {
            found = Some(value);
        }
    }
    found
}

/// `logind.conf` followed by its drop-ins in precedence order (later wins).
#[cfg(target_os = "linux")]
fn logind_conf_text() -> String {
    let mut text = String::new();
    let mut dropins = Vec::new();
    for dir in [
        "/usr/lib/systemd/logind.conf.d",
        "/run/systemd/logind.conf.d",
        "/etc/systemd/logind.conf.d",
    ] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            dropins.extend(
                entries
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "conf")),
            );
        }
    }
    if let Ok(main) = std::fs::read_to_string("/etc/systemd/logind.conf") {
        text.push_str(&main);
        text.push('\n');
    }
    dropins.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    for path in dropins {
        if let Ok(body) = std::fs::read_to_string(path) {
            text.push_str(&body);
            text.push('\n');
        }
    }
    text
}

/// `loginctl show-user $USER -p KillUserProcesses -p Linger`, bounded to a
/// few seconds. `None` when it is missing, fails or does not finish.
#[cfg(target_os = "linux")]
fn run_loginctl() -> Option<String> {
    use std::process::{Command, Stdio};

    // SAFETY: getuid(2) has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let user = std::env::var("USER")
        .ok()
        .filter(|user| !user.is_empty())
        .unwrap_or_else(|| uid.to_string());
    let child = Command::new("loginctl")
        .args([
            "show-user",
            &user,
            "-p",
            "KillUserProcesses",
            "-p",
            "Linger",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output = rx.recv_timeout(Duration::from_secs(3)).ok()?.ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_on_and_linger_off_kills_at_logout() {
        let facts = parse_logind("KillUserProcesses=yes\nLinger=no\n");
        assert!(facts.kills_at_logout());
        assert!(parse_logind("KillUserProcesses=yes\n").kills_at_logout());
    }

    #[test]
    fn linger_or_kill_off_survives_logout() {
        assert!(!parse_logind("KillUserProcesses=yes\nLinger=yes\n").kills_at_logout());
        assert!(!parse_logind("KillUserProcesses=no\nLinger=no\n").kills_at_logout());
        assert!(!parse_logind("Linger=no\n").kills_at_logout());
        assert!(!parse_logind("").kills_at_logout());
    }

    #[test]
    fn the_first_value_of_a_key_wins_and_noise_is_skipped() {
        let facts = parse_logind("garbage\nKillProcesses=yes\nKillProcesses=no\nLinger=maybe\n");
        assert_eq!(facts.kill_user_processes, Some(true));
        assert_eq!(facts.linger, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn logind_conf_last_assignment_wins_and_comments_do_not_count() {
        assert_eq!(parse_logind_conf("#KillUserProcesses=yes\n"), None);
        assert_eq!(
            parse_logind_conf("[Login]\nKillUserProcesses=yes\n\nKillUserProcesses=no\n"),
            Some(false)
        );
    }
}
