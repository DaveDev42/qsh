//! The commands a platform-neutral test runs on the host it drives: an
//! interactive shell, a program that copies its stdin to its stdout, a
//! program that outlives the test unless it is killed. Each answers with the
//! program the platform has (`sh`, `cat`, `sleep` on unix; `cmd`, `findstr`,
//! `ping` on Windows) so one test body serves both.

/// The line terminator a terminal sends for Enter: what a PTY-backed shell
/// needs to run the line before it.
#[cfg(unix)]
pub const ENTER: &str = "\n";
/// See the unix definition.
#[cfg(windows)]
pub const ENTER: &str = "\r\n";

/// An interactive command interpreter for a PTY session.
pub fn pty_shell() -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["sh".to_string()]
    }
    #[cfg(windows)]
    {
        vec!["cmd".to_string()]
    }
}

/// The line that makes an interactive shell print `tag` followed by a value
/// it computes itself, so the shell's echo of the line (which holds `tag` but
/// not the value) is never mistaken for the answer. See [`said`].
pub fn say(tag: &str) -> Vec<u8> {
    #[cfg(unix)]
    let line = format!("printf '{tag}%s\\n' 1\n");
    #[cfg(windows)]
    let line = format!("echo {tag}%OS%\r\n");
    line.into_bytes()
}

/// What the shell prints in answer to [`say`].
pub fn said(tag: &str) -> String {
    #[cfg(unix)]
    {
        format!("{tag}1")
    }
    #[cfg(windows)]
    {
        format!("{tag}Windows_NT")
    }
}

/// A program that copies its stdin to its stdout and exits `0` at the end of
/// stdin (`cat`; `findstr "^"` matches every line).
pub fn cat_argv() -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["cat".to_string()]
    }
    #[cfg(windows)]
    {
        vec!["findstr".to_string(), "^".to_string()]
    }
}

/// A program that prints nothing and keeps running for about half a minute
/// (`sleep 30`; `ping -n 30` against loopback, which sends one probe a
/// second).
pub fn idle_argv() -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["sleep".to_string(), "30".to_string()]
    }
    #[cfg(windows)]
    {
        ["ping", "-n", "30", "127.0.0.1"].map(String::from).to_vec()
    }
}

/// A program that exits `0` at once (`true`; `cmd /c exit 0`).
pub fn true_argv() -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["true".to_string()]
    }
    #[cfg(windows)]
    {
        ["cmd", "/c", "exit", "0"].map(String::from).to_vec()
    }
}

/// A program that reads one line, prints `prefix` and the line, and exits
/// with `code`.
pub fn read_line_then_exit(prefix: &str, code: i32) -> Vec<String> {
    #[cfg(unix)]
    {
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("read line; printf '{prefix}%s\\n' \"$line\"; exit {code}"),
        ]
    }
    #[cfg(windows)]
    {
        vec![
            "cmd".to_string(),
            "/v:on".to_string(),
            "/c".to_string(),
            format!("set line=& set /p line=& echo {prefix}!line!& exit {code}"),
        ]
    }
}

/// A program that answers every line it reads with `prefix` and the line,
/// until it is stopped. An empty line (the second half of a `\r\n` Enter on
/// Windows) is not answered.
pub fn line_echo_loop(prefix: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("while IFS= read -r line; do printf '{prefix}%s\\n' \"$line\"; done"),
        ]
    }
    #[cfg(windows)]
    {
        vec![
            "cmd".to_string(),
            "/v:on".to_string(),
            "/c".to_string(),
            format!(
                "for /l %i in (1,1,1000000) do @(set line=& set /p line=& if defined line echo {prefix}!line!)"
            ),
        ]
    }
}

use std::path::{Path, PathBuf};
use std::time::Duration;

/// A remote command that outlives the test unless the host kills it, and the
/// two observations a test needs of it: it has started, and it is gone.
///
/// unix: `sh` records its pid in the marker file and `exec`s the program, so
/// the pid names the very process that must disappear; `kill -0` tells
/// whether it lives. Windows: `cmd` runs the program with stderr redirected
/// to the marker file, which the program (and `cmd` itself) holds open
/// without delete sharing. The file exists once the command runs and can be
/// deleted only after the whole tree is gone.
pub struct Runaway {
    marker: PathBuf,
}

impl Runaway {
    /// A runaway whose marker (and scratch files) live in `dir`.
    pub fn new(dir: &Path) -> Self {
        Self {
            marker: dir.join("runaway-marker"),
        }
    }

    /// Runs for a minute and prints nothing.
    pub fn silent_argv(&self) -> Vec<String> {
        #[cfg(unix)]
        {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("echo $$ > {} ; exec sleep 60", self.marker.display()),
            ]
        }
        #[cfg(windows)]
        {
            let marker = format!("2>{}", self.marker.display());
            [
                "cmd",
                "/c",
                "(ping",
                "-n",
                "120",
                "127.0.0.1)",
                marker.as_str(),
            ]
            .map(String::from)
            .to_vec()
        }
    }

    /// Prints more than the client's output cap at once and then keeps
    /// running (unix: `yes` never stops; Windows: `type` of a file larger
    /// than the cap, then `ping`).
    pub fn noisy_argv(&self, cap: usize) -> Vec<String> {
        #[cfg(unix)]
        {
            let _ = cap;
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!(
                    "echo $$ > {} ; exec yes 0123456789abcdef",
                    self.marker.display()
                ),
            ]
        }
        #[cfg(windows)]
        {
            let big = self.marker.with_file_name("runaway-output.txt");
            let line = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n";
            let mut bytes = Vec::with_capacity(cap + 2 * line.len());
            while bytes.len() <= cap + line.len() {
                bytes.extend_from_slice(line);
            }
            std::fs::write(&big, bytes).expect("write the output the cap must stop");
            let marker = format!("2>{}", self.marker.display());
            let big = big.display().to_string();
            [
                "cmd",
                "/c",
                "(type",
                big.as_str(),
                "&",
                "ping",
                "-n",
                "120",
                "127.0.0.1)",
                marker.as_str(),
            ]
            .map(String::from)
            .to_vec()
        }
    }

    /// The command has started and left its mark.
    pub async fn wait_running(&self, within: Duration) {
        tokio::time::timeout(within, async {
            loop {
                #[cfg(unix)]
                let started = std::fs::read_to_string(&self.marker)
                    .is_ok_and(|text| text.trim().parse::<u32>().is_ok());
                #[cfg(windows)]
                let started = self.marker.exists();
                if started {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the child must start within {within:?}"));
    }

    /// The command (on Windows, its whole tree) no longer runs.
    pub async fn wait_gone(&self, within: Duration) {
        tokio::time::timeout(within, async {
            loop {
                #[cfg(unix)]
                let gone = {
                    let pid = std::fs::read_to_string(&self.marker)
                        .expect("the pid file")
                        .trim()
                        .parse::<u32>()
                        .expect("a pid");
                    !tokio::process::Command::new("kill")
                        .args(["-0", &pid.to_string()])
                        .status()
                        .await
                        .expect("run kill -0")
                        .success()
                };
                #[cfg(windows)]
                let gone = std::fs::remove_file(&self.marker).is_ok();
                if gone {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the child must be gone within {within:?}"));
    }
}
