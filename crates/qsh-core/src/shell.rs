//! Which shell runs a `shell_command` on this host (ADR-0051 decision 6,
//! `docs/design/protocol.md` §7.1).
//!
//! `qsh host command...` sends the words joined with spaces as one string,
//! the way `ssh` does, and the host hands that string to the account's own
//! shell. The pieces here are pure so every platform's rule is unit-tested on
//! every platform; the spawn code that uses them lives in `exec/` and
//! `pty/`.
//!
//! - **unix**: the account's login shell from the password database with
//!   `-c <string>`, `/bin/sh` when the entry names no executable
//!   (`pty::posix`'s `Account::login_shell`, the same fallback `sshd`
//!   uses).
//! - **Windows**: Win32-OpenSSH's rule. `HKLM\SOFTWARE\OpenSSH\DefaultShell`
//!   names the shell and `DefaultShellCommandOption` its command switch
//!   (default `/c`); with no `DefaultShell` the command runs as
//!   `cmd.exe /c <string>`. The string reaches the shell as the raw tail of
//!   the command line, not quoted as one argument: `cmd.exe` does not undo
//!   the C runtime's quoting.
//!
//! The string is the user's command. It is never logged: [`ShellRequest`]'s
//! `Debug` prints its length only, and audit records have no field for it.

use std::fmt;

/// What the host asked its shell to do.
#[derive(Clone, PartialEq, Eq)]
pub enum ShellRequest {
    /// Run this string (`shell -c <string>`).
    Command(String),
    /// The login shell itself (`qsh -T host`), no `-c`.
    Login,
}

impl fmt::Debug for ShellRequest {
    /// Length only. A derived `Debug` would put the user's command into
    /// whatever log line formats the surrounding spec.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(command) => write!(f, "Command(<{} bytes>)", command.len()),
            Self::Login => f.write_str("Login"),
        }
    }
}

/// The `-c` form of [`ShellRequest`] on unix: `[shell, "-c", command]`, or
/// `[shell]` for the login shell.
pub fn unix_argv(shell: &str, request: &ShellRequest) -> Vec<String> {
    match request {
        ShellRequest::Command(command) => {
            vec![shell.to_string(), "-c".to_string(), command.clone()]
        }
        ShellRequest::Login => vec![shell.to_string()],
    }
}

/// The two Win32-OpenSSH registry values, as read (or not) from
/// `HKLM\SOFTWARE\OpenSSH`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultShellConfig {
    /// `DefaultShell`.
    pub default_shell: Option<String>,
    /// `DefaultShellCommandOption`.
    pub command_option: Option<String>,
}

/// The switch Win32-OpenSSH uses when `DefaultShellCommandOption` is unset.
pub const WINDOWS_DEFAULT_COMMAND_OPTION: &str = "/c";

/// A resolved Windows shell: the program and the switch before the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsShell {
    /// Path or name of the shell program.
    pub program: String,
    /// Switch that precedes the command string.
    pub option: String,
}

impl DefaultShellConfig {
    /// Pick the shell. A blank value counts as unset, like a missing one.
    /// `cmd_exe` is the full path of `cmd.exe` the host would use anyway
    /// (`COMSPEC`, else `<SystemRoot>\System32\cmd.exe`).
    pub fn windows_shell(&self, cmd_exe: &str) -> WindowsShell {
        let set = |value: &Option<String>| {
            value
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        match set(&self.default_shell) {
            Some(program) => WindowsShell {
                program,
                option: set(&self.command_option)
                    .unwrap_or_else(|| WINDOWS_DEFAULT_COMMAND_OPTION.to_string()),
            },
            None => WindowsShell {
                program: cmd_exe.to_string(),
                option: WINDOWS_DEFAULT_COMMAND_OPTION.to_string(),
            },
        }
    }
}

impl WindowsShell {
    /// The `CreateProcessW` command line: the program quoted, then the
    /// switch, then the command string verbatim. The login shell is the
    /// program alone.
    pub fn command_line(&self, request: &ShellRequest) -> String {
        // A path cannot contain `"`, so wrapping in quotes is always whole.
        let program = format!("\"{}\"", self.program.trim_matches('"'));
        match request {
            ShellRequest::Command(command) => format!("{program} {} {command}", self.option),
            ShellRequest::Login => program,
        }
    }
}

/// Shape check shared by the exec and session handlers: the string must be
/// something a process can be started with.
pub fn validate_command(command: &str) -> Result<(), &'static str> {
    if command.contains('\0') {
        return Err("shell_command must not contain NUL");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: &str = r"C:\Windows\System32\cmd.exe";

    fn cmd(s: &str) -> ShellRequest {
        ShellRequest::Command(s.to_string())
    }

    #[test]
    fn unix_runs_the_string_with_dash_c_and_the_login_shell_bare() {
        assert_eq!(
            unix_argv("/bin/zsh", &cmd("echo \"$HOME\" | wc -c && true")),
            ["/bin/zsh", "-c", "echo \"$HOME\" | wc -c && true"]
        );
        assert_eq!(unix_argv("/bin/zsh", &ShellRequest::Login), ["/bin/zsh"]);
        // The empty string is a command (`ssh host ''`), not "no command".
        assert_eq!(unix_argv("/bin/sh", &cmd("")), ["/bin/sh", "-c", ""]);
    }

    #[test]
    fn windows_without_registry_values_is_cmd_exe_slash_c() {
        let shell = DefaultShellConfig::default().windows_shell(CMD);
        assert_eq!(
            shell,
            WindowsShell {
                program: CMD.into(),
                option: "/c".into()
            }
        );
        assert_eq!(
            shell.command_line(&cmd(r#"echo "a b" & dir"#)),
            r#""C:\Windows\System32\cmd.exe" /c echo "a b" & dir"#
        );
    }

    #[test]
    fn windows_default_shell_uses_its_option_or_slash_c() {
        let pwsh = r"C:\Program Files\PowerShell\7\pwsh.exe";
        let with_option = DefaultShellConfig {
            default_shell: Some(pwsh.into()),
            command_option: Some("-Command".into()),
        }
        .windows_shell(CMD);
        assert_eq!(with_option.program, pwsh);
        assert_eq!(with_option.option, "-Command");
        assert_eq!(
            with_option.command_line(&cmd("Get-Date")),
            format!("\"{pwsh}\" -Command Get-Date")
        );

        let no_option = DefaultShellConfig {
            default_shell: Some(pwsh.into()),
            command_option: None,
        }
        .windows_shell(CMD);
        assert_eq!(no_option.option, "/c");
    }

    #[test]
    fn windows_blank_registry_values_count_as_unset() {
        let blank = DefaultShellConfig {
            default_shell: Some("  ".into()),
            command_option: Some("-x".into()),
        };
        // No shell: the option is ignored too, as it names the shell's switch.
        assert_eq!(
            blank.windows_shell(CMD),
            DefaultShellConfig::default().windows_shell(CMD)
        );
        let blank_option = DefaultShellConfig {
            default_shell: Some(r"C:\bash.exe".into()),
            command_option: Some("".into()),
        };
        assert_eq!(blank_option.windows_shell(CMD).option, "/c");
    }

    #[test]
    fn windows_login_shell_is_the_program_alone() {
        let shell = DefaultShellConfig::default().windows_shell(CMD);
        assert_eq!(
            shell.command_line(&ShellRequest::Login),
            r#""C:\Windows\System32\cmd.exe""#
        );
    }

    #[test]
    fn debug_never_prints_the_command() {
        let shown = format!("{:?}", cmd("curl -H 'Authorization: secret' x"));
        assert!(!shown.contains("secret"), "{shown}");
        assert_eq!(shown, "Command(<33 bytes>)");
    }

    #[test]
    fn nul_is_refused() {
        assert!(validate_command("a\0b").is_err());
        assert!(validate_command("").is_ok());
    }
}
