//! What the root form `qsh [ssh options] [user@]host [command...]` does,
//! decided from its flags (ADR-0051 decisions 6 and 7).
//!
//! The frontend parses the flags and runs the mode this returns; the
//! combination rules (which flags exclude each other, which are not
//! available yet) live here, so every frontend gives the same answer.

use qsh_proto::ErrorCode;

use crate::ops::{ExecCommand, OpError};

/// The flags that decide the mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FormInput {
    /// The words after the host.
    pub command: Vec<String>,
    /// How many times `-t` was given.
    pub force_tty: u8,
    /// `-T`.
    pub no_tty: bool,
    /// `-N`.
    pub no_command: bool,
    /// `-f`.
    pub background: bool,
    /// Whether any `-L`, `-R` or `-D` was given.
    pub has_forwards: bool,
}

/// What the form runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormMode {
    /// A PTY session. `argv` is empty for the login shell, otherwise the
    /// program of `-t host command`.
    Interactive {
        /// The session program; empty = login shell.
        argv: Vec<String>,
    },
    /// A command without a PTY, through the `exec` path.
    Exec(ExecCommand),
    /// `-N`: only the forwards.
    Forwards {
        /// `-f`: go to the background once the forwards stand.
        background: bool,
    },
}

/// Decide the mode.
///
/// - No command: a PTY session (`-T`: the login shell without a PTY).
/// - A command: `exec` by default, a PTY session with `-t`/`-tt`.
/// - `-N` needs a forward and no command. `-f` needs `-N`; backgrounding a
///   command needs a streaming exec and is `UNSUPPORTED` for now.
/// - Forwards next to a command that runs without a PTY have no holder and
///   are `UNSUPPORTED`; `-t` or `-N` say which of the two was meant.
pub fn plan_form(input: &FormInput) -> Result<FormMode, OpError> {
    if input.force_tty > 0 && input.no_tty {
        return Err(invalid("-t and -T do not combine"));
    }
    if input.no_command {
        if !input.command.is_empty() {
            return Err(invalid("-N runs no command, but a command was given"));
        }
        if !input.has_forwards {
            return Err(invalid("-N needs at least one of -L, -R or -D"));
        }
        return Ok(FormMode::Forwards {
            background: input.background,
        });
    }
    if input.background {
        return Err(OpError::new(
            ErrorCode::Unsupported,
            "-f is supported with -N only (backgrounding a command is not implemented yet)",
        )
        .with_retryable(false));
    }
    if input.command.is_empty() {
        return Ok(if input.no_tty {
            if input.has_forwards {
                return Err(forwards_with_exec());
            }
            FormMode::Exec(ExecCommand::LoginShell)
        } else {
            FormMode::Interactive { argv: Vec::new() }
        });
    }
    let command = ExecCommand::shell_command(&input.command);
    if input.force_tty > 0 {
        return Ok(FormMode::Interactive {
            argv: command.wire_argv(),
        });
    }
    if input.has_forwards {
        return Err(forwards_with_exec());
    }
    Ok(FormMode::Exec(command))
}

fn invalid(message: &str) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message).with_retryable(false)
}

fn forwards_with_exec() -> OpError {
    OpError::new(
        ErrorCode::Unsupported,
        "-L, -R and -D next to a command without a PTY are not supported; use -t to run the \
         command in a session that holds them, or -N for forwards only",
    )
    .with_retryable(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> FormInput {
        FormInput::default()
    }

    fn cmd(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_string()).collect()
    }

    #[test]
    fn modes() {
        assert_eq!(
            plan_form(&input()).unwrap(),
            FormMode::Interactive { argv: vec![] }
        );
        assert_eq!(
            plan_form(&FormInput {
                no_tty: true,
                ..input()
            })
            .unwrap(),
            FormMode::Exec(ExecCommand::LoginShell)
        );
        assert_eq!(
            plan_form(&FormInput {
                command: cmd(&["ls", "-l", "/tmp"]),
                ..input()
            })
            .unwrap(),
            FormMode::Exec(ExecCommand::ShellCommand("ls -l /tmp".into()))
        );
        let FormMode::Interactive { argv } = plan_form(&FormInput {
            command: cmd(&["top"]),
            force_tty: 2,
            ..input()
        })
        .unwrap() else {
            panic!("-tt with a command is a PTY session");
        };
        assert!(!argv.is_empty());
        assert_eq!(
            plan_form(&FormInput {
                no_command: true,
                has_forwards: true,
                background: true,
                ..input()
            })
            .unwrap(),
            FormMode::Forwards { background: true }
        );
    }

    #[test]
    fn refusals() {
        let code = |i: FormInput| plan_form(&i).unwrap_err().code;
        assert_eq!(
            code(FormInput {
                force_tty: 1,
                no_tty: true,
                ..input()
            }),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            code(FormInput {
                no_command: true,
                ..input()
            }),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            code(FormInput {
                no_command: true,
                has_forwards: true,
                command: cmd(&["ls"]),
                ..input()
            }),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            code(FormInput {
                background: true,
                command: cmd(&["ls"]),
                ..input()
            }),
            ErrorCode::Unsupported
        );
        assert_eq!(
            code(FormInput {
                has_forwards: true,
                command: cmd(&["ls"]),
                ..input()
            }),
            ErrorCode::Unsupported
        );
    }
}
