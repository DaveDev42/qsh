//! The Windows Task Scheduler row of `qsh service` (ADR-0035 decision 27):
//! the task definition renderer, its file encoding, and the seam the doctor
//! reads a registered task's principal through.
//!
//! The renderer is a plain function of the mode, the binary path, the
//! controller literal and the user's SID, with no `cfg`, so the Windows rows
//! of `tests.rs` and the `docs/deploy/service.md` fence comparison run on
//! every build target (ADR-0032 decision 10, the same rule the launchd and
//! systemd renderers follow).
//!
//! The definition is fixed. `qsh service run <mode>` is the one action
//! (`run.rs` explains why a console executable needs it), the trigger is the
//! current user's logon, and the principal is that user's `InteractiveToken`
//! with `LeastPrivilege`, so no password is ever stored. Two settings carry
//! measurements taken on Windows 11 (`docs/deploy/service.md`, Windows):
//!
//! - `RestartOnFailure` alone did not start the action again after a
//!   non-zero exit or a crash, so the logon trigger also repeats every
//!   minute with no end. `MultipleInstancesPolicy=IgnoreNew` turns a tick
//!   that lands while the action still runs into a no-op, which leaves one
//!   process and a restart within a minute of a death.
//! - `schtasks /Create /XML` rejected a UTF-8 file that declared its
//!   encoding and accepted a UTF-16 one, so the text declares UTF-16 and
//!   [`encode_task_file`] writes UTF-16 little-endian with a byte order mark.

use crate::ops::OpError;

use super::manager::TaskStateQuery;
use super::{mode_description, xml_escape};

/// The example binary path `docs/deploy/service.md`'s Windows fences show.
/// Production passes `std::env::current_exe()`; only the doc-contract test
/// passes this.
pub const DOC_EXAMPLE_EXE_WINDOWS: &str = r"C:\Users\YOU\.local\bin\qsh.exe";
/// The example SID `docs/deploy/service.md`'s Windows fences show in place of
/// the current user's.
pub const DOC_EXAMPLE_USER_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

/// Quotes `s` for a Windows command line (`CommandLineToArgvW` rules) when it
/// holds whitespace or a quote, and otherwise returns it unchanged, so the
/// common case renders exactly as typed. Without this a controller literal
/// with whitespace would split `Arguments` into extra argv elements.
fn windows_quote(s: &str) -> String {
    if s.is_empty() || s.chars().any(|c| c.is_whitespace() || c == '"') {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        let mut backslashes = 0usize;
        for c in s.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    // Backslashes before a quote double, and the quote itself
                    // is escaped.
                    out.push_str(&"\\".repeat(backslashes * 2 + 1));
                    out.push('"');
                    backslashes = 0;
                }
                _ => {
                    out.push_str(&"\\".repeat(backslashes));
                    out.push(c);
                    backslashes = 0;
                }
            }
        }
        // Backslashes before the closing quote double so they cannot escape it.
        out.push_str(&"\\".repeat(backslashes * 2));
        out.push('"');
        out
    } else {
        s.to_string()
    }
}

/// The fixed arguments after `<EXE>`: `service run <mode>`, and the controller
/// literal after `reverse`, the same rule `mode_argv` applies to the launchd
/// and systemd units (the literal is frozen at install time and never reaches
/// a manager command line).
fn task_arguments(mode: &str, controller: &str) -> String {
    let mut args = format!("service run {mode}");
    if mode == "reverse" {
        args.push(' ');
        args.push_str(&windows_quote(controller));
    }
    args
}

/// The Task Scheduler task definition for `(mode)` at `exe` for the user
/// `user_sid`: a `LogonTrigger` that repeats every minute, an
/// `InteractiveToken`/`LeastPrivilege` principal, `IgnoreNew`, no execution
/// time limit, no battery conditions and `RestartOnFailure` (1 minute).
/// `controller` is only used when `mode == "reverse"`. Everything
/// interpolated is XML-escaped, and the path and the controller are quoted
/// for the command line when they hold whitespace.
pub fn render_windows_task(mode: &str, exe: &str, controller: &str, user_sid: &str) -> String {
    let command = xml_escape(&windows_quote(exe));
    let arguments = xml_escape(&task_arguments(mode, controller));
    let description = mode_description(mode);
    let sid = xml_escape(user_sid);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">
  <RegistrationInfo>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{sid}</UserId>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id=\"Author\">
      <UserId>{sid}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context=\"Author\">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"
    )
}

/// The bytes of the task definition file: UTF-16 little-endian with a byte
/// order mark, the encoding the text declares and `schtasks /Create /XML`
/// accepts. Line endings stay `\n`, as the renderer produced them.
pub fn encode_task_file(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + text.len() * 2);
    out.extend_from_slice(&[0xFF, 0xFE]);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// The principal of a registered task, as far as `qsh doctor` tells them
/// apart (`TASK_LOGON_TYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskLogonType {
    /// `TASK_LOGON_INTERACTIVE_TOKEN`: runs only while the user is logged on.
    /// What `qsh service install` writes.
    InteractiveToken,
    /// `TASK_LOGON_PASSWORD`: a stored password, so the task can run with
    /// nobody logged on. The always-on variant of `docs/deploy/service.md`.
    Password,
    /// Any other principal (S4U, service account, group, token-or-password).
    Other,
}

/// The definition-side read of the Task Scheduler (ADR-0035 decision 27): a
/// task name in, whether it is registered and under which principal out. The
/// Windows implementation reads the COM API (`ITaskService` ->
/// `IRegisteredTask` -> the definition's principal) and starts no process.
/// Tests inject a fake; a production run on any other OS never calls it.
pub trait TaskDefinitionReader: Send + Sync {
    /// `Ok(None)` when no task named `task_name` (for example
    /// `\qsh\qsh-serve`) is registered, `Ok(Some(_))` with its principal when
    /// one is, and `Err` when the Task Scheduler could not be read, in which
    /// case the doctor reports nothing about the task.
    fn logon_type(&self, task_name: &str) -> Result<Option<TaskLogonType>, OpError>;
}

/// The reader of every host that has no Task Scheduler, and of the doctor
/// entry that takes its host state by value: it reads nothing, for the
/// principal and for the run state alike.
pub struct UnreadableTaskScheduler;

impl TaskDefinitionReader for UnreadableTaskScheduler {
    fn logon_type(&self, _task_name: &str) -> Result<Option<TaskLogonType>, OpError> {
        Err(OpError::new(
            qsh_proto::ErrorCode::Unsupported,
            "the Task Scheduler is not available on this platform",
        )
        .with_retryable(false))
    }
}

impl TaskStateQuery for UnreadableTaskScheduler {
    fn is_running(&self, _task_name: &str) -> Result<bool, OpError> {
        Err(OpError::new(
            qsh_proto::ErrorCode::Unsupported,
            "the Task Scheduler is not available on this platform",
        )
        .with_retryable(false))
    }
}
