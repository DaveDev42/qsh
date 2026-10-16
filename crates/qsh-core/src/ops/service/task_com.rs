//! The Task Scheduler COM reader (ADR-0035 decisions 27 and 28):
//! `ITaskService` -> `IRegisteredTask`, for the definition's principal
//! ([`TaskDefinitionReader`]) and for the run state ([`TaskStateQuery`],
//! ADR-0032 decision 3). No process is started and no output is parsed; the
//! answers are the `TASK_LOGON_TYPE` and the `TASK_STATE` the scheduler itself
//! reports.
//!
//! COM state belongs to a thread, so every read runs on a thread of its own
//! that initializes COM, drops every interface it took, and uninitializes
//! before it ends. A runtime worker's COM state is never touched.

use qsh_proto::ErrorCode;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{
    IRegisteredTask, ITaskService, TASK_LOGON_INTERACTIVE_TOKEN, TASK_LOGON_PASSWORD,
    TASK_LOGON_TYPE, TASK_STATE_RUNNING, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, HRESULT};

use super::manager::TaskStateQuery;
use super::task::{TaskDefinitionReader, TaskLogonType};
use crate::ops::OpError;

/// The production [`TaskDefinitionReader`] and [`TaskStateQuery`], over the
/// local Task Scheduler.
pub struct ComTaskScheduler;

impl TaskDefinitionReader for ComTaskScheduler {
    fn logon_type(&self, task_name: &str) -> Result<Option<TaskLogonType>, OpError> {
        read_on_com_thread(task_name, |task| {
            let mut logon = TASK_LOGON_TYPE(0);
            // SAFETY: COM method calls on interfaces owned here, with an
            // out-pointer to a local that outlives the call.
            unsafe {
                task.Definition()?.Principal()?.LogonType(&mut logon)?;
            }
            Ok(if logon == TASK_LOGON_INTERACTIVE_TOKEN {
                TaskLogonType::InteractiveToken
            } else if logon == TASK_LOGON_PASSWORD {
                TaskLogonType::Password
            } else {
                TaskLogonType::Other
            })
        })
    }
}

impl TaskStateQuery for ComTaskScheduler {
    /// A task that is not registered is not running, so an absent name is
    /// `Ok(false)`.
    fn is_running(&self, task_name: &str) -> Result<bool, OpError> {
        read_on_com_thread(task_name, |task| {
            // SAFETY: a COM method call on an interface owned by the caller.
            let state = unsafe { task.State()? };
            Ok(state == TASK_STATE_RUNNING)
        })
        .map(|running| running.unwrap_or(false))
    }
}

/// Runs `read` against the registered task `task_name` on a COM thread of its
/// own. `Ok(None)` when the task is not registered.
fn read_on_com_thread<T: Send>(
    task_name: &str,
    read: impl FnOnce(&IRegisteredTask) -> windows::core::Result<T> + Send,
) -> Result<Option<T>, OpError> {
    let outcome =
        std::thread::scope(|scope| scope.spawn(|| read_registered(task_name, read)).join());
    match outcome {
        Ok(Ok(found)) => Ok(found),
        Ok(Err(err)) => Err(com_error(task_name, &err)),
        Err(_) => Err(OpError::new(
            ErrorCode::Internal,
            "the Task Scheduler read thread panicked",
        )
        .with_retryable(false)),
    }
}

fn com_error(task_name: &str, err: &windows::core::Error) -> OpError {
    OpError::new(
        ErrorCode::Internal,
        format!(
            "the Task Scheduler could not be read for `{task_name}` (HRESULT {:#010x}): {}",
            err.code().0,
            err.message()
        ),
    )
    .with_retryable(false)
}

/// Whether `code` says the task (or its folder) is not there, which is an
/// answer ("not registered") and not a failure to read.
fn is_absent(code: HRESULT) -> bool {
    code == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0)
        || code == HRESULT::from_win32(ERROR_PATH_NOT_FOUND.0)
}

fn read_registered<T>(
    task_name: &str,
    read: impl FnOnce(&IRegisteredTask) -> windows::core::Result<T>,
) -> windows::core::Result<Option<T>> {
    // SAFETY: plain COM initialization on this thread; it is undone below on
    // every path after the interfaces taken in `read_task` are gone.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
    let result = read_task(task_name, read);
    // SAFETY: balances the successful `CoInitializeEx` above on this thread.
    unsafe { CoUninitialize() };
    result
}

fn read_task<T>(
    task_name: &str,
    read: impl FnOnce(&IRegisteredTask) -> windows::core::Result<T>,
) -> windows::core::Result<Option<T>> {
    // SAFETY: every call below is a COM method call on an interface this
    // function owns, with arguments that outlive the call. The interfaces
    // drop at the end of the function, before `CoUninitialize`.
    unsafe {
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
        let none = VARIANT::default();
        service.Connect(&none, &none, &none, &none)?;
        let root = service.GetFolder(&BSTR::from("\\"))?;
        let task = match root.GetTask(&BSTR::from(task_name)) {
            Ok(task) => task,
            Err(err) if is_absent(err.code()) => return Ok(None),
            Err(err) => return Err(err),
        };
        read(&task).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A task that is not registered is an answer, not a failure: the read
    /// returns `Ok(None)` for a name in a folder that does not exist and for
    /// a name at the root alike. Read-only; nothing is registered.
    #[test]
    fn com_reader_reports_a_missing_task_as_absent() {
        for name in [
            r"\qsh-no-such-folder\qsh-serve",
            r"\qsh-no-such-task-at-the-root",
        ] {
            assert_eq!(ComTaskScheduler.logon_type(name).unwrap(), None, "{name}");
        }
    }

    /// The run-state query answers "not running" for a task that is not
    /// registered, and creates nothing: the same names are still absent after
    /// it. Read-only; no task is ever registered by a test.
    #[test]
    fn task_state_query_reports_an_unregistered_task_as_not_running() {
        for name in [
            r"\qsh-no-such-folder\qsh-serve",
            r"\qsh-no-such-task-at-the-root",
        ] {
            assert!(!ComTaskScheduler.is_running(name).unwrap(), "{name}");
            assert_eq!(ComTaskScheduler.logon_type(name).unwrap(), None, "{name}");
        }
    }
}
