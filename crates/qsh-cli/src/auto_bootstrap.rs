//! The frontend half of the automatic bootstrap (ADR-0044 decision 2): print
//! the one-line notice, run `Ops::auto_bootstrap`, print what `qsh pair ssh`
//! would have printed, and hand the outcome back to the command that was
//! about to connect.
//!
//! Everything that decides anything is `qsh-core`'s
//! (`Ops::should_auto_bootstrap`, `Ops::auto_bootstrap`). This module sits
//! before `tui::run` and `Ops::file_copy` so that ssh runs, with the
//! person's terminal and its prompts, before raw mode is entered
//! (decision 16) and before any connection is opened. Every line goes to
//! stderr; no envelope is written and stdout is untouched (the automatic
//! path never runs in a machine mode, and `qsh [user@]host` has no machine
//! mode at all).
//!
//! The same on Windows: the ssh child inherits the console, which stays in
//! cooked mode until `tui::run` switches it, and the first interrupt ends
//! the child through the cancel token (ADR-0035 decision 1).

use std::io::{self, IsTerminal};

use qsh_core::{AutoBootstrap, CancelToken, OpError, Ops, PairSshEnv};

use crate::render::human;

/// Write the notice, run the bootstrap and report its notices. `Ok` means
/// the pins stand and the original command should run. The first interrupt
/// ends the ssh child through `cancel`; the caller owns the interrupt
/// handling (`arm_cancel_on_interrupt`, or [`InterruptScope`]).
pub(crate) fn run(
    ops: &Ops,
    plan: &AutoBootstrap,
    cancel: CancelToken,
    quiet: bool,
) -> Result<(), OpError> {
    // Always printed, `--quiet` included: a person must learn that ssh is
    // about to run, and how to switch that off, before it asks for anything.
    let _ = human::print_notice(&plan.notice());
    let report = ops.auto_bootstrap(
        plan,
        PairSshEnv {
            machine_mode: false,
            stdin_is_terminal: io::stdin().is_terminal(),
            cancel,
        },
    );
    if !quiet {
        for line in &report.notices {
            let _ = human::print_notice(line);
        }
    }
    report.result
}

/// Cancels a token on the first SIGINT and ends the process on the second,
/// like `arm_cancel_on_interrupt`, but only while the guard lives. The
/// interactive form needs the scope: once the bootstrap is over, its raw-mode
/// driver owns SIGINT (it forwards an external one as the `^C` byte), and a
/// listener left behind would end the client on the second one.
pub(crate) struct InterruptScope {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl InterruptScope {
    pub(crate) fn new(cancel: &CancelToken) -> Self {
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async {
                tokio::select! {
                    interrupted = tokio::signal::ctrl_c() => {
                        if interrupted.is_err() {
                            return;
                        }
                        cancel.cancel();
                    }
                    _ = &mut stopped => return,
                }
                tokio::select! {
                    interrupted = tokio::signal::ctrl_c() => {
                        if interrupted.is_ok() {
                            std::process::exit(crate::EXIT_RUNTIME_FAILURE);
                        }
                    }
                    _ = &mut stopped => {}
                }
            });
        });
        Self { stop: Some(stop) }
    }
}

impl Drop for InterruptScope {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
