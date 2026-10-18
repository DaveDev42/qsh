//! The Windows console [`Terminal`] for the interactive client, and the
//! echo-suppressed input mode of the invitation-code prompt
//! (`docs/CLI.md` §7, ADR-0035 decisions 4-8 and 11).
//!
//! Keys are never parsed. Raw mode switches the console input to VT bytes
//! (`ENABLE_VIRTUAL_TERMINAL_INPUT`, the line editor, echo and the system
//! Ctrl-C handling off), the output to VT processing, and both code pages
//! to UTF-8; what the console then hands back from `ReadFile` goes to the
//! remote PTY unchanged, and `Ctrl-C` is the byte `0x03`. The mode
//! arithmetic is [`super::console_mode`].
//!
//! # Restoring
//!
//! Every way out puts the original modes and code pages back, through one
//! idempotent [`Restorer`]: the guard's `Drop` (normal and error exits), a
//! panic hook (a panic on any thread), and the console control handler
//! (`CTRL_BREAK`, window close, log off, shutdown). The saved values live in
//! the restorer, which a process-wide slot points at while a terminal state
//! is armed, because the hook and the handler own no guard.
//!
//! # Shutting a long-running process down
//!
//! `qsh listen`, `qsh serve` and `qsh serve --to` have no terminal session to
//! hang up. They arm [`arm_shutdown`] instead, and the same console control
//! handler then turns a window close, log off or shutdown (and `CTRL_BREAK`)
//! into a call of their notifier, so the process stops through the path
//! `Ctrl-C` takes. The system ends the process as soon as the handler
//! returns, so the handler waits for [`shutdown_finished`] (bounded by
//! [`SHUTDOWN_GRACE`]) before it does. `Ctrl-C` itself stays with the
//! runtime's own `ctrl_c`.
//!
//! # Seams
//!
//! The Win32 calls sit behind [`ConsoleApi`] and the resize poll's pause
//! behind [`Sleep`], so the logic here is compiled and tested on every CI
//! leg with fakes; the real implementations ([`system`]) exist on Windows
//! only. This file uses nothing outside `super`, `std`, `qsh-core` and
//! `qsh-proto` because `qsh-testkit`'s console probe includes it by path to
//! exercise the real code under a ConPTY.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::Duration;

use qsh_core::OpError;
use qsh_core::ops::CONSOLE_VT_UNAVAILABLE_MESSAGE;
use qsh_proto::ErrorCode;

use super::console_mode::{echo_suppressed_input_mode, raw_input_mode, raw_output_mode};
use super::terminal::{EventSource, HangupCause, RawGuard, TermEvent, Terminal};

/// `CTRL_C_EVENT`.
pub const CTRL_C_EVENT: u32 = 0;
/// `CTRL_BREAK_EVENT`.
pub const CTRL_BREAK_EVENT: u32 = 1;
/// `CTRL_CLOSE_EVENT`: the console window is closing.
pub const CTRL_CLOSE_EVENT: u32 = 2;
/// `CTRL_LOGOFF_EVENT`.
pub const CTRL_LOGOFF_EVENT: u32 = 5;
/// `CTRL_SHUTDOWN_EVENT`.
pub const CTRL_SHUTDOWN_EVENT: u32 = 6;

/// How long the console handler holds a closing window for a process armed
/// with [`arm_shutdown`] to finish stopping. Windows gives a closing
/// console process about five seconds, so this stays below that.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(4);

/// The UTF-8 code page.
pub const CP_UTF8: u32 = 65001;

/// How often the console window size is read (ADR-0035 decision 8). A
/// constant on purpose: there is no setting for it.
pub const RESIZE_POLL: Duration = Duration::from_millis(200);

/// The console calls the terminal needs, over the process's standard handles.
pub trait ConsoleApi: Send + Sync + 'static {
    /// The input mode, or `None` when stdin is not a console (a pipe, a
    /// file, a terminal that hands over a pipe such as mintty).
    fn input_mode(&self) -> Option<u32>;
    /// Set the console input mode.
    fn set_input_mode(&self, mode: u32) -> io::Result<()>;
    /// The output mode, or `None` when stdout is not a console.
    fn output_mode(&self) -> Option<u32>;
    /// Set the console output mode.
    fn set_output_mode(&self, mode: u32) -> io::Result<()>;
    /// The input and output code pages.
    fn code_pages(&self) -> (u32, u32);
    /// Set the input and output code pages.
    fn set_code_pages(&self, input: u32, output: u32) -> io::Result<()>;
    /// The window (`srWindow`) size in columns and rows.
    fn window_size(&self) -> Option<(u16, u16)>;
    /// One blocking read of stdin. `Ok(0)` is end of input.
    fn read_stdin(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Route console control events to [`on_console_event`]. Idempotent.
    fn install_ctrl_handler(&self) -> io::Result<()>;
}

/// The pause between two reads of the window size.
pub trait Sleep: Send + Sync + 'static {
    /// Block for `duration`.
    fn sleep(&self, duration: Duration);
}

/// What the console looked like before it was touched.
#[derive(Debug, Clone, Copy)]
struct Saved {
    input: Option<u32>,
    output: Option<u32>,
    code_pages: Option<(u32, u32)>,
}

/// Puts a saved console state back, once.
struct Restorer {
    api: Arc<dyn ConsoleApi>,
    saved: Mutex<Option<Saved>>,
}

impl Restorer {
    fn new(api: Arc<dyn ConsoleApi>) -> Arc<Self> {
        Arc::new(Self {
            api,
            saved: Mutex::new(None),
        })
    }

    /// Publish `saved` as the state to put back, and make this restorer the
    /// one the panic hook and the console handler act on.
    fn arm(self: &Arc<Self>, saved: Saved) {
        *self.saved.lock().unwrap_or_else(|e| e.into_inner()) = Some(saved);
        *ACTIVE.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(self));
        install_panic_hook();
    }

    /// Put the console back. Idempotent and callable from any thread: the
    /// first caller takes the saved state, the rest find nothing.
    fn restore(&self) {
        let saved = self.saved.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(saved) = saved else { return };
        // Modes first, then code pages; each is best effort, because there
        // is nothing better to do with a failure on the way out.
        if let Some(mode) = saved.input {
            let _ = self.api.set_input_mode(mode);
        }
        if let Some(mode) = saved.output {
            let _ = self.api.set_output_mode(mode);
        }
        if let Some((input, output)) = saved.code_pages {
            let _ = self.api.set_code_pages(input, output);
        }
    }
}

/// The restorer of the console state that is currently changed.
static ACTIVE: Mutex<Option<Arc<Restorer>>> = Mutex::new(None);

/// Where console control events go while a session is attached.
static EVENTS: Mutex<Option<Sender<TermEvent>>> = Mutex::new(None);

/// What a process armed with [`arm_shutdown`] is told, and what it tells back.
struct ShutdownSink {
    notify: Box<dyn Fn() + Send + Sync>,
    finished: Mutex<bool>,
    finished_cv: Condvar,
}

/// How long the console handler holds a closing window after it has told an
/// attached session to leave. Zero unless the terminal was built with
/// [`WindowsTerminal::detaching_on_hangup`].
static HANGUP_GRACE: Mutex<Duration> = Mutex::new(Duration::ZERO);

/// The armed shutdown sink, if any.
static SHUTDOWN: Mutex<Option<Arc<ShutdownSink>>> = Mutex::new(None);

static HOOK: Once = Once::new();

/// Route a closing console (`CTRL_CLOSE`, log off, shutdown, `CTRL_BREAK`)
/// to `notify` while no terminal session is attached. `notify` runs on the
/// system's handler thread and must only signal; the process stops on its
/// own thread, then calls [`shutdown_finished`]. Arming again replaces the
/// previous notifier.
pub fn arm_shutdown(notify: impl Fn() + Send + Sync + 'static) {
    let sink = Arc::new(ShutdownSink {
        notify: Box::new(notify),
        finished: Mutex::new(false),
        finished_cv: Condvar::new(),
    });
    *SHUTDOWN.lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);
}

/// The process armed with [`arm_shutdown`] has stopped: let a console
/// handler that is holding a closing window go. A no-op when nothing is
/// armed.
pub fn shutdown_finished() {
    let sink = SHUTDOWN.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(sink) = sink {
        *sink.finished.lock().unwrap_or_else(|e| e.into_inner()) = true;
        sink.finished_cv.notify_all();
    }
}

/// Tell the armed process to stop and wait for it, up to [`SHUTDOWN_GRACE`].
/// `false` when nothing is armed, so the default action runs.
fn request_shutdown() -> bool {
    let sink = SHUTDOWN.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let Some(sink) = sink else { return false };
    (sink.notify)();
    let finished = sink.finished.lock().unwrap_or_else(|e| e.into_inner());
    let _ = sink
        .finished_cv
        .wait_timeout_while(finished, SHUTDOWN_GRACE, |done| !*done)
        .unwrap_or_else(|e| e.into_inner());
    true
}

/// Restore whatever is armed. Used by the panic hook and the console
/// handler.
fn restore_active() {
    let active = ACTIVE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(restorer) = active {
        restorer.restore();
    }
}

/// Restore the console before the default panic message is printed, so a
/// panic on the input or signal thread does not leave a raw console behind.
fn install_panic_hook() {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_active();
            previous(info);
        }));
    });
}

/// The console control handler's body: `true` when the event is handled and
/// the system must not run the next handler (which would end the process).
///
/// The console is put back first for every event but `Ctrl-C`, because a
/// closing window gives the process only a few seconds. `Ctrl-C` with a
/// session attached is forwarded as the interrupt and leaves the console
/// raw. With a session attached any other event then becomes a hang-up for
/// the driver to detach on (the session stays on the host,
/// `docs/CLI.md` §7). With nobody listening (the
/// invitation-code prompt) the default action, ending the process, is left
/// to run on the restored console, unless the process armed [`arm_shutdown`]:
/// then the event is handed to it and held until it has stopped.
pub fn on_console_event(ctrl_type: u32) -> bool {
    let cause = match ctrl_type {
        CTRL_C_EVENT => {
            // From the keyboard this cannot happen in raw mode (`Ctrl-C` is
            // a byte); it is an interrupt delivered from outside, or the
            // keyboard's when stdin is not a console. A session being
            // attached takes it as the `^C` byte and the console stays raw,
            // since the session keeps running. Only when nobody listens does
            // the default action end the process, on a restored console.
            let events = EVENTS.lock().unwrap_or_else(|e| e.into_inner()).clone();
            return match events {
                Some(events) => events.send(TermEvent::Interrupt).is_ok(),
                None => {
                    restore_active();
                    false
                }
            };
        }
        CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => ctrl_type,
        _ => return false,
    };
    restore_active();
    let events = EVENTS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match events {
        Some(events) => {
            let told = events
                .send(TermEvent::Hangup(HangupCause(cause as i32)))
                .is_ok();
            // The system ends the process as soon as this handler returns,
            // and a detach needs the signal thread and then the main thread
            // to run first. The process ends itself when the client is done,
            // so this wait is cut short by the exit and only runs out when
            // the client is stuck.
            let grace = *HANGUP_GRACE.lock().unwrap_or_else(|e| e.into_inner());
            if told && !grace.is_zero() {
                std::thread::sleep(grace);
            }
            told
        }
        None => request_shutdown(),
    }
}

/// The Windows console as a [`Terminal`].
pub struct WindowsTerminal {
    api: Arc<dyn ConsoleApi>,
    sleeper: Arc<dyn Sleep>,
    restorer: Arc<Restorer>,
    /// Set by a successful [`preflight`](Terminal::preflight) on a console
    /// stdout.
    vt: AtomicBool,
    /// Whether a closing console detaches the attach
    /// ([`Self::detaching_on_hangup`]).
    detach_on_hangup: bool,
}

impl WindowsTerminal {
    /// A terminal over `api`, pausing between size reads with `sleeper`.
    pub fn new(api: Arc<dyn ConsoleApi>, sleeper: Arc<dyn Sleep>) -> Self {
        let restorer = Restorer::new(Arc::clone(&api));
        Self {
            api,
            sleeper,
            restorer,
            vt: AtomicBool::new(false),
            detach_on_hangup: false,
        }
    }

    /// Have a closing console detach the attached client, and hold the
    /// closing window while it does ([`SHUTDOWN_GRACE`]). The host then sees
    /// the client go at once instead of when the connection idles out, so an
    /// attach from another console is not kept waiting. Off by default: the
    /// probes and the unit tests drive the handler with nothing behind it to
    /// detach.
    #[must_use]
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn detaching_on_hangup(mut self) -> Self {
        self.detach_on_hangup = true;
        self
    }
}

impl Terminal for WindowsTerminal {
    /// With a console on stdin, its raw input mode must be accepted; with a
    /// console on stdout, VT processing must be. Both are tried and put
    /// straight back. A refusal means a conhost older than Windows 10 1809.
    fn preflight(&self) -> Result<(), OpError> {
        let unsupported = || {
            OpError::new(ErrorCode::Unsupported, CONSOLE_VT_UNAVAILABLE_MESSAGE)
                .with_retryable(false)
        };
        let input = self.api.input_mode();
        let output = self.api.output_mode();
        if let Some(original) = input {
            let accepted = self.api.set_input_mode(raw_input_mode(original));
            let _ = self.api.set_input_mode(original);
            accepted.map_err(|_| unsupported())?;
        }
        if let Some(original) = output {
            let accepted = self.api.set_output_mode(raw_output_mode(original));
            let _ = self.api.set_output_mode(original);
            accepted.map_err(|_| unsupported())?;
        }
        // VT is what the output console was just shown to accept; a piped
        // stdin does not change what the remote output is rendered by.
        self.vt.store(output.is_some(), Ordering::SeqCst);
        Ok(())
    }

    fn fallback_term(&self) -> Option<&'static str> {
        self.vt.load(Ordering::SeqCst).then_some("xterm-256color")
    }

    fn window_size(&self) -> Option<(u16, u16)> {
        self.api.input_mode()?;
        self.api.window_size()
    }

    fn enter_raw(&self) -> io::Result<Box<dyn RawGuard>> {
        let input = self.api.input_mode();
        let output = self.api.output_mode();
        let console = input.is_some() || output.is_some();
        // Publish what to put back *before* changing anything, so a panic
        // or a close event in the middle still has it.
        self.restorer.arm(Saved {
            input,
            output,
            code_pages: console.then(|| self.api.code_pages()),
        });
        let apply = || -> io::Result<()> {
            if let Some(mode) = input {
                self.api.set_input_mode(raw_input_mode(mode))?;
            }
            if let Some(mode) = output {
                self.api.set_output_mode(raw_output_mode(mode))?;
            }
            if console {
                self.api.set_code_pages(CP_UTF8, CP_UTF8)?;
            }
            Ok(())
        };
        if let Err(err) = apply() {
            self.restorer.restore();
            return Err(err);
        }
        Ok(Box::new(ConsoleGuard {
            restorer: Arc::clone(&self.restorer),
            raw: input.is_some(),
        }))
    }

    fn read_stdin(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.api.read_stdin(buf)
    }

    /// Console control events, and the size poll on its own thread.
    fn open_events(&self) -> io::Result<Box<dyn EventSource>> {
        self.api.install_ctrl_handler()?;
        let (tx, rx) = channel();
        *EVENTS.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx.clone());
        *HANGUP_GRACE.lock().unwrap_or_else(|e| e.into_inner()) = if self.detach_on_hangup {
            SHUTDOWN_GRACE
        } else {
            Duration::ZERO
        };
        let api = Arc::clone(&self.api);
        let sleeper = Arc::clone(&self.sleeper);
        let mut poller = ResizePoller::new(self.window_size());
        let has_input_console = self.api.input_mode().is_some();
        if has_input_console {
            let spawned = std::thread::Builder::new()
                .name("qsh-tui-resize".into())
                .spawn(move || {
                    loop {
                        sleeper.sleep(RESIZE_POLL);
                        if poller.changed(api.window_size()) && tx.send(TermEvent::Resize).is_err()
                        {
                            return;
                        }
                    }
                });
            if let Err(err) = spawned {
                *EVENTS.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return Err(err);
            }
        }
        Ok(Box::new(WindowsEvents { rx }))
    }

    fn strips_win32_input_mode(&self) -> bool {
        true
    }

    fn detaches_on_hangup(&self) -> bool {
        self.detach_on_hangup
    }

    /// Put the console back and leave; the session stays on the host. The
    /// exit status is `128 + <event number>`, the shape a POSIX shell
    /// reports for a client killed by that signal.
    fn leave_on_hangup(&self, cause: HangupCause) {
        self.restorer.restore();
        restore_active();
        std::process::exit(128 + cause.0);
    }
}

/// Raw mode for as long as it lives; dropping it restores the console.
struct ConsoleGuard {
    restorer: Arc<Restorer>,
    raw: bool,
}

impl RawGuard for ConsoleGuard {
    fn is_raw(&self) -> bool {
        self.raw
    }
}

impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        self.restorer.restore();
    }
}

/// The events of one attach.
struct WindowsEvents {
    rx: Receiver<TermEvent>,
}

impl EventSource for WindowsEvents {
    fn next_event(&mut self) -> Option<TermEvent> {
        self.rx.recv().ok()
    }
}

impl Drop for WindowsEvents {
    fn drop(&mut self) {
        *EVENTS.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Decides, from successive reads of the window size, when it changed.
pub struct ResizePoller {
    last: Option<(u16, u16)>,
}

impl ResizePoller {
    /// A poller that treats `initial` as the size already known.
    pub fn new(initial: Option<(u16, u16)>) -> Self {
        Self { last: initial }
    }

    /// Whether `now` differs from the previous size. A read that fails
    /// (`None`) is not a change.
    pub fn changed(&mut self, now: Option<(u16, u16)>) -> bool {
        match now {
            Some(size) if self.last != Some(size) => {
                self.last = Some(size);
                true
            }
            _ => false,
        }
    }
}

/// Echo off on a console stdin for as long as it lives (the invitation-code
/// prompt and `--code-stdin`, ADR-0035 decision 11).
///
/// Only `ENABLE_ECHO_INPUT` changes: line editing and the system's Ctrl-C
/// handling stay, so a mistyped code can be corrected and the prompt
/// aborted. It follows the same restore rules as raw mode. When stdin is not
/// a console there is nothing to suppress and the guard does nothing.
pub struct EchoSuppressed {
    restorer: Arc<Restorer>,
}

impl EchoSuppressed {
    /// Switch echo off on `api`'s console input.
    pub fn enter(api: Arc<dyn ConsoleApi>) -> io::Result<Self> {
        let restorer = Restorer::new(Arc::clone(&api));
        if let Some(original) = api.input_mode() {
            restorer.arm(Saved {
                input: Some(original),
                output: None,
                code_pages: None,
            });
            let applied = api
                .install_ctrl_handler()
                .and_then(|()| api.set_input_mode(echo_suppressed_input_mode(original)));
            if let Err(err) = applied {
                restorer.restore();
                return Err(err);
            }
            // No flush of typed-ahead input: the console echoes while a read
            // consumes input, not when a key is pressed, so what was typed
            // before this point was not shown and is still the operator's code.
        }
        Ok(Self { restorer })
    }
}

impl Drop for EchoSuppressed {
    fn drop(&mut self) {
        self.restorer.restore();
    }
}

/// The real console and clock.
#[cfg(windows)]
pub mod system {
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{ERROR_BROKEN_PIPE, GetLastError, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, GetConsoleCP, GetConsoleMode, GetConsoleOutputCP,
        GetConsoleScreenBufferInfo, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
        STD_OUTPUT_HANDLE, SetConsoleCP, SetConsoleCtrlHandler, SetConsoleMode, SetConsoleOutputCP,
    };

    use super::{ConsoleApi, Sleep, WindowsTerminal, on_console_event};

    /// The process's standard handles as a console.
    pub struct Win32Console;

    /// A real pause.
    pub struct ThreadSleep;

    impl Sleep for ThreadSleep {
        fn sleep(&self, duration: Duration) {
            std::thread::sleep(duration);
        }
    }

    /// The terminal of this process.
    pub fn terminal() -> WindowsTerminal {
        WindowsTerminal::new(Arc::new(Win32Console), Arc::new(ThreadSleep))
    }

    /// This process's console, as the trait the prompt takes.
    pub fn console() -> Arc<dyn ConsoleApi> {
        Arc::new(Win32Console)
    }

    fn get_mode(which: u32) -> Option<u32> {
        let mut mode = 0u32;
        // SAFETY: a plain query of a standard handle with a live
        // out-pointer; a handle that is not a console makes it return 0.
        let ok = unsafe { GetConsoleMode(GetStdHandle(which), &mut mode) };
        (ok != 0).then_some(mode)
    }

    fn set_mode(which: u32, mode: u32) -> io::Result<()> {
        // SAFETY: a plain set on a standard handle.
        if unsafe { SetConsoleMode(GetStdHandle(which), mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn screen_window(handle: HANDLE) -> Option<(u16, u16)> {
        // SAFETY: a zeroed `CONSOLE_SCREEN_BUFFER_INFO` is a valid
        // out-parameter.
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } == 0 {
            return None;
        }
        let w = &info.srWindow;
        let cols = i32::from(w.Right) - i32::from(w.Left) + 1;
        let rows = i32::from(w.Bottom) - i32::from(w.Top) + 1;
        match (u16::try_from(cols), u16::try_from(rows)) {
            (Ok(cols), Ok(rows)) if cols > 0 && rows > 0 => Some((cols, rows)),
            _ => None,
        }
    }

    impl ConsoleApi for Win32Console {
        fn input_mode(&self) -> Option<u32> {
            get_mode(STD_INPUT_HANDLE)
        }

        fn set_input_mode(&self, mode: u32) -> io::Result<()> {
            set_mode(STD_INPUT_HANDLE, mode)
        }

        fn output_mode(&self) -> Option<u32> {
            get_mode(STD_OUTPUT_HANDLE)
        }

        fn set_output_mode(&self, mode: u32) -> io::Result<()> {
            set_mode(STD_OUTPUT_HANDLE, mode)
        }

        fn code_pages(&self) -> (u32, u32) {
            // SAFETY: plain queries of this process's console.
            unsafe { (GetConsoleCP(), GetConsoleOutputCP()) }
        }

        fn set_code_pages(&self, input: u32, output: u32) -> io::Result<()> {
            // SAFETY: plain sets on this process's console.
            unsafe {
                if SetConsoleCP(input) == 0 || SetConsoleOutputCP(output) == 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }

        fn window_size(&self) -> Option<(u16, u16)> {
            // SAFETY: standard handle queries.
            let (out, err) = unsafe {
                (
                    GetStdHandle(STD_OUTPUT_HANDLE),
                    GetStdHandle(STD_ERROR_HANDLE),
                )
            };
            screen_window(out).or_else(|| screen_window(err))
        }

        fn read_stdin(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut read = 0u32;
            let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            // SAFETY: `buf` is live for the call and `len` does not exceed
            // it; a console or pipe handle takes no OVERLAPPED.
            let ok = unsafe {
                ReadFile(
                    GetStdHandle(STD_INPUT_HANDLE),
                    buf.as_mut_ptr().cast(),
                    len,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok != 0 {
                return Ok(read as usize);
            }
            // The write end of a pipe closing is end of input, not a failure.
            // SAFETY: reads the calling thread's last error.
            if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                return Ok(0);
            }
            Err(io::Error::last_os_error())
        }

        fn install_ctrl_handler(&self) -> io::Result<()> {
            static INSTALLED: AtomicBool = AtomicBool::new(false);
            if INSTALLED.swap(true, Ordering::SeqCst) {
                return Ok(());
            }
            // SAFETY: registers a routine that outlives the process's use of
            // it; it runs on a system thread and only touches statics.
            if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 {
                INSTALLED.store(false, Ordering::SeqCst);
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    unsafe extern "system" fn handler(ctrl_type: u32) -> i32 {
        i32::from(on_console_event(ctrl_type))
    }
}

// The explicit path is the same from here and from `qsh-testkit`'s console
// probe, which includes this file by path (a module loaded through `#[path]`
// would otherwise look for `tests.rs` beside this file).
#[cfg(test)]
#[path = "windows/tests.rs"]
mod tests;
