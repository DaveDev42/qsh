//! ConPTY backend for the session broker (`docs/design/architecture.md` §4,
//! ADR-0035 decision 20): the Windows counterpart of `posix.rs`.
//!
//! [`ConPtySource`] is a [`crate::broker::SessionSource`]. One session is:
//!
//! - a **pseudo-console** (`CreatePseudoConsole`) with two pipes: input
//!   (the host writes keystrokes, conhost reads) and output (conhost writes
//!   the VT stream, the host reads);
//! - a **Job Object** with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and a child
//!   created inside it by one `CreateProcessW` call whose attribute list
//!   carries both the pseudo-console and the job
//!   ([`crate::winproc::spawn_in_job`]). The child and everything it starts
//!   are in the job from the first instruction, so the tree can be ended as
//!   one unit (the counterpart of `setsid` + `killpg`) and ends with the host
//!   if the host dies;
//! - the **host ends of the pipes** as overlapped named pipes with an owner
//!   only DACL and an unguessable name, read and written through tokio. The
//!   conhost ends must be synchronous handles, which is why the host ends are
//!   named pipes (an anonymous pipe has no overlapped mode) and no thread is
//!   parked on a read per session.
//!
//! **Exit and output.** The child's exit is a process-handle wait on the
//! system thread pool. ConPTY keeps the output pipe open after the child
//! exits: it flushes what is left of the screen and closes the pipe only when
//! the pseudo-console is closed. Earlier Windows builds make
//! `ClosePseudoConsole` itself wait until that output has been read; Windows
//! 11 24H2 returns at once. So the close runs on a blocking thread while the
//! pump keeps reading, and the end of the stream (not the exit) is what tells
//! the session actor that every byte is in the replay buffer. The actor
//! appends `session.exit` only after both, which keeps the output before exit
//! invariant of `docs/design/testing.md` L5. Closing early would cut the
//! output short, so the close is tied to the child's exit and nothing else.
//! Whatever else still runs on the console at that point ends with it.
//!
//! **What the child starts from** (ADR-0035 decision 21). The child does not
//! inherit the `qsh serve` environment. [`plan`] builds the environment from
//! the user's environment block (`CreateEnvironmentBlock` for the process
//! token), `TERM`, a locale and time zone pass-through and the client's `env`,
//! with the pinned keys applied last (`env_policy`). An empty `argv` runs
//! `COMSPEC` (else `%SystemRoot%\System32\cmd.exe`), always as a full path.
//! A program named in `argv` is looked up on the child's own `PATH`, never
//! in the host's working directory or on the host's `PATH`, which is what
//! `CreateProcessW` would search without an application name. The working
//! directory is `USERPROFILE`. A `user` hint that does not name the token's
//! account fails before anything is created.
//!
//! **Signals** (ADR-0035 decision 22, `signal_map`). `Kill` is
//! `TerminateJobObject`. `Hup` and `Term` are one event, `ClosePseudoConsole`
//! (`CTRL_CLOSE_EVENT`), sent at most once per session. `Int` and `Quit` are
//! `CTRL_C_EVENT` and `CTRL_BREAK_EVENT` to every process on the console,
//! sent by the hidden `qsh internal console-ctrl` helper (`console_ctrl`)
//! because attaching to a console is process-global. `Usr1` and `Usr2` set
//! one of two named auto-reset events the host creates for the session
//! ([`SignalEvents`]) and names in `QSH_SIGNAL_EVENT_USR1` and
//! `QSH_SIGNAL_EVENT_USR2`. Whichever step comes first, the close escalation
//! (`Term`, then `Kill`) ends the session. The control remembers the signal
//! of the last step it actually sent; a session that ends after one reports
//! that signal's name in `session.exit`, and one that ends on its own
//! reports none. `Usr1` and `Usr2` are the exception: they cannot end a
//! program, so an exit right after one reports the program's own status and
//! no signal (ADR-0047).

use std::ffi::OsString;
use std::io;
use std::os::windows::io::OwnedHandle;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};

use super::console_ctrl::{self, CtrlKind};
use super::env_policy::{self, DEFAULT_TERM, SIGNAL_EVENT_USR1, SIGNAL_EVENT_USR2, WINDOWS};
use super::signal_map::{self, Step, UserEvent};
use crate::broker::{
    SessionSource, SessionSpec, Signal, SourceControl, SourceExit, SourceFactory, SpawnedSource,
};
use crate::winproc::launch::{self, command_line, resolve_program};
use crate::winproc::pipe::host_pipe;
use crate::winproc::{self, ExitWatch, JobObject, NamedEvent, ProcessSpec};

#[cfg(test)]
mod tests;

/// The window size used when the client sends `0` in either dimension (the
/// same fallback as the POSIX backend).
const FALLBACK_SIZE: (u16, u16) = (80, 24);

fn normalize_size(cols: u16, rows: u16) -> (u16, u16) {
    if cols == 0 || rows == 0 {
        FALLBACK_SIZE
    } else {
        (cols, rows)
    }
}

/// The production [`SourceFactory`] on Windows: one [`ConPtySource`] per
/// session.
#[derive(Debug, Default, Clone)]
pub struct ConPtyFactory {
    console_ctrl_program: Option<PathBuf>,
}

impl ConPtyFactory {
    /// A factory whose sessions send `CTRL_C_EVENT` and `CTRL_BREAK_EVENT`
    /// through `program internal console-ctrl <pid> <c|break>` instead of
    /// through this executable (see [`ConPtySource::with_console_ctrl_program`]).
    pub fn with_console_ctrl_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.console_ctrl_program = Some(program.into());
        self
    }
}

impl SourceFactory for ConPtyFactory {
    fn create(&self, _spec: &SessionSpec) -> io::Result<Box<dyn SessionSource>> {
        let mut source = ConPtySource::new();
        source
            .console_ctrl_program
            .clone_from(&self.console_ctrl_program);
        Ok(Box::new(source))
    }
}

/// Login name of the account `qsh serve` runs as: the process token's user
/// name, without the domain. The dispatch edge compares the `user` hint of
/// `session.open` against the account's names after authorization
/// (`docs/design/architecture.md` §4).
pub fn login_name() -> io::Result<String> {
    winproc::account_names()?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other("the process token has no account name"))
}

/// The [`SessionSource`] for Windows: runs the session's `argv` (or the
/// default shell) in a pseudo-console inside its own Job Object.
#[derive(Debug, Default)]
pub struct ConPtySource {
    /// The executable that runs `internal console-ctrl`; `None` is this one.
    console_ctrl_program: Option<PathBuf>,
    /// Test hook: receives a handle to each child, which keeps its pid from
    /// being reused while a test inspects it.
    #[cfg(test)]
    process_observer: Option<Arc<Mutex<Vec<Arc<OwnedHandle>>>>>,
    /// Test hook: where the control records the steps it takes.
    #[cfg(test)]
    stage_observer: Option<StageLog>,
}

impl ConPtySource {
    /// A source that spawns per the [`SessionSpec`] it is given.
    pub fn new() -> Self {
        Self::default()
    }

    /// Send `CTRL_C_EVENT` and `CTRL_BREAK_EVENT` through `program internal
    /// console-ctrl <pid> <c|break>`. The default is this executable, which
    /// is `qsh` for a host (the entry is `qsh internal console-ctrl`). A
    /// caller whose executable is something else, such as a test binary,
    /// names the `qsh`-compatible one here.
    pub fn with_console_ctrl_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.console_ctrl_program = Some(program.into());
        self
    }

    /// Publish a handle to each child into `slot` right after it is spawned
    /// (tests: process-exit and handle-leak assertions).
    #[cfg(test)]
    pub(crate) fn observe_processes(mut self, slot: Arc<Mutex<Vec<Arc<OwnedHandle>>>>) -> Self {
        self.process_observer = Some(slot);
        self
    }

    /// Record the control's close steps into `log` (tests: the close path).
    #[cfg(test)]
    pub(crate) fn observe_stages(mut self, log: StageLog) -> Self {
        self.stage_observer = Some(log);
        self
    }
}

impl SessionSource for ConPtySource {
    fn spawn(self: Box<Self>, spec: &SessionSpec) -> io::Result<SpawnedSource> {
        // The host pipes are registered with the reactor here.
        let _rt = tokio::runtime::Handle::try_current().map_err(|_| {
            io::Error::other("ConPtySource::spawn must be called from within a tokio runtime")
        })?;
        let events = Arc::new(SignalEvents::create()?);
        let launch = plan(spec, &events)?;
        let (cols, rows) = normalize_size(spec.cols, spec.rows);
        let mut session = ConPtySession::start(&launch, events, cols, rows)?;
        session.console_ctrl_program = self.console_ctrl_program.clone();
        #[cfg(test)]
        if let Some(log) = &self.stage_observer {
            session.log = Arc::clone(log);
        }
        #[cfg(test)]
        if let Some(slot) = &self.process_observer {
            slot.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(Arc::clone(&session.process));
        }
        session.into_spawned()
    }
}

// ---------------------------------------------------------------------------
// What to run, and in which environment
// ---------------------------------------------------------------------------

/// Everything `CreateProcessW` is given for a session child.
#[derive(Debug)]
pub(crate) struct Launch {
    /// The program, as a full path.
    application: PathBuf,
    command_line: OsString,
    current_dir: PathBuf,
    /// The UTF-16 environment block.
    environment: Vec<u16>,
}

/// The two named events of one session, `Usr1` and `Usr2` (ADR-0035
/// decision 22). They are created before the child so their names can go in
/// its environment, and live as long as the session's control does.
#[derive(Debug)]
pub(crate) struct SignalEvents {
    usr1: NamedEvent,
    usr2: NamedEvent,
}

impl SignalEvents {
    /// Two fresh events under names that carry 128 random bits.
    pub(crate) fn create() -> io::Result<Self> {
        let id = format!("{:032x}", rand::random::<u128>());
        Ok(Self {
            usr1: NamedEvent::create_owner_only(format!(r"Local\qsh-sig-{id}-usr1"))?,
            usr2: NamedEvent::create_owner_only(format!(r"Local\qsh-sig-{id}-usr2"))?,
        })
    }

    /// The variables that tell the session's programs the events' names.
    pub(crate) fn environment(&self) -> Vec<(String, String)> {
        vec![
            (SIGNAL_EVENT_USR1.to_string(), self.usr1.name().to_string()),
            (SIGNAL_EVENT_USR2.to_string(), self.usr2.name().to_string()),
        ]
    }

    fn set(&self, which: UserEvent) -> io::Result<()> {
        match which {
            UserEvent::Usr1 => self.usr1.set(),
            UserEvent::Usr2 => self.usr2.set(),
        }
    }
}

/// Plan the child of `spec` against this host: the account check, the
/// user's environment block, the Windows directory, and the names of the
/// session's signal `events`.
pub(crate) fn plan(spec: &SessionSpec, events: &SignalEvents) -> io::Result<Launch> {
    // Defence in depth for architecture.md §4: no user switching, and the
    // dispatch edge has already turned a foreign hint into UNSUPPORTED after
    // the ACL check. Fail closed, before anything exists, if it did not.
    if let Some(user) = &spec.user {
        let names = winproc::account_names()?;
        if !env_policy::login_name_matches(user, &names, WINDOWS) {
            return Err(super::user_switching_unsupported());
        }
    }
    // An embedded NUL would end the command line there and drop the
    // arguments after it without a word.
    if spec.argv.iter().any(|arg| arg.contains('\0')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ConPtySource argv must not contain NUL",
        ));
    }
    let user_env = winproc::user_environment()?;
    plan_from(
        spec,
        &user_env,
        &launch::serve_environment(),
        &winproc::windows_directory()?,
        &events.environment(),
    )
}

/// [`plan`] with its host inputs given: the user's environment block, the
/// serve process's own environment (the pass-through source), the Windows
/// directory and the variables the host makes for this one session
/// (`session_env`, pinned like the user's own identity variables).
fn plan_from(
    spec: &SessionSpec,
    user_env: &[(String, String)],
    serve_env: &[(String, String)],
    windows_dir: &str,
    session_env: &[(String, String)],
) -> io::Result<Launch> {
    let term = spec
        .term
        .as_deref()
        .filter(|t| env_policy::is_valid_entry("TERM", t))
        .unwrap_or(DEFAULT_TERM);
    let term = [("TERM".to_string(), term.to_string())];
    let locale = launch::locale_entries(serve_env);
    let pinned = env_policy::windows_session_pinned(user_env, session_env);
    let env = env_policy::windows_overlay_env(user_env, &[&term, &locale, &spec.env], &pinned);

    let system_root = env_policy::windows_lookup(&env, "SystemRoot").unwrap_or(windows_dir);
    let current_dir = match env_policy::windows_lookup(&env, "USERPROFILE") {
        Some(profile) if Path::new(profile).is_dir() => PathBuf::from(profile),
        other => {
            tracing::warn!(
                profile = other.unwrap_or(""),
                fallback = windows_dir,
                "session starts in the Windows directory: the profile directory is not usable"
            );
            PathBuf::from(windows_dir)
        }
    };
    let (application, command_line) = if spec.argv.is_empty() {
        let shell = match env_policy::windows_lookup(&env, "COMSPEC") {
            Some(comspec) if !comspec.is_empty() => PathBuf::from(comspec),
            _ => Path::new(system_root).join("System32").join("cmd.exe"),
        };
        let command_line = command_line(&[shell.to_string_lossy().into_owned()]);
        (shell, command_line)
    } else {
        let search = launch::system_dirs(windows_dir);
        let application = resolve_program(
            &spec.argv[0],
            env_policy::windows_lookup(&env, "PATH"),
            &current_dir,
            &search,
        )?;
        (application, command_line(&spec.argv))
    };
    Ok(Launch {
        application,
        command_line,
        current_dir,
        environment: env_policy::windows_environment_block(&env),
    })
}

// ---------------------------------------------------------------------------
// Pseudo-console
// ---------------------------------------------------------------------------

/// An open pseudo-console. Closing is idempotent and may block (see the
/// module doc), so it never runs on an async task: [`Self::close`] is called
/// from a blocking task, and dropping an open console closes it on a detached
/// thread.
#[derive(Debug)]
struct PseudoConsole {
    handle: Mutex<Option<HPCON>>,
}

impl PseudoConsole {
    fn create(
        cols: u16,
        rows: u16,
        input_read: &OwnedHandle,
        output_write: &OwnedHandle,
    ) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle as _;
        let mut hpc: HPCON = 0;
        // SAFETY: both handles are live, synchronous pipe ends; conhost
        // duplicates them, so the caller may close its copies afterwards.
        let hr = unsafe {
            CreatePseudoConsole(
                coord(cols, rows),
                input_read.as_raw_handle(),
                output_write.as_raw_handle(),
                0,
                &mut hpc,
            )
        };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "CreatePseudoConsole failed: HRESULT {hr:#010x}"
            )));
        }
        Ok(Self {
            handle: Mutex::new(Some(hpc)),
        })
    }

    /// The handle for the process attribute list, while the console is open.
    fn raw(&self) -> Option<HPCON> {
        *self.handle.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn resize(&self, cols: u16, rows: u16) -> io::Result<()> {
        let guard = self.handle.lock().unwrap_or_else(|e| e.into_inner());
        let Some(hpc) = *guard else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the pseudo-console is closed",
            ));
        };
        // SAFETY: `hpc` is an open pseudo-console (the lock is held).
        let hr = unsafe { ResizePseudoConsole(hpc, coord(cols, rows)) };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "ResizePseudoConsole failed: HRESULT {hr:#010x}"
            )));
        }
        Ok(())
    }

    /// Take the handle out, leaving the console closed as far as this value
    /// is concerned. `None` if it was already taken. Whoever takes it must
    /// call [`close_handle`], which may block.
    fn take(&self) -> Option<HPCON> {
        self.handle.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// Close the console. Blocks until conhost has flushed its last output
    /// into the output pipe and the reader has taken it (or the reader is
    /// gone). Returns whether this call did the closing.
    fn close(&self) -> bool {
        match self.take() {
            Some(hpc) => {
                close_handle(hpc);
                true
            }
            None => false,
        }
    }
}

/// `ClosePseudoConsole` on a handle taken out of a [`PseudoConsole`]: the
/// children attached to the console get `CTRL_CLOSE_EVENT`, conhost flushes
/// and ends the output pipe.
fn close_handle(hpc: HPCON) {
    // SAFETY: `hpc` was an open pseudo-console, and it was taken out of its
    // cell, so nothing else closes it.
    unsafe { ClosePseudoConsole(hpc) };
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        let hpc = self
            .handle
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(hpc) = hpc {
            // A blocking close must not stall whichever task drops us.
            let _ = std::thread::Builder::new()
                .name("qsh-conpty-close".into())
                .spawn(move || close_handle(hpc));
        }
    }
}

fn coord(cols: u16, rows: u16) -> COORD {
    COORD {
        X: cols.min(i16::MAX as u16) as i16,
        Y: rows.min(i16::MAX as u16) as i16,
    }
}

// ---------------------------------------------------------------------------
// Host pipes
// ---------------------------------------------------------------------------

/// The output side as an `AsyncRead` that reports a closed pipe as a clean
/// end of stream, like a pty master at hang-up.
struct HostOutput(NamedPipeServer);

impl AsyncRead for HostOutput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.0).poll_read(cx, buf) {
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => Poll::Ready(Ok(())),
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A step the control took on the session, in the order it took them (tests
/// read this to pin the close path).
#[cfg(test)]
pub(crate) type Stage = Step;

#[cfg(test)]
pub(crate) type StageLog = Arc<Mutex<Vec<Stage>>>;

/// The signal of the last step the control sent, shared with the exit
/// watch: a session that ends after a step reports that step's signal.
type SentSignal = Arc<Mutex<Option<Signal>>>;

/// A started pseudo-console session before it is split into the broker's
/// I/O trio. Field order is drop order: the job goes first, so the tree ends
/// before the console and the pipes are torn down.
pub(crate) struct ConPtySession {
    job: Arc<JobObject>,
    console: Arc<PseudoConsole>,
    process: Arc<OwnedHandle>,
    pid: u32,
    /// The session's `Usr1` and `Usr2` events, whose names `launch` put in
    /// the child's environment.
    events: Arc<SignalEvents>,
    /// The executable that runs `internal console-ctrl`; `None` is this one.
    console_ctrl_program: Option<PathBuf>,
    output: NamedPipeServer,
    input: NamedPipeServer,
    #[cfg(test)]
    log: StageLog,
}

impl ConPtySession {
    /// Start `launch` in a new pseudo-console of `cols` x `rows`. `events`
    /// are the events `launch` was planned against.
    pub(crate) fn start(
        launch: &Launch,
        events: Arc<SignalEvents>,
        cols: u16,
        rows: u16,
    ) -> io::Result<Self> {
        let output = host_pipe(true)?;
        let input = host_pipe(false)?;
        let console = PseudoConsole::create(cols, rows, &input.child, &output.child)?;
        // conhost holds its own duplicates now. Ours must go, or the output
        // pipe would not end while this process lives.
        drop((input.child, output.child));
        let console = Arc::new(console);
        let job = Arc::new(JobObject::new_kill_on_close()?);
        // From here a failure drops `job` (and the console) on the way out;
        // the child is in the job from its first instruction, so there is
        // no child to clean up separately.
        let process = winproc::spawn_in_job(
            &job,
            &ProcessSpec {
                application: Some(launch.application.as_os_str()),
                command_line: &launch.command_line,
                creation_flags: 0,
                pseudo_console: console.raw(),
                environment: Some(&launch.environment),
                current_dir: Some(launch.current_dir.as_os_str()),
                stdio: None,
            },
        )?;
        tracing::debug!(pid = process.pid, "ConPTY session started");
        Ok(Self {
            job,
            console,
            pid: process.pid,
            process: Arc::new(process.handle),
            events,
            console_ctrl_program: None,
            output: output.host,
            input: input.host,
            #[cfg(test)]
            log: StageLog::default(),
        })
    }

    #[cfg(test)]
    fn pid(&self) -> u32 {
        self.pid
    }

    /// Split into what the broker drives.
    pub(crate) fn into_spawned(self) -> io::Result<SpawnedSource> {
        self.into_spawned_with(ExitWatch::new)
    }

    /// [`Self::into_spawned`] with the exit watch given. If anything after
    /// the child exists fails, `self` is dropped on the way out and with it
    /// the job, which ends the child and whatever it started.
    fn into_spawned_with(
        self,
        watch: impl FnOnce(Arc<OwnedHandle>) -> io::Result<ExitWatch>,
    ) -> io::Result<SpawnedSource> {
        let watch = watch(Arc::clone(&self.process))?;
        let Self {
            job,
            console,
            process,
            pid,
            events,
            console_ctrl_program,
            output,
            input,
            #[cfg(test)]
            log,
        } = self;
        let closer = Arc::clone(&console);
        let sent = SentSignal::default();
        let sent_at_exit = Arc::clone(&sent);
        let wait = Box::pin(async move {
            watch.exited().await;
            let exit_code = winproc::exit_code(&process)
                .ok()
                .map(env_policy::windows_exit_code);
            // Closing flushes conhost's last frame into the output pipe and
            // returns once the reader has taken it; the pump is reading on
            // its own task meanwhile, so this only has to leave the async
            // threads. The end of the output stream, not this call, is what
            // the actor waits for. (If a `Hup` already closed the console,
            // this is a no-op.)
            drop(tokio::task::spawn_blocking(move || {
                closer.close();
            }));
            // A session that ends after a step qsh sent reports that step's
            // signal; one that ends on its own reports none. `Usr1` and
            // `Usr2` only set an event and cannot end a program, so an exit
            // right after one is the program's own and reports its status
            // with no signal (ADR-0047, ADR-0035 decision 22). A later
            // `Hup`, `Term` or `Kill` replaced the record and is reported.
            let signal = sent_at_exit
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .filter(|signal| signal_map::reported_at_exit(*signal))
                .map(|signal| signal.as_str().to_string());
            SourceExit { exit_code, signal }
        });
        Ok(SpawnedSource {
            output: Box::new(HostOutput(output)),
            input: Box::new(input),
            control: Box::new(ConPtyControl {
                job,
                console,
                pid,
                events,
                console_ctrl_program,
                sent,
                taken: Vec::new(),
                #[cfg(test)]
                log,
            }),
            wait,
        })
    }

    #[cfg(test)]
    fn job(&self) -> &Arc<JobObject> {
        &self.job
    }

    #[cfg(test)]
    fn host_pipe_handles(&self) -> [std::os::windows::io::RawHandle; 2] {
        use std::os::windows::io::AsRawHandle as _;
        [self.output.as_raw_handle(), self.input.as_raw_handle()]
    }
}

/// Resize and signal control over a running session. Dropping it drops the
/// job, which ends whatever is still running in the session.
struct ConPtyControl {
    job: Arc<JobObject>,
    console: Arc<PseudoConsole>,
    /// The session's root process, whose console the helper attaches to.
    pid: u32,
    events: Arc<SignalEvents>,
    console_ctrl_program: Option<PathBuf>,
    sent: SentSignal,
    /// The steps already performed, which `signal_map::next_step` reads.
    taken: Vec<Step>,
    #[cfg(test)]
    log: StageLog,
}

impl ConPtyControl {
    #[cfg(test)]
    fn record(&self, stage: Stage) {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(stage);
    }

    /// `CTRL_CLOSE_EVENT` for everything on the console, at most once per
    /// session. `ClosePseudoConsole` can block (see the module doc), so it
    /// runs on a blocking task and the caller, the session actor, goes on.
    /// `false` if the console was already closed and nothing was sent.
    fn close_console(&self) -> bool {
        let Some(hpc) = self.console.take() else {
            return false;
        };
        drop(tokio::task::spawn_blocking(move || close_handle(hpc)));
        true
    }

    /// Do `step`. `Ok(false)` is a step that has nothing left to do.
    fn perform(&self, step: Step) -> io::Result<bool> {
        let sent = match step {
            Step::CtrlC => {
                console_ctrl::send(self.console_ctrl_program.as_deref(), self.pid, CtrlKind::C)?;
                true
            }
            Step::CtrlBreak => {
                console_ctrl::send(
                    self.console_ctrl_program.as_deref(),
                    self.pid,
                    CtrlKind::Break,
                )?;
                true
            }
            Step::CloseConsole => self.close_console(),
            Step::SetEvent(which) => {
                self.events.set(which)?;
                true
            }
            Step::TerminateJob => {
                self.job.terminate(1)?;
                true
            }
        };
        #[cfg(test)]
        if sent {
            self.record(step);
        }
        Ok(sent)
    }
}

impl SourceControl for ConPtyControl {
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        let (cols, rows) = normalize_size(cols, rows);
        self.console.resize(cols, rows)
    }

    /// Each signal is the Windows step `signal_map` names. The close
    /// escalation sends `Hup` or the caller's signal, then `Term`, then
    /// `Kill`: `signal_map::next_step` decides that `Term` after a `Hup` is
    /// the same console close and sends nothing again.
    ///
    /// The signal is noted before the step runs, because the session may
    /// end the instant the step lands and the exit watch reads the note; a
    /// step that sends nothing or fails puts the earlier note back.
    ///
    /// For `Int` and `Quit` the step runs the console control helper and
    /// waits (bounded) for its delivery report, like `kill(2)` returning: a
    /// helper that could not start, or started and failed to generate the
    /// event (`AttachConsole` on a console that just went away), is an
    /// error and leaves no note. Only a delivered event keeps its signal,
    /// including one whose receivers end the session at once. The note is
    /// optimistic for the length of the wait, so a session that ends by
    /// itself inside that window can still report the signal.
    fn signal(&mut self, signal: Signal) -> io::Result<()> {
        let Some(step) = signal_map::next_step(&self.taken, signal) else {
            return Ok(());
        };
        let earlier = self
            .sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(signal);
        match self.perform(step) {
            Ok(true) => {
                self.taken.push(step);
                Ok(())
            }
            outcome => {
                *self.sent.lock().unwrap_or_else(|e| e.into_inner()) = earlier;
                outcome.map(|_| ())
            }
        }
    }
}
