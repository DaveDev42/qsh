//! L5 for the session signals on Windows (ADR-0035 decision 22): each of
//! the seven signals is measured by what a real program on the session's
//! console receives, not by what the host says it sent.
//!
//! The program is `qsh-signal-probe` (`qsh-testkit`): it reports the event it
//! received on the console and in a report file, and ends with an exit code
//! that stands for the event. `qsh-core` cannot depend on `qsh-testkit`, so
//! the probe is found like any helper executable (the `QSH_SIGNAL_PROBE_BIN`
//! variable, or next to the test executable) and the event names and exit
//! codes below mirror `qsh_testkit::signal_probe`.
//!
//! A signal is sent only after the probe printed its `ready` record. A
//! process that a snapshot lists may not yet be attached to the console, and
//! a console event sent before the probe installed its handler would be
//! missed (or ignored through an inherited flag). The probe is also the
//! `internal console-ctrl` helper of these sessions, so `Int` and `Quit` go
//! through the real attach, ignore and generate sequence.

use tokio::io::AsyncReadExt as _;

use super::*;
use crate::fsutil::dacl::testing::read_dacl_of_kernel_handle;

const READY: &str = "<<QSH-SIGNAL ready>>";

/// What the probe reports for a signal: the event name and the exit code.
/// `Kill` reaches no program, so it has no event.
fn expected_event(signal: Signal) -> Option<(&'static str, i32)> {
    match signal {
        Signal::Hup | Signal::Term => Some(("ctrl-close", 12)),
        Signal::Int => Some(("ctrl-c", 10)),
        Signal::Quit => Some(("ctrl-break", 11)),
        Signal::Usr1 => Some(("usr1", 21)),
        Signal::Usr2 => Some(("usr2", 22)),
        Signal::Kill => None,
    }
}

fn probe_bin() -> PathBuf {
    if let Some(path) = std::env::var_os("QSH_SIGNAL_PROBE_BIN") {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let dir = exe.parent().expect("the test executable has a directory");
    [
        dir.join("qsh-signal-probe.exe"),
        dir.join("..").join("qsh-signal-probe.exe"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect(
        "qsh-signal-probe.exe is not next to the test executable; build it with \
         `cargo build -p qsh-testkit --bin qsh-signal-probe` or set QSH_SIGNAL_PROBE_BIN",
    )
}

/// A source whose `Int` and `Quit` go through the probe's own
/// `internal console-ctrl` entry.
fn source() -> ConPtySource {
    ConPtySource::new().with_console_ctrl_program(probe_bin())
}

/// A session running the probe in `mode`, reporting into `report`. The
/// console is wide so a record of the probe never wraps.
fn probe_spec(mode: &str, report: &Path, env: &[(&str, &str)]) -> SessionSpec {
    SessionSpec {
        argv: vec![
            probe_bin().into_os_string().into_string().unwrap(),
            mode.into(),
            "--report".into(),
            report.to_str().unwrap().into(),
        ],
        env: pairs(env),
        term: Some("xterm-qshtest".into()),
        cols: 200,
        rows: 24,
        user: None,
    }
}

/// The event names the probe appended to its report file, in order.
fn reported(report: &Path) -> Vec<String> {
    std::fs::read_to_string(report)
        .map(|body| body.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Read `output` until its rendered text contains `needle`, returning
/// everything read so far.
async fn read_until(output: &mut (impl tokio::io::AsyncRead + Unpin), needle: &str) -> String {
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let text = String::from_utf8_lossy(&seen).into_owned();
        if text.contains(needle) {
            return text;
        }
        let n = within(output.read(&mut chunk)).await.unwrap();
        assert_ne!(n, 0, "the console ended before {needle:?}; saw {text:?}");
        seen.extend_from_slice(&chunk[..n]);
    }
}

/// Keep reading `output` so nothing the session does can wait on us.
fn drain(mut output: Box<dyn tokio::io::AsyncRead + Send + Unpin>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        let _ = tokio::io::copy(&mut output, &mut sink).await;
    })
}

/// The value of the record `<<QSH-SIGNAL key VALUE>>` in rendered output.
fn record_value(out: &str, key: &str) -> Option<String> {
    let plain = strip_vt(out);
    let start = plain.find(&format!("<<QSH-SIGNAL {key} "))? + format!("<<QSH-SIGNAL {key} ").len();
    let end = plain[start..].find(">>")?;
    Some(plain[start..start + end].to_string())
}

/// Every signal reaches a program on the session's console as the event
/// ADR-0035 decision 22 names, through the whole stack (broker, close
/// escalation, control, helper process), and the session's exit reports the
/// signal that was sent. `Hup` and `Term` are the same event; `Kill` ends the
/// job and no program receives it.
///
/// Two passes per signal. In `exit` mode the program quits at its first
/// event, which pins the event and the exit code that stands for it. In
/// `hold` mode the program survives its event, so the close goes on after
/// the first step on the clock (grace, `Term`, grace, `Kill`) and must end
/// the session; the stage log shows the first step and the exit reports a
/// step the escalation took.
#[tokio::test]
async fn each_signal_raises_its_windows_event_then_escalates_to_an_ended_session() {
    for signal in Signal::ALL {
        first_event_ends_an_exiting_program(signal).await;
        escalation_ends_a_surviving_program(signal).await;
    }
}

/// The `exit` pass: the first event is the whole story.
async fn first_event_ends_an_exiting_program(signal: Signal) {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("events.txt");
    let (broker, clock) = broker(1 << 20);
    let handle = broker
        .open_with(&probe_spec("exit", &report, &[]), Box::new(source()))
        .unwrap();
    pull_until(&handle, &clock, usize::MAX, |ev| text(ev).contains(READY)).await;

    within(broker.close(&handle_id(&handle), CloseReason::Closed, Some(signal)))
        .await
        .unwrap();
    let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
        .await
        .unwrap();

    let (exit_code, exit_signal) = exit_of(&out.events).expect("the session ended");
    // A program that handles `Usr1`/`Usr2` and exits ended on its own: its
    // status and no signal (ADR-0047).
    let expected_signal = signal_map::reported_at_exit(signal).then(|| signal.as_str());
    assert_eq!(
        exit_signal.as_deref(),
        expected_signal,
        "{signal}: {:?}",
        out.events
    );
    match expected_event(signal) {
        Some((name, code)) => {
            assert_eq!(exit_code, Some(code), "{signal}: the probe's exit code");
            assert_eq!(reported(&report), [name], "{signal}: the event it received");
        }
        None => {
            assert_eq!(exit_code, Some(1), "{signal}: TerminateJobObject status");
            assert!(reported(&report).is_empty(), "{signal} reached the program");
        }
    }
    eprintln!(
        "signal {signal}: event {:?}, exit_code {exit_code:?}, exit signal {exit_signal:?}",
        reported(&report)
    );
}

/// The `hold` pass: the program reports its event and stays, so only the
/// escalation can end the session.
async fn escalation_ends_a_surviving_program(signal: Signal) {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("events.txt");
    let (broker, clock) = broker(1 << 20);
    let log = StageLog::default();
    let handle = broker
        .open_with(
            &probe_spec("hold", &report, &[]),
            Box::new(source().observe_stages(Arc::clone(&log))),
        )
        .unwrap();
    pull_until(&handle, &clock, usize::MAX, |ev| text(ev).contains(READY)).await;

    let closer = {
        let broker = Arc::clone(&broker);
        let id = handle_id(&handle);
        tokio::spawn(async move { broker.close(&id, CloseReason::Closed, Some(signal)).await })
    };
    if let Some((name, _)) = expected_event(signal) {
        pull_until(&handle, &clock, usize::MAX, |ev| {
            text(ev).contains(&format!("<<QSH-SIGNAL event {name}>>"))
        })
        .await;
    }
    finish_by_escalation(&clock, closer).await;

    let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
        .await
        .unwrap();
    let (_, exit_signal) = exit_of(&out.events).expect("the session ended");
    match signal {
        // The console close ends the program by itself, or the job does.
        Signal::Hup | Signal::Term => assert!(
            matches!(
                exit_signal.as_deref(),
                Some("SIGHUP" | "SIGTERM" | "SIGKILL")
            ),
            "{signal}: {exit_signal:?}"
        ),
        Signal::Kill => assert_eq!(exit_signal.as_deref(), Some("SIGKILL")),
        // A program that survives the event is ended by the steps after it.
        _ => assert!(
            matches!(exit_signal.as_deref(), Some("SIGTERM" | "SIGKILL")),
            "{signal}: the exit reports a step of the escalation: {exit_signal:?}"
        ),
    }
    let stages = log.lock().unwrap().clone();
    assert_eq!(
        stages.first(),
        Some(&signal_map::first_step(signal)),
        "{signal}: {stages:?}"
    );
    if let Some((name, _)) = expected_event(signal) {
        assert_eq!(reported(&report)[0], name, "{signal}: the first event");
    }
}

/// `Int` is delivered to every process on the console, not only the root:
/// the probe starts a child of its own on the same console and both report
/// `CTRL_C_EVENT`.
#[tokio::test]
async fn int_reaches_every_process_on_the_session_console() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("events.txt");
    let (broker, clock) = broker(1 << 20);
    let handle = broker
        .open_with(&probe_spec("tree", &report, &[]), Box::new(source()))
        .unwrap();
    // The probe prints `ready` once its child has installed its handlers.
    pull_until(&handle, &clock, usize::MAX, |ev| text(ev).contains(READY)).await;

    within(broker.close(&handle_id(&handle), CloseReason::Closed, Some(Signal::Int)))
        .await
        .unwrap();
    let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
        .await
        .unwrap();
    assert_eq!(
        exit_of(&out.events),
        Some((Some(10), Some("SIGINT".to_string()))),
        "{:?}",
        out.events
    );
    assert_eq!(reported(&report), ["ctrl-c", "ctrl-c"], "root and child");
    assert_eq!(
        record_value(&text(&out.events), "child-exit").as_deref(),
        Some("10"),
        "the child's own exit code: {:?}",
        text(&out.events)
    );
}

/// `Quit` is `CTRL_BREAK_EVENT` and not `CTRL_C_EVENT`: the program reports
/// the first and only the first.
#[tokio::test]
async fn quit_is_ctrl_break_not_ctrl_c() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("events.txt");
    let (broker, clock) = broker(1 << 20);
    let handle = broker
        .open_with(&probe_spec("hold", &report, &[]), Box::new(source()))
        .unwrap();
    pull_until(&handle, &clock, usize::MAX, |ev| text(ev).contains(READY)).await;

    // `hold` keeps running after the event, so the close is still in flight.
    let closer = {
        let broker = Arc::clone(&broker);
        let id = handle_id(&handle);
        tokio::spawn(async move {
            broker
                .close(&id, CloseReason::Closed, Some(Signal::Quit))
                .await
        })
    };
    pull_until(&handle, &clock, usize::MAX, |ev| {
        text(ev).contains("<<QSH-SIGNAL event ctrl-break>>")
    })
    .await;
    assert_eq!(reported(&report), ["ctrl-break"]);
    // The escalation is what ends a program that survives its event.
    finish_by_escalation(&clock, closer).await;
}

/// Advance the test clock one grace at a time until the close resolves. The
/// real-time wait between two advances only lets the actor take the step; it
/// elapses in full only when a step has not ended the session.
async fn finish_by_escalation(
    clock: &TestClock,
    mut closer: tokio::task::JoinHandle<Result<u64, BrokerError>>,
) {
    for _ in 0..6 {
        match tokio::time::timeout(Duration::from_secs(2), &mut closer).await {
            Ok(done) => {
                done.unwrap().unwrap();
                return;
            }
            Err(_) => clock.advance(Duration::from_millis(5000)),
        }
    }
    panic!("the escalation did not end the session");
}

/// `Hup` closes the console once. The escalation's `Term` is the same event,
/// so it finds the console closed and sends nothing: the program sees
/// `CTRL_CLOSE_EVENT` once.
#[tokio::test]
async fn hup_then_term_does_not_send_ctrl_close_twice() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("events.txt");
    let spec = probe_spec("hold", &report, &[]);
    let events = Arc::new(SignalEvents::create().unwrap());
    let launch = plan(&spec, &events).unwrap();
    let mut session = ConPtySession::start(&launch, events, 200, 24).unwrap();
    session.console_ctrl_program = Some(probe_bin());
    let log = Arc::clone(&session.log);
    let root = Arc::clone(&session.process);
    let mut spawned = session.into_spawned().unwrap();
    let mut output = spawned.output;
    read_until(&mut output, READY).await;
    let drain = drain(output);

    spawned.control.signal(Signal::Hup).unwrap();
    // SAFETY: a live handle.
    let state = unsafe { WaitForSingleObject(root.as_raw_handle(), 30_000) };
    assert_eq!(state, WAIT_OBJECT_0, "the root outlived the console close");
    spawned.control.signal(Signal::Term).unwrap();
    assert_eq!(*log.lock().unwrap(), vec![Stage::CloseConsole]);
    assert_eq!(reported(&report), ["ctrl-close"]);
    let exit = within(spawned.wait).await;
    assert_eq!(exit.signal.as_deref(), Some("SIGHUP"), "{exit:?}");
    drain.abort();
}

/// The wide-console records `env-usr1` and `env-usr2` of the probe in `env`
/// mode: the names the session's program was told, and whether it could open
/// the events by them.
struct SeenEvents {
    events: Arc<SignalEvents>,
    usr1: String,
    usr2: String,
    out: String,
}

async fn probe_env(env: &[(&str, &str)]) -> (SeenEvents, SpawnedSource) {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("events.txt");
    let spec = probe_spec("env", &report, env);
    let events = Arc::new(SignalEvents::create().unwrap());
    let launch = plan(&spec, &events).unwrap();
    let mut session = ConPtySession::start(&launch, Arc::clone(&events), 200, 24).unwrap();
    session.console_ctrl_program = Some(probe_bin());
    let mut spawned = session.into_spawned().unwrap();
    // `ready` follows both records.
    let out = read_until(&mut spawned.output, READY).await;
    let seen = SeenEvents {
        events,
        usr1: record_value(&out, "env-usr1").expect("the Usr1 record"),
        usr2: record_value(&out, "env-usr2").expect("the Usr2 record"),
        out,
    };
    (seen, spawned)
}

/// The names of the events are in the session's environment, the program can
/// open them (the probe records `open-failed` otherwise), and both events
/// carry the owner-only DACL.
#[tokio::test]
async fn usr_signal_events_are_owner_only_and_named_in_the_session_environment() {
    let (seen, _spawned) = probe_env(&[]).await;
    let announced = seen.events.environment();
    assert_eq!(announced[0].1, seen.usr1);
    assert_eq!(announced[1].1, seen.usr2);
    for (name, suffix) in [(&seen.usr1, "-usr1"), (&seen.usr2, "-usr2")] {
        let id = name
            .strip_prefix(r"Local\qsh-sig-")
            .and_then(|rest| rest.strip_suffix(suffix))
            .unwrap_or_else(|| panic!("{name:?} is not a session event name"));
        assert_eq!(id.len(), 32, "{name}: 128 random bits");
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
    }
    assert_ne!(seen.usr1, seen.usr2);
    assert!(
        !strip_vt(&seen.out).contains("open-failed"),
        "the program could not open an event: {}",
        seen.out
    );
    assert_owner_only_report(
        "the Usr1 event",
        read_dacl_of_kernel_handle(seen.events.usr1.raw()),
        ObjectKind::Event,
    );
    assert_owner_only_report(
        "the Usr2 event",
        read_dacl_of_kernel_handle(seen.events.usr2.raw()),
        ObjectKind::Event,
    );
}

/// A client cannot point the signal variables elsewhere, in any case: the
/// host's names win (ADR-0035 decision 22), or `Usr1` could be aimed at an
/// event the client made.
#[tokio::test]
async fn usr_signal_event_variables_cannot_be_overridden_by_the_client() {
    let (seen, _spawned) = probe_env(&[
        ("QSH_SIGNAL_EVENT_USR1", r"Local\client-chosen-one"),
        ("qsh_signal_event_usr2", r"Local\client-chosen-two"),
    ])
    .await;
    let announced = seen.events.environment();
    assert_eq!(announced[0].1, seen.usr1);
    assert_eq!(announced[1].1, seen.usr2);
    assert!(
        !strip_vt(&seen.out).contains("client-chosen"),
        "{}",
        seen.out
    );
}

/// A program that handles `Usr1` or `Usr2` and exits on its own reports its
/// exit code and no signal, like a unix child that handled `SIGUSR1`.
#[tokio::test]
async fn usr1_handled_by_the_program_reports_its_exit_code_and_no_signal() {
    for (signal, code) in [(Signal::Usr1, 21), (Signal::Usr2, 22)] {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("events.txt");
        let (broker, clock) = broker(1 << 20);
        let handle = broker
            .open_with(&probe_spec("exit", &report, &[]), Box::new(source()))
            .unwrap();
        pull_until(&handle, &clock, usize::MAX, |ev| text(ev).contains(READY)).await;
        within(broker.close(&handle_id(&handle), CloseReason::Closed, Some(signal)))
            .await
            .unwrap();
        let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
            .await
            .unwrap();
        let (exit_code, exit_signal) = exit_of(&out.events).expect("the session ended");
        assert_eq!(exit_code, Some(code), "{signal}: the probe's exit code");
        assert_eq!(exit_signal, None, "{signal}: {:?}", out.events);
    }
}

/// A program that never waits on `Usr1` does not end by it. The close that
/// started with `Usr1` goes on to `Term` (the console close) and `Kill` on
/// the clock, as for any signal, and the session ends.
#[tokio::test]
async fn an_unwaited_usr_signal_ends_the_session_by_escalation() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("events.txt");
    let (broker, clock) = broker(1 << 20);
    let log = StageLog::default();
    let handle = broker
        .open_with(
            &probe_spec("hold", &report, &[]),
            Box::new(source().observe_stages(Arc::clone(&log))),
        )
        .unwrap();
    pull_until(&handle, &clock, usize::MAX, |ev| text(ev).contains(READY)).await;

    let closer = {
        let broker = Arc::clone(&broker);
        let id = handle_id(&handle);
        tokio::spawn(async move {
            broker
                .close(&id, CloseReason::Closed, Some(Signal::Usr1))
                .await
        })
    };
    let before = pull_until(&handle, &clock, usize::MAX, |ev| {
        text(ev).contains("<<QSH-SIGNAL event usr1>>")
    })
    .await;
    assert!(exit_of(&before).is_none(), "Usr1 alone ended the program");
    finish_by_escalation(&clock, closer).await;

    let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
        .await
        .unwrap();
    let (_, signal) = exit_of(&out.events).expect("the session ended");
    assert!(
        matches!(signal.as_deref(), Some("SIGTERM" | "SIGKILL")),
        "the exit reports the last step: {signal:?}"
    );
    let stages = log.lock().unwrap().clone();
    assert_eq!(stages[0], Step::SetEvent(UserEvent::Usr1), "{stages:?}");
    assert_eq!(stages[1], Step::CloseConsole, "{stages:?}");
    assert_eq!(reported(&report)[0], "usr1");
}

/// The exit a session reports carries the signal of the last step qsh sent.
/// A step that failed to send is not that step: the signal falls back to the
/// earlier one (here none) instead of claiming an event nobody received.
#[tokio::test]
async fn exit_after_a_qsh_sent_event_reports_the_stage_signal() {
    // Sent: `Usr2` is delivered and the session ends with it.
    {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("events.txt");
        let spec = probe_spec("exit", &report, &[]);
        let events = Arc::new(SignalEvents::create().unwrap());
        let launch = plan(&spec, &events).unwrap();
        let session = ConPtySession::start(&launch, events, 200, 24).unwrap();
        let mut spawned = session.into_spawned().unwrap();
        let mut output = spawned.output;
        read_until(&mut output, READY).await;
        let drain = drain(output);
        spawned.control.signal(Signal::Usr2).unwrap();
        let exit = within(spawned.wait).await;
        assert_eq!(exit.exit_code, Some(22), "{exit:?}");
        assert_eq!(exit.signal.as_deref(), Some("SIGUSR2"), "{exit:?}");
        drain.abort();
    }

    // Not sent: a helper that cannot start fails the `Int` step, which
    // leaves no note, and the later `Kill` is what the exit reports.
    {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("events.txt");
        let spec = probe_spec("hold", &report, &[]);
        let events = Arc::new(SignalEvents::create().unwrap());
        let launch = plan(&spec, &events).unwrap();
        let mut session = ConPtySession::start(&launch, events, 200, 24).unwrap();
        session.console_ctrl_program = Some(dir.path().join("no-such-helper.exe"));
        let log = Arc::clone(&session.log);
        let mut spawned = session.into_spawned().unwrap();
        let mut output = spawned.output;
        read_until(&mut output, READY).await;
        let drain = drain(output);
        assert!(spawned.control.signal(Signal::Int).is_err());
        assert!(log.lock().unwrap().is_empty(), "a failed step was logged");
        spawned.control.signal(Signal::Kill).unwrap();
        let exit = within(spawned.wait).await;
        assert_eq!(exit.signal.as_deref(), Some("SIGKILL"), "{exit:?}");
        assert!(reported(&report).is_empty());
        drain.abort();
    }
}

/// The helper reports delivery itself, and the host waits for the report. A
/// helper that starts and then fails (`AttachConsole` on a process that is
/// gone) is an error from `signal`, leaves no note, and the session that
/// then ends by itself reports no signal: its exit status could not have
/// told this apart from a delivered event.
#[tokio::test]
async fn a_failed_console_ctrl_delivery_leaves_no_signal_note() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("events.txt");
    let spec = probe_spec("exit", &report, &[]);
    let events = Arc::new(SignalEvents::create().unwrap());
    let launch = plan(&spec, &events).unwrap();
    let mut session = ConPtySession::start(&launch, events, 200, 24).unwrap();
    session.console_ctrl_program = Some(probe_bin());
    let log = Arc::clone(&session.log);
    let root = Arc::clone(&session.process);
    let mut spawned = session.into_spawned().unwrap();
    let mut output = spawned.output;
    read_until(&mut output, READY).await;
    let drain = drain(output);

    // End the root by itself, with no signal from qsh. The handle in `root`
    // keeps the process id valid, but nothing is left to attach to.
    // SAFETY: a live handle.
    unsafe { windows_sys::Win32::System::Threading::TerminateProcess(root.as_raw_handle(), 3) };
    // SAFETY: a live handle.
    let state = unsafe { WaitForSingleObject(root.as_raw_handle(), 30_000) };
    assert_eq!(state, WAIT_OBJECT_0, "the root did not end");

    for signal in [Signal::Int, Signal::Quit] {
        let err = spawned.control.signal(signal).unwrap_err();
        assert!(err.to_string().contains("did not deliver"), "{err}");
    }
    assert!(log.lock().unwrap().is_empty(), "a failed step was logged");
    let exit = within(spawned.wait).await;
    assert_eq!(exit.signal, None, "{exit:?}");
    assert!(reported(&report).is_empty());
    drain.abort();
}

/// The other side of the report: a `Quit` the helper delivered is kept as
/// the session's signal even though its receiver ends the session at once.
#[tokio::test]
async fn a_delivered_quit_is_still_reported_as_sigquit() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("events.txt");
    let spec = probe_spec("exit", &report, &[]);
    let events = Arc::new(SignalEvents::create().unwrap());
    let launch = plan(&spec, &events).unwrap();
    let mut session = ConPtySession::start(&launch, events, 200, 24).unwrap();
    session.console_ctrl_program = Some(probe_bin());
    let log = Arc::clone(&session.log);
    let mut spawned = session.into_spawned().unwrap();
    let mut output = spawned.output;
    read_until(&mut output, READY).await;
    let drain = drain(output);

    spawned.control.signal(Signal::Quit).unwrap();
    let exit = within(spawned.wait).await;
    assert_eq!(exit.exit_code, Some(11), "{exit:?}");
    assert_eq!(exit.signal.as_deref(), Some("SIGQUIT"), "{exit:?}");
    assert_eq!(*log.lock().unwrap(), vec![Stage::CtrlBreak]);
    assert_eq!(reported(&report), ["ctrl-break"]);
    drain.abort();
}
