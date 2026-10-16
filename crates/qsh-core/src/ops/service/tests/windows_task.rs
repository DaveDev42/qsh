//! The Task Scheduler row (ADR-0035 decision 27). Every test but the DACL one
//! runs on every build target: the renderer has no `cfg`, the host carries an
//! injected SID, and no test starts `schtasks`.

use std::sync::Arc;

use super::*;
use crate::audit::{AuditError, AuditRecord, AuditSink};

const EXE: &str = DOC_EXAMPLE_EXE_WINDOWS;
const SID: &str = DOC_EXAMPLE_USER_SID;

fn task_host(runner: &FakeRunner) -> ServiceHost<'_> {
    host_for(Manager::TaskScheduler, runner, Path::new(""))
}

/// UTF-16 little-endian after a byte order mark, decoded.
fn decode_task_file(bytes: &[u8]) -> String {
    assert_eq!(&bytes[..2], &[0xFF, 0xFE], "UTF-16 LE byte order mark");
    let (pairs, rest) = bytes[2..].as_chunks::<2>();
    assert!(rest.is_empty());
    let units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    String::from_utf16(&units).unwrap()
}

/// The task file at `path`, decoded from UTF-16.
fn read_task_file(path: &Path) -> String {
    decode_task_file(&std::fs::read(path).unwrap())
}

#[test]
fn windows_task_definition_renders_the_fixed_settings() {
    let xml = render_windows_task("serve", EXE, "", SID);
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"));
    // The trigger is the user's logon, repeating every minute with no end.
    assert!(xml.contains("<LogonTrigger>"));
    assert!(xml.contains(&format!("<UserId>{SID}</UserId>")));
    assert!(xml.contains(
        "<Interval>PT1M</Interval>\n        <StopAtDurationEnd>false</StopAtDurationEnd>"
    ));
    assert!(!xml.contains("<Duration>"));
    // No stored password and no elevation.
    assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
    assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
    assert!(!xml.contains("<BootTrigger>"));
    assert!(!xml.contains("HighestAvailable"));
    // One instance, no limits, no battery conditions, restart on failure.
    assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
    assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
    assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
    assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
    assert!(xml.contains(
        "<RestartOnFailure>\n      <Interval>PT1M</Interval>\n      <Count>999</Count>\n    </RestartOnFailure>"
    ));
    // The one action is `service run <mode>`, with the path unquoted when it
    // holds no whitespace.
    assert!(xml.contains(&format!("<Command>{EXE}</Command>")));
    assert!(xml.contains("<Arguments>service run serve</Arguments>"));
    assert_eq!(xml.matches("<Exec>").count(), 1);
}

#[test]
fn windows_task_definition_quotes_and_escapes_what_it_interpolates() {
    let xml = render_windows_task(
        "reverse",
        r"C:\Program Files\qsh & co\qsh.exe",
        "my controller",
        "S-1-5-21-1&2",
    );
    assert!(xml.contains(r"<Command>&quot;C:\Program Files\qsh &amp; co\qsh.exe&quot;</Command>"));
    assert!(xml.contains("<Arguments>service run reverse &quot;my controller&quot;</Arguments>"));
    assert!(xml.contains("<UserId>S-1-5-21-1&amp;2</UserId>"));
    // The controller literal is never split into extra argv elements.
    let xml = render_windows_task("reverse", EXE, r"back\slash\", SID);
    assert!(xml.contains("<Arguments>service run reverse back\\slash\\</Arguments>"));
    let xml = render_windows_task("reverse", EXE, "", SID);
    assert!(xml.contains("<Arguments>service run reverse &quot;&quot;</Arguments>"));
}

#[test]
fn windows_task_definition_covers_serve_listen_and_reverse_modes() {
    for (mode, description, arguments) in [
        ("serve", "qsh serve", "service run serve"),
        ("listen", "qsh listen", "service run listen"),
        (
            "reverse",
            "qsh serve --to",
            "service run reverse controller",
        ),
    ] {
        let xml = render_windows_task(mode, EXE, "controller", SID);
        assert!(
            xml.contains(&format!("<Description>{description}</Description>")),
            "{mode}"
        );
        assert!(
            xml.contains(&format!("<Arguments>{arguments}</Arguments>")),
            "{mode}"
        );
        // Only `reverse` names a controller; the others never carry one.
        assert_eq!(xml.contains("controller</Arguments>"), mode == "reverse");
    }
}

#[test]
fn windows_task_file_is_utf_16_little_endian_with_a_byte_order_mark() {
    let text = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\nécho\n";
    let bytes = encode_task_file(text);
    assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
    assert_eq!(&bytes[2..6], &[b'<', 0, b'?', 0]);
    assert_eq!(decode_task_file(&bytes), text);
}

#[test]
fn windows_task_path_is_under_config_dir_service() {
    let config_dir = Path::new("cfg");
    for mode in ["serve", "listen", "reverse"] {
        let path = unit_path(Manager::TaskScheduler, Path::new(""), config_dir, mode);
        assert_eq!(
            path,
            config_dir
                .join("service")
                .join(format!("qsh-{mode}.task.xml"))
        );
        assert_eq!(
            path,
            crate::doctor::probe::windows_task_definition_path(config_dir, mode)
        );
        assert_eq!(
            crate::doctor::probe::windows_task_name(mode),
            format!("\\qsh\\qsh-{mode}")
        );
    }
}

#[test]
fn windows_install_writes_the_definition_under_config_dir_and_reports_the_manager() {
    for (mode, config) in MODE_CONFIGS {
        let (_dir, ops) = ops_with(config);
        let runner = FakeRunner::default();
        let host = task_host(&runner);
        let data = ops
            .service_install_with_home(&host, None, false)
            .unwrap_or_else(|err| panic!("{mode}: {err:?}"));
        assert_eq!(data.manager, "task_scheduler");
        assert_eq!(data.mode, mode);
        assert!(data.created);
        assert_eq!(data.activation, None);
        let path = ops
            .paths()
            .config_dir
            .join("service")
            .join(format!("qsh-{mode}.task.xml"));
        assert_eq!(data.path, path.display().to_string());
        let text = read_task_file(&path);
        assert!(text.contains(&format!("<UserId>{SID}</UserId>")), "{mode}");
        assert!(text.contains(&format!("service run {mode}")), "{mode}");
        assert!(runner.calls().is_empty());

        // Rewriting reports `created: false` and the same bytes.
        let again = ops.service_install_with_home(&host, None, false).unwrap();
        assert!(!again.created);
        assert_eq!(read_task_file(&path), text);
    }
}

#[test]
fn windows_install_names_the_controller_of_a_reverse_task() {
    let (_dir, ops) = ops_with("[serve]\nto = \"ctrl box\"\n");
    let runner = FakeRunner::default();
    let host = task_host(&runner);
    let data = ops.service_install_with_home(&host, None, false).unwrap();
    assert_eq!(data.mode, "reverse");
    let text = read_task_file(Path::new(&data.path));
    assert!(text.contains("<Arguments>service run reverse &quot;ctrl box&quot;</Arguments>"));
}

#[test]
fn windows_install_without_a_user_sid_is_internal_and_writes_nothing() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let mut host = task_host(&runner);
    host.user_sid = None;
    let sink = Arc::new(crate::audit::FailingAuditSink::new());
    let ops = ops.with_audit_sink(sink.clone());
    let err = ops
        .service_install_with_home(&host, None, false)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(sink.records().is_empty());
    assert!(!ops.paths().config_dir.join("service").exists());
}

#[test]
fn windows_status_reports_existence_from_the_task_file_only() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let host = task_host(&runner);

    let before = ops.service_status_with_home(&host, None, false).unwrap();
    assert_eq!(before.manager, "task_scheduler");
    assert!(!before.installed);
    assert_eq!(before.active, None);

    ops.service_install_with_home(&host, None, false).unwrap();
    let after = ops.service_status_with_home(&host, None, false).unwrap();
    assert!(after.installed);
    assert_eq!(after.active, None);

    // A task registered by hand with no file here still reads as absent: the
    // scheduler is never asked.
    std::fs::remove_file(&after.path).unwrap();
    let removed = ops.service_status_with_home(&host, None, false).unwrap();
    assert!(!removed.installed);
    assert!(runner.calls().is_empty());
}

#[test]
fn windows_uninstall_deletes_the_file_only() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let host = task_host(&runner);

    let absent = ops.service_uninstall_with_home(&host, None, false).unwrap();
    assert_eq!(absent.manager, "task_scheduler");
    assert!(!absent.removed);

    let installed = ops.service_install_with_home(&host, None, false).unwrap();
    let removed = ops.service_uninstall_with_home(&host, None, false).unwrap();
    assert!(removed.removed);
    assert_eq!(removed.deactivation, None);
    assert!(!Path::new(&installed.path).exists());
    assert!(runner.calls().is_empty());
}

#[test]
fn windows_flags_are_unsupported_before_anything_is_read_or_written() {
    let (_dir, ops) = temp_ops();
    // A config the strict prefix would refuse: the flag check comes first.
    std::fs::create_dir_all(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().config_file(), "not valid toml === {{{").unwrap();
    let runner = FakeRunner::default();
    let host = task_host(&runner);
    for err in [
        ops.service_install_with_home(&host, None, true)
            .unwrap_err(),
        ops.service_uninstall_with_home(&host, None, true)
            .unwrap_err(),
        ops.service_status_with_home(&host, None, true).unwrap_err(),
    ] {
        assert_eq!(err.code, ErrorCode::Unsupported);
        assert!(!err.retryable);
    }
    assert!(runner.calls().is_empty());
    assert!(!ops.paths().config_dir.join("service").exists());
}

/// Records, at the moment of each audit record, whether the task file is
/// already there.
struct OrderingSink {
    task_file: PathBuf,
    seen: std::sync::Mutex<Vec<(AuditRecord, bool)>>,
}

impl AuditSink for OrderingSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.seen
            .lock()
            .unwrap()
            .push((record.clone(), self.task_file.exists()));
        Ok(())
    }
}

#[test]
fn windows_install_writes_one_audit_record_before_the_file() {
    let (_dir, ops) = ops_with("");
    let task_file = ops
        .paths()
        .config_dir
        .join("service")
        .join("qsh-serve.task.xml");
    let sink = Arc::new(OrderingSink {
        task_file: task_file.clone(),
        seen: Default::default(),
    });
    let ops = ops.with_audit_sink(sink.clone());
    let runner = FakeRunner::default();
    let host = task_host(&runner);

    ops.service_install_with_home(&host, None, false).unwrap();
    {
        let seen = sink.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].0.action, "service.install");
        assert_eq!(seen[0].0.resource, "serve");
        assert!(!seen[0].1, "the task file existed before its audit record");
    }
    assert!(task_file.exists());

    // The record is structural: no task text reaches it.
    let line = serde_json::to_string(&sink.seen.lock().unwrap()[0].0).unwrap();
    assert!(!line.contains("LogonTrigger") && !line.contains(SID));

    ops.service_uninstall_with_home(&host, None, false).unwrap();
    let seen = sink.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].0.action, "service.uninstall");
    assert!(seen[1].1, "the file is removed after its audit record");
}

#[test]
fn windows_install_is_refused_when_the_audit_sink_fails() {
    let (_dir, ops) = ops_with("");
    let sink = Arc::new(crate::audit::FailingAuditSink::new());
    sink.fail();
    let ops = ops.with_audit_sink(sink);
    let runner = FakeRunner::default();
    let host = task_host(&runner);
    let err = ops
        .service_install_with_home(&host, None, false)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(!ops.paths().config_dir.join("service").exists());
}

#[cfg(windows)]
#[test]
fn windows_task_definition_file_has_an_owner_only_dacl() {
    use crate::fsutil::dacl::ObjectKind;
    use crate::fsutil::dacl::testing::assert_owner_only;

    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    // The real SID: the DACL pin compares against the token user.
    let mut host = task_host(&runner);
    host.user_sid = current_user_sid();
    let data = ops.service_install_with_home(&host, None, false).unwrap();
    assert_owner_only(Path::new(&data.path), ObjectKind::File);
    assert_owner_only(&ops.paths().config_dir.join("service"), ObjectKind::Dir);
}
