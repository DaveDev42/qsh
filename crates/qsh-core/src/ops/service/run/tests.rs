use std::io::Write as _;

use super::*;
use crate::ops::test_support::temp_ops;

#[test]
fn service_log_paths_sit_under_the_state_dir_log_directory() {
    let (_dir, ops) = temp_ops();
    for mode in SERVICE_RUN_MODES {
        let (out, err) = service_log_paths(ops.paths(), mode);
        let log = ops.paths().state_dir.join("log");
        assert_eq!(out, log.join(format!("{mode}.out.log")));
        assert_eq!(err, log.join(format!("{mode}.err.log")));
    }
}

#[test]
fn service_run_logs_are_appended_to_not_truncated() {
    let (_dir, ops) = temp_ops();
    let (mut out, mut err) = open_service_logs(ops.paths(), "serve").unwrap();
    out.write_all(b"first out\n").unwrap();
    err.write_all(b"first err\n").unwrap();
    drop((out, err));

    let (mut out, mut err) = open_service_logs(ops.paths(), "serve").unwrap();
    out.write_all(b"second out\n").unwrap();
    err.write_all(b"second err\n").unwrap();
    drop((out, err));

    let (out_path, err_path) = service_log_paths(ops.paths(), "serve");
    assert_eq!(
        std::fs::read_to_string(out_path).unwrap(),
        "first out\nsecond out\n"
    );
    assert_eq!(
        std::fs::read_to_string(err_path).unwrap(),
        "first err\nsecond err\n"
    );
}

#[test]
fn a_log_directory_that_cannot_be_made_fails_before_anything_is_opened() {
    let (_dir, ops) = temp_ops();
    std::fs::create_dir_all(&ops.paths().state_dir).unwrap();
    std::fs::write(ops.paths().state_dir.join("log"), b"a file").unwrap();
    assert!(open_service_logs(ops.paths(), "listen").is_err());
}

#[cfg(unix)]
#[test]
fn service_run_log_files_have_an_owner_only_mode() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_dir, ops) = temp_ops();
    open_service_logs(ops.paths(), "serve").unwrap();
    let (out, err) = service_log_paths(ops.paths(), "serve");
    for path in [out, err] {
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{}", path.display());
    }
}

#[cfg(windows)]
#[test]
fn service_run_log_files_have_an_owner_only_dacl() {
    use crate::fsutil::dacl::ObjectKind;
    use crate::fsutil::dacl::testing::assert_owner_only;

    let (_dir, ops) = temp_ops();
    for mode in SERVICE_RUN_MODES {
        open_service_logs(ops.paths(), mode).unwrap();
        let (out, err) = service_log_paths(ops.paths(), mode);
        assert_owner_only(&out, ObjectKind::File);
        assert_owner_only(&err, ObjectKind::File);
    }
    assert_owner_only(&ops.paths().state_dir.join("log"), ObjectKind::Dir);
}
