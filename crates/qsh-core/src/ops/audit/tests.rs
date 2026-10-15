use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use qsh_proto::{AuditQueryReq, ErrorCode};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink};
use crate::ops::test_support::temp_ops;

fn ts(n: i64) -> String {
    OffsetDateTime::from_unix_timestamp(1_760_000_000 + n)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

fn record(n: i64) -> AuditRecord {
    AuditRecord {
        ts: ts(n),
        request_id: n.to_string(),
        principal: "device:laptop".to_string(),
        action: "exec.run".to_string(),
        resource: "exec".to_string(),
        decision: "allow".to_string(),
        rule: Some(0),
        auth_path: "pin".to_string(),
        peer_addr: "127.0.0.1:4433".to_string(),
        count: None,
        role: None,
    }
}

fn write_log(path: &Path, ns: &[i64]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = Vec::new();
    for n in ns {
        bytes.extend_from_slice(&serde_json::to_vec(&record(*n)).unwrap());
        bytes.push(b'\n');
    }
    fs::write(path, bytes).unwrap();
}

/// Every file under `dir` with its bytes, sorted, so "nothing was created,
/// changed or removed" is one comparison.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = fs::read(&path).unwrap();
                out.push((path, bytes));
            }
        }
    }
    out.sort();
    out
}

/// A sink that refuses every record, as a latched-degraded writer does.
struct DegradedSink;

impl AuditSink for DegradedSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Err(AuditError::Degraded)
    }
}

#[test]
fn audit_query_writes_no_audit_record() {
    let (dir, ops) = temp_ops();
    let memory = Arc::new(MemoryAuditSink::new());
    let ops = ops.with_audit_sink(memory.clone());
    let log = ops.paths().audit_log();
    write_log(&log, &[1, 2, 3]);
    write_log(&log.with_extension("log.1"), &[0]);

    let before = snapshot(dir.path());
    for _ in 0..3 {
        let data = ops.audit_query(AuditQueryReq::default()).unwrap();
        assert_eq!(data.records.len(), 4);
    }
    let filtered = ops
        .audit_query(AuditQueryReq {
            principal: Some("device:nobody".into()),
            limit: Some(1),
            ..Default::default()
        })
        .unwrap();
    assert!(filtered.records.is_empty());

    assert!(
        memory.records().is_empty(),
        "a query must not hand the audit sink a record"
    );
    assert_eq!(
        snapshot(dir.path()),
        before,
        "a query must not create, change or remove any file (no record, no lock sidecar)"
    );
}

#[test]
fn audit_query_works_while_the_op_audit_sink_is_degraded() {
    let (_dir, ops) = temp_ops();
    let ops = ops.with_audit_sink(Arc::new(DegradedSink));
    write_log(&ops.paths().audit_log(), &[1, 2]);

    let data = ops.audit_query(AuditQueryReq::default()).unwrap();
    assert_eq!(data.records.len(), 2);
    assert_eq!(data.skipped_lines, 0);
}

#[test]
fn audit_query_on_a_missing_log_is_empty_at_the_op_level() {
    let (_dir, ops) = temp_ops();
    let data = ops.audit_query(AuditQueryReq::default()).unwrap();
    assert!(data.records.is_empty());
    assert_eq!(data.oldest_ts, None);
    assert!(!data.truncated);
    assert_eq!(data.skipped_lines, 0);
}

#[test]
fn audit_query_reads_the_configured_path_and_retain() {
    let (dir, ops) = temp_ops();
    let moved = dir.path().join("elsewhere").join("moved.log");
    fs::create_dir_all(ops.paths().config_file().parent().unwrap()).unwrap();
    fs::write(
        ops.paths().config_file(),
        format!(
            "[audit]\npath = {path:?}\nretain = 1\n",
            path = moved.display().to_string()
        ),
    )
    .unwrap();
    // The default location holds a record the configured path must not show.
    write_log(&ops.paths().audit_log(), &[99]);
    write_log(&moved, &[3]);
    write_log(&PathBuf::from(format!("{}.1", moved.display())), &[2]);
    // retain = 1: a second rotated file is outside the horizon.
    write_log(&PathBuf::from(format!("{}.2", moved.display())), &[1]);

    let data = ops.audit_query(AuditQueryReq::default()).unwrap();
    let ids: Vec<&str> = data.records.iter().map(|r| r.request_id.as_str()).collect();
    assert_eq!(ids, ["3", "2"], "newest first, configured path only");
    assert_eq!(data.oldest_ts, Some(ts(2)));
}

#[test]
fn audit_query_with_an_unparseable_config_is_config_error_not_a_guess() {
    let (_dir, ops) = temp_ops();
    fs::create_dir_all(ops.paths().config_file().parent().unwrap()).unwrap();
    fs::write(ops.paths().config_file(), "[audit\nthis is not toml").unwrap();
    // A record at the default path must not be read as a fallback.
    write_log(&ops.paths().audit_log(), &[1]);

    let err = ops.audit_query(AuditQueryReq::default()).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
}

#[test]
fn audit_query_since_counts_back_from_the_supplied_clock() {
    let (_dir, ops) = temp_ops();
    write_log(&ops.paths().audit_log(), &[0, 60, 600, 3600]);
    let now =
        SystemTime::from(OffsetDateTime::from_unix_timestamp(1_760_000_000 + 3600 + 30).unwrap());

    let req = AuditQueryReq {
        since: Some("5m".into()),
        ..Default::default()
    };
    let data = ops.audit_query_at(&req, now).unwrap();
    let ids: Vec<&str> = data.records.iter().map(|r| r.request_id.as_str()).collect();
    assert_eq!(
        ids,
        ["3600"],
        "only the record within the last five minutes"
    );
    // The retention horizon ignores the filter.
    assert_eq!(data.oldest_ts, Some(ts(0)));
}

#[test]
fn audit_query_limit_and_decision_errors_are_invalid_argument_at_the_op_level() {
    let (_dir, ops) = temp_ops();
    write_log(&ops.paths().audit_log(), &[1]);
    for req in [
        AuditQueryReq {
            limit: Some(0),
            ..Default::default()
        },
        AuditQueryReq {
            limit: Some(1001),
            ..Default::default()
        },
        AuditQueryReq {
            decision: Some("maybe".into()),
            ..Default::default()
        },
    ] {
        let err = ops.audit_query(req.clone()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{req:?}");
    }
}
