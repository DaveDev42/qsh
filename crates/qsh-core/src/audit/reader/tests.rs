use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use qsh_proto::ErrorCode;
use qsh_proto::types::{AuditQueryReq, AuditRecordView};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::*;
use crate::audit::{AuditError, AuditSink, RotatingAuditSink};

/// 2026-10-16T12:00:00Z, the injected clock of every relative-`since` row.
fn fixed_now() -> SystemTime {
    SystemTime::from(OffsetDateTime::parse("2026-10-16T12:00:00Z", &Rfc3339).unwrap())
}

/// An RFC 3339 `ts` `n` seconds after a fixed base, so records order by `n`.
fn ts(n: i64) -> String {
    OffsetDateTime::from_unix_timestamp(1_760_000_000 + n)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

fn record(n: i64, principal: &str, action: &str, resource: &str, decision: &str) -> AuditRecord {
    AuditRecord {
        ts: ts(n),
        request_id: n.to_string(),
        principal: principal.to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        decision: decision.to_string(),
        rule: None,
        auth_path: "pin".to_string(),
        peer_addr: "127.0.0.1:4433".to_string(),
        count: None,
        role: None,
    }
}

fn simple(n: i64) -> AuditRecord {
    record(n, "device:laptop", "exec.run", "exec", "allow")
}

fn line_of(record: &AuditRecord) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(record).unwrap();
    bytes.push(b'\n');
    bytes
}

fn write_log(path: &Path, records: &[AuditRecord]) {
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend_from_slice(&line_of(record));
    }
    fs::write(path, bytes).unwrap();
}

fn run(path: &Path, retain: u32, req: &AuditQueryReq) -> AuditQueryData {
    query(path, retain, req, fixed_now()).unwrap()
}

fn ids(data: &AuditQueryData) -> Vec<String> {
    data.records.iter().map(|r| r.request_id.clone()).collect()
}

fn log_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("audit.log")
}

#[test]
fn audit_record_view_fields_equal_audit_record_fields() {
    // Every optional key present.
    let mut full = simple(1);
    full.rule = Some(3);
    full.count = Some(9);
    full.role = Some("operator".to_string());
    // Every optional key absent: the stored line has `rule: null` and no
    // `count` or `role`, and the view must show exactly the same keys.
    let bare = simple(2);

    for record in [full, bare] {
        let stored = serde_json::to_value(&record).unwrap();
        let shown = serde_json::to_value(record_view(record.clone())).unwrap();
        assert_eq!(
            stored, shown,
            "the view must be the record, field for field"
        );
    }

    // The view round-trips through its own JSON (what `audit.query` emits).
    let view = record_view(simple(3));
    let back: AuditRecordView =
        serde_json::from_value(serde_json::to_value(&view).unwrap()).unwrap();
    assert_eq!(back, view);
}

#[test]
fn audit_query_reads_active_and_rotated_files_newest_first() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    write_log(&rotated_path(&path, 2), &[simple(1), simple(2)]);
    write_log(&rotated_path(&path, 1), &[simple(3), simple(4)]);
    write_log(&path, &[simple(5), simple(6)]);
    // Beyond `retain`: a stale leftover the writer would sweep, never read.
    write_log(&rotated_path(&path, 3), &[simple(99)]);

    let data = run(&path, 2, &AuditQueryReq::default());
    assert_eq!(ids(&data), ["6", "5", "4", "3", "2", "1"]);
    assert_eq!(data.skipped_lines, 0);
    assert!(!data.truncated);

    // `retain = 0` reads the active file alone.
    let data = run(&path, 0, &AuditQueryReq::default());
    assert_eq!(ids(&data), ["6", "5"]);
}

#[test]
fn audit_query_filters_are_and_combined() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    write_log(
        &path,
        &[
            record(1, "device:a", "exec.run", "exec", "allow"),
            record(2, "device:a", "exec.run", "exec", "deny"),
            record(3, "device:b", "exec.run", "exec", "allow"),
            record(4, "device:a", "session.open", "s1", "allow"),
            record(5, "device:a", "exec.run", "other", "allow"),
            record(6, "device:a", "exec.run", "exec", "allow"),
        ],
    );
    let req = |f: &dyn Fn(&mut AuditQueryReq)| {
        let mut req = AuditQueryReq::default();
        f(&mut req);
        ids(&run(&path, 0, &req))
    };

    assert_eq!(req(&|r| r.principal = Some("device:a".into())).len(), 5);
    assert_eq!(req(&|r| r.action = Some("session.open".into())), ["4"]);
    assert_eq!(req(&|r| r.resource = Some("other".into())), ["5"]);
    assert_eq!(req(&|r| r.decision = Some("deny".into())), ["2"]);
    // Exact match, not prefix or substring.
    assert!(req(&|r| r.principal = Some("device".into())).is_empty());
    assert!(req(&|r| r.action = Some("exec".into())).is_empty());
    // Combined: every set filter must hold.
    assert_eq!(
        req(&|r| {
            r.principal = Some("device:a".into());
            r.action = Some("exec.run".into());
            r.resource = Some("exec".into());
            r.decision = Some("allow".into());
        }),
        ["6", "1"]
    );
    assert!(
        req(&|r| {
            r.principal = Some("device:b".into());
            r.decision = Some("deny".into());
        })
        .is_empty()
    );
    // Time bounds are inclusive and AND with the rest.
    assert_eq!(
        req(&|r| {
            r.since = Some(ts(2));
            r.until = Some(ts(4));
            r.principal = Some("device:a".into());
        }),
        ["4", "2"]
    );
}

#[test]
fn audit_query_limit_above_the_cap_is_invalid_argument() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    write_log(&path, &(0..150).map(simple).collect::<Vec<_>>());

    for bad in [MAX_LIMIT + 1, u32::MAX, 0] {
        let req = AuditQueryReq {
            limit: Some(bad),
            ..AuditQueryReq::default()
        };
        let err = query(&path, 0, &req, fixed_now()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "limit {bad}");
    }
    let err = query(
        &path,
        0,
        &AuditQueryReq {
            decision: Some("maybe".into()),
            ..AuditQueryReq::default()
        },
        fixed_now(),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    // The cap itself is allowed, and the default is 100.
    let req = AuditQueryReq {
        limit: Some(MAX_LIMIT),
        ..AuditQueryReq::default()
    };
    assert_eq!(run(&path, 0, &req).records.len(), 150);
    let data = run(&path, 0, &AuditQueryReq::default());
    assert_eq!(data.records.len(), DEFAULT_LIMIT as usize);
    assert!(data.truncated);
    assert_eq!(data.records[0].request_id, "149");
}

#[test]
fn audit_query_skips_a_torn_line_and_counts_it_without_echoing_it() {
    const SECRET: &str = "SECRET-PAYLOAD-MARKER";
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    let mut bytes = line_of(&simple(1));
    // A line cut mid-record, one that is not JSON at all, and bytes that are
    // not UTF-8: each is one skipped line.
    bytes.extend_from_slice(
        format!("{{\"ts\":\"{}\",\"request_id\":\"{SECRET}\n", ts(2)).as_bytes(),
    );
    bytes.extend_from_slice(format!("not json {SECRET}\n").as_bytes());
    bytes.extend_from_slice(b"\xff\xfe\xfd\n");
    bytes.extend_from_slice(&line_of(&simple(3)));
    // The writer is mid-append: a torn tail with no newline.
    bytes.extend_from_slice(format!("{{\"ts\":\"{}\",\"resource\":\"{SECRET}", ts(4)).as_bytes());
    fs::write(&path, bytes).unwrap();

    let data = run(&path, 0, &AuditQueryReq::default());
    assert_eq!(ids(&data), ["3", "1"]);
    assert_eq!(data.skipped_lines, 4);
    let shown = serde_json::to_string(&data).unwrap();
    assert!(!shown.contains(SECRET), "a skipped line must not be echoed");
    assert!(!shown.contains("not json"));
}

#[test]
fn audit_query_skips_overlong_lines_and_counts_them() {
    const SECRET: &str = "OVERLONG-MARKER";
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    let mut bytes = line_of(&simple(1));
    // One byte over the cap, then exactly at the cap (garbage, so it fails
    // to parse and is counted as skipped too), then a line larger than a
    // reader buffer several times over.
    let mut over = SECRET.as_bytes().to_vec();
    over.resize(MAX_LINE_BYTES + 1, b'a');
    over.push(b'\n');
    bytes.extend_from_slice(&over);
    let mut at_cap = SECRET.as_bytes().to_vec();
    at_cap.resize(MAX_LINE_BYTES, b'b');
    at_cap.push(b'\n');
    bytes.extend_from_slice(&at_cap);
    let mut huge = SECRET.as_bytes().to_vec();
    huge.resize(MAX_LINE_BYTES * 5, b'c');
    huge.push(b'\n');
    bytes.extend_from_slice(&huge);
    bytes.extend_from_slice(&line_of(&simple(2)));
    // An overlong tail with no newline at end of file.
    bytes.extend_from_slice(&vec![b'd'; MAX_LINE_BYTES + 10]);
    fs::write(&path, bytes).unwrap();

    let data = run(&path, 0, &AuditQueryReq::default());
    assert_eq!(
        ids(&data),
        ["2", "1"],
        "good lines around overlong ones survive"
    );
    assert_eq!(data.skipped_lines, 4);
    assert!(!serde_json::to_string(&data).unwrap().contains(SECRET));
}

/// Every regular file under `dir` with its bytes, for a before/after compare.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(&path).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn audit_query_does_not_modify_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    write_log(&rotated_path(&path, 1), &[simple(1), simple(2)]);
    // A torn tail: a writer would repair it, a reader must leave it alone.
    let mut active = line_of(&simple(3));
    active.extend_from_slice(b"{\"ts\":\"torn");
    fs::write(&path, active).unwrap();

    let before = snapshot(dir.path());
    for req in [
        AuditQueryReq::default(),
        AuditQueryReq {
            principal: Some("nobody".into()),
            limit: Some(1),
            ..AuditQueryReq::default()
        },
    ] {
        run(&path, 2, &req);
    }
    assert_eq!(
        snapshot(dir.path()),
        before,
        "bytes and file set are unchanged"
    );
    assert!(
        !dir.path().join("audit.log.lock").exists(),
        "the reader never creates the writer's lock file"
    );
}

#[test]
fn audit_query_works_while_the_audit_sink_is_degraded() {
    let dir = tempfile::tempdir().unwrap();
    // A superuser appends to a read-only file regardless, so the sink would
    // never latch.
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
    }
    let path = log_in(&dir);
    {
        let sink = RotatingAuditSink::spawn(&path, 64 * 1024, 2, 8);
        for n in 0..3 {
            let mut attempts = 0;
            while sink.record(&simple(n)).is_err() {
                attempts += 1;
                assert!(attempts < 1_000_000, "healthy sink must accept records");
                std::thread::yield_now();
            }
        }
    } // dropping the sink flushes and joins the writer thread

    // A read-only file makes the next writer's append-open fail on every
    // platform, which latches it degraded.
    let original = fs::metadata(&path).unwrap().permissions();
    let mut readonly = original.clone();
    readonly.set_readonly(true);
    fs::set_permissions(&path, readonly).unwrap();

    let before = fs::read(&path).unwrap();
    let sink = RotatingAuditSink::spawn(&path, 64 * 1024, 2, 8);
    let mut latched = false;
    for n in 100..200_000 {
        match sink.record(&simple(n)) {
            Err(AuditError::Degraded) => {
                latched = true;
                break;
            }
            Ok(()) | Err(AuditError::QueueFull) => std::thread::yield_now(),
        }
    }
    assert!(latched, "an unwritable log must latch the writer degraded");

    let data = run(&path, 2, &AuditQueryReq::default());
    assert_eq!(
        ids(&data),
        ["2", "1", "0"],
        "the log reads while the sink is degraded"
    );
    assert!(
        sink.is_degraded(),
        "reading neither clears nor needs the latch"
    );
    assert_eq!(fs::read(&path).unwrap(), before, "and writes nothing");

    // Restore before the sink's drop flush so the temp dir cleans up.
    fs::set_permissions(&path, original).unwrap();
    drop(sink);
}

#[test]
fn audit_query_on_a_missing_log_is_empty_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let data = run(
        &dir.path().join("never-written.log"),
        5,
        &AuditQueryReq::default(),
    );
    assert_eq!(
        data,
        AuditQueryData {
            records: Vec::new(),
            skipped_lines: 0,
            oldest_ts: None,
            truncated: false,
        }
    );
    // A directory that does not exist yet is the same.
    let data = run(
        &dir.path().join("no/such/dir/audit.log"),
        5,
        &AuditQueryReq::default(),
    );
    assert!(data.records.is_empty() && data.oldest_ts.is_none());
}

#[test]
fn audit_query_oldest_ts_matches_the_oldest_retained_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    write_log(&rotated_path(&path, 2), &[simple(10), simple(11)]);
    write_log(&rotated_path(&path, 1), &[simple(12)]);
    write_log(&path, &[simple(13)]);

    // Independent of every filter, including ones that exclude the record.
    let req = AuditQueryReq {
        principal: Some("device:nobody".into()),
        since: Some(ts(13)),
        ..AuditQueryReq::default()
    };
    let data = run(&path, 2, &req);
    assert!(data.records.is_empty());
    assert_eq!(data.oldest_ts.as_deref(), Some(ts(10).as_str()));
    // Limited output does not move the horizon.
    let limited = AuditQueryReq {
        limit: Some(1),
        ..AuditQueryReq::default()
    };
    assert_eq!(
        run(&path, 2, &limited).oldest_ts.as_deref(),
        Some(ts(10).as_str())
    );

    // Retention drops the oldest file: the horizon moves with it.
    fs::remove_file(rotated_path(&path, 2)).unwrap();
    assert_eq!(
        run(&path, 2, &AuditQueryReq::default())
            .oldest_ts
            .as_deref(),
        Some(ts(12).as_str())
    );

    // A torn first line is skipped, so the horizon is the first real record.
    let mut bytes = b"{\"ts\":\"torn\n".to_vec();
    bytes.extend_from_slice(&line_of(&simple(20)));
    fs::write(rotated_path(&path, 1), bytes).unwrap();
    assert_eq!(
        run(&path, 2, &AuditQueryReq::default())
            .oldest_ts
            .as_deref(),
        Some(ts(20).as_str())
    );
}

#[test]
fn audit_query_since_accepts_rfc3339_and_relative_units() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    // `fixed_now()` is 2026-10-16T12:00:00Z.
    let at = |text: &str| OffsetDateTime::parse(text, &Rfc3339).unwrap();
    let stamps = [
        "2026-10-14T12:00:00Z", // exactly 2d before
        "2026-10-15T12:00:00Z", // exactly 1d before
        "2026-10-16T10:59:59Z", // 1h + 1s before
        "2026-10-16T11:00:00Z", // exactly 1h before
        "2026-10-16T11:30:00Z", // exactly 30m before
        "2026-10-16T11:58:30Z", // exactly 90s before
        "2026-10-16T12:00:00Z", // now
    ];
    let records: Vec<_> = stamps
        .iter()
        .enumerate()
        .map(|(i, text)| {
            let mut r = simple(i as i64);
            r.ts = (*text).to_string();
            r
        })
        .collect();
    write_log(&path, &records);

    let count = |since: &str| {
        let req = AuditQueryReq {
            since: Some(since.to_string()),
            ..AuditQueryReq::default()
        };
        run(&path, 0, &req).records.len()
    };
    // Relative spans count back from the injected clock, inclusive.
    assert_eq!(count("90s"), 2);
    assert_eq!(count("30m"), 3);
    assert_eq!(count("1h"), 4);
    assert_eq!(count("1d"), 6);
    assert_eq!(count("2d"), 7);
    assert_eq!(count("0s"), 1);
    // Absolute RFC 3339, in UTC and with an offset naming the same instant.
    assert_eq!(count("2026-10-16T11:00:00Z"), 4);
    assert_eq!(count("2026-10-16T20:00:00+09:00"), 4);
    assert_eq!(at("2026-10-16T20:00:00+09:00"), at("2026-10-16T11:00:00Z"));

    // `until` is RFC 3339 only.
    let until = |text: &str| {
        let req = AuditQueryReq {
            until: Some(text.to_string()),
            ..AuditQueryReq::default()
        };
        query(&path, 0, &req, fixed_now())
    };
    assert_eq!(until("2026-10-15T12:00:00Z").unwrap().records.len(), 2);
    assert_eq!(until("1h").unwrap_err().code, ErrorCode::InvalidArgument);

    for bad in [
        "",
        "m",
        "5",
        "5x",
        "-5m",
        "1.5h",
        " 1h",
        "1h ",
        "+1h",
        "yesterday",
        "99999999999999999999d",
        "9223372036854775807d",
    ] {
        let req = AuditQueryReq {
            since: Some(bad.to_string()),
            ..AuditQueryReq::default()
        };
        let err = query(&path, 0, &req, fixed_now()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "since {bad:?}");
    }
}

#[test]
fn audit_query_role_key_is_present_only_when_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    let mut with_role = simple(1);
    with_role.role = Some("operator".to_string());
    // A line written before roles existed has no `role` key at all.
    let mut bytes = br#"{"ts":"2026-10-16T00:00:00Z","request_id":"0","principal":"device:old","action":"exec.run","resource":"exec","decision":"allow","rule":null,"auth_path":"pin","peer_addr":"127.0.0.1:1"}"#
        .to_vec();
    bytes.push(b'\n');
    bytes.extend_from_slice(&line_of(&with_role));
    bytes.extend_from_slice(&line_of(&simple(2)));
    fs::write(&path, bytes).unwrap();

    let data = run(&path, 0, &AuditQueryReq::default());
    assert_eq!(data.skipped_lines, 0);
    let json = serde_json::to_value(&data).unwrap();
    let rows = json["records"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    // Newest first: plain, with role, legacy.
    assert!(rows[0].get("role").is_none());
    assert_eq!(rows[1]["role"], "operator");
    assert!(rows[2].get("role").is_none());
    for row in rows {
        assert!(row.get("count").is_none());
        assert!(
            row.get("rule").is_some(),
            "rule is always present, null when unset"
        );
    }
}

#[cfg(unix)]
#[test]
fn audit_query_unreadable_log_is_internal_with_path_and_kind_only() {
    use std::os::unix::fs::PermissionsExt;

    const SECRET: &str = "UNREADABLE-CONTENT-MARKER";
    // A superuser reads a mode-0 file regardless, so the row cannot fail.
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    let mut r = simple(1);
    r.resource = SECRET.to_string();
    write_log(&path, &[r]);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

    let err = query(&path, 0, &AuditQueryReq::default(), fixed_now()).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(
        err.message.contains(&path.display().to_string()),
        "{}",
        err.message
    );
    assert!(err.message.contains("permission denied"), "{}", err.message);
    assert!(!err.message.contains(SECRET));
    assert!(
        !err.message.contains("os error"),
        "kind only: {}",
        err.message
    );

    // The same holds for a rotated file.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let rotated = rotated_path(&path, 1);
    write_log(&rotated, &[simple(2)]);
    fs::set_permissions(&rotated, fs::Permissions::from_mode(0o000)).unwrap();
    let err = query(&path, 1, &AuditQueryReq::default(), fixed_now()).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(err.message.contains(&rotated.display().to_string()));
}

#[cfg(unix)]
#[test]
fn audit_query_refuses_a_non_regular_audit_path_without_blocking() {
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a valid NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

    let err = query(&path, 0, &AuditQueryReq::default(), fixed_now()).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(err.message.contains(&path.display().to_string()));
    assert!(
        err.message.contains("not a regular file"),
        "{}",
        err.message
    );
}

/// The Windows row of the test above: a DACL that denies read access plays
/// the part of mode 0 (ADR-0033 decision 6, ADR-0035 decision 9).
#[cfg(windows)]
#[test]
fn audit_query_unreadable_log_is_internal_with_path_and_kind_only() {
    use crate::fsutil::dacl::testing::deny_all_access;

    const SECRET: &str = "UNREADABLE-CONTENT-MARKER";
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    let mut r = simple(1);
    r.resource = SECRET.to_string();
    write_log(&path, &[r]);
    deny_all_access(&path);

    let err = query(&path, 0, &AuditQueryReq::default(), fixed_now()).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(
        err.message.contains(&path.display().to_string()),
        "{}",
        err.message
    );
    assert!(err.message.contains("permission denied"), "{}", err.message);
    assert!(!err.message.contains(SECRET));
    assert!(
        !err.message.contains("os error"),
        "kind only: {}",
        err.message
    );

    // The same holds for a rotated file.
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    write_log(&path, &[simple(1)]);
    let rotated = rotated_path(&path, 1);
    write_log(&rotated, &[simple(2)]);
    deny_all_access(&rotated);
    let err = query(&path, 1, &AuditQueryReq::default(), fixed_now()).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(err.message.contains(&rotated.display().to_string()));
}

#[test]
fn audit_query_truncated_is_set_only_when_the_limit_cut_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    write_log(&path, &(0..5).map(simple).collect::<Vec<_>>());
    let with = |limit: u32| {
        let req = AuditQueryReq {
            limit: Some(limit),
            ..AuditQueryReq::default()
        };
        run(&path, 0, &req)
    };
    // Exactly the limit: nothing was cut.
    let data = with(5);
    assert_eq!(data.records.len(), 5);
    assert!(!data.truncated);
    // One short: the oldest match is cut, the newest are kept.
    let data = with(4);
    assert_eq!(ids(&data), ["4", "3", "2", "1"]);
    assert!(data.truncated);
    let data = with(1);
    assert_eq!(ids(&data), ["4"]);
    assert!(data.truncated);
    // Records the filters exclude do not count as cut.
    let mut mixed: Vec<_> = (0..5).map(simple).collect();
    mixed.extend((5..9).map(|n| record(n, "device:other", "exec.run", "exec", "deny")));
    write_log(&path, &mixed);
    let req = AuditQueryReq {
        decision: Some("allow".into()),
        limit: Some(5),
        ..AuditQueryReq::default()
    };
    let data = run(&path, 0, &req);
    assert_eq!(data.records.len(), 5);
    assert!(!data.truncated);
}

#[test]
fn audit_query_reads_while_the_writer_rotates() {
    // Phase 1, deterministic: a handle opened the way the reader opens files
    // must not stop the writer's rotation. On Windows this is what
    // FILE_SHARE_DELETE buys; on Unix it holds trivially.
    {
        let dir = tempfile::tempdir().unwrap();
        let path = log_in(&dir);
        write_log(&path, &[simple(1)]);
        let held = open_read_only(&path).unwrap().expect("file exists");
        let rotated = rotated_path(&path, 1);
        fs::rename(&path, &rotated).expect("a reader's handle must not block the rotation rename");
        // The writer starts the next active file and keeps appending.
        write_log(&path, &[simple(2)]);
        let data = run(&path, 1, &AuditQueryReq::default());
        assert_eq!(ids(&data), ["2", "1"]);
        // Evicting the oldest slot must work while the handle is still open.
        fs::remove_file(&rotated)
            .expect("a reader's handle must not block deleting a rotated file");
        drop(held);
    }

    // Phase 2: a real writer thread rotating a tiny log while queries run
    // back to back. The queries must never fail and the writer must never
    // block; the record count seen mid-rotation is not asserted (ADR-0033
    // 결정 6 puts "never block" above exactness).
    const TOTAL: i64 = 20_000;
    const RETAIN: u32 = 3;
    let dir = tempfile::tempdir().unwrap();
    let path = log_in(&dir);
    let sink = RotatingAuditSink::spawn(&path, 4096, RETAIN, 64);
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Sets `done` on every exit of the writer thread, a panic included, so a
    // failing writer ends the query loop and the test fails fast at `join`.
    struct SetOnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let writer = {
        let guard = SetOnDrop(std::sync::Arc::clone(&done));
        std::thread::spawn(move || {
            let _guard = guard;
            for n in 0..TOTAL {
                loop {
                    match sink.record(&simple(n)) {
                        Ok(()) => break,
                        Err(AuditError::QueueFull) => std::thread::yield_now(),
                        Err(AuditError::Degraded) => panic!("the writer latched degraded"),
                    }
                }
            }
            drop(sink); // flushes and joins the writer thread
        })
    };

    let mut queries = 0u32;
    while !done.load(std::sync::atomic::Ordering::SeqCst) {
        let data = query(&path, RETAIN, &AuditQueryReq::default(), fixed_now())
            .expect("a query must not fail while the writer rotates");
        assert!(data.records.len() <= DEFAULT_LIMIT as usize);
        queries += 1;
    }
    writer
        .join()
        .expect("the writer must finish: a reader never blocks it");
    assert!(queries > 0);

    // Quiescent now: the writer rotated at least `RETAIN` times (so no
    // rename was ever stuck behind a reader) and the newest record leads.
    assert!(
        rotated_path(&path, RETAIN).exists(),
        "rotation must have run at least {RETAIN} times"
    );
    let data = run(&path, RETAIN, &AuditQueryReq::default());
    assert_eq!(data.records[0].request_id, (TOTAL - 1).to_string());
    assert_eq!(data.skipped_lines, 0);
}

/// The reader opens files for reading only (ADR-0033 결정 6, 10): no write,
/// append, truncate or create mode, no lock, and nothing that removes or
/// renames a file may appear in the module's code.
#[test]
fn audit_reader_source_has_no_write_mode_open_and_no_delete_api() {
    let source = include_str!("../reader.rs");
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        ".write(",
        ".append(",
        ".truncate(",
        ".create(",
        ".create_new(",
        "set_len",
        "remove_file",
        "remove_dir",
        "rename(",
        "flock",
        "LockFile",
        "fs2",
        "fs::write",
        "File::create",
    ] {
        assert!(
            !code.contains(banned),
            "reader.rs must not contain {banned:?}"
        );
    }
    assert!(code.contains(".read(true)"));
}
