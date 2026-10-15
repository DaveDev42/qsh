//! Read-only audit log reader behind `audit.query` (ADR-0033 결정 5~10,
//! `docs/design/architecture.md` §6).
//!
//! The reader is the mirror image of [`super::writer`]: it never takes the
//! writer's sidecar lock, never repairs a torn tail, and opens every file
//! with read access only. There is deliberately no function here that
//! deletes, truncates or rewrites a log (결정 10); retention stays the
//! writer's count-based rotation alone.
//!
//! **Order and bounds.** Files are read oldest first (`<path>.<retain>` down
//! to `<path>.1`, then the active file), each exactly once, and records are
//! kept in a window of at most `limit` entries, so memory is bounded by the
//! limit rather than by `[audit].max_bytes`. The window is returned newest
//! first. A line over [`MAX_LINE_BYTES`] is skipped without being buffered.
//!
//! **No payloads in errors.** A line that does not parse, is cut short or is
//! too long is only counted in `skipped_lines`; its bytes never reach an error
//! message or the output (결정 6). An unreadable file is `INTERNAL` carrying the
//! path and the [`io::ErrorKind`], nothing else.
//!
//! **Platforms.** The same code runs on Unix and Windows. On Windows each
//! file is opened with `FILE_SHARE_READ | FILE_SHARE_WRITE |
//! FILE_SHARE_DELETE`, so the writer can keep appending and can rename the
//! file during rotation while a query holds it (결정 6). The host-side
//! `LockFileEx` lock (ADR-0035 결정 24) sits on the sidecar lock file this
//! module never opens.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::time::SystemTime;

use qsh_proto::ErrorCode;
use qsh_proto::types::{AuditQueryData, AuditQueryReq, AuditRecordView};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use super::AuditRecord;
use super::writer::rotated_path;
use crate::ops::OpError;

/// `limit` when the request names none (ADR-0033 결정 5).
pub const DEFAULT_LIMIT: u32 = 100;
/// The largest accepted `limit`; above it the request is `INVALID_ARGUMENT`.
pub const MAX_LIMIT: u32 = 1000;
/// Longest line the reader will parse, 64 KiB. The writer's records are far
/// smaller; a longer line is skipped and counted, never buffered.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Move an [`AuditRecord`] into its [`AuditRecordView`], field for field
/// (ADR-0033 결정 8). The destructuring is exhaustive on purpose: a field
/// added to [`AuditRecord`] stops compiling here until someone decides
/// whether the view shows it.
pub fn record_view(record: AuditRecord) -> AuditRecordView {
    let AuditRecord {
        ts,
        request_id,
        principal,
        action,
        resource,
        decision,
        rule,
        auth_path,
        peer_addr,
        count,
        role,
    } = record;
    AuditRecordView {
        ts,
        request_id,
        principal,
        action,
        resource,
        decision,
        rule,
        auth_path,
        peer_addr,
        count,
        role,
    }
}

/// Answer an `audit.query` against the log at `active` and its `retain`
/// rotated files. `now` is the clock a relative `since` counts back from;
/// the caller injects it so tests are deterministic.
///
/// A missing file contributes nothing (an empty log is not an error).
/// Reading writes no audit record and works whatever state the writer is in
/// (결정 7): this function never touches a sink.
pub fn query(
    active: &Path,
    retain: u32,
    req: &AuditQueryReq,
    now: SystemTime,
) -> Result<AuditQueryData, OpError> {
    let filter = Filter::from_request(req, now)?;

    let mut window: VecDeque<AuditRecordView> = VecDeque::new();
    let mut matched: u64 = 0;
    let mut skipped_lines: u64 = 0;
    let mut oldest_ts: Option<String> = None;

    let rotated = (1..=retain).rev().map(|n| rotated_path(active, n));
    for path in rotated.chain(std::iter::once(active.to_path_buf())) {
        let Some(file) = open_read_only(&path)? else {
            continue;
        };
        scan_file(file, &path, |outcome| match outcome {
            None => skipped_lines += 1,
            Some(record) => {
                if oldest_ts.is_none() {
                    oldest_ts = Some(record.ts.clone());
                }
                if filter.matches(&record) {
                    matched += 1;
                    if window.len() == filter.limit {
                        window.pop_front();
                    }
                    window.push_back(record_view(record));
                }
            }
        })?;
    }

    Ok(AuditQueryData {
        truncated: matched > filter.limit as u64,
        records: window.into_iter().rev().collect(),
        skipped_lines,
        oldest_ts,
    })
}

/// A request turned into comparable values, validated once up front.
struct Filter<'a> {
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
    principal: Option<&'a str>,
    action: Option<&'a str>,
    resource: Option<&'a str>,
    decision: Option<&'a str>,
    limit: usize,
}

impl<'a> Filter<'a> {
    fn from_request(req: &'a AuditQueryReq, now: SystemTime) -> Result<Self, OpError> {
        let limit = match req.limit {
            None => DEFAULT_LIMIT,
            Some(n) if (1..=MAX_LIMIT).contains(&n) => n,
            Some(n) => {
                return Err(invalid(format!(
                    "limit {n} is out of range: expected 1..={MAX_LIMIT}"
                )));
            }
        };
        if let Some(decision) = req.decision.as_deref()
            && decision != "allow"
            && decision != "deny"
        {
            return Err(invalid(
                "invalid decision: expected \"allow\" or \"deny\"".to_string(),
            ));
        }
        let since = req
            .since
            .as_deref()
            .map(|text| parse_since(text, now))
            .transpose()?;
        let until = req
            .until
            .as_deref()
            .map(|text| {
                parse_instant(text)
                    .ok_or_else(|| invalid("invalid until: expected an RFC 3339 timestamp".into()))
            })
            .transpose()?;
        Ok(Self {
            since,
            until,
            principal: req.principal.as_deref(),
            action: req.action.as_deref(),
            resource: req.resource.as_deref(),
            decision: req.decision.as_deref(),
            limit: limit as usize,
        })
    }

    /// Exact-match AND of every filter that is set. `since` and `until` are
    /// both inclusive; a record whose `ts` does not parse never satisfies a
    /// time bound.
    fn matches(&self, record: &AuditRecord) -> bool {
        fn eq(want: Option<&str>, have: &str) -> bool {
            want.is_none_or(|want| want == have)
        }
        if !(eq(self.principal, &record.principal)
            && eq(self.action, &record.action)
            && eq(self.resource, &record.resource)
            && eq(self.decision, &record.decision))
        {
            return false;
        }
        if self.since.is_none() && self.until.is_none() {
            return true;
        }
        let Some(at) = parse_instant(&record.ts) else {
            return false;
        };
        self.since.is_none_or(|since| at >= since) && self.until.is_none_or(|until| at <= until)
    }
}

fn invalid(message: String) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message)
}

fn parse_instant(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

/// `--since`: an RFC 3339 timestamp, or `N[smhd]` counted back from `now`.
fn parse_since(text: &str, now: SystemTime) -> Result<OffsetDateTime, OpError> {
    if let Some(at) = parse_instant(text) {
        return Ok(at);
    }
    let bad = || invalid("invalid since: expected an RFC 3339 timestamp or N[smhd]".to_string());
    let unit = match text.chars().last() {
        Some('s') => 1_i64,
        Some('m') => 60,
        Some('h') => 3600,
        Some('d') => 86_400,
        _ => return Err(bad()),
    };
    let digits = &text[..text.len() - 1];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let seconds = digits
        .parse::<i64>()
        .ok()
        .and_then(|n| n.checked_mul(unit))
        .ok_or_else(bad)?;
    OffsetDateTime::from(now)
        .checked_sub(Duration::seconds(seconds))
        .ok_or_else(bad)
}

/// Open `path` for reading and nothing else. `Ok(None)` when it does not
/// exist (never created yet, or rotated away between two opens).
fn open_read_only(path: &Path) -> Result<Option<File>, OpError> {
    // Opening a FIFO for reading blocks until a writer appears, so refuse
    // anything that is not a regular file before opening it.
    // A failing `metadata` call is not an answer here: it falls through to
    // the open below, which owns the not-found handling.
    if let Ok(meta) = std::fs::metadata(path)
        && !meta.is_file()
    {
        return Err(OpError::new(
            ErrorCode::Internal,
            format!(
                "cannot read audit log {}: not a regular file",
                path.display()
            ),
        ));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE: the writer
        // may append and rename the file while this handle is open.
        opts.share_mode(0x1 | 0x2 | 0x4);
    }
    // On Windows a file the writer just deleted or renamed stays "delete
    // pending" while any handle is open on it, and opening it meanwhile
    // fails with access denied. That clears as soon as the handles close,
    // so retry briefly before reporting a real permission problem.
    #[cfg(windows)]
    const ATTEMPTS: u32 = 40;
    #[cfg(not(windows))]
    const ATTEMPTS: u32 = 1;
    let mut attempt = 1;
    loop {
        match opts.open(path) {
            Ok(file) => return Ok(Some(file)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied && attempt < ATTEMPTS => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(err) => return Err(unreadable(path, &err)),
        }
    }
}

/// `INTERNAL` naming the path and the error kind only (결정 6).
fn unreadable(path: &Path, err: &io::Error) -> OpError {
    OpError::new(
        ErrorCode::Internal,
        format!("cannot read audit log {}: {}", path.display(), err.kind()),
    )
}

/// Feed every line of `file` to `sink`: `Some(record)` for a parsed line,
/// `None` for a line that was skipped.
fn scan_file(
    file: File,
    path: &Path,
    mut sink: impl FnMut(Option<AuditRecord>),
) -> Result<(), OpError> {
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    loop {
        match read_bounded_line(&mut reader, &mut line, MAX_LINE_BYTES)
            .map_err(|err| unreadable(path, &err))?
        {
            Line::End => return Ok(()),
            Line::TooLong => sink(None),
            Line::Complete => sink(serde_json::from_slice::<AuditRecord>(&line).ok()),
        }
    }
}

enum Line {
    /// Nothing left to read.
    End,
    /// `buf` holds one line without its newline. A final line with no
    /// newline is returned too; if it was cut short it fails to parse.
    Complete,
    /// The line exceeded the cap; it was consumed and `buf` is empty.
    TooLong,
}

/// Read up to the next newline into `buf` without ever holding more than
/// `cap` bytes; a longer line is consumed to its end and reported as
/// [`Line::TooLong`].
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    cap: usize,
) -> io::Result<Line> {
    buf.clear();
    let mut seen_any = false;
    let mut too_long = false;
    loop {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if chunk.is_empty() {
            break;
        }
        seen_any = true;
        let newline = chunk.iter().position(|&b| b == b'\n');
        let take = newline.unwrap_or(chunk.len());
        if !too_long {
            if buf.len() + take > cap {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(&chunk[..take]);
            }
        }
        match newline {
            Some(_) => {
                reader.consume(take + 1);
                break;
            }
            None => reader.consume(take),
        }
    }
    Ok(if !seen_any {
        Line::End
    } else if too_long {
        Line::TooLong
    } else {
        Line::Complete
    })
}

#[cfg(test)]
mod tests;
