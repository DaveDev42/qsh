//! `file.copy` request and data types (`docs/CLI.md` §6.21,
//! `docs/adr/0029-file-copy.md` decisions 18 and 21).
//!
//! `file.copy` is the client-side synthetic operation behind `qsh cp`: it
//! strings the wire ops `file.read`, `file.write`, `file.list` and
//! `file.mkdir` together and has no wire message of its own.

use super::*;

/// Most `entries` a `file.copy` envelope carries; a longer copy sets
/// `entries_truncated` and the totals still count every entry (ADR-0029
/// decision 18). Every entry reaches a `--jsonl` consumer.
pub const COPY_JSON_ENTRIES_MAX: usize = 1000;

/// Most `failures` a failed `file.copy` envelope lists in `error.details`;
/// a longer list sets `failures_truncated` and the counts still cover every
/// failure (ADR-0029 decision 21).
pub const COPY_JSON_FAILURES_MAX: usize = 64;

/// Request for `file.copy`: `qsh cp [-r] [-p] [--no-clobber] SRC... DST`
/// with the operands exactly as the user typed them (`docs/CLI.md` §6.21).
/// Which operand is remote, and so whether this is a put or a get, is the
/// operand grammar's decision (ADR-0029 decision 2), made in `qsh-core`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileCopyReq {
    /// The source operands, in the order given. At least one.
    pub sources: Vec<String>,
    /// The destination operand (the last one on the command line).
    pub destination: String,
    /// `-r`: copy directories recursively.
    #[serde(default)]
    pub recursive: bool,
    /// `-p`: carry the file mode and modification time over.
    #[serde(default)]
    pub preserve: bool,
    /// `--no-clobber`: skip a destination file that already exists.
    #[serde(default)]
    pub no_clobber: bool,
}

/// One item `file.copy` handled (ADR-0029 decision 18). `status` is an open
/// string: `copied` (a file), `created` (a directory), `skipped` (with a
/// `reason`: `exists` or `symlink`) or `failed` (with a `code`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileCopyEntry {
    /// `copied`, `created`, `skipped` or `failed`.
    pub status: String,
    /// `file` or `directory`.
    pub kind: String,
    /// The remote side of the item, derived from the operand (never a
    /// canonical path the host resolved).
    pub remote_path: String,
    /// The local side of the item, derived from the operand.
    pub local_path: String,
    /// Bytes transferred (`copied` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// BLAKE3-256 of the transferred bytes, 64 lowercase hex digits
    /// (`copied` only), so a user can compare it with the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
    /// The source's permission bits (`st_mode & 0o777`) as a decimal
    /// integer (`copied` and `created`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Whether a file already at the destination was replaced (`copied`
    /// only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overwritten: Option<bool>,
    /// Why the item was skipped (`skipped` only): `exists` or `symlink`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Why the item failed (`failed` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<ErrorCode>,
    /// A one-line explanation for the person reading the item (`failed`
    /// only). Not a contract: automation reads `code`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Data payload of a successful `file.copy` (ADR-0029 decision 18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileCopyData {
    /// The host name as the user gave it.
    pub host: String,
    /// `get` (host to this machine) or `put` (this machine to the host).
    pub direction: String,
    /// Files copied.
    pub files: u64,
    /// Directories created (an existing directory merged into is not
    /// counted).
    pub directories: u64,
    /// Bytes transferred over every copied file.
    pub bytes: u64,
    /// Items skipped.
    pub skipped: u64,
    /// Wall-clock duration of the whole copy in milliseconds.
    pub duration_ms: u64,
    /// The first [`COPY_JSON_ENTRIES_MAX`] items, in the order they
    /// finished. A `--jsonl` run leaves this empty (its items were streamed
    /// as `file.entry` events).
    pub entries: Vec<FileCopyEntry>,
    /// Whether `entries` was cut at [`COPY_JSON_ENTRIES_MAX`].
    pub entries_truncated: bool,
}

/// One failed item in a failed `file.copy`'s `error.details`
/// (ADR-0029 decision 21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileCopyFailure {
    /// `local` when the failure happened on this machine, `remote` when the
    /// host refused or failed it.
    pub side: String,
    /// The operand-derived path of the failed item.
    pub path: String,
    /// Why it failed.
    pub code: ErrorCode,
}

/// The `error.details` of a failed `file.copy` (ADR-0029 decision 21): the
/// five counts and the first [`COPY_JSON_FAILURES_MAX`] failures. A copy
/// of one file that fails has the same shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileCopyErrorDetails {
    /// Items copied before the copy ended.
    pub copied: u64,
    /// Directories created before the copy ended.
    pub created: u64,
    /// Items skipped.
    pub skipped: u64,
    /// Items that failed.
    pub failed: u64,
    /// Items never tried because the copy stopped (a lost connection,
    /// Ctrl-C, a missing capability).
    pub not_attempted: u64,
    /// The first [`COPY_JSON_FAILURES_MAX`] failures.
    pub failures: Vec<FileCopyFailure>,
    /// Whether `failures` was cut at [`COPY_JSON_FAILURES_MAX`].
    pub failures_truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copied() -> FileCopyEntry {
        FileCopyEntry {
            status: "copied".into(),
            kind: "file".into(),
            remote_path: "/srv/a".into(),
            local_path: "a".into(),
            bytes: Some(3),
            blake3: Some("0".repeat(64)),
            mode: Some(0o644),
            overwritten: Some(false),
            reason: None,
            code: None,
            message: None,
        }
    }

    #[test]
    fn a_request_defaults_its_flags_to_false() {
        let req: FileCopyReq =
            serde_json::from_str(r#"{"sources":["a"],"destination":"box:/tmp"}"#).unwrap();
        assert!(!req.recursive && !req.preserve && !req.no_clobber);
    }

    #[test]
    fn an_entry_omits_the_fields_its_status_does_not_use() {
        let value = serde_json::to_value(copied()).unwrap();
        let object = value.as_object().unwrap();
        for absent in ["reason", "code", "message"] {
            assert!(!object.contains_key(absent), "{value}");
        }
        assert_eq!(value["mode"], 0o644);
        let back: FileCopyEntry = serde_json::from_value(value).unwrap();
        assert_eq!(back, copied());
    }

    #[test]
    fn a_failed_entry_carries_the_error_code_by_its_wire_name() {
        let mut entry = copied();
        entry.status = "failed".into();
        entry.code = Some(ErrorCode::PermissionDenied);
        let value = serde_json::to_value(&entry).unwrap();
        assert_eq!(value["code"], "PERMISSION_DENIED");
    }

    #[test]
    fn the_error_details_round_trip_with_their_five_counts() {
        let details = FileCopyErrorDetails {
            copied: 1,
            created: 0,
            skipped: 0,
            failed: 1,
            not_attempted: 2,
            failures: vec![FileCopyFailure {
                side: "remote".into(),
                path: "/srv/b".into(),
                code: ErrorCode::InvalidArgument,
            }],
            failures_truncated: false,
        };
        let value = serde_json::to_value(&details).unwrap();
        assert_eq!(value["not_attempted"], 2);
        assert_eq!(value["failures"][0]["code"], "INVALID_ARGUMENT");
        let back: FileCopyErrorDetails = serde_json::from_value(value).unwrap();
        assert_eq!(back, details);
    }

    #[test]
    fn the_file_entry_event_flattens_the_entry_under_its_type() {
        let event = crate::event::FileEntryEvent::new(copied());
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["schema"], "qsh.event/v1");
        assert_eq!(value["type"], "file.entry");
        assert_eq!(value["status"], "copied");
        assert_eq!(value["remote_path"], "/srv/a");
    }
}
