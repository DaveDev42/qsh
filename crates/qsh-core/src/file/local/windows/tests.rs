//! Tests of the Windows local steps, over real files in a temp directory.
//!
//! The `windows_get_*` tests drive the same transfer tail a download runs
//! (`xfer::create_guarded_temp`, then `xfer::commit_temp`), so they pin what
//! `qsh cp host:file .` leaves on a Windows disk without needing a host.

use std::ffi::OsStr;
use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;
use crate::file::xfer::{self, Placement};
use crate::fsutil::dacl::ObjectKind;
use crate::fsutil::dacl::testing::{assert_owner_only, read_dacl};

/// `INHERITED_ACE`: the ACE came from the parent.
const INHERITED_ACE: u8 = 0x10;

fn dir_in(tmp: &tempfile::TempDir) -> Arc<File> {
    Arc::new(open_dir(tmp.path()).expect("open the temp dir"))
}

/// Write `body` through a guarded temp and commit it as `name`.
fn commit(
    dir: &Arc<File>,
    name: &str,
    body: &[u8],
    mode: u32,
    overwrite: bool,
    preserve: bool,
    mtime: i64,
) -> io::Result<xfer::Committed> {
    let (mut file, mut guard) = xfer::create_guarded_temp(dir, OsStr::new(name))?;
    file.write_all(body)?;
    let temp = guard.name().expect("armed");
    let committed = xfer::commit_temp(
        dir,
        &temp,
        &file,
        &Placement {
            name: OsStr::new(name),
            mode,
            overwrite,
            preserve,
            mtime,
        },
    )?;
    if committed.temp_gone {
        guard.disarm();
    }
    Ok(committed)
}

fn read_only(path: &Path) -> bool {
    std::fs::metadata(path).unwrap().permissions().readonly()
}

#[test]
fn windows_get_writes_a_read_only_attribute_only_when_owner_write_is_clear() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dir_in(&tmp);
    for (mode, expect_read_only) in [
        (0o644, false),
        (0o755, false),
        (0o600, false),
        (0o200, false),
        (0o222, false),
        (0o444, true),
        (0o555, true),
        (0o400, true),
        (0o040, true),
        (0o000, true),
    ] {
        let name = format!("m{mode:03o}.bin");
        commit(&dir, &name, b"payload", mode, true, false, 0).unwrap();
        let path = tmp.path().join(&name);
        assert_eq!(
            read_only(&path),
            expect_read_only,
            "mode {mode:03o} gives the wrong attribute"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    }
}

#[test]
fn windows_get_replaces_a_read_only_file_like_a_unix_rename_does() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dir_in(&tmp);
    commit(&dir, "x.bin", b"first", 0o444, true, false, 0).unwrap();
    assert!(read_only(&tmp.path().join("x.bin")));
    let committed = commit(&dir, "x.bin", b"second", 0o644, true, false, 0).unwrap();
    assert!(committed.overwritten);
    assert_eq!(std::fs::read(tmp.path().join("x.bin")).unwrap(), b"second");
    assert!(!read_only(&tmp.path().join("x.bin")));
}

#[test]
fn windows_get_temp_file_is_owner_only_until_rename() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dir_in(&tmp);
    let (mut file, mut guard) = xfer::create_guarded_temp(&dir, OsStr::new("held.bin")).unwrap();
    file.write_all(b"half a file").unwrap();
    let temp = guard.name().expect("armed");
    let temp_path = tmp.path().join(&temp);
    // While the bytes arrive nobody but the owner can read them.
    assert_owner_only(&temp_path, ObjectKind::File);

    let committed = xfer::commit_temp(
        &dir,
        &temp,
        &file,
        &Placement {
            name: OsStr::new("held.bin"),
            mode: 0o644,
            overwrite: true,
            preserve: false,
            mtime: 0,
        },
    )
    .unwrap();
    assert!(committed.temp_gone);
    guard.disarm();

    // The finished file carries what its directory hands down, not the
    // temp file's own ACE.
    assert!(!temp_path.exists(), "the temp name is gone");
    let report = read_dacl(&tmp.path().join("held.bin"));
    assert!(!report.protected, "still protected: {report:?}");
    assert!(!report.aces.is_empty(), "no ACEs: {report:?}");
    assert!(
        report.aces.iter().all(|ace| ace.flags & INHERITED_ACE != 0),
        "an explicit ACE survived the rename: {report:?}"
    );
}

#[test]
fn windows_get_preserves_mtime_with_p() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dir_in(&tmp);
    let wanted = 1_600_000_000_i64;
    commit(&dir, "p.bin", b"abc", 0o644, true, true, wanted).unwrap();
    let modified = std::fs::metadata(tmp.path().join("p.bin"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        modified,
        UNIX_EPOCH + Duration::from_secs(wanted.unsigned_abs())
    );

    // Without `-p` the time is the write time, not the source's.
    commit(&dir, "n.bin", b"abc", 0o644, true, false, wanted).unwrap();
    let modified = std::fs::metadata(tmp.path().join("n.bin"))
        .unwrap()
        .modified()
        .unwrap();
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default();
    assert!(age < Duration::from_secs(3600), "mtime was copied: {age:?}");

    // A source older than the epoch is a time too.
    commit(&dir, "old.bin", b"abc", 0o644, true, true, -86_400).unwrap();
    let modified = std::fs::metadata(tmp.path().join("old.bin"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(modified, UNIX_EPOCH - Duration::from_secs(86_400));
}

#[test]
fn windows_get_with_no_clobber_never_replaces_and_leaves_no_temp() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dir_in(&tmp);
    std::fs::write(tmp.path().join("keep.bin"), b"mine").unwrap();
    let err = commit(&dir, "keep.bin", b"theirs", 0o644, false, false, 0).unwrap_err();
    assert!(matches!(classify(&err), IoClass::Exists), "{err:?}");
    assert_eq!(std::fs::read(tmp.path().join("keep.bin")).unwrap(), b"mine");

    // A new name is placed and the temp name is gone with the rename.
    let committed = commit(&dir, "new.bin", b"theirs", 0o644, false, false, 0).unwrap();
    assert!(!committed.overwritten);
    assert!(committed.temp_gone);
    assert_eq!(
        std::fs::read(tmp.path().join("new.bin")).unwrap(),
        b"theirs"
    );
}

#[test]
fn windows_temp_files_are_cleaned_by_their_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dir_in(&tmp);
    {
        let (_file, guard) = xfer::create_guarded_temp(&dir, OsStr::new("gone.bin")).unwrap();
        assert!(tmp.path().join(guard.name().unwrap()).exists());
    }
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);

    // Even a temp that was already finished read-only goes.
    let (file, mut guard) = xfer::create_guarded_temp(&dir, OsStr::new("ro.bin")).unwrap();
    apply_final_attrs(&file, 0o444, false, 0).unwrap();
    drop(file);
    guard.clean();
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn windows_temp_name_stays_inside_the_component_limit() {
    for len in [1, 100, 231, 232, 255] {
        let name = "é".repeat(len.min(255));
        let temp = temp_name(OsStr::new(&name));
        let units = temp.encode_wide().count();
        assert!(units <= NAME_MAX, "{len}: {units} units");
        assert!(temp.to_string_lossy().ends_with(".part"));
    }
}

#[test]
fn windows_stat_and_mode_are_synthesized() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dir_in(&tmp);
    std::fs::write(tmp.path().join("rw.txt"), b"x").unwrap();
    std::fs::write(tmp.path().join("ro.txt"), b"x").unwrap();
    let mut permissions = std::fs::metadata(tmp.path().join("ro.txt"))
        .unwrap()
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(tmp.path().join("ro.txt"), permissions).unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();

    let rw = stat_at(&dir, OsStr::new("rw.txt")).unwrap().unwrap();
    assert_eq!((rw.kind, rw.mode, rw.size), (FsKind::Regular, 0o644, 1));
    let ro = stat_at(&dir, OsStr::new("ro.txt")).unwrap().unwrap();
    assert_eq!((ro.kind, ro.mode), (FsKind::Regular, 0o444));
    let sub = stat_at(&dir, OsStr::new("sub")).unwrap().unwrap();
    assert_eq!((sub.kind, sub.mode), (FsKind::Directory, 0o755));
    assert!(stat_at(&dir, OsStr::new("missing")).unwrap().is_none());

    // An open file reports the same facts.
    let file = open_source(&tmp.path().join("ro.txt"), true).unwrap();
    assert_eq!(fstat(&file).unwrap().mode, 0o444);

    // Clean up the read-only file so the temp dir can go.
    let mut permissions = std::fs::metadata(tmp.path().join("ro.txt"))
        .unwrap()
        .permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(tmp.path().join("ro.txt"), permissions).unwrap();
}

#[test]
fn windows_mkdir_reports_what_it_found() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dir_in(&tmp);
    assert_eq!(
        mkdir_at(&dir, OsStr::new("d"), 0o555, true).unwrap(),
        MkdirOutcome::Created
    );
    assert_eq!(
        mkdir_at(&dir, OsStr::new("d"), 0o755, false).unwrap(),
        MkdirOutcome::Existed
    );
    std::fs::write(tmp.path().join("f"), b"x").unwrap();
    assert_eq!(
        mkdir_at(&dir, OsStr::new("f"), 0o755, false).unwrap(),
        MkdirOutcome::ExistsNotDirectory
    );
    let sub = open_dir_at(&dir, OsStr::new("d")).unwrap();
    assert_eq!(
        mkdir_at(&sub, OsStr::new("inner"), 0o755, false).unwrap(),
        MkdirOutcome::Created
    );
    assert!(tmp.path().join("d").join("inner").is_dir());
}

#[test]
fn windows_a_junction_is_never_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let link = tmp.path().join("link");
    // `mklink /J` needs no privilege, unlike a symlink.
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "mklink: {}",
        String::from_utf8_lossy(&made.stdout)
    );
    let dir = dir_in(&tmp);

    let stat = stat_at(&dir, OsStr::new("link")).unwrap().unwrap();
    assert_eq!(stat.kind, FsKind::Symlink);
    let err = open_dir_at(&dir, OsStr::new("link")).unwrap_err();
    assert!(matches!(classify(&err), IoClass::SymlinkRefused), "{err:?}");
    // The directory behind it is a plain directory when opened by its name.
    assert!(open_dir_at(&dir, OsStr::new("target")).is_ok());
    // A walked source is opened as the reparse point itself.
    let file = open_source(&link, false).unwrap();
    assert_eq!(fstat(&file).unwrap().kind, FsKind::Symlink);

    // Remove the junction itself, not what it points at.
    std::fs::remove_dir(&link).unwrap();
    assert!(target.is_dir());
}

#[test]
fn windows_an_open_destination_directory_cannot_be_renamed_away() {
    let tmp = tempfile::tempdir().unwrap();
    let inner = tmp.path().join("inner");
    std::fs::create_dir(&inner).unwrap();
    let dir = open_dir(&inner).unwrap();
    let moved = tmp.path().join("moved");
    assert!(
        std::fs::rename(&inner, &moved).is_err(),
        "a held destination directory was renamed"
    );
    drop(dir);
    assert!(std::fs::rename(&inner, &moved).is_ok());
}

#[test]
fn windows_open_dir_refuses_a_file_and_follows_nothing_it_was_not_given() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("f"), b"x").unwrap();
    let err = open_dir(&tmp.path().join("f")).unwrap_err();
    assert!(matches!(classify(&err), IoClass::NotDirectory), "{err:?}");
    let err = open_dir(&tmp.path().join("absent")).unwrap_err();
    assert!(matches!(classify(&err), IoClass::NotFound), "{err:?}");
}

#[test]
fn windows_names_with_a_stream_or_separator_are_refused_below_the_check_too() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dir_in(&tmp);
    for bad in ["a:b", "a\\b", "a/b", ""] {
        let err = stat_at(&dir, OsStr::new(bad)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
    }
}
