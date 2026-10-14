use super::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

fn open_dir(path: &Path) -> File {
    crate::file::guard::open_dir_nofollow(path).expect("open dir")
}

#[test]
fn list_dir_sorts_by_name_bytes_and_resumes_after_the_cursor() {
    let tmp = tempfile::tempdir().unwrap();
    for name in ["b", "a", "B", "ab", "z"] {
        std::fs::write(tmp.path().join(name), name).unwrap();
    }
    std::fs::create_dir(tmp.path().join("d")).unwrap();
    let dir = open_dir(tmp.path());

    let all = list_dir(&dir, b"", 100, 100).unwrap();
    let names: Vec<&str> = all.entries.iter().map(|e| e.name.as_str()).collect();
    // Byte order: uppercase before lowercase, prefix before extension.
    assert_eq!(names, ["B", "a", "ab", "b", "d", "z"]);
    assert!(!all.more);
    let d = all.entries.iter().find(|e| e.name == "d").unwrap();
    assert_eq!(d.info.kind, FsKind::Directory);
    let a = all.entries.iter().find(|e| e.name == "a").unwrap();
    assert_eq!((a.info.kind, a.info.size), (FsKind::Regular, 1));

    // Two-entry pages walk the same sequence without gaps or repeats.
    let mut seen = Vec::new();
    let mut after = Vec::new();
    loop {
        let page = list_dir(&dir, &after, 2, 100).unwrap();
        assert!(page.entries.len() <= 2);
        seen.extend(page.entries.iter().map(|e| e.name.clone()));
        if !page.more {
            break;
        }
        after = page.entries.last().unwrap().name.clone().into_bytes();
    }
    assert_eq!(seen, ["B", "a", "ab", "b", "d", "z"]);
}

#[test]
fn list_dir_refuses_a_directory_over_the_entry_cap() {
    let tmp = tempfile::tempdir().unwrap();
    for i in 0..5 {
        std::fs::write(tmp.path().join(format!("f{i}")), b"").unwrap();
    }
    let dir = open_dir(tmp.path());
    assert!(
        list_dir(&dir, b"", 10, 5).is_ok(),
        "exactly at the cap is fine"
    );
    assert!(matches!(
        list_dir(&dir, b"", 10, 4),
        Err(ListError::TooManyEntries(4))
    ));
}

#[test]
fn list_dir_counts_names_that_are_not_utf8_and_skips_them() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("ok"), b"").unwrap();
    let bad = OsStr::from_bytes(b"bad\xff");
    std::fs::write(tmp.path().join(bad), b"").unwrap();
    let dir = open_dir(tmp.path());
    let page = list_dir(&dir, b"", 10, 10).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].name, "ok");
    assert_eq!(page.unlistable, 1);
}

#[test]
fn list_dir_reports_a_symlink_as_a_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("/etc/passwd", tmp.path().join("link")).unwrap();
    let dir = open_dir(tmp.path());
    let page = list_dir(&dir, b"", 10, 10).unwrap();
    assert_eq!(page.entries[0].info.kind, FsKind::Symlink);
}

#[test]
fn mkdir_at_creates_with_owner_rwx_even_for_a_read_only_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = open_dir(tmp.path());
    assert_eq!(
        mkdir_at(&dir, OsStr::new("ro"), 0o555, false).unwrap(),
        MkdirOutcome::Created
    );
    let mode = std::fs::metadata(tmp.path().join("ro"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode & 0o700, 0o700, "owner rwx is always on: {mode:o}");
    // `preserve` sets exactly mode | 0o700, whatever the umask was.
    assert_eq!(
        mkdir_at(&dir, OsStr::new("kept"), 0o750, true).unwrap(),
        MkdirOutcome::Created
    );
    let mode = std::fs::metadata(tmp.path().join("kept"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o750);
}

#[test]
fn mkdir_at_merges_into_a_directory_and_refuses_a_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = open_dir(tmp.path());
    std::fs::create_dir(tmp.path().join("there")).unwrap();
    std::fs::write(tmp.path().join("file"), b"x").unwrap();
    assert_eq!(
        mkdir_at(&dir, OsStr::new("there"), 0o700, false).unwrap(),
        MkdirOutcome::Existed
    );
    assert_eq!(
        mkdir_at(&dir, OsStr::new("file"), 0o700, false).unwrap(),
        MkdirOutcome::ExistsNotDirectory
    );
    assert_eq!(std::fs::read(tmp.path().join("file")).unwrap(), b"x");
}

#[test]
fn stat_at_does_not_follow_a_final_symlink_and_reports_a_missing_name() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("t"), b"abc").unwrap();
    std::os::unix::fs::symlink("t", tmp.path().join("l")).unwrap();
    let dir = open_dir(tmp.path());
    assert_eq!(
        stat_at(&dir, OsStr::new("l")).unwrap().unwrap().kind,
        FsKind::Symlink
    );
    let t = stat_at(&dir, OsStr::new("t")).unwrap().unwrap();
    assert_eq!((t.kind, t.size), (FsKind::Regular, 3));
    assert!(stat_at(&dir, OsStr::new("missing")).unwrap().is_none());
}
