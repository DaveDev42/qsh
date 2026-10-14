use super::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

fn open_dir(path: &Path) -> File {
    crate::file::guard::open_dir_nofollow(path).expect("open dir")
}

#[test]
fn list_dir_sorts_by_name_bytes_and_resumes_after_the_cursor() {
    let tmp = tempfile::tempdir().unwrap();
    // No two names differ only by case: APFS (macOS) folds case.
    for name in ["b", "a", "C", "ab", "z"] {
        std::fs::write(tmp.path().join(name), name).unwrap();
    }
    std::fs::create_dir(tmp.path().join("d")).unwrap();
    let dir = open_dir(tmp.path());

    let all = list_dir(&dir, b"", 100, 100).unwrap();
    let names: Vec<&str> = all.entries.iter().map(|e| e.name.as_str()).collect();
    // Byte order: uppercase before lowercase, prefix before extension.
    assert_eq!(names, ["C", "a", "ab", "b", "d", "z"]);
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
    assert_eq!(seen, ["C", "a", "ab", "b", "d", "z"]);
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
    match std::fs::write(tmp.path().join(bad), b"") {
        Ok(()) => {}
        // APFS (macOS) refuses names that are not UTF-8, so there is
        // nothing to skip; Linux CI exercises this.
        Err(e) if e.raw_os_error() == Some(libc::EILSEQ) => return,
        Err(e) => panic!("create non-UTF-8 name: {e}"),
    }
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

#[test]
fn create_temp_makes_a_private_exclusive_file_under_the_documented_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = open_dir(tmp.path());
    let a = create_temp(&dir, OsStr::new("data.bin")).unwrap();
    let b = create_temp(&dir, OsStr::new("data.bin")).unwrap();
    for temp in [&a, &b] {
        let name = temp.name.to_str().unwrap();
        assert!(name.starts_with(".data.bin.qsh-"), "{name}");
        assert!(name.ends_with(".part"), "{name}");
        // ".data.bin.qsh-" + 16 hex + ".part"
        assert_eq!(name.len(), ".data.bin.qsh-".len() + 16 + ".part".len());
        let path = tmp.path().join(name);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_ne!(a.name, b.name, "each call picks a fresh random name");
}

#[test]
fn create_temp_cuts_a_name_that_would_overrun_name_max() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = open_dir(tmp.path());
    let long = "x".repeat(255);
    let temp = create_temp(&dir, OsStr::new(&long)).unwrap();
    assert!(temp.name.as_bytes().len() <= 255);
    assert!(temp.name.to_str().unwrap().ends_with(".part"));
}

#[test]
fn create_temp_does_not_follow_a_planted_symlink_of_the_same_name() {
    // `O_EXCL | O_NOFOLLOW`: whatever sits under the chosen name makes that
    // attempt fail, so the victim behind a symlink is never opened. The name
    // is random, so plant by listing after the fact instead: the created
    // file is a regular file of its own, and a symlink dropped in the
    // directory is left alone.
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    std::os::unix::fs::symlink(&victim, tmp.path().join("link")).unwrap();
    let dir = open_dir(tmp.path());
    let temp = create_temp(&dir, OsStr::new("link")).unwrap();
    let meta = std::fs::symlink_metadata(tmp.path().join(&temp.name)).unwrap();
    assert!(meta.file_type().is_file());
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
}

#[test]
fn unlink_at_removes_a_file_but_never_a_directory() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("f"), b"x").unwrap();
    std::fs::create_dir(tmp.path().join("d")).unwrap();
    let dir = open_dir(tmp.path());
    unlink_at(&dir, OsStr::new("f")).unwrap();
    assert!(!tmp.path().join("f").exists());
    assert!(unlink_at(&dir, OsStr::new("d")).is_err());
    assert!(tmp.path().join("d").is_dir());
    assert_eq!(
        unlink_at(&dir, OsStr::new("f")).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn apply_final_attrs_masks_the_mode_unless_preserving_and_sets_mtime_only_then() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("f");
    let file = File::create(&path).unwrap();
    let umask = process_umask();

    apply_final_attrs(&file, 0o777, false, 123).unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o777 & !umask);
    assert_ne!(
        meta.modified().unwrap(),
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(123),
        "without -p the modification time is the write time"
    );

    apply_final_attrs(&file, 0o4755, true, 1_000_000_000).unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o7777,
        0o755,
        "-p keeps the nine permission bits exactly and never carries setuid"
    );
    assert_eq!(
        meta.modified().unwrap(),
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000)
    );
}

#[test]
fn replace_at_swaps_the_name_to_a_new_inode_and_replaces_a_symlink_without_following_it() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("dest"), b"old").unwrap();
    let old_ino = std::fs::metadata(tmp.path().join("dest")).unwrap().ino();
    std::fs::write(tmp.path().join("t1"), b"new").unwrap();
    let dir = open_dir(tmp.path());
    replace_at(&dir, OsStr::new("t1"), OsStr::new("dest")).unwrap();
    assert_eq!(std::fs::read(tmp.path().join("dest")).unwrap(), b"new");
    assert_ne!(
        std::fs::metadata(tmp.path().join("dest")).unwrap().ino(),
        old_ino
    );
    assert!(!tmp.path().join("t1").exists());

    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    std::os::unix::fs::symlink(&victim, tmp.path().join("sym")).unwrap();
    std::fs::write(tmp.path().join("t2"), b"fresh").unwrap();
    replace_at(&dir, OsStr::new("t2"), OsStr::new("sym")).unwrap();
    assert_eq!(std::fs::read(tmp.path().join("sym")).unwrap(), b"fresh");
    assert!(
        !std::fs::symlink_metadata(tmp.path().join("sym"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
}

#[test]
fn link_new_at_never_replaces_an_existing_name() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("t"), b"new").unwrap();
    std::fs::write(tmp.path().join("taken"), b"first").unwrap();
    let dir = open_dir(tmp.path());
    let err = link_new_at(&dir, OsStr::new("t"), OsStr::new("taken")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
    assert_eq!(std::fs::read(tmp.path().join("taken")).unwrap(), b"first");

    link_new_at(&dir, OsStr::new("t"), OsStr::new("free")).unwrap();
    assert_eq!(std::fs::read(tmp.path().join("free")).unwrap(), b"new");
    // The caller drops the temp name afterwards.
    unlink_at(&dir, OsStr::new("t")).unwrap();
    assert_eq!(std::fs::read(tmp.path().join("free")).unwrap(), b"new");
}

#[test]
fn the_statvfs_probe_reports_a_plausible_free_size() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = open_dir(tmp.path());
    let free = StatvfsFreeSpace.available_bytes(&dir).unwrap();
    assert!(free > 0, "a writable temp dir has room");
}
