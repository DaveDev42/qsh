//! The Windows twins of the host steps' unit tests (`tests.rs` holds the unix
//! ones). The steps that stat, make, create and place under a directory are
//! `file::local`'s and are pinned in `local/windows/tests.rs`; what is host
//! specific is the listing and the free-space probe.

use super::*;
use crate::file::guard;

/// The guard opens canonical paths only (it compares the handle's final path
/// with the one it was given), and a temp directory can be spelled with an
/// 8.3 short name (`C:\Users\RUNNER~1\...` on a CI runner).
fn open_dir(path: &std::path::Path) -> File {
    let verbatim = std::fs::canonicalize(path).expect("canonicalize");
    let canonical = guard::windows_path::strip_verbatim_prefix(verbatim.to_str().unwrap());
    guard::open_dir_nofollow(std::path::Path::new(&canonical)).expect("open dir")
}

#[test]
fn list_dir_sorts_by_name_bytes_and_resumes_after_the_cursor() {
    let tmp = tempfile::tempdir().unwrap();
    // Windows compares names without regard to case, but the listing orders
    // by UTF-8 bytes, which is what a cursor round-trips through.
    for name in ["b", "a", "C", "ab", "z"] {
        std::fs::write(tmp.path().join(name), name).unwrap();
    }
    std::fs::create_dir(tmp.path().join("d")).unwrap();
    let dir = open_dir(tmp.path());

    let all = list_dir(&dir, b"", 100, 100).unwrap();
    let names: Vec<&str> = all.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["C", "a", "ab", "b", "d", "z"]);
    assert!(!all.more);
    let d = all.entries.iter().find(|e| e.name == "d").unwrap();
    assert_eq!(d.info.kind, FsKind::Directory);
    assert_eq!(d.info.mode, 0o755);
    let a = all.entries.iter().find(|e| e.name == "a").unwrap();
    assert_eq!(
        (a.info.kind, a.info.size, a.info.mode),
        (FsKind::Regular, 1, 0o644)
    );

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
fn list_dir_orders_non_ascii_names_by_their_utf8_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    // U+FF21 sorts after U+00E9 in UTF-8 bytes, and an astral name (a
    // surrogate pair in UTF-16) sorts after both, which UTF-16 order would
    // get wrong.
    for name in ["\u{ff21}", "\u{e9}", "\u{1f600}", "z"] {
        std::fs::write(tmp.path().join(name), b"").unwrap();
    }
    let dir = open_dir(tmp.path());
    let page = list_dir(&dir, b"", 10, 10).unwrap();
    let names: Vec<&str> = page.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["z", "\u{e9}", "\u{ff21}", "\u{1f600}"]);
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
fn list_dir_reports_a_read_only_file_with_its_synthesized_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ro");
    std::fs::write(&path, b"x").unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions).unwrap();
    let dir = open_dir(tmp.path());
    let page = list_dir(&dir, b"", 10, 10).unwrap();
    assert_eq!(page.entries[0].info.mode, 0o444);
    // Let the temp dir clean up.
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions).unwrap();
}

#[test]
fn list_dir_reports_a_junction_as_a_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let link = tmp.path().join("link");
    {
        let _spawning = crate::winproc::spawn_guard();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink failed");
    }
    let dir = open_dir(tmp.path());
    let page = list_dir(&dir, b"", 10, 10).unwrap();
    let entry = page.entries.iter().find(|e| e.name == "link").unwrap();
    assert_eq!(entry.info.kind, FsKind::Symlink);
    std::fs::remove_dir(&link).unwrap();
}

#[test]
fn the_free_space_probe_reports_a_plausible_free_size() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = open_dir(tmp.path());
    let free = DiskFreeSpace.available_bytes(&dir).unwrap();
    assert!(free > 0, "a test disk with no free byte");
    assert!(free < 1 << 60);
}
