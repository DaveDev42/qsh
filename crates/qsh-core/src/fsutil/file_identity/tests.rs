use super::*;

#[test]
fn file_identity_is_volume_serial_and_file_index() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("audit.log");
    std::fs::write(&original, b"one").unwrap();

    // Two handles on one file, and the path, agree.
    let first = File::open(&original).unwrap();
    let second = File::open(&original).unwrap();
    let identity = of_file(&first).unwrap();
    assert_eq!(of_file(&second).unwrap(), identity);
    assert_eq!(of_path(&original).unwrap(), identity);

    // A rename moves the name, not the file: the open handle and the new name
    // still agree, and the old name is gone.
    let moved = dir.path().join("audit.log.1");
    std::fs::rename(&original, &moved).unwrap();
    assert_eq!(of_file(&first).unwrap(), identity);
    assert_eq!(of_path(&moved).unwrap(), identity);
    assert!(of_path(&original).is_err());

    // A new file at the old name is another file, whatever its name.
    std::fs::write(&original, b"two").unwrap();
    assert_ne!(of_path(&original).unwrap(), identity);
    assert_ne!(of_file(&File::open(&original).unwrap()).unwrap(), identity);

    // A directory has an identity too, and it is not a file's.
    assert_ne!(of_path(dir.path()).unwrap(), identity);
}

#[test]
fn looking_at_a_path_does_not_block_a_rename_or_a_delete() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    std::fs::write(&path, b"x").unwrap();
    // The attribute-only handle is held open across both operations.
    let held = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&path)
        .unwrap();
    let moved = dir.path().join("audit.log.1");
    std::fs::rename(&path, &moved).unwrap();
    std::fs::remove_file(&moved).unwrap();
    drop(held);
}
