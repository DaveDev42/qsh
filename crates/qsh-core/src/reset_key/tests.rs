use super::*;

fn key_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join(RESET_KEY_FILE_NAME)
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Leftover temp files from the `link(2)` install would show up here.
fn dir_entries(dir: &tempfile::TempDir) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn reset_key_file_is_created_once_with_mode_0600_and_reused_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let path = key_path(&dir);

    let first = load_or_create(&path);
    assert!(first.diagnostic.is_none(), "{:?}", first.diagnostic);
    assert!(first.is_persistent());
    let on_disk = std::fs::read(&path).unwrap();
    assert_eq!(on_disk.len(), RESET_KEY_LEN);
    assert_eq!(&on_disk[..], &first.bytes()[..]);
    #[cfg(unix)]
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(
        dir_entries(&dir),
        vec![RESET_KEY_FILE_NAME.to_string()],
        "the temp file used for the link(2) install is gone"
    );

    // "Restarts": every later start reads the same bytes and writes nothing.
    for _ in 0..3 {
        let again = load_or_create(&path);
        assert!(again.diagnostic.is_none());
        assert_eq!(again.bytes(), first.bytes());
        assert_eq!(std::fs::read(&path).unwrap(), on_disk);
    }
}

#[test]
fn concurrent_first_starts_agree_on_one_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = key_path(&dir);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let loaded = load_or_create(&path);
                let persistent = loaded.is_persistent();
                (*loaded.bytes(), loaded.diagnostic, persistent)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let on_disk = std::fs::read(&path).unwrap();
    for (key, diagnostic, persistent) in results {
        assert_eq!(&key[..], &on_disk[..]);
        assert!(diagnostic.is_none());
        assert!(persistent);
    }
    assert_eq!(dir_entries(&dir), vec![RESET_KEY_FILE_NAME.to_string()]);
}

#[cfg(unix)]
#[test]
fn reset_key_file_with_wider_permissions_emits_a_startup_diagnostic() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = key_path(&dir);
    let created = load_or_create(&path);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let loaded = load_or_create(&path);
    assert_eq!(
        loaded.bytes(),
        created.bytes(),
        "a wide mode is reported, the key is still used"
    );
    assert!(loaded.is_persistent());
    let diagnostic = loaded.diagnostic.expect("one diagnostic");
    assert!(diagnostic.contains(&path.display().to_string()));
    assert!(diagnostic.contains("0644"), "{diagnostic}");
    assert!(diagnostic.contains(RESET_KEY_WIDE_MODE_HEADLINE));
    assert!(!diagnostic.contains('\n'), "a single line: {diagnostic:?}");
    assert_eq!(mode_of(&path), 0o644, "the mode is not silently fixed");
    // 0640 and 0604 are wider too; 0400 is not.
    for (mode, wide) in [(0o640, true), (0o604, true), (0o400, false), (0o600, false)] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            load_or_create(&path).diagnostic.is_some(),
            wide,
            "mode {mode:o}"
        );
    }
}

#[test]
fn unreadable_or_malformed_reset_key_is_never_silently_replaced() {
    // Wrong lengths, including empty, one short and one long.
    for bytes in [
        &b""[..],
        &[7u8; RESET_KEY_LEN - 1][..],
        &[7u8; RESET_KEY_LEN + 1][..],
        &[7u8; 4096][..],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        std::fs::write(&path, bytes).unwrap();

        let loaded = load_or_create(&path);
        assert!(!loaded.is_persistent());
        let diagnostic = loaded.diagnostic.as_deref().expect("one diagnostic");
        assert!(diagnostic.contains(&path.display().to_string()));
        assert!(diagnostic.contains("malformed"), "{diagnostic}");
        assert!(diagnostic.contains(RESET_KEY_UNUSABLE_REMEDY));
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "bytes unchanged");
        assert_eq!(dir_entries(&dir), vec![RESET_KEY_FILE_NAME.to_string()]);

        // The throwaway key is fresh per run.
        let other = load_or_create(&path);
        assert_ne!(other.bytes(), loaded.bytes());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    // A directory where the file should be: unreadable, not replaced.
    let dir = tempfile::tempdir().unwrap();
    let path = key_path(&dir);
    std::fs::create_dir(&path).unwrap();
    let loaded = load_or_create(&path);
    assert!(!loaded.is_persistent());
    assert!(loaded.diagnostic.is_some());
    assert!(path.is_dir());
}

#[cfg(unix)]
#[test]
fn a_permission_denied_reset_key_is_kept_byte_for_byte() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = key_path(&dir);
    let original = [0xA5u8; RESET_KEY_LEN];
    std::fs::write(&path, original).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&path).is_ok() {
        // Running as root (or an ACL grants access): nothing to deny.
        return;
    }

    let loaded = load_or_create(&path);
    assert!(!loaded.is_persistent());
    let diagnostic = loaded.diagnostic.as_deref().expect("one diagnostic");
    assert!(diagnostic.contains("PermissionDenied"), "{diagnostic}");
    assert!(diagnostic.contains(&path.display().to_string()));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(dir_entries(&dir), vec![RESET_KEY_FILE_NAME.to_string()]);
    // Once the operator fixes the permissions the next start is normal.
    let fixed = load_or_create(&path);
    assert!(fixed.is_persistent());
    assert!(fixed.diagnostic.is_none());
    assert_eq!(fixed.bytes(), &original);
}

#[test]
fn a_directory_that_cannot_hold_the_file_falls_back_without_creating_anything() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-subdir").join(RESET_KEY_FILE_NAME);
    let loaded = load_or_create(&path);
    assert!(!loaded.is_persistent());
    let diagnostic = loaded.diagnostic.as_deref().expect("one diagnostic");
    assert!(diagnostic.contains("NotFound"), "{diagnostic}");
    assert!(dir_entries(&dir).is_empty());
}

#[test]
fn reset_key_never_appears_in_logs_audit_or_diagnostics() {
    use base64::Engine as _;

    // Every shape the module can produce: created, reused, wide mode,
    // malformed, unreadable. None of the strings it hands out, nor the
    // `Debug` of the loaded key, may carry the key in any common encoding.
    fn encodings(key: &[u8]) -> Vec<String> {
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let hex_upper = hex.to_uppercase();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        let list = format!("{:?}", key.to_vec());
        vec![hex, hex_upper, b64, b64url, list]
    }

    let dir = tempfile::tempdir().unwrap();
    let path = key_path(&dir);
    let mut outputs = Vec::new();

    let created = load_or_create(&path);
    let key = *created.bytes();
    outputs.push(format!("{created:?}"));
    outputs.extend(created.diagnostic.clone());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let wide = load_or_create(&path);
        outputs.push(format!("{wide:?}"));
        outputs.extend(wide.diagnostic.clone());
    }

    // A malformed file whose bytes are the key plus one: the diagnostic must
    // not echo file contents.
    let mut longer = key.to_vec();
    longer.push(0);
    std::fs::write(&path, &longer).unwrap();
    let malformed = load_or_create(&path);
    outputs.push(format!("{malformed:?}"));
    outputs.extend(malformed.diagnostic.clone());
    let throwaway = *malformed.bytes();
    outputs.push(format!("{malformed:?}"));

    for output in &outputs {
        for key in [&key[..], &throwaway[..]] {
            for needle in encodings(key) {
                assert!(
                    !output.contains(&needle),
                    "key material {needle} leaked into {output:?}"
                );
            }
        }
    }
    assert!(outputs.iter().any(|o| o.contains("<redacted>")));
}
