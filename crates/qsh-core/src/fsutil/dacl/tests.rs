use std::path::{Path, PathBuf};

use qsh_proto::ErrorCode;

use super::testing::{NoAcls, NoSid, assert_owner_only, read_dacl};
use super::*;
use crate::config::{FileLock, Paths, ensure_private_dir, write_private_file_with};
use qsh_proto::KeyStoreMode;

/// One row of [`creators`]: a label and the code that creates the files.
type Creator = (&'static str, fn(&Path) -> Made);

/// What one creator made: the files and the directories.
struct Made {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

fn audit_record() -> crate::audit::AuditRecord {
    crate::audit::AuditRecord::now(
        7,
        &qsh_transport::Principal::Device("laptop".into()),
        qsh_transport::AuthPath::Pin,
        crate::acl::Action::ExecRun,
        "exec",
        crate::acl::Decision::Allow,
        None,
        "127.0.0.1:4433".parse().unwrap(),
    )
}

/// Every place in this crate that creates a private file or directory, run
/// under `root`. A new creator belongs in this table.
fn creators() -> Vec<Creator> {
    vec![
        ("write_private_file", |root| {
            let dir = root.join("cfg");
            ensure_private_dir(&dir).unwrap();
            let file = dir.join("trust.toml");
            crate::config::write_private_file(&file, b"x").unwrap();
            Made {
                files: vec![file],
                dirs: vec![dir],
            }
        }),
        ("durable atomic write (resume.json)", |root| {
            let file = root.join("resume.json");
            crate::fsutil::write_atomically(&file, b"{}", true).unwrap();
            Made {
                files: vec![file],
                dirs: vec![],
            }
        }),
        ("sidecar lock file", |root| {
            let file = root.join("trust.toml.lock");
            drop(FileLock::acquire(&file).unwrap());
            Made {
                files: vec![file],
                dirs: vec![],
            }
        }),
        ("stateless_reset.key", |root| {
            let file = root.join("stateless_reset.key");
            assert!(crate::reset_key::load_or_create(&file).is_persistent());
            Made {
                files: vec![file],
                dirs: vec![],
            }
        }),
        ("identity (device.pem, device.key, identity.toml)", |root| {
            let paths = Paths::new(root.join("config"), root.join("state"));
            crate::identity::init(&paths, KeyStoreMode::File).unwrap();
            let identity_dir = paths.identity_dir();
            Made {
                files: ["device.pem", "device.key", "identity.toml"]
                    .map(|n| identity_dir.join(n))
                    .to_vec(),
                dirs: vec![paths.config_dir.clone(), identity_dir],
            }
        }),
        ("private CA (ca.key, ca.pem, lock)", |root| {
            let paths = Paths::new(root.join("config"), root.join("state"));
            crate::ca::init(&paths).unwrap();
            let ca_dir = paths.ca_dir();
            Made {
                files: [".lock", "ca.key", "ca.pem"]
                    .map(|n| ca_dir.join(n))
                    .to_vec(),
                dirs: vec![paths.config_dir.clone(), ca_dir],
            }
        }),
        ("file audit sink", |root| {
            let dir = root.join("audit-a");
            let file = dir.join("audit.log");
            let sink = crate::audit::FileAuditSink::new(&file);
            crate::audit::AuditSink::record(&sink, &audit_record()).unwrap();
            Made {
                files: vec![file],
                dirs: vec![dir],
            }
        }),
        ("rotating audit sink (active and rotated)", |root| {
            let dir = root.join("audit-b");
            let file = dir.join("audit.log");
            let sink = crate::audit::RotatingAuditSink::spawn(&file, 200, 3, 64);
            for _ in 0..10 {
                crate::audit::AuditSink::record(&sink, &audit_record()).unwrap();
            }
            // Dropping the last owner joins the writer thread.
            drop(sink);
            let rotated = dir.join("audit.log.1");
            assert!(rotated.exists(), "the sink must have rotated");
            Made {
                files: vec![file, rotated],
                dirs: vec![dir],
            }
        }),
    ]
}

#[test]
fn windows_private_files_have_an_owner_only_protected_dacl() {
    for (label, create) in creators() {
        let root = tempfile::tempdir().unwrap();
        let made = create(root.path());
        assert!(!made.files.is_empty(), "{label} made no file");
        for file in made.files {
            assert!(file.is_file(), "{label}: {} is missing", file.display());
            assert_owner_only(&file, ObjectKind::File);
        }
    }
}

#[test]
fn windows_private_dirs_have_an_inheriting_owner_only_dacl() {
    for (label, create) in creators() {
        let root = tempfile::tempdir().unwrap();
        for dir in create(root.path()).dirs {
            assert!(dir.is_dir(), "{label}: {} is missing", dir.display());
            assert_owner_only(&dir, ObjectKind::Dir);
        }
    }

    // The ACE is inheritable: a file made inside with no descriptor of its
    // own ends up with the owner's access only.
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("private");
    create_private_dir(&dir).unwrap();
    let child = dir.join("plain.txt");
    std::fs::write(&child, b"x").unwrap();
    let report = read_dacl(&child);
    assert_eq!(report.aces.len(), 1, "{report:?}");
    assert!(report.aces[0].is_current_user, "{report:?}");
}

#[test]
fn every_missing_parent_of_a_private_dir_is_private() {
    let root = tempfile::tempdir().unwrap();
    let leaf = root.path().join("a").join("b").join("c");
    create_private_dir(&leaf).unwrap();
    for dir in [root.path().join("a"), root.path().join("a").join("b"), leaf] {
        assert_owner_only(&dir, ObjectKind::Dir);
    }
}

#[test]
fn an_existing_directory_is_left_as_it_is() {
    let root = tempfile::tempdir().unwrap();
    let before = format!("{:?}", read_dacl(root.path()));
    create_private_dir(root.path()).unwrap();
    assert_eq!(format!("{:?}", read_dacl(root.path())), before);
}

#[test]
fn a_dacl_failure_creates_no_file() {
    let root = tempfile::tempdir().unwrap();

    let path = root.path().join("key.pem");
    let err = crate::fsutil::write_atomically_with(&path, b"secret", false, &NoSid).unwrap_err();
    assert!(err.to_string().contains("injected"), "{err}");
    assert!(!path.exists());

    let opened = root.path().join("opened.key");
    assert!(open_private_file_with(PrivateOpen::CreateNew, &opened, &NoSid).is_err());
    assert!(!opened.exists());

    let dir = root.path().join("state").join("private");
    assert!(create_private_dir_with(&dir, &NoSid).is_err());
    assert!(!dir.exists());
    assert!(
        !root.path().join("state").exists(),
        "no parent is created either"
    );

    // Nothing, not even a temp file, is left in the directory.
    let leftovers: Vec<_> = std::fs::read_dir(root.path()).unwrap().collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn a_volume_without_acls_creates_nothing() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("key.pem");
    let err = crate::fsutil::write_atomically_with(&path, b"secret", false, &NoAcls).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("access control lists"), "{err}");
    assert!(!path.exists());
    let dir = root.path().join("private");
    assert!(create_private_dir_with(&dir, &NoAcls).is_err());
    assert!(!dir.exists());
}

#[test]
fn the_volume_under_the_test_directory_keeps_acls() {
    let root = tempfile::tempdir().unwrap();
    // The directory exists; a path below it that does not yet is judged by
    // the nearest ancestor that does.
    assert!(volume_keeps_acls(root.path()).unwrap());
    assert!(volume_keeps_acls(&root.path().join("not").join("yet")).unwrap());
}

#[test]
fn a_legacy_inherited_acl_file_is_replaced_on_the_next_write() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("device.key");
    // What an older build left: created with the directory's inherited ACL.
    std::fs::write(&path, b"old").unwrap();
    assert!(
        !read_dacl(&path).protected,
        "the precondition: an inherited, unprotected DACL"
    );

    crate::fsutil::write_atomically(&path, b"new", false).unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    assert_owner_only(&path, ObjectKind::File);
}

#[test]
fn a_leftover_temp_file_of_the_same_name_does_not_keep_its_old_acl() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("device.key");
    // The name the next write will use, as after a pid reuse.
    let next_ticket_tmp = crate::fsutil::temp_path(
        root.path(),
        std::ffi::OsStr::new("device.key"),
        std::process::id(),
        crate::fsutil::next_write_ticket_for_test(),
    );
    std::fs::write(&next_ticket_tmp, b"leftover").unwrap();
    assert!(!read_dacl(&next_ticket_tmp).protected);

    crate::fsutil::write_atomically(&path, b"final", false).unwrap();

    assert_owner_only(&path, ObjectKind::File);
}

#[test]
fn a_sid_lookup_failure_is_config_error_with_the_path() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("trust.toml");
    let err = write_private_file_with(&path, b"x", &NoSid).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(
        err.message.contains(&path.display().to_string()),
        "{}",
        err.message
    );
    assert!(err.message.contains("SID"), "the cause: {}", err.message);
    assert!(!path.exists());
}

#[test]
fn the_current_user_sid_is_a_valid_sid() {
    let sid = token_user_sid().unwrap();
    assert!(sid.len() >= 3, "a SID is at least 12 bytes");
    // Revision 1, as every SID has it.
    assert_eq!(sid[0] & 0xFF, 1);
}
