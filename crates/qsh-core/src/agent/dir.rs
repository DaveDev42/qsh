//! `qsh doctor`'s read-only view of the host's `agent/` directory (ADR-0055
//! decisions 6 and 19). It never creates anything: the directory is made by
//! the first agent socket, so a missing one is fine as long as the runtime
//! directory it would be made in is private to this user.

use std::path::Path;

/// `Ok` when an agent socket could live under `runtime_dir`, otherwise a
/// short reason. Unix: `agent/` must be a real directory owned by this user
/// with mode 0700, or absent under a runtime directory that only this user
/// can write. Windows has no such directory (the endpoint is a named pipe),
/// so there is nothing to be wrong.
pub fn check_agent_dir(runtime_dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: `geteuid(2)` takes no arguments, touches no memory and
        // cannot fail.
        let euid = unsafe { libc::geteuid() };
        let dir = runtime_dir.join("agent");
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) => {
                if !meta.is_dir() || meta.uid() != euid || meta.mode() & 0o777 != 0o700 {
                    return Err("agent/ is not a private directory owned by this user".into());
                }
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let meta = std::fs::metadata(runtime_dir)
                    .map_err(|err| format!("the runtime directory is unreadable: {err}"))?;
                if !meta.is_dir() || meta.uid() != euid || meta.mode() & 0o022 != 0 {
                    return Err(
                        "the runtime directory is not private to this user, so agent/ cannot be \
                         created in it"
                            .into(),
                    );
                }
                Ok(())
            }
            Err(err) => Err(format!("agent/ cannot be read: {err}")),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = runtime_dir;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn private(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_missing_agent_dir_under_a_private_runtime_dir_is_fine() {
        let tmp = tempfile::tempdir().unwrap();
        private(tmp.path());
        assert!(check_agent_dir(tmp.path()).is_ok());
        assert!(!tmp.path().join("agent").exists(), "doctor creates nothing");
    }

    #[test]
    fn a_private_agent_dir_is_fine_and_a_loose_one_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        private(tmp.path());
        private(&tmp.path().join("agent"));
        assert!(check_agent_dir(tmp.path()).is_ok());
        std::fs::set_permissions(
            tmp.path().join("agent"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(check_agent_dir(tmp.path()).is_err());
    }

    #[test]
    fn a_file_where_the_directory_belongs_is_unusable() {
        let tmp = tempfile::tempdir().unwrap();
        private(tmp.path());
        std::fs::write(tmp.path().join("agent"), b"x").unwrap();
        assert!(check_agent_dir(tmp.path()).is_err());
    }

    #[test]
    fn a_world_writable_runtime_dir_cannot_hold_agent() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_agent_dir(tmp.path()).is_err());
    }
}
