//! What both kinds of Windows child (a session's and an `exec`'s) are started
//! from, beyond the environment composition in `pty::env_policy`: the
//! command line, the program lookup, and the serve process's own variables
//! that pass through.
//!
//! The client picks the command and the host's account decides what its name
//! means, so a program is never looked up in the host's working directory or
//! on the host's `PATH` ([`resolve_program`]).

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use crate::pty::env_policy::{self, WINDOWS};

/// The serve process's own environment, as `(name, value)` pairs. It is the
/// source of the locale pass-through and of nothing else.
pub(crate) fn serve_environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect()
}

/// The locale and time zone entries of `serve_env` (`LANG`, `LANGUAGE`,
/// `TZ`, `LC_*`), which pass through to a child when the serve process has
/// them. Nothing else of it does.
pub(crate) fn locale_entries(serve_env: &[(String, String)]) -> Vec<(String, String)> {
    serve_env
        .iter()
        .filter(|(k, _)| is_locale_key(k))
        .cloned()
        .collect()
}

fn is_locale_key(key: &str) -> bool {
    env_policy::PASSTHROUGH
        .iter()
        .any(|k| WINDOWS.same_key(k, key))
        || key.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("LC_"))
}

/// The system directories a bare program name is looked up in after the
/// child's own `PATH`.
pub(crate) fn system_dirs(windows_dir: &str) -> [PathBuf; 2] {
    [
        Path::new(windows_dir).join("System32"),
        PathBuf::from(windows_dir),
    ]
}

/// The program `argv[0]` names, as a full path.
///
/// A name with a directory part is that path (relative to the child's working
/// directory). A bare name is looked up in the directories of the child's
/// own `PATH`, then the system directories, and never in the host's working
/// directory or on the host's `PATH`: the client picks the command, the
/// host's account decides what that name means. Without an extension the
/// name gets `.exe`, like `CreateProcessW` does. Batch files and `cmd.exe`
/// built-ins are not run through a shell here: the client has to send
/// `cmd /c ...` itself.
pub(crate) fn resolve_program(
    argv0: &str,
    path: Option<&str>,
    cwd: &Path,
    system_dirs: &[PathBuf],
) -> io::Result<PathBuf> {
    let name = Path::new(argv0);
    let names: Vec<OsString> = if name.extension().is_none() {
        let mut exe = OsString::from(argv0);
        exe.push(".exe");
        vec![exe]
    } else {
        let mut exe = OsString::from(argv0);
        exe.push(".exe");
        vec![OsString::from(argv0), exe]
    };
    let not_found = || {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{argv0}: program not found"),
        )
    };
    if argv0.is_empty() {
        return Err(not_found());
    }
    if argv0.contains(['\\', '/', ':']) {
        return names
            .iter()
            .map(|n| {
                let n = Path::new(n);
                if n.is_absolute() {
                    n.to_path_buf()
                } else {
                    cwd.join(n)
                }
            })
            .find(|p| p.is_file())
            .ok_or_else(not_found);
    }
    let dirs = path
        .into_iter()
        .flat_map(|p| std::env::split_paths(OsStr::new(p)))
        .filter(|dir| dir.is_absolute())
        .chain(system_dirs.iter().cloned());
    for dir in dirs {
        for n in &names {
            let candidate = dir.join(n);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(not_found())
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

/// `argv` as one `CreateProcessW` command line, quoted the way Rust's
/// `std::process::Command` quotes a Windows command line (the rules every
/// MSVCRT-style `argv` parser undoes).
pub(crate) fn command_line(argv: &[String]) -> OsString {
    let mut wide: Vec<u16> = Vec::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            wide.push(u16::from(b' '));
        }
        push_arg(&mut wide, OsStr::new(arg));
    }
    OsString::from_wide(&wide)
}

fn push_arg(out: &mut Vec<u16>, arg: &OsStr) {
    let units: Vec<u16> = arg.encode_wide().collect();
    let quote = units.is_empty() || units.iter().any(|&c| c == 0x20 || c == 0x09);
    if quote {
        out.push(u16::from(b'"'));
    }
    let mut backslashes = 0usize;
    for &unit in &units {
        if unit == u16::from(b'\\') {
            backslashes += 1;
        } else {
            if unit == u16::from(b'"') {
                // n backslashes before a quote become 2n + 1.
                out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes + 1));
            }
            backslashes = 0;
        }
        out.push(unit);
    }
    if quote {
        // n backslashes before the closing quote become 2n.
        out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        out.push(u16::from(b'"'));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The program `argv[0]` names is found on the child's own `PATH`, then the
    /// system directories, never in the host's working directory.
    #[test]
    fn a_bare_program_name_is_never_searched_in_the_working_directory() {
        let cwd = tempfile::tempdir().unwrap();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        for (dir, name) in [
            (&cwd, "evil.exe"),
            (&first, "tool.exe"),
            (&second, "tool.exe"),
            (&second, "only-second.exe"),
            (&system, "sysonly.exe"),
            (&cwd, "local.exe"),
        ] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        let path = std::env::join_paths([Path::new(r"relative\dir"), first.path(), second.path()])
            .unwrap();
        let path = path.to_str().unwrap();
        let system_dirs = [system.path().to_path_buf()];
        let find = |name: &str| resolve_program(name, Some(path), cwd.path(), &system_dirs);

        // A file in the working directory is not on the search path.
        assert_eq!(find("evil").unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(
            find("evil.exe").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        // The first `PATH` entry that has it wins; `.exe` is added.
        assert_eq!(find("tool").unwrap(), first.path().join("tool.exe"));
        assert_eq!(
            find("only-second").unwrap(),
            second.path().join("only-second.exe")
        );
        // The system directories come after `PATH`.
        assert_eq!(find("sysonly").unwrap(), system.path().join("sysonly.exe"));
        // A name with a directory part is that path, relative to the child's
        // working directory.
        assert_eq!(find(r".\local").unwrap(), cwd.path().join(r".\local.exe"));
        assert_eq!(
            find(first.path().join("tool").to_str().unwrap()).unwrap(),
            first.path().join("tool.exe")
        );
        assert_eq!(find("").unwrap_err().kind(), io::ErrorKind::NotFound);
        // No PATH at all still reaches the system directories.
        assert_eq!(
            resolve_program("sysonly", None, cwd.path(), &system_dirs).unwrap(),
            system.path().join("sysonly.exe")
        );
    }

    fn quoted(args: &[&str]) -> String {
        let argv: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        command_line(&argv).to_string_lossy().into_owned()
    }

    /// The quoting rules every MSVCRT `argv` parser undoes.
    #[test]
    fn command_line_quotes_arguments_the_way_the_c_runtime_parses_them() {
        assert_eq!(
            quoted(&["cmd.exe", "/c", "echo x"]),
            r#"cmd.exe /c "echo x""#
        );
        assert_eq!(quoted(&["a", ""]), r#"a """#);
        assert_eq!(quoted(&["a", r#"say "hi""#]), r#"a "say \"hi\"""#);
        // Backslashes are literal unless a quote follows them.
        assert_eq!(quoted(&["a", r"C:\dir\"]), r"a C:\dir\");
        assert_eq!(quoted(&["a", r"C:\my dir\"]), r#"a "C:\my dir\\""#);
        assert_eq!(quoted(&["a", r#"x\"y"#]), r#"a x\\\"y"#);
    }

    #[test]
    fn only_locale_and_time_zone_variables_pass_through() {
        let serve = [
            ("LANG", "C"),
            ("lc_all", "x"),
            ("Tz", "UTC"),
            ("LANGUAGE", "en"),
            ("LCX", "no"),
            ("PATH", r"C:\serve"),
            ("TERM", "dumb"),
            ("SECRET", "s"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let names: Vec<String> = locale_entries(&serve).into_iter().map(|(k, _)| k).collect();
        assert_eq!(names, ["LANG", "lc_all", "Tz", "LANGUAGE"]);
    }
}
