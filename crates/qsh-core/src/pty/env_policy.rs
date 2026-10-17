//! Which environment keys a session child gets from the host and which the
//! client may not touch (`docs/design/architecture.md` §4, ADR-0035
//! decision 21). The tables and the composition are plain functions without
//! `cfg`, so every platform's test leg runs them; only the code that reads
//! the account and the environment is per-platform.
//!
//! A session child never inherits the `qsh serve` environment. It gets the
//! host's own idea of the account's environment (`HOME`/`USER`/... from the
//! password database on unix, the user's environment block on Windows), the
//! `TERM` hint, a locale and time zone pass-through, and the client's `env`
//! overlay. The **pinned** keys are the ones the overlay may not change: the
//! identity of the login, and `PATH`, because `argv[0]` is resolved against
//! it and a client-supplied `PATH` would let the client pick which binary a
//! policy-approved command name runs.

// The Windows half is compiled everywhere so that every test leg runs it; a
// unix build only uses it from tests.
#![cfg_attr(not(windows), allow(dead_code))]

/// `TERM` when the client sent no hint.
pub(crate) const DEFAULT_TERM: &str = "xterm-256color";

/// Environment keys copied from the `qsh serve` process into the child (in
/// addition to anything the client sends), besides every `LC_*`: locale and
/// time zone only, never `PATH`, never secrets.
pub(crate) const PASSTHROUGH: &[&str] = &["LANG", "LANGUAGE", "TZ"];

/// Keys the client's `env` may not override on unix: the identity of the
/// login (fixed by the password database) and `PATH`. `crate::exec`
/// (`exec.run`, no PTY) pins the same five keys the same way.
pub(crate) const PINNED_POSIX: &[&str] = &["HOME", "USER", "LOGNAME", "SHELL", "PATH"];

/// Keys the client's `env` may not override on a Windows host: the unix five
/// plus the Windows identity variables. Environment variable names on
/// Windows are case-insensitive, so the comparison is too ([`KeyTable`]).
pub(crate) const PINNED_WINDOWS: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "PATH",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "HOMEDRIVE",
    "HOMEPATH",
    "COMSPEC",
    "SystemRoot",
];

/// A platform's pinned keys and how it compares environment names.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyTable {
    pinned: &'static [&'static str],
    ignore_case: bool,
}

/// unix: exact names.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) const POSIX: KeyTable = KeyTable {
    pinned: PINNED_POSIX,
    ignore_case: false,
};

/// Windows: names compare ignoring ASCII case.
pub(crate) const WINDOWS: KeyTable = KeyTable {
    pinned: PINNED_WINDOWS,
    ignore_case: true,
};

impl KeyTable {
    /// Whether `a` and `b` name the same variable.
    pub(crate) fn same_key(&self, a: &str, b: &str) -> bool {
        if self.ignore_case {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    }

    /// Whether the client may not set `key`.
    pub(crate) fn is_pinned(&self, key: &str) -> bool {
        self.pinned.iter().any(|p| self.same_key(p, key))
    }
}

/// Whether `(key, value)` can be an environment entry at all. A client entry
/// that cannot is dropped without a word on both platforms.
pub(crate) fn is_valid_entry(key: &str, value: &str) -> bool {
    !(key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0'))
}

/// The pinned entries of the user's environment, with their own spelling.
/// A pinned key the user's environment does not define has no entry: the
/// child gets no such variable, and the client cannot add one.
pub(crate) fn windows_pinned_values(user_env: &[(String, String)]) -> Vec<(String, String)> {
    user_env
        .iter()
        .filter(|(k, _)| WINDOWS.is_pinned(k))
        .cloned()
        .collect()
}

/// The child's environment on a Windows host: the user's `base`, then each
/// layer in order (`TERM`, locale pass-through, the client's overlay; a later
/// entry replaces an earlier one with the same name, whatever its case), and
/// then the `pinned` entries applied again last, so nothing in a layer can
/// change or add a pinned key. The result is sorted the way Windows lists an
/// environment block and has one entry per name.
pub(crate) fn windows_overlay_env(
    base: &[(String, String)],
    layers: &[&[(String, String)]],
    pinned: &[(String, String)],
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::with_capacity(base.len() + 8);
    let set = |env: &mut Vec<(String, String)>, key: &str, value: &str| match env
        .iter_mut()
        .find(|(k, _)| WINDOWS.same_key(k, key))
    {
        Some(slot) => *slot = (key.to_string(), value.to_string()),
        None => env.push((key.to_string(), value.to_string())),
    };
    for (k, v) in base {
        if is_valid_entry(k, v) {
            set(&mut env, k, v);
        }
    }
    for layer in layers {
        for (k, v) in *layer {
            if is_valid_entry(k, v) {
                set(&mut env, k, v);
            }
        }
    }
    env.retain(|(k, _)| !WINDOWS.is_pinned(k));
    for (k, v) in pinned {
        set(&mut env, k, v);
    }
    env.sort_by_cached_key(|(k, _)| k.to_ascii_uppercase());
    env
}

/// `env` as the UTF-16 block `CreateProcessW` takes with
/// `CREATE_UNICODE_ENVIRONMENT`: `NAME=value` entries each ended by a NUL,
/// and one more NUL after the last (an empty environment is two NULs).
pub(crate) fn windows_environment_block(env: &[(String, String)]) -> Vec<u16> {
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in env {
        block.extend(k.encode_utf16());
        block.push(u16::from(b'='));
        block.extend(v.encode_utf16());
        block.push(0);
    }
    if env.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// The value of `key` in `env` (ignoring case, as Windows does).
pub(crate) fn windows_lookup<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter()
        .find(|(k, _)| WINDOWS.same_key(k, key))
        .map(|(_, v)| v.as_str())
}

/// Whether the `user@` hint names the account, given every name the account
/// is known by. unix compares exactly (one name, from the password
/// database); a Windows account is known as `user` and as `DOMAIN\user`, and
/// either spelling, in any case, is the account.
pub(crate) fn login_name_matches(hint: &str, names: &[String], table: KeyTable) -> bool {
    names.iter().any(|name| table.same_key(name, hint))
}

/// A Windows process exit code as the `exit_code` of `session.exit`: the same
/// 32 bits read as signed, which is what `ExitStatus::code()` returns. A
/// process ended by `STATUS_CONTROL_C_EXIT` (`0xC000013A`) reports a negative
/// number.
pub(crate) const fn windows_exit_code(code: u32) -> i32 {
    code as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn windows_pinned_keys_match_case_insensitively() {
        for key in [
            "PATH",
            "Path",
            "path",
            "UserProfile",
            "USERPROFILE",
            "comspec",
            "SYSTEMROOT",
            "systemroot",
            "UserName",
            "userdomain",
            "HomeDrive",
            "homepath",
            "home",
            "User",
            "logname",
            "shell",
        ] {
            assert!(WINDOWS.is_pinned(key), "{key} must be pinned on Windows");
        }
        for key in ["TERM", "PATHEXT", "TEMP", "USERPROFILES", "PATH ", ""] {
            assert!(!WINDOWS.is_pinned(key), "{key:?} must not be pinned");
        }
        // unix names are exact: `path` is a different variable there.
        assert!(POSIX.is_pinned("PATH"));
        assert!(!POSIX.is_pinned("path"));
        assert!(!POSIX.is_pinned("USERPROFILE"));
        // The Windows set is the unix set plus the identity variables.
        for key in PINNED_POSIX {
            assert!(WINDOWS.is_pinned(key), "{key}");
        }
    }

    #[test]
    fn windows_env_overlay_reapplies_pinned_keys_last() {
        let user = pairs(&[
            ("Path", r"C:\Windows\System32"),
            ("USERPROFILE", r"C:\Users\alice"),
            ("COMSPEC", r"C:\Windows\System32\cmd.exe"),
            ("SystemRoot", r"C:\Windows"),
            ("TEMP", r"C:\Users\alice\AppData\Local\Temp"),
        ]);
        let pinned = windows_pinned_values(&user);
        let term = pairs(&[("TERM", "xterm-256color")]);
        let locale = pairs(&[("LANG", "en_US.UTF-8")]);
        let client = pairs(&[
            ("path", r"C:\evil"),
            ("UserProfile", r"C:\evil"),
            ("comspec", r"C:\evil\cmd.exe"),
            ("SYSTEMROOT", r"C:\evil"),
            ("home", r"C:\evil"),
            ("USERDOMAIN", "EVIL"),
            ("FOO", "bar"),
            ("temp", r"D:\scratch"),
            ("TERM", "dumb"),
            ("", "empty-name"),
            ("A=B", "equals"),
            ("NUL", "a\0b"),
        ]);
        let env = windows_overlay_env(&user, &[&term, &locale, &client], &pinned);
        let get = |key: &str| windows_lookup(&env, key);

        // Pinned keys keep the user's value and the user's spelling.
        assert_eq!(get("PATH"), Some(r"C:\Windows\System32"));
        assert!(env.iter().any(|(k, _)| k == "Path"), "{env:?}");
        assert!(!env.iter().any(|(k, _)| k == "path"), "{env:?}");
        assert_eq!(get("USERPROFILE"), Some(r"C:\Users\alice"));
        assert_eq!(get("COMSPEC"), Some(r"C:\Windows\System32\cmd.exe"));
        assert_eq!(get("SystemRoot"), Some(r"C:\Windows"));
        // Pinned keys the user's environment lacks cannot be added.
        assert_eq!(get("HOME"), None);
        assert_eq!(get("USERDOMAIN"), None);
        // Everything else layers in order; a later layer wins, any case.
        assert_eq!(get("TERM"), Some("dumb"));
        assert_eq!(get("LANG"), Some("en_US.UTF-8"));
        assert_eq!(get("FOO"), Some("bar"));
        assert_eq!(get("TEMP"), Some(r"D:\scratch"));
        // Malformed client entries are dropped.
        assert_eq!(get("A=B"), None);
        assert_eq!(get("NUL"), None);
        assert!(env.iter().all(|(k, _)| !k.is_empty()));
        // One entry per name, sorted like a Windows environment block.
        for pair in env.windows(2) {
            assert!(
                pair[0].0.to_ascii_uppercase() < pair[1].0.to_ascii_uppercase(),
                "{env:?}"
            );
        }
    }

    #[test]
    fn windows_environment_block_is_double_nul_terminated_utf16() {
        let env = pairs(&[("A", "1"), ("B", "")]);
        let block = windows_environment_block(&env);
        let expected: Vec<u16> = "A=1\0B=\0\0".encode_utf16().collect();
        assert_eq!(block, expected);
        assert_eq!(windows_environment_block(&[]), vec![0, 0]);
        let wide = pairs(&[("K", "caf\u{e9} \u{1f600}")]);
        let block = windows_environment_block(&wide);
        assert_eq!(
            String::from_utf16(&block[..block.len() - 2]).unwrap(),
            "K=caf\u{e9} \u{1f600}"
        );
    }

    #[test]
    fn login_name_comparison_accepts_user_and_domain_user_case_insensitively() {
        let names = vec!["Alice".to_string(), r"WORKGROUP\Alice".to_string()];
        for hint in [
            "Alice",
            "alice",
            "ALICE",
            r"WORKGROUP\Alice",
            r"workgroup\ALICE",
        ] {
            assert!(login_name_matches(hint, &names, WINDOWS), "{hint}");
        }
        for hint in [
            "",
            "bob",
            "Alic",
            "Alice ",
            r"OTHER\Alice",
            r"WORKGROUP\bob",
            r"WORKGROUP\",
            "WORKGROUP",
        ] {
            assert!(!login_name_matches(hint, &names, WINDOWS), "{hint:?}");
        }
        // unix: one name, exact, case-sensitive.
        let unix = vec!["alice".to_string()];
        assert!(login_name_matches("alice", &unix, POSIX));
        assert!(!login_name_matches("Alice", &unix, POSIX));
        // No known name (the lookup failed): nothing matches, fail closed.
        assert!(!login_name_matches("alice", &[], WINDOWS));
        assert!(!login_name_matches("", &[], POSIX));
    }

    #[test]
    fn windows_exit_code_is_the_u32_bit_pattern_as_i32() {
        assert_eq!(windows_exit_code(0), 0);
        assert_eq!(windows_exit_code(7), 7);
        assert_eq!(windows_exit_code(0xC000_013A), -1_073_741_510);
        assert_eq!(windows_exit_code(u32::MAX), -1);
        assert_eq!(windows_exit_code(0x8000_0000), i32::MIN);
    }
}
